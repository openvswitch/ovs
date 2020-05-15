/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <config.h>

#include "rbac.h"

#include <limits.h>

#include "column.h"
#include "condition.h"
#include "file.h"
#include "mutation.h"
#include "openvswitch/vlog.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb-util.h"
#include "ovsdb.h"
#include "query.h"
#include "row.h"
#include "server.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_rbac);

static const struct ovsdb_row *
ovsdb_find_row_by_string_key(const struct ovsdb_table *table,
                             const char *column_name,
                             const char *key)
{
    const struct ovsdb_column *column;
    column = ovsdb_table_schema_get_column(table->schema, column_name);

    if (column) {
        /* XXX This is O(n) in the size of the table.  If the table has an
         * index on the column, then we could implement it in O(1). */
        const struct ovsdb_row *row;
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum = &row->fields[column->index];
            for (size_t i = 0; i < datum->n; i++) {
                if (datum->keys[i].string[0] &&
                    !strcmp(key, datum->keys[i].string)) {
                    return row;
                }
            }
        }
    }

    return NULL;
}

static const struct ovsdb_row *
ovsdb_rbac_lookup_perms(const struct ovsdb *db, const char *role,
                        const char *table)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    const struct ovsdb_row *role_row, *perm_row;
    const struct ovsdb_column *column;

    /* Lookup role in roles table */
    role_row = ovsdb_find_row_by_string_key(db->rbac_role, "name", role);
    if (!role_row) {
        VLOG_INFO_RL(&rl, "rbac: role \"%s\" not found in rbac roles table",
                     role);
        return NULL;
    }

    /* Find row in permissions column for table from "permissions" column */
    column = ovsdb_table_schema_get_column(role_row->table->schema,
                                           "permissions");
    if (!column) {
        VLOG_INFO_RL(&rl, "rbac: \"permissions\" column not present in rbac "
                  "roles table");
        return NULL;
    }
    perm_row = ovsdb_util_read_map_string_uuid_column(role_row, "permissions",
                                                      table);

    return perm_row;
}

static bool
ovsdb_rbac_authorized(const struct ovsdb_row *perms,
                      const char *id,
                      const struct ovsdb_row *row)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    const struct ovsdb_datum *datum;
    size_t i;

    datum = ovsdb_util_get_datum(CONST_CAST(struct ovsdb_row *, perms),
                                 "authorization",
                                 OVSDB_TYPE_STRING, OVSDB_TYPE_VOID, UINT_MAX);

    if (!datum) {
        VLOG_INFO_RL(&rl, "rbac: error reading authorization column");
        return false;
    }

    for (i = 0; i < datum->n; i++) {
        const char *name = datum->keys[i].string;
        const char *value = NULL;
        bool is_map;

        if (name[0] == '\0') {
            /* empty string means all are authorized */
            return true;
        }

        is_map = strchr(name, ':') != NULL;

        if (is_map) {
            char *tmp = xstrdup(name);
            char *col_name, *key, *save_ptr = NULL;
            col_name = strtok_r(tmp, ":", &save_ptr);
            key = strtok_r(NULL, ":", &save_ptr);

            if (col_name && key) {
                value = ovsdb_util_read_map_string_column(row, col_name, key);
            }
            free(tmp);
        } else {
            ovsdb_util_read_string_column(row, name, &value);
        }
        if (value && !strcmp(value, id)) {
            return true;
        }
    }

    return false;
}

bool
ovsdb_rbac_insert(const struct ovsdb *db, const struct ovsdb_table *table,
                  const struct ovsdb_row *row,
                  const char *role, const char *id)
{
    const struct ovsdb_table_schema *ts = table->schema;
    const struct ovsdb_row *perms;
    bool insdel;

    if (!db->rbac_role || !role || *role == '\0') {
        return true;
    }

    if (!id) {
        goto denied;
    }

    perms = ovsdb_rbac_lookup_perms(db, role, ts->name);

    if (!perms) {
        goto denied;
    }

    if (!ovsdb_rbac_authorized(perms, id, row)) {
        goto denied;
    }

    if (!ovsdb_util_read_bool_column(perms, "insert_delete", &insdel)) {
        return false;
    }

    if (insdel) {
        return true;
    }

denied:
    return false;
}

struct rbac_delete_cbdata {
    const struct ovsdb_table *table;
    const struct ovsdb_row *perms;
    const char *role;
    const char *id;
    bool permitted;
};

static bool
rbac_delete_cb(const struct ovsdb_row *row, void *rd_)
{
    struct rbac_delete_cbdata *rd = rd_;
    bool insdel;

    if (!ovsdb_rbac_authorized(rd->perms, rd->id, row)) {
        goto denied;
    }

    if (!ovsdb_util_read_bool_column(rd->perms, "insert_delete", &insdel)) {
        goto denied;
    }

    if (!insdel) {
        goto denied;
    }
    return true;

denied:
    rd->permitted = false;
    return false;
}

bool
ovsdb_rbac_delete(const struct ovsdb *db, struct ovsdb_table *table,
                  struct ovsdb_condition *condition,
                  const char *role, const char *id)
{
    const struct ovsdb_table_schema *ts = table->schema;
    const struct ovsdb_row *perms;
    struct rbac_delete_cbdata rd;

    if (!db->rbac_role || !role || *role == '\0') {
        return true;
    }
    if (!id) {
        goto denied;
    }

    perms = ovsdb_rbac_lookup_perms(db, role, ts->name);

    if (!perms) {
        goto denied;
    }

    rd.permitted = true;
    rd.perms = perms;
    rd.table = table;
    rd.role = role;
    rd.id = id;

    ovsdb_query(table, condition, rbac_delete_cb, &rd);

    if (rd.permitted) {
        return true;
    }

denied:
    return false;
}

struct rbac_update_cbdata {
    const struct ovsdb_table *table;
    const struct ovsdb_column_set *columns; /* columns to be modified */
    const struct ovsdb_datum *modifiable; /* modifiable column names */
    const struct ovsdb_row *perms;
    const char *role;
    const char *id;
    bool permitted;
};

static bool
rbac_column_modification_permitted(const struct ovsdb_column *column,
                                   const struct ovsdb_datum *modifiable)
{
    size_t i;

    for (i = 0; i < modifiable->n; i++) {
        char *name = modifiable->keys[i].string;

        if (!strcmp(name, column->name)) {
            return true;
        }
    }
    return false;
}

static bool
rbac_update_cb(const struct ovsdb_row *row, void *ru_)
{
    struct rbac_update_cbdata *ru = ru_;
    size_t i;

    if (!ovsdb_rbac_authorized(ru->perms, ru->id, row)) {
        goto denied;
    }

    for (i = 0; i < ru->columns->n_columns; i++) {
        const struct ovsdb_column *column = ru->columns->columns[i];

        if (!rbac_column_modification_permitted(column, ru->modifiable)) {
            goto denied;
        }
    }
    return true;

denied:
    ru->permitted = false;
    return false;
}

bool
ovsdb_rbac_update(const struct ovsdb *db,
                  struct ovsdb_table *table,
                  struct ovsdb_column_set *columns,
                  struct ovsdb_condition *condition,
                  const char *role, const char *id)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    const struct ovsdb_table_schema *ts = table->schema;
    const struct ovsdb_datum *datum;
    const struct ovsdb_row *perms;
    struct rbac_update_cbdata ru;

    if (!db->rbac_role || !role || *role == '\0') {
        return true;
    }
    if (!id) {
        goto denied;
    }

    perms = ovsdb_rbac_lookup_perms(db, role, ts->name);

    if (!perms) {
        goto denied;
    }

    datum = ovsdb_util_get_datum(CONST_CAST(struct ovsdb_row *, perms),
                                 "update",
                                 OVSDB_TYPE_STRING, OVSDB_TYPE_VOID, UINT_MAX);

    if (!datum) {
        VLOG_INFO_RL(&rl, "ovsdb_rbac_update: could not read \"update\" "
                     "column");
        goto denied;
    }

    ru.table = table;
    ru.columns = columns;
    ru.role = role;
    ru.id = id;
    ru.perms = perms;
    ru.modifiable = datum;
    ru.permitted = true;

    ovsdb_query(table, condition, rbac_update_cb, &ru);

    if (ru.permitted) {
        return true;
    }

denied:
    return false;
}

struct rbac_mutate_cbdata {
    const struct ovsdb_table *table;
    const struct ovsdb_mutation_set *mutations; /* columns to be mutated */
    const struct ovsdb_datum *modifiable; /* modifiable column names */
    const struct ovsdb_row *perms;
    const char *role;
    const char *id;
    bool permitted;
};

static bool
rbac_mutate_cb(const struct ovsdb_row *row, void *rm_)
{
    struct rbac_mutate_cbdata *rm = rm_;
    size_t i;

    if (!ovsdb_rbac_authorized(rm->perms, rm->id, row)) {
        goto denied;
    }

    for (i = 0; i < rm->mutations->n_mutations; i++) {
        const struct ovsdb_column *column = rm->mutations->mutations[i].column;

        if (!rbac_column_modification_permitted(column, rm->modifiable)) {
            goto denied;
        }
    }

    return true;

denied:
    rm->permitted = false;
    return false;
}

bool
ovsdb_rbac_mutate(const struct ovsdb *db,
                  struct ovsdb_table *table,
                  struct ovsdb_mutation_set *mutations,
                  struct ovsdb_condition *condition,
                  const char *role, const char *id)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    const struct ovsdb_table_schema *ts = table->schema;
    const struct ovsdb_datum *datum;
    const struct ovsdb_row *perms;
    struct rbac_mutate_cbdata rm;

    if (!db->rbac_role || !role || *role == '\0') {
        return true;
    }
    if (!id) {
        goto denied;
    }

    perms = ovsdb_rbac_lookup_perms(db, role, ts->name);

    if (!perms) {
        goto denied;
    }

    datum = ovsdb_util_get_datum(CONST_CAST(struct ovsdb_row *, perms),
                                 "update",
                                 OVSDB_TYPE_STRING, OVSDB_TYPE_VOID, UINT_MAX);

    if (!datum) {
        VLOG_INFO_RL(&rl, "ovsdb_rbac_mutate: could not read \"update\" "
                     "column");
        goto denied;
    }

    rm.table = table;
    rm.mutations = mutations;
    rm.role = role;
    rm.id = id;
    rm.perms = perms;
    rm.modifiable = datum;
    rm.permitted = true;

    ovsdb_query(table, condition, rbac_mutate_cb, &rm);

    if (rm.permitted) {
        return true;
    }

denied:
    return false;
}
