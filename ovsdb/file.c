/* Copyright (c) 2009 Nicira Networks
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

#include "file.h"

#include <assert.h>
#include <fcntl.h>

#include "column.h"
#include "log.h"
#include "json.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "row.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "uuid.h"
#include "util.h"

#define THIS_MODULE VLM_ovsdb_file
#include "vlog.h"

static struct ovsdb_error *ovsdb_file_txn_from_json(struct ovsdb *,
                                                    const struct json *,
                                                    struct ovsdb_txn **);
static void ovsdb_file_replica_create(struct ovsdb *, struct ovsdb_log *);

struct ovsdb_error *
ovsdb_file_open(const char *file_name, bool read_only, struct ovsdb **dbp)
{
    struct ovsdb_schema *schema;
    struct ovsdb_error *error;
    struct ovsdb_log *log;
    struct json *json;
    struct ovsdb *db;

    error = ovsdb_log_open(file_name, read_only ? O_RDONLY : O_RDWR, &log);
    if (error) {
        return error;
    }

    error = ovsdb_log_read(log, &json);
    if (error) {
        return error;
    } else if (!json) {
        return ovsdb_io_error(EOF, "%s: database file contains no schema",
                              file_name);
    }

    error = ovsdb_schema_from_json(json, &schema);
    if (error) {
        json_destroy(json);
        return ovsdb_wrap_error(error,
                                "failed to parse \"%s\" as ovsdb schema",
                                file_name);
    }
    json_destroy(json);

    db = ovsdb_create(schema);
    while ((error = ovsdb_log_read(log, &json)) == NULL && json) {
        struct ovsdb_txn *txn;

        error = ovsdb_file_txn_from_json(db, json, &txn);
        json_destroy(json);
        if (error) {
            break;
        }

        ovsdb_txn_commit(txn, false);
    }
    if (error) {
        char *msg = ovsdb_error_to_string(error);
        VLOG_WARN("%s", msg);
        free(msg);

        ovsdb_error_destroy(error);
    }

    if (!read_only) {
        ovsdb_file_replica_create(db, log);
    } else {
        ovsdb_log_close(log);
    }

    *dbp = db;
    return NULL;
}

static struct ovsdb_error *
ovsdb_file_txn_row_from_json(struct ovsdb_txn *txn, struct ovsdb_table *table,
                             const struct uuid *row_uuid, struct json *json)
{
    const struct ovsdb_row *row = ovsdb_table_get_row(table, row_uuid);
    if (json->type == JSON_NULL) {
        if (!row) {
            return ovsdb_syntax_error(NULL, NULL, "transaction deletes "
                                      "row "UUID_FMT" that does not exist",
                                      UUID_ARGS(row_uuid));
        }
        ovsdb_txn_row_delete(txn, row);
        return NULL;
    } else if (row) {
        return ovsdb_row_from_json(ovsdb_txn_row_modify(txn, row),
                                   json, NULL, NULL);
    } else {
        struct ovsdb_error *error;
        struct ovsdb_row *new;

        new = ovsdb_row_create(table);
        *ovsdb_row_get_uuid_rw(new) = *row_uuid;
        error = ovsdb_row_from_json(new, json, NULL, NULL);
        if (error) {
            ovsdb_row_destroy(new);
        }

        ovsdb_txn_row_insert(txn, new);

        return error;
    }
}

static struct ovsdb_error *
ovsdb_file_txn_table_from_json(struct ovsdb_txn *txn,
                               struct ovsdb_table *table, struct json *json)
{
    struct shash_node *node;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "object expected");
    }

    SHASH_FOR_EACH (node, json->u.object) {
        const char *uuid_string = node->name;
        struct json *txn_row_json = node->data;
        struct ovsdb_error *error;
        struct uuid row_uuid;

        if (!uuid_from_string(&row_uuid, uuid_string)) {
            return ovsdb_syntax_error(json, NULL, "\"%s\" is not a valid UUID",
                                      uuid_string);
        }

        error = ovsdb_file_txn_row_from_json(txn, table, &row_uuid,
                                             txn_row_json);
        if (error) {
            return error;
        }
    }

    return NULL;
}

static struct ovsdb_error *
ovsdb_file_txn_from_json(struct ovsdb *db, const struct json *json,
                         struct ovsdb_txn **txnp)
{
    struct ovsdb_error *error;
    struct shash_node *node;
    struct ovsdb_txn *txn;

    *txnp = NULL;
    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "object expected");
    }

    txn = ovsdb_txn_create(db);
    SHASH_FOR_EACH (node, json->u.object) {
        const char *table_name = node->name;
        struct json *txn_table_json = node->data;
        struct ovsdb_table *table;

        table = shash_find_data(&db->tables, table_name);
        if (!table) {
            if (!strcmp(table_name, "_date")
                || !strcmp(table_name, "_comment")) {
                continue;
            }

            error = ovsdb_syntax_error(json, "unknown table",
                                       "No table named %s.", table_name);
            goto error;
        }

        error = ovsdb_file_txn_table_from_json(txn, table, txn_table_json);
        if (error) {
            goto error;
        }
    }
    *txnp = txn;
    return NULL;

error:
    ovsdb_txn_abort(txn);
    return error;
}

/* Replica implementation. */

struct ovsdb_file_replica {
    struct ovsdb_replica replica;
    struct ovsdb_log *log;
};

static const struct ovsdb_replica_class ovsdb_file_replica_class;

static void
ovsdb_file_replica_create(struct ovsdb *db, struct ovsdb_log *log)
{
    struct ovsdb_file_replica *r = xmalloc(sizeof *r);
    ovsdb_replica_init(&r->replica, &ovsdb_file_replica_class);
    r->log = log;
    ovsdb_add_replica(db, &r->replica);

}

static struct ovsdb_file_replica *
ovsdb_file_replica_cast(struct ovsdb_replica *replica)
{
    assert(replica->class == &ovsdb_file_replica_class);
    return CONTAINER_OF(replica, struct ovsdb_file_replica, replica);
}

struct ovsdb_file_replica_aux {
    struct json *json;          /* JSON for the whole transaction. */
    struct json *table_json;    /* JSON for 'table''s transaction. */
    struct ovsdb_table *table;  /* Table described in 'table_json'.  */
};

static bool
ovsdb_file_replica_change_cb(const struct ovsdb_row *old,
                             const struct ovsdb_row *new,
                             void *aux_)
{
    struct ovsdb_file_replica_aux *aux = aux_;
    struct json *row;

    if (!new) {
        row = json_null_create();
    } else {
        struct shash_node *node;

        row = NULL;
        SHASH_FOR_EACH (node, &new->table->schema->columns) {
            const struct ovsdb_column *column = node->data;
            const struct ovsdb_type *type = &column->type;
            unsigned int idx = column->index;

            if (idx != OVSDB_COL_UUID && column->persistent
                && (!old || !ovsdb_datum_equals(&old->fields[idx],
                                                &new->fields[idx], type)))
            {
                if (!row) {
                    row = json_object_create();
                }
                json_object_put(row, column->name,
                                ovsdb_datum_to_json(&new->fields[idx], type));
            }
        }
    }

    if (row) {
        struct ovsdb_table *table = new ? new->table : old->table;
        char uuid[UUID_LEN + 1];

        if (table != aux->table) {
            /* Create JSON object for transaction overall. */
            if (!aux->json) {
                aux->json = json_object_create();
            }

            /* Create JSON object for transaction on this table. */
            aux->table_json = json_object_create();
            aux->table = table;
            json_object_put(aux->json, table->schema->name, aux->table_json);
        }

        /* Add row to transaction for this table. */
        snprintf(uuid, sizeof uuid,
                 UUID_FMT, UUID_ARGS(ovsdb_row_get_uuid(new ? new : old)));
        json_object_put(aux->table_json, uuid, row);
    }

    return true;
}

static struct ovsdb_error *
ovsdb_file_replica_commit(struct ovsdb_replica *r_,
                          const struct ovsdb_txn *txn, bool durable)
{
    struct ovsdb_file_replica *r = ovsdb_file_replica_cast(r_);
    struct ovsdb_file_replica_aux aux;
    struct ovsdb_error *error;
    const char *comment;

    aux.json = NULL;
    aux.table_json = NULL;
    aux.table = NULL;
    ovsdb_txn_for_each_change(txn, ovsdb_file_replica_change_cb, &aux);

    if (!aux.json) {
        /* Nothing to commit. */
        return NULL;
    }

    comment = ovsdb_txn_get_comment(txn);
    if (comment) {
        json_object_put_string(aux.json, "_comment", comment);
    }

    json_object_put(aux.json, "_date", json_integer_create(time_now()));

    error = ovsdb_log_write(r->log, aux.json);
    json_destroy(aux.json);
    if (error) {
        return ovsdb_wrap_error(error, "writing transaction failed");
    }

    if (durable) {
        error = ovsdb_log_commit(r->log);
        if (error) {
            return ovsdb_wrap_error(error, "committing transaction failed");
        }
    }

    return NULL;
}

static void
ovsdb_file_replica_destroy(struct ovsdb_replica *r_)
{
    struct ovsdb_file_replica *r = ovsdb_file_replica_cast(r_);

    ovsdb_log_close(r->log);
    free(r);
}

static const struct ovsdb_replica_class ovsdb_file_replica_class = {
    ovsdb_file_replica_commit,
    ovsdb_file_replica_destroy
};
