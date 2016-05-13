/*
 * Copyright (c) 2015 Nicira, Inc.
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

#include <errno.h>

#include "bitmap.h"
#include "column.h"
#include "openvswitch/dynamic-string.h"
#include "json.h"
#include "jsonrpc.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb.h"
#include "row.h"
#include "simap.h"
#include "hash.h"
#include "table.h"
#include "hash.h"
#include "timeval.h"
#include "transaction.h"
#include "jsonrpc-server.h"
#include "monitor.h"
#include "openvswitch/vlog.h"


static const struct ovsdb_replica_class ovsdb_jsonrpc_replica_class;
static struct hmap ovsdb_monitors = HMAP_INITIALIZER(&ovsdb_monitors);

/*  Backend monitor.
 *
 *  ovsdb_monitor keep track of the ovsdb changes.
 */

/* A collection of tables being monitored. */
struct ovsdb_monitor {
    struct ovsdb_replica replica;
    struct shash tables;     /* Holds "struct ovsdb_monitor_table"s. */
    struct ovs_list jsonrpc_monitors;  /* Contains "jsonrpc_monitor_node"s. */
    struct ovsdb *db;
    uint64_t n_transactions;      /* Count number of committed transactions. */
    struct hmap_node hmap_node;   /* Elements within ovsdb_monitors.  */
    struct hmap json_cache;       /* Contains "ovsdb_monitor_json_cache_node"s.*/
};

/* A json object of updates between 'from_txn' and 'dbmon->n_transactions'
 * inclusive.  */
struct ovsdb_monitor_json_cache_node {
    struct hmap_node hmap_node;   /* Elements in json cache. */
    enum ovsdb_monitor_version version;
    uint64_t from_txn;
    struct json *json;            /* Null, or a cloned of json */
};

struct jsonrpc_monitor_node {
    struct ovsdb_jsonrpc_monitor *jsonrpc_monitor;
    struct ovs_list node;
};

/* A particular column being monitored. */
struct ovsdb_monitor_column {
    const struct ovsdb_column *column;
    enum ovsdb_monitor_selection select;
};

/* A row that has changed in a monitored table. */
struct ovsdb_monitor_row {
    struct hmap_node hmap_node; /* In ovsdb_jsonrpc_monitor_table.changes. */
    struct uuid uuid;           /* UUID of row that changed. */
    struct ovsdb_datum *old;    /* Old data, NULL for an inserted row. */
    struct ovsdb_datum *new;    /* New data, NULL for a deleted row. */
};

/* Contains 'struct ovsdb_monitor_row's for rows that have been
 * updated but not yet flushed to all the jsonrpc connection.
 *
 * 'n_refs' represent the number of jsonrpc connections that have
 * not received updates. Generate the update for the last jsonprc
 * connection will also destroy the whole "struct ovsdb_monitor_changes"
 * object.
 *
 * 'transaction' stores the first update's transaction id.
 * */
struct ovsdb_monitor_changes {
    struct ovsdb_monitor_table *mt;
    struct hmap rows;
    int n_refs;
    uint64_t transaction;
    struct hmap_node hmap_node;  /* Element in ovsdb_monitor_tables' changes
                                    hmap.  */
};

/* A particular table being monitored. */
struct ovsdb_monitor_table {
    const struct ovsdb_table *table;

    /* This is the union (bitwise-OR) of the 'select' values in all of the
     * members of 'columns' below. */
    enum ovsdb_monitor_selection select;

    /* Columns being monitored. */
    struct ovsdb_monitor_column *columns;
    size_t n_columns;

    /* Contains 'ovsdb_monitor_changes' indexed by 'transaction'. */
    struct hmap changes;
};

typedef struct json *
(*compose_row_update_cb_func)(const struct ovsdb_monitor_table *mt,
                              const struct ovsdb_monitor_row *row,
                              bool initial, unsigned long int *changed);

static void ovsdb_monitor_destroy(struct ovsdb_monitor *dbmon);
static struct ovsdb_monitor_changes * ovsdb_monitor_table_add_changes(
    struct ovsdb_monitor_table *mt, uint64_t next_txn);
static struct ovsdb_monitor_changes *ovsdb_monitor_table_find_changes(
    struct ovsdb_monitor_table *mt, uint64_t unflushed);
static void ovsdb_monitor_changes_destroy(
                                  struct ovsdb_monitor_changes *changes);
static void ovsdb_monitor_table_track_changes(struct ovsdb_monitor_table *mt,
                                  uint64_t unflushed);

static uint32_t
json_cache_hash(enum ovsdb_monitor_version version, uint64_t from_txn)
{
    uint32_t hash;

    hash = hash_uint64(version);
    hash = hash_uint64_basis(from_txn, hash);

    return hash;
}

static struct ovsdb_monitor_json_cache_node *
ovsdb_monitor_json_cache_search(const struct ovsdb_monitor *dbmon,
                                enum ovsdb_monitor_version version,
                                uint64_t from_txn)
{
    struct ovsdb_monitor_json_cache_node *node;
    uint32_t hash = json_cache_hash(version, from_txn);

    HMAP_FOR_EACH_WITH_HASH(node, hmap_node, hash, &dbmon->json_cache) {
        if (node->from_txn == from_txn && node->version == version) {
            return node;
        }
    }

    return NULL;
}

static void
ovsdb_monitor_json_cache_insert(struct ovsdb_monitor *dbmon,
                                enum ovsdb_monitor_version version,
                                uint64_t from_txn, struct json *json)
{
    struct ovsdb_monitor_json_cache_node *node;
    uint32_t hash = json_cache_hash(version, from_txn);

    node = xmalloc(sizeof *node);

    node->version = version;
    node->from_txn = from_txn;
    node->json = json ? json_clone(json) : NULL;

    hmap_insert(&dbmon->json_cache, &node->hmap_node, hash);
}

static void
ovsdb_monitor_json_cache_flush(struct ovsdb_monitor *dbmon)
{
    struct ovsdb_monitor_json_cache_node *node;

    HMAP_FOR_EACH_POP(node, hmap_node, &dbmon->json_cache) {
        json_destroy(node->json);
        free(node);
    }
}

static int
compare_ovsdb_monitor_column(const void *a_, const void *b_)
{
    const struct ovsdb_monitor_column *a = a_;
    const struct ovsdb_monitor_column *b = b_;

    return a->column < b->column ? -1 : a->column > b->column;
}

static struct ovsdb_monitor *
ovsdb_monitor_cast(struct ovsdb_replica *replica)
{
    ovs_assert(replica->class == &ovsdb_jsonrpc_replica_class);
    return CONTAINER_OF(replica, struct ovsdb_monitor, replica);
}

/* Finds and returns the ovsdb_monitor_row in 'mt->changes->rows' for the
 * given 'uuid', or NULL if there is no such row. */
static struct ovsdb_monitor_row *
ovsdb_monitor_changes_row_find(const struct ovsdb_monitor_changes *changes,
                               const struct uuid *uuid)
{
    struct ovsdb_monitor_row *row;

    HMAP_FOR_EACH_WITH_HASH (row, hmap_node, uuid_hash(uuid),
                             &changes->rows) {
        if (uuid_equals(uuid, &row->uuid)) {
            return row;
        }
    }
    return NULL;
}

/* Allocates an array of 'mt->n_columns' ovsdb_datums and initializes them as
 * copies of the data in 'row' drawn from the columns represented by
 * mt->columns[].  Returns the array.
 *
 * If 'row' is NULL, returns NULL. */
static struct ovsdb_datum *
clone_monitor_row_data(const struct ovsdb_monitor_table *mt,
                       const struct ovsdb_row *row)
{
    struct ovsdb_datum *data;
    size_t i;

    if (!row) {
        return NULL;
    }

    data = xmalloc(mt->n_columns * sizeof *data);
    for (i = 0; i < mt->n_columns; i++) {
        const struct ovsdb_column *c = mt->columns[i].column;
        const struct ovsdb_datum *src = &row->fields[c->index];
        struct ovsdb_datum *dst = &data[i];
        const struct ovsdb_type *type = &c->type;

        ovsdb_datum_clone(dst, src, type);
    }
    return data;
}

/* Replaces the mt->n_columns ovsdb_datums in row[] by copies of the data from
 * in 'row' drawn from the columns represented by mt->columns[]. */
static void
update_monitor_row_data(const struct ovsdb_monitor_table *mt,
                        const struct ovsdb_row *row,
                        struct ovsdb_datum *data)
{
    size_t i;

    for (i = 0; i < mt->n_columns; i++) {
        const struct ovsdb_column *c = mt->columns[i].column;
        const struct ovsdb_datum *src = &row->fields[c->index];
        struct ovsdb_datum *dst = &data[i];
        const struct ovsdb_type *type = &c->type;

        if (!ovsdb_datum_equals(src, dst, type)) {
            ovsdb_datum_destroy(dst, type);
            ovsdb_datum_clone(dst, src, type);
        }
    }
}

/* Frees all of the mt->n_columns ovsdb_datums in data[], using the types taken
 * from mt->columns[], plus 'data' itself. */
static void
free_monitor_row_data(const struct ovsdb_monitor_table *mt,
                      struct ovsdb_datum *data)
{
    if (data) {
        size_t i;

        for (i = 0; i < mt->n_columns; i++) {
            const struct ovsdb_column *c = mt->columns[i].column;

            ovsdb_datum_destroy(&data[i], &c->type);
        }
        free(data);
    }
}

/* Frees 'row', which must have been created from 'mt'. */
static void
ovsdb_monitor_row_destroy(const struct ovsdb_monitor_table *mt,
                          struct ovsdb_monitor_row *row)
{
    if (row) {
        free_monitor_row_data(mt, row->old);
        free_monitor_row_data(mt, row->new);
        free(row);
    }
}

void
ovsdb_monitor_add_jsonrpc_monitor(struct ovsdb_monitor *dbmon,
                                  struct ovsdb_jsonrpc_monitor *jsonrpc_monitor)
{
    struct jsonrpc_monitor_node *jm;

    jm = xzalloc(sizeof *jm);
    jm->jsonrpc_monitor = jsonrpc_monitor;
    ovs_list_push_back(&dbmon->jsonrpc_monitors, &jm->node);
}

struct ovsdb_monitor *
ovsdb_monitor_create(struct ovsdb *db,
                     struct ovsdb_jsonrpc_monitor *jsonrpc_monitor)
{
    struct ovsdb_monitor *dbmon;

    dbmon = xzalloc(sizeof *dbmon);

    ovsdb_replica_init(&dbmon->replica, &ovsdb_jsonrpc_replica_class);
    ovsdb_add_replica(db, &dbmon->replica);
    ovs_list_init(&dbmon->jsonrpc_monitors);
    dbmon->db = db;
    dbmon->n_transactions = 0;
    shash_init(&dbmon->tables);
    hmap_node_nullify(&dbmon->hmap_node);
    hmap_init(&dbmon->json_cache);

    ovsdb_monitor_add_jsonrpc_monitor(dbmon, jsonrpc_monitor);
    return dbmon;
}

void
ovsdb_monitor_add_table(struct ovsdb_monitor *m,
                        const struct ovsdb_table *table)
{
    struct ovsdb_monitor_table *mt;

    mt = xzalloc(sizeof *mt);
    mt->table = table;
    shash_add(&m->tables, table->schema->name, mt);
    hmap_init(&mt->changes);
}

void
ovsdb_monitor_add_column(struct ovsdb_monitor *dbmon,
                         const struct ovsdb_table *table,
                         const struct ovsdb_column *column,
                         enum ovsdb_monitor_selection select,
                         size_t *allocated_columns)
{
    struct ovsdb_monitor_table *mt;
    struct ovsdb_monitor_column *c;

    mt = shash_find_data(&dbmon->tables, table->schema->name);

    if (mt->n_columns >= *allocated_columns) {
        mt->columns = x2nrealloc(mt->columns, allocated_columns,
                                 sizeof *mt->columns);
    }

    mt->select |= select;
    c = &mt->columns[mt->n_columns++];
    c->column = column;
    c->select = select;
}

/* Check for duplicated column names. Return the first
 * duplicated column's name if found. Otherwise return
 * NULL.  */
const char * OVS_WARN_UNUSED_RESULT
ovsdb_monitor_table_check_duplicates(struct ovsdb_monitor *m,
                                     const struct ovsdb_table *table)
{
    struct ovsdb_monitor_table *mt;
    int i;

    mt = shash_find_data(&m->tables, table->schema->name);

    if (mt) {
        /* Check for duplicate columns. */
        qsort(mt->columns, mt->n_columns, sizeof *mt->columns,
              compare_ovsdb_monitor_column);
        for (i = 1; i < mt->n_columns; i++) {
            if (mt->columns[i].column == mt->columns[i - 1].column) {
                return mt->columns[i].column->name;
            }
        }
    }

    return NULL;
}

static struct ovsdb_monitor_changes *
ovsdb_monitor_table_add_changes(struct ovsdb_monitor_table *mt,
                                uint64_t next_txn)
{
    struct ovsdb_monitor_changes *changes;

    changes = xzalloc(sizeof *changes);

    changes->transaction = next_txn;
    changes->mt = mt;
    changes->n_refs = 1;
    hmap_init(&changes->rows);
    hmap_insert(&mt->changes, &changes->hmap_node, hash_uint64(next_txn));

    return changes;
};

static struct ovsdb_monitor_changes *
ovsdb_monitor_table_find_changes(struct ovsdb_monitor_table *mt,
                                 uint64_t transaction)
{
    struct ovsdb_monitor_changes *changes;
    size_t hash = hash_uint64(transaction);

    HMAP_FOR_EACH_WITH_HASH(changes, hmap_node, hash, &mt->changes) {
        if (changes->transaction == transaction) {
            return changes;
        }
    }

    return NULL;
}

/* Stop currently tracking changes to table 'mt' since 'transaction'. */
static void
ovsdb_monitor_table_untrack_changes(struct ovsdb_monitor_table *mt,
                                    uint64_t transaction)
{
    struct ovsdb_monitor_changes *changes =
                ovsdb_monitor_table_find_changes(mt, transaction);
    if (changes) {
        if (--changes->n_refs == 0) {
            hmap_remove(&mt->changes, &changes->hmap_node);
            ovsdb_monitor_changes_destroy(changes);
        }
    }
}

/* Start tracking changes to table 'mt' begins from 'transaction' inclusive.
 */
static void
ovsdb_monitor_table_track_changes(struct ovsdb_monitor_table *mt,
                                  uint64_t transaction)
{
    struct ovsdb_monitor_changes *changes;

    changes = ovsdb_monitor_table_find_changes(mt, transaction);
    if (changes) {
        changes->n_refs++;
    } else {
        ovsdb_monitor_table_add_changes(mt, transaction);
    }
}

static void
ovsdb_monitor_changes_destroy(struct ovsdb_monitor_changes *changes)
{
    struct ovsdb_monitor_row *row, *next;

    HMAP_FOR_EACH_SAFE (row, next, hmap_node, &changes->rows) {
        hmap_remove(&changes->rows, &row->hmap_node);
        ovsdb_monitor_row_destroy(changes->mt, row);
    }
    hmap_destroy(&changes->rows);
    free(changes);
}

static enum ovsdb_monitor_selection
ovsdb_monitor_row_update_type(bool initial, const bool old, const bool new)
{
    return initial ? OJMS_INITIAL
            : !old ? OJMS_INSERT
            : !new ? OJMS_DELETE
            : OJMS_MODIFY;
}
static bool
ovsdb_monitor_row_skip_update(const struct ovsdb_monitor_table *mt,
                              const struct ovsdb_monitor_row *row,
                              enum ovsdb_monitor_selection type,
                              unsigned long int *changed)
{
    if (!(mt->select & type)) {
        return true;
    }

    if (type == OJMS_MODIFY) {
        size_t i, n_changes;

        n_changes = 0;
        memset(changed, 0, bitmap_n_bytes(mt->n_columns));
        for (i = 0; i < mt->n_columns; i++) {
            const struct ovsdb_column *c = mt->columns[i].column;
            if (!ovsdb_datum_equals(&row->old[i], &row->new[i], &c->type)) {
                bitmap_set1(changed, i);
                n_changes++;
            }
        }
        if (!n_changes) {
            /* No actual changes: presumably a row changed and then
             * changed back later. */
            return true;
        }
    }

    return false;
}

/* Returns JSON for a <row-update> (as described in RFC 7047) for 'row' within
 * 'mt', or NULL if no row update should be sent.
 *
 * The caller should specify 'initial' as true if the returned JSON is going to
 * be used as part of the initial reply to a "monitor" request, false if it is
 * going to be used as part of an "update" notification.
 *
 * 'changed' must be a scratch buffer for internal use that is at least
 * bitmap_n_bytes(mt->n_columns) bytes long. */
static struct json *
ovsdb_monitor_compose_row_update(
    const struct ovsdb_monitor_table *mt,
    const struct ovsdb_monitor_row *row,
    bool initial, unsigned long int *changed)
{
    enum ovsdb_monitor_selection type;
    struct json *old_json, *new_json;
    struct json *row_json;
    size_t i;

    type = ovsdb_monitor_row_update_type(initial, row->old, row->new);
    if (ovsdb_monitor_row_skip_update(mt, row, type, changed)) {
        return NULL;
    }

    row_json = json_object_create();
    old_json = new_json = NULL;
    if (type & (OJMS_DELETE | OJMS_MODIFY)) {
        old_json = json_object_create();
        json_object_put(row_json, "old", old_json);
    }
    if (type & (OJMS_INITIAL | OJMS_INSERT | OJMS_MODIFY)) {
        new_json = json_object_create();
        json_object_put(row_json, "new", new_json);
    }
    for (i = 0; i < mt->n_columns; i++) {
        const struct ovsdb_monitor_column *c = &mt->columns[i];

        if (!(type & c->select)) {
            /* We don't care about this type of change for this
             * particular column (but we will care about it for some
             * other column). */
            continue;
        }

        if ((type == OJMS_MODIFY && bitmap_is_set(changed, i))
            || type == OJMS_DELETE) {
            json_object_put(old_json, c->column->name,
                            ovsdb_datum_to_json(&row->old[i],
                                                &c->column->type));
        }
        if (type & (OJMS_INITIAL | OJMS_INSERT | OJMS_MODIFY)) {
            json_object_put(new_json, c->column->name,
                            ovsdb_datum_to_json(&row->new[i],
                                                &c->column->type));
        }
    }

    return row_json;
}

/* Returns JSON for a <row-update2> (as described in ovsdb-server(1) mapage)
 * for 'row' within * 'mt', or NULL if no row update should be sent.
 *
 * The caller should specify 'initial' as true if the returned JSON is
 * going to be used as part of the initial reply to a "monitor2" request,
 * false if it is going to be used as part of an "update2" notification.
 *
 * 'changed' must be a scratch buffer for internal use that is at least
 * bitmap_n_bytes(mt->n_columns) bytes long. */
static struct json *
ovsdb_monitor_compose_row_update2(
    const struct ovsdb_monitor_table *mt,
    const struct ovsdb_monitor_row *row,
    bool initial, unsigned long int *changed)
{
    enum ovsdb_monitor_selection type;
    struct json *row_update2, *diff_json;
    size_t i;

    type = ovsdb_monitor_row_update_type(initial, row->old, row->new);
    if (ovsdb_monitor_row_skip_update(mt, row, type, changed)) {
        return NULL;
    }

    row_update2 = json_object_create();
    if (type == OJMS_DELETE) {
        json_object_put(row_update2, "delete", json_null_create());
    } else {
        diff_json = json_object_create();
        const char *op;

        for (i = 0; i < mt->n_columns; i++) {
            const struct ovsdb_monitor_column *c = &mt->columns[i];

            if (!(type & c->select)) {
                /* We don't care about this type of change for this
                 * particular column (but we will care about it for some
                 * other column). */
                continue;
            }

            if (type == OJMS_MODIFY) {
                struct ovsdb_datum diff;

                if (!bitmap_is_set(changed, i)) {
                    continue;
                }

                ovsdb_datum_diff(&diff ,&row->old[i], &row->new[i],
                                        &c->column->type);
                json_object_put(diff_json, c->column->name,
                                ovsdb_datum_to_json(&diff, &c->column->type));
                ovsdb_datum_destroy(&diff, &c->column->type);
            } else {
                if (!ovsdb_datum_is_default(&row->new[i], &c->column->type)) {
                    json_object_put(diff_json, c->column->name,
                                    ovsdb_datum_to_json(&row->new[i],
                                                        &c->column->type));
                }
            }
        }

        op = type == OJMS_INITIAL ? "initial"
                                  : type == OJMS_MODIFY ? "modify" : "insert";
        json_object_put(row_update2, op, diff_json);
    }

    return row_update2;
}

static size_t
ovsdb_monitor_max_columns(struct ovsdb_monitor *dbmon)
{
    struct shash_node *node;
    size_t max_columns = 0;

    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;

        max_columns = MAX(max_columns, mt->n_columns);
    }

    return max_columns;
}

/* Constructs and returns JSON for a <table-updates> object (as described in
 * RFC 7047) for all the outstanding changes within 'monitor', starting from
 * 'transaction'.  */
static struct json*
ovsdb_monitor_compose_update(struct ovsdb_monitor *dbmon,
                             bool initial, uint64_t transaction,
                             compose_row_update_cb_func row_update)
{
    struct shash_node *node;
    struct json *json;
    size_t max_columns = ovsdb_monitor_max_columns(dbmon);
    unsigned long int *changed = xmalloc(bitmap_n_bytes(max_columns));

    json = NULL;
    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;
        struct ovsdb_monitor_row *row, *next;
        struct ovsdb_monitor_changes *changes;
        struct json *table_json = NULL;

        changes = ovsdb_monitor_table_find_changes(mt, transaction);
        if (!changes) {
            continue;
        }

        HMAP_FOR_EACH_SAFE (row, next, hmap_node, &changes->rows) {
            struct json *row_json;

            row_json = (*row_update)(mt, row, initial, changed);
            if (row_json) {
                char uuid[UUID_LEN + 1];

                /* Create JSON object for transaction overall. */
                if (!json) {
                    json = json_object_create();
                }

                /* Create JSON object for transaction on this table. */
                if (!table_json) {
                    table_json = json_object_create();
                    json_object_put(json, mt->table->schema->name, table_json);
                }

                /* Add JSON row to JSON table. */
                snprintf(uuid, sizeof uuid, UUID_FMT, UUID_ARGS(&row->uuid));
                json_object_put(table_json, uuid, row_json);
            }
        }
    }
    free(changed);

    return json;
}

/* Returns JSON for a <table-updates> object (as described in RFC 7047)
 * for all the outstanding changes within 'monitor' that starts from
 * '*unflushed' transaction id.
 *
 * The caller should specify 'initial' as true if the returned JSON is going to
 * be used as part of the initial reply to a "monitor" request, false if it is
 * going to be used as part of an "update" notification. */
struct json *
ovsdb_monitor_get_update(struct ovsdb_monitor *dbmon,
                         bool initial, uint64_t *unflushed_,
                         enum ovsdb_monitor_version version)
{
    struct ovsdb_monitor_json_cache_node *cache_node;
    struct shash_node *node;
    struct json *json;
    const uint64_t unflushed = *unflushed_;
    const uint64_t next_unflushed = dbmon->n_transactions + 1;

    /* Return a clone of cached json if one exists. Otherwise,
     * generate a new one and add it to the cache.  */
    cache_node = ovsdb_monitor_json_cache_search(dbmon, version, unflushed);
    if (cache_node) {
        json = cache_node->json ? json_clone(cache_node->json) : NULL;
    } else {
        if (version == OVSDB_MONITOR_V1) {
            json = ovsdb_monitor_compose_update(dbmon, initial, unflushed,
                                        ovsdb_monitor_compose_row_update);
        } else {
            ovs_assert(version == OVSDB_MONITOR_V2);
            json = ovsdb_monitor_compose_update(dbmon, initial, unflushed,
                                        ovsdb_monitor_compose_row_update2);
        }
        ovsdb_monitor_json_cache_insert(dbmon, version, unflushed, json);
    }

    /* Maintain transaction id of 'changes'. */
    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;

        ovsdb_monitor_table_untrack_changes(mt, unflushed);
        ovsdb_monitor_table_track_changes(mt, next_unflushed);
    }
    *unflushed_ = next_unflushed;

    return json;
}

bool
ovsdb_monitor_needs_flush(struct ovsdb_monitor *dbmon,
                          uint64_t next_transaction)
{
    ovs_assert(next_transaction <= dbmon->n_transactions + 1);
    return (next_transaction <= dbmon->n_transactions);
}

void
ovsdb_monitor_table_add_select(struct ovsdb_monitor *dbmon,
                               const struct ovsdb_table *table,
                               enum ovsdb_monitor_selection select)
{
    struct ovsdb_monitor_table * mt;

    mt = shash_find_data(&dbmon->tables, table->schema->name);
    mt->select |= select;
}

 /*
 * If a row's change type (insert, delete or modify) matches that of
 * the monitor, they should be sent to the monitor's clients as updates.
 * Of cause, the monitor should also internally update with this change.
 *
 * When a change type does not require client side update, the monitor
 * may still need to keep track of certain changes in order to generate
 * correct future updates.  For example, the monitor internal state should
 * be updated whenever a new row is inserted, in order to generate the
 * correct initial state, regardless if a insert change type is being
 * monitored.
 *
 * On the other hand, if a transaction only contains changes to columns
 * that are not monitored, this transaction can be safely ignored by the
 * monitor.
 *
 * Thus, the order of the declaration is important:
 * 'OVSDB_CHANGES_REQUIRE_EXTERNAL_UPDATE' always implies
 * 'OVSDB_CHANGES_REQUIRE_INTERNAL_UPDATE', but not vice versa.  */
enum ovsdb_monitor_changes_efficacy {
    OVSDB_CHANGES_NO_EFFECT,                /* Monitor does not care about this
                                               change.  */
    OVSDB_CHANGES_REQUIRE_INTERNAL_UPDATE,  /* Monitor internal updates. */
    OVSDB_CHANGES_REQUIRE_EXTERNAL_UPDATE,  /* Client needs to be updated.  */
};

struct ovsdb_monitor_aux {
    const struct ovsdb_monitor *monitor;
    struct ovsdb_monitor_table *mt;
    enum ovsdb_monitor_changes_efficacy efficacy;
};

static void
ovsdb_monitor_init_aux(struct ovsdb_monitor_aux *aux,
                       const struct ovsdb_monitor *m)
{
    aux->monitor = m;
    aux->mt = NULL;
    aux->efficacy = OVSDB_CHANGES_NO_EFFECT;
}

static void
ovsdb_monitor_changes_update(const struct ovsdb_row *old,
                             const struct ovsdb_row *new,
                             const struct ovsdb_monitor_table *mt,
                             struct ovsdb_monitor_changes *changes)
{
    const struct uuid *uuid = ovsdb_row_get_uuid(new ? new : old);
    struct ovsdb_monitor_row *change;

    change = ovsdb_monitor_changes_row_find(changes, uuid);
    if (!change) {
        change = xzalloc(sizeof *change);
        hmap_insert(&changes->rows, &change->hmap_node, uuid_hash(uuid));
        change->uuid = *uuid;
        change->old = clone_monitor_row_data(mt, old);
        change->new = clone_monitor_row_data(mt, new);
    } else {
        if (new) {
            update_monitor_row_data(mt, new, change->new);
        } else {
            free_monitor_row_data(mt, change->new);
            change->new = NULL;

            if (!change->old) {
                /* This row was added then deleted.  Forget about it. */
                hmap_remove(&changes->rows, &change->hmap_node);
                free(change);
            }
        }
    }
}

static bool
ovsdb_monitor_columns_changed(const struct ovsdb_monitor_table *mt,
                              const unsigned long int *changed)
{
    size_t i;

    for (i = 0; i < mt->n_columns; i++) {
        size_t column_index = mt->columns[i].column->index;

        if (bitmap_is_set(changed, column_index)) {
            return true;
        }
    }

    return false;
}

/* Return the efficacy of a row's change to a monitor table.
 *
 * Please see the block comment above 'ovsdb_monitor_changes_efficacy'
 * definition form more information.  */
static enum ovsdb_monitor_changes_efficacy
ovsdb_monitor_changes_classify(enum ovsdb_monitor_selection type,
                               const struct ovsdb_monitor_table *mt,
                               const unsigned long int *changed)
{
    if (type == OJMS_MODIFY &&
        !ovsdb_monitor_columns_changed(mt, changed)) {
        return OVSDB_CHANGES_NO_EFFECT;
    }

    return (mt->select & type)
                ?  OVSDB_CHANGES_REQUIRE_EXTERNAL_UPDATE
                :  OVSDB_CHANGES_REQUIRE_INTERNAL_UPDATE;
}

static bool
ovsdb_monitor_change_cb(const struct ovsdb_row *old,
                        const struct ovsdb_row *new,
                        const unsigned long int *changed,
                        void *aux_)
{
    struct ovsdb_monitor_aux *aux = aux_;
    const struct ovsdb_monitor *m = aux->monitor;
    struct ovsdb_table *table = new ? new->table : old->table;
    struct ovsdb_monitor_table *mt;
    struct ovsdb_monitor_changes *changes;

    if (!aux->mt || table != aux->mt->table) {
        aux->mt = shash_find_data(&m->tables, table->schema->name);
        if (!aux->mt) {
            /* We don't care about rows in this table at all.  Tell the caller
             * to skip it.  */
            return false;
        }
    }
    mt = aux->mt;

    HMAP_FOR_EACH(changes, hmap_node, &mt->changes) {
        enum ovsdb_monitor_changes_efficacy efficacy;
        enum ovsdb_monitor_selection type;

        type = ovsdb_monitor_row_update_type(false, old, new);
        efficacy = ovsdb_monitor_changes_classify(type, mt, changed);
        if (efficacy > OVSDB_CHANGES_NO_EFFECT) {
            ovsdb_monitor_changes_update(old, new, mt, changes);
        }

        if (aux->efficacy < efficacy) {
            aux->efficacy = efficacy;
        }
    }

    return true;
}

void
ovsdb_monitor_get_initial(const struct ovsdb_monitor *dbmon)
{
    struct ovsdb_monitor_aux aux;
    struct shash_node *node;

    ovsdb_monitor_init_aux(&aux, dbmon);
    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;

        if (mt->select & OJMS_INITIAL) {
            struct ovsdb_row *row;
            struct ovsdb_monitor_changes *changes;

            changes = ovsdb_monitor_table_find_changes(mt, 0);
            if (!changes) {
                changes = ovsdb_monitor_table_add_changes(mt, 0);
                HMAP_FOR_EACH (row, hmap_node, &mt->table->rows) {
                    ovsdb_monitor_changes_update(NULL, row, mt, changes);
                }
            } else {
                changes->n_refs++;
            }
        }
    }
}

void
ovsdb_monitor_remove_jsonrpc_monitor(struct ovsdb_monitor *dbmon,
                   struct ovsdb_jsonrpc_monitor *jsonrpc_monitor,
                   uint64_t unflushed)
{
    struct jsonrpc_monitor_node *jm;

    if (ovs_list_is_empty(&dbmon->jsonrpc_monitors)) {
        ovsdb_monitor_destroy(dbmon);
        return;
    }

    /* Find and remove the jsonrpc monitor from the list.  */
    LIST_FOR_EACH(jm, node, &dbmon->jsonrpc_monitors) {
        if (jm->jsonrpc_monitor == jsonrpc_monitor) {
            /* Release the tracked changes. */
            struct shash_node *node;
            SHASH_FOR_EACH (node, &dbmon->tables) {
                struct ovsdb_monitor_table *mt = node->data;
                ovsdb_monitor_table_untrack_changes(mt, unflushed);
            }
            ovs_list_remove(&jm->node);
            free(jm);

            /* Destroy ovsdb monitor if this is the last user.  */
            if (ovs_list_is_empty(&dbmon->jsonrpc_monitors)) {
                ovsdb_monitor_destroy(dbmon);
            }

            return;
        };
    }

    /* Should never reach here. jsonrpc_monitor should be on the list.  */
    OVS_NOT_REACHED();
}

static bool
ovsdb_monitor_table_equal(const struct ovsdb_monitor_table *a,
                          const struct ovsdb_monitor_table *b)
{
    size_t i;

    if ((a->table != b->table) ||
        (a->select != b->select) ||
        (a->n_columns != b->n_columns)) {
        return false;
    }

    for (i = 0; i < a->n_columns; i++) {
        if ((a->columns[i].column != b->columns[i].column) ||
            (a->columns[i].select != b->columns[i].select)) {
            return false;
        }
    }

    return true;
}

static bool
ovsdb_monitor_equal(const struct ovsdb_monitor *a,
                    const struct ovsdb_monitor *b)
{
    struct shash_node *node;

    if (shash_count(&a->tables) != shash_count(&b->tables)) {
        return false;
    }

    SHASH_FOR_EACH(node, &a->tables) {
        const struct ovsdb_monitor_table *mta = node->data;
        const struct ovsdb_monitor_table *mtb;

        mtb = shash_find_data(&b->tables, node->name);
        if (!mtb) {
            return false;
        }

        if (!ovsdb_monitor_table_equal(mta, mtb)) {
            return false;
        }
    }

    return true;
}

static size_t
ovsdb_monitor_hash(const struct ovsdb_monitor *dbmon, size_t basis)
{
    const struct shash_node **nodes;
    size_t i, j, n;

    nodes = shash_sort(&dbmon->tables);
    n = shash_count(&dbmon->tables);

    for (i = 0; i < n; i++) {
        struct ovsdb_monitor_table *mt = nodes[i]->data;

        basis = hash_pointer(mt->table, basis);
        basis = hash_3words(mt->select, mt->n_columns, basis);

        for (j = 0; j < mt->n_columns; j++) {
            basis = hash_pointer(mt->columns[j].column, basis);
            basis = hash_2words(mt->columns[j].select, basis);
        }
    }
    free(nodes);

    return basis;
}

struct ovsdb_monitor *
ovsdb_monitor_add(struct ovsdb_monitor *new_dbmon)
{
    struct ovsdb_monitor *dbmon;
    size_t hash;

    /* New_dbmon should be associated with only one jsonrpc
     * connections.  */
    ovs_assert(ovs_list_is_singleton(&new_dbmon->jsonrpc_monitors));

    hash = ovsdb_monitor_hash(new_dbmon, 0);
    HMAP_FOR_EACH_WITH_HASH(dbmon, hmap_node, hash, &ovsdb_monitors) {
        if (ovsdb_monitor_equal(dbmon,  new_dbmon)) {
            return dbmon;
        }
    }

    hmap_insert(&ovsdb_monitors, &new_dbmon->hmap_node, hash);
    return new_dbmon;
}

static void
ovsdb_monitor_destroy(struct ovsdb_monitor *dbmon)
{
    struct shash_node *node;

    ovs_list_remove(&dbmon->replica.node);

    if (!hmap_node_is_null(&dbmon->hmap_node)) {
        hmap_remove(&ovsdb_monitors, &dbmon->hmap_node);
    }

    ovsdb_monitor_json_cache_flush(dbmon);
    hmap_destroy(&dbmon->json_cache);

    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;
        struct ovsdb_monitor_changes *changes, *next;

        HMAP_FOR_EACH_SAFE (changes, next, hmap_node, &mt->changes) {
            hmap_remove(&mt->changes, &changes->hmap_node);
            ovsdb_monitor_changes_destroy(changes);
        }
        hmap_destroy(&mt->changes);
        free(mt->columns);
        free(mt);
    }
    shash_destroy(&dbmon->tables);
    free(dbmon);
}

static struct ovsdb_error *
ovsdb_monitor_commit(struct ovsdb_replica *replica,
                     const struct ovsdb_txn *txn,
                     bool durable OVS_UNUSED)
{
    struct ovsdb_monitor *m = ovsdb_monitor_cast(replica);
    struct ovsdb_monitor_aux aux;

    ovsdb_monitor_init_aux(&aux, m);
    /* Update ovsdb_monitor's transaction number for
     * each transaction, before calling ovsdb_monitor_change_cb().  */
    m->n_transactions++;
    ovsdb_txn_for_each_change(txn, ovsdb_monitor_change_cb, &aux);

    switch(aux.efficacy) {
    case OVSDB_CHANGES_NO_EFFECT:
        /* The transaction is ignored by the monitor.
         * Roll back the 'n_transactions' as if the transaction
         * has never happened. */
        m->n_transactions--;
        break;
    case OVSDB_CHANGES_REQUIRE_INTERNAL_UPDATE:
        /* Nothing.  */
        break;
    case  OVSDB_CHANGES_REQUIRE_EXTERNAL_UPDATE:
        ovsdb_monitor_json_cache_flush(m);
        break;
    }

    return NULL;
}

static void
ovsdb_monitor_destroy_callback(struct ovsdb_replica *replica)
{
    struct ovsdb_monitor *dbmon = ovsdb_monitor_cast(replica);
    struct jsonrpc_monitor_node *jm, *next;

    /* Delete all front end monitors. Removing the last front
     * end monitor will also destroy the corresponding 'ovsdb_monitor'.
     * ovsdb monitor will also be destroied.  */
    LIST_FOR_EACH_SAFE(jm, next, node, &dbmon->jsonrpc_monitors) {
        ovsdb_jsonrpc_monitor_destroy(jm->jsonrpc_monitor);
    }
}

/* Add some memory usage statics for monitors into 'usage', for use with
 * memory_report().  */
void
ovsdb_monitor_get_memory_usage(struct simap *usage)
{
    struct ovsdb_monitor *dbmon;
    simap_put(usage, "monitors", hmap_count(&ovsdb_monitors));

    HMAP_FOR_EACH(dbmon, hmap_node,  &ovsdb_monitors) {
        simap_increase(usage, "json-caches", hmap_count(&dbmon->json_cache));
    }
}

static const struct ovsdb_replica_class ovsdb_jsonrpc_replica_class = {
    ovsdb_monitor_commit,
    ovsdb_monitor_destroy_callback,
};
