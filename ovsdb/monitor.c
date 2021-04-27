/*
 * Copyright (c) 2015, 2017 Nicira, Inc.
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
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb.h"
#include "row.h"
#include "condition.h"
#include "simap.h"
#include "hash.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "jsonrpc-server.h"
#include "monitor.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_monitor);

static struct hmap ovsdb_monitors = HMAP_INITIALIZER(&ovsdb_monitors);

/* Keep state of session's conditions */
struct ovsdb_monitor_session_condition {
    bool conditional;        /* True iff every table's condition is true. */
    struct shash tables;     /* Contains
                              *   "struct ovsdb_monitor_table_condition *"s. */
};

/* Monitored table session's conditions */
struct ovsdb_monitor_table_condition {
    const struct ovsdb_table *table;
    struct ovsdb_monitor_table *mt;
    struct ovsdb_condition old_condition;
    struct ovsdb_condition new_condition;
};

/*  Backend monitor.
 *
 *  ovsdb_monitor keep track of the ovsdb changes.
 */

/* A collection of tables being monitored. */
struct ovsdb_monitor {
    struct ovs_list list_node;  /* In struct ovsdb's "monitors" list. */
    struct shash tables;     /* Holds "struct ovsdb_monitor_table"s. */
    struct ovs_list jsonrpc_monitors;  /* Contains "jsonrpc_monitor_node"s. */
    struct ovsdb *db;

    /* Contains "ovsdb_monitor_change_set". Each change set contains changes
     * from some start point up to the latest committed transaction. There can
     * be different change sets for the same struct ovsdb_monitor because there
     * are different clients pending on changes starting from different points.
     * The different change sets are maintained as a list. */
    struct ovs_list change_sets;

    /* The new change set that is to be populated for future transactions. */
    struct ovsdb_monitor_change_set *new_change_set;

    /* The change set that starts from the first transaction of the DB, which
     * is used for populating the initial data for new clients. */
    struct ovsdb_monitor_change_set *init_change_set;

    struct hmap_node hmap_node; /* Elements within ovsdb_monitors.  */
    struct hmap json_cache;     /* Contains "ovsdb_monitor_json_cache_node"s.*/
};

/* A json object of updates for the ovsdb_monitor_change_set and the given
 * monitor version. */
struct ovsdb_monitor_json_cache_node {
    struct hmap_node hmap_node;   /* Elements in json cache. */
    enum ovsdb_monitor_version version;
    struct uuid change_set_uuid;
    struct json *json;            /* Null, or a cloned of json */
};

struct jsonrpc_monitor_node {
    struct ovs_list node;
    struct ovsdb_jsonrpc_monitor *jsonrpc_monitor;
};

/* A particular column being monitored. */
struct ovsdb_monitor_column {
    const struct ovsdb_column *column;
    enum ovsdb_monitor_selection select;
    bool monitored;
};

/* A row that has changed in a monitored table. */
struct ovsdb_monitor_row {
    struct hmap_node hmap_node; /* In ovsdb_monitor_change_set_for_table. */
    struct uuid uuid;           /* UUID of row that changed. */
    struct ovsdb_datum *old;    /* Old data, NULL for an inserted row. */
    struct ovsdb_datum *new;    /* New data, NULL for a deleted row. */
};

/* Contains a set of changes that are not yet flushed to all the jsonrpc
 * connections.
 *
 * 'n_refs' represent the number of jsonrpc connections that depend on this
 * change set (have not received updates). Generate the update for the last
 * jsonprc connection will also destroy the whole "struct
 * ovsdb_monitor_change_set" object.
 */
struct ovsdb_monitor_change_set {
    /* Element in change_sets of ovsdb_monitor. */
    struct ovs_list list_node;

    /* Internally generated uuid that identifies this data structure. */
    struct uuid uuid;

    /* Contains struct ovsdb_monitor_change_set_for_table. */
    struct ovs_list change_set_for_tables;

    int n_refs;

    /* The previous txn id before this change set's start point. */
    struct uuid prev_txn;
};

/* Contains 'struct ovsdb_monitor_row's for rows in a specific table
 * of struct ovsdb_monitor_change_set. It can also be searched from
 * member 'change_sets' of struct ovsdb_monitor_table. */
struct ovsdb_monitor_change_set_for_table {
    /* Element in ovsdb_monitor_tables' change_sets list. */
    struct ovs_list list_in_mt;

    /* Element in ovsdb_monitor_change_sets' change_set_for_tables list. */
    struct ovs_list list_in_change_set;

    struct ovsdb_monitor_table *mt;
    struct ovsdb_monitor_change_set *mcs;

    /* Contains struct ovsdb_monitor_row. */
    struct hmap rows;

    /* Save the mt->n_columns that is used when creating the changes.
     * It can be different from the current mt->n_columns because
     * mt->n_columns can be increased when there are condition changes
     * from any of the clients sharing the dbmon. */
    size_t n_columns;
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
    size_t n_monitored_columns;
    size_t allocated_columns;

    /* Columns in ovsdb_monitor_row have different indexes then in
     * ovsdb_row. This field maps between column->index to the index in the
     * ovsdb_monitor_row. It is used for condition evaluation. */
    unsigned int *columns_index_map;

    /* Contains 'ovsdb_monitor_change_set_for_table'. */
    struct ovs_list change_sets;
};

enum ovsdb_monitor_row_type {
    OVSDB_ROW,
    OVSDB_MONITOR_ROW
};

typedef struct json *
(*compose_row_update_cb_func)
    (const struct ovsdb_monitor_table *mt,
     const struct ovsdb_monitor_session_condition * condition,
     enum ovsdb_monitor_row_type row_type,
     const void *,
     bool initial, unsigned long int *changed,
     size_t n_columns);

static void ovsdb_monitor_destroy(struct ovsdb_monitor *);
static struct ovsdb_monitor_change_set * ovsdb_monitor_add_change_set(
        struct ovsdb_monitor *, bool init_only, const struct uuid *prev_txn);
static struct ovsdb_monitor_change_set * ovsdb_monitor_find_change_set(
        const struct ovsdb_monitor *, const struct uuid *prev_txn);
static void ovsdb_monitor_change_set_destroy(
        struct ovsdb_monitor_change_set *);
static void ovsdb_monitor_track_new_change_set(struct ovsdb_monitor *);

static uint32_t
json_cache_hash(enum ovsdb_monitor_version version,
                struct ovsdb_monitor_change_set *change_set)
{
    return hash_uint64_basis(version, uuid_hash(&change_set->uuid));
}

static struct ovsdb_monitor_json_cache_node *
ovsdb_monitor_json_cache_search(const struct ovsdb_monitor *dbmon,
                                enum ovsdb_monitor_version version,
                                struct ovsdb_monitor_change_set *change_set)
{
    struct ovsdb_monitor_json_cache_node *node;
    uint32_t hash = json_cache_hash(version, change_set);

    HMAP_FOR_EACH_WITH_HASH(node, hmap_node, hash, &dbmon->json_cache) {
        if (uuid_equals(&node->change_set_uuid, &change_set->uuid) &&
            node->version == version) {
            return node;
        }
    }

    return NULL;
}

static void
ovsdb_monitor_json_cache_insert(struct ovsdb_monitor *dbmon,
                                enum ovsdb_monitor_version version,
                                struct ovsdb_monitor_change_set *change_set,
                                struct json *json)
{
    struct ovsdb_monitor_json_cache_node *node;
    uint32_t hash = json_cache_hash(version, change_set);

    node = xmalloc(sizeof *node);

    node->version = version;
    node->change_set_uuid = change_set->uuid;
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

/* Free all versions of json cache for a given change_set.*/
static void
ovsdb_monitor_json_cache_destroy(struct ovsdb_monitor *dbmon,
                                 struct ovsdb_monitor_change_set *change_set)
{
    enum ovsdb_monitor_version v;
    for (v = OVSDB_MONITOR_V1; v < OVSDB_MONITOR_VERSION_MAX; v++) {
        struct ovsdb_monitor_json_cache_node *node
            = ovsdb_monitor_json_cache_search(dbmon, v, change_set);
        if (node) {
            hmap_remove(&dbmon->json_cache, &node->hmap_node);
            json_destroy(node->json);
            free(node);
        }
    }
}

static int
compare_ovsdb_monitor_column(const void *a_, const void *b_)
{
    const struct ovsdb_monitor_column *a = a_;
    const struct ovsdb_monitor_column *b = b_;

    /* put all monitored columns at the begining */
    if (a->monitored != b->monitored) {
        return a->monitored ? -1 : 1;
    }

    return a->column < b->column ? -1 : a->column > b->column;
}

/* Finds and returns the ovsdb_monitor_row in 'mt->changes->rows' for the
 * given 'uuid', or NULL if there is no such row. */
static struct ovsdb_monitor_row *
ovsdb_monitor_changes_row_find(
        const struct ovsdb_monitor_change_set_for_table *changes,
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

/* Allocates an array of 'n_columns' ovsdb_datums and initializes them as
 * copies of the data in 'row' drawn from the columns represented by
 * mt->columns[].  Returns the array.
 *
 * If 'row' is NULL, returns NULL. */
static struct ovsdb_datum *
clone_monitor_row_data(const struct ovsdb_monitor_table *mt,
                       const struct ovsdb_row *row,
                       size_t n_columns)
{
    struct ovsdb_datum *data;
    size_t i;

    if (!row) {
        return NULL;
    }

    data = xmalloc(n_columns * sizeof *data);
    for (i = 0; i < n_columns; i++) {
        const struct ovsdb_column *c = mt->columns[i].column;
        const struct ovsdb_datum *src = &row->fields[c->index];
        struct ovsdb_datum *dst = &data[i];
        const struct ovsdb_type *type = &c->type;

        ovsdb_datum_clone(dst, src, type);
    }
    return data;
}

/* Replaces the n_columns ovsdb_datums in row[] by copies of the data from
 * in 'row' drawn from the columns represented by mt->columns[]. */
static void
update_monitor_row_data(const struct ovsdb_monitor_table *mt,
                        const struct ovsdb_row *row,
                        struct ovsdb_datum *data,
                        size_t n_columns)
{
    size_t i;

    for (i = 0; i < n_columns; i++) {
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

/* Frees all of the n_columns ovsdb_datums in data[], using the types taken
 * from mt->columns[], plus 'data' itself. */
static void
free_monitor_row_data(const struct ovsdb_monitor_table *mt,
                      struct ovsdb_datum *data,
                      size_t n_columns)
{
    if (data) {
        size_t i;

        for (i = 0; i < n_columns; i++) {
            const struct ovsdb_column *c = mt->columns[i].column;

            ovsdb_datum_destroy(&data[i], &c->type);
        }
        free(data);
    }
}

/* Frees 'row', which must have been created from 'mt'. */
static void
ovsdb_monitor_row_destroy(const struct ovsdb_monitor_table *mt,
                          struct ovsdb_monitor_row *row,
                          size_t n_columns)
{
    if (row) {
        free_monitor_row_data(mt, row->old, n_columns);
        free_monitor_row_data(mt, row->new, n_columns);
        free(row);
    }
}

static void
ovsdb_monitor_columns_sort(struct ovsdb_monitor *dbmon)
{
    int i;
    struct shash_node *node;

    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;

        qsort(mt->columns, mt->n_columns, sizeof *mt->columns,
              compare_ovsdb_monitor_column);
        for (i = 0; i < mt->n_columns; i++) {
            /* re-set index map due to sort */
            mt->columns_index_map[mt->columns[i].column->index] = i;
        }
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

    ovs_list_push_back(&db->monitors, &dbmon->list_node);
    ovs_list_init(&dbmon->jsonrpc_monitors);
    dbmon->db = db;
    ovs_list_init(&dbmon->change_sets);
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
    int i;
    size_t n_columns = shash_count(&table->schema->columns);

    mt = xzalloc(sizeof *mt);
    mt->table = table;
    shash_add(&m->tables, table->schema->name, mt);
    ovs_list_init(&mt->change_sets);
    mt->columns_index_map =
        xmalloc(sizeof *mt->columns_index_map * n_columns);
    for (i = 0; i < n_columns; i++) {
        mt->columns_index_map[i] = -1;
    }
}

const char *
ovsdb_monitor_add_column(struct ovsdb_monitor *dbmon,
                         const struct ovsdb_table *table,
                         const struct ovsdb_column *column,
                         enum ovsdb_monitor_selection select,
                         bool monitored)
{
    struct ovsdb_monitor_table *mt;
    struct ovsdb_monitor_column *c;

    mt = shash_find_data(&dbmon->tables, table->schema->name);

    /* Check for column duplication. Return duplicated column name. */
    if (mt->columns_index_map[column->index] != -1) {
        return column->name;
    }

    if (mt->n_columns >= mt->allocated_columns) {
        mt->columns = x2nrealloc(mt->columns, &mt->allocated_columns,
                                 sizeof *mt->columns);
    }

    mt->select |= select;
    mt->columns_index_map[column->index] = mt->n_columns;
    c = &mt->columns[mt->n_columns++];
    c->column = column;
    c->select = select;
    c->monitored = monitored;
    if (monitored) {
        mt->n_monitored_columns++;
    }

    return NULL;
}

static void
ovsdb_monitor_condition_add_columns(struct ovsdb_monitor *dbmon,
                                    const struct ovsdb_table *table,
                                    struct ovsdb_condition *condition)
{
    size_t n_columns;
    int i;
    const struct ovsdb_column **columns =
        ovsdb_condition_get_columns(condition, &n_columns);

    for (i = 0; i < n_columns; i++) {
        ovsdb_monitor_add_column(dbmon, table, columns[i],
                                 OJMS_NONE, false);
    }

    free(columns);
}

/* Bind this session's condition to ovsdb_monitor */
void
ovsdb_monitor_condition_bind(struct ovsdb_monitor *dbmon,
                          struct ovsdb_monitor_session_condition *cond)
{
    struct shash_node *node;

    SHASH_FOR_EACH(node, &cond->tables) {
        struct ovsdb_monitor_table_condition *mtc = node->data;
        struct ovsdb_monitor_table *mt =
            shash_find_data(&dbmon->tables, mtc->table->schema->name);

        mtc->mt = mt;
        ovsdb_monitor_condition_add_columns(dbmon, mtc->table,
                                            &mtc->new_condition);
    }
}

bool
ovsdb_monitor_table_exists(struct ovsdb_monitor *m,
                           const struct ovsdb_table *table)
{
    return shash_find_data(&m->tables, table->schema->name);
}

static struct ovsdb_monitor_change_set *
ovsdb_monitor_add_change_set(struct ovsdb_monitor *dbmon,
                             bool init_only, const struct uuid *prev_txn)
{
    struct ovsdb_monitor_change_set *change_set = xzalloc(sizeof *change_set);
    change_set->uuid = uuid_random();
    ovs_list_push_back(&(dbmon->change_sets), &change_set->list_node);
    ovs_list_init(&change_set->change_set_for_tables);
    change_set->n_refs = 1;
    change_set->prev_txn = prev_txn ? *prev_txn : UUID_ZERO;

    struct shash_node *node;
    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;
        if (!init_only || (mt->select & OJMS_INITIAL)) {
            struct ovsdb_monitor_change_set_for_table *mcst =
                xzalloc(sizeof *mcst);
            mcst->mt = mt;
            mcst->n_columns = mt->n_columns;
            mcst->mcs = change_set;
            hmap_init(&mcst->rows);
            ovs_list_push_back(&mt->change_sets, &mcst->list_in_mt);
            ovs_list_push_back(&change_set->change_set_for_tables,
                               &mcst->list_in_change_set);
        }
    }

    return change_set;
};

static struct ovsdb_monitor_change_set *
ovsdb_monitor_find_change_set(const struct ovsdb_monitor *dbmon,
                              const struct uuid *prev_txn)
{
    struct ovsdb_monitor_change_set *cs;
    LIST_FOR_EACH (cs, list_node, &dbmon->change_sets) {
        if (uuid_equals(&cs->prev_txn, prev_txn)) {
            /* Check n_columns for each table in dbmon, in case it is changed
             * after the change set is populated. */
            bool n_col_is_equal = true;
            struct ovsdb_monitor_change_set_for_table *mcst;
            LIST_FOR_EACH (mcst, list_in_change_set,
                           &cs->change_set_for_tables) {
                struct ovsdb_monitor_table *mt = mcst->mt;
                if (mt->n_columns != mcst->n_columns) {
                    n_col_is_equal = false;
                    break;
                }
            }
            if (n_col_is_equal) {
                return cs;
            }
        }
    }
    return NULL;
}

static void
ovsdb_monitor_untrack_change_set(struct ovsdb_monitor *dbmon,
                                 struct ovsdb_monitor_change_set *mcs)
{
    ovs_assert(mcs);
    if (--mcs->n_refs == 0) {
        if (mcs == dbmon->init_change_set) {
            dbmon->init_change_set = NULL;
        } else if (mcs == dbmon->new_change_set) {
            dbmon->new_change_set = NULL;
        }
        ovsdb_monitor_json_cache_destroy(dbmon, mcs);
        ovsdb_monitor_change_set_destroy(mcs);
    }
}

static void
ovsdb_monitor_track_new_change_set(struct ovsdb_monitor *dbmon)
{
    struct ovsdb_monitor_change_set *change_set = dbmon->new_change_set;

    if (change_set) {
        change_set->n_refs++;
    } else {
        change_set = ovsdb_monitor_add_change_set(dbmon, false,
                                 ovsdb_monitor_get_last_txnid(dbmon));
        dbmon->new_change_set = change_set;
    }
}

static void
ovsdb_monitor_change_set_destroy(struct ovsdb_monitor_change_set *mcs)
{
    ovs_list_remove(&mcs->list_node);

    struct ovsdb_monitor_change_set_for_table *mcst, *next_mcst;
    LIST_FOR_EACH_SAFE (mcst, next_mcst, list_in_change_set,
                        &mcs->change_set_for_tables) {
        ovs_list_remove(&mcst->list_in_change_set);
        ovs_list_remove(&mcst->list_in_mt);

        struct ovsdb_monitor_row *row, *next;
        HMAP_FOR_EACH_SAFE (row, next, hmap_node, &mcst->rows) {
            hmap_remove(&mcst->rows, &row->hmap_node);
            ovsdb_monitor_row_destroy(mcst->mt, row, mcst->n_columns);
        }
        hmap_destroy(&mcst->rows);

        free(mcst);
    }
    free(mcs);
}

static enum ovsdb_monitor_selection
ovsdb_monitor_row_update_type(bool initial, const bool old, const bool new)
{
    return initial ? OJMS_INITIAL
            : !old ? OJMS_INSERT
            : !new ? OJMS_DELETE
            : OJMS_MODIFY;
}

/* Set conditional monitoring mode only if we have non-empty condition in one
 * of the tables at least */
static inline void
ovsdb_monitor_session_condition_set_mode(
                                  struct ovsdb_monitor_session_condition *cond)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &cond->tables) {
        struct ovsdb_monitor_table_condition *mtc = node->data;

        if (!ovsdb_condition_is_true(&mtc->new_condition)) {
            cond->conditional = true;
            return;
        }
    }
    cond->conditional = false;
}

/* Returnes an empty allocated session's condition state holder */
struct ovsdb_monitor_session_condition *
ovsdb_monitor_session_condition_create(void)
{
    struct ovsdb_monitor_session_condition *condition =
        xzalloc(sizeof *condition);

    condition->conditional = false;
    shash_init(&condition->tables);
    return condition;
}

void
ovsdb_monitor_session_condition_destroy(
                           struct ovsdb_monitor_session_condition *condition)
{
    struct shash_node *node, *next;

    if (!condition) {
        return;
    }

    SHASH_FOR_EACH_SAFE (node, next, &condition->tables) {
        struct ovsdb_monitor_table_condition *mtc = node->data;

        ovsdb_condition_destroy(&mtc->new_condition);
        ovsdb_condition_destroy(&mtc->old_condition);
        shash_delete(&condition->tables, node);
        free(mtc);
    }
    shash_destroy(&condition->tables);
    free(condition);
}

struct ovsdb_error *
ovsdb_monitor_table_condition_create(
                         struct ovsdb_monitor_session_condition *condition,
                         const struct ovsdb_table *table,
                         const struct json *json_cnd)
{
    struct ovsdb_monitor_table_condition *mtc;
    struct ovsdb_error *error;

    mtc = xzalloc(sizeof *mtc);
    mtc->table = table;
    ovsdb_condition_init(&mtc->old_condition);
    ovsdb_condition_init(&mtc->new_condition);

    if (json_cnd) {
        error = ovsdb_condition_from_json(table->schema,
                                          json_cnd,
                                          NULL,
                                          &mtc->old_condition);
        if (error) {
            free(mtc);
            return error;
        }
    }

    shash_add(&condition->tables, table->schema->name, mtc);
    /* On session startup old == new condition */
    ovsdb_condition_clone(&mtc->new_condition, &mtc->old_condition);
    ovsdb_monitor_session_condition_set_mode(condition);

    return NULL;
}

static bool
ovsdb_monitor_get_table_conditions(
                      const struct ovsdb_monitor_table *mt,
                      const struct ovsdb_monitor_session_condition *condition,
                      struct ovsdb_condition **old_condition,
                      struct ovsdb_condition **new_condition)
{
    if (!condition) {
        return false;
    }

    struct ovsdb_monitor_table_condition *mtc =
        shash_find_data(&condition->tables, mt->table->schema->name);

    if (!mtc) {
        return false;
    }
    *old_condition = &mtc->old_condition;
    *new_condition = &mtc->new_condition;

    return true;
}

struct ovsdb_error *
ovsdb_monitor_table_condition_update(
                            struct ovsdb_monitor *dbmon,
                            struct ovsdb_monitor_session_condition *condition,
                            const struct ovsdb_table *table,
                            const struct json *cond_json)
{
    if (!condition) {
        return NULL;
    }

    struct ovsdb_monitor_table_condition *mtc =
        shash_find_data(&condition->tables, table->schema->name);
    struct ovsdb_error *error;
    struct ovsdb_condition cond = OVSDB_CONDITION_INITIALIZER(&cond);

    error = ovsdb_condition_from_json(table->schema, cond_json,
                                      NULL, &cond);
    if (error) {
        return error;
    }
    ovsdb_condition_destroy(&mtc->new_condition);
    ovsdb_condition_clone(&mtc->new_condition, &cond);
    ovsdb_condition_destroy(&cond);
    ovsdb_monitor_condition_add_columns(dbmon,
                                        table,
                                        &mtc->new_condition);

    return NULL;
}

static void
ovsdb_monitor_table_condition_updated(struct ovsdb_monitor_table *mt,
                    struct ovsdb_monitor_session_condition *condition)
{
    struct ovsdb_monitor_table_condition *mtc =
        shash_find_data(&condition->tables, mt->table->schema->name);

    if (mtc) {
        /* If conditional monitoring - set old condition to new condition */
        if (ovsdb_condition_cmp_3way(&mtc->old_condition,
                                     &mtc->new_condition)) {
            ovsdb_condition_destroy(&mtc->old_condition);
            ovsdb_condition_clone(&mtc->old_condition, &mtc->new_condition);
            ovsdb_monitor_session_condition_set_mode(condition);
        }
    }
}

static enum ovsdb_monitor_selection
ovsdb_monitor_row_update_type_condition(
                      const struct ovsdb_monitor_table *mt,
                      const struct ovsdb_monitor_session_condition *condition,
                      bool initial,
                      enum ovsdb_monitor_row_type row_type,
                      const struct ovsdb_datum *old,
                      const struct ovsdb_datum *new)
{
    struct ovsdb_condition *old_condition, *new_condition;
    enum ovsdb_monitor_selection type =
        ovsdb_monitor_row_update_type(initial, old, new);

    if (ovsdb_monitor_get_table_conditions(mt,
                                           condition,
                                           &old_condition,
                                           &new_condition)) {
        bool old_cond = !old ? false
            : ovsdb_condition_empty_or_match_any(old,
                                                old_condition,
                                                row_type == OVSDB_MONITOR_ROW ?
                                                mt->columns_index_map :
                                                NULL);
        bool new_cond = !new ? false
            : ovsdb_condition_empty_or_match_any(new,
                                                new_condition,
                                                row_type == OVSDB_MONITOR_ROW ?
                                                mt->columns_index_map :
                                                NULL);

        if (!old_cond && !new_cond) {
            type = OJMS_NONE;
        }

        switch (type) {
        case OJMS_INITIAL:
        case OJMS_INSERT:
            if (!new_cond) {
                type = OJMS_NONE;
            }
            break;
        case OJMS_MODIFY:
            type = !old_cond ? OJMS_INSERT : !new_cond
                ? OJMS_DELETE : OJMS_MODIFY;
            break;
        case OJMS_DELETE:
            if (!old_cond) {
                type = OJMS_NONE;
            }
            break;
        case OJMS_NONE:
            break;
        }
    }
    return type;
}

static bool
ovsdb_monitor_row_skip_update(const struct ovsdb_monitor_table *mt,
                              enum ovsdb_monitor_row_type row_type,
                              const struct ovsdb_datum *old,
                              const struct ovsdb_datum *new,
                              enum ovsdb_monitor_selection type,
                              unsigned long int *changed,
                              size_t n_columns)
{
    if (!(mt->select & type)) {
        return true;
    }

    if (type == OJMS_MODIFY) {
        size_t i, n_changes;

        n_changes = 0;
        memset(changed, 0, bitmap_n_bytes(n_columns));
        for (i = 0; i < n_columns; i++) {
            const struct ovsdb_column *c = mt->columns[i].column;
            size_t index = row_type == OVSDB_ROW ? c->index : i;
            if (!ovsdb_datum_equals(&old[index], &new[index], &c->type)) {
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
 * bitmap_n_bytes(n_columns) bytes long. */
static struct json *
ovsdb_monitor_compose_row_update(
    const struct ovsdb_monitor_table *mt,
    const struct ovsdb_monitor_session_condition *condition OVS_UNUSED,
    enum ovsdb_monitor_row_type row_type OVS_UNUSED,
    const void *_row,
    bool initial, unsigned long int *changed,
    size_t n_columns OVS_UNUSED)
{
    const struct ovsdb_monitor_row *row = _row;
    enum ovsdb_monitor_selection type;
    struct json *old_json, *new_json;
    struct json *row_json;
    size_t i;

    ovs_assert(row_type == OVSDB_MONITOR_ROW);
    type = ovsdb_monitor_row_update_type(initial, row->old, row->new);
    if (ovsdb_monitor_row_skip_update(mt, row_type, row->old,
                                      row->new, type, changed,
                                      mt->n_columns)) {
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
    for (i = 0; i < mt->n_monitored_columns; i++) {
        const struct ovsdb_monitor_column *c = &mt->columns[i];

        if (!c->monitored || !(type & c->select))  {
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
 * going to be used as part of the initial reply to a "monitor_cond" request,
 * false if it is going to be used as part of an "update2" notification.
 *
 * 'changed' must be a scratch buffer for internal use that is at least
 * bitmap_n_bytes(n_columns) bytes long. */
static struct json *
ovsdb_monitor_compose_row_update2(
    const struct ovsdb_monitor_table *mt,
    const struct ovsdb_monitor_session_condition *condition,
    enum ovsdb_monitor_row_type row_type,
    const void *_row,
    bool initial, unsigned long int *changed,
    size_t n_columns)
{
    enum ovsdb_monitor_selection type;
    struct json *row_update2, *diff_json;
    const struct ovsdb_datum *old, *new;
    size_t i;

    if (row_type == OVSDB_MONITOR_ROW) {
        old = ((const struct ovsdb_monitor_row *)_row)->old;;
        new = ((const struct ovsdb_monitor_row *)_row)->new;
    } else {
        old = new = ((const struct ovsdb_row *)_row)->fields;
    }

    type = ovsdb_monitor_row_update_type_condition(mt, condition, initial,
                                                   row_type, old, new);
    if (ovsdb_monitor_row_skip_update(mt, row_type, old, new, type, changed,
                                      n_columns)) {
        return NULL;
    }

    row_update2 = json_object_create();
    if (type == OJMS_DELETE) {
        json_object_put(row_update2, "delete", json_null_create());
    } else {
        diff_json = json_object_create();
        const char *op;

        for (i = 0; i < mt->n_monitored_columns; i++) {
            const struct ovsdb_monitor_column *c = &mt->columns[i];
            size_t index = row_type == OVSDB_ROW ? c->column->index : i;
            if (!c->monitored || !(type & c->select))  {
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

                ovsdb_datum_diff(&diff ,&old[index], &new[index],
                                        &c->column->type);
                json_object_put(diff_json, c->column->name,
                                ovsdb_datum_to_json(&diff, &c->column->type));
                ovsdb_datum_destroy(&diff, &c->column->type);
            } else {
                if (!ovsdb_datum_is_default(&new[index], &c->column->type)) {
                    json_object_put(diff_json, c->column->name,
                                    ovsdb_datum_to_json(&new[index],
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

static void
ovsdb_monitor_add_json_row(struct json **json, const char *table_name,
                           struct json **table_json, struct json *row_json,
                           const struct uuid *row_uuid)
{
    char uuid[UUID_LEN + 1];

    /* Create JSON object for transaction overall. */
    if (!*json) {
        *json = json_object_create();
    }

    /* Create JSON object for transaction on this table. */
    if (!*table_json) {
        *table_json = json_object_create();
        json_object_put(*json, table_name, *table_json);
    }

    /* Add JSON row to JSON table. */
    snprintf(uuid, sizeof uuid, UUID_FMT, UUID_ARGS(row_uuid));
    json_object_put(*table_json, uuid, row_json);
}

/* Constructs and returns JSON for a <table-updates> object (as described in
 * RFC 7047) for all the outstanding changes within 'monitor', starting from
 * 'transaction'.  */
static struct json*
ovsdb_monitor_compose_update(
                      struct ovsdb_monitor *dbmon,
                      bool initial, struct ovsdb_monitor_change_set *mcs,
                      const struct ovsdb_monitor_session_condition *condition,
                      compose_row_update_cb_func row_update)
{
    struct json *json;
    size_t max_columns = ovsdb_monitor_max_columns(dbmon);
    unsigned long int *changed = xmalloc(bitmap_n_bytes(max_columns));

    json = NULL;
    struct ovsdb_monitor_change_set_for_table *mcst;
    LIST_FOR_EACH (mcst, list_in_change_set, &mcs->change_set_for_tables) {
        struct ovsdb_monitor_row *row, *next;
        struct json *table_json = NULL;
        struct ovsdb_monitor_table *mt = mcst->mt;

        HMAP_FOR_EACH_SAFE (row, next, hmap_node, &mcst->rows) {
            struct json *row_json;
            row_json = (*row_update)(mt, condition, OVSDB_MONITOR_ROW, row,
                                     initial, changed, mcst->n_columns);
            if (row_json) {
                ovsdb_monitor_add_json_row(&json, mt->table->schema->name,
                                           &table_json, row_json,
                                           &row->uuid);
            }
        }
    }
    free(changed);

    return json;
}

static struct json*
ovsdb_monitor_compose_cond_change_update(
                    struct ovsdb_monitor *dbmon,
                    struct ovsdb_monitor_session_condition *condition)
{
    struct shash_node *node;
    struct json *json = NULL;
    size_t max_columns = ovsdb_monitor_max_columns(dbmon);
    unsigned long int *changed = xmalloc(bitmap_n_bytes(max_columns));

    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;
        struct ovsdb_row *row;
        struct json *table_json = NULL;
        struct ovsdb_condition *old_condition, *new_condition;

        if (!ovsdb_monitor_get_table_conditions(mt,
                                                condition,
                                                &old_condition,
                                                &new_condition) ||
            !ovsdb_condition_cmp_3way(old_condition, new_condition)) {
            /* Nothing to update on this table */
            continue;
        }

        /* Iterate over all rows in table */
        HMAP_FOR_EACH (row, hmap_node, &mt->table->rows) {
            struct json *row_json;

            row_json = ovsdb_monitor_compose_row_update2(mt, condition,
                                                         OVSDB_ROW, row,
                                                         false, changed,
                                                         mt->n_columns);
            if (row_json) {
                ovsdb_monitor_add_json_row(&json, mt->table->schema->name,
                                           &table_json, row_json,
                                           ovsdb_row_get_uuid(row));
            }
        }
        ovsdb_monitor_table_condition_updated(mt, condition);
    }
    free(changed);

    return json;
}

/* Returns JSON for a <table-updates> object (as described in RFC 7047)
 * for all the outstanding changes in dbmon that are tracked by the change set
 * *p_mcs.
 *
 * If cond_updated is true all rows in the db that match conditions will be
 * sent.
 *
 * The caller should specify 'initial' as true if the returned JSON is going to
 * be used as part of the initial reply to a "monitor" request, false if it is
 * going to be used as part of an "update" notification. */
struct json *
ovsdb_monitor_get_update(
             struct ovsdb_monitor *dbmon,
             bool initial, bool cond_updated,
             struct ovsdb_monitor_session_condition *condition,
             enum ovsdb_monitor_version version,
             struct ovsdb_monitor_change_set **p_mcs)
{
    struct ovsdb_monitor_json_cache_node *cache_node = NULL;
    struct json *json;
    struct ovsdb_monitor_change_set *mcs = *p_mcs;

    ovs_assert(cond_updated ? mcs == dbmon->new_change_set : true);

    /* Return a clone of cached json if one exists. Otherwise,
     * generate a new one and add it to the cache.  */
    if (!condition || (!condition->conditional && !cond_updated)) {
        cache_node = ovsdb_monitor_json_cache_search(dbmon, version,
                                                     mcs);
    }
    if (cache_node) {
        json = cache_node->json ? json_clone(cache_node->json) : NULL;
    } else {
        if (version == OVSDB_MONITOR_V1) {
            json =
               ovsdb_monitor_compose_update(dbmon, initial, mcs,
                                            condition,
                                            ovsdb_monitor_compose_row_update);
        } else {
            ovs_assert(version == OVSDB_MONITOR_V2 ||
                       version == OVSDB_MONITOR_V3);

            if (!cond_updated) {
                json = ovsdb_monitor_compose_update(dbmon, initial, mcs,
                                            condition,
                                            ovsdb_monitor_compose_row_update2);
                if (!condition || !condition->conditional) {
                    ovsdb_monitor_json_cache_insert(dbmon, version, mcs,
                                                    json);
                }
            } else {
                /* Compose update on whole db due to condition update.
                   Session must be flushed (change list is empty)*/
                json =
                    ovsdb_monitor_compose_cond_change_update(dbmon, condition);
            }
        }
    }

    /* Maintain tracking change set. */
    ovsdb_monitor_untrack_change_set(dbmon, mcs);
    ovsdb_monitor_track_new_change_set(dbmon);
    *p_mcs = dbmon->new_change_set;

    return json;
}

bool
ovsdb_monitor_needs_flush(struct ovsdb_monitor *dbmon,
                          struct ovsdb_monitor_change_set *change_set)
{
    ovs_assert(change_set);
    return (change_set != dbmon->new_change_set);
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
                             struct ovsdb_monitor_change_set_for_table *mcst)
{
    const struct uuid *uuid = ovsdb_row_get_uuid(new ? new : old);
    struct ovsdb_monitor_row *change;

    change = ovsdb_monitor_changes_row_find(mcst, uuid);
    if (!change) {
        change = xzalloc(sizeof *change);
        hmap_insert(&mcst->rows, &change->hmap_node, uuid_hash(uuid));
        change->uuid = *uuid;
        change->old = clone_monitor_row_data(mt, old, mcst->n_columns);
        change->new = clone_monitor_row_data(mt, new, mcst->n_columns);
    } else {
        if (new) {
            if (!change->new) {
                /* Reinsert the row that was just deleted.
                 *
                 * This path won't be hit without replication.  Whenever OVSDB
                 * server inserts a new row, It always generates a new UUID
                 * that is different from the row just deleted.
                 *
                 * With replication, this path can be hit in a corner
                 * case when two OVSDB servers are set up to replicate
                 * each other. Not that is a useful set up, but can
                 * happen in practice.
                 *
                 * An example of how this path can be hit is documented below.
                 * The details is not as important to the correctness of the
                 * logic, but added here to convince ourselves that this path
                 * can be hit.
                 *
                 * Imagine two OVSDB servers that replicates from each
                 * other. For each replication session, there is a
                 * corresponding monitor at the other end of the replication
                 * JSONRPC connection.
                 *
                 * The events can lead to a back to back deletion and
                 * insertion operation of the same row for the monitor of
                 * the first server are:
                 *
                 * 1. A row is inserted in the first OVSDB server.
                 * 2. The row is then replicated to the remote OVSDB server.
                 * 3. The row is now  deleted by the local OVSDB server. This
                 *    deletion operation is replicated to the local monitor
                 *    of the OVSDB server.
                 * 4. The monitor now receives the same row, as an insertion,
                 *    from the replication server. Because of
                 *    replication, the row carries the same UUID as the row
                 *    just deleted.
                 */
                change->new = clone_monitor_row_data(mt, new, mcst->n_columns);
            } else {
                update_monitor_row_data(mt, new, change->new, mcst->n_columns);
            }
        } else {
            free_monitor_row_data(mt, change->new, mcst->n_columns);
            change->new = NULL;

            if (!change->old) {
                /* This row was added then deleted.  Forget about it. */
                hmap_remove(&mcst->rows, &change->hmap_node);
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

    if (type == OJMS_MODIFY) {
        /* Condition might turn a modify operation to insert or delete */
        type |= OJMS_INSERT | OJMS_DELETE;
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
    struct ovsdb_monitor_change_set_for_table *mcst;

    if (!aux->mt || table != aux->mt->table) {
        aux->mt = shash_find_data(&m->tables, table->schema->name);
        if (!aux->mt) {
            /* We don't care about rows in this table at all.  Tell the caller
             * to skip it.  */
            return false;
        }
    }
    mt = aux->mt;

    enum ovsdb_monitor_selection type =
        ovsdb_monitor_row_update_type(false, old, new);
    enum ovsdb_monitor_changes_efficacy efficacy =
        ovsdb_monitor_changes_classify(type, mt, changed);

    if (efficacy > OVSDB_CHANGES_NO_EFFECT) {
        LIST_FOR_EACH (mcst, list_in_mt, &mt->change_sets) {
            ovsdb_monitor_changes_update(old, new, mt, mcst);
        }
    }
    if (aux->efficacy < efficacy) {
        aux->efficacy = efficacy;
    }

    return true;
}

void
ovsdb_monitor_get_initial(struct ovsdb_monitor *dbmon,
                          struct ovsdb_monitor_change_set **p_mcs)
{
    if (!dbmon->init_change_set) {
        struct ovsdb_monitor_change_set *change_set =
            ovsdb_monitor_add_change_set(dbmon, true, NULL);
        dbmon->init_change_set = change_set;

        struct ovsdb_monitor_change_set_for_table *mcst;
        LIST_FOR_EACH (mcst, list_in_change_set,
                       &change_set->change_set_for_tables) {
            if (mcst->mt->select & OJMS_INITIAL) {
                struct ovsdb_row *row;
                HMAP_FOR_EACH (row, hmap_node, &mcst->mt->table->rows) {
                    ovsdb_monitor_changes_update(NULL, row, mcst->mt, mcst);
                }
            }
        }
    } else {
        dbmon->init_change_set->n_refs++;
    }

    *p_mcs = dbmon->init_change_set;
}

static bool
ovsdb_monitor_history_change_cb(const struct ovsdb_row *old,
                        const struct ovsdb_row *new,
                        const unsigned long int *changed,
                        void *aux)
{
    struct ovsdb_monitor_change_set *change_set = aux;
    struct ovsdb_table *table = new ? new->table : old->table;
    struct ovsdb_monitor_change_set_for_table *mcst;

    enum ovsdb_monitor_selection type =
        ovsdb_monitor_row_update_type(false, old, new);
    LIST_FOR_EACH (mcst, list_in_change_set,
                   &change_set->change_set_for_tables) {
        if (mcst->mt->table == table) {
            enum ovsdb_monitor_changes_efficacy efficacy =
                ovsdb_monitor_changes_classify(type, mcst->mt, changed);
            if (efficacy > OVSDB_CHANGES_NO_EFFECT) {
                ovsdb_monitor_changes_update(old, new, mcst->mt, mcst);
            }
            return true;
        }
    }
    return false;
}

void
ovsdb_monitor_get_changes_after(const struct uuid *txn_uuid,
                                struct ovsdb_monitor *dbmon,
                                struct ovsdb_monitor_change_set **p_mcs)
{
    ovs_assert(*p_mcs == NULL);
    ovs_assert(!uuid_is_zero(txn_uuid));
    struct ovsdb_monitor_change_set *change_set =
        ovsdb_monitor_find_change_set(dbmon, txn_uuid);
    if (change_set) {
        change_set->n_refs++;
        *p_mcs = change_set;
        return;
    }

    struct ovsdb_txn_history_node *h_node;
    bool found = false;
    LIST_FOR_EACH (h_node, node, &dbmon->db->txn_history) {
        struct ovsdb_txn *txn = h_node->txn;
        if (!found) {
            /* find the txn with last_id in history */
            if (uuid_equals(ovsdb_txn_get_txnid(txn), txn_uuid)) {
                found = true;
                change_set = ovsdb_monitor_add_change_set(dbmon, false,
                                                          txn_uuid);
            }
        } else {
            /* Already found. Add changes in each follow up transaction to
             * the new change_set. */
            ovsdb_txn_for_each_change(txn, ovsdb_monitor_history_change_cb,
                                      change_set);
        }
    }
    *p_mcs = change_set;
}

void
ovsdb_monitor_remove_jsonrpc_monitor(struct ovsdb_monitor *dbmon,
                   struct ovsdb_jsonrpc_monitor *jsonrpc_monitor,
                   struct ovsdb_monitor_change_set *change_set)
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
            if (change_set) {
                ovsdb_monitor_untrack_change_set(dbmon, change_set);
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

    ovs_assert(b->n_columns == b->n_monitored_columns);

    if ((a->table != b->table) ||
        (a->select != b->select) ||
        (a->n_monitored_columns != b->n_monitored_columns)) {
        return false;
    }

    /* Compare only monitored columns that must be sorted already */
    for (i = 0; i < a->n_monitored_columns; i++) {
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

    ovsdb_monitor_columns_sort(new_dbmon);

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

    ovs_list_remove(&dbmon->list_node);

    if (!hmap_node_is_null(&dbmon->hmap_node)) {
        hmap_remove(&ovsdb_monitors, &dbmon->hmap_node);
    }

    ovsdb_monitor_json_cache_flush(dbmon);
    hmap_destroy(&dbmon->json_cache);

    struct ovsdb_monitor_change_set *cs, *cs_next;
    LIST_FOR_EACH_SAFE (cs, cs_next, list_node, &dbmon->change_sets) {
        ovsdb_monitor_change_set_destroy(cs);
    }

    SHASH_FOR_EACH (node, &dbmon->tables) {
        struct ovsdb_monitor_table *mt = node->data;
        ovs_assert(ovs_list_is_empty(&mt->change_sets));
        free(mt->columns);
        free(mt->columns_index_map);
        free(mt);
    }
    shash_destroy(&dbmon->tables);
    free(dbmon);
}

static void
ovsdb_monitor_commit(struct ovsdb_monitor *m, const struct ovsdb_txn *txn)
{
    struct ovsdb_monitor_aux aux;

    ovsdb_monitor_init_aux(&aux, m);
    ovsdb_txn_for_each_change(txn, ovsdb_monitor_change_cb, &aux);

    if (aux.efficacy > OVSDB_CHANGES_NO_EFFECT) {
        /* The transaction is has impact to the monitor.
         * Reset new_change_set, so that a new change set will be
         * created for future trackings. */
        m->new_change_set = NULL;

        if (aux.efficacy == OVSDB_CHANGES_REQUIRE_EXTERNAL_UPDATE) {
            ovsdb_monitor_json_cache_flush(m);
        }
    }
}

void
ovsdb_monitors_commit(struct ovsdb *db, const struct ovsdb_txn *txn)
{
    struct ovsdb_monitor *m;

    LIST_FOR_EACH (m, list_node, &db->monitors) {
        ovsdb_monitor_commit(m, txn);
    }
}

void
ovsdb_monitors_remove(struct ovsdb *db)
{
    struct ovsdb_monitor *m, *next_m;

    LIST_FOR_EACH_SAFE (m, next_m, list_node, &db->monitors) {
        struct jsonrpc_monitor_node *jm, *next_jm;

        /* Delete all front-end monitors.  Removing the last front-end monitor
         * will also destroy the corresponding ovsdb_monitor. */
        LIST_FOR_EACH_SAFE (jm, next_jm, node, &m->jsonrpc_monitors) {
            ovsdb_jsonrpc_monitor_destroy(jm->jsonrpc_monitor, false);
        }
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

void
ovsdb_monitor_prereplace_db(struct ovsdb *db)
{
    struct ovsdb_monitor *m, *next_m;

    LIST_FOR_EACH_SAFE (m, next_m, list_node, &db->monitors) {
        struct jsonrpc_monitor_node *jm, *next_jm;

        /* Delete all front-end monitors.  Removing the last front-end monitor
         * will also destroy the corresponding ovsdb_monitor. */
        LIST_FOR_EACH_SAFE (jm, next_jm, node, &m->jsonrpc_monitors) {
            ovsdb_jsonrpc_monitor_destroy(jm->jsonrpc_monitor, true);
        }
    }
}

const struct uuid *
ovsdb_monitor_get_last_txnid(struct ovsdb_monitor *dbmon) {
    static struct uuid dummy = { .parts = { 0, 0, 0, 0 } };
    if (dbmon->db->n_txn_history) {
        struct ovsdb_txn_history_node *thn = CONTAINER_OF(
                ovs_list_back(&dbmon->db->txn_history),
                struct ovsdb_txn_history_node, node);
        return ovsdb_txn_get_txnid(thn->txn);
    }
    return &dummy;
}
