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

#include "transaction.h"

#include <assert.h>

#include "hash.h"
#include "hmap.h"
#include "json.h"
#include "ovsdb-error.h"
#include "ovsdb.h"
#include "row.h"
#include "table.h"
#include "uuid.h"

struct ovsdb_txn {
    struct ovsdb *db;
    struct hmap txn_tables;     /* Contains "struct ovsdb_txn_table"s. */
};

/* A table modified by a transaction. */
struct ovsdb_txn_table {
    struct hmap_node hmap_node; /* Element in ovsdb_txn's txn_tables hmap. */
    struct ovsdb_table *table;
    struct hmap txn_rows;       /* Contains "struct ovsdb_txn_row"s. */
};

/* A row modified by the transaction:
 *
 *      - A row added by a transaction will have null 'old' and non-null 'new'.
 *
 *      - A row deleted by a transaction will have non-null 'old' and null
 *        'new'.
 *
 *      - A row modified by a transaction will have non-null 'old' and 'new'.
 *
 *      - 'old' and 'new' both null is invalid.  It would indicate that a row
 *        was added then deleted within a single transaction, but we instead
 *        handle that case by deleting the txn_row entirely.
 */
struct ovsdb_txn_row {
    struct hmap_node hmap_node; /* In ovsdb_txn_table's txn_rows hmap. */
    struct ovsdb_row *old;      /* The old row. */
    struct ovsdb_row *new;      /* The new row. */
};

static const struct uuid *
ovsdb_txn_row_get_uuid(const struct ovsdb_txn_row *txn_row)
{
    const struct ovsdb_row *row = txn_row->old ? txn_row->old : txn_row->new;
    return ovsdb_row_get_uuid(row);
}

struct ovsdb_txn *
ovsdb_txn_create(struct ovsdb *db)
{
    struct ovsdb_txn *txn = xmalloc(sizeof *txn);
    txn->db = db;
    hmap_init(&txn->txn_tables);
    return txn;
}

static void
ovsdb_txn_destroy(struct ovsdb_txn *txn, void (*cb)(struct ovsdb_txn_row *))
{
    struct ovsdb_txn_table *txn_table, *next_txn_table;

    HMAP_FOR_EACH_SAFE (txn_table, next_txn_table,
                        struct ovsdb_txn_table, hmap_node, &txn->txn_tables)
    {
        struct ovsdb_txn_row *txn_row, *next_txn_row;

        HMAP_FOR_EACH_SAFE (txn_row, next_txn_row,
                            struct ovsdb_txn_row, hmap_node,
                            &txn_table->txn_rows)
        {
            if (txn_row->new) {
                txn_row->new->txn_row = NULL;
            }
            cb(txn_row);
            free(txn_row);
        }

        hmap_destroy(&txn_table->txn_rows);
        free(txn_table);
    }
    hmap_destroy(&txn->txn_tables);
    free(txn);
}

static void
ovsdb_txn_row_abort(struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_row *old = txn_row->old;
    struct ovsdb_row *new = txn_row->new;

    if (!old) {
        hmap_remove(&new->table->rows, &new->hmap_node);
    } else if (!new) {
        hmap_insert(&old->table->rows, &old->hmap_node, ovsdb_row_hash(old));
    } else {
        hmap_replace(&new->table->rows, &new->hmap_node, &old->hmap_node);
    }
    ovsdb_row_destroy(new);
}

void
ovsdb_txn_abort(struct ovsdb_txn *txn)
{
    ovsdb_txn_destroy(txn, ovsdb_txn_row_abort);
}

static void
ovsdb_txn_row_commit(struct ovsdb_txn_row *txn_row)
{
    ovsdb_row_destroy(txn_row->old);
}

void
ovsdb_txn_commit(struct ovsdb_txn *txn)
{
    txn->db->run_triggers = true;
    ovsdb_txn_destroy(txn, ovsdb_txn_row_commit);
}

static void
put_json_column(struct json *object, const struct ovsdb_row *row,
                const struct ovsdb_column *column)
{
    json_object_put(object, column->name,
                    ovsdb_datum_to_json(&row->fields[column->index],
                                        &column->type));
}

static struct json *
ovsdb_txn_row_to_json(const struct ovsdb_txn_row *txn_row)
{
    const struct ovsdb_row *old = txn_row->old;
    const struct ovsdb_row *new = txn_row->new;
    struct shash_node *node;
    struct json *json;

    if (!new) {
        return json_null_create();
    }

    json = NULL;
    SHASH_FOR_EACH (node, &new->table->schema->columns) {
        struct ovsdb_column *column = node->data;
        unsigned int index = column->index;

        if (index != OVSDB_COL_UUID && column->persistent
            && (!old || !ovsdb_datum_equals(&old->fields[index],
                                            &new->fields[index],
                                            &column->type)))
        {
            if (!json) {
                json = json_object_create();
            }
            put_json_column(json, new, column);
        }
    }
    return json;
}

static struct json *
ovsdb_txn_table_to_json(const struct ovsdb_txn_table *txn_table)
{
    struct ovsdb_txn_row *txn_row;
    struct json *txn_table_json;

    txn_table_json = NULL;
    HMAP_FOR_EACH (txn_row, struct ovsdb_txn_row, hmap_node,
                   &txn_table->txn_rows) {
        struct json *txn_row_json = ovsdb_txn_row_to_json(txn_row);
        if (txn_row_json) {
            char uuid[UUID_LEN + 1];

            if (!txn_table_json) {
                txn_table_json = json_object_create();
            }

            snprintf(uuid, sizeof uuid,
                     UUID_FMT, UUID_ARGS(ovsdb_txn_row_get_uuid(txn_row)));
            json_object_put(txn_table_json, uuid, txn_row_json);
        }
    }
    return txn_table_json;
}

struct json *
ovsdb_txn_to_json(const struct ovsdb_txn *txn)
{
    struct ovsdb_txn_table *txn_table;
    struct json *txn_json;

    txn_json = NULL;
    HMAP_FOR_EACH (txn_table, struct ovsdb_txn_table, hmap_node,
                   &txn->txn_tables) {
        struct json *txn_table_json = ovsdb_txn_table_to_json(txn_table);
        if (!txn_json) {
            txn_json = json_object_create();
        }
        json_object_put(txn_json, txn_table->table->schema->name,
                        txn_table_json);
    }
    return txn_json;
}

static struct ovsdb_error *
ovsdb_txn_row_from_json(struct ovsdb_txn *txn, struct ovsdb_table *table,
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
ovsdb_txn_table_from_json(struct ovsdb_txn *txn, struct ovsdb_table *table,
                          struct json *json)
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

        error = ovsdb_txn_row_from_json(txn, table, &row_uuid, txn_row_json);
        if (error) {
            return error;
        }
    }

    return NULL;
}

struct ovsdb_error *
ovsdb_txn_from_json(struct ovsdb *db, const struct json *json,
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
            error = ovsdb_syntax_error(json, "unknown table",
                                       "No table named %s.", table_name);
            goto error;
        }

        error = ovsdb_txn_table_from_json(txn, table, txn_table_json);
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

static struct ovsdb_txn_table *
ovsdb_txn_get_txn_table__(struct ovsdb_txn *txn,
                          const struct ovsdb_table *table,
                          uint32_t hash)
{
    struct ovsdb_txn_table *txn_table;

    HMAP_FOR_EACH_IN_BUCKET (txn_table, struct ovsdb_txn_table, hmap_node,
                             hash, &txn->txn_tables) {
        if (txn_table->table == table) {
            return txn_table;
        }
    }

    return NULL;
}

static struct ovsdb_txn_table *
ovsdb_txn_get_txn_table(struct ovsdb_txn *txn, const struct ovsdb_table *table)
{
    return ovsdb_txn_get_txn_table__(txn, table, hash_pointer(table, 0));
}

static struct ovsdb_txn_table *
ovsdb_txn_create_txn_table(struct ovsdb_txn *txn,
                           struct ovsdb_table *table)
{
    uint32_t hash = hash_pointer(table, 0);
    struct ovsdb_txn_table *txn_table;

    txn_table = ovsdb_txn_get_txn_table__(txn, table, hash);
    if (!txn_table) {
        txn_table = xmalloc(sizeof *txn_table);
        txn_table->table = table;
        hmap_init(&txn_table->txn_rows);
        hmap_insert(&txn->txn_tables, &txn_table->hmap_node, hash);
    }
    return txn_table;
}

static struct ovsdb_txn_row *
ovsdb_txn_row_create(struct ovsdb_txn_table *txn_table,
                     const struct ovsdb_row *old, struct ovsdb_row *new)
{
    uint32_t hash = ovsdb_row_hash(old ? old : new);
    struct ovsdb_txn_row *txn_row;

    txn_row = xmalloc(sizeof *txn_row);
    txn_row->old = (struct ovsdb_row *) old;
    txn_row->new = new;
    hmap_insert(&txn_table->txn_rows, &txn_row->hmap_node, hash);

    return txn_row;
}

struct ovsdb_row *
ovsdb_txn_row_modify(struct ovsdb_txn *txn, const struct ovsdb_row *ro_row_)
{
    struct ovsdb_row *ro_row = (struct ovsdb_row *) ro_row_;

    if (ro_row->txn_row) {
        assert(ro_row == ro_row->txn_row->new);
        return ro_row;
    } else {
        struct ovsdb_table *table = ro_row->table;
        struct ovsdb_txn_table *txn_table;
        struct ovsdb_row *rw_row;

        txn_table = ovsdb_txn_create_txn_table(txn, table);
        rw_row = ovsdb_row_clone(ro_row);
        uuid_generate(ovsdb_row_get_version_rw(rw_row));
        rw_row->txn_row = ovsdb_txn_row_create(txn_table, ro_row, rw_row);
        hmap_replace(&table->rows, &ro_row->hmap_node, &rw_row->hmap_node);

        return rw_row;
    }
}

void
ovsdb_txn_row_insert(struct ovsdb_txn *txn, struct ovsdb_row *row)
{
    uint32_t hash = ovsdb_row_hash(row);
    struct ovsdb_table *table = row->table;
    struct ovsdb_txn_table *txn_table;

    uuid_generate(ovsdb_row_get_version_rw(row));

    txn_table = ovsdb_txn_create_txn_table(txn, table);
    row->txn_row = ovsdb_txn_row_create(txn_table, NULL, row);
    hmap_insert(&table->rows, &row->hmap_node, hash);
}

/* 'row' must be assumed destroyed upon return; the caller must not reference
 * it again. */
void
ovsdb_txn_row_delete(struct ovsdb_txn *txn, const struct ovsdb_row *row_)
{
    struct ovsdb_row *row = (struct ovsdb_row *) row_;
    struct ovsdb_table *table = row->table;
    struct ovsdb_txn_row *txn_row = row->txn_row;
    struct ovsdb_txn_table *txn_table;

    hmap_remove(&table->rows, &row->hmap_node);

    if (!txn_row) {
        txn_table = ovsdb_txn_create_txn_table(txn, table);
        row->txn_row = ovsdb_txn_row_create(txn_table, row, NULL);
    } else {
        assert(txn_row->new == row);
        if (txn_row->old) {
            txn_row->new = NULL;
        } else {
            txn_table = ovsdb_txn_get_txn_table(txn, table);
            hmap_remove(&txn_table->txn_rows, &txn_row->hmap_node);
        }
        ovsdb_row_destroy(row);
    }
}
