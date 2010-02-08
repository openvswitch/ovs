/* Copyright (c) 2009, 2010 Nicira Networks
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

#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "json.h"
#include "list.h"
#include "ovsdb-error.h"
#include "ovsdb.h"
#include "row.h"
#include "table.h"
#include "uuid.h"

struct ovsdb_txn {
    struct ovsdb *db;
    struct list txn_tables;     /* Contains "struct ovsdb_txn_table"s. */
    struct ds comment;
};

/* A table modified by a transaction. */
struct ovsdb_txn_table {
    struct list node;           /* Element in ovsdb_txn's txn_tables list. */
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

struct ovsdb_txn *
ovsdb_txn_create(struct ovsdb *db)
{
    struct ovsdb_txn *txn = xmalloc(sizeof *txn);
    txn->db = db;
    list_init(&txn->txn_tables);
    ds_init(&txn->comment);
    return txn;
}

static void
ovsdb_txn_destroy(struct ovsdb_txn *txn, void (*cb)(struct ovsdb_txn_row *))
{
    struct ovsdb_txn_table *txn_table, *next_txn_table;

    LIST_FOR_EACH_SAFE (txn_table, next_txn_table,
                        struct ovsdb_txn_table, node, &txn->txn_tables) {
        struct ovsdb_txn_row *txn_row, *next_txn_row;

        HMAP_FOR_EACH_SAFE (txn_row, next_txn_row,
                            struct ovsdb_txn_row, hmap_node,
                            &txn_table->txn_rows)
        {
            if (txn_row->old) {
                txn_row->old->txn_row = NULL;
            }
            if (txn_row->new) {
                txn_row->new->txn_row = NULL;
            }
            cb(txn_row);
            free(txn_row);
        }

        txn_table->table->txn_table = NULL;
        hmap_destroy(&txn_table->txn_rows);
        free(txn_table);
    }
    ds_destroy(&txn->comment);
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

static struct ovsdb_txn_row *
find_txn_row(const struct ovsdb_table *table, const struct uuid *uuid)
{
    struct ovsdb_txn_row *txn_row;

    if (!table->txn_table) {
        return NULL;
    }

    HMAP_FOR_EACH_WITH_HASH (txn_row, struct ovsdb_txn_row, hmap_node,
                             uuid_hash(uuid), &table->txn_table->txn_rows) {
        const struct ovsdb_row *row;

        row = txn_row->old ? txn_row->old : txn_row->new;
        if (uuid_equals(uuid, ovsdb_row_get_uuid(row))) {
            return txn_row;
        }
    }

    return NULL;
}

static void
ovsdb_txn_adjust_atom_refs(const union ovsdb_atom *atoms, unsigned int n,
                           const struct ovsdb_table *table,
                           int delta, struct ovsdb_error **errorp)
{
    unsigned int i;

    for (i = 0; i < n; i++) {
        const struct uuid *uuid = &atoms[i].uuid;
        struct ovsdb_txn_row *txn_row = find_txn_row(table, uuid);
        if (txn_row) {
            if (txn_row->old) {
                txn_row->old->n_refs += delta;
            }
            if (txn_row->new) {
                txn_row->new->n_refs += delta;
            }
        } else {
            const struct ovsdb_row *row_ = ovsdb_table_get_row(table, uuid);
            if (row_) {
                struct ovsdb_row *row = (struct ovsdb_row *) row_;
                row->n_refs += delta;
            } else if (errorp) {
                if (!*errorp) {
                    *errorp = ovsdb_error("referential integrity violation",
                                          "reference to nonexistent row "
                                          UUID_FMT, UUID_ARGS(uuid));
                }
            } else {
                NOT_REACHED();
            }
        }
    }
}

static void
ovsdb_txn_adjust_row_refs(const struct ovsdb_row *r,
                          const struct ovsdb_column *column, int delta,
                          struct ovsdb_error **errorp)
{
    const struct ovsdb_datum *field = &r->fields[column->index];
    const struct ovsdb_type *type = &column->type;

    if (type->key.type == OVSDB_TYPE_UUID && type->key.u.uuid.refTable) {
        ovsdb_txn_adjust_atom_refs(field->keys, field->n,
                                   type->key.u.uuid.refTable, delta, errorp);
    }
    if (type->value.type == OVSDB_TYPE_UUID && type->value.u.uuid.refTable) {
        ovsdb_txn_adjust_atom_refs(field->values, field->n,
                                   type->value.u.uuid.refTable, delta, errorp);
    }
}

static struct ovsdb_error * WARN_UNUSED_RESULT
ovsdb_txn_adjust_ref_counts__(struct ovsdb_txn *txn, int delta)
{
    struct ovsdb_txn_table *t;
    struct ovsdb_error *error;

    error = NULL;
    LIST_FOR_EACH (t, struct ovsdb_txn_table, node, &txn->txn_tables) {
        struct ovsdb_table *table = t->table;
        struct ovsdb_txn_row *r;

        HMAP_FOR_EACH (r, struct ovsdb_txn_row, hmap_node, &t->txn_rows) {
            struct shash_node *node;

            SHASH_FOR_EACH (node, &table->schema->columns) {
                const struct ovsdb_column *column = node->data;

                if (r->old) {
                    ovsdb_txn_adjust_row_refs(r->old, column, -delta, NULL);
                }
                if (r->new) {
                    ovsdb_txn_adjust_row_refs(r->new, column, delta, &error);
                }
            }
        }
    }
    return error;
}

static void
ovsdb_txn_rollback_counts(struct ovsdb_txn *txn)
{
    ovsdb_error_destroy(ovsdb_txn_adjust_ref_counts__(txn, -1));
}

static struct ovsdb_error * WARN_UNUSED_RESULT
ovsdb_txn_commit_ref_counts(struct ovsdb_txn *txn)
{
    struct ovsdb_error *error = ovsdb_txn_adjust_ref_counts__(txn, 1);
    if (error) {
        ovsdb_txn_rollback_counts(txn);
    }
    return error;
}

static struct ovsdb_error * WARN_UNUSED_RESULT
update_ref_counts(struct ovsdb_txn *txn)
{
    struct ovsdb_error *error;
    struct ovsdb_txn_table *t;

    error = ovsdb_txn_commit_ref_counts(txn);
    if (error) {
        return error;
    }

    LIST_FOR_EACH (t, struct ovsdb_txn_table, node, &txn->txn_tables) {
        struct ovsdb_txn_row *r;

        HMAP_FOR_EACH (r, struct ovsdb_txn_row, hmap_node, &t->txn_rows) {
            if (!r->new && r->old->n_refs) {
                error = ovsdb_error("referential integrity violation",
                                    "cannot delete %s row "UUID_FMT" because "
                                    "of %zu remaining reference(s)",
                                    t->table->schema->name,
                                    UUID_ARGS(ovsdb_row_get_uuid(r->old)),
                                    r->old->n_refs);
                ovsdb_txn_rollback_counts(txn);
                return error;
            }
        }
    }

    return NULL;
}

struct ovsdb_error *
ovsdb_txn_commit(struct ovsdb_txn *txn, bool durable)
{
    struct ovsdb_replica *replica;
    struct ovsdb_error *error;

    error = update_ref_counts(txn);
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    }

    LIST_FOR_EACH (replica, struct ovsdb_replica, node, &txn->db->replicas) {
        error = (replica->class->commit)(replica, txn, durable);
        if (error) {
            /* We don't support two-phase commit so only the first replica is
             * allowed to report an error. */
            assert(&replica->node == txn->db->replicas.next);

            ovsdb_txn_abort(txn);
            return error;
        }
    }

    txn->db->run_triggers = true;
    ovsdb_txn_destroy(txn, ovsdb_txn_row_commit);
    return NULL;
}

void
ovsdb_txn_for_each_change(const struct ovsdb_txn *txn,
                          ovsdb_txn_row_cb_func *cb, void *aux)
{
    struct ovsdb_txn_table *t;
    struct ovsdb_txn_row *r;

    LIST_FOR_EACH (t, struct ovsdb_txn_table, node, &txn->txn_tables) {
        HMAP_FOR_EACH (r, struct ovsdb_txn_row, hmap_node, &t->txn_rows) {
            if (!cb(r->old, r->new, aux)) {
                break;
            }
        }
   }
}

static struct ovsdb_txn_table *
ovsdb_txn_create_txn_table(struct ovsdb_txn *txn, struct ovsdb_table *table)
{
    if (!table->txn_table) {
        struct ovsdb_txn_table *txn_table;

        table->txn_table = txn_table = xmalloc(sizeof *table->txn_table);
        txn_table->table = table;
        hmap_init(&txn_table->txn_rows);
        list_push_back(&txn->txn_tables, &txn_table->node);
    }
    return table->txn_table;
}

static struct ovsdb_txn_row *
ovsdb_txn_row_create(struct ovsdb_txn *txn, struct ovsdb_table *table,
                     const struct ovsdb_row *old, struct ovsdb_row *new)
{
    struct ovsdb_txn_table *txn_table;
    struct ovsdb_txn_row *txn_row;

    txn_row = xmalloc(sizeof *txn_row);
    txn_row->old = (struct ovsdb_row *) old;
    txn_row->new = new;

    txn_table = ovsdb_txn_create_txn_table(txn, table);
    hmap_insert(&txn_table->txn_rows, &txn_row->hmap_node,
                ovsdb_row_hash(old ? old : new));

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
        struct ovsdb_row *rw_row;

        rw_row = ovsdb_row_clone(ro_row);
        rw_row->n_refs = ro_row->n_refs;
        uuid_generate(ovsdb_row_get_version_rw(rw_row));
        rw_row->txn_row = ovsdb_txn_row_create(txn, table, ro_row, rw_row);
        hmap_replace(&table->rows, &ro_row->hmap_node, &rw_row->hmap_node);

        return rw_row;
    }
}

void
ovsdb_txn_row_insert(struct ovsdb_txn *txn, struct ovsdb_row *row)
{
    uint32_t hash = ovsdb_row_hash(row);
    struct ovsdb_table *table = row->table;

    uuid_generate(ovsdb_row_get_version_rw(row));

    row->txn_row = ovsdb_txn_row_create(txn, table, NULL, row);
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

    hmap_remove(&table->rows, &row->hmap_node);

    if (!txn_row) {
        row->txn_row = ovsdb_txn_row_create(txn, table, row, NULL);
    } else {
        assert(txn_row->new == row);
        if (txn_row->old) {
            txn_row->new = NULL;
        } else {
            hmap_remove(&table->txn_table->txn_rows, &txn_row->hmap_node);
            free(txn_row);
        }
        ovsdb_row_destroy(row);
    }
}

void
ovsdb_txn_add_comment(struct ovsdb_txn *txn, const char *s)
{
    if (txn->comment.length) {
        ds_put_char(&txn->comment, '\n');
    }
    ds_put_cstr(&txn->comment, s);
}

const char *
ovsdb_txn_get_comment(const struct ovsdb_txn *txn)
{
    return txn->comment.length ? ds_cstr_ro(&txn->comment) : NULL;
}
