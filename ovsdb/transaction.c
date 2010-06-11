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

#include "bitmap.h"
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

    /* Used by for_each_txn_row(). */
    unsigned int serial;        /* Serial number of in-progress iteration. */
    unsigned int n_processed;   /* Number of rows processed. */
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
    size_t n_refs;              /* Number of remaining references. */

    /* Used by for_each_txn_row(). */
    unsigned int serial;        /* Serial number of in-progress commit. */

    unsigned long changed[];    /* Bits set to 1 for columns that changed. */
};

static void ovsdb_txn_row_prefree(struct ovsdb_txn_row *);
static struct ovsdb_error * WARN_UNUSED_RESULT
for_each_txn_row(struct ovsdb_txn *txn,
                      struct ovsdb_error *(*)(struct ovsdb_txn *,
                                              struct ovsdb_txn_row *));

/* Used by for_each_txn_row() to track tables and rows that have been
 * processed.  */
static unsigned int serial;

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
ovsdb_txn_free(struct ovsdb_txn *txn)
{
    assert(list_is_empty(&txn->txn_tables));
    ds_destroy(&txn->comment);
    free(txn);
}

static struct ovsdb_error *
ovsdb_txn_row_abort(struct ovsdb_txn *txn OVS_UNUSED,
                    struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_row *old = txn_row->old;
    struct ovsdb_row *new = txn_row->new;

    ovsdb_txn_row_prefree(txn_row);
    if (!old) {
        hmap_remove(&new->table->rows, &new->hmap_node);
    } else if (!new) {
        hmap_insert(&old->table->rows, &old->hmap_node, ovsdb_row_hash(old));
    } else {
        hmap_replace(&new->table->rows, &new->hmap_node, &old->hmap_node);
    }
    ovsdb_row_destroy(new);
    free(txn_row);

    return NULL;
}

void
ovsdb_txn_abort(struct ovsdb_txn *txn)
{
    ovsdb_error_assert(for_each_txn_row(txn, ovsdb_txn_row_abort));
    ovsdb_txn_free(txn);
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

static struct ovsdb_error * WARN_UNUSED_RESULT
ovsdb_txn_adjust_atom_refs(struct ovsdb_txn *txn, const struct ovsdb_row *r,
                           const struct ovsdb_column *c,
                           const struct ovsdb_base_type *base,
                           const union ovsdb_atom *atoms, unsigned int n,
                           int delta)
{
    const struct ovsdb_table *table;
    unsigned int i;

    if (!ovsdb_base_type_is_strong_ref(base)) {
        return NULL;
    }

    table = base->u.uuid.refTable;
    for (i = 0; i < n; i++) {
        const struct uuid *uuid = &atoms[i].uuid;
        struct ovsdb_txn_row *txn_row = find_txn_row(table, uuid);
        if (!txn_row) {
            const struct ovsdb_row *row = ovsdb_table_get_row(table, uuid);
            if (row) {
                txn_row = ovsdb_txn_row_modify(txn, row)->txn_row;
            } else {
                return ovsdb_error("referential integrity violation",
                                   "Table %s column %s row "UUID_FMT" "
                                   "references nonexistent row "UUID_FMT" in "
                                   "table %s.",
                                   r->table->schema->name, c->name,
                                   UUID_ARGS(ovsdb_row_get_uuid(r)),
                                   UUID_ARGS(uuid), table->schema->name);
            }
        }
        txn_row->n_refs += delta;
    }

    return NULL;
}

static struct ovsdb_error * WARN_UNUSED_RESULT
ovsdb_txn_adjust_row_refs(struct ovsdb_txn *txn, const struct ovsdb_row *r,
                          const struct ovsdb_column *column, int delta)
{
    const struct ovsdb_datum *field = &r->fields[column->index];
    struct ovsdb_error *error;

    error = ovsdb_txn_adjust_atom_refs(txn, r, column, &column->type.key,
                                       field->keys, field->n, delta);
    if (!error) {
        error = ovsdb_txn_adjust_atom_refs(txn, r, column, &column->type.value,
                                           field->values, field->n, delta);
    }
    return error;
}

static struct ovsdb_error * WARN_UNUSED_RESULT
update_row_ref_count(struct ovsdb_txn *txn, struct ovsdb_txn_row *r)
{
    struct ovsdb_table *table = r->old ? r->old->table : r->new->table;
    struct shash_node *node;

    SHASH_FOR_EACH (node, &table->schema->columns) {
        const struct ovsdb_column *column = node->data;
        struct ovsdb_error *error;

        if (r->old) {
            error = ovsdb_txn_adjust_row_refs(txn, r->old, column, -1);
            if (error) {
                ovsdb_error_destroy(error);
                return OVSDB_BUG("error decreasing refcount");
            }
        }
        if (r->new) {
            error = ovsdb_txn_adjust_row_refs(txn, r->new, column, 1);
            if (error) {
                return error;
            }
        }
    }

    return NULL;
}

static struct ovsdb_error * WARN_UNUSED_RESULT
check_ref_count(struct ovsdb_txn *txn OVS_UNUSED, struct ovsdb_txn_row *r)
{
    if (r->new || !r->n_refs) {
        return NULL;
    } else {
        return ovsdb_error("referential integrity violation",
                           "cannot delete %s row "UUID_FMT" because "
                           "of %zu remaining reference(s)",
                           r->old->table->schema->name,
                           UUID_ARGS(ovsdb_row_get_uuid(r->old)),
                           r->n_refs);
    }
}

static struct ovsdb_error * WARN_UNUSED_RESULT
update_ref_counts(struct ovsdb_txn *txn)
{
    struct ovsdb_error *error;

    error = for_each_txn_row(txn, update_row_ref_count);
    if (error) {
        return error;
    }

    return for_each_txn_row(txn, check_ref_count);
}

static struct ovsdb_error *
ovsdb_txn_row_commit(struct ovsdb_txn *txn OVS_UNUSED,
                     struct ovsdb_txn_row *txn_row)
{
    ovsdb_txn_row_prefree(txn_row);
    if (txn_row->new) {
        txn_row->new->n_refs = txn_row->n_refs;
    }
    ovsdb_row_destroy(txn_row->old);
    free(txn_row);

    return NULL;
}

static void
add_weak_ref(struct ovsdb_txn *txn,
             const struct ovsdb_row *src_, const struct ovsdb_row *dst_)
{
    struct ovsdb_row *src = (struct ovsdb_row *) src_;
    struct ovsdb_row *dst = (struct ovsdb_row *) dst_;
    struct ovsdb_weak_ref *weak;

    if (src == dst) {
        return;
    }

    dst = ovsdb_txn_row_modify(txn, dst);

    if (!list_is_empty(&dst->dst_refs)) {
        /* Omit duplicates. */
        weak = CONTAINER_OF(list_back(&dst->dst_refs),
                            struct ovsdb_weak_ref, dst_node);
        if (weak->src == src) {
            return;
        }
    }

    weak = xmalloc(sizeof *weak);
    weak->src = src;
    list_push_back(&dst->dst_refs, &weak->dst_node);
    list_push_back(&src->src_refs, &weak->src_node);
}

static struct ovsdb_error * WARN_UNUSED_RESULT
assess_weak_refs(struct ovsdb_txn *txn, struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_table *table;
    struct shash_node *node;

    if (txn_row->old) {
        /* Mark rows that have weak references to 'txn_row' as modified, so
         * that their weak references will get reassessed. */
        struct ovsdb_weak_ref *weak, *next;

        LIST_FOR_EACH_SAFE (weak, next, struct ovsdb_weak_ref, dst_node,
                            &txn_row->old->dst_refs) {
            if (!weak->src->txn_row) {
                ovsdb_txn_row_modify(txn, weak->src);
            }
        }
    }

    if (!txn_row->new) {
        /* We don't have to do anything about references that originate at
         * 'txn_row', because ovsdb_row_destroy() will remove those weak
         * references. */
        return NULL;
    }

    table = txn_row->new->table;
    SHASH_FOR_EACH (node, &table->schema->columns) {
        const struct ovsdb_column *column = node->data;
        struct ovsdb_datum *datum = &txn_row->new->fields[column->index];
        unsigned int orig_n, i;
        bool zero = false;

        orig_n = datum->n;

        if (ovsdb_base_type_is_weak_ref(&column->type.key)) {
            for (i = 0; i < datum->n; ) {
                const struct ovsdb_row *row;

                row = ovsdb_table_get_row(column->type.key.u.uuid.refTable,
                                          &datum->keys[i].uuid);
                if (row) {
                    add_weak_ref(txn, txn_row->new, row);
                    i++;
                } else {
                    if (uuid_is_zero(&datum->keys[i].uuid)) {
                        zero = true;
                    }
                    ovsdb_datum_remove_unsafe(datum, i, &column->type);
                }
            }
        }

        if (ovsdb_base_type_is_weak_ref(&column->type.value)) {
            for (i = 0; i < datum->n; ) {
                const struct ovsdb_row *row;

                row = ovsdb_table_get_row(column->type.value.u.uuid.refTable,
                                          &datum->values[i].uuid);
                if (row) {
                    add_weak_ref(txn, txn_row->new, row);
                    i++;
                } else {
                    if (uuid_is_zero(&datum->values[i].uuid)) {
                        zero = true;
                    }
                    ovsdb_datum_remove_unsafe(datum, i, &column->type);
                }
            }
        }

        if (datum->n != orig_n) {
            bitmap_set1(txn_row->changed, column->index);
            ovsdb_datum_sort_assert(datum, column->type.key.type);
            if (datum->n < column->type.n_min) {
                const struct uuid *row_uuid = ovsdb_row_get_uuid(txn_row->new);
                if (zero && !txn_row->old) {
                    return ovsdb_error(
                        "constraint violation",
                        "Weak reference column \"%s\" in \"%s\" row "UUID_FMT
                        " (inserted within this transaction) contained "
                        "all-zeros UUID (probably as the default value for "
                        "this column) but deleting this value caused a "
                        "constraint volation because this column is not "
                        "allowed to be empty.", column->name,
                        table->schema->name, UUID_ARGS(row_uuid));
                } else {
                    return ovsdb_error(
                        "constraint violation",
                        "Deletion of %u weak reference(s) to deleted (or "
                        "never-existing) rows from column \"%s\" in \"%s\" "
                        "row "UUID_FMT" %scaused this column to become empty, "
                        "but constraints on this column disallow an "
                        "empty column.",
                        orig_n - datum->n, column->name, table->schema->name,
                        UUID_ARGS(row_uuid),
                        (txn_row->old
                         ? ""
                         : "(inserted within this transaction) "));
                }
            }
        }
    }

    return NULL;
}

static struct ovsdb_error * WARN_UNUSED_RESULT
determine_changes(struct ovsdb_txn *txn, struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_table *table;

    table = (txn_row->old ? txn_row->old : txn_row->new)->table;
    if (txn_row->old && txn_row->new) {
        struct shash_node *node;
        bool changed = false;

        SHASH_FOR_EACH (node, &table->schema->columns) {
            const struct ovsdb_column *column = node->data;
            const struct ovsdb_type *type = &column->type;
            unsigned int idx = column->index;

            if (!ovsdb_datum_equals(&txn_row->old->fields[idx],
                                    &txn_row->new->fields[idx],
                                    type)) {
                bitmap_set1(txn_row->changed, idx);
                changed = true;
            }
        }

        if (!changed) {
            /* Nothing actually changed in this row, so drop it. */
            ovsdb_txn_row_abort(txn, txn_row);
        }
    } else {
        bitmap_set_multiple(txn_row->changed, 0,
                            shash_count(&table->schema->columns), 1);
    }

    return NULL;
}

static struct ovsdb_error * WARN_UNUSED_RESULT
check_max_rows(struct ovsdb_txn *txn)
{
    struct ovsdb_txn_table *t;

    LIST_FOR_EACH (t, struct ovsdb_txn_table, node, &txn->txn_tables) {
        size_t n_rows = hmap_count(&t->table->rows);
        unsigned int max_rows = t->table->schema->max_rows;

        if (n_rows > max_rows) {
            return ovsdb_error("constraint violation",
                               "transaction causes \"%s\" table to contain "
                               "%zu rows, greater than the schema-defined "
                               "limit of %u row(s)",
                               t->table->schema->name, n_rows, max_rows);
        }
    }

    return NULL;
}

struct ovsdb_error *
ovsdb_txn_commit(struct ovsdb_txn *txn, bool durable)
{
    struct ovsdb_replica *replica;
    struct ovsdb_error *error;

    /* Figure out what actually changed, and abort early if the transaction
     * was really a no-op. */
    error = for_each_txn_row(txn, determine_changes);
    if (error) {
        ovsdb_error_destroy(error);
        return OVSDB_BUG("can't happen");
    }
    if (list_is_empty(&txn->txn_tables)) {
        ovsdb_txn_abort(txn);
        return NULL;
    }

    /* Check maximum rows table constraints. */
    error = check_max_rows(txn);
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    }

    /* Update reference counts and check referential integrity. */
    error = update_ref_counts(txn);
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    }

    /* Check reference counts and remove bad reference for "weak" referential
     * integrity. */
    error = for_each_txn_row(txn, assess_weak_refs);
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    }

    /* Send the commit to each replica. */
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

    /* Finalize commit. */
    txn->db->run_triggers = true;
    ovsdb_error_assert(for_each_txn_row(txn, ovsdb_txn_row_commit));
    ovsdb_txn_free(txn);

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
            if (!cb(r->old, r->new, r->changed, aux)) {
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
        txn_table->serial = serial - 1;
        list_push_back(&txn->txn_tables, &txn_table->node);
    }
    return table->txn_table;
}

static struct ovsdb_txn_row *
ovsdb_txn_row_create(struct ovsdb_txn *txn, struct ovsdb_table *table,
                     const struct ovsdb_row *old_, struct ovsdb_row *new)
{
    struct ovsdb_row *old = (struct ovsdb_row *) old_;
    size_t n_columns = shash_count(&table->schema->columns);
    struct ovsdb_txn_table *txn_table;
    struct ovsdb_txn_row *txn_row;

    txn_row = xzalloc(offsetof(struct ovsdb_txn_row, changed)
                      + bitmap_n_bytes(n_columns));
    txn_row->old = (struct ovsdb_row *) old;
    txn_row->new = new;
    txn_row->n_refs = old ? old->n_refs : 0;
    txn_row->serial = serial - 1;

    if (old) {
        old->txn_row = txn_row;
    }
    if (new) {
        new->txn_row = txn_row;
    }

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
        ovsdb_txn_row_create(txn, table, ro_row, rw_row);
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

    ovsdb_txn_row_create(txn, table, NULL, row);
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
        ovsdb_txn_row_create(txn, table, row, NULL);
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

static void
ovsdb_txn_row_prefree(struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_row *row = txn_row->old ? txn_row->old : txn_row->new;
    struct ovsdb_txn_table *txn_table = row->table->txn_table;

    txn_table->n_processed--;
    hmap_remove(&txn_table->txn_rows, &txn_row->hmap_node);

    if (txn_row->old) {
        txn_row->old->txn_row = NULL;
    }
    if (txn_row->new) {
        txn_row->new->txn_row = NULL;
    }
}

static void
ovsdb_txn_table_destroy(struct ovsdb_txn_table *txn_table)
{
    assert(hmap_is_empty(&txn_table->txn_rows));
    txn_table->table->txn_table = NULL;
    hmap_destroy(&txn_table->txn_rows);
    list_remove(&txn_table->node);
    free(txn_table);
}

/* Calls 'cb' for every txn_row within 'txn'.  If 'cb' returns nonnull, this
 * aborts the iteration and for_each_txn_row() passes the error up.  Otherwise,
 * returns a null pointer after iteration is complete.
 *
 * 'cb' may insert new txn_rows and new txn_tables into 'txn'.  It may delete
 * the txn_row that it is passed in, or txn_rows in txn_tables other than the
 * one passed to 'cb'.  It may *not* delete txn_rows other than the one passed
 * in within the same txn_table.  It may *not* delete any txn_tables.  As long
 * as these rules are followed, 'cb' will be called exactly once for each
 * txn_row in 'txn', even those added by 'cb'.
 */
static struct ovsdb_error * WARN_UNUSED_RESULT
for_each_txn_row(struct ovsdb_txn *txn,
                 struct ovsdb_error *(*cb)(struct ovsdb_txn *,
                                           struct ovsdb_txn_row *))
{
    bool any_work;

    serial++;

    do {
        struct ovsdb_txn_table *t, *next_txn_table;

        any_work = false;
        LIST_FOR_EACH_SAFE (t, next_txn_table, struct ovsdb_txn_table, node,
                            &txn->txn_tables) {
            if (t->serial != serial) {
                t->serial = serial;
                t->n_processed = 0;
            }

            while (t->n_processed < hmap_count(&t->txn_rows)) {
                struct ovsdb_txn_row *r, *next_txn_row;

                HMAP_FOR_EACH_SAFE (r, next_txn_row,
                                    struct ovsdb_txn_row, hmap_node,
                                    &t->txn_rows) {
                    if (r->serial != serial) {
                        struct ovsdb_error *error;

                        r->serial = serial;
                        t->n_processed++;
                        any_work = true;

                        error = cb(txn, r);
                        if (error) {
                            return error;
                        }
                    }
                }
            }
            if (hmap_is_empty(&t->txn_rows)) {
                /* Table is empty.  Drop it. */
                ovsdb_txn_table_destroy(t);
            }
        }
    } while (any_work);

    return NULL;
}
