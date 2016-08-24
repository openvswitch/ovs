/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include "bitmap.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "ovsdb-error.h"
#include "ovsdb.h"
#include "row.h"
#include "table.h"
#include "perf-counter.h"
#include "uuid.h"

struct ovsdb_txn {
    struct ovsdb *db;
    struct ovs_list txn_tables; /* Contains "struct ovsdb_txn_table"s. */
    struct ds comment;
};

/* A table modified by a transaction. */
struct ovsdb_txn_table {
    struct ovs_list node;       /* Element in ovsdb_txn's txn_tables list. */
    struct ovsdb_table *table;
    struct hmap txn_rows;       /* Contains "struct ovsdb_txn_row"s. */

    /* This has the same form as the 'indexes' member of struct ovsdb_table,
     * but it is only used or updated at transaction commit time, from
     * check_index_uniqueness(). */
    struct hmap *txn_indexes;

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
 *      - 'old' and 'new' both null indicates that a row was added then deleted
 *        within a single transaction.  Most of the time we instead delete the
 *        ovsdb_txn_row entirely, but inside a for_each_txn_row() callback
 *        there are restrictions that sometimes mean we have to leave the
 *        ovsdb_txn_row in place.
 */
struct ovsdb_txn_row {
    struct hmap_node hmap_node; /* In ovsdb_txn_table's txn_rows hmap. */
    struct ovsdb_row *old;      /* The old row. */
    struct ovsdb_row *new;      /* The new row. */
    size_t n_refs;              /* Number of remaining references. */

    /* These members are the same as the corresponding members of 'old' or
     * 'new'.  They are present here for convenience and because occasionally
     * there can be an ovsdb_txn_row where both 'old' and 'new' are NULL. */
    struct uuid uuid;
    struct ovsdb_table *table;

    /* Used by for_each_txn_row(). */
    unsigned int serial;        /* Serial number of in-progress commit. */

    unsigned long changed[];    /* Bits set to 1 for columns that changed. */
};

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
delete_garbage_row(struct ovsdb_txn *txn, struct ovsdb_txn_row *r);
static void ovsdb_txn_row_prefree(struct ovsdb_txn_row *);
static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
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
    ovs_list_init(&txn->txn_tables);
    ds_init(&txn->comment);
    return txn;
}

static void
ovsdb_txn_free(struct ovsdb_txn *txn)
{
    ovs_assert(ovs_list_is_empty(&txn->txn_tables));
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
        if (new) {
            hmap_remove(&new->table->rows, &new->hmap_node);
        }
    } else if (!new) {
        hmap_insert(&old->table->rows, &old->hmap_node, ovsdb_row_hash(old));
    } else {
        hmap_replace(&new->table->rows, &new->hmap_node, &old->hmap_node);
    }
    ovsdb_row_destroy(new);
    free(txn_row);

    return NULL;
}

/* Returns the offset in bytes from the start of an ovsdb_row for 'table' to
 * the hmap_node for the index numbered 'i'. */
static size_t
ovsdb_row_index_offset__(const struct ovsdb_table *table, size_t i)
{
    size_t n_fields = shash_count(&table->schema->columns);
    return (offsetof(struct ovsdb_row, fields)
            + n_fields * sizeof(struct ovsdb_datum)
            + i * sizeof(struct hmap_node));
}

/* Returns the hmap_node in 'row' for the index numbered 'i'. */
static struct hmap_node *
ovsdb_row_get_index_node(struct ovsdb_row *row, size_t i)
{
    return (void *) ((char *) row + ovsdb_row_index_offset__(row->table, i));
}

/* Returns the ovsdb_row given 'index_node', which is a pointer to that row's
 * hmap_node for the index numbered 'i' within 'table'. */
static struct ovsdb_row *
ovsdb_row_from_index_node(struct hmap_node *index_node,
                          const struct ovsdb_table *table, size_t i)
{
    return (void *) ((char *) index_node - ovsdb_row_index_offset__(table, i));
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

    HMAP_FOR_EACH_WITH_HASH (txn_row, hmap_node,
                             uuid_hash(uuid), &table->txn_table->txn_rows) {
        if (uuid_equals(uuid, &txn_row->uuid)) {
            return txn_row;
        }
    }

    return NULL;
}

static struct ovsdb_txn_row *
find_or_make_txn_row(struct ovsdb_txn *txn, const struct ovsdb_table *table,
                     const struct uuid *uuid)
{
    struct ovsdb_txn_row *txn_row = find_txn_row(table, uuid);
    if (!txn_row) {
        const struct ovsdb_row *row = ovsdb_table_get_row(table, uuid);
        if (row) {
            txn_row = ovsdb_txn_row_modify(txn, row)->txn_row;
        }
    }
    return txn_row;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
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
        struct ovsdb_txn_row *txn_row;

        if (uuid_equals(uuid, ovsdb_row_get_uuid(r))) {
            /* Self-references don't count. */
            continue;
        }

        txn_row = find_or_make_txn_row(txn, table, uuid);
        if (!txn_row) {
            return ovsdb_error("referential integrity violation",
                               "Table %s column %s row "UUID_FMT" "
                               "references nonexistent row "UUID_FMT" in "
                               "table %s.",
                               r->table->schema->name, c->name,
                               UUID_ARGS(ovsdb_row_get_uuid(r)),
                               UUID_ARGS(uuid), table->schema->name);
        }
        txn_row->n_refs += delta;
    }

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
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

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
update_row_ref_count(struct ovsdb_txn *txn, struct ovsdb_txn_row *r)
{
    struct ovsdb_table *table = r->table;
    struct shash_node *node;

    SHASH_FOR_EACH (node, &table->schema->columns) {
        const struct ovsdb_column *column = node->data;
        struct ovsdb_error *error;

        if (bitmap_is_set(r->changed, column->index)) {
            if (r->old) {
                error = ovsdb_txn_adjust_row_refs(txn, r->old, column, -1);
                if (error) {
                    return OVSDB_WRAP_BUG("error decreasing refcount", error);
                }
            }
            if (r->new) {
                error = ovsdb_txn_adjust_row_refs(txn, r->new, column, 1);
                if (error) {
                    return error;
                }
            }
        }
    }

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
check_ref_count(struct ovsdb_txn *txn OVS_UNUSED, struct ovsdb_txn_row *r)
{
    if (r->new || !r->n_refs) {
        return NULL;
    } else {
        return ovsdb_error("referential integrity violation",
                           "cannot delete %s row "UUID_FMT" because "
                           "of %"PRIuSIZE" remaining reference(s)",
                           r->table->schema->name, UUID_ARGS(&r->uuid),
                           r->n_refs);
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
delete_row_refs(struct ovsdb_txn *txn, const struct ovsdb_row *row,
                const struct ovsdb_base_type *base,
                const union ovsdb_atom *atoms, unsigned int n)
{
    const struct ovsdb_table *table;
    unsigned int i;

    if (!ovsdb_base_type_is_strong_ref(base)) {
        return NULL;
    }

    table = base->u.uuid.refTable;
    for (i = 0; i < n; i++) {
        const struct uuid *uuid = &atoms[i].uuid;
        struct ovsdb_txn_row *txn_row;

        if (uuid_equals(uuid, ovsdb_row_get_uuid(row))) {
            /* Self-references don't count. */
            continue;
        }

        txn_row = find_or_make_txn_row(txn, table, uuid);
        if (!txn_row) {
            return OVSDB_BUG("strong ref target missing");
        } else if (!txn_row->n_refs) {
            return OVSDB_BUG("strong ref target has zero n_refs");
        } else if (!txn_row->new) {
            return OVSDB_BUG("deleted strong ref target");
        }

        if (--txn_row->n_refs == 0) {
            struct ovsdb_error *error = delete_garbage_row(txn, txn_row);
            if (error) {
                return error;
            }
        }
    }

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
delete_garbage_row(struct ovsdb_txn *txn, struct ovsdb_txn_row *txn_row)
{
    struct shash_node *node;
    struct ovsdb_row *row;

    if (txn_row->table->schema->is_root) {
        return NULL;
    }

    row = txn_row->new;
    txn_row->new = NULL;
    hmap_remove(&txn_row->table->rows, &row->hmap_node);
    SHASH_FOR_EACH (node, &txn_row->table->schema->columns) {
        const struct ovsdb_column *column = node->data;
        const struct ovsdb_datum *field = &row->fields[column->index];
        struct ovsdb_error *error;

        error = delete_row_refs(txn, row,
                                &column->type.key, field->keys, field->n);
        if (error) {
            return error;
        }

        error = delete_row_refs(txn, row,
                                &column->type.value, field->values, field->n);
        if (error) {
            return error;
        }
    }
    ovsdb_row_destroy(row);

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
collect_garbage(struct ovsdb_txn *txn, struct ovsdb_txn_row *txn_row)
{
    if (txn_row->new && !txn_row->n_refs) {
        return delete_garbage_row(txn, txn_row);
    }
    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
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
    size_t n_indexes = txn_row->table->schema->n_indexes;

    if (txn_row->old) {
        size_t i;

        for (i = 0; i < n_indexes; i++) {
            struct hmap_node *node = ovsdb_row_get_index_node(txn_row->old, i);
            hmap_remove(&txn_row->table->indexes[i], node);
        }
    }
    if (txn_row->new) {
        size_t i;

        for (i = 0; i < n_indexes; i++) {
            struct hmap_node *node = ovsdb_row_get_index_node(txn_row->new, i);
            hmap_insert(&txn_row->table->indexes[i], node, node->hash);
        }
    }

    ovsdb_txn_row_prefree(txn_row);
    if (txn_row->new) {
        txn_row->new->n_refs = txn_row->n_refs;
    }
    ovsdb_row_destroy(txn_row->old);
    free(txn_row);

    return NULL;
}

static struct ovsdb_error *
ovsdb_txn_update_weak_refs(struct ovsdb_txn *txn OVS_UNUSED,
                           struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_weak_ref *weak, *next;

    /* Remove the weak references originating in the old version of the row. */
    if (txn_row->old) {
        LIST_FOR_EACH_SAFE (weak, next, src_node, &txn_row->old->src_refs) {
            ovs_list_remove(&weak->src_node);
            ovs_list_remove(&weak->dst_node);
            free(weak);
        }
    }

    /* Although the originating rows have the responsibility of updating the
     * weak references in the dst, it is possible that some source rows aren't
     * part of the transaction.  In that situation this row needs to move the
     * list of incoming weak references from the old row into the new one.
     */
    if (txn_row->old && txn_row->new) {
        /* Move the incoming weak references from old to new. */
        ovs_list_push_back_all(&txn_row->new->dst_refs,
                               &txn_row->old->dst_refs);
    }

    /* Insert the weak references originating in the new version of the row. */
    struct ovsdb_row *dst_row;
    if (txn_row->new) {
        LIST_FOR_EACH (weak, src_node, &txn_row->new->src_refs) {
            /* dst_row MUST exist. */
            dst_row = CONST_CAST(struct ovsdb_row *,
                    ovsdb_table_get_row(weak->dst_table, &weak->dst));
            ovs_list_insert(&dst_row->dst_refs, &weak->dst_node);
        }
    }

    return NULL;
}

static void
add_weak_ref(const struct ovsdb_row *src_, const struct ovsdb_row *dst_)
{
    struct ovsdb_row *src = CONST_CAST(struct ovsdb_row *, src_);
    struct ovsdb_row *dst = CONST_CAST(struct ovsdb_row *, dst_);
    struct ovsdb_weak_ref *weak;

    if (src == dst) {
        return;
    }

    if (!ovs_list_is_empty(&dst->dst_refs)) {
        /* Omit duplicates. */
        weak = CONTAINER_OF(ovs_list_back(&dst->dst_refs),
                            struct ovsdb_weak_ref, dst_node);
        if (weak->src == src) {
            return;
        }
    }

    weak = xmalloc(sizeof *weak);
    weak->src = src;
    weak->dst_table = dst->table;
    weak->dst = *ovsdb_row_get_uuid(dst);
    /* The dst_refs list is updated at commit time. */
    ovs_list_init(&weak->dst_node);
    ovs_list_push_back(&src->src_refs, &weak->src_node);
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
assess_weak_refs(struct ovsdb_txn *txn, struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_table *table;
    struct shash_node *node;

    if (txn_row->old && !txn_row->new) {
        /* Mark rows that have weak references to 'txn_row' as modified, so
         * that their weak references will get reassessed. */
        struct ovsdb_weak_ref *weak, *next;

        LIST_FOR_EACH_SAFE (weak, next, dst_node, &txn_row->old->dst_refs) {
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

    table = txn_row->table;
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
                    add_weak_ref(txn_row->new, row);
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
                    add_weak_ref(txn_row->new, row);
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

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
determine_changes(struct ovsdb_txn *txn, struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_table *table = txn_row->table;

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

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
check_max_rows(struct ovsdb_txn *txn)
{
    struct ovsdb_txn_table *t;

    LIST_FOR_EACH (t, node, &txn->txn_tables) {
        size_t n_rows = hmap_count(&t->table->rows);
        unsigned int max_rows = t->table->schema->max_rows;

        if (n_rows > max_rows) {
            return ovsdb_error("constraint violation",
                               "transaction causes \"%s\" table to contain "
                               "%"PRIuSIZE" rows, greater than the schema-defined "
                               "limit of %u row(s)",
                               t->table->schema->name, n_rows, max_rows);
        }
    }

    return NULL;
}

static struct ovsdb_row *
ovsdb_index_search(struct hmap *index, struct ovsdb_row *row, size_t i,
                   uint32_t hash)
{
    const struct ovsdb_table *table = row->table;
    const struct ovsdb_column_set *columns = &table->schema->indexes[i];
    struct hmap_node *node;

    for (node = hmap_first_with_hash(index, hash); node;
         node = hmap_next_with_hash(node)) {
        struct ovsdb_row *irow = ovsdb_row_from_index_node(node, table, i);
        if (ovsdb_row_equal_columns(row, irow, columns)) {
            return irow;
        }
    }

    return NULL;
}

static void
duplicate_index_row__(const struct ovsdb_column_set *index,
                      const struct ovsdb_row *row,
                      const char *title,
                      struct ds *out)
{
    size_t n_columns = shash_count(&row->table->schema->columns);

    ds_put_format(out, "%s row, with UUID "UUID_FMT", ",
                  title, UUID_ARGS(ovsdb_row_get_uuid(row)));
    if (!row->txn_row
        || bitmap_scan(row->txn_row->changed, 1, 0, n_columns) == n_columns) {
        ds_put_cstr(out, "existed in the database before this "
                    "transaction and was not modified by the transaction.");
    } else if (!row->txn_row->old) {
        ds_put_cstr(out, "was inserted by this transaction.");
    } else if (ovsdb_row_equal_columns(row->txn_row->old,
                                       row->txn_row->new, index)) {
        ds_put_cstr(out, "existed in the database before this "
                    "transaction, which modified some of the row's columns "
                    "but not any columns in this index.");
    } else {
        ds_put_cstr(out, "had the following index values before the "
                    "transaction: ");
        ovsdb_row_columns_to_string(row->txn_row->old, index, out);
        ds_put_char(out, '.');
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
duplicate_index_row(const struct ovsdb_column_set *index,
                    const struct ovsdb_row *a,
                    const struct ovsdb_row *b)
{
    struct ovsdb_column_set all_columns;
    struct ovsdb_error *error;
    char *index_s;
    struct ds s;

    /* Put 'a' and 'b' in a predictable order to make error messages
     * reproducible for testing. */
    ovsdb_column_set_init(&all_columns);
    ovsdb_column_set_add_all(&all_columns, a->table);
    if (ovsdb_row_compare_columns_3way(a, b, &all_columns) < 0) {
        const struct ovsdb_row *tmp = a;
        a = b;
        b = tmp;
    }
    ovsdb_column_set_destroy(&all_columns);

    index_s = ovsdb_column_set_to_string(index);

    ds_init(&s);
    ds_put_format(&s, "Transaction causes multiple rows in \"%s\" table to "
                  "have identical values (", a->table->schema->name);
    ovsdb_row_columns_to_string(a, index, &s);
    ds_put_format(&s, ") for index on %s.  ", index_s);
    duplicate_index_row__(index, a, "First", &s);
    ds_put_cstr(&s, "  ");
    duplicate_index_row__(index, b, "Second", &s);

    free(index_s);

    error = ovsdb_error("constraint violation", "%s", ds_cstr(&s));
    ds_destroy(&s);
    return error;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
check_index_uniqueness(struct ovsdb_txn *txn OVS_UNUSED,
                       struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_txn_table *txn_table = txn_row->table->txn_table;
    struct ovsdb_table *table = txn_row->table;
    struct ovsdb_row *row = txn_row->new;
    size_t i;

    if (!row) {
        return NULL;
    }

    for (i = 0; i < table->schema->n_indexes; i++) {
        const struct ovsdb_column_set *index = &table->schema->indexes[i];
        struct ovsdb_row *irow;
        uint32_t hash;

        hash = ovsdb_row_hash_columns(row, index, 0);
        irow = ovsdb_index_search(&txn_table->txn_indexes[i], row, i, hash);
        if (irow) {
            return duplicate_index_row(index, irow, row);
        }

        irow = ovsdb_index_search(&table->indexes[i], row, i, hash);
        if (irow && !irow->txn_row) {
            return duplicate_index_row(index, irow, row);
        }

        hmap_insert(&txn_table->txn_indexes[i],
                    ovsdb_row_get_index_node(row, i), hash);
    }

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
update_version(struct ovsdb_txn *txn OVS_UNUSED, struct ovsdb_txn_row *txn_row)
{
    struct ovsdb_table *table = txn_row->table;
    size_t n_columns = shash_count(&table->schema->columns);

    if (txn_row->old && txn_row->new
        && !bitmap_is_all_zeros(txn_row->changed, n_columns)) {
        bitmap_set1(txn_row->changed, OVSDB_COL_VERSION);
        uuid_generate(ovsdb_row_get_version_rw(txn_row->new));
    }

    return NULL;
}

static struct ovsdb_error *
ovsdb_txn_commit_(struct ovsdb_txn *txn, bool durable)
{
    struct ovsdb_replica *replica;
    struct ovsdb_error *error;

    /* Figure out what actually changed, and abort early if the transaction
     * was really a no-op. */
    error = for_each_txn_row(txn, determine_changes);
    if (error) {
        return OVSDB_WRAP_BUG("can't happen", error);
    }
    if (ovs_list_is_empty(&txn->txn_tables)) {
        ovsdb_txn_abort(txn);
        return NULL;
    }

    /* Update reference counts and check referential integrity. */
    error = update_ref_counts(txn);
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    }

    /* Delete unreferenced, non-root rows. */
    error = for_each_txn_row(txn, collect_garbage);
    if (error) {
        ovsdb_txn_abort(txn);
        return OVSDB_WRAP_BUG("can't happen", error);
    }

    /* Check maximum rows table constraints. */
    error = check_max_rows(txn);
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    }

    /* Check reference counts and remove bad references for "weak" referential
     * integrity. */
    error = for_each_txn_row(txn, assess_weak_refs);
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    }

    /* Verify that the indexes will still be unique post-transaction. */
    error = for_each_txn_row(txn, check_index_uniqueness);
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    }

    /* Update _version for rows that changed.  */
    error = for_each_txn_row(txn, update_version);
    if (error) {
        return OVSDB_WRAP_BUG("can't happen", error);
    }

    /* Send the commit to each replica. */
    LIST_FOR_EACH (replica, node, &txn->db->replicas) {
        error = (replica->class->commit)(replica, txn, durable);
        if (error) {
            /* We don't support two-phase commit so only the first replica is
             * allowed to report an error. */
            ovs_assert(&replica->node == txn->db->replicas.next);

            ovsdb_txn_abort(txn);
            return error;
        }
    }

    /* Finalize commit. */
    txn->db->run_triggers = true;
    ovsdb_error_assert(for_each_txn_row(txn, ovsdb_txn_update_weak_refs));
    ovsdb_error_assert(for_each_txn_row(txn, ovsdb_txn_row_commit));
    ovsdb_txn_free(txn);

    return NULL;
}

struct ovsdb_error *
ovsdb_txn_commit(struct ovsdb_txn *txn, bool durable)
{
   struct ovsdb_error *err;

   PERF(__func__, err = ovsdb_txn_commit_(txn, durable));
   return err;
}

void
ovsdb_txn_for_each_change(const struct ovsdb_txn *txn,
                          ovsdb_txn_row_cb_func *cb, void *aux)
{
    struct ovsdb_txn_table *t;
    struct ovsdb_txn_row *r;

    LIST_FOR_EACH (t, node, &txn->txn_tables) {
        HMAP_FOR_EACH (r, hmap_node, &t->txn_rows) {
            if ((r->old || r->new) && !cb(r->old, r->new, r->changed, aux)) {
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
        size_t i;

        table->txn_table = txn_table = xmalloc(sizeof *table->txn_table);
        txn_table->table = table;
        hmap_init(&txn_table->txn_rows);
        txn_table->serial = serial - 1;
        txn_table->txn_indexes = xmalloc(table->schema->n_indexes
                                         * sizeof *txn_table->txn_indexes);
        for (i = 0; i < table->schema->n_indexes; i++) {
            hmap_init(&txn_table->txn_indexes[i]);
        }
        ovs_list_push_back(&txn->txn_tables, &txn_table->node);
    }
    return table->txn_table;
}

static struct ovsdb_txn_row *
ovsdb_txn_row_create(struct ovsdb_txn *txn, struct ovsdb_table *table,
                     const struct ovsdb_row *old_, struct ovsdb_row *new)
{
    const struct ovsdb_row *row = old_ ? old_ : new;
    struct ovsdb_row *old = CONST_CAST(struct ovsdb_row *, old_);
    size_t n_columns = shash_count(&table->schema->columns);
    struct ovsdb_txn_table *txn_table;
    struct ovsdb_txn_row *txn_row;

    txn_row = xzalloc(offsetof(struct ovsdb_txn_row, changed)
                      + bitmap_n_bytes(n_columns));
    txn_row->uuid = *ovsdb_row_get_uuid(row);
    txn_row->table = row->table;
    txn_row->old = old;
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
    struct ovsdb_row *ro_row = CONST_CAST(struct ovsdb_row *, ro_row_);

    if (ro_row->txn_row) {
        ovs_assert(ro_row == ro_row->txn_row->new);
        return ro_row;
    } else {
        struct ovsdb_table *table = ro_row->table;
        struct ovsdb_row *rw_row;

        rw_row = ovsdb_row_clone(ro_row);
        rw_row->n_refs = ro_row->n_refs;
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
    struct ovsdb_row *row = CONST_CAST(struct ovsdb_row *, row_);
    struct ovsdb_table *table = row->table;
    struct ovsdb_txn_row *txn_row = row->txn_row;

    hmap_remove(&table->rows, &row->hmap_node);

    if (!txn_row) {
        ovsdb_txn_row_create(txn, table, row, NULL);
    } else {
        ovs_assert(txn_row->new == row);
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
    struct ovsdb_txn_table *txn_table = txn_row->table->txn_table;

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
    size_t i;

    ovs_assert(hmap_is_empty(&txn_table->txn_rows));

    for (i = 0; i < txn_table->table->schema->n_indexes; i++) {
        hmap_destroy(&txn_table->txn_indexes[i]);
    }
    free(txn_table->txn_indexes);

    txn_table->table->txn_table = NULL;
    hmap_destroy(&txn_table->txn_rows);
    ovs_list_remove(&txn_table->node);
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
 *
 * (Even though 'cb' is not allowed to delete some txn_rows, it can still
 * delete any actual row by clearing a txn_row's 'new' member.)
 */
static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
for_each_txn_row(struct ovsdb_txn *txn,
                 struct ovsdb_error *(*cb)(struct ovsdb_txn *,
                                           struct ovsdb_txn_row *))
{
    bool any_work;

    serial++;

    do {
        struct ovsdb_txn_table *t, *next_txn_table;

        any_work = false;
        LIST_FOR_EACH_SAFE (t, next_txn_table, node, &txn->txn_tables) {
            if (t->serial != serial) {
                t->serial = serial;
                t->n_processed = 0;
            }

            while (t->n_processed < hmap_count(&t->txn_rows)) {
                struct ovsdb_txn_row *r, *next_txn_row;

                HMAP_FOR_EACH_SAFE (r, next_txn_row, hmap_node, &t->txn_rows) {
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
