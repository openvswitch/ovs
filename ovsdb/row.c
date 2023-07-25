/* Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include "row.h"

#include <stddef.h>

#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/shash.h"
#include "ovsdb-error.h"
#include "ovsdb.h"
#include "sort.h"
#include "table.h"
#include "util.h"

static struct ovsdb_row *
allocate_row(const struct ovsdb_table *table)
{
    size_t n_fields = shash_count(&table->schema->columns);
    size_t n_indexes = table->schema->n_indexes;
    size_t row_size = (offsetof(struct ovsdb_row, fields)
                       + sizeof(struct ovsdb_datum) * n_fields
                       + sizeof(struct hmap_node) * n_indexes);
    struct ovsdb_row *row = xmalloc(row_size);
    row->table = CONST_CAST(struct ovsdb_table *, table);
    row->txn_row = NULL;
    hmap_init(&row->dst_refs);
    row->n_refs = 0;
    return row;
}

/* Creates and returns a new row suitable for insertion into 'table'.  Does not
 * actually insert the row into 'table' (use ovsdb_txn_row_insert()).  The
 * caller must assign a UUID to the row. */
struct ovsdb_row *
ovsdb_row_create(const struct ovsdb_table *table)
{
    struct shash_node *node;
    struct ovsdb_row *row;

    row = allocate_row(table);
    SHASH_FOR_EACH (node, &table->schema->columns) {
        const struct ovsdb_column *column = node->data;
        ovsdb_datum_init_default(&row->fields[column->index], &column->type);
    }
    return row;
}

static struct ovsdb_weak_ref *
ovsdb_weak_ref_clone(struct ovsdb_weak_ref *src)
{
    struct ovsdb_weak_ref *weak = xzalloc(sizeof *weak);

    hmap_node_nullify(&weak->dst_node);
    ovs_list_init(&weak->src_node);
    weak->src_table = src->src_table;
    weak->src = src->src;
    weak->dst_table = src->dst_table;
    weak->dst = src->dst;
    ovsdb_atom_clone(&weak->key, &src->key, src->type.key.type);
    if (src->type.value.type != OVSDB_TYPE_VOID) {
        ovsdb_atom_clone(&weak->value, &src->value, src->type.value.type);
    }
    ovsdb_type_clone(&weak->type, &src->type);
    weak->column_idx = src->column_idx;
    weak->by_key = src->by_key;
    n_weak_refs++;
    return weak;
}

uint32_t
ovsdb_weak_ref_hash(const struct ovsdb_weak_ref *weak)
{
    return uuid_hash(&weak->src);
}

static bool
ovsdb_weak_ref_equals(const struct ovsdb_weak_ref *a,
                      const struct ovsdb_weak_ref *b)
{
    if (a == b) {
        return true;
    }
    return a->src_table == b->src_table
           && a->dst_table == b->dst_table
           && uuid_equals(&a->src, &b->src)
           && uuid_equals(&a->dst, &b->dst)
           && a->column_idx == b->column_idx
           && a->by_key == b->by_key
           && ovsdb_atom_equals(&a->key, &b->key, a->type.key.type);
}

struct ovsdb_weak_ref *
ovsdb_row_find_weak_ref(const struct ovsdb_row *row,
                        const struct ovsdb_weak_ref *ref)
{
    struct ovsdb_weak_ref *weak;
    HMAP_FOR_EACH_WITH_HASH (weak, dst_node,
                             ovsdb_weak_ref_hash(ref), &row->dst_refs) {
        if (ovsdb_weak_ref_equals(weak, ref)) {
            return weak;
        }
    }
    return NULL;
}

void
ovsdb_weak_ref_destroy(struct ovsdb_weak_ref *weak)
{
    if (!weak) {
        return;
    }
    ovs_assert(ovs_list_is_empty(&weak->src_node));
    ovsdb_atom_destroy(&weak->key, weak->type.key.type);
    if (weak->type.value.type != OVSDB_TYPE_VOID) {
        ovsdb_atom_destroy(&weak->value, weak->type.value.type);
    }
    ovsdb_type_destroy(&weak->type);
    free(weak);
    n_weak_refs--;
}

struct ovsdb_row *
ovsdb_row_clone(const struct ovsdb_row *old)
{
    const struct ovsdb_table *table = old->table;
    const struct shash_node *node;
    struct ovsdb_row *new;

    new = allocate_row(table);
    SHASH_FOR_EACH (node, &table->schema->columns) {
        const struct ovsdb_column *column = node->data;
        ovsdb_datum_clone(&new->fields[column->index],
                          &old->fields[column->index]);
    }

    struct ovsdb_weak_ref *weak, *clone;
    HMAP_FOR_EACH (weak, dst_node, &old->dst_refs) {
        clone = ovsdb_weak_ref_clone(weak);
        hmap_insert(&new->dst_refs, &clone->dst_node,
                    ovsdb_weak_ref_hash(clone));
    }
    return new;
}

struct ovsdb_row *
ovsdb_row_datum_clone(const struct ovsdb_row *old)
{
    const struct ovsdb_table *table = old->table;
    const struct shash_node *node;
    struct ovsdb_row *new;

    new = allocate_row(table);
    SHASH_FOR_EACH (node, &table->schema->columns) {
        const struct ovsdb_column *column = node->data;
        ovsdb_datum_clone(&new->fields[column->index],
                          &old->fields[column->index]);
    }
    return new;
}


/* The caller is responsible for ensuring that 'row' has been removed from its
 * table and that it is not participating in a transaction. */
void
ovsdb_row_destroy(struct ovsdb_row *row)
{
    if (row) {
        const struct ovsdb_table *table = row->table;
        struct ovsdb_weak_ref *weak;
        const struct shash_node *node;

        HMAP_FOR_EACH_POP (weak, dst_node, &row->dst_refs) {
            ovsdb_weak_ref_destroy(weak);
        }
        hmap_destroy(&row->dst_refs);

        SHASH_FOR_EACH (node, &table->schema->columns) {
            const struct ovsdb_column *column = node->data;
            ovsdb_datum_destroy(&row->fields[column->index], &column->type);
        }
        free(row);
    }
}

uint32_t
ovsdb_row_hash_columns(const struct ovsdb_row *row,
                       const struct ovsdb_column_set *columns,
                       uint32_t basis)
{
    size_t i;

    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];
        basis = ovsdb_datum_hash(&row->fields[column->index], &column->type,
                                 basis);
    }

    return basis;
}

int
ovsdb_row_compare_columns_3way(const struct ovsdb_row *a,
                               const struct ovsdb_row *b,
                               const struct ovsdb_column_set *columns)
{
    size_t i;

    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];
        int cmp = ovsdb_datum_compare_3way(&a->fields[column->index],
                                           &b->fields[column->index],
                                           &column->type);
        if (cmp) {
            return cmp;
        }
    }

    return 0;
}

bool
ovsdb_row_equal_columns(const struct ovsdb_row *a,
                        const struct ovsdb_row *b,
                        const struct ovsdb_column_set *columns)
{
    size_t i;

    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];
        if (!ovsdb_datum_equals(&a->fields[column->index],
                                &b->fields[column->index],
                                &column->type)) {
            return false;
        }
    }

    return true;
}

struct ovsdb_error *
ovsdb_row_update_columns(struct ovsdb_row *dst,
                         const struct ovsdb_row *src,
                         const struct ovsdb_column_set *columns,
                         bool xor)
{
    size_t i;

    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];
        struct ovsdb_error *error;

        if (xor) {
            error = ovsdb_datum_apply_diff_in_place(
                            &dst->fields[column->index],
                            &src->fields[column->index],
                            &column->type);
            if (error) {
                return error;
            }
        } else {
            ovsdb_datum_destroy(&dst->fields[column->index], &column->type);
            ovsdb_datum_clone(&dst->fields[column->index],
                              &src->fields[column->index]);
        }
    }
    return NULL;
}

/* Appends the string form of the value in 'row' of each of the columns in
 * 'columns' to 'out', e.g. "1, \"xyz\", and [1, 2, 3]". */
void
ovsdb_row_columns_to_string(const struct ovsdb_row *row,
                            const struct ovsdb_column_set *columns,
                            struct ds *out)
{
    size_t i;

    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];

        ds_put_cstr(out, english_list_delimiter(i, columns->n_columns));
        ovsdb_datum_to_string(&row->fields[column->index], &column->type, out);
    }
}

struct ovsdb_error *
ovsdb_row_from_json(struct ovsdb_row *row, const struct json *json,
                    struct ovsdb_symbol_table *symtab,
                    struct ovsdb_column_set *included, bool is_diff)
{
    struct ovsdb_table_schema *schema = row->table->schema;
    struct ovsdb_error *error;
    struct shash_node *node;

    ovs_assert(!is_diff || !symtab);

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "row must be JSON object");
    }

    SHASH_FOR_EACH (node, json_object(json)) {
        const char *column_name = node->name;
        const struct ovsdb_column *column;
        struct ovsdb_datum datum;

        column = ovsdb_table_schema_get_column(schema, column_name);
        if (!column) {
            return ovsdb_syntax_error(json, "unknown column",
                                      "No column %s in table %s.",
                                      column_name, schema->name);
        }

        if (is_diff) {
            error = ovsdb_transient_datum_from_json(&datum, &column->type,
                                                    node->data);
        } else {
            error = ovsdb_datum_from_json(&datum, &column->type, node->data,
                                          symtab);
        }
        if (error) {
            return error;
        }
        ovsdb_datum_swap(&row->fields[column->index], &datum);
        ovsdb_datum_destroy(&datum, &column->type);
        if (included) {
            ovsdb_column_set_add(included, column);
        }
    }

    return NULL;
}

static void
put_json_column(struct json *object, const struct ovsdb_row *row,
                const struct ovsdb_column *column)
{
    json_object_put(object, column->name,
                    ovsdb_datum_to_json(&row->fields[column->index],
                                        &column->type));
}

struct json *
ovsdb_row_to_json(const struct ovsdb_row *row,
                  const struct ovsdb_column_set *columns)
{
    struct json *json;
    size_t i;

    json = json_object_create();
    for (i = 0; i < columns->n_columns; i++) {
        put_json_column(json, row, columns->columns[i]);
    }
    return json;
}

void
ovsdb_row_to_string(const struct ovsdb_row *row, struct ds *out)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &row->table->schema->columns) {
        const struct ovsdb_column *column = node->data;

        ds_put_format(out, "%s:", column->name);
        ovsdb_datum_to_string(&row->fields[column->index], &column->type, out);
        ds_put_char(out, ',');
    }
    if (shash_count(&row->table->schema->columns)) {
        ds_chomp(out, ',');
    }
}

void
ovsdb_row_set_init(struct ovsdb_row_set *set)
{
    set->rows = NULL;
    set->n_rows = set->allocated_rows = 0;
}

void
ovsdb_row_set_destroy(struct ovsdb_row_set *set)
{
    free(set->rows);
}

void
ovsdb_row_set_add_row(struct ovsdb_row_set *set, const struct ovsdb_row *row)
{
    if (set->n_rows >= set->allocated_rows) {
        set->rows = x2nrealloc(set->rows, &set->allocated_rows,
                               sizeof *set->rows);
    }
    set->rows[set->n_rows++] = row;
}

struct json *
ovsdb_row_set_to_json(const struct ovsdb_row_set *rows,
                      const struct ovsdb_column_set *columns)
{
    struct json **json_rows;
    size_t i;

    json_rows = xmalloc(rows->n_rows * sizeof *json_rows);
    for (i = 0; i < rows->n_rows; i++) {
        json_rows[i] = ovsdb_row_to_json(rows->rows[i], columns);
    }
    return json_array_create(json_rows, rows->n_rows);
}

struct ovsdb_row_set_sort_cbdata {
    struct ovsdb_row_set *set;
    const struct ovsdb_column_set *columns;
};

static int
ovsdb_row_set_sort_compare_cb(size_t a, size_t b, void *cbdata_)
{
    struct ovsdb_row_set_sort_cbdata *cbdata = cbdata_;
    return ovsdb_row_compare_columns_3way(cbdata->set->rows[a],
                                          cbdata->set->rows[b],
                                          cbdata->columns);
}

static void
ovsdb_row_set_sort_swap_cb(size_t a, size_t b, void *cbdata_)
{
    struct ovsdb_row_set_sort_cbdata *cbdata = cbdata_;
    const struct ovsdb_row *tmp = cbdata->set->rows[a];
    cbdata->set->rows[a] = cbdata->set->rows[b];
    cbdata->set->rows[b] = tmp;
}

void
ovsdb_row_set_sort(struct ovsdb_row_set *set,
                   const struct ovsdb_column_set *columns)
{
    if (columns && columns->n_columns && set->n_rows > 1) {
        struct ovsdb_row_set_sort_cbdata cbdata;
        cbdata.set = set;
        cbdata.columns = columns;
        sort(set->n_rows,
             ovsdb_row_set_sort_compare_cb,
             ovsdb_row_set_sort_swap_cb,
             &cbdata);
    }
}

void
ovsdb_row_hash_init(struct ovsdb_row_hash *rh,
                    const struct ovsdb_column_set *columns)
{
    hmap_init(&rh->rows);
    ovsdb_column_set_clone(&rh->columns, columns);
}

void
ovsdb_row_hash_destroy(struct ovsdb_row_hash *rh, bool destroy_rows)
{
    struct ovsdb_row_hash_node *node;

    HMAP_FOR_EACH_POP (node, hmap_node, &rh->rows) {
        if (destroy_rows) {
            ovsdb_row_destroy(CONST_CAST(struct ovsdb_row *, node->row));
        }
        free(node);
    }
    hmap_destroy(&rh->rows);
    ovsdb_column_set_destroy(&rh->columns);
}

size_t
ovsdb_row_hash_count(const struct ovsdb_row_hash *rh)
{
    return hmap_count(&rh->rows);
}

bool
ovsdb_row_hash_contains(const struct ovsdb_row_hash *rh,
                        const struct ovsdb_row *row)
{
    size_t hash = ovsdb_row_hash_columns(row, &rh->columns, 0);
    return ovsdb_row_hash_contains__(rh, row, hash);
}

/* Returns true if every row in 'b' has an equal row in 'a'. */
bool
ovsdb_row_hash_contains_all(const struct ovsdb_row_hash *a,
                            const struct ovsdb_row_hash *b)
{
    struct ovsdb_row_hash_node *node;

    ovs_assert(ovsdb_column_set_equals(&a->columns, &b->columns));
    HMAP_FOR_EACH (node, hmap_node, &b->rows) {
        if (!ovsdb_row_hash_contains__(a, node->row, node->hmap_node.hash)) {
            return false;
        }
    }
    return true;
}

bool
ovsdb_row_hash_insert(struct ovsdb_row_hash *rh, const struct ovsdb_row *row)
{
    size_t hash = ovsdb_row_hash_columns(row, &rh->columns, 0);
    return ovsdb_row_hash_insert__(rh, row, hash);
}

bool
ovsdb_row_hash_contains__(const struct ovsdb_row_hash *rh,
                          const struct ovsdb_row *row, size_t hash)
{
    struct ovsdb_row_hash_node *node;
    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash, &rh->rows) {
        if (ovsdb_row_equal_columns(row, node->row, &rh->columns)) {
            return true;
        }
    }
    return false;
}

bool
ovsdb_row_hash_insert__(struct ovsdb_row_hash *rh, const struct ovsdb_row *row,
                        size_t hash)
{
    if (!ovsdb_row_hash_contains__(rh, row, hash)) {
        struct ovsdb_row_hash_node *node = xmalloc(sizeof *node);
        node->row = row;
        hmap_insert(&rh->rows, &node->hmap_node, hash);
        return true;
    } else {
        return false;
    }
}
