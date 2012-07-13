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

#include <assert.h>
#include <stddef.h>

#include "dynamic-string.h"
#include "json.h"
#include "ovsdb-error.h"
#include "shash.h"
#include "sort.h"
#include "table.h"

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
    list_init(&row->src_refs);
    list_init(&row->dst_refs);
    row->n_refs = 0;
    return row;
}

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
                          &old->fields[column->index],
                          &column->type);
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
        struct ovsdb_weak_ref *weak, *next;
        const struct shash_node *node;

        LIST_FOR_EACH_SAFE (weak, next, dst_node, &row->dst_refs) {
            list_remove(&weak->src_node);
            list_remove(&weak->dst_node);
            free(weak);
        }

        LIST_FOR_EACH_SAFE (weak, next, src_node, &row->src_refs) {
            list_remove(&weak->src_node);
            list_remove(&weak->dst_node);
            free(weak);
        }

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

void
ovsdb_row_update_columns(struct ovsdb_row *dst,
                         const struct ovsdb_row *src,
                         const struct ovsdb_column_set *columns)
{
    size_t i;

    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];
        ovsdb_datum_destroy(&dst->fields[column->index], &column->type);
        ovsdb_datum_clone(&dst->fields[column->index],
                          &src->fields[column->index],
                          &column->type);
    }
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
                    struct ovsdb_column_set *included)
{
    struct ovsdb_table_schema *schema = row->table->schema;
    struct ovsdb_error *error;
    struct shash_node *node;

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

        error = ovsdb_datum_from_json(&datum, &column->type, node->data,
                                      symtab);
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
    struct ovsdb_row_hash_node *node, *next;

    HMAP_FOR_EACH_SAFE (node, next, hmap_node, &rh->rows) {
        hmap_remove(&rh->rows, &node->hmap_node);
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

    assert(ovsdb_column_set_equals(&a->columns, &b->columns));
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
