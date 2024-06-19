/* Copyright (c) 2009, 2010 Nicira, Inc.
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

#include "query.h"

#include "column.h"
#include "condition.h"
#include "row.h"
#include "table.h"
#include "transaction.h"

struct txn_state {
    const struct ovsdb_condition *cnd;
    struct ovsdb_table *table;
    bool match;
};

static bool
search_txn(const struct ovsdb_row *old, const struct ovsdb_row *new,
           const unsigned long int *changed OVS_UNUSED, void *aux)
{
    struct txn_state *ts = aux;

    if (ts->match) {
        return false;
    }

    if (new && new->table == ts->table) {
        if (ovsdb_condition_match_every_clause(new, ts->cnd)) {
            ts->match = true;
            return false;
        }
    }

    if (old && old->table == ts->table) {
        if (ovsdb_condition_match_every_clause(old, ts->cnd)) {
            ts->match = true;
            return false;
        }
    }

    return true;
}

static bool
ovsdb_query_index(struct ovsdb_table *table,
                  const struct ovsdb_condition *cnd,
                  const struct ovsdb_row **out,
                  const struct ovsdb_txn *txn)
{
    size_t n_fields = shash_count(&table->schema->columns);
    struct ovsdb_row *row;
    bool ret = false;

    if (txn) {
        /* Check the transaction first. If a modified row matches the
         * conditions then bail out before an index search.  There are a lot of
         * different possible conditions and including support for returning
         * mid-transaction rows adds a lot of complications. */

        struct txn_state ts = {
            .cnd = cnd,
            .table = table,
            .match = false,
        };

        ovsdb_txn_for_each_change(txn, search_txn, &ts);

        if (ts.match) {
            return false;
        }
    }

    /* Construct a mock row. */
    row = xzalloc(sizeof *row + sizeof *row->fields * n_fields);
    row->table = table;

    for (size_t c = 0; c < cnd->n_clauses; c++) {
        const struct ovsdb_clause *cnd_cls = &cnd->clauses[c];

        if (cnd_cls->function != OVSDB_F_EQ) {
            goto done;
        }

        row->fields[cnd_cls->index] = cnd_cls->arg;
    }

    /* Per index search. */
    for (size_t idx = 0; idx < table->schema->n_indexes; idx++) {
        const struct ovsdb_column_set *index = &table->schema->indexes[idx];
        size_t matches = 0;
        size_t hash;

        if (index->n_columns > cnd->n_clauses) {
            /* Only index search if condition counts are greater or equal to
             * index length. */
            continue;
        }

        hash = 0;

        /* The conditions may not be in the same order as the index. */
        for (size_t i = 0; i < index->n_columns && matches == i; i++) {
            const struct ovsdb_column *idx_col = index->columns[i];

            if (row->fields[idx_col->index].n) {
                hash = ovsdb_datum_hash(&row->fields[idx_col->index],
                                        &idx_col->type, hash);
                matches++;
            }
        }

        if (matches != index->n_columns) {
            continue;
        }

        /* The index matches so a linear search isn't needed. */
        ret = true;

        /* The return code doesn't matter in this case, because this function
         * returns true on a suitable index instead of a matching key. */
        *out = ovsdb_index_search(&table->indexes[idx], row, idx, hash);

        /* If the index has fewer rows than the condition, verify that all
         * conditions are true. */
        if (*out && index->n_columns != cnd->n_clauses) {
            if (!ovsdb_condition_match_every_clause(*out, cnd)) {
                /* Non-index condition doesn't match. */
                *out = NULL;
            }
        }

        /* In the case that there was a matching index but no matching row, the
         * index check is still considered to be a success. */
        break;
    }

done:
    free(row);
    return ret;
}

void
ovsdb_query(struct ovsdb_table *table, const struct ovsdb_condition *cnd,
            bool (*output_row)(const struct ovsdb_row *, void *aux), void *aux,
            const struct ovsdb_txn *txn)
{
    const struct ovsdb_row *row = NULL;

    if (cnd->n_clauses > 0
        && cnd->clauses[0].column->index == OVSDB_COL_UUID
        && cnd->clauses[0].function == OVSDB_F_EQ) {
        /* Optimize the case where the query has a clause of the form "uuid ==
         * <some-uuid>", since we have an index on UUID. */

        row = ovsdb_table_get_row(table, &cnd->clauses[0].arg.keys[0].uuid);
        if (row && row->table == table &&
            ovsdb_condition_match_every_clause(row, cnd)) {
            output_row(row, aux);
        }
        return;
    }

    /* Check the indexes. */
    if (ovsdb_query_index(table, cnd, &row, txn)) {
        if (row) {
            output_row(row, aux);
            return;
        }
        return;
    }

    /* Linear scan. */
    HMAP_FOR_EACH_SAFE (row, hmap_node, &table->rows) {
        if (ovsdb_condition_match_every_clause(row, cnd) &&
            !output_row(row, aux)) {
            break;
        }
    }
}

static bool
query_row_set_cb(const struct ovsdb_row *row, void *results_)
{
    struct ovsdb_row_set *results = results_;
    ovsdb_row_set_add_row(results, row);
    return true;
}

void
ovsdb_query_row_set(struct ovsdb_table *table,
                    const struct ovsdb_condition *condition,
                    struct ovsdb_row_set *results,
                    const struct ovsdb_txn *txn)
{
    ovsdb_query(table, condition, query_row_set_cb, results, txn);
}

static bool
query_distinct_cb(const struct ovsdb_row *row, void *hash_)
{
    struct ovsdb_row_hash *hash = hash_;
    ovsdb_row_hash_insert(hash, row);
    return true;
}

void
ovsdb_query_distinct(struct ovsdb_table *table,
                     const struct ovsdb_condition *condition,
                     const struct ovsdb_column_set *columns,
                     struct ovsdb_row_set *results,
                     const struct ovsdb_txn *txn)
{
    if (!columns || ovsdb_column_set_contains(columns, OVSDB_COL_UUID)) {
        /* All the result rows are guaranteed to be distinct anyway. */
        ovsdb_query_row_set(table, condition, results, txn);
        return;
    } else {
        /* Use hash table to drop duplicates. */
        struct ovsdb_row_hash_node *node;
        struct ovsdb_row_hash hash;

        ovsdb_row_hash_init(&hash, columns);
        ovsdb_query(table, condition, query_distinct_cb, &hash, txn);
        HMAP_FOR_EACH (node, hmap_node, &hash.rows) {
            ovsdb_row_set_add_row(results, node->row);
        }
        ovsdb_row_hash_destroy(&hash, false);
    }
}
