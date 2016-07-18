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

#ifndef OVSDB_CONDITION_H
#define OVSDB_CONDITION_H 1

#include <stddef.h>
#include "compiler.h"
#include "ovsdb-data.h"
#include "bitmap.h"
#include "ovsdb-condition.h"

struct json;
struct ovsdb_table_schema;
struct ovsdb_row;

struct ovsdb_clause {
    enum ovsdb_function function;
    const struct ovsdb_column *column;
    unsigned int index;
    struct ovsdb_datum arg;
};

struct ovsdb_condition {
    struct ovsdb_clause *clauses;
    size_t n_clauses;
    bool optimized;
    struct shash o_columns;
};

#define OVSDB_CONDITION_INITIALIZER(COND) \
    { NULL, 0, true, SHASH_INITIALIZER(&(COND)->o_columns)}

void ovsdb_condition_init(struct ovsdb_condition *);
bool ovsdb_condition_empty(const struct ovsdb_condition *);
struct ovsdb_error *ovsdb_condition_from_json(
    const struct ovsdb_table_schema *,
    const struct json *, struct ovsdb_symbol_table *,
    struct ovsdb_condition *) OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_condition_to_json(const struct ovsdb_condition *);
void ovsdb_condition_destroy(struct ovsdb_condition *);
bool ovsdb_condition_match_every_clause(const struct ovsdb_row *,
                                        const struct ovsdb_condition *);
bool ovsdb_condition_match_any_clause(const struct ovsdb_datum *,
                                      const struct ovsdb_condition *,
                                      unsigned int index_map[]);
int ovsdb_condition_cmp_3way(const struct ovsdb_condition *a,
                             const struct ovsdb_condition *b);
void ovsdb_condition_clone(struct ovsdb_condition *to,
                           const struct ovsdb_condition *from);
bool ovsdb_condition_is_true(const struct ovsdb_condition *cond);
bool ovsdb_condition_is_false(const struct ovsdb_condition *cond);
const struct ovsdb_column **
ovsdb_condition_get_columns(const struct ovsdb_condition *cond,
                            size_t *n_columns);

static inline bool
ovsdb_condition_empty_or_match_any(const struct ovsdb_datum *row_datum,
                                   const struct ovsdb_condition *cnd,
                                   unsigned int index_map[])
{
    return (ovsdb_condition_empty(cnd) ||
            ovsdb_condition_match_any_clause(row_datum, cnd, index_map));
}

#endif /* ovsdb/condition.h */
