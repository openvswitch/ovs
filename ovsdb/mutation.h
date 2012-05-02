/* Copyright (c) 2009, 2010, 2011 Nicira, Inc.
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

#ifndef OVSDB_MUTATION_H
#define OVSDB_MUTATION_H 1

#include <stddef.h>
#include "compiler.h"
#include "ovsdb-data.h"

struct json;
struct ovsdb_table_schema;
struct ovsdb_row;

/* These list is ordered in ascending order of the fraction of tables row that
 * they are (heuristically) expected to leave in query results. */
#define OVSDB_MUTATORS                              \
    OVSDB_MUTATOR(OVSDB_M_ADD, "+=")                \
    OVSDB_MUTATOR(OVSDB_M_SUB, "-=")                \
    OVSDB_MUTATOR(OVSDB_M_MUL, "*=")                \
    OVSDB_MUTATOR(OVSDB_M_DIV, "/=")                \
    OVSDB_MUTATOR(OVSDB_M_MOD, "%=")                \
    OVSDB_MUTATOR(OVSDB_M_INSERT, "insert")         \
    OVSDB_MUTATOR(OVSDB_M_DELETE, "delete")

enum ovsdb_mutator {
#define OVSDB_MUTATOR(ENUM, NAME) ENUM,
    OVSDB_MUTATORS
#undef OVSDB_MUTATOR
};

struct ovsdb_error *ovsdb_mutator_from_string(const char *,
                                              enum ovsdb_mutator *)
    WARN_UNUSED_RESULT;
const char *ovsdb_mutator_to_string(enum ovsdb_mutator);

struct ovsdb_mutation {
    enum ovsdb_mutator mutator;
    const struct ovsdb_column *column;
    struct ovsdb_datum arg;
    struct ovsdb_type type;
};

struct ovsdb_mutation_set {
    struct ovsdb_mutation *mutations;
    size_t n_mutations;
};

#define OVSDB_MUTATION_SET_INITIALIZER { NULL, 0 }

struct ovsdb_error *ovsdb_mutation_set_from_json(
    const struct ovsdb_table_schema *,
    const struct json *, struct ovsdb_symbol_table *,
    struct ovsdb_mutation_set *) WARN_UNUSED_RESULT;
struct json *ovsdb_mutation_set_to_json(const struct ovsdb_mutation_set *);
void ovsdb_mutation_set_destroy(struct ovsdb_mutation_set *);
struct ovsdb_error *ovsdb_mutation_set_execute(
    struct ovsdb_row *, const struct ovsdb_mutation_set *) WARN_UNUSED_RESULT;

#endif /* ovsdb/mutation.h */
