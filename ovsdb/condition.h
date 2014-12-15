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

struct json;
struct ovsdb_table_schema;
struct ovsdb_row;

/* These list is ordered in ascending order of the fraction of tables row that
 * they are (heuristically) expected to leave in query results. */
#define OVSDB_FUNCTIONS                         \
    OVSDB_FUNCTION(OVSDB_F_EQ, "==")                  \
    OVSDB_FUNCTION(OVSDB_F_INCLUDES, "includes")      \
    OVSDB_FUNCTION(OVSDB_F_LE, "<=")                  \
    OVSDB_FUNCTION(OVSDB_F_LT, "<")                   \
    OVSDB_FUNCTION(OVSDB_F_GE, ">=")                  \
    OVSDB_FUNCTION(OVSDB_F_GT, ">")                   \
    OVSDB_FUNCTION(OVSDB_F_EXCLUDES, "excludes")      \
    OVSDB_FUNCTION(OVSDB_F_NE, "!=")

enum ovsdb_function {
#define OVSDB_FUNCTION(ENUM, NAME) ENUM,
    OVSDB_FUNCTIONS
#undef OVSDB_FUNCTION
};

struct ovsdb_error *ovsdb_function_from_string(const char *,
                                               enum ovsdb_function *)
    OVS_WARN_UNUSED_RESULT;
const char *ovsdb_function_to_string(enum ovsdb_function);

struct ovsdb_clause {
    enum ovsdb_function function;
    const struct ovsdb_column *column;
    struct ovsdb_datum arg;
};

struct ovsdb_condition {
    struct ovsdb_clause *clauses;
    size_t n_clauses;
};

#define OVSDB_CONDITION_INITIALIZER { NULL, 0 }

struct ovsdb_error *ovsdb_condition_from_json(
    const struct ovsdb_table_schema *,
    const struct json *, struct ovsdb_symbol_table *,
    struct ovsdb_condition *) OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_condition_to_json(const struct ovsdb_condition *);
void ovsdb_condition_destroy(struct ovsdb_condition *);
bool ovsdb_condition_evaluate(const struct ovsdb_row *,
                              const struct ovsdb_condition *);

#endif /* ovsdb/condition.h */
