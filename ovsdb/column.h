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

#ifndef OVSDB_COLUMN_H
#define OVSDB_COLUMN_H 1

#include <stdbool.h>
#include "compiler.h"
#include "ovsdb-types.h"

struct ovsdb_table;
struct ovsdb_table_schema;

/* A column or a column schema (currently there is no distinction). */
struct ovsdb_column {
    unsigned int index;
    char *name;

    bool mutable;
    bool persistent;
    struct ovsdb_type type;
};

/* A few columns appear in every table with standardized column indexes.
 * These macros define those columns' indexes.
 *
 * Don't change these values, because ovsdb_query() depends on OVSDB_COL_UUID
 * having value 0. */
enum {
    OVSDB_COL_UUID = 0,         /* UUID for the row. */
    OVSDB_COL_VERSION = 1,      /* Version number for the row. */
    OVSDB_N_STD_COLUMNS
};

struct ovsdb_column *ovsdb_column_create(
    const char *name, bool mutable, bool persistent,
    const struct ovsdb_type *);
struct ovsdb_column *ovsdb_column_clone(const struct ovsdb_column *);
void ovsdb_column_destroy(struct ovsdb_column *);

struct ovsdb_error *ovsdb_column_from_json(const struct json *,
                                           const char *name,
                                           struct ovsdb_column **)
    WARN_UNUSED_RESULT;
struct json *ovsdb_column_to_json(const struct ovsdb_column *);

/* An unordered set of distinct columns. */

struct ovsdb_column_set {
    const struct ovsdb_column **columns;
    size_t n_columns, allocated_columns;
};

#define OVSDB_COLUMN_SET_INITIALIZER { NULL, 0, 0 }

void ovsdb_column_set_init(struct ovsdb_column_set *);
void ovsdb_column_set_destroy(struct ovsdb_column_set *);
void ovsdb_column_set_clone(struct ovsdb_column_set *,
                            const struct ovsdb_column_set *);
struct ovsdb_error *ovsdb_column_set_from_json(
    const struct json *, const struct ovsdb_table_schema *,
    struct ovsdb_column_set *);
struct json *ovsdb_column_set_to_json(const struct ovsdb_column_set *);
char *ovsdb_column_set_to_string(const struct ovsdb_column_set *);

void ovsdb_column_set_add(struct ovsdb_column_set *,
                          const struct ovsdb_column *);
void ovsdb_column_set_add_all(struct ovsdb_column_set *,
                              const struct ovsdb_table *);
bool ovsdb_column_set_contains(const struct ovsdb_column_set *,
                               unsigned int column_index);
bool ovsdb_column_set_equals(const struct ovsdb_column_set *,
                             const struct ovsdb_column_set *);

#endif /* column.h */
