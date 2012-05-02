/* Copyright (c) 2009 Nicira, Inc.
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

#ifndef OVSDB_QUERY_H
#define OVSDB_QUERY_H 1

#include <stdbool.h>

struct ovsdb_column_set;
struct ovsdb_condition;
struct ovsdb_row;
struct ovsdb_row_set;
struct ovsdb_table;
struct ovsdb_txn;

void ovsdb_query(struct ovsdb_table *, const struct ovsdb_condition *,
                 bool (*output_row)(const struct ovsdb_row *, void *aux),
                 void *aux);
void ovsdb_query_row_set(struct ovsdb_table *, const struct ovsdb_condition *,
                         struct ovsdb_row_set *);
void ovsdb_query_distinct(struct ovsdb_table *, const struct ovsdb_condition *,
                          const struct ovsdb_column_set *,
                          struct ovsdb_row_set *);

#endif /* ovsdb/query.h */
