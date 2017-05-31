/*
 * Copyright (c) 2017 Red Hat, Inc.
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

#ifndef OVSDB_RBAC_H
#define OVSDB_RBAC_H 1

#include <stdbool.h>

struct ovsdb;
struct ovsdb_column_set;
struct ovsdb_condition;
struct ovsdb_mutation_set;
struct ovsdb_row;
struct ovsdb_table;

bool ovsdb_rbac_insert(const struct ovsdb *,
                       const struct ovsdb_table *,
                       const struct ovsdb_row *,
                       const char *role, const char *id);
bool ovsdb_rbac_delete(const struct ovsdb *,
                       struct ovsdb_table *,
                       struct ovsdb_condition *,
                       const char *role, const char *id);
bool ovsdb_rbac_update(const struct ovsdb *,
                       struct ovsdb_table *,
                       struct ovsdb_column_set *,
                       struct ovsdb_condition *condition,
                       const char *role, const char *id);
bool ovsdb_rbac_mutate(const struct ovsdb *,
                       struct ovsdb_table *,
                       struct ovsdb_mutation_set *,
                       struct ovsdb_condition *,
                       const char *role, const char *id);

#endif /* ovsdb/rbac.h */
