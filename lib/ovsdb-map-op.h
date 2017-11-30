/* Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef OVSDB_MAP_OP_H
#define OVSDB_MAP_OP_H 1

#include "ovsdb-data.h"

#ifdef __cplusplus
extern "C" {
#endif

enum map_op_type {
    MAP_OP_UPDATE,
    MAP_OP_INSERT,
    MAP_OP_DELETE
};

struct map_op; /* Map Operation: a Partial Map Update */
struct map_op_list; /* List of Map Operations */

/* Map Operation functions */
struct map_op *map_op_create(struct ovsdb_datum *, enum map_op_type);
void map_op_destroy(struct map_op *, const struct ovsdb_type *);
struct ovsdb_datum *map_op_datum(const struct map_op*);
enum map_op_type map_op_type(const struct map_op*);

/* Map Operation List functions */
struct map_op_list *map_op_list_create(void);
void map_op_list_destroy(struct map_op_list *, const struct ovsdb_type *);
void map_op_list_add(struct map_op_list *, struct map_op *,
                     const struct ovsdb_type *);
struct map_op *map_op_list_first(struct map_op_list *);
struct map_op *map_op_list_next(struct map_op_list *, struct map_op *);

#ifdef __cplusplus
}
#endif

#endif /* ovsdb-map-op.h */
