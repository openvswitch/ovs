/* Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 * Copyright (C) 2016, IBM
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef OVSDB_SET_OP_H
#define OVSDB_SET_OP_H 1

#include "ovsdb-data.h"

enum set_op_type {
    SET_OP_INSERT,
    SET_OP_DELETE
};

struct set_op; /* Set Operation: a Partial Set Update */
struct set_op_list; /* List of Set Operations */

/* Set Operation functions */
struct set_op *set_op_create(struct ovsdb_datum *, enum set_op_type);
void set_op_destroy(struct set_op *, const struct ovsdb_type *);
struct ovsdb_datum *set_op_datum(const struct set_op*);
enum set_op_type set_op_type(const struct set_op*);

/* Set Operation List functions */
struct set_op_list *set_op_list_create(void);
void set_op_list_destroy(struct set_op_list *, const struct ovsdb_type *);
void set_op_list_add(struct set_op_list *, struct set_op *,
                     const struct ovsdb_type *);
struct set_op *set_op_list_first(struct set_op_list *);
struct set_op *set_op_list_next(struct set_op_list *, struct set_op *);

#endif /* ovsdb-set-op.h */
