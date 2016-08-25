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

#include <config.h>
#include "ovsdb-set-op.h"
#include "util.h"

/* Set Operation: a Partial Set Update */
struct set_op {
    struct hmap_node node;
    struct ovsdb_datum *datum;
    enum set_op_type type;
};

/* List of Set Operations */
struct set_op_list {
    struct hmap hmap;
};

static void set_op_destroy_datum(struct set_op *, const struct ovsdb_type *);
static struct set_op *set_op_list_find(struct set_op_list *, struct set_op *,
                                       const struct ovsdb_type *, size_t);

struct set_op*
set_op_create(struct ovsdb_datum *datum, enum set_op_type type)
{
    struct set_op *set_op = xmalloc(sizeof *set_op);
    set_op->node.hash = 0;
    set_op->node.next = HMAP_NODE_NULL;
    set_op->datum = datum;
    set_op->type = type;
    return set_op;
}

static void
set_op_destroy_datum(struct set_op *set_op, const struct ovsdb_type *type)
{
    if (set_op->type == SET_OP_DELETE){
        struct ovsdb_type type_ = *type;
        type_.value.type = OVSDB_TYPE_VOID;
        ovsdb_datum_destroy(set_op->datum, &type_);
    } else {
        ovsdb_datum_destroy(set_op->datum, type);
    }
    free(set_op->datum);
    set_op->datum = NULL;
}

void
set_op_destroy(struct set_op *set_op, const struct ovsdb_type *type)
{
    set_op_destroy_datum(set_op, type);
    free(set_op);
}

struct ovsdb_datum*
set_op_datum(const struct set_op *set_op)
{
    return set_op->datum;
}

enum set_op_type
set_op_type(const struct set_op *set_op)
{
    return set_op->type;
}

struct set_op_list*
set_op_list_create(void)
{
    struct set_op_list *list = xmalloc(sizeof *list);
    hmap_init(&list->hmap);
    return list;
}

void
set_op_list_destroy(struct set_op_list *list, const struct ovsdb_type *type)
{
    struct set_op *set_op, *next;
    HMAP_FOR_EACH_SAFE (set_op, next, node, &list->hmap) {
        set_op_destroy(set_op, type);
    }
    hmap_destroy(&list->hmap);
    free(list);
}

static struct set_op*
set_op_list_find(struct set_op_list *list, struct set_op *set_op,
                 const struct ovsdb_type *type, size_t hash)
{
    struct set_op *found = NULL;
    struct set_op *old;
    HMAP_FOR_EACH_WITH_HASH(old, node, hash, &list->hmap) {
        if (ovsdb_atom_equals(&old->datum->keys[0], &set_op->datum->keys[0],
                              type->key.type)) {
            found = old;
            break;
        }
    }
    return found;
}

/* Inserts 'set_op' into 'list'. Makes sure that any conflict with a previous
 * set operation is resolved, so only one set operation is possible on each key
 * per transactions. 'type' must be the type of the column over which the set
 * operation will be applied. */
void
set_op_list_add(struct set_op_list *list, struct set_op *set_op,
                const struct ovsdb_type *type)
{
    /* Check if there is a previous update with the same key. */
    size_t hash;
    struct set_op *prev_set_op;

    hash = ovsdb_atom_hash(&set_op->datum->keys[0], type->key.type, 0);
    prev_set_op = set_op_list_find(list, set_op, type, hash);
    if (prev_set_op == NULL){
        hmap_insert(&list->hmap, &set_op->node, hash);
    } else {
        if (prev_set_op->type == SET_OP_INSERT &&
            set_op->type == SET_OP_DELETE) {
            /* These operations cancel each other out. */
            hmap_remove(&list->hmap, &prev_set_op->node);
            set_op_destroy(prev_set_op, type);
            set_op_destroy(set_op, type);
        } else {
            /* For any other case, the new update operation replaces
             * the previous update operation. */
            set_op_destroy_datum(prev_set_op, type);
            prev_set_op->type = set_op->type;
            prev_set_op->datum = set_op->datum;
            free(set_op);
        }
    }
}

struct set_op*
set_op_list_first(struct set_op_list *list)
{
    struct hmap_node *node = hmap_first(&list->hmap);
    if (node == NULL) {
        return NULL;
    }
    struct set_op *set_op = CONTAINER_OF(node, struct set_op, node);
    return set_op;
}

struct set_op*
set_op_list_next(struct set_op_list *list, struct set_op *set_op)
{
    struct hmap_node *node = hmap_next(&list->hmap, &set_op->node);
    if (node == NULL) {
        return NULL;
    }
    struct set_op *next = CONTAINER_OF(node, struct set_op, node);
    return next;
}
