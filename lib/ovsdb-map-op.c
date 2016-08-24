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

#include <config.h>
#include "ovsdb-map-op.h"
#include "util.h"
#include "openvswitch/hmap.h"
#include "hash.h"

/* Map Operation: a Partial Map Update */
struct map_op {
    struct hmap_node node;
    struct ovsdb_datum *datum;
    enum map_op_type type;
};

/* List of Map Operations */
struct map_op_list {
    struct hmap hmap;
};

static void map_op_destroy_datum(struct map_op *, const struct ovsdb_type *);
static struct map_op *map_op_list_find(struct map_op_list *, struct map_op *,
                                       const struct ovsdb_type *, size_t);

struct map_op*
map_op_create(struct ovsdb_datum *datum, enum map_op_type type)
{
    struct map_op *map_op = xmalloc(sizeof *map_op);
    map_op->node.hash = 0;
    map_op->node.next = HMAP_NODE_NULL;
    map_op->datum = datum;
    map_op->type = type;
    return map_op;
}

static void
map_op_destroy_datum(struct map_op *map_op, const struct ovsdb_type *type)
{
    if (map_op->type == MAP_OP_DELETE){
        struct ovsdb_type type_ = *type;
        type_.value.type = OVSDB_TYPE_VOID;
        ovsdb_datum_destroy(map_op->datum, &type_);
    } else {
        ovsdb_datum_destroy(map_op->datum, type);
    }
    free(map_op->datum);
    map_op->datum = NULL;
}

void
map_op_destroy(struct map_op *map_op, const struct ovsdb_type *type)
{
    map_op_destroy_datum(map_op, type);
    free(map_op);
}

struct ovsdb_datum*
map_op_datum(const struct map_op *map_op)
{
    return map_op->datum;
}

enum map_op_type
map_op_type(const struct map_op *map_op)
{
    return map_op->type;
}

struct map_op_list*
map_op_list_create(void)
{
    struct map_op_list *list = xmalloc(sizeof *list);
    hmap_init(&list->hmap);
    return list;
}

void
map_op_list_destroy(struct map_op_list *list, const struct ovsdb_type *type)
{
    struct map_op *map_op, *next;
    HMAP_FOR_EACH_SAFE (map_op, next, node, &list->hmap) {
        map_op_destroy(map_op, type);
    }
    hmap_destroy(&list->hmap);
    free(list);
}

static struct map_op*
map_op_list_find(struct map_op_list *list, struct map_op *map_op,
                 const struct ovsdb_type *type, size_t hash)
{
    struct map_op *found = NULL;
    struct map_op *old;
    HMAP_FOR_EACH_WITH_HASH(old, node, hash, &list->hmap) {
        if (ovsdb_atom_equals(&old->datum->keys[0], &map_op->datum->keys[0],
                              type->key.type)) {
            found = old;
            break;
        }
    }
    return found;
}

/* Inserts 'map_op' into 'list'. Makes sure that any conflict with a previous
 * map operation is resolved, so only one map operation is possible on each key
 * per transactions. 'type' must be the type of the column over which the map
 * operation will be applied. */
void
map_op_list_add(struct map_op_list *list, struct map_op *map_op,
                const struct ovsdb_type *type)
{
    /* Check if there is a previous update with the same key. */
    size_t hash;
    struct map_op *prev_map_op;

    hash = ovsdb_atom_hash(&map_op->datum->keys[0], type->key.type, 0);
    prev_map_op = map_op_list_find(list, map_op, type, hash);
    if (prev_map_op == NULL){
        hmap_insert(&list->hmap, &map_op->node, hash);
    } else {
        if (prev_map_op->type == MAP_OP_INSERT &&
            map_op->type == MAP_OP_DELETE) {
            /* These operations cancel each other out. */
            hmap_remove(&list->hmap, &prev_map_op->node);
            map_op_destroy(prev_map_op, type);
            map_op_destroy(map_op, type);
        } else {
            /* For any other case, the new update operation replaces
             * the previous update operation. */
            map_op_destroy_datum(prev_map_op, type);
            prev_map_op->type = map_op->type;
            prev_map_op->datum = map_op->datum;
            free(map_op);
        }
    }
}

struct map_op*
map_op_list_first(struct map_op_list *list)
{
    struct hmap_node *node = hmap_first(&list->hmap);
    if (node == NULL) {
        return NULL;
    }
    struct map_op *map_op = CONTAINER_OF(node, struct map_op, node);
    return map_op;
}

struct map_op*
map_op_list_next(struct map_op_list *list, struct map_op *map_op)
{
    struct hmap_node *node = hmap_next(&list->hmap, &map_op->node);
    if (node == NULL) {
        return NULL;
    }
    struct map_op *next = CONTAINER_OF(node, struct map_op, node);
    return next;
}
