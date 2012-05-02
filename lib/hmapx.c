/*
 * Copyright (c) 2011 Nicira, Inc.
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

#include <config.h>

#include "hmapx.h"

#include <assert.h>

#include "hash.h"

static struct hmapx_node *
hmapx_find__(const struct hmapx *map, const void *data, size_t hash)
{
    struct hmapx_node *node;

    HMAP_FOR_EACH_IN_BUCKET (node, hmap_node, hash, &map->map) {
        if (node->data == data) {
            return node;
        }
    }
    return NULL;
}

static struct hmapx_node *
hmapx_add__(struct hmapx *map, void *data, size_t hash)
{
    struct hmapx_node *node = xmalloc(sizeof *node);
    node->data = data;
    hmap_insert(&map->map, &node->hmap_node, hash);
    return node;
}

/* Initializes 'map' as an empty set of pointers. */
void
hmapx_init(struct hmapx *map)
{
    hmap_init(&map->map);
}

/* Destroys 'map'. */
void
hmapx_destroy(struct hmapx *map)
{
    if (map) {
        hmapx_clear(map);
        hmap_destroy(&map->map);
    }
}

/* Initializes 'map' to contain the same pointers as 'orig'. */
void
hmapx_clone(struct hmapx *map, const struct hmapx *orig)
{
    struct hmapx_node *node;

    hmapx_init(map);
    HMAP_FOR_EACH (node, hmap_node, &orig->map) {
        hmapx_add__(map, node->data, node->hmap_node.hash);
    }
}

/* Exchanges the contents of 'a' and 'b'. */
void
hmapx_swap(struct hmapx *a, struct hmapx *b)
{
    hmap_swap(&a->map, &b->map);
}

/* Adjusts 'map' so that it is still valid after it has been moved around in
 * memory (e.g. due to realloc()). */
void
hmapx_moved(struct hmapx *map)
{
    hmap_moved(&map->map);
}

/* Returns true if 'map' contains no nodes, false if it contains at least one
 * node. */
bool
hmapx_is_empty(const struct hmapx *map)
{
    return hmap_is_empty(&map->map);
}

/* Returns the number of nodes in 'map'. */
size_t
hmapx_count(const struct hmapx *map)
{
    return hmap_count(&map->map);
}

/* Adds 'data' to 'map'.  If 'data' is new, returns the new hmapx_node;
 * otherwise (if a 'data' already existed in 'map'), returns NULL. */
struct hmapx_node *
hmapx_add(struct hmapx *map, void *data)
{
    uint32_t hash = hash_pointer(data, 0);
    return (hmapx_find__(map, data, hash)
            ? NULL
            : hmapx_add__(map, data, hash));
}

/* Adds 'data' to 'map'.  Assert-fails if 'data' was already in 'map'. */
void
hmapx_add_assert(struct hmapx *map, void *data)
{
    bool added OVS_UNUSED = hmapx_add(map, data);
    assert(added);
}

/* Removes all of the nodes from 'map'. */
void
hmapx_clear(struct hmapx *map)
{
    struct hmapx_node *node, *next;

    HMAPX_FOR_EACH_SAFE (node, next, map) {
        hmapx_delete(map, node);
    }
}

/* Deletes 'node' from 'map' and frees 'node'. */
void
hmapx_delete(struct hmapx *map, struct hmapx_node *node)
{
    hmap_remove(&map->map, &node->hmap_node);
    free(node);
}

/* Searches for 'data' in 'map'.  If found, deletes it and returns true.  If
 * not found, returns false without modifying 'map'. */
bool
hmapx_find_and_delete(struct hmapx *map, const void *data)
{
    struct hmapx_node *node = hmapx_find(map, data);
    if (node) {
        hmapx_delete(map, node);
    }
    return node != NULL;
}

/* Searches for 'data' in 'map' and deletes it.  Assert-fails if 'data' is not
 * in 'map'. */
void
hmapx_find_and_delete_assert(struct hmapx *map, const void *data)
{
    bool deleted OVS_UNUSED = hmapx_find_and_delete(map, data);
    assert(deleted);
}

/* Searches for 'data' in 'map'.  Returns its node, if found, otherwise a null
 * pointer. */
struct hmapx_node *
hmapx_find(const struct hmapx *map, const void *data)
{
    return hmapx_find__(map, data, hash_pointer(data, 0));
}

/* Returns true if 'map' contains 'data', false otherwise. */
bool
hmapx_contains(const struct hmapx *map, const void *data)
{
    return hmapx_find(map, data) != NULL;
}

/* Returns true if 'a' and 'b' contain the same pointers, false otherwise. */
bool
hmapx_equals(const struct hmapx *a, const struct hmapx *b)
{
    struct hmapx_node *node;

    if (hmapx_count(a) != hmapx_count(b)) {
        return false;
    }

    HMAP_FOR_EACH (node, hmap_node, &a->map) {
        if (!hmapx_find__(b, node->data, node->hmap_node.hash)) {
            return false;
        }
    }

    return true;
}
