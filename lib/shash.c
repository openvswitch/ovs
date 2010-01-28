/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include "shash.h"
#include <assert.h>
#include "hash.h"

static size_t
hash_name(const char *name)
{
    return hash_string(name, 0);
}

void
shash_init(struct shash *sh)
{
    hmap_init(&sh->map);
}

void
shash_destroy(struct shash *sh)
{
    if (sh) {
        shash_clear(sh);
        hmap_destroy(&sh->map);
    }
}

void
shash_swap(struct shash *a, struct shash *b)
{
    hmap_swap(&a->map, &b->map);
}

void
shash_moved(struct shash *sh)
{
    hmap_moved(&sh->map);
}

void
shash_clear(struct shash *sh)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, sh) {
        hmap_remove(&sh->map, &node->node);
        free(node->name);
        free(node);
    }
}

bool
shash_is_empty(const struct shash *shash)
{
    return hmap_is_empty(&shash->map);
}

size_t
shash_count(const struct shash *shash)
{
    return hmap_count(&shash->map);
}

/* It is the caller's responsibility to avoid duplicate names, if that is
 * desirable. */
struct shash_node *
shash_add(struct shash *sh, const char *name, const void *data)
{
    struct shash_node *node = xmalloc(sizeof *node);
    node->name = xstrdup(name);
    node->data = (void *) data;
    hmap_insert(&sh->map, &node->node, hash_name(name));
    return node;
}

bool
shash_add_once(struct shash *sh, const char *name, const void *data)
{
    if (!shash_find(sh, name)) {
        shash_add(sh, name, data);
        return true;
    } else {
        return false;
    }
}

void
shash_delete(struct shash *sh, struct shash_node *node)
{
    hmap_remove(&sh->map, &node->node);
    free(node->name);
    free(node);
}

/* If there are duplicates, returns a random element. */
struct shash_node *
shash_find(const struct shash *sh, const char *name)
{
    struct shash_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, struct shash_node, node,
                             hash_name(name), &sh->map) {
        if (!strcmp(node->name, name)) {
            return node;
        }
    }
    return NULL;
}

void *
shash_find_data(const struct shash *sh, const char *name)
{
    struct shash_node *node = shash_find(sh, name);
    return node ? node->data : NULL;
}

void *
shash_find_and_delete(struct shash *sh, const char *name)
{
    struct shash_node *node = shash_find(sh, name);
    if (node) {
        void *data = node->data;
        shash_delete(sh, node);
        return data;
    } else {
        return NULL;
    }
}

struct shash_node *
shash_first(const struct shash *shash)
{
    struct hmap_node *node = hmap_first(&shash->map);
    return node ? CONTAINER_OF(node, struct shash_node, node) : NULL;
}

static int
compare_nodes_by_name(const void *a_, const void *b_)
{
    const struct shash_node *const *a = a_;
    const struct shash_node *const *b = b_;
    return strcmp((*a)->name, (*b)->name);
}

const struct shash_node **
shash_sort(const struct shash *sh)
{
    if (shash_is_empty(sh)) {
        return NULL;
    } else {
        const struct shash_node **nodes;
        struct shash_node *node;
        size_t i, n;

        n = shash_count(sh);
        nodes = xmalloc(n * sizeof *nodes);
        i = 0;
        SHASH_FOR_EACH (node, sh) {
            nodes[i++] = node;
        }
        assert(i == n);

        qsort(nodes, n, sizeof *nodes, compare_nodes_by_name);

        return nodes;
    }
}

/* Returns true if 'a' and 'b' contain the same keys (regardless of their
 * values), false otherwise. */
bool
shash_equal_keys(const struct shash *a, const struct shash *b)
{
    struct shash_node *node;

    if (hmap_count(&a->map) != hmap_count(&b->map)) {
        return false;
    }
    SHASH_FOR_EACH (node, a) {
        if (!shash_find(b, node->name)) {
            return false;
        }
    }
    return true;
}
