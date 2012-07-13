/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

static struct shash_node *shash_find__(const struct shash *,
                                       const char *name, size_t name_len,
                                       size_t hash);

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

/* Like shash_destroy(), but also free() each node's 'data'. */
void
shash_destroy_free_data(struct shash *sh)
{
    if (sh) {
        shash_clear_free_data(sh);
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

/* Like shash_clear(), but also free() each node's 'data'. */
void
shash_clear_free_data(struct shash *sh)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, sh) {
        hmap_remove(&sh->map, &node->node);
        free(node->data);
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

static struct shash_node *
shash_add_nocopy__(struct shash *sh, char *name, const void *data, size_t hash)
{
    struct shash_node *node = xmalloc(sizeof *node);
    node->name = name;
    node->data = CONST_CAST(void *, data);
    hmap_insert(&sh->map, &node->node, hash);
    return node;
}

/* It is the caller's responsibility to avoid duplicate names, if that is
 * desirable. */
struct shash_node *
shash_add_nocopy(struct shash *sh, char *name, const void *data)
{
    return shash_add_nocopy__(sh, name, data, hash_name(name));
}

/* It is the caller's responsibility to avoid duplicate names, if that is
 * desirable. */
struct shash_node *
shash_add(struct shash *sh, const char *name, const void *data)
{
    return shash_add_nocopy(sh, xstrdup(name), data);
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
shash_add_assert(struct shash *sh, const char *name, const void *data)
{
    bool added OVS_UNUSED = shash_add_once(sh, name, data);
    assert(added);
}

/* Searches for 'name' in 'sh'.  If it does not already exist, adds it along
 * with 'data' and returns NULL.  If it does already exist, replaces its data
 * by 'data' and returns the data that it formerly contained. */
void *
shash_replace(struct shash *sh, const char *name, const void *data)
{
    size_t hash = hash_name(name);
    struct shash_node *node;

    node = shash_find__(sh, name, strlen(name), hash);
    if (!node) {
        shash_add_nocopy__(sh, xstrdup(name), data, hash);
        return NULL;
    } else {
        void *old_data = node->data;
        node->data = CONST_CAST(void *, data);
        return old_data;
    }
}

/* Deletes 'node' from 'sh' and frees the node's name.  The caller is still
 * responsible for freeing the node's data, if necessary. */
void
shash_delete(struct shash *sh, struct shash_node *node)
{
    free(shash_steal(sh, node));
}

/* Deletes 'node' from 'sh'.  Neither the node's name nor its data is freed;
 * instead, ownership is transferred to the caller.  Returns the node's
 * name. */
char *
shash_steal(struct shash *sh, struct shash_node *node)
{
    char *name = node->name;

    hmap_remove(&sh->map, &node->node);
    free(node);
    return name;
}

static struct shash_node *
shash_find__(const struct shash *sh, const char *name, size_t name_len,
             size_t hash)
{
    struct shash_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, node, hash, &sh->map) {
        if (!strncmp(node->name, name, name_len) && !node->name[name_len]) {
            return node;
        }
    }
    return NULL;
}

/* If there are duplicates, returns a random element. */
struct shash_node *
shash_find(const struct shash *sh, const char *name)
{
    return shash_find__(sh, name, strlen(name), hash_name(name));
}

/* Finds and returns a shash_node within 'sh' that has the given 'name' that is
 * exactly 'len' bytes long.  Returns NULL if no node in 'sh' has that name. */
struct shash_node *
shash_find_len(const struct shash *sh, const char *name, size_t len)
{
    return shash_find__(sh, name, len, hash_bytes(name, len, 0));
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

void *
shash_find_and_delete_assert(struct shash *sh, const char *name)
{
    void *data = shash_find_and_delete(sh, name);
    assert(data != NULL);
    return data;
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

/* Chooses and returns a randomly selected node from 'sh', which must not be
 * empty.
 *
 * I wouldn't depend on this algorithm to be fair, since I haven't analyzed it.
 * But it does at least ensure that any node in 'sh' can be chosen. */
struct shash_node *
shash_random_node(struct shash *sh)
{
    return CONTAINER_OF(hmap_random_node(&sh->map), struct shash_node, node);
}
