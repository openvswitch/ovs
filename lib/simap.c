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
#include "simap.h"
#include <assert.h>
#include "hash.h"

static size_t hash_name(const char *, size_t length);
static struct simap_node *simap_find__(const struct simap *,
                                       const char *name, size_t name_len,
                                       size_t hash);
static struct simap_node *simap_add_nocopy__(struct simap *,
                                             char *name, unsigned int data,
                                             size_t hash);
static int compare_nodes_by_name(const void *a_, const void *b_);

/* Initializes 'simap' as an empty string-to-integer map. */
void
simap_init(struct simap *simap)
{
    hmap_init(&simap->map);
}

/* Frees all the data that 'simap' contains. */
void
simap_destroy(struct simap *simap)
{
    if (simap) {
        simap_clear(simap);
        hmap_destroy(&simap->map);
    }
}

/* Exchanges the contents of 'a' and 'b'. */
void
simap_swap(struct simap *a, struct simap *b)
{
    hmap_swap(&a->map, &b->map);
}

/* Adjusts 'simap' so that it is still valid after it has been moved around in
 * memory (e.g. due to realloc()). */
void
simap_moved(struct simap *simap)
{
    hmap_moved(&simap->map);
}

/* Removes all of the mappings from 'simap' and frees them. */
void
simap_clear(struct simap *simap)
{
    struct simap_node *node, *next;

    SIMAP_FOR_EACH_SAFE (node, next, simap) {
        hmap_remove(&simap->map, &node->node);
        free(node->name);
        free(node);
    }
}

/* Returns true if 'simap' contains no mappings, false if it contains at least
 * one. */
bool
simap_is_empty(const struct simap *simap)
{
    return hmap_is_empty(&simap->map);
}

/* Returns the number of mappings in 'simap'. */
size_t
simap_count(const struct simap *simap)
{
    return hmap_count(&simap->map);
}

/* Inserts a mapping from 'name' to 'data' into 'simap', replacing any
 * existing mapping for 'name'.  Returns true if a new mapping was added,
 * false if an existing mapping's value was replaced.
 *
 * The caller retains ownership of 'name'. */
bool
simap_put(struct simap *simap, const char *name, unsigned int data)
{
    size_t length = strlen(name);
    size_t hash = hash_name(name, length);
    struct simap_node *node;

    node = simap_find__(simap, name, length, hash);
    if (node) {
        node->data = data;
        return false;
    } else {
        simap_add_nocopy__(simap, xmemdup0(name, length), data, hash);
        return true;
    }
}

/* Increases the data value in the mapping for 'name' by 'amt', or inserts a
 * mapping from 'name' to 'amt' if no such mapping exists.  Returns the
 * new total data value for the mapping.
 *
 * If 'amt' is zero, this function does nothing and returns 0.  That is, this
 * function won't create a mapping with a initial value of 0.
 *
 * The caller retains ownership of 'name'. */
unsigned int
simap_increase(struct simap *simap, const char *name, unsigned int amt)
{
    if (amt) {
        size_t length = strlen(name);
        size_t hash = hash_name(name, length);
        struct simap_node *node;

        node = simap_find__(simap, name, length, hash);
        if (node) {
            node->data += amt;
        } else {
            node = simap_add_nocopy__(simap, xmemdup0(name, length),
                                      amt, hash);
        }
        return node->data;
    } else {
        return 0;
    }
}

/* Deletes 'node' from 'simap' and frees its associated memory. */
void
simap_delete(struct simap *simap, struct simap_node *node)
{
    hmap_remove(&simap->map, &node->node);
    free(node->name);
    free(node);
}

/* Searches 'simap' for a mapping with the given 'name'.  Returns it, if found,
 * or a null pointer if not. */
struct simap_node *
simap_find(const struct simap *simap, const char *name)
{
    return simap_find_len(simap, name, strlen(name));
}

/* Searches 'simap' for a mapping whose name is the first 'name_len' bytes
 * starting at 'name'.  Returns it, if found, or a null pointer if not. */
struct simap_node *
simap_find_len(const struct simap *simap, const char *name, size_t len)
{
    return simap_find__(simap, name, len, hash_name(name, len));
}

/* Searches 'simap' for a mapping with the given 'name'.  Returns the
 * associated data value, if found, otherwise zero. */
unsigned int
simap_get(const struct simap *simap, const char *name)
{
    struct simap_node *node = simap_find(simap, name);
    return node ? node->data : 0;
}

/* Returns an array that contains a pointer to each mapping in 'simap',
 * ordered alphabetically by name.  The returned array has simap_count(simap)
 * elements.
 *
 * The caller is responsible for freeing the returned array (with free()).  It
 * should not free the individual "simap_node"s in the array, because they are
 * still part of 'simap'. */
const struct simap_node **
simap_sort(const struct simap *simap)
{
    if (simap_is_empty(simap)) {
        return NULL;
    } else {
        const struct simap_node **nodes;
        struct simap_node *node;
        size_t i, n;

        n = simap_count(simap);
        nodes = xmalloc(n * sizeof *nodes);
        i = 0;
        SIMAP_FOR_EACH (node, simap) {
            nodes[i++] = node;
        }
        assert(i == n);

        qsort(nodes, n, sizeof *nodes, compare_nodes_by_name);

        return nodes;
    }
}

static size_t
hash_name(const char *name, size_t length)
{
    return hash_bytes(name, length, 0);
}

static struct simap_node *
simap_find__(const struct simap *simap, const char *name, size_t name_len,
             size_t hash)
{
    struct simap_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, node, hash, &simap->map) {
        if (!strncmp(node->name, name, name_len) && !node->name[name_len]) {
            return node;
        }
    }
    return NULL;
}

static struct simap_node *
simap_add_nocopy__(struct simap *simap, char *name, unsigned int data,
                   size_t hash)
{
    struct simap_node *node = xmalloc(sizeof *node);
    node->name = name;
    node->data = data;
    hmap_insert(&simap->map, &node->node, hash);
    return node;
}

static int
compare_nodes_by_name(const void *a_, const void *b_)
{
    const struct simap_node *const *a = a_;
    const struct simap_node *const *b = b_;
    return strcmp((*a)->name, (*b)->name);
}
