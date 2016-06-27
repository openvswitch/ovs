/*
 * Copyright (c) 2011, 2012, 2013, 2015 Nicira, Inc.
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

#include "sset.h"

#include "hash.h"

static uint32_t
hash_name__(const char *name, size_t length)
{
    return hash_bytes(name, length, 0);
}

static uint32_t
hash_name(const char *name)
{
    return hash_name__(name, strlen(name));
}

static struct sset_node *
sset_find__(const struct sset *set, const char *name, size_t hash)
{
    struct sset_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash, &set->map) {
        if (!strcmp(node->name, name)) {
            return node;
        }
    }
    return NULL;
}

static struct sset_node *
sset_add__(struct sset *set, const char *name, size_t length, size_t hash)
{
    struct sset_node *node = xmalloc(length + sizeof *node);
    memcpy(node->name, name, length + 1);
    hmap_insert(&set->map, &node->hmap_node, hash);
    return node;
}

/* Initializes 'set' as an empty set of strings. */
void
sset_init(struct sset *set)
{
    hmap_init(&set->map);
}

/* Destroys 'sets'. */
void
sset_destroy(struct sset *set)
{
    if (set) {
        sset_clear(set);
        hmap_destroy(&set->map);
    }
}

/* Initializes 'set' to contain the same strings as 'orig'. */
void
sset_clone(struct sset *set, const struct sset *orig)
{
    struct sset_node *node;

    sset_init(set);
    HMAP_FOR_EACH (node, hmap_node, &orig->map) {
        sset_add__(set, node->name, strlen(node->name),
                   node->hmap_node.hash);
    }
}

/* Exchanges the contents of 'a' and 'b'. */
void
sset_swap(struct sset *a, struct sset *b)
{
    hmap_swap(&a->map, &b->map);
}

/* Adjusts 'set' so that it is still valid after it has been moved around in
 * memory (e.g. due to realloc()). */
void
sset_moved(struct sset *set)
{
    hmap_moved(&set->map);
}

/* Returns true if 'set' contains no strings, false if it contains at least one
 * string. */
bool
sset_is_empty(const struct sset *set)
{
    return hmap_is_empty(&set->map);
}

/* Returns the number of strings in 'set'. */
size_t
sset_count(const struct sset *set)
{
    return hmap_count(&set->map);
}

/* Adds 'name' to 'set'.  If 'name' is new, returns the new sset_node;
 * otherwise (if a copy of 'name' already existed in 'set'), returns NULL. */
struct sset_node *
sset_add(struct sset *set, const char *name)
{
    size_t length = strlen(name);
    uint32_t hash = hash_name__(name, length);

    return (sset_find__(set, name, hash)
            ? NULL
            : sset_add__(set, name, length, hash));
}

/* Adds a copy of 'name' to 'set' and frees 'name'.
 *
 * If 'name' is new, returns the new sset_node; otherwise (if a copy of 'name'
 * already existed in 'set'), returns NULL. */
struct sset_node *
sset_add_and_free(struct sset *set, char *name)
{
    struct sset_node *node = sset_add(set, name);
    free(name);
    return node;
}

/* Adds 'name' to 'set'.  Assert-fails if a copy of 'name' was already in
 * 'set'. */
void
sset_add_assert(struct sset *set, const char *name)
{
    bool added OVS_UNUSED = sset_add(set, name);
    ovs_assert(added);
}

/* Adds a copy of each of the 'n' names in 'names' to 'set'. */
void
sset_add_array(struct sset *set, char **names, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        sset_add(set, names[i]);
    }
}

/* Removes all of the strings from 'set'. */
void
sset_clear(struct sset *set)
{
    const char *name, *next;

    SSET_FOR_EACH_SAFE (name, next, set) {
        sset_delete(set, SSET_NODE_FROM_NAME(name));
    }
}

/* Deletes 'node' from 'set' and frees 'node'. */
void
sset_delete(struct sset *set, struct sset_node *node)
{
    hmap_remove(&set->map, &node->hmap_node);
    free(node);
}

/* Searches for 'name' in 'set'.  If found, deletes it and returns true.  If
 * not found, returns false without modifying 'set'. */
bool
sset_find_and_delete(struct sset *set, const char *name)
{
    struct sset_node *node = sset_find(set, name);
    if (node) {
        sset_delete(set, node);
    }
    return node != NULL;
}

/* Searches for 'name' in 'set' and deletes it.  Assert-fails if 'name' is not
 * in 'set'. */
void
sset_find_and_delete_assert(struct sset *set, const char *name)
{
    bool deleted OVS_UNUSED = sset_find_and_delete(set, name);
    ovs_assert(deleted);
}

/* Removes a string from 'set' and returns a copy of it.  The caller must free
 * the returned string (with free()).
 *
 * 'set' must not be empty.
 *
 * This is not a very good way to iterate through an sset: it copies each name
 * and it takes O(n**2) time to remove all the names.  Use SSET_FOR_EACH_SAFE
 * instead, if you can. */
char *
sset_pop(struct sset *set)
{
    const char *name = SSET_FIRST(set);
    char *copy = xstrdup(name);
    sset_delete(set, SSET_NODE_FROM_NAME(name));
    return copy;
}

/* Searches for 'name' in 'set'.  Returns its node, if found, otherwise a null
 * pointer. */
struct sset_node *
sset_find(const struct sset *set, const char *name)
{
    return sset_find__(set, name, hash_name(name));
}

/* Returns true if 'set' contains a copy of 'name', false otherwise. */
bool
sset_contains(const struct sset *set, const char *name)
{
    return sset_find(set, name) != NULL;
}

/* Returns true if 'a' and 'b' contain the same strings, false otherwise. */
bool
sset_equals(const struct sset *a, const struct sset *b)
{
    struct sset_node *node;

    if (sset_count(a) != sset_count(b)) {
        return false;
    }

    HMAP_FOR_EACH (node, hmap_node, &a->map) {
        if (!sset_find__(b, node->name, node->hmap_node.hash)) {
            return false;
        }
    }

    return true;
}

/* Returns the next node in 'set' in hash order, or NULL if no nodes remain in
 * 'set'.  Uses '*pos' to determine where to begin iteration, and updates
 * '*pos' to pass on the next iteration into them before returning.
 *
 * It's better to use plain SSET_FOR_EACH and related functions, since they are
 * faster and better at dealing with ssets that change during iteration.
 *
 * Before beginning iteration, set '*pos' to all zeros. */
struct sset_node *
sset_at_position(const struct sset *set, struct sset_position *pos)
{
    struct hmap_node *hmap_node;

    hmap_node = hmap_at_position(&set->map, &pos->pos);
    return SSET_NODE_FROM_HMAP_NODE(hmap_node);
}

/* Replaces 'a' by the intersection of 'a' and 'b'.  That is, removes from 'a'
 * all of the strings that are not also in 'b'. */
void
sset_intersect(struct sset *a, const struct sset *b)
{
    const char *name, *next;

    SSET_FOR_EACH_SAFE (name, next, a) {
        if (!sset_contains(b, name)) {
            sset_delete(a, SSET_NODE_FROM_NAME(name));
        }
    }
}

/* Returns a null-terminated array of pointers to the strings in 'set', in no
 * particular order.  The caller must free the returned array when it is no
 * longer needed, but the strings in the array belong to 'set' and thus must
 * not be modified or freed. */
const char **
sset_array(const struct sset *set)
{
    size_t n = sset_count(set);
    const char **array;
    const char *s;
    size_t i;

    array = xmalloc(sizeof *array * (n + 1));
    i = 0;
    SSET_FOR_EACH (s, set) {
        array[i++] = s;
    }
    ovs_assert(i == n);
    array[n] = NULL;

    return array;
}

static int
compare_string_pointers(const void *a_, const void *b_)
{
    const char *const *a = a_;
    const char *const *b = b_;

    return strcmp(*a, *b);
}

/* Returns a null-terminated array of pointers to the strings in 'set', sorted
 * alphabetically.  The caller must free the returned array when it is no
 * longer needed, but the strings in the array belong to 'set' and thus must
 * not be modified or freed. */
const char **
sset_sort(const struct sset *set)
{
    const char **array = sset_array(set);
    qsort(array, sset_count(set), sizeof *array, compare_string_pointers);
    return array;
}
