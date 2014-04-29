/*
 * Copyright (c) 2013 Nicira, Inc.
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
#include "hindex.h"
#include "coverage.h"

static bool hindex_node_is_body(const struct hindex_node *);
static bool hindex_node_is_head(const struct hindex_node *);
static void hindex_resize(struct hindex *, size_t new_mask);
static size_t hindex_calc_mask(size_t capacity);

COVERAGE_DEFINE(hindex_pathological);
COVERAGE_DEFINE(hindex_expand);
COVERAGE_DEFINE(hindex_shrink);
COVERAGE_DEFINE(hindex_reserve);

/* Initializes 'hindex' as an empty hash index. */
void
hindex_init(struct hindex *hindex)
{
    hindex->buckets = &hindex->one;
    hindex->one = NULL;
    hindex->mask = 0;
    hindex->n_unique = 0;
}

/* Frees memory reserved by 'hindex'.  It is the client's responsibility to
 * free the nodes themselves, if necessary. */
void
hindex_destroy(struct hindex *hindex)
{
    if (hindex && hindex->buckets != &hindex->one) {
        free(hindex->buckets);
    }
}

/* Removes all node from 'hindex', leaving it ready to accept more nodes.  Does
 * not free memory allocated for 'hindex'.
 *
 * This function is appropriate when 'hindex' will soon have about as many
 * elements as it before.  If 'hindex' will likely have fewer elements than
 * before, use hindex_destroy() followed by hindex_clear() to save memory and
 * iteration time. */
void
hindex_clear(struct hindex *hindex)
{
    if (hindex->n_unique > 0) {
        hindex->n_unique = 0;
        memset(hindex->buckets, 0,
               (hindex->mask + 1) * sizeof *hindex->buckets);
    }
}

/* Exchanges hash indexes 'a' and 'b'. */
void
hindex_swap(struct hindex *a, struct hindex *b)
{
    struct hindex tmp = *a;
    *a = *b;
    *b = tmp;
    hindex_moved(a);
    hindex_moved(b);
}

/* Adjusts 'hindex' to compensate for having moved position in memory (e.g. due
 * to realloc()). */
void
hindex_moved(struct hindex *hindex)
{
    if (!hindex->mask) {
        hindex->buckets = &hindex->one;
    }
}

/* Expands 'hindex', if necessary, to optimize the performance of searches. */
void
hindex_expand(struct hindex *hindex)
{
    size_t new_mask = hindex_calc_mask(hindex->n_unique);
    if (new_mask > hindex->mask) {
        COVERAGE_INC(hindex_expand);
        hindex_resize(hindex, new_mask);
    }
}

/* Shrinks 'hindex', if necessary, to optimize the performance of iteration. */
void
hindex_shrink(struct hindex *hindex)
{
    size_t new_mask = hindex_calc_mask(hindex->n_unique);
    if (new_mask < hindex->mask) {
        COVERAGE_INC(hindex_shrink);
        hindex_resize(hindex, new_mask);
    }
}

/* Expands 'hindex', if necessary, to optimize the performance of searches when
 * it has up to 'n' unique hashes.  (But iteration will be slow in a hash index
 * whose allocated capacity is much higher than its current number of
 * nodes.)  */
void
hindex_reserve(struct hindex *hindex, size_t n)
{
    size_t new_mask = hindex_calc_mask(n);
    if (new_mask > hindex->mask) {
        COVERAGE_INC(hindex_reserve);
        hindex_resize(hindex, new_mask);
    }
}

/* Inserts 'node', with the given 'hash', into 'hindex'.  Never automatically
 * expands 'hindex' (use hindex_insert() instead if you want that). */
void
hindex_insert_fast(struct hindex *hindex,
                   struct hindex_node *node, size_t hash)
{
    struct hindex_node *head = hindex_node_with_hash(hindex, hash);
    if (head) {
        /* 'head' is an existing head with hash == 'hash'.
         * Insert 'node' as a body node just below 'head'. */
        node->s = head->s;
        node->d = head;
        if (node->s) {
            node->s->d = node;
        }
        head->s = node;
    } else {
        /* No existing node has hash 'hash'.  Insert 'node' as a new head in
         * its bucket. */
        struct hindex_node **bucket = &hindex->buckets[hash & hindex->mask];
        node->s = NULL;
        node->d = *bucket;
        *bucket = node;
        hindex->n_unique++;
    }
    node->hash = hash;
}

/* Inserts 'node', with the given 'hash', into 'hindex', and expands 'hindex'
 * if necessary to optimize search performance. */
void
hindex_insert(struct hindex *hindex, struct hindex_node *node, size_t hash)
{
    hindex_insert_fast(hindex, node, hash);
    if (hindex->n_unique / 2 > hindex->mask) {
        hindex_expand(hindex);
    }
}

/* Removes 'node' from 'hindex'.  Does not shrink the hash index; call
 * hindex_shrink() directly if desired. */
void
hindex_remove(struct hindex *hindex, struct hindex_node *node)
{
    if (!hindex_node_is_head(node)) {
        node->d->s = node->s;
        if (node->s) {
            node->s->d = node->d;
        }
    } else {
        struct hindex_node **head;

        for (head = &hindex->buckets[node->hash & hindex->mask];
             (*head)->hash != node->hash;
             head = &(*head)->d)
        {
            continue;
        }

        if (node->s) {
            *head = node->s;
            node->s->d = node->d;
        } else {
            *head = node->d;
            hindex->n_unique--;
        }
    }
}

/* Helper functions. */

/* Returns true if 'node', which must be inserted into an hindex, is a "body"
 * node, that is, it is not reachable from a bucket by following zero or more
 * 'd' pointers.  Returns false otherwise. */
static bool
hindex_node_is_body(const struct hindex_node *node)
{
    return node->d && node->d->hash == node->hash;
}

/* Returns true if 'node', which must be inserted into an hindex, is a "head"
 * node, that is, if it is reachable from a bucket by following zero or more
 * 'd' pointers.  Returns false if 'node' is a body node (and therefore one
 * must follow at least one 's' pointer to reach it). */
static bool
hindex_node_is_head(const struct hindex_node *node)
{
    return !hindex_node_is_body(node);
}

/* Reallocates 'hindex''s array of buckets to use bitwise mask 'new_mask'. */
static void
hindex_resize(struct hindex *hindex, size_t new_mask)
{
    struct hindex tmp;
    size_t i;

    ovs_assert(is_pow2(new_mask + 1));
    ovs_assert(new_mask != SIZE_MAX);

    hindex_init(&tmp);
    if (new_mask) {
        tmp.buckets = xmalloc(sizeof *tmp.buckets * (new_mask + 1));
        tmp.mask = new_mask;
        for (i = 0; i <= tmp.mask; i++) {
            tmp.buckets[i] = NULL;
        }
    }
    for (i = 0; i <= hindex->mask; i++) {
        struct hindex_node *node, *next;
        int count;

        count = 0;
        for (node = hindex->buckets[i]; node; node = next) {
            struct hindex_node **head = &tmp.buckets[node->hash & tmp.mask];

            next = node->d;
            node->d = *head;
            *head = node;
            count++;
        }
        if (count > 5) {
            COVERAGE_INC(hindex_pathological);
        }
    }
    tmp.n_unique = hindex->n_unique;
    hindex_swap(hindex, &tmp);
    hindex_destroy(&tmp);
}

/* Returns the bitwise mask to use in struct hindex to support 'capacity'
 * hindex_nodes with unique hashes. */
static size_t
hindex_calc_mask(size_t capacity)
{
    size_t mask = capacity / 2;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
#if SIZE_MAX > UINT32_MAX
    mask |= mask >> 32;
#endif

    /* If we need to dynamically allocate buckets we might as well allocate at
     * least 4 of them. */
    mask |= (mask & 1) << 1;

    return mask;
}

/* Returns the head node in 'hindex' with the given 'hash'.  'hindex' must
 * contain a head node with the given hash. */
static struct hindex_node *
hindex_head_node(const struct hindex *hindex, size_t hash)
{
    struct hindex_node *node = hindex->buckets[hash & hindex->mask];

    while (node->hash != hash) {
        node = node->d;
    }
    return node;
}

static struct hindex_node *
hindex_next__(const struct hindex *hindex, size_t start)
{
    size_t i;
    for (i = start; i <= hindex->mask; i++) {
        struct hindex_node *node = hindex->buckets[i];
        if (node) {
            return node;
        }
    }
    return NULL;
}

/* Returns the first node in 'hindex', in arbitrary order, or a null pointer if
 * 'hindex' is empty. */
struct hindex_node *
hindex_first(const struct hindex *hindex)
{
    return hindex_next__(hindex, 0);
}

/* Returns the next node in 'hindex' following 'node', in arbitrary order, or a
 * null pointer if 'node' is the last node in 'hindex'.
 *
 * If the hash index has been reallocated since 'node' was visited, some nodes
 * may be skipped or visited twice. */
struct hindex_node *
hindex_next(const struct hindex *hindex, const struct hindex_node *node)
{
    struct hindex_node *head;

    /* If there's a node with the same hash, return it. */
    if (node->s) {
        return node->s;
    }

    /* If there's another node in the same bucket, return it. */
    head = hindex_head_node(hindex, node->hash);
    if (head->d) {
        return head->d;
    }

    /* Return the first node in the next (or later) bucket. */
    return hindex_next__(hindex, (node->hash & hindex->mask) + 1);
}
