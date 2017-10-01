/*
 * Copyright (c) 2014, 2016 Nicira, Inc.
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
#include "ccmap.h"
#include "coverage.h"
#include "bitmap.h"
#include "hash.h"
#include "ovs-rcu.h"
#include "random.h"
#include "util.h"

COVERAGE_DEFINE(ccmap_expand);
COVERAGE_DEFINE(ccmap_shrink);

/* A count-only version of the cmap. */

/* Allow protected access to the value without atomic semantics.  This makes
 * the exclusive writer somewhat faster. */
typedef union {
    unsigned long long         protected_value;
    ATOMIC(unsigned long long) atomic_value;
} ccmap_node_t;
BUILD_ASSERT_DECL(sizeof(ccmap_node_t) == sizeof(uint64_t));

static uint64_t
ccmap_node_get(const ccmap_node_t *node)
{
    uint64_t value;

    atomic_read_relaxed(&CONST_CAST(ccmap_node_t *, node)->atomic_value,
                        &value);

    return value;
}

/* It is safe to allow compiler optimize reads by the exclusive writer. */
static uint64_t
ccmap_node_get_protected(const ccmap_node_t *node)
{
    return node->protected_value;
}

static void
ccmap_node_set_protected(ccmap_node_t *node, uint64_t value)
{
    atomic_store_relaxed(&node->atomic_value, value);
}

static uint64_t
ccmap_node(uint32_t count, uint32_t hash)
{
    return (uint64_t)count << 32 | hash;
}

static uint32_t
ccmap_node_hash(uint64_t node)
{
    return node;
}

static uint32_t
ccmap_node_count(uint64_t node)
{
    return node >> 32;
}

/* Number of nodes per bucket. */
#define CCMAP_K (CACHE_LINE_SIZE / sizeof(ccmap_node_t))

/* A cuckoo hash bucket.  Designed to be cache-aligned and exactly one cache
 * line long. */
struct ccmap_bucket {
    /* Each node incudes both the hash (low 32-bits) and the count (high
     * 32-bits), allowing readers always getting a consistent pair. */
    ccmap_node_t nodes[CCMAP_K];
};
BUILD_ASSERT_DECL(sizeof(struct ccmap_bucket) == CACHE_LINE_SIZE);

/* Default maximum load factor (as a fraction of UINT32_MAX + 1) before
 * enlarging a ccmap.  Reasonable values lie between about 75% and 93%.  Smaller
 * values waste memory; larger values increase the average insertion time. */
#define CCMAP_MAX_LOAD ((uint32_t) (UINT32_MAX * .85))

/* Default minimum load factor (as a fraction of UINT32_MAX + 1) before
 * shrinking a ccmap.  Currently, the value is chosen to be 20%, this
 * means ccmap will have a 40% load factor after shrink. */
#define CCMAP_MIN_LOAD ((uint32_t) (UINT32_MAX * .20))

/* The implementation of a concurrent hash map. */
struct ccmap_impl {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        unsigned int n_unique;      /* Number of in-use nodes. */
        unsigned int n;             /* Number of hashes inserted. */
        unsigned int max_n;         /* Max nodes before enlarging. */
        unsigned int min_n;         /* Min nodes before shrinking. */
        uint32_t mask;              /* Number of 'buckets', minus one. */
        uint32_t basis;             /* Basis for rehashing client's
                                       hash values. */
    );
    struct ccmap_bucket buckets[];
};
BUILD_ASSERT_DECL(sizeof(struct ccmap_impl) == CACHE_LINE_SIZE);

static struct ccmap_impl *ccmap_rehash(struct ccmap *, uint32_t mask);

/* Given a rehashed value 'hash', returns the other hash for that rehashed
 * value.  This is symmetric: other_hash(other_hash(x)) == x.  (See also "Hash
 * Functions" at the top of cmap.c.) */
static uint32_t
other_hash(uint32_t hash)
{
    return (hash << 16) | (hash >> 16);
}

/* Returns the rehashed value for 'hash' within 'impl'.  (See also "Hash
 * Functions" at the top of this file.) */
static uint32_t
rehash(const struct ccmap_impl *impl, uint32_t hash)
{
    return hash_finish(impl->basis, hash);
}

static struct ccmap_impl *
ccmap_get_impl(const struct ccmap *ccmap)
{
    return ovsrcu_get(struct ccmap_impl *, &ccmap->impl);
}

static uint32_t
calc_max_n(uint32_t mask)
{
    return ((uint64_t) (mask + 1) * CCMAP_K * CCMAP_MAX_LOAD) >> 32;
}

static uint32_t
calc_min_n(uint32_t mask)
{
    return ((uint64_t) (mask + 1) * CCMAP_K * CCMAP_MIN_LOAD) >> 32;
}

static struct ccmap_impl *
ccmap_impl_create(uint32_t mask)
{
    struct ccmap_impl *impl;

    ovs_assert(is_pow2(mask + 1));

    impl = xzalloc_cacheline(sizeof *impl
                             + (mask + 1) * sizeof *impl->buckets);
    impl->n_unique = 0;
    impl->n = 0;
    impl->max_n = calc_max_n(mask);
    impl->min_n = calc_min_n(mask);
    impl->mask = mask;
    impl->basis = random_uint32();

    return impl;
}

/* Initializes 'ccmap' as an empty concurrent hash map. */
void
ccmap_init(struct ccmap *ccmap)
{
    ovsrcu_set(&ccmap->impl, ccmap_impl_create(0));
}

/* Destroys 'ccmap'.
 *
 * The client is responsible for destroying any data previously held in
 * 'ccmap'. */
void
ccmap_destroy(struct ccmap *ccmap)
{
    if (ccmap) {
        ovsrcu_postpone(free_cacheline, ccmap_get_impl(ccmap));
    }
}

/* Returns the number of hashes inserted in 'ccmap', including duplicates. */
size_t
ccmap_count(const struct ccmap *ccmap)
{
    return ccmap_get_impl(ccmap)->n;
}

/* Returns true if 'ccmap' is empty, false otherwise. */
bool
ccmap_is_empty(const struct ccmap *ccmap)
{
    return ccmap_count(ccmap) == 0;
}

/* returns 0 if not found. Map does not contain zero counts. */
static uint32_t
ccmap_find_in_bucket(const struct ccmap_bucket *bucket, uint32_t hash)
{
    for (int i = 0; i < CCMAP_K; i++) {
        uint64_t node = ccmap_node_get(&bucket->nodes[i]);

        if (ccmap_node_hash(node) == hash) {
            return ccmap_node_count(node);
        }
    }
    return 0;
}

/* Searches 'ccmap' for a node with the specified 'hash'.  If one is
 * found, returns the count associated with it, otherwise zero.
 */
uint32_t
ccmap_find(const struct ccmap *ccmap, uint32_t hash)
{
    const struct ccmap_impl *impl = ccmap_get_impl(ccmap);
    uint32_t h = rehash(impl, hash);
    uint32_t count;

    count = ccmap_find_in_bucket(&impl->buckets[h & impl->mask], hash);
    if (!count) {
        h = other_hash(h);
        count = ccmap_find_in_bucket(&impl->buckets[h & impl->mask], hash);
    }
    return count;
}

static int
ccmap_find_slot_protected(struct ccmap_bucket *b, uint32_t hash,
                          uint32_t *count)
{
    for (int i = 0; i < CCMAP_K; i++) {
        uint64_t node = ccmap_node_get_protected(&b->nodes[i]);

        *count = ccmap_node_count(node);
        if (ccmap_node_hash(node) == hash && *count) {
            return i;
        }
    }
    return -1;
}

static int
ccmap_find_empty_slot_protected(struct ccmap_bucket *b)
{
    for (int i = 0; i < CCMAP_K; i++) {
        uint64_t node = ccmap_node_get_protected(&b->nodes[i]);

        if (!ccmap_node_count(node)) {
            return i;
        }
    }
    return -1;
}

static void
ccmap_set_bucket(struct ccmap_bucket *b, int i, uint32_t count, uint32_t hash)
{
    ccmap_node_set_protected(&b->nodes[i], ccmap_node(count, hash));
}

/* Searches 'b' for a node with the given 'hash'.  If it finds one, increments
 * the associated count by 'inc' and returns the new value. Otherwise returns
 * 0. */
static uint32_t
ccmap_inc_bucket_existing(struct ccmap_bucket *b, uint32_t hash, uint32_t inc)
{
    uint32_t count;

    int i = ccmap_find_slot_protected(b, hash, &count);
    if (i < 0) {
        return 0;
    }
    count += inc;
    ccmap_set_bucket(b, i, count, hash);
    return count;
}

/* Searches 'b' for an empty slot.  If successful, stores 'inc' and 'hash' in
 * the slot and returns 'inc'.  Otherwise, returns 0. */
static uint32_t
ccmap_inc_bucket_new(struct ccmap_bucket *b, uint32_t hash, uint32_t inc)
{
    int i = ccmap_find_empty_slot_protected(b);
    if (i < 0) {
        return 0;
    }
    ccmap_set_bucket(b, i, inc, hash);
    return inc;
}

/* Returns the other bucket that b->nodes[slot] could occupy in 'impl'.  (This
 * might be the same as 'b'.) */
static struct ccmap_bucket *
other_bucket_protected(struct ccmap_impl *impl, struct ccmap_bucket *b, int slot)
{
    uint64_t node = ccmap_node_get_protected(&b->nodes[slot]);

    uint32_t h1 = rehash(impl, ccmap_node_hash(node));
    uint32_t h2 = other_hash(h1);
    uint32_t b_idx = b - impl->buckets;
    uint32_t other_h = (h1 & impl->mask) == b_idx ? h2 : h1;

    return &impl->buckets[other_h & impl->mask];
}

/* Count 'inc' for 'hash' is to be inserted into 'impl', but both candidate
 * buckets 'b1' and 'b2' are full.  This function attempts to rearrange buckets
 * within 'impl' to make room for 'hash'.
 *
 * Returns 'inc' if the new count for the 'hash' was inserted, otherwise
 * returns 0.
 *
 * The implementation is a general-purpose breadth-first search.  At first
 * glance, this is more complex than a random walk through 'impl' (suggested by
 * some references), but random walks have a tendency to loop back through a
 * single bucket.  We have to move nodes backward along the path that we find,
 * so that no node actually disappears from the hash table, which means a
 * random walk would have to be careful to deal with loops.  By contrast, a
 * successful breadth-first search always finds a *shortest* path through the
 * hash table, and a shortest path will never contain loops, so it avoids that
 * problem entirely.
 */
static uint32_t
ccmap_inc_bfs(struct ccmap_impl *impl, uint32_t hash,
              struct ccmap_bucket *b1, struct ccmap_bucket *b2, uint32_t inc)
{
    enum { MAX_DEPTH = 4 };

    /* A path from 'start' to 'end' via the 'n' steps in 'slots[]'.
     *
     * One can follow the path via:
     *
     *     struct ccmap_bucket *b;
     *     int i;
     *
     *     b = path->start;
     *     for (i = 0; i < path->n; i++) {
     *         b = other_bucket_protected(impl, b, path->slots[i]);
     *     }
     *     ovs_assert(b == path->end);
     */
    struct ccmap_path {
        struct ccmap_bucket *start; /* First bucket along the path. */
        struct ccmap_bucket *end;   /* Last bucket on the path. */
        uint8_t slots[MAX_DEPTH];  /* Slots used for each hop. */
        int n;                     /* Number of slots[]. */
    };

    /* We need to limit the amount of work we do trying to find a path.  It
     * might actually be impossible to rearrange the ccmap, and after some time
     * it is likely to be easier to rehash the entire ccmap.
     *
     * This value of MAX_QUEUE is an arbitrary limit suggested by one of the
     * references.  Empirically, it seems to work OK. */
    enum { MAX_QUEUE = 500 };
    struct ccmap_path queue[MAX_QUEUE];
    int head = 0;
    int tail = 0;

    /* Add 'b1' and 'b2' as starting points for the search. */
    queue[head].start = b1;
    queue[head].end = b1;
    queue[head].n = 0;
    head++;
    if (b1 != b2) {
        queue[head].start = b2;
        queue[head].end = b2;
        queue[head].n = 0;
        head++;
    }

    while (tail < head) {
        const struct ccmap_path *path = &queue[tail++];
        struct ccmap_bucket *this = path->end;
        int i;

        for (i = 0; i < CCMAP_K; i++) {
            struct ccmap_bucket *next = other_bucket_protected(impl, this, i);
            int j;

            if (this == next) {
                continue;
            }

            j = ccmap_find_empty_slot_protected(next);
            if (j >= 0) {
                /* We've found a path along which we can rearrange the hash
                 * table:  Start at path->start, follow all the slots in
                 * path->slots[], then follow slot 'i', then the bucket you
                 * arrive at has slot 'j' empty. */
                struct ccmap_bucket *buckets[MAX_DEPTH + 2];
                int slots[MAX_DEPTH + 2];
                int k;

                /* Figure out the full sequence of slots. */
                for (k = 0; k < path->n; k++) {
                    slots[k] = path->slots[k];
                }
                slots[path->n] = i;
                slots[path->n + 1] = j;

                /* Figure out the full sequence of buckets. */
                buckets[0] = path->start;
                for (k = 0; k <= path->n; k++) {
                    buckets[k + 1] = other_bucket_protected(impl, buckets[k], slots[k]);
                }

                /* Now the path is fully expressed.  One can start from
                 * buckets[0], go via slots[0] to buckets[1], via slots[1] to
                 * buckets[2], and so on.
                 *
                 * Move all the nodes across the path "backward".  After each
                 * step some node appears in two buckets.  Thus, every node is
                 * always visible to a concurrent search. */
                for (k = path->n + 1; k > 0; k--) {
                    uint64_t node = ccmap_node_get_protected
                        (&buckets[k - 1]->nodes[slots[k - 1]]);
                    ccmap_node_set_protected(&buckets[k]->nodes[slots[k]],
                                             node);
                }

                /* Finally, insert the count. */
                ccmap_set_bucket(buckets[0], slots[0], inc, hash);

                return inc;
            }

            if (path->n < MAX_DEPTH && head < MAX_QUEUE) {
                struct ccmap_path *new_path = &queue[head++];

                *new_path = *path;
                new_path->end = next;
                new_path->slots[new_path->n++] = i;
            }
        }
    }

    return 0;
}

/* Increments the count associated with 'hash', in 'impl', by 'inc'. */
static uint32_t
ccmap_try_inc(struct ccmap_impl *impl, uint32_t hash, uint32_t inc)
{
    uint32_t h1 = rehash(impl, hash);
    uint32_t h2 = other_hash(h1);
    struct ccmap_bucket *b1 = &impl->buckets[h1 & impl->mask];
    struct ccmap_bucket *b2 = &impl->buckets[h2 & impl->mask];
    uint32_t count;

    return OVS_UNLIKELY(count = ccmap_inc_bucket_existing(b1, hash, inc))
        ? count : OVS_UNLIKELY(count = ccmap_inc_bucket_existing(b2, hash, inc))
        ? count : OVS_LIKELY(count = ccmap_inc_bucket_new(b1, hash, inc))
        ? count : OVS_LIKELY(count = ccmap_inc_bucket_new(b2, hash, inc))
        ? count : ccmap_inc_bfs(impl, hash, b1, b2, inc);
}

/* Increments the count of 'hash' values in the 'ccmap'.  The caller must
 * ensure that 'ccmap' cannot change concurrently (from another thread).
 *
 * Returns the current count of the given hash value after the incremention. */
uint32_t
ccmap_inc(struct ccmap *ccmap, uint32_t hash)
{
    struct ccmap_impl *impl = ccmap_get_impl(ccmap);
    uint32_t count;

    if (OVS_UNLIKELY(impl->n_unique >= impl->max_n)) {
        COVERAGE_INC(ccmap_expand);
        impl = ccmap_rehash(ccmap, (impl->mask << 1) | 1);
    }

    while (OVS_UNLIKELY(!(count = ccmap_try_inc(impl, hash, 1)))) {
        impl = ccmap_rehash(ccmap, impl->mask);
    }
    ++impl->n;
    if (count == 1) {
        ++impl->n_unique;
    }
    return count;
}

/* Decrement the count associated with 'hash' in the bucket identified by
 * 'h'. Return the OLD count if successful, or 0. */
static uint32_t
ccmap_dec__(struct ccmap_impl *impl, uint32_t hash, uint32_t h)
{
    struct ccmap_bucket *b = &impl->buckets[h & impl->mask];
    uint32_t count;

    int slot = ccmap_find_slot_protected(b, hash, &count);
    if (slot < 0) {
        return 0;
    }

    ccmap_set_bucket(b, slot, count - 1, hash);
    return count;
}

/* Decrements the count associated with 'hash'.  The caller must
 * ensure that 'ccmap' cannot change concurrently (from another thread).
 *
 * Returns the current count related to 'hash' in the ccmap after the
 * decrement. */
uint32_t
ccmap_dec(struct ccmap *ccmap, uint32_t hash)
{
    struct ccmap_impl *impl = ccmap_get_impl(ccmap);
    uint32_t h1 = rehash(impl, hash);
    uint32_t h2 = other_hash(h1);

    uint32_t old_count = ccmap_dec__(impl, hash, h1);
    if (!old_count) {
        old_count = ccmap_dec__(impl, hash, h2);
    }
    ovs_assert(old_count);

    old_count--;

    if (old_count == 0) {
        impl->n_unique--;
        if (OVS_UNLIKELY(impl->n_unique < impl->min_n)) {
            COVERAGE_INC(ccmap_shrink);
            impl = ccmap_rehash(ccmap, impl->mask >> 1);
        }
    }
    impl->n--;
    return old_count;
}

static bool
ccmap_try_rehash(const struct ccmap_impl *old, struct ccmap_impl *new)
{
    const struct ccmap_bucket *b;

    for (b = old->buckets; b <= &old->buckets[old->mask]; b++) {
        for (int i = 0; i < CCMAP_K; i++) {
            uint64_t node = ccmap_node_get_protected(&b->nodes[i]);
            uint32_t count = ccmap_node_count(node);

            if (count && !ccmap_try_inc(new, ccmap_node_hash(node), count)) {
                return false;
            }
        }
    }
    return true;
}

static struct ccmap_impl *
ccmap_rehash(struct ccmap *ccmap, uint32_t mask)
{
    struct ccmap_impl *old = ccmap_get_impl(ccmap);
    struct ccmap_impl *new = ccmap_impl_create(mask);

    ovs_assert(old->n_unique < new->max_n);

    while (!ccmap_try_rehash(old, new)) {
        memset(new->buckets, 0, (mask + 1) * sizeof *new->buckets);
        new->basis = random_uint32();
    }

    new->n = old->n;
    new->n_unique = old->n_unique;
    ovsrcu_set(&ccmap->impl, new);
    ovsrcu_postpone(free_cacheline, old);

    return new;
}
