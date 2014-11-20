/*
 * Copyright (c) 2014 Nicira, Inc.
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
#include "cmap.h"
#include "coverage.h"
#include "bitmap.h"
#include "hash.h"
#include "ovs-rcu.h"
#include "random.h"
#include "util.h"

COVERAGE_DEFINE(cmap_expand);
COVERAGE_DEFINE(cmap_shrink);

/* Optimistic Concurrent Cuckoo Hash
 * =================================
 *
 * A "cuckoo hash" is an open addressing hash table schema, designed such that
 * a given element can be in one of only a small number of buckets 'd', each of
 * which holds up to a small number 'k' elements.  Thus, the expected and
 * worst-case lookup times are O(1) because they require comparing no more than
 * a fixed number of elements (k * d).  Inserting a new element can require
 * moving around existing elements, but it is also O(1) amortized expected
 * time.
 *
 * An optimistic concurrent hash table goes one step further, making it
 * possible for a single writer to execute concurrently with any number of
 * readers without requiring the readers to take any locks.
 *
 * This cuckoo hash implementation uses:
 *
 *    - Two hash functions (d=2).  More hash functions allow for a higher load
 *      factor, but increasing 'k' is easier and the benefits of increasing 'd'
 *      quickly fall off with the 'k' values used here.  Also, the method of
 *      generating hashes used in this implementation is hard to reasonably
 *      extend beyond d=2.  Finally, each additional hash function means that a
 *      lookup has to look at least one extra cache line.
 *
 *    - 5 or 7 elements per bucket (k=5 or k=7), chosen to make buckets
 *      exactly one cache line in size.
 *
 * According to Erlingsson [4], these parameters suggest a maximum load factor
 * of about 93%.  The current implementation is conservative, expanding the
 * hash table when it is over 85% full.
 *
 * When the load factor is below 20%, the hash table will be shrinked by half.
 * This is to reduce the memory utilization of the hash table and to avoid
 * the hash table occupying the top of heap chunk which prevents the trimming
 * of heap.
 *
 * Hash Functions
 * ==============
 *
 * A cuckoo hash requires multiple hash functions.  When reorganizing the hash
 * becomes too difficult, it also requires the ability to change the hash
 * functions.  Requiring the client to provide multiple hashes and to be able
 * to change them to new hashes upon insertion is inconvenient.
 *
 * This implementation takes another approach.  The client provides a single,
 * fixed hash.  The cuckoo hash internally "rehashes" this hash against a
 * randomly selected basis value (see rehash()).  This rehashed value is one of
 * the two hashes.  The other hash is computed by 16-bit circular rotation of
 * the rehashed value.  Updating the basis changes the hash functions.
 *
 * To work properly, the hash functions used by a cuckoo hash must be
 * independent.  If one hash function is a function of the other (e.g. h2(x) =
 * h1(x) + 1, or h2(x) = hash(h1(x))), then insertion will eventually fail
 * catastrophically (loop forever) because of collisions.  With this rehashing
 * technique, the two hashes are completely independent for masks up to 16 bits
 * wide.  For masks wider than 16 bits, only 32-n bits are independent between
 * the two hashes.  Thus, it becomes risky to grow a cuckoo hash table beyond
 * about 2**24 buckets (about 71 million elements with k=5 and maximum load
 * 85%).  Fortunately, Open vSwitch does not normally deal with hash tables
 * this large.
 *
 *
 * Handling Duplicates
 * ===================
 *
 * This cuckoo hash table implementation deals with duplicate client-provided
 * hash values by chaining: the second and subsequent cmap_nodes with a given
 * hash are chained off the initially inserted node's 'next' member.  The hash
 * table maintains the invariant that a single client-provided hash value
 * exists in only a single chain in a single bucket (even though that hash
 * could be stored in two buckets).
 *
 *
 * References
 * ==========
 *
 * [1] D. Zhou, B. Fan, H. Lim, M. Kaminsky, D. G. Andersen, "Scalable, High
 *     Performance Ethernet Forwarding with CuckooSwitch".  In Proc. 9th
 *     CoNEXT, Dec. 2013.
 *
 * [2] B. Fan, D. G. Andersen, and M. Kaminsky. "MemC3: Compact and concurrent
 *     memcache with dumber caching and smarter hashing".  In Proc. 10th USENIX
 *     NSDI, Apr. 2013
 *
 * [3] R. Pagh and F. Rodler. "Cuckoo hashing". Journal of Algorithms, 51(2):
 *     122-144, May 2004.
 *
 * [4] U. Erlingsson, M. Manasse, F. McSherry, "A Cool and Practical
 *     Alternative to Traditional Hash Tables".  In Proc. 7th Workshop on
 *     Distributed Data and Structures (WDAS'06), 2006.
 */
/* An entry is an int and a pointer: 8 bytes on 32-bit, 12 bytes on 64-bit. */
#define CMAP_ENTRY_SIZE (4 + (UINTPTR_MAX == UINT32_MAX ? 4 : 8))

/* Number of entries per bucket: 7 on 32-bit, 5 on 64-bit. */
#define CMAP_K ((CACHE_LINE_SIZE - 4) / CMAP_ENTRY_SIZE)

/* Pad to make a bucket a full cache line in size: 4 on 32-bit, 0 on 64-bit. */
#define CMAP_PADDING ((CACHE_LINE_SIZE - 4) - (CMAP_K * CMAP_ENTRY_SIZE))

/* A cuckoo hash bucket.  Designed to be cache-aligned and exactly one cache
 * line long. */
struct cmap_bucket {
    /* Allows readers to track in-progress changes.  Initially zero, each
     * writer increments this value just before and just after each change (see
     * cmap_set_bucket()).  Thus, a reader can ensure that it gets a consistent
     * snapshot by waiting for the counter to become even (see
     * read_even_counter()), then checking that its value does not change while
     * examining the bucket (see cmap_find()). */
    atomic_uint32_t counter;

    /* (hash, node) slots.  They are parallel arrays instead of an array of
     * structs to reduce the amount of space lost to padding.
     *
     * The slots are in no particular order.  A null pointer indicates that a
     * pair is unused.  In-use slots are not necessarily in the earliest
     * slots. */
    uint32_t hashes[CMAP_K];
    struct cmap_node nodes[CMAP_K];

    /* Padding to make cmap_bucket exactly one cache line long. */
#if CMAP_PADDING > 0
    uint8_t pad[CMAP_PADDING];
#endif
};
BUILD_ASSERT_DECL(sizeof(struct cmap_bucket) == CACHE_LINE_SIZE);

/* Default maximum load factor (as a fraction of UINT32_MAX + 1) before
 * enlarging a cmap.  Reasonable values lie between about 75% and 93%.  Smaller
 * values waste memory; larger values increase the average insertion time. */
#define CMAP_MAX_LOAD ((uint32_t) (UINT32_MAX * .85))

/* Default minimum load factor (as a fraction of UINT32_MAX + 1) before
 * shrinking a cmap.  Currently, the value is chosen to be 20%, this
 * means cmap will have a 40% load factor after shrink. */
#define CMAP_MIN_LOAD ((uint32_t) (UINT32_MAX * .20))

/* The implementation of a concurrent hash map. */
struct cmap_impl {
    unsigned int n;             /* Number of in-use elements. */
    unsigned int max_n;         /* Max elements before enlarging. */
    unsigned int min_n;         /* Min elements before shrinking. */
    uint32_t mask;              /* Number of 'buckets', minus one. */
    uint32_t basis;             /* Basis for rehashing client's hash values. */

    /* Padding to make cmap_impl exactly one cache line long. */
    uint8_t pad[CACHE_LINE_SIZE - sizeof(unsigned int) * 5];

    struct cmap_bucket buckets[];
};
BUILD_ASSERT_DECL(sizeof(struct cmap_impl) == CACHE_LINE_SIZE);

static struct cmap_impl *cmap_rehash(struct cmap *, uint32_t mask);

/* Explicit inline keywords in utility functions seem to be necessary
 * to prevent performance regression on cmap_find(). */

/* Given a rehashed value 'hash', returns the other hash for that rehashed
 * value.  This is symmetric: other_hash(other_hash(x)) == x.  (See also "Hash
 * Functions" at the top of this file.) */
static inline uint32_t
other_hash(uint32_t hash)
{
    return (hash << 16) | (hash >> 16);
}

/* Returns the rehashed value for 'hash' within 'impl'.  (See also "Hash
 * Functions" at the top of this file.) */
static inline uint32_t
rehash(const struct cmap_impl *impl, uint32_t hash)
{
    return hash_finish(impl->basis, hash);
}

/* Not always without the inline keyword. */
static inline struct cmap_impl *
cmap_get_impl(const struct cmap *cmap)
{
    return ovsrcu_get(struct cmap_impl *, &cmap->impl);
}

static uint32_t
calc_max_n(uint32_t mask)
{
    return ((uint64_t) (mask + 1) * CMAP_K * CMAP_MAX_LOAD) >> 32;
}

static uint32_t
calc_min_n(uint32_t mask)
{
    return ((uint64_t) (mask + 1) * CMAP_K * CMAP_MIN_LOAD) >> 32;
}

static struct cmap_impl *
cmap_impl_create(uint32_t mask)
{
    struct cmap_impl *impl;

    ovs_assert(is_pow2(mask + 1));

    impl = xzalloc_cacheline(sizeof *impl
                             + (mask + 1) * sizeof *impl->buckets);
    impl->n = 0;
    impl->max_n = calc_max_n(mask);
    impl->min_n = calc_min_n(mask);
    impl->mask = mask;
    impl->basis = random_uint32();

    return impl;
}

/* Initializes 'cmap' as an empty concurrent hash map. */
void
cmap_init(struct cmap *cmap)
{
    ovsrcu_set(&cmap->impl, cmap_impl_create(0));
}

/* Destroys 'cmap'.
 *
 * The client is responsible for destroying any data previously held in
 * 'cmap'. */
void
cmap_destroy(struct cmap *cmap)
{
    if (cmap) {
        ovsrcu_postpone(free_cacheline, cmap_get_impl(cmap));
    }
}

/* Returns the number of elements in 'cmap'. */
size_t
cmap_count(const struct cmap *cmap)
{
    return cmap_get_impl(cmap)->n;
}

/* Returns true if 'cmap' is empty, false otherwise. */
bool
cmap_is_empty(const struct cmap *cmap)
{
    return cmap_count(cmap) == 0;
}

static inline uint32_t
read_counter(const struct cmap_bucket *bucket_)
{
    struct cmap_bucket *bucket = CONST_CAST(struct cmap_bucket *, bucket_);
    uint32_t counter;

    atomic_read_explicit(&bucket->counter, &counter, memory_order_acquire);

    return counter;
}

static inline uint32_t
read_even_counter(const struct cmap_bucket *bucket)
{
    uint32_t counter;

    do {
        counter = read_counter(bucket);
    } while (OVS_UNLIKELY(counter & 1));

    return counter;
}

static inline bool
counter_changed(const struct cmap_bucket *b_, uint32_t c)
{
    struct cmap_bucket *b = CONST_CAST(struct cmap_bucket *, b_);
    uint32_t counter;

    /* Need to make sure the counter read is not moved up, before the hash and
     * cmap_node_next().  Using atomic_read_explicit with memory_order_acquire
     * would allow prior reads to be moved after the barrier.
     * atomic_thread_fence prevents all following memory accesses from moving
     * prior to preceding loads. */
    atomic_thread_fence(memory_order_acquire);
    atomic_read_relaxed(&b->counter, &counter);

    return OVS_UNLIKELY(counter != c);
}

static inline const struct cmap_node *
cmap_find_in_bucket(const struct cmap_bucket *bucket, uint32_t hash)
{
    for (int i = 0; i < CMAP_K; i++) {
        if (bucket->hashes[i] == hash) {
            return cmap_node_next(&bucket->nodes[i]);
        }
    }
    return NULL;
}

static inline const struct cmap_node *
cmap_find__(const struct cmap_bucket *b1, const struct cmap_bucket *b2,
            uint32_t hash)
{
    uint32_t c1, c2;
    const struct cmap_node *node;

    do {
        do {
            c1 = read_even_counter(b1);
            node = cmap_find_in_bucket(b1, hash);
        } while (OVS_UNLIKELY(counter_changed(b1, c1)));
        if (node) {
            break;
        }
        do {
            c2 = read_even_counter(b2);
            node = cmap_find_in_bucket(b2, hash);
        } while (OVS_UNLIKELY(counter_changed(b2, c2)));
        if (node) {
            break;
        }
    } while (OVS_UNLIKELY(counter_changed(b1, c1)));

    return node;
}

/* Searches 'cmap' for an element with the specified 'hash'.  If one or more is
 * found, returns a pointer to the first one, otherwise a null pointer.  All of
 * the nodes on the returned list are guaranteed to have exactly the given
 * 'hash'.
 *
 * This function works even if 'cmap' is changing concurrently.  If 'cmap' is
 * not changing, then cmap_find_protected() is slightly faster.
 *
 * CMAP_FOR_EACH_WITH_HASH is usually more convenient. */
const struct cmap_node *
cmap_find(const struct cmap *cmap, uint32_t hash)
{
    const struct cmap_impl *impl = cmap_get_impl(cmap);
    uint32_t h1 = rehash(impl, hash);
    uint32_t h2 = other_hash(h1);

    return cmap_find__(&impl->buckets[h1 & impl->mask],
                       &impl->buckets[h2 & impl->mask],
                       hash);
}

/* Looks up multiple 'hashes', when the corresponding bit in 'map' is 1,
 * and sets the corresponding pointer in 'nodes', if the hash value was
 * found from the 'cmap'.  In other cases the 'nodes' values are not changed,
 * i.e., no NULL pointers are stored there.
 * Returns a map where a bit is set to 1 if the corresponding 'nodes' pointer
 * was stored, 0 otherwise.
 * Generally, the caller wants to use CMAP_NODE_FOR_EACH to verify for
 * hash collisions. */
unsigned long
cmap_find_batch(const struct cmap *cmap, unsigned long map,
                uint32_t hashes[], const struct cmap_node *nodes[])
{
    const struct cmap_impl *impl = cmap_get_impl(cmap);
    unsigned long result = map;
    int i;
    uint32_t h1s[sizeof map * CHAR_BIT];
    const struct cmap_bucket *b1s[sizeof map * CHAR_BIT];
    const struct cmap_bucket *b2s[sizeof map * CHAR_BIT];
    uint32_t c1s[sizeof map * CHAR_BIT];

    /* Compute hashes and prefetch 1st buckets. */
    ULONG_FOR_EACH_1(i, map) {
        h1s[i] = rehash(impl, hashes[i]);
        b1s[i] = &impl->buckets[h1s[i] & impl->mask];
        OVS_PREFETCH(b1s[i]);
    }
    /* Lookups, Round 1. Only look up at the first bucket. */
    ULONG_FOR_EACH_1(i, map) {
        uint32_t c1;
        const struct cmap_bucket *b1 = b1s[i];
        const struct cmap_node *node;

        do {
            c1 = read_even_counter(b1);
            node = cmap_find_in_bucket(b1, hashes[i]);
        } while (OVS_UNLIKELY(counter_changed(b1, c1)));

        if (!node) {
            /* Not found (yet); Prefetch the 2nd bucket. */
            b2s[i] = &impl->buckets[other_hash(h1s[i]) & impl->mask];
            OVS_PREFETCH(b2s[i]);
            c1s[i] = c1; /* We may need to check this after Round 2. */
            continue;
        }
        /* Found. */
        ULONG_SET0(map, i); /* Ignore this on round 2. */
        OVS_PREFETCH(node);
        nodes[i] = node;
    }
    /* Round 2. Look into the 2nd bucket, if needed. */
    ULONG_FOR_EACH_1(i, map) {
        uint32_t c2;
        const struct cmap_bucket *b2 = b2s[i];
        const struct cmap_node *node;

        do {
            c2 = read_even_counter(b2);
            node = cmap_find_in_bucket(b2, hashes[i]);
        } while (OVS_UNLIKELY(counter_changed(b2, c2)));

        if (!node) {
            /* Not found, but the node may have been moved from b2 to b1 right
             * after we finished with b1 earlier.  We just got a clean reading
             * of the 2nd bucket, so we check the counter of the 1st bucket
             * only.  However, we need to check both buckets again, as the
             * entry may be moved again to the 2nd bucket.  Basically, we
             * need to loop as long as it takes to get stable readings of
             * both buckets.  cmap_find__() does that, and now that we have
             * fetched both buckets we can just use it. */
            if (OVS_UNLIKELY(counter_changed(b1s[i], c1s[i]))) {
                node = cmap_find__(b1s[i], b2s[i], hashes[i]);
                if (node) {
                    goto found;
                }
            }
            /* Not found. */
            ULONG_SET0(result, i); /* Fix the result. */
            continue;
        }
found:
        OVS_PREFETCH(node);
        nodes[i] = node;
    }
    return result;
}

static int
cmap_find_slot_protected(struct cmap_bucket *b, uint32_t hash)
{
    int i;

    for (i = 0; i < CMAP_K; i++) {
        if (b->hashes[i] == hash && cmap_node_next_protected(&b->nodes[i])) {
            return i;
        }
    }
    return -1;
}

static struct cmap_node *
cmap_find_bucket_protected(struct cmap_impl *impl, uint32_t hash, uint32_t h)
{
    struct cmap_bucket *b = &impl->buckets[h & impl->mask];
    int i;

    for (i = 0; i < CMAP_K; i++) {
        if (b->hashes[i] == hash) {
            return cmap_node_next_protected(&b->nodes[i]);
        }
    }
    return NULL;
}

/* Like cmap_find(), but only for use if 'cmap' cannot change concurrently.
 *
 * CMAP_FOR_EACH_WITH_HASH_PROTECTED is usually more convenient. */
struct cmap_node *
cmap_find_protected(const struct cmap *cmap, uint32_t hash)
{
    struct cmap_impl *impl = cmap_get_impl(cmap);
    uint32_t h1 = rehash(impl, hash);
    uint32_t h2 = other_hash(hash);
    struct cmap_node *node;

    node = cmap_find_bucket_protected(impl, hash, h1);
    if (node) {
        return node;
    }
    return cmap_find_bucket_protected(impl, hash, h2);
}

static int
cmap_find_empty_slot_protected(const struct cmap_bucket *b)
{
    int i;

    for (i = 0; i < CMAP_K; i++) {
        if (!cmap_node_next_protected(&b->nodes[i])) {
            return i;
        }
    }
    return -1;
}

static void
cmap_set_bucket(struct cmap_bucket *b, int i,
                struct cmap_node *node, uint32_t hash)
{
    uint32_t c;

    atomic_read_explicit(&b->counter, &c, memory_order_acquire);
    atomic_store_explicit(&b->counter, c + 1, memory_order_release);
    ovsrcu_set(&b->nodes[i].next, node); /* Also atomic. */
    b->hashes[i] = hash;
    atomic_store_explicit(&b->counter, c + 2, memory_order_release);
}

/* Searches 'b' for a node with the given 'hash'.  If it finds one, adds
 * 'new_node' to the node's linked list and returns true.  If it does not find
 * one, returns false. */
static bool
cmap_insert_dup(struct cmap_node *new_node, uint32_t hash,
                struct cmap_bucket *b)
{
    int i;

    for (i = 0; i < CMAP_K; i++) {
        if (b->hashes[i] == hash) {
            struct cmap_node *node = cmap_node_next_protected(&b->nodes[i]);

            if (node) {
                struct cmap_node *p;

                /* The common case is that 'new_node' is a singleton,
                 * with a null 'next' pointer.  Rehashing can add a
                 * longer chain, but due to our invariant of always
                 * having all nodes with the same (user) hash value at
                 * a single chain, rehashing will always insert the
                 * chain to an empty node.  The only way we can end up
                 * here is by the user inserting a chain of nodes at
                 * once.  Find the end of the chain starting at
                 * 'new_node', then splice 'node' to the end of that
                 * chain. */
                p = new_node;
                for (;;) {
                    struct cmap_node *next = cmap_node_next_protected(p);

                    if (!next) {
                        break;
                    }
                    p = next;
                }
                ovsrcu_set_hidden(&p->next, node);
            } else {
                /* The hash value is there from some previous insertion, but
                 * the associated node has been removed.  We're not really
                 * inserting a duplicate, but we can still reuse the slot.
                 * Carry on. */
            }

            /* Change the bucket to point to 'new_node'.  This is a degenerate
             * form of cmap_set_bucket() that doesn't update the counter since
             * we're only touching one field and in a way that doesn't change
             * the bucket's meaning for readers. */
            ovsrcu_set(&b->nodes[i].next, new_node);

            return true;
        }
    }
    return false;
}

/* Searches 'b' for an empty slot.  If successful, stores 'node' and 'hash' in
 * the slot and returns true.  Otherwise, returns false. */
static bool
cmap_insert_bucket(struct cmap_node *node, uint32_t hash,
                   struct cmap_bucket *b)
{
    int i;

    for (i = 0; i < CMAP_K; i++) {
        if (!cmap_node_next_protected(&b->nodes[i])) {
            cmap_set_bucket(b, i, node, hash);
            return true;
        }
    }
    return false;
}

/* Returns the other bucket that b->nodes[slot] could occupy in 'impl'.  (This
 * might be the same as 'b'.) */
static struct cmap_bucket *
other_bucket_protected(struct cmap_impl *impl, struct cmap_bucket *b, int slot)
{
    uint32_t h1 = rehash(impl, b->hashes[slot]);
    uint32_t h2 = other_hash(h1);
    uint32_t b_idx = b - impl->buckets;
    uint32_t other_h = (h1 & impl->mask) == b_idx ? h2 : h1;

    return &impl->buckets[other_h & impl->mask];
}

/* 'new_node' is to be inserted into 'impl', but both candidate buckets 'b1'
 * and 'b2' are full.  This function attempts to rearrange buckets within
 * 'impl' to make room for 'new_node'.
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
static bool
cmap_insert_bfs(struct cmap_impl *impl, struct cmap_node *new_node,
                uint32_t hash, struct cmap_bucket *b1, struct cmap_bucket *b2)
{
    enum { MAX_DEPTH = 4 };

    /* A path from 'start' to 'end' via the 'n' steps in 'slots[]'.
     *
     * One can follow the path via:
     *
     *     struct cmap_bucket *b;
     *     int i;
     *
     *     b = path->start;
     *     for (i = 0; i < path->n; i++) {
     *         b = other_bucket_protected(impl, b, path->slots[i]);
     *     }
     *     ovs_assert(b == path->end);
     */
    struct cmap_path {
        struct cmap_bucket *start; /* First bucket along the path. */
        struct cmap_bucket *end;   /* Last bucket on the path. */
        uint8_t slots[MAX_DEPTH];  /* Slots used for each hop. */
        int n;                     /* Number of slots[]. */
    };

    /* We need to limit the amount of work we do trying to find a path.  It
     * might actually be impossible to rearrange the cmap, and after some time
     * it is likely to be easier to rehash the entire cmap.
     *
     * This value of MAX_QUEUE is an arbitrary limit suggested by one of the
     * references.  Empirically, it seems to work OK. */
    enum { MAX_QUEUE = 500 };
    struct cmap_path queue[MAX_QUEUE];
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
        const struct cmap_path *path = &queue[tail++];
        struct cmap_bucket *this = path->end;
        int i;

        for (i = 0; i < CMAP_K; i++) {
            struct cmap_bucket *next = other_bucket_protected(impl, this, i);
            int j;

            if (this == next) {
                continue;
            }

            j = cmap_find_empty_slot_protected(next);
            if (j >= 0) {
                /* We've found a path along which we can rearrange the hash
                 * table:  Start at path->start, follow all the slots in
                 * path->slots[], then follow slot 'i', then the bucket you
                 * arrive at has slot 'j' empty. */
                struct cmap_bucket *buckets[MAX_DEPTH + 2];
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
                    int slot = slots[k - 1];

                    cmap_set_bucket(
                        buckets[k], slots[k],
                        cmap_node_next_protected(&buckets[k - 1]->nodes[slot]),
                        buckets[k - 1]->hashes[slot]);
                }

                /* Finally, replace the first node on the path by
                 * 'new_node'. */
                cmap_set_bucket(buckets[0], slots[0], new_node, hash);

                return true;
            }

            if (path->n < MAX_DEPTH && head < MAX_QUEUE) {
                struct cmap_path *new_path = &queue[head++];

                *new_path = *path;
                new_path->end = next;
                new_path->slots[new_path->n++] = i;
            }
        }
    }

    return false;
}

/* Adds 'node', with the given 'hash', to 'impl'.
 *
 * 'node' is ordinarily a single node, with a null 'next' pointer.  When
 * rehashing, however, it may be a longer chain of nodes. */
static bool
cmap_try_insert(struct cmap_impl *impl, struct cmap_node *node, uint32_t hash)
{
    uint32_t h1 = rehash(impl, hash);
    uint32_t h2 = other_hash(h1);
    struct cmap_bucket *b1 = &impl->buckets[h1 & impl->mask];
    struct cmap_bucket *b2 = &impl->buckets[h2 & impl->mask];

    return (OVS_UNLIKELY(cmap_insert_dup(node, hash, b1) ||
                         cmap_insert_dup(node, hash, b2)) ||
            OVS_LIKELY(cmap_insert_bucket(node, hash, b1) ||
                       cmap_insert_bucket(node, hash, b2)) ||
            cmap_insert_bfs(impl, node, hash, b1, b2));
}

/* Inserts 'node', with the given 'hash', into 'cmap'.  The caller must ensure
 * that 'cmap' cannot change concurrently (from another thread).  If duplicates
 * are undesirable, the caller must have already verified that 'cmap' does not
 * contain a duplicate of 'node'.
 *
 * Returns the current number of nodes in the cmap after the insertion. */
size_t
cmap_insert(struct cmap *cmap, struct cmap_node *node, uint32_t hash)
{
    struct cmap_impl *impl = cmap_get_impl(cmap);

    ovsrcu_set_hidden(&node->next, NULL);

    if (OVS_UNLIKELY(impl->n >= impl->max_n)) {
        COVERAGE_INC(cmap_expand);
        impl = cmap_rehash(cmap, (impl->mask << 1) | 1);
    }

    while (OVS_UNLIKELY(!cmap_try_insert(impl, node, hash))) {
        impl = cmap_rehash(cmap, impl->mask);
    }
    return ++impl->n;
}

static bool
cmap_replace__(struct cmap_impl *impl, struct cmap_node *node,
               struct cmap_node *replacement, uint32_t hash, uint32_t h)
{
    struct cmap_bucket *b = &impl->buckets[h & impl->mask];
    int slot;

    slot = cmap_find_slot_protected(b, hash);
    if (slot < 0) {
        return false;
    }

    /* The pointer to 'node' is changed to point to 'replacement',
     * which is the next node if no replacement node is given. */
    if (!replacement) {
        replacement = cmap_node_next_protected(node);
    } else {
        /* 'replacement' takes the position of 'node' in the list. */
        ovsrcu_set_hidden(&replacement->next, cmap_node_next_protected(node));
    }

    struct cmap_node *iter = &b->nodes[slot];
    for (;;) {
        struct cmap_node *next = cmap_node_next_protected(iter);

        if (next == node) {
            ovsrcu_set(&iter->next, replacement);
            return true;
        }
        iter = next;
    }
}

/* Replaces 'old_node' in 'cmap' with 'new_node'.  The caller must
 * ensure that 'cmap' cannot change concurrently (from another thread).
 *
 * 'old_node' must not be destroyed or modified or inserted back into 'cmap' or
 * into any other concurrent hash map while any other thread might be accessing
 * it.  One correct way to do this is to free it from an RCU callback with
 * ovsrcu_postpone().
 *
 * Returns the current number of nodes in the cmap after the replacement.  The
 * number of nodes decreases by one if 'new_node' is NULL. */
size_t
cmap_replace(struct cmap *cmap, struct cmap_node *old_node,
             struct cmap_node *new_node, uint32_t hash)
{
    struct cmap_impl *impl = cmap_get_impl(cmap);
    uint32_t h1 = rehash(impl, hash);
    uint32_t h2 = other_hash(h1);
    bool ok;

    ok = cmap_replace__(impl, old_node, new_node, hash, h1)
        || cmap_replace__(impl, old_node, new_node, hash, h2);
    ovs_assert(ok);

    if (!new_node) {
        impl->n--;
        if (OVS_UNLIKELY(impl->n < impl->min_n)) {
            COVERAGE_INC(cmap_shrink);
            impl = cmap_rehash(cmap, impl->mask >> 1);
        }
    }
    return impl->n;
}

static bool
cmap_try_rehash(const struct cmap_impl *old, struct cmap_impl *new)
{
    const struct cmap_bucket *b;

    for (b = old->buckets; b <= &old->buckets[old->mask]; b++) {
        int i;

        for (i = 0; i < CMAP_K; i++) {
            /* possible optimization here because we know the hashes are
             * unique */
            struct cmap_node *node = cmap_node_next_protected(&b->nodes[i]);

            if (node && !cmap_try_insert(new, node, b->hashes[i])) {
                return false;
            }
        }
    }
    return true;
}

static struct cmap_impl *
cmap_rehash(struct cmap *cmap, uint32_t mask)
{
    struct cmap_impl *old = cmap_get_impl(cmap);
    struct cmap_impl *new;

    new = cmap_impl_create(mask);
    ovs_assert(old->n < new->max_n);

    while (!cmap_try_rehash(old, new)) {
        memset(new->buckets, 0, (mask + 1) * sizeof *new->buckets);
        new->basis = random_uint32();
    }

    new->n = old->n;
    ovsrcu_set(&cmap->impl, new);
    ovsrcu_postpone(free_cacheline, old);

    return new;
}

struct cmap_cursor
cmap_cursor_start(const struct cmap *cmap)
{
    struct cmap_cursor cursor;

    cursor.impl = cmap_get_impl(cmap);
    cursor.bucket_idx = 0;
    cursor.entry_idx = 0;
    cursor.node = NULL;
    cmap_cursor_advance(&cursor);

    return cursor;
}

void
cmap_cursor_advance(struct cmap_cursor *cursor)
{
    const struct cmap_impl *impl = cursor->impl;

    if (cursor->node) {
        cursor->node = cmap_node_next(cursor->node);
        if (cursor->node) {
            return;
        }
    }

    while (cursor->bucket_idx <= impl->mask) {
        const struct cmap_bucket *b = &impl->buckets[cursor->bucket_idx];

        while (cursor->entry_idx < CMAP_K) {
            cursor->node = cmap_node_next(&b->nodes[cursor->entry_idx++]);
            if (cursor->node) {
                return;
            }
        }

        cursor->bucket_idx++;
        cursor->entry_idx = 0;
    }
}

/* Returns the next node in 'cmap' in hash order, or NULL if no nodes remain in
 * 'cmap'.  Uses '*pos' to determine where to begin iteration, and updates
 * '*pos' to pass on the next iteration into them before returning.
 *
 * It's better to use plain CMAP_FOR_EACH and related functions, since they are
 * faster and better at dealing with cmaps that change during iteration.
 *
 * Before beginning iteration, set '*pos' to all zeros. */
struct cmap_node *
cmap_next_position(const struct cmap *cmap,
                   struct cmap_position *pos)
{
    struct cmap_impl *impl = cmap_get_impl(cmap);
    unsigned int bucket = pos->bucket;
    unsigned int entry = pos->entry;
    unsigned int offset = pos->offset;

    while (bucket <= impl->mask) {
        const struct cmap_bucket *b = &impl->buckets[bucket];

        while (entry < CMAP_K) {
            const struct cmap_node *node = cmap_node_next(&b->nodes[entry]);
            unsigned int i;

            for (i = 0; node; i++, node = cmap_node_next(node)) {
                if (i == offset) {
                    if (cmap_node_next(node)) {
                        offset++;
                    } else {
                        entry++;
                        offset = 0;
                    }
                    pos->bucket = bucket;
                    pos->entry = entry;
                    pos->offset = offset;
                    return CONST_CAST(struct cmap_node *, node);
                }
            }

            entry++;
            offset = 0;
        }

        bucket++;
        entry = offset = 0;
    }

    pos->bucket = pos->entry = pos->offset = 0;
    return NULL;
}
