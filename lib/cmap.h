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

#ifndef CMAP_H
#define CMAP_H 1

#include <stdbool.h>
#include <stdint.h>
#include "ovs-rcu.h"
#include "util.h"

/* Concurrent hash map
 * ===================
 *
 * A single-writer, multiple-reader hash table that efficiently supports
 * duplicates.
 *
 *
 * Thread-safety
 * =============
 *
 * The general rules are:
 *
 *    - Only a single thread may safely call into cmap_insert(),
 *      cmap_remove(), or cmap_replace() at any given time.
 *
 *    - Any number of threads may use functions and macros that search or
 *      iterate through a given cmap, even in parallel with other threads
 *      calling cmap_insert(), cmap_remove(), or cmap_replace().
 *
 *      There is one exception: cmap_find_protected() is only safe if no thread
 *      is currently calling cmap_insert(), cmap_remove(), or cmap_replace().
 *      (Use ordinary cmap_find() if that is not guaranteed.)
 *
 *    - See "Iteration" below for additional thread safety rules.
 *
 * Writers must use special care to ensure that any elements that they remove
 * do not get freed or reused until readers have finished with them.  This
 * includes inserting the element back into its original cmap or a different
 * one.  One correct way to do this is to free them from an RCU callback with
 * ovsrcu_postpone().
 */

/* A concurrent hash map node, to be embedded inside the data structure being
 * mapped.
 *
 * All nodes linked together on a chain have exactly the same hash value. */
struct cmap_node {
    OVSRCU_TYPE(struct cmap_node *) next; /* Next node with same hash. */
};

static inline struct cmap_node *
cmap_node_next(const struct cmap_node *node)
{
    return ovsrcu_get(struct cmap_node *, &node->next);
}

static inline struct cmap_node *
cmap_node_next_protected(const struct cmap_node *node)
{
    return ovsrcu_get_protected(struct cmap_node *, &node->next);
}

/* Concurrent hash map. */
struct cmap {
    OVSRCU_TYPE(struct cmap_impl *) impl;
};

/* Initializer for an empty cmap. */
#define CMAP_INITIALIZER {                                              \
        .impl = OVSRCU_INITIALIZER((struct cmap_impl *) &empty_cmap)    \
    }
extern OVS_ALIGNED_VAR(CACHE_LINE_SIZE) const struct cmap_impl empty_cmap;

/* Initialization. */
void cmap_init(struct cmap *);
void cmap_destroy(struct cmap *);

/* Count. */
size_t cmap_count(const struct cmap *);
bool cmap_is_empty(const struct cmap *);

/* Insertion and deletion.  Return the current count after the operation. */
size_t cmap_insert(struct cmap *, struct cmap_node *, uint32_t hash);
static inline size_t cmap_remove(struct cmap *, struct cmap_node *,
                                 uint32_t hash);
size_t cmap_replace(struct cmap *, struct cmap_node *old_node,
                    struct cmap_node *new_node, uint32_t hash);

/* Search.
 *
 * These macros iterate NODE over all of the nodes in CMAP that have hash value
 * equal to HASH.  MEMBER must be the name of the 'struct cmap_node' member
 * within NODE.
 *
 * CMAP and HASH are evaluated only once.  NODE is evaluated many times.
 *
 *
 * Thread-safety
 * =============
 *
 * CMAP_NODE_FOR_EACH will reliably visit each of the nodes starting with
 * CMAP_NODE, even with concurrent insertions and deletions.  (Of
 * course, if nodes are being inserted or deleted, it might or might not visit
 * the nodes actually being inserted or deleted.)
 *
 * CMAP_NODE_FOR_EACH_PROTECTED may only be used if the containing CMAP is
 * guaranteed not to change during iteration.  It may be only slightly faster.
 *
 * CMAP_FOR_EACH_WITH_HASH will reliably visit each of the nodes with the
 * specified hash in CMAP, even with concurrent insertions and deletions.  (Of
 * course, if nodes with the given HASH are being inserted or deleted, it might
 * or might not visit the nodes actually being inserted or deleted.)
 *
 * CMAP_FOR_EACH_WITH_HASH_PROTECTED may only be used if CMAP is guaranteed not
 * to change during iteration.  It may be very slightly faster.
 */
#define CMAP_NODE_FOR_EACH(NODE, MEMBER, CMAP_NODE)                     \
    for (INIT_CONTAINER(NODE, CMAP_NODE, MEMBER);                       \
         (NODE) != OBJECT_CONTAINING(NULL, NODE, MEMBER);               \
         ASSIGN_CONTAINER(NODE, cmap_node_next(&(NODE)->MEMBER), MEMBER))
#define CMAP_NODE_FOR_EACH_PROTECTED(NODE, MEMBER, CMAP_NODE)           \
    for (INIT_CONTAINER(NODE, CMAP_NODE, MEMBER);                       \
         (NODE) != OBJECT_CONTAINING(NULL, NODE, MEMBER);               \
         ASSIGN_CONTAINER(NODE, cmap_node_next_protected(&(NODE)->MEMBER), \
                          MEMBER))
#define CMAP_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, CMAP)   \
    CMAP_NODE_FOR_EACH(NODE, MEMBER, cmap_find(CMAP, HASH))
#define CMAP_FOR_EACH_WITH_HASH_PROTECTED(NODE, MEMBER, HASH, CMAP)     \
    CMAP_NODE_FOR_EACH_PROTECTED(NODE, MEMBER, cmap_find_protected(CMAP, HASH))

const struct cmap_node *cmap_find(const struct cmap *, uint32_t hash);
struct cmap_node *cmap_find_protected(const struct cmap *, uint32_t hash);

/* Find node by index or find index by hash. The 'index' of a cmap entry is a
 * way to combine the specific bucket and the entry of the bucket into a
 * convenient single integer value. In other words, it is the index of the
 * entry and each entry has an unique index. It is not used internally by
 * cmap.
 * Currently the functions assume index will not be larger than uint32_t. In
 * OvS table size is usually much smaller than this size.*/
const struct cmap_node * cmap_find_by_index(const struct cmap *,
                                            uint32_t index);
uint32_t cmap_find_index(const struct cmap *, uint32_t hash);

/* Looks up multiple 'hashes', when the corresponding bit in 'map' is 1,
 * and sets the corresponding pointer in 'nodes', if the hash value was
 * found from the 'cmap'.  In other cases the 'nodes' values are not changed,
 * i.e., no NULL pointers are stored there.
 * Returns a map where a bit is set to 1 if the corresponding 'nodes' pointer
 * was stored, 0 otherwise.
 * Generally, the caller wants to use CMAP_NODE_FOR_EACH to verify for
 * hash collisions. */
unsigned long cmap_find_batch(const struct cmap *cmap, unsigned long map,
                              uint32_t hashes[],
                              const struct cmap_node *nodes[]);

/* Iteration.
 *
 *
 * Thread-safety
 * =============
 *
 * Iteration is safe even in a cmap that is changing concurrently.  However:
 *
 *     - In the presence of concurrent calls to cmap_insert(), any given
 *       iteration might skip some nodes and might visit some nodes more than
 *       once.  If this is a problem, then the iterating code should lock the
 *       data structure (a rwlock can be used to allow multiple threads to
 *       iterate in parallel).
 *
 *     - Concurrent calls to cmap_remove() don't have the same problem.  (A
 *       node being deleted may be visited once or not at all.  Other nodes
 *       will be visited once.)
 *
 *     - If the cmap is changing, it is not safe to quiesce while iterating.
 *       Even if the changes are done by the same thread that's performing the
 *       iteration (Corollary: it is not safe to call cmap_remove() and quiesce
 *       in the loop body).
 *
 *
 * Example
 * =======
 *
 *     struct my_node {
 *         struct cmap_node cmap_node;
 *         int extra_data;
 *     };
 *
 *     struct cmap my_map;
 *     struct my_node *my_node;
 *
 *     cmap_init(&my_map);
 *     ...add data...
 *     CMAP_FOR_EACH (my_node, cmap_node, &my_map) {
 *         ...operate on my_node...
 *     }
 *
 * CMAP_FOR_EACH is "safe" in the sense of HMAP_FOR_EACH_SAFE.  That is, it is
 * safe to free the current node before going on to the next iteration.  Most
 * of the time, though, this doesn't matter for a cmap because node
 * deallocation has to be postponed until the next grace period.  This means
 * that this guarantee is useful only in deallocation code already executing at
 * postponed time, when it is known that the RCU grace period has already
 * expired.
 */

#define CMAP_CURSOR_FOR_EACH__(NODE, CURSOR, MEMBER)    \
    ((CURSOR)->node                                     \
     ? (INIT_CONTAINER(NODE, (CURSOR)->node, MEMBER),   \
        cmap_cursor_advance(CURSOR),                    \
        true)                                           \
     : false)

#define CMAP_CURSOR_FOR_EACH(NODE, MEMBER, CURSOR, CMAP)    \
    for (*(CURSOR) = cmap_cursor_start(CMAP);               \
         CMAP_CURSOR_FOR_EACH__(NODE, CURSOR, MEMBER);      \
        )

#define CMAP_CURSOR_FOR_EACH_CONTINUE(NODE, MEMBER, CURSOR)   \
    while (CMAP_CURSOR_FOR_EACH__(NODE, CURSOR, MEMBER))

struct cmap_cursor {
    const struct cmap_impl *impl;
    uint32_t bucket_idx;
    int entry_idx;
    struct cmap_node *node;
};

struct cmap_cursor cmap_cursor_start(const struct cmap *);
void cmap_cursor_advance(struct cmap_cursor *);

/* Generate a unique name for the cursor with the __COUNTER__ macro to
 * allow nesting of CMAP_FOR_EACH loops. */
#define CURSOR_JOIN2(x,y) x##y
#define CURSOR_JOIN(x, y) CURSOR_JOIN2(x,y)

#define CMAP_FOR_EACH__(NODE, MEMBER, CMAP, CURSOR_NAME)           \
    for (struct cmap_cursor CURSOR_NAME = cmap_cursor_start(CMAP); \
         CMAP_CURSOR_FOR_EACH__(NODE, &CURSOR_NAME, MEMBER);       \
        )

#define CMAP_FOR_EACH(NODE, MEMBER, CMAP) \
          CMAP_FOR_EACH__(NODE, MEMBER, CMAP, \
                CURSOR_JOIN(cursor_, __COUNTER__))

static inline struct cmap_node *cmap_first(const struct cmap *);

/* Another, less preferred, form of iteration, for use in situations where it
 * is difficult to maintain a pointer to a cmap_node. */
struct cmap_position {
    unsigned int bucket;
    unsigned int entry;
    unsigned int offset;
};

struct cmap_node *cmap_next_position(const struct cmap *,
                                     struct cmap_position *);

/* Returns the first node in 'cmap', in arbitrary order, or a null pointer if
 * 'cmap' is empty. */
static inline struct cmap_node *
cmap_first(const struct cmap *cmap)
{
    struct cmap_position pos = { 0, 0, 0 };

    return cmap_next_position(cmap, &pos);
}

/* Removes 'node' from 'cmap'.  The caller must ensure that 'cmap' cannot
 * change concurrently (from another thread).
 *
 * 'node' must not be destroyed or modified or inserted back into 'cmap' or
 * into any other concurrent hash map while any other thread might be accessing
 * it.  One correct way to do this is to free it from an RCU callback with
 * ovsrcu_postpone().
 *
 * Returns the current number of nodes in the cmap after the removal. */
static inline size_t
cmap_remove(struct cmap *cmap, struct cmap_node *node, uint32_t hash)
{
    return cmap_replace(cmap, node, NULL, hash);
}

#endif /* cmap.h */
