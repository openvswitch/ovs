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
 *    - Only a single thread may safely call into cmap_insert() or
 *      cmap_remove() at any given time.
 *
 *    - Any number of threads may use functions and macros that search or
 *      iterate through a given cmap, even in parallel with other threads
 *      calling cmap_insert() or cmap_remove().
 *
 *      There is one exception: cmap_find_protected() is only safe if no thread
 *      is currently calling cmap_insert() or cmap_remove().  (Use ordinary
 *      cmap_find() if that is not guaranteed.)
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

/* Initialization. */
void cmap_init(struct cmap *);
void cmap_destroy(struct cmap *);

/* Count. */
size_t cmap_count(const struct cmap *);
bool cmap_is_empty(const struct cmap *);

/* Insertion and deletion. */
void cmap_insert(struct cmap *, struct cmap_node *, uint32_t hash);
void cmap_remove(struct cmap *, struct cmap_node *, uint32_t hash);

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
 * CMAP_FOR_EACH_WITH_HASH will reliably visit each of the nodes with the
 * specified hash in CMAP, even with concurrent insertions and deletions.  (Of
 * course, if nodes with the given HASH are being inserted or deleted, it might
 * or might not visit the nodes actually being inserted or deleted.)
 *
 * CMAP_FOR_EACH_WITH_HASH_PROTECTED may only be used if CMAP is guaranteed not
 * to change during iteration.  It may be very slightly faster.
 */
#define CMAP_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, CMAP)       \
    for (ASSIGN_CONTAINER(NODE, cmap_find(CMAP, HASH), MEMBER); \
         (NODE) != OBJECT_CONTAINING(NULL, NODE, MEMBER);       \
         ASSIGN_CONTAINER(NODE, cmap_node_next(&(NODE)->MEMBER), MEMBER))
#define CMAP_FOR_EACH_WITH_HASH_PROTECTED(NODE, MEMBER, HASH, CMAP)        \
    for (ASSIGN_CONTAINER(NODE, cmap_find_locked(CMAP, HASH), MEMBER);  \
         (NODE) != OBJECT_CONTAINING(NULL, NODE, MEMBER);               \
         ASSIGN_CONTAINER(NODE, cmap_node_next_protected(&(NODE)->MEMBER), \
                          MEMBER))

struct cmap_node *cmap_find(const struct cmap *, uint32_t hash);
struct cmap_node *cmap_find_protected(const struct cmap *, uint32_t hash);

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
 *
 * Example
 * =======
 *
 *     struct my_node {
 *         struct cmap_node cmap_node;
 *         int extra_data;
 *     };
 *
 *     struct cmap_cursor cursor;
 *     struct my_node *iter;
 *     struct cmap my_map;
 *
 *     cmap_init(&cmap);
 *     ...add data...
 *     CMAP_FOR_EACH (my_node, cmap_node, &cursor, &cmap) {
 *         ...operate on my_node...
 *     }
 *
 * There is no CMAP_FOR_EACH_SAFE variant because it would be rarely useful:
 * usually destruction of an element has to wait for an RCU grace period to
 * expire.
 */
#define CMAP_FOR_EACH(NODE, MEMBER, CURSOR, CMAP)                       \
    for ((cmap_cursor_init(CURSOR, CMAP),                               \
          ASSIGN_CONTAINER(NODE, cmap_cursor_next(CURSOR, NULL), MEMBER)); \
         NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER);                 \
         ASSIGN_CONTAINER(NODE, cmap_cursor_next(CURSOR, &(NODE)->MEMBER), \
                          MEMBER))

struct cmap_cursor {
    const struct cmap_impl *impl;
    uint32_t bucket_idx;
    int entry_idx;
};

void cmap_cursor_init(struct cmap_cursor *, const struct cmap *);
struct cmap_node *cmap_cursor_next(struct cmap_cursor *,
                                   const struct cmap_node *);

/* Another, less preferred, form of iteration, for use in situations where it
 * is difficult to maintain a pointer to a cmap_node. */
struct cmap_position {
    unsigned int bucket;
    unsigned int entry;
    unsigned int offset;
};

struct cmap_node *cmap_next_position(const struct cmap *,
                                     struct cmap_position *);

#endif /* cmap.h */
