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

#ifndef HINDEX_H
#define HINDEX_H 1

/* Hashed multimap.
 *
 * hindex is a hash table data structure that gracefully handles duplicates.
 * With a high-quality hash function, insertion, deletion, and search are O(1)
 * expected time, regardless of the number of duplicates for a given key.  */

#include <stdbool.h>
#include <stdlib.h>
#include "util.h"

/* A hash index node, to embed inside the data structure being indexed.
 *
 * Nodes are linked together like this (the boxes are labeled with hash
 * values):
 *
 *             +--------+ d   +--------+ d   +--------+ d
 *  bucket---> |    6   |---->|   20   |---->|   15   |---->null
 *             +-|------+     +-|------+     +-|------+
 *               |    ^         |              |    ^
 *              s|    |d        |s            s|    |d
 *               V    |         V              V    |
 *             +------|-+      null          +------|-+
 *             |    6   |                    |   15   |
 *             +-|------+                    +-|------+
 *               |    ^                        |
 *              s|    |d                      s|
 *               V    |                        V
 *             +------|-+                     null
 *             |    6   |
 *             +-|------+
 *               |
 *              s|
 *               V
 *              null
 *
 * The basic usage is:
 *
 *     - To visit the unique hash values in the hindex, follow the 'd'
 *       ("different") pointers starting from each bucket.  The nodes visited
 *       this way are called "head" nodes, because they are at the head of the
 *       vertical chains.
 *
 *     - To visit the nodes with hash value H, follow the 'd' pointers in the
 *       appropriate bucket until you find one with hash H, then follow the 's'
 *       ("same") pointers until you hit a null pointer.  The non-head nodes
 *       visited this way are called "body" nodes.
 *
 *     - The 'd' pointers in body nodes point back to the previous body node
 *       or, for the first body node, to the head node.  (This makes it
 *       possible to remove a body node without traversing all the way downward
 *       from the head).
 */
struct hindex_node {
    /* Hash value. */
    size_t hash;

    /* In a head node, the next head node (with a hash different from this
     * node), or NULL if this is the last node in this bucket.
     *
     * In a body node, the previous head or body node (with the same hash as
     * this node).  Never null. */
    struct hindex_node *d;

    /* In a head or a body node, the next body node with the same hash as this
     * node.  NULL if this is the last node with this hash. */
    struct hindex_node *s;
};

/* A hash index. */
struct hindex {
    struct hindex_node **buckets; /* Must point to 'one' iff 'mask' == 0. */
    struct hindex_node *one;
    size_t mask;      /* 0 or more lowest-order bits set, others cleared. */
    size_t n_unique;  /* Number of unique hashes (the number of head nodes). */
};

/* Initializer for an empty hash index. */
#define HINDEX_INITIALIZER(HINDEX) \
    { (struct hindex_node **const) &(HINDEX)->one, NULL, 0, 0 }

/* Initialization. */
void hindex_init(struct hindex *);
void hindex_destroy(struct hindex *);
void hindex_clear(struct hindex *);
void hindex_swap(struct hindex *a, struct hindex *b);
void hindex_moved(struct hindex *hindex);
static inline bool hindex_is_empty(const struct hindex *);

/* Adjusting capacity. */
void hindex_expand(struct hindex *);
void hindex_shrink(struct hindex *);
void hindex_reserve(struct hindex *, size_t capacity);

/* Insertion and deletion. */
void hindex_insert_fast(struct hindex *, struct hindex_node *, size_t hash);
void hindex_insert(struct hindex *, struct hindex_node *, size_t hash);
void hindex_remove(struct hindex *, struct hindex_node *);

/* Search.
 *
 * HINDEX_FOR_EACH_WITH_HASH iterates NODE over all of the nodes in HINDEX that
 * have hash value equal to HASH.  MEMBER must be the name of the 'struct
 * hindex_node' member within NODE.
 *
 * The loop should not change NODE to point to a different node or insert or
 * delete nodes in HINDEX (unless it "break"s out of the loop to terminate
 * iteration).
 *
 * Evaluates HASH only once.
 */
#define HINDEX_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, HINDEX)               \
    for (INIT_CONTAINER(NODE, hindex_node_with_hash(HINDEX, HASH), MEMBER); \
         NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER);                     \
         ASSIGN_CONTAINER(NODE, (NODE)->MEMBER.s, MEMBER))

/* Returns the head node in 'hindex' with the given 'hash', or a null pointer
 * if no nodes have that hash value. */
static inline struct hindex_node *
hindex_node_with_hash(const struct hindex *hindex, size_t hash)
{
    struct hindex_node *node = hindex->buckets[hash & hindex->mask];

    while (node && node->hash != hash) {
        node = node->d;
    }
    return node;
}

/* Iteration. */

/* Iterates through every node in HINDEX. */
#define HINDEX_FOR_EACH(NODE, MEMBER, HINDEX)                           \
    for (INIT_CONTAINER(NODE, hindex_first(HINDEX), MEMBER);            \
         NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER);                 \
         ASSIGN_CONTAINER(NODE, hindex_next(HINDEX, &(NODE)->MEMBER), MEMBER))

/* Safe when NODE may be freed (not needed when NODE may be removed from the
 * hash index but its members remain accessible and intact). */
#define HINDEX_FOR_EACH_SAFE(NODE, NEXT, MEMBER, HINDEX)              \
    for (INIT_CONTAINER(NODE, hindex_first(HINDEX), MEMBER);          \
         (NODE != OBJECT_CONTAINING(NULL, NODE, MEMBER)                 \
          ? INIT_CONTAINER(NEXT, hindex_next(HINDEX, &(NODE)->MEMBER), MEMBER), 1 \
          : 0);                                                         \
         (NODE) = (NEXT))

struct hindex_node *hindex_first(const struct hindex *);
struct hindex_node *hindex_next(const struct hindex *,
                                const struct hindex_node *);

/* Returns true if 'hindex' currently contains no nodes, false otherwise. */
static inline bool
hindex_is_empty(const struct hindex *hindex)
{
    return hindex->n_unique == 0;
}

#endif /* hindex.h */
