/*
 * Copyright (c) 2012 Nicira, Inc.
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

#ifndef HEAP_H
#define HEAP_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A heap node, to be embedded inside the data structure in the heap. */
struct heap_node {
    size_t idx;
    uint32_t priority;
};

/* A max-heap. */
struct heap {
    struct heap_node **array;   /* Data in elements 1...n, element 0 unused. */
    size_t n;                   /* Number of nodes currently in the heap. */
    size_t allocated;           /* Max 'n' before 'array' must be enlarged. */
};

/* Initialization. */
void heap_init(struct heap *);
void heap_destroy(struct heap *);
void heap_clear(struct heap *);
void heap_swap(struct heap *a, struct heap *b);
static inline size_t heap_count(const struct heap *);
static inline bool heap_is_empty(const struct heap *);

/* Insertion and deletion. */
void heap_insert(struct heap *, struct heap_node *, uint32_t priority);
void heap_change(struct heap *, struct heap_node *, uint32_t priority);
void heap_remove(struct heap *, struct heap_node *);
static inline struct heap_node *heap_pop(struct heap *);

/* Maximum.  */
static inline struct heap_node *heap_max(const struct heap *);

/* The "raw" functions below do not preserve the heap invariants.  After you
 * call them, heap_max() will not necessarily return the right value until you
 * subsequently call heap_rebuild(). */
void heap_raw_insert(struct heap *, struct heap_node *, uint32_t priority);
static inline void heap_raw_change(struct heap_node *, uint32_t priority);
void heap_raw_remove(struct heap *, struct heap_node *);
void heap_rebuild(struct heap *);

/* Iterates through each NODE in HEAP, where NODE->MEMBER must be a "struct
 * heap_node".  Iterates in heap level order, which in particular means that
 * the first node visited is the maximum value in the heap.
 *
 * If a heap_raw_*() function has been called without a later call to
 * heap_rebuild(), then the first node visited may not be the maximum
 * element. */
#define HEAP_FOR_EACH(NODE, MEMBER, HEAP)                           \
    for (((HEAP)->n > 0                                             \
          ? ASSIGN_CONTAINER(NODE, (HEAP)->array[1], MEMBER)        \
          : ((NODE) = NULL, 1));                                    \
         (NODE) != NULL;                                            \
         ((NODE)->MEMBER.idx < (HEAP)->n                            \
          ? ASSIGN_CONTAINER(NODE,                                  \
                             (HEAP)->array[(NODE)->MEMBER.idx + 1], \
                             MEMBER)                                \
          : ((NODE) = NULL, 1)))

/* Returns the index of the node that is the parent of the node with the given
 * 'idx' within a heap. */
static inline size_t
heap_parent__(size_t idx)
{
    return idx / 2;
}

/* Returns the index of the node that is the left child of the node with the
 * given 'idx' within a heap. */
static inline size_t
heap_left__(size_t idx)
{
    return idx * 2;
}

/* Returns the index of the node that is the right child of the node with the
 * given 'idx' within a heap. */
static inline size_t
heap_right__(size_t idx)
{
    return idx * 2 + 1;
}

/* Returns true if 'idx' is the index of a leaf node in 'heap', false
 * otherwise. */
static inline bool
heap_is_leaf__(const struct heap *heap, size_t idx)
{
    return heap_left__(idx) > heap->n;
}

/* Returns the number of elements in 'heap'. */
static inline size_t
heap_count(const struct heap *heap)
{
    return heap->n;
}

/* Returns true if 'heap' is empty, false if it contains at least one
 * element. */
static inline bool
heap_is_empty(const struct heap *heap)
{
    return heap->n == 0;
}

/* Returns the largest element in 'heap'.
 *
 * The caller must ensure that 'heap' contains at least one element.
 *
 * The return value may be wrong (i.e. not the maximum element but some other
 * element) if a heap_raw_*() function has been called without a later call to
 * heap_rebuild(). */
static inline struct heap_node *
heap_max(const struct heap *heap)
{
    return heap->array[1];
}

/* Removes an arbitrary node from 'heap', in O(1), maintaining the heap
 * invariant.  Returns the node removed.
 *
 * The caller must ensure that 'heap' contains at least one element. */
static inline struct heap_node *
heap_pop(struct heap *heap)
{
    return heap->array[heap->n--];
}

/* Changes the priority of 'node' (which must be in 'heap') to 'priority'.
 *
 * After this call, heap_max() will no longer necessarily return the maximum
 * value in the heap, and HEAP_FOR_EACH will no longer necessarily iterate in
 * heap level order, until the next call to heap_rebuild(heap).
 *
 * This takes time O(1). */
static inline void
heap_raw_change(struct heap_node *node, uint32_t priority)
{
    node->priority = priority;
}

#endif /* heap.h */
