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

#include <config.h>
#include "heap.h"
#include <stdlib.h>
#include "util.h"

static void put_node(struct heap *, struct heap_node *, size_t i);
static void swap_nodes(struct heap *, size_t i, size_t j);
static bool float_up(struct heap *, size_t i);
static void float_down(struct heap *, size_t i);
static void float_up_or_down(struct heap *, size_t i);

/* Initializes 'heap' as an empty heap. */
void
heap_init(struct heap *heap)
{
    heap->array = NULL;
    heap->n = 0;
    heap->allocated = 0;
}

/* Frees memory owned internally by 'heap'.  The caller is responsible for
 * freeing 'heap' itself, if necessary. */
void
heap_destroy(struct heap *heap)
{
    if (heap) {
        free(heap->array);
    }
}

/* Removes all of the elements from 'heap', without freeing any allocated
 * memory. */
void
heap_clear(struct heap *heap)
{
    heap->n = 0;
}

/* Exchanges the contents of 'a' and 'b'. */
void
heap_swap(struct heap *a, struct heap *b)
{
    struct heap tmp = *a;
    *a = *b;
    *b = tmp;
}

/* Inserts 'node' into 'heap' with the specified 'priority'.
 *
 * This takes time O(lg n). */
void
heap_insert(struct heap *heap, struct heap_node *node, uint64_t priority)
{
    heap_raw_insert(heap, node, priority);
    float_up(heap, node->idx);
}

/* Removes 'node' from 'heap'.
 *
 * This takes time O(lg n). */
void
heap_remove(struct heap *heap, struct heap_node *node)
{
    size_t i = node->idx;

    heap_raw_remove(heap, node);
    if (i <= heap->n) {
        float_up_or_down(heap, i);
    }
}

/* Changes the priority of 'node' (which must be in 'heap') to 'priority'.
 *
 * This takes time O(lg n). */
void
heap_change(struct heap *heap, struct heap_node *node, uint64_t priority)
{
    heap_raw_change(node, priority);
    float_up_or_down(heap, node->idx);
}

/* Inserts 'node' into 'heap' with the specified 'priority', without
 * maintaining the heap invariant.
 *
 * After this call, heap_max() will no longer necessarily return the maximum
 * value in the heap, and HEAP_FOR_EACH will no longer necessarily iterate in
 * heap level order, until the next call to heap_rebuild(heap).
 *
 * This takes time O(1). */
void
heap_raw_insert(struct heap *heap, struct heap_node *node, uint64_t priority)
{
    if (heap->n >= heap->allocated) {
        heap->allocated = heap->n == 0 ? 1 : 2 * heap->n;
        heap->array = xrealloc(heap->array,
                               (heap->allocated + 1) * sizeof *heap->array);
    }

    put_node(heap, node, ++heap->n);
    node->priority = priority;
}

/* Removes 'node' from 'heap', without maintaining the heap invariant.
 *
 * After this call, heap_max() will no longer necessarily return the maximum
 * value in the heap, and HEAP_FOR_EACH will no longer necessarily iterate in
 * heap level order, until the next call to heap_rebuild(heap).
 *
 * This takes time O(1). */
void
heap_raw_remove(struct heap *heap, struct heap_node *node)
{
    size_t i = node->idx;
    if (i < heap->n) {
        put_node(heap, heap->array[heap->n], i);
    }
    heap->n--;
}

/* Rebuilds 'heap' to restore the heap invariant following a series of one or
 * more calls to heap_raw_*() functions.  (Otherwise this function need not be
 * called.)
 *
 * This takes time O(n) in the current size of the heap. */
void
heap_rebuild(struct heap *heap)
{
    size_t i;

    for (i = heap->n / 2; i >= 1; i--) {
        float_down(heap, i);
    }
}

static void
put_node(struct heap *heap, struct heap_node *node, size_t i)
{
    heap->array[i] = node;
    node->idx = i;
}

static void
swap_nodes(struct heap *heap, size_t i, size_t j)
{
    struct heap_node *old_i = heap->array[i];
    struct heap_node *old_j = heap->array[j];

    put_node(heap, old_j, i);
    put_node(heap, old_i, j);
}

static bool
float_up(struct heap *heap, size_t i)
{
    bool moved = false;
    size_t parent;

    for (; i > 1; i = parent) {
        parent = heap_parent__(i);
        if (heap->array[parent]->priority >= heap->array[i]->priority) {
            break;
        }
        swap_nodes(heap, parent, i);
        moved = true;
    }
    return moved;
}

static void
float_down(struct heap *heap, size_t i)
{
    while (!heap_is_leaf__(heap, i)) {
        size_t left = heap_left__(i);
        size_t right = heap_right__(i);
        size_t max = i;

        if (heap->array[left]->priority > heap->array[max]->priority) {
            max = left;
        }
        if (right <= heap->n
            && heap->array[right]->priority > heap->array[max]->priority) {
            max = right;
        }
        if (max == i) {
            break;
        }

        swap_nodes(heap, max, i);
        i = max;
    }
}

static void
float_up_or_down(struct heap *heap, size_t i)
{
    if (!float_up(heap, i)) {
        float_down(heap, i);
    }
}

