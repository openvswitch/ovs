/*
 * Copyright (c) 2010, Andrea Mazzoleni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/** \file
 * Chain of nodes.
 * A chain of nodes is an abstraction used to implements complex list operations
 * like sorting.
 *
 * Do not use this directly. Use lists instead.
 */

#ifndef __TOMMYCHAIN_H
#define __TOMMYCHAIN_H

#include "tommytypes.h"

/******************************************************************************/
/* chain */

/**
 * Chain of nodes.
 * A chain of nodes is a sequence of nodes with the following properties:
 * - It contains at least one node. A chains of zero nodes cannot exist.
 * - The next field of the tail is of *undefined* value.
 * - The prev field of the head is of *undefined* value.
 * - All the other inner prev and next fields are correctly set.
 */
typedef struct tommy_chain_struct {
    tommy_node* head; /**< Pointer to the head of the chain. */
    tommy_node* tail; /**< Pointer to the tail of the chain. */
} tommy_chain;

/**
 * Splices a chain in the middle of another chain.
 */
tommy_inline void tommy_chain_splice(tommy_node* first_before, tommy_node* first_after, tommy_node* second_head, tommy_node* second_tail)
{
    /* set the prev list */
    first_after->prev = second_tail;
    second_head->prev = first_before;

    /* set the next list */
    first_before->next = second_head;
    second_tail->next = first_after;
}

/**
 * Concats two chains.
 */
tommy_inline void tommy_chain_concat(tommy_node* first_tail, tommy_node* second_head)
{
    /* set the prev list */
    second_head->prev = first_tail;

    /* set the next list */
    first_tail->next = second_head;
}

/**
 * Merges two chains.
 */
tommy_inline void tommy_chain_merge(tommy_chain* first, tommy_chain* second, tommy_compare_func* cmp)
{
    tommy_node* first_i = first->head;
    tommy_node* second_i = second->head;

    /* merge */
    while (1) {
        if (cmp(first_i->data, second_i->data) > 0) {
            tommy_node* next = second_i->next;
            if (first_i == first->head) {
                tommy_chain_concat(second_i, first_i);
                first->head = second_i;
            } else {
                tommy_chain_splice(first_i->prev, first_i, second_i, second_i);
            }
            if (second_i == second->tail)
                break;
            second_i = next;
        } else {
            if (first_i == first->tail) {
                tommy_chain_concat(first_i, second_i);
                first->tail = second->tail;
                break;
            }
            first_i = first_i->next;
        }
    }
}

/**
 * Merges two chains managing special degenerated cases.
 * It's funtionally equivalent at tommy_chain_merge() but faster with already ordered chains.
 */
tommy_inline void tommy_chain_merge_degenerated(tommy_chain* first, tommy_chain* second, tommy_compare_func* cmp)
{
    /* identify the condition first <= second */
    if (cmp(first->tail->data, second->head->data) <= 0) {
        tommy_chain_concat(first->tail, second->head);
        first->tail = second->tail;
        return;
    }

    /* identify the condition second < first */
    /* here we must be strict on comparison to keep the sort stable */
    if (cmp(second->tail->data, first->head->data) < 0) {
        tommy_chain_concat(second->tail, first->head);
        first->head = second->head;
        return;
    }

    tommy_chain_merge(first, second, cmp);
}

/**
 * Sorts a chain.
 * It's a stable merge sort using power of 2 buckets, with O(N*log(N)) complexity,
 * similar at the one used in the SGI STL libraries and in the Linux Kernel,
 * but faster on degenerated cases like already ordered lists.
 *
 * SGI STL stl_list.h
 * http://www.sgi.com/tech/stl/stl_list.h
 *
 * Linux Kernel lib/list_sort.c
 * http://lxr.linux.no/#linux+v2.6.36/lib/list_sort.c
 */
tommy_inline void tommy_chain_mergesort(tommy_chain* chain, tommy_compare_func* cmp)
{
    /*
     * Bit buckets of chains.
     * Each bucket contains 2^i nodes or it's empty.
     * The chain at address TOMMY_BIT_MAX is an independet variable operating as "carry".
     * We keep it in the same "bit" vector to avoid reports from the valgrind tool sgcheck.
     */
    tommy_chain bit[TOMMY_SIZE_BIT + 1];

    /**
     * Value stored inside the bit bucket.
     * It's used to know which bucket is empty of full.
     */
    tommy_size_t counter;
    tommy_node* node = chain->head;
    tommy_node* tail = chain->tail;
    tommy_size_t mask;
    tommy_size_t i;

    counter = 0;
    while (1) {
        tommy_node* next;
        tommy_chain* last;

        /* carry bit to add */
        last = &bit[TOMMY_SIZE_BIT];
        bit[TOMMY_SIZE_BIT].head = node;
        bit[TOMMY_SIZE_BIT].tail = node;
        next = node->next;

        /* add the bit, propagating the carry */
        i = 0;
        mask = counter;
        while ((mask & 1) != 0) {
            tommy_chain_merge_degenerated(&bit[i], last, cmp);
            mask >>= 1;
            last = &bit[i];
            ++i;
        }

        /* copy the carry in the first empty bit */
        bit[i] = *last;

        /* add the carry in the counter */
        ++counter;

        if (node == tail)
            break;
        node = next;
    }

    /* merge the buckets */
    i = tommy_ctz(counter);
    mask = counter >> i;
    while (mask != 1) {
        mask >>= 1;
        if (mask & 1)
            tommy_chain_merge_degenerated(&bit[i + 1], &bit[i], cmp);
        else
            bit[i + 1] = bit[i];
        ++i;
    }

    *chain = bit[i];
}

#endif
