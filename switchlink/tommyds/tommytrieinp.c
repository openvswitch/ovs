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

#include <config.h>
#include "tommytrieinp.h"

#include "util.h" /* for ovs_assert */

/******************************************************************************/
/* trie_inplace */

/**
 * Mask for the inner branches.
 */
#define TOMMY_TRIE_INPLACE_TREE_MASK (TOMMY_TRIE_INPLACE_TREE_MAX - 1)

/**
 * Shift for the first level of branches.
 */
#define TOMMY_TRIE_INPLACE_BUCKET_SHIFT (TOMMY_TRIE_INPLACE_BIT - TOMMY_TRIE_INPLACE_BUCKET_BIT)

/**
 * Create a new list with a single element.
 */
tommy_inline tommy_trie_inplace_node* tommy_trie_inplace_list_insert_first(tommy_trie_inplace_node* node)
{
    /* one element "circular" prev list */
    node->prev = node;

    /* one element "0 terminated" next list */
    node->next = 0;

    return node;
}

/**
 * Add an element to an existing list.
 * \note The element is inserted at the end of the list.
 */
tommy_inline void tommy_trie_inplace_list_insert_tail_not_empty(tommy_trie_inplace_node* head, tommy_trie_inplace_node* node)
{
    /* insert in the list in the last position */

    /* insert in the "circular" prev list */
    node->prev = head->prev;
    head->prev = node;

    /* insert in the "0 terminated" next list */
    node->next = 0;
    node->prev->next = node;
}

/**
 * Remove an element from the list.
 */
tommy_inline void tommy_trie_inplace_list_remove(tommy_trie_inplace_node** let_ptr, tommy_trie_inplace_node* node)
{
    tommy_trie_inplace_node* head = *let_ptr;

    /* remove from the "circular" prev list */
    if (node->next)
        node->next->prev = node->prev;
    else
        head->prev = node->prev; /* the last */

    /* remove from the "0 terminated" next list */
    if (head == node)
        *let_ptr = node->next; /* the new first */
    else
        node->prev->next = node->next;
}

void tommy_trie_inplace_init(tommy_trie_inplace* trie_inplace)
{
    tommy_uint_t i;

    for (i = 0; i < TOMMY_TRIE_INPLACE_BUCKET_MAX; ++i)
        trie_inplace->bucket[i] = 0;

    trie_inplace->count = 0;
}

static void trie_inplace_bucket_insert(tommy_uint_t shift, tommy_trie_inplace_node** let_ptr, tommy_trie_inplace_node* insert, tommy_key_t key)
{
    tommy_trie_inplace_node* node;

    node = *let_ptr;
    while (node && node->key != key) {
        let_ptr = &node->map[(key >> shift) & TOMMY_TRIE_INPLACE_TREE_MASK];
        node = *let_ptr;
        shift -= TOMMY_TRIE_INPLACE_TREE_BIT;
    }

    /* if null, just insert the node */
    if (!node) {
        /* setup the node as a list */
        *let_ptr = tommy_trie_inplace_list_insert_first(insert);
    } else {
        /* if it's the same key, insert in the list */
        tommy_trie_inplace_list_insert_tail_not_empty(node, insert);
    }
}

void tommy_trie_inplace_insert(tommy_trie_inplace* trie_inplace, tommy_trie_inplace_node* node, void* data, tommy_key_t key)
{
    tommy_trie_inplace_node** let_ptr;
    tommy_uint_t i;

    /* ensure that the element is not too big */
    ovs_assert(key >> TOMMY_TRIE_INPLACE_BUCKET_SHIFT < TOMMY_TRIE_INPLACE_BUCKET_MAX);

    node->data = data;
    node->key = key;
    /* clear the child pointers */
    for (i = 0; i < TOMMY_TRIE_INPLACE_TREE_MAX; ++i)
        node->map[i] = 0;

    let_ptr = &trie_inplace->bucket[key >> TOMMY_TRIE_INPLACE_BUCKET_SHIFT];

    trie_inplace_bucket_insert(TOMMY_TRIE_INPLACE_BUCKET_SHIFT, let_ptr, node, key);

    ++trie_inplace->count;
}

static tommy_trie_inplace_node* trie_inplace_bucket_remove(tommy_uint_t shift, tommy_trie_inplace_node** let_ptr, tommy_trie_inplace_node* remove, tommy_key_t key)
{
    tommy_trie_inplace_node* node;
    int i;
    tommy_trie_inplace_node** leaf_let_ptr;
    tommy_trie_inplace_node* leaf;

    node = *let_ptr;
    while (node && node->key != key) {
        let_ptr = &node->map[(key >> shift) & TOMMY_TRIE_INPLACE_TREE_MASK];
        node = *let_ptr;
        shift -= TOMMY_TRIE_INPLACE_TREE_BIT;
    }

    if (!node)
        return 0;

    /* if the node to remove is not specified */
    if (!remove)
        remove = node; /* remove the first */

    tommy_trie_inplace_list_remove(let_ptr, remove);

    /* if not change in the node, nothing more to do */
    if (*let_ptr == node)
        return remove;

    /* if we have a substitute */
    if (*let_ptr != 0) {
        /* copy the child pointers to the new one */
        node = *let_ptr;
        for (i = 0; i < TOMMY_TRIE_INPLACE_TREE_MAX; ++i)
            node->map[i] = remove->map[i];

        return remove;
    }

    /* find a leaf */
    leaf_let_ptr = 0;
    leaf = remove;

    /* search backward, statistically we have more zeros than ones */
    i = TOMMY_TRIE_INPLACE_TREE_MAX - 1;
    while (i >= 0) {
        if (leaf->map[i]) {
            leaf_let_ptr = &leaf->map[i];
            leaf = *leaf_let_ptr;
            i = TOMMY_TRIE_INPLACE_TREE_MAX - 1;
            continue;
        }
        --i;
    }

    /* if it's itself a leaf */
    if (!leaf_let_ptr)
        return remove;

    /* remove the leaf */
    *leaf_let_ptr = 0;

    /* copy the child pointers */
    for (i = 0; i < TOMMY_TRIE_INPLACE_TREE_MAX; ++i)
        leaf->map[i] = remove->map[i];

    /* put it in place */
    *let_ptr = leaf;

    return remove;
}

void* tommy_trie_inplace_remove(tommy_trie_inplace* trie_inplace, tommy_key_t key)
{
    tommy_trie_inplace_node* ret;
    tommy_trie_inplace_node** let_ptr;

    /* ensure that the element is not too big */
    ovs_assert(key >> TOMMY_TRIE_INPLACE_BUCKET_SHIFT < TOMMY_TRIE_INPLACE_BUCKET_MAX);

    let_ptr = &trie_inplace->bucket[key >> TOMMY_TRIE_INPLACE_BUCKET_SHIFT];

    ret = trie_inplace_bucket_remove(TOMMY_TRIE_INPLACE_BUCKET_SHIFT, let_ptr, 0, key);

    if (!ret)
        return 0;

    --trie_inplace->count;

    return ret->data;
}

void* tommy_trie_inplace_remove_existing(tommy_trie_inplace* trie_inplace, tommy_trie_inplace_node* node)
{
    tommy_trie_inplace_node* ret;
    tommy_key_t key = node->key;
    tommy_trie_inplace_node** let_ptr;

    /* ensure that the element is not too big */
    ovs_assert(key >> TOMMY_TRIE_INPLACE_BUCKET_SHIFT < TOMMY_TRIE_INPLACE_BUCKET_MAX);

    let_ptr = &trie_inplace->bucket[key >> TOMMY_TRIE_INPLACE_BUCKET_SHIFT];

    ret = trie_inplace_bucket_remove(TOMMY_TRIE_INPLACE_BUCKET_SHIFT, let_ptr, node, key);

    /* the element removed must match the one passed */
    ovs_assert(ret == node);

    --trie_inplace->count;

    return ret->data;
}

tommy_trie_inplace_node* tommy_trie_inplace_bucket(tommy_trie_inplace* trie_inplace, tommy_key_t key)
{
    tommy_trie_inplace_node* node;
    tommy_uint_t shift;

    /* ensure that the element is not too big */
    ovs_assert(key >> TOMMY_TRIE_INPLACE_BUCKET_SHIFT < TOMMY_TRIE_INPLACE_BUCKET_MAX);

    node = trie_inplace->bucket[key >> TOMMY_TRIE_INPLACE_BUCKET_SHIFT];
    shift = TOMMY_TRIE_INPLACE_BUCKET_SHIFT;

    while (node && node->key != key) {
        node = node->map[(key >> shift) & TOMMY_TRIE_INPLACE_TREE_MASK];
        shift -= TOMMY_TRIE_INPLACE_TREE_BIT;
    }

    return node;
}

tommy_size_t tommy_trie_inplace_memory_usage(tommy_trie_inplace* trie_inplace)
{
    return tommy_trie_inplace_count(trie_inplace) * (tommy_size_t)sizeof(tommy_trie_inplace_node);
}
