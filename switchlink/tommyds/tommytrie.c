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
#include "tommytrie.h"
#include "tommylist.h"

#include "util.h" /* for ovs_assert */

/******************************************************************************/
/* trie */

/**
 * Mask for the inner branches.
 */
#define TOMMY_TRIE_TREE_MASK (TOMMY_TRIE_TREE_MAX - 1)

/**
 * Shift for the first level of branches.
 */
#define TOMMY_TRIE_BUCKET_SHIFT (TOMMY_TRIE_BIT - TOMMY_TRIE_BUCKET_BIT)

/**
 * Max number of levels.
 */
#define TOMMY_TRIE_LEVEL_MAX ((TOMMY_TRIE_BIT - TOMMY_TRIE_BUCKET_BIT) / TOMMY_TRIE_TREE_BIT)

/**
 * Hashtrie tree.
 * A tree contains TOMMY_TRIE_TREE_MAX ordered pointers to <null/node/tree>.
 *
 * Each tree level uses exactly TOMMY_TRIE_TREE_BIT bits from the key.
 */
struct tommy_trie_tree_struct {
    tommy_trie_node* map[TOMMY_TRIE_TREE_MAX];
};
typedef struct tommy_trie_tree_struct tommy_trie_tree;

/**
 * Kinds of an trie node.
 */
#define TOMMY_TRIE_TYPE_NODE 0 /**< The node is of type ::tommy_trie_node. */
#define TOMMY_TRIE_TYPE_TREE 1 /**< The node is of type ::tommy_trie_tree. */

/**
 * Get and set pointer of trie nodes.
 *
 * The pointer type is stored in the lower bit.
 */
#define trie_get_type(ptr) (((tommy_uintptr_t)(ptr)) & 1)
#define trie_get_tree(ptr) ((tommy_trie_tree*)(((tommy_uintptr_t)(ptr)) - TOMMY_TRIE_TYPE_TREE))
#define trie_set_tree(ptr) (void*)(((tommy_uintptr_t)(ptr)) + TOMMY_TRIE_TYPE_TREE)

void tommy_trie_init(tommy_trie* trie, tommy_allocator* alloc)
{
    tommy_uint_t i;

    for (i = 0; i < TOMMY_TRIE_BUCKET_MAX; ++i)
        trie->bucket[i] = 0;

    trie->count = 0;
    trie->node_count = 0;

    trie->alloc = alloc;
}

static void trie_bucket_insert(tommy_trie* trie, tommy_uint_t shift, tommy_trie_node** let_ptr, tommy_trie_node* insert, tommy_key_t key)
{
    tommy_trie_tree* tree;
    tommy_trie_node* node;
    void* ptr;
    tommy_uint_t i;
    tommy_uint_t j;

recurse:
    ptr = *let_ptr;

    /* if null, just insert the node */
    if (!ptr) {
        /* setup the node as a list */
        tommy_list_insert_first(let_ptr, insert);
        return;
    }

    if (trie_get_type(ptr) == TOMMY_TRIE_TYPE_TREE) {
        /* repeat the process one level down */
        let_ptr = &trie_get_tree(ptr)->map[(key >> shift) & TOMMY_TRIE_TREE_MASK];
        shift -= TOMMY_TRIE_TREE_BIT;
        goto recurse;
    }

    node = tommy_cast(tommy_trie_node*, ptr);

    /* if it's the same key, insert in the list */
    if (node->index == key) {
        tommy_list_insert_tail_not_empty(node, insert);
        return;
    }

expand:
    /* convert to a tree */
    tree = tommy_cast(tommy_trie_tree*, tommy_allocator_alloc(trie->alloc));
    ++trie->node_count;
    *let_ptr = tommy_cast(tommy_trie_node*, trie_set_tree(tree));

    /* initialize it */
    for (i = 0; i < TOMMY_TRIE_TREE_MAX; ++i)
        tree->map[i] = 0;

    /* get the position of the two elements */
    i = (node->index >> shift) & TOMMY_TRIE_TREE_MASK;
    j = (key >> shift) & TOMMY_TRIE_TREE_MASK;

    /* if they don't collide */
    if (i != j) {
        /* insert the already existing element */
        tree->map[i] = node;

        /* insert the new node */
        tommy_list_insert_first(&tree->map[j], insert);
        return;
    }

    /* expand one more level */
    let_ptr = &tree->map[i];
    shift -= TOMMY_TRIE_TREE_BIT;
    goto expand;
}

void tommy_trie_insert(tommy_trie* trie, tommy_trie_node* node, void* data, tommy_key_t key)
{
    tommy_trie_node** let_ptr;

    /* ensure that the element is not too big */
    ovs_assert(key >> TOMMY_TRIE_BUCKET_SHIFT < TOMMY_TRIE_BUCKET_MAX);

    node->data = data;
    node->index = key;

    let_ptr = &trie->bucket[key >> TOMMY_TRIE_BUCKET_SHIFT];

    trie_bucket_insert(trie, TOMMY_TRIE_BUCKET_SHIFT, let_ptr, node, key);

    ++trie->count;
}

static tommy_trie_node* trie_bucket_remove_existing(tommy_trie* trie, tommy_uint_t shift, tommy_trie_node** let_ptr, tommy_trie_node* remove, tommy_key_t key)
{
    tommy_trie_node* node;
    tommy_trie_tree* tree;
    void* ptr;
    tommy_trie_node** let_back[TOMMY_TRIE_LEVEL_MAX + 1];
    tommy_uint_t level;
    tommy_uint_t i;
    tommy_uint_t count;
    tommy_uint_t last;

    level = 0;
recurse:
    ptr = *let_ptr;

    if (!ptr)
        return 0;

    if (trie_get_type(ptr) == TOMMY_TRIE_TYPE_TREE) {
        tree = trie_get_tree(ptr);

        /* save the path */
        let_back[level++] = let_ptr;

        /* go down one level */
        let_ptr = &tree->map[(key >> shift) & TOMMY_TRIE_TREE_MASK];
        shift -= TOMMY_TRIE_TREE_BIT;

        goto recurse;
    }

    node = tommy_cast(tommy_trie_node*, ptr);

    /* if the node to remove is not specified */
    if (!remove) {
        /* remove the first */
        remove = node;

        /* check if it's really the element to remove */
        if (remove->index != key)
            return 0;
    }

    tommy_list_remove_existing(let_ptr, remove);

    /* if the list is not empty, try to reduce */
    if (*let_ptr || !level)
        return remove;

reduce:
    /* go one level up */
    let_ptr = let_back[--level];

    tree = trie_get_tree(*let_ptr);

    /* check if there is only one child node */
    count = 0;
    last = 0;
    for (i = 0; i < TOMMY_TRIE_TREE_MAX; ++i) {
        if (tree->map[i]) {
            /* if we have a sub tree, we cannot reduce */
            if (trie_get_type(tree->map[i]) != TOMMY_TRIE_TYPE_NODE)
                return remove;
            /* if more than one node, we cannot reduce */
            if (++count > 1)
                return remove;
            last = i;
        }
    }

    /* here count is never 0, as we cannot have a tree with only one sub node */
    ovs_assert(count == 1);

    *let_ptr = tree->map[last];

    tommy_allocator_free(trie->alloc, tree);
    --trie->node_count;

    /* repeat until more level */
    if (level)
        goto reduce;

    return remove;
}

void* tommy_trie_remove(tommy_trie* trie, tommy_key_t key)
{
    tommy_trie_node* ret;
    tommy_trie_node** let_ptr;

    /* ensure that the element is not too big */
    ovs_assert(key >> TOMMY_TRIE_BUCKET_SHIFT < TOMMY_TRIE_BUCKET_MAX);

    let_ptr = &trie->bucket[key >> TOMMY_TRIE_BUCKET_SHIFT];

    ret = trie_bucket_remove_existing(trie, TOMMY_TRIE_BUCKET_SHIFT, let_ptr, 0, key);

    if (!ret)
        return 0;

    --trie->count;

    return ret->data;
}

void* tommy_trie_remove_existing(tommy_trie* trie, tommy_trie_node* node)
{
    tommy_trie_node* ret;
    tommy_key_t key = node->index;
    tommy_trie_node** let_ptr;

    /* ensure that the element is not too big */
    ovs_assert(key >> TOMMY_TRIE_BUCKET_SHIFT < TOMMY_TRIE_BUCKET_MAX);

    let_ptr = &trie->bucket[key >> TOMMY_TRIE_BUCKET_SHIFT];

    ret = trie_bucket_remove_existing(trie, TOMMY_TRIE_BUCKET_SHIFT, let_ptr, node, key);

    /* the element removed must match the one passed */
    ovs_assert(ret == node);

    --trie->count;

    return ret->data;
}

tommy_trie_node* tommy_trie_bucket(tommy_trie* trie, tommy_key_t key)
{
    tommy_trie_node* node;
    void* ptr;
    tommy_uint_t type;
    tommy_uint_t shift;

    /* ensure that the element is not too big */
    ovs_assert(key >> TOMMY_TRIE_BUCKET_SHIFT < TOMMY_TRIE_BUCKET_MAX);

    ptr = trie->bucket[key >> TOMMY_TRIE_BUCKET_SHIFT];

    shift = TOMMY_TRIE_BUCKET_SHIFT;

recurse:
    if (!ptr)
        return 0;

    type = trie_get_type(ptr);

    switch (type) {
    case TOMMY_TRIE_TYPE_NODE :
        node = tommy_cast(tommy_trie_node*, ptr);
        if (node->index != key)
            return 0;
        return node;
    default :
    case TOMMY_TRIE_TYPE_TREE :
        ptr = trie_get_tree(ptr)->map[(key >> shift) & TOMMY_TRIE_TREE_MASK];
        shift -= TOMMY_TRIE_TREE_BIT;
        goto recurse;
    }
}

tommy_size_t tommy_trie_memory_usage(tommy_trie* trie)
{
    return tommy_trie_count(trie) * (tommy_size_t)sizeof(tommy_trie_node)
           + trie->node_count * (tommy_size_t)TOMMY_TRIE_BLOCK_SIZE;
}
