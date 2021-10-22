/*
 * Copyright (c) 2015, Andrea Mazzoleni. All rights reserved.
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
#include "tommytree.h"

#include "util.h" /* for ovs_assert */

/******************************************************************************/
/* tree */

void tommy_tree_init(tommy_tree* tree, tommy_compare_func* cmp)
{
    tree->root = 0;
    tree->count = 0;
    tree->cmp = cmp;
}

static tommy_ssize_t tommy_tree_delta(tommy_tree_node* root)
{
    tommy_ssize_t left_height = root->prev ? root->prev->index : 0;
    tommy_ssize_t right_height = root->next ? root->next->index : 0;

    return left_height - right_height;
}

/* AVL tree operations */
static tommy_tree_node* tommy_tree_balance(tommy_tree_node*);

static tommy_tree_node* tommy_tree_rotate_left(tommy_tree_node* root)
{
    tommy_tree_node* next = root->next;

    root->next = next->prev;

    next->prev = tommy_tree_balance(root);

    return tommy_tree_balance(next);
}

static tommy_tree_node* tommy_tree_rotate_right(tommy_tree_node* root)
{
    tommy_tree_node* prev = root->prev;

    root->prev = prev->next;

    prev->next = tommy_tree_balance(root);

    return tommy_tree_balance(prev);
}

static tommy_tree_node* tommy_tree_move_right(tommy_tree_node* root, tommy_tree_node* node)
{
    if (!root)
        return node;

    root->next = tommy_tree_move_right(root->next, node);

    return tommy_tree_balance(root);
}

static tommy_tree_node* tommy_tree_balance(tommy_tree_node* root)
{
    tommy_ssize_t delta = tommy_tree_delta(root);

    if (delta < -1) {
        if (tommy_tree_delta(root->next) > 0)
            root->next = tommy_tree_rotate_right(root->next);
        return tommy_tree_rotate_left(root);
    }

    if (delta > 1) {
        if (tommy_tree_delta(root->prev) < 0)
            root->prev = tommy_tree_rotate_left(root->prev);
        return tommy_tree_rotate_right(root);
    }

    /* recompute key */
    root->index = 0;

    if (root->prev && root->prev->index > root->index)
        root->index = root->prev->index;

    if (root->next && root->next->index > root->index)
        root->index = root->next->index;

    /* count itself */
    root->index += 1;

    return root;
}

static tommy_tree_node* tommy_tree_insert_node(tommy_compare_func* cmp, tommy_tree_node* root, tommy_tree_node** let)
{
    int c;

    if (!root)
        return *let;

    c = cmp((*let)->data, root->data);

    if (c < 0) {
        root->prev = tommy_tree_insert_node(cmp, root->prev, let);
        return tommy_tree_balance(root);
    }

    if (c > 0) {
        root->next = tommy_tree_insert_node(cmp, root->next, let);
        return tommy_tree_balance(root);
    }

    /* already present, set the return pointer */
    *let = root;

    return root;
}

void* tommy_tree_insert(tommy_tree* tree, tommy_tree_node* node, void* data)
{
    tommy_tree_node* insert = node;

    insert->data = data;
    insert->prev = 0;
    insert->next = 0;
    insert->index = 0;

    tree->root = tommy_tree_insert_node(tree->cmp, tree->root, &insert);

    if (insert == node)
        ++tree->count;

    return insert->data;
}

static tommy_tree_node* tommy_tree_remove_node(tommy_compare_func* cmp, tommy_tree_node* root, void* data, tommy_tree_node** let)
{
    int c;

    if (!root)
        return 0;

    c = cmp(data, root->data);

    if (c < 0) {
        root->prev = tommy_tree_remove_node(cmp, root->prev, data, let);
        return tommy_tree_balance(root);
    }

    if (c > 0) {
        root->next = tommy_tree_remove_node(cmp, root->next, data, let);
        return tommy_tree_balance(root);
    }

    /* found */
    *let = root;

    return tommy_tree_move_right(root->prev, root->next);
}

void* tommy_tree_remove(tommy_tree* tree, void* data)
{
    tommy_tree_node* node = 0;

    tree->root = tommy_tree_remove_node(tree->cmp, tree->root, data, &node);

    if (!node)
        return 0;

    --tree->count;

    return node->data;
}

static tommy_tree_node* tommy_tree_search_node(tommy_compare_func* cmp, tommy_tree_node* root, void* data)
{
    int c;

    if (!root)
        return 0;

    c = cmp(data, root->data);

    if (c < 0)
        return tommy_tree_search_node(cmp, root->prev, data);

    if (c > 0)
        return tommy_tree_search_node(cmp, root->next, data);

    return root;
}

void* tommy_tree_search(tommy_tree* tree, void* data)
{
    tommy_tree_node* node = tommy_tree_search_node(tree->cmp, tree->root, data);

    if (!node)
        return 0;

    return node->data;
}

void* tommy_tree_search_compare(tommy_tree* tree, tommy_compare_func* cmp, void* cmp_arg)
{
    tommy_tree_node* node = tommy_tree_search_node(cmp, tree->root, cmp_arg);

    if (!node)
        return 0;

    return node->data;
}

void* tommy_tree_remove_existing(tommy_tree* tree, tommy_tree_node* node)
{
    void* data = tommy_tree_remove(tree, node->data);

    ovs_assert(data != 0);

    return data;
}

static void tommy_tree_foreach_node(tommy_tree_node* root, tommy_foreach_func* func)
{
    tommy_tree_node* next;

    if (!root)
        return;

    tommy_tree_foreach_node(root->prev, func);

    /* make a copy in case func is free() */
    next = root->next;

    func(root->data);

    tommy_tree_foreach_node(next, func);
}

void tommy_tree_foreach(tommy_tree* tree, tommy_foreach_func* func)
{
    tommy_tree_foreach_node(tree->root, func);
}

static void tommy_tree_foreach_arg_node(tommy_tree_node* root, tommy_foreach_arg_func* func, void* arg)
{
    tommy_tree_node* next;

    if (!root)
        return;

    tommy_tree_foreach_arg_node(root->prev, func, arg);

    /* make a copy in case func is free() */
    next = root->next;

    func(arg, root->data);

    tommy_tree_foreach_arg_node(next, func, arg);
}

void tommy_tree_foreach_arg(tommy_tree* tree, tommy_foreach_arg_func* func, void* arg)
{
    tommy_tree_foreach_arg_node(tree->root, func, arg);
}

tommy_size_t tommy_tree_memory_usage(tommy_tree* tree)
{
    return tommy_tree_count(tree) * sizeof(tommy_tree_node);
}
