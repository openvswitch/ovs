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

/** \file
 * AVL tree.
 *
 * This tree is a standard AVL tree implementation that stores elements in the
 * order defined by the comparison function.
 *
 * As difference than other tommy containers, duplicate elements cannot be inserted.
 *
 * To initialize a tree you have to call tommy_tree_init() specifing a comparison
 * function that will define the order in the tree.
 *
 * \code
 * tommy_tree tree;
 *
 * tommy_tree_init(&tree, cmp);
 * \endcode
 *
 * To insert elements in the tree you have to call tommy_tree_insert() for
 * each element.
 * In the insertion call you have to specify the address of the node and the
 * address of the object.
 * The address of the object is used to initialize the tommy_node::data field
 * of the node.
 *
 * \code
 * struct object {
 *     int value;
 *     // other fields
 *     tommy_tree_node node;
 * };
 *
 * struct object* obj = malloc(sizeof(struct object)); // creates the object
 *
 * obj->value = ...; // initializes the object
 *
 * tommy_tree_insert(&tree, &obj->node, obj); // inserts the object
 * \endcode
 *
 * To find and element in the tree you have to call tommy_tree_search() providing
 * the key to search.
 *
 * \code
 * struct object value_to_find = { 1 };
 * struct object* obj = tommy_tree_search(&tree, &value_to_find);
 * if (!obj) {
 *     // not found
 * } else {
 *     // found
 * }
 * \endcode
 *
 * To remove an element from the tree you have to call tommy_tree_remove()
 * providing the key to search and remove.
 *
 * \code
 * struct object value_to_remove = { 1 };
 * struct object* obj = tommy_tree_remove(&tree, &value_to_remove);
 * if (obj) {
 *     free(obj); // frees the object allocated memory
 * }
 * \endcode
 *
 * To destroy the tree you have to remove or destroy all the contained elements.
 * The tree itself doesn't have or need a deallocation function.
 *
 * If you need to iterate over all the elements in the tree, you can use
 * tommy_tree_foreach() or tommy_tree_foreach_arg().
 * If you need a more precise control with a real iteration, you have to insert
 * all the elements also in a ::tommy_list, and use the list to iterate.
 * See the \ref multiindex example for more detail.
 */

#ifndef __TOMMYTREE_H
#define __TOMMYTREE_H

#include "tommytypes.h"

/******************************************************************************/
/* tree */

/**
 * Tree node.
 * This is the node that you have to include inside your objects.
 */
typedef tommy_node tommy_tree_node;

/**
 * Tree container type.
 * \note Don't use internal fields directly, but access the container only using functions.
 */
typedef struct tommy_tree_struct {
    tommy_tree_node* root; /**< Root node. */
    tommy_compare_func* cmp; /**< Comparison function. */
    tommy_size_t count; /**< Number of elements. */
} tommy_tree;

/**
 * Initializes the tree.
 * \param cmp The comparison function that defines the orderin the tree.
 */
void tommy_tree_init(tommy_tree* tree, tommy_compare_func* cmp);

/**
 * Inserts an element in the tree.
 * If the element is already present, it's not inserted again.
 * Check the return value to identify if the element was already present or not.
 * You have to provide the pointer of the node embedded into the object and
 * the pointer to the object.
 * \param node Pointer to the node embedded into the object to insert.
 * \param data Pointer to the object to insert.
 * \return The element in the tree. Either the already existing one, or the one just inserted.
 */
void* tommy_tree_insert(tommy_tree* tree, tommy_tree_node* node, void* data);

/**
 * Searches and removes an element.
 * If the element is not found, 0 is returned.
 * \param data Element used for comparison.
 * \return The removed element, or 0 if not found.
 */
void* tommy_tree_remove(tommy_tree* tree, void* data);

/**
 * Searches an element in the tree.
 * If the element is not found, 0 is returned.
 * \param data Element used for comparison.
 * \return The first element found, or 0 if none.
 */
void* tommy_tree_search(tommy_tree* tree, void* data);

/**
 * Searches an element in the tree with a specific comparison function.
 *
 * Like tommy_tree_search() but you can specify a different comparison function.
 * Note that this function must define a suborder of the original one.
 *
 * The ::data argument will be the first argument of the comparison function,
 * and it can be of a different type of the objects in the tree.
 */
void* tommy_tree_search_compare(tommy_tree* tree, tommy_compare_func* cmp, void* cmp_arg);

/**
 * Removes an element from the tree.
 * You must already have the address of the element to remove.
 * \return The tommy_node::data field of the node removed.
 */
void* tommy_tree_remove_existing(tommy_tree* tree, tommy_tree_node* node);

/**
 * Calls the specified function for each element in the tree.
 *
 * The elements are processed in order.
 *
 * You cannot add or remove elements from the inside of the callback,
 * but can use it to deallocate them.
 *
 * \code
 * tommy_tree tree;
 *
 * // initializes the tree
 * tommy_tree_init(&tree, cmp);
 *
 * ...
 *
 * // creates an object
 * struct object* obj = malloc(sizeof(struct object));
 *
 * ...
 *
 * // insert it in the tree
 * tommy_tree_insert(&tree, &obj->node, obj);
 *
 * ...
 *
 * // deallocates all the objects iterating the tree
 * tommy_tree_foreach(&tree, free);
 * \endcode
 */
void tommy_tree_foreach(tommy_tree* tree, tommy_foreach_func* func);

/**
 * Calls the specified function with an argument for each element in the tree.
 */
void tommy_tree_foreach_arg(tommy_tree* tree, tommy_foreach_arg_func* func, void* arg);

/**
 * Gets the number of elements.
 */
tommy_inline tommy_size_t tommy_tree_count(tommy_tree* tree)
{
    return tree->count;
}

/**
 * Gets the size of allocated memory.
 * It includes the size of the ::tommy_tree_node of the stored elements.
 */
tommy_size_t tommy_tree_memory_usage(tommy_tree* tree);

#endif
