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
 * Inplace trie.
 *
 * This trie is a inplace implementation not needing any external allocation.
 *
 * Elements are not stored in order, like ::tommy_trie, because some elements
 * should be used to represent the inner nodes in the trie.
 *
 * You can control the number of branches of each node using the ::TOMMY_TRIE_INPLACE_TREE_MAX define.
 * More branches imply more speed, but a bigger memory occupation.
 *
 * Compared to ::tommy_trie you should use a lower number of branches to limit the unused memory
 * occupation of the leaf nodes. This imply a lower speed, but without the need of an external allocator.
 *
 * To initialize the trie you have to call tommy_trie_inplace_init().
 *
 * \code
 * tommy_trie_inplace trie_inplace;
 *
 * tommy_trie_inplace_init(&trie_inplace);
 * \endcode
 *
 * To insert elements in the trie you have to call tommy_trie_inplace_insert() for
 * each element.
 * In the insertion call you have to specify the address of the node, the
 * address of the object, and the key value to use.
 * The address of the object is used to initialize the tommy_node::data field
 * of the node, and the key to initialize the tommy_node::key field.
 *
 * \code
 * struct object {
 *     int value;
 *     // other fields
 *     tommy_node node;
 * };
 *
 * struct object* obj = malloc(sizeof(struct object)); // creates the object
 *
 * obj->value = ...; // initializes the object
 *
 * tommy_trie_inplace_insert(&trie_inplace, &obj->node, obj, obj->value); // inserts the object
 * \endcode
 *
 * To find and element in the trie you have to call tommy_trie_inplace_search() providing
 * the key to search.
 *
 * \code
 * int value_to_find = 1;
 * struct object* obj = tommy_trie_inplace_search(&trie_inplace, value_to_find);
 * if (!obj) {
 *     // not found
 * } else {
 *     // found
 * }
 * \endcode
 *
 * To iterate over all the elements in the trie with the same key, you have to
 * use tommy_trie_inplace_bucket() and follow the tommy_node::next pointer until NULL.
 *
 * \code
 * int value_to_find = 1;
 * tommy_node* i = tommy_trie_inplace_bucket(&trie_inplace, value_to_find);
 * while (i) {
 *     struct object* obj = i->data; // gets the object pointer
 *
 *     printf("%d\n", obj->value); // process the object
 *
 *     i = i->next; // goes to the next element
 * }
 * \endcode
 *
 * To remove an element from the trie you have to call tommy_trie_inplace_remove()
 * providing the key to search and remove.
 *
 * \code
 * struct object* obj = tommy_trie_inplace_remove(&trie_inplace, value_to_remove);
 * if (obj) {
 *     free(obj); // frees the object allocated memory
 * }
 * \endcode
 *
 * To destroy the trie you have only to remove all the elements, as the trie is
 * completely inplace and it doesn't allocate memory.
 *
 * Note that you cannot iterate over all the elements in the trie using the
 * trie itself. You have to insert all the elements also in a ::tommy_list,
 * and use the list to iterate. See the \ref multiindex example for more detail.
 */

#ifndef __TOMMYTRIEINP_H
#define __TOMMYTRIEINP_H

#include "tommytypes.h"

/******************************************************************************/
/* trie_inplace */

/**
 * Number of bits of the elements to store in the trie.
 *
 * If you need to store integers bigger than 32 bits you can
 * increse this value.
 *
 * Keeping this value small improves the performance of the trie.
 */
#define TOMMY_TRIE_INPLACE_BIT 32

/**
 * Number of branches on each node. It must be a power of 2.
 * Suggested values are 2, 4 and 8.
 * Any node, including leafs, contains a pointer to each branch.
 */
#define TOMMY_TRIE_INPLACE_TREE_MAX 4

/** \internal
 * Number of bits for each branch.
 */
#define TOMMY_TRIE_INPLACE_TREE_BIT TOMMY_ILOG2(TOMMY_TRIE_INPLACE_TREE_MAX)

/** \internal
 * Number of bits of the first level.
 */
#define TOMMY_TRIE_INPLACE_BUCKET_BIT ((TOMMY_TRIE_INPLACE_BIT % TOMMY_TRIE_INPLACE_TREE_BIT) + 3 * TOMMY_TRIE_INPLACE_TREE_BIT)

/** \internal
 * Number of branches of the first level.
 * It's like a inner branch, but bigger to get any remainder bits.
 */
#define TOMMY_TRIE_INPLACE_BUCKET_MAX (1 << TOMMY_TRIE_INPLACE_BUCKET_BIT)

/**
 * Trie node.
 * This is the node that you have to include inside your objects.
 */
typedef struct tommy_trie_inplace_node_struct {
    struct tommy_trie_inplace_node_struct* next; /**< Next element. 0 if it's the last. */
    struct tommy_trie_inplace_node_struct* prev; /**< Circular previous element. */
    void* data; /**< Pointer to the data. */
    struct tommy_trie_inplace_node_struct* map[TOMMY_TRIE_INPLACE_TREE_MAX]; /** Branches of the node. */
    tommy_key_t key; /**< Used to store the key or the hash. */
} tommy_trie_inplace_node;

/**
 * Trie container type.
 * \note Don't use internal fields directly, but access the container only using functions.
 */
typedef struct tommy_trie_inplace_struct {
    tommy_trie_inplace_node* bucket[TOMMY_TRIE_INPLACE_BUCKET_MAX]; /**< First tree level. */
    tommy_size_t count; /**< Number of elements. */
} tommy_trie_inplace;

/**
 * Initializes the trie.
 *
 * The tries is completely inplace, and it doesn't need to be deinitialized.
 */
void tommy_trie_inplace_init(tommy_trie_inplace* trie_inplace);

/**
 * Inserts an element in the trie.
 */
void tommy_trie_inplace_insert(tommy_trie_inplace* trie_inplace, tommy_trie_inplace_node* node, void* data, tommy_key_t key);

/**
 * Searches and removes the first element with the specified key.
 * If the element is not found, 0 is returned.
 * If more equal elements are present, the first one is removed.
 * This operation is faster than calling tommy_trie_inplace_bucket() and tommy_trie_inplace_remove_existing() separately.
 * \param key Key of the element to find and remove.
 * \return The removed element, or 0 if not found.
 */
void* tommy_trie_inplace_remove(tommy_trie_inplace* trie_inplace, tommy_key_t key);

/**
 * Gets the bucket of the specified key.
 * The bucket is guaranteed to contain ALL and ONLY the elements with the specified key.
 * You can access elements in the bucket following the ::next pointer until 0.
 * \param key Key of the element to find.
 * \return The head of the bucket, or 0 if empty.
 */
tommy_trie_inplace_node* tommy_trie_inplace_bucket(tommy_trie_inplace* trie_inplace, tommy_key_t key);

/**
 * Searches an element in the trie.
 * You have to provide the key of the element you want to find.
 * If more elements with the same key are present, the first one is returned.
 * \param key Key of the element to find.
 * \return The first element found, or 0 if none.
 */
tommy_inline void* tommy_trie_inplace_search(tommy_trie_inplace* trie_inplace, tommy_key_t key)
{
    tommy_trie_inplace_node* i = tommy_trie_inplace_bucket(trie_inplace, key);

    if (!i)
        return 0;

    return i->data;
}

/**
 * Removes an element from the trie.
 * You must already have the address of the element to remove.
 * \return The tommy_node::data field of the node removed.
 */
void* tommy_trie_inplace_remove_existing(tommy_trie_inplace* trie_inplace, tommy_trie_inplace_node* node);

/**
 * Gets the number of elements.
 */
tommy_inline tommy_size_t tommy_trie_inplace_count(tommy_trie_inplace* trie_inplace)
{
    return trie_inplace->count;
}

/**
 * Gets the size of allocated memory.
 * It includes the size of the ::tommy_inplace_node of the stored elements.
 */
tommy_size_t tommy_trie_inplace_memory_usage(tommy_trie_inplace* trie_inplace);

#endif
