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
 * Trie optimized for cache utilization.
 *
 * This trie is a standard implementation that stores elements in the order defined
 * by the key.
 *
 * It needs an external allocator for the inner nodes in the trie.
 *
 * You can control the number of branches of each node using the ::TOMMY_TRIE_TREE_MAX
 * define. More branches imply more speed, but a bigger memory occupation.
 *
 * Compared to ::tommy_trie_inplace you have to provide a ::tommy_allocator allocator.
 * Note that the C malloc() is too slow to futfill this role.
 *
 * To initialize the trie you have to call tommy_allocator_init() to initialize
 * the allocator, and tommy_trie_init() for the trie.
 *
 * \code
 * tommy_allocator alloc;
 * tommy_trie trie;
 *
 * tommy_allocator_init(&alloc, TOMMY_TRIE_BLOCK_SIZE, TOMMY_TRIE_BLOCK_SIZE);
 *
 * tommy_trie_init(&trie, &alloc);
 * \endcode
 *
 * To insert elements in the trie you have to call tommy_trie_insert() for
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
 * tommy_trie_insert(&trie, &obj->node, obj, obj->value); // inserts the object
 * \endcode
 *
 * To find and element in the trie you have to call tommy_trie_search() providing
 * the key to search.
 *
 * \code
 * int value_to_find = 1;
 * struct object* obj = tommy_trie_search(&trie, value_to_find);
 * if (!obj) {
 *     // not found
 * } else {
 *     // found
 * }
 * \endcode
 *
 * To iterate over all the elements in the trie with the same key, you have to
 * use tommy_trie_bucket() and follow the tommy_node::next pointer until NULL.
 *
 * \code
 * int value_to_find = 1;
 * tommy_node* i = tommy_trie_bucket(&trie, value_to_find);
 * while (i) {
 *     struct object* obj = i->data; // gets the object pointer
 *
 *     printf("%d\n", obj->value); // process the object
 *
 *     i = i->next; // goes to the next element
 * }
 * \endcode
 *
 * To remove an element from the trie you have to call tommy_trie_remove()
 * providing the key to search and remove.
 *
 * \code
 * struct object* obj = tommy_trie_remove(&trie, value_to_remove);
 * if (obj) {
 *     free(obj); // frees the object allocated memory
 * }
 * \endcode
 *
 * To destroy the trie you have to remove all the elements, and deinitialize
 * the allocator using tommy_allocator_done().
 *
 * \code
 * tommy_allocator_done(&alloc);
 * \endcode
 *
 * Note that you cannot iterate over all the elements in the trie using the
 * trie itself. You have to insert all the elements also in a ::tommy_list,
 * and use the list to iterate. See the \ref multiindex example for more detail.
 */

#ifndef __TOMMYTRIE_H
#define __TOMMYTRIE_H

#include "tommytypes.h"
#include "tommyalloc.h"

/******************************************************************************/
/* trie */

/**
 * Number of bits of the elements to store in the trie.
 *
 * If you need to store integers bigger than 32 bits you can
 * increse this value.
 *
 * Keeping this value small improves the performance of the trie.
 */
#define TOMMY_TRIE_BIT 32

/**
 * Number of branches on each inner node. It must be a power of 2.
 * Suggested values are 8, 16 and 32.
 * Any inner node, excluding leafs, contains a pointer to each branch.
 *
 * The default size is choosen to exactly fit a typical cache line of 64 bytes.
 */
#define TOMMY_TRIE_TREE_MAX (64 / sizeof(void*))

/**
 * Trie block size.
 * You must use this value to initialize the allocator.
 */
#define TOMMY_TRIE_BLOCK_SIZE (TOMMY_TRIE_TREE_MAX * sizeof(void*))

/** \internal
 * Number of bits for each branch.
 */
#define TOMMY_TRIE_TREE_BIT TOMMY_ILOG2(TOMMY_TRIE_TREE_MAX)

/** \internal
 * Number of bits of the first level.
 */
#define TOMMY_TRIE_BUCKET_BIT ((TOMMY_TRIE_BIT % TOMMY_TRIE_TREE_BIT) + TOMMY_TRIE_TREE_BIT)

/** \internal
 * Number of branches of the first level.
 * It's like a inner branch, but bigger to get any remainder bits.
 */
#define TOMMY_TRIE_BUCKET_MAX (1 << TOMMY_TRIE_BUCKET_BIT)

/**
 * Trie node.
 * This is the node that you have to include inside your objects.
 */
typedef tommy_node tommy_trie_node;

/**
 * Trie container type.
 * \note Don't use internal fields directly, but access the container only using functions.
 */
typedef struct tommy_trie_struct {
    tommy_trie_node* bucket[TOMMY_TRIE_BUCKET_MAX]; /**< First tree level. */
    tommy_size_t count; /**< Number of elements. */
    tommy_size_t node_count; /**< Number of nodes. */
    tommy_allocator* alloc; /**< Allocator for internal nodes. */
} tommy_trie;

/**
 * Initializes the trie.
 * You have to provide an allocator initialized with *both* the size and align with TOMMY_TRIE_BLOCK_SIZE.
 * You can share this allocator with other tries.
 *
 * The tries is completely allocated through the allocator, and it doesn't need to be deinitialized.
 * \param alloc Allocator initialized with *both* the size and align with TOMMY_TRIE_BLOCK_SIZE.
 */
void tommy_trie_init(tommy_trie* trie, tommy_allocator* alloc);

/**
 * Inserts an element in the trie.
 * You have to provide the pointer of the node embedded into the object,
 * the pointer to the object and the key to use.
 * \param node Pointer to the node embedded into the object to insert.
 * \param data Pointer to the object to insert.
 * \param key Key to use to insert the object.
 */
void tommy_trie_insert(tommy_trie* trie, tommy_trie_node* node, void* data, tommy_key_t key);

/**
 * Searches and removes the first element with the specified key.
 * If the element is not found, 0 is returned.
 * If more equal elements are present, the first one is removed.
 * This operation is faster than calling tommy_trie_bucket() and tommy_trie_remove_existing() separately.
 * \param key Key of the element to find and remove.
 * \return The removed element, or 0 if not found.
 */
void* tommy_trie_remove(tommy_trie* trie, tommy_key_t key);

/**
 * Gets the bucket of the specified key.
 * The bucket is guaranteed to contain ALL and ONLY the elements with the specified key.
 * You can access elements in the bucket following the ::next pointer until 0.
 * \param key Key of the element to find.
 * \return The head of the bucket, or 0 if empty.
 */
tommy_trie_node* tommy_trie_bucket(tommy_trie* trie, tommy_key_t key);

/**
 * Searches an element in the trie.
 * You have to provide the key of the element you want to find.
 * If more elements with the same key are present, the first one is returned.
 * \param key Key of the element to find.
 * \return The first element found, or 0 if none.
 */
tommy_inline void* tommy_trie_search(tommy_trie* trie, tommy_key_t key)
{
    tommy_trie_node* i = tommy_trie_bucket(trie, key);

    if (!i)
        return 0;

    return i->data;
}

/**
 * Removes an element from the trie.
 * You must already have the address of the element to remove.
 * \return The tommy_node::data field of the node removed.
 */
void* tommy_trie_remove_existing(tommy_trie* trie, tommy_trie_node* node);

/**
 * Gets the number of elements.
 */
tommy_inline tommy_size_t tommy_trie_count(tommy_trie* trie)
{
    return trie->count;
}

/**
 * Gets the size of allocated memory.
 * It includes the size of the ::tommy_trie_node of the stored elements.
 */
tommy_size_t tommy_trie_memory_usage(tommy_trie* trie);

#endif
