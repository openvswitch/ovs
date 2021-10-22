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
 * Dynamic chained hashtable.
 *
 * This hashtable resizes dynamically. It starts with the minimal size of 16 buckets, it doubles
 * the size then it reaches a load factor greater than 0.5 and it halves the size with a load
 * factor lower than 0.125.
 *
 * All the elements are reallocated in a single resize operation done inside
 * tommy_hashdyn_insert() or tommy_hashdyn_remove().
 *
 * Note that the resize operation takes approximatively 100 [ms] with 1 million of elements,
 * and 1 [second] with 10 millions. This could be a problem in real-time applications.
 *
 * The resize also fragment the heap, as it involves allocating a double-sized table, copy elements,
 * and deallocating the older table. Leaving a big hole in the heap.
 *
 * The ::tommy_hashlin hashtable fixes both problems.
 *
 * To initialize the hashtable you have to call tommy_hashdyn_init().
 *
 * \code
 * tommy_hashslin hashdyn;
 *
 * tommy_hashdyn_init(&hashdyn);
 * \endcode
 *
 * To insert elements in the hashtable you have to call tommy_hashdyn_insert() for
 * each element.
 * In the insertion call you have to specify the address of the node, the
 * address of the object, and the hash value of the key to use.
 * The address of the object is used to initialize the tommy_node::data field
 * of the node, and the hash to initialize the tommy_node::key field.
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
 * tommy_hashdyn_insert(&hashdyn, &obj->node, obj, tommy_inthash_u32(obj->value)); // inserts the object
 * \endcode
 *
 * To find and element in the hashtable you have to call tommy_hashtable_search()
 * providing a comparison function, its argument, and the hash of the key to search.
 *
 * \code
 * int compare(const void* arg, const void* obj)
 * {
 *     return *(const int*)arg != ((const struct object*)obj)->value;
 * }
 *
 * int value_to_find = 1;
 * struct object* obj = tommy_hashdyn_search(&hashdyn, compare, &value_to_find, tommy_inthash_u32(value_to_find));
 * if (!obj) {
 *     // not found
 * } else {
 *     // found
 * }
 * \endcode
 *
 * To iterate over all the elements in the hashtable with the same key, you have to
 * use tommy_hashdyn_bucket() and follow the tommy_node::next pointer until NULL.
 * You have also to check explicitely for the key, as the bucket may contains
 * different keys.
 *
 * \code
 * int value_to_find = 1;
 * tommy_node* i = tommy_hashdyn_bucket(&hashdyn, tommy_inthash_u32(value_to_find));
 * while (i) {
 *     struct object* obj = i->data; // gets the object pointer
 *
 *     if (obj->value == value_to_find) {
 *         printf("%d\n", obj->value); // process the object
 *     }
 *
 *     i = i->next; // goes to the next element
 * }
 * \endcode
 *
 * To remove an element from the hashtable you have to call tommy_hashdyn_remove()
 * providing a comparison function, its argument, and the hash of the key to search
 * and remove.
 *
 * \code
 * struct object* obj = tommy_hashdyn_remove(&hashdyn, compare, &value_to_remove, tommy_inthash_u32(value_to_remove));
 * if (obj) {
 *     free(obj); // frees the object allocated memory
 * }
 * \endcode
 *
 * To destroy the hashtable you have to remove all the elements, and deinitialize
 * the hashtable calling tommy_hashdyn_done().
 *
 * \code
 * tommy_hashdyn_done(&hashdyn);
 * \endcode
 *
 * If you need to iterate over all the elements in the hashtable, you can use
 * tommy_hashdyn_foreach() or tommy_hashdyn_foreach_arg().
 * If you need a more precise control with a real iteration, you have to insert
 * all the elements also in a ::tommy_list, and use the list to iterate.
 * See the \ref multiindex example for more detail.
 */

#ifndef __TOMMYHASHDYN_H
#define __TOMMYHASHDYN_H

#include "tommyhash.h"

/******************************************************************************/
/* hashdyn */

/** \internal
 * Initial and minimal size of the hashtable expressed as a power of 2.
 * The initial size is 2^TOMMY_HASHDYN_BIT.
 */
#define TOMMY_HASHDYN_BIT 4

/**
 * Hashtable node.
 * This is the node that you have to include inside your objects.
 */
typedef tommy_node tommy_hashdyn_node;

/**
 * Hashtable container type.
 * \note Don't use internal fields directly, but access the container only using functions.
 */
typedef struct tommy_hashdyn_struct {
    tommy_hashdyn_node** bucket; /**< Hash buckets. One list for each hash modulus. */
    tommy_size_t bucket_max; /**< Number of buckets. */
    tommy_size_t bucket_mask; /**< Bit mask to access the buckets. */
    tommy_size_t count; /**< Number of elements. */
    tommy_uint_t bucket_bit; /**< Bits used in the bit mask. */
} tommy_hashdyn;

/**
 * Initializes the hashtable.
 */
void tommy_hashdyn_init(tommy_hashdyn* hashdyn);

/**
 * Deinitializes the hashtable.
 *
 * You can call this function with elements still contained,
 * but such elements are not going to be freed by this call.
 */
void tommy_hashdyn_done(tommy_hashdyn* hashdyn);

/**
 * Inserts an element in the hashtable.
 */
void tommy_hashdyn_insert(tommy_hashdyn* hashdyn, tommy_hashdyn_node* node, void* data, tommy_hash_t hash);

/**
 * Searches and removes an element from the hashtable.
 * You have to provide a compare function and the hash of the element you want to remove.
 * If the element is not found, 0 is returned.
 * If more equal elements are present, the first one is removed.
 * \param cmp Compare function called with cmp_arg as first argument and with the element to compare as a second one.
 * The function should return 0 for equal elements, anything other for different elements.
 * \param cmp_arg Compare argument passed as first argument of the compare function.
 * \param hash Hash of the element to find and remove.
 * \return The removed element, or 0 if not found.
 */
void* tommy_hashdyn_remove(tommy_hashdyn* hashdyn, tommy_search_func* cmp, const void* cmp_arg, tommy_hash_t hash);

/**
 * Gets the bucket of the specified hash.
 * The bucket is guaranteed to contain ALL the elements with the specified hash,
 * but it can contain also others.
 * You can access elements in the bucket following the ::next pointer until 0.
 * \param hash Hash of the element to find.
 * \return The head of the bucket, or 0 if empty.
 */
tommy_inline tommy_hashdyn_node* tommy_hashdyn_bucket(tommy_hashdyn* hashdyn, tommy_hash_t hash)
{
    return hashdyn->bucket[hash & hashdyn->bucket_mask];
}

/**
 * Searches an element in the hashtable.
 * You have to provide a compare function and the hash of the element you want to find.
 * If more equal elements are present, the first one is returned.
 * \param cmp Compare function called with cmp_arg as first argument and with the element to compare as a second one.
 * The function should return 0 for equal elements, anything other for different elements.
 * \param cmp_arg Compare argument passed as first argument of the compare function.
 * \param hash Hash of the element to find.
 * \return The first element found, or 0 if none.
 */
tommy_inline void* tommy_hashdyn_search(tommy_hashdyn* hashdyn, tommy_search_func* cmp, const void* cmp_arg, tommy_hash_t hash)
{
    tommy_hashdyn_node* i = tommy_hashdyn_bucket(hashdyn, hash);

    while (i) {
        /* we first check if the hash matches, as in the same bucket we may have multiples hash values */
        if (i->index == hash && cmp(cmp_arg, i->data) == 0)
            return i->data;
        i = i->next;
    }
    return 0;
}

/**
 * Removes an element from the hashtable.
 * You must already have the address of the element to remove.
 * \return The tommy_node::data field of the node removed.
 */
void* tommy_hashdyn_remove_existing(tommy_hashdyn* hashdyn, tommy_hashdyn_node* node);

/**
 * Calls the specified function for each element in the hashtable.
 *
 * You cannot add or remove elements from the inside of the callback,
 * but can use it to deallocate them.
 *
 * \code
 * tommy_hashdyn hashdyn;
 *
 * // initializes the hashtable
 * tommy_hashdyn_init(&hashdyn);
 *
 * ...
 *
 * // creates an object
 * struct object* obj = malloc(sizeof(struct object));
 *
 * ...
 *
 * // insert it in the hashtable
 * tommy_hashdyn_insert(&hashdyn, &obj->node, obj, tommy_inthash_u32(obj->value));
 *
 * ...
 *
 * // deallocates all the objects iterating the hashtable
 * tommy_hashdyn_foreach(&hashdyn, free);
 *
 * // deallocates the hashtable
 * tommy_hashdyn_done(&hashdyn);
 * \endcode
 */
void tommy_hashdyn_foreach(tommy_hashdyn* hashdyn, tommy_foreach_func* func);

/**
 * Calls the specified function with an argument for each element in the hashtable.
 */
void tommy_hashdyn_foreach_arg(tommy_hashdyn* hashdyn, tommy_foreach_arg_func* func, void* arg);

/**
 * Gets the number of elements.
 */
tommy_inline tommy_size_t tommy_hashdyn_count(tommy_hashdyn* hashdyn)
{
    return hashdyn->count;
}

/**
 * Gets the size of allocated memory.
 * It includes the size of the ::tommy_hashdyn_node of the stored elements.
 */
tommy_size_t tommy_hashdyn_memory_usage(tommy_hashdyn* hashdyn);

#endif
