/*
 * Copyright (c) 2011, Andrea Mazzoleni. All rights reserved.
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
 * Dynamic array based on segments of exponential growing size.
 *
 * This array is able to grow dynamically upon request, without any reallocation.
 *
 * The grow operation involves an allocation of a new array segment, without reallocating
 * the already used memory, and then not increasing the heap fragmentation.
 * This also implies that the address of the stored elements never change.
 *
 * Allocated segments grow in size exponentially.
 */

#ifndef __TOMMYARRAY_H
#define __TOMMYARRAY_H

#include "tommytypes.h"

#include "util.h" /* for ovs_assert */

/******************************************************************************/
/* array */

/**
 * Initial and minimal size of the array expressed as a power of 2.
 * The initial size is 2^TOMMY_ARRAY_BIT.
 */
#define TOMMY_ARRAY_BIT 6

/**
 * Array container type.
 * \note Don't use internal fields directly, but access the container only using functions.
 */
typedef struct tommy_array_struct {
    void** bucket[TOMMY_SIZE_BIT]; /**< Dynamic array of buckets. */
    tommy_size_t bucket_max; /**< Number of buckets. */
    tommy_size_t count; /**< Number of initialized elements in the array. */
    tommy_uint_t bucket_bit; /**< Bits used in the bit mask. */
} tommy_array;

/**
 * Initializes the array.
 */
void tommy_array_init(tommy_array* array);

/**
 * Deinitializes the array.
 */
void tommy_array_done(tommy_array* array);

/**
 * Grows the size up to the specified value.
 * All the new elements in the array are initialized with the 0 value.
 */
void tommy_array_grow(tommy_array* array, tommy_size_t size);

/**
 * Gets a reference of the element at the specified position.
 * You must be sure that space for this position is already
 * allocated calling tommy_array_grow().
 */
tommy_inline void** tommy_array_ref(tommy_array* array, tommy_size_t pos)
{
    tommy_uint_t bsr;

    ovs_assert(pos < array->count);

    /* get the highest bit set, in case of all 0, return 0 */
    bsr = tommy_ilog2(pos | 1);

    return &array->bucket[bsr][pos];
}

/**
 * Sets the element at the specified position.
 * You must be sure that space for this position is already
 * allocated calling tommy_array_grow().
 */
tommy_inline void tommy_array_set(tommy_array* array, tommy_size_t pos, void* element)
{
    *tommy_array_ref(array, pos) = element;
}

/**
 * Gets the element at the specified position.
 * You must be sure that space for this position is already
 * allocated calling tommy_array_grow().
 */
tommy_inline void* tommy_array_get(tommy_array* array, tommy_size_t pos)
{
    return *tommy_array_ref(array, pos);
}

/**
 * Grows and inserts a new element at the end of the array.
 */
tommy_inline void tommy_array_insert(tommy_array* array, void* element)
{
    tommy_size_t pos = array->count;

    tommy_array_grow(array, pos + 1);

    tommy_array_set(array, pos, element);
}

/**
 * Gets the initialized size of the array.
 */
tommy_inline tommy_size_t tommy_array_size(tommy_array* array)
{
    return array->count;
}

/**
 * Gets the size of allocated memory.
 */
tommy_size_t tommy_array_memory_usage(tommy_array* array);

#endif
