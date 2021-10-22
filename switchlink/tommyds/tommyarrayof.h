/*
 * Copyright (c) 2013, Andrea Mazzoleni. All rights reserved.
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
 * This is very similar at ::tommy_array, but it allows to store elements of any
 * size and not just pointers.
 *
 * Note that in this case tommy_arrayof_ref() returns a pointer to the element,
 * that should be used for getting and setting elements in the array,
 * as generic getter and setter are not available.
 */

#ifndef __TOMMYARRAYOF_H
#define __TOMMYARRAYOF_H

#include "tommytypes.h"

#include "util.h" /* for ovs_assert */

/******************************************************************************/
/* array */

/**
 * Initial and minimal size of the array expressed as a power of 2.
 * The initial size is 2^TOMMY_ARRAYOF_BIT.
 */
#define TOMMY_ARRAYOF_BIT 6

/**
 * Array container type.
 * \note Don't use internal fields directly, but access the container only using functions.
 */
typedef struct tommy_arrayof_struct {
    void* bucket[TOMMY_SIZE_BIT]; /**< Dynamic array of buckets. */
    tommy_size_t element_size; /**< Size of the stored element in bytes. */
    tommy_size_t bucket_max; /**< Number of buckets. */
    tommy_size_t count; /**< Number of initialized elements in the array. */
    tommy_uint_t bucket_bit; /**< Bits used in the bit mask. */
} tommy_arrayof;

/**
 * Initializes the array.
 * \param element_size Size in byte of the element to store in the array.
 */
void tommy_arrayof_init(tommy_arrayof* array, tommy_size_t element_size);

/**
 * Deinitializes the array.
 */
void tommy_arrayof_done(tommy_arrayof* array);

/**
 * Grows the size up to the specified value.
 * All the new elements in the array are initialized with the 0 value.
 */
void tommy_arrayof_grow(tommy_arrayof* array, tommy_size_t size);

/**
 * Gets a reference of the element at the specified position.
 * You must be sure that space for this position is already
 * allocated calling tommy_arrayof_grow().
 */
tommy_inline void* tommy_arrayof_ref(tommy_arrayof* array, tommy_size_t pos)
{
    unsigned char* ptr;
    tommy_uint_t bsr;

    ovs_assert(pos < array->count);

    /* get the highest bit set, in case of all 0, return 0 */
    bsr = tommy_ilog2(pos | 1);

    ptr = tommy_cast(unsigned char*, array->bucket[bsr]);

    return ptr + pos * array->element_size;
}

/**
 * Gets the initialized size of the array.
 */
tommy_inline tommy_size_t tommy_arrayof_size(tommy_arrayof* array)
{
    return array->count;
}

/**
 * Gets the size of allocated memory.
 */
tommy_size_t tommy_arrayof_memory_usage(tommy_arrayof* array);

#endif
