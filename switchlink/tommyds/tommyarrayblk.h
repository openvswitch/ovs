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
 * Dynamic array based on blocks of fixed size.
 *
 * This array is able to grow dynamically upon request, without any reallocation.
 *
 * The grow operation involves an allocation of a new array block, without reallocating
 * the already used memory, and then not increasing the heap fragmentation,
 * and minimize the space occupation.
 * This also implies that the address of the stored elements never change.
 *
 * Allocated blocks are always of the same fixed size of 4 Ki pointers.
 */

#ifndef __TOMMYARRAYBLK_H
#define __TOMMYARRAYBLK_H

#include "tommytypes.h"
#include "tommyarray.h"

#include "util.h" /* for ovs_assert */

/******************************************************************************/
/* array */

/**
 * Elements for each block.
 */
#define TOMMY_ARRAYBLK_SIZE (4 * 1024)

/**
 * Array container type.
 * \note Don't use internal fields directly, but access the container only using functions.
 */
typedef struct tommy_arrayblk_struct {
    tommy_array block; /**< Array of blocks. */
    tommy_size_t count; /**< Number of initialized elements in the array. */
} tommy_arrayblk;

/**
 * Initializes the array.
 */
void tommy_arrayblk_init(tommy_arrayblk* array);

/**
 * Deinitializes the array.
 */
void tommy_arrayblk_done(tommy_arrayblk* array);

/**
 * Grows the size up to the specified value.
 * All the new elements in the array are initialized with the 0 value.
 */
void tommy_arrayblk_grow(tommy_arrayblk* array, tommy_size_t size);

/**
 * Gets a reference of the element at the specified position.
 * You must be sure that space for this position is already
 * allocated calling tommy_arrayblk_grow().
 */
tommy_inline void** tommy_arrayblk_ref(tommy_arrayblk* array, tommy_size_t pos)
{
    void** ptr;

    ovs_assert(pos < array->count);

    ptr = tommy_cast(void**, tommy_array_get(&array->block, pos / TOMMY_ARRAYBLK_SIZE));

    return &ptr[pos % TOMMY_ARRAYBLK_SIZE];
}

/**
 * Sets the element at the specified position.
 * You must be sure that space for this position is already
 * allocated calling tommy_arrayblk_grow().
 */
tommy_inline void tommy_arrayblk_set(tommy_arrayblk* array, tommy_size_t pos, void* element)
{
    *tommy_arrayblk_ref(array, pos) = element;
}

/**
 * Gets the element at the specified position.
 * You must be sure that space for this position is already
 * allocated calling tommy_arrayblk_grow().
 */
tommy_inline void* tommy_arrayblk_get(tommy_arrayblk* array, tommy_size_t pos)
{
    return *tommy_arrayblk_ref(array, pos);
}

/**
 * Grows and inserts a new element at the end of the array.
 */
tommy_inline void tommy_arrayblk_insert(tommy_arrayblk* array, void* element)
{
    tommy_size_t pos = array->count;

    tommy_arrayblk_grow(array, pos + 1);

    tommy_arrayblk_set(array, pos, element);
}

/**
 * Gets the initialized size of the array.
 */
tommy_inline tommy_size_t tommy_arrayblk_size(tommy_arrayblk* array)
{
    return array->count;
}

/**
 * Gets the size of allocated memory.
 */
tommy_size_t tommy_arrayblk_memory_usage(tommy_arrayblk* array);

#endif
