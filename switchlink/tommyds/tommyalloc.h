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
 * Allocator of fixed size blocks.
 */

#ifndef __TOMMYALLOC_H
#define __TOMMYALLOC_H

#include "tommytypes.h"

/******************************************************************************/
/* allocator */

/** \internal
 * Allocator entry.
 */
struct tommy_allocator_entry_struct {
    struct tommy_allocator_entry_struct* next; /**< Pointer to the next entry. 0 for last. */
};
typedef struct tommy_allocator_entry_struct tommy_allocator_entry;

/**
 * Allocator of fixed size blocks.
 */
typedef struct tommy_allocator_struct {
    struct tommy_allocator_entry_struct* free_block; /**< List of free blocks. */
    struct tommy_allocator_entry_struct* used_segment; /**< List of allocated segments. */
    tommy_size_t block_size; /**< Block size. */
    tommy_size_t align_size; /**< Alignment size. */
    tommy_size_t count; /**< Number of allocated elements. */
} tommy_allocator;

/**
 * Initializes the allocator.
 * \param alloc Allocator to initialize.
 * \param block_size Size of the block to allocate.
 * \param align_size Minimum alignment requirement. No less than sizeof(void*).
 */
void tommy_allocator_init(tommy_allocator* alloc, tommy_size_t block_size, tommy_size_t align_size);

/**
 * Deinitialize the allocator.
 * It also releases all the allocated memory to the heap.
 * \param alloc Allocator to deinitialize.
 */
void tommy_allocator_done(tommy_allocator* alloc);

/**
 * Allocates a block.
 * \param alloc Allocator to use.
 */
void* tommy_allocator_alloc(tommy_allocator* alloc);

/**
 * Deallocates a block.
 * You must use the same allocator used in the tommy_allocator_alloc() call.
 * \param alloc Allocator to use.
 * \param ptr Block to free.
 */
void tommy_allocator_free(tommy_allocator* alloc, void* ptr);

/**
 * Gets the size of allocated memory.
 * \param alloc Allocator to use.
 */
tommy_size_t tommy_allocator_memory_usage(tommy_allocator* alloc);

#endif
