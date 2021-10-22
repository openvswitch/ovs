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

#include <config.h>
#include "tommyarrayblk.h"

/******************************************************************************/
/* array */

void tommy_arrayblk_init(tommy_arrayblk* array)
{
    tommy_array_init(&array->block);

    array->count = 0;
}

void tommy_arrayblk_done(tommy_arrayblk* array)
{
    tommy_size_t i;

    for (i = 0; i < tommy_array_size(&array->block); ++i)
        tommy_free(tommy_array_get(&array->block, i));

    tommy_array_done(&array->block);
}

void tommy_arrayblk_grow(tommy_arrayblk* array, tommy_size_t count)
{
    tommy_size_t block_max;
    tommy_size_t block_mac;

    if (array->count >= count)
        return;
    array->count = count;

    block_max = (count + TOMMY_ARRAYBLK_SIZE - 1) / TOMMY_ARRAYBLK_SIZE;
    block_mac = tommy_array_size(&array->block);

    if (block_mac < block_max) {
        /* grow the block array */
        tommy_array_grow(&array->block, block_max);

        /* allocate new blocks */
        while (block_mac < block_max) {
            void** ptr = tommy_cast(void**, tommy_calloc(TOMMY_ARRAYBLK_SIZE, sizeof(void*)));

            /* set the new block */
            tommy_array_set(&array->block, block_mac, ptr);

            ++block_mac;
        }
    }
}

tommy_size_t tommy_arrayblk_memory_usage(tommy_arrayblk* array)
{
    return tommy_array_memory_usage(&array->block) + tommy_array_size(&array->block) * TOMMY_ARRAYBLK_SIZE * sizeof(void*);
}
