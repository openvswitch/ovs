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
#include "tommyarrayblkof.h"

/******************************************************************************/
/* array */

void tommy_arrayblkof_init(tommy_arrayblkof* array, tommy_size_t element_size)
{
    tommy_array_init(&array->block);

    array->element_size = element_size;
    array->count = 0;
}

void tommy_arrayblkof_done(tommy_arrayblkof* array)
{
    tommy_size_t i;

    for (i = 0; i < tommy_array_size(&array->block); ++i)
        tommy_free(tommy_array_get(&array->block, i));

    tommy_array_done(&array->block);
}

void tommy_arrayblkof_grow(tommy_arrayblkof* array, tommy_size_t count)
{
    tommy_size_t block_max;
    tommy_size_t block_mac;

    if (array->count >= count)
        return;
    array->count = count;

    block_max = (count + TOMMY_ARRAYBLKOF_SIZE - 1) / TOMMY_ARRAYBLKOF_SIZE;
    block_mac = tommy_array_size(&array->block);

    if (block_mac < block_max) {
        /* grow the block array */
        tommy_array_grow(&array->block, block_max);

        /* allocate new blocks */
        while (block_mac < block_max) {
            void** ptr = tommy_cast(void**, tommy_calloc(TOMMY_ARRAYBLKOF_SIZE, array->element_size));

            /* set the new block */
            tommy_array_set(&array->block, block_mac, ptr);

            ++block_mac;
        }
    }
}

tommy_size_t tommy_arrayblkof_memory_usage(tommy_arrayblkof* array)
{
    return tommy_array_memory_usage(&array->block) + tommy_array_size(&array->block) * TOMMY_ARRAYBLKOF_SIZE * array->element_size;
}
