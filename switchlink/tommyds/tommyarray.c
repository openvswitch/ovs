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

#include <config.h>
#include "tommyarray.h"

/******************************************************************************/
/* array */

void tommy_array_init(tommy_array* array)
{
    tommy_uint_t i;

    /* fixed initial size */
    array->bucket_bit = TOMMY_ARRAY_BIT;
    array->bucket_max = (tommy_size_t)1 << array->bucket_bit;
    array->bucket[0] = tommy_cast(void**, tommy_calloc(array->bucket_max, sizeof(void*)));
    for (i = 1; i < TOMMY_ARRAY_BIT; ++i)
        array->bucket[i] = array->bucket[0];

    array->count = 0;
}

void tommy_array_done(tommy_array* array)
{
    tommy_uint_t i;

    tommy_free(array->bucket[0]);
    for (i = TOMMY_ARRAY_BIT; i < array->bucket_bit; ++i) {
        void** segment = array->bucket[i];
        tommy_free(&segment[(tommy_ptrdiff_t)1 << i]);
    }
}

void tommy_array_grow(tommy_array* array, tommy_size_t count)
{
    if (array->count >= count)
        return;
    array->count = count;

    while (count > array->bucket_max) {
        void** segment;

        /* allocate one more segment */
        segment = tommy_cast(void**, tommy_calloc(array->bucket_max, sizeof(void*)));

        /* store it adjusting the offset */
        /* cast to ptrdiff_t to ensure to get a negative value */
        array->bucket[array->bucket_bit] = &segment[-(tommy_ptrdiff_t)array->bucket_max];

        ++array->bucket_bit;
        array->bucket_max = (tommy_size_t)1 << array->bucket_bit;
    }
}

tommy_size_t tommy_array_memory_usage(tommy_array* array)
{
    return array->bucket_max * (tommy_size_t)sizeof(void*);
}
