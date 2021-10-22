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
#include "tommyarrayof.h"

/******************************************************************************/
/* array */

void tommy_arrayof_init(tommy_arrayof* array, tommy_size_t element_size)
{
    tommy_uint_t i;

    /* fixed initial size */
    array->element_size = element_size;
    array->bucket_bit = TOMMY_ARRAYOF_BIT;
    array->bucket_max = (tommy_size_t)1 << array->bucket_bit;
    array->bucket[0] = tommy_calloc(array->bucket_max, array->element_size);
    for (i = 1; i < TOMMY_ARRAYOF_BIT; ++i)
        array->bucket[i] = array->bucket[0];

    array->count = 0;
}

void tommy_arrayof_done(tommy_arrayof* array)
{
    tommy_uint_t i;

    tommy_free(array->bucket[0]);
    for (i = TOMMY_ARRAYOF_BIT; i < array->bucket_bit; ++i) {
        unsigned char* segment = tommy_cast(unsigned char*, array->bucket[i]);
        tommy_free(segment + ((tommy_ptrdiff_t)1 << i) * array->element_size);
    }
}

void tommy_arrayof_grow(tommy_arrayof* array, tommy_size_t count)
{
    if (array->count >= count)
        return;
    array->count = count;

    while (count > array->bucket_max) {
        unsigned char* segment;

        /* allocate one more segment */
        segment = tommy_cast(unsigned char*, tommy_calloc(array->bucket_max, array->element_size));

        /* store it adjusting the offset */
        /* cast to ptrdiff_t to ensure to get a negative value */
        array->bucket[array->bucket_bit] = segment - (tommy_ptrdiff_t)array->bucket_max * array->element_size;

        ++array->bucket_bit;
        array->bucket_max = (tommy_size_t)1 << array->bucket_bit;
    }
}

tommy_size_t tommy_arrayof_memory_usage(tommy_arrayof* array)
{
    return array->bucket_max * (tommy_size_t)array->element_size;
}
