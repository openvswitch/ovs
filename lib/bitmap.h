/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BITMAP_H
#define BITMAP_H 1

#include <limits.h>
#include <stdlib.h>
#include "util.h"

#define BITMAP_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)

static inline unsigned long *
bitmap_unit__(const unsigned long *bitmap, size_t offset)
{
    return (unsigned long *) &bitmap[offset / BITMAP_ULONG_BITS];
}

static inline unsigned long
bitmap_bit__(size_t offset)
{
    return 1UL << (offset % BITMAP_ULONG_BITS);
}

static inline unsigned long *
bitmap_allocate(size_t n_bits)
{
    size_t n_longs = DIV_ROUND_UP(n_bits, BITMAP_ULONG_BITS);
    return xcalloc(sizeof(unsigned long int), n_longs);
}

static inline void
bitmap_free(unsigned long *bitmap)
{
    free(bitmap);
}

static inline bool
bitmap_is_set(const unsigned long *bitmap, size_t offset)
{
    return (*bitmap_unit__(bitmap, offset) & bitmap_bit__(offset)) != 0;
}

static inline void
bitmap_set1(unsigned long *bitmap, size_t offset)
{
    *bitmap_unit__(bitmap, offset) |= bitmap_bit__(offset);
}

static inline void
bitmap_set0(unsigned long *bitmap, size_t offset)
{
    *bitmap_unit__(bitmap, offset) &= ~bitmap_bit__(offset);
}

static inline void
bitmap_set(unsigned long *bitmap, size_t offset, bool value)
{
    if (value) {
        bitmap_set1(bitmap, offset);
    } else {
        bitmap_set0(bitmap, offset);
    }
}

void bitmap_set_multiple(unsigned long *, size_t start, size_t count,
                         bool value);
bool bitmap_equal(const unsigned long *, const unsigned long *, size_t n);

#endif /* bitmap.h */
