/*
 * Copyright (c) 2008 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
    return xcalloc(1, ROUND_UP(n_bits, BITMAP_ULONG_BITS));
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
