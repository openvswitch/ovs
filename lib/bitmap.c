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

#include <config.h>
#include "bitmap.h"
#include <string.h>

/* Sets 'count' consecutive bits in 'bitmap', starting at bit offset 'start',
 * to 'value'. */
void
bitmap_set_multiple(unsigned long *bitmap, size_t start, size_t count,
                    bool value)
{
    for (; count && start % BITMAP_ULONG_BITS; count--) {
        bitmap_set(bitmap, start++, value);
    }
    for (; count >= BITMAP_ULONG_BITS; count -= BITMAP_ULONG_BITS) {
        *bitmap_unit__(bitmap, start) = -(unsigned long) value;
        start += BITMAP_ULONG_BITS;
    }
    for (; count; count--) {
        bitmap_set(bitmap, start++, value);
    }
}

/* Compares the 'n' bits in bitmaps 'a' and 'b'.  Returns true if all bits are
 * equal, false otherwise. */
bool
bitmap_equal(const unsigned long *a, const unsigned long *b, size_t n)
{
    size_t i;

    if (memcmp(a, b, n / BITMAP_ULONG_BITS * sizeof(unsigned long))) {
        return false;
    }
    for (i = ROUND_DOWN(n, BITMAP_ULONG_BITS); i < n; i++) {
        if (bitmap_is_set(a, i) != bitmap_is_set(b, i)) {
            return false;
        }
    }
    return true;
}
