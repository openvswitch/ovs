/*
 * Copyright (c) 2008, 2009, 2011 Nicira, Inc.
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

#include <config.h>
#include "bitmap.h"
#include <string.h>
#include "util.h"

/* Allocates and returns a bitmap initialized to all-1-bits. */
unsigned long *
bitmap_allocate1(size_t n_bits)
{
    size_t n_bytes = bitmap_n_bytes(n_bits);
    size_t n_longs = bitmap_n_longs(n_bits);
    size_t r_bits = n_bits % BITMAP_ULONG_BITS;
    unsigned long *bitmap;

    /* Allocate and initialize most of the bitmap. */
    bitmap = xmalloc(n_bytes);
    memset(bitmap, 0xff, n_bytes);

    /* Ensure that the last "unsigned long" in the bitmap only has as many
     * 1-bits as there actually should be. */
    if (r_bits) {
        bitmap[n_longs - 1] = (1UL << r_bits) - 1;
    }

    return bitmap;
}

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

/* Scans 'bitmap' from bit offset 'start' to 'end', excluding 'end' itself.
 * Returns the bit offset of the lowest-numbered bit set to 1, or 'end' if
 * all of the bits are set to 0. */
size_t
bitmap_scan(const unsigned long int *bitmap, size_t start, size_t end)
{
    /* XXX slow */
    size_t i;

    for (i = start; i < end; i++) {
        if (bitmap_is_set(bitmap, i)) {
            break;
        }
    }
    return i;
}

/* Returns the number of 1-bits in the 'n'-bit bitmap at 'bitmap'. */
size_t
bitmap_count1(const unsigned long int *bitmap, size_t n)
{
    size_t i;
    size_t count = 0;

    BUILD_ASSERT(ULONG_MAX <= UINT64_MAX);
    for (i = 0; i < BITMAP_N_LONGS(n); i++) {
        count += count_1bits(bitmap[i]);
    }

    return count;
}
