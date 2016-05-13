/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

static inline unsigned long *
bitmap_unit__(const unsigned long *bitmap, size_t offset)
{
    return CONST_CAST(unsigned long *, &bitmap[offset / BITMAP_ULONG_BITS]);
}

static inline unsigned long
bitmap_bit__(size_t offset)
{
    return 1UL << (offset % BITMAP_ULONG_BITS);
}

static inline size_t
bitmap_n_longs(size_t n_bits)
{
    return BITMAP_N_LONGS(n_bits);
}

static inline size_t
bitmap_n_bytes(size_t n_bits)
{
    return bitmap_n_longs(n_bits) * sizeof(unsigned long int);
}

static inline unsigned long *
bitmap_allocate(size_t n_bits)
{
    return xzalloc(bitmap_n_bytes(n_bits));
}

/* Initializes bitmap to all-1-bits and returns the bitmap pointer. */
static inline unsigned long *
bitmap_init1(unsigned long *bitmap, size_t n_bits)
{
    size_t n_longs = bitmap_n_longs(n_bits);
    size_t n_bytes = bitmap_n_bytes(n_bits);
    size_t r_bits = n_bits % BITMAP_ULONG_BITS;

    memset(bitmap, 0xff, n_bytes);
    if (r_bits) {
        bitmap[n_longs - 1] >>= BITMAP_ULONG_BITS - r_bits;
    }
    return bitmap;
}

/* Allocates and returns a bitmap initialized to all-1-bits. */
static inline unsigned long *
bitmap_allocate1(size_t n_bits)
{
    return bitmap_init1(xmalloc(bitmap_n_bytes(n_bits)), n_bits);
}

static inline unsigned long *
bitmap_clone(const unsigned long *bitmap, size_t n_bits)
{
    return xmemdup(bitmap, bitmap_n_bytes(n_bits));
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

static inline unsigned long *
bitmap_set1(unsigned long *bitmap, size_t offset)
{
    *bitmap_unit__(bitmap, offset) |= bitmap_bit__(offset);
    return bitmap;
}

static inline unsigned long *
bitmap_set0(unsigned long *bitmap, size_t offset)
{
    *bitmap_unit__(bitmap, offset) &= ~bitmap_bit__(offset);
    return bitmap;
}

static inline unsigned long *
bitmap_set(unsigned long *bitmap, size_t offset, bool value)
{
    return (value) ? bitmap_set1(bitmap, offset) : bitmap_set0(bitmap, offset);
}

/* Sets 'n' bits of a single unit. */
static inline void
bitmap_set_n__(unsigned long *bitmap, size_t start, size_t n, bool value)
{
    unsigned long mask = ((1UL << n) - 1) << start % BITMAP_ULONG_BITS;

    if (value) {
        *bitmap_unit__(bitmap, start) |= mask;
    } else {
        *bitmap_unit__(bitmap, start) &= ~mask;
    }
}

/* Sets 'count' consecutive bits in 'bitmap', starting at bit offset 'start',
 * to 'value'. */
static inline unsigned long *
bitmap_set_multiple(unsigned long *bitmap, size_t start, size_t count,
                    bool value)
{
    if (count && start % BITMAP_ULONG_BITS) {
        size_t n = MIN(count, BITMAP_ULONG_BITS - start % BITMAP_ULONG_BITS);

        bitmap_set_n__(bitmap, start, n, value);
        count -= n;
        start += n;
    }
    for (; count >= BITMAP_ULONG_BITS; count -= BITMAP_ULONG_BITS) {
        *bitmap_unit__(bitmap, start) = (unsigned long)!value - 1;
        start += BITMAP_ULONG_BITS;
    }
    if (count) {
        bitmap_set_n__(bitmap, start, count, value);
    }
    return bitmap;
}

/* Returns the number of 1-bits in the 'n'-bit bitmap at 'bitmap'. */
static inline size_t
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

/* "dst &= arg;" for n-bit dst and arg.  */
static inline unsigned long *
bitmap_and(unsigned long *dst, const unsigned long *arg, size_t n)
{
    size_t i;

    for (i = 0; i < BITMAP_N_LONGS(n); i++) {
        dst[i] &= arg[i];
    }
    return dst;
}

/* "dst |= arg;" for n-bit dst and arg.  */
static inline unsigned long *
bitmap_or(unsigned long *dst, const unsigned long *arg, size_t n)
{
    size_t i;

    for (i = 0; i < BITMAP_N_LONGS(n); i++) {
        dst[i] |= arg[i];
    }
    return dst;
}

/* "dst = ~dst;" for n-bit dst.  */
static inline unsigned long *
bitmap_not(unsigned long *dst, size_t n)
{
    size_t i;

    for (i = 0; i < n / BITMAP_ULONG_BITS; i++) {
        dst[i] = ~dst[i];
    }
    if (n % BITMAP_ULONG_BITS) {
        dst[i] ^= (1UL << (n % BITMAP_ULONG_BITS)) - 1;
    }
    return dst;
}

/* Compares the 'n' bits in bitmaps 'a' and 'b'.  Returns true if all bits are
 * equal, false otherwise. */
static inline bool
bitmap_equal(const unsigned long *a, const unsigned long *b, size_t n)
{
    if (memcmp(a, b, n / BITMAP_ULONG_BITS * sizeof(unsigned long))) {
        return false;
    }
    if (n % BITMAP_ULONG_BITS) {
        unsigned long mask = (1UL << n % BITMAP_ULONG_BITS) - 1;
        unsigned long diff = *bitmap_unit__(a, n) ^ *bitmap_unit__(b, n);

        return !(diff & mask);
    }
    return true;
}

/* Scans 'bitmap' from bit offset 'start' to 'end', excluding 'end' itself.
 * Returns the bit offset of the lowest-numbered bit set to 'target', or 'end'
 * if all of the bits are set to '!target'.  'target' is typically a
 * compile-time constant, so it makes sense to inline this.  Compiler may also
 * optimize parts away depending on the 'start' and 'end' values passed in. */
static inline size_t
bitmap_scan(const unsigned long *bitmap, bool target, size_t start, size_t end)
{
    if (OVS_LIKELY(start < end)) {
        unsigned long *p, unit;

        p = bitmap_unit__(bitmap, start);
        unit = (target ? *p : ~*p) >> (start % BITMAP_ULONG_BITS);
        if (!unit) {
            start -= start % BITMAP_ULONG_BITS; /* Round down. */
            start += BITMAP_ULONG_BITS; /* Start of the next unit. */

            for (; start < end; start += BITMAP_ULONG_BITS) {
                unit = target ? *++p : ~*++p;
                if (unit) {
                    goto found;
                }
            }
            return end;
        }
found:
        start += raw_ctz(unit);  /* unit != 0 */
        if (OVS_LIKELY(start < end)) {
            return start;
        }
    }
    return end;
}

/* Returns true if all of the 'n' bits in 'bitmap' are 0,
 * false if at least one bit is a 1.*/
static inline bool
bitmap_is_all_zeros(const unsigned long *bitmap, size_t n)
{
    return bitmap_scan(bitmap, true, 0, n) == n;
}

#define BITMAP_FOR_EACH_1_RANGE(IDX, BEGIN, END, BITMAP)           \
    for ((IDX) = bitmap_scan(BITMAP, true, BEGIN, END); (IDX) < (END);   \
         (IDX) = bitmap_scan(BITMAP, true, (IDX) + 1, END))
#define BITMAP_FOR_EACH_1(IDX, SIZE, BITMAP)        \
    BITMAP_FOR_EACH_1_RANGE(IDX, 0, SIZE, BITMAP)

/* More efficient access to a map of single ullong. */
#define ULLONG_FOR_EACH_1(IDX, MAP)                 \
    for (uint64_t map__ = (MAP);                    \
         map__ && (((IDX) = raw_ctz(map__)), true); \
         map__ = zero_rightmost_1bit(map__))

#define ULLONG_SET0(MAP, OFFSET) ((MAP) &= ~(1ULL << (OFFSET)))
#define ULLONG_SET1(MAP, OFFSET) ((MAP) |= 1ULL << (OFFSET))

/* Returns the value of a bit in a map as a bool. */
#define ULLONG_GET(MAP, OFFSET) !!((MAP) & (1ULL << (OFFSET)))

#endif /* bitmap.h */
