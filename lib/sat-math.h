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

#ifndef SAT_MATH_H
#define SAT_MATH_H 1

#include <assert.h>
#include <limits.h>

/* Saturating addition: overflow yields UINT_MAX. */
static inline unsigned int
sat_add(unsigned int x, unsigned int y)
{
    return x + y >= x ? x + y : UINT_MAX;
}

/* Saturating subtraction: underflow yields 0. */
static inline unsigned int
sat_sub(unsigned int x, unsigned int y)
{
    return x >= y ? x - y : 0;
}

/* Saturating multiplication: overflow yields UINT_MAX. */
static inline unsigned int
sat_mul(unsigned int x, unsigned int y)
{
    return (!y ? 0
            : x <= UINT_MAX / y ? x * y
            : UINT_MAX);
}

#endif /* sat-math.h */
