/*
 * Copyright (c) 2008, 2012, 2019 Nicira, Inc.
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

#ifndef SAT_MATH_H
#define SAT_MATH_H 1

#include <limits.h>
#include "openvswitch/util.h"

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/* Returns x + y, clamping out-of-range results into the range of the return
 * type. */
static inline unsigned int
sat_add(unsigned int x, unsigned int y)
{
    return x + y >= x ? x + y : UINT_MAX;
}
static inline long long int
llsat_add__(long long int x, long long int y)
{
    return (x >= 0 && y >= 0 && x > LLONG_MAX - y ? LLONG_MAX
            : x < 0 && y < 0 && x < LLONG_MIN - y ? LLONG_MIN
            : x + y);
}
static inline long long int
llsat_add(long long int x, long long int y)
{
#if (__GNUC__ >= 5 || __has_builtin(__builtin_saddll_overflow)) && !__CHECKER__
    long long int sum;
    return (!__builtin_saddll_overflow(x, y, &sum) ? sum
            : x > 0 ? LLONG_MAX : LLONG_MIN);
#else
    return llsat_add__(x, y);
#endif
}

/* Returns x - y, clamping out-of-range results into the range of the return
 * type. */
static inline unsigned int
sat_sub(unsigned int x, unsigned int y)
{
    return x >= y ? x - y : 0;
}
static inline long long int
llsat_sub__(long long int x, long long int y)
{
    return (x >= 0 && y < 0 && x > LLONG_MAX + y ? LLONG_MAX
            : x < 0 && y >= 0 && x < LLONG_MIN + y ? LLONG_MIN
            : x - y);
}
static inline long long int
llsat_sub(long long int x, long long int y)
{
#if (__GNUC__ >= 5 || __has_builtin(__builtin_ssubll_overflow)) && !__CHECKER__
    long long int difference;
    return (!__builtin_ssubll_overflow(x, y, &difference) ? difference
            : x >= 0 ? LLONG_MAX : LLONG_MIN);
#else
    return llsat_sub__(x, y);
#endif
}

/* Returns x * y, clamping out-of-range results into the range of the return
 * type. */
static inline unsigned int
sat_mul(unsigned int x, unsigned int y)
{
    return OVS_SAT_MUL(x, y);
}
static inline long long int
llsat_mul__(long long int x, long long int y)
{
    return (  x > 0 && y > 0 && x > LLONG_MAX / y ? LLONG_MAX
            : x < 0 && y > 0 && x < LLONG_MIN / y ? LLONG_MIN
            : x > 0 && y < 0 && y < LLONG_MIN / x ? LLONG_MIN
            /* Special case because -LLONG_MIN / -1 overflows: */
            : x == LLONG_MIN && y == -1 ? LLONG_MAX
            : x < 0 && y < 0 && x < LLONG_MAX / y ? LLONG_MAX
            : x * y);
}
static inline long long int
llsat_mul(long long int x, long long int y)
{
#if (__GNUC__ >= 5 || __has_builtin(__builtin_smulll_overflow)) && !__CHECKER__
    long long int product;
    return (!__builtin_smulll_overflow(x, y, &product) ? product
            : (x > 0) == (y > 0) ? LLONG_MAX : LLONG_MIN);
#else
    return llsat_mul__(x, y);
#endif
}

#endif /* sat-math.h */
