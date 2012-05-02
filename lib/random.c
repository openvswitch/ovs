/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "random.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

#include "entropy.h"
#include "timeval.h"
#include "util.h"

/* This is the 32-bit PRNG recommended in G. Marsaglia, "Xorshift RNGs",
 * _Journal of Statistical Software_ 8:14 (July 2003).  According to the paper,
 * it has a period of 2**32 - 1 and passes almost all tests of randomness.
 *
 * We use this PRNG instead of libc's rand() because rand() varies in quality
 * and because its maximum value also varies between 32767 and INT_MAX, whereas
 * we often want random numbers in the full range of uint32_t.
 *
 * This random number generator is intended for purposes that do not require
 * cryptographic-quality randomness. */

/* Current random state. */
static uint32_t seed;

static uint32_t random_next(void);

void
random_init(void)
{
    while (!seed) {
        struct timeval tv;
        uint32_t entropy;

        xgettimeofday(&tv);
        get_entropy_or_die(&entropy, 4);

        seed = tv.tv_sec ^ tv.tv_usec ^ entropy;
    }
}

void
random_set_seed(uint32_t seed_)
{
    assert(seed_);
    seed = seed_;
}

void
random_bytes(void *p_, size_t n)
{
    uint8_t *p = p_;

    random_init();

    for (; n > 4; p += 4, n -= 4) {
        uint32_t x = random_next();
        memcpy(p, &x, 4);
    }

    if (n) {
        uint32_t x = random_next();
        memcpy(p, &x, n);
    }
}

uint8_t
random_uint8(void)
{
    return random_uint32();
}

uint16_t
random_uint16(void)
{
    return random_uint32();
}

uint32_t
random_uint32(void)
{
    random_init();
    return random_next();
}

uint64_t
random_uint64(void)
{
    uint64_t x;

    random_init();

    x = random_next();
    x |= (uint64_t) random_next() << 32;
    return x;
}

int
random_range(int max)
{
    return random_uint32() % max;
}

static uint32_t
random_next(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;

    return seed;
}
