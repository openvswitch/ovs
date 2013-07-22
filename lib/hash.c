/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013 Nicira, Inc.
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
#include "hash.h"
#include <string.h>
#include "unaligned.h"

/* Returns the hash of 'a', 'b', and 'c'. */
uint32_t
hash_3words(uint32_t a, uint32_t b, uint32_t c)
{
    return mhash_finish(mhash_add(mhash_add(mhash_add(a, 0), b), c), 12);
}

/* Returns the hash of the 'n' bytes at 'p', starting from 'basis'. */
uint32_t
hash_bytes(const void *p_, size_t n, uint32_t basis)
{
    const uint32_t *p = p_;
    size_t orig_n = n;
    uint32_t hash;

    hash = basis;
    while (n >= 4) {
        hash = mhash_add(hash, get_unaligned_u32(p));
        n -= 4;
        p += 1;
    }

    if (n) {
        uint32_t tmp = 0;

        memcpy(&tmp, p, n);
        hash = mhash_add__(hash, tmp);
    }

    return mhash_finish(hash, orig_n);
}

/* Returns the hash of the 'n' 32-bit words at 'p', starting from 'basis'.
 * 'p' must be properly aligned. */
uint32_t
hash_words(const uint32_t p[], size_t n_words, uint32_t basis)
{
    uint32_t hash;
    size_t i;

    hash = basis;
    for (i = 0; i < n_words; i++) {
        hash = mhash_add(hash, p[i]);
    }
    return mhash_finish(hash, n_words * 4);
}

uint32_t
hash_double(double x, uint32_t basis)
{
    uint32_t value[2];
    BUILD_ASSERT_DECL(sizeof x == sizeof value);

    memcpy(value, &x, sizeof value);
    return hash_3words(value[0], value[1], basis);
}
