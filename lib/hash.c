/*
 * Copyright (c) 2008, 2009, 2010, 2012 Nicira, Inc.
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

/* Returns the hash of the 'n' 32-bit words at 'p', starting from 'basis'.
 * 'p' must be properly aligned. */
uint32_t
hash_words(const uint32_t *p, size_t n, uint32_t basis)
{
    uint32_t a, b, c;

    a = b = c = 0xdeadbeef + (((uint32_t) n) << 2) + basis;

    while (n > 3) {
        a += p[0];
        b += p[1];
        c += p[2];
        hash_mix(&a, &b, &c);
        n -= 3;
        p += 3;
    }

    switch (n) {
    case 3:
        c += p[2];
        /* fall through */
    case 2:
        b += p[1];
        /* fall through */
    case 1:
        a += p[0];
        hash_final(&a, &b, &c);
        /* fall through */
    case 0:
        break;
    }
    return c;
}

/* Returns the hash of 'a', 'b', and 'c'. */
uint32_t
hash_3words(uint32_t a, uint32_t b, uint32_t c)
{
    a += 0xdeadbeef;
    b += 0xdeadbeef;
    c += 0xdeadbeef;
    hash_final(&a, &b, &c);
    return c;
}

/* Returns the hash of 'a' and 'b'. */
uint32_t
hash_2words(uint32_t a, uint32_t b)
{
    return hash_3words(a, b, 0);
}

/* Returns the hash of the 'n' bytes at 'p', starting from 'basis'. */
uint32_t
hash_bytes(const void *p_, size_t n, uint32_t basis)
{
    const uint8_t *p = p_;
    uint32_t a, b, c;

    a = b = c = 0xdeadbeef + n + basis;

    while (n >= 12) {
        a += get_unaligned_u32((uint32_t *) p);
        b += get_unaligned_u32((uint32_t *) (p + 4));
        c += get_unaligned_u32((uint32_t *) (p + 8));
        hash_mix(&a, &b, &c);
        n -= 12;
        p += 12;
    }

    if (n) {
        uint32_t tmp[3];

        tmp[0] = tmp[1] = tmp[2] = 0;
        memcpy(tmp, p, n);
        a += tmp[0];
        b += tmp[1];
        c += tmp[2];
        hash_final(&a, &b, &c);
    }

    return c;
}

/* Returns the hash of the 'n' 32-bit words at 'p', starting from 'basis'.
 * 'p' must be properly aligned. */
uint32_t
mhash_words(const uint32_t p[], size_t n_words, uint32_t basis)
{
    uint32_t hash;
    size_t i;

    hash = basis;
    for (i = 0; i < n_words; i++) {
        hash = mhash_add(hash, p[i]);
    }
    return mhash_finish(hash, n_words);
}
