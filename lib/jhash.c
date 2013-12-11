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
#include "jhash.h"
#include <string.h>
#include "unaligned.h"

/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style. */

static inline uint32_t
jhash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}

static inline void
jhash_mix(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *a -= *c; *a ^= jhash_rot(*c,  4); *c += *b;
      *b -= *a; *b ^= jhash_rot(*a,  6); *a += *c;
      *c -= *b; *c ^= jhash_rot(*b,  8); *b += *a;
      *a -= *c; *a ^= jhash_rot(*c, 16); *c += *b;
      *b -= *a; *b ^= jhash_rot(*a, 19); *a += *c;
      *c -= *b; *c ^= jhash_rot(*b,  4); *b += *a;
}

static inline void
jhash_final(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *c ^= *b; *c -= jhash_rot(*b, 14);
      *a ^= *c; *a -= jhash_rot(*c, 11);
      *b ^= *a; *b -= jhash_rot(*a, 25);
      *c ^= *b; *c -= jhash_rot(*b, 16);
      *a ^= *c; *a -= jhash_rot(*c,  4);
      *b ^= *a; *b -= jhash_rot(*a, 14);
      *c ^= *b; *c -= jhash_rot(*b, 24);
}

/* Returns the Jenkins hash of the 'n' 32-bit words at 'p', starting from
 * 'basis'.  'p' must be properly aligned.
 *
 * Use hash_words() instead, unless you're computing a hash function whose
 * value is exposed "on the wire" so we don't want to change it. */
uint32_t
jhash_words(const uint32_t *p, size_t n, uint32_t basis)
{
    uint32_t a, b, c;

    a = b = c = 0xdeadbeef + (((uint32_t) n) << 2) + basis;

    while (n > 3) {
        a += p[0];
        b += p[1];
        c += p[2];
        jhash_mix(&a, &b, &c);
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
        jhash_final(&a, &b, &c);
        /* fall through */
    case 0:
        break;
    }
    return c;
}

/* Returns the Jenkins hash of the 'n' bytes at 'p', starting from 'basis'.
 *
 * Use hash_bytes() instead, unless you're computing a hash function whose
 * value is exposed "on the wire" so we don't want to change it. */
uint32_t
jhash_bytes(const void *p_, size_t n, uint32_t basis)
{
    const uint32_t *p = p_;
    uint32_t a, b, c;

    a = b = c = 0xdeadbeef + n + basis;

    while (n >= 12) {
        a += get_unaligned_u32(p);
        b += get_unaligned_u32(p + 1);
        c += get_unaligned_u32(p + 2);
        jhash_mix(&a, &b, &c);
        n -= 12;
        p += 3;
    }

    if (n) {
        uint32_t tmp[3];

        tmp[0] = tmp[1] = tmp[2] = 0;
        memcpy(tmp, p, n);
        a += tmp[0];
        b += tmp[1];
        c += tmp[2];
        jhash_final(&a, &b, &c);
    }

    return c;
}
