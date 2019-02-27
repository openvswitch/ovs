/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2014 Nicira, Inc.
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
    return hash_finish(hash_add(hash_add(hash_add(a, 0), b), c), 12);
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
        hash = hash_add(hash, get_unaligned_u32(p));
        n -= 4;
        p += 1;
    }

    if (n) {
        uint32_t tmp = 0;

        memcpy(&tmp, p, n);
        hash = hash_add(hash, tmp);
    }

    return hash_finish(hash, orig_n);
}

uint32_t
hash_double(double x, uint32_t basis)
{
    uint32_t value[2];
    BUILD_ASSERT_DECL(sizeof x == sizeof value);

    memcpy(value, &x, sizeof value);
    return hash_3words(value[0], value[1], basis);
}

uint32_t
hash_words__(const uint32_t p[], size_t n_words, uint32_t basis)
{
    return hash_words_inline(p, n_words, basis);
}

uint32_t
hash_words64__(const uint64_t p[], size_t n_words, uint32_t basis)
{
    return hash_words64_inline(p, n_words, basis);
}

#if !(defined(__x86_64__)) && !(defined(__aarch64__))
void
hash_bytes128(const void *p_, size_t len, uint32_t basis, ovs_u128 *out)
{
    const uint32_t c1 = 0x239b961b;
    const uint32_t c2 = 0xab0e9789;
    const uint32_t c3 = 0x38b34ae5;
    const uint32_t c4 = 0xa1e38b93;
    const uint8_t *tail, *data = (const uint8_t *)p_;
    const uint32_t *blocks = (const uint32_t *)p_;
    const int nblocks = len / 16;
    uint32_t h1 = basis;
    uint32_t h2 = basis;
    uint32_t h3 = basis;
    uint32_t h4 = basis;

    /* Body */
    for (int i = 0; i < nblocks; i++) {
        uint32_t k1 = get_unaligned_u32(&blocks[i * 4 + 0]);
        uint32_t k2 = get_unaligned_u32(&blocks[i * 4 + 1]);
        uint32_t k3 = get_unaligned_u32(&blocks[i * 4 + 2]);
        uint32_t k4 = get_unaligned_u32(&blocks[i * 4 + 3]);

        k1 *= c1;
        k1 = hash_rot(k1, 15);
        k1 *= c2;
        h1 ^= k1;

        h1 = hash_rot(h1, 19);
        h1 += h2;
        h1 = h1 * 5 + 0x561ccd1b;

        k2 *= c2;
        k2 = hash_rot(k2, 16);
        k2 *= c3;
        h2 ^= k2;

        h2 = hash_rot(h2, 17);
        h2 += h3;
        h2 = h2 * 5 + 0x0bcaa747;

        k3 *= c3;
        k3 = hash_rot(k3, 17);
        k3 *= c4;
        h3 ^= k3;

        h3 = hash_rot(h3, 15);
        h3 += h4;
        h3 = h3 * 5 + 0x96cd1c35;

        k4 *= c4;
        k4 = hash_rot(k4, 18);
        k4 *= c1;
        h4 ^= k4;

        h4 = hash_rot(h4, 13);
        h4 += h1;
        h4 = h4 * 5 + 0x32ac3b17;
    }

    /* Tail */
    uint32_t k1, k2, k3, k4;
    k1 = k2 = k3 = k4 = 0;
    tail = data + nblocks * 16;
    switch (len & 15) {
    case 15:
        k4 ^= tail[14] << 16;
        /* fall through */
    case 14:
        k4 ^= tail[13] << 8;
        /* fall through */
    case 13:
        k4 ^= tail[12] << 0;
        k4 *= c4;
        k4 = hash_rot(k4, 18);
        k4 *= c1;
        h4 ^= k4;
        /* fall through */

    case 12:
        k3 ^= tail[11] << 24;
        /* fall through */
    case 11:
        k3 ^= tail[10] << 16;
        /* fall through */
    case 10:
        k3 ^= tail[9] << 8;
        /* fall through */
    case 9:
        k3 ^= tail[8] << 0;
        k3 *= c3;
        k3 = hash_rot(k3, 17);
        k3 *= c4;
        h3 ^= k3;
        /* fall through */

    case 8:
        k2 ^= tail[7] << 24;
        /* fall through */
    case 7:
        k2 ^= tail[6] << 16;
        /* fall through */
    case 6:
        k2 ^= tail[5] << 8;
        /* fall through */
    case 5:
        k2 ^= tail[4] << 0;
        k2 *= c2;
        k2 = hash_rot(k2, 16);
        k2 *= c3;
        h2 ^= k2;
        /* fall through */

    case 4:
        k1 ^= tail[3] << 24;
        /* fall through */
    case 3:
        k1 ^= tail[2] << 16;
        /* fall through */
    case 2:
        k1 ^= tail[1] << 8;
        /* fall through */
    case 1:
        k1 ^= tail[0] << 0;
        k1 *= c1;
        k1 = hash_rot(k1, 15);
        k1 *= c2;
        h1 ^= k1;
    };

    /* Finalization */
    h1 ^= len;
    h2 ^= len;
    h3 ^= len;
    h4 ^= len;

    h1 += h2;
    h1 += h3;
    h1 += h4;
    h2 += h1;
    h3 += h1;
    h4 += h1;

    h1 = mhash_finish(h1);
    h2 = mhash_finish(h2);
    h3 = mhash_finish(h3);
    h4 = mhash_finish(h4);

    h1 += h2;
    h1 += h3;
    h1 += h4;
    h2 += h1;
    h3 += h1;
    h4 += h1;

    out->u32[0] = h1;
    out->u32[1] = h2;
    out->u32[2] = h3;
    out->u32[3] = h4;
}

#else /* __x86_64__ or __aarch64__*/

static inline uint64_t
hash_rot64(uint64_t x, int8_t r)
{
    return (x << r) | (x >> (64 - r));
}

static inline uint64_t
fmix64(uint64_t k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;

    return k;
}

void
hash_bytes128(const void *p_, size_t len, uint32_t basis, ovs_u128 *out)
{
    const uint64_t c1 = 0x87c37b91114253d5ULL;
    const uint64_t c2 = 0x4cf5ad432745937fULL;
    const uint8_t *tail, *data = (const uint8_t *)p_;
    const uint64_t *blocks = (const uint64_t *)p_;
    const int nblocks = len / 16;
    uint64_t h1 = basis;
    uint64_t h2 = basis;
    uint64_t k1, k2;

    /* Body */
    for (int i = 0; i < nblocks; i++) {
        k1 = get_unaligned_u64(&blocks[i * 2 + 0]);
        k2 = get_unaligned_u64(&blocks[i * 2 + 1]);

        k1 *= c1;
        k1 = hash_rot64(k1, 31);
        k1 *= c2;
        h1 ^= k1;

        h1 = hash_rot64(h1, 27);
        h1 += h2;
        h1 = h1 * 5 + 0x52dce729;

        k2 *= c2;
        k2 = hash_rot64(k2, 33);
        k2 *= c1;
        h2 ^= k2;

        h2 = hash_rot64(h2, 31);
        h2 += h1;
        h2 = h2 * 5 + 0x38495ab5;
    }

    /* Tail */
    k1 = 0;
    k2 = 0;
    tail = data + nblocks * 16;
    switch (len & 15) {
    case 15:
        k2 ^= ((uint64_t) tail[14]) << 48;
        /* fall through */
    case 14:
        k2 ^= ((uint64_t) tail[13]) << 40;
        /* fall through */
    case 13:
        k2 ^= ((uint64_t) tail[12]) << 32;
        /* fall through */
    case 12:
        k2 ^= ((uint64_t) tail[11]) << 24;
        /* fall through */
    case 11:
        k2 ^= ((uint64_t) tail[10]) << 16;
        /* fall through */
    case 10:
        k2 ^= ((uint64_t) tail[9]) << 8;
        /* fall through */
    case 9:
        k2 ^= ((uint64_t) tail[8]) << 0;
        k2 *= c2;
        k2 = hash_rot64(k2, 33);
        k2 *= c1;
        h2 ^= k2;
        /* fall through */
    case 8:
        k1 ^= ((uint64_t) tail[7]) << 56;
        /* fall through */
    case 7:
        k1 ^= ((uint64_t) tail[6]) << 48;
        /* fall through */
    case 6:
        k1 ^= ((uint64_t) tail[5]) << 40;
        /* fall through */
    case 5:
        k1 ^= ((uint64_t) tail[4]) << 32;
        /* fall through */
    case 4:
        k1 ^= ((uint64_t) tail[3]) << 24;
        /* fall through */
    case 3:
        k1 ^= ((uint64_t) tail[2]) << 16;
        /* fall through */
    case 2:
        k1 ^= ((uint64_t) tail[1]) << 8;
        /* fall through */
    case 1:
        k1 ^= ((uint64_t) tail[0]) << 0;
        k1 *= c1;
        k1 = hash_rot64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
    };

    /* Finalization */
    h1 ^= len;
    h2 ^= len;
    h1 += h2;
    h2 += h1;
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 += h2;
    h2 += h1;

    out->u64.lo = h1;
    out->u64.hi = h2;
}
#endif /* __x86_64__ or __aarch64__*/
