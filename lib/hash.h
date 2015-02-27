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
#ifndef HASH_H
#define HASH_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t
hash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}

uint32_t hash_bytes(const void *, size_t n_bytes, uint32_t basis);
/* The hash input must be a word larger than 128 bits. */
void hash_bytes128(const void *_, size_t n_bytes, uint32_t basis,
                   ovs_u128 *out);

static inline uint32_t hash_int(uint32_t x, uint32_t basis);
static inline uint32_t hash_2words(uint32_t, uint32_t);
static inline uint32_t hash_uint64(const uint64_t);
static inline uint32_t hash_uint64_basis(const uint64_t x,
                                         const uint32_t basis);
uint32_t hash_3words(uint32_t, uint32_t, uint32_t);

static inline uint32_t hash_boolean(bool x, uint32_t basis);
uint32_t hash_double(double, uint32_t basis);

static inline uint32_t hash_pointer(const void *, uint32_t basis);
static inline uint32_t hash_string(const char *, uint32_t basis);

/* Murmurhash by Austin Appleby,
 * from http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp.
 *
 * The upstream license there says:
 *
 * // MurmurHash3 was written by Austin Appleby, and is placed in the public
 * // domain. The author hereby disclaims copyright to this source code.
 *
 * See hash_words() for sample usage. */

static inline uint32_t mhash_add__(uint32_t hash, uint32_t data)
{
    data *= 0xcc9e2d51;
    data = hash_rot(data, 15);
    data *= 0x1b873593;
    return hash ^ data;
}

static inline uint32_t mhash_add(uint32_t hash, uint32_t data)
{
    hash = mhash_add__(hash, data);
    hash = hash_rot(hash, 13);
    return hash * 5 + 0xe6546b64;
}

static inline uint32_t mhash_finish(uint32_t hash)
{
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash;
}

#if !(defined(__SSE4_2__) && defined(__x86_64__))
/* Mhash-based implementation. */

static inline uint32_t hash_add(uint32_t hash, uint32_t data)
{
    return mhash_add(hash, data);
}

static inline uint32_t hash_add64(uint32_t hash, uint64_t data)
{
    return hash_add(hash_add(hash, data), data >> 32);
}

static inline uint32_t hash_finish(uint32_t hash, uint32_t final)
{
    return mhash_finish(hash ^ final);
}

/* Returns the hash of the 'n' 32-bit words at 'p', starting from 'basis'.
 * 'p' must be properly aligned.
 *
 * This is inlined for the compiler to have access to the 'n_words', which
 * in many cases is a constant. */
static inline uint32_t
hash_words_inline(const uint32_t p[], size_t n_words, uint32_t basis)
{
    uint32_t hash;
    size_t i;

    hash = basis;
    for (i = 0; i < n_words; i++) {
        hash = hash_add(hash, p[i]);
    }
    return hash_finish(hash, n_words * 4);
}

static inline uint32_t
hash_words64_inline(const uint64_t p[], size_t n_words, uint32_t basis)
{
    uint32_t hash;
    size_t i;

    hash = basis;
    for (i = 0; i < n_words; i++) {
        hash = hash_add64(hash, p[i]);
    }
    return hash_finish(hash, n_words * 8);
}

static inline uint32_t hash_pointer(const void *p, uint32_t basis)
{
    /* Often pointers are hashed simply by casting to integer type, but that
     * has pitfalls since the lower bits of a pointer are often all 0 for
     * alignment reasons.  It's hard to guess where the entropy really is, so
     * we give up here and just use a high-quality hash function.
     *
     * The double cast suppresses a warning on 64-bit systems about casting to
     * an integer to different size.  That's OK in this case, since most of the
     * entropy in the pointer is almost certainly in the lower 32 bits. */
    return hash_int((uint32_t) (uintptr_t) p, basis);
}

static inline uint32_t hash_2words(uint32_t x, uint32_t y)
{
    return hash_finish(hash_add(hash_add(x, 0), y), 8);
}

static inline uint32_t hash_uint64_basis(const uint64_t x,
                                         const uint32_t basis)
{
    return hash_finish(hash_add64(basis, x), 8);
}

static inline uint32_t hash_uint64(const uint64_t x)
{
    return hash_uint64_basis(x, 0);
}

#else /* __SSE4_2__ && __x86_64__ */
#include <smmintrin.h>

static inline uint32_t hash_add(uint32_t hash, uint32_t data)
{
    return _mm_crc32_u32(hash, data);
}

/* Add the halves of 'data' in the memory order. */
static inline uint32_t hash_add64(uint32_t hash, uint64_t data)
{
    return _mm_crc32_u64(hash, data);
}

static inline uint32_t hash_finish(uint64_t hash, uint64_t final)
{
    /* The finishing multiplier 0x805204f3 has been experimentally
     * derived to pass the testsuite hash tests. */
    hash = _mm_crc32_u64(hash, final) * 0x805204f3;
    return hash ^ (uint32_t)hash >> 16; /* Increase entropy in LSBs. */
}

/* Returns the hash of the 'n' 32-bit words at 'p_', starting from 'basis'.
 * We access 'p_' as a uint64_t pointer, which is fine for __SSE_4_2__.
 *
 * This is inlined for the compiler to have access to the 'n_words', which
 * in many cases is a constant. */
static inline uint32_t
hash_words_inline(const uint32_t p_[], size_t n_words, uint32_t basis)
{
    const uint64_t *p = (const void *)p_;
    uint64_t hash1 = basis;
    uint64_t hash2 = 0;
    uint64_t hash3 = n_words;
    const uint32_t *endp = (const uint32_t *)p + n_words;
    const uint64_t *limit = p + n_words / 2 - 3;

    while (p <= limit) {
        hash1 = _mm_crc32_u64(hash1, p[0]);
        hash2 = _mm_crc32_u64(hash2, p[1]);
        hash3 = _mm_crc32_u64(hash3, p[2]);
        p += 3;
    }
    switch (endp - (const uint32_t *)p) {
    case 1:
        hash1 = _mm_crc32_u32(hash1, *(const uint32_t *)&p[0]);
        break;
    case 2:
        hash1 = _mm_crc32_u64(hash1, p[0]);
        break;
    case 3:
        hash1 = _mm_crc32_u64(hash1, p[0]);
        hash2 = _mm_crc32_u32(hash2, *(const uint32_t *)&p[1]);
        break;
    case 4:
        hash1 = _mm_crc32_u64(hash1, p[0]);
        hash2 = _mm_crc32_u64(hash2, p[1]);
        break;
    case 5:
        hash1 = _mm_crc32_u64(hash1, p[0]);
        hash2 = _mm_crc32_u64(hash2, p[1]);
        hash3 = _mm_crc32_u32(hash3, *(const uint32_t *)&p[2]);
        break;
    }
    return hash_finish(hash1, hash2 << 32 | hash3);
}

/* A simpler version for 64-bit data.
 * 'n_words' is the count of 64-bit words, basis is 64 bits. */
static inline uint32_t
hash_words64_inline(const uint64_t p[], size_t n_words, uint32_t basis)
{
    uint64_t hash1 = basis;
    uint64_t hash2 = 0;
    uint64_t hash3 = n_words;
    const uint64_t *endp = p + n_words;
    const uint64_t *limit = endp - 3;

    while (p <= limit) {
        hash1 = _mm_crc32_u64(hash1, p[0]);
        hash2 = _mm_crc32_u64(hash2, p[1]);
        hash3 = _mm_crc32_u64(hash3, p[2]);
        p += 3;
    }
    switch (endp - p) {
    case 1:
        hash1 = _mm_crc32_u64(hash1, p[0]);
        break;
    case 2:
        hash1 = _mm_crc32_u64(hash1, p[0]);
        hash2 = _mm_crc32_u64(hash2, p[1]);
        break;
    }
    return hash_finish(hash1, hash2 << 32 | hash3);
}

static inline uint32_t hash_uint64_basis(const uint64_t x,
                                         const uint32_t basis)
{
    /* '23' chosen to mix bits enough for the test-hash to pass. */
    return hash_finish(hash_add64(basis, x), 23);
}

static inline uint32_t hash_uint64(const uint64_t x)
{
    return hash_uint64_basis(x, 0);
}

static inline uint32_t hash_2words(uint32_t x, uint32_t y)
{
    return hash_uint64((uint64_t)y << 32 | x);
}

static inline uint32_t hash_pointer(const void *p, uint32_t basis)
{
    return hash_uint64_basis((uint64_t) (uintptr_t) p, basis);
}
#endif

uint32_t hash_words__(const uint32_t p[], size_t n_words, uint32_t basis);
uint32_t hash_words64__(const uint64_t p[], size_t n_words, uint32_t basis);

/* Inline the larger hash functions only when 'n_words' is known to be
 * compile-time constant. */
#if __GNUC__ >= 4
static inline uint32_t
hash_words(const uint32_t p[], size_t n_words, uint32_t basis)
{
    if (__builtin_constant_p(n_words)) {
        return hash_words_inline(p, n_words, basis);
    } else {
        return hash_words__(p, n_words, basis);
    }
}

static inline uint32_t
hash_words64(const uint64_t p[], size_t n_words, uint32_t basis)
{
    if (__builtin_constant_p(n_words)) {
        return hash_words64_inline(p, n_words, basis);
    } else {
        return hash_words64__(p, n_words, basis);
    }
}

#else

static inline uint32_t
hash_words(const uint32_t p[], size_t n_words, uint32_t basis)
{
    return hash_words__(p, n_words, basis);
}

static inline uint32_t
hash_words64(const uint64_t p[], size_t n_words, uint32_t basis)
{
    return hash_words64__(p, n_words, basis);
}
#endif

static inline uint32_t hash_string(const char *s, uint32_t basis)
{
    return hash_bytes(s, strlen(s), basis);
}

static inline uint32_t hash_int(uint32_t x, uint32_t basis)
{
    return hash_2words(x, basis);
}

/* An attempt at a useful 1-bit hash function.  Has not been analyzed for
 * quality. */
static inline uint32_t hash_boolean(bool x, uint32_t basis)
{
    const uint32_t P0 = 0xc2b73583;   /* This is hash_int(1, 0). */
    const uint32_t P1 = 0xe90f1258;   /* This is hash_int(2, 0). */
    return (x ? P0 : P1) ^ hash_rot(basis, 1);
}

#ifdef __cplusplus
}
#endif

#endif /* hash.h */
