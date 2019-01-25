/*
 * Copyright (c) 2019 Arm Limited
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

/* This header implements HASH operation primitives on aarch64. */
#ifndef HASH_AARCH64_H
#define HASH_AARCH64_H 1

#ifndef HASH_H
#error "This header should only be included indirectly via hash.h."
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <arm_acle.h>

static inline uint32_t hash_add(uint32_t hash, uint32_t data)
{
    return __crc32cw(hash, data);
}

/* Add the halves of 'data' in the memory order. */
static inline uint32_t hash_add64(uint32_t hash, uint64_t data)
{
    return __crc32cd(hash, data);
}

static inline uint32_t hash_finish(uint32_t hash, uint64_t final)
{
    /* The finishing multiplier 0x805204f3 has been experimentally
     * derived to pass the testsuite hash tests. */
    hash = __crc32cd(hash, final) * 0x805204f3;
    return hash ^ hash >> 16; /* Increase entropy in LSBs. */
}

/* Returns the hash of the 'n' 32-bit words at 'p_', starting from 'basis'.
 * We access 'p_' as a uint64_t pointer.
 *
 * This is inlined for the compiler to have access to the 'n_words', which
 * in many cases is a constant. */
static inline uint32_t
hash_words_inline(const uint32_t p_[], size_t n_words, uint32_t basis)
{
    const uint64_t *p = (const void *)p_;
    uint32_t hash1 = basis;
    uint32_t hash2 = 0;
    uint32_t hash3 = n_words;
    const uint32_t *endp = (const uint32_t *)p + n_words;
    const uint64_t *limit = p + n_words / 2 - 3;

    while (p <= limit) {
        hash1 = __crc32cd(hash1, p[0]);
        hash2 = __crc32cd(hash2, p[1]);
        hash3 = __crc32cd(hash3, p[2]);
        p += 3;
    }
    switch (endp - (const uint32_t *)p) {
    case 1:
        hash1 = __crc32cw(hash1, *(const uint32_t *)&p[0]);
        break;
    case 2:
        hash1 = __crc32cd(hash1, p[0]);
        break;
    case 3:
        hash1 = __crc32cd(hash1, p[0]);
        hash2 = __crc32cw(hash2, *(const uint32_t *)&p[1]);
        break;
    case 4:
        hash1 = __crc32cd(hash1, p[0]);
        hash2 = __crc32cd(hash2, p[1]);
        break;
    case 5:
        hash1 = __crc32cd(hash1, p[0]);
        hash2 = __crc32cd(hash2, p[1]);
        hash3 = __crc32cw(hash3, *(const uint32_t *)&p[2]);
        break;
    }
    return hash_finish(hash1, (uint64_t)hash2 << 32 | hash3);
}

/* A simpler version for 64-bit data.
 * 'n_words' is the count of 64-bit words, basis is 64 bits. */
static inline uint32_t
hash_words64_inline(const uint64_t p[], size_t n_words, uint32_t basis)
{
    uint32_t hash1 = basis;
    uint32_t hash2 = 0;
    uint32_t hash3 = n_words;
    const uint64_t *endp = p + n_words;
    const uint64_t *limit = endp - 3;

    while (p <= limit) {
        hash1 = __crc32cd(hash1, p[0]);
        hash2 = __crc32cd(hash2, p[1]);
        hash3 = __crc32cd(hash3, p[2]);
        p += 3;
    }
    switch (endp - p) {
    case 1:
        hash1 = __crc32cd(hash1, p[0]);
        break;
    case 2:
        hash1 = __crc32cd(hash1, p[0]);
        hash2 = __crc32cd(hash2, p[1]);
        break;
    }
    return hash_finish(hash1, (uint64_t)hash2 << 32 | hash3);
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

#ifdef __cplusplus
}
#endif

#endif /* hash-aarch64.h */
