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

/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style. */

static inline uint32_t
hash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}

static inline void
hash_mix(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *a -= *c; *a ^= hash_rot(*c,  4); *c += *b;
      *b -= *a; *b ^= hash_rot(*a,  6); *a += *c;
      *c -= *b; *c ^= hash_rot(*b,  8); *b += *a;
      *a -= *c; *a ^= hash_rot(*c, 16); *c += *b;
      *b -= *a; *b ^= hash_rot(*a, 19); *a += *c;
      *c -= *b; *c ^= hash_rot(*b,  4); *b += *a;
}

static inline void
hash_final(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *c ^= *b; *c -= hash_rot(*b, 14);
      *a ^= *c; *a -= hash_rot(*c, 11);
      *b ^= *a; *b -= hash_rot(*a, 25);
      *c ^= *b; *c -= hash_rot(*b, 16);
      *a ^= *c; *a -= hash_rot(*c,  4);
      *b ^= *a; *b -= hash_rot(*a, 14);
      *c ^= *b; *c -= hash_rot(*b, 24);
}

uint32_t hash_words(const uint32_t *, size_t n_word, uint32_t basis);
uint32_t hash_2words(uint32_t, uint32_t);
uint32_t hash_3words(uint32_t, uint32_t, uint32_t);
uint32_t hash_bytes(const void *, size_t n_bytes, uint32_t basis);

static inline uint32_t hash_string(const char *s, uint32_t basis)
{
    return hash_bytes(s, strlen(s), basis);
}

/* This is Bob Jenkins' integer hash from
 * http://burtleburtle.net/bob/hash/integer.html, modified for style.
 *
 * This hash is faster than hash_2words(), but it isn't as good when 'basis' is
 * important.  So use this function for speed or hash_2words() for hash
 * quality. */
static inline uint32_t hash_int(uint32_t x, uint32_t basis)
{
    x -= x << 6;
    x ^= x >> 17;
    x -= x << 9;
    x ^= x << 4;
    x += basis;
    x -= x << 3;
    x ^= x << 10;
    x ^= x >> 15;
    return x;
}

/* An attempt at a useful 1-bit hash function.  Has not been analyzed for
 * quality. */
static inline uint32_t hash_boolean(bool x, uint32_t basis)
{
    const uint32_t P0 = 0xc2b73583;   /* This is hash_int(1, 0). */
    const uint32_t P1 = 0xe90f1258;   /* This is hash_int(2, 0). */
    return (x ? P0 : P1) ^ hash_rot(basis, 1);
}

static inline uint32_t hash_double(double x, uint32_t basis)
{
    uint32_t value[2];
    BUILD_ASSERT_DECL(sizeof x == sizeof value);

    memcpy(value, &x, sizeof value);
    return hash_3words(value[0], value[1], basis);
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

/* Murmurhash by Austin Appleby,
 * from http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp.
 *
 * The upstream license there says:
 *
 * // MurmurHash3 was written by Austin Appleby, and is placed in the public
 * // domain. The author hereby disclaims copyright to this source code.
 *
 * Murmurhash is faster and higher-quality than the Jenkins lookup3 hash.  When
 * we have a little more familiarity with it, it's probably a good idea to
 * switch all of OVS to it.
 *
 * For now, we have this implementation here for use by code that needs a hash
 * that is convenient for use one word at a time, since the Jenkins lookup3
 * hash works three words at a time.
 *
 * See mhash_words() for sample usage. */

uint32_t mhash_words(const uint32_t data[], size_t n_words, uint32_t basis);

static inline uint32_t mhash_add(uint32_t hash, uint32_t data)
{
    data *= 0xcc9e2d51;
    data = hash_rot(data, 15);
    data *= 0x1b873593;

    hash ^= data;
    hash = hash_rot(hash, 13);
    return hash * 5 + 0xe6546b64;
}

static inline uint32_t mhash_finish(uint32_t hash, size_t n)
{
    hash ^= n * 4;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash;
}

#ifdef __cplusplus
}
#endif

#endif /* hash.h */
