/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style. */

#define HASH_ROT(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define HASH_MIX(a, b, c)                       \
    do {                                        \
      a -= c; a ^= HASH_ROT(c,  4); c += b;     \
      b -= a; b ^= HASH_ROT(a,  6); a += c;     \
      c -= b; c ^= HASH_ROT(b,  8); b += a;     \
      a -= c; a ^= HASH_ROT(c, 16); c += b;     \
      b -= a; b ^= HASH_ROT(a, 19); a += c;     \
      c -= b; c ^= HASH_ROT(b,  4); b += a;     \
    } while (0)

#define HASH_FINAL(a, b, c)                     \
    do {                                        \
      c ^= b; c -= HASH_ROT(b, 14);             \
      a ^= c; a -= HASH_ROT(c, 11);             \
      b ^= a; b -= HASH_ROT(a, 25);             \
      c ^= b; c -= HASH_ROT(b, 16);             \
      a ^= c; a -= HASH_ROT(c,  4);             \
      b ^= a; b -= HASH_ROT(a, 14);             \
      c ^= b; c -= HASH_ROT(b, 24);             \
    } while (0)

uint32_t hash_words(const uint32_t *, size_t n_word, uint32_t basis);
uint32_t hash_bytes(const void *, size_t n_bytes, uint32_t basis);

static inline uint32_t hash_string(const char *s, uint32_t basis)
{
    return hash_bytes(s, strlen(s), basis);
}

/* This is Bob Jenkins' integer hash from
 * http://burtleburtle.net/bob/hash/integer.html, modified for style. */
static inline uint32_t hash_int(uint32_t x, uint32_t basis)
{
    x -= x << 6;
    x ^= x >> 17;
    x -= x << 9;
    x ^= x << 4;
    x -= x << 3;
    x ^= x << 10;
    x ^= x >> 15;
    return x + basis;
}

#endif /* hash.h */
