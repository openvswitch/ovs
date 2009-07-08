/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
