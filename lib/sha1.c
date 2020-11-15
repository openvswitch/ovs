/*
 * This file is from the Apache Portable Runtime Library.
 * The full upstream copyright and license statement is included below.
 * Modifications copyright (c) 2009, 2010 Nicira, Inc.
 */

/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This software also makes use of the following component:
 *
 * NIST Secure Hash Algorithm
 *      heavily modified by Uwe Hollerbach uh@alumni.caltech edu
 *  from Peter C. Gutmann's implementation as found in
 *  Applied Cryptography by Bruce Schneier
 *  This code is hereby placed in the public domain
 */

#include <config.h>
#include "sha1.h"
#include <ctype.h>
#include <string.h>
#include "compiler.h"
#include "util.h"

/* a bit faster & bigger, if defined */
#define UNROLL_LOOPS

/* SHA f()-functions */
static inline uint32_t
f1(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (~x & z);
}

static inline uint32_t
f2(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

static inline uint32_t
f3(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (x & z) | (y & z);
}

static inline uint32_t
f4(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

/* SHA constants */
#define CONST1      0x5a827999L
#define CONST2      0x6ed9eba1L
#define CONST3      0x8f1bbcdcL
#define CONST4      0xca62c1d6L

/* 32-bit rotate */
static inline uint32_t
rotate32(uint32_t x, int n)
{
    return ((x << n) | (x >> (32 - n)));
}

#define FUNC(n, i)                                                      \
    do {                                                                \
        temp = rotate32(A, 5) + f##n(B, C, D) + E + W[i] + CONST##n;    \
        E = D;                                                          \
        D = C;                                                          \
        C = rotate32(B, 30);                                            \
        B = A;                                                          \
        A = temp;                                                       \
    } while (0)

#define SHA_BLOCK_SIZE           64

/* Do SHA transformation. */
static void
sha_transform(struct sha1_ctx *sha_info)
{
    int i;
    uint32_t temp, A, B, C, D, E, W[80];

    for (i = 0; i < 16; ++i) {
        W[i] = sha_info->data[i];
    }
    for (i = 16; i < 80; ++i) {
        W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
        W[i] = rotate32(W[i], 1);
    }
    A = sha_info->digest[0];
    B = sha_info->digest[1];
    C = sha_info->digest[2];
    D = sha_info->digest[3];
    E = sha_info->digest[4];
#ifdef UNROLL_LOOPS
    FUNC(1, 0);  FUNC(1, 1);  FUNC(1, 2);  FUNC(1, 3);  FUNC(1, 4);
    FUNC(1, 5);  FUNC(1, 6);  FUNC(1, 7);  FUNC(1, 8);  FUNC(1, 9);
    FUNC(1,10);  FUNC(1,11);  FUNC(1,12);  FUNC(1,13);  FUNC(1,14);
    FUNC(1,15);  FUNC(1,16);  FUNC(1,17);  FUNC(1,18);  FUNC(1,19);

    FUNC(2,20);  FUNC(2,21);  FUNC(2,22);  FUNC(2,23);  FUNC(2,24);
    FUNC(2,25);  FUNC(2,26);  FUNC(2,27);  FUNC(2,28);  FUNC(2,29);
    FUNC(2,30);  FUNC(2,31);  FUNC(2,32);  FUNC(2,33);  FUNC(2,34);
    FUNC(2,35);  FUNC(2,36);  FUNC(2,37);  FUNC(2,38);  FUNC(2,39);

    FUNC(3,40);  FUNC(3,41);  FUNC(3,42);  FUNC(3,43);  FUNC(3,44);
    FUNC(3,45);  FUNC(3,46);  FUNC(3,47);  FUNC(3,48);  FUNC(3,49);
    FUNC(3,50);  FUNC(3,51);  FUNC(3,52);  FUNC(3,53);  FUNC(3,54);
    FUNC(3,55);  FUNC(3,56);  FUNC(3,57);  FUNC(3,58);  FUNC(3,59);

    FUNC(4,60);  FUNC(4,61);  FUNC(4,62);  FUNC(4,63);  FUNC(4,64);
    FUNC(4,65);  FUNC(4,66);  FUNC(4,67);  FUNC(4,68);  FUNC(4,69);
    FUNC(4,70);  FUNC(4,71);  FUNC(4,72);  FUNC(4,73);  FUNC(4,74);
    FUNC(4,75);  FUNC(4,76);  FUNC(4,77);  FUNC(4,78);  FUNC(4,79);
#else /* !UNROLL_LOOPS */
    for (i = 0; i < 20; ++i) {
        FUNC(1,i);
    }
    for (i = 20; i < 40; ++i) {
        FUNC(2,i);
    }
    for (i = 40; i < 60; ++i) {
        FUNC(3,i);
    }
    for (i = 60; i < 80; ++i) {
        FUNC(4,i);
    }
#endif /* !UNROLL_LOOPS */
    sha_info->digest[0] += A;
    sha_info->digest[1] += B;
    sha_info->digest[2] += C;
    sha_info->digest[3] += D;
    sha_info->digest[4] += E;
}

/* 'count' is the number of bytes to do an endian flip. */
static void
maybe_byte_reverse(uint32_t *buffer OVS_UNUSED, int count OVS_UNUSED)
{
#if !WORDS_BIGENDIAN
    int i;
    uint8_t ct[4], *cp;

    count /= sizeof(uint32_t);
    cp = (uint8_t *) buffer;
    for (i = 0; i < count; i++) {
        ct[0] = cp[0];
        ct[1] = cp[1];
        ct[2] = cp[2];
        ct[3] = cp[3];
        cp[0] = ct[3];
        cp[1] = ct[2];
        cp[2] = ct[1];
        cp[3] = ct[0];
        cp += sizeof(uint32_t);
    }
#endif
}

/*
 * Initialize the SHA digest.
 * context: The SHA context to initialize
 */
void
sha1_init(struct sha1_ctx *sha_info)
{
    sha_info->digest[0] = 0x67452301L;
    sha_info->digest[1] = 0xefcdab89L;
    sha_info->digest[2] = 0x98badcfeL;
    sha_info->digest[3] = 0x10325476L;
    sha_info->digest[4] = 0xc3d2e1f0L;
    sha_info->count_lo = 0L;
    sha_info->count_hi = 0L;
    sha_info->local = 0;
}

/*
 * Update the SHA digest.
 * context: The SHA1 context to update.
 * input: The buffer to add to the SHA digest.
 * inputLen: The length of the input buffer.
 */
void
sha1_update(struct sha1_ctx *ctx, const void *buffer_, uint32_t count)
{
    const uint8_t *buffer = buffer_;
    unsigned int i;

    if ((ctx->count_lo + (count << 3)) < ctx->count_lo) {
        ctx->count_hi++;
    }
    ctx->count_lo += count << 3;
    ctx->count_hi += count >> 29;
    if (ctx->local) {
        i = SHA_BLOCK_SIZE - ctx->local;
        if (i > count) {
            i = count;
        }
        memcpy(((uint8_t *) ctx->data) + ctx->local, buffer, i);
        count -= i;
        buffer += i;
        ctx->local += i;
        if (ctx->local == SHA_BLOCK_SIZE) {
            maybe_byte_reverse(ctx->data, SHA_BLOCK_SIZE);
            sha_transform(ctx);
        } else {
            return;
        }
    }
    while (count >= SHA_BLOCK_SIZE) {
        memcpy(ctx->data, buffer, SHA_BLOCK_SIZE);
        buffer += SHA_BLOCK_SIZE;
        count -= SHA_BLOCK_SIZE;
        maybe_byte_reverse(ctx->data, SHA_BLOCK_SIZE);
        sha_transform(ctx);
    }
    memcpy(ctx->data, buffer, count);
    ctx->local = count;
}

/*
 * Finish computing the SHA digest.
 * digest: the output buffer in which to store the digest.
 * context: The context to finalize.
 */
void
sha1_final(struct sha1_ctx *ctx, uint8_t digest[SHA1_DIGEST_SIZE])
{
    int count, i, j;
    uint32_t lo_bit_count, hi_bit_count, k;

    lo_bit_count = ctx->count_lo;
    hi_bit_count = ctx->count_hi;
    count = (int) ((lo_bit_count >> 3) & 0x3f);
    ((uint8_t *) ctx->data)[count++] = 0x80;
    if (count > SHA_BLOCK_SIZE - 8) {
        memset(((uint8_t *) ctx->data) + count, 0, SHA_BLOCK_SIZE - count);
        maybe_byte_reverse(ctx->data, SHA_BLOCK_SIZE);
        sha_transform(ctx);
        memset((uint8_t *) ctx->data, 0, SHA_BLOCK_SIZE - 8);
    } else {
        memset(((uint8_t *) ctx->data) + count, 0,
               SHA_BLOCK_SIZE - 8 - count);
    }
    maybe_byte_reverse(ctx->data, SHA_BLOCK_SIZE);
    ctx->data[14] = hi_bit_count;
    ctx->data[15] = lo_bit_count;
    sha_transform(ctx);

    for (i = j = 0; j < SHA1_DIGEST_SIZE; i++) {
        k = ctx->digest[i];
        digest[j++] = k >> 24;
        digest[j++] = k >> 16;
        digest[j++] = k >> 8;
        digest[j++] = k;
    }
}

/* Computes the hash of 'n' bytes in 'data' into 'digest'. */
void
sha1_bytes(const void *data, uint32_t n, uint8_t digest[SHA1_DIGEST_SIZE])
{
    struct sha1_ctx ctx;

    sha1_init(&ctx);
    sha1_update(&ctx, data, n);
    sha1_final(&ctx, digest);
}

void
sha1_to_hex(const uint8_t digest[SHA1_DIGEST_SIZE],
            char hex[SHA1_HEX_DIGEST_LEN + 1])
{
    int i;

    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        *hex++ = "0123456789abcdef"[digest[i] >> 4];
        *hex++ = "0123456789abcdef"[digest[i] & 15];
    }
    *hex = '\0';
}

bool
sha1_from_hex(uint8_t digest[SHA1_DIGEST_SIZE], const char *hex)
{
    int i;

    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        bool ok;

        digest[i] = hexits_value(hex, 2, &ok);
        if (!ok) {
            return false;
        }
        hex += 2;
    }
    return true;
}

