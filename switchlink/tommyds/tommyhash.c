/*
 * Copyright (c) 2010, Andrea Mazzoleni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
#include "tommyhash.h"

/******************************************************************************/
/* hash */

tommy_inline tommy_uint32_t tommy_le_uint32_read(const void* ptr)
{
    /* allow unaligned read on Intel x86 and x86_64 platforms */
#if defined(__i386__) || defined(_M_IX86) || defined(_X86_) || defined(__x86_64__) || defined(_M_X64)
    /* defines from http://predef.sourceforge.net/ */
    return *(const tommy_uint32_t*)ptr;
#else
    const unsigned char* ptr8 = tommy_cast(const unsigned char*, ptr);
    return ptr8[0] + ((tommy_uint32_t)ptr8[1] << 8) + ((tommy_uint32_t)ptr8[2] << 16) + ((tommy_uint32_t)ptr8[3] << 24);
#endif
}

#define tommy_rot(x, k) \
    (((x) << (k)) | ((x) >> (32 - (k))))

#define tommy_mix(a, b, c) \
    do { \
        a -= c;  a ^= tommy_rot(c, 4);  c += b; \
        b -= a;  b ^= tommy_rot(a, 6);  a += c; \
        c -= b;  c ^= tommy_rot(b, 8);  b += a; \
        a -= c;  a ^= tommy_rot(c, 16);  c += b; \
        b -= a;  b ^= tommy_rot(a, 19);  a += c; \
        c -= b;  c ^= tommy_rot(b, 4);  b += a; \
    } while (0)

#define tommy_final(a, b, c) \
    do { \
        c ^= b; c -= tommy_rot(b, 14); \
        a ^= c; a -= tommy_rot(c, 11); \
        b ^= a; b -= tommy_rot(a, 25); \
        c ^= b; c -= tommy_rot(b, 16); \
        a ^= c; a -= tommy_rot(c, 4);  \
        b ^= a; b -= tommy_rot(a, 14); \
        c ^= b; c -= tommy_rot(b, 24); \
    } while (0)

tommy_uint32_t tommy_hash_u32(tommy_uint32_t init_val, const void* void_key, tommy_size_t key_len)
{
    const unsigned char* key = tommy_cast(const unsigned char*, void_key);
    tommy_uint32_t a, b, c;

    a = b = c = 0xdeadbeef + ((tommy_uint32_t)key_len) + init_val;

    while (key_len > 12) {
        a += tommy_le_uint32_read(key + 0);
        b += tommy_le_uint32_read(key + 4);
        c += tommy_le_uint32_read(key + 8);

        tommy_mix(a, b, c);

        key_len -= 12;
        key += 12;
    }

    switch (key_len) {
    case 0 :
        return c; /* used only when called with a zero length */
    case 12 :
        c += tommy_le_uint32_read(key + 8);
        b += tommy_le_uint32_read(key + 4);
        a += tommy_le_uint32_read(key + 0);
        break;
    case 11 : c += ((tommy_uint32_t)key[10]) << 16; /* fallthrough */
    case 10 : c += ((tommy_uint32_t)key[9]) << 8; /* fallthrough */
    case 9 : c += key[8]; /* fallthrough */
    case 8 :
        b += tommy_le_uint32_read(key + 4);
        a += tommy_le_uint32_read(key + 0);
        break;
    case 7 : b += ((tommy_uint32_t)key[6]) << 16; /* fallthrough */
    case 6 : b += ((tommy_uint32_t)key[5]) << 8; /* fallthrough */
    case 5 : b += key[4]; /* fallthrough */
    case 4 :
        a += tommy_le_uint32_read(key + 0);
        break;
    case 3 : a += ((tommy_uint32_t)key[2]) << 16; /* fallthrough */
    case 2 : a += ((tommy_uint32_t)key[1]) << 8; /* fallthrough */
    case 1 : a += key[0]; /* fallthrough */
    }

    tommy_final(a, b, c);

    return c;
}

tommy_uint64_t tommy_hash_u64(tommy_uint64_t init_val, const void* void_key, tommy_size_t key_len)
{
    const unsigned char* key = tommy_cast(const unsigned char*, void_key);
    tommy_uint32_t a, b, c;

    a = b = c = 0xdeadbeef + ((tommy_uint32_t)key_len) + (init_val & 0xffffffff);
    c += init_val >> 32;

    while (key_len > 12) {
        a += tommy_le_uint32_read(key + 0);
        b += tommy_le_uint32_read(key + 4);
        c += tommy_le_uint32_read(key + 8);

        tommy_mix(a, b, c);

        key_len -= 12;
        key += 12;
    }

    switch (key_len) {
    case 0 :
        return c + ((tommy_uint64_t)b << 32); /* used only when called with a zero length */
    case 12 :
        c += tommy_le_uint32_read(key + 8);
        b += tommy_le_uint32_read(key + 4);
        a += tommy_le_uint32_read(key + 0);
        break;
    case 11 : c += ((tommy_uint32_t)key[10]) << 16; /* fallthrough */
    case 10 : c += ((tommy_uint32_t)key[9]) << 8; /* fallthrough */
    case 9 : c += key[8]; /* fallthrough */
    case 8 :
        b += tommy_le_uint32_read(key + 4);
        a += tommy_le_uint32_read(key + 0);
        break;
    case 7 : b += ((tommy_uint32_t)key[6]) << 16; /* fallthrough */
    case 6 : b += ((tommy_uint32_t)key[5]) << 8; /* fallthrough */
    case 5 : b += key[4]; /* fallthrough */
    case 4 :
        a += tommy_le_uint32_read(key + 0);
        break;
    case 3 : a += ((tommy_uint32_t)key[2]) << 16; /* fallthrough */
    case 2 : a += ((tommy_uint32_t)key[1]) << 8; /* fallthrough */
    case 1 : a += key[0]; /* fallthrough */
    }

    tommy_final(a, b, c);

    return c + ((tommy_uint64_t)b << 32);
}

tommy_uint32_t tommy_strhash_u32(tommy_uint64_t init_val, const void* void_key)
{
    const unsigned char* key = tommy_cast(const unsigned char*, void_key);
    tommy_uint32_t a, b, c;
    tommy_uint32_t m[3] = { 0xff, 0xff00, 0xff0000 };

    a = b = c = 0xdeadbeef + init_val;
    /* this is different than original lookup3 and the result won't match */

    while (1) {
        tommy_uint32_t v = tommy_le_uint32_read(key);

        if (tommy_haszero_u32(v)) {
            if (v & m[0]) {
                a += v & m[0];
                if (v & m[1]) {
                    a += v & m[1];
                    if (v & m[2])
                        a += v & m[2];
                }
            }

            break;
        }

        a += v;

        v = tommy_le_uint32_read(key + 4);

        if (tommy_haszero_u32(v)) {
            if (v & m[0]) {
                b += v & m[0];
                if (v & m[1]) {
                    b += v & m[1];
                    if (v & m[2])
                        b += v & m[2];
                }
            }

            break;
        }

        b += v;

        v = tommy_le_uint32_read(key + 8);

        if (tommy_haszero_u32(v)) {
            if (v & m[0]) {
                c += v & m[0];
                if (v & m[1]) {
                    c += v & m[1];
                    if (v & m[2])
                        c += v & m[2];
                }
            }

            break;
        }

        c += v;

        tommy_mix(a, b, c);

        key += 12;
    }

    /* for lengths that are multiplers of 12 we already have called mix */
    /* this is different than the original lookup3 and the result won't match */

    tommy_final(a, b, c);

    return c;
}
