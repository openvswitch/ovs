/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2014 Nicira, Inc.
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

#include "precomp.h"

static __inline UINT32
GetUnalignedU32(const UINT32 *p_)
{
    const UINT8 *p = (const UINT8 *)p_;
    return ntohl((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style. */

static __inline UINT32
JhashRot(UINT32 x, INT k)
{
    return (x << k) | (x >> (32 - k));
}

static __inline VOID
JhashMix(UINT32 *a, UINT32 *b, UINT32 *c)
{
      *a -= *c; *a ^= JhashRot(*c,  4); *c += *b;
      *b -= *a; *b ^= JhashRot(*a,  6); *a += *c;
      *c -= *b; *c ^= JhashRot(*b,  8); *b += *a;
      *a -= *c; *a ^= JhashRot(*c, 16); *c += *b;
      *b -= *a; *b ^= JhashRot(*a, 19); *a += *c;
      *c -= *b; *c ^= JhashRot(*b,  4); *b += *a;
}

static __inline VOID
JhashFinal(UINT32 *a, UINT32 *b, UINT32 *c)
{
      *c ^= *b; *c -= JhashRot(*b, 14);
      *a ^= *c; *a -= JhashRot(*c, 11);
      *b ^= *a; *b -= JhashRot(*a, 25);
      *c ^= *b; *c -= JhashRot(*b, 16);
      *a ^= *c; *a -= JhashRot(*c,  4);
      *b ^= *a; *b -= JhashRot(*a, 14);
      *c ^= *b; *c -= JhashRot(*b, 24);
}

/* Returns the Jenkins hash of the 'n' 32-bit words at 'p', starting from
 * 'basis'.  'p' must be properly aligned.
 *
 * Use hash_words() instead, unless you're computing a hash function whose
 * value is exposed "on the wire" so we don't want to change it. */
UINT32
OvsJhashWords(const UINT32 *p, SIZE_T n, UINT32 basis)
{
    UINT32 a, b, c;

    a = b = c = 0xdeadbeef + (((UINT32) n) << 2) + basis;

    while (n > 3) {
        a += p[0];
        b += p[1];
        c += p[2];
        JhashMix(&a, &b, &c);
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
        JhashFinal(&a, &b, &c);
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
UINT32
OvsJhashBytes(const VOID *p_, SIZE_T n, UINT32 basis)
{
    const UINT32 *p = p_;
    UINT32 a, b, c;

    a = b = c = 0xdeadbeef + (UINT32)n + basis;

    while (n >= 12) {
        a += GetUnalignedU32(p);
        b += GetUnalignedU32(p + 1);
        c += GetUnalignedU32(p + 2);
        JhashMix(&a, &b, &c);
        n -= 12;
        p += 3;
    }

    if (n) {
        UINT32 tmp[3];

        tmp[0] = tmp[1] = tmp[2] = 0;
        memcpy(tmp, p, n);
        a += tmp[0];
        b += tmp[1];
#pragma warning(suppress: 6385)
        /* Suppress buffer overflow, it is either zero or some random value */
        c += tmp[2];
        JhashFinal(&a, &b, &c);
    }

    return c;
}
