/*
 * Copyright (c) 2009, 2011, 2012 Nicira, Inc.
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
#undef NDEBUG
#include "sha1.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ovstest.h"
#include "random.h"
#include "util.h"

struct test_vector {
    char *data;
    size_t size;
    const uint8_t output[20];
};

static const struct test_vector vectors[] = {
    /* FIPS 180-1. */
    {
        "abc", 3,
        { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
          0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D }
    }, {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
          0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 },
    },

    /* RFC 3174. */
    {
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567"
        "0123456701234567012345670123456701234567012345670123456701234567",
        64 * 10,
        { 0xDE, 0xA3, 0x56, 0xA2, 0xCD, 0xDD, 0x90, 0xC7, 0xA7, 0xEC,
          0xED, 0xC5, 0xEB, 0xB5, 0x63, 0x93, 0x4F, 0x46, 0x04, 0x52 },
    },

    /* http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/ */
    {
        "", 0,
        { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
          0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 }
    }, {
        "Test vector from febooti.com", 28,
        { 0xa7, 0x63, 0x17, 0x95, 0xf6, 0xd5, 0x9c, 0xd6, 0xd1, 0x4e,
          0xbd, 0x00, 0x58, 0xa6, 0x39, 0x4a, 0x4b, 0x93, 0xd8, 0x68 }
    },

    /* http://en.wikipedia.org/wiki/SHA_hash_functions */
    {
        "The quick brown fox jumps over the lazy dog", 43,
        { 0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84,
          0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12 },
    }, {
        "The quick brown fox jumps over the lazy cog", 43,
        { 0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3,
          0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3 },
    },

    /* http://www.hashcash.org/docs/sha1-hashcash.html */
    {
        "0:030626:adam@cypherspace.org:6470e06d773e05a8", 46,
        { 0x00, 0x00, 0x00, 0x00, 0xc7, 0x0d, 0xb7, 0x38, 0x9f, 0x24,
          0x1b, 0x8f, 0x44, 0x1f, 0xcf, 0x06, 0x8a, 0xea, 0xd3, 0xf0 },
    },
};

static void
test_one(const struct test_vector *vec)
{
    uint8_t md[SHA1_DIGEST_SIZE];
    int i;

    /* All at once. */
    sha1_bytes(vec->data, vec->size, md);
    assert(!memcmp(md, vec->output, SHA1_DIGEST_SIZE));

    /* In two pieces. */
    for (i = 0; i < 20; i++) {
        int n0 = vec->size ? random_range(vec->size) : 0;
        int n1 = vec->size - n0;
        struct sha1_ctx sha1;

        sha1_init(&sha1);
        sha1_update(&sha1, vec->data, n0);
        sha1_update(&sha1, vec->data + n0, n1);
        sha1_final(&sha1, md);
        assert(!memcmp(md, vec->output, SHA1_DIGEST_SIZE));
    }

    putchar('.');
    fflush(stdout);
}

static void
test_big_vector(void)
{
    enum { SIZE = 1000000 };
    struct test_vector vec = {
        NULL, SIZE,
        { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
          0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F }
    };
    size_t i;

    vec.data = xmalloc(SIZE);
    for (i = 0; i < SIZE; i++) {
        vec.data[i] = 'a';
    }
    test_one(&vec);
    free(vec.data);
}

static void
test_shar1_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(vectors); i++) {
        test_one(&vectors[i]);
    }

    test_big_vector();

    putchar('\n');
}

OVSTEST_REGISTER("test-sha1", test_shar1_main);
