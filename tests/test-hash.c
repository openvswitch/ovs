/*
 * Copyright (c) 2009, 2012, 2014, 2015 Nicira, Inc.
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
#include "hash.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jhash.h"
#include "ovstest.h"

static void
set_bit(uint32_t array[3], int bit)
{
    assert(bit >= 0 && bit <= 96);
    memset(array, 0, sizeof(uint32_t) * 3);
    if (bit < 96) {
        array[bit / 32] = UINT32_C(1) << (bit % 32);
    }
}

/* When bit == n_bits, the function just 0 sets the 'values'. */
static void
set_bit128(ovs_u128 *values, int bit, int n_bits)
{
    assert(bit >= 0 && bit <= 2048);
    memset(values, 0, n_bits/8);
    if (bit < n_bits) {
        int b = bit % 128;

        if (b < 64) {
            values[bit / 128].u64.lo = UINT64_C(1) << (b % 64);
        } else {
            values[bit / 128].u64.hi = UINT64_C(1) << (b % 64);
        }
    }
}

static uint64_t
get_range128(ovs_u128 *value, int ofs, uint64_t mask)
{
    return ((ofs < 64 ? (value->u64.lo >> ofs) : 0) & mask)
        | ((ofs <= 64 ? (value->u64.hi << (64 - ofs)) : (value->u64.hi >> (ofs - 64)) & mask));
}

static uint32_t
hash_words_cb(uint32_t input)
{
    return hash_words(&input, 1, 0);
}

static uint32_t
jhash_words_cb(uint32_t input)
{
    return jhash_words(&input, 1, 0);
}

static uint32_t
hash_int_cb(uint32_t input)
{
    return hash_int(input, 0);
}

static void
check_word_hash(uint32_t (*hash)(uint32_t), const char *name,
                int min_unique)
{
    int i, j;

    for (i = 0; i <= 32; i++) {
        uint32_t in1 = i < 32 ? UINT32_C(1) << i : 0;
        for (j = i + 1; j <= 32; j++) {
            uint32_t in2 = j < 32 ? UINT32_C(1) << j : 0;
            uint32_t out1 = hash(in1);
            uint32_t out2 = hash(in2);
            const uint32_t unique_mask = (UINT32_C(1) << min_unique) - 1;
            int ofs;
            for (ofs = 0; ofs < 32 - min_unique; ofs++) {
                uint32_t bits1 = (out1 >> ofs) & unique_mask;
                uint32_t bits2 = (out2 >> ofs) & unique_mask;
                if (bits1 == bits2) {
                    printf("Partial collision for '%s':\n", name);
                    printf("%s(%08"PRIx32") = %08"PRIx32"\n", name, in1, out1);
                    printf("%s(%08"PRIx32") = %08"PRIx32"\n", name, in2, out2);
                    printf("%d bits of output starting at bit %d "
                           "are both 0x%"PRIx32"\n", min_unique, ofs, bits1);
                }
            }
        }
    }
}

static void
check_3word_hash(uint32_t (*hash)(const uint32_t[], size_t, uint32_t),
                 const char *name)
{
    int i, j;

    for (i = 0; i <= 96; i++) {
        for (j = i + 1; j <= 96; j++) {
            uint32_t in0[3], in1[3], in2[3];
            uint32_t out0,out1, out2;
            const int min_unique = 12;
            const uint32_t unique_mask = (UINT32_C(1) << min_unique) - 1;

            set_bit(in0, i);
            set_bit(in1, i);
            set_bit(in2, j);
            out0 = hash(in0, 3, 0);
            out1 = hash(in1, 3, 0);
            out2 = hash(in2, 3, 0);

            if (out0 != out1) {
                printf("%s hash not the same for non-64 aligned data "
                       "%08"PRIx32" != %08"PRIx32"\n", name, out0, out1);
            }
            if ((out1 & unique_mask) == (out2 & unique_mask)) {
                printf("%s has a partial collision:\n", name);
                printf("hash(1 << %d) == %08"PRIx32"\n", i, out1);
                printf("hash(1 << %d) == %08"PRIx32"\n", j, out2);
                printf("The low-order %d bits of output are both "
                       "0x%"PRIx32"\n", min_unique, out1 & unique_mask);
            }
        }
    }
}

static void
check_hash_bytes128(void (*hash)(const void *, size_t, uint32_t, ovs_u128 *),
                    const char *name, const int min_unique)
{
    const uint64_t unique_mask = (UINT64_C(1) << min_unique) - 1;
    const int n_bits = sizeof(ovs_u128) * 8;
    int i, j;

    for (i = 0; i <= n_bits; i++) {
        OVS_PACKED(struct offset_ovs_u128 {
            uint32_t a;
            ovs_u128 b;
        }) in0;
        ovs_u128 in1;
        ovs_u128 out0, out1;

        set_bit128(&in1, i, n_bits);
        in0.b = in1;
        hash(&in0.b, sizeof(ovs_u128), 0, &out0);
        hash(&in1, sizeof(ovs_u128), 0, &out1);
        if (!ovs_u128_equals(out0, out1)) {
            printf("%s hash not the same for non-64 aligned data "
                   "%016"PRIx64"%016"PRIx64" != %016"PRIx64"%016"PRIx64"\n",
                   name, out0.u64.lo, out0.u64.hi, out1.u64.lo, out1.u64.hi);
        }

        for (j = i + 1; j <= n_bits; j++) {
            ovs_u128 in2;
            ovs_u128 out2;
            int ofs;

            set_bit128(&in2, j, n_bits);
            hash(&in2, sizeof(ovs_u128), 0, &out2);
            for (ofs = 0; ofs < 128 - min_unique; ofs++) {
                uint64_t bits1 = get_range128(&out1, ofs, unique_mask);
                uint64_t bits2 = get_range128(&out2, ofs, unique_mask);

                if (bits1 == bits2) {
                    printf("%s has a partial collision:\n", name);
                    printf("hash(1 << %d) == %016"PRIx64"%016"PRIx64"\n",
                           i, out1.u64.hi, out1.u64.lo);
                    printf("hash(1 << %d) == %016"PRIx64"%016"PRIx64"\n",
                           j, out2.u64.hi, out2.u64.lo);
                    printf("%d bits of output starting at bit %d "
                           "are both 0x%016"PRIx64"\n", min_unique, ofs, bits1);
                }
            }
        }
    }
}

static void
check_256byte_hash(void (*hash)(const void *, size_t, uint32_t, ovs_u128 *),
                   const char *name, const int min_unique)
{
    const uint64_t unique_mask = (UINT64_C(1) << min_unique) - 1;
    const int n_bits = sizeof(ovs_u128) * 8 * 16;
    int i, j;

    for (i = 0; i <= n_bits; i++) {
        OVS_PACKED(struct offset_ovs_u128 {
            uint32_t a;
            ovs_u128 b[16];
        }) in0;
        ovs_u128 in1[16];
        ovs_u128 out0, out1;

        set_bit128(in1, i, n_bits);
        for (j = 0; j < 16; j++) {
            in0.b[j] = in1[j];
        }
        hash(&in0.b, sizeof(ovs_u128) * 16, 0, &out0);
        hash(in1, sizeof(ovs_u128) * 16, 0, &out1);
        if (!ovs_u128_equals(out0, out1)) {
            printf("%s hash not the same for non-64 aligned data "
                   "%016"PRIx64"%016"PRIx64" != %016"PRIx64"%016"PRIx64"\n",
                   name, out0.u64.lo, out0.u64.hi, out1.u64.lo, out1.u64.hi);
        }

        for (j = i + 1; j <= n_bits; j++) {
            ovs_u128 in2[16];
            ovs_u128 out2;

            set_bit128(in2, j, n_bits);
            hash(in2, sizeof(ovs_u128) * 16, 0, &out2);
            if ((out1.u64.lo & unique_mask) == (out2.u64.lo & unique_mask)) {
                printf("%s has a partial collision:\n", name);
                printf("hash(1 << %4d) == %016"PRIx64"%016"PRIx64"\n", i,
                       out1.u64.hi, out1.u64.lo);
                printf("hash(1 << %4d) == %016"PRIx64"%016"PRIx64"\n", j,
                       out2.u64.hi, out2.u64.lo);
                printf("The low-order %d bits of output are both "
                       "0x%"PRIx64"\n", min_unique, out1.u64.lo & unique_mask);
            }
        }
    }
}

static void
test_hash_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    /*
     * The following tests check that all hashes computed with hash_function
     * with one 1-bit (or no 1-bits) set within a X-bit word have different
     * values in all N-bit consecutive comparisons.
     *
     *    test_function(hash_function, test_name, N)
     *
     * Given a random distribution, the probability of at least one collision
     * in any set of N bits is approximately
     *
     *                      1 - (prob of no collisions)
     *                          **(combination of all possible comparisons)
     *                   == 1 - ((2**N - 1)/2**N)**C(X+1,2)
     *                   == p
     *
     * There are (X-N) ways to pick N consecutive bits in a X-bit word, so if we
     * assumed independence then the chance of having no collisions in any of
     * those X-bit runs would be (1-p)**(X-N) == q.  If this q is very small
     * and we can also find a relatively small 'magic number' N such that there
     * is no collision in any comparison, then it means we have a pretty good
     * hash function.
     *
     * The values of each parameters mentioned above for the tested hash
     * functions are summarized as follow:
     *
     * hash_function       X      N        p             q
     * -------------      ---    ---    -------       -------
     *
     * hash_words_cb       32     11     0.22          0.0044
     * jhash_words_cb      32     11     0.22          0.0044
     * hash_int_cb         32     12     0.12          0.0078
     * hash_bytes128      128     19     0.0156        0.174
     *
     */
    check_word_hash(hash_words_cb, "hash_words", 11);
    check_word_hash(jhash_words_cb, "jhash_words", 11);
    check_word_hash(hash_int_cb, "hash_int", 12);
    check_hash_bytes128(hash_bytes128, "hash_bytes128", 19);

    /*
     * The following tests check that all hashes computed with hash_function
     * with one 1-bit (or no 1-bits) set within Y X-bit word have different
     * values in their lowest N bits.
     *
     *    test_function(hash_function, test_name, N)
     *
     * Given a random distribution, the probability of at least one collision
     * in any set of N bits is approximately
     *
     *                      1 - (prob of no collisions)
     *                          **(combination of all possible comparisons)
     *                   == 1 - ((2**N - 1)/2**N)**C(Y*X+1,2)
     *                   == p
     *
     * If this p is not very small and we can also find a relatively small
     * 'magic number' N such that there is no collision in any comparison,
     * then it means we have a pretty good hash function.
     *
     * The values of each parameters mentioned above for the tested hash
     * functions are summarized as follow:
     *
     * hash_function       Y      X      N        p
     * -------------      ---    ---    ---    -------
     *
     * hash_words          3      32     12     0.68
     * jhash_words         3      32     12     0.68
     * hash_bytes128      16     128     23     0.22
     *
     */
    check_3word_hash(hash_words, "hash_words");
    check_3word_hash(jhash_words, "jhash_words");
    check_256byte_hash(hash_bytes128, "hash_bytes128", 23);
}

OVSTEST_REGISTER("test-hash", test_hash_main);
