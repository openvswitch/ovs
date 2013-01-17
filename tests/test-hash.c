/*
 * Copyright (c) 2009, 2012 Nicira, Inc.
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "jhash.h"

#undef NDEBUG
#include <assert.h>

static void
set_bit(uint32_t array[3], int bit)
{
    assert(bit >= 0 && bit <= 96);
    memset(array, 0, sizeof(uint32_t) * 3);
    if (bit < 96) {
        array[bit / 32] = UINT32_C(1) << (bit % 32);
    }
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
                    exit(1);
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
            uint32_t in1[3], in2[3];
            uint32_t out1, out2;
            const int min_unique = 12;
            const uint32_t unique_mask = (UINT32_C(1) << min_unique) - 1;

            set_bit(in1, i);
            set_bit(in2, j);
            out1 = hash(in1, 3, 0);
            out2 = hash(in2, 3, 0);
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

int
main(void)
{
    /* Check that all hashes computed with hash_words with one 1-bit (or no
     * 1-bits) set within a single 32-bit word have different values in all
     * 11-bit consecutive runs.
     *
     * Given a random distribution, the probability of at least one collision
     * in any set of 11 bits is approximately
     *
     *                      1 - ((2**11 - 1)/2**11)**C(33,2)
     *                   == 1 - (2047/2048)**528
     *                   =~ 0.22
     *
     * There are 21 ways to pick 11 consecutive bits in a 32-bit word, so if we
     * assumed independence then the chance of having no collisions in any of
     * those 11-bit runs would be (1-0.22)**21 =~ .0044.  Obviously
     * independence must be a bad assumption :-)
     */
    check_word_hash(hash_words_cb, "hash_words", 11);
    check_word_hash(jhash_words_cb, "jhash_words", 11);

    /* Check that all hash functions of with one 1-bit (or no 1-bits) set
     * within three 32-bit words have different values in their lowest 12
     * bits.
     *
     * Given a random distribution, the probability of at least one collision
     * in 12 bits is approximately
     *
     *                      1 - ((2**12 - 1)/2**12)**C(97,2)
     *                   == 1 - (4095/4096)**4656
     *                   =~ 0.68
     *
     * so we are doing pretty well to not have any collisions in 12 bits.
     */
    check_3word_hash(hash_words, "hash_words");
    check_3word_hash(jhash_words, "jhash_words");

    /* Check that all hashes computed with hash_int with one 1-bit (or no
     * 1-bits) set within a single 32-bit word have different values in all
     * 12-bit consecutive runs.
     *
     * Given a random distribution, the probability of at least one collision
     * in any set of 12 bits is approximately
     *
     *                      1 - ((2**12 - 1)/2**12)**C(33,2)
     *                   == 1 - (4,095/4,096)**528
     *                   =~ 0.12
     *
     * There are 20 ways to pick 12 consecutive bits in a 32-bit word, so if we
     * assumed independence then the chance of having no collisions in any of
     * those 12-bit runs would be (1-0.12)**20 =~ 0.078.  This refutes our
     * assumption of independence, which makes it seem like a good hash
     * function.
     */
    check_word_hash(hash_int_cb, "hash_int", 12);

    return 0;
}
