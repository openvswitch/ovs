/*
 * Copyright (c) 2011, 2012 Nicira, Inc.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "byte-order.h"
#include "command-line.h"
#include "random.h"
#include "util.h"

#undef NDEBUG
#include <assert.h>

static void
check_log_2_floor(uint32_t x, int n)
{
    if (log_2_floor(x) != n) {
        fprintf(stderr, "log_2_floor(%"PRIu32") is %d but should be %d\n",
                x, log_2_floor(x), n);
        abort();
    }
}

static void
test_log_2_floor(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int n;

    for (n = 0; n < 32; n++) {
        /* Check minimum x such that f(x) == n. */
        check_log_2_floor(1 << n, n);

        /* Check maximum x such that f(x) == n. */
        check_log_2_floor((1 << n) | ((1 << n) - 1), n);

        /* Check a random value in the middle. */
        check_log_2_floor((random_uint32() & ((1 << n) - 1)) | (1 << n), n);
    }

    /* log_2_floor(0) is undefined, so don't check it. */
}

static void
check_ctz(uint32_t x, int n)
{
    if (ctz(x) != n) {
        fprintf(stderr, "ctz(%"PRIu32") is %d but should be %d\n",
                x, ctz(x), n);
        abort();
    }
}

static void
test_ctz(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int n;

    for (n = 0; n < 32; n++) {
        /* Check minimum x such that f(x) == n. */
        check_ctz(1 << n, n);

        /* Check maximum x such that f(x) == n. */
        check_ctz(UINT32_MAX << n, n);

        /* Check a random value in the middle. */
        check_ctz((random_uint32() | 1) << n, n);
    }

    /* Check ctz(0). */
    check_ctz(0, 32);
}

static void
shuffle(unsigned int *p, size_t n)
{
    for (; n > 1; n--, p++) {
        unsigned int *q = &p[rand() % n];
        unsigned int tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

static void
check_popcount(uint32_t x, int n)
{
    if (popcount(x) != n) {
        fprintf(stderr, "popcount(%#"PRIx32") is %d but should be %d\n",
                x, popcount(x), n);
        abort();
    }
}

static void
test_popcount(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned int bits[32];
    int i;

    for (i = 0; i < ARRAY_SIZE(bits); i++) {
        bits[i] = 1u << i;
    }

    check_popcount(0, 0);

    for (i = 0; i < 1000; i++) {
        uint32_t x = 0;
        int j;

        shuffle(bits, ARRAY_SIZE(bits));
        for (j = 0; j < 32; j++) {
            x |= bits[j];
            check_popcount(x, j + 1);
        }
        assert(x == UINT32_MAX);

        shuffle(bits, ARRAY_SIZE(bits));
        for (j = 31; j >= 0; j--) {
            x &= ~bits[j];
            check_popcount(x, j);
        }
        assert(x == 0);
    }
}

/* Returns the sum of the squares of the first 'n' positive integers. */
static unsigned int
sum_of_squares(int n)
{
    return n * (n + 1) * (2 * n + 1) / 6;
}

static void
test_bitwise_copy(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned int n_loops;
    int src_ofs;
    int dst_ofs;
    int n_bits;

    n_loops = 0;
    for (n_bits = 0; n_bits <= 64; n_bits++) {
        for (src_ofs = 0; src_ofs < 64 - n_bits; src_ofs++) {
            for (dst_ofs = 0; dst_ofs < 64 - n_bits; dst_ofs++) {
                ovs_be64 src = htonll(random_uint64());
                ovs_be64 dst = htonll(random_uint64());
                ovs_be64 orig_dst = dst;
                ovs_be64 expect;

                if (n_bits == 64) {
                    expect = dst;
                } else {
                    uint64_t mask = (UINT64_C(1) << n_bits) - 1;
                    expect = orig_dst & ~htonll(mask << dst_ofs);
                    expect |= htonll(((ntohll(src) >> src_ofs) & mask)
                                     << dst_ofs);
                }

                bitwise_copy(&src, sizeof src, src_ofs,
                             &dst, sizeof dst, dst_ofs,
                             n_bits);
                if (expect != dst) {
                    fprintf(stderr,"copy_bits(0x%016"PRIx64",8,%d, "
                            "0x%016"PRIx64",8,%d, %d) yielded 0x%016"PRIx64" "
                            "instead of the expected 0x%016"PRIx64"\n",
                            ntohll(src), src_ofs,
                            ntohll(orig_dst), dst_ofs,
                            n_bits,
                            ntohll(dst), ntohll(expect));
                    abort();
                }

                n_loops++;
            }
        }
    }

    if (n_loops != sum_of_squares(64)) {
        abort();
    }
}

static void
test_bitwise_zero(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned int n_loops;
    int dst_ofs;
    int n_bits;

    n_loops = 0;
    for (n_bits = 0; n_bits <= 64; n_bits++) {
        for (dst_ofs = 0; dst_ofs < 64 - n_bits; dst_ofs++) {
            ovs_be64 dst = htonll(random_uint64());
            ovs_be64 orig_dst = dst;
            ovs_be64 expect;

            if (n_bits == 64) {
                expect = htonll(0);
            } else {
                uint64_t mask = (UINT64_C(1) << n_bits) - 1;
                expect = orig_dst & ~htonll(mask << dst_ofs);
            }

            bitwise_zero(&dst, sizeof dst, dst_ofs, n_bits);
            if (expect != dst) {
                fprintf(stderr,"bitwise_zero(0x%016"PRIx64",8,%d, %d) "
                        "yielded 0x%016"PRIx64" "
                        "instead of the expected 0x%016"PRIx64"\n",
                        ntohll(orig_dst), dst_ofs,
                        n_bits,
                        ntohll(dst), ntohll(expect));
                abort();
            }

            n_loops++;
        }
    }

    if (n_loops != 64 * (64 + 1) / 2) {
        abort();
    }
}

static void
test_bitwise_one(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned int n_loops;
    int dst_ofs;
    int n_bits;

    n_loops = 0;
    for (n_bits = 0; n_bits <= 64; n_bits++) {
        for (dst_ofs = 0; dst_ofs < 64 - n_bits; dst_ofs++) {
            ovs_be64 dst = htonll(random_uint64());
            ovs_be64 orig_dst = dst;
            ovs_be64 expect;

            if (n_bits == 64) {
                expect = htonll(UINT64_MAX);
            } else {
                uint64_t mask = (UINT64_C(1) << n_bits) - 1;
                expect = orig_dst | htonll(mask << dst_ofs);
            }

            bitwise_one(&dst, sizeof dst, dst_ofs, n_bits);
            if (expect != dst) {
                fprintf(stderr,"bitwise_one(0x%016"PRIx64",8,%d, %d) "
                        "yielded 0x%016"PRIx64" "
                        "instead of the expected 0x%016"PRIx64"\n",
                        ntohll(orig_dst), dst_ofs,
                        n_bits,
                        ntohll(dst), ntohll(expect));
                abort();
            }

            n_loops++;
        }
    }

    if (n_loops != 64 * (64 + 1) / 2) {
        abort();
    }
}

static void
test_bitwise_is_all_zeros(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int n_loops;

    for (n_loops = 0; n_loops < 100; n_loops++) {
        ovs_be64 x = htonll(0);
        int i;

        for (i = 0; i < 64; i++) {
            ovs_be64 bit;
            int ofs, n;

            /* Change a random 0-bit into a 1-bit. */
            do {
                bit = htonll(UINT64_C(1) << (random_uint32() % 64));
            } while (x & bit);
            x |= bit;

            for (ofs = 0; ofs < 64; ofs++) {
                for (n = 0; n <= 64 - ofs; n++) {
                    bool expect;
                    bool answer;

                    expect = (n == 64
                              ? x == 0
                              : !(x & htonll(((UINT64_C(1) << n) - 1)
                                             << ofs)));
                    answer = bitwise_is_all_zeros(&x, sizeof x, ofs, n);
                    if (expect != answer) {
                        fprintf(stderr,
                                "bitwise_is_all_zeros(0x%016"PRIx64",8,%d,%d "
                                "returned %s instead of %s\n",
                                ntohll(x), ofs, n,
                                answer ? "true" : "false",
                                expect ? "true" : "false");
                        abort();
                    }
                }
            }
        }
    }
}

static void
test_follow_symlinks(int argc, char *argv[])
{
    int i;

    for (i = 1; i < argc; i++) {
        char *target = follow_symlinks(argv[i]);
        puts(target);
        free(target);
    }
}

static const struct command commands[] = {
    {"ctz", 0, 0, test_ctz},
    {"popcount", 0, 0, test_popcount},
    {"log_2_floor", 0, 0, test_log_2_floor},
    {"bitwise_copy", 0, 0, test_bitwise_copy},
    {"bitwise_zero", 0, 0, test_bitwise_zero},
    {"bitwise_one", 0, 0, test_bitwise_one},
    {"bitwise_is_all_zeros", 0, 0, test_bitwise_is_all_zeros},
    {"follow-symlinks", 1, INT_MAX, test_follow_symlinks},
    {NULL, 0, 0, NULL},
};

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    run_command(argc - 1, argv + 1, commands);
    return 0;
}
