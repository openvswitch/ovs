/*
 * Copyright (c) 2011, 2012, 2013, 2014, 2015, 2016, 2019 Nicira, Inc.
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
#include "util.h"
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "byte-order.h"
#include "command-line.h"
#include "ovstest.h"
#include "random.h"
#include "sat-math.h"
#include "openvswitch/vlog.h"

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
test_log_2_floor(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
check_ctz32(uint32_t x, int n)
{
    if (ctz32(x) != n) {
        fprintf(stderr, "ctz32(%"PRIu32") is %d but should be %d\n",
                x, ctz32(x), n);
        abort();
    }
}

static void
check_ctz64(uint64_t x, int n)
{
    if (ctz64(x) != n) {
        fprintf(stderr, "ctz64(%"PRIu64") is %d but should be %d\n",
                x, ctz64(x), n);
        abort();
    }
}

static void
test_ctz(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int n;

    for (n = 0; n < 32; n++) {
        /* Check minimum x such that f(x) == n. */
        check_ctz32(1 << n, n);

        /* Check maximum x such that f(x) == n. */
        check_ctz32(UINT32_MAX << n, n);

        /* Check a random value in the middle. */
        check_ctz32((random_uint32() | 1) << n, n);
    }


    for (n = 0; n < 64; n++) {
        /* Check minimum x such that f(x) == n. */
        check_ctz64(UINT64_C(1) << n, n);

        /* Check maximum x such that f(x) == n. */
        check_ctz64(UINT64_MAX << n, n);

        /* Check a random value in the middle. */
        check_ctz64((random_uint64() | UINT64_C(1)) << n, n);
    }

    /* Check ctz(0). */
    check_ctz32(0, 32);
    check_ctz64(0, 64);
}

static void
check_clz32(uint32_t x, int n)
{
    if (clz32(x) != n) {
        fprintf(stderr, "clz32(%"PRIu32") is %d but should be %d\n",
                x, clz32(x), n);
        abort();
    }
}

static void
check_clz64(uint64_t x, int n)
{
    if (clz64(x) != n) {
        fprintf(stderr, "clz64(%"PRIu64") is %d but should be %d\n",
                x, clz64(x), n);
        abort();
    }
}

static void
test_clz(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int n;

    for (n = 0; n < 32; n++) {
        /* Check minimum x such that f(x) == n. */
        check_clz32((1u << 31) >> n, n);

        /* Check maximum x such that f(x) == n. */
        check_clz32(UINT32_MAX >> n, n);

        /* Check a random value in the middle. */
        check_clz32((random_uint32() | 1u << 31) >> n, n);
    }

    for (n = 0; n < 64; n++) {
        /* Check minimum x such that f(x) == n. */
        check_clz64((UINT64_C(1) << 63) >> n, n);

        /* Check maximum x such that f(x) == n. */
        check_clz64(UINT64_MAX >> n, n);

        /* Check a random value in the middle. */
        check_clz64((random_uint64() | UINT64_C(1) << 63) >> n, n);
    }

    /* Check clz(0). */
    check_clz32(0, 32);
    check_clz64(0, 64);
}

/* Returns a random number in the range 'min'...'max' inclusive. */
static uint32_t
random_in_range(uint32_t min, uint32_t max)
{
    return min == max ? min : min + random_range(max - min + 1);
}

static void
check_rup2(uint32_t x, int n)
{
    uint32_t rup2 = ROUND_UP_POW2(x);
    if (rup2 != n) {
        fprintf(stderr, "ROUND_UP_POW2(%#"PRIx32") is %#"PRIx32" "
                "but should be %#"PRIx32"\n", x, rup2, n);
        abort();
    }
}

static void
test_round_up_pow2(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int n;

    for (n = 0; n < 32; n++) {
        /* Min, max value for which ROUND_UP_POW2 should yield (1 << n). */
        uint32_t min = ((1u << n) >> 1) + 1;
        uint32_t max = 1u << n;

        check_rup2(min, 1u << n);
        check_rup2(max, 1u << n);
        check_rup2(random_in_range(min, max), 1u << n);
    }
    check_rup2(0, 0);
}

static void
check_rdp2(uint32_t x, int n)
{
    uint32_t rdp2 = ROUND_DOWN_POW2(x);
    if (rdp2 != n) {
        fprintf(stderr, "ROUND_DOWN_POW2(%#"PRIx32") is %#"PRIx32" "
                "but should be %#"PRIx32"\n", x, rdp2, n);
        abort();
    }
}

static void
test_round_down_pow2(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int n;

    for (n = 0; n < 32; n++) {
        /* Min, max value for which ROUND_DOWN_POW2 should yield (1 << n). */
        uint32_t min = 1u << n;
        uint32_t max = ((1u << n) << 1) - 1;

        check_rdp2(min, 1u << n);
        check_rdp2(max, 1u << n);
        check_rdp2(random_in_range(min, max), 1u << n);
    }
    check_rdp2(0, 0);
}

static void
shuffle(uint64_t *p, size_t n)
{
    for (; n > 1; n--, p++) {
        uint64_t *q = &p[random_range(n)];
        uint64_t tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

static void
check_count_1bits(uint64_t x, int n)
{
    if (count_1bits(x) != n) {
        fprintf(stderr, "count_1bits(%#"PRIx64") is %d but should be %d\n",
                x, count_1bits(x), n);
        abort();
    }
}

static void
test_count_1bits(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    uint64_t bits[64];
    int i;

    for (i = 0; i < ARRAY_SIZE(bits); i++) {
        bits[i] = UINT64_C(1) << i;
    }

    check_count_1bits(0, 0);

    for (i = 0; i < 1000; i++) {
        uint64_t x = 0;
        int j;

        shuffle(bits, ARRAY_SIZE(bits));
        for (j = 0; j < 64; j++) {
            x |= bits[j];
            check_count_1bits(x, j + 1);
        }
        assert(x == UINT64_MAX);

        shuffle(bits, ARRAY_SIZE(bits));
        for (j = 63; j >= 0; j--) {
            x &= ~bits[j];
            check_count_1bits(x, j);
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
test_bitwise_copy(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
test_bitwise_zero(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
test_bitwise_one(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
                expect = OVS_BE64_MAX;
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
test_bitwise_is_all_zeros(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
                bit = htonll(UINT64_C(1) << (random_range(64)));
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

static int
trivial_bitwise_rscan(const void *p, unsigned int len, bool target,
                      int start, int end)
{
    int ofs;

    for (ofs = start; ofs > end; ofs--) {
        if (bitwise_get_bit(p, len, ofs) == target) {
            break;
        }
    }
    return ofs;
}

static void
test_bitwise_rscan(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* All 1s */
    uint8_t s1[3] = {0xff, 0xff, 0xff};
    /* Target is the first bit */
    ovs_assert(23 == bitwise_rscan(s1, 3, 1, 23, -1));
    /* Target is not found, return -1 */
    ovs_assert(-1 == bitwise_rscan(s1, 3, 0, 23, -1));
    /* Target is not found and end != -1, return end */
    ovs_assert(20 == bitwise_rscan(s1, 3, 0, 23, 20));

    /* bit 20 - 23 are 0s */
    uint8_t s2[3] = {0x0f, 0xff, 0xff};
    /* Target is in the first byte but not the first bit */
    ovs_assert(19 == bitwise_rscan(s2, 3, 1, 23, -1));
    /* Target exists before the start postion */
    ovs_assert(18 == bitwise_rscan(s2, 3, 1, 18, -1));
    /* Target exists after the end postion, return end */
    ovs_assert(20 == bitwise_rscan(s2, 3, 1, 23, 20));
    /* Target is at the end postion, return end */
    ovs_assert(19 == bitwise_rscan(s2, 3, 1, 23, 19));
    /* start == end, target at start */
    ovs_assert(19 == bitwise_rscan(s2, 3, 1, 19, 19));
    /* start == end, target not at start */
    ovs_assert(20 == bitwise_rscan(s2, 3, 1, 20, 20));
    /* Target is 0 ... */
    ovs_assert(22 == bitwise_rscan(s2, 3, 0, 22, -1));

    /* bit 4 - 23 are 0s */
    uint8_t s3[3] = {0x00, 0x00, 0x0f};
    /* Target is in the end byte */
    ovs_assert(3 == bitwise_rscan(s3, 3, 1, 16, -1));
    /* Target exists after the end byte, return end */
    ovs_assert(15 == bitwise_rscan(s3, 3, 1, 23, 15));
    /* Target exists in end byte but after the end bit, return end */
    ovs_assert(4 == bitwise_rscan(s3, 3, 1, 23, 4));
    /* Target is 0 ... */
    ovs_assert(12 == bitwise_rscan(s3, 3, 0, 12, -1));

    /* All 0s */
    uint8_t s4[3] = {0x00, 0x00, 0x00};
    /* Target not found */
    ovs_assert(-1 == bitwise_rscan(s4, 3, 1, 23, -1));
    /* Target is 0 ..., start is 0 */
    ovs_assert(0 == bitwise_rscan(s4, 3, 0, 0, -1));

    int n_loops;
    for (n_loops = 0; n_loops < 100; n_loops++) {
        ovs_be64 x = htonll(0);
        int i;

        for (i = 0; i < 64; i++) {
            ovs_be64 bit;

            /* Change a random 0-bit into a 1-bit. */
            do {
                bit = htonll(UINT64_C(1) << (random_range(64)));
            } while (x & bit);
            x |= bit;

            for (int end = -1; end <= 63; end++) {
                for (int start = end; start <= 63; start++) {
                    for (int target = 0; target < 2; target++) {
                        bool expect = trivial_bitwise_rscan(
                            &x, sizeof x, target, start, end);
                        bool answer = bitwise_rscan(
                            &x, sizeof x, target, start, end);
                        if (expect != answer) {
                            fprintf(stderr,
                                    "bitwise_rscan(0x%016"PRIx64",8,%s,%d,%d) "
                                    "returned %s instead of %s\n",
                                    ntohll(x),
                                    target ? "true" : "false",
                                    start, end,
                                    answer ? "true" : "false",
                                    expect ? "true" : "false");
                            abort();
                        }
                    }
                }
            }
        }
    }
}

static void
test_follow_symlinks(struct ovs_cmdl_context *ctx)
{
    int i;

    for (i = 1; i < ctx->argc; i++) {
        char *target = follow_symlinks(ctx->argv[i]);
        puts(target);
        free(target);
    }
}

static void
test_assert(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ovs_assert(false);
}

static void
test_ovs_scan(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    char str[16], str2[16], str3[16];
    long double ld, ld2;
    long long ll, ll2;
    signed char c, c2;
    ptrdiff_t pd, pd2;
    intmax_t im, im2;
    size_t sz, sz2;
    int n, n2, n3;
    double d, d2;
    short s, s2;
    float f, f2;
    long l, l2;
    int i, i2;

    ovs_assert(ovs_scan("", " "));
    ovs_assert(ovs_scan(" ", " "));
    ovs_assert(ovs_scan("  ", " "));
    ovs_assert(ovs_scan(" \t ", " "));

    ovs_assert(ovs_scan("xyzzy", "xyzzy"));
    ovs_assert(ovs_scan("xy%zzy", "xy%%zzy"));
    ovs_assert(!ovs_scan(" xy%zzy", "xy%%zzy"));
    ovs_assert(ovs_scan("    xy%\tzzy", " xy%% zzy"));

    ovs_assert(ovs_scan("123", "%d", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("0", "%d", &i));
    ovs_assert(i == 0);
    ovs_assert(!ovs_scan("123", "%d%d", &i, &i2));
    ovs_assert(ovs_scan("+123", "%d", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("-123", "%d", &i));
    ovs_assert(i == -123);
    ovs_assert(ovs_scan("0123", "%d", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan(" 123", "%d", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("0x123", "%d", &i));
    ovs_assert(i == 0);
    ovs_assert(ovs_scan("123", "%2d %d", &i, &i2));
    ovs_assert(i == 12);
    ovs_assert(i2 == 3);
    ovs_assert(ovs_scan("+123", "%2d %d", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("-123", "%2d %d", &i, &i2));
    ovs_assert(i == -1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("0123", "%2d %d", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("123", "%*2d %d", &i));
    ovs_assert(i == 3);
    ovs_assert(ovs_scan("+123", "%2d %*d", &i));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("-123", "%*2d %*d"));

    ovs_assert(ovs_scan("123", "%u", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("0", "%u", &i));
    ovs_assert(i == 0);
    ovs_assert(!ovs_scan("123", "%u%u", &i, &i2));
    ovs_assert(ovs_scan("+123", "%u", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("-123", "%u", &i));
    ovs_assert(i == -123);
    ovs_assert(ovs_scan("0123", "%u", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan(" 123", "%u", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("0x123", "%u", &i));
    ovs_assert(i == 0);
    ovs_assert(ovs_scan("123", "%2u %u", &i, &i2));
    ovs_assert(i == 12);
    ovs_assert(i2 == 3);
    ovs_assert(ovs_scan("+123", "%2u %u", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("-123", "%2u %u", &i, &i2));
    ovs_assert(i == -1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("0123", "%2u %u", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("123", "%*2u %u", &i));
    ovs_assert(i == 3);
    ovs_assert(ovs_scan("+123", "%2u %*u", &i));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("-123", "%*2u %*u"));

    ovs_assert(ovs_scan("123", "%i", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("0", "%i", &i));
    ovs_assert(i == 0);
    ovs_assert(!ovs_scan("123", "%i%i", &i, &i2));
    ovs_assert(ovs_scan("+123", "%i", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("-123", "%i", &i));
    ovs_assert(i == -123);
    ovs_assert(ovs_scan("0123", "%i", &i));
    ovs_assert(i == 0123);
    ovs_assert(ovs_scan(" 123", "%i", &i));
    ovs_assert(i == 123);
    ovs_assert(ovs_scan("0x123", "%i", &i));
    ovs_assert(i == 0x123);
    ovs_assert(ovs_scan("123", "%2i %i", &i, &i2));
    ovs_assert(i == 12);
    ovs_assert(i2 == 3);
    ovs_assert(ovs_scan("+123", "%2i %i", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("-123", "%2i %i", &i, &i2));
    ovs_assert(i == -1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("0123", "%2i %i", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("123", "%*2i %i", &i));
    ovs_assert(i == 3);
    ovs_assert(ovs_scan("+123", "%2i %*i", &i));
    ovs_assert(i == 1);
    ovs_assert(i2 == 23);
    ovs_assert(ovs_scan("-123", "%*2i %*i"));

    ovs_assert(ovs_scan("123", "%o", &i));
    ovs_assert(i == 0123);
    ovs_assert(ovs_scan("0", "%o", &i));
    ovs_assert(i == 0);
    ovs_assert(!ovs_scan("123", "%o%o", &i, &i2));
    ovs_assert(ovs_scan("+123", "%o", &i));
    ovs_assert(i == 0123);
    ovs_assert(ovs_scan("-123", "%o", &i));
    ovs_assert(i == -0123);
    ovs_assert(ovs_scan("0123", "%o", &i));
    ovs_assert(i == 0123);
    ovs_assert(ovs_scan(" 123", "%o", &i));
    ovs_assert(i == 0123);
    ovs_assert(ovs_scan("0x123", "%o", &i));
    ovs_assert(i == 0);
    ovs_assert(ovs_scan("123", "%2o %o", &i, &i2));
    ovs_assert(i == 012);
    ovs_assert(i2 == 3);
    ovs_assert(ovs_scan("+123", "%2o %o", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 023);
    ovs_assert(ovs_scan("-123", "%2o %o", &i, &i2));
    ovs_assert(i == -1);
    ovs_assert(i2 == 023);
    ovs_assert(ovs_scan("0123", "%2o %o", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 023);
    ovs_assert(ovs_scan("123", "%*2o %o", &i));
    ovs_assert(i == 3);
    ovs_assert(ovs_scan("+123", "%2o %*o", &i));
    ovs_assert(i == 1);
    ovs_assert(i2 == 023);
    ovs_assert(ovs_scan("-123", "%*2o %*o"));

    ovs_assert(ovs_scan("123", "%x", &i));
    ovs_assert(i == 0x123);
    ovs_assert(ovs_scan("0", "%x", &i));
    ovs_assert(i == 0);
    ovs_assert(!ovs_scan("123", "%x%x", &i, &i2));
    ovs_assert(ovs_scan("+123", "%x", &i));
    ovs_assert(i == 0x123);
    ovs_assert(ovs_scan("-123", "%x", &i));
    ovs_assert(i == -0x123);
    ovs_assert(ovs_scan("0123", "%x", &i));
    ovs_assert(i == 0x123);
    ovs_assert(ovs_scan(" 123", "%x", &i));
    ovs_assert(i == 0x123);
    ovs_assert(ovs_scan("0x123", "%x", &i));
    ovs_assert(i == 0x123);
    ovs_assert(ovs_scan("123", "%2x %x", &i, &i2));
    ovs_assert(i == 0x12);
    ovs_assert(i2 == 3);
    ovs_assert(ovs_scan("+123", "%2x %x", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 0x23);
    ovs_assert(ovs_scan("-123", "%2x %x", &i, &i2));
    ovs_assert(i == -1);
    ovs_assert(i2 == 0x23);
    ovs_assert(ovs_scan("0123", "%2x %x", &i, &i2));
    ovs_assert(i == 1);
    ovs_assert(i2 == 0x23);
    ovs_assert(ovs_scan("123", "%*2x %x", &i));
    ovs_assert(i == 3);
    ovs_assert(ovs_scan("+123", "%2x %*x", &i));
    ovs_assert(i == 1);
    ovs_assert(i2 == 0x23);
    ovs_assert(ovs_scan("-123", "%*2x %*x"));

    ovs_assert(ovs_scan("123", "%hd", &s));
    ovs_assert(s == 123);
    ovs_assert(!ovs_scan("123", "%hd%hd", &s, &s2));
    ovs_assert(ovs_scan("+123", "%hd", &s));
    ovs_assert(s == 123);
    ovs_assert(ovs_scan("-123", "%hd", &s));
    ovs_assert(s == -123);
    ovs_assert(ovs_scan("0123", "%hd", &s));
    ovs_assert(s == 123);
    ovs_assert(ovs_scan(" 123", "%hd", &s));
    ovs_assert(s == 123);
    ovs_assert(ovs_scan("0x123", "%hd", &s));
    ovs_assert(s == 0);
    ovs_assert(ovs_scan("123", "%2hd %hd", &s, &s2));
    ovs_assert(s == 12);
    ovs_assert(s2 == 3);
    ovs_assert(ovs_scan("+123", "%2hd %hd", &s, &s2));
    ovs_assert(s == 1);
    ovs_assert(s2 == 23);
    ovs_assert(ovs_scan("-123", "%2hd %hd", &s, &s2));
    ovs_assert(s == -1);
    ovs_assert(s2 == 23);
    ovs_assert(ovs_scan("0123", "%2hd %hd", &s, &s2));
    ovs_assert(s == 1);
    ovs_assert(s2 == 23);

    ovs_assert(ovs_scan("123", "%hhd", &c));
    ovs_assert(c == 123);
    ovs_assert(ovs_scan("0", "%hhd", &c));
    ovs_assert(c == 0);
    ovs_assert(!ovs_scan("123", "%hhd%hhd", &c, &c2));
    ovs_assert(ovs_scan("+123", "%hhd", &c));
    ovs_assert(c == 123);
    ovs_assert(ovs_scan("-123", "%hhd", &c));
    ovs_assert(c == -123);
    ovs_assert(ovs_scan("0123", "%hhd", &c));
    ovs_assert(c == 123);
    ovs_assert(ovs_scan(" 123", "%hhd", &c));
    ovs_assert(c == 123);
    ovs_assert(ovs_scan("0x123", "%hhd", &c));
    ovs_assert(c == 0);
    ovs_assert(ovs_scan("123", "%2hhd %hhd", &c, &c2));
    ovs_assert(c == 12);
    ovs_assert(c2 == 3);
    ovs_assert(ovs_scan("+123", "%2hhd %hhd", &c, &c2));
    ovs_assert(c == 1);
    ovs_assert(c2 == 23);
    ovs_assert(ovs_scan("-123", "%2hhd %hhd", &c, &c2));
    ovs_assert(c == -1);
    ovs_assert(c2 == 23);
    ovs_assert(ovs_scan("0123", "%2hhd %hhd", &c, &c2));
    ovs_assert(c == 1);
    ovs_assert(c2 == 23);

    ovs_assert(ovs_scan("123", "%ld", &l));
    ovs_assert(l == 123);
    ovs_assert(ovs_scan("0", "%ld", &l));
    ovs_assert(l == 0);
    ovs_assert(!ovs_scan("123", "%ld%ld", &l, &l2));
    ovs_assert(ovs_scan("+123", "%ld", &l));
    ovs_assert(l == 123);
    ovs_assert(ovs_scan("-123", "%ld", &l));
    ovs_assert(l == -123);
    ovs_assert(ovs_scan("0123", "%ld", &l));
    ovs_assert(l == 123);
    ovs_assert(ovs_scan(" 123", "%ld", &l));
    ovs_assert(l == 123);
    ovs_assert(ovs_scan("0x123", "%ld", &l));
    ovs_assert(l == 0);
    ovs_assert(ovs_scan("123", "%2ld %ld", &l, &l2));
    ovs_assert(l == 12);
    ovs_assert(l2 == 3);
    ovs_assert(ovs_scan("+123", "%2ld %ld", &l, &l2));
    ovs_assert(l == 1);
    ovs_assert(l2 == 23);
    ovs_assert(ovs_scan("-123", "%2ld %ld", &l, &l2));
    ovs_assert(l == -1);
    ovs_assert(l2 == 23);
    ovs_assert(ovs_scan("0123", "%2ld %ld", &l, &l2));
    ovs_assert(l == 1);
    ovs_assert(l2 == 23);

    ovs_assert(ovs_scan("123", "%lld", &ll));
    ovs_assert(ll == 123);
    ovs_assert(ovs_scan("0", "%lld", &ll));
    ovs_assert(ll == 0);
    ovs_assert(!ovs_scan("123", "%lld%lld", &ll, &ll2));
    ovs_assert(ovs_scan("+123", "%lld", &ll));
    ovs_assert(ll == 123);
    ovs_assert(ovs_scan("-123", "%lld", &ll));
    ovs_assert(ll == -123);
    ovs_assert(ovs_scan("0123", "%lld", &ll));
    ovs_assert(ll == 123);
    ovs_assert(ovs_scan(" 123", "%lld", &ll));
    ovs_assert(ll == 123);
    ovs_assert(ovs_scan("0x123", "%lld", &ll));
    ovs_assert(ll == 0);
    ovs_assert(ovs_scan("123", "%2lld %lld", &ll, &ll2));
    ovs_assert(ll == 12);
    ovs_assert(ll2 == 3);
    ovs_assert(ovs_scan("+123", "%2lld %lld", &ll, &ll2));
    ovs_assert(ll == 1);
    ovs_assert(ll2 == 23);
    ovs_assert(ovs_scan("-123", "%2lld %lld", &ll, &ll2));
    ovs_assert(ll == -1);
    ovs_assert(ll2 == 23);
    ovs_assert(ovs_scan("0123", "%2lld %lld", &ll, &ll2));
    ovs_assert(ll == 1);
    ovs_assert(ll2 == 23);

    ovs_assert(ovs_scan("123", "%jd", &im));
    ovs_assert(im == 123);
    ovs_assert(ovs_scan("0", "%jd", &im));
    ovs_assert(im == 0);
    ovs_assert(!ovs_scan("123", "%jd%jd", &im, &im2));
    ovs_assert(ovs_scan("+123", "%jd", &im));
    ovs_assert(im == 123);
    ovs_assert(ovs_scan("-123", "%jd", &im));
    ovs_assert(im == -123);
    ovs_assert(ovs_scan("0123", "%jd", &im));
    ovs_assert(im == 123);
    ovs_assert(ovs_scan(" 123", "%jd", &im));
    ovs_assert(im == 123);
    ovs_assert(ovs_scan("0x123", "%jd", &im));
    ovs_assert(im == 0);
    ovs_assert(ovs_scan("123", "%2jd %jd", &im, &im2));
    ovs_assert(im == 12);
    ovs_assert(im2 == 3);
    ovs_assert(ovs_scan("+123", "%2jd %jd", &im, &im2));
    ovs_assert(im == 1);
    ovs_assert(im2 == 23);
    ovs_assert(ovs_scan("-123", "%2jd %jd", &im, &im2));
    ovs_assert(im == -1);
    ovs_assert(im2 == 23);
    ovs_assert(ovs_scan("0123", "%2jd %jd", &im, &im2));
    ovs_assert(im == 1);
    ovs_assert(im2 == 23);

    ovs_assert(ovs_scan("123", "%td", &pd));
    ovs_assert(pd == 123);
    ovs_assert(ovs_scan("0", "%td", &pd));
    ovs_assert(pd == 0);
    ovs_assert(!ovs_scan("123", "%td%td", &pd, &pd2));
    ovs_assert(ovs_scan("+123", "%td", &pd));
    ovs_assert(pd == 123);
    ovs_assert(ovs_scan("-123", "%td", &pd));
    ovs_assert(pd == -123);
    ovs_assert(ovs_scan("0123", "%td", &pd));
    ovs_assert(pd == 123);
    ovs_assert(ovs_scan(" 123", "%td", &pd));
    ovs_assert(pd == 123);
    ovs_assert(ovs_scan("0x123", "%td", &pd));
    ovs_assert(pd == 0);
    ovs_assert(ovs_scan("123", "%2td %td", &pd, &pd2));
    ovs_assert(pd == 12);
    ovs_assert(pd2 == 3);
    ovs_assert(ovs_scan("+123", "%2td %td", &pd, &pd2));
    ovs_assert(pd == 1);
    ovs_assert(pd2 == 23);
    ovs_assert(ovs_scan("-123", "%2td %td", &pd, &pd2));
    ovs_assert(pd == -1);
    ovs_assert(pd2 == 23);
    ovs_assert(ovs_scan("0123", "%2td %td", &pd, &pd2));
    ovs_assert(pd == 1);
    ovs_assert(pd2 == 23);

    ovs_assert(ovs_scan("123", "%zd", &sz));
    ovs_assert(sz == 123);
    ovs_assert(ovs_scan("0", "%zd", &sz));
    ovs_assert(sz == 0);
    ovs_assert(!ovs_scan("123", "%zd%zd", &sz, &sz2));
    ovs_assert(ovs_scan("+123", "%zd", &sz));
    ovs_assert(sz == 123);
    ovs_assert(ovs_scan("-123", "%zd", &sz));
    ovs_assert(sz == -123);
    ovs_assert(ovs_scan("0123", "%zd", &sz));
    ovs_assert(sz == 123);
    ovs_assert(ovs_scan(" 123", "%zd", &sz));
    ovs_assert(sz == 123);
    ovs_assert(ovs_scan("0x123", "%zd", &sz));
    ovs_assert(sz == 0);
    ovs_assert(ovs_scan("123", "%2zd %zd", &sz, &sz2));
    ovs_assert(sz == 12);
    ovs_assert(sz2 == 3);
    ovs_assert(ovs_scan("+123", "%2zd %zd", &sz, &sz2));
    ovs_assert(sz == 1);
    ovs_assert(sz2 == 23);
    ovs_assert(ovs_scan("-123", "%2zd %zd", &sz, &sz2));
    ovs_assert(sz == -1);
    ovs_assert(sz2 == 23);
    ovs_assert(ovs_scan("0123", "%2zd %zd", &sz, &sz2));
    ovs_assert(sz == 1);
    ovs_assert(sz2 == 23);

    ovs_assert(ovs_scan("0.25", "%f", &f));
    ovs_assert(f == 0.25);
    ovs_assert(ovs_scan("1.0", "%f", &f));
    ovs_assert(f == 1.0);
    ovs_assert(ovs_scan("-5", "%f", &f));
    ovs_assert(f == -5.0);
    ovs_assert(ovs_scan("+6", "%f", &f));
    ovs_assert(f == 6.0);
    ovs_assert(ovs_scan("-1e5", "%f", &f));
    ovs_assert(f == -1e5);
    ovs_assert(ovs_scan("-.25", "%f", &f));
    ovs_assert(f == -.25);
    ovs_assert(ovs_scan("+123.e1", "%f", &f));
    ovs_assert(f == 1230.0);
    ovs_assert(ovs_scan("25e-2", "%f", &f));
    ovs_assert(f == 0.25);
    ovs_assert(ovs_scan("0.25", "%1f %f", &f, &f2));
    ovs_assert(f == 0);
    ovs_assert(f2 == 0.25);
    ovs_assert(ovs_scan("1.0", "%2f %f", &f, &f2));
    ovs_assert(f == 1.0);
    ovs_assert(f2 == 0.0);
    ovs_assert(!ovs_scan("-5", "%1f", &f));
    ovs_assert(!ovs_scan("+6", "%1f", &f));
    ovs_assert(!ovs_scan("-1e5", "%2f %*f", &f));
    ovs_assert(f == -1);
    ovs_assert(!ovs_scan("-.25", "%2f", &f));
    ovs_assert(!ovs_scan("+123.e1", "%6f", &f));
    ovs_assert(!ovs_scan("25e-2", "%4f", &f));

    ovs_assert(ovs_scan("0.25", "%lf", &d));
    ovs_assert(d == 0.25);
    ovs_assert(ovs_scan("1.0", "%lf", &d));
    ovs_assert(d == 1.0);
    ovs_assert(ovs_scan("-5", "%lf", &d));
    ovs_assert(d == -5.0);
    ovs_assert(ovs_scan("+6", "%lf", &d));
    ovs_assert(d == 6.0);
    ovs_assert(ovs_scan("-1e5", "%lf", &d));
    ovs_assert(d == -1e5);
    ovs_assert(ovs_scan("-.25", "%lf", &d));
    ovs_assert(d == -.25);
    ovs_assert(ovs_scan("+123.e1", "%lf", &d));
    ovs_assert(d == 1230.0);
    ovs_assert(ovs_scan("25e-2", "%lf", &d));
    ovs_assert(d == 0.25);
    ovs_assert(ovs_scan("0.25", "%1lf %lf", &d, &d2));
    ovs_assert(d == 0);
    ovs_assert(d2 == 0.25);
    ovs_assert(ovs_scan("1.0", "%2lf %lf", &d, &d2));
    ovs_assert(d == 1.0);
    ovs_assert(d2 == 0.0);
    ovs_assert(!ovs_scan("-5", "%1lf", &d));
    ovs_assert(!ovs_scan("+6", "%1lf", &d));
    ovs_assert(!ovs_scan("-1e5", "%2lf %*f", &d));
    ovs_assert(d == -1);
    ovs_assert(!ovs_scan("-.25", "%2lf", &d));
    ovs_assert(!ovs_scan("+123.e1", "%6lf", &d));
    ovs_assert(!ovs_scan("25e-2", "%4lf", &d));

    ovs_assert(ovs_scan("0.25", "%Lf", &ld));
    ovs_assert(ld == 0.25);
    ovs_assert(ovs_scan("1.0", "%Lf", &ld));
    ovs_assert(ld == 1.0);
    ovs_assert(ovs_scan("-5", "%Lf", &ld));
    ovs_assert(ld == -5.0);
    ovs_assert(ovs_scan("+6", "%Lf", &ld));
    ovs_assert(ld == 6.0);
    ovs_assert(ovs_scan("-1e5", "%Lf", &ld));
    ovs_assert(ld == -1e5);
    ovs_assert(ovs_scan("-.25", "%Lf", &ld));
    ovs_assert(ld == -.25);
    ovs_assert(ovs_scan("+123.e1", "%Lf", &ld));
    ovs_assert(ld == 1230.0);
    ovs_assert(ovs_scan("25e-2", "%Lf", &ld));
    ovs_assert(ld == 0.25);
    ovs_assert(ovs_scan("0.25", "%1Lf %Lf", &ld, &ld2));
    ovs_assert(ld == 0);
    ovs_assert(ld2 == 0.25);
    ovs_assert(ovs_scan("1.0", "%2Lf %Lf", &ld, &ld2));
    ovs_assert(ld == 1.0);
    ovs_assert(ld2 == 0.0);
    ovs_assert(!ovs_scan("-5", "%1Lf", &ld));
    ovs_assert(!ovs_scan("+6", "%1Lf", &ld));
    ovs_assert(!ovs_scan("-1e5", "%2Lf %*f", &ld));
    ovs_assert(ld == -1);
    ovs_assert(!ovs_scan("-.25", "%2Lf", &ld));
    ovs_assert(!ovs_scan("+123.e1", "%6Lf", &ld));
    ovs_assert(!ovs_scan("25e-2", "%4Lf", &ld));

    ovs_assert(ovs_scan(" Hello,\tworld ", "%*s%n%*s%n", &n, &n2));
    ovs_assert(n == 7);
    ovs_assert(n2 == 13);
    ovs_assert(!ovs_scan(" Hello,\tworld ", "%*s%*s%*s"));
    ovs_assert(ovs_scan(" Hello,\tworld ", "%6s%n%5s%n", str, &n, str2, &n2));
    ovs_assert(!strcmp(str, "Hello,"));
    ovs_assert(n == 7);
    ovs_assert(!strcmp(str2, "world"));
    ovs_assert(n2 == 13);
    ovs_assert(ovs_scan(" Hello,\tworld ", "%5s%5s%5s", str, str2, str3));
    ovs_assert(!strcmp(str, "Hello"));
    ovs_assert(!strcmp(str2, ","));
    ovs_assert(!strcmp(str3, "world"));
    ovs_assert(!ovs_scan(" ", "%*s"));

    ovs_assert(ovs_scan(" Hello,\tworld ", "%*c%n%*c%n%c%n",
                        &n, &n2, &c, &n3));
    ovs_assert(n == 1);
    ovs_assert(n2 == 2);
    ovs_assert(c == 'e');
    ovs_assert(n3 == 3);
    ovs_assert(ovs_scan(" Hello,\tworld ", "%*5c%5c", str));
    ovs_assert(!memcmp(str, "o,\two", 5));
    ovs_assert(!ovs_scan(" Hello,\tworld ", "%*15c"));

    ovs_assert(ovs_scan("0x1234xyzzy", "%9[x0-9a-fA-F]%n", str, &n));
    ovs_assert(!strcmp(str, "0x1234x"));
    ovs_assert(n == 7);
    ovs_assert(ovs_scan("foo:bar=baz", "%5[^:=]%n:%5[^:=]%n=%5[^:=]%n",
                        str, &n, str2, &n2, str3, &n3));
    ovs_assert(!strcmp(str, "foo"));
    ovs_assert(n == 3);
    ovs_assert(!strcmp(str2, "bar"));
    ovs_assert(n2 == 7);
    ovs_assert(!strcmp(str3, "baz"));
    ovs_assert(n3 == 11);
    ovs_assert(!ovs_scan(" ", "%*[0-9]"));
    ovs_assert(ovs_scan("0x123a]4xyzzy-", "%[]x0-9a-fA-F]", str));
    ovs_assert(!strcmp(str, "0x123a]4x"));
    ovs_assert(ovs_scan("abc]xyz","%[^]xyz]", str));
    ovs_assert(!strcmp(str, "abc"));
    ovs_assert(!ovs_scan("0x123a]4xyzzy-", "%[x0-9]a-fA-F]", str));
    ovs_assert(ovs_scan("0x12-3]xyz", "%[x0-9a-f-]", str));
    ovs_assert(!strcmp(str, "0x12-3"));
    ovs_assert(ovs_scan("0x12-3]xyz", "%[^a-f-]", str));
    ovs_assert(!strcmp(str, "0x12"));
    ovs_assert(sscanf("0x12-3]xyz", "%[^-a-f]", str));
    ovs_assert(!strcmp(str, "0x12"));
}

static void
test_snprintf(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    char s[16];

#if __GNUC__ >= 7
    /* GCC 7+ warns about the following calls that truncate a string using
     * snprintf().  We're testing that truncation works properly, so
     * temporarily disable the warning. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
    ovs_assert(snprintf(s, 4, "abcde") == 5);
    ovs_assert(!strcmp(s, "abc"));

    ovs_assert(snprintf(s, 5, "abcde") == 5);
    ovs_assert(!strcmp(s, "abcd"));
#if __GNUC__ >= 7
#pragma GCC diagnostic pop
#endif

    ovs_assert(snprintf(s, 6, "abcde") == 5);
    ovs_assert(!strcmp(s, "abcde"));

    ovs_assert(snprintf(NULL, 0, "abcde") == 5);
}

static void
check_sat(long long int x, long long int y, const char *op,
          long long int r_a, long long int r_b)
{
    if (r_a != r_b) {
        fprintf(stderr, "%lld %s %lld saturates differently: %lld vs %lld\n",
                x, op, y, r_a, r_b);
        abort();
    }
}

static void
test_sat_math(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    long long int values[] = {
        LLONG_MIN, LLONG_MIN + 1, LLONG_MIN + 2, LLONG_MIN + 3,
        LLONG_MIN + 4, LLONG_MIN + 5, LLONG_MIN + 6, LLONG_MIN + 7,
        LLONG_MIN / 2, LLONG_MIN / 3, LLONG_MIN / 4, LLONG_MIN / 5,
        -1000, -50, -10, -9, -8, -7, -6, -5, -4, -3, -2, -1, 0,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 50, 1000,
        LLONG_MAX / 5, LLONG_MAX / 4, LLONG_MAX / 3, LLONG_MAX / 2,
        LLONG_MAX - 7, LLONG_MAX - 6, LLONG_MAX - 5, LLONG_MAX - 4,
        LLONG_MAX - 3, LLONG_MAX - 2, LLONG_MAX - 1, LLONG_MAX,
    };

    /* Compare the behavior of our local implementation of these functions
     * against the compiler implementation or its fallback.  (If the fallback
     * is in use then this is comparing the fallback to itself, so this test is
     * only really useful if the compiler has an implementation.) */
    for (long long int *x = values; x < values + ARRAY_SIZE(values); x++) {
        for (long long int *y = values; y < values + ARRAY_SIZE(values); y++) {
            check_sat(*x, *y, "+", llsat_add(*x, *y), llsat_add__(*x, *y));
            check_sat(*x, *y, "-", llsat_sub(*x, *y), llsat_sub__(*x, *y));
            check_sat(*x, *y, "*", llsat_mul(*x, *y), llsat_mul__(*x, *y));
        }
    }
}

#ifndef _WIN32
static void
test_file_name(struct ovs_cmdl_context *ctx)
{
    int i;

    for (i = 1; i < ctx->argc; i++) {
        char *dir, *base;

        dir = dir_name(ctx->argv[i]);
        puts(dir);
        free(dir);

        base = base_name(ctx->argv[i]);
        puts(base);
        free(base);
    }
}
#endif /* _WIN32 */

static const struct ovs_cmdl_command commands[] = {
    {"ctz", NULL, 0, 0, test_ctz, OVS_RO},
    {"clz", NULL, 0, 0, test_clz, OVS_RO},
    {"round_up_pow2", NULL, 0, 0, test_round_up_pow2, OVS_RO},
    {"round_down_pow2", NULL, 0, 0, test_round_down_pow2, OVS_RO},
    {"count_1bits", NULL, 0, 0, test_count_1bits, OVS_RO},
    {"log_2_floor", NULL, 0, 0, test_log_2_floor, OVS_RO},
    {"bitwise_copy", NULL, 0, 0, test_bitwise_copy, OVS_RO},
    {"bitwise_zero", NULL, 0, 0, test_bitwise_zero, OVS_RO},
    {"bitwise_one", NULL, 0, 0, test_bitwise_one, OVS_RO},
    {"bitwise_is_all_zeros", NULL, 0, 0, test_bitwise_is_all_zeros, OVS_RO},
    {"bitwise_rscan", NULL, 0, 0, test_bitwise_rscan, OVS_RO},
    {"follow-symlinks", NULL, 1, INT_MAX, test_follow_symlinks, OVS_RO},
    {"assert", NULL, 0, 0, test_assert, OVS_RO},
    {"ovs_scan", NULL, 0, 0, test_ovs_scan, OVS_RO},
    {"snprintf", NULL, 0, 0, test_snprintf, OVS_RO},
    {"sat_math", NULL, 0, 0, test_sat_math, OVS_RO},
#ifndef _WIN32
    {"file_name", NULL, 1, INT_MAX, test_file_name, OVS_RO},
#endif
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
parse_options(int argc, char *argv[])
{
    enum {
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
test_util_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = { .argc = 0, };
    set_program_name(argv[0]);
    parse_options(argc, argv);
    /* On Windows, stderr is fully buffered if connected to a pipe.
     * Make it _IONBF so that an abort does not miss log contents.
     * POSIX doesn't define the circumstances in which stderr is
     * fully buffered either. */
    setvbuf(stderr, NULL, _IONBF, 0);
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-util", test_util_main);
