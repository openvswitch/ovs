/*
 * Copyright (c) 2014 Kmindg <kmindg@gmail.com>
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
#include "bitmap.h"
#include <assert.h>
#include "command-line.h"
#include "ovstest.h"
#include "timeval.h"

enum { MAX_BITS = 20 * BITMAP_ULONG_BITS };

static int
elapsed(const struct timeval *start)
{
    struct timeval end;

    xgettimeofday(&end);
    return timeval_to_msec(&end) - timeval_to_msec(start);
}

/* Tests bitmap_equal. */
static void
test_bitmap_equal(void)
{
    unsigned long *a, *b;

    a = bitmap_allocate(MAX_BITS);
    b = bitmap_allocate(MAX_BITS);

    /* equal test */
    assert(bitmap_equal(a, b, MAX_BITS));
    assert(bitmap_equal(a, b, MAX_BITS - 1));
    assert(bitmap_equal(a, b, MAX_BITS - (BITMAP_ULONG_BITS - 1)));

    bitmap_set_multiple(a, 10 * BITMAP_ULONG_BITS, BITMAP_ULONG_BITS, true);
    assert(bitmap_equal(a, b, 10 * BITMAP_ULONG_BITS));

    /* non-equal test */
    assert(!bitmap_equal(a, b, 11 * BITMAP_ULONG_BITS));
    assert(!bitmap_equal(a, b, 11 * BITMAP_ULONG_BITS - 1));
    assert(!bitmap_equal(a, b,
                         11 * BITMAP_ULONG_BITS - (BITMAP_ULONG_BITS - 1)));

    free(b);
    free(a);
}

/* Tests bitmap_scan. */
static void
test_bitmap_scan(void)
{
    unsigned long *a;

    a = bitmap_allocate(MAX_BITS);

    /* scan for 1 */
    assert(bitmap_scan(a, true, 1, BITMAP_ULONG_BITS) == BITMAP_ULONG_BITS);
    assert(bitmap_scan(a, true, BITMAP_ULONG_BITS - 1, BITMAP_ULONG_BITS)
           == BITMAP_ULONG_BITS);
    assert(bitmap_scan(a, true, 0, BITMAP_ULONG_BITS) == BITMAP_ULONG_BITS);
    assert(bitmap_scan(a, true, 0, BITMAP_ULONG_BITS + 1)
           == BITMAP_ULONG_BITS + 1);
    assert(bitmap_scan(a, true, 0, 2 * BITMAP_ULONG_BITS - 1)
           == 2 * BITMAP_ULONG_BITS - 1);

    bitmap_set1(a, MAX_BITS - 1);
    assert(bitmap_scan(a, true, 0, MAX_BITS) == MAX_BITS - 1);
    bitmap_set1(a, MAX_BITS - BITMAP_ULONG_BITS + 1);
    assert(bitmap_scan(a, true, 3, MAX_BITS)
           == MAX_BITS - BITMAP_ULONG_BITS + 1);
    bitmap_set1(a, BITMAP_ULONG_BITS - 1);
    assert(bitmap_scan(a, true, 7, MAX_BITS - 1) == BITMAP_ULONG_BITS - 1);
    bitmap_set1(a, 0);
    assert(bitmap_scan(a, true, 0, MAX_BITS - 7) == 0);

    bitmap_set_multiple(a, 0, MAX_BITS, true);

    /* scan for 0 */
    assert(bitmap_scan(a, false, 1, BITMAP_ULONG_BITS) == BITMAP_ULONG_BITS);
    assert(bitmap_scan(a, false, BITMAP_ULONG_BITS - 1, BITMAP_ULONG_BITS)
           == BITMAP_ULONG_BITS);
    assert(bitmap_scan(a, false, 0, BITMAP_ULONG_BITS) == BITMAP_ULONG_BITS);
    assert(bitmap_scan(a, false, 0, BITMAP_ULONG_BITS + 1)
           == BITMAP_ULONG_BITS + 1);
    assert(bitmap_scan(a, false, 0, 2 * BITMAP_ULONG_BITS - 1)
           == 2 * BITMAP_ULONG_BITS - 1);

    bitmap_set0(a, MAX_BITS - 1);
    assert(bitmap_scan(a, false, 0, MAX_BITS) == MAX_BITS - 1);
    bitmap_set0(a, MAX_BITS - BITMAP_ULONG_BITS + 1);
    assert(bitmap_scan(a, false, 3, MAX_BITS)
           == MAX_BITS - BITMAP_ULONG_BITS + 1);
    bitmap_set0(a, BITMAP_ULONG_BITS - 1);
    assert(bitmap_scan(a, false, 7, MAX_BITS - 1) == BITMAP_ULONG_BITS - 1);
    bitmap_set0(a, 0);
    assert(bitmap_scan(a, false, 0, MAX_BITS - 7) == 0);

    free(a);
}

static void
run_test(void (*function)(void))
{
    function();
    printf(".");
}

static void
run_tests(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    run_test(test_bitmap_equal);
    run_test(test_bitmap_scan);
    printf("\n");
}

static void
run_benchmarks(struct ovs_cmdl_context *ctx)
{
    int n_iter = strtol(ctx->argv[1], NULL, 10);
    struct timeval start;

    xgettimeofday(&start);
    for (int i = 0; i < n_iter; i++) {
        test_bitmap_equal();
    }
    printf("bitmap equal:  %5d ms\n", elapsed(&start));

    xgettimeofday(&start);
    for (int i = 0; i < n_iter; i++) {
        test_bitmap_scan();
    }
    printf("bitmap scan:  %5d ms\n", elapsed(&start));
    printf("\n");
}

static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 0, run_tests, OVS_RO},
    {"benchmark", NULL, 1, 1, run_benchmarks, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
test_bitmap_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - 1,
        .argv = argv + 1,
    };

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-bitmap", test_bitmap_main);
