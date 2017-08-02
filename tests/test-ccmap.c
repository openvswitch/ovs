/*
 * Copyright (c) 2008, 2009, 2010, 2013, 2014, 2016 Nicira, Inc.
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

/* A non-exhaustive test for some of the functions and macros declared in
 * ccmap.h. */

#include <config.h>
#undef NDEBUG
#include "ccmap.h"
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include "bitmap.h"
#include "command-line.h"
#include "fat-rwlock.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "ovstest.h"
#include "ovs-thread.h"
#include "random.h"
#include "timeval.h"
#include "util.h"

typedef size_t hash_func(int value);

static int
compare_uint32s(const void *a_, const void *b_)
{
    const uint32_t *a = a_;
    const uint32_t *b = b_;
    return *a < *b ? -1 : *a > *b;
}

/* Verifies that 'ccmap' contains exactly the 'n' values in 'values'. */
static void
check_ccmap(struct ccmap *ccmap, const int values[], size_t n, hash_func *hash)
{
    uint32_t *hashes = xmalloc(sizeof *hashes * n);
    int i;

    for (i = 0; i < n; i++) {
        hashes[i] = hash(values[i]);
    }
    qsort(hashes, n, sizeof *hashes, compare_uint32s);

    /* Check that all the values are there in lookup. */
    for (i = 0; i < n; i++) {
        uint32_t h = hashes[i];
        size_t count = ccmap_find(ccmap, h);

        assert(count);   /* Must have at least one. */
        assert(i + count <= n); /* May not have too many. */

        /* Skip colliding hash values and assert they were in the count. */
        while (--count) {
            i++;
            assert(hashes[i] == h);
        }
        /* Make sure next hash is different. */
        if (i + 1 < n) {
            assert(hashes[i + 1] != h);
        }
    }

    /* Check counters. */
    assert(ccmap_is_empty(ccmap) == !n);
    assert(ccmap_count(ccmap) == n);

    free(hashes);
}

static void
shuffle(int *p, size_t n)
{
    for (; n > 1; n--, p++) {
        int *q = &p[random_range(n)];
        int tmp = *p;

        *p = *q;
        *q = tmp;
    }
}

static size_t
identity_hash(int value)
{
    return value;
}

static size_t
good_hash(int value)
{
    return hash_int(value, 0x1234abcd);
}

static size_t
constant_hash(int value OVS_UNUSED)
{
    return 123;
}

/* Tests basic ccmap increment and decrement. */
static void
test_ccmap_inc_dec(hash_func *hash)
{
    enum { N_ELEMS = 1000 };

    int values[N_ELEMS];
    struct ccmap ccmap;
    size_t i;

    ccmap_init(&ccmap);
    for (i = 0; i < N_ELEMS; i++) {
        ccmap_inc(&ccmap, hash(i));
        values[i] = i;
        check_ccmap(&ccmap, values, i + 1, hash);
    }
    shuffle(values, N_ELEMS);
    for (i = 0; i < N_ELEMS; i++) {
        ccmap_dec(&ccmap, hash(values[i]));
        check_ccmap(&ccmap, values + (i + 1), N_ELEMS - (i + 1), hash);
    }
    ccmap_destroy(&ccmap);
}

static void
run_test(void (*function)(hash_func *))
{
    hash_func *hash_funcs[] = { identity_hash, good_hash, constant_hash };

    for (size_t i = 0; i < ARRAY_SIZE(hash_funcs); i++) {
        function(hash_funcs[i]);
        printf(".");
        fflush(stdout);
    }
}

static void
run_tests(struct ovs_cmdl_context *ctx)
{
    int n = ctx->argc >= 2 ? atoi(ctx->argv[1]) : 100;
    for (int i = 0; i < n; i++) {
        run_test(test_ccmap_inc_dec);
    }
    printf("\n");
}

static int n_elems;             /* Number of elements to insert. */
static int n_threads;           /* Number of threads to search and mutate. */
static uint32_t mutation_frac;  /* % mutations, as fraction of UINT32_MAX. */


static void benchmark_ccmap(void);

static int
elapsed(const struct timeval *start)
{
    struct timeval end;

    xgettimeofday(&end);
    return timeval_to_msec(&end) - timeval_to_msec(start);
}

static void
run_benchmarks(struct ovs_cmdl_context *ctx)
{
    n_elems = strtol(ctx->argv[1], NULL, 10);
    n_threads = strtol(ctx->argv[2], NULL, 10);
    mutation_frac = strtod(ctx->argv[3], NULL) / 100.0 * UINT32_MAX;

    printf("Benchmarking with n=%d, %d threads, %.2f%% mutations\n",
           n_elems, n_threads, (double) mutation_frac / UINT32_MAX * 100.);

    benchmark_ccmap();
}

/* ccmap benchmark. */

struct ccmap_aux {
    struct ovs_mutex mutex;
    struct ccmap *ccmap;
};

static void *
search_ccmap(void *aux_)
{
    struct ccmap_aux *aux = aux_;
    size_t i;

    if (mutation_frac) {
        for (i = 0; i < n_elems; i++) {
            uint32_t hash = hash_int(i, 0);

            if (random_uint32() < mutation_frac) {
                ovs_mutex_lock(&aux->mutex);
                uint32_t count = ccmap_find(aux->ccmap, hash);
                if (count) {
                    ccmap_dec(aux->ccmap, hash);
                }
                ovs_mutex_unlock(&aux->mutex);
            } else {
                ignore(ccmap_find(aux->ccmap, hash));
            }
        }
    } else {
        for (i = 0; i < n_elems; i++) {
            ignore(ccmap_find(aux->ccmap, hash_int(i, 0)));
        }
    }
    return NULL;
}

static void
benchmark_ccmap(void)
{
    struct ccmap ccmap;
    struct timeval start;
    pthread_t *threads;
    struct ccmap_aux aux;
    size_t i;

    /* Insertions. */
    xgettimeofday(&start);
    ccmap_init(&ccmap);
    for (i = 0; i < n_elems; i++) {
        ccmap_inc(&ccmap, hash_int(i, 0));
    }
    printf("ccmap insert:  %5d ms\n", elapsed(&start));

    /* Search and mutation. */
    xgettimeofday(&start);
    aux.ccmap = &ccmap;
    ovs_mutex_init(&aux.mutex);
    threads = xmalloc(n_threads * sizeof *threads);
    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("search", search_ccmap, &aux);
    }
    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }
    free(threads);
    printf("ccmap search:  %5d ms\n", elapsed(&start));

    /* Destruction. */
    xgettimeofday(&start);
    for (i = 0; i < n_elems; i++) {
        uint32_t hash = hash_int(i, 0);

        if (ccmap_find(&ccmap, hash)) {
            /* Also remove any colliding hashes. */
            while (ccmap_dec(&ccmap, hash)) {
                ;
            }
        }
    }
    ccmap_destroy(&ccmap);
    printf("ccmap destroy: %5d ms\n", elapsed(&start));
}


static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 1, run_tests, OVS_RO},
    {"benchmark", NULL, 3, 3, run_benchmarks, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
test_ccmap_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ccmap", test_ccmap_main);
