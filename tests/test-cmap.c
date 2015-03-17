/*
 * Copyright (c) 2008, 2009, 2010, 2013, 2014 Nicira, Inc.
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
 * cmap.h. */

#include <config.h>
#undef NDEBUG
#include "cmap.h"
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include "bitmap.h"
#include "command-line.h"
#include "fat-rwlock.h"
#include "hash.h"
#include "hmap.h"
#include "ovstest.h"
#include "ovs-thread.h"
#include "random.h"
#include "timeval.h"
#include "util.h"

/* Sample cmap element. */
struct element {
    int value;
    struct cmap_node node;
};

typedef size_t hash_func(int value);

static int
compare_ints(const void *a_, const void *b_)
{
    const int *a = a_;
    const int *b = b_;
    return *a < *b ? -1 : *a > *b;
}

/* Verifies that 'cmap' contains exactly the 'n' values in 'values'. */
static void
check_cmap(struct cmap *cmap, const int values[], size_t n,
           hash_func *hash)
{
    int *sort_values, *cmap_values, *cmap_values2;
    const struct element *e;
    size_t i, batch_size;

    struct cmap_position pos = { 0, 0, 0 };
    struct cmap_node *node;

    /* Check that all the values are there in iteration. */
    sort_values = xmalloc(sizeof *sort_values * n);
    cmap_values = xmalloc(sizeof *sort_values * n);
    cmap_values2 = xmalloc(sizeof *sort_values * n);

    /* Here we test cursor iteration */
    i = 0;
    CMAP_FOR_EACH (e, node, cmap) {
        assert(i < n);
        cmap_values[i++] = e->value;
    }
    assert(i == n);

    /* Here we test iteration with cmap_next_position() */
    i = 0;
    while ((node = cmap_next_position(cmap, &pos))) {
        struct element *e = NULL;
        e = OBJECT_CONTAINING(node, e, node);

        assert(i < n);
        cmap_values2[i++] = e->value;
    }
    assert(i == n);

    memcpy(sort_values, values, sizeof *sort_values * n);
    qsort(sort_values, n, sizeof *sort_values, compare_ints);
    qsort(cmap_values, n, sizeof *cmap_values, compare_ints);
    qsort(cmap_values2, n, sizeof *cmap_values2, compare_ints);

    for (i = 0; i < n; i++) {
        assert(sort_values[i] == cmap_values[i]);
        assert(sort_values[i] == cmap_values2[i]);
    }

    free(cmap_values2);
    free(cmap_values);
    free(sort_values);

    /* Check that all the values are there in lookup. */
    for (i = 0; i < n; i++) {
        size_t count = 0;

        CMAP_FOR_EACH_WITH_HASH (e, node, hash(values[i]), cmap) {
            count += e->value == values[i];
        }
        assert(count == 1);
    }

    /* Check that all the values are there in batched lookup. */
    batch_size = n % BITMAP_ULONG_BITS + 1;
    for (i = 0; i < n; i += batch_size) {
        unsigned long map;
        uint32_t hashes[sizeof map * CHAR_BIT];
        const struct cmap_node *nodes[sizeof map * CHAR_BIT];
        size_t count = 0;
        int k, j;

        j = MIN(n - i, batch_size); /* Actual batch size. */
        map = ~0UL >> (BITMAP_ULONG_BITS - j);

        for (k = 0; k < j; k++) {
            hashes[k] = hash(values[i + k]);
        }
        map = cmap_find_batch(cmap, map, hashes, nodes);

        ULONG_FOR_EACH_1(k, map) {
            struct element *e;

            CMAP_NODE_FOR_EACH (e, node, nodes[k]) {
                count += e->value == values[i + k];
            }
        }
        assert(count == j); /* j elements in a batch. */
    }

    /* Check that cmap_first() returns NULL only when cmap_is_empty(). */
    assert(!cmap_first(cmap) == cmap_is_empty(cmap));

    /* Check counters. */
    assert(cmap_is_empty(cmap) == !n);
    assert(cmap_count(cmap) == n);
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

/* Prints the values in 'cmap', plus 'name' as a title. */
static void OVS_UNUSED
print_cmap(const char *name, struct cmap *cmap)
{
    struct cmap_cursor cursor;
    struct element *e;

    printf("%s:", name);
    CMAP_CURSOR_FOR_EACH (e, node, &cursor, cmap) {
        printf(" %d", e->value);
    }
    printf("\n");
}

/* Prints the 'n' values in 'values', plus 'name' as a title. */
static void OVS_UNUSED
print_ints(const char *name, const int *values, size_t n)
{
    size_t i;

    printf("%s:", name);
    for (i = 0; i < n; i++) {
        printf(" %d", values[i]);
    }
    printf("\n");
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

/* Tests basic cmap insertion and deletion. */
static void
test_cmap_insert_replace_delete(hash_func *hash)
{
    enum { N_ELEMS = 1000 };

    struct element elements[N_ELEMS];
    struct element copies[N_ELEMS];
    int values[N_ELEMS];
    struct cmap cmap;
    size_t i;

    cmap_init(&cmap);
    for (i = 0; i < N_ELEMS; i++) {
        elements[i].value = i;
        cmap_insert(&cmap, &elements[i].node, hash(i));
        values[i] = i;
        check_cmap(&cmap, values, i + 1, hash);
    }
    shuffle(values, N_ELEMS);
    for (i = 0; i < N_ELEMS; i++) {
        copies[values[i]].value = values[i];
        cmap_replace(&cmap, &elements[values[i]].node,
                     &copies[values[i]].node, hash(values[i]));
        check_cmap(&cmap, values, N_ELEMS, hash);
    }
    shuffle(values, N_ELEMS);
    for (i = 0; i < N_ELEMS; i++) {
        cmap_remove(&cmap, &copies[values[i]].node, hash(values[i]));
        check_cmap(&cmap, values + (i + 1), N_ELEMS - (i + 1), hash);
    }
    cmap_destroy(&cmap);
}

static void
run_test(void (*function)(hash_func *))
{
    hash_func *hash_funcs[] = { identity_hash, good_hash, constant_hash };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(hash_funcs); i++) {
        function(hash_funcs[i]);
        printf(".");
        fflush(stdout);
    }
}

static void
run_tests(struct ovs_cmdl_context *ctx)
{
    int n;
    int i;

    n = ctx->argc >= 2 ? atoi(ctx->argv[1]) : 100;
    for (i = 0; i < n; i++) {
        run_test(test_cmap_insert_replace_delete);
    }
    printf("\n");
}

static int n_elems;             /* Number of elements to insert. */
static int n_threads;           /* Number of threads to search and mutate. */
static uint32_t mutation_frac;  /* % mutations, as fraction of UINT32_MAX. */
static int n_batch;             /* Number of elements in each batch. */

#define N_BATCH_MAX BITMAP_ULONG_BITS

static void benchmark_cmap(void);
static void benchmark_cmap_batched(void);
static void benchmark_hmap(void);

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
    n_batch = ctx->argc > 4 ? strtol(ctx->argv[4], NULL, 10) : 1;

    if (n_batch > N_BATCH_MAX) {
        n_batch = N_BATCH_MAX;
    }
    printf("Benchmarking with n=%d, %d threads, %.2f%% mutations, batch size %d:\n",
           n_elems, n_threads, (double) mutation_frac / UINT32_MAX * 100.,
           n_batch);

    if (n_batch > 0) {
        benchmark_cmap_batched();
    }
    putchar('\n');
    benchmark_cmap();
    putchar('\n');
    benchmark_hmap();
}

/* cmap benchmark. */

static struct element *
find(const struct cmap *cmap, int value)
{
    struct element *e;

    CMAP_FOR_EACH_WITH_HASH (e, node, hash_int(value, 0), cmap) {
        if (e->value == value) {
            return e;
        }
    }
    return NULL;
}

struct cmap_aux {
    struct ovs_mutex mutex;
    struct cmap *cmap;
};

static void *
search_cmap(void *aux_)
{
    struct cmap_aux *aux = aux_;
    size_t i;

    if (mutation_frac) {
        for (i = 0; i < n_elems; i++) {
            struct element *e;

            if (random_uint32() < mutation_frac) {
                ovs_mutex_lock(&aux->mutex);
                e = find(aux->cmap, i);
                if (e) {
                    cmap_remove(aux->cmap, &e->node, hash_int(e->value, 0));
                }
                ovs_mutex_unlock(&aux->mutex);
            } else {
                ignore(find(aux->cmap, i));
            }
        }
    } else {
        for (i = 0; i < n_elems; i++) {
            ignore(find(aux->cmap, i));
        }
    }
    return NULL;
}

static void
benchmark_cmap(void)
{
    struct element *elements;
    struct cmap cmap;
    struct element *e;
    struct timeval start;
    pthread_t *threads;
    struct cmap_aux aux;
    size_t i;

    elements = xmalloc(n_elems * sizeof *elements);

    /* Insertions. */
    xgettimeofday(&start);
    cmap_init(&cmap);
    for (i = 0; i < n_elems; i++) {
        elements[i].value = i;
        cmap_insert(&cmap, &elements[i].node, hash_int(i, 0));
    }
    printf("cmap insert:  %5d ms\n", elapsed(&start));

    /* Iteration. */
    xgettimeofday(&start);
    CMAP_FOR_EACH (e, node, &cmap) {
        ignore(e);
    }
    printf("cmap iterate: %5d ms\n", elapsed(&start));

    /* Search and mutation. */
    xgettimeofday(&start);
    aux.cmap = &cmap;
    ovs_mutex_init(&aux.mutex);
    threads = xmalloc(n_threads * sizeof *threads);
    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("search", search_cmap, &aux);
    }
    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }
    free(threads);
    printf("cmap search:  %5d ms\n", elapsed(&start));

    /* Destruction. */
    xgettimeofday(&start);
    CMAP_FOR_EACH (e, node, &cmap) {
        cmap_remove(&cmap, &e->node, hash_int(e->value, 0));
    }
    cmap_destroy(&cmap);
    printf("cmap destroy: %5d ms\n", elapsed(&start));

    free(elements);
}

static size_t
find_batch(const struct cmap *cmap, const int value)
{
    size_t i, ret;
    const size_t end = MIN(n_batch, n_elems - value);
    unsigned long map = ~0;
    uint32_t hashes[N_BATCH_MAX];
    const struct cmap_node *nodes[N_BATCH_MAX];

    if (mutation_frac) {
        for (i = 0; i < end; i++) {
            if (random_uint32() < mutation_frac) {
                break;
            }
            hashes[i] = hash_int(value + i, 0);
        }
    } else {
        for (i = 0; i < end; i++) {
            hashes[i] = hash_int(value + i, 0);
        }
    }

    ret = i;

    map >>= BITMAP_ULONG_BITS - i; /* Clear excess bits. */
    map = cmap_find_batch(cmap, map, hashes, nodes);

    ULONG_FOR_EACH_1(i, map) {
        struct element *e;

        CMAP_NODE_FOR_EACH (e, node, nodes[i]) {
            if (OVS_LIKELY(e->value == value + i)) {
                ignore(e); /* Found result. */
                break;
            }
        }
    }
    return ret;
}

static void *
search_cmap_batched(void *aux_)
{
    struct cmap_aux *aux = aux_;
    size_t i = 0, j;

    for (;;) {
        struct element *e;

        j = find_batch(aux->cmap, i);
        i += j;
        if (i >= n_elems) {
            break;
        }
        if (j < n_batch) {
            ovs_mutex_lock(&aux->mutex);
            e = find(aux->cmap, i);
            if (e) {
                cmap_remove(aux->cmap, &e->node, hash_int(e->value, 0));
            }
            ovs_mutex_unlock(&aux->mutex);
        }
    }

    return NULL;
}

static void
benchmark_cmap_batched(void)
{
    struct element *elements;
    struct cmap cmap;
    struct element *e;
    struct timeval start;
    pthread_t *threads;
    struct cmap_aux aux;
    size_t i;

    elements = xmalloc(n_elems * sizeof *elements);

    /* Insertions. */
    xgettimeofday(&start);
    cmap_init(&cmap);
    for (i = 0; i < n_elems; i++) {
        elements[i].value = i;
        cmap_insert(&cmap, &elements[i].node, hash_int(i, 0));
    }
    printf("cmap insert:  %5d ms\n", elapsed(&start));

    /* Iteration. */
    xgettimeofday(&start);
    CMAP_FOR_EACH (e, node, &cmap) {
        ignore(e);
    }
    printf("cmap iterate: %5d ms\n", elapsed(&start));

    /* Search and mutation. */
    xgettimeofday(&start);
    aux.cmap = &cmap;
    ovs_mutex_init(&aux.mutex);
    threads = xmalloc(n_threads * sizeof *threads);
    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("search", search_cmap_batched, &aux);
    }
    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }
    free(threads);
    printf("batch search: %5d ms\n", elapsed(&start));

    /* Destruction. */
    xgettimeofday(&start);
    CMAP_FOR_EACH (e, node, &cmap) {
        cmap_remove(&cmap, &e->node, hash_int(e->value, 0));
    }
    cmap_destroy(&cmap);
    printf("cmap destroy: %5d ms\n", elapsed(&start));

    free(elements);
}

/* hmap benchmark. */
struct helement {
    int value;
    struct hmap_node node;
};

static struct helement *
hfind(const struct hmap *hmap, int value)
{
    struct helement *e;

    HMAP_FOR_EACH_WITH_HASH (e, node, hash_int(value, 0), hmap) {
        if (e->value == value) {
            return e;
        }
    }
    return NULL;
}

struct hmap_aux {
    struct hmap *hmap;
    struct fat_rwlock fatlock;
};

static void *
search_hmap(void *aux_)
{
    struct hmap_aux *aux = aux_;
    size_t i;

    if (mutation_frac) {
        for (i = 0; i < n_elems; i++) {
            if (random_uint32() < mutation_frac) {
                struct helement *e;

                fat_rwlock_wrlock(&aux->fatlock);
                e = hfind(aux->hmap, i);
                if (e) {
                    hmap_remove(aux->hmap, &e->node);
                }
                fat_rwlock_unlock(&aux->fatlock);
            } else {
                fat_rwlock_rdlock(&aux->fatlock);
                ignore(hfind(aux->hmap, i));
                fat_rwlock_unlock(&aux->fatlock);
            }
        }
    } else {
        for (i = 0; i < n_elems; i++) {
            ignore(hfind(aux->hmap, i));
        }
    }
    return NULL;
}

static void
benchmark_hmap(void)
{
    struct helement *elements;
    struct hmap hmap;
    struct helement *e, *next;
    struct timeval start;
    pthread_t *threads;
    struct hmap_aux aux;
    size_t i;

    elements = xmalloc(n_elems * sizeof *elements);

    xgettimeofday(&start);
    hmap_init(&hmap);
    for (i = 0; i < n_elems; i++) {
        elements[i].value = i;
        hmap_insert(&hmap, &elements[i].node, hash_int(i, 0));
    }

    printf("hmap insert:  %5d ms\n", elapsed(&start));

    xgettimeofday(&start);
    HMAP_FOR_EACH (e, node, &hmap) {
        ignore(e);
    }
    printf("hmap iterate: %5d ms\n", elapsed(&start));

    xgettimeofday(&start);
    aux.hmap = &hmap;
    fat_rwlock_init(&aux.fatlock);
    threads = xmalloc(n_threads * sizeof *threads);
    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("search", search_hmap, &aux);
    }
    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }
    free(threads);
    printf("hmap search:  %5d ms\n", elapsed(&start));

    /* Destruction. */
    xgettimeofday(&start);
    HMAP_FOR_EACH_SAFE (e, next, node, &hmap) {
        hmap_remove(&hmap, &e->node);
    }
    hmap_destroy(&hmap);
    printf("hmap destroy: %5d ms\n", elapsed(&start));

    free(elements);
}

static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 1, run_tests},
    {"benchmark", NULL, 3, 4, run_benchmarks},
    {NULL, NULL, 0, 0, NULL},
};

static void
test_cmap_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-cmap", test_cmap_main);
