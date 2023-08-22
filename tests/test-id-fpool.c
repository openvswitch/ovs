/*
 * Copyright (c) 2021 NVIDIA Corporation.
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
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>

#include "command-line.h"
#include "id-fpool.h"
#include "id-pool.h"
#include "openvswitch/vlog.h"
#include "openvswitch/util.h"
#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "ovs-numa.h"
#include "ovstest.h"
#include "random.h"
#include "timeval.h"
#include "util.h"

static void
test_id_fpool_alloc(void)
{
    const uint32_t base = 0;
    const uint32_t n_id = 10;
    struct id_fpool *pool = id_fpool_create(1, base, n_id);
    uint32_t ids[10];
    size_t i;

    /* Can do n_id allocs. */
    for (i = 0; i < n_id; i++) {
        ovs_assert(id_fpool_new_id(pool, 0, &ids[i]));
        ovs_assert(ids[i] >= base);
        ovs_assert(ids[i] < base + n_id);
    }
    /* Only n_id successful allocations. */
    ovs_assert(id_fpool_new_id(pool, 0, NULL) == false);

    /* Monotonic alloc. */
    for (i = 0; i < n_id - 1; i++) {
        ovs_assert(ids[i] < ids[i + 1]);
    }

    for (i = 0; i < n_id; i++) {
        id_fpool_free_id(pool, 0, ids[i]);
    }

    /* Can do n_id new allocs. */
    for (i = 0; i < n_id; i++) {
        ovs_assert(id_fpool_new_id(pool, 0, &ids[i]));
        ovs_assert(ids[i] >= base);
        ovs_assert(ids[i] < base + n_id);
    }
    /* Only n_id successful allocations. */
    ovs_assert(id_fpool_new_id(pool, 0, NULL) == false);

    for (i = 0; i < n_id; i++) {
        id_fpool_free_id(pool, 0, ids[i]);
    }

    id_fpool_destroy(pool);
}

static void
test_id_fpool_alloc_range(void)
{
    const uint32_t base = 200;
    const uint32_t n_id = 100;
    const uint32_t ceil = base + n_id;
    struct id_fpool *pool = id_fpool_create(1, base, n_id);
    bool id_allocated[100];
    size_t i;

    memset(id_allocated, 0, sizeof id_allocated);

    /* Allocate all IDs only once. */
    for (i = 0; i < n_id; i++) {
        uint32_t id;

        ovs_assert(id_fpool_new_id(pool, 0, &id));
        ovs_assert(id >= base);
        ovs_assert(id < ceil);

        ovs_assert(id_allocated[id - base] == false);
        id_allocated[id - base] = true;
    }
    /* Only n_id successful allocations. */
    ovs_assert(id_fpool_new_id(pool, 0, NULL) == false);

    for (i = 0; i < n_id; i++) {
        ovs_assert(id_allocated[i]);
        id_fpool_free_id(pool, 0, base + i);
        id_allocated[i] = false;
    }

    /* The full range is again fully available. */
    for (i = 0; i < n_id; i++) {
        uint32_t id;

        ovs_assert(id_fpool_new_id(pool, 0, &id));
        ovs_assert(id >= base);
        ovs_assert(id < ceil);

        ovs_assert(id_allocated[id - base] == false);
        id_allocated[id - base] = true;
    }

    id_fpool_destroy(pool);
}

static void
test_id_fpool_alloc_steal(void)
{
    /* N must be less than a slab size to force the second user
     * to steal from the first.
     */
#define N (ID_FPOOL_CACHE_SIZE / 2)
    bool ids[N];
    struct id_fpool *pool;
    uint32_t id;
    size_t i;

    memset(ids, 0, sizeof ids);
    pool = id_fpool_create(2, 0, N);

    /* Fill up user 0 cache. */
    ovs_assert(id_fpool_new_id(pool, 0, &id));
    for (i = 0; i < N - 1; i++) {
        /* Check that user 1 can still alloc from user 0 cache. */
        ovs_assert(id_fpool_new_id(pool, 1, &id));
    }

    id_fpool_destroy(pool);
}

static void
test_id_fpool_alloc_under_limit(void)
{
    const size_t n_id = 100;
    uint32_t ids[100];
    unsigned int limit;
    struct id_fpool *pool;
    size_t i;

    memset(ids, 0, sizeof ids);
    pool = id_fpool_create(1, 0, n_id);

    for (limit = 1; limit < n_id; limit++) {
        /* Allocate until arbitrary limit then free allocated ids. */
        for (i = 0; i < limit; i++) {
            ovs_assert(id_fpool_new_id(pool, 0, &ids[i]));
        }
        for (i = 0; i < limit; i++) {
            id_fpool_free_id(pool, 0, ids[i]);
        }
        /* Verify that the N='limit' next allocations are under limit. */
        for (i = 0; i < limit; i++) {
            ovs_assert(id_fpool_new_id(pool, 0, &ids[i]));
            ovs_assert(ids[i] < limit + ID_FPOOL_CACHE_SIZE);
        }
        for (i = 0; i < limit; i++) {
            id_fpool_free_id(pool, 0, ids[i]);
        }
    }

    id_fpool_destroy(pool);
}

static void
run_tests(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_id_fpool_alloc();
    test_id_fpool_alloc_range();
    test_id_fpool_alloc_steal();
    test_id_fpool_alloc_under_limit();
}

static uint32_t *ids;
static uint64_t *thread_working_ms; /* Measured work time. */

static unsigned int n_threads;
static unsigned int n_ids;

static struct ovs_barrier barrier;

#define TIMEOUT_MS (10 * 1000) /* 10 sec timeout */
static int running_time_ms;
static volatile bool stop = false;

static int
elapsed(int *start)
{
    return running_time_ms - *start;
}

static void
swap_u32(uint32_t *a, uint32_t *b)
{
    uint32_t t;
    t = *a;
    *a = *b;
    *b = t;
}

static void
shuffle(uint32_t *p, size_t n)
{
    for (; n > 1; n--, p++) {
        uint32_t *q = &p[random_range(n)];
        swap_u32(p, q);
    }
}

static void
print_result(const char *prefix)
{
    uint64_t avg;
    size_t i;

    avg = 0;
    for (i = 0; i < n_threads; i++) {
        avg += thread_working_ms[i];
    }
    avg /= n_threads;
    printf("%s: ", prefix);
    for (i = 0; i < n_threads; i++) {
        if (thread_working_ms[i] >= TIMEOUT_MS) {
            printf(" %5" PRIu64 "+", thread_working_ms[i]);
        } else {
            printf(" %6" PRIu64, thread_working_ms[i]);
        }
    }
    if (avg >= TIMEOUT_MS) {
        printf("     -1 ms\n");
    } else {
        printf(" %6" PRIu64 " ms\n", avg);
    }
}

struct id_fpool_aux {
    struct id_fpool *pool;
    atomic_uint thread_id;
};

static void *
id_fpool_thread(void *aux_)
{
    unsigned int n_ids_per_thread;
    struct id_fpool_aux *aux = aux_;
    uint32_t *th_ids;
    unsigned int tid;
    int start;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &tid);
    n_ids_per_thread = n_ids / n_threads;
    th_ids = &ids[tid * n_ids_per_thread];

    /* NEW / ALLOC */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ignore(id_fpool_new_id(aux->pool, tid, &th_ids[i]));
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* DEL */

    shuffle(th_ids, n_ids_per_thread);

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        id_fpool_free_id(aux->pool, tid, th_ids[i]);
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* MIX */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ignore(id_fpool_new_id(aux->pool, tid, &th_ids[i]));
        id_fpool_free_id(aux->pool, tid, th_ids[i]);
        ignore(id_fpool_new_id(aux->pool, tid, &th_ids[i]));
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* Do not interfere with other threads still in 'MIX' phase. */
    for (i = 0; i < n_ids_per_thread; i++) {
        id_fpool_free_id(aux->pool, tid, th_ids[i]);
    }

    ovs_barrier_block(&barrier);

    /* MIX SHUFFLED */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        if (elapsed(&start) >= TIMEOUT_MS) {
            break;
        }
        ignore(id_fpool_new_id(aux->pool, tid, &th_ids[i]));
        swap_u32(&th_ids[i], &th_ids[random_range(i + 1)]);
        id_fpool_free_id(aux->pool, tid, th_ids[i]);
        ignore(id_fpool_new_id(aux->pool, tid, &th_ids[i]));
    }
    thread_working_ms[tid] = elapsed(&start);

    return NULL;
}

static void
benchmark_id_fpool(void)
{
    pthread_t *threads;
    struct id_fpool_aux aux;
    size_t i;

    memset(ids, 0, n_ids & sizeof *ids);
    memset(thread_working_ms, 0, n_threads & sizeof *thread_working_ms);

    aux.pool = id_fpool_create(n_threads, 0, n_ids);
    atomic_store(&aux.thread_id, 0);

    for (i = n_ids - (n_ids % n_threads); i < n_ids; i++) {
        id_fpool_new_id(aux.pool, 0, &ids[i]);
    }

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads + 1);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("id_fpool_alloc",
                                       id_fpool_thread, &aux);
    }

    ovs_barrier_block(&barrier);

    print_result("id-fpool new");

    ovs_barrier_block(&barrier);

    print_result("id-fpool del");

    ovs_barrier_block(&barrier);
    /* Cleanup. */
    ovs_barrier_block(&barrier);

    print_result("id-fpool mix");

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    print_result("id-fpool rnd");

    id_fpool_destroy(aux.pool);
    ovs_barrier_destroy(&barrier);
    free(threads);
}

struct id_pool_aux {
    struct id_pool *pool;
    struct ovs_mutex *lock;
    atomic_uint thread_id;
};

static void *
id_pool_thread(void *aux_)
{
    unsigned int n_ids_per_thread;
    struct id_pool_aux *aux = aux_;
    uint32_t *th_ids;
    unsigned int tid;
    int start;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &tid);
    n_ids_per_thread = n_ids / n_threads;
    th_ids = &ids[tid * n_ids_per_thread];

    /* NEW */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ovs_mutex_lock(aux->lock);
        ovs_assert(id_pool_alloc_id(aux->pool, &th_ids[i]));
        ovs_mutex_unlock(aux->lock);
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* DEL */

    shuffle(th_ids, n_ids_per_thread);

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ovs_mutex_lock(aux->lock);
        id_pool_free_id(aux->pool, th_ids[i]);
        ovs_mutex_unlock(aux->lock);
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* MIX */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ovs_mutex_lock(aux->lock);
        ignore(id_pool_alloc_id(aux->pool, &th_ids[i]));
        id_pool_free_id(aux->pool, th_ids[i]);
        ignore(id_pool_alloc_id(aux->pool, &th_ids[i]));
        ovs_mutex_unlock(aux->lock);
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* Do not interfere with other threads still in 'MIX' phase. */
    ovs_mutex_lock(aux->lock);
    for (i = 0; i < n_ids_per_thread; i++) {
        id_pool_free_id(aux->pool, th_ids[i]);
    }
    ovs_mutex_unlock(aux->lock);

    ovs_barrier_block(&barrier);

    /* MIX SHUFFLED */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        if (elapsed(&start) >= TIMEOUT_MS) {
            break;
        }
        ovs_mutex_lock(aux->lock);
        ignore(id_pool_alloc_id(aux->pool, &th_ids[i]));
        swap_u32(&th_ids[i], &th_ids[random_range(i + 1)]);
        id_pool_free_id(aux->pool, th_ids[i]);
        ignore(id_pool_alloc_id(aux->pool, &th_ids[i]));
        ovs_mutex_unlock(aux->lock);
    }
    thread_working_ms[tid] = elapsed(&start);

    return NULL;
}

OVS_UNUSED
static void
benchmark_id_pool(void)
{
    pthread_t *threads;
    struct id_pool_aux aux;
    struct ovs_mutex lock;
    size_t i;

    memset(ids, 0, n_ids & sizeof *ids);
    memset(thread_working_ms, 0, n_threads & sizeof *thread_working_ms);

    aux.pool = id_pool_create(0, n_ids);
    aux.lock = &lock;
    ovs_mutex_init(&lock);
    atomic_store(&aux.thread_id, 0);

    for (i = n_ids - (n_ids % n_threads); i < n_ids; i++) {
        id_pool_alloc_id(aux.pool, &ids[i]);
    }

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads + 1);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("id_pool_alloc", id_pool_thread, &aux);
    }

    ovs_barrier_block(&barrier);

    print_result(" id-pool new");

    ovs_barrier_block(&barrier);

    print_result(" id-pool del");

    ovs_barrier_block(&barrier);
    /* Cleanup. */
    ovs_barrier_block(&barrier);

    print_result(" id-pool mix");

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    print_result(" id-pool rnd");

    id_pool_destroy(aux.pool);
    ovs_barrier_destroy(&barrier);
    free(threads);
}

static void *
clock_main(void *arg OVS_UNUSED)
{
    struct timeval start;
    struct timeval end;

    xgettimeofday(&start);
    while (!stop) {
        xgettimeofday(&end);
        running_time_ms = timeval_to_msec(&end) - timeval_to_msec(&start);
        xnanosleep(1000);
    }

    return NULL;
}

static void
do_perf_test(struct ovs_cmdl_context *ctx, bool test_id_pool)
{
    pthread_t clock;
    long int l_threads;
    long int l_ids;
    size_t i;

    l_ids = strtol(ctx->argv[1], NULL, 10);
    l_threads = strtol(ctx->argv[2], NULL, 10);
    ovs_assert(l_ids > 0 && l_threads > 0);

    n_ids = l_ids;
    n_threads = l_threads;

    ids = xcalloc(n_ids, sizeof *ids);
    thread_working_ms = xcalloc(n_threads, sizeof *thread_working_ms);

    clock = ovs_thread_create("clock", clock_main, NULL);

    printf("Benchmarking n=%u on %u thread%s.\n", n_ids, n_threads,
           n_threads > 1 ? "s" : "");

    printf(" type\\thread:  ");
    for (i = 0; i < n_threads; i++) {
        printf("   %3" PRIuSIZE " ", i + 1);
    }
    printf("   Avg\n");

    ovsrcu_quiesce_start();

    benchmark_id_fpool();
    if (test_id_pool) {
        benchmark_id_pool();
    }

    stop = true;

    free(thread_working_ms);
    xpthread_join(clock, NULL);
}

static void
run_benchmark(struct ovs_cmdl_context *ctx)
{
    do_perf_test(ctx, true);
}

static void
run_perf(struct ovs_cmdl_context *ctx)
{
    do_perf_test(ctx, false);
}

static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 0, run_tests, OVS_RO},
    {"benchmark", "<nb elem> <nb threads>", 2, 2, run_benchmark, OVS_RO},
    {"perf", "<nb elem> <nb threads>", 2, 2, run_perf, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
id_fpool_test_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_OFF);

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-id-fpool", id_fpool_test_main);
