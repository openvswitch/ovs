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
#include <getopt.h>

#include "ovstest.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "random.h"
#include "util.h"

#define DEFAULT_N_THREADS 4
#define NB_STEPS 4

static bool verbose;
static struct ovs_barrier barrier;

struct blocker_aux {
    unsigned int tid;
    bool leader;
    int step;
};

static void *
basic_blocker_main(void *aux_)
{
    struct blocker_aux *aux = aux_;
    size_t i;

    aux->step = 0;
    for (i = 0; i < NB_STEPS; i++) {
        ovs_barrier_block(&barrier);
        aux->step++;
        ovs_barrier_block(&barrier);
    }

    return NULL;
}

static void
basic_block_check(struct blocker_aux *aux, size_t n, int expected)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (verbose) {
            printf("aux[%" PRIuSIZE "]=%d == %d", i, aux[i].step, expected);
            if (aux[i].step != expected) {
                printf(" <--- X");
            }
            printf("\n");
        } else {
            ovs_assert(aux[i].step == expected);
        }
    }
    ovs_barrier_block(&barrier);
    ovs_barrier_block(&barrier);
}

/*
 * Basic barrier test.
 *
 * N writers and 1 reader participate in the test.
 * Each thread goes through M steps (=NB_STEPS).
 * The main thread participates as the reader.
 *
 * A Step is divided in three parts:
 *    1. before
 *      (barrier)
 *    2. during
 *      (barrier)
 *    3. after
 *
 * Each writer updates a thread-local variable with the
 * current step number within part 2 and waits.
 *
 * The reader checks all variables during part 3, expecting
 * all variables to be equal. If any variable differs, it means
 * its thread was not properly blocked by the barrier.
 */
static void
test_barrier_basic(size_t n_threads)
{
    struct blocker_aux *aux;
    pthread_t *threads;
    size_t i;

    ovs_barrier_init(&barrier, n_threads + 1);

    aux = xcalloc(n_threads, sizeof *aux);
    threads = xmalloc(n_threads * sizeof *threads);
    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("ovs-barrier",
                                       basic_blocker_main, &aux[i]);
    }

    for (i = 0; i < NB_STEPS; i++) {
        basic_block_check(aux, n_threads, i);
    }
    ovs_barrier_destroy(&barrier);

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    free(threads);
    free(aux);
}

static unsigned int *shared_mem;

static void *
lead_blocker_main(void *aux_)
{
    struct blocker_aux *aux = aux_;
    size_t i;

    aux->step = 0;
    for (i = 0; i < NB_STEPS; i++) {
        if (aux->leader) {
            shared_mem = xmalloc(sizeof *shared_mem);
            if (verbose) {
                printf("*T1: allocated shmem\n");
            }
        }
        xnanosleep(random_range(100) * 1000);

        ovs_barrier_block(&barrier);

        if (verbose) {
            printf("%cT%u: ENTER, writing\n",
                    (aux->leader ? '*' : ' '), aux->tid);
        }

        shared_mem[0] = 42;

        ovs_barrier_block(&barrier);

        if (verbose) {
            printf("%cT%u: EXIT\n",
                    (aux->leader ? '*' : ' '), aux->tid);
        }

        if (aux->leader) {
            free(shared_mem);
            if (verbose) {
                printf("*T1: freed shmem\n");
            }
        }
        xnanosleep(random_range(100) * 1000);
    }

    return NULL;
}

/*
 * Leader barrier test.
 *
 * N threads participates, one of which is marked as
 * the leader (thread 0). The main thread does not
 * participate.
 *
 * The test is divided in M steps (=NB_STEPS).
 * A Step is divided in three parts:
 *    1. before
 *      (barrier)
 *    2. during
 *      (barrier)
 *    3. after
 *
 * Part 1, the leader allocates a block of shared memory.
 * Part 2, all threads write to the shared memory.
 * Part 3: the leader frees the shared memory.
 *
 * If any thread is improperly blocked by the barrier,
 * the shared memory accesses will trigger a segfault
 * or a use-after-free if ASAN is enabled.
 */
static void
test_barrier_lead(size_t n_threads)
{
    struct blocker_aux *aux;
    pthread_t *threads;
    size_t i;

    ovs_barrier_init(&barrier, n_threads);

    aux = xcalloc(n_threads, sizeof *aux);
    threads = xmalloc(n_threads * sizeof *threads);

    aux[0].leader = true;

    for (i = 0; i < n_threads; i++) {
        aux[i].tid = i + 1;
        threads[i] = ovs_thread_create("ovs-barrier",
                                       lead_blocker_main, &aux[i]);
    }

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    /* If the main thread does not participate in the barrier,
     * it must wait for all threads to join before destroying it.
     */
    ovs_barrier_destroy(&barrier);

    free(threads);
    free(aux);
}

static void
usage(char *test_name)
{
    fprintf(stderr, "Usage: %s [n_threads=%d] [-v]\n",
            test_name, DEFAULT_N_THREADS);
}

static void
test_barrier(int argc, char *argv[])
{
    size_t n_threads = DEFAULT_N_THREADS;
    char **args = argv + optind - 1;

    set_program_name(argv[0]);

    argc -= optind;
    if (argc > 2) {
        usage(args[0]);
        return;
    }

    while (argc-- > 0) {
        args++;
        if (!strcmp(args[0], "-v")) {
            verbose = true;
        } else {
            n_threads = strtol(args[0], NULL, 10);
            if (n_threads > 20) {
                n_threads = 20;
            }
        }
    }

    test_barrier_basic(n_threads);
    test_barrier_lead(n_threads);
}

OVSTEST_REGISTER("test-barrier", test_barrier);
