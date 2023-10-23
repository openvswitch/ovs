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
#include "guarded-list.h"
#include "mpsc-queue.h"
#include "openvswitch/list.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "timeval.h"
#include "util.h"

struct element {
    union {
        struct mpsc_queue_node mpscq;
        struct ovs_list list;
    } node;
    uint64_t mark;
};

static void
test_mpsc_queue_mark_element(struct mpsc_queue_node *node,
                             uint64_t mark,
                             unsigned int *counter)
{
    struct element *elem;

    elem = CONTAINER_OF(node, struct element, node.mpscq);
    elem->mark = mark;
    *counter += 1;
}

static void
test_mpsc_queue_insert(void)
{
    struct element elements[100];
    struct mpsc_queue_node *node;
    struct mpsc_queue queue;
    unsigned int counter;
    size_t i;

    memset(elements, 0, sizeof(elements));
    mpsc_queue_init(&queue);
    mpsc_queue_acquire(&queue);

    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        mpsc_queue_insert(&queue, &elements[i].node.mpscq);
    }

    counter = 0;
    while (mpsc_queue_poll(&queue, &node) == MPSC_QUEUE_ITEM) {
        test_mpsc_queue_mark_element(node, 1, &counter);
    }

    mpsc_queue_release(&queue);
    mpsc_queue_destroy(&queue);

    ovs_assert(counter == ARRAY_SIZE(elements));
    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        ovs_assert(elements[i].mark == 1);
    }

    printf(".");
}

static void
test_mpsc_queue_removal_fifo(void)
{
    struct element elements[100];
    struct mpsc_queue_node *node;
    struct mpsc_queue queue;
    unsigned int counter;
    size_t i;

    memset(elements, 0, sizeof(elements));

    mpsc_queue_init(&queue);
    mpsc_queue_acquire(&queue);

    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        mpsc_queue_insert(&queue, &elements[i].node.mpscq);
    }

    /* Elements are in the same order in the list as they
     * were declared / initialized.
     */
    counter = 0;
    while (mpsc_queue_poll(&queue, &node) == MPSC_QUEUE_ITEM) {
        test_mpsc_queue_mark_element(node, counter, &counter);
    }

    /* The list is valid once extracted from the queue,
     * the queue can be destroyed here.
     */
    mpsc_queue_release(&queue);
    mpsc_queue_destroy(&queue);

    for (i = 0; i < ARRAY_SIZE(elements) - 1; i++) {
        struct element *e1, *e2;

        e1 = &elements[i];
        e2 = &elements[i + 1];

        ovs_assert(e1->mark < e2->mark);
    }

    printf(".");
}

/* Partial insert:
 *
 * Those functions are 'mpsc_queue_insert()' divided in two parts.
 * They serve to test the behavior of the queue when forcing the potential
 * condition of a thread starting an insertion then yielding.
 */
static struct mpsc_queue_node *
mpsc_queue_insert_begin(struct mpsc_queue *queue, struct mpsc_queue_node *node)
{
    struct mpsc_queue_node *prev;

    atomic_store_explicit(&node->next, NULL, memory_order_relaxed);
    prev = atomic_exchange_explicit(&queue->head, node, memory_order_acq_rel);
    return prev;
}

static void
mpsc_queue_insert_end(struct mpsc_queue_node *prev,
                      struct mpsc_queue_node *node)
{
    atomic_store_explicit(&prev->next, node, memory_order_release);
}

static void
test_mpsc_queue_insert_partial(void)
{
    struct element elements[10];
    struct mpsc_queue_node *prevs[ARRAY_SIZE(elements)];
    struct mpsc_queue_node *node;
    struct mpsc_queue queue, *q = &queue;
    size_t i;

    mpsc_queue_init(q);

    /* Insert the first half of elements entirely,
     * insert the second hald of elements partially.
     */
    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        elements[i].mark = i;
        if (i > ARRAY_SIZE(elements) / 2) {
            prevs[i] = mpsc_queue_insert_begin(q, &elements[i].node.mpscq);
        } else {
            prevs[i] = NULL;
            mpsc_queue_insert(q, &elements[i].node.mpscq);
        }
    }

    mpsc_queue_acquire(q);

    /* Verify that when the chain is broken, iterators will stop. */
    i = 0;
    MPSC_QUEUE_FOR_EACH (node, q) {
        struct element *e = CONTAINER_OF(node, struct element, node.mpscq);
        ovs_assert(e == &elements[i]);
        i++;
    }
    ovs_assert(i < ARRAY_SIZE(elements));

    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        if (prevs[i] != NULL) {
            mpsc_queue_insert_end(prevs[i], &elements[i].node.mpscq);
        }
    }

    i = 0;
    MPSC_QUEUE_FOR_EACH (node, q) {
        struct element *e = CONTAINER_OF(node, struct element, node.mpscq);
        ovs_assert(e == &elements[i]);
        i++;
    }
    ovs_assert(i == ARRAY_SIZE(elements));

    MPSC_QUEUE_FOR_EACH_POP (node, q) {
        struct element *e = CONTAINER_OF(node, struct element, node.mpscq);
        ovs_assert(e->mark == (unsigned int)(e - elements));
    }

    mpsc_queue_release(q);
    mpsc_queue_destroy(q);

    printf(".");
}

static void
test_mpsc_queue_push_front(void)
{
    struct mpsc_queue queue, *q = &queue;
    struct mpsc_queue_node *node;
    struct element elements[10];
    size_t i;

    mpsc_queue_init(q);
    mpsc_queue_acquire(q);

    ovs_assert(mpsc_queue_pop(q) == NULL);
    mpsc_queue_push_front(q, &elements[0].node.mpscq);
    node = mpsc_queue_pop(q);
    ovs_assert(node == &elements[0].node.mpscq);
    ovs_assert(mpsc_queue_pop(q) == NULL);

    mpsc_queue_push_front(q, &elements[0].node.mpscq);
    mpsc_queue_push_front(q, &elements[1].node.mpscq);
    ovs_assert(mpsc_queue_pop(q) == &elements[1].node.mpscq);
    ovs_assert(mpsc_queue_pop(q) == &elements[0].node.mpscq);
    ovs_assert(mpsc_queue_pop(q) == NULL);

    mpsc_queue_push_front(q, &elements[1].node.mpscq);
    mpsc_queue_push_front(q, &elements[0].node.mpscq);
    mpsc_queue_insert(q, &elements[2].node.mpscq);
    ovs_assert(mpsc_queue_pop(q) == &elements[0].node.mpscq);
    ovs_assert(mpsc_queue_pop(q) == &elements[1].node.mpscq);
    ovs_assert(mpsc_queue_pop(q) == &elements[2].node.mpscq);
    ovs_assert(mpsc_queue_pop(q) == NULL);

    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        elements[i].mark = i;
        mpsc_queue_insert(q, &elements[i].node.mpscq);
    }

    node = mpsc_queue_pop(q);
    mpsc_queue_push_front(q, node);
    ovs_assert(mpsc_queue_pop(q) == node);
    mpsc_queue_push_front(q, node);

    i = 0;
    MPSC_QUEUE_FOR_EACH (node, q) {
        struct element *e = CONTAINER_OF(node, struct element, node.mpscq);
        ovs_assert(e == &elements[i]);
        i++;
    }
    ovs_assert(i == ARRAY_SIZE(elements));

    MPSC_QUEUE_FOR_EACH_POP (node, q) {
        struct element *e = CONTAINER_OF(node, struct element, node.mpscq);
        ovs_assert(e->mark == (unsigned int)(e - elements));
    }

    mpsc_queue_release(q);
    mpsc_queue_destroy(q);

    printf(".");
}

static void
run_tests(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* Verify basic insertion. */
    test_mpsc_queue_insert();
    /* Test partial insertion. */
    test_mpsc_queue_insert_partial();
    /* Verify removal order is respected. */
    test_mpsc_queue_removal_fifo();
    /* Verify tail-end insertion works. */
    test_mpsc_queue_push_front();
    printf("\n");
}

static struct element *elements;
static uint64_t *thread_working_ms; /* Measured work time. */

static unsigned int n_threads;
static unsigned int n_elems;

static struct ovs_barrier barrier;
static volatile bool working;

static int
elapsed(const struct timeval *start)
{
    struct timeval end;

    xgettimeofday(&end);
    return timeval_to_msec(&end) - timeval_to_msec(start);
}

static void
print_result(const char *prefix, int reader_elapsed)
{
    uint64_t avg;
    size_t i;

    avg = 0;
    for (i = 0; i < n_threads; i++) {
        avg += thread_working_ms[i];
    }
    avg /= n_threads ? n_threads : 1;
    printf("%s:  %6d", prefix, reader_elapsed);
    for (i = 0; i < n_threads; i++) {
        printf(" %6" PRIu64, thread_working_ms[i]);
    }
    printf(" %6" PRIu64 " ms\n", avg);
}

struct mpscq_aux {
    struct mpsc_queue *queue;
    atomic_uint thread_id;
};

static void *
mpsc_queue_insert_thread(void *aux_)
{
    unsigned int n_elems_per_thread;
    struct element *th_elements;
    struct mpscq_aux *aux = aux_;
    struct timeval start;
    unsigned int id;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &id);
    n_elems_per_thread = n_elems / n_threads;
    th_elements = &elements[id * n_elems_per_thread];

    ovs_barrier_block(&barrier);
    xgettimeofday(&start);

    for (i = 0; i < n_elems_per_thread; i++) {
        mpsc_queue_insert(aux->queue, &th_elements[i].node.mpscq);
    }

    thread_working_ms[id] = elapsed(&start);
    ovs_barrier_block(&barrier);

    working = false;

    return NULL;
}

static void
benchmark_mpsc_queue(void)
{
    struct mpsc_queue_node *node;
    struct mpsc_queue queue;
    struct timeval start;
    unsigned int counter;
    bool work_complete;
    pthread_t *threads;
    struct mpscq_aux aux;
    uint64_t epoch;
    size_t i;

    memset(elements, 0, n_elems & sizeof *elements);
    memset(thread_working_ms, 0, n_threads & sizeof *thread_working_ms);

    mpsc_queue_init(&queue);

    aux.queue = &queue;
    atomic_store(&aux.thread_id, 0);

    for (i = n_elems - (n_elems % n_threads); i < n_elems; i++) {
        mpsc_queue_insert(&queue, &elements[i].node.mpscq);
    }

    working = true;

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("sc_queue_insert",
                                       mpsc_queue_insert_thread, &aux);
    }

    mpsc_queue_acquire(&queue);
    xgettimeofday(&start);

    counter = 0;
    epoch = 1;
    do {
        while (mpsc_queue_poll(&queue, &node) == MPSC_QUEUE_ITEM) {
            test_mpsc_queue_mark_element(node, epoch, &counter);
        }
        if (epoch == UINT64_MAX) {
            epoch = 0;
        }
        epoch++;
    } while (working);

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    /* Elements might have been inserted before threads were joined. */
    while (mpsc_queue_poll(&queue, &node) == MPSC_QUEUE_ITEM) {
        test_mpsc_queue_mark_element(node, epoch, &counter);
    }

    print_result("  mpsc-queue", elapsed(&start));

    mpsc_queue_release(&queue);
    mpsc_queue_destroy(&queue);
    ovs_barrier_destroy(&barrier);
    free(threads);

    work_complete = true;
    for (i = 0; i < n_elems; i++) {
        if (elements[i].mark == 0) {
            printf("Element %" PRIuSIZE " was never consumed.\n", i);
            work_complete = false;
        }
    }
    ovs_assert(work_complete);
    ovs_assert(counter == n_elems);
}

#ifdef HAVE_PTHREAD_SPIN_LOCK
#define spin_lock_type       ovs_spin
#define spin_lock_init(l)    ovs_spin_init(l)
#define spin_lock_destroy(l) ovs_spin_destroy(l)
#define spin_lock(l)         ovs_spin_lock(l)
#define spin_unlock(l)       ovs_spin_unlock(l)
#else
#define spin_lock_type       ovs_mutex
#define spin_lock_init(l)    ovs_mutex_init(l)
#define spin_lock_destroy(l) ovs_mutex_destroy(l)
#define spin_lock(l)         ovs_mutex_lock(l)
#define spin_unlock(l)       ovs_mutex_unlock(l)
#endif

struct list_aux {
    struct ovs_list *list;
    struct ovs_mutex *mutex;
    struct spin_lock_type *spin;
    atomic_uint thread_id;
};

static void *
locked_list_insert_main(void *aux_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    unsigned int n_elems_per_thread;
    struct element *th_elements;
    struct list_aux *aux = aux_;
    struct timeval start;
    unsigned int id;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &id);
    n_elems_per_thread = n_elems / n_threads;
    th_elements = &elements[id * n_elems_per_thread];

    ovs_barrier_block(&barrier);
    xgettimeofday(&start);

    for (i = 0; i < n_elems_per_thread; i++) {
        aux->mutex ? ovs_mutex_lock(aux->mutex)
                   : spin_lock(aux->spin);
        ovs_list_push_front(aux->list, &th_elements[i].node.list);
        aux->mutex ? ovs_mutex_unlock(aux->mutex)
                   : spin_unlock(aux->spin);
    }

    thread_working_ms[id] = elapsed(&start);
    ovs_barrier_block(&barrier);

    working = false;

    return NULL;
}

static void
benchmark_list(bool use_mutex)
{
    struct ovs_mutex mutex;
    struct spin_lock_type spin;
    struct ovs_list list;
    struct element *elem;
    struct timeval start;
    unsigned int counter;
    bool work_complete;
    pthread_t *threads;
    struct list_aux aux;
    uint64_t epoch;
    size_t i;

    memset(elements, 0, n_elems * sizeof *elements);
    memset(thread_working_ms, 0, n_threads * sizeof *thread_working_ms);

    use_mutex ? ovs_mutex_init(&mutex) : spin_lock_init(&spin);

    ovs_list_init(&list);

    aux.list = &list;
    aux.mutex = use_mutex ? &mutex : NULL;
    aux.spin = use_mutex ? NULL : &spin;
    atomic_store(&aux.thread_id, 0);

    for (i = n_elems - (n_elems % n_threads); i < n_elems; i++) {
        ovs_list_push_front(&list, &elements[i].node.list);
    }

    working = true;

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("locked_list_insert",
                                       locked_list_insert_main, &aux);
    }

    xgettimeofday(&start);

    counter = 0;
    epoch = 1;
    do {
        if (use_mutex) {
            ovs_mutex_lock(&mutex);
            LIST_FOR_EACH_POP (elem, node.list, &list) {
                elem->mark = epoch;
                counter++;
            }
            ovs_mutex_unlock(&mutex);
        } else {
            struct ovs_list *node = NULL;

            spin_lock(&spin);
            if (!ovs_list_is_empty(&list)) {
                node = ovs_list_pop_front(&list);
            }
            spin_unlock(&spin);

            if (!node) {
                continue;
            }

            elem = CONTAINER_OF(node, struct element, node.list);
            elem->mark = epoch;
            counter++;
        }
        if (epoch == UINT64_MAX) {
            epoch = 0;
        }
        epoch++;
    } while (working);

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    /* Elements might have been inserted before threads were joined. */
    LIST_FOR_EACH_POP (elem, node.list, &list) {
        elem->mark = epoch;
        counter++;
    }

    if (use_mutex) {
        print_result(" list(mutex)", elapsed(&start));
    } else {
        print_result("  list(spin)", elapsed(&start));
    }

    use_mutex ? ovs_mutex_destroy(&mutex) : spin_lock_destroy(&spin);
    ovs_barrier_destroy(&barrier);
    free(threads);

    work_complete = true;
    for (i = 0; i < n_elems; i++) {
        if (elements[i].mark == 0) {
            printf("Element %" PRIuSIZE " was never consumed.\n", i);
            work_complete = false;
        }
    }
    ovs_assert(work_complete);
    ovs_assert(counter == n_elems);
}

struct guarded_list_aux {
    struct guarded_list *glist;
    atomic_uint thread_id;
};

static void *
guarded_list_insert_thread(void *aux_)
{
    unsigned int n_elems_per_thread;
    struct element *th_elements;
    struct guarded_list_aux *aux = aux_;
    struct timeval start;
    unsigned int id;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &id);
    n_elems_per_thread = n_elems / n_threads;
    th_elements = &elements[id * n_elems_per_thread];

    ovs_barrier_block(&barrier);
    xgettimeofday(&start);

    for (i = 0; i < n_elems_per_thread; i++) {
        guarded_list_push_back(aux->glist, &th_elements[i].node.list, n_elems);
    }

    thread_working_ms[id] = elapsed(&start);
    ovs_barrier_block(&barrier);

    working = false;

    return NULL;
}

static void
benchmark_guarded_list(void)
{
    struct guarded_list_aux aux;
    struct ovs_list extracted;
    struct guarded_list glist;
    struct element *elem;
    struct timeval start;
    unsigned int counter;
    bool work_complete;
    pthread_t *threads;
    uint64_t epoch;
    size_t i;

    memset(elements, 0, n_elems * sizeof *elements);
    memset(thread_working_ms, 0, n_threads * sizeof *thread_working_ms);

    guarded_list_init(&glist);
    ovs_list_init(&extracted);

    aux.glist = &glist;
    atomic_store(&aux.thread_id, 0);

    for (i = n_elems - (n_elems % n_threads); i < n_elems; i++) {
        guarded_list_push_back(&glist, &elements[i].node.list, n_elems);
    }

    working = true;

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("guarded_list_insert",
                                       guarded_list_insert_thread, &aux);
    }

    xgettimeofday(&start);

    counter = 0;
    epoch = 1;
    do {
        guarded_list_pop_all(&glist, &extracted);
        LIST_FOR_EACH_POP (elem, node.list, &extracted) {
            elem->mark = epoch;
            counter++;
        }
        if (epoch == UINT64_MAX) {
            epoch = 0;
        }
        epoch++;
    } while (working);

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    /* Elements might have been inserted before threads were joined. */
    guarded_list_pop_all(&glist, &extracted);
    LIST_FOR_EACH_POP (elem, node.list, &extracted) {
        elem->mark = epoch;
        counter++;
    }

    print_result("guarded list", elapsed(&start));

    ovs_barrier_destroy(&barrier);
    free(threads);
    guarded_list_destroy(&glist);

    work_complete = true;
    for (i = 0; i < n_elems; i++) {
        if (elements[i].mark == 0) {
            printf("Element %" PRIuSIZE " was never consumed.\n", i);
            work_complete = false;
        }
    }
    ovs_assert(work_complete);
    ovs_assert(counter == n_elems);
}

static void
run_benchmarks(struct ovs_cmdl_context *ctx)
{
    long int l_threads;
    long int l_elems;
    size_t i;

    ovsrcu_quiesce_start();

    l_elems = strtol(ctx->argv[1], NULL, 10);
    l_threads = strtol(ctx->argv[2], NULL, 10);
    ovs_assert(l_elems > 0 && l_threads > 0);

    n_elems = l_elems;
    n_threads = l_threads;

    elements = xcalloc(n_elems, sizeof *elements);
    thread_working_ms = xcalloc(n_threads, sizeof *thread_working_ms);

    printf("Benchmarking n=%u on 1 + %u threads.\n", n_elems, n_threads);

    printf(" type\\thread:  Reader ");
    for (i = 0; i < n_threads; i++) {
        printf("   %3" PRIuSIZE " ", i + 1);
    }
    printf("   Avg\n");

    benchmark_mpsc_queue();
#ifdef HAVE_PTHREAD_SPIN_LOCK
    benchmark_list(false);
#endif
    benchmark_list(true);
    benchmark_guarded_list();

    free(thread_working_ms);
    free(elements);
}

static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 0, run_tests, OVS_RO},
    {"benchmark", "<nb elem> <nb threads>", 2, 2, run_benchmarks, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
test_mpsc_queue_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_OFF);

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-mpsc-queue", test_mpsc_queue_main);
