/*
 * Copyright (c) 2013, 2014 Nicira, Inc.
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
#include "fatal-signal.h"
#include "ovs-atomic.h"
#include "ovstest.h"
#include "ovs-thread.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(test_atomic);

#define TEST_ATOMIC_TYPE(ATOMIC_TYPE, BASE_TYPE)        \
    {                                                   \
        ATOMIC_TYPE x = ATOMIC_VAR_INIT(1);             \
        BASE_TYPE value, orig;                          \
                                                        \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 1);                         \
                                                        \
        atomic_store(&x, 2);                            \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 2);                         \
                                                        \
        atomic_init(&x, 3);                             \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 3);                         \
                                                        \
        atomic_add(&x, 1, &orig);                       \
        ovs_assert(orig == 3);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 4);                         \
                                                        \
        atomic_sub(&x, 2, &orig);                       \
        ovs_assert(orig == 4);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 2);                         \
                                                        \
        atomic_or(&x, 6, &orig);                        \
        ovs_assert(orig == 2);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 6);                         \
                                                        \
        atomic_and(&x, 10, &orig);                      \
        ovs_assert(orig == 6);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 2);                         \
                                                        \
        atomic_xor(&x, 10, &orig);                      \
        ovs_assert(orig == 2);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 8);                         \
    }

#define TEST_ATOMIC_TYPE_EXPLICIT(ATOMIC_TYPE, BASE_TYPE,               \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW)   \
    {                                                                   \
        ATOMIC_TYPE x = ATOMIC_VAR_INIT(1);                             \
        BASE_TYPE value, orig;                                          \
                                                                        \
        atomic_read_explicit(&x, &value, ORDER_READ);                   \
        ovs_assert(value == 1);                                         \
                                                                        \
        atomic_store_explicit(&x, 2, ORDER_STORE);                      \
        atomic_read_explicit(&x, &value, ORDER_READ);                   \
        ovs_assert(value == 2);                                         \
                                                                        \
        atomic_init(&x, 3);                                             \
        atomic_read_explicit(&x, &value, ORDER_READ);                   \
        ovs_assert(value == 3);                                         \
                                                                        \
        atomic_add_explicit(&x, 1, &orig, ORDER_RMW);                   \
        ovs_assert(orig == 3);                                          \
        atomic_read_explicit(&x, &value, ORDER_READ);                   \
        ovs_assert(value == 4);                                         \
                                                                        \
        atomic_sub_explicit(&x, 2, &orig, ORDER_RMW);                   \
        ovs_assert(orig == 4);                                          \
        atomic_read_explicit(&x, &value, ORDER_READ);                   \
        ovs_assert(value == 2);                                         \
                                                                        \
        atomic_or_explicit(&x, 6, &orig, ORDER_RMW);                    \
        ovs_assert(orig == 2);                                          \
        atomic_read_explicit(&x, &value, ORDER_READ);                   \
        ovs_assert(value == 6);                                         \
                                                                        \
        atomic_and_explicit(&x, 10, &orig, ORDER_RMW);                  \
        ovs_assert(orig == 6);                                          \
        atomic_read_explicit(&x, &value, ORDER_READ);                   \
        ovs_assert(value == 2);                                         \
                                                                        \
        atomic_xor_explicit(&x, 10, &orig, ORDER_RMW);                  \
        ovs_assert(orig == 2);                                          \
        atomic_read_explicit(&x, &value, ORDER_READ);                   \
        ovs_assert(value == 8);                                         \
    }


#define TEST_ATOMIC_ORDER(ORDER_READ, ORDER_STORE, ORDER_RMW)           \
    {                                                                   \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_char, char,                    \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_uchar, unsigned char,          \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_schar, signed char,            \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_short, short,                  \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_ushort, unsigned short,        \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_int, int,                      \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_uint, unsigned int,            \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_long, long int,                \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_ulong, unsigned long int,      \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_llong, long long int,          \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_ullong, unsigned long long int, \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_size_t, size_t,                \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_ptrdiff_t, ptrdiff_t,          \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_intmax_t, intmax_t,            \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_uintmax_t, uintmax_t,          \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_intptr_t, intptr_t,            \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_uintptr_t, uintptr_t,          \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_uint8_t, uint8_t,              \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_int8_t, int8_t,                \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_uint16_t, uint16_t,            \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_int16_t, int16_t,              \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_uint32_t, uint32_t,            \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
        TEST_ATOMIC_TYPE_EXPLICIT(atomic_int32_t, int32_t,              \
                                  ORDER_READ, ORDER_STORE, ORDER_RMW);  \
    }

static void
test_atomic_flag(void)
{
    atomic_flag flag = ATOMIC_FLAG_INIT;
    ovs_assert(atomic_flag_test_and_set(&flag) == false);
    ovs_assert(atomic_flag_test_and_set(&flag) == true);
    atomic_flag_clear(&flag);
    ovs_assert(atomic_flag_test_and_set(&flag) == false);
}

static uint32_t a;

struct atomic_aux {
    ATOMIC(uint64_t) count;
    uint32_t b;
    ATOMIC(uint32_t *) data;
    ATOMIC(uint64_t) data64;
};

static ATOMIC(struct atomic_aux *) paux = ATOMIC_VAR_INIT(NULL);
static struct atomic_aux *auxes = NULL;

#define ATOMIC_ITEM_COUNT 1000000
#define	DURATION 5000

static void *
atomic_consumer(void * arg1 OVS_UNUSED)
{
    struct atomic_aux *old_aux = NULL;
    uint64_t count;
    long long int stop_time = time_msec() + DURATION;

    do {
        struct atomic_aux *aux;
        uint32_t b;

        /* Wait for a new item.  We may not be fast enough to process every
         * item, but we are guaranteed to see the last one. */
        do {
            atomic_read_explicit(&paux, &aux, memory_order_consume);
        } while (aux == old_aux);

        b = aux->b;
        atomic_read_explicit(&aux->count, &count, memory_order_relaxed);
        ovs_assert(b == count + 42);

        old_aux = aux;
    } while (count < ATOMIC_ITEM_COUNT - 1 && time_msec() < stop_time);

    if (time_msec() >= stop_time) {
        if (count < 10) {
            VLOG_WARN("atomic_consumer test stopped due to excessive runtime. "
                      "Count = %"PRIu64, count);
        }
    }

    return NULL;
}

static void *
atomic_producer(void * arg1 OVS_UNUSED)
{
    size_t i;

    for (i = 0; i < ATOMIC_ITEM_COUNT; i++) {
        struct atomic_aux *aux = &auxes[i];

        aux->count = ATOMIC_VAR_INIT(i);
        aux->b = i + 42;

        /* Publish the new item. */
        atomic_store_explicit(&paux, aux, memory_order_release);
    }

    return NULL;
}

static void
test_cons_rel(void)
{
    pthread_t reader, writer;

    atomic_init(&paux, NULL);

    auxes = xmalloc(sizeof *auxes * ATOMIC_ITEM_COUNT);

    reader = ovs_thread_create("consumer", atomic_consumer, NULL);
    writer = ovs_thread_create("producer", atomic_producer, NULL);

    xpthread_join(reader, NULL);
    xpthread_join(writer, NULL);

    free(auxes);
}

static void *
atomic_reader(void *aux_)
{
    struct atomic_aux *aux = aux_;
    uint64_t count;
    uint64_t data;
    long long int now = time_msec();
    long long int stop_time = now + DURATION;

    do {
        /* Non-synchronized add. */
        atomic_add_explicit(&aux->count, 1, &count, memory_order_relaxed);

        do {
            atomic_read_explicit(&aux->data64, &data, memory_order_acquire);
        } while (!data && (now = time_msec()) < stop_time);

        if (now >= stop_time) {
            if (count < 10) {
                VLOG_WARN("atomic_reader test stopped due to excessive "
                          "runtime. Count = %"PRIu64, count);
            }
            break;
        }

        ovs_assert(data == a && data == aux->b && a == aux->b);

        atomic_read_explicit(&aux->count, &count, memory_order_relaxed);

        ovs_assert(count == 2 * a && count == 2 * aux->b && count == 2 * data);

        atomic_store_explicit(&aux->data64, UINT64_C(0), memory_order_release);
    } while (count < 2 * ATOMIC_ITEM_COUNT);

    return NULL;
}

static void *
atomic_writer(void *aux_)
{
    struct atomic_aux *aux = aux_;
    uint64_t old_count;
    uint64_t data;
    size_t i;
    long long int now = time_msec();
    long long int stop_time = now + DURATION;

    for (i = 0; i < ATOMIC_ITEM_COUNT; i++) {
        /* Wait for the reader to be done with the data. */
        do {
            atomic_read_explicit(&aux->data64, &data, memory_order_acquire);
        } while (data && (now = time_msec()) < stop_time);

        if (now >= stop_time) {
            if (i < 10) {
                VLOG_WARN("atomic_writer test stopped due to excessive "
                          "runtime, Count = %"PRIuSIZE, i);
            }
            break;
        }

        a = i + 1;
        atomic_add_explicit(&aux->count, 1, &old_count, memory_order_relaxed);
        aux->b++;
        atomic_store_explicit(&aux->data64,
                              (i & 1) ? (uint64_t)aux->b : a, memory_order_release);
    }

    return NULL;
}

static void
test_acq_rel(void)
{
    pthread_t reader, writer;
    struct atomic_aux *aux = xmalloc(sizeof *aux);

    a = 0;
    aux->b = 0;

    aux->count = ATOMIC_VAR_INIT(0);
    atomic_init(&aux->data, NULL);
    aux->data64 = ATOMIC_VAR_INIT(0);

    reader = ovs_thread_create("reader", atomic_reader, aux);
    writer = ovs_thread_create("writer", atomic_writer, aux);

    xpthread_join(reader, NULL);
    xpthread_join(writer, NULL);
    free(aux);
}

static void
test_atomic_plain(void)
{
    TEST_ATOMIC_TYPE(atomic_char, char);
    TEST_ATOMIC_TYPE(atomic_uchar, unsigned char);
    TEST_ATOMIC_TYPE(atomic_schar, signed char);
    TEST_ATOMIC_TYPE(atomic_short, short);
    TEST_ATOMIC_TYPE(atomic_ushort, unsigned short);
    TEST_ATOMIC_TYPE(atomic_int, int);
    TEST_ATOMIC_TYPE(atomic_uint, unsigned int);
    TEST_ATOMIC_TYPE(atomic_long, long int);
    TEST_ATOMIC_TYPE(atomic_ulong, unsigned long int);
    TEST_ATOMIC_TYPE(atomic_llong, long long int);
    TEST_ATOMIC_TYPE(atomic_ullong, unsigned long long int);
    TEST_ATOMIC_TYPE(atomic_size_t, size_t);
    TEST_ATOMIC_TYPE(atomic_ptrdiff_t, ptrdiff_t);
    TEST_ATOMIC_TYPE(atomic_intmax_t, intmax_t);
    TEST_ATOMIC_TYPE(atomic_uintmax_t, uintmax_t);
    TEST_ATOMIC_TYPE(atomic_intptr_t, intptr_t);
    TEST_ATOMIC_TYPE(atomic_uintptr_t, uintptr_t);
    TEST_ATOMIC_TYPE(atomic_uint8_t, uint8_t);
    TEST_ATOMIC_TYPE(atomic_int8_t, int8_t);
    TEST_ATOMIC_TYPE(atomic_uint16_t, uint16_t);
    TEST_ATOMIC_TYPE(atomic_int16_t, int16_t);
    TEST_ATOMIC_TYPE(atomic_uint32_t, uint32_t);
    TEST_ATOMIC_TYPE(atomic_int32_t, int32_t);
}

static void
test_atomic_relaxed(void)
{
    TEST_ATOMIC_ORDER(memory_order_relaxed, memory_order_relaxed,
                      memory_order_relaxed);
}

static void
test_atomic_consume(void)
{
    TEST_ATOMIC_ORDER(memory_order_consume, memory_order_release,
                      memory_order_release);
}

static void
test_atomic_acquire(void)
{
    TEST_ATOMIC_ORDER(memory_order_acquire, memory_order_release,
                      memory_order_release);
}

static void
test_atomic_acq_rel(void)
{
    TEST_ATOMIC_ORDER(memory_order_acquire, memory_order_release,
                      memory_order_acq_rel);
}

static void
test_atomic_seq_cst(void)
{
    TEST_ATOMIC_ORDER(memory_order_seq_cst, memory_order_seq_cst,
                      memory_order_seq_cst);
}

static void
test_atomic_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    fatal_signal_init();
    test_atomic_plain();
    test_atomic_relaxed();
    test_atomic_consume();
    test_atomic_acquire();
    test_atomic_acq_rel();
    test_atomic_seq_cst();

    test_atomic_flag();

    test_acq_rel();
    test_cons_rel();
}

OVSTEST_REGISTER("test-atomic", test_atomic_main);
