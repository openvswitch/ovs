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

/* This header implements atomic operation primitives on GCC 4.x. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#include "ovs-atomic-locked.h"
#define OVS_ATOMIC_GCC4P_IMPL 1

#define ATOMIC(TYPE) TYPE

#define ATOMIC_BOOL_LOCK_FREE 2
#define ATOMIC_CHAR_LOCK_FREE 2
#define ATOMIC_SHORT_LOCK_FREE 2
#define ATOMIC_INT_LOCK_FREE 2
#define ATOMIC_LONG_LOCK_FREE (ULONG_MAX <= UINTPTR_MAX ? 2 : 0)
#define ATOMIC_LLONG_LOCK_FREE (ULLONG_MAX <= UINTPTR_MAX ? 2 : 0)
#define ATOMIC_POINTER_LOCK_FREE 2

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

#define IS_LOCKLESS_ATOMIC(OBJECT) (sizeof(OBJECT) <= sizeof(void *))

#define ATOMIC_VAR_INIT(VALUE) VALUE
#define atomic_init(OBJECT, VALUE) (*(OBJECT) = (VALUE), (void) 0)

static inline void
atomic_thread_fence(memory_order order)
{
    if (order != memory_order_relaxed) {
        __sync_synchronize();
    }
}

static inline void
atomic_thread_fence_if_seq_cst(memory_order order)
{
    if (order == memory_order_seq_cst) {
        __sync_synchronize();
    }
}

static inline void
atomic_signal_fence(memory_order order OVS_UNUSED)
{
    if (order != memory_order_relaxed) {
        asm volatile("" : : : "memory");
    }
}

#define atomic_is_lock_free(OBJ)                \
    ((void) *(OBJ),                             \
     IF_LOCKLESS_ATOMIC(OBJ, true, false))

#define atomic_store(DST, SRC) \
    atomic_store_explicit(DST, SRC, memory_order_seq_cst)
#define atomic_store_explicit(DST, SRC, ORDER)          \
    ({                                                  \
        typeof(DST) dst__ = (DST);                      \
        typeof(SRC) src__ = (SRC);                      \
        memory_order order__ = (ORDER);                 \
                                                        \
        if (IS_LOCKLESS_ATOMIC(*dst__)) {               \
            atomic_thread_fence(order__);               \
            *dst__ = src__;                             \
            atomic_thread_fence_if_seq_cst(order__);    \
        } else {                                        \
            atomic_store_locked(DST, SRC);              \
        }                                               \
        (void) 0;                                       \
    })
#define atomic_read(SRC, DST) \
    atomic_read_explicit(SRC, DST, memory_order_seq_cst)
#define atomic_read_explicit(SRC, DST, ORDER)           \
    ({                                                  \
        typeof(DST) dst__ = (DST);                      \
        typeof(SRC) src__ = (SRC);                      \
        memory_order order__ = (ORDER);                 \
                                                        \
        if (IS_LOCKLESS_ATOMIC(*src__)) {               \
            atomic_thread_fence_if_seq_cst(order__);    \
            *dst__ = *src__;                            \
        } else {                                        \
            atomic_read_locked(SRC, DST);               \
        }                                               \
        (void) 0;                                       \
    })

#define atomic_op__(RMW, OP, ARG, ORIG)                     \
    ({                                                      \
        typeof(RMW) rmw__ = (RMW);                          \
        typeof(ARG) arg__ = (ARG);                          \
        typeof(ORIG) orig__ = (ORIG);                       \
                                                            \
        if (IS_LOCKLESS_ATOMIC(*rmw__)) {                   \
            *orig__ = __sync_fetch_and_##OP(rmw__, arg__);  \
        } else {                                            \
            atomic_op_locked(RMW, OP, ARG, ORIG);           \
        }                                                   \
    })

#define atomic_add(RMW, ARG, ORIG) atomic_op__(RMW, add, ARG, ORIG)
#define atomic_sub(RMW, ARG, ORIG) atomic_op__(RMW, sub, ARG, ORIG)
#define atomic_or( RMW, ARG, ORIG) atomic_op__(RMW, or,  ARG, ORIG)
#define atomic_xor(RMW, ARG, ORIG) atomic_op__(RMW, xor, ARG, ORIG)
#define atomic_and(RMW, ARG, ORIG) atomic_op__(RMW, and, ARG, ORIG)

#define atomic_add_explicit(RMW, OPERAND, ORIG, ORDER)  \
    ((void) (ORDER), atomic_add(RMW, OPERAND, ORIG))
#define atomic_sub_explicit(RMW, OPERAND, ORIG, ORDER)  \
    ((void) (ORDER), atomic_sub(RMW, OPERAND, ORIG))
#define atomic_or_explicit(RMW, OPERAND, ORIG, ORDER)   \
    ((void) (ORDER), atomic_or(RMW, OPERAND, ORIG))
#define atomic_xor_explicit(RMW, OPERAND, ORIG, ORDER)  \
    ((void) (ORDER), atomic_xor(RMW, OPERAND, ORIG))
#define atomic_and_explicit(RMW, OPERAND, ORIG, ORDER)  \
    ((void) (ORDER), atomic_and(RMW, OPERAND, ORIG))

/* atomic_flag */

typedef struct {
    int b;
} atomic_flag;
#define ATOMIC_FLAG_INIT { false }

static inline bool
atomic_flag_test_and_set(volatile atomic_flag *object)
{
    return __sync_lock_test_and_set(&object->b, 1);
}

static inline bool
atomic_flag_test_and_set_explicit(volatile atomic_flag *object,
                                  memory_order order OVS_UNUSED)
{
    return atomic_flag_test_and_set(object);
}

static inline void
atomic_flag_clear(volatile atomic_flag *object)
{
    __sync_lock_release(&object->b);
}

static inline void
atomic_flag_clear_explicit(volatile atomic_flag *object,
                           memory_order order OVS_UNUSED)
{
    atomic_flag_clear(object);
}
