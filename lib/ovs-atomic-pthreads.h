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

/* This header implements atomic operation primitives using pthreads. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#include "ovs-atomic-locked.h"

#define OVS_ATOMIC_PTHREADS_IMPL 1

#define ATOMIC(TYPE) TYPE

#define ATOMIC_BOOL_LOCK_FREE 0
#define ATOMIC_CHAR_LOCK_FREE 0
#define ATOMIC_SHORT_LOCK_FREE 0
#define ATOMIC_INT_LOCK_FREE 0
#define ATOMIC_LONG_LOCK_FREE 0
#define ATOMIC_LLONG_LOCK_FREE 0
#define ATOMIC_POINTER_LOCK_FREE 0

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

#define ATOMIC_VAR_INIT(VALUE) (VALUE)
#define atomic_init(OBJECT, VALUE) (*(OBJECT) = (VALUE), (void) 0)

static inline void
atomic_thread_fence(memory_order order OVS_UNUSED)
{
    /* Nothing to do. */
}

static inline void
atomic_signal_fence(memory_order order OVS_UNUSED)
{
    /* Nothing to do. */
}

#define atomic_is_lock_free(OBJ) false

#define atomic_store(DST, SRC) atomic_store_locked(DST, SRC)
#define atomic_store_explicit(DST, SRC, ORDER) \
    ((void) (ORDER), atomic_store(DST, SRC))

#define atomic_read(SRC, DST) atomic_read_locked(SRC, DST)
#define atomic_read_explicit(SRC, DST, ORDER)   \
    ((void) (ORDER), atomic_read(SRC, DST))

#define atomic_add(RMW, ARG, ORIG) atomic_op_locked(RMW, add, ARG, ORIG)
#define atomic_sub(RMW, ARG, ORIG) atomic_op_locked(RMW, sub, ARG, ORIG)
#define atomic_or( RMW, ARG, ORIG) atomic_op_locked(RMW, or, ARG, ORIG)
#define atomic_xor(RMW, ARG, ORIG) atomic_op_locked(RMW, xor, ARG, ORIG)
#define atomic_and(RMW, ARG, ORIG) atomic_op_locked(RMW, and, ARG, ORIG)

#define atomic_add_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_add(RMW, ARG, ORIG))
#define atomic_sub_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_sub(RMW, ARG, ORIG))
#define atomic_or_explicit(RMW, ARG, ORIG, ORDER)   \
    ((void) (ORDER), atomic_or(RMW, ARG, ORIG))
#define atomic_xor_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_xor(RMW, ARG, ORIG))
#define atomic_and_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_and(RMW, ARG, ORIG))

/* atomic_flag */

typedef struct {
    bool b;
} atomic_flag;
#define ATOMIC_FLAG_INIT { false }

static inline bool
atomic_flag_test_and_set(volatile atomic_flag *flag_)
{
    atomic_flag *flag = CONST_CAST(atomic_flag *, flag_);
    bool old_value;

    atomic_lock__(flag);
    old_value = flag->b;
    flag->b = true;
    atomic_unlock__(flag);

    return old_value;
}

static inline bool
atomic_flag_test_and_set_explicit(volatile atomic_flag *flag,
                                  memory_order order OVS_UNUSED)
{
    return atomic_flag_test_and_set(flag);
}

static inline void
atomic_flag_clear(volatile atomic_flag *flag_)
{
    atomic_flag *flag = CONST_CAST(atomic_flag *, flag_);

    atomic_lock__(flag);
    flag->b = false;
    atomic_unlock__(flag);
}

static inline void
atomic_flag_clear_explicit(volatile atomic_flag *flag,
                           memory_order order OVS_UNUSED)
{
    atomic_flag_clear(flag);
}
