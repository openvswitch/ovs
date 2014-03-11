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

/* This header implements atomic operation primitives on GCC 4.7 and later. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#define ATOMIC(TYPE) TYPE

typedef enum {
    memory_order_relaxed = __ATOMIC_RELAXED,
    memory_order_consume = __ATOMIC_CONSUME,
    memory_order_acquire = __ATOMIC_ACQUIRE,
    memory_order_release = __ATOMIC_RELEASE,
    memory_order_acq_rel = __ATOMIC_ACQ_REL,
    memory_order_seq_cst = __ATOMIC_SEQ_CST
} memory_order;

#define ATOMIC_VAR_INIT(VALUE) (VALUE)
#define atomic_init(OBJECT, VALUE) (*(OBJECT) = (VALUE), (void) 0)

#define atomic_thread_fence __atomic_thread_fence
#define atomic_signal_fence __atomic_signal_fence
#define atomic_is_lock_free __atomic_is_lock_free

#define atomic_store(DST, SRC) \
    atomic_store_explicit(DST, SRC, memory_order_seq_cst)
#define atomic_store_explicit __atomic_store_n

#define atomic_read(SRC, DST) \
    atomic_read_explicit(SRC, DST, memory_order_seq_cst)
#define atomic_read_explicit(SRC, DST, ORDER)   \
    (*(DST) = __atomic_load_n(SRC, ORDER),      \
     (void) 0)

#define atomic_add(RMW, OPERAND, ORIG) \
        atomic_add_explicit(RMW, OPERAND, ORIG, memory_order_seq_cst)
#define atomic_sub(RMW, OPERAND, ORIG) \
        atomic_sub_explicit(RMW, OPERAND, ORIG, memory_order_seq_cst)
#define atomic_or(RMW, OPERAND, ORIG) \
        atomic_or_explicit(RMW, OPERAND, ORIG, memory_order_seq_cst)
#define atomic_xor(RMW, OPERAND, ORIG) \
        atomic_xor_explicit(RMW, OPERAND, ORIG, memory_order_seq_cst)
#define atomic_and(RMW, OPERAND, ORIG) \
        atomic_and_explicit(RMW, OPERAND, ORIG, memory_order_seq_cst)

#define atomic_add_explicit(RMW, OPERAND, ORIG, ORDER)  \
    (*(ORIG) = __atomic_fetch_add(RMW, OPERAND, ORDER), (void) 0)
#define atomic_sub_explicit(RMW, OPERAND, ORIG, ORDER)  \
    (*(ORIG) = __atomic_fetch_sub(RMW, OPERAND, ORDER), (void) 0)
#define atomic_or_explicit(RMW, OPERAND, ORIG, ORDER)  \
    (*(ORIG) = __atomic_fetch_or(RMW, OPERAND, ORDER), (void) 0)
#define atomic_xor_explicit(RMW, OPERAND, ORIG, ORDER)  \
    (*(ORIG) = __atomic_fetch_xor(RMW, OPERAND, ORDER), (void) 0)
#define atomic_and_explicit(RMW, OPERAND, ORIG, ORDER)  \
    (*(ORIG) = __atomic_fetch_and(RMW, OPERAND, ORDER), (void) 0)

#include "ovs-atomic-flag-gcc4.7+.h"
