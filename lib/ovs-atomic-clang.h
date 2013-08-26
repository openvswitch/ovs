/*
 * Copyright (c) 2013 Nicira, Inc.
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

/* This header implements atomic operation primitives on Clang. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#define OVS_ATOMIC_CLANG_IMPL 1

/* Standard atomic types. */
typedef _Atomic(_Bool) atomic_bool;

typedef _Atomic(char) atomic_char;
typedef _Atomic(signed char) atomic_schar;
typedef _Atomic(unsigned char) atomic_uchar;

typedef _Atomic(short) atomic_short;
typedef _Atomic(unsigned short) atomic_ushort;

typedef _Atomic(int) atomic_int;
typedef _Atomic(unsigned int) atomic_uint;

typedef _Atomic(long) atomic_long;
typedef _Atomic(unsigned long) atomic_ulong;

typedef _Atomic(long long) atomic_llong;
typedef _Atomic(unsigned long long) atomic_ullong;

typedef _Atomic(size_t) atomic_size_t;
typedef _Atomic(ptrdiff_t) atomic_ptrdiff_t;

typedef _Atomic(intmax_t) atomic_intmax_t;
typedef _Atomic(uintmax_t) atomic_uintmax_t;

typedef _Atomic(intptr_t) atomic_intptr_t;
typedef _Atomic(uintptr_t) atomic_uintptr_t;

/* Nonstandard atomic types. */
typedef _Atomic(uint8_t)   atomic_uint8_t;
typedef _Atomic(uint16_t)  atomic_uint16_t;
typedef _Atomic(uint32_t)  atomic_uint32_t;
typedef _Atomic(uint64_t)  atomic_uint64_t;

typedef _Atomic(int8_t)    atomic_int8_t;
typedef _Atomic(int16_t)   atomic_int16_t;
typedef _Atomic(int32_t)   atomic_int32_t;
typedef _Atomic(int64_t)   atomic_int64_t;

#define ATOMIC_VAR_INIT(VALUE) (VALUE)

#define atomic_init(OBJECT, VALUE) __c11_atomic_init(OBJECT, VALUE)

/* Clang hard-codes these exact values internally but does not appear to
 * export any names for them. */
typedef enum {
    memory_order_relaxed = 0,
    memory_order_consume = 1,
    memory_order_acquire = 2,
    memory_order_release = 3,
    memory_order_acq_rel = 4,
    memory_order_seq_cst = 5
} memory_order;

#define atomic_thread_fence(ORDER) __c11_atomic_thread_fence(ORDER)
#define atomic_signal_fence(ORDER) __c11_atomic_signal_fence(ORDER)

#define atomic_store(DST, SRC) \
    atomic_store_explicit(DST, SRC, memory_order_seq_cst)
#define atomic_store_explicit(DST, SRC, ORDER) \
    __c11_atomic_store(DST, SRC, ORDER)


#define atomic_read(SRC, DST) \
    atomic_read_explicit(SRC, DST, memory_order_seq_cst)
#define atomic_read_explicit(SRC, DST, ORDER)   \
    (*(DST) = __c11_atomic_load(SRC, ORDER), \
     (void) 0)

#define atomic_add(RMW, ARG, ORIG) \
    atomic_add_explicit(RMW, ARG, ORIG, memory_order_seq_cst)
#define atomic_sub(RMW, ARG, ORIG) \
    atomic_sub_explicit(RMW, ARG, ORIG, memory_order_seq_cst)
#define atomic_or(RMW, ARG, ORIG) \
    atomic_or_explicit(RMW, ARG, ORIG, memory_order_seq_cst)
#define atomic_xor(RMW, ARG, ORIG) \
    atomic_xor_explicit(RMW, ARG, ORIG, memory_order_seq_cst)
#define atomic_and(RMW, ARG, ORIG) \
    atomic_and_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_add_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = __c11_atomic_fetch_add(RMW, ARG, ORDER), (void) 0)
#define atomic_sub_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = __c11_atomic_fetch_sub(RMW, ARG, ORDER), (void) 0)
#define atomic_or_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = __c11_atomic_fetch_or(RMW, ARG, ORDER), (void) 0)
#define atomic_xor_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = __c11_atomic_fetch_xor(RMW, ARG, ORDER), (void) 0)
#define atomic_and_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = __c11_atomic_fetch_and(RMW, ARG, ORDER), (void) 0)

#include "ovs-atomic-flag-gcc4.7+.h"
