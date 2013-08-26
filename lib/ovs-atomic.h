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

#ifndef OVS_ATOMIC_H
#define OVS_ATOMIC_H 1

/* Atomic operations.
 *
 * This library implements atomic operations with an API based on the one
 * defined in C11.  It includes multiple implementations for compilers and
 * libraries with varying degrees of built-in support for C11, including a
 * fallback implementation for systems that have pthreads but no other support
 * for atomics.
 *
 * This comment describes the common features of all the implementations.
 *
 *
 * Types
 * =====
 *
 * The following atomic types are supported as typedefs for atomic versions of
 * the listed ordinary types:
 *
 *     ordinary type            atomic version
 *     -------------------      ----------------------
 *     bool                     atomic_bool
 *
 *     char                     atomic_char
 *     signed char              atomic_schar
 *     unsigned char            atomic_uchar
 *
 *     short                    atomic_short
 *     unsigned short           atomic_ushort
 *
 *     int                      atomic_int
 *     unsigned int             atomic_uint
 *
 *     long                     atomic_long
 *     unsigned long            atomic_ulong
 *
 *     long long                atomic_llong
 *     unsigned long long       atomic_ullong
 *
 *     size_t                   atomic_size_t
 *     ptrdiff_t                atomic_ptrdiff_t
 *
 *     intmax_t                 atomic_intmax_t
 *     uintmax_t                atomic_uintmax_t
 *
 *     intptr_t                 atomic_intptr_t
 *     uintptr_t                atomic_uintptr_t
 *
 *     uint8_t                  atomic_uint8_t     (*)
 *     uint16_t                 atomic_uint16_t    (*)
 *     uint32_t                 atomic_uint32_t    (*)
 *     int8_t                   atomic_int8_t      (*)
 *     int16_t                  atomic_int16_t     (*)
 *     int32_t                  atomic_int32_t     (*)
 *     uint64_t                 atomic_uint64_t    (*)
 *     int64_t                  atomic_int64_t     (*)
 *
 *     (*) Not specified by C11.
 *
 * The atomic version of a type doesn't necessarily have the same size or
 * representation as the ordinary version; for example, atomic_int might be a
 * typedef for a struct that also includes a mutex.  The range of an atomic
 * type does match the range of the corresponding ordinary type.
 *
 * C11 says that one may use the _Atomic keyword in place of the typedef name,
 * e.g. "_Atomic int" instead of "atomic_int".  This library doesn't support
 * that.
 *
 *
 * Initialization
 * ==============
 *
 * To initialize an atomic variable at its point of definition, use
 * ATOMIC_VAR_INIT:
 *
 *     static atomic_int ai = ATOMIC_VAR_INIT(123);
 *
 * To initialize an atomic variable in code, use atomic_init():
 *
 *     static atomic_int ai;
 * ...
 *     atomic_init(&ai, 123);
 *
 *
 * Barriers
 * ========
 *
 * enum memory_order specifies the strictness of a memory barrier.  It has the
 * following values:
 *
 *    memory_order_relaxed:
 *
 *        Compiler barrier only.  Does not imply any CPU memory ordering.
 *
 *    memory_order_acquire:
 *
 *        Memory accesses after an acquire barrier cannot be moved before the
 *        barrier.  Memory accesses before an acquire barrier *can* be moved
 *        after it.
 *
 *    memory_order_release:
 *
 *        Memory accesses before a release barrier cannot be moved after the
 *        barrier.  Memory accesses after a release barrier *can* be moved
 *        before it.
 *
 *    memory_order_acq_rel:
 *
 *        Memory accesses cannot be moved across an acquire-release barrier in
 *        either direction.
 *
 *    memory_order_seq_cst:
 *
 *        Prevents movement of memory accesses like an acquire-release barrier,
 *        but whereas acquire-release synchronizes cooperating threads,
 *        sequential-consistency synchronizes the whole system.
 *
 *    memory_order_consume:
 *
 *        A slight relaxation of memory_order_acquire.
 *
 * The following functions insert explicit barriers.  Most of the other atomic
 * functions also include barriers.
 *
 *     void atomic_thread_fence(memory_order order);
 *
 *         Inserts a barrier of the specified type.
 *
 *         For memory_order_relaxed, this is a no-op.
 *
 *     void atomic_signal_fence(memory_order order);
 *
 *         Inserts a barrier of the specified type, but only with respect to
 *         signal handlers in the same thread as the barrier.  This is
 *         basically a compiler optimization barrier, except for
 *         memory_order_relaxed, which is a no-op.
 *
 *
 * Atomic Operations
 * =================
 *
 * In this section, A is an atomic type and C is the corresponding non-atomic
 * type.
 *
 * The "store" primitives match C11:
 *
 *     void atomic_store(A *object, C value);
 *     void atomic_store_explicit(A *object, C value, memory_order);
 *
 *         Atomically stores 'value' into '*object', respecting the given
 *         memory order (or memory_order_seq_cst for atomic_store()).
 *
 * The following primitives differ from the C11 ones (and have different names)
 * because there does not appear to be a way to implement the standard
 * primitives in standard C:
 *
 *     void atomic_read(A *src, C *dst);
 *     void atomic_read_explicit(A *src, C *dst, memory_order);
 *
 *         Atomically loads a value from 'src', writing the value read into
 *         '*dst', respecting the given memory order (or memory_order_seq_cst
 *         for atomic_read()).
 *
 *     void atomic_add(A *rmw, C arg, C *orig);
 *     void atomic_sub(A *rmw, C arg, C *orig);
 *     void atomic_or(A *rmw, C arg, C *orig);
 *     void atomic_xor(A *rmw, C arg, C *orig);
 *     void atomic_and(A *rmw, C arg, C *orig);
 *     void atomic_add_explicit(A *rmw, C arg, C *orig, memory_order);
 *     void atomic_sub_explicit(A *rmw, C arg, C *orig, memory_order);
 *     void atomic_or_explicit(A *rmw, C arg, C *orig, memory_order);
 *     void atomic_xor_explicit(A *rmw, C arg, C *orig, memory_order);
 *     void atomic_and_explicit(A *rmw, C arg, C *orig, memory_order);
 *
 *         Atomically applies the given operation, with 'arg' as the second
 *         operand, to '*rmw', and stores the original value of '*rmw' into
 *         '*orig', respecting the given memory order (or memory_order_seq_cst
 *         if none is specified).
 *
 *         The results are similar to those that would be obtained with +=, -=,
 *         |=, ^=, or |= on non-atomic types.
 *
 *
 * atomic_flag
 * ===========
 *
 * atomic_flag is a typedef for a type with two states, set and clear, that
 * provides atomic test-and-set functionality.
 *
 * ATOMIC_FLAG_INIT is an initializer for atomic_flag.  The initial state is
 * "clear".
 *
 * The following functions are available.
 *
 *     bool atomic_flag_test_and_set(atomic_flag *object)
 *     bool atomic_flag_test_and_set_explicit(atomic_flag *object,
 *                                            memory_order);
 *
 *         Atomically sets '*object', respsecting the given memory order (or
 *         memory_order_seq_cst for atomic_flag_test_and_set()).  Returns the
 *         previous value of the flag (false for clear, true for set).
 *
 *     void atomic_flag_clear(atomic_flag *object);
 *     void atomic_flag_clear_explicit(atomic_flag *object, memory_order);
 *
 *         Atomically clears '*object', respecting the given memory order (or
 *         memory_order_seq_cst for atomic_flag_clear()).
 */

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "compiler.h"
#include "util.h"

#define IN_OVS_ATOMIC_H
    #if __CHECKER__
        /* sparse doesn't understand some GCC extensions we use. */
        #include "ovs-atomic-pthreads.h"
    #elif HAVE_STDATOMIC_H
        #include "ovs-atomic-c11.h"
    #elif __has_extension(c_atomic)
        #include "ovs-atomic-clang.h"
    #elif __GNUC__ >= 4 && __GNUC_MINOR__ >= 7
        #include "ovs-atomic-gcc4.7+.h"
    #elif HAVE_GCC4_ATOMICS
        #include "ovs-atomic-gcc4+.h"
    #else
        #include "ovs-atomic-pthreads.h"
    #endif
#undef IN_OVS_ATOMIC_H

#endif /* ovs-atomic.h */
