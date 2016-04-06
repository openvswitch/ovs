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
 *
 *     (*) Not specified by C11.
 *
 * Atomic types may also be obtained via ATOMIC(TYPE), e.g. ATOMIC(void *).
 * Only basic integer types and pointer types can be made atomic this way,
 * e.g. atomic structs are not supported.
 *
 * The atomic version of a type doesn't necessarily have the same size or
 * representation as the ordinary version; for example, atomic_int might be a
 * typedef for a struct.  The range of an atomic type does match the range of
 * the corresponding ordinary type.
 *
 * C11 says that one may use the _Atomic keyword in place of the typedef name,
 * e.g. "_Atomic int" instead of "atomic_int".  This library doesn't support
 * that.
 *
 *
 * Life Cycle
 * ==========
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
 *        Only atomicity is provided, does not imply any memory ordering with
 *        respect to any other variable (atomic or not).  Relaxed accesses to
 *        the same atomic variable will be performed in the program order.
 *        The compiler and CPU are free to move memory accesses to other
 *        variables past the atomic operation.
 *
 *    memory_order_consume:
 *
 *        Memory accesses with data dependency on the result of the consume
 *        operation (atomic_read_explicit, or a load operation preceding a
 *        atomic_thread_fence) will not be moved prior to the consume
 *        barrier.  Non-data-dependent loads and stores can be reordered to
 *        happen before the consume barrier.
 *
 *        RCU is the prime example of the use of the consume barrier: The
 *        consume barrier guarantees that reads from a RCU protected object
 *        are performed after the RCU protected pointer is read.  A
 *        corresponding release barrier is used to store the modified RCU
 *        protected pointer after the RCU protected object has been fully
 *        constructed.  The synchronization between these barriers prevents
 *        the RCU "consumer" from seeing uninitialized data.
 *
 *        May not be used with atomic_store_explicit(), as consume semantics
 *        applies only to atomic loads.
 *
 *    memory_order_acquire:
 *
 *        Memory accesses after an acquire barrier cannot be moved before the
 *        barrier.  Memory accesses before an acquire barrier *can* be moved
 *        after it.
 *
 *        An atomic_thread_fence with memory_order_acquire does not have a
 *        load operation by itself; it prevents all following memory accesses
 *        from moving prior to preceding loads.
 *
 *        May not be used with atomic_store_explicit(), as acquire semantics
 *        applies only to atomic loads.
 *
 *    memory_order_release:
 *
 *        Memory accesses before a release barrier cannot be moved after the
 *        barrier.  Memory accesses after a release barrier *can* be moved
 *        before it.
 *
 *        An atomic_thread_fence with memory_order_release does not have a
 *        store operation by itself; it prevents all preceding memory accesses
 *        from moving past subsequent stores.
 *
 *        May not be used with atomic_read_explicit(), as release semantics
 *        applies only to atomic stores.
 *
 *    memory_order_acq_rel:
 *
 *        Memory accesses cannot be moved across an acquire-release barrier in
 *        either direction.
 *
 *        May only be used with atomic read-modify-write operations, as both
 *        load and store operation is required for acquire-release semantics.
 *
 *        An atomic_thread_fence with memory_order_acq_rel does not have
 *        either load or store operation by itself; it prevents all following
 *        memory accesses from moving prior to preceding loads and all
 *        preceding memory accesses from moving past subsequent stores.
 *
 *    memory_order_seq_cst:
 *
 *        Prevents movement of memory accesses like an acquire-release barrier,
 *        but whereas acquire-release synchronizes cooperating threads (using
 *        the same atomic variable), sequential-consistency synchronizes the
 *        whole system, providing a total order for stores on all atomic
 *        variables.
 *
 * OVS atomics require the memory_order to be passed as a compile-time constant
 * value, as some compiler implementations may perform poorly if the memory
 * order parameter is passed in as a run-time value.
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
 * The "store" and "compare_exchange" primitives match C11:
 *
 *     void atomic_store(A *object, C value);
 *     void atomic_store_explicit(A *object, C value, memory_order);
 *
 *         Atomically stores 'value' into '*object', respecting the given
 *         memory order (or memory_order_seq_cst for atomic_store()).
 *
 *     bool atomic_compare_exchange_strong(A *object, C *expected, C desired);
 *     bool atomic_compare_exchange_weak(A *object, C *expected, C desired);
 *     bool atomic_compare_exchange_strong_explicit(A *object, C *expected,
 *                                                  C desired,
 *                                                  memory_order success,
 *                                                  memory_order failure);
 *     bool atomic_compare_exchange_weak_explicit(A *object, C *expected,
 *                                                  C desired,
 *                                                  memory_order success,
 *                                                  memory_order failure);
 *
 *         Atomically loads '*object' and compares it with '*expected' and if
 *         equal, stores 'desired' into '*object' (an atomic read-modify-write
 *         operation) and returns true, and if non-equal, stores the actual
 *         value of '*object' into '*expected' (an atomic load operation) and
 *         returns false.  The memory order for the successful case (atomic
 *         read-modify-write operation) is 'success', and for the unsuccessful
 *         case (atomic load operation) 'failure'.  'failure' may not be
 *         stronger than 'success'.
 *
 *         The weak forms may fail (returning false) also when '*object' equals
 *         '*expected'.  The strong form can be implemented by the weak form in
 *         a loop.  Some platforms can implement the weak form more
 *         efficiently, so it should be used if the application will need to
 *         loop anyway.
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
 *
 * Life Cycle
 * ----------
 *
 * ATOMIC_FLAG_INIT is an initializer for atomic_flag.  The initial state is
 * "clear".
 *
 * An atomic_flag may also be initialized at runtime with atomic_flag_clear().
 *
 *
 * Operations
 * ----------
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
    #elif __has_extension(c_atomic)
        #include "ovs-atomic-clang.h"
    #elif HAVE_STDATOMIC_H
        #include "ovs-atomic-c11.h"
    #elif __GNUC__ >= 4 && __GNUC_MINOR__ >= 7
        #include "ovs-atomic-gcc4.7+.h"
    #elif __GNUC__ && defined(__x86_64__)
        #include "ovs-atomic-x86_64.h"
    #elif __GNUC__ && defined(__i386__)
        #include "ovs-atomic-i586.h"
    #elif HAVE_GCC4_ATOMICS
        #include "ovs-atomic-gcc4+.h"
    #elif _MSC_VER && _M_IX86 >= 500
        #include "ovs-atomic-msvc.h"
    #else
        /* ovs-atomic-pthreads implementation is provided for portability.
         * It might be too slow for real use because Open vSwitch is
         * optimized for platforms where real atomic ops are available. */
        #include "ovs-atomic-pthreads.h"
    #endif
#undef IN_OVS_ATOMIC_H

#ifndef OMIT_STANDARD_ATOMIC_TYPES
typedef ATOMIC(bool)               atomic_bool;

typedef ATOMIC(char)               atomic_char;
typedef ATOMIC(signed char)        atomic_schar;
typedef ATOMIC(unsigned char)      atomic_uchar;

typedef ATOMIC(short)              atomic_short;
typedef ATOMIC(unsigned short)     atomic_ushort;

typedef ATOMIC(int)                atomic_int;
typedef ATOMIC(unsigned int)       atomic_uint;

typedef ATOMIC(long)               atomic_long;
typedef ATOMIC(unsigned long)      atomic_ulong;

typedef ATOMIC(long long)          atomic_llong;
typedef ATOMIC(unsigned long long) atomic_ullong;

typedef ATOMIC(size_t)             atomic_size_t;
typedef ATOMIC(ptrdiff_t)          atomic_ptrdiff_t;

typedef ATOMIC(intmax_t)           atomic_intmax_t;
typedef ATOMIC(uintmax_t)          atomic_uintmax_t;

typedef ATOMIC(intptr_t)           atomic_intptr_t;
typedef ATOMIC(uintptr_t)          atomic_uintptr_t;
#endif  /* !OMIT_STANDARD_ATOMIC_TYPES */

/* Nonstandard atomic types. */
typedef ATOMIC(uint8_t)   atomic_uint8_t;
typedef ATOMIC(uint16_t)  atomic_uint16_t;
typedef ATOMIC(uint32_t)  atomic_uint32_t;

typedef ATOMIC(int8_t)    atomic_int8_t;
typedef ATOMIC(int16_t)   atomic_int16_t;
typedef ATOMIC(int32_t)   atomic_int32_t;

/* Relaxed atomic operations.
 *
 * When an operation on an atomic variable is not expected to synchronize
 * with operations on other (atomic or non-atomic) variables, no memory
 * barriers are needed and the relaxed memory ordering can be used.  These
 * macros make such uses less daunting, but not invisible. */
#define atomic_store_relaxed(VAR, VALUE)                        \
    atomic_store_explicit(VAR, VALUE, memory_order_relaxed)
#define atomic_read_relaxed(VAR, DST)                                   \
    atomic_read_explicit(VAR, DST, memory_order_relaxed)
#define atomic_compare_exchange_strong_relaxed(DST, EXP, SRC)     \
    atomic_compare_exchange_strong_explicit(DST, EXP, SRC,        \
                                            memory_order_relaxed, \
                                            memory_order_relaxed)
#define atomic_compare_exchange_weak_relaxed(DST, EXP, SRC)       \
    atomic_compare_exchange_weak_explicit(DST, EXP, SRC,          \
                                          memory_order_relaxed,   \
                                          memory_order_relaxed)
#define atomic_add_relaxed(RMW, ARG, ORIG)                              \
    atomic_add_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_sub_relaxed(RMW, ARG, ORIG)                              \
    atomic_sub_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_or_relaxed(RMW, ARG, ORIG)                               \
    atomic_or_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_xor_relaxed(RMW, ARG, ORIG)                              \
    atomic_xor_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_and_relaxed(RMW, ARG, ORIG)                              \
    atomic_and_explicit(RMW, ARG, ORIG, memory_order_relaxed)
#define atomic_flag_test_and_set_relaxed(FLAG)                          \
    atomic_flag_test_and_set_explicit(FLAG, memory_order_relaxed)
#define atomic_flag_clear_relaxed(FLAG)                         \
    atomic_flag_clear_explicit(FLAG, memory_order_relaxed)

/* A simplified atomic count.  Does not provide any synchronization with any
 * other variables.
 *
 * Typically a counter is not used to synchronize the state of any other
 * variables (with the notable exception of reference count, below).
 * This abstraction releaves the user from the memory order considerations,
 * and may make the code easier to read.
 *
 * We only support the unsigned int counters, as those are the most common. */
typedef struct atomic_count {
    atomic_uint count;
} atomic_count;

#define ATOMIC_COUNT_INIT(VALUE) { VALUE }

static inline void
atomic_count_init(atomic_count *count, unsigned int value)
{
    atomic_init(&count->count, value);
}

static inline unsigned int
atomic_count_inc(atomic_count *count)
{
    unsigned int old;

    atomic_add_relaxed(&count->count, 1, &old);

    return old;
}

static inline unsigned int
atomic_count_dec(atomic_count *count)
{
    unsigned int old;

    atomic_sub_relaxed(&count->count, 1, &old);

    return old;
}

static inline unsigned int
atomic_count_get(atomic_count *count)
{
    unsigned int value;

    atomic_read_relaxed(&count->count, &value);

    return value;
}

static inline void
atomic_count_set(atomic_count *count, unsigned int value)
{
    atomic_store_relaxed(&count->count, value);
}

/* Reference count. */
struct ovs_refcount {
    atomic_uint count;
};

/* Initializes 'refcount'.  The reference count is initially 1. */
static inline void
ovs_refcount_init(struct ovs_refcount *refcount)
{
    atomic_init(&refcount->count, 1);
}

/* Increments 'refcount'.
 *
 * Does not provide a memory barrier, as the calling thread must have
 * protected access to the object already. */
static inline void
ovs_refcount_ref(struct ovs_refcount *refcount)
{
    unsigned int old_refcount;

    atomic_add_explicit(&refcount->count, 1, &old_refcount,
                        memory_order_relaxed);
    ovs_assert(old_refcount > 0);
}

/* Decrements 'refcount' and returns the previous reference count.  Often used
 * in this form:
 *
 * if (ovs_refcount_unref(&object->ref_cnt) == 1) {
 *     // ...uninitialize object...
 *     free(object);
 * }
 *
 * Provides a release barrier making the preceding loads and stores to not be
 * reordered after the unref, and in case of the last reference provides also
 * an acquire barrier to keep all the following uninitialization from being
 * reordered before the atomic decrement operation.  Together these synchronize
 * any concurrent unref operations between each other. */
static inline unsigned int
ovs_refcount_unref(struct ovs_refcount *refcount)
{
    unsigned int old_refcount;

    atomic_sub_explicit(&refcount->count, 1, &old_refcount,
                        memory_order_release);
    ovs_assert(old_refcount > 0);
    if (old_refcount == 1) {
        /* 'memory_order_release' above means that there are no (reordered)
         * accesses to the protected object from any thread at this point.
         * An acquire barrier is needed to keep all subsequent access to the
         * object's memory from being reordered before the atomic operation
         * above. */
        atomic_thread_fence(memory_order_acquire);
    }
    return old_refcount;
}

/* Reads and returns 'refcount_''s current reference count.
 *
 * Does not provide a memory barrier.
 *
 * Rarely useful. */
static inline unsigned int
ovs_refcount_read(const struct ovs_refcount *refcount_)
{
    struct ovs_refcount *refcount
        = CONST_CAST(struct ovs_refcount *, refcount_);
    unsigned int count;

    atomic_read_explicit(&refcount->count, &count, memory_order_relaxed);
    return count;
}

/* Increments 'refcount', but only if it is non-zero.
 *
 * This may only be called for an object which is RCU protected during
 * this call.  This implies that its possible destruction is postponed
 * until all current RCU threads quiesce.
 *
 * Returns false if the refcount was zero.  In this case the object may
 * be safely accessed until the current thread quiesces, but no additional
 * references to the object may be taken.
 *
 * Does not provide a memory barrier, as the calling thread must have
 * RCU protected access to the object already.
 *
 * It is critical that we never increment a zero refcount to a
 * non-zero value, as whenever a refcount reaches the zero value, the
 * protected object may be irrevocably scheduled for deletion. */
static inline bool
ovs_refcount_try_ref_rcu(struct ovs_refcount *refcount)
{
    unsigned int count;

    atomic_read_explicit(&refcount->count, &count, memory_order_relaxed);
    do {
        if (count == 0) {
            return false;
        }
    } while (!atomic_compare_exchange_weak_explicit(&refcount->count, &count,
                                                    count + 1,
                                                    memory_order_relaxed,
                                                    memory_order_relaxed));
    return true;
}

/* Decrements 'refcount' and returns the previous reference count.  To
 * be used only when a memory barrier is already provided for the
 * protected object independently.
 *
 * For example:
 *
 * if (ovs_refcount_unref_relaxed(&object->ref_cnt) == 1) {
 *     // Schedule uninitialization and freeing of the object:
 *     ovsrcu_postpone(destructor_function, object);
 * }
 *
 * Here RCU quiescing already provides a full memory barrier.  No additional
 * barriers are needed here.
 *
 * Or:
 *
 * if (stp && ovs_refcount_unref_relaxed(&stp->ref_cnt) == 1) {
 *     ovs_mutex_lock(&mutex);
 *     ovs_list_remove(&stp->node);
 *     ovs_mutex_unlock(&mutex);
 *     free(stp->name);
 *     free(stp);
 * }
 *
 * Here a mutex is used to guard access to all of 'stp' apart from
 * 'ref_cnt'.  Hence all changes to 'stp' by other threads must be
 * visible when we get the mutex, and no access after the unlock can
 * be reordered to happen prior the lock operation.  No additional
 * barriers are needed here.
 */
static inline unsigned int
ovs_refcount_unref_relaxed(struct ovs_refcount *refcount)
{
    unsigned int old_refcount;

    atomic_sub_explicit(&refcount->count, 1, &old_refcount,
                        memory_order_relaxed);
    ovs_assert(old_refcount > 0);
    return old_refcount;
}

#endif /* ovs-atomic.h */
