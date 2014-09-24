/*
 * Copyright (c) 2014 Nicira, Inc.
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

/* This header implements atomic operation primitives for MSVC
 * on i586 or greater platforms (32 bit). */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

/* From msdn documentation: With Visual Studio 2003, volatile to volatile
 * references are ordered; the compiler will not re-order volatile variable
 * access. With Visual Studio 2005, the compiler also uses acquire semantics
 * for read operations on volatile variables and release semantics for write
 * operations on volatile variables (when supported by the CPU).
 *
 * Though there is no clear documentation that states that anything greater
 * than VS 2005 has the same behavior as described above, looking through MSVCs
 * C++ atomics library in VS2013 shows that the compiler still takes
 * acquire/release semantics on volatile variables. */
#define ATOMIC(TYPE) TYPE volatile

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

#define ATOMIC_BOOL_LOCK_FREE 2
#define ATOMIC_CHAR_LOCK_FREE 2
#define ATOMIC_SHORT_LOCK_FREE 2
#define ATOMIC_INT_LOCK_FREE 2
#define ATOMIC_LONG_LOCK_FREE 2
#define ATOMIC_LLONG_LOCK_FREE 2
#define ATOMIC_POINTER_LOCK_FREE 2

#define IS_LOCKLESS_ATOMIC(OBJECT)                      \
    (sizeof(OBJECT) <= 8 && IS_POW2(sizeof(OBJECT)))

#define ATOMIC_VAR_INIT(VALUE) (VALUE)
#define atomic_init(OBJECT, VALUE) (*(OBJECT) = (VALUE), (void) 0)

static inline void
atomic_compiler_barrier(memory_order order)
{
    /* In case of 'memory_order_consume', it is implicitly assumed that
     * the compiler will not move instructions that have data-dependency
     * on the variable in question before the barrier. */
    if (order > memory_order_consume) {
        _ReadWriteBarrier();
    }
}

static inline void
atomic_thread_fence(memory_order order)
{
    /* x86 is strongly ordered and acquire/release semantics come
     * automatically. */
    atomic_compiler_barrier(order);
    if (order == memory_order_seq_cst) {
        MemoryBarrier();
        atomic_compiler_barrier(order);
    }
}

static inline void
atomic_signal_fence(memory_order order)
{
    atomic_compiler_barrier(order);
}

/* 1, 2 and 4 bytes loads and stores are atomic on aligned memory. In addition,
 * since the compiler automatically takes acquire and release semantics on
 * volatile variables, for any order lesser than 'memory_order_seq_cst', we
 * can directly assign or read values. */

#define atomic_store32(DST, SRC, ORDER)                                 \
    if (ORDER == memory_order_seq_cst) {                                \
        InterlockedExchange((int32_t volatile *) (DST),                 \
                               (int32_t) (SRC));                        \
    } else {                                                            \
        *(DST) = (SRC);                                                 \
    }

/* MSVC converts 64 bit writes into two instructions. So there is
 * a possibility that an interrupt can make a 64 bit write non-atomic even
 * when 8 byte aligned. So use InterlockedExchange64().
 *
 * For atomic stores, 'consume' and 'acquire' semantics are not valid. But we
 * are using 'Exchange' to get atomic stores here and we only have
 * InterlockedExchange64(), InterlockedExchangeNoFence64() and
 * InterlockedExchange64Acquire() available. So we are forced to use
 * InterlockedExchange64() which uses full memory barrier for everything
 * greater than 'memory_order_relaxed'. */
#define atomic_store64(DST, SRC, ORDER)                                    \
    if (ORDER == memory_order_relaxed) {                                   \
        InterlockedExchangeNoFence64((int64_t volatile *) (DST),           \
                                     (int64_t) (SRC));                     \
    } else {                                                               \
        InterlockedExchange64((int64_t volatile *) (DST), (int64_t) (SRC));\
    }

/* Used for 8 and 16 bit variations. */
#define atomic_storeX(X, DST, SRC, ORDER)                               \
    if (ORDER == memory_order_seq_cst) {                                \
        InterlockedExchange##X((int##X##_t volatile *) (DST),           \
                               (int##X##_t) (SRC));                     \
    } else {                                                            \
        *(DST) = (SRC);                                                 \
    }

#define atomic_store(DST, SRC)                               \
        atomic_store_explicit(DST, SRC, memory_order_seq_cst)

#define atomic_store_explicit(DST, SRC, ORDER)                           \
    if (sizeof *(DST) == 1) {                                            \
        atomic_storeX(8, DST, SRC, ORDER)                                \
    } else if (sizeof *(DST) == 2) {                                     \
        atomic_storeX(16, DST, SRC, ORDER)                               \
    } else if (sizeof *(DST) == 4) {                                     \
        atomic_store32(DST, SRC, ORDER)                                  \
    } else if (sizeof *(DST) == 8) {                                     \
        atomic_store64(DST, SRC, ORDER)                                  \
    } else {                                                             \
        abort();                                                         \
    }

/* On x86, for 'memory_order_seq_cst', if stores are locked, the corresponding
 * reads don't need to be locked (based on the following in Intel Developers
 * manual:
 * “Locked operations are atomic with respect to all other memory operations
 * and all externally visible events. Only instruction fetch and page table
 * accesses can pass locked instructions. Locked instructions can be used to
 * synchronize data written by one processor and read by another processor.
 * For the P6 family processors, locked operations serialize all outstanding
 * load and store operations (that is, wait for them to complete). This rule
 * is also true for the Pentium 4 and Intel Xeon processors, with one
 * exception. Load operations that reference weakly ordered memory types
 * (such as the WC memory type) may not be serialized."). */

 /* For 8, 16 and 32 bit variations. */
#define atomic_readX(SRC, DST, ORDER)                                      \
    *(DST) = *(SRC);

/* MSVC converts 64 bit reads into two instructions. So there is
 * a possibility that an interrupt can make a 64 bit read non-atomic even
 * when 8 byte aligned. So use fully memory barrier InterlockedOr64(). */
#define atomic_read64(SRC, DST, ORDER)                                     \
    __pragma (warning(push))                                               \
    __pragma (warning(disable:4047))                                       \
    *(DST) = InterlockedOr64((int64_t volatile *) (SRC), 0);               \
    __pragma (warning(pop))

#define atomic_read(SRC, DST)                               \
        atomic_read_explicit(SRC, DST, memory_order_seq_cst)

#define atomic_read_explicit(SRC, DST, ORDER)                             \
    if (sizeof *(DST) == 1 || sizeof *(DST) == 2 || sizeof *(DST) == 4) { \
        atomic_readX(SRC, DST, ORDER)                                     \
    } else if (sizeof *(DST) == 8) {                                      \
        atomic_read64(SRC, DST, ORDER)                                    \
    } else {                                                              \
        abort();                                                          \
    }

/* For add, sub, and logical operations, for 8, 16 and 64 bit data types,
 * functions for all the different memory orders does not exist
 * (though documentation exists for some of them).  The MSVC C++ library which
 * implements the c11 atomics simply calls the full memory barrier function
 * for everything in x86(see xatomic.h). So do the same here. */

/* For 8, 16 and 64 bit variations. */
#define atomic_op(OP, X, RMW, ARG, ORIG, ORDER)                         \
    atomic_##OP##_generic(X, RMW, ARG, ORIG, ORDER)

/* Arithmetic addition calls. */

#define atomic_add32(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedExchangeAdd((int32_t volatile *) (RMW),   \
                                      (int32_t) (ARG));

/* For 8, 16 and 64 bit variations. */
#define atomic_add_generic(X, RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = _InterlockedExchangeAdd##X((int##X##_t volatile *) (RMW),     \
                                      (int##X##_t) (ARG));

#define atomic_add(RMW, ARG, ORIG)                               \
        atomic_add_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_add_explicit(RMW, ARG, ORIG, ORDER)             \
    if (sizeof *(RMW) == 1) {                                  \
        atomic_op(add, 8, RMW, ARG, ORIG, ORDER)               \
    } else if (sizeof *(RMW) == 2) {                           \
        atomic_op(add, 16, RMW, ARG, ORIG, ORDER)              \
    } else if (sizeof *(RMW) == 4) {                           \
        atomic_add32(RMW, ARG, ORIG, ORDER)                    \
    } else if (sizeof *(RMW) == 8) {                           \
        atomic_op(add, 64, RMW, ARG, ORIG, ORDER)              \
    } else {                                                   \
        abort();                                               \
    }

/* Arithmetic subtraction calls. */

#define atomic_sub(RMW, ARG, ORIG)                             \
        atomic_add_explicit(RMW, (0 - (ARG)), ORIG, memory_order_seq_cst)

#define atomic_sub_explicit(RMW, ARG, ORIG, ORDER)           \
        atomic_add_explicit(RMW, (0 - (ARG)), ORIG, ORDER)

/* Logical 'and' calls. */

#define atomic_and32(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedAnd((int32_t volatile *) (RMW), (int32_t) (ARG));

/* For 8, 16 and 64 bit variations. */
#define atomic_and_generic(X, RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedAnd##X((int##X##_t volatile *) (RMW),              \
                                (int##X##_t) (ARG));

#define atomic_and(RMW, ARG, ORIG)                               \
        atomic_and_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_and_explicit(RMW, ARG, ORIG, ORDER)             \
    if (sizeof *(RMW) == 1) {                                  \
        atomic_op(and, 8, RMW, ARG, ORIG, ORDER)               \
    } else if (sizeof *(RMW) == 2) {                           \
        atomic_op(and, 16, RMW, ARG, ORIG, ORDER)              \
    } else if (sizeof *(RMW) == 4) {                           \
        atomic_and32(RMW, ARG, ORIG, ORDER)                    \
    } else if (sizeof *(RMW) == 8) {                           \
        atomic_op(and, 64, RMW, ARG, ORIG, ORDER)              \
    } else {                                                   \
        abort();                                               \
    }

/* Logical 'Or' calls. */

#define atomic_or32(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedOr((int32_t volatile *) (RMW), (int32_t) (ARG));

/* For 8, 16 and 64 bit variations. */
#define atomic_or_generic(X, RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedOr##X((int##X##_t volatile *) (RMW),              \
                               (int##X##_t) (ARG));

#define atomic_or(RMW, ARG, ORIG)                               \
        atomic_or_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_or_explicit(RMW, ARG, ORIG, ORDER)              \
    if (sizeof *(RMW) == 1) {                                  \
        atomic_op(or, 8, RMW, ARG, ORIG, ORDER)                \
    } else if (sizeof *(RMW) == 2) {                           \
        atomic_op(or, 16, RMW, ARG, ORIG, ORDER)               \
    } else if (sizeof *(RMW) == 4) {                           \
        atomic_or32(RMW, ARG, ORIG, ORDER)                     \
    } else if (sizeof *(RMW) == 8) {                           \
        atomic_op(or, 64, RMW, ARG, ORIG, ORDER)               \
    } else {                                                   \
        abort();                                               \
    }

/* Logical Xor calls. */

#define atomic_xor32(RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedXor((int32_t volatile *) (RMW), (int32_t) (ARG));

/* For 8, 16 and 64 bit variations. */
#define atomic_xor_generic(X, RMW, ARG, ORIG, ORDER)                        \
    *(ORIG) = InterlockedXor##X((int##X##_t volatile *) (RMW),              \
                                (int##X##_t) (ARG));

#define atomic_xor(RMW, ARG, ORIG)                               \
        atomic_xor_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_xor_explicit(RMW, ARG, ORIG, ORDER)             \
    if (sizeof *(RMW) == 1) {                                  \
        atomic_op(xor, 8, RMW, ARG, ORIG, ORDER)               \
    } else if (sizeof *(RMW) == 2) {                           \
        atomic_op(xor, 16, RMW, ARG, ORIG, ORDER)              \
    } else if (sizeof *(RMW) == 4) {                           \
        atomic_xor32(RMW, ARG, ORIG, ORDER);                   \
    } else if (sizeof *(RMW) == 8) {                           \
        atomic_op(xor, 64, RMW, ARG, ORIG, ORDER)              \
    } else {                                                   \
        abort();                                               \
    }

#define atomic_compare_exchange_strong(DST, EXP, SRC)   \
    atomic_compare_exchange_strong_explicit(DST, EXP, SRC, \
                                            memory_order_seq_cst, \
                                            memory_order_seq_cst)

#define atomic_compare_exchange_weak atomic_compare_exchange_strong
#define atomic_compare_exchange_weak_explicit \
        atomic_compare_exchange_strong_explicit

/* MSVCs c++ compiler implements c11 atomics and looking through its
 * implementation (in xatomic.h), orders are ignored for x86 platform.
 * Do the same here. */
static inline bool
atomic_compare_exchange8(int8_t volatile *dst, int8_t *expected, int8_t src)
{
    int8_t previous = _InterlockedCompareExchange8(dst, src, *expected);
    if (previous == *expected) {
        return true;
    } else {
        *expected = previous;
        return false;
    }
}

static inline bool
atomic_compare_exchange16(int16_t volatile *dst, int16_t *expected,
                          int16_t src)
{
    int16_t previous = InterlockedCompareExchange16(dst, src, *expected);
    if (previous == *expected) {
        return true;
    } else {
        *expected = previous;
        return false;
    }
}

static inline bool
atomic_compare_exchange32(int32_t volatile *dst, int32_t *expected,
                          int32_t src)
{
    int32_t previous = InterlockedCompareExchange(dst, src, *expected);
    if (previous == *expected) {
        return true;
    } else {
        *expected = previous;
        return false;
    }
}

static inline bool
atomic_compare_exchange64(int64_t volatile *dst, int64_t *expected,
                          int64_t src)
{
    int64_t previous = InterlockedCompareExchange64(dst, src, *expected);
    if (previous == *expected) {
        return true;
    } else {
        *expected = previous;
        return false;
    }
}

static inline bool
atomic_compare_unreachable()
{
    return true;
}

#define atomic_compare_exchange_strong_explicit(DST, EXP, SRC, ORD1, ORD2)    \
    (sizeof *(DST) == 1                                                       \
     ? atomic_compare_exchange8((int8_t volatile *) (DST), (int8_t *) (EXP),  \
                                (int8_t) (SRC))                               \
     : (sizeof *(DST) == 2                                                    \
     ? atomic_compare_exchange16((int16_t volatile *) (DST),                  \
                                 (int16_t *) (EXP), (int16_t) (SRC))          \
     : (sizeof *(DST) == 4                                                    \
     ? atomic_compare_exchange32((int32_t volatile *) (DST),                  \
                                 (int32_t *) (EXP), (int32_t) (SRC))          \
     : (sizeof *(DST) == 8                                                    \
     ? atomic_compare_exchange64((int64_t volatile *) (DST),                  \
                                 (int64_t *) (EXP), (int64_t) (SRC))          \
     : ovs_fatal(0, "atomic operation with size greater than 8 bytes"),       \
       atomic_compare_unreachable()))))


/* atomic_flag */

typedef ATOMIC(int32_t) atomic_flag;
#define ATOMIC_FLAG_INIT 0

#define atomic_flag_test_and_set(FLAG)                 \
    (bool) InterlockedBitTestAndSet(FLAG, 0)

#define atomic_flag_test_and_set_explicit(FLAG, ORDER) \
        atomic_flag_test_and_set(FLAG)

#define atomic_flag_clear_explicit(FLAG, ORDER) \
        atomic_flag_clear()
#define atomic_flag_clear(FLAG)                 \
    InterlockedBitTestAndReset(FLAG, 0)
