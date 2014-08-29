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

/* This header implements atomic operation primitives on x86_64 with GCC. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#define OVS_ATOMIC_X86_64_IMPL 1

/*
 * x86_64 Memory model (http://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.html):
 *
 * - 1, 2, 4, and 8 byte loads and stores are atomic on aligned memory.
 * - Loads are not reordered with other loads.
 * - Stores are not reordered with OLDER loads.
 *   - Loads may be reordered with OLDER stores to a different memory location,
 *     but not with OLDER stores to the same memory location.
 * - Stores are not reordered with other stores, except for special
 *   instructions (CLFLUSH, streaming stores, fast string operations).
 *   Most of these are not emitted by compilers, and as long as the
 *   atomic stores are not combined with any other stores, even the allowed
 *   reordering of the stores by a single fast string operation (e.g., "stos")
 *   is not a problem.
 * - Neither loads nor stores are reordered with locked instructions.
 * - Loads cannot pass earlier LFENCE or MFENCE instructions.
 * - Stores cannot pass earlier LFENCE, SFENCE, or MFENCE instructions.
 * - LFENCE instruction cannot pass earlier loads.
 * - SFENCE instruction cannot pass earlier stores.
 * - MFENCE instruction cannot pass earlier loads or stores.
 * - Stores by a single processor are observed in the same order by all
 *   processors.
 * - (Unlocked) Stores from different processors are NOT ordered.
 * - Memory ordering obeys causality (memory ordering respects transitive
 *   visibility).
 * - Any two stores are seen in a consistent order by processors other than
 *   the those performing the stores.
 * - Locked instructions have total order.
 *
 * These rules imply that:
 *
 * - Locked instructions are not needed for aligned loads or stores to make
 *   them atomic.
 * - All stores have release semantics; none of the preceding stores or loads
 *   can be reordered with following stores.  Following loads could still be
 *   reordered to happen before the store, but that is not a violation of the
 *   release semantics.
 * - All loads from a given memory location have acquire semantics with
 *   respect to the stores on the same memory location; none of the following
 *   loads or stores can be reordered with the load.  Preceding stores to a
 *   different memory location MAY be reordered with the load, but that is not
 *   a violation of the acquire semantics (i.e., the loads and stores of two
 *   critical sections guarded by a different memory location can overlap).
 * - Locked instructions serve as CPU memory barriers by themselves.
 * - Locked stores implement the sequential consistency memory order.  Using
 *   locked instructions when seq_cst memory order is requested allows normal
 *   loads to observe the stores in the same (total) order without using CPU
 *   memory barrier after the loads.
 *
 * NOTE: Some older AMD Opteron processors have a bug that violates the
 * acquire semantics described above.  The bug manifests as an unlocked
 * read-modify-write operation following a "semaphore operation" operating
 * on data that existed before entering the critical section; i.e., the
 * preceding "semaphore operation" fails to function as an acquire barrier.
 * The affected CPUs are AMD family 15, models 32 to 63.
 *
 * Ref. http://support.amd.com/TechDocs/25759.pdf errata #147.
 */

/* Barriers. */

#define compiler_barrier()      asm volatile(" " : : : "memory")
#define cpu_barrier()           asm volatile("mfence;" : : : "memory")

/*
 * The 'volatile' keyword prevents the compiler from keeping the atomic
 * value in a register, and generates a new memory access for each atomic
 * operation.  This allows the implementations of memory_order_relaxed and
 * memory_order_consume to avoid issuing a compiler memory barrier, allowing
 * full optimization of all surrounding non-atomic variables.
 *
 * The placement of the 'volatile' keyword after the 'TYPE' below is highly
 * significant when the TYPE is a pointer type.  In that case we want the
 * pointer to be declared volatile, not the data type that is being pointed
 * at!
 */
#define ATOMIC(TYPE) TYPE volatile

/* Memory ordering.  Must be passed in as a constant. */
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

#define ATOMIC_VAR_INIT(VALUE) VALUE
#define atomic_init(OBJECT, VALUE) (*(OBJECT) = (VALUE), (void) 0)

/*
 * The memory_model_relaxed does not need a compiler barrier, if the
 * atomic operation can otherwise be guaranteed to not be moved with
 * respect to other atomic operations on the same memory location.  Using
 * the 'volatile' keyword in the definition of the atomic types
 * accomplishes this, as memory accesses to volatile data may not be
 * optimized away, or be reordered with other volatile accesses.
 *
 * On x86 also memory_order_consume is automatic, and data dependency on a
 * volatile atomic variable means that the compiler optimizations should not
 * cause problems.  That is, the compiler should not speculate the value of
 * the atomic_read, as it is going to read it from the memory anyway.
 * This allows omiting the compiler memory barrier on atomic_reads with
 * memory_order_consume.  This matches the definition of
 * smp_read_barrier_depends() in Linux kernel as a nop for x86, and its usage
 * in rcu_dereference().
 *
 * We use this same logic below to choose inline assembly statements with or
 * without a compiler memory barrier.
 */
static inline void
atomic_compiler_barrier(memory_order order)
{
    if (order > memory_order_consume) {
        compiler_barrier();
    }
}

static inline void
atomic_thread_fence(memory_order order)
{
    if (order == memory_order_seq_cst) {
        cpu_barrier();
    } else {
        atomic_compiler_barrier(order);
    }
}

static inline void
atomic_signal_fence(memory_order order)
{
    atomic_compiler_barrier(order);
}

#define atomic_is_lock_free(OBJ)                \
    ((void) *(OBJ),                             \
     IS_LOCKLESS_ATOMIC(*(OBJ)) ? 2 : 0)

#define atomic_exchange__(DST, SRC, ORDER)        \
    ({                                            \
        typeof(DST) dst___ = (DST);               \
        typeof(*(DST)) src___ = (SRC);            \
                                                  \
        if ((ORDER) > memory_order_consume) {           \
            asm volatile("xchg %1,%0 ; "                \
                         "# atomic_exchange__"          \
                         : "+r" (src___),    /* 0 */    \
                           "+m" (*dst___)    /* 1 */    \
                         :: "memory");                  \
        } else {                                        \
            asm volatile("xchg %1,%0 ; "                \
                         "# atomic_exchange__"          \
                         : "+r" (src___),    /* 0 */    \
                           "+m" (*dst___));  /* 1 */    \
        }                                               \
        src___;                                         \
    })

/* Atomic store: Valid memory models are:
 *
 * memory_order_relaxed, memory_order_release, and
 * memory_order_seq_cst. */
#define atomic_store_explicit(DST, SRC, ORDER)          \
    ({                                                  \
        typeof(DST) dst__ = (DST);                      \
        typeof(*(DST)) src__ = (SRC);                   \
                                                        \
        if ((ORDER) != memory_order_seq_cst) {          \
            atomic_compiler_barrier(ORDER);             \
            *dst__ = src__;                             \
        } else {                                        \
            atomic_exchange__(dst__, src__, ORDER);     \
        }                                               \
        (void) 0;                                       \
    })
#define atomic_store(DST, SRC)                                  \
    atomic_store_explicit(DST, SRC, memory_order_seq_cst)

/* Atomic read: Valid memory models are:
 *
 * memory_order_relaxed, memory_order_consume, memory_model_acquire,
 * and memory_order_seq_cst. */
#define atomic_read_explicit(SRC, DST, ORDER)           \
    ({                                                  \
        typeof(DST) dst__ = (DST);                      \
        typeof(SRC) src__ = (SRC);                      \
                                                        \
        *dst__ = *src__;                                \
        atomic_compiler_barrier(ORDER);                 \
        (void) 0;                                       \
    })
#define atomic_read(SRC, DST)                                   \
    atomic_read_explicit(SRC, DST, memory_order_seq_cst)

#define atomic_compare_exchange__(DST, EXP, SRC, RES, CLOB)           \
    asm volatile("lock; cmpxchg %3,%1 ; "                             \
                 "      sete    %0      "                             \
                 "# atomic_compare_exchange__"                        \
                 : "=q" (RES),           /* 0 */                      \
                   "+m" (*DST),          /* 1 */                      \
                   "+a" (EXP)            /* 2 */                      \
                 : "r" (SRC)             /* 3 */                      \
                 : CLOB, "cc")

/* All memory models are valid for read-modify-write operations.
 *
 * Valid memory models for the read operation of the current value in
 * the failure case are the same as for atomic read, but can not be
 * stronger than the success memory model.
 * ORD_FAIL is ignored, as atomic_compare_exchange__ already implements
 * at least as strong a barrier as allowed for ORD_FAIL in all cases. */
#define atomic_compare_exchange_strong_explicit(DST, EXP, SRC, ORDER, ORD_FAIL) \
    ({                                                              \
        typeof(DST) dst__ = (DST);                                  \
        typeof(DST) expp__ = (EXP);                                 \
        typeof(*(DST)) src__ = (SRC);                               \
        typeof(*(DST)) exp__ = *expp__;                             \
        uint8_t res__;                                              \
        (void)ORD_FAIL;                                             \
                                                                    \
        if ((ORDER) > memory_order_consume) {                       \
            atomic_compare_exchange__(dst__, exp__, src__, res__,   \
                                      "memory");                    \
        } else {                                                    \
            atomic_compare_exchange__(dst__, exp__, src__, res__,   \
                                      "cc");                        \
        }                                                           \
        if (!res__) {                                               \
            *expp__ = exp__;                                        \
        }                                                           \
        (bool)res__;                                                \
    })
#define atomic_compare_exchange_strong(DST, EXP, SRC)             \
    atomic_compare_exchange_strong_explicit(DST, EXP, SRC,        \
                                            memory_order_seq_cst, \
                                            memory_order_seq_cst)
#define atomic_compare_exchange_weak            \
    atomic_compare_exchange_strong
#define atomic_compare_exchange_weak_explicit   \
    atomic_compare_exchange_strong_explicit

#define atomic_add__(RMW, ARG, CLOB)            \
    asm volatile("lock; xadd %0,%1 ; "          \
                 "# atomic_add__     "          \
                 : "+r" (ARG),       /* 0 */    \
                   "+m" (*RMW)       /* 1 */    \
                 :: CLOB, "cc")

#define atomic_add_explicit(RMW, ARG, ORIG, ORDER)  \
    ({                                              \
        typeof(RMW) rmw__ = (RMW);                  \
        typeof(*(RMW)) arg__ = (ARG);               \
                                                    \
        if ((ORDER) > memory_order_consume) {       \
            atomic_add__(rmw__, arg__, "memory");   \
        } else {                                    \
            atomic_add__(rmw__, arg__, "cc");       \
        }                                           \
        *(ORIG) = arg__;                            \
    })
#define atomic_add(RMW, ARG, ORIG)                              \
    atomic_add_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_sub_explicit(RMW, ARG, ORIG, ORDER)      \
    atomic_add_explicit(RMW, -(ARG), ORIG, ORDER)
#define atomic_sub(RMW, ARG, ORIG)                              \
    atomic_sub_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

/* We could use simple locked instructions if the original value was not
 * needed. */
#define atomic_op__(RMW, OP, ARG, ORIG, ORDER)              \
    ({                                                      \
        typeof(RMW) rmw__ = (RMW);                          \
        typeof(ARG) arg__ = (ARG);                                      \
                                                                        \
        typeof(*(RMW)) val__;                                           \
                                                                        \
        atomic_read_explicit(rmw__, &val__, memory_order_relaxed);      \
        do {                                                            \
        } while (!atomic_compare_exchange_weak_explicit(rmw__, &val__,  \
                                                        val__ OP arg__, \
                                                        ORDER,          \
                                                        memory_order_relaxed)); \
        *(ORIG) = val__;                                                \
    })

#define atomic_or_explicit(RMW, ARG, ORIG, ORDER)       \
    atomic_op__(RMW, |, ARG, ORIG, ORDER)
#define atomic_or(RMW, ARG, ORIG)                              \
    atomic_or_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_xor_explicit(RMW, ARG, ORIG, ORDER)      \
    atomic_op__(RMW, ^, ARG, ORIG, ORDER)
#define atomic_xor(RMW, ARG, ORIG)                              \
    atomic_xor_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_and_explicit(RMW, ARG, ORIG, ORDER)      \
    atomic_op__(RMW, &, ARG, ORIG, ORDER)
#define atomic_and(RMW, ARG, ORIG)                              \
    atomic_and_explicit(RMW, ARG, ORIG, memory_order_seq_cst)


/* atomic_flag */

typedef ATOMIC(int) atomic_flag;
#define ATOMIC_FLAG_INIT { false }

#define atomic_flag_test_and_set_explicit(FLAG, ORDER)  \
    ((bool)atomic_exchange__(FLAG, 1, ORDER))
#define atomic_flag_test_and_set(FLAG)                                  \
    atomic_flag_test_and_set_explicit(FLAG, memory_order_seq_cst)

#define atomic_flag_clear_explicit(FLAG, ORDER) \
    atomic_store_explicit(FLAG, 0, ORDER)
#define atomic_flag_clear(FLAG)                                 \
    atomic_flag_clear_explicit(FLAG, memory_order_seq_cst)
