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

/* This header implements atomic operation primitives on 32-bit 586+ with GCC.
 */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#define OVS_ATOMIC_I586_IMPL 1

/*
 * These assumptions have been adopted from the x86_64 Memory model:
 *
 * - 1, 2, and 4 byte loads and stores are atomic on aligned memory.
 * - Loads are not reordered with other loads.
 * - Stores are not reordered with OLDER loads.
 *   - Loads may be reordered with OLDER stores to a different memory location,
 *     but not with OLDER stores to the same memory location.
 * - Stores are not reordered with other stores, except maybe for special
 *   instructions not emitted by compilers, or by the stores performed by
 *   a single fast string operation (e.g., "stos").  As long as the atomic
 *   stores are not combined with any other stores, even the allowed reordering
 *   of the stores by a single fast string operation is not a problem.
 * - Neither loads nor stores are reordered with locked instructions.
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
 *   them atomic for sizes upto 4 bytes.  8 byte objects need locked
 *   instructions.
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

#define compiler_barrier()  asm volatile(" " : : : "memory")
#define cpu_barrier()  asm volatile("lock; addl $0,(%%esp)" ::: "memory", "cc")

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
 *
 * Attribute aligned is used to tell the compiler to align 64-bit data
 * on a 8-byte boundary.  This allows more efficient atomic access, as the
 * the CPU guarantees such memory accesses to be atomic. */
#define ATOMIC(TYPE) TYPE volatile __attribute__((aligned(sizeof(TYPE))))

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

/* The 8-byte atomic exchange uses cmpxchg8b with the SRC (ax:dx) as
 * the expected value (bx:cx), which will get replaced by the current
 * value in the likely case it did not match, after which we keep
 * trying until the swap succeeds. */

#if defined(__PIC__)
/* ebx may not be clobbered when compiled with -fPIC, must save and
 * restore it.  Furthermore, 'DST' may be addressed via ebx, so the
 * address must be passed via a register so that it remains valid also
 * after changing ebx. */
#define atomic_exchange_8__(DST, SRC, CLOB)       \
    uint32_t temp____;                            \
                                                  \
    asm volatile("      movl %%ebx,%2 ;    "      \
                 "      movl %%eax,%%ebx ; "      \
                 "      movl %%edx,%%ecx ; "      \
                 "1:                       "      \
                 "lock; cmpxchg8b (%0);    "      \
                 "      jne 1b ;           "      \
                 "      movl %2,%%ebx ;    "      \
                 " # atomic_exchange_8__   "      \
                 : "+r" (DST),       /* 0 */      \
                   "+A" (SRC),       /* 1 */      \
                   "=mr" (temp____)  /* 2 */      \
                 :: "ecx", CLOB, "cc")

#else
#define atomic_exchange_8__(DST, SRC, CLOB)       \
    asm volatile("      movl %%eax,%%ebx ; "      \
                 "      movl %%edx,%%ecx ; "      \
                 "1:                       "      \
                 "lock; cmpxchg8b %0 ;     "      \
                 "      jne 1b ;           "      \
                 " # atomic_exchange_8__   "      \
                 : "+m" (*DST),      /* 0 */      \
                   "+A" (SRC)        /* 1 */      \
                 :: "ebx", "ecx", CLOB, "cc")
#endif

#define atomic_exchange__(DST, SRC, ORDER)        \
    ({                                            \
        typeof(DST) dst___ = (DST);               \
        typeof(*(DST)) src___ = (SRC);            \
                                                  \
        if ((ORDER) > memory_order_consume) {                  \
            if (sizeof(*(DST)) == 8) {                         \
                atomic_exchange_8__(dst___, src___, "memory"); \
            } else {                                           \
                asm volatile("xchg %1,%0 ;       "             \
                             "# atomic_exchange__"             \
                             : "+r" (src___),   /* 0 */        \
                               "+m" (*dst___)   /* 1 */        \
                             :: "memory");                     \
            }                                                  \
        } else {                                               \
            if (sizeof(*(DST)) == 8) {                         \
                atomic_exchange_8__(dst___, src___, "cc");     \
            } else {                                           \
                asm volatile("xchg %1,%0 ;       "             \
                             "# atomic_exchange__"             \
                             : "+r" (src___),    /* 0 */       \
                               "+m" (*dst___));  /* 1 */       \
            }                                                  \
        }                                                      \
        src___;                                                \
    })

#if defined(__SSE__)
/* SSE registers are 128-bit wide, and moving the lowest 64-bits of an SSE
 * register to proerly aligned memory is atomic.  See ATOMIC(TYPE) above. */
#define atomic_store_8__(DST, SRC)                 \
    asm volatile("movq %1,%0 ; # atomic_store_8__" \
                 : "=m" (*DST)   /* 0 */           \
                 : "x" (SRC))    /* 1, SSE */
#else
/* Locked 64-bit exchange is available on all i586 CPUs. */
#define atomic_store_8__(DST, SRC)          \
    atomic_exchange_8__(DST, SRC, "cc")
#endif

#define atomic_store_explicit(DST, SRC, ORDER)          \
    ({                                                  \
        typeof(DST) dst__ = (DST);                      \
        typeof(*(DST)) src__ = (SRC);                   \
                                                        \
        if ((ORDER) != memory_order_seq_cst) {          \
            atomic_compiler_barrier(ORDER);             \
            if (sizeof(*(DST)) == 8) {                  \
                atomic_store_8__(dst__, src__);         \
            } else {                                    \
                *dst__ = src__;                         \
            }                                           \
        } else {                                        \
            atomic_exchange__(dst__, src__, ORDER);     \
        }                                               \
        (void) 0;                                       \
    })
#define atomic_store(DST, SRC)                              \
    atomic_store_explicit(DST, SRC, memory_order_seq_cst)

#if defined(__SSE__)
/* SSE registers are 128-bit wide, and moving 64-bits from properly aligned
 * memory to an SSE register is atomic.  See ATOMIC(TYPE) above. */
#define atomic_read_8__(SRC, DST)               \
    ({                                          \
        typeof(*(DST)) res__;                   \
                                                \
        asm ("movq %1,%0 ; # atomic_read_8__"   \
             : "=x" (res__)   /* 0, SSE. */     \
             : "m" (*SRC));   /* 1 */           \
        *(DST) = res__;                         \
    })
#else
/* Must use locked cmpxchg8b (available on all i586 CPUs) if compiled w/o sse
 * support.  Compare '*DST' to a random value in bx:cx and returns the actual
 * value in ax:dx.  The registers bx and cx are only read, so they are not
 * clobbered. */
#define atomic_read_8__(SRC, DST)               \
    ({                                          \
        typeof(*(DST)) res__;                   \
                                                \
        asm ("      movl %%ebx,%%eax ; "        \
             "      movl %%ecx,%%edx ; "        \
             "lock; cmpxchg8b %1 ;     "        \
             "# atomic_read_8__        "        \
             : "=&A" (res__), /* 0 */           \
               "+m"  (*SRC)   /* 1 */           \
             : : "cc");                         \
        *(DST) = res__;                         \
    })
#endif

#define atomic_read_explicit(SRC, DST, ORDER)   \
    ({                                          \
        typeof(DST) dst__ = (DST);              \
        typeof(SRC) src__ = (SRC);              \
                                                \
        if (sizeof(*(DST)) <= 4) {              \
            *dst__ = *src__;                    \
        } else {                                \
            atomic_read_8__(SRC, DST);          \
        }                                       \
        atomic_compiler_barrier(ORDER);         \
        (void) 0;                               \
    })
#define atomic_read(SRC, DST)                               \
    atomic_read_explicit(SRC, DST, memory_order_seq_cst)

#if defined(__PIC__)
/* ebx may not be used as an input when compiled with -fPIC, must save
 * and restore it.  Furthermore, 'DST' may be addressed via ebx, so
 * the address must be passed via a register so that it remains valid
 * also after changing ebx. */
#define atomic_compare_exchange_8__(DST, EXP, SRC, RES, CLOB)         \
    asm volatile("      xchgl %%ebx,%3 ;    "                         \
                 "lock; cmpxchg8b (%1) ;    "                         \
                 "      xchgl %3,%%ebx ;    "                         \
                 "      sete %0             "                         \
                 "# atomic_compare_exchange_8__"                      \
                 : "=q" (RES),                 /* 0 */                \
                   "+r" (DST),                 /* 1 */                \
                   "+A" (EXP)                  /* 2 */                \
                 : "r" ((uint32_t)SRC),        /* 3 */                \
                   "c" ((uint32_t)((uint64_t)SRC >> 32)) /* 4 */      \
                 : CLOB, "cc")
#else
#define atomic_compare_exchange_8__(DST, EXP, SRC, RES, CLOB)         \
    asm volatile("lock; cmpxchg8b %1 ; "                              \
                 "      sete %0        "                              \
                 "# atomic_compare_exchange_8__"                      \
                 : "=q" (RES),                 /* 0 */                \
                   "+m" (*DST),                /* 1 */                \
                   "+A" (EXP)                  /* 2 */                \
                 : "b" ((uint32_t)SRC),        /* 3 */                \
                   "c" ((uint32_t)((uint64_t)SRC >> 32)) /* 4 */      \
                 : CLOB, "cc")
#endif

#define atomic_compare_exchange__(DST, EXP, SRC, RES, CLOB)           \
    asm volatile("lock; cmpxchg %3,%1 ; "                             \
                 "      sete    %0      "                             \
                 "# atomic_compare_exchange__"                        \
                 : "=q" (RES),           /* 0 */                      \
                   "+m" (*DST),          /* 1 */                      \
                   "+a" (EXP)            /* 2 */                      \
                 : "r" (SRC)             /* 3 */                      \
                 : CLOB, "cc")

/* ORD_FAIL is ignored, as atomic_compare_exchange__ already implements
 * at least as strong a barrier as allowed for ORD_FAIL in all cases. */
#define atomic_compare_exchange_strong_explicit(DST, EXP, SRC, ORDER, ORD_FAIL) \
    ({                                                                  \
        typeof(DST) dst__ = (DST);                                      \
        typeof(DST) expp__ = (EXP);                                     \
        typeof(*(DST)) src__ = (SRC);                                   \
        typeof(*(DST)) exp__ = *expp__;                                 \
        uint8_t res__;                                                  \
        (void)ORD_FAIL;                                                 \
                                                                        \
        if ((ORDER) > memory_order_consume) {                           \
            if (sizeof(*(DST)) <= 4) {                                  \
                atomic_compare_exchange__(dst__, exp__, src__, res__,   \
                                          "memory");                    \
            } else {                                                    \
                atomic_compare_exchange_8__(dst__, exp__, src__, res__, \
                                            "memory");                  \
            }                                                           \
        } else {                                                        \
            if (sizeof(*(DST)) <= 4) {                                  \
                atomic_compare_exchange__(dst__, exp__, src__, res__,   \
                                          "cc");                        \
            } else {                                                    \
                atomic_compare_exchange_8__(dst__, exp__, src__, res__, \
                                            "cc");                      \
            }                                                           \
        }                                                               \
        if (!res__) {                                                   \
            *expp__ = exp__;                                            \
        }                                                               \
        (bool)res__;                                                    \
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

#define atomic_add_32__(RMW, ARG, ORIG, ORDER)     \
    ({                                             \
        typeof(RMW) rmw__ = (RMW);                 \
        typeof(*(RMW)) arg__ = (ARG);              \
                                                   \
        if ((ORDER) > memory_order_consume) {      \
            atomic_add__(rmw__, arg__, "memory");  \
        } else {                                   \
            atomic_add__(rmw__, arg__, "cc");      \
        }                                          \
        *(ORIG) = arg__;                           \
    })

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

#define atomic_add_explicit(RMW, ARG, ORIG, ORDER)              \
    (sizeof(*(RMW)) <= 4                                        \
     ? atomic_add_32__(RMW, ARG, ORIG, ORDER)                   \
     : atomic_op__(RMW, +, ARG, ORIG, ORDER))
#define atomic_add(RMW, ARG, ORIG)                              \
    atomic_add_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

#define atomic_sub_explicit(RMW, ARG, ORIG, ORDER)              \
    (sizeof(*(RMW)) <= 4                                        \
     ? atomic_add_32__(RMW, -(ARG), ORIG, ORDER)                \
     : atomic_op__(RMW, -, ARG, ORIG, ORDER))
#define atomic_sub(RMW, ARG, ORIG)                              \
    atomic_sub_explicit(RMW, ARG, ORIG, memory_order_seq_cst)

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
