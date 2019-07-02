/* This header implements atomic operation primitives on compilers that
 * have built-in support for ++C11 <atomic>  */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#include <atomic>

#define ATOMIC(TYPE) std::atomic<TYPE>

using std::atomic_init;

using std::memory_order_relaxed;
using std::memory_order_consume;
using std::memory_order_acquire;
using std::memory_order_release;
using std::memory_order_acq_rel;
using std::memory_order_seq_cst;

using std::atomic_thread_fence;
using std::atomic_signal_fence;
using std::atomic_is_lock_free;

using std::atomic_store;
using std::atomic_store_explicit;

using std::atomic_compare_exchange_strong;
using std::atomic_compare_exchange_strong_explicit;
using std::atomic_compare_exchange_weak;
using std::atomic_compare_exchange_weak_explicit;

#define atomic_read(SRC, DST) \
    atomic_read_explicit(SRC, DST, memory_order_seq_cst)
#define atomic_read_explicit(SRC, DST, ORDER)   \
    (*(DST) = std::atomic_load_explicit(SRC, ORDER),    \
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
    (*(ORIG) = (*(RMW)).fetch_add(ARG, ORDER), (void) 0)
#define atomic_sub_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = (*(RMW)).fetch_sub(ARG, ORDER), (void) 0)
#define atomic_or_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = (*(RMW)).fetch_or(ARG, ORDER), (void) 0)
#define atomic_xor_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = (*(RMW)).fetch_xor(ARG, ORDER), (void) 0)
#define atomic_and_explicit(RMW, ARG, ORIG, ORDER) \
    (*(ORIG) = (*(RMW)).fetch_and(ARG, ORDER), (void) 0)

using std::atomic_flag;
using std::atomic_flag_test_and_set_explicit;
using std::atomic_flag_test_and_set;
using std::atomic_flag_clear_explicit;
using std::atomic_flag_clear;
