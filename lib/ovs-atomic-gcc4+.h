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

/* This header implements atomic operation primitives on GCC 4.x. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#define OVS_ATOMIC_GCC4P_IMPL 1

#define DEFINE_LOCKLESS_ATOMIC(TYPE, NAME) typedef struct { TYPE value; } NAME

#define ATOMIC_BOOL_LOCK_FREE 2
DEFINE_LOCKLESS_ATOMIC(bool, atomic_bool);

#define ATOMIC_CHAR_LOCK_FREE 2
DEFINE_LOCKLESS_ATOMIC(char, atomic_char);
DEFINE_LOCKLESS_ATOMIC(signed char, atomic_schar);
DEFINE_LOCKLESS_ATOMIC(unsigned char, atomic_uchar);

#define ATOMIC_SHORT_LOCK_FREE 2
DEFINE_LOCKLESS_ATOMIC(short, atomic_short);
DEFINE_LOCKLESS_ATOMIC(unsigned short, atomic_ushort);

#define ATOMIC_INT_LOCK_FREE 2
DEFINE_LOCKLESS_ATOMIC(int, atomic_int);
DEFINE_LOCKLESS_ATOMIC(unsigned int, atomic_uint);

#if ULONG_MAX <= UINTPTR_MAX
    #define ATOMIC_LONG_LOCK_FREE 2
    DEFINE_LOCKLESS_ATOMIC(long, atomic_long);
    DEFINE_LOCKLESS_ATOMIC(unsigned long, atomic_ulong);
#elif ULONG_MAX == UINT64_MAX
    #define ATOMIC_LONG_LOCK_FREE 0
    typedef struct locked_int64  atomic_long;
    typedef struct locked_uint64 atomic_ulong;
#else
    #error "not implemented"
#endif

#if ULLONG_MAX <= UINTPTR_MAX
    #define ATOMIC_LLONG_LOCK_FREE 2
    DEFINE_LOCKLESS_ATOMIC(long long, atomic_llong);
    DEFINE_LOCKLESS_ATOMIC(unsigned long long, atomic_ullong);
#elif ULLONG_MAX == UINT64_MAX
    #define ATOMIC_LLONG_LOCK_FREE 0
    typedef struct locked_int64  atomic_llong;
    typedef struct locked_uint64 atomic_ullong;
#else
    #error "not implemented"
#endif

#if SIZE_MAX <= UINTPTR_MAX
    DEFINE_LOCKLESS_ATOMIC(size_t, atomic_size_t);
    DEFINE_LOCKLESS_ATOMIC(ptrdiff_t, atomic_ptrdiff_t);
#elif SIZE_MAX == UINT64_MAX
    typedef struct locked_uint64 atomic_size_t;
    typedef struct locked_int64  atomic_ptrdiff_t;
#else
    #error "not implemented"
#endif

#if UINTMAX_MAX <= UINTPTR_MAX
    DEFINE_LOCKLESS_ATOMIC(intmax_t, atomic_intmax_t);
    DEFINE_LOCKLESS_ATOMIC(uintmax_t, atomic_uintmax_t);
#elif UINTMAX_MAX == UINT64_MAX
    typedef struct locked_int64  atomic_intmax_t;
    typedef struct locked_uint64 atomic_uintmax_t;
#else
    #error "not implemented"
#endif

#define ATOMIC_POINTER_LOCK_FREE 2
DEFINE_LOCKLESS_ATOMIC(intptr_t, atomic_intptr_t);
DEFINE_LOCKLESS_ATOMIC(uintptr_t, atomic_uintptr_t);

/* Nonstandard atomic types. */
DEFINE_LOCKLESS_ATOMIC(uint8_t,  atomic_uint8_t);
DEFINE_LOCKLESS_ATOMIC(uint16_t, atomic_uint16_t);
DEFINE_LOCKLESS_ATOMIC(uint32_t, atomic_uint32_t);
DEFINE_LOCKLESS_ATOMIC(int8_t,   atomic_int8_t);
DEFINE_LOCKLESS_ATOMIC(int16_t,  atomic_int16_t);
DEFINE_LOCKLESS_ATOMIC(int32_t,  atomic_int32_t);
#if UINT64_MAX <= UINTPTR_MAX
    DEFINE_LOCKLESS_ATOMIC(uint64_t, atomic_uint64_t);
    DEFINE_LOCKLESS_ATOMIC(int64_t,  atomic_int64_t);
#else
    typedef struct locked_uint64 atomic_uint64_t;
    typedef struct locked_int64  atomic_int64_t;
#endif

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

/* locked_uint64. */

#define IF_LOCKED_UINT64(OBJECT, THEN, ELSE)                            \
    __builtin_choose_expr(                                              \
        __builtin_types_compatible_p(typeof(OBJECT), struct locked_uint64), \
        (THEN), (ELSE))
#define AS_LOCKED_UINT64(OBJECT) ((struct locked_uint64 *) (void *) (OBJECT))
#define AS_UINT64(OBJECT) ((uint64_t *) (OBJECT))
struct locked_uint64 {
    uint64_t value;
};

uint64_t locked_uint64_load(const struct locked_uint64 *);
void locked_uint64_store(struct locked_uint64 *, uint64_t);
uint64_t locked_uint64_add(struct locked_uint64 *, uint64_t arg);
uint64_t locked_uint64_sub(struct locked_uint64 *, uint64_t arg);
uint64_t locked_uint64_or(struct locked_uint64 *, uint64_t arg);
uint64_t locked_uint64_xor(struct locked_uint64 *, uint64_t arg);
uint64_t locked_uint64_and(struct locked_uint64 *, uint64_t arg);

#define IF_LOCKED_INT64(OBJECT, THEN, ELSE)                             \
    __builtin_choose_expr(                                              \
        __builtin_types_compatible_p(typeof(OBJECT), struct locked_int64), \
        (THEN), (ELSE))
#define AS_LOCKED_INT64(OBJECT) ((struct locked_int64 *) (void *) (OBJECT))
#define AS_INT64(OBJECT) ((int64_t *) (OBJECT))
struct locked_int64 {
    int64_t value;
};
int64_t locked_int64_load(const struct locked_int64 *);
void locked_int64_store(struct locked_int64 *, int64_t);
int64_t locked_int64_add(struct locked_int64 *, int64_t arg);
int64_t locked_int64_sub(struct locked_int64 *, int64_t arg);
int64_t locked_int64_or(struct locked_int64 *, int64_t arg);
int64_t locked_int64_xor(struct locked_int64 *, int64_t arg);
int64_t locked_int64_and(struct locked_int64 *, int64_t arg);

#define ATOMIC_VAR_INIT(VALUE) { .value = (VALUE) }
#define atomic_init(OBJECT, VALUE) ((OBJECT)->value = (VALUE), (void) 0)

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

#define ATOMIC_SWITCH(OBJECT, LOCKLESS_CASE,                    \
                      LOCKED_UINT64_CASE, LOCKED_INT64_CASE)    \
    IF_LOCKED_UINT64(OBJECT, LOCKED_UINT64_CASE,                \
                     IF_LOCKED_INT64(OBJECT, LOCKED_INT64_CASE, \
                                     LOCKLESS_CASE))

#define atomic_is_lock_free(OBJ)                \
    ((void) (OBJ)->value,                       \
     ATOMIC_SWITCH(OBJ, true, false, false))

#define atomic_store(DST, SRC) \
    atomic_store_explicit(DST, SRC, memory_order_seq_cst)
#define atomic_store_explicit(DST, SRC, ORDER)                          \
    (ATOMIC_SWITCH(DST,                                                 \
                   (atomic_thread_fence(ORDER),                         \
                    (DST)->value = (SRC),                               \
                    atomic_thread_fence_if_seq_cst(ORDER)),             \
                   locked_uint64_store(AS_LOCKED_UINT64(DST), SRC),     \
                   locked_int64_store(AS_LOCKED_INT64(DST), SRC)),      \
     (void) 0)

#define atomic_read(SRC, DST) \
    atomic_read_explicit(SRC, DST, memory_order_seq_cst)
#define atomic_read_explicit(SRC, DST, ORDER)                           \
    (ATOMIC_SWITCH(SRC,                                                 \
                   (atomic_thread_fence_if_seq_cst(ORDER),              \
                    (*DST) = (SRC)->value,                              \
                    atomic_thread_fence(ORDER)),                        \
                   *(DST) = locked_uint64_load(AS_LOCKED_UINT64(SRC)),  \
                   *(DST) = locked_int64_load(AS_LOCKED_INT64(SRC))),   \
     (void) 0)

#define atomic_op__(RMW, OP, ARG, ORIG)                                 \
    (ATOMIC_SWITCH(RMW,                                                 \
                   *(ORIG) = __sync_fetch_and_##OP(&(RMW)->value, ARG), \
                   *(ORIG) = locked_uint64_##OP(AS_LOCKED_UINT64(RMW), ARG), \
                   *(ORIG) = locked_int64_##OP(AS_LOCKED_INT64(RMW), ARG)), \
     (void) 0)

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
