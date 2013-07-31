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

/* This header implements atomic operation primitives using pthreads. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#define OVS_ATOMIC_PTHREADS_IMPL 1

#define DEFINE_PTHREAD_ATOMIC(TYPE, NAME)       \
    typedef struct {                            \
        TYPE value;                             \
        pthread_mutex_t mutex;                  \
    } NAME;

#define ATOMIC_BOOL_LOCK_FREE 0
DEFINE_PTHREAD_ATOMIC(bool, atomic_bool);

#define ATOMIC_CHAR_LOCK_FREE 0
DEFINE_PTHREAD_ATOMIC(char, atomic_char);
DEFINE_PTHREAD_ATOMIC(signed char, atomic_schar);
DEFINE_PTHREAD_ATOMIC(unsigned char, atomic_uchar);

#define ATOMIC_SHORT_LOCK_FREE 0
DEFINE_PTHREAD_ATOMIC(short, atomic_short);
DEFINE_PTHREAD_ATOMIC(unsigned short, atomic_ushort);

#define ATOMIC_INT_LOCK_FREE 0
DEFINE_PTHREAD_ATOMIC(int, atomic_int);
DEFINE_PTHREAD_ATOMIC(unsigned int, atomic_uint);

#define ATOMIC_LONG_LOCK_FREE 0
DEFINE_PTHREAD_ATOMIC(long, atomic_long);
DEFINE_PTHREAD_ATOMIC(unsigned long, atomic_ulong);

#define ATOMIC_LLONG_LOCK_FREE 0
DEFINE_PTHREAD_ATOMIC(long long, atomic_llong);
DEFINE_PTHREAD_ATOMIC(unsigned long long, atomic_ullong);

DEFINE_PTHREAD_ATOMIC(size_t, atomic_size_t);
DEFINE_PTHREAD_ATOMIC(ptrdiff_t, atomic_ptrdiff_t);

DEFINE_PTHREAD_ATOMIC(intmax_t, atomic_intmax_t);
DEFINE_PTHREAD_ATOMIC(uintmax_t, atomic_uintmax_t);

#define ATOMIC_POINTER_LOCK_FREE 0
DEFINE_PTHREAD_ATOMIC(intptr_t, atomic_intptr_t);
DEFINE_PTHREAD_ATOMIC(uintptr_t, atomic_uintptr_t);

/* Nonstandard atomic types. */
DEFINE_PTHREAD_ATOMIC(uint8_t,  atomic_uint8_t);
DEFINE_PTHREAD_ATOMIC(uint16_t, atomic_uint16_t);
DEFINE_PTHREAD_ATOMIC(uint32_t, atomic_uint32_t);
DEFINE_PTHREAD_ATOMIC(int8_t,   atomic_int8_t);
DEFINE_PTHREAD_ATOMIC(int16_t,  atomic_int16_t);
DEFINE_PTHREAD_ATOMIC(int32_t,  atomic_int32_t);
DEFINE_PTHREAD_ATOMIC(uint64_t, atomic_uint64_t);
DEFINE_PTHREAD_ATOMIC(int64_t,  atomic_int64_t);

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

#define ATOMIC_VAR_INIT(VALUE) { VALUE, PTHREAD_MUTEX_INITIALIZER }
#define atomic_init(OBJECT, VALUE)                      \
    ((OBJECT)->value = (VALUE),                         \
     pthread_mutex_init(&(OBJECT)->mutex, NULL),        \
     (void) 0)

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

#define atomic_store(DST, SRC)                  \
    (pthread_mutex_lock(&(DST)->mutex),         \
     (DST)->value = (SRC),                      \
     pthread_mutex_unlock(&(DST)->mutex),       \
     (void) 0)
#define atomic_store_explicit(DST, SRC, ORDER) \
    ((void) (ORDER), atomic_store(DST, SRC))

#define atomic_read(SRC, DST)                                           \
    (pthread_mutex_lock(CONST_CAST(pthread_mutex_t *, &(SRC)->mutex)),  \
     *(DST) = (SRC)->value,                                             \
     pthread_mutex_unlock(CONST_CAST(pthread_mutex_t *, &(SRC)->mutex)), \
     (void) 0)
#define atomic_read_explicit(SRC, DST, ORDER)   \
    ((void) (ORDER), atomic_read(SRC, DST))

#define atomic_op__(RMW, OPERATOR, OPERAND, ORIG)       \
    (pthread_mutex_lock(&(RMW)->mutex),                 \
     *(ORIG) = (RMW)->value,                            \
     (RMW)->value OPERATOR (OPERAND),                   \
     pthread_mutex_unlock(&(RMW)->mutex),               \
     (void) 0)

#define atomic_add(RMW, OPERAND, ORIG) atomic_op__(RMW, +=, OPERAND, ORIG)
#define atomic_sub(RMW, OPERAND, ORIG) atomic_op__(RMW, -=, OPERAND, ORIG)
#define atomic_or( RMW, OPERAND, ORIG) atomic_op__(RMW, |=, OPERAND, ORIG)
#define atomic_xor(RMW, OPERAND, ORIG) atomic_op__(RMW, ^=, OPERAND, ORIG)
#define atomic_and(RMW, OPERAND, ORIG) atomic_op__(RMW, &=, OPERAND, ORIG)

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
    bool b;
    pthread_mutex_t mutex;
} atomic_flag;
#define ATOMIC_FLAG_INIT { false, PTHREAD_MUTEX_INITIALIZER }

bool atomic_flag_test_and_set(volatile atomic_flag *);
bool atomic_flag_test_and_set_explicit(volatile atomic_flag *, memory_order);

void atomic_flag_clear(volatile atomic_flag *);
void atomic_flag_clear_explicit(volatile atomic_flag *, memory_order);
