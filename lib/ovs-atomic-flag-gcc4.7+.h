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

/* This header implements atomic_flag on Clang and on GCC 4.7 and later. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

/* atomic_flag */

typedef struct {
    unsigned char b;
} atomic_flag;
#define ATOMIC_FLAG_INIT { .b = false }

static inline bool
atomic_flag_test_and_set_explicit(volatile atomic_flag *object,
                                  memory_order order)
{
    return __atomic_test_and_set(&object->b, order);
}

static inline bool
atomic_flag_test_and_set(volatile atomic_flag *object)
{
    return atomic_flag_test_and_set_explicit(object, memory_order_seq_cst);
}

static inline void
atomic_flag_clear_explicit(volatile atomic_flag *object, memory_order order)
{
    __atomic_clear(object, order);
}

static inline void
atomic_flag_clear(volatile atomic_flag *object)
{
    atomic_flag_clear_explicit(object, memory_order_seq_cst);
}
