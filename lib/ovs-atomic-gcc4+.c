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

#include <config.h>

#include "ovs-atomic.h"
#include "ovs-thread.h"

#if OVS_ATOMIC_GCC4P_IMPL
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

#define DEFINE_LOCKED_OP(TYPE, NAME, OPERATOR)                          \
    TYPE##_t                                                            \
    locked_##TYPE##_##NAME(struct locked_##TYPE *u, TYPE##_t arg)       \
    {                                                                   \
        TYPE##_t old_value;                                             \
                                                                        \
        ovs_mutex_lock(&mutex);                                         \
        old_value = u->value;                                           \
        u->value OPERATOR arg;                                          \
        ovs_mutex_unlock(&mutex);                                       \
                                                                        \
        return old_value;                                               \
    }

#define DEFINE_LOCKED_TYPE(TYPE)                                        \
    TYPE##_t                                                            \
    locked_##TYPE##_load(const struct locked_##TYPE *u)                 \
    {                                                                   \
        TYPE##_t value;                                                 \
                                                                        \
        ovs_mutex_lock(&mutex);                                         \
        value = u->value;                                               \
        ovs_mutex_unlock(&mutex);                                       \
                                                                        \
        return value;                                                   \
    }                                                                   \
                                                                        \
    void                                                                \
    locked_##TYPE##_store(struct locked_##TYPE *u, TYPE##_t value)      \
    {                                                                   \
        ovs_mutex_lock(&mutex);                                         \
        u->value = value;                                               \
        ovs_mutex_unlock(&mutex);                                       \
    }                                                                   \
    DEFINE_LOCKED_OP(TYPE, add, +=);                                    \
    DEFINE_LOCKED_OP(TYPE, sub, -=);                                    \
    DEFINE_LOCKED_OP(TYPE, or,  |=);                                    \
    DEFINE_LOCKED_OP(TYPE, xor, ^=);                                    \
    DEFINE_LOCKED_OP(TYPE, and, &=)

DEFINE_LOCKED_TYPE(uint64);
DEFINE_LOCKED_TYPE(int64);

#endif  /* OVS_ATOMIC_GCC4P_IMPL */
