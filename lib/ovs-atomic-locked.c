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

#include <config.h>

#include "ovs-atomic.h"
#include "hash.h"
#include "ovs-thread.h"

#ifdef OVS_ATOMIC_LOCKED_IMPL
static struct ovs_mutex *
mutex_for_pointer(void *p)
{
    OVS_ALIGNED_STRUCT(CACHE_LINE_SIZE, aligned_mutex) {
        struct ovs_mutex mutex;
        char pad[PAD_SIZE(sizeof(struct ovs_mutex), CACHE_LINE_SIZE)];
    };

    static struct aligned_mutex atomic_mutexes[] = {
#define MUTEX_INIT { .mutex = OVS_MUTEX_INITIALIZER }
#define MUTEX_INIT4  MUTEX_INIT,  MUTEX_INIT,  MUTEX_INIT,  MUTEX_INIT
#define MUTEX_INIT16 MUTEX_INIT4, MUTEX_INIT4, MUTEX_INIT4, MUTEX_INIT4
        MUTEX_INIT16, MUTEX_INIT16,
    };
    BUILD_ASSERT_DECL(IS_POW2(ARRAY_SIZE(atomic_mutexes)));

    uint32_t hash = hash_pointer(p, 0);
    uint32_t indx = hash & (ARRAY_SIZE(atomic_mutexes) - 1);
    return &atomic_mutexes[indx].mutex;
}

void
atomic_lock__(void *p)
    OVS_ACQUIRES(mutex_for_pointer(p))
{
    ovs_mutex_lock(mutex_for_pointer(p));
}

void
atomic_unlock__(void *p)
    OVS_RELEASES(mutex_for_pointer(p))
{
    ovs_mutex_unlock(mutex_for_pointer(p));
}
#endif /* OVS_ATOMIC_LOCKED_IMPL */
