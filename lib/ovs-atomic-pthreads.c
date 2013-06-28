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

#if OVS_ATOMIC_PTHREADS_IMPL
bool
atomic_flag_test_and_set(volatile atomic_flag *flag_)
{
    atomic_flag *flag = CONST_CAST(atomic_flag *, flag_);
    bool old_value;

    xpthread_mutex_lock(&flag->mutex);
    old_value = flag->b;
    flag->b = true;
    xpthread_mutex_unlock(&flag->mutex);

    return old_value;
}

bool
atomic_flag_test_and_set_explicit(volatile atomic_flag *flag,
                                  memory_order order OVS_UNUSED)
{
    return atomic_flag_test_and_set(flag);
}

void
atomic_flag_clear(volatile atomic_flag *flag_)
{
    atomic_flag *flag = CONST_CAST(atomic_flag *, flag_);

    xpthread_mutex_lock(&flag->mutex);
    flag->b = false;
    xpthread_mutex_unlock(&flag->mutex);
}

void
atomic_flag_clear_explicit(volatile atomic_flag *flag,
                           memory_order order OVS_UNUSED)
{
    return atomic_flag_clear(flag);
}

#endif  /* OVS_ATOMIC_PTHREADS_IMPL */
