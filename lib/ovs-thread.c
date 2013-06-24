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
#include "ovs-thread.h"
#include <errno.h>
#include "compiler.h"
#include "util.h"

#ifdef __CHECKER__
/* Omit the definitions in this file because they are somewhat difficult to
 * write without prompting "sparse" complaints, without ugliness or
 * cut-and-paste.  Since "sparse" is just a checker, not a compiler, it
 * doesn't matter that we don't define them. */
#else
#define XPTHREAD_FUNC1(FUNCTION, PARAM1)                \
    void                                                \
    x##FUNCTION(PARAM1 arg1)                            \
    {                                                   \
        int error = FUNCTION(arg1);                     \
        if (OVS_UNLIKELY(error)) {                      \
            ovs_abort(error, "%s failed", #FUNCTION);   \
        }                                               \
    }
#define XPTHREAD_TRY_FUNC1(FUNCTION, PARAM1)            \
    int                                                 \
    x##FUNCTION(PARAM1 arg1)                            \
    {                                                   \
        int error = FUNCTION(arg1);                     \
        if (OVS_UNLIKELY(error && error != EBUSY)) {    \
            ovs_abort(error, "%s failed", #FUNCTION);   \
        }                                               \
        return error;                                   \
    }
#define XPTHREAD_FUNC2(FUNCTION, PARAM1, PARAM2)        \
    void                                                \
    x##FUNCTION(PARAM1 arg1, PARAM2 arg2)               \
    {                                                   \
        int error = FUNCTION(arg1, arg2);               \
        if (OVS_UNLIKELY(error)) {                      \
            ovs_abort(error, "%s failed", #FUNCTION);   \
        }                                               \
    }

XPTHREAD_FUNC2(pthread_mutex_init, pthread_mutex_t *, pthread_mutexattr_t *);
XPTHREAD_FUNC1(pthread_mutex_lock, pthread_mutex_t *);
XPTHREAD_FUNC1(pthread_mutex_unlock, pthread_mutex_t *);
XPTHREAD_TRY_FUNC1(pthread_mutex_trylock, pthread_mutex_t *);

XPTHREAD_FUNC2(pthread_rwlock_init,
               pthread_rwlock_t *, pthread_rwlockattr_t *);
XPTHREAD_FUNC1(pthread_rwlock_rdlock, pthread_rwlock_t *);
XPTHREAD_FUNC1(pthread_rwlock_wrlock, pthread_rwlock_t *);
XPTHREAD_FUNC1(pthread_rwlock_unlock, pthread_rwlock_t *);
XPTHREAD_TRY_FUNC1(pthread_rwlock_tryrdlock, pthread_rwlock_t *);
XPTHREAD_TRY_FUNC1(pthread_rwlock_trywrlock, pthread_rwlock_t *);

XPTHREAD_FUNC2(pthread_cond_init, pthread_cond_t *, pthread_condattr_t *);
XPTHREAD_FUNC1(pthread_cond_signal, pthread_cond_t *);
XPTHREAD_FUNC1(pthread_cond_broadcast, pthread_cond_t *);
XPTHREAD_FUNC2(pthread_cond_wait, pthread_cond_t *, pthread_mutex_t *);

typedef void destructor_func(void *);
XPTHREAD_FUNC2(pthread_key_create, pthread_key_t *, destructor_func *);

void
xpthread_create(pthread_t *threadp, pthread_attr_t *attr,
                void *(*start)(void *), void *arg)
{
    pthread_t thread;
    int error;

    error = pthread_create(threadp ? threadp : &thread, attr, start, arg);
    if (error) {
        ovs_abort(error, "pthread_create failed");
    }
}
#endif
