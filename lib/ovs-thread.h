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

#ifndef OVS_THREAD_H
#define OVS_THREAD_H 1

#include <pthread.h>
#include "util.h"

/* glibc has some non-portable mutex types and initializers:
 *
 *    - PTHREAD_MUTEX_ADAPTIVE_NP is a mutex type that works as a spinlock that
 *      falls back to a mutex after spinning for some number of iterations.
 *
 *    - PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP is a non-portable initializer
 *      for an error-checking mutex.
 *
 * We use these definitions to fall back to PTHREAD_MUTEX_NORMAL instead in
 * these cases.
 *
 * (glibc has other non-portable initializers, but we can't reasonably
 * substitute for them here.) */
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#define PTHREAD_MUTEX_ADAPTIVE PTHREAD_MUTEX_ADAPTIVE_NP
#define PTHREAD_ADAPTIVE_MUTEX_INITIALIZER \
    PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#else
#define PTHREAD_MUTEX_ADAPTIVE PTHREAD_MUTEX_NORMAL
#define PTHREAD_ADAPTIVE_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#endif

#ifdef PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#define PTHREAD_ERRORCHECK_MUTEX_INITIALIZER \
    PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#else
#define PTHREAD_ERRORCHECK_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#endif

/* Simple wrappers for pthreads functions.  Most of these functions abort the
 * process with an error message on any error.  The *_trylock() functions are
 * exceptions: they pass through a 0 or EBUSY return value to the caller and
 * abort on any other error. */
void xpthread_mutex_init(pthread_mutex_t *, pthread_mutexattr_t *);
void xpthread_mutex_lock(pthread_mutex_t *mutex) OVS_ACQUIRES(mutex);
void xpthread_mutex_unlock(pthread_mutex_t *mutex) OVS_RELEASES(mutex);
int xpthread_mutex_trylock(pthread_mutex_t *);

void xpthread_rwlock_init(pthread_rwlock_t *, pthread_rwlockattr_t *);
void xpthread_rwlock_rdlock(pthread_rwlock_t *rwlock) OVS_ACQUIRES(rwlock);
void xpthread_rwlock_wrlock(pthread_rwlock_t *rwlock) OVS_ACQUIRES(rwlock);
void xpthread_rwlock_unlock(pthread_rwlock_t *rwlock) OVS_RELEASES(rwlock);
int xpthread_rwlock_tryrdlock(pthread_rwlock_t *);
int xpthread_rwlock_trywrlock(pthread_rwlock_t *);

void xpthread_cond_init(pthread_cond_t *, pthread_condattr_t *);
void xpthread_cond_signal(pthread_cond_t *);
void xpthread_cond_broadcast(pthread_cond_t *);
void xpthread_cond_wait(pthread_cond_t *, pthread_mutex_t *mutex)
    OVS_MUST_HOLD(mutex);

#ifdef __CHECKER__
/* Replace these functions by the macros already defined in the <pthread.h>
 * annotations, because the macro definitions have correct semantics for the
 * conditional acquisition that can't be captured in a function annotation.
 * The difference in semantics from pthread_*() to xpthread_*() does not matter
 * because sparse is not a compiler. */
#define xpthread_mutex_trylock pthread_mutex_trylock
#define xpthread_rwlock_tryrdlock pthread_rwlock_tryrdlock
#define xpthread_rwlock_trywrlock pthread_rwlock_trywrlock
#endif

void xpthread_key_create(pthread_key_t *, void (*destructor)(void *));

void xpthread_create(pthread_t *, pthread_attr_t *, void *(*)(void *), void *);

#endif /* ovs-thread.h */
