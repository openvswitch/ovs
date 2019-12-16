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

#ifndef OPENVSWITCH_THREAD_H
#define OPENVSWITCH_THREAD_H 1

#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include "openvswitch/compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Mutex. */
struct OVS_LOCKABLE ovs_mutex {
    pthread_mutex_t lock;
    const char *where;          /* NULL if and only if uninitialized. */
};

#ifdef HAVE_PTHREAD_SPIN_LOCK
struct OVS_LOCKABLE ovs_spin {
    pthread_spinlock_t lock;
    const char *where;          /* NULL if and only if uninitialized. */
};
#endif

/* "struct ovs_mutex" initializer. */
#ifdef PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#define OVS_MUTEX_INITIALIZER { PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP, \
                                "<unlocked>" }
#else
#define OVS_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER, "<unlocked>" }
#endif

#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#define OVS_ADAPTIVE_MUTEX_INITIALIZER                  \
    { PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP, "<unlocked>" }
#else
#define OVS_ADAPTIVE_MUTEX_INITIALIZER OVS_MUTEX_INITIALIZER
#endif

/* ovs_mutex functions analogous to pthread_mutex_*() functions.
 *
 * Most of these functions abort the process with an error message on any
 * error.  ovs_mutex_trylock() is an exception: it passes through a 0 or EBUSY
 * return value to the caller and aborts on any other error. */
void ovs_mutex_init(const struct ovs_mutex *);
void ovs_mutex_init_recursive(const struct ovs_mutex *);
void ovs_mutex_init_adaptive(const struct ovs_mutex *);
void ovs_mutex_destroy(const struct ovs_mutex *);
void ovs_mutex_unlock(const struct ovs_mutex *mutex) OVS_RELEASES(mutex);
void ovs_mutex_lock_at(const struct ovs_mutex *mutex, const char *where)
    OVS_ACQUIRES(mutex);
#define ovs_mutex_lock(mutex) \
        ovs_mutex_lock_at(mutex, OVS_SOURCE_LOCATOR)

int ovs_mutex_trylock_at(const struct ovs_mutex *mutex, const char *where)
    OVS_TRY_LOCK(0, mutex);
#define ovs_mutex_trylock(mutex) \
        ovs_mutex_trylock_at(mutex, OVS_SOURCE_LOCATOR)

void ovs_mutex_cond_wait(pthread_cond_t *, const struct ovs_mutex *mutex)
    OVS_REQUIRES(mutex);

#ifdef HAVE_PTHREAD_SPIN_LOCK
void ovs_spin_init(const struct ovs_spin *);
void ovs_spin_destroy(const struct ovs_spin *);
void ovs_spin_unlock(const struct ovs_spin *spin) OVS_RELEASES(spin);
void ovs_spin_lock_at(const struct ovs_spin *spin, const char *where)
    OVS_ACQUIRES(spin);
#define ovs_spin_lock(spin) \
        ovs_spin_lock_at(spin, OVS_SOURCE_LOCATOR)

int ovs_spin_trylock_at(const struct ovs_spin *spin, const char *where)
    OVS_TRY_LOCK(0, spin);
#define ovs_spin_trylock(spin) \
        ovs_spin_trylock_at(spin, OVS_SOURCE_LOCATOR)
#endif

/* Convenient once-only execution.
 *
 *
 * Problem
 * =======
 *
 * POSIX provides pthread_once_t and pthread_once() as primitives for running a
 * set of code only once per process execution.  They are used like this:
 *
 *     static void run_once(void) { ...initialization... }
 *     static pthread_once_t once = PTHREAD_ONCE_INIT;
 * ...
 *     pthread_once(&once, run_once);
 *
 * pthread_once() does not allow passing any parameters to the initialization
 * function, which is often inconvenient, because it means that the function
 * can only access data declared at file scope.
 *
 *
 * Solution
 * ========
 *
 * Use ovsthread_once, like this, instead:
 *
 *     static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
 *
 *     if (ovsthread_once_start(&once)) {
 *         ...initialization...
 *         ovsthread_once_done(&once);
 *     }
 */

struct ovsthread_once {
    bool done;               /* Non-atomic, false negatives possible. */
    struct ovs_mutex mutex;
};

#define OVSTHREAD_ONCE_INITIALIZER              \
    {                                           \
        false,                                  \
        OVS_MUTEX_INITIALIZER,                  \
    }

static inline bool ovsthread_once_start(struct ovsthread_once *once)
    OVS_TRY_LOCK(true, once->mutex);
void ovsthread_once_done(struct ovsthread_once *once)
    OVS_RELEASES(once->mutex);

bool ovsthread_once_start__(struct ovsthread_once *once)
    OVS_TRY_LOCK(true, once->mutex);

/* Returns true if this is the first call to ovsthread_once_start() for
 * 'once'.  In this case, the caller should perform whatever initialization
 * actions it needs to do, then call ovsthread_once_done() for 'once'.
 *
 * Returns false if this is not the first call to ovsthread_once_start() for
 * 'once'.  In this case, the call will not return until after
 * ovsthread_once_done() has been called. */
static inline bool
ovsthread_once_start(struct ovsthread_once *once)
{
    /* We may be reading 'done' at the same time as the first thread
     * is writing on it, or we can be using a stale copy of it.  The
     * worst that can happen is that we call ovsthread_once_start__()
     * once when strictly not necessary. */
    return OVS_UNLIKELY(!once->done && ovsthread_once_start__(once));
}

#ifdef __cplusplus
}
#endif

#endif /* ovs-thread.h */
