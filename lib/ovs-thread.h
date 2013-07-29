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
#include <stddef.h>
#include <sys/types.h>
#include "ovs-atomic.h"
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
void xpthread_mutex_destroy(pthread_mutex_t *);
void xpthread_mutex_lock(pthread_mutex_t *mutex) OVS_ACQUIRES(mutex);
void xpthread_mutex_unlock(pthread_mutex_t *mutex) OVS_RELEASES(mutex);
int xpthread_mutex_trylock(pthread_mutex_t *);

void xpthread_mutexattr_init(pthread_mutexattr_t *);
void xpthread_mutexattr_destroy(pthread_mutexattr_t *);
void xpthread_mutexattr_settype(pthread_mutexattr_t *, int type);
void xpthread_mutexattr_gettype(pthread_mutexattr_t *, int *typep);

void xpthread_rwlock_init(pthread_rwlock_t *, pthread_rwlockattr_t *);
void xpthread_rwlock_destroy(pthread_rwlock_t *);
void xpthread_rwlock_rdlock(pthread_rwlock_t *rwlock) OVS_ACQUIRES(rwlock);
void xpthread_rwlock_wrlock(pthread_rwlock_t *rwlock) OVS_ACQUIRES(rwlock);
void xpthread_rwlock_unlock(pthread_rwlock_t *rwlock) OVS_RELEASES(rwlock);
int xpthread_rwlock_tryrdlock(pthread_rwlock_t *);
int xpthread_rwlock_trywrlock(pthread_rwlock_t *);

void xpthread_cond_init(pthread_cond_t *, pthread_condattr_t *);
void xpthread_cond_destroy(pthread_cond_t *);
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

/* Per-thread data.
 *
 * Multiple forms of per-thread data exist, each with its own pluses and
 * minuses:
 *
 *     - POSIX per-thread data via pthread_key_t is portable to any pthreads
 *       implementation, and allows a destructor function to be defined.  It
 *       only (directly) supports per-thread pointers, which are always
 *       initialized to NULL.  It requires once-only allocation of a
 *       pthread_key_t value.  It is relatively slow.
 *
 *     - The thread_local feature newly defined in C11 <threads.h> works with
 *       any data type and initializer, and it is fast.  thread_local does not
 *       require once-only initialization like pthread_key_t.  C11 does not
 *       define what happens if one attempts to access a thread_local object
 *       from a thread other than the one to which that object belongs.  There
 *       is no provision to call a user-specified destructor when a thread
 *       ends.
 *
 *     - The __thread keyword is a GCC extension similar to thread_local but
 *       with a longer history.  __thread is not portable to every GCC version
 *       or environment.  __thread does not restrict the use of a thread-local
 *       object outside its own thread.
 *
 * Here's a handy summary:
 *
 *                     pthread_key_t     thread_local       __thread
 *                     -------------     ------------     -------------
 * portability             high               low             medium
 * speed                    low              high               high
 * supports destructors?    yes                no                 no
 * needs key allocation?    yes                no                 no
 * arbitrary initializer?    no               yes                yes
 * cross-thread access?     yes                no                yes
 */

/* DEFINE_PER_THREAD_DATA(TYPE, NAME, INITIALIZER).
 *
 * One should prefer to use POSIX per-thread data, via pthread_key_t, when its
 * performance is acceptable, because of its portability (see the table above).
 * This macro is an alternatives that takes advantage of thread_local (and
 * __thread), for its performance, when it is available, and falls back to
 * POSIX per-thread data otherwise.
 *
 * Defines per-thread variable NAME with the given TYPE, initialized to
 * INITIALIZER (which must be valid as an initializer for a variable with
 * static lifetime).
 *
 * The public interface to the variable is:
 *
 *    TYPE *NAME_get(void)
 *    TYPE *NAME_get_unsafe(void)
 *
 *       Returns the address of this thread's instance of NAME.
 *
 *       Use NAME_get() in a context where this might be the first use of the
 *       per-thread variable in the program.  Use NAME_get_unsafe(), which
 *       avoids a conditional test and is thus slightly faster, in a context
 *       where one knows that NAME_get() has already been called previously.
 *
 * There is no "NAME_set()" (or "NAME_set_unsafe()") function.  To set the
 * value of the per-thread variable, dereference the pointer returned by
 * TYPE_get() or TYPE_get_unsafe(), e.g. *TYPE_get() = 0.
 */
#if HAVE_THREAD_LOCAL || HAVE___THREAD

#if HAVE_THREAD_LOCAL
#include <threads.h>
#elif HAVE___THREAD
#define thread_local __thread
#else
#error
#endif

#define DEFINE_PER_THREAD_DATA(TYPE, NAME, ...)                 \
    typedef TYPE NAME##_type;                                   \
    static thread_local NAME##_type NAME##_var = __VA_ARGS__;   \
                                                                \
    static NAME##_type *                                        \
    NAME##_get_unsafe(void)                                     \
    {                                                           \
        return &NAME##_var;                                     \
    }                                                           \
                                                                \
    static NAME##_type *                                        \
    NAME##_get(void)                                            \
    {                                                           \
        return NAME##_get_unsafe();                             \
    }
#else  /* no C implementation support for thread-local storage  */
#define DEFINE_PER_THREAD_DATA(TYPE, NAME, ...)                         \
    typedef TYPE NAME##_type;                                           \
    static pthread_key_t NAME##_key;                                    \
                                                                        \
    static NAME##_type *                                                \
    NAME##_get_unsafe(void)                                             \
    {                                                                   \
        return pthread_getspecific(NAME##_key);                         \
    }                                                                   \
                                                                        \
    static void                                                         \
    NAME##_once_init(void)                                              \
    {                                                                   \
        if (pthread_key_create(&NAME##_key, free)) {                    \
            abort();                                                    \
        }                                                               \
    }                                                                   \
                                                                        \
    static NAME##_type *                                                \
    NAME##_get(void)                                                    \
    {                                                                   \
        static pthread_once_t once = PTHREAD_ONCE_INIT;                 \
        NAME##_type *value;                                             \
                                                                        \
        pthread_once(&once, NAME##_once_init);                          \
        value = NAME##_get_unsafe();                                    \
        if (!value) {                                                   \
            static const NAME##_type initial_value = __VA_ARGS__;       \
                                                                        \
            value = xmalloc(sizeof *value);                             \
            *value = initial_value;                                     \
            pthread_setspecific(NAME##_key, value);                     \
        }                                                               \
        return value;                                                   \
    }
#endif

/* DEFINE_PER_THREAD_MALLOCED_DATA(TYPE, NAME).
 *
 * This is a simple wrapper around POSIX per-thread data primitives.  It
 * defines per-thread variable NAME with the given TYPE, which must be a
 * pointer type.  In each thread, the per-thread variable is initialized to
 * NULL.  When a thread terminates, the variable is freed with free().
 *
 * The public interface to the variable is:
 *
 *    TYPE NAME_get(void)
 *    TYPE NAME_get_unsafe(void)
 *
 *       Returns the value of per-thread variable NAME in this thread.
 *
 *       Use NAME_get() in a context where this might be the first use of the
 *       per-thread variable in the program.  Use NAME_get_unsafe(), which
 *       avoids a conditional test and is thus slightly faster, in a context
 *       where one knows that NAME_get() has already been called previously.
 *
 *    TYPE NAME_set(TYPE new_value)
 *    TYPE NAME_set_unsafe(TYPE new_value)
 *
 *       Sets the value of per-thread variable NAME to 'new_value' in this
 *       thread, and returns its previous value.
 *
 *       Use NAME_set() in a context where this might be the first use of the
 *       per-thread variable in the program.  Use NAME_set_unsafe(), which
 *       avoids a conditional test and is thus slightly faster, in a context
 *       where one knows that NAME_set() has already been called previously.
 */
#define DEFINE_PER_THREAD_MALLOCED_DATA(TYPE, NAME)     \
    static pthread_key_t NAME##_key;                    \
                                                        \
    static void                                         \
    NAME##_once_init(void)                              \
    {                                                   \
        if (pthread_key_create(&NAME##_key, free)) {    \
            abort();                                    \
        }                                               \
    }                                                   \
                                                        \
    static void                                         \
    NAME##_init(void)                                   \
    {                                                   \
        static pthread_once_t once = PTHREAD_ONCE_INIT; \
        pthread_once(&once, NAME##_once_init);          \
    }                                                   \
                                                        \
    static TYPE                                         \
    NAME##_get_unsafe(void)                             \
    {                                                   \
        return pthread_getspecific(NAME##_key);         \
    }                                                   \
                                                        \
    static OVS_UNUSED TYPE                              \
    NAME##_get(void)                                    \
    {                                                   \
        NAME##_init();                                  \
        return NAME##_get_unsafe();                     \
    }                                                   \
                                                        \
    static TYPE                                         \
    NAME##_set_unsafe(TYPE value)                       \
    {                                                   \
        TYPE old_value = NAME##_get_unsafe();           \
        pthread_setspecific(NAME##_key, value);         \
        return old_value;                               \
    }                                                   \
                                                        \
    static OVS_UNUSED TYPE                              \
    NAME##_set(TYPE value)                              \
    {                                                   \
        NAME##_init();                                  \
        return NAME##_set_unsafe(value);                \
    }

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
    atomic_bool done;
    pthread_mutex_t mutex;
};

#define OVSTHREAD_ONCE_INITIALIZER              \
    {                                           \
        ATOMIC_VAR_INIT(false),                 \
        PTHREAD_ADAPTIVE_MUTEX_INITIALIZER,     \
    }

static inline bool ovsthread_once_start(struct ovsthread_once *);
void ovsthread_once_done(struct ovsthread_once *once) OVS_RELEASES(once);

bool ovsthread_once_start__(struct ovsthread_once *);

static inline bool
ovsthread_once_is_done__(const struct ovsthread_once *once)
{
    bool done;

    atomic_read_explicit(&once->done, &done, memory_order_relaxed);
    return done;
}

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
    return OVS_UNLIKELY(!ovsthread_once_is_done__(once)
                        && !ovsthread_once_start__(once));
}

#ifdef __CHECKER__
#define ovsthread_once_start(ONCE) \
    ((ONCE)->done ? false : ({ OVS_ACQUIRE(ONCE); true; }))
#endif

void assert_single_threaded_at(const char *where);
#define assert_single_threaded() assert_single_threaded_at(SOURCE_LOCATOR)

pid_t xfork_at(const char *where);
#define xfork() xfork_at(SOURCE_LOCATOR)

void forbid_forking(const char *reason);
bool may_fork(void);

#endif /* ovs-thread.h */
