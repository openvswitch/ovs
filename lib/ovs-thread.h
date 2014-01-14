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

#ifndef OVS_THREAD_H
#define OVS_THREAD_H 1

#include <pthread.h>
#include <stddef.h>
#include <sys/types.h>
#include "ovs-atomic.h"
#include "util.h"


/* Mutex. */
struct OVS_LOCKABLE ovs_mutex {
    pthread_mutex_t lock;
    const char *where;
};

/* "struct ovs_mutex" initializer. */
#ifdef PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#define OVS_MUTEX_INITIALIZER { PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP, NULL }
#else
#define OVS_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER, NULL }
#endif

/* ovs_mutex functions analogous to pthread_mutex_*() functions.
 *
 * Most of these functions abort the process with an error message on any
 * error.  ovs_mutex_trylock() is an exception: it passes through a 0 or EBUSY
 * return value to the caller and aborts on any other error. */
void ovs_mutex_init(const struct ovs_mutex *);
void ovs_mutex_init_recursive(const struct ovs_mutex *);
void ovs_mutex_destroy(const struct ovs_mutex *);
void ovs_mutex_unlock(const struct ovs_mutex *mutex) OVS_RELEASES(mutex);
void ovs_mutex_lock_at(const struct ovs_mutex *mutex, const char *where)
    OVS_ACQUIRES(mutex);
#define ovs_mutex_lock(mutex) \
        ovs_mutex_lock_at(mutex, SOURCE_LOCATOR)

int ovs_mutex_trylock_at(const struct ovs_mutex *mutex, const char *where)
    OVS_TRY_LOCK(0, mutex);
#define ovs_mutex_trylock(mutex) \
        ovs_mutex_trylock_at(mutex, SOURCE_LOCATOR)

void ovs_mutex_cond_wait(pthread_cond_t *, const struct ovs_mutex *);

/* Wrappers for pthread_mutex_*() that abort the process on any error.
 * This is still needed when ovs-atomic-pthreads.h is used. */
void xpthread_mutex_lock(pthread_mutex_t *mutex);
void xpthread_mutex_unlock(pthread_mutex_t *mutex);

/* Wrappers for pthread_mutexattr_*() that abort the process on any error. */
void xpthread_mutexattr_init(pthread_mutexattr_t *);
void xpthread_mutexattr_destroy(pthread_mutexattr_t *);
void xpthread_mutexattr_settype(pthread_mutexattr_t *, int type);
void xpthread_mutexattr_gettype(pthread_mutexattr_t *, int *typep);

/* Read-write lock. */
struct OVS_LOCKABLE ovs_rwlock {
    pthread_rwlock_t lock;
    const char *where;
};

/* Initializer. */
#define OVS_RWLOCK_INITIALIZER { PTHREAD_RWLOCK_INITIALIZER, NULL }

/* ovs_rwlock functions analogous to pthread_rwlock_*() functions.
 *
 * Most of these functions abort the process with an error message on any
 * error.  The "trylock" functions are exception: they pass through a 0 or
 * EBUSY return value to the caller and abort on any other error. */
void ovs_rwlock_init(const struct ovs_rwlock *);
void ovs_rwlock_destroy(const struct ovs_rwlock *);
void ovs_rwlock_unlock(const struct ovs_rwlock *rwlock) OVS_RELEASES(rwlock);

void ovs_rwlock_wrlock_at(const struct ovs_rwlock *rwlock, const char *where)
    OVS_ACQ_WRLOCK(rwlock);
#define ovs_rwlock_wrlock(rwlock) \
        ovs_rwlock_wrlock_at(rwlock, SOURCE_LOCATOR)

int ovs_rwlock_trywrlock_at(const struct ovs_rwlock *rwlock, const char *where)
    OVS_TRY_WRLOCK(0, rwlock);
#define ovs_rwlock_trywrlock(rwlock) \
    ovs_rwlock_trywrlock_at(rwlock, SOURCE_LOCATOR)

void ovs_rwlock_rdlock_at(const struct ovs_rwlock *rwlock, const char *where)
    OVS_ACQ_RDLOCK(rwlock);
#define ovs_rwlock_rdlock(rwlock) \
        ovs_rwlock_rdlock_at(rwlock, SOURCE_LOCATOR)

int ovs_rwlock_tryrdlock_at(const struct ovs_rwlock *rwlock, const char *where)
    OVS_TRY_RDLOCK(0, rwlock);
#define ovs_rwlock_tryrdlock(rwlock) \
        ovs_rwlock_tryrdlock_at(rwlock, SOURCE_LOCATOR)

/* Wrappers for xpthread_cond_*() that abort the process on any error.
 *
 * Use ovs_mutex_cond_wait() to wait for a condition. */
void xpthread_cond_init(pthread_cond_t *, pthread_condattr_t *);
void xpthread_cond_destroy(pthread_cond_t *);
void xpthread_cond_signal(pthread_cond_t *);
void xpthread_cond_broadcast(pthread_cond_t *);

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
void xpthread_key_delete(pthread_key_t);
void xpthread_setspecific(pthread_key_t, const void *);

void xpthread_create(pthread_t *, pthread_attr_t *, void *(*)(void *), void *);
void xpthread_join(pthread_t, void **);

/* Per-thread data.
 *
 *
 * Standard Forms
 * ==============
 *
 * Multiple forms of standard per-thread data exist, each with its own pluses
 * and minuses.  In general, if one of these forms is appropriate, then it's a
 * good idea to use it:
 *
 *     - POSIX per-thread data via pthread_key_t is portable to any pthreads
 *       implementation, and allows a destructor function to be defined.  It
 *       only (directly) supports per-thread pointers, which are always
 *       initialized to NULL.  It requires once-only allocation of a
 *       pthread_key_t value.  It is relatively slow.  Typically few
 *       "pthread_key_t"s are available (POSIX requires only at least 128,
 *       glibc supplies only 1024).
 *
 *     - The thread_local feature newly defined in C11 <threads.h> works with
 *       any data type and initializer, and it is fast.  thread_local does not
 *       require once-only initialization like pthread_key_t.  C11 does not
 *       define what happens if one attempts to access a thread_local object
 *       from a thread other than the one to which that object belongs.  There
 *       is no provision to call a user-specified destructor when a thread
 *       ends.  Typical implementations allow for an arbitrary amount of
 *       thread_local storage, but statically allocated only.
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
 * amount available?        few            arbitrary         arbitrary
 * dynamically allocated?   yes                no                 no
 *
 *
 * Extensions
 * ==========
 *
 * OVS provides some extensions and wrappers:
 *
 *     - In a situation where the performance of thread_local or __thread is
 *       desirable, but portability is required, DEFINE_STATIC_PER_THREAD_DATA
 *       and DECLARE_EXTERN_PER_THREAD_DATA/DEFINE_EXTERN_PER_THREAD_DATA may
 *       be appropriate (see below).
 *
 *     - DEFINE_PER_THREAD_MALLOCED_DATA can be convenient for simple
 *       per-thread malloc()'d buffers.
 *
 *     - struct ovs_tsd provides an alternative to pthread_key_t that isn't
 *       limited to a small number of keys.
 */

/* For static data, use this macro in a source file:
 *
 *    DEFINE_STATIC_PER_THREAD_DATA(TYPE, NAME, INITIALIZER).
 *
 * For global data, "declare" the data in the header and "define" it in
 * the source file, with:
 *
 *    DECLARE_EXTERN_PER_THREAD_DATA(TYPE, NAME).
 *    DEFINE_EXTERN_PER_THREAD_DATA(NAME, INITIALIZER).
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

#define DEFINE_STATIC_PER_THREAD_DATA(TYPE, NAME, ...)                  \
    typedef TYPE NAME##_type;                                           \
                                                                        \
    static NAME##_type *                                                \
    NAME##_get_unsafe(void)                                             \
    {                                                                   \
        static thread_local NAME##_type var = __VA_ARGS__;              \
        return &var;                                                    \
    }                                                                   \
                                                                        \
    static NAME##_type *                                                \
    NAME##_get(void)                                                    \
    {                                                                   \
        return NAME##_get_unsafe();                                     \
    }
#define DECLARE_EXTERN_PER_THREAD_DATA(TYPE, NAME)                      \
    typedef TYPE NAME##_type;                                           \
    extern thread_local NAME##_type NAME##_var;                         \
                                                                        \
    static inline NAME##_type *                                         \
    NAME##_get_unsafe(void)                                             \
    {                                                                   \
        return &NAME##_var;                                             \
    }                                                                   \
                                                                        \
    static inline NAME##_type *                                         \
    NAME##_get(void)                                                    \
    {                                                                   \
        return NAME##_get_unsafe();                                     \
    }
#define DEFINE_EXTERN_PER_THREAD_DATA(NAME, ...)         \
    thread_local NAME##_type NAME##_var = __VA_ARGS__;
#else  /* no C implementation support for thread-local storage  */
#define DEFINE_STATIC_PER_THREAD_DATA(TYPE, NAME, ...)                  \
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
            value = malloc(sizeof *value);                              \
            if (value == NULL) {                                        \
                out_of_memory();                                        \
            }                                                           \
            *value = initial_value;                                     \
            xpthread_setspecific(NAME##_key, value);                    \
        }                                                               \
        return value;                                                   \
    }
#define DECLARE_EXTERN_PER_THREAD_DATA(TYPE, NAME)                      \
    typedef TYPE NAME##_type;                                           \
    static pthread_key_t NAME##_key;                                    \
                                                                        \
    static inline NAME##_type *                                         \
    NAME##_get_unsafe(void)                                             \
    {                                                                   \
        return pthread_getspecific(NAME##_key);                         \
    }                                                                   \
                                                                        \
    NAME##_type *NAME##_get(void);
#define DEFINE_EXTERN_PER_THREAD_DATA(NAME, ...)                        \
    static void                                                         \
    NAME##_once_init(void)                                              \
    {                                                                   \
        if (pthread_key_create(&NAME##_key, free)) {                    \
            abort();                                                    \
        }                                                               \
    }                                                                   \
                                                                        \
    NAME##_type *                                                       \
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
            value = malloc(sizeof *value);                              \
            if (value == NULL) {                                        \
                out_of_memory();                                        \
            }                                                           \
            *value = initial_value;                                     \
            xpthread_setspecific(NAME##_key, value);                    \
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
        xpthread_setspecific(NAME##_key, value);        \
        return old_value;                               \
    }                                                   \
                                                        \
    static OVS_UNUSED TYPE                              \
    NAME##_set(TYPE value)                              \
    {                                                   \
        NAME##_init();                                  \
        return NAME##_set_unsafe(value);                \
    }

/* Dynamically allocated thread-specific data with lots of slots.
 *
 * pthread_key_t can provide as few as 128 pieces of thread-specific data (even
 * glibc is limited to 1,024).  Thus, one must be careful to allocate only a
 * few keys globally.  One cannot, for example, allocate a key for every
 * instance of a data structure if there might be an arbitrary number of those
 * data structures.
 *
 * This API is similar to the pthread one (simply search and replace pthread_
 * by ovsthread_) but it a much larger limit that can be raised if necessary
 * (by recompiling).  Thus, one may more freely use this form of
 * thread-specific data.
 *
 * Compared to pthread_key_t, ovsthread_key_t has the follow limitations:
 *
 *    - Destructors must not access thread-specific data (via ovsthread_key).
 */
typedef struct ovsthread_key *ovsthread_key_t;

void ovsthread_key_create(ovsthread_key_t *, void (*destructor)(void *));
void ovsthread_key_delete(ovsthread_key_t);

void ovsthread_setspecific(ovsthread_key_t, const void *);
void *ovsthread_getspecific(ovsthread_key_t);

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
    struct ovs_mutex mutex;
};

#define OVSTHREAD_ONCE_INITIALIZER              \
    {                                           \
        ATOMIC_VAR_INIT(false),                 \
        OVS_MUTEX_INITIALIZER,                  \
    }

static inline bool ovsthread_once_start(struct ovsthread_once *once)
    OVS_TRY_LOCK(true, once->mutex);
void ovsthread_once_done(struct ovsthread_once *once)
    OVS_RELEASES(once->mutex);

bool ovsthread_once_start__(struct ovsthread_once *once)
    OVS_TRY_LOCK(false, once->mutex);

static inline bool
ovsthread_once_is_done__(struct ovsthread_once *once)
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

/* Thread ID.
 *
 * pthread_t isn't so nice for some purposes.  Its size and representation are
 * implementation dependent, which means that there is no way to hash it.
 * This thread ID avoids the problem.
 */

DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, ovsthread_id);

/* Returns a per-thread identifier unique within the lifetime of the
 * process. */
static inline unsigned int
ovsthread_id_self(void)
{
    return *ovsthread_id_get();
}

void assert_single_threaded_at(const char *where);
#define assert_single_threaded() assert_single_threaded_at(SOURCE_LOCATOR)

pid_t xfork_at(const char *where);
#define xfork() xfork_at(SOURCE_LOCATOR)

void forbid_forking(const char *reason);
bool may_fork(void);

/* Useful functions related to threading. */

int count_cpu_cores(void);

#endif /* ovs-thread.h */
