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
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include "compiler.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"

#ifdef __CHECKER__
/* Omit the definitions in this file because they are somewhat difficult to
 * write without prompting "sparse" complaints, without ugliness or
 * cut-and-paste.  Since "sparse" is just a checker, not a compiler, it
 * doesn't matter that we don't define them. */
#else
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_thread);

/* If there is a reason that we cannot fork anymore (unless the fork will be
 * immediately followed by an exec), then this points to a string that
 * explains why. */
static const char *must_not_fork;

/* True if we created any threads beyond the main initial thread. */
static bool multithreaded;

#define LOCK_FUNCTION(TYPE, FUN) \
    void \
    ovs_##TYPE##_##FUN##_at(const struct ovs_##TYPE *l_, \
                            const char *where) \
        OVS_NO_THREAD_SAFETY_ANALYSIS \
    { \
        struct ovs_##TYPE *l = CONST_CAST(struct ovs_##TYPE *, l_); \
        int error = pthread_##TYPE##_##FUN(&l->lock); \
        if (OVS_UNLIKELY(error)) { \
            ovs_abort(error, "pthread_%s_%s failed", #TYPE, #FUN); \
        } \
        l->where = where; \
    }
LOCK_FUNCTION(mutex, lock);
LOCK_FUNCTION(rwlock, rdlock);
LOCK_FUNCTION(rwlock, wrlock);

#define TRY_LOCK_FUNCTION(TYPE, FUN) \
    int \
    ovs_##TYPE##_##FUN##_at(const struct ovs_##TYPE *l_, \
                            const char *where) \
        OVS_NO_THREAD_SAFETY_ANALYSIS \
    { \
        struct ovs_##TYPE *l = CONST_CAST(struct ovs_##TYPE *, l_); \
        int error = pthread_##TYPE##_##FUN(&l->lock); \
        if (OVS_UNLIKELY(error) && error != EBUSY) { \
            ovs_abort(error, "pthread_%s_%s failed", #TYPE, #FUN); \
        } \
        if (!error) { \
            l->where = where; \
        } \
        return error; \
    }
TRY_LOCK_FUNCTION(mutex, trylock);
TRY_LOCK_FUNCTION(rwlock, tryrdlock);
TRY_LOCK_FUNCTION(rwlock, trywrlock);

#define UNLOCK_FUNCTION(TYPE, FUN) \
    void \
    ovs_##TYPE##_##FUN(const struct ovs_##TYPE *l_) \
        OVS_NO_THREAD_SAFETY_ANALYSIS \
    { \
        struct ovs_##TYPE *l = CONST_CAST(struct ovs_##TYPE *, l_); \
        int error; \
        l->where = NULL; \
        error = pthread_##TYPE##_##FUN(&l->lock); \
        if (OVS_UNLIKELY(error)) { \
            ovs_abort(error, "pthread_%s_%sfailed", #TYPE, #FUN); \
        } \
    }
UNLOCK_FUNCTION(mutex, unlock);
UNLOCK_FUNCTION(mutex, destroy);
UNLOCK_FUNCTION(rwlock, unlock);
UNLOCK_FUNCTION(rwlock, destroy);

#define XPTHREAD_FUNC1(FUNCTION, PARAM1)                \
    void                                                \
    x##FUNCTION(PARAM1 arg1)                            \
    {                                                   \
        int error = FUNCTION(arg1);                     \
        if (OVS_UNLIKELY(error)) {                      \
            ovs_abort(error, "%s failed", #FUNCTION);   \
        }                                               \
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

XPTHREAD_FUNC1(pthread_mutex_lock, pthread_mutex_t *);
XPTHREAD_FUNC1(pthread_mutex_unlock, pthread_mutex_t *);
XPTHREAD_FUNC1(pthread_mutexattr_init, pthread_mutexattr_t *);
XPTHREAD_FUNC1(pthread_mutexattr_destroy, pthread_mutexattr_t *);
XPTHREAD_FUNC2(pthread_mutexattr_settype, pthread_mutexattr_t *, int);
XPTHREAD_FUNC2(pthread_mutexattr_gettype, pthread_mutexattr_t *, int *);

XPTHREAD_FUNC2(pthread_cond_init, pthread_cond_t *, pthread_condattr_t *);
XPTHREAD_FUNC1(pthread_cond_destroy, pthread_cond_t *);
XPTHREAD_FUNC1(pthread_cond_signal, pthread_cond_t *);
XPTHREAD_FUNC1(pthread_cond_broadcast, pthread_cond_t *);

XPTHREAD_FUNC2(pthread_join, pthread_t, void **);

typedef void destructor_func(void *);
XPTHREAD_FUNC2(pthread_key_create, pthread_key_t *, destructor_func *);
XPTHREAD_FUNC2(pthread_setspecific, pthread_key_t, const void *);

static void
ovs_mutex_init__(const struct ovs_mutex *l_, int type)
{
    struct ovs_mutex *l = CONST_CAST(struct ovs_mutex *, l_);
    pthread_mutexattr_t attr;
    int error;

    l->where = NULL;
    xpthread_mutexattr_init(&attr);
    xpthread_mutexattr_settype(&attr, type);
    error = pthread_mutex_init(&l->lock, &attr);
    if (OVS_UNLIKELY(error)) {
        ovs_abort(error, "pthread_mutex_init failed");
    }
    xpthread_mutexattr_destroy(&attr);
}

/* Initializes 'mutex' as a normal (non-recursive) mutex. */
void
ovs_mutex_init(const struct ovs_mutex *mutex)
{
    ovs_mutex_init__(mutex, PTHREAD_MUTEX_ERRORCHECK);
}

/* Initializes 'mutex' as a recursive mutex. */
void
ovs_mutex_init_recursive(const struct ovs_mutex *mutex)
{
    ovs_mutex_init__(mutex, PTHREAD_MUTEX_RECURSIVE);
}

void
ovs_rwlock_init(const struct ovs_rwlock *l_)
{
    struct ovs_rwlock *l = CONST_CAST(struct ovs_rwlock *, l_);
    int error;

    l->where = NULL;
    error = pthread_rwlock_init(&l->lock, NULL);
    if (OVS_UNLIKELY(error)) {
        ovs_abort(error, "pthread_rwlock_init failed");
    }
}

void
ovs_mutex_cond_wait(pthread_cond_t *cond, const struct ovs_mutex *mutex_)
{
    struct ovs_mutex *mutex = CONST_CAST(struct ovs_mutex *, mutex_);
    int error = pthread_cond_wait(cond, &mutex->lock);
    if (OVS_UNLIKELY(error)) {
        ovs_abort(error, "pthread_cond_wait failed");
    }
}

DEFINE_EXTERN_PER_THREAD_DATA(ovsthread_id, 0);

struct ovsthread_aux {
    void *(*start)(void *);
    void *arg;
};

static void *
ovsthread_wrapper(void *aux_)
{
    static atomic_uint next_id = ATOMIC_VAR_INIT(1);

    struct ovsthread_aux *auxp = aux_;
    struct ovsthread_aux aux;
    unsigned int id;

    atomic_add(&next_id, 1, &id);
    *ovsthread_id_get() = id;

    aux = *auxp;
    free(auxp);

    return aux.start(aux.arg);
}

void
xpthread_create(pthread_t *threadp, pthread_attr_t *attr,
                void *(*start)(void *), void *arg)
{
    struct ovsthread_aux *aux;
    pthread_t thread;
    int error;

    forbid_forking("multiple threads exist");
    multithreaded = true;

    aux = xmalloc(sizeof *aux);
    aux->start = start;
    aux->arg = arg;

    error = pthread_create(threadp ? threadp : &thread, attr,
                           ovsthread_wrapper, aux);
    if (error) {
        ovs_abort(error, "pthread_create failed");
    }
}

bool
ovsthread_once_start__(struct ovsthread_once *once)
{
    ovs_mutex_lock(&once->mutex);
    if (!ovsthread_once_is_done__(once)) {
        return false;
    }
    ovs_mutex_unlock(&once->mutex);
    return true;
}

void
ovsthread_once_done(struct ovsthread_once *once)
{
    atomic_store(&once->done, true);
    ovs_mutex_unlock(&once->mutex);
}

/* Asserts that the process has not yet created any threads (beyond the initial
 * thread).
 *
 * ('where' is used in logging.  Commonly one would use
 * assert_single_threaded() to automatically provide the caller's source file
 * and line number for 'where'.) */
void
assert_single_threaded_at(const char *where)
{
    if (multithreaded) {
        VLOG_FATAL("%s: attempted operation not allowed when multithreaded",
                   where);
    }
}

/* Forks the current process (checking that this is allowed).  Aborts with
 * VLOG_FATAL if fork() returns an error, and otherwise returns the value
 * returned by fork().
 *
 * ('where' is used in logging.  Commonly one would use xfork() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
pid_t
xfork_at(const char *where)
{
    pid_t pid;

    if (must_not_fork) {
        VLOG_FATAL("%s: attempted to fork but forking not allowed (%s)",
                   where, must_not_fork);
    }

    pid = fork();
    if (pid < 0) {
        VLOG_FATAL("%s: fork failed (%s)", where, ovs_strerror(errno));
    }
    return pid;
}

/* Notes that the process must not call fork() from now on, for the specified
 * 'reason'.  (The process may still fork() if it execs itself immediately
 * afterward.) */
void
forbid_forking(const char *reason)
{
    ovs_assert(reason != NULL);
    must_not_fork = reason;
}

/* Returns true if the process is allowed to fork, false otherwise. */
bool
may_fork(void)
{
    return !must_not_fork;
}
#endif
