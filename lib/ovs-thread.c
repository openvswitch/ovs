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
XPTHREAD_FUNC1(pthread_mutex_destroy, pthread_mutex_t *);
XPTHREAD_FUNC1(pthread_mutex_lock, pthread_mutex_t *);
XPTHREAD_FUNC1(pthread_mutex_unlock, pthread_mutex_t *);
XPTHREAD_TRY_FUNC1(pthread_mutex_trylock, pthread_mutex_t *);

XPTHREAD_FUNC1(pthread_mutexattr_init, pthread_mutexattr_t *);
XPTHREAD_FUNC1(pthread_mutexattr_destroy, pthread_mutexattr_t *);
XPTHREAD_FUNC2(pthread_mutexattr_settype, pthread_mutexattr_t *, int);
XPTHREAD_FUNC2(pthread_mutexattr_gettype, pthread_mutexattr_t *, int *);

XPTHREAD_FUNC2(pthread_rwlock_init,
               pthread_rwlock_t *, pthread_rwlockattr_t *);
XPTHREAD_FUNC1(pthread_rwlock_destroy, pthread_rwlock_t *);
XPTHREAD_FUNC1(pthread_rwlock_rdlock, pthread_rwlock_t *);
XPTHREAD_FUNC1(pthread_rwlock_wrlock, pthread_rwlock_t *);
XPTHREAD_FUNC1(pthread_rwlock_unlock, pthread_rwlock_t *);
XPTHREAD_TRY_FUNC1(pthread_rwlock_tryrdlock, pthread_rwlock_t *);
XPTHREAD_TRY_FUNC1(pthread_rwlock_trywrlock, pthread_rwlock_t *);

XPTHREAD_FUNC2(pthread_cond_init, pthread_cond_t *, pthread_condattr_t *);
XPTHREAD_FUNC1(pthread_cond_destroy, pthread_cond_t *);
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

    forbid_forking("multiple threads exist");
    multithreaded = true;

    error = pthread_create(threadp ? threadp : &thread, attr, start, arg);
    if (error) {
        ovs_abort(error, "pthread_create failed");
    }
}

bool
ovsthread_once_start__(struct ovsthread_once *once)
{
    xpthread_mutex_lock(&once->mutex);
    if (!ovsthread_once_is_done__(once)) {
        return false;
    }
    xpthread_mutex_unlock(&once->mutex);
    return true;
}

void OVS_RELEASES(once)
ovsthread_once_done(struct ovsthread_once *once)
{
    atomic_store(&once->done, true);
    xpthread_mutex_unlock(&once->mutex);
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
        VLOG_FATAL("fork failed (%s)", ovs_strerror(errno));
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
