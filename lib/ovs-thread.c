/*
 * Copyright (c) 2013, 2014, 2015, 2016 Nicira, Inc.
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
#ifndef _WIN32
#include <signal.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include "compiler.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/list.h"
#include "netdev-dpdk.h"
#include "ovs-rcu.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "socket-util.h"
#include "util.h"

#ifdef __CHECKER__
/* Omit the definitions in this file because they are somewhat difficult to
 * write without prompting "sparse" complaints, without ugliness or
 * cut-and-paste.  Since "sparse" is just a checker, not a compiler, it
 * doesn't matter that we don't define them. */
#else
#include "openvswitch/vlog.h"

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
        int error; \
 \
        /* Verify that 'l' was initialized. */ \
        if (OVS_UNLIKELY(!l->where)) { \
            ovs_abort(0, "%s: %s() passed uninitialized ovs_"#TYPE, \
                      where, __func__); \
        } \
 \
        error = pthread_##TYPE##_##FUN(&l->lock); \
        if (OVS_UNLIKELY(error)) { \
            ovs_abort(error, "%s: pthread_%s_%s failed", where, #TYPE, #FUN); \
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
        int error; \
 \
        /* Verify that 'l' was initialized. */ \
        if (OVS_UNLIKELY(!l->where)) { \
            ovs_abort(0, "%s: %s() passed uninitialized ovs_"#TYPE, \
                      where, __func__); \
        } \
 \
        error = pthread_##TYPE##_##FUN(&l->lock); \
        if (OVS_UNLIKELY(error) && error != EBUSY) { \
            ovs_abort(error, "%s: pthread_%s_%s failed", where, #TYPE, #FUN); \
        } \
        if (!error) { \
            l->where = where; \
        } \
        return error; \
    }
TRY_LOCK_FUNCTION(mutex, trylock);
TRY_LOCK_FUNCTION(rwlock, tryrdlock);
TRY_LOCK_FUNCTION(rwlock, trywrlock);

#define UNLOCK_FUNCTION(TYPE, FUN, WHERE) \
    void \
    ovs_##TYPE##_##FUN(const struct ovs_##TYPE *l_) \
        OVS_NO_THREAD_SAFETY_ANALYSIS \
    { \
        struct ovs_##TYPE *l = CONST_CAST(struct ovs_##TYPE *, l_); \
        int error; \
 \
        /* Verify that 'l' was initialized. */ \
        ovs_assert(l->where); \
 \
        l->where = WHERE; \
        error = pthread_##TYPE##_##FUN(&l->lock); \
        if (OVS_UNLIKELY(error)) { \
            ovs_abort(error, "pthread_%s_%s failed", #TYPE, #FUN); \
        } \
    }
UNLOCK_FUNCTION(mutex, unlock, "<unlocked>");
UNLOCK_FUNCTION(mutex, destroy, NULL);
UNLOCK_FUNCTION(rwlock, unlock, "<unlocked>");
UNLOCK_FUNCTION(rwlock, destroy, NULL);

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
#define XPTHREAD_FUNC3(FUNCTION, PARAM1, PARAM2, PARAM3)\
    void                                                \
    x##FUNCTION(PARAM1 arg1, PARAM2 arg2, PARAM3 arg3)  \
    {                                                   \
        int error = FUNCTION(arg1, arg2, arg3);         \
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

XPTHREAD_FUNC1(pthread_rwlockattr_init, pthread_rwlockattr_t *);
XPTHREAD_FUNC1(pthread_rwlockattr_destroy, pthread_rwlockattr_t *);
#ifdef PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
XPTHREAD_FUNC2(pthread_rwlockattr_setkind_np, pthread_rwlockattr_t *, int);
#endif

XPTHREAD_FUNC2(pthread_cond_init, pthread_cond_t *, pthread_condattr_t *);
XPTHREAD_FUNC1(pthread_cond_destroy, pthread_cond_t *);
XPTHREAD_FUNC1(pthread_cond_signal, pthread_cond_t *);
XPTHREAD_FUNC1(pthread_cond_broadcast, pthread_cond_t *);

XPTHREAD_FUNC2(pthread_join, pthread_t, void **);

typedef void destructor_func(void *);
XPTHREAD_FUNC2(pthread_key_create, pthread_key_t *, destructor_func *);
XPTHREAD_FUNC1(pthread_key_delete, pthread_key_t);
XPTHREAD_FUNC2(pthread_setspecific, pthread_key_t, const void *);

#ifndef _WIN32
XPTHREAD_FUNC3(pthread_sigmask, int, const sigset_t *, sigset_t *);
#endif

static void
ovs_mutex_init__(const struct ovs_mutex *l_, int type)
{
    struct ovs_mutex *l = CONST_CAST(struct ovs_mutex *, l_);
    pthread_mutexattr_t attr;
    int error;

    l->where = "<unlocked>";
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

/* Initializes 'mutex' as a recursive mutex. */
void
ovs_mutex_init_adaptive(const struct ovs_mutex *mutex)
{
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
    ovs_mutex_init__(mutex, PTHREAD_MUTEX_ADAPTIVE_NP);
#else
    ovs_mutex_init(mutex);
#endif
}

void
ovs_rwlock_init(const struct ovs_rwlock *l_)
{
    struct ovs_rwlock *l = CONST_CAST(struct ovs_rwlock *, l_);
    int error;

    l->where = "<unlocked>";

#ifdef PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
    pthread_rwlockattr_t attr;
    xpthread_rwlockattr_init(&attr);
    xpthread_rwlockattr_setkind_np(
        &attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    error = pthread_rwlock_init(&l->lock, &attr);
    xpthread_rwlockattr_destroy(&attr);
#else
    /* It is important to avoid passing a rwlockattr in this case because
     * Windows pthreads 2.9.1 (and earlier) fail and abort if passed one, even
     * one without any special attributes. */
    error = pthread_rwlock_init(&l->lock, NULL);
#endif

    if (OVS_UNLIKELY(error)) {
        ovs_abort(error, "pthread_rwlock_init failed");
    }
}

/* Provides an error-checking wrapper around pthread_cond_wait().
 *
 * If the wait can take a significant amount of time, consider bracketing this
 * call with calls to ovsrcu_quiesce_start() and ovsrcu_quiesce_end().  */
void
ovs_mutex_cond_wait(pthread_cond_t *cond, const struct ovs_mutex *mutex_)
{
    struct ovs_mutex *mutex = CONST_CAST(struct ovs_mutex *, mutex_);
    int error;

    error = pthread_cond_wait(cond, &mutex->lock);

    if (OVS_UNLIKELY(error)) {
        ovs_abort(error, "pthread_cond_wait failed");
    }
}

/* Initializes the 'barrier'.  'size' is the number of threads
 * expected to hit the barrier. */
void
ovs_barrier_init(struct ovs_barrier *barrier, uint32_t size)
{
    barrier->size = size;
    atomic_count_init(&barrier->count, 0);
    barrier->seq = seq_create();
}

/* Destroys the 'barrier'. */
void
ovs_barrier_destroy(struct ovs_barrier *barrier)
{
    seq_destroy(barrier->seq);
}

/* Makes the calling thread block on the 'barrier' until all
 * 'barrier->size' threads hit the barrier.
 * ovs_barrier provides the necessary acquire-release semantics to make
 * the effects of prior memory accesses of all the participating threads
 * visible on return and to prevent the following memory accesses to be
 * reordered before the ovs_barrier_block(). */
void
ovs_barrier_block(struct ovs_barrier *barrier)
{
    uint64_t seq = seq_read(barrier->seq);
    uint32_t orig;

    orig = atomic_count_inc(&barrier->count);
    if (orig + 1 == barrier->size) {
        atomic_count_set(&barrier->count, 0);
        /* seq_change() serves as a release barrier against the other threads,
         * so the zeroed count is visible to them as they continue. */
        seq_change(barrier->seq);
    } else {
        /* To prevent thread from waking up by other event,
         * keeps waiting for the change of 'barrier->seq'. */
        while (seq == seq_read(barrier->seq)) {
            seq_wait(barrier->seq, seq);
            poll_block();
        }
    }
}

DEFINE_EXTERN_PER_THREAD_DATA(ovsthread_id, OVSTHREAD_ID_UNSET);

struct ovsthread_aux {
    void *(*start)(void *);
    void *arg;
    char name[16];
};

unsigned int
ovsthread_id_init(void)
{
    static atomic_count next_id = ATOMIC_COUNT_INIT(0);

    ovs_assert(*ovsthread_id_get() == OVSTHREAD_ID_UNSET);
    return *ovsthread_id_get() = atomic_count_inc(&next_id);
}

static void *
ovsthread_wrapper(void *aux_)
{
    struct ovsthread_aux *auxp = aux_;
    struct ovsthread_aux aux;
    unsigned int id;

    id = ovsthread_id_init();

    aux = *auxp;
    free(auxp);

    /* The order of the following calls is important, because
     * ovsrcu_quiesce_end() saves a copy of the thread name. */
    char *subprogram_name = xasprintf("%s%u", aux.name, id);
    set_subprogram_name(subprogram_name);
    free(subprogram_name);
    ovsrcu_quiesce_end();

    return aux.start(aux.arg);
}

static void
set_min_stack_size(pthread_attr_t *attr, size_t min_stacksize)
{
    size_t stacksize;
    int error;

    error = pthread_attr_getstacksize(attr, &stacksize);
    if (error) {
        ovs_abort(error, "pthread_attr_getstacksize failed");
    }

    if (stacksize < min_stacksize) {
        error = pthread_attr_setstacksize(attr, min_stacksize);
        if (error) {
            ovs_abort(error, "pthread_attr_setstacksize failed");
        }
    }
}

/* Starts a thread that calls 'start(arg)'.  Sets the thread's name to 'name'
 * (suffixed by its ovsthread_id()).  Returns the new thread's pthread_t. */
pthread_t
ovs_thread_create(const char *name, void *(*start)(void *), void *arg)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct ovsthread_aux *aux;
    pthread_t thread;
    int error;

    forbid_forking("multiple threads exist");

    if (ovsthread_once_start(&once)) {
        /* The first call to this function has to happen in the main thread.
         * Before the process becomes multithreaded we make sure that the
         * main thread is considered non quiescent.
         *
         * For other threads this is done in ovs_thread_wrapper(), but the
         * main thread has no such wrapper.
         *
         * There's no reason to call ovsrcu_quiesce_end() in subsequent
         * invocations of this function and it might introduce problems
         * for other threads. */
        ovsrcu_quiesce_end();
        ovsthread_once_done(&once);
    }

    multithreaded = true;
    aux = xmalloc(sizeof *aux);
    aux->start = start;
    aux->arg = arg;
    ovs_strlcpy(aux->name, name, sizeof aux->name);

    /* Some small systems use a default stack size as small as 80 kB, but OVS
     * requires approximately 384 kB according to the following analysis:
     * https://mail.openvswitch.org/pipermail/ovs-dev/2016-January/308592.html
     *
     * We use 512 kB to give us some margin of error. */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    set_min_stack_size(&attr, 512 * 1024);

    error = pthread_create(&thread, &attr, ovsthread_wrapper, aux);
    if (error) {
        ovs_abort(error, "pthread_create failed");
    }
    pthread_attr_destroy(&attr);
    return thread;
}

bool
ovsthread_once_start__(struct ovsthread_once *once)
{
    ovs_mutex_lock(&once->mutex);
    /* Mutex synchronizes memory, so we get the current value of 'done'. */
    if (!once->done) {
        return true;
    }
    ovs_mutex_unlock(&once->mutex);
    return false;
}

void
ovsthread_once_done(struct ovsthread_once *once)
{
    /* We need release semantics here, so that the following store may not
     * be moved ahead of any of the preceding initialization operations.
     * A release atomic_thread_fence provides that prior memory accesses
     * will not be reordered to take place after the following store. */
    atomic_thread_fence(memory_order_release);
    once->done = true;
    ovs_mutex_unlock(&once->mutex);
}

bool
single_threaded(void)
{
    return !multithreaded;
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

#ifndef _WIN32
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
#endif

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

/* ovsthread_stats. */

void
ovsthread_stats_init(struct ovsthread_stats *stats)
{
    int i;

    ovs_mutex_init(&stats->mutex);
    for (i = 0; i < ARRAY_SIZE(stats->buckets); i++) {
        stats->buckets[i] = NULL;
    }
}

void
ovsthread_stats_destroy(struct ovsthread_stats *stats)
{
    ovs_mutex_destroy(&stats->mutex);
}

void *
ovsthread_stats_bucket_get(struct ovsthread_stats *stats,
                           void *(*new_bucket)(void))
{
    unsigned int idx = ovsthread_id_self() & (ARRAY_SIZE(stats->buckets) - 1);
    void *bucket = stats->buckets[idx];
    if (!bucket) {
        ovs_mutex_lock(&stats->mutex);
        bucket = stats->buckets[idx];
        if (!bucket) {
            bucket = stats->buckets[idx] = new_bucket();
        }
        ovs_mutex_unlock(&stats->mutex);
    }
    return bucket;
}

size_t
ovs_thread_stats_next_bucket(const struct ovsthread_stats *stats, size_t i)
{
    for (; i < ARRAY_SIZE(stats->buckets); i++) {
        if (stats->buckets[i]) {
            break;
        }
    }
    return i;
}


/* Returns the total number of cores available to this process, or 0 if the
 * number cannot be determined. */
int
count_cpu_cores(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static long int n_cores;

    if (ovsthread_once_start(&once)) {
#ifndef _WIN32
        n_cores = sysconf(_SC_NPROCESSORS_ONLN);
#ifdef __linux__
        if (n_cores > 0) {
            cpu_set_t *set = CPU_ALLOC(n_cores);

            if (set) {
                size_t size = CPU_ALLOC_SIZE(n_cores);

                if (!sched_getaffinity(0, size, set)) {
                    n_cores = CPU_COUNT_S(size, set);
                }
                CPU_FREE(set);
            }
        }
#endif
#else
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        n_cores = sysinfo.dwNumberOfProcessors;
#endif
        ovsthread_once_done(&once);
    }

    return n_cores > 0 ? n_cores : 0;
}

/* Returns 'true' if current thread is PMD thread. */
bool
thread_is_pmd(void)
{
    const char *name = get_subprogram_name();
    return !strncmp(name, "pmd", 3);
}


/* ovsthread_key. */

#define L1_SIZE 1024
#define L2_SIZE 1024
#define MAX_KEYS (L1_SIZE * L2_SIZE)

/* A piece of thread-specific data. */
struct ovsthread_key {
    struct ovs_list list_node;  /* In 'inuse_keys' or 'free_keys'. */
    void (*destructor)(void *); /* Called at thread exit. */

    /* Indexes into the per-thread array in struct ovsthread_key_slots.
     * This key's data is stored in p1[index / L2_SIZE][index % L2_SIZE]. */
    unsigned int index;
};

/* Per-thread data structure. */
struct ovsthread_key_slots {
    struct ovs_list list_node;  /* In 'slots_list'. */
    void **p1[L1_SIZE];
};

/* Contains "struct ovsthread_key_slots *". */
static pthread_key_t tsd_key;

/* Guards data structures below. */
static struct ovs_mutex key_mutex = OVS_MUTEX_INITIALIZER;

/* 'inuse_keys' holds "struct ovsthread_key"s that have been created and not
 * yet destroyed.
 *
 * 'free_keys' holds "struct ovsthread_key"s that have been deleted and are
 * ready for reuse.  (We keep them around only to be able to easily locate
 * free indexes.)
 *
 * Together, 'inuse_keys' and 'free_keys' hold an ovsthread_key for every index
 * from 0 to n_keys - 1, inclusive. */
static struct ovs_list inuse_keys OVS_GUARDED_BY(key_mutex)
    = OVS_LIST_INITIALIZER(&inuse_keys);
static struct ovs_list free_keys OVS_GUARDED_BY(key_mutex)
    = OVS_LIST_INITIALIZER(&free_keys);
static unsigned int n_keys OVS_GUARDED_BY(key_mutex);

/* All existing struct ovsthread_key_slots. */
static struct ovs_list slots_list OVS_GUARDED_BY(key_mutex)
    = OVS_LIST_INITIALIZER(&slots_list);

static void *
clear_slot(struct ovsthread_key_slots *slots, unsigned int index)
{
    void **p2 = slots->p1[index / L2_SIZE];
    if (p2) {
        void **valuep = &p2[index % L2_SIZE];
        void *value = *valuep;
        *valuep = NULL;
        return value;
    } else {
        return NULL;
    }
}

static void
ovsthread_key_destruct__(void *slots_)
{
    struct ovsthread_key_slots *slots = slots_;
    struct ovsthread_key *key;
    unsigned int n;
    int i;

    ovs_mutex_lock(&key_mutex);
    ovs_list_remove(&slots->list_node);
    LIST_FOR_EACH (key, list_node, &inuse_keys) {
        void *value = clear_slot(slots, key->index);
        if (value && key->destructor) {
            key->destructor(value);
        }
    }
    n = n_keys;
    ovs_mutex_unlock(&key_mutex);

    for (i = 0; i < DIV_ROUND_UP(n, L2_SIZE); i++) {
        free(slots->p1[i]);
    }
    free(slots);
}

/* Cancels the callback to ovsthread_key_destruct__().
 *
 * Cancelling the call to the destructor during the main thread exit
 * is needed while using pthreads-win32 library in Windows. It has been
 * observed that in pthreads-win32, a call to the destructor during
 * main thread exit causes undefined behavior. */
static void
ovsthread_cancel_ovsthread_key_destruct__(void *aux OVS_UNUSED)
{
    pthread_setspecific(tsd_key, NULL);
}

/* Initializes '*keyp' as a thread-specific data key.  The data items are
 * initially null in all threads.
 *
 * If a thread exits with non-null data, then 'destructor', if nonnull, will be
 * called passing the final data value as its argument.  'destructor' must not
 * call any thread-specific data functions in this API.
 *
 * This function is similar to xpthread_key_create(). */
void
ovsthread_key_create(ovsthread_key_t *keyp, void (*destructor)(void *))
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct ovsthread_key *key;

    if (ovsthread_once_start(&once)) {
        xpthread_key_create(&tsd_key, ovsthread_key_destruct__);
        fatal_signal_add_hook(ovsthread_cancel_ovsthread_key_destruct__,
                              NULL, NULL, true);
        ovsthread_once_done(&once);
    }

    ovs_mutex_lock(&key_mutex);
    if (ovs_list_is_empty(&free_keys)) {
        key = xmalloc(sizeof *key);
        key->index = n_keys++;
        if (key->index >= MAX_KEYS) {
            abort();
        }
    } else {
        key = CONTAINER_OF(ovs_list_pop_back(&free_keys),
                            struct ovsthread_key, list_node);
    }
    ovs_list_push_back(&inuse_keys, &key->list_node);
    key->destructor = destructor;
    ovs_mutex_unlock(&key_mutex);

    *keyp = key;
}

/* Frees 'key'.  The destructor supplied to ovsthread_key_create(), if any, is
 * not called.
 *
 * This function is similar to xpthread_key_delete(). */
void
ovsthread_key_delete(ovsthread_key_t key)
{
    struct ovsthread_key_slots *slots;

    ovs_mutex_lock(&key_mutex);

    /* Move 'key' from 'inuse_keys' to 'free_keys'. */
    ovs_list_remove(&key->list_node);
    ovs_list_push_back(&free_keys, &key->list_node);

    /* Clear this slot in all threads. */
    LIST_FOR_EACH (slots, list_node, &slots_list) {
        clear_slot(slots, key->index);
    }

    ovs_mutex_unlock(&key_mutex);
}

static void **
ovsthread_key_lookup__(const struct ovsthread_key *key)
{
    struct ovsthread_key_slots *slots;
    void **p2;

    slots = pthread_getspecific(tsd_key);
    if (!slots) {
        slots = xzalloc(sizeof *slots);

        ovs_mutex_lock(&key_mutex);
        pthread_setspecific(tsd_key, slots);
        ovs_list_push_back(&slots_list, &slots->list_node);
        ovs_mutex_unlock(&key_mutex);
    }

    p2 = slots->p1[key->index / L2_SIZE];
    if (!p2) {
        p2 = xzalloc(L2_SIZE * sizeof *p2);
        slots->p1[key->index / L2_SIZE] = p2;
    }

    return &p2[key->index % L2_SIZE];
}

/* Sets the value of thread-specific data item 'key', in the current thread, to
 * 'value'.
 *
 * This function is similar to pthread_setspecific(). */
void
ovsthread_setspecific(ovsthread_key_t key, const void *value)
{
    *ovsthread_key_lookup__(key) = CONST_CAST(void *, value);
}

/* Returns the value of thread-specific data item 'key' in the current thread.
 *
 * This function is similar to pthread_getspecific(). */
void *
ovsthread_getspecific(ovsthread_key_t key)
{
    return *ovsthread_key_lookup__(key);
}
#endif
