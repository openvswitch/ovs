/*
 * Copyright (c) 2014, 2017 Nicira, Inc.
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
#include <errno.h>
#include "ovs-rcu.h"
#include "fatal-signal.h"
#include "guarded-list.h"
#include "latch.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_rcu);

struct ovsrcu_cb {
    void (*function)(void *aux);
    void *aux;
};

struct ovsrcu_cbset {
    struct ovs_list list_node;
    struct ovsrcu_cb cbs[16];
    int n_cbs;
};

struct ovsrcu_perthread {
    struct ovs_list list_node;  /* In global list. */

    struct ovs_mutex mutex;
    uint64_t seqno;
    struct ovsrcu_cbset *cbset;
    char name[16];              /* This thread's name. */
};

static struct seq *global_seqno;

static pthread_key_t perthread_key;
static struct ovs_list ovsrcu_threads;
static struct ovs_mutex ovsrcu_threads_mutex;

static struct guarded_list flushed_cbsets;
static struct seq *flushed_cbsets_seq;

static struct latch postpone_exit;
static struct ovs_barrier postpone_barrier;

static void ovsrcu_init_module(void);
static void ovsrcu_flush_cbset__(struct ovsrcu_perthread *, bool);
static void ovsrcu_flush_cbset(struct ovsrcu_perthread *);
static void ovsrcu_unregister__(struct ovsrcu_perthread *);
static bool ovsrcu_call_postponed(void);
static void *ovsrcu_postpone_thread(void *arg OVS_UNUSED);

static struct ovsrcu_perthread *
ovsrcu_perthread_get(void)
{
    struct ovsrcu_perthread *perthread;

    ovsrcu_init_module();

    perthread = pthread_getspecific(perthread_key);
    if (!perthread) {
        const char *name = get_subprogram_name();

        perthread = xmalloc(sizeof *perthread);
        ovs_mutex_init(&perthread->mutex);
        perthread->seqno = seq_read(global_seqno);
        perthread->cbset = NULL;
        ovs_strlcpy(perthread->name, name[0] ? name : "main",
                    sizeof perthread->name);

        ovs_mutex_lock(&ovsrcu_threads_mutex);
        ovs_list_push_back(&ovsrcu_threads, &perthread->list_node);
        ovs_mutex_unlock(&ovsrcu_threads_mutex);

        pthread_setspecific(perthread_key, perthread);
    }
    return perthread;
}

/* Indicates the end of a quiescent state.  See "Details" near the top of
 * ovs-rcu.h.
 *
 * Quiescent states don't stack or nest, so this always ends a quiescent state
 * even if ovsrcu_quiesce_start() was called multiple times in a row. */
void
ovsrcu_quiesce_end(void)
{
    ovsrcu_perthread_get();
}

static void
ovsrcu_quiesced(void)
{
    if (single_threaded()) {
        ovsrcu_call_postponed();
    } else {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
        if (ovsthread_once_start(&once)) {
            latch_init(&postpone_exit);
            ovs_barrier_init(&postpone_barrier, 2);
            ovs_thread_create("urcu", ovsrcu_postpone_thread, NULL);
            ovsthread_once_done(&once);
        }
    }
}

/* Indicates the beginning of a quiescent state.  See "Details" near the top of
 * ovs-rcu.h. */
void
ovsrcu_quiesce_start(void)
{
    struct ovsrcu_perthread *perthread;

    ovsrcu_init_module();
    perthread = pthread_getspecific(perthread_key);
    if (perthread) {
        pthread_setspecific(perthread_key, NULL);
        ovsrcu_unregister__(perthread);
    }

    ovsrcu_quiesced();
}

/* Indicates a momentary quiescent state.  See "Details" near the top of
 * ovs-rcu.h.
 *
 * Provides a full memory barrier via seq_change().
 */
void
ovsrcu_quiesce(void)
{
    struct ovsrcu_perthread *perthread;

    perthread = ovsrcu_perthread_get();
    perthread->seqno = seq_read(global_seqno);
    if (perthread->cbset) {
        ovsrcu_flush_cbset(perthread);
    }
    seq_change(global_seqno);

    ovsrcu_quiesced();
}

int
ovsrcu_try_quiesce(void)
{
    struct ovsrcu_perthread *perthread;
    int ret = EBUSY;

    ovs_assert(!single_threaded());
    perthread = ovsrcu_perthread_get();
    if (!seq_try_lock()) {
        perthread->seqno = seq_read_protected(global_seqno);
        if (perthread->cbset) {
            ovsrcu_flush_cbset__(perthread, true);
        }
        seq_change_protected(global_seqno);
        seq_unlock();
        ovsrcu_quiesced();
        ret = 0;
    }
    return ret;
}

bool
ovsrcu_is_quiescent(void)
{
    ovsrcu_init_module();
    return pthread_getspecific(perthread_key) == NULL;
}

void
ovsrcu_synchronize(void)
{
    unsigned int warning_threshold = 1000;
    uint64_t target_seqno;
    long long int start;

    if (single_threaded()) {
        return;
    }

    target_seqno = seq_read(global_seqno);
    ovsrcu_quiesce_start();
    start = time_msec();

    for (;;) {
        uint64_t cur_seqno = seq_read(global_seqno);
        struct ovsrcu_perthread *perthread;
        char stalled_thread[16];
        unsigned int elapsed;
        bool done = true;

        ovs_mutex_lock(&ovsrcu_threads_mutex);
        LIST_FOR_EACH (perthread, list_node, &ovsrcu_threads) {
            if (perthread->seqno <= target_seqno) {
                ovs_strlcpy_arrays(stalled_thread, perthread->name);
                done = false;
                break;
            }
        }
        ovs_mutex_unlock(&ovsrcu_threads_mutex);

        if (done) {
            break;
        }

        elapsed = time_msec() - start;
        if (elapsed >= warning_threshold) {
            VLOG_WARN("blocked %u ms waiting for %s to quiesce",
                      elapsed, stalled_thread);
            warning_threshold *= 2;
        }
        poll_timer_wait_until(start + warning_threshold);

        seq_wait(global_seqno, cur_seqno);
        poll_block();
    }
    ovsrcu_quiesce_end();
}

/* Waits until as many postponed callbacks as possible have executed.
 *
 * As a side effect, stops the background thread that calls the callbacks and
 * prevents it from being restarted.  This means that this function should only
 * be called soon before a process exits, as a mechanism for releasing memory
 * to make memory leaks easier to detect, since any further postponed callbacks
 * won't actually get called.
 *
 * This function can only wait for callbacks registered by the current thread
 * and the background thread that calls the callbacks.  Thus, it will be most
 * effective if other threads have already exited. */
void
ovsrcu_exit(void)
{
    /* Stop the postpone thread and wait for it to exit.  Otherwise, there's no
     * way to wait for that thread to finish calling callbacks itself. */
    if (!single_threaded()) {
        ovsrcu_quiesced();      /* Ensure that the postpone thread exists. */
        latch_set(&postpone_exit);
        ovs_barrier_block(&postpone_barrier);
    }

    /* Repeatedly:
     *
     *    - Wait for a grace period.  One important side effect is to push the
     *      running thread's cbset into 'flushed_cbsets' so that the next call
     *      has something to call.
     *
     *    - Call all the callbacks in 'flushed_cbsets'.  If there aren't any,
     *      we're done, otherwise the callbacks themselves might have requested
     *      more deferred callbacks so we go around again.
     *
     * We limit the number of iterations just in case some bug causes an
     * infinite loop.  This function is just for making memory leaks easier to
     * spot so there's no point in breaking things on that basis. */
    for (int i = 0; i < 8; i++) {
        ovsrcu_synchronize();
        if (!ovsrcu_call_postponed()) {
            break;
        }
    }
}

/* Registers 'function' to be called, passing 'aux' as argument, after the
 * next grace period.
 *
 * The call is guaranteed to happen after the next time all participating
 * threads have quiesced at least once, but there is no quarantee that all
 * registered functions are called as early as possible, or that the functions
 * registered by different threads would be called in the order the
 * registrations took place.  In particular, even if two threads provably
 * register a function each in a specific order, the functions may still be
 * called in the opposite order, depending on the timing of when the threads
 * call ovsrcu_quiesce(), how many functions they postpone, and when the
 * ovs-rcu thread happens to grab the functions to be called.
 *
 * All functions registered by a single thread are guaranteed to execute in the
 * registering order, however.
 *
 * This function is more conveniently called through the ovsrcu_postpone()
 * macro, which provides a type-safe way to allow 'function''s parameter to be
 * any pointer type. */
void
ovsrcu_postpone__(void (*function)(void *aux), void *aux)
{
    struct ovsrcu_perthread *perthread = ovsrcu_perthread_get();
    struct ovsrcu_cbset *cbset;
    struct ovsrcu_cb *cb;

    cbset = perthread->cbset;
    if (!cbset) {
        cbset = perthread->cbset = xmalloc(sizeof *perthread->cbset);
        cbset->n_cbs = 0;
    }

    cb = &cbset->cbs[cbset->n_cbs++];
    cb->function = function;
    cb->aux = aux;

    if (cbset->n_cbs >= ARRAY_SIZE(cbset->cbs)) {
        ovsrcu_flush_cbset(perthread);
    }
}

static bool
ovsrcu_call_postponed(void)
{
    struct ovsrcu_cbset *cbset;
    struct ovs_list cbsets;

    guarded_list_pop_all(&flushed_cbsets, &cbsets);
    if (ovs_list_is_empty(&cbsets)) {
        return false;
    }

    ovsrcu_synchronize();

    LIST_FOR_EACH_POP (cbset, list_node, &cbsets) {
        struct ovsrcu_cb *cb;

        for (cb = cbset->cbs; cb < &cbset->cbs[cbset->n_cbs]; cb++) {
            cb->function(cb->aux);
        }
        free(cbset);
    }

    return true;
}

static void *
ovsrcu_postpone_thread(void *arg OVS_UNUSED)
{
    pthread_detach(pthread_self());

    while (!latch_is_set(&postpone_exit)) {
        uint64_t seqno = seq_read(flushed_cbsets_seq);
        if (!ovsrcu_call_postponed()) {
            seq_wait(flushed_cbsets_seq, seqno);
            latch_wait(&postpone_exit);
            poll_block();
        }
    }

    ovs_barrier_block(&postpone_barrier);
    return NULL;
}

static void
ovsrcu_flush_cbset__(struct ovsrcu_perthread *perthread, bool protected)
{
    struct ovsrcu_cbset *cbset = perthread->cbset;

    if (cbset) {
        guarded_list_push_back(&flushed_cbsets, &cbset->list_node, SIZE_MAX);
        perthread->cbset = NULL;

        if (protected) {
            seq_change_protected(flushed_cbsets_seq);
        } else {
            seq_change(flushed_cbsets_seq);
        }
    }
}

static void
ovsrcu_flush_cbset(struct ovsrcu_perthread *perthread)
{
    ovsrcu_flush_cbset__(perthread, false);
}

static void
ovsrcu_unregister__(struct ovsrcu_perthread *perthread)
{
    if (perthread->cbset) {
        ovsrcu_flush_cbset(perthread);
    }

    ovs_mutex_lock(&ovsrcu_threads_mutex);
    ovs_list_remove(&perthread->list_node);
    ovs_mutex_unlock(&ovsrcu_threads_mutex);

    ovs_mutex_destroy(&perthread->mutex);
    free(perthread);

    seq_change(global_seqno);
}

static void
ovsrcu_thread_exit_cb(void *perthread)
{
    ovsrcu_unregister__(perthread);
}

/* Cancels the callback to ovsrcu_thread_exit_cb().
 *
 * Cancelling the call to the destructor during the main thread exit
 * is needed while using pthreads-win32 library in Windows. It has been
 * observed that in pthreads-win32, a call to the destructor during
 * main thread exit causes undefined behavior. */
static void
ovsrcu_cancel_thread_exit_cb(void *aux OVS_UNUSED)
{
    pthread_setspecific(perthread_key, NULL);
}

static void
ovsrcu_init_module(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    if (ovsthread_once_start(&once)) {
        global_seqno = seq_create();
        xpthread_key_create(&perthread_key, ovsrcu_thread_exit_cb);
        fatal_signal_add_hook(ovsrcu_cancel_thread_exit_cb, NULL, NULL, true);
        ovs_list_init(&ovsrcu_threads);
        ovs_mutex_init(&ovsrcu_threads_mutex);

        guarded_list_init(&flushed_cbsets);
        flushed_cbsets_seq = seq_create();

        ovsthread_once_done(&once);
    }
}
