/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "fatal-signal.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "poll-loop.h"
#include "shash.h"
#include "sset.h"
#include "signals.h"
#include "socket-util.h"
#include "util.h"
#include "vlog.h"

#include "type-props.h"

#ifndef SIG_ATOMIC_MAX
#define SIG_ATOMIC_MAX TYPE_MAXIMUM(sig_atomic_t)
#endif

VLOG_DEFINE_THIS_MODULE(fatal_signal);

/* Signals to catch. */
static const int fatal_signals[] = { SIGTERM, SIGINT, SIGHUP, SIGALRM };

/* Signals to catch as a sigset_t. */
static sigset_t fatal_signal_set;

/* Hooks to call upon catching a signal */
struct hook {
    void (*hook_cb)(void *aux);
    void (*cancel_cb)(void *aux);
    void *aux;
    bool run_at_exit;
};
#define MAX_HOOKS 32
static struct hook hooks[MAX_HOOKS];
static size_t n_hooks;

static int signal_fds[2];
static volatile sig_atomic_t stored_sig_nr = SIG_ATOMIC_MAX;

static void fatal_signal_init(void);
static void atexit_handler(void);
static void call_hooks(int sig_nr);

static void
fatal_signal_init(void)
{
    static bool inited = false;

    if (!inited) {
        size_t i;

        inited = true;

        xpipe_nonblocking(signal_fds);

        sigemptyset(&fatal_signal_set);
        for (i = 0; i < ARRAY_SIZE(fatal_signals); i++) {
            int sig_nr = fatal_signals[i];
            struct sigaction old_sa;

            sigaddset(&fatal_signal_set, sig_nr);
            xsigaction(sig_nr, NULL, &old_sa);
            if (old_sa.sa_handler == SIG_DFL
                && signal(sig_nr, fatal_signal_handler) == SIG_ERR) {
                VLOG_FATAL("signal failed (%s)", strerror(errno));
            }
        }
        atexit(atexit_handler);
    }
}

/* Registers 'hook_cb' to be called when a process termination signal is
 * raised.  If 'run_at_exit' is true, 'hook_cb' is also called during normal
 * process termination, e.g. when exit() is called or when main() returns.
 *
 * 'hook_cb' is not called immediately from the signal handler but rather the
 * next time the poll loop iterates, so it is freed from the usual restrictions
 * on signal handler functions.
 *
 * If the current process forks, fatal_signal_fork() may be called to clear the
 * parent process's fatal signal hooks, so that 'hook_cb' is only called when
 * the child terminates, not when the parent does.  When fatal_signal_fork() is
 * called, it calls the 'cancel_cb' function if it is nonnull, passing 'aux',
 * to notify that the hook has been canceled.  This allows the hook to free
 * memory, etc. */
void
fatal_signal_add_hook(void (*hook_cb)(void *aux), void (*cancel_cb)(void *aux),
                      void *aux, bool run_at_exit)
{
    fatal_signal_init();

    assert(n_hooks < MAX_HOOKS);
    hooks[n_hooks].hook_cb = hook_cb;
    hooks[n_hooks].cancel_cb = cancel_cb;
    hooks[n_hooks].aux = aux;
    hooks[n_hooks].run_at_exit = run_at_exit;
    n_hooks++;
}

/* Handles fatal signal number 'sig_nr'.
 *
 * Ordinarily this is the actual signal handler.  When other code needs to
 * handle one of our signals, however, it can register for that signal and, if
 * and when necessary, call this function to do fatal signal processing for it
 * and terminate the process.  Currently only timeval.c does this, for SIGALRM.
 * (It is not important whether the other code sets up its signal handler
 * before or after this file, because this file will only set up a signal
 * handler in the case where the signal has its default handling.)  */
void
fatal_signal_handler(int sig_nr)
{
    ignore(write(signal_fds[1], "", 1));
    stored_sig_nr = sig_nr;
}

/* Check whether a fatal signal has occurred and, if so, call the fatal signal
 * hooks and exit.
 *
 * This function is called automatically by poll_block(), but specialized
 * programs that may not always call poll_block() on a regular basis should
 * also call it periodically.  (Therefore, any function with "block" in its
 * name should call fatal_signal_run() each time it is called, either directly
 * or through poll_block(), because such functions can only used by specialized
 * programs that can afford to block outside their main loop around
 * poll_block().)
 */
void
fatal_signal_run(void)
{
    sig_atomic_t sig_nr;

    fatal_signal_init();

    sig_nr = stored_sig_nr;
    if (sig_nr != SIG_ATOMIC_MAX) {
        VLOG_WARN("terminating with signal %d (%s)",
                  (int)sig_nr, signal_name(sig_nr));
        call_hooks(sig_nr);

        /* Re-raise the signal with the default handling so that the program
         * termination status reflects that we were killed by this signal */
        signal(sig_nr, SIG_DFL);
        raise(sig_nr);
    }
}

void
fatal_signal_wait(void)
{
    fatal_signal_init();
    poll_fd_wait(signal_fds[0], POLLIN);
}

static void
atexit_handler(void)
{
    call_hooks(0);
}

static void
call_hooks(int sig_nr)
{
    static volatile sig_atomic_t recurse = 0;
    if (!recurse) {
        size_t i;

        recurse = 1;

        for (i = 0; i < n_hooks; i++) {
            struct hook *h = &hooks[i];
            if (sig_nr || h->run_at_exit) {
                h->hook_cb(h->aux);
            }
        }
    }
}

/* Files to delete on exit. */
static struct sset files = SSET_INITIALIZER(&files);

/* Has a hook function been registered with fatal_signal_add_hook() (and not
 * cleared by fatal_signal_fork())? */
static bool added_hook;

static void unlink_files(void *aux);
static void cancel_files(void *aux);
static void do_unlink_files(void);

/* Registers 'file' to be unlinked when the program terminates via exit() or a
 * fatal signal. */
void
fatal_signal_add_file_to_unlink(const char *file)
{
    if (!added_hook) {
        added_hook = true;
        fatal_signal_add_hook(unlink_files, cancel_files, NULL, true);
    }

    sset_add(&files, file);
}

/* Unregisters 'file' from being unlinked when the program terminates via
 * exit() or a fatal signal. */
void
fatal_signal_remove_file_to_unlink(const char *file)
{
    sset_find_and_delete(&files, file);
}

/* Like fatal_signal_remove_file_to_unlink(), but also unlinks 'file'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
fatal_signal_unlink_file_now(const char *file)
{
    int error = unlink(file) ? errno : 0;
    if (error) {
        VLOG_WARN("could not unlink \"%s\" (%s)", file, strerror(error));
    }

    fatal_signal_remove_file_to_unlink(file);

    return error;
}

static void
unlink_files(void *aux OVS_UNUSED)
{
    do_unlink_files();
}

static void
cancel_files(void *aux OVS_UNUSED)
{
    sset_clear(&files);
    added_hook = false;
}

static void
do_unlink_files(void)
{
    const char *file;

    SSET_FOR_EACH (file, &files) {
        unlink(file);
    }
}

/* Clears all of the fatal signal hooks without executing them.  If any of the
 * hooks passed a 'cancel_cb' function to fatal_signal_add_hook(), then those
 * functions will be called, allowing them to free resources, etc.
 *
 * Following a fork, one of the resulting processes can call this function to
 * allow it to terminate without calling the hooks registered before calling
 * this function.  New hooks registered after calling this function will take
 * effect normally. */
void
fatal_signal_fork(void)
{
    size_t i;

    for (i = 0; i < n_hooks; i++) {
        struct hook *h = &hooks[i];
        if (h->cancel_cb) {
            h->cancel_cb(h->aux);
        }
    }
    n_hooks = 0;

    /* Raise any signals that we have already received with the default
     * handler. */
    if (stored_sig_nr != SIG_ATOMIC_MAX) {
        raise(stored_sig_nr);
    }
}
