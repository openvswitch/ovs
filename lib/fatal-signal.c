/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "socket-util.h"
#include "util.h"

#define THIS_MODULE VLM_fatal_signal
#include "vlog.h"

/* Signals to catch. */
static const int fatal_signals[] = { SIGTERM, SIGINT, SIGHUP, SIGALRM };

/* Signals to catch as a sigset_t. */
static sigset_t fatal_signal_set;

/* Hooks to call upon catching a signal */
struct hook {
    void (*func)(void *aux);
    void *aux;
    bool run_at_exit;
};
#define MAX_HOOKS 32
static struct hook hooks[MAX_HOOKS];
static size_t n_hooks;

static int signal_fds[2];
static volatile sig_atomic_t stored_sig_nr = SIG_ATOMIC_MAX;

/* Disabled by fatal_signal_fork()? */
static bool disabled;

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

        if (pipe(signal_fds)) {
            ovs_fatal(errno, "could not create pipe");
        }
        set_nonblocking(signal_fds[0]);
        set_nonblocking(signal_fds[1]);

        sigemptyset(&fatal_signal_set);
        for (i = 0; i < ARRAY_SIZE(fatal_signals); i++) {
            int sig_nr = fatal_signals[i];
            struct sigaction old_sa;

            sigaddset(&fatal_signal_set, sig_nr);
            if (sigaction(sig_nr, NULL, &old_sa)) {
                ovs_fatal(errno, "sigaction");
            }
            if (old_sa.sa_handler == SIG_DFL
                && signal(sig_nr, fatal_signal_handler) == SIG_ERR) {
                ovs_fatal(errno, "signal");
            }
        }
        atexit(atexit_handler);
    }
}

/* Registers 'hook' to be called when a process termination signal is raised.
 * If 'run_at_exit' is true, 'hook' is also called during normal process
 * termination, e.g. when exit() is called or when main() returns.
 *
 * The hook is not called immediately from the signal handler but rather the
 * next time the poll loop iterates, so it is freed from the usual restrictions
 * on signal handler functions. */
void
fatal_signal_add_hook(void (*func)(void *aux), void *aux, bool run_at_exit)
{
    fatal_signal_init();
    assert(n_hooks < MAX_HOOKS);
    hooks[n_hooks].func = func;
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

void
fatal_signal_run(void)
{
    int sig_nr = stored_sig_nr;

    if (sig_nr != SIG_ATOMIC_MAX) {
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
    poll_fd_wait(signal_fds[0], POLLIN);
}

static void
atexit_handler(void)
{
    if (!disabled) {
        call_hooks(0);
    }
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
                h->func(h->aux);
            }
        }
    }
}

static struct shash files = SHASH_INITIALIZER(&files);

static void unlink_files(void *aux);
static void do_unlink_files(void);

/* Registers 'file' to be unlinked when the program terminates via exit() or a
 * fatal signal. */
void
fatal_signal_add_file_to_unlink(const char *file)
{
    static bool added_hook = false;
    if (!added_hook) {
        added_hook = true;
        fatal_signal_add_hook(unlink_files, NULL, true);
    }

    if (!shash_find(&files, file)) {
        shash_add(&files, file, NULL);
    }
}

/* Unregisters 'file' from being unlinked when the program terminates via
 * exit() or a fatal signal. */
void
fatal_signal_remove_file_to_unlink(const char *file)
{
    struct shash_node *node;

    node = shash_find(&files, file);
    if (node) {
        shash_delete(&files, node);
    }
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
unlink_files(void *aux UNUSED)
{
    do_unlink_files(); 
}

static void
do_unlink_files(void)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &files) {
        unlink(node->name);
    }
}

/* Disables the fatal signal hook mechanism.  Following a fork, one of the
 * resulting processes can call this function to allow it to terminate without
 * triggering fatal signal processing or removing files.  Fatal signal
 * processing is still enabled in the other process. */
void
fatal_signal_fork(void)
{
    size_t i;

    disabled = true;

    for (i = 0; i < ARRAY_SIZE(fatal_signals); i++) {
        int sig_nr = fatal_signals[i];
        if (signal(sig_nr, SIG_DFL) == SIG_IGN) {
            signal(sig_nr, SIG_IGN);
        }
    }

    /* Raise any signals that we have already received with the default
     * handler. */
    if (stored_sig_nr != SIG_ATOMIC_MAX) {
        raise(stored_sig_nr);
    }
}
