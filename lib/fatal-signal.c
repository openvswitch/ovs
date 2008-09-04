/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */
#include <config.h>
#include "fatal-signal.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util.h"

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

/* Number of nesting signal blockers. */
static int block_level = 0;

/* Signal mask saved by outermost signal blocker. */
static sigset_t saved_signal_mask;

/* Disabled by fatal_signal_fork()? */
static bool disabled;

static void call_sigprocmask(int how, sigset_t* new_set, sigset_t* old_set);
static void atexit_handler(void);
static void call_hooks(int sig_nr);

/* Registers 'hook' to be called when a process termination signal is raised.
 * If 'run_at_exit' is true, 'hook' is also called during normal process
 * termination, e.g. when exit() is called or when main() returns. */
void
fatal_signal_add_hook(void (*func)(void *aux), void *aux, bool run_at_exit)
{
    fatal_signal_block();
    assert(n_hooks < MAX_HOOKS);
    hooks[n_hooks].func = func;
    hooks[n_hooks].aux = aux;
    hooks[n_hooks].run_at_exit = run_at_exit;
    n_hooks++;
    fatal_signal_unblock();
}

/* Blocks program termination signals until fatal_signal_unblock() is called.
 * May be called multiple times with nesting; if so, fatal_signal_unblock()
 * must be called the same number of times to unblock signals.
 *
 * This is needed while adjusting a data structure that will be accessed by a
 * fatal signal hook, so that the hook is not invoked while the data structure
 * is in an inconsistent state. */
void
fatal_signal_block()
{
    static bool inited = false;
    if (!inited) {
        size_t i;

        inited = true;
        sigemptyset(&fatal_signal_set);
        for (i = 0; i < ARRAY_SIZE(fatal_signals); i++) {
            int sig_nr = fatal_signals[i];
            struct sigaction old_sa;

            sigaddset(&fatal_signal_set, sig_nr);
            if (sigaction(sig_nr, NULL, &old_sa)) {
                ofp_fatal(errno, "sigaction");
            }
            if (old_sa.sa_handler == SIG_DFL
                && signal(sig_nr, fatal_signal_handler) == SIG_ERR) {
                ofp_fatal(errno, "signal");
            }
        }
        atexit(atexit_handler);
    }

    if (++block_level == 1) {
        call_sigprocmask(SIG_BLOCK, &fatal_signal_set, &saved_signal_mask);
    }
}

/* Unblocks program termination signals blocked by fatal_signal_block() is
 * called.  If multiple calls to fatal_signal_block() are nested,
 * fatal_signal_unblock() must be called the same number of times to unblock
 * signals. */
void
fatal_signal_unblock()
{
    assert(block_level > 0);
    if (--block_level == 0) {
        call_sigprocmask(SIG_SETMASK, &saved_signal_mask, NULL);
    }
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
    call_hooks(sig_nr);

    /* Re-raise the signal with the default handling so that the program
     * termination status reflects that we were killed by this signal */
    signal(sig_nr, SIG_DFL);
    raise(sig_nr);
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
    volatile sig_atomic_t recurse = 0;
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

static char **files;
static size_t n_files, max_files;

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

    fatal_signal_block();
    if (n_files >= max_files) {
        max_files = max_files * 2 + 1;
        files = xrealloc(files, sizeof *files * max_files);
    }
    files[n_files++] = xstrdup(file);
    fatal_signal_unblock();
}

/* Unregisters 'file' from being unlinked when the program terminates via
 * exit() or a fatal signal. */
void
fatal_signal_remove_file_to_unlink(const char *file)
{
    size_t i;

    fatal_signal_block();
    for (i = 0; i < n_files; i++) {
        if (!strcmp(files[i], file)) {
            free(files[i]);
            files[i] = files[--n_files];
            break;
        }
    }
    fatal_signal_unblock();
}

static void
unlink_files(void *aux UNUSED)
{
    do_unlink_files(); 
}

static void
do_unlink_files(void)
{
    size_t i;

    for (i = 0; i < n_files; i++) {
        unlink(files[i]);
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
}

static void
call_sigprocmask(int how, sigset_t* new_set, sigset_t* old_set)
{
    int error = sigprocmask(how, new_set, old_set);
    if (error) {
        fprintf(stderr, "sigprocmask: %s\n", strerror(errno));
    }
}
