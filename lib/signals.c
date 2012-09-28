/*
 * Copyright (c) 2008, 2009, 2011, 2012 Nicira, Inc.
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
#include "signals.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "poll-loop.h"
#include "socket-util.h"
#include "type-props.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(signals);

#if defined(_NSIG)
#define N_SIGNALS _NSIG
#elif defined(NSIG)
#define N_SIGNALS NSIG
#else
/* We could try harder to get the maximum signal number, but in practice we
 * only care about SIGHUP, which is normally signal 1 anyway. */
#define N_SIGNALS 32
#endif

struct signal {
    struct sigaction saved_sa;
    int signr;
};

static volatile sig_atomic_t signaled[N_SIGNALS];

static int fds[2];

static void signal_handler(int signr);

/* Initializes the signals subsystem (if it is not already initialized).  Calls
 * exit() if initialization fails.
 *
 * Calling this function is optional; it will be called automatically by
 * signal_start() if necessary.  Calling it explicitly allows the client to
 * prevent the process from exiting at an unexpected time. */
void
signal_init(void)
{
    static bool inited;
    if (!inited) {
        inited = true;
        xpipe_nonblocking(fds);
    }
}

/* Sets up a handler for 'signr' and returns a structure that represents it.
 *
 * Only one handler for a given signal may be registered at a time. */
struct signal *
signal_register(int signr)
{
    struct sigaction sa;
    struct signal *s;

    signal_init();

    s = xmalloc(sizeof *s);
    s->signr = signr;

    /* Set up signal handler. */
    assert(signr >= 1 && signr < N_SIGNALS);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    xsigaction(signr, &sa, &s->saved_sa);

    return s;
}

/* Unregisters the handler for 's', restores the signal handler that was in
 * effect before signal_register() was called, and frees 's'. */
void
signal_unregister(struct signal *s)
{
    if (s) {
        xsigaction(s->signr, &s->saved_sa, NULL);
        free(s);
    }
}

/* Returns true if signal 's' has been received since the last call to this
 * function with argument 's'. */
bool
signal_poll(struct signal *s)
{
    char buf[_POSIX_PIPE_BUF];
    ignore(read(fds[0], buf, sizeof buf));
    if (signaled[s->signr]) {
        signaled[s->signr] = 0;
        return true;
    }
    return false;
}

/* Causes the next call to poll_block() to wake up when signal_poll(s) would
 * return true. */
void
signal_wait(struct signal *s)
{
    if (signaled[s->signr]) {
        poll_immediate_wake();
    } else {
        poll_fd_wait(fds[0], POLLIN);
    }
}

static void
signal_handler(int signr)
{
    if (signr >= 1 && signr < N_SIGNALS) {
        ignore(write(fds[1], "", 1));
        signaled[signr] = true;
    }
}

/* Returns the name of signal 'signum' as a string.  The string may be in a
 * static buffer that is reused from one call to the next.
 *
 * The string is probably a (possibly multi-word) description of the signal
 * (e.g. "Hangup") instead of just the stringified version of the macro
 * (e.g. "SIGHUP"). */
const char *
signal_name(int signum)
{
    const char *name = NULL;
#ifdef HAVE_STRSIGNAL
    name = strsignal(signum);
#endif
    if (!name) {
        static char buffer[7 + INT_STRLEN(int) + 1];
        sprintf(buffer, "signal %d", signum);
        name = buffer;
    }
    return name;
}

void
xsigaction(int signum, const struct sigaction *new, struct sigaction *old)
{
    if (sigaction(signum, new, old)) {
        VLOG_FATAL("sigaction(%s) failed (%s)",
                   signal_name(signum), strerror(errno));
    }
}

void
xsigprocmask(int how, const sigset_t *new, sigset_t *old)
{
    if (sigprocmask(how, new, old)) {
        VLOG_FATAL("sigprocmask failed (%s)", strerror(errno));
    }
}
