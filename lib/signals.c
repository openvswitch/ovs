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
#include "signals.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"

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
        if (pipe(fds)) {
            ovs_fatal(errno, "could not create pipe");
        }
        set_nonblocking(fds[0]);
        set_nonblocking(fds[1]);
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

    /* Set up signal handler. */
    assert(signr >= 1 && signr < N_SIGNALS);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(signr, &sa, NULL)) {
        ovs_fatal(errno, "sigaction(%d) failed", signr);
    }

    /* Return structure. */
    s = xmalloc(sizeof *s);
    s->signr = signr;
    return s;
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
