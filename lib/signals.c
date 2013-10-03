/*
 * Copyright (c) 2008, 2009, 2011, 2012, 2013 Nicira, Inc.
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
    int fds[2];
};

static struct signal signals[N_SIGNALS];

static void signal_handler(int signr);

/* Sets up a handler for 'signr' and returns a structure that represents it.
 *
 * Only one handler for a given signal may be registered. */
struct signal *
signal_register(int signr)
{
    struct sigaction sa;
    struct signal *s;

    ovs_assert(signr >= 1 && signr < N_SIGNALS);

    /* Create a pipe. */
    s = &signals[signr];
    ovs_assert(!s->fds[0] && !s->fds[1]);
    xpipe_nonblocking(s->fds);

    /* Install signal handler. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    xsigaction(signr, &sa, NULL);

    return s;
}

/* Returns true if signal 's' has been received since the last call to this
 * function with argument 's'. */
bool
signal_poll(struct signal *s)
{
    char buf[_POSIX_PIPE_BUF];

    return read(s->fds[0], buf, sizeof buf) > 0;
}

/* Causes the next call to poll_block() to wake up when signal_poll(s) would
 * return true. */
void
signal_wait(struct signal *s)
{
    poll_fd_wait(s->fds[0], POLLIN);
}

static void
signal_handler(int signr)
{
    if (signr >= 1 && signr < N_SIGNALS) {
        ignore(write(signals[signr].fds[1], "", 1));
    }
}

/* Returns the name of signal 'signum' as a string.  The return value is either
 * a statically allocated constant string or the 'bufsize'-byte buffer
 * 'namebuf'.  'bufsize' should be at least SIGNAL_NAME_BUFSIZE.
 *
 * The string is probably a (possibly multi-word) description of the signal
 * (e.g. "Hangup") instead of just the stringified version of the macro
 * (e.g. "SIGHUP"). */
const char *
signal_name(int signum, char *namebuf, size_t bufsize)
{
#if HAVE_DECL_SYS_SIGLIST
    if (signum >= 0 && signum < N_SIGNALS) {
        const char *name = sys_siglist[signum];
        if (name) {
            return name;
        }
    }
#endif

    snprintf(namebuf, bufsize, "signal %d", signum);
    return namebuf;
}

void
xsigaction(int signum, const struct sigaction *new, struct sigaction *old)
{
    if (sigaction(signum, new, old)) {
        char namebuf[SIGNAL_NAME_BUFSIZE];

        VLOG_FATAL("sigaction(%s) failed (%s)",
                   signal_name(signum, namebuf, sizeof namebuf),
                   ovs_strerror(errno));
    }
}

void
xpthread_sigmask(int how, const sigset_t *new, sigset_t *old)
{
    int error = pthread_sigmask(how, new, old);
    if (error) {
        VLOG_FATAL("pthread_sigmask failed (%s)", ovs_strerror(error));
    }
}
