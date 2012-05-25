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
#include "poll-loop.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "list.h"
#include "socket-util.h"
#include "timeval.h"
#include "vlog.h"

#undef poll_fd_wait
#undef poll_timer_wait
#undef poll_timer_wait_until
#undef poll_immediate_wake

VLOG_DEFINE_THIS_MODULE(poll_loop);

COVERAGE_DEFINE(poll_fd_wait);
COVERAGE_DEFINE(poll_zero_timeout);

/* An event that will wake the following call to poll_block(). */
struct poll_waiter {
    /* Set when the waiter is created. */
    struct list node;           /* Element in global waiters list. */
    int fd;                     /* File descriptor. */
    short int events;           /* Events to wait for (POLLIN, POLLOUT). */
    const char *where;          /* Where the waiter was created. */

    /* Set only when poll_block() is called. */
    struct pollfd *pollfd;      /* Pointer to element of the pollfds array. */
};

/* All active poll waiters. */
static struct list waiters = LIST_INITIALIZER(&waiters);

/* Time at which to wake up the next call to poll_block(), in milliseconds as
 * returned by time_msec(), LLONG_MIN to wake up immediately, or LLONG_MAX to
 * wait forever. */
static long long int timeout_when = LLONG_MAX;

/* Location where waiter created. */
static const char *timeout_where;

static struct poll_waiter *new_waiter(int fd, short int events,
                                      const char *where);

/* Registers 'fd' as waiting for the specified 'events' (which should be POLLIN
 * or POLLOUT or POLLIN | POLLOUT).  The following call to poll_block() will
 * wake up when 'fd' becomes ready for one or more of the requested events.
 *
 * The event registration is one-shot: only the following call to poll_block()
 * is affected.  The event will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * Ordinarily the 'where' argument is supplied automatically; see poll-loop.h
 * for more information. */
struct poll_waiter *
poll_fd_wait(int fd, short int events, const char *where)
{
    COVERAGE_INC(poll_fd_wait);
    return new_waiter(fd, events, where);
}

/* Causes the following call to poll_block() to block for no more than 'msec'
 * milliseconds.  If 'msec' is nonpositive, the following call to poll_block()
 * will not block at all.
 *
 * The timer registration is one-shot: only the following call to poll_block()
 * is affected.  The timer will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * Ordinarily the 'where' argument is supplied automatically; see poll-loop.h
 * for more information. */
void
poll_timer_wait(long long int msec, const char *where)
{
    long long int now = time_msec();
    long long int when;

    if (msec <= 0) {
        /* Wake up immediately. */
        when = LLONG_MIN;
    } else if ((unsigned long long int) now + msec <= LLONG_MAX) {
        /* Normal case. */
        when = now + msec;
    } else {
        /* now + msec would overflow. */
        when = LLONG_MAX;
    }

    poll_timer_wait_until(when, where);
}

/* Causes the following call to poll_block() to wake up when the current time,
 * as returned by time_msec(), reaches 'when' or later.  If 'when' is earlier
 * than the current time, the following call to poll_block() will not block at
 * all.
 *
 * The timer registration is one-shot: only the following call to poll_block()
 * is affected.  The timer will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * Ordinarily the 'where' argument is supplied automatically; see poll-loop.h
 * for more information. */
void
poll_timer_wait_until(long long int when, const char *where)
{
    if (when < timeout_when) {
        timeout_when = when;
        timeout_where = where;
    }
}

/* Causes the following call to poll_block() to wake up immediately, without
 * blocking.
 *
 * Ordinarily the 'where' argument is supplied automatically; see poll-loop.h
 * for more information. */
void
poll_immediate_wake(const char *where)
{
    poll_timer_wait(0, where);
}

/* Logs, if appropriate, that the poll loop was awakened by an event
 * registered at 'where' (typically a source file and line number).  The other
 * arguments have two possible interpretations:
 *
 *   - If 'pollfd' is nonnull then it should be the "struct pollfd" that caused
 *     the wakeup.  'timeout' is ignored.
 *
 *   - If 'pollfd' is NULL then 'timeout' is the number of milliseconds after
 *     which the poll loop woke up.
 */
static void
log_wakeup(const char *where, const struct pollfd *pollfd, int timeout)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    enum vlog_level level;
    int cpu_usage;
    struct ds s;

    cpu_usage = get_cpu_usage();
    if (VLOG_IS_DBG_ENABLED()) {
        level = VLL_DBG;
    } else if (cpu_usage > 50 && !VLOG_DROP_WARN(&rl)) {
        level = VLL_WARN;
    } else {
        return;
    }

    ds_init(&s);
    ds_put_cstr(&s, "wakeup due to ");
    if (pollfd) {
        char *description = describe_fd(pollfd->fd);
        if (pollfd->revents & POLLIN) {
            ds_put_cstr(&s, "[POLLIN]");
        }
        if (pollfd->revents & POLLOUT) {
            ds_put_cstr(&s, "[POLLOUT]");
        }
        if (pollfd->revents & POLLERR) {
            ds_put_cstr(&s, "[POLLERR]");
        }
        if (pollfd->revents & POLLHUP) {
            ds_put_cstr(&s, "[POLLHUP]");
        }
        if (pollfd->revents & POLLNVAL) {
            ds_put_cstr(&s, "[POLLNVAL]");
        }
        ds_put_format(&s, " on fd %d (%s)", pollfd->fd, description);
        free(description);
    } else {
        ds_put_format(&s, "%d-ms timeout", timeout);
    }
    if (where) {
        ds_put_format(&s, " at %s", where);
    }
    if (cpu_usage >= 0) {
        ds_put_format(&s, " (%d%% CPU usage)", cpu_usage);
    }
    VLOG(level, "%s", ds_cstr(&s));
    ds_destroy(&s);
}

/* Blocks until one or more of the events registered with poll_fd_wait()
 * occurs, or until the minimum duration registered with poll_timer_wait()
 * elapses, or not at all if poll_immediate_wake() has been called. */
void
poll_block(void)
{
    static struct pollfd *pollfds;
    static size_t max_pollfds;

    struct poll_waiter *pw, *next;
    int n_waiters, n_pollfds;
    int elapsed;
    int retval;

    /* Register fatal signal events before actually doing any real work for
     * poll_block. */
    fatal_signal_wait();

    n_waiters = list_size(&waiters);
    if (max_pollfds < n_waiters) {
        max_pollfds = n_waiters;
        pollfds = xrealloc(pollfds, max_pollfds * sizeof *pollfds);
    }

    n_pollfds = 0;
    LIST_FOR_EACH (pw, node, &waiters) {
        pw->pollfd = &pollfds[n_pollfds];
        pollfds[n_pollfds].fd = pw->fd;
        pollfds[n_pollfds].events = pw->events;
        pollfds[n_pollfds].revents = 0;
        n_pollfds++;
    }

    if (timeout_when == LLONG_MIN) {
        COVERAGE_INC(poll_zero_timeout);
    }
    retval = time_poll(pollfds, n_pollfds, timeout_when, &elapsed);
    if (retval < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "poll: %s", strerror(-retval));
    } else if (!retval) {
        log_wakeup(timeout_where, NULL, elapsed);
    }

    LIST_FOR_EACH_SAFE (pw, next, node, &waiters) {
        if (pw->pollfd->revents) {
            log_wakeup(pw->where, pw->pollfd, 0);
        }
        poll_cancel(pw);
    }

    timeout_when = LLONG_MAX;
    timeout_where = NULL;

    /* Handle any pending signals before doing anything else. */
    fatal_signal_run();
}

/* Cancels the file descriptor event registered with poll_fd_wait() using 'pw',
 * the struct poll_waiter returned by that function.
 *
 * An event registered with poll_fd_wait() may be canceled from its time of
 * registration until the next call to poll_block().  At that point, the event
 * is automatically canceled by the system and its poll_waiter is freed. */
void
poll_cancel(struct poll_waiter *pw)
{
    if (pw) {
        list_remove(&pw->node);
        free(pw);
    }
}

/* Creates and returns a new poll_waiter for 'fd' and 'events'. */
static struct poll_waiter *
new_waiter(int fd, short int events, const char *where)
{
    struct poll_waiter *waiter = xzalloc(sizeof *waiter);
    assert(fd >= 0);
    waiter->fd = fd;
    waiter->events = events;
    waiter->where = where;
    list_push_back(&waiters, &waiter->node);
    return waiter;
}
