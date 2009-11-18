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
#include "poll-loop.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "backtrace.h"
#include "coverage.h"
#include "dynamic-string.h"
#include "list.h"
#include "timeval.h"

#define THIS_MODULE VLM_poll_loop
#include "vlog.h"

/* An event that will wake the following call to poll_block(). */
struct poll_waiter {
    /* Set when the waiter is created. */
    struct list node;           /* Element in global waiters list. */
    int fd;                     /* File descriptor. */
    short int events;           /* Events to wait for (POLLIN, POLLOUT). */
    poll_fd_func *function;     /* Callback function, if any, or null. */
    void *aux;                  /* Argument to callback function. */
    struct backtrace *backtrace; /* Optionally, event that created waiter. */

    /* Set only when poll_block() is called. */
    struct pollfd *pollfd;      /* Pointer to element of the pollfds array
                                   (null if added from a callback). */
};

/* All active poll waiters. */
static struct list waiters = LIST_INITIALIZER(&waiters);

/* Number of elements in the waiters list. */
static size_t n_waiters;

/* Max time to wait in next call to poll_block(), in milliseconds, or -1 to
 * wait forever. */
static int timeout = -1;

/* Backtrace of 'timeout''s registration, if debugging is enabled. */
static struct backtrace timeout_backtrace;

/* Callback currently running, to allow verifying that poll_cancel() is not
 * being called on a running callback. */
#ifndef NDEBUG
static struct poll_waiter *running_cb;
#endif

static struct poll_waiter *new_waiter(int fd, short int events);

/* Registers 'fd' as waiting for the specified 'events' (which should be POLLIN
 * or POLLOUT or POLLIN | POLLOUT).  The following call to poll_block() will
 * wake up when 'fd' becomes ready for one or more of the requested events.
 *
 * The event registration is one-shot: only the following call to poll_block()
 * is affected.  The event will need to be re-registered after poll_block() is
 * called if it is to persist. */
struct poll_waiter *
poll_fd_wait(int fd, short int events)
{
    COVERAGE_INC(poll_fd_wait);
    return new_waiter(fd, events);
}

/* Causes the following call to poll_block() to block for no more than 'msec'
 * milliseconds.  If 'msec' is nonpositive, the following call to poll_block()
 * will not block at all.
 *
 * The timer registration is one-shot: only the following call to poll_block()
 * is affected.  The timer will need to be re-registered after poll_block() is
 * called if it is to persist. */
void
poll_timer_wait(int msec)
{
    if (timeout < 0 || msec < timeout) {
        timeout = MAX(0, msec);
        if (VLOG_IS_DBG_ENABLED()) {
            backtrace_capture(&timeout_backtrace);
        }
    }
}

/* Causes the following call to poll_block() to wake up immediately, without
 * blocking. */
void
poll_immediate_wake(void)
{
    poll_timer_wait(0);
}

static void PRINTF_FORMAT(2, 3)
log_wakeup(const struct backtrace *backtrace, const char *format, ...)
{
    struct ds ds;
    va_list args;

    ds_init(&ds);
    va_start(args, format);
    ds_put_format_valist(&ds, format, args);
    va_end(args);

    if (backtrace) {
        int i;

        ds_put_char(&ds, ':');
        for (i = 0; i < backtrace->n_frames; i++) {
            ds_put_format(&ds, " 0x%"PRIxPTR, backtrace->frames[i]);
        }
    }
    VLOG_DBG("%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

/* Blocks until one or more of the events registered with poll_fd_wait()
 * occurs, or until the minimum duration registered with poll_timer_wait()
 * elapses, or not at all if poll_immediate_wake() has been called.
 *
 * Also executes any autonomous subroutines registered with poll_fd_callback(),
 * if their file descriptors have become ready. */
void
poll_block(void)
{
    static struct pollfd *pollfds;
    static size_t max_pollfds;

    struct poll_waiter *pw;
    struct list *node;
    int n_pollfds;
    int retval;

    assert(!running_cb);
    if (max_pollfds < n_waiters) {
        max_pollfds = n_waiters;
        pollfds = xrealloc(pollfds, max_pollfds * sizeof *pollfds);
    }

    n_pollfds = 0;
    LIST_FOR_EACH (pw, struct poll_waiter, node, &waiters) {
        pw->pollfd = &pollfds[n_pollfds];
        pollfds[n_pollfds].fd = pw->fd;
        pollfds[n_pollfds].events = pw->events;
        pollfds[n_pollfds].revents = 0;
        n_pollfds++;
    }

    if (!timeout) {
        COVERAGE_INC(poll_zero_timeout);
    }
    retval = time_poll(pollfds, n_pollfds, timeout);
    if (retval < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "poll: %s", strerror(-retval));
    } else if (!retval && VLOG_IS_DBG_ENABLED()) {
        log_wakeup(&timeout_backtrace, "%d-ms timeout", timeout);
    }

    for (node = waiters.next; node != &waiters; ) {
        pw = CONTAINER_OF(node, struct poll_waiter, node);
        if (!pw->pollfd || !pw->pollfd->revents) {
            if (pw->function) {
                node = node->next;
                continue;
            }
        } else {
            if (VLOG_IS_DBG_ENABLED()) {
                log_wakeup(pw->backtrace, "%s%s%s%s%s on fd %d",
                           pw->pollfd->revents & POLLIN ? "[POLLIN]" : "",
                           pw->pollfd->revents & POLLOUT ? "[POLLOUT]" : "",
                           pw->pollfd->revents & POLLERR ? "[POLLERR]" : "",
                           pw->pollfd->revents & POLLHUP ? "[POLLHUP]" : "",
                           pw->pollfd->revents & POLLNVAL ? "[POLLNVAL]" : "",
                           pw->fd);
            }

            if (pw->function) {
#ifndef NDEBUG
                running_cb = pw;
#endif
                pw->function(pw->fd, pw->pollfd->revents, pw->aux);
#ifndef NDEBUG
                running_cb = NULL;
#endif
            }
        }
        node = node->next;
        poll_cancel(pw);
    }

    timeout = -1;
    timeout_backtrace.n_frames = 0;
}

/* Registers 'function' to be called with argument 'aux' by poll_block() when
 * 'fd' becomes ready for one of the events in 'events', which should be POLLIN
 * or POLLOUT or POLLIN | POLLOUT.
 *
 * The callback registration persists until the event actually occurs.  At that
 * point, it is automatically de-registered.  The callback function must
 * re-register the event by calling poll_fd_callback() again within the
 * callback, if it wants to be called back again later. */
struct poll_waiter *
poll_fd_callback(int fd, short int events, poll_fd_func *function, void *aux)
{
    struct poll_waiter *pw = new_waiter(fd, events);
    pw->function = function;
    pw->aux = aux;
    return pw;
}

/* Cancels the file descriptor event registered with poll_fd_wait() or
 * poll_fd_callback().  'pw' must be the struct poll_waiter returned by one of
 * those functions.
 *
 * An event registered with poll_fd_wait() may be canceled from its time of
 * registration until the next call to poll_block().  At that point, the event
 * is automatically canceled by the system and its poll_waiter is freed.
 *
 * An event registered with poll_fd_callback() may be canceled from its time of
 * registration until its callback is actually called.  At that point, the
 * event is automatically canceled by the system and its poll_waiter is
 * freed. */
void
poll_cancel(struct poll_waiter *pw)
{
    if (pw) {
        assert(pw != running_cb);
        list_remove(&pw->node);
        free(pw->backtrace);
        free(pw);
        n_waiters--;
    }
}

/* Creates and returns a new poll_waiter for 'fd' and 'events'. */
static struct poll_waiter *
new_waiter(int fd, short int events)
{
    struct poll_waiter *waiter = xcalloc(1, sizeof *waiter);
    assert(fd >= 0);
    waiter->fd = fd;
    waiter->events = events;
    if (VLOG_IS_DBG_ENABLED()) {
        waiter->backtrace = xmalloc(sizeof *waiter->backtrace);
        backtrace_capture(waiter->backtrace);
    }
    list_push_back(&waiters, &waiter->node);
    n_waiters++;
    return waiter;
}
