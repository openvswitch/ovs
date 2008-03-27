/* Copyright (C) 2008 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "poll-loop.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include "list.h"

#define THIS_MODULE VLM_poll_loop
#include "vlog.h"

struct poll_waiter {
    struct list node;
    int fd;
    short int events;
    struct pollfd *pollfd;

    short int *revents;

    poll_fd_func *function;
    void *aux;
};

static struct list waiters = LIST_INITIALIZER(&waiters);
static size_t n_waiters;
static int timeout = -1;

#ifndef NDEBUG
static struct poll_waiter *running_cb;
#endif

static struct poll_waiter *
new_waiter(int fd, short int events)
{
    struct poll_waiter *waiter = xcalloc(1, sizeof *waiter);
    assert(fd >= 0);
    waiter->fd = fd;
    waiter->events = events;
    list_push_back(&waiters, &waiter->node);
    n_waiters++;
    return waiter;
}

struct poll_waiter *
poll_fd_callback(int fd, short int events, poll_fd_func *function, void *aux)
{
    struct poll_waiter *pw = new_waiter(fd, events);
    pw->function = function;
    pw->aux = aux;
    return pw;
}

struct poll_waiter *
poll_fd_wait(int fd, short int events, short int *revents)
{
    struct poll_waiter *pw = new_waiter(fd, events);
    pw->revents = revents;
    if (revents) {
        *revents = 0;
    }
    return pw;
}

void
poll_cancel(struct poll_waiter *pw)
{
    if (pw) {
        assert(pw != running_cb);
        list_remove(&pw->node);
        n_waiters--;
    }
}

void
poll_immediate_wake(void)
{
    timeout = 0;
}

void
poll_timer_wait(int msec)
{
    if (timeout < 0 || msec < timeout) {
        timeout = MAX(0, msec);
    }
}

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

    do {
        retval = poll(pollfds, n_pollfds, timeout);
    } while (retval < 0 && errno == EINTR);
    if (retval < 0) {
        VLOG_ERR("poll: %s", strerror(errno));
    }

    for (node = waiters.next; node != &waiters; ) {
        pw = CONTAINER_OF(node, struct poll_waiter, node);
        if (!pw->pollfd || !pw->pollfd->revents) {
            if (pw->function) {
                node = node->next;
                continue;
            }
        } else {
            if (pw->function) {
#ifndef NDEBUG
                running_cb = pw;
#endif
                pw->function(pw->fd, pw->pollfd->revents, pw->aux);
#ifndef NDEBUG
                running_cb = NULL;
#endif
            } else if (pw->revents) {
                *pw->revents = pw->pollfd->revents;
            }
        }
        node = list_remove(node);
        n_waiters--;
    }

    timeout = -1;
}
