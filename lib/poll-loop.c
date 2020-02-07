/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "openvswitch/poll-loop.h"
#include <errno.h>
#include <inttypes.h>
#ifdef OVS_USE_EPOLL
#include <sys/epoll.h>
#endif
#ifndef _WIN32
#include <unistd.h>
#endif
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "seq.h"
#include "socket-util.h"
#include "timeval.h"
#include "openvswitch/vlog.h"
#include "openvswitch/hmap.h"
#include "hash.h"

VLOG_DEFINE_THIS_MODULE(poll_loop);

COVERAGE_DEFINE(poll_create_node);
COVERAGE_DEFINE(poll_zero_timeout);

struct poll_node {
#ifndef OVS_USE_EPOLL
    struct ovs_list list_node;
#endif
    struct hmap_node hmap_node;
    struct pollfd pollfd;       /* Events to pass to time_poll(). */
    HANDLE wevent;              /* Events for WaitForMultipleObjects(). */
    const char *where;          /* Where poll_node was created. */
};

#define MAX_EPOLL_EVENTS 64

struct poll_loop {
    /* All active poll waiters. */
    struct hmap poll_nodes;

    /* Time at which to wake up the next call to poll_block(), LLONG_MIN to
     * wake up immediately, or LLONG_MAX to wait forever. */
    long long int timeout_when; /* In msecs as returned by time_msec(). */
    const char *timeout_where;  /* Where 'timeout_when' was set. */
#ifdef OVS_USE_EPOLL
    int epoll_fd;
    struct epoll_event epoll_events[MAX_EPOLL_EVENTS];
#endif
};

static struct poll_loop *poll_loop(void);

/* Look up the node with same fd or wevent. */
static struct poll_node *
find_poll_node(struct poll_loop *loop, int fd, HANDLE wevent)
{
    struct poll_node *node;

    /* Both 'fd' and 'wevent' cannot be set. */
    ovs_assert(!fd != !wevent);

    HMAP_FOR_EACH_WITH_HASH (node, hmap_node,
                             hash_2words(fd, (uint32_t)wevent),
                             &loop->poll_nodes) {
        if ((fd && node->pollfd.fd == fd)
            || (wevent && node->wevent == wevent)) {
            return node;
        }
    }
    return NULL;
}
/* Registers 'fd' as waiting for the specified 'events' (which should be OVS_POLLIN
 * or OVS_POLLOUT or OVS_POLLIN | OVS_POLLOUT).  The following call to poll_block() will
 * wake up when 'fd' becomes ready for one or more of the requested events.
 *
 * The event registration is PERSISTENT. This is intended for OSes which have a persistent
 * event framework. For now it is implemented only for epoll and Linux, other
 * implementations such as BSD kqueue and Solaris /dev/poll may follow.
 *
 * If the OS has no persistent even framework does nothing
 *
 * ('where' is used in debug logging.  Commonly one would use poll_fd_wait() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */

static void
poll_fd_subscribe_at(int fd, HANDLE wevent, int events, struct pollfd **hint, const char *where)
{
    struct poll_loop *loop = poll_loop();
    struct poll_node *node;
#ifdef OVS_USE_EPOLL
    struct epoll_event event;
#endif

    ovs_assert(!fd != !wevent);

    /* Check for duplicate.  If found, "or" the events. */
    node = find_poll_node(loop, fd, wevent);
    if (node) {
#ifdef OVS_USE_EPOLL
        int old_event_mask = node->pollfd.events;
#endif
        /* If there is an existing event mask we do not need to inc - this will be waited upon */
        node->pollfd.events |= (events & 0x0000FFFF); /* or without epoll specific bits */

#ifdef OVS_USE_EPOLL
        /* modify existing epoll entry if there is an epoll specific ask or if the
         * mask has changed
         */
        if ((events & 0xFFFF0000) || (old_event_mask != node->pollfd.events)) {
            event.events = node->pollfd.events | events;
            event.data.ptr = node;
            epoll_ctl(loop->epoll_fd, EPOLL_CTL_MOD, fd, &event);
        }
#endif
    } else {
        node = xzalloc(sizeof *node);
        hmap_insert(&loop->poll_nodes, &node->hmap_node,
                    hash_2words(fd, 0));
        node->pollfd.fd = fd;
        node->pollfd.events = (events & 0x0000FFFF);
        node->wevent = wevent;
        node->where = where;
#ifdef OVS_USE_EPOLL
        event.events = node->pollfd.events;
        event.data.ptr = node;
        epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, fd, &event);
#endif
    }
    if (hint) {
        *hint = &node->pollfd;
    }
}

void
poll_fd_register_at(int fd, int events, struct pollfd **hint, const char *where) {
    poll_fd_subscribe_at(fd, 0, events, hint, where);
}

/* Deregisters a fd for OSes which have persistent IO event frameworks */

void
poll_fd_deregister_at(int fd, const char *where)
{
    struct poll_loop *loop = poll_loop();
    struct poll_node *node, *next;

    VLOG(VLL_DBG, "Deregister %d from %s", fd, where);
    HMAP_FOR_EACH_SAFE (node, next, hmap_node, &loop->poll_nodes) {
        if (fd == node->pollfd.fd) {
#ifdef OVS_USE_EPOLL
            epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, node->pollfd.fd, NULL);
#endif
            hmap_remove(&loop->poll_nodes, &node->hmap_node);
            free(node);
            return;
        }
    }
}


void
poll_fd_wait_at(int fd, int events, const char *where)
{
#ifdef OVS_USE_EPOLL
    /* on linux all pollfds are registered with epoll at creation for POLLIN */
    if (!(events & (OVS_POLLOUT | OVS_ONESHOT))) 
        return;
#endif
    poll_fd_subscribe_at(fd, 0, events, NULL, where);
}


#ifdef _WIN32
/* Registers for the next call to poll_block() to wake up when 'wevent' is
 * signaled.
 *
 * The event registration is one-shot: only the following call to poll_block()
 * is affected.  The event will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * ('where' is used in debug logging.  Commonly one would use
 * poll_wevent_wait() to automatically provide the caller's source file and
 * line number for 'where'.) */
void
poll_wevent_wait_at(HANDLE wevent, const char *where)
{
    poll_fd_subscribe_at(0, wevent, 0, NULL, where);
}
#endif /* _WIN32 */

/* Causes the following call to poll_block() to block for no more than 'msec'
 * milliseconds.  If 'msec' is nonpositive, the following call to poll_block()
 * will not block at all.
 *
 * The timer registration is one-shot: only the following call to poll_block()
 * is affected.  The timer will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * ('where' is used in debug logging.  Commonly one would use poll_timer_wait()
 * to automatically provide the caller's source file and line number for
 * 'where'.) */
void
poll_timer_wait_at(long long int msec, const char *where)
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

    poll_timer_wait_until_at(when, where);
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
 * ('where' is used in debug logging.  Commonly one would use
 * poll_timer_wait_until() to automatically provide the caller's source file
 * and line number for 'where'.) */
void
poll_timer_wait_until_at(long long int when, const char *where)
{
    struct poll_loop *loop = poll_loop();
    if (when < loop->timeout_when) {
        loop->timeout_when = when;
        loop->timeout_where = where;
    }
}

/* Causes the following call to poll_block() to wake up immediately, without
 * blocking.
 *
 * ('where' is used in debug logging.  Commonly one would use
 * poll_immediate_wake() to automatically provide the caller's source file and
 * line number for 'where'.) */
void
poll_immediate_wake_at(const char *where)
{
    poll_timer_wait_at(0, where);
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
    } else if (cpu_usage > 50
               && !thread_is_pmd()
               && !VLOG_DROP_INFO(&rl)) {
        level = VLL_INFO;
    } else {
        return;
    }

    ds_init(&s);
    ds_put_cstr(&s, "wakeup due to ");
    if (pollfd) {
        char *description = describe_fd(pollfd->fd);
        if (pollfd->revents & OVS_POLLIN) {
            ds_put_cstr(&s, "[OVS_POLLIN]");
        }
        if (pollfd->revents & OVS_POLLOUT) {
            ds_put_cstr(&s, "[OVS_POLLOUT]");
        }
        if (pollfd->revents & OVS_POLLERR) {
            ds_put_cstr(&s, "[OVS_POLLERR]");
        }
        if (pollfd->revents & OVS_POLLHUP) {
            ds_put_cstr(&s, "[OVS_POLLHUP]");
        }
#ifndef OVS_USE_EPOLL
        /* epoll does not have NVAL */
        if (pollfd->revents & OVS_POLLNVAL) {
            ds_put_cstr(&s, "[OVS_POLLNVAL]");
        }
#endif
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


static void
free_poll_nodes(struct poll_loop *loop)
{
    struct poll_node *node, *next;

    HMAP_FOR_EACH_SAFE (node, next, hmap_node, &loop->poll_nodes) {
#ifdef OVS_USE_EPOLL
        epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, node->pollfd.fd, NULL);
#endif
        hmap_remove(&loop->poll_nodes, &node->hmap_node);
#ifdef _WIN32
        if (node->wevent && node->pollfd.fd) {
            WSAEventSelect(node->pollfd.fd, NULL, 0);
            CloseHandle(node->wevent);
        }
#endif
        free(node);
    }
}

/* Blocks until one or more of the events registered with poll_fd_wait()
 * occurs, or until the minimum duration registered with poll_timer_wait()
 * elapses, or not at all if poll_immediate_wake() has been called. */
void
poll_block(void)
{
    struct poll_loop *loop = poll_loop();
    struct poll_node *node;
#ifndef OVS_USE_EPOLL
    struct pollfd *pollfds;
#endif
#ifndef OVS_USE_EPOLL
    HANDLE *wevents = NULL;
#endif
    int elapsed;
    int retval;
    int i;
    int counter;

    /* Register fatal signal events before actually doing any real work for
     * poll_block. */
    fatal_signal_wait();

    if (loop->timeout_when == LLONG_MIN) {
        COVERAGE_INC(poll_zero_timeout);
    }

    timewarp_run();

#ifdef OVS_USE_EPOLL
    retval = time_epoll_wait(loop->epoll_fd,
        (struct epoll_event *) &loop->epoll_events, MAX_EPOLL_EVENTS, loop->timeout_when, &elapsed);
    if (retval < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "epoll: %s", ovs_strerror(retval));
    } else if (!retval) {
        log_wakeup(loop->timeout_where, NULL, elapsed);
    } else {
        for (i = 0; i < retval; i++) {
            node = (struct poll_node *) loop->epoll_events[i].data.ptr;
            if (loop->epoll_events[i].events) {
                node->pollfd.revents |= loop->epoll_events[i].events;
            }
            if (loop->epoll_events[i].events & OVS_POLLOUT) {
                struct epoll_event event;

                node->pollfd.events = OVS_POLLIN; /* reset back to defaults - write needs one shot */
                event.events = node->pollfd.events;
                event.data.ptr = node;
                epoll_ctl(loop->epoll_fd, EPOLL_CTL_MOD, node->pollfd.fd, &event);
            }
        }
        if (get_cpu_usage() > 50 || VLOG_IS_DBG_ENABLED()) {
            for (i = 0; i < retval; i++) {
                node = (struct poll_node *) loop->epoll_events[i].data.ptr;
                if (loop->epoll_events[i].events) {
                    node->pollfd.revents = loop->epoll_events[i].events;
                    log_wakeup(node->where, &node->pollfd, 0);
                }
            }
        }
    }
#else
    pollfds = xmalloc(hmap_count(&loop->poll_nodes) * sizeof *pollfds);
#ifdef _WIN32
    wevents = xmalloc(hmap_count(&loop->poll_nodes) * sizeof *wevents);
#endif


    /* Populate with all the fds and events. */
    counter = 0;
    HMAP_FOR_EACH (node, hmap_node, &loop->poll_nodes) {
        if (node->pollfd.events) {
            pollfds[counter] = node->pollfd;
#ifdef _WIN32
            wevents[counter] = node->wevent;
            if (node->pollfd.fd && node->wevent) {
                short int wsa_events = 0;
                if (node->pollfd.events & OVS_POLLIN) {
                    wsa_events |= FD_READ | FD_ACCEPT | FD_CLOSE;
                }
                if (node->pollfd.events & OVS_POLLOUT) {
                    wsa_events |= FD_WRITE | FD_CONNECT | FD_CLOSE;
                }
                WSAEventSelect(node->pollfd.fd, node->wevent, wsa_events);
            }
#endif
            counter++;
        }
    }

    retval = time_poll(pollfds, counter, wevents,
                       loop->timeout_when, &elapsed);
    if (retval < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "poll: %s", ovs_strerror(-retval));
    } else if (retval == 0) {
        log_wakeup(loop->timeout_where, NULL, elapsed);
    } else {
        for (i = 0; i < counter; i++) {
            if (pollfds[i].revents) {

                node = find_poll_node(loop, pollfds[i].fd, 0);

                if (!node) {
                    VLOG_FATAL("poll: persistence state corrupted, no hash entry for %d", pollfds[i].fd);
                }

                if (get_cpu_usage() > 50 || VLOG_IS_DBG_ENABLED()) {
                    log_wakeup(node->where, &pollfds[i], 0);
                }
                /* update "requested" events. Note - old code had a logical error
                 * here - it was overwriting all events even if ONLY one type of event
                 * has occured. F.E. - poll reported only read, but it was overwriting
                 *  a request for both read + write.
                 * If you see a regression - fix your caller, this the way it SHOULD be.
                 */
                node->pollfd.events &= ~pollfds[i].revents;
                /* update "occured" events for use by streams and handlers. In case there
                 * is an existing (but not consumed yet) event, we OR the events in the
                 * stored record with the new ones - it is the job of the stream to clear
                 * that.
                 */
                node->pollfd.revents |= pollfds[i].revents;
            }
        }
    }

    free(pollfds);
    if (wevents)
        free(wevents);
#endif
    loop->timeout_when = LLONG_MAX;
    loop->timeout_where = NULL;

    /* Handle any pending signals before doing anything else. */
    fatal_signal_run();

    seq_woke();
}

static void
free_poll_loop(void *loop_)
{
    struct poll_loop *loop = loop_;

    free_poll_nodes(loop);
    hmap_destroy(&loop->poll_nodes);
    free(loop);
}

static struct poll_loop *
poll_loop(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static pthread_key_t key;
    struct poll_loop *loop;

    if (ovsthread_once_start(&once)) {
        xpthread_key_create(&key, free_poll_loop);
        ovsthread_once_done(&once);
    }

    loop = pthread_getspecific(key);
    if (!loop) {
        loop = xzalloc(sizeof *loop);
        loop->timeout_when = LLONG_MAX;
        hmap_init(&loop->poll_nodes);
        xpthread_setspecific(key, loop);
#ifdef OVS_USE_EPOLL
        loop->epoll_fd = epoll_create(MAX_EPOLL_EVENTS);
#endif
    }
    return loop;
}

