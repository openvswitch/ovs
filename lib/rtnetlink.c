/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#include "rtnetlink.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>

#include "coverage.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "ofpbuf.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(rtnetlink);

COVERAGE_DEFINE(rtnetlink_changed);

static void rtnetlink_report(struct rtnetlink *rtn, void *change);

struct rtnetlink {
    struct nl_sock *notify_sock; /* Rtnetlink socket. */
    struct list all_notifiers;   /* All rtnetlink notifiers. */

    /* Passed in by rtnetlink_create(). */
    int multicast_group;         /* Multicast group we listen on. */
    rtnetlink_parse_func *parse; /* Message parsing function. */
    void *change;                /* Change passed to parse. */
};

/* Creates an rtnetlink handle which may be used to manage change
 * notifications.  The created handle will listen for rtnetlink messages on
 * 'multicast_group'.  Incoming messages will be parsed with 'parse' which will
 * be passed 'change' as an argument. */
struct rtnetlink *
rtnetlink_create(int multicast_group, rtnetlink_parse_func *parse,
                 void *change)
{
    struct rtnetlink *rtn;

    rtn                  = xzalloc(sizeof *rtn);
    rtn->notify_sock     = NULL;
    rtn->multicast_group = multicast_group;
    rtn->parse           = parse;
    rtn->change          = change;

    list_init(&rtn->all_notifiers);
    return rtn;
}

/* Destroys 'rtn' by freeing any memory it has reserved and closing any sockets
 * it has opened. */
void
rtnetlink_destroy(struct rtnetlink *rtn)
{
    if (rtn) {
        nl_sock_destroy(rtn->notify_sock);
        free(rtn);
    }
}

/* Registers 'cb' to be called with auxiliary data 'aux' with change
 * notifications.  The notifier is stored in 'notifier', which the caller must
 * not modify or free.
 *
 * This is probably not the function you want.  You should probably be using
 * message specific notifiers like rtnetlink_link_notifier_register().
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
rtnetlink_notifier_register(struct rtnetlink *rtn,
                            struct rtnetlink_notifier *notifier,
                            rtnetlink_notify_func *cb, void *aux)
{
    if (!rtn->notify_sock) {
        struct nl_sock *sock;
        int error;

        error = nl_sock_create(NETLINK_ROUTE, &sock);
        if (!error) {
            error = nl_sock_join_mcgroup(sock, rtn->multicast_group);
        }
        if (error) {
            nl_sock_destroy(sock);
            VLOG_WARN("could not create rtnetlink socket: %s",
                      strerror(error));
            return error;
        }
        rtn->notify_sock = sock;
    } else {
        /* Catch up on notification work so that the new notifier won't
         * receive any stale notifications. */
        rtnetlink_notifier_run(rtn);
    }

    list_push_back(&rtn->all_notifiers, &notifier->node);
    notifier->cb = cb;
    notifier->aux = aux;
    return 0;
}

/* Cancels notification on 'notifier', which must have previously been
 * registered with rtnetlink_notifier_register(). */
void
rtnetlink_notifier_unregister(struct rtnetlink *rtn,
                              struct rtnetlink_notifier *notifier)
{
    list_remove(&notifier->node);
    if (list_is_empty(&rtn->all_notifiers)) {
        nl_sock_destroy(rtn->notify_sock);
        rtn->notify_sock = NULL;
    }
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * change events. */
void
rtnetlink_notifier_run(struct rtnetlink *rtn)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (!rtn->notify_sock) {
        return;
    }

    for (;;) {
        struct ofpbuf *buf;
        int error;

        error = nl_sock_recv(rtn->notify_sock, &buf, false);
        if (!error) {
            if (rtn->parse(buf, rtn->change)) {
                rtnetlink_report(rtn, rtn->change);
            } else {
                VLOG_WARN_RL(&rl, "received bad rtnl message");
                rtnetlink_report(rtn, NULL);
            }
            ofpbuf_delete(buf);
        } else if (error == EAGAIN) {
            return;
        } else {
            if (error == ENOBUFS) {
                VLOG_WARN_RL(&rl, "rtnetlink receive buffer overflowed");
            } else {
                VLOG_WARN_RL(&rl, "error reading rtnetlink socket: %s",
                             strerror(error));
            }
            rtnetlink_report(rtn, NULL);
        }
    }
}

/* Causes poll_block() to wake up when change notifications are ready. */
void
rtnetlink_notifier_wait(struct rtnetlink *rtn)
{
    if (rtn->notify_sock) {
        nl_sock_wait(rtn->notify_sock, POLLIN);
    }
}

static void
rtnetlink_report(struct rtnetlink *rtn, void *change)
{
    struct rtnetlink_notifier *notifier;

    if (change) {
        COVERAGE_INC(rtnetlink_changed);
    }

    LIST_FOR_EACH (notifier, node, &rtn->all_notifiers) {
        notifier->cb(change, notifier->aux);
    }
}

