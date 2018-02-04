/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
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

#include "netlink-notifier.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>

#include "coverage.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netlink_notifier);

COVERAGE_DEFINE(nln_changed);

struct nln {
    struct nl_sock *notify_sock; /* Netlink socket. */
    struct ovs_list all_notifiers;   /* All nln notifiers. */
    bool has_run;                /* Guard for run and wait functions. */

    /* Passed in by nln_create(). */
    int protocol;                /* Protocol passed to nl_sock_create(). */
    nln_parse_func *parse;       /* Message parsing function. */
    void *change;                /* Change passed to parse. */
};

struct nln_notifier {
    struct ovs_list node;        /* In struct nln's 'all_notifiers' list. */
    struct nln *nln;             /* Parent nln. */

    int multicast_group;         /* Multicast group we listen on. */
    nln_notify_func *cb;
    void *aux;
};

/* Creates an nln handle which may be used to manage change notifications.  The
 * created handle will listen for netlink messages on 'multicast_group' using
 * netlink protocol 'protocol' (e.g. NETLINK_ROUTE, NETLINK_GENERIC, ...).
 * Incoming messages will be parsed with 'parse' which will be passed 'change'
 * as an argument. */
struct nln *
nln_create(int protocol, nln_parse_func *parse, void *change)
{
    struct nln *nln;

    nln = xzalloc(sizeof *nln);
    nln->notify_sock = NULL;
    nln->protocol = protocol;
    nln->parse = parse;
    nln->change = change;
    nln->has_run = false;

    ovs_list_init(&nln->all_notifiers);
    return nln;
}

/* Destroys 'nln' by freeing any memory it has reserved and closing any sockets
 * it has opened.
 *
 * The caller is responsible for destroying any notifiers created by this
 * 'nln' before destroying 'nln'. */
void
nln_destroy(struct nln *nln)
{
    if (nln) {
        ovs_assert(ovs_list_is_empty(&nln->all_notifiers));
        nl_sock_destroy(nln->notify_sock);
        free(nln);
    }
}

/* Registers 'cb' to be called with auxiliary data 'aux' with change
 * notifications.  The notifier is stored in 'notifier', which the caller must
 * not modify or free.
 *
 * This is probably not the function you want.  You should probably be using
 * message specific notifiers like rtnetlink_link_notifier_register().
 *
 * Returns an initialized nln_notifier if successful, otherwise NULL. */
struct nln_notifier *
nln_notifier_create(struct nln *nln, int multicast_group, nln_notify_func *cb,
                    void *aux)
{
    struct nln_notifier *notifier;
    int error;

    if (!nln->notify_sock) {
        struct nl_sock *sock;

        error = nl_sock_create(nln->protocol, &sock);
        if (error) {
            VLOG_WARN("could not create netlink socket: %s",
                      ovs_strerror(error));
            return NULL;
        }
        nln->notify_sock = sock;
    } else {
        /* Catch up on notification work so that the new notifier won't
         * receive any stale notifications. */
        nln_run(nln);
    }

    error = nl_sock_join_mcgroup(nln->notify_sock, multicast_group);
    if (error) {
        VLOG_WARN("could not join netlink multicast group: %s",
                  ovs_strerror(error));
        return NULL;
    }

    notifier = xmalloc(sizeof *notifier);
    notifier->multicast_group = multicast_group;
    notifier->cb = cb;
    notifier->aux = aux;
    notifier->nln = nln;

    ovs_list_push_back(&nln->all_notifiers, &notifier->node);

    return notifier;
}

/* Destroys 'notifier', which must have previously been created with
 * nln_notifier_register(). */
void
nln_notifier_destroy(struct nln_notifier *notifier)
{
    if (notifier) {
        struct nln *nln = notifier->nln;
        struct nln_notifier *iter;
        int count = 0;

        ovs_list_remove(&notifier->node);

        /* Leave the group if no other notifier is interested in it. */
        LIST_FOR_EACH (iter, node, &nln->all_notifiers) {
            if (iter->multicast_group == notifier->multicast_group) {
                count++;
            }
        }
        if (count == 0) {
            nl_sock_leave_mcgroup(nln->notify_sock, notifier->multicast_group);
        }

        if (ovs_list_is_empty(&nln->all_notifiers)) {
            nl_sock_destroy(nln->notify_sock);
            nln->notify_sock = NULL;
        }
        free(notifier);
    }
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * change events. */
void
nln_run(struct nln *nln)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (!nln->notify_sock || nln->has_run) {
        return;
    }

    nln->has_run = true;
    for (;;) {
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;
        int error;

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(nln->notify_sock, &buf, false);
        if (!error) {
            int group = nln->parse(&buf, nln->change);

            if (group != 0) {
                nln_report(nln, nln->change, group);
            } else {
                VLOG_WARN_RL(&rl, "unexpected netlink message contents");
                nln_report(nln, NULL, 0);
            }
            ofpbuf_uninit(&buf);
        } else if (error == EAGAIN) {
            return;
        } else {
            if (error == ENOBUFS) {
                /* The socket buffer might be full, there could be too many
                 * notifications, so it makes sense to call nln_report() */
                nln_report(nln, NULL, 0);
                VLOG_WARN_RL(&rl, "netlink receive buffer overflowed");
            } else {
                VLOG_WARN_RL(&rl, "error reading netlink socket: %s",
                             ovs_strerror(error));
            }
            return;
        }
    }
}

/* Causes poll_block() to wake up when change notifications are ready. */
void
nln_wait(struct nln *nln)
{
    nln->has_run = false;
    if (nln->notify_sock) {
        nl_sock_wait(nln->notify_sock, POLLIN);
    }
}

void
nln_report(const struct nln *nln, void *change, int group)
{
    struct nln_notifier *notifier;

    if (change) {
        COVERAGE_INC(nln_changed);
    }

    LIST_FOR_EACH (notifier, node, &nln->all_notifiers) {
        if (!change || group == notifier->multicast_group) {
            notifier->cb(change, notifier->aux);
        }
    }
}
