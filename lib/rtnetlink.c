/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>

#include "coverage.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(rtnetlink)

/* rtnetlink socket. */
static struct nl_sock *notify_sock;

/* All registered notifiers. */
static struct list all_notifiers = LIST_INITIALIZER(&all_notifiers);

static void rtnetlink_report_change(const struct nlmsghdr *,
                                    const struct ifinfomsg *,
                                    struct nlattr *attrs[]);
static void rtnetlink_report_notify_error(void);

/* Registers 'cb' to be called with auxiliary data 'aux' with network device
 * change notifications.  The notifier is stored in 'notifier', which the
 * caller must not modify or free.
 *
 * This is probably not the function that you want.  You should probably be
 * using dpif_port_poll() or netdev_monitor_create(), which unlike this
 * function are not Linux-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
rtnetlink_notifier_register(struct rtnetlink_notifier *notifier,
                            rtnetlink_notify_func *cb, void *aux)
{
    if (!notify_sock) {
        int error = nl_sock_create(NETLINK_ROUTE, RTNLGRP_LINK, 0, 0,
                                   &notify_sock);
        if (error) {
            VLOG_WARN("could not create rtnetlink socket: %s",
                      strerror(error));
            return error;
        }
    } else {
        /* Catch up on notification work so that the new notifier won't
         * receive any stale notifications. */
        rtnetlink_notifier_run();
    }

    list_push_back(&all_notifiers, &notifier->node);
    notifier->cb = cb;
    notifier->aux = aux;
    return 0;
}

/* Cancels notification on 'notifier', which must have previously been
 * registered with rtnetlink_notifier_register(). */
void
rtnetlink_notifier_unregister(struct rtnetlink_notifier *notifier)
{
    list_remove(&notifier->node);
    if (list_is_empty(&all_notifiers)) {
        nl_sock_destroy(notify_sock);
        notify_sock = NULL;
    }
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * netdev change events. */
void
rtnetlink_notifier_run(void)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (!notify_sock) {
        return;
    }

    for (;;) {
        /* Policy for RTNLGRP_LINK messages.
         *
         * There are *many* more fields in these messages, but currently we
         * only care about these fields. */
        static const struct nl_policy rtnetlink_policy[] = {
            [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
            [IFLA_MASTER] = { .type = NL_A_U32, .optional = true },
        };

        struct nlattr *attrs[ARRAY_SIZE(rtnetlink_policy)];
        struct ofpbuf *buf;
        int error;

        error = nl_sock_recv(notify_sock, &buf, false);
        if (!error) {
            if (nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                                rtnetlink_policy,
                                attrs, ARRAY_SIZE(rtnetlink_policy))) {
                struct ifinfomsg *ifinfo;

                ifinfo = (void *) ((char *) buf->data + NLMSG_HDRLEN);
                rtnetlink_report_change(buf->data, ifinfo, attrs);
            } else {
                VLOG_WARN_RL(&rl, "received bad rtnl message");
                rtnetlink_report_notify_error();
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
            rtnetlink_report_notify_error();
        }
    }
}

/* Causes poll_block() to wake up when network device change notifications are
 * ready. */
void
rtnetlink_notifier_wait(void)
{
    if (notify_sock) {
        nl_sock_wait(notify_sock, POLLIN);
    }
}

static void
rtnetlink_report_change(const struct nlmsghdr *nlmsg,
                           const struct ifinfomsg *ifinfo,
                           struct nlattr *attrs[])
{
    struct rtnetlink_notifier *notifier;
    struct rtnetlink_change change;

    COVERAGE_INC(rtnetlink_changed);

    change.nlmsg_type = nlmsg->nlmsg_type;
    change.ifi_index = ifinfo->ifi_index;
    change.ifname = nl_attr_get_string(attrs[IFLA_IFNAME]);
    change.master_ifindex = (attrs[IFLA_MASTER]
                             ? nl_attr_get_u32(attrs[IFLA_MASTER]) : 0);

    LIST_FOR_EACH (notifier, struct rtnetlink_notifier, node,
                   &all_notifiers) {
        notifier->cb(&change, notifier->aux);
    }
}

static void
rtnetlink_report_notify_error(void)
{
    struct rtnetlink_notifier *notifier;

    LIST_FOR_EACH (notifier, struct rtnetlink_notifier, node,
                   &all_notifiers) {
        notifier->cb(NULL, notifier->aux);
    }
}
