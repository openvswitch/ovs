/*
 * Copyright (c) 2009 Nicira Networks.
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

#include "netdev-linux.h"

#include <errno.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <poll.h>

#include "coverage.h"
#include "netlink.h"
#include "ofpbuf.h"

#define THIS_MODULE VLM_netdev_linux
#include "vlog.h"

/* rtnetlink socket. */
static struct nl_sock *rtnl_sock;

/* All registered notifiers. */
static struct list all_notifiers = LIST_INITIALIZER(&all_notifiers);

static void linux_netdev_report_change(const struct nlmsghdr *,
                                       const struct ifinfomsg *,
                                       struct nlattr *attrs[]);
static void linux_netdev_report_notify_error(int error);

int
linux_netdev_notifier_register(struct linux_netdev_notifier *notifier,
                               linux_netdev_notify_func *cb, void *aux)
{
    if (!rtnl_sock) {
        int error = nl_sock_create(NETLINK_ROUTE, RTNLGRP_LINK, 0, 0,
                                   &rtnl_sock);
        if (error) {
            VLOG_WARN("could not create rtnetlink socket: %s",
                      strerror(error));
            return error;
        }
    } else {
        /* Catch up on notification work so that the new notifier won't
         * receive any stale notifications. */
        linux_netdev_notifier_run();
    }

    list_push_back(&all_notifiers, &notifier->node);
    notifier->error = 0;
    notifier->cb = cb;
    notifier->aux = aux;
    return 0;
}

void
linux_netdev_notifier_unregister(struct linux_netdev_notifier *notifier)
{
    list_remove(&notifier->node);
    if (list_is_empty(&all_notifiers)) {
        nl_sock_destroy(rtnl_sock);
        rtnl_sock = NULL;
    }
}

int
linux_netdev_notifier_get_error(struct linux_netdev_notifier *notifier)
{
    int error = notifier->error;
    notifier->error = 0;
    return error;
}

int
linux_netdev_notifier_peek_error(const struct linux_netdev_notifier *notifier)
{
    return notifier->error;
}

static const struct nl_policy rtnlgrp_link_policy[] = {
    [IFLA_IFNAME] = { .type = NL_A_STRING },
    [IFLA_MASTER] = { .type = NL_A_U32, .optional = true },
};

void
linux_netdev_notifier_run(void)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (!rtnl_sock) {
        return;
    }

    for (;;) {
        struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
        struct ofpbuf *buf;
        int error;

        error = nl_sock_recv(rtnl_sock, &buf, false);
        if (!error) {
            if (nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                                rtnlgrp_link_policy,
                                attrs, ARRAY_SIZE(rtnlgrp_link_policy))) {
                struct ifinfomsg *ifinfo;

                ifinfo = (void *) ((char *) buf->data + NLMSG_HDRLEN);
                linux_netdev_report_change(buf->data, ifinfo, attrs);
            } else {
                VLOG_WARN_RL(&rl, "received bad rtnl message");
                linux_netdev_report_notify_error(ENOBUFS);
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
            linux_netdev_report_notify_error(error);
        }
    }
}

void
linux_netdev_notifier_wait(void)
{
    if (rtnl_sock) {
        nl_sock_wait(rtnl_sock, POLLIN);
    }
}

static void
linux_netdev_report_change(const struct nlmsghdr *nlmsg,
                           const struct ifinfomsg *ifinfo,
                           struct nlattr *attrs[])
{
    struct linux_netdev_notifier *notifier;
    struct linux_netdev_change change;

    COVERAGE_INC(linux_netdev_changed);

    change.nlmsg_type = nlmsg->nlmsg_type;
    change.ifi_index = ifinfo->ifi_index;
    change.ifname = nl_attr_get_string(attrs[IFLA_IFNAME]);
    change.master_ifindex = (attrs[IFLA_MASTER]
                             ? nl_attr_get_u32(attrs[IFLA_MASTER]) : 0);

    LIST_FOR_EACH (notifier, struct linux_netdev_notifier, node,
                   &all_notifiers) {
        if (!notifier->error) {
            notifier->cb(&change, notifier->aux);
        }
    }
}

static void
linux_netdev_report_notify_error(int error)
{
    struct linux_netdev_notifier *notifier;

    LIST_FOR_EACH (notifier, struct linux_netdev_notifier, node,
                   &all_notifiers) {
        if (error != ENOBUFS || !notifier->error) {
            notifier->error = error;
        }
    }
}
