/*
 * Copyright (c) 2011, 2013 Gaetano Catalli.
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

#include "rtbsd.h"

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>

#include "coverage.h"
#include "socket-util.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(rtbsd);
COVERAGE_DEFINE(rtbsd_changed);

static struct ovs_mutex rtbsd_mutex = OVS_MUTEX_INITIALIZER;

/* PF_ROUTE socket. */
static int notify_sock = -1;

/* All registered notifiers. */
static struct ovs_list all_notifiers = OVS_LIST_INITIALIZER(&all_notifiers);

static void rtbsd_report_change(const struct if_msghdr *)
    OVS_REQUIRES(rtbsd_mutex);
static void rtbsd_report_notify_error(void) OVS_REQUIRES(rtbsd_mutex);

/* Registers 'cb' to be called with auxiliary data 'aux' with network device
 * change notifications.  The notifier is stored in 'notifier', which the
 * caller must not modify or free.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
rtbsd_notifier_register(struct rtbsd_notifier *notifier,
                            rtbsd_notify_func *cb, void *aux)
    OVS_EXCLUDED(rtbsd_mutex)
{
    int error = 0;

    ovs_mutex_lock(&rtbsd_mutex);
    if (notify_sock < 0) {
        notify_sock = socket(PF_ROUTE, SOCK_RAW, 0);
        if (notify_sock < 0) {
            VLOG_WARN("could not create PF_ROUTE socket: %s",
                      ovs_strerror(errno));
            error = errno;
            goto out;
        }
        error = set_nonblocking(notify_sock);
        if (error) {
            VLOG_WARN("error set_nonblocking PF_ROUTE socket: %s",
                    ovs_strerror(error));
            goto out;
        }
    }

    ovs_list_push_back(&all_notifiers, &notifier->node);
    notifier->cb = cb;
    notifier->aux = aux;

out:
    ovs_mutex_unlock(&rtbsd_mutex);
    return error;
}

/* Cancels notification on 'notifier', which must have previously been
 * registered with rtbsd_notifier_register(). */
void
rtbsd_notifier_unregister(struct rtbsd_notifier *notifier)
    OVS_EXCLUDED(rtbsd_mutex)
{
    ovs_mutex_lock(&rtbsd_mutex);
    ovs_list_remove(&notifier->node);
    if (ovs_list_is_empty(&all_notifiers)) {
        close(notify_sock);
        notify_sock = -1;
    }
    ovs_mutex_unlock(&rtbsd_mutex);
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * netdev change events. */
void
rtbsd_notifier_run(void)
    OVS_EXCLUDED(rtbsd_mutex)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    struct if_msghdr msg;

    ovs_mutex_lock(&rtbsd_mutex);
    if (notify_sock < 0) {
        ovs_mutex_unlock(&rtbsd_mutex);
        return;
    }

    for (;;) {
        int retval;

        msg.ifm_type = RTM_IFINFO;
        msg.ifm_version = RTM_VERSION; /* XXX Check if necessary. */

        /* read from PF_ROUTE socket */
        retval = read(notify_sock, (char *)&msg, sizeof(msg));
        if (retval >= 0) {
            /* received packet from PF_ROUTE socket
             * XXX check for bad packets */
            switch (msg.ifm_type) {
            case RTM_IFINFO:
            /* Since RTM_IFANNOUNCE messages are smaller than RTM_IFINFO
             * messages, the same buffer may be used. */
#ifndef __MACH__ /* OS X does not implement RTM_IFANNOUNCE */
            case RTM_IFANNOUNCE:
#endif
                rtbsd_report_change(&msg);
                break;
            default:
                break;
            }
        } else if (errno == EAGAIN) {
            ovs_mutex_unlock(&rtbsd_mutex);
            return;
        } else {
            if (errno == ENOBUFS) {
                VLOG_WARN_RL(&rl, "PF_ROUTE receive buffer overflowed");
            } else {
                VLOG_WARN_RL(&rl, "error reading PF_ROUTE socket: %s",
                             ovs_strerror(errno));
            }
            rtbsd_report_notify_error();
        }
    }
}

/* Causes poll_block() to wake up when network device change notifications are
 * ready. */
void
rtbsd_notifier_wait(void)
    OVS_EXCLUDED(rtbsd_mutex)
{
    ovs_mutex_lock(&rtbsd_mutex);
    if (notify_sock >= 0) {
        poll_fd_wait(notify_sock, POLLIN);
    }
    ovs_mutex_unlock(&rtbsd_mutex);
}

static void
rtbsd_report_change(const struct if_msghdr *msg)
    OVS_REQUIRES(rtbsd_mutex)
{
    struct rtbsd_notifier *notifier;
    struct rtbsd_change change;
#ifndef __MACH__
    const struct if_announcemsghdr *ahdr;
#endif

    COVERAGE_INC(rtbsd_changed);

    change.msg_type = msg->ifm_type; /* XXX */
    change.master_ifindex = 0; /* XXX */

    switch (msg->ifm_type) {
    case RTM_IFINFO:
        change.if_index = msg->ifm_index;
        if_indextoname(msg->ifm_index, change.if_name);
        break;
#ifndef __MACH__ /* OS X does not implement RTM_IFANNOUNCE */
    case RTM_IFANNOUNCE:
        ahdr = (const struct if_announcemsghdr *) msg;
        change.if_index = ahdr->ifan_index;
        strncpy(change.if_name, ahdr->ifan_name, IF_NAMESIZE);
        break;
#endif
    }

    LIST_FOR_EACH (notifier, node, &all_notifiers) {
        notifier->cb(&change, notifier->aux);
    }
}

/* If an error occurs the notifiers' callbacks are called with NULL changes */
static void
rtbsd_report_notify_error(void)
    OVS_REQUIRES(rtbsd_mutex)
{
    struct rtbsd_notifier *notifier;

    LIST_FOR_EACH (notifier, node, &all_notifiers) {
        notifier->cb(NULL, notifier->aux);
    }
}
