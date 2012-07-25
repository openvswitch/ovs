/*
 * Copyright (c) 2011 Gaetano Catalli.
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

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>

#include "coverage.h"
#include "socket-util.h"
#include "poll-loop.h"
#include "vlog.h"
#include "rtbsd.h"

VLOG_DEFINE_THIS_MODULE(rtbsd);
COVERAGE_DEFINE(rtbsd_changed);

/* PF_ROUTE socket. */
static int notify_sock = -1;

/* All registered notifiers. */
static struct list all_notifiers = LIST_INITIALIZER(&all_notifiers);

static void rtbsd_report_change(const struct if_msghdr *);
static void rtbsd_report_notify_error(void);

/* Registers 'cb' to be called with auxiliary data 'aux' with network device
 * change notifications.  The notifier is stored in 'notifier', which the
 * caller must not modify or free.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
rtbsd_notifier_register(struct rtbsd_notifier *notifier,
                            rtbsd_notify_func *cb, void *aux)
{
    if (notify_sock < 0) {
        int error;
        notify_sock = socket(PF_ROUTE, SOCK_RAW, 0);
        if (notify_sock < 0) {
            VLOG_WARN("could not create PF_ROUTE socket: %s",
                      strerror(errno));
            return errno;
        }
        error = set_nonblocking(notify_sock);
        if (error) {
            VLOG_WARN("error set_nonblocking PF_ROUTE socket: %s",
                    strerror(error));
            return error;
        }
    } else {
        /* Catch up on notification work so that the new notifier won't
         * receive any stale notifications. XXX*/
        rtbsd_notifier_run();
    }

    list_push_back(&all_notifiers, &notifier->node);
    notifier->cb = cb;
    notifier->aux = aux;
    return 0;
}

/* Cancels notification on 'notifier', which must have previously been
 * registered with rtbsd_notifier_register(). */
void
rtbsd_notifier_unregister(struct rtbsd_notifier *notifier)
{
    list_remove(&notifier->node);
    if (list_is_empty(&all_notifiers)) {
        close(notify_sock);
        notify_sock = -1;
    }
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * netdev change events. */
void
rtbsd_notifier_run(void)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    struct if_msghdr msg;
    if (notify_sock < 0) {
        return;
    }

    for (;;) {
        int retval;

        msg.ifm_type = RTM_IFINFO;
        msg.ifm_version = RTM_VERSION; //XXX check if necessary

        /* read from PF_ROUTE socket */
        retval = read(notify_sock, (char *)&msg, sizeof(msg));
        if (retval >= 0) {
            /* received packet from PF_ROUTE socket
             * XXX check for bad packets */
            if (msg.ifm_type == RTM_IFINFO) {
                rtbsd_report_change(&msg);
            }
        } else if (errno == EAGAIN) {
            return;
        } else {
            if (errno == ENOBUFS) {
                VLOG_WARN_RL(&rl, "PF_ROUTE receive buffer overflowed");
            } else {
                VLOG_WARN_RL(&rl, "error reading PF_ROUTE socket: %s",
                             strerror(errno));
            }
            rtbsd_report_notify_error();
        }
    }
}

/* Causes poll_block() to wake up when network device change notifications are
 * ready. */
void
rtbsd_notifier_wait(void)
{
    if (notify_sock >= 0) {
        poll_fd_wait(notify_sock, POLLIN);
    }
}

static void
rtbsd_report_change(const struct if_msghdr *msg)
{
    struct rtbsd_notifier *notifier;
    struct rtbsd_change change;

    COVERAGE_INC(rtbsd_changed);

    change.msg_type = msg->ifm_type; //XXX
    change.if_index = msg->ifm_index;
    if_indextoname(msg->ifm_index, change.if_name);
    change.master_ifindex = 0; //XXX

    LIST_FOR_EACH (notifier, node, &all_notifiers) {
        notifier->cb(&change, notifier->aux);
    }
}

/* If an error occurs the notifiers' callbacks are called with NULL changes */
static void
rtbsd_report_notify_error(void)
{
    struct rtbsd_notifier *notifier;

    LIST_FOR_EACH (notifier, node, &all_notifiers) {
        notifier->cb(NULL, notifier->aux);
    }
}
