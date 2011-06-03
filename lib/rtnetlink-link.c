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

#include "rtnetlink-link.h"

#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "netlink.h"
#include "ofpbuf.h"
#include "rtnetlink.h"

static struct rtnetlink *rtn = NULL;
static struct rtnetlink_link_change rtn_change;

/* Parses a rtnetlink message 'buf' into 'change'.  If 'buf' is unparseable,
 * leaves 'change' untouched and returns false.  Otherwise, populates 'change'
 * and returns true. */
bool
rtnetlink_link_parse(struct ofpbuf *buf,
                     struct rtnetlink_link_change *change)
{
    bool parsed;

    /* Policy for RTNLGRP_LINK messages.
     *
     * There are *many* more fields in these messages, but currently we
     * only care about these fields. */
    static const struct nl_policy policy[] = {
        [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
        [IFLA_MASTER] = { .type = NL_A_U32,    .optional = true },
    };

    static struct nlattr *attrs[ARRAY_SIZE(policy)];

    parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                             policy, attrs, ARRAY_SIZE(policy));

    if (parsed) {
        const struct nlmsghdr *nlmsg;
        const struct ifinfomsg *ifinfo;

        nlmsg  = buf->data;
        ifinfo = ((const struct ifinfomsg *)
                  ((const char *) buf->data + NLMSG_HDRLEN));

        change->nlmsg_type     = nlmsg->nlmsg_type;
        change->ifi_index      = ifinfo->ifi_index;
        change->ifname         = nl_attr_get_string(attrs[IFLA_IFNAME]);
        change->master_ifindex = (attrs[IFLA_MASTER]
                                  ? nl_attr_get_u32(attrs[IFLA_MASTER])
                                  : 0);
    }

    return parsed;
}

static bool
rtnetlink_link_parse_cb(struct ofpbuf *buf, void *change)
{
    return rtnetlink_link_parse(buf, change);
}

/* Registers 'cb' to be called with auxiliary data 'aux' with network device
 * change notifications.  The notifier is stored in 'notifier', which the
 * caller must not modify or free.
 *
 * This is probably not the function that you want.  You should probably be
 * using dpif_port_poll() or netdev_change_seq(), which unlike this function
 * are not Linux-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
rtnetlink_link_notifier_register(struct rtnetlink_notifier *notifier,
                                 rtnetlink_link_notify_func *cb, void *aux)
{
    rtnetlink_notify_func *nf = (rtnetlink_notify_func *) cb;

    if (!rtn) {
        rtn = rtnetlink_create(RTNLGRP_LINK, rtnetlink_link_parse_cb,
                               &rtn_change);
    }

    return rtnetlink_notifier_register(rtn, notifier, nf, aux);
}

/* Cancels notification on 'notifier', which must have previously been
 * registered with rtnetlink_link_notifier_register(). */
void
rtnetlink_link_notifier_unregister(struct rtnetlink_notifier *notifier)
{
    rtnetlink_notifier_unregister(rtn, notifier);
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * netdev change events. */
void
rtnetlink_link_notifier_run(void)
{
    if (rtn) {
        rtnetlink_notifier_run(rtn);
    }
}

/* Causes poll_block() to wake up when network device change notifications are
 * ready. */
void
rtnetlink_link_notifier_wait(void)
{
    if (rtn) {
        rtnetlink_notifier_wait(rtn);
    }
}
