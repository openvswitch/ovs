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

#include "rtnetlink-route.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "netlink.h"
#include "ofpbuf.h"
#include "rtnetlink.h"

static struct rtnetlink *rtn = NULL;
static struct rtnetlink_route_change rtn_change;

/* Parses a rtnetlink message 'buf' into 'change'.  If 'buf' is unparseable,
 * leaves 'change' untouched and returns false.  Otherwise, populates 'change'
 * and returns true. */
bool
rtnetlink_route_parse(struct ofpbuf *buf,
                      struct rtnetlink_route_change *change)
{
    bool parsed;

    static const struct nl_policy policy[] = {
        [RTA_DST] = { .type = NL_A_U32, .optional = true  },
        [RTA_OIF] = { .type = NL_A_U32, .optional = false },
    };

    static struct nlattr *attrs[ARRAY_SIZE(policy)];

    parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                             policy, attrs, ARRAY_SIZE(policy));

    if (parsed) {
        const struct nlmsghdr *nlmsg;
        const struct rtmsg *rtm;

        nlmsg = buf->data;
        rtm = (const struct rtmsg *) ((const char *) buf->data + NLMSG_HDRLEN);

        if (rtm->rtm_family != AF_INET) {
            return false;
        }

        change->nlmsg_type  = nlmsg->nlmsg_type;
        change->rtm_dst_len = rtm->rtm_dst_len;
        change->rta_oif     = nl_attr_get_u32(attrs[RTA_OIF]);
        change->rta_dst     = (attrs[RTA_DST]
                               ? ntohl(nl_attr_get_be32(attrs[RTA_DST]))
                               : 0);
    }

    return parsed;
}

/* Registers 'cb' to be called with auxiliary data 'aux' with route change
 * notifications.  The notifier is stored in 'notifier', which callers must
 * not modify or free.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
rtnetlink_route_notifier_register(struct rtnetlink_notifier *notifier,
                                 rtnetlink_route_notify_func *cb, void *aux)
{
    rtnetlink_parse_func *pf = (rtnetlink_parse_func *) rtnetlink_route_parse;
    rtnetlink_notify_func *nf = (rtnetlink_notify_func *) cb;

    if (!rtn) {
        rtn = rtnetlink_create(RTNLGRP_IPV4_ROUTE, pf, &rtn_change);
    }

    return rtnetlink_notifier_register(rtn, notifier, nf, aux);
}

/* Cancels notification on 'notifier', which must have previously been
 * registered with rtnetlink_route_notifier_register(). */
void
rtnetlink_route_notifier_unregister(struct rtnetlink_notifier *notifier)
{
    rtnetlink_notifier_unregister(rtn, notifier);
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * address change events. */
void
rtnetlink_route_notifier_run(void)
{
    if (rtn) {
        rtnetlink_notifier_run(rtn);
    }
}

/* Causes poll_block() to wake up when address change notifications are ready.
 */
void
rtnetlink_route_notifier_wait(void)
{
    if (rtn) {
        rtnetlink_notifier_wait(rtn);
    }
}
