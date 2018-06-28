/*
 * Copyright (c) 2009, 2010, 2013, 2015, 2016 Nicira, Inc.
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

#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "netlink.h"
#include "netlink-notifier.h"
#include "openvswitch/ofpbuf.h"
#include "packets.h"

#if IFLA_INFO_MAX < 5
#define IFLA_INFO_SLAVE_KIND 4
#endif

static struct nln *nln = NULL;
static struct rtnetlink_change rtn_change;

/* Returns true if the given netlink msg type corresponds to RTNLGRP_LINK. */
bool
rtnetlink_type_is_rtnlgrp_link(uint16_t type)
{
    return type == RTM_NEWLINK || type == RTM_DELLINK;
}

/* Returns true if the given netlink msg type corresponds to
 * RTNLGRP_IPV4_IFADDR or RTNLGRP_IPV6_IFADDR. */
bool
rtnetlink_type_is_rtnlgrp_addr(uint16_t type)
{
    return type == RTM_NEWADDR || type == RTM_DELADDR;
}

/* Parses nested nlattr for link info. Returns false if unparseable, else
 * populates 'change' and returns true. */
static bool
rtnetlink_parse_link_info(const struct nlattr *nla,
                          struct rtnetlink_change *change)
{
    bool parsed = false;

    static const struct nl_policy linkinfo_policy[] = {
        [IFLA_INFO_KIND] = { .type = NL_A_STRING, .optional = true  },
        [IFLA_INFO_SLAVE_KIND] = { .type = NL_A_STRING, .optional = true  },
    };

    struct nlattr *linkinfo[ARRAY_SIZE(linkinfo_policy)];

    parsed = nl_parse_nested(nla, linkinfo_policy, linkinfo,
                             ARRAY_SIZE(linkinfo_policy));

    if (parsed) {
        change->master = (linkinfo[IFLA_INFO_KIND]
                          ? nl_attr_get_string(linkinfo[IFLA_INFO_KIND])
                          : NULL);
        change->slave = (linkinfo[IFLA_INFO_SLAVE_KIND]
                         ? nl_attr_get_string(linkinfo[IFLA_INFO_SLAVE_KIND])
                         : NULL);
    }

    return parsed;
}

/* Parses a rtnetlink message 'buf' into 'change'.  If 'buf' is unparseable,
 * leaves 'change' untouched and returns false.  Otherwise, populates 'change'
 * and returns true. */
bool
rtnetlink_parse(struct ofpbuf *buf, struct rtnetlink_change *change)
{
    const struct nlmsghdr *nlmsg = buf->data;
    bool parsed = false;

    if (rtnetlink_type_is_rtnlgrp_link(nlmsg->nlmsg_type)) {
        /* Policy for RTNLGRP_LINK messages.
         *
         * There are *many* more fields in these messages, but currently we
         * only care about these fields. */
        static const struct nl_policy policy[] = {
            [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
            [IFLA_MASTER] = { .type = NL_A_U32,    .optional = true },
            [IFLA_MTU]    = { .type = NL_A_U32,    .optional = true },
            [IFLA_ADDRESS] = { .type = NL_A_UNSPEC, .optional = true },
            [IFLA_LINKINFO] = { .type = NL_A_NESTED, .optional = true },
        };

        struct nlattr *attrs[ARRAY_SIZE(policy)];

        parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                                 policy, attrs, ARRAY_SIZE(policy));

        if (parsed) {
            const struct ifinfomsg *ifinfo;

            ifinfo = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *ifinfo);

            change->nlmsg_type     = nlmsg->nlmsg_type;
            change->if_index       = ifinfo->ifi_index;
            change->ifname         = nl_attr_get_string(attrs[IFLA_IFNAME]);
            change->ifi_flags      = ifinfo->ifi_flags;
            change->master_ifindex = (attrs[IFLA_MASTER]
                                      ? nl_attr_get_u32(attrs[IFLA_MASTER])
                                      : 0);
            change->mtu            = (attrs[IFLA_MTU]
                                      ? nl_attr_get_u32(attrs[IFLA_MTU])
                                      : 0);

            if (attrs[IFLA_ADDRESS] &&
                nl_attr_get_size(attrs[IFLA_ADDRESS]) == ETH_ADDR_LEN) {
                memcpy(&change->mac, nl_attr_get(attrs[IFLA_ADDRESS]),
                       ETH_ADDR_LEN);
            } else {
                memset(&change->mac, 0, ETH_ADDR_LEN);
            }

            if (attrs[IFLA_LINKINFO]) {
                parsed = rtnetlink_parse_link_info(attrs[IFLA_LINKINFO],
                                                   change);
            } else {
                change->master = NULL;
                change->slave = NULL;
            }
        }
    } else if (rtnetlink_type_is_rtnlgrp_addr(nlmsg->nlmsg_type)) {
        /* Policy for RTNLGRP_IPV4_IFADDR/RTNLGRP_IPV6_IFADDR messages.
         *
         * There are *many* more fields in these messages, but currently we
         * only care about these fields. */
        static const struct nl_policy policy[] = {
            [IFA_LABEL] = { .type = NL_A_STRING, .optional = true },
        };

        struct nlattr *attrs[ARRAY_SIZE(policy)];

        parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifaddrmsg),
                                 policy, attrs, ARRAY_SIZE(policy));

        if (parsed) {
            const struct ifaddrmsg *ifaddr;

            ifaddr = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *ifaddr);

            change->nlmsg_type     = nlmsg->nlmsg_type;
            change->if_index       = ifaddr->ifa_index;
            change->ifname         = (attrs[IFA_LABEL]
                                      ? nl_attr_get_string(attrs[IFA_LABEL])
                                      : NULL);
        }
    }

    return parsed;
}

/* Return RTNLGRP_LINK on success, 0 on parse error. */
static int
rtnetlink_parse_cb(struct ofpbuf *buf, void *change)
{
    return rtnetlink_parse(buf, change) ? RTNLGRP_LINK : 0;
}

/* Registers 'cb' to be called with auxiliary data 'aux' with network device
 * change notifications.  The notifier is stored in 'notifier', which the
 * caller must not modify or free.
 *
 * This is probably not the function that you want.  You should probably be
 * using dpif_port_poll() or netdev_change_seq(), which unlike this function
 * are not Linux-specific.
 *
 * xxx Joins more multicast groups when needed.
 *
 * Returns an initialized nln_notifier if successful, NULL otherwise. */
struct nln_notifier *
rtnetlink_notifier_create(rtnetlink_notify_func *cb, void *aux)
{
    if (!nln) {
        nln = nln_create(NETLINK_ROUTE, rtnetlink_parse_cb, &rtn_change);
    }

    return nln_notifier_create(nln, RTNLGRP_LINK, (nln_notify_func *) cb, aux);
}

/* Destroys 'notifier', which must have previously been created with
 * rtnetlink_notifier_register(). */
void
rtnetlink_notifier_destroy(struct nln_notifier *notifier)
{
    nln_notifier_destroy(notifier);
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * netdev change events. */
void
rtnetlink_run(void)
{
    if (nln) {
        nln_run(nln);
    }
}

/* Causes poll_block() to wake up when network device change notifications are
 * ready. */
void
rtnetlink_wait(void)
{
    if (nln) {
        nln_wait(nln);
    }
}

/* Report RTNLGRP_LINK netdev change events. */
void
rtnetlink_report_link(void)
{
    if (nln) {
        nln_report(nln, NULL, RTNLGRP_LINK);
    }
}
