/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stddef.h>
#include <linux/rtnetlink.h>
#include "netlink.h"
#include "netlink-socket.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

static const struct nl_policy rtnlgrp_link_policy[] = {
    [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
    [IFLA_MASTER] = { .type = NL_A_U32, .optional = true },
};

int
main(int argc OVS_UNUSED, char *argv[])
{
    uint64_t buf_stub[4096 / 64];
    struct nl_sock *sock;
    struct ofpbuf buf;
    int error;

    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_DBG);

    error = nl_sock_create(NETLINK_ROUTE, &sock);
    if (error) {
        ovs_fatal(error, "could not create rtnetlink socket");
    }

    error = nl_sock_join_mcgroup(sock, RTNLGRP_LINK);
    if (error) {
        ovs_fatal(error, "could not join RTNLGRP_LINK multicast group");
    }

    ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
    for (;;) {
        error = nl_sock_recv(sock, &buf, false);
        if (error == EAGAIN) {
            /* Nothing to do. */
        } else if (error == ENOBUFS) {
            ovs_error(0, "network monitor socket overflowed");
        } else if (error) {
            ovs_fatal(error, "error on network monitor socket");
        } else {
            struct iff_flag {
                unsigned int flag;
                const char *name;
            };

            static const struct iff_flag flags[] = {
                { IFF_UP, "UP", },
                { IFF_BROADCAST, "BROADCAST", },
                { IFF_DEBUG, "DEBUG", },
                { IFF_LOOPBACK, "LOOPBACK", },
                { IFF_POINTOPOINT, "POINTOPOINT", },
                { IFF_NOTRAILERS, "NOTRAILERS", },
                { IFF_RUNNING, "RUNNING", },
                { IFF_NOARP, "NOARP", },
                { IFF_PROMISC, "PROMISC", },
                { IFF_ALLMULTI, "ALLMULTI", },
                { IFF_MASTER, "MASTER", },
                { IFF_SLAVE, "SLAVE", },
                { IFF_MULTICAST, "MULTICAST", },
                { IFF_PORTSEL, "PORTSEL", },
                { IFF_AUTOMEDIA, "AUTOMEDIA", },
                { IFF_DYNAMIC, "DYNAMIC", },
            };

            struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
            struct nlmsghdr *nlh;
            struct ifinfomsg *iim;
            int i;

            nlh = ofpbuf_at(&buf, 0, NLMSG_HDRLEN);
            iim = ofpbuf_at(&buf, NLMSG_HDRLEN, sizeof *iim);
            if (!iim) {
                ovs_error(0, "received bad rtnl message (no ifinfomsg)");
                continue;
            }

            if (!nl_policy_parse(&buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                                 rtnlgrp_link_policy,
                                 attrs, ARRAY_SIZE(rtnlgrp_link_policy))) {
                ovs_error(0, "received bad rtnl message (policy)");
                continue;
            }
            printf("netdev %s changed (%s):\n",
                   nl_attr_get_string(attrs[IFLA_IFNAME]),
                   (nlh->nlmsg_type == RTM_NEWLINK ? "RTM_NEWLINK"
                    : nlh->nlmsg_type == RTM_DELLINK ? "RTM_DELLINK"
                    : nlh->nlmsg_type == RTM_GETLINK ? "RTM_GETLINK"
                    : nlh->nlmsg_type == RTM_SETLINK ? "RTM_SETLINK"
                    : "other"));
            printf("\tflags:");
            for (i = 0; i < ARRAY_SIZE(flags); i++) {
                if (iim->ifi_flags & flags[i].flag) {
                    printf(" %s", flags[i].name);
                }
            }
            printf("\n");
            if (attrs[IFLA_MASTER]) {
                uint32_t idx = nl_attr_get_u32(attrs[IFLA_MASTER]);
                char ifname[IFNAMSIZ];
                if (!if_indextoname(idx, ifname)) {
                    strcpy(ifname, "unknown");
                }
                printf("\tmaster=%"PRIu32" (%s)\n", idx, ifname);
            }
        }

        nl_sock_wait(sock, POLLIN);
        poll_block();
    }
}

