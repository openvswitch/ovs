/*
 * Copyright (c) 2009 Nicira, Inc.
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

#ifndef RTNETLINK_LINK_H
#define RTNETLINK_LINK_H 1

#include <stdbool.h>
#include <stdint.h>
#include <linux/if_ether.h>

struct ofpbuf;
struct nln_notifier;

/* These functions are Linux specific, so they should be used directly only by
 * Linux-specific code. */

/* A digested version of an rtnetlink_link message sent down by the kernel to
 * indicate that a network device has been created, destroyed or changed.  */
struct rtnetlink_link_change {
    /* Copied from struct nlmsghdr. */
    int nlmsg_type;             /* e.g. RTM_NEWLINK, RTM_DELLINK. */

    /* Copied from struct ifinfomsg. */
    int ifi_index;              /* Index of network device. */

    /* Extracted from Netlink attributes. */
    const char *ifname;         /* Name of network device. */
    int master_ifindex;         /* Ifindex of datapath master (0 if none). */
    int mtu;                    /* Current MTU. */
    uint8_t addr[ETH_ALEN];
    unsigned int ifi_flags;     /* Flags of network device. */
};

/* Function called to report that a netdev has changed.  'change' describes the
 * specific change.  It may be null if the buffer of change information
 * overflowed, in which case the function must assume that every device may
 * have changed.  'aux' is as specified in the call to
 * rtnetlink_link_notifier_register().  */
typedef
void rtnetlink_link_notify_func(const struct rtnetlink_link_change *change,
                                void *aux);

bool rtnetlink_link_parse(struct ofpbuf *buf,
                          struct rtnetlink_link_change *change);
struct nln_notifier *
rtnetlink_link_notifier_create(rtnetlink_link_notify_func *, void *aux);
void rtnetlink_link_notifier_destroy(struct nln_notifier *);
void rtnetlink_link_run(void);
void rtnetlink_link_wait(void);
#endif /* rtnetlink-link.h */
