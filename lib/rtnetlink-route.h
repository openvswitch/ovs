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

#ifndef RTNETLINK_ROUTE_H
#define RTNETLINK_ROUTE_H 1

#include <stdbool.h>
#include <stdint.h>

struct ofpbuf;
struct rtnetlink_notifier;

/* A digested version of a route message sent down by the kernel to indicate
 * that a route has changed. */
struct rtnetlink_route_change {
    /* Copied from struct nlmsghdr. */
    int nlmsg_type;               /* e.g. RTM_NEWROUTE, RTM_DELROUTE. */

    /* Copied from struct rtmsg. */
    unsigned char rtm_dst_len;

    /* Extracted from Netlink attributes. */
    uint32_t rta_dst; /* Destination in host byte order. 0 if missing. */
    int rta_oif;      /* Output interface index. */
};

/* Function called to report that a route has changed.  'change' describes
 * the specific change.  It may be null, in which case the function must assume
 * everything has changed.  'aux' is as specified in the call to
 * rtnetlink_route_notifier_register(). */
typedef
void rtnetlink_route_notify_func(const struct rtnetlink_route_change *change,
                                 void *aux);

bool rtnetlink_route_parse(struct ofpbuf *, struct rtnetlink_route_change *);
int rtnetlink_route_notifier_register(struct rtnetlink_notifier *,
                                     rtnetlink_route_notify_func *, void *aux);
void rtnetlink_route_notifier_unregister(struct rtnetlink_notifier *);
void rtnetlink_route_notifier_run(void);
void rtnetlink_route_notifier_wait(void);

#endif /* rtnetlink-route.h */
