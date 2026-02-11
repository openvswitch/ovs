/*
 * Copyright (c) 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef ROUTE_TABLE_H
#define ROUTE_TABLE_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "openvswitch/list.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/types.h"

/*
 * route-table, system route table synchronization for Open vSwitch.
 *
 * Overview
 * ========
 *
 * The route-table module has two use cases:
 *
 * 1) Internal use by Open vSwitch which together with the ovs-router module
 *    implement route lookup for features such as flow based tunneling,
 *    userspace tunneling, and sFlow.
 *
 * 2) External use by projects such as Open Virtual Network (OVN), that use
 *    Open vSwitch as a compile time library.
 *
 * Typical External Usage
 * ======================
 *
 * static void
 * my_handle_msg(const struct route_table_msg *change, void *data)
 * {
 *     struct my_data *aux = data;
 *
 *     if (data) {
 *         aux->rta_dst = change->rd.rta_dst;
 *     }
 * }
 *
 * static void
 * my_route_table_dump(void)
 * {
 *     struct my_data *aux;
 *
 *     route_table_dump_one_table(RT_TABLE_MAIN, my_handle_msg, aux);
 * }
 *
 * static void
 * my_route_table_change(struct route_table_msg *change, void *aux OVS_UNUSED);
 * {
 *     my_handle_msg(change, NULL);
 *     route_data_destroy(&change->rd);
 * }
 *
 * static void
 * my_init(void)
 * {
 *     static struct nln_notifier *route6_notifier = NULL;
 *     static struct nln_notifier *route_notifier = NULL;
 *     static struct route_table_msg nln_change;
 *     static struct nln *nln = NULL;
 *
 *     nln = nln_create(NETLINK_ROUTE, route_table_parse, NULL);
 *
 *     route6_notifier =
 *        nln_notifier_create(nln, RTNLGRP_IPV6_ROUTE,
 *                            (nln_notify_func *) test_lib_route_table_change,
 *                            NULL);
 *
 *     route_notifier =
 *        nln_notifier_create(nln, RTNLGRP_IPV4_ROUTE,
 *                            (nln_notify_func *) test_lib_route_table_change,
 *                            NULL);
 * }
 *
 * Thread-safety
 * =============
 *
 * Assuming thread safe initialization of dependencies such as netlink socket,
 * netlink notifier and so on, the functions in this module are thread safe.
 */

/* Information about a next hop stored in a linked list with base in struct
 * route_data.  Please refer to comment in struct route_data for details. */
struct route_data_nexthop {
    struct ovs_list nexthop_node;

    sa_family_t family;
    struct in6_addr addr;
    char ifname[IFNAMSIZ]; /* Interface name. */
};

struct route_data {
    /* Routes can have multiple next hops per destination.
     *
     * Each next hop has its own set of attributes such as address family,
     * interface and IP address.
     *
     * When retrieving information about a route from the kernel, in the case
     * of multiple next hops, information is provided as nested attributes.
     *
     * A linked list with struct route_data_nexthop entries is used to store
     * this information as we parse each attribute.
     *
     * For the common case of one next hop, the nexthops list will contain a
     * single entry pointing to the struct route_data primary_next_hop__
     * element.
     *
     * Any dynamically allocated list elements MUST be freed with a call to the
     * route_data_destroy function. */
    struct ovs_list nexthops;
    struct route_data_nexthop primary_next_hop__;

    /* Copied from struct rtmsg. */
    unsigned char rtm_dst_len;
    unsigned char rtm_protocol;
    bool rtn_local;

    /* Extracted from Netlink attributes. */
    struct in6_addr rta_dst;     /* 0 if missing. */
    struct in6_addr rta_prefsrc; /* 0 if missing. */
    uint32_t rta_mark;           /* 0 if missing. */
    uint32_t rta_table_id;       /* 0 if missing. */
    uint32_t rta_priority;       /* 0 if missing. */
};

struct rule_data {
    bool invert;
    uint32_t prio;
    uint8_t src_len;
    struct in6_addr from_addr;
    uint32_t lookup_table;
    bool ipv4;
};

/* A digested version of a route message sent down by the kernel to indicate
 * that a route or a rule has changed. */
struct route_table_msg {
    bool relevant;        /* Should this message be processed? */
    uint16_t nlmsg_type;  /* e.g. RTM_NEWROUTE, RTM_DELROUTE, RTM_NEWRULE,
                           * RTM_DELRULE. */
    union {               /* Data parsed from this message, depending on
                           * nlmsg_type. */
        struct route_data rd;
        struct rule_data rud;
    };
};

uint64_t route_table_get_change_seq(void);
void route_table_init(void);
void route_table_run(void);
void route_table_wait(void);
bool route_table_fallback_lookup(const struct in6_addr *ip6_dst,
                                 char name[],
                                 struct in6_addr *gw6);

typedef void route_table_handle_msg_callback(const struct route_table_msg *,
                                             void *aux, uint32_t table);

bool route_table_dump_one_table(uint32_t id, sa_family_t family,
                                route_table_handle_msg_callback *,
                                void *aux);
int route_table_parse(struct ofpbuf *, void *change);
void route_data_destroy(struct route_data *);
#endif /* route-table.h */
