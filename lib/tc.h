/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
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

#ifndef TC_H
#define TC_H 1

#include <sys/types.h>
#include <netinet/in.h> /* Must happen before linux/pkt_cls.h - Glibc #20215 */
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>

#include "netlink-socket.h"
#include "odp-netlink.h"
#include "openvswitch/ofpbuf.h"

/* For backwards compatability with older kernels */
#ifndef TC_H_CLSACT
#define TC_H_CLSACT    TC_H_INGRESS
#endif
#ifndef TC_H_MIN_INGRESS
#define TC_H_MIN_INGRESS       0xFFF2U
#endif

#define TC_INGRESS_PARENT TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)

#define TC_POLICY_DEFAULT "none"

/* Returns tc handle 'major':'minor'. */
static inline unsigned int
tc_make_handle(unsigned int major, unsigned int minor)
{
    return TC_H_MAKE(major << 16, minor);
}

/* Returns the major number from 'handle'. */
static inline unsigned int
tc_get_major(unsigned int handle)
{
    return TC_H_MAJ(handle) >> 16;
}

/* Returns the minor number from 'handle'. */
static inline unsigned int
tc_get_minor(unsigned int handle)
{
    return TC_H_MIN(handle);
}

struct tcmsg *tc_make_request(int ifindex, int type,
                              unsigned int flags, struct ofpbuf *);
int tc_transact(struct ofpbuf *request, struct ofpbuf **replyp);
int tc_add_del_ingress_qdisc(int ifindex, bool add);

struct tc_cookie {
    const void *data;
    size_t len;
};

struct tc_flower_key {
    ovs_be16 eth_type;
    uint8_t ip_proto;

    struct eth_addr dst_mac;
    struct eth_addr src_mac;

    ovs_be16 tcp_src;
    ovs_be16 tcp_dst;
    ovs_be16 tcp_flags;

    ovs_be16 udp_src;
    ovs_be16 udp_dst;

    ovs_be16 sctp_src;
    ovs_be16 sctp_dst;

    uint16_t vlan_id;
    uint8_t vlan_prio;

    ovs_be16 encap_eth_type;

    uint8_t flags;
    uint8_t ip_ttl;

    struct {
        ovs_be32 ipv4_src;
        ovs_be32 ipv4_dst;
        uint8_t rewrite_ttl;
    } ipv4;
    struct {
        struct in6_addr ipv6_src;
        struct in6_addr ipv6_dst;
    } ipv6;
};

struct tc_flower {
    uint32_t handle;
    uint32_t prio;

    struct tc_flower_key key;
    struct tc_flower_key mask;

    uint8_t vlan_pop;
    uint16_t vlan_push_id;
    uint8_t vlan_push_prio;

    int ifindex_out;

    struct ovs_flow_stats stats;
    uint64_t lastused;

    struct {
        bool rewrite;
        struct tc_flower_key key;
        struct tc_flower_key mask;
    } rewrite;

    uint32_t csum_update_flags;

    struct {
        bool set;
        ovs_be64 id;
        ovs_be16 tp_src;
        ovs_be16 tp_dst;
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_dst;
        } ipv4;
        struct {
            struct in6_addr ipv6_src;
            struct in6_addr ipv6_dst;
        } ipv6;
    } set;

    struct {
        bool tunnel;
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_dst;
        } ipv4;
        struct {
            struct in6_addr ipv6_src;
            struct in6_addr ipv6_dst;
        } ipv6;
        ovs_be64 id;
        ovs_be16 tp_src;
        ovs_be16 tp_dst;
    } tunnel;

    struct tc_cookie act_cookie;

    bool needs_full_ip_proto_mask;
};

/* assert that if we overflow with a masked write of uint32_t to the last byte
 * of flower.rewrite we overflow inside struct flower.
 * shouldn't happen unless someone moves rewrite to the end of flower */
BUILD_ASSERT_DECL(offsetof(struct tc_flower, rewrite)
                  + MEMBER_SIZEOF(struct tc_flower, rewrite)
                  + sizeof(uint32_t) - 2 < sizeof(struct tc_flower));

int tc_replace_flower(int ifindex, uint16_t prio, uint32_t handle,
                      struct tc_flower *flower);
int tc_del_filter(int ifindex, int prio, int handle);
int tc_get_flower(int ifindex, int prio, int handle,
                  struct tc_flower *flower);
int tc_flush(int ifindex);
int tc_dump_flower_start(int ifindex, struct nl_dump *dump);
int parse_netlink_to_tc_flower(struct ofpbuf *reply,
                               struct tc_flower *flower);
void tc_set_policy(const char *policy);

#endif /* tc.h */
