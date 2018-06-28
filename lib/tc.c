/*
 * Copyright (c) 2009-2017 Nicira, Inc.
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

#include <config.h>
#include "tc.h"

#include <errno.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_pedit.h>
#include <linux/tc_act/tc_tunnel_key.h>
#include <linux/tc_act/tc_vlan.h>
#include <linux/gen_stats.h>
#include <net/if.h>
#include <unistd.h>

#include "byte-order.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "timeval.h"
#include "unaligned.h"

#define MAX_PEDIT_OFFSETS 32

#ifndef TCM_IFINDEX_MAGIC_BLOCK
#define TCM_IFINDEX_MAGIC_BLOCK (0xFFFFFFFFU)
#endif

#if TCA_MAX < 14
#define TCA_INGRESS_BLOCK 13
#endif

VLOG_DEFINE_THIS_MODULE(tc);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

enum tc_offload_policy {
    TC_POLICY_NONE,
    TC_POLICY_SKIP_SW,
    TC_POLICY_SKIP_HW
};

static enum tc_offload_policy tc_policy = TC_POLICY_NONE;

struct tc_pedit_key_ex {
    enum pedit_header_type htype;
    enum pedit_cmd cmd;
};

struct flower_key_to_pedit {
    enum pedit_header_type htype;
    int offset;
    int flower_offset;
    int size;
};

static struct flower_key_to_pedit flower_pedit_map[] = {
    {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
        12,
        offsetof(struct tc_flower_key, ipv4.ipv4_src),
        MEMBER_SIZEOF(struct tc_flower_key, ipv4.ipv4_src)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
        16,
        offsetof(struct tc_flower_key, ipv4.ipv4_dst),
        MEMBER_SIZEOF(struct tc_flower_key, ipv4.ipv4_dst)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
        8,
        offsetof(struct tc_flower_key, ipv4.rewrite_ttl),
        MEMBER_SIZEOF(struct tc_flower_key, ipv4.rewrite_ttl)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP6,
        8,
        offsetof(struct tc_flower_key, ipv6.ipv6_src),
        MEMBER_SIZEOF(struct tc_flower_key, ipv6.ipv6_src)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP6,
        24,
        offsetof(struct tc_flower_key, ipv6.ipv6_dst),
        MEMBER_SIZEOF(struct tc_flower_key, ipv6.ipv6_dst)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
        6,
        offsetof(struct tc_flower_key, src_mac),
        MEMBER_SIZEOF(struct tc_flower_key, src_mac)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
        0,
        offsetof(struct tc_flower_key, dst_mac),
        MEMBER_SIZEOF(struct tc_flower_key, dst_mac)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
        12,
        offsetof(struct tc_flower_key, eth_type),
        MEMBER_SIZEOF(struct tc_flower_key, eth_type)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
        0,
        offsetof(struct tc_flower_key, tcp_src),
        MEMBER_SIZEOF(struct tc_flower_key, tcp_src)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
        2,
        offsetof(struct tc_flower_key, tcp_dst),
        MEMBER_SIZEOF(struct tc_flower_key, tcp_dst)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
        0,
        offsetof(struct tc_flower_key, udp_src),
        MEMBER_SIZEOF(struct tc_flower_key, udp_src)
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
        2,
        offsetof(struct tc_flower_key, udp_dst),
        MEMBER_SIZEOF(struct tc_flower_key, udp_dst)
    },
};

static inline int
csum_update_flag(struct tc_flower *flower,
                 enum pedit_header_type htype);

struct tcmsg *
tc_make_request(int ifindex, int type, unsigned int flags,
                struct ofpbuf *request)
{
    struct tcmsg *tcmsg;

    ofpbuf_init(request, 512);
    nl_msg_put_nlmsghdr(request, sizeof *tcmsg, type, NLM_F_REQUEST | flags);
    tcmsg = ofpbuf_put_zeros(request, sizeof *tcmsg);
    tcmsg->tcm_family = AF_UNSPEC;
    tcmsg->tcm_ifindex = ifindex;
    /* Caller should fill in tcmsg->tcm_handle. */
    /* Caller should fill in tcmsg->tcm_parent. */

    return tcmsg;
}

int
tc_transact(struct ofpbuf *request, struct ofpbuf **replyp)
{
    int error = nl_transact(NETLINK_ROUTE, request, replyp);
    ofpbuf_uninit(request);
    return error;
}

/* Adds or deletes a root ingress qdisc on device with specified ifindex.
 *
 * This function is equivalent to running the following when 'add' is true:
 *     /sbin/tc qdisc add dev <devname> handle ffff: ingress
 *
 * This function is equivalent to running the following when 'add' is false:
 *     /sbin/tc qdisc del dev <devname> handle ffff: ingress
 *
 * Where dev <devname> is the device with specified ifindex name.
 *
 * The configuration and stats may be seen with the following command:
 *     /sbin/tc -s qdisc show dev <devname>
 *
 * If block_id is greater than 0, then the ingress qdisc is added to a block.
 * In this case, it is equivalent to running (when 'add' is true):
 *     /sbin/tc qdisc add dev <devname> ingress_block <block_id> ingress
 *
 * Returns 0 if successful, otherwise a positive errno value.
 */
int
tc_add_del_ingress_qdisc(int ifindex, bool add, uint32_t block_id)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    int error;
    int type = add ? RTM_NEWQDISC : RTM_DELQDISC;
    int flags = add ? NLM_F_EXCL | NLM_F_CREATE : 0;

    tcmsg = tc_make_request(ifindex, type, flags, &request);
    tcmsg->tcm_handle = TC_H_MAKE(TC_H_INGRESS, 0);
    tcmsg->tcm_parent = TC_H_INGRESS;
    nl_msg_put_string(&request, TCA_KIND, "ingress");
    nl_msg_put_unspec(&request, TCA_OPTIONS, NULL, 0);
    if (block_id) {
        nl_msg_put_u32(&request, TCA_INGRESS_BLOCK, block_id);
    }

    error = tc_transact(&request, NULL);
    if (error) {
        /* If we're deleting the qdisc, don't worry about some of the
         * error conditions. */
        if (!add && (error == ENOENT || error == EINVAL)) {
            return 0;
        }
        return error;
    }

    return 0;
}

static const struct nl_policy tca_policy[] = {
    [TCA_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_OPTIONS] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_STATS] = { .type = NL_A_UNSPEC,
                    .min_len = sizeof(struct tc_stats), .optional = true, },
    [TCA_STATS2] = { .type = NL_A_NESTED, .optional = true, },
};

static const struct nl_policy tca_flower_policy[] = {
    [TCA_FLOWER_CLASSID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_INDEV] = { .type = NL_A_STRING, .max_len = IFNAMSIZ,
                           .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_TYPE] = { .type = NL_A_U16, .optional = false, },
    [TCA_FLOWER_FLAGS] = { .type = NL_A_U32, .optional = false, },
    [TCA_FLOWER_ACT] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_FLOWER_KEY_IP_PROTO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST] = {.type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_PRIO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ETH_TYPE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_ENC_KEY_ID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK] = { .type = NL_A_U32,
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST_MASK] = { .type = NL_A_U32,
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_DST] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                           .min_len = sizeof(struct in6_addr),
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                           .min_len = sizeof(struct in6_addr),
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_UDP_DST_PORT] = { .type = NL_A_U16,
                                          .optional = true, },
    [TCA_FLOWER_KEY_FLAGS] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_FLAGS_MASK] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_IP_TTL] = { .type = NL_A_U8,
                                .optional = true, },
    [TCA_FLOWER_KEY_IP_TTL_MASK] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_TCP_FLAGS] = { .type = NL_A_U16,
                                   .optional = true, },
    [TCA_FLOWER_KEY_TCP_FLAGS_MASK] = { .type = NL_A_U16,
                                        .optional = true, },
};

static void
nl_parse_flower_eth(struct nlattr **attrs, struct tc_flower *flower)
{
    const struct eth_addr *eth;

    if (attrs[TCA_FLOWER_KEY_ETH_SRC_MASK]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_SRC], ETH_ALEN);
        memcpy(&flower->key.src_mac, eth, sizeof flower->key.src_mac);

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_SRC_MASK], ETH_ALEN);
        memcpy(&flower->mask.src_mac, eth, sizeof flower->mask.src_mac);
    }
    if (attrs[TCA_FLOWER_KEY_ETH_DST_MASK]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_DST], ETH_ALEN);
        memcpy(&flower->key.dst_mac, eth, sizeof flower->key.dst_mac);

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_DST_MASK], ETH_ALEN);
        memcpy(&flower->mask.dst_mac, eth, sizeof flower->mask.dst_mac);
    }
}

static void
nl_parse_flower_vlan(struct nlattr **attrs, struct tc_flower *flower)
{
    if (flower->key.eth_type != htons(ETH_TYPE_VLAN)) {
        return;
    }

    flower->key.encap_eth_type =
        nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ETH_TYPE]);

    if (attrs[TCA_FLOWER_KEY_VLAN_ID]) {
        flower->key.vlan_id =
            nl_attr_get_u16(attrs[TCA_FLOWER_KEY_VLAN_ID]);
    }
    if (attrs[TCA_FLOWER_KEY_VLAN_PRIO]) {
        flower->key.vlan_prio =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_VLAN_PRIO]);
    }
}

static void
nl_parse_flower_tunnel(struct nlattr **attrs, struct tc_flower *flower)
{
    if (attrs[TCA_FLOWER_KEY_ENC_KEY_ID]) {
        ovs_be32 id = nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_KEY_ID]);

        flower->tunnel.id = be32_to_be64(id);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK]) {
        flower->tunnel.ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_IPV4_SRC]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV4_DST_MASK]) {
        flower->tunnel.ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_IPV4_DST]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK]) {
        flower->tunnel.ipv6.ipv6_src =
            nl_attr_get_in6_addr(attrs[TCA_FLOWER_KEY_ENC_IPV6_SRC]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV6_DST_MASK]) {
        flower->tunnel.ipv6.ipv6_dst =
            nl_attr_get_in6_addr(attrs[TCA_FLOWER_KEY_ENC_IPV6_DST]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_UDP_DST_PORT]) {
        flower->tunnel.tp_dst =
            nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ENC_UDP_DST_PORT]);
    }
}

static void
nl_parse_flower_ip(struct nlattr **attrs, struct tc_flower *flower) {
    uint8_t ip_proto = 0;
    struct tc_flower_key *key = &flower->key;
    struct tc_flower_key *mask = &flower->mask;

    if (attrs[TCA_FLOWER_KEY_IP_PROTO]) {
        ip_proto = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_PROTO]);
        key->ip_proto = ip_proto;
        mask->ip_proto = UINT8_MAX;
    }

    if (attrs[TCA_FLOWER_KEY_FLAGS_MASK]) {
        key->flags = ntohl(nl_attr_get_be32(attrs[TCA_FLOWER_KEY_FLAGS]));
        mask->flags =
                ntohl(nl_attr_get_be32(attrs[TCA_FLOWER_KEY_FLAGS_MASK]));
    }

    if (attrs[TCA_FLOWER_KEY_IPV4_SRC_MASK]) {
        key->ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_SRC]);
        mask->ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_SRC_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_IPV4_DST_MASK]) {
        key->ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_DST]);
        mask->ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_DST_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_IPV6_SRC_MASK]) {
        struct nlattr *attr = attrs[TCA_FLOWER_KEY_IPV6_SRC];
        struct nlattr *attr_mask = attrs[TCA_FLOWER_KEY_IPV6_SRC_MASK];

        key->ipv6.ipv6_src = nl_attr_get_in6_addr(attr);
        mask->ipv6.ipv6_src = nl_attr_get_in6_addr(attr_mask);
    }
    if (attrs[TCA_FLOWER_KEY_IPV6_DST_MASK]) {
        struct nlattr *attr = attrs[TCA_FLOWER_KEY_IPV6_DST];
        struct nlattr *attr_mask = attrs[TCA_FLOWER_KEY_IPV6_DST_MASK];

        key->ipv6.ipv6_dst = nl_attr_get_in6_addr(attr);
        mask->ipv6.ipv6_dst = nl_attr_get_in6_addr(attr_mask);
    }

    if (ip_proto == IPPROTO_TCP) {
        if (attrs[TCA_FLOWER_KEY_TCP_SRC_MASK]) {
            key->tcp_src =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_SRC]);
            mask->tcp_src =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_SRC_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_TCP_DST_MASK]) {
            key->tcp_dst =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_DST]);
            mask->tcp_dst =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_DST_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_TCP_FLAGS_MASK]) {
            key->tcp_flags =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_FLAGS]);
            mask->tcp_flags =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_FLAGS_MASK]);
        }
    } else if (ip_proto == IPPROTO_UDP) {
        if (attrs[TCA_FLOWER_KEY_UDP_SRC_MASK]) {
            key->udp_src = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_SRC]);
            mask->udp_src =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_SRC_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_UDP_DST_MASK]) {
            key->udp_dst = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_DST]);
            mask->udp_dst =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_DST_MASK]);
        }
    } else if (ip_proto == IPPROTO_SCTP) {
        if (attrs[TCA_FLOWER_KEY_SCTP_SRC_MASK]) {
            key->sctp_src = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_SCTP_SRC]);
            mask->sctp_src =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_SCTP_SRC_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_SCTP_DST_MASK]) {
            key->sctp_dst = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_SCTP_DST]);
            mask->sctp_dst =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_SCTP_DST_MASK]);
        }
    }

    if (attrs[TCA_FLOWER_KEY_IP_TTL_MASK]) {
        key->ip_ttl = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_TTL]);
        mask->ip_ttl = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_TTL_MASK]);
    }
}

static enum tc_offloaded_state
nl_get_flower_offloaded_state(struct nlattr **attrs)
{
    uint32_t flower_flags = 0;

    if (attrs[TCA_FLOWER_FLAGS]) {
        flower_flags = nl_attr_get_u32(attrs[TCA_FLOWER_FLAGS]);
        if (flower_flags & TCA_CLS_FLAGS_NOT_IN_HW) {
            return TC_OFFLOADED_STATE_NOT_IN_HW;
        } else if (flower_flags & TCA_CLS_FLAGS_IN_HW) {
            return TC_OFFLOADED_STATE_IN_HW;
        }
    }
    return TC_OFFLOADED_STATE_UNDEFINED;
}

static void
nl_parse_flower_flags(struct nlattr **attrs, struct tc_flower *flower)
{
    flower->offloaded_state = nl_get_flower_offloaded_state(attrs);
}

static const struct nl_policy pedit_policy[] = {
            [TCA_PEDIT_PARMS_EX] = { .type = NL_A_UNSPEC,
                                     .min_len = sizeof(struct tc_pedit),
                                     .optional = false, },
            [TCA_PEDIT_KEYS_EX]   = { .type = NL_A_NESTED,
                                      .optional = false, },
};

static int
nl_parse_act_pedit(struct nlattr *options, struct tc_flower *flower)
{
    struct tc_action *action;
    struct nlattr *pe_attrs[ARRAY_SIZE(pedit_policy)];
    const struct tc_pedit *pe;
    const struct tc_pedit_key *keys;
    const struct nlattr *nla, *keys_ex, *ex_type;
    const void *keys_attr;
    char *rewrite_key = (void *) &flower->rewrite.key;
    char *rewrite_mask = (void *) &flower->rewrite.mask;
    size_t keys_ex_size, left;
    int type, i = 0, err;

    if (!nl_parse_nested(options, pedit_policy, pe_attrs,
                         ARRAY_SIZE(pedit_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse pedit action options");
        return EPROTO;
    }

    pe = nl_attr_get_unspec(pe_attrs[TCA_PEDIT_PARMS_EX], sizeof *pe);
    keys = pe->keys;
    keys_attr = pe_attrs[TCA_PEDIT_KEYS_EX];
    keys_ex = nl_attr_get(keys_attr);
    keys_ex_size = nl_attr_get_size(keys_attr);

    NL_ATTR_FOR_EACH (nla, left, keys_ex, keys_ex_size) {
        if (i >= pe->nkeys) {
            break;
        }

        if (nl_attr_type(nla) != TCA_PEDIT_KEY_EX) {
            VLOG_ERR_RL(&error_rl, "unable to parse legacy pedit type: %d",
                        nl_attr_type(nla));
            return EOPNOTSUPP;
        }

        ex_type = nl_attr_find_nested(nla, TCA_PEDIT_KEY_EX_HTYPE);
        type = nl_attr_get_u16(ex_type);

        err = csum_update_flag(flower, type);
        if (err) {
            return err;
        }

        for (int j = 0; j < ARRAY_SIZE(flower_pedit_map); j++) {
            struct flower_key_to_pedit *m = &flower_pedit_map[j];
            int flower_off = m->flower_offset;
            int sz = m->size;
            int mf = m->offset;

            if (m->htype != type) {
               continue;
            }

            /* check overlap between current pedit key, which is always
             * 4 bytes (range [off, off + 3]), and a map entry in
             * flower_pedit_map (range [mf, mf + sz - 1]) */
            if ((keys->off >= mf && keys->off < mf + sz)
                || (keys->off + 3 >= mf && keys->off + 3 < mf + sz)) {
                int diff = flower_off + (keys->off - mf);
                uint32_t *dst = (void *) (rewrite_key + diff);
                uint32_t *dst_m = (void *) (rewrite_mask + diff);
                uint32_t mask = ~(keys->mask);
                uint32_t zero_bits;

                if (keys->off < mf) {
                    zero_bits = 8 * (mf - keys->off);
                    mask &= UINT32_MAX << zero_bits;
                } else if (keys->off + 4 > mf + m->size) {
                    zero_bits = 8 * (keys->off + 4 - mf - m->size);
                    mask &= UINT32_MAX >> zero_bits;
                }

                *dst_m |= mask;
                *dst |= keys->val & mask;
            }
        }

        keys++;
        i++;
    }

    action = &flower->actions[flower->action_count++];
    action->type = TC_ACT_PEDIT;

    return 0;
}

static const struct nl_policy tunnel_key_policy[] = {
    [TCA_TUNNEL_KEY_PARMS] = { .type = NL_A_UNSPEC,
                               .min_len = sizeof(struct tc_tunnel_key),
                               .optional = false, },
    [TCA_TUNNEL_KEY_ENC_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV4_DST] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV6_DST] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_TUNNEL_KEY_ENC_KEY_ID] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_DST_PORT] = { .type = NL_A_U16, .optional = true, },
};

static int
nl_parse_act_tunnel_key(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *tun_attrs[ARRAY_SIZE(tunnel_key_policy)];
    const struct nlattr *tun_parms;
    const struct tc_tunnel_key *tun;
    struct tc_action *action;

    if (!nl_parse_nested(options, tunnel_key_policy, tun_attrs,
                ARRAY_SIZE(tunnel_key_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse tunnel_key action options");
        return EPROTO;
    }

    tun_parms = tun_attrs[TCA_TUNNEL_KEY_PARMS];
    tun = nl_attr_get_unspec(tun_parms, sizeof *tun);
    if (tun->t_action == TCA_TUNNEL_KEY_ACT_SET) {
        struct nlattr *id = tun_attrs[TCA_TUNNEL_KEY_ENC_KEY_ID];
        struct nlattr *dst_port = tun_attrs[TCA_TUNNEL_KEY_ENC_DST_PORT];
        struct nlattr *ipv4_src = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV4_SRC];
        struct nlattr *ipv4_dst = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV4_DST];
        struct nlattr *ipv6_src = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV6_SRC];
        struct nlattr *ipv6_dst = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV6_DST];

        action = &flower->actions[flower->action_count++];
        action->type = TC_ACT_ENCAP;
        action->encap.ipv4.ipv4_src = ipv4_src ? nl_attr_get_be32(ipv4_src) : 0;
        action->encap.ipv4.ipv4_dst = ipv4_dst ? nl_attr_get_be32(ipv4_dst) : 0;
        if (ipv6_src) {
            action->encap.ipv6.ipv6_src = nl_attr_get_in6_addr(ipv6_src);
        }
        if (ipv6_dst) {
            action->encap.ipv6.ipv6_dst = nl_attr_get_in6_addr(ipv6_dst);
        }
        action->encap.id = id ? be32_to_be64(nl_attr_get_be32(id)) : 0;
        action->encap.tp_dst = dst_port ? nl_attr_get_be16(dst_port) : 0;
    } else if (tun->t_action == TCA_TUNNEL_KEY_ACT_RELEASE) {
        flower->tunnel.tunnel = true;
    } else {
        VLOG_ERR_RL(&error_rl, "unknown tunnel actions: %d, %d",
                    tun->action, tun->t_action);
        return EINVAL;
    }
    return 0;
}

static const struct nl_policy gact_policy[] = {
    [TCA_GACT_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_gact),
                         .optional = false, },
    [TCA_GACT_TM] = { .type = NL_A_UNSPEC,
                      .min_len = sizeof(struct tcf_t),
                      .optional = false, },
};

static int
get_user_hz(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int user_hz = 100;

    if (ovsthread_once_start(&once)) {
        user_hz = sysconf(_SC_CLK_TCK);
        ovsthread_once_done(&once);
    }

    return user_hz;
}

static void
nl_parse_tcf(const struct tcf_t *tm, struct tc_flower *flower)
{
    flower->lastused = time_msec() - (tm->lastuse * 1000 / get_user_hz());
}

static int
nl_parse_act_drop(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *gact_attrs[ARRAY_SIZE(gact_policy)];
    const struct tc_gact *p;
    struct nlattr *gact_parms;
    const struct tcf_t *tm;

    if (!nl_parse_nested(options, gact_policy, gact_attrs,
                         ARRAY_SIZE(gact_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse gact action options");
        return EPROTO;
    }

    gact_parms = gact_attrs[TCA_GACT_PARMS];
    p = nl_attr_get_unspec(gact_parms, sizeof *p);

    if (p->action != TC_ACT_SHOT) {
        VLOG_ERR_RL(&error_rl, "unknown gact action: %d", p->action);
        return EINVAL;
    }

    tm = nl_attr_get_unspec(gact_attrs[TCA_GACT_TM], sizeof *tm);
    nl_parse_tcf(tm, flower);

    return 0;
}

static const struct nl_policy mirred_policy[] = {
    [TCA_MIRRED_PARMS] = { .type = NL_A_UNSPEC,
                           .min_len = sizeof(struct tc_mirred),
                           .optional = false, },
    [TCA_MIRRED_TM] = { .type = NL_A_UNSPEC,
                        .min_len = sizeof(struct tcf_t),
                        .optional = false, },
};

static int
nl_parse_act_mirred(struct nlattr *options, struct tc_flower *flower)
{

    struct nlattr *mirred_attrs[ARRAY_SIZE(mirred_policy)];
    const struct tc_mirred *m;
    const struct nlattr *mirred_parms;
    const struct tcf_t *tm;
    struct nlattr *mirred_tm;
    struct tc_action *action;

    if (!nl_parse_nested(options, mirred_policy, mirred_attrs,
                         ARRAY_SIZE(mirred_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse mirred action options");
        return EPROTO;
    }

    mirred_parms = mirred_attrs[TCA_MIRRED_PARMS];
    m = nl_attr_get_unspec(mirred_parms, sizeof *m);

    if (m->eaction != TCA_EGRESS_REDIR && m->eaction != TCA_EGRESS_MIRROR) {
        VLOG_ERR_RL(&error_rl, "unknown mirred action: %d, %d, %d",
                    m->action, m->eaction, m->ifindex);
        return EINVAL;
    }

    action = &flower->actions[flower->action_count++];
    action->ifindex_out = m->ifindex;
    action->type = TC_ACT_OUTPUT;

    mirred_tm = mirred_attrs[TCA_MIRRED_TM];
    tm = nl_attr_get_unspec(mirred_tm, sizeof *tm);
    nl_parse_tcf(tm, flower);

    return 0;
}

static const struct nl_policy vlan_policy[] = {
    [TCA_VLAN_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_vlan),
                         .optional = false, },
    [TCA_VLAN_PUSH_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_VLAN_PUSH_VLAN_PROTOCOL] = { .type = NL_A_U16, .optional = true, },
    [TCA_VLAN_PUSH_VLAN_PRIORITY] = { .type = NL_A_U8, .optional = true, },
};

static int
nl_parse_act_vlan(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *vlan_attrs[ARRAY_SIZE(vlan_policy)];
    const struct tc_vlan *v;
    const struct nlattr *vlan_parms;
    struct tc_action *action;

    if (!nl_parse_nested(options, vlan_policy, vlan_attrs,
                         ARRAY_SIZE(vlan_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse vlan action options");
        return EPROTO;
    }

    action = &flower->actions[flower->action_count++];
    vlan_parms = vlan_attrs[TCA_VLAN_PARMS];
    v = nl_attr_get_unspec(vlan_parms, sizeof *v);
    if (v->v_action == TCA_VLAN_ACT_PUSH) {
        struct nlattr *vlan_id = vlan_attrs[TCA_VLAN_PUSH_VLAN_ID];
        struct nlattr *vlan_prio = vlan_attrs[TCA_VLAN_PUSH_VLAN_PRIORITY];

        action->vlan.vlan_push_id = nl_attr_get_u16(vlan_id);
        action->vlan.vlan_push_prio = vlan_prio ? nl_attr_get_u8(vlan_prio) : 0;
        action->type = TC_ACT_VLAN_PUSH;
    } else if (v->v_action == TCA_VLAN_ACT_POP) {
        action->type = TC_ACT_VLAN_POP;
    } else {
        VLOG_ERR_RL(&error_rl, "unknown vlan action: %d, %d",
                    v->action, v->v_action);
        return EINVAL;
    }
    return 0;
}

static const struct nl_policy csum_policy[] = {
    [TCA_CSUM_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_csum),
                         .optional = false, },
};

static int
nl_parse_act_csum(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *csum_attrs[ARRAY_SIZE(csum_policy)];
    const struct tc_csum *c;
    const struct nlattr *csum_parms;

    if (!nl_parse_nested(options, csum_policy, csum_attrs,
                         ARRAY_SIZE(csum_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse csum action options");
        return EPROTO;
    }

    csum_parms = csum_attrs[TCA_CSUM_PARMS];
    c = nl_attr_get_unspec(csum_parms, sizeof *c);

    /* sanity checks */
    if (c->update_flags != flower->csum_update_flags) {
        VLOG_WARN_RL(&error_rl,
                     "expected different act csum flags: 0x%x != 0x%x",
                     flower->csum_update_flags, c->update_flags);
        return EINVAL;
    }
    flower->csum_update_flags = 0; /* so we know csum was handled */

    if (flower->needs_full_ip_proto_mask
        && flower->mask.ip_proto != UINT8_MAX) {
        VLOG_WARN_RL(&error_rl, "expected full matching on flower ip_proto");
        return EINVAL;
    }

    return 0;
}

static const struct nl_policy act_policy[] = {
    [TCA_ACT_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_ACT_COOKIE] = { .type = NL_A_UNSPEC, .optional = true, },
    [TCA_ACT_OPTIONS] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_ACT_STATS] = { .type = NL_A_NESTED, .optional = false, },
};

static const struct nl_policy stats_policy[] = {
    [TCA_STATS_BASIC] = { .type = NL_A_UNSPEC,
                          .min_len = sizeof(struct gnet_stats_basic),
                          .optional = false, },
};

static int
nl_parse_single_action(struct nlattr *action, struct tc_flower *flower)
{
    struct nlattr *act_options;
    struct nlattr *act_stats;
    struct nlattr *act_cookie;
    const char *act_kind;
    struct nlattr *action_attrs[ARRAY_SIZE(act_policy)];
    struct nlattr *stats_attrs[ARRAY_SIZE(stats_policy)];
    struct ovs_flow_stats *stats = &flower->stats;
    const struct gnet_stats_basic *bs;
    int err = 0;

    if (!nl_parse_nested(action, act_policy, action_attrs,
                         ARRAY_SIZE(act_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse single action options");
        return EPROTO;
    }

    act_kind = nl_attr_get_string(action_attrs[TCA_ACT_KIND]);
    act_options = action_attrs[TCA_ACT_OPTIONS];
    act_cookie = action_attrs[TCA_ACT_COOKIE];

    if (!strcmp(act_kind, "gact")) {
        err = nl_parse_act_drop(act_options, flower);
    } else if (!strcmp(act_kind, "mirred")) {
        err = nl_parse_act_mirred(act_options, flower);
    } else if (!strcmp(act_kind, "vlan")) {
        err = nl_parse_act_vlan(act_options, flower);
    } else if (!strcmp(act_kind, "tunnel_key")) {
        err = nl_parse_act_tunnel_key(act_options, flower);
    } else if (!strcmp(act_kind, "pedit")) {
        err = nl_parse_act_pedit(act_options, flower);
    } else if (!strcmp(act_kind, "csum")) {
        nl_parse_act_csum(act_options, flower);
    } else {
        VLOG_ERR_RL(&error_rl, "unknown tc action kind: %s", act_kind);
        err = EINVAL;
    }

    if (err) {
        return err;
    }

    if (act_cookie) {
        flower->act_cookie.data = nl_attr_get(act_cookie);
        flower->act_cookie.len = nl_attr_get_size(act_cookie);
    }

    act_stats = action_attrs[TCA_ACT_STATS];

    if (!nl_parse_nested(act_stats, stats_policy, stats_attrs,
                         ARRAY_SIZE(stats_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse action stats policy");
        return EPROTO;
    }

    bs = nl_attr_get_unspec(stats_attrs[TCA_STATS_BASIC], sizeof *bs);
    put_32aligned_u64(&stats->n_packets, bs->packets);
    put_32aligned_u64(&stats->n_bytes, bs->bytes);

    return 0;
}

#define TCA_ACT_MIN_PRIO 1

static int
nl_parse_flower_actions(struct nlattr **attrs, struct tc_flower *flower)
{
    const struct nlattr *actions = attrs[TCA_FLOWER_ACT];
    static struct nl_policy actions_orders_policy[TCA_ACT_MAX_PRIO + 1] = {};
    struct nlattr *actions_orders[ARRAY_SIZE(actions_orders_policy)];
    const int max_size = ARRAY_SIZE(actions_orders_policy);

    for (int i = TCA_ACT_MIN_PRIO; i < max_size; i++) {
        actions_orders_policy[i].type = NL_A_NESTED;
        actions_orders_policy[i].optional = true;
    }

    if (!nl_parse_nested(actions, actions_orders_policy, actions_orders,
                         ARRAY_SIZE(actions_orders_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse flower order of actions");
        return EPROTO;
    }

    for (int i = TCA_ACT_MIN_PRIO; i < max_size; i++) {
        if (actions_orders[i]) {
            int err;

            if (flower->action_count >= TCA_ACT_MAX_PRIO) {
                VLOG_DBG_RL(&error_rl, "Can only support %d actions", flower->action_count);
                return EOPNOTSUPP;
            }
            err = nl_parse_single_action(actions_orders[i], flower);

            if (err) {
                return err;
            }
        }
    }

    if (flower->csum_update_flags) {
        VLOG_WARN_RL(&error_rl,
                     "expected act csum with flags: 0x%x",
                     flower->csum_update_flags);
        return EINVAL;
    }

    return 0;
}

static int
nl_parse_flower_options(struct nlattr *nl_options, struct tc_flower *flower)
{
    struct nlattr *attrs[ARRAY_SIZE(tca_flower_policy)];

    if (!nl_parse_nested(nl_options, tca_flower_policy,
                         attrs, ARRAY_SIZE(tca_flower_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse flower classifier options");
        return EPROTO;
    }

    nl_parse_flower_eth(attrs, flower);
    nl_parse_flower_vlan(attrs, flower);
    nl_parse_flower_ip(attrs, flower);
    nl_parse_flower_tunnel(attrs, flower);
    nl_parse_flower_flags(attrs, flower);
    return nl_parse_flower_actions(attrs, flower);
}

int
parse_netlink_to_tc_flower(struct ofpbuf *reply, struct tc_flower *flower)
{
    struct tcmsg *tc;
    struct nlattr *ta[ARRAY_SIZE(tca_policy)];
    const char *kind;

    if (NLMSG_HDRLEN + sizeof *tc > reply->size) {
        return EPROTO;
    }

    memset(flower, 0, sizeof *flower);

    tc = ofpbuf_at_assert(reply, NLMSG_HDRLEN, sizeof *tc);
    flower->handle = tc->tcm_handle;
    flower->key.eth_type = (OVS_FORCE ovs_be16) tc_get_minor(tc->tcm_info);
    flower->mask.eth_type = OVS_BE16_MAX;
    flower->prio = tc_get_major(tc->tcm_info);

    if (!flower->handle) {
        return EAGAIN;
    }

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + sizeof *tc,
                         tca_policy, ta, ARRAY_SIZE(ta))) {
        VLOG_ERR_RL(&error_rl, "failed to parse tca policy");
        return EPROTO;
    }

    kind = nl_attr_get_string(ta[TCA_KIND]);
    if (strcmp(kind, "flower")) {
        VLOG_DBG_ONCE("Unsupported filter: %s", kind);
        return EPROTO;
    }

    return nl_parse_flower_options(ta[TCA_OPTIONS], flower);
}

int
tc_dump_flower_start(int ifindex, struct nl_dump *dump, uint32_t block_id)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    int index;

    index = block_id ? TCM_IFINDEX_MAGIC_BLOCK : ifindex;
    tcmsg = tc_make_request(index, RTM_GETTFILTER, NLM_F_DUMP, &request);
    tcmsg->tcm_parent = block_id ? : TC_INGRESS_PARENT;
    tcmsg->tcm_info = TC_H_UNSPEC;
    tcmsg->tcm_handle = 0;

    nl_dump_start(dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    return 0;
}

int
tc_flush(int ifindex, uint32_t block_id)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    int index;

    index = block_id ? TCM_IFINDEX_MAGIC_BLOCK : ifindex;
    tcmsg = tc_make_request(index, RTM_DELTFILTER, NLM_F_ACK, &request);
    tcmsg->tcm_parent = block_id ? : TC_INGRESS_PARENT;
    tcmsg->tcm_info = TC_H_UNSPEC;

    return tc_transact(&request, NULL);
}

int
tc_del_filter(int ifindex, int prio, int handle, uint32_t block_id)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;
    int error;
    int index;

    index = block_id ? TCM_IFINDEX_MAGIC_BLOCK : ifindex;
    tcmsg = tc_make_request(index, RTM_DELTFILTER, NLM_F_ECHO, &request);
    tcmsg->tcm_parent = block_id ? : TC_INGRESS_PARENT;
    tcmsg->tcm_info = tc_make_handle(prio, 0);
    tcmsg->tcm_handle = handle;

    error = tc_transact(&request, &reply);
    if (!error) {
        ofpbuf_delete(reply);
    }
    return error;
}

int
tc_get_flower(int ifindex, int prio, int handle, struct tc_flower *flower,
              uint32_t block_id)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;
    int error;
    int index;

    index = block_id ? TCM_IFINDEX_MAGIC_BLOCK : ifindex;
    tcmsg = tc_make_request(index, RTM_GETTFILTER, NLM_F_ECHO, &request);
    tcmsg->tcm_parent = block_id ? : TC_INGRESS_PARENT;
    tcmsg->tcm_info = tc_make_handle(prio, 0);
    tcmsg->tcm_handle = handle;

    error = tc_transact(&request, &reply);
    if (error) {
        return error;
    }

    error = parse_netlink_to_tc_flower(reply, flower);
    ofpbuf_delete(reply);
    return error;
}

static int
tc_get_tc_cls_policy(enum tc_offload_policy policy)
{
    if (policy == TC_POLICY_SKIP_HW) {
        return TCA_CLS_FLAGS_SKIP_HW;
    } else if (policy == TC_POLICY_SKIP_SW) {
        return TCA_CLS_FLAGS_SKIP_SW;
    }

    return 0;
}

static void
nl_msg_put_act_csum(struct ofpbuf *request, uint32_t flags)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "csum");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_csum parm = { .action = TC_ACT_PIPE,
                                .update_flags = flags };

        nl_msg_put_unspec(request, TCA_CSUM_PARMS, &parm, sizeof parm);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_pedit(struct ofpbuf *request, struct tc_pedit *parm,
                     struct tc_pedit_key_ex *ex)
{
    size_t ksize = sizeof *parm + parm->nkeys * sizeof(struct tc_pedit_key);
    size_t offset, offset_keys_ex, offset_key;
    int i;

    nl_msg_put_string(request, TCA_ACT_KIND, "pedit");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        parm->action = TC_ACT_PIPE;

        nl_msg_put_unspec(request, TCA_PEDIT_PARMS_EX, parm, ksize);
        offset_keys_ex = nl_msg_start_nested(request, TCA_PEDIT_KEYS_EX);
        for (i = 0; i < parm->nkeys; i++, ex++) {
            offset_key = nl_msg_start_nested(request, TCA_PEDIT_KEY_EX);
            nl_msg_put_u16(request, TCA_PEDIT_KEY_EX_HTYPE, ex->htype);
            nl_msg_put_u16(request, TCA_PEDIT_KEY_EX_CMD, ex->cmd);
            nl_msg_end_nested(request, offset_key);
        }
        nl_msg_end_nested(request, offset_keys_ex);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_push_vlan(struct ofpbuf *request, uint16_t vid, uint8_t prio)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "vlan");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_vlan parm = { .action = TC_ACT_PIPE,
                                .v_action = TCA_VLAN_ACT_PUSH };

        nl_msg_put_unspec(request, TCA_VLAN_PARMS, &parm, sizeof parm);
        nl_msg_put_u16(request, TCA_VLAN_PUSH_VLAN_ID, vid);
        nl_msg_put_u8(request, TCA_VLAN_PUSH_VLAN_PRIORITY, prio);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_pop_vlan(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "vlan");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_vlan parm = { .action = TC_ACT_PIPE,
                                .v_action = TCA_VLAN_ACT_POP };

        nl_msg_put_unspec(request, TCA_VLAN_PARMS, &parm, sizeof parm);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_tunnel_key_release(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "tunnel_key");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_tunnel_key tun = { .action = TC_ACT_PIPE,
                                     .t_action = TCA_TUNNEL_KEY_ACT_RELEASE };

        nl_msg_put_unspec(request, TCA_TUNNEL_KEY_PARMS, &tun, sizeof tun);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_tunnel_key_set(struct ofpbuf *request, ovs_be64 id,
                                ovs_be32 ipv4_src, ovs_be32 ipv4_dst,
                                struct in6_addr *ipv6_src,
                                struct in6_addr *ipv6_dst,
                                ovs_be16 tp_dst)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "tunnel_key");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_tunnel_key tun = { .action = TC_ACT_PIPE,
                                     .t_action = TCA_TUNNEL_KEY_ACT_SET };

        nl_msg_put_unspec(request, TCA_TUNNEL_KEY_PARMS, &tun, sizeof tun);

        ovs_be32 id32 = be64_to_be32(id);
        nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_KEY_ID, id32);
        if (ipv4_dst) {
            nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_IPV4_SRC, ipv4_src);
            nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_IPV4_DST, ipv4_dst);
        } else if (!is_all_zeros(ipv6_dst, sizeof *ipv6_dst)) {
            nl_msg_put_in6_addr(request, TCA_TUNNEL_KEY_ENC_IPV6_DST,
                                ipv6_dst);
            nl_msg_put_in6_addr(request, TCA_TUNNEL_KEY_ENC_IPV6_SRC,
                                ipv6_src);
        }
        nl_msg_put_be16(request, TCA_TUNNEL_KEY_ENC_DST_PORT, tp_dst);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_drop(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "gact");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_gact p = { .action = TC_ACT_SHOT };

        nl_msg_put_unspec(request, TCA_GACT_PARMS, &p, sizeof p);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_mirred(struct ofpbuf *request, int ifindex, int action,
                      int eaction)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "mirred");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_mirred m = { .action = action,
                               .eaction = eaction,
                               .ifindex = ifindex };

        nl_msg_put_unspec(request, TCA_MIRRED_PARMS, &m, sizeof m);
    }
    nl_msg_end_nested(request, offset);
}

static inline void
nl_msg_put_act_cookie(struct ofpbuf *request, struct tc_cookie *ck) {
    if (ck->len) {
        nl_msg_put_unspec(request, TCA_ACT_COOKIE, ck->data, ck->len);
    }
}

/* Given flower, a key_to_pedit map entry, calculates the rest,
 * where:
 *
 * mask, data - pointers of where read the first word of flower->key/mask.
 * current_offset - which offset to use for the first pedit action.
 * cnt - max pedits actions to use.
 * first_word_mask/last_word_mask - the mask to use for the first/last read
 * (as we read entire words). */
static void
calc_offsets(struct tc_flower *flower, struct flower_key_to_pedit *m,
             int *cur_offset, int *cnt, uint32_t *last_word_mask,
             uint32_t *first_word_mask, uint32_t **mask, uint32_t **data)
{
    int start_offset, max_offset, total_size;
    int diff, right_zero_bits, left_zero_bits;
    char *rewrite_key = (void *) &flower->rewrite.key;
    char *rewrite_mask = (void *) &flower->rewrite.mask;

    max_offset = m->offset + m->size;
    start_offset = ROUND_DOWN(m->offset, 4);
    diff = m->offset - start_offset;
    total_size = max_offset - start_offset;
    right_zero_bits = 8 * (4 - (max_offset % 4));
    left_zero_bits = 8 * (m->offset - start_offset);

    *cur_offset = start_offset;
    *cnt = (total_size / 4) + (total_size % 4 ? 1 : 0);
    *last_word_mask = UINT32_MAX >> right_zero_bits;
    *first_word_mask = UINT32_MAX << left_zero_bits;
    *data = (void *) (rewrite_key + m->flower_offset - diff);
    *mask = (void *) (rewrite_mask + m->flower_offset - diff);
}

static inline int
csum_update_flag(struct tc_flower *flower,
                 enum pedit_header_type htype) {
    /* Explictily specifiy the csum flags so HW can return EOPNOTSUPP
     * if it doesn't support a checksum recalculation of some headers.
     * And since OVS allows a flow such as
     * eth(dst=<mac>),eth_type(0x0800) actions=set(ipv4(src=<new_ip>))
     * we need to force a more specific flow as this can, for example,
     * need a recalculation of icmp checksum if the packet that passes
     * is ICMPv6 and tcp checksum if its tcp. */

    switch (htype) {
    case TCA_PEDIT_KEY_EX_HDR_TYPE_IP4:
        flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_IPV4HDR;
        /* Fall through. */
    case TCA_PEDIT_KEY_EX_HDR_TYPE_IP6:
    case TCA_PEDIT_KEY_EX_HDR_TYPE_TCP:
    case TCA_PEDIT_KEY_EX_HDR_TYPE_UDP:
        if (flower->key.ip_proto == IPPROTO_TCP) {
            flower->needs_full_ip_proto_mask = true;
            flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_TCP;
        } else if (flower->key.ip_proto == IPPROTO_UDP) {
            flower->needs_full_ip_proto_mask = true;
            flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_UDP;
        } else if (flower->key.ip_proto == IPPROTO_ICMP) {
            flower->needs_full_ip_proto_mask = true;
        } else if (flower->key.ip_proto == IPPROTO_ICMPV6) {
            flower->needs_full_ip_proto_mask = true;
            flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_ICMP;
        } else {
            VLOG_WARN_RL(&error_rl,
                         "can't offload rewrite of IP/IPV6 with ip_proto: %d",
                         flower->key.ip_proto);
            break;
        }
        /* Fall through. */
    case TCA_PEDIT_KEY_EX_HDR_TYPE_ETH:
        return 0; /* success */

    case TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK:
    case __PEDIT_HDR_TYPE_MAX:
    default:
        break;
    }

    return EOPNOTSUPP;
}

static int
nl_msg_put_flower_rewrite_pedits(struct ofpbuf *request,
                                 struct tc_flower *flower)
{
    struct {
        struct tc_pedit sel;
        struct tc_pedit_key keys[MAX_PEDIT_OFFSETS];
        struct tc_pedit_key_ex keys_ex[MAX_PEDIT_OFFSETS];
    } sel = {
        .sel = {
            .nkeys = 0
        }
    };
    int i, j, err;

    for (i = 0; i < ARRAY_SIZE(flower_pedit_map); i++) {
        struct flower_key_to_pedit *m = &flower_pedit_map[i];
        struct tc_pedit_key *pedit_key = NULL;
        struct tc_pedit_key_ex *pedit_key_ex = NULL;
        uint32_t *mask, *data, first_word_mask, last_word_mask;
        int cnt = 0, cur_offset = 0;

        if (!m->size) {
            continue;
        }

        calc_offsets(flower, m, &cur_offset, &cnt, &last_word_mask,
                     &first_word_mask, &mask, &data);

        for (j = 0; j < cnt; j++,  mask++, data++, cur_offset += 4) {
            uint32_t mask_word = *mask;

            if (j == 0) {
                mask_word &= first_word_mask;
            }
            if (j == cnt - 1) {
                mask_word &= last_word_mask;
            }
            if (!mask_word) {
                continue;
            }
            if (sel.sel.nkeys == MAX_PEDIT_OFFSETS) {
                VLOG_WARN_RL(&error_rl, "reached too many pedit offsets: %d",
                             MAX_PEDIT_OFFSETS);
                return EOPNOTSUPP;
            }

            pedit_key = &sel.keys[sel.sel.nkeys];
            pedit_key_ex = &sel.keys_ex[sel.sel.nkeys];
            pedit_key_ex->cmd = TCA_PEDIT_KEY_EX_CMD_SET;
            pedit_key_ex->htype = m->htype;
            pedit_key->off = cur_offset;
            pedit_key->mask = ~mask_word;
            pedit_key->val = *data & mask_word;
            sel.sel.nkeys++;

            err = csum_update_flag(flower, m->htype);
            if (err) {
                return err;
            }

            if (flower->needs_full_ip_proto_mask) {
                flower->mask.ip_proto = UINT8_MAX;
            }
        }
    }
    nl_msg_put_act_pedit(request, &sel.sel, sel.keys_ex);

    return 0;
}

static int
nl_msg_put_flower_acts(struct ofpbuf *request, struct tc_flower *flower)
{
    size_t offset;
    size_t act_offset;
    uint16_t act_index = 1;
    struct tc_action *action;
    int i, ifindex = 0;

    offset = nl_msg_start_nested(request, TCA_FLOWER_ACT);
    {
        int error;

        if (flower->tunnel.tunnel) {
            act_offset = nl_msg_start_nested(request, act_index++);
            nl_msg_put_act_tunnel_key_release(request);
            nl_msg_end_nested(request, act_offset);
        }

        action = flower->actions;
        for (i = 0; i < flower->action_count; i++, action++) {
            switch (action->type) {
            case TC_ACT_PEDIT: {
                act_offset = nl_msg_start_nested(request, act_index++);
                error = nl_msg_put_flower_rewrite_pedits(request, flower);
                if (error) {
                    return error;
                }
                nl_msg_end_nested(request, act_offset);

                if (flower->csum_update_flags) {
                    act_offset = nl_msg_start_nested(request, act_index++);
                    nl_msg_put_act_csum(request, flower->csum_update_flags);
                    nl_msg_end_nested(request, act_offset);
                }
            }
            break;
            case TC_ACT_ENCAP: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_tunnel_key_set(request, action->encap.id,
                                              action->encap.ipv4.ipv4_src,
                                              action->encap.ipv4.ipv4_dst,
                                              &action->encap.ipv6.ipv6_src,
                                              &action->encap.ipv6.ipv6_dst,
                                              action->encap.tp_dst);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_VLAN_POP: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_pop_vlan(request);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_VLAN_PUSH: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_push_vlan(request,
                                         action->vlan.vlan_push_id,
                                         action->vlan.vlan_push_prio);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_OUTPUT: {
                ifindex = action->ifindex_out;
                if (ifindex < 1) {
                    VLOG_ERR_RL(&error_rl, "%s: invalid ifindex: %d, type: %d",
                                __func__, ifindex, action->type);
                    return EINVAL;
                }
                act_offset = nl_msg_start_nested(request, act_index++);
                if (i == flower->action_count - 1) {
                    nl_msg_put_act_mirred(request, ifindex, TC_ACT_STOLEN,
                                          TCA_EGRESS_REDIR);
                } else {
                    nl_msg_put_act_mirred(request, ifindex, TC_ACT_PIPE,
                                          TCA_EGRESS_MIRROR);
                }
                nl_msg_put_act_cookie(request, &flower->act_cookie);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            }
        }
    }
    if (!ifindex) {
        act_offset = nl_msg_start_nested(request, act_index++);
        nl_msg_put_act_drop(request);
        nl_msg_put_act_cookie(request, &flower->act_cookie);
        nl_msg_end_nested(request, act_offset);
    }
    nl_msg_end_nested(request, offset);

    return 0;
}

static void
nl_msg_put_masked_value(struct ofpbuf *request, uint16_t type,
                        uint16_t mask_type, const void *data,
                        const void *mask_data, size_t len)
{
    if (mask_type != TCA_FLOWER_UNSPEC) {
        if (is_all_zeros(mask_data, len)) {
            return;
        }
        nl_msg_put_unspec(request, mask_type, mask_data, len);
    }
    nl_msg_put_unspec(request, type, data, len);
}

static void
nl_msg_put_flower_tunnel(struct ofpbuf *request, struct tc_flower *flower)
{
    ovs_be32 ipv4_src = flower->tunnel.ipv4.ipv4_src;
    ovs_be32 ipv4_dst = flower->tunnel.ipv4.ipv4_dst;
    struct in6_addr *ipv6_src = &flower->tunnel.ipv6.ipv6_src;
    struct in6_addr *ipv6_dst = &flower->tunnel.ipv6.ipv6_dst;
    ovs_be16 tp_dst = flower->tunnel.tp_dst;
    ovs_be32 id = be64_to_be32(flower->tunnel.id);

    nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_KEY_ID, id);
    if (ipv4_dst) {
        nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_IPV4_SRC, ipv4_src);
        nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_IPV4_DST, ipv4_dst);
    } else if (!is_all_zeros(ipv6_dst, sizeof *ipv6_dst)) {
        nl_msg_put_in6_addr(request, TCA_FLOWER_KEY_ENC_IPV6_SRC, ipv6_src);
        nl_msg_put_in6_addr(request, TCA_FLOWER_KEY_ENC_IPV6_DST, ipv6_dst);
    }
    nl_msg_put_be16(request, TCA_FLOWER_KEY_ENC_UDP_DST_PORT, tp_dst);
}

#define FLOWER_PUT_MASKED_VALUE(member, type) \
    nl_msg_put_masked_value(request, type, type##_MASK, &flower->key.member, \
                            &flower->mask.member, sizeof flower->key.member)

static int
nl_msg_put_flower_options(struct ofpbuf *request, struct tc_flower *flower)
{

    uint16_t host_eth_type = ntohs(flower->key.eth_type);
    bool is_vlan = (host_eth_type == ETH_TYPE_VLAN);
    int err;

    /* need to parse acts first as some acts require changing the matching
     * see csum_update_flag()  */
    err  = nl_msg_put_flower_acts(request, flower);
    if (err) {
        return err;
    }

    if (is_vlan) {
        host_eth_type = ntohs(flower->key.encap_eth_type);
    }

    FLOWER_PUT_MASKED_VALUE(dst_mac, TCA_FLOWER_KEY_ETH_DST);
    FLOWER_PUT_MASKED_VALUE(src_mac, TCA_FLOWER_KEY_ETH_SRC);

    if (host_eth_type == ETH_P_IP || host_eth_type == ETH_P_IPV6) {
        if (flower->mask.ip_proto && flower->key.ip_proto) {
            nl_msg_put_u8(request, TCA_FLOWER_KEY_IP_PROTO,
                          flower->key.ip_proto);
        }

        if (flower->mask.flags) {
            nl_msg_put_be32(request, TCA_FLOWER_KEY_FLAGS,
                           htonl(flower->key.flags));
            nl_msg_put_be32(request, TCA_FLOWER_KEY_FLAGS_MASK,
                           htonl(flower->mask.flags));
        }

        if (flower->key.ip_proto == IPPROTO_UDP) {
            FLOWER_PUT_MASKED_VALUE(udp_src, TCA_FLOWER_KEY_UDP_SRC);
            FLOWER_PUT_MASKED_VALUE(udp_dst, TCA_FLOWER_KEY_UDP_DST);
        } else if (flower->key.ip_proto == IPPROTO_TCP) {
            FLOWER_PUT_MASKED_VALUE(tcp_src, TCA_FLOWER_KEY_TCP_SRC);
            FLOWER_PUT_MASKED_VALUE(tcp_dst, TCA_FLOWER_KEY_TCP_DST);
            FLOWER_PUT_MASKED_VALUE(tcp_flags, TCA_FLOWER_KEY_TCP_FLAGS);
        } else if (flower->key.ip_proto == IPPROTO_SCTP) {
            FLOWER_PUT_MASKED_VALUE(sctp_src, TCA_FLOWER_KEY_SCTP_SRC);
            FLOWER_PUT_MASKED_VALUE(sctp_dst, TCA_FLOWER_KEY_SCTP_DST);
        }
    }

    if (host_eth_type == ETH_P_IP) {
            FLOWER_PUT_MASKED_VALUE(ipv4.ipv4_src, TCA_FLOWER_KEY_IPV4_SRC);
            FLOWER_PUT_MASKED_VALUE(ipv4.ipv4_dst, TCA_FLOWER_KEY_IPV4_DST);
            FLOWER_PUT_MASKED_VALUE(ip_ttl, TCA_FLOWER_KEY_IP_TTL);
    } else if (host_eth_type == ETH_P_IPV6) {
            FLOWER_PUT_MASKED_VALUE(ipv6.ipv6_src, TCA_FLOWER_KEY_IPV6_SRC);
            FLOWER_PUT_MASKED_VALUE(ipv6.ipv6_dst, TCA_FLOWER_KEY_IPV6_DST);
    }

    nl_msg_put_be16(request, TCA_FLOWER_KEY_ETH_TYPE, flower->key.eth_type);

    if (is_vlan) {
        if (flower->key.vlan_id || flower->key.vlan_prio) {
            nl_msg_put_u16(request, TCA_FLOWER_KEY_VLAN_ID,
                           flower->key.vlan_id);
            nl_msg_put_u8(request, TCA_FLOWER_KEY_VLAN_PRIO,
                          flower->key.vlan_prio);
        }
        if (flower->key.encap_eth_type) {
            nl_msg_put_be16(request, TCA_FLOWER_KEY_VLAN_ETH_TYPE,
                            flower->key.encap_eth_type);
        }
    }

    nl_msg_put_u32(request, TCA_FLOWER_FLAGS, tc_get_tc_cls_policy(tc_policy));

    if (flower->tunnel.tunnel) {
        nl_msg_put_flower_tunnel(request, flower);
    }

    return 0;
}

int
tc_replace_flower(int ifindex, uint16_t prio, uint32_t handle,
                  struct tc_flower *flower, uint32_t block_id)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;
    int error = 0;
    size_t basic_offset;
    uint16_t eth_type = (OVS_FORCE uint16_t) flower->key.eth_type;
    int index;

    index = block_id ? TCM_IFINDEX_MAGIC_BLOCK : ifindex;
    tcmsg = tc_make_request(index, RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_ECHO,
                            &request);
    tcmsg->tcm_parent = block_id ? : TC_INGRESS_PARENT;
    tcmsg->tcm_info = tc_make_handle(prio, eth_type);
    tcmsg->tcm_handle = handle;

    nl_msg_put_string(&request, TCA_KIND, "flower");
    basic_offset = nl_msg_start_nested(&request, TCA_OPTIONS);
    {
        error = nl_msg_put_flower_options(&request, flower);

        if (error) {
            ofpbuf_uninit(&request);
            return error;
        }
    }
    nl_msg_end_nested(&request, basic_offset);

    error = tc_transact(&request, &reply);
    if (!error) {
        struct tcmsg *tc =
            ofpbuf_at_assert(reply, NLMSG_HDRLEN, sizeof *tc);

        flower->prio = tc_get_major(tc->tcm_info);
        flower->handle = tc->tcm_handle;
        ofpbuf_delete(reply);
    }

    return error;
}

void
tc_set_policy(const char *policy)
{
    if (!policy) {
        return;
    }

    if (!strcmp(policy, "skip_sw")) {
        tc_policy = TC_POLICY_SKIP_SW;
    } else if (!strcmp(policy, "skip_hw")) {
        tc_policy = TC_POLICY_SKIP_HW;
    } else if (!strcmp(policy, "none")) {
        tc_policy = TC_POLICY_NONE;
    } else {
        VLOG_WARN("tc: Invalid policy '%s'", policy);
        return;
    }

    VLOG_INFO("tc: Using policy '%s'", policy);
}
