/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
 * Copyright (c) 2013 Simon Horman
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
#include "odp-execute.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>

#include "dp-packet.h"
#include "dpif.h"
#include "netlink.h"
#include "odp-netlink.h"
#include "odp-util.h"
#include "packets.h"
#include "flow.h"
#include "unaligned.h"
#include "util.h"

/* Masked copy of an ethernet address. 'src' is already properly masked. */
static void
ether_addr_copy_masked(struct eth_addr *dst, const struct eth_addr src,
                       const struct eth_addr mask)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(dst->be16); i++) {
        dst->be16[i] = src.be16[i] | (dst->be16[i] & ~mask.be16[i]);
    }
}

static void
odp_eth_set_addrs(struct dp_packet *packet, const struct ovs_key_ethernet *key,
                  const struct ovs_key_ethernet *mask)
{
    struct eth_header *eh = dp_packet_l2(packet);

    if (eh) {
        if (!mask) {
            eh->eth_src = key->eth_src;
            eh->eth_dst = key->eth_dst;
        } else {
            ether_addr_copy_masked(&eh->eth_src, key->eth_src, mask->eth_src);
            ether_addr_copy_masked(&eh->eth_dst, key->eth_dst, mask->eth_dst);
        }
    }
}

static void
odp_set_ipv4(struct dp_packet *packet, const struct ovs_key_ipv4 *key,
             const struct ovs_key_ipv4 *mask)
{
    struct ip_header *nh = dp_packet_l3(packet);

    packet_set_ipv4(
        packet,
        key->ipv4_src | (get_16aligned_be32(&nh->ip_src) & ~mask->ipv4_src),
        key->ipv4_dst | (get_16aligned_be32(&nh->ip_dst) & ~mask->ipv4_dst),
        key->ipv4_tos | (nh->ip_tos & ~mask->ipv4_tos),
        key->ipv4_ttl | (nh->ip_ttl & ~mask->ipv4_ttl));
}

static const ovs_be32 *
mask_ipv6_addr(const ovs_16aligned_be32 *old, const ovs_be32 *addr,
               const ovs_be32 *mask, ovs_be32 *masked)
{
    for (int i = 0; i < 4; i++) {
        masked[i] = addr[i] | (get_16aligned_be32(&old[i]) & ~mask[i]);
    }

    return masked;
}

static void
odp_set_ipv6(struct dp_packet *packet, const struct ovs_key_ipv6 *key,
             const struct ovs_key_ipv6 *mask)
{
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(packet);
    ovs_be32 sbuf[4], dbuf[4];
    uint8_t old_tc = ntohl(get_16aligned_be32(&nh->ip6_flow)) >> 20;
    ovs_be32 old_fl = get_16aligned_be32(&nh->ip6_flow) & htonl(0xfffff);

    packet_set_ipv6(
        packet,
        mask_ipv6_addr(nh->ip6_src.be32, key->ipv6_src, mask->ipv6_src, sbuf),
        mask_ipv6_addr(nh->ip6_dst.be32, key->ipv6_dst, mask->ipv6_dst, dbuf),
        key->ipv6_tclass | (old_tc & ~mask->ipv6_tclass),
        key->ipv6_label | (old_fl & ~mask->ipv6_label),
        key->ipv6_hlimit | (nh->ip6_hlim & ~mask->ipv6_hlimit));
}

static void
odp_set_tcp(struct dp_packet *packet, const struct ovs_key_tcp *key,
             const struct ovs_key_tcp *mask)
{
    struct tcp_header *th = dp_packet_l4(packet);

    if (OVS_LIKELY(th && dp_packet_get_tcp_payload(packet))) {
        packet_set_tcp_port(packet,
                            key->tcp_src | (th->tcp_src & ~mask->tcp_src),
                            key->tcp_dst | (th->tcp_dst & ~mask->tcp_dst));
    }
}

static void
odp_set_udp(struct dp_packet *packet, const struct ovs_key_udp *key,
             const struct ovs_key_udp *mask)
{
    struct udp_header *uh = dp_packet_l4(packet);

    if (OVS_LIKELY(uh && dp_packet_get_udp_payload(packet))) {
        packet_set_udp_port(packet,
                            key->udp_src | (uh->udp_src & ~mask->udp_src),
                            key->udp_dst | (uh->udp_dst & ~mask->udp_dst));
    }
}

static void
odp_set_sctp(struct dp_packet *packet, const struct ovs_key_sctp *key,
             const struct ovs_key_sctp *mask)
{
    struct sctp_header *sh = dp_packet_l4(packet);

    if (OVS_LIKELY(sh && dp_packet_get_sctp_payload(packet))) {
        packet_set_sctp_port(packet,
                             key->sctp_src | (sh->sctp_src & ~mask->sctp_src),
                             key->sctp_dst | (sh->sctp_dst & ~mask->sctp_dst));
    }
}

static void
odp_set_tunnel_action(const struct nlattr *a, struct flow_tnl *tun_key)
{
    enum odp_key_fitness fitness;

    fitness = odp_tun_key_from_attr(a, tun_key);
    ovs_assert(fitness != ODP_FIT_ERROR);
}

static void
set_arp(struct dp_packet *packet, const struct ovs_key_arp *key,
        const struct ovs_key_arp *mask)
{
    struct arp_eth_header *arp = dp_packet_l3(packet);

    if (!mask) {
        arp->ar_op = key->arp_op;
        arp->ar_sha = key->arp_sha;
        put_16aligned_be32(&arp->ar_spa, key->arp_sip);
        arp->ar_tha = key->arp_tha;
        put_16aligned_be32(&arp->ar_tpa, key->arp_tip);
    } else {
        ovs_be32 ar_spa = get_16aligned_be32(&arp->ar_spa);
        ovs_be32 ar_tpa = get_16aligned_be32(&arp->ar_tpa);

        arp->ar_op = key->arp_op | (arp->ar_op & ~mask->arp_op);
        ether_addr_copy_masked(&arp->ar_sha, key->arp_sha, mask->arp_sha);
        put_16aligned_be32(&arp->ar_spa,
                           key->arp_sip | (ar_spa & ~mask->arp_sip));
        ether_addr_copy_masked(&arp->ar_tha, key->arp_tha, mask->arp_tha);
        put_16aligned_be32(&arp->ar_tpa,
                           key->arp_tip | (ar_tpa & ~mask->arp_tip));
    }
}

static void
odp_set_nd(struct dp_packet *packet, const struct ovs_key_nd *key,
           const struct ovs_key_nd *mask)
{
    const struct ovs_nd_msg *ns = dp_packet_l4(packet);
    const struct ovs_nd_opt *nd_opt = dp_packet_get_nd_payload(packet);

    if (OVS_LIKELY(ns && nd_opt)) {
        int bytes_remain = dp_packet_l4_size(packet) - sizeof(*ns);
        ovs_be32 tgt_buf[4];
        struct eth_addr sll_buf = eth_addr_zero;
        struct eth_addr tll_buf = eth_addr_zero;

        while (bytes_remain >= ND_OPT_LEN && nd_opt->nd_opt_len != 0) {
            if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR
                && nd_opt->nd_opt_len == 1) {
                sll_buf = nd_opt->nd_opt_mac;
                ether_addr_copy_masked(&sll_buf, key->nd_sll, mask->nd_sll);

                /* A packet can only contain one SLL or TLL option */
                break;
            } else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR
                       && nd_opt->nd_opt_len == 1) {
                tll_buf = nd_opt->nd_opt_mac;
                ether_addr_copy_masked(&tll_buf, key->nd_tll, mask->nd_tll);

                /* A packet can only contain one SLL or TLL option */
                break;
            }

            nd_opt += nd_opt->nd_opt_len;
            bytes_remain -= nd_opt->nd_opt_len * ND_OPT_LEN;
        }

        packet_set_nd(packet,
                      mask_ipv6_addr(ns->target.be32,
                                     key->nd_target, mask->nd_target, tgt_buf),
                      sll_buf,
                      tll_buf);
    }
}

static void
odp_execute_set_action(struct dp_packet *packet, const struct nlattr *a)
{
    enum ovs_key_attr type = nl_attr_type(a);
    const struct ovs_key_ipv4 *ipv4_key;
    const struct ovs_key_ipv6 *ipv6_key;
    struct pkt_metadata *md = &packet->md;

    switch (type) {
    case OVS_KEY_ATTR_PRIORITY:
        md->skb_priority = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_TUNNEL:
        odp_set_tunnel_action(a, &md->tunnel);
        break;

    case OVS_KEY_ATTR_SKB_MARK:
        md->pkt_mark = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_ETHERNET:
        odp_eth_set_addrs(packet, nl_attr_get(a), NULL);
        break;

    case OVS_KEY_ATTR_IPV4:
        ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
        packet_set_ipv4(packet, ipv4_key->ipv4_src,
                        ipv4_key->ipv4_dst, ipv4_key->ipv4_tos,
                        ipv4_key->ipv4_ttl);
        break;

    case OVS_KEY_ATTR_IPV6:
        ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));
        packet_set_ipv6(packet, ipv6_key->ipv6_src, ipv6_key->ipv6_dst,
                        ipv6_key->ipv6_tclass, ipv6_key->ipv6_label,
                        ipv6_key->ipv6_hlimit);
        break;

    case OVS_KEY_ATTR_TCP:
        if (OVS_LIKELY(dp_packet_get_tcp_payload(packet))) {
            const struct ovs_key_tcp *tcp_key
                = nl_attr_get_unspec(a, sizeof(struct ovs_key_tcp));

            packet_set_tcp_port(packet, tcp_key->tcp_src,
                                tcp_key->tcp_dst);
        }
        break;

    case OVS_KEY_ATTR_UDP:
        if (OVS_LIKELY(dp_packet_get_udp_payload(packet))) {
            const struct ovs_key_udp *udp_key
                = nl_attr_get_unspec(a, sizeof(struct ovs_key_udp));

            packet_set_udp_port(packet, udp_key->udp_src,
                                udp_key->udp_dst);
        }
        break;

    case OVS_KEY_ATTR_SCTP:
        if (OVS_LIKELY(dp_packet_get_sctp_payload(packet))) {
            const struct ovs_key_sctp *sctp_key
                = nl_attr_get_unspec(a, sizeof(struct ovs_key_sctp));

            packet_set_sctp_port(packet, sctp_key->sctp_src,
                                 sctp_key->sctp_dst);
        }
        break;

    case OVS_KEY_ATTR_MPLS:
        set_mpls_lse(packet, nl_attr_get_be32(a));
        break;

    case OVS_KEY_ATTR_ARP:
        set_arp(packet, nl_attr_get(a), NULL);
        break;

    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
        if (OVS_LIKELY(dp_packet_get_icmp_payload(packet))) {
            const struct ovs_key_icmp *icmp_key
                = nl_attr_get_unspec(a, sizeof(struct ovs_key_icmp));

            packet_set_icmp(packet, icmp_key->icmp_type, icmp_key->icmp_code);
        }
        break;

    case OVS_KEY_ATTR_ND:
        if (OVS_LIKELY(dp_packet_get_nd_payload(packet))) {
            const struct ovs_key_nd *nd_key
                   = nl_attr_get_unspec(a, sizeof(struct ovs_key_nd));
            packet_set_nd(packet, nd_key->nd_target, nd_key->nd_sll,
                          nd_key->nd_tll);
        }
        break;

    case OVS_KEY_ATTR_DP_HASH:
        md->dp_hash = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_RECIRC_ID:
        md->recirc_id = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case __OVS_KEY_ATTR_MAX:
    default:
        OVS_NOT_REACHED();
    }
}

#define get_mask(a, type) ((const type *)(const void *)(a + 1) + 1)

static void
odp_execute_masked_set_action(struct dp_packet *packet,
                              const struct nlattr *a)
{
    struct pkt_metadata *md = &packet->md;
    enum ovs_key_attr type = nl_attr_type(a);
    struct mpls_hdr *mh;

    switch (type) {
    case OVS_KEY_ATTR_PRIORITY:
        md->skb_priority = nl_attr_get_u32(a)
            | (md->skb_priority & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_SKB_MARK:
        md->pkt_mark = nl_attr_get_u32(a)
            | (md->pkt_mark & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_ETHERNET:
        odp_eth_set_addrs(packet, nl_attr_get(a),
                          get_mask(a, struct ovs_key_ethernet));
        break;

    case OVS_KEY_ATTR_IPV4:
        odp_set_ipv4(packet, nl_attr_get(a),
                     get_mask(a, struct ovs_key_ipv4));
        break;

    case OVS_KEY_ATTR_IPV6:
        odp_set_ipv6(packet, nl_attr_get(a),
                     get_mask(a, struct ovs_key_ipv6));
        break;

    case OVS_KEY_ATTR_TCP:
        odp_set_tcp(packet, nl_attr_get(a),
                    get_mask(a, struct ovs_key_tcp));
        break;

    case OVS_KEY_ATTR_UDP:
        odp_set_udp(packet, nl_attr_get(a),
                    get_mask(a, struct ovs_key_udp));
        break;

    case OVS_KEY_ATTR_SCTP:
        odp_set_sctp(packet, nl_attr_get(a),
                     get_mask(a, struct ovs_key_sctp));
        break;

    case OVS_KEY_ATTR_MPLS:
        mh = dp_packet_l2_5(packet);
        if (mh) {
            put_16aligned_be32(&mh->mpls_lse, nl_attr_get_be32(a)
                               | (get_16aligned_be32(&mh->mpls_lse)
                                  & ~*get_mask(a, ovs_be32)));
        }
        break;

    case OVS_KEY_ATTR_ARP:
        set_arp(packet, nl_attr_get(a),
                get_mask(a, struct ovs_key_arp));
        break;

    case OVS_KEY_ATTR_ND:
        odp_set_nd(packet, nl_attr_get(a),
                   get_mask(a, struct ovs_key_nd));
        break;

    case OVS_KEY_ATTR_DP_HASH:
        md->dp_hash = nl_attr_get_u32(a)
            | (md->dp_hash & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_RECIRC_ID:
        md->recirc_id = nl_attr_get_u32(a)
            | (md->recirc_id & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_TUNNEL:    /* Masked data not supported for tunnel. */
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case __OVS_KEY_ATTR_MAX:
    default:
        OVS_NOT_REACHED();
    }
}

static void
odp_execute_sample(void *dp, struct dp_packet *packet, bool steal,
                   const struct nlattr *action,
                   odp_execute_cb dp_execute_action)
{
    const struct nlattr *subactions = NULL;
    const struct nlattr *a;
    struct dp_packet_batch pb;
    size_t left;

    NL_NESTED_FOR_EACH_UNSAFE (a, left, action) {
        int type = nl_attr_type(a);

        switch ((enum ovs_sample_attr) type) {
        case OVS_SAMPLE_ATTR_PROBABILITY:
            if (random_uint32() >= nl_attr_get_u32(a)) {
                if (steal) {
                    dp_packet_delete(packet);
                }
                return;
            }
            break;

        case OVS_SAMPLE_ATTR_ACTIONS:
            subactions = a;
            break;

        case OVS_SAMPLE_ATTR_UNSPEC:
        case __OVS_SAMPLE_ATTR_MAX:
        default:
            OVS_NOT_REACHED();
        }
    }

    packet_batch_init_packet(&pb, packet);
    odp_execute_actions(dp, &pb, steal, nl_attr_get(subactions),
                        nl_attr_get_size(subactions), dp_execute_action);
}

static bool
requires_datapath_assistance(const struct nlattr *a)
{
    enum ovs_action_attr type = nl_attr_type(a);

    switch (type) {
        /* These only make sense in the context of a datapath. */
    case OVS_ACTION_ATTR_OUTPUT:
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
    case OVS_ACTION_ATTR_TUNNEL_POP:
    case OVS_ACTION_ATTR_USERSPACE:
    case OVS_ACTION_ATTR_RECIRC:
    case OVS_ACTION_ATTR_CT:
        return true;

    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_TRUNC:
        return false;

    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    return false;
}

void
odp_execute_actions(void *dp, struct dp_packet_batch *batch, bool steal,
                    const struct nlattr *actions, size_t actions_len,
                    odp_execute_cb dp_execute_action)
{
    struct dp_packet **packets = batch->packets;
    int cnt = batch->count;
    const struct nlattr *a;
    unsigned int left;
    int i;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        bool last_action = (left <= NLA_ALIGN(a->nla_len));

        if (requires_datapath_assistance(a)) {
            if (dp_execute_action) {
                /* Allow 'dp_execute_action' to steal the packet data if we do
                 * not need it any more. */
                bool may_steal = steal && last_action;

                dp_execute_action(dp, batch, a, may_steal);

                if (last_action) {
                    /* We do not need to free the packets. dp_execute_actions()
                     * has stolen them */
                    return;
                }
            }
            continue;
        }

        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_HASH: {
            const struct ovs_action_hash *hash_act = nl_attr_get(a);

            /* Calculate a hash value directly.  This might not match the
             * value computed by the datapath, but it is much less expensive,
             * and the current use case (bonding) does not require a strict
             * match to work properly. */
            if (hash_act->hash_alg == OVS_HASH_ALG_L4) {
                struct flow flow;
                uint32_t hash;

                for (i = 0; i < cnt; i++) {
                    flow_extract(packets[i], &flow);
                    hash = flow_hash_5tuple(&flow, hash_act->hash_basis);

                    packets[i]->md.dp_hash = hash;
                }
            } else {
                /* Assert on unknown hash algorithm.  */
                OVS_NOT_REACHED();
            }
            break;
        }

        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);

            for (i = 0; i < cnt; i++) {
                eth_push_vlan(packets[i], vlan->vlan_tpid, vlan->vlan_tci);
            }
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN:
            for (i = 0; i < cnt; i++) {
                eth_pop_vlan(packets[i]);
            }
            break;

        case OVS_ACTION_ATTR_PUSH_MPLS: {
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);

            for (i = 0; i < cnt; i++) {
                push_mpls(packets[i], mpls->mpls_ethertype, mpls->mpls_lse);
            }
            break;
         }

        case OVS_ACTION_ATTR_POP_MPLS:
            for (i = 0; i < cnt; i++) {
                pop_mpls(packets[i], nl_attr_get_be16(a));
            }
            break;

        case OVS_ACTION_ATTR_SET:
            for (i = 0; i < cnt; i++) {
                odp_execute_set_action(packets[i], nl_attr_get(a));
            }
            break;

        case OVS_ACTION_ATTR_SET_MASKED:
            for (i = 0; i < cnt; i++) {
                odp_execute_masked_set_action(packets[i], nl_attr_get(a));
            }
            break;

        case OVS_ACTION_ATTR_SAMPLE:
            for (i = 0; i < cnt; i++) {
                odp_execute_sample(dp, packets[i], steal && last_action, a,
                                   dp_execute_action);
            }

            if (last_action) {
                /* We do not need to free the packets. odp_execute_sample() has
                 * stolen them*/
                return;
            }
            break;

        case OVS_ACTION_ATTR_TRUNC: {
            const struct ovs_action_trunc *trunc =
                        nl_attr_get_unspec(a, sizeof *trunc);

            batch->trunc = true;
            for (i = 0; i < cnt; i++) {
                dp_packet_set_cutlen(packets[i], trunc->max_len);
            }
            break;
        }

        case OVS_ACTION_ATTR_OUTPUT:
        case OVS_ACTION_ATTR_TUNNEL_PUSH:
        case OVS_ACTION_ATTR_TUNNEL_POP:
        case OVS_ACTION_ATTR_USERSPACE:
        case OVS_ACTION_ATTR_RECIRC:
        case OVS_ACTION_ATTR_CT:
        case OVS_ACTION_ATTR_UNSPEC:
        case __OVS_ACTION_ATTR_MAX:
            OVS_NOT_REACHED();
        }
    }

    if (steal) {
        for (i = 0; i < cnt; i++) {
            dp_packet_delete(packets[i]);
        }
    }
}
