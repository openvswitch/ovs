/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include <linux/openvswitch.h>
#include <stdlib.h>
#include <string.h>

#include "netlink.h"
#include "ofpbuf.h"
#include "odp-util.h"
#include "packets.h"
#include "unaligned.h"
#include "util.h"

static void
odp_eth_set_addrs(struct ofpbuf *packet, const struct ovs_key_ethernet *eth_key)
{
    struct eth_header *eh = packet->l2;

    memcpy(eh->eth_src, eth_key->eth_src, sizeof eh->eth_src);
    memcpy(eh->eth_dst, eth_key->eth_dst, sizeof eh->eth_dst);
}

static void
odp_set_tunnel_action(const struct nlattr *a, struct flow_tnl *tun_key)
{
    enum odp_key_fitness fitness;

    fitness = odp_tun_key_from_attr(a, tun_key);
    ovs_assert(fitness != ODP_FIT_ERROR);
}

static void
set_arp(struct ofpbuf *packet, const struct ovs_key_arp *arp_key)
{
    struct arp_eth_header *arp = packet->l3;

    arp->ar_op = arp_key->arp_op;
    memcpy(arp->ar_sha, arp_key->arp_sha, ETH_ADDR_LEN);
    put_16aligned_be32(&arp->ar_spa, arp_key->arp_sip);
    memcpy(arp->ar_tha, arp_key->arp_tha, ETH_ADDR_LEN);
    put_16aligned_be32(&arp->ar_tpa, arp_key->arp_tip);
}

static void
odp_execute_set_action(struct ofpbuf *packet, const struct nlattr *a,
                       struct flow *flow)
{
    enum ovs_key_attr type = nl_attr_type(a);
    const struct ovs_key_ipv4 *ipv4_key;
    const struct ovs_key_ipv6 *ipv6_key;
    const struct ovs_key_tcp *tcp_key;
    const struct ovs_key_udp *udp_key;
    const struct ovs_key_sctp *sctp_key;

    switch (type) {
    case OVS_KEY_ATTR_PRIORITY:
        flow->skb_priority = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_TUNNEL:
        odp_set_tunnel_action(a, &flow->tunnel);
        break;

    case OVS_KEY_ATTR_SKB_MARK:
        flow->pkt_mark = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_ETHERNET:
        odp_eth_set_addrs(packet,
                          nl_attr_get_unspec(a, sizeof(struct ovs_key_ethernet)));
        break;

    case OVS_KEY_ATTR_IPV4:
        ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
        packet_set_ipv4(packet, ipv4_key->ipv4_src, ipv4_key->ipv4_dst,
                        ipv4_key->ipv4_tos, ipv4_key->ipv4_ttl);
        break;

    case OVS_KEY_ATTR_IPV6:
        ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));
        packet_set_ipv6(packet, ipv6_key->ipv6_proto, ipv6_key->ipv6_src,
                        ipv6_key->ipv6_dst, ipv6_key->ipv6_tclass,
                        ipv6_key->ipv6_label, ipv6_key->ipv6_hlimit);
        break;

    case OVS_KEY_ATTR_TCP:
        tcp_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_tcp));
        packet_set_tcp_port(packet, tcp_key->tcp_src, tcp_key->tcp_dst);
        break;

    case OVS_KEY_ATTR_UDP:
        udp_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_udp));
        packet_set_udp_port(packet, udp_key->udp_src, udp_key->udp_dst);
        break;

    case OVS_KEY_ATTR_SCTP:
        sctp_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_sctp));
        packet_set_sctp_port(packet, sctp_key->sctp_src, sctp_key->sctp_dst);
        break;

    case OVS_KEY_ATTR_MPLS:
         set_mpls_lse(packet, nl_attr_get_be32(a));
         break;

    case OVS_KEY_ATTR_ARP:
        set_arp(packet, nl_attr_get_unspec(a, sizeof(struct ovs_key_arp)));
        break;

    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
    case OVS_KEY_ATTR_ND:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case __OVS_KEY_ATTR_MAX:
    default:
        OVS_NOT_REACHED();
    }
}

static void
odp_execute_actions__(void *dp, struct ofpbuf *packet, struct flow *key,
                      const struct nlattr *actions, size_t actions_len,
                      odp_output_cb output, odp_userspace_cb userspace,
                      bool more_actions);

static void
odp_execute_sample(void *dp, struct ofpbuf *packet, struct flow *key,
                   const struct nlattr *action, odp_output_cb output,
                   odp_userspace_cb userspace, bool more_actions)
{
    const struct nlattr *subactions = NULL;
    const struct nlattr *a;
    size_t left;

    NL_NESTED_FOR_EACH_UNSAFE (a, left, action) {
        int type = nl_attr_type(a);

        switch ((enum ovs_sample_attr) type) {
        case OVS_SAMPLE_ATTR_PROBABILITY:
            if (random_uint32() >= nl_attr_get_u32(a)) {
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

    odp_execute_actions__(dp, packet, key, nl_attr_get(subactions),
                          nl_attr_get_size(subactions), output, userspace,
                          more_actions);
}

static void
odp_execute_actions__(void *dp, struct ofpbuf *packet, struct flow *key,
                      const struct nlattr *actions, size_t actions_len,
                      odp_output_cb output, odp_userspace_cb userspace,
                      bool more_actions)
{
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);

        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_OUTPUT:
            if (output) {
                output(dp, packet, key, u32_to_odp(nl_attr_get_u32(a)));
            }
            break;

        case OVS_ACTION_ATTR_USERSPACE: {
            if (userspace) {
                /* Allow 'userspace' to steal the packet data if we do not
                 * need it any more. */
                bool steal = !more_actions && left <= NLA_ALIGN(a->nla_len);
                userspace(dp, packet, key, a, steal);
            }
            break;
        }

        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
            eth_push_vlan(packet, vlan->vlan_tci);
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN:
            eth_pop_vlan(packet);
            break;

        case OVS_ACTION_ATTR_PUSH_MPLS: {
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);
            push_mpls(packet, mpls->mpls_ethertype, mpls->mpls_lse);
            break;
         }

        case OVS_ACTION_ATTR_POP_MPLS:
            pop_mpls(packet, nl_attr_get_be16(a));
            break;

        case OVS_ACTION_ATTR_SET:
            odp_execute_set_action(packet, nl_attr_get(a), key);
            break;

        case OVS_ACTION_ATTR_SAMPLE:
            odp_execute_sample(dp, packet, key, a, output, userspace,
                               more_actions || left > NLA_ALIGN(a->nla_len));
            break;

        case OVS_ACTION_ATTR_UNSPEC:
        case __OVS_ACTION_ATTR_MAX:
            OVS_NOT_REACHED();
        }
    }
}

void
odp_execute_actions(void *dp, struct ofpbuf *packet, struct flow *key,
                    const struct nlattr *actions, size_t actions_len,
                    odp_output_cb output, odp_userspace_cb userspace)
{
    odp_execute_actions__(dp, packet, key, actions, actions_len, output,
                          userspace, false);
}
