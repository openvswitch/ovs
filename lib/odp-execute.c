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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
#include "csum.h"

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
    struct eth_header *eh = dp_packet_eth(packet);

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
    ovs_be32 ip_src_nh;
    ovs_be32 ip_dst_nh;
    ovs_be32 new_ip_src;
    ovs_be32 new_ip_dst;
    uint8_t new_tos;
    uint8_t new_ttl;

    if (mask->ipv4_src) {
        ip_src_nh = get_16aligned_be32(&nh->ip_src);
        new_ip_src = key->ipv4_src | (ip_src_nh & ~mask->ipv4_src);

        if (ip_src_nh != new_ip_src) {
            packet_set_ipv4_addr(packet, &nh->ip_src, new_ip_src);
        }
    }

    if (mask->ipv4_dst) {
        ip_dst_nh = get_16aligned_be32(&nh->ip_dst);
        new_ip_dst = key->ipv4_dst | (ip_dst_nh & ~mask->ipv4_dst);

        if (ip_dst_nh != new_ip_dst) {
            packet_set_ipv4_addr(packet, &nh->ip_dst, new_ip_dst);
        }
    }

    if (mask->ipv4_tos) {
        new_tos = key->ipv4_tos | (nh->ip_tos & ~mask->ipv4_tos);

        if (nh->ip_tos != new_tos) {
            nh->ip_csum = recalc_csum16(nh->ip_csum,
                                        htons((uint16_t) nh->ip_tos),
                                        htons((uint16_t) new_tos));
            nh->ip_tos = new_tos;
        }
    }

    if (OVS_LIKELY(mask->ipv4_ttl)) {
        new_ttl = key->ipv4_ttl | (nh->ip_ttl & ~mask->ipv4_ttl);

        if (OVS_LIKELY(nh->ip_ttl != new_ttl)) {
            nh->ip_csum = recalc_csum16(nh->ip_csum, htons(nh->ip_ttl << 8),
                                        htons(new_ttl << 8));
            nh->ip_ttl = new_ttl;
        }
    }
}

static struct in6_addr *
mask_ipv6_addr(const ovs_16aligned_be32 *old, const struct in6_addr *addr,
               const struct in6_addr *mask, struct in6_addr *masked)
{
#ifdef s6_addr32
    for (int i = 0; i < 4; i++) {
        masked->s6_addr32[i] = addr->s6_addr32[i]
            | (get_16aligned_be32(&old[i]) & ~mask->s6_addr32[i]);
    }
#else
    const uint8_t *old8 = (const uint8_t *)old;
    for (int i = 0; i < 16; i++) {
        masked->s6_addr[i] = addr->s6_addr[i] | (old8[i] & ~mask->s6_addr[i]);
    }
#endif
    return masked;
}

static void
odp_set_ipv6(struct dp_packet *packet, const struct ovs_key_ipv6 *key,
             const struct ovs_key_ipv6 *mask)
{
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(packet);
    struct in6_addr sbuf, dbuf;
    uint8_t old_tc = ntohl(get_16aligned_be32(&nh->ip6_flow)) >> 20;
    ovs_be32 old_fl = get_16aligned_be32(&nh->ip6_flow) & htonl(0xfffff);

    packet_set_ipv6(
        packet,
        mask_ipv6_addr(nh->ip6_src.be32, &key->ipv6_src, &mask->ipv6_src,
                       &sbuf),
        mask_ipv6_addr(nh->ip6_dst.be32, &key->ipv6_dst, &mask->ipv6_dst,
                       &dbuf),
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
    const struct ovs_nd_lla_opt *lla_opt = dp_packet_get_nd_payload(packet);

    if (OVS_LIKELY(ns && lla_opt)) {
        int bytes_remain = dp_packet_l4_size(packet) - sizeof(*ns);
        struct in6_addr tgt_buf;
        struct eth_addr sll_buf = eth_addr_zero;
        struct eth_addr tll_buf = eth_addr_zero;

        while (bytes_remain >= ND_LLA_OPT_LEN && lla_opt->len != 0) {
            if (lla_opt->type == ND_OPT_SOURCE_LINKADDR
                && lla_opt->len == 1) {
                sll_buf = lla_opt->mac;
                ether_addr_copy_masked(&sll_buf, key->nd_sll, mask->nd_sll);

                /* A packet can only contain one SLL or TLL option */
                break;
            } else if (lla_opt->type == ND_OPT_TARGET_LINKADDR
                       && lla_opt->len == 1) {
                tll_buf = lla_opt->mac;
                ether_addr_copy_masked(&tll_buf, key->nd_tll, mask->nd_tll);

                /* A packet can only contain one SLL or TLL option */
                break;
            }

            lla_opt += lla_opt->len;
            bytes_remain -= lla_opt->len * ND_LLA_OPT_LEN;
        }

        packet_set_nd(packet,
                      mask_ipv6_addr(ns->target.be32, &key->nd_target,
                                     &mask->nd_target, &tgt_buf),
                      sll_buf,
                      tll_buf);
    }
}

/* Set the NSH header. Assumes the NSH header is present and matches the
 * MD format of the key. The slow path must take case of that. */
static void
odp_set_nsh(struct dp_packet *packet, const struct nlattr *a, bool has_mask)
{
    struct ovs_key_nsh key, mask;
    struct nsh_hdr *nsh = dp_packet_l3(packet);
    uint8_t mdtype = nsh_md_type(nsh);
    ovs_be32 path_hdr;

    if (has_mask) {
        odp_nsh_key_from_attr(a, &key, &mask);
    } else {
        odp_nsh_key_from_attr(a, &key, NULL);
    }

    if (!has_mask) {
        nsh_set_flags_and_ttl(nsh, key.flags, key.ttl);
        put_16aligned_be32(&nsh->path_hdr, key.path_hdr);
        switch (mdtype) {
            case NSH_M_TYPE1:
                for (int i = 0; i < 4; i++) {
                    put_16aligned_be32(&nsh->md1.context[i], key.context[i]);
                }
                break;
            case NSH_M_TYPE2:
            default:
                /* No support for setting any other metadata format yet. */
                break;
        }
    } else {
        uint8_t flags = nsh_get_flags(nsh);
        uint8_t ttl = nsh_get_ttl(nsh);

        flags = key.flags | (flags & ~mask.flags);
        ttl = key.ttl | (ttl & ~mask.ttl);
        nsh_set_flags_and_ttl(nsh, flags, ttl);

        uint32_t spi = ntohl(nsh_get_spi(nsh));
        uint8_t si = nsh_get_si(nsh);
        uint32_t spi_mask = nsh_path_hdr_to_spi_uint32(mask.path_hdr);
        uint8_t si_mask = nsh_path_hdr_to_si(mask.path_hdr);
        if (spi_mask == 0x00ffffff) {
            spi_mask = UINT32_MAX;
        }
        spi = nsh_path_hdr_to_spi_uint32(key.path_hdr) | (spi & ~spi_mask);
        si = nsh_path_hdr_to_si(key.path_hdr) | (si & ~si_mask);
        path_hdr = nsh_get_path_hdr(nsh);
        nsh_path_hdr_set_spi(&path_hdr, htonl(spi));
        nsh_path_hdr_set_si(&path_hdr, si);
        put_16aligned_be32(&nsh->path_hdr, path_hdr);
        switch (mdtype) {
            case NSH_M_TYPE1:
                for (int i = 0; i < 4; i++) {
                    ovs_be32 p = get_16aligned_be32(&nsh->md1.context[i]);
                    ovs_be32 k = key.context[i];
                    ovs_be32 m = mask.context[i];
                    put_16aligned_be32(&nsh->md1.context[i], k | (p & ~m));
                }
                break;
            case NSH_M_TYPE2:
            default:
                /* No support for setting any other metadata format yet. */
                break;
        }
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

    case OVS_KEY_ATTR_NSH: {
        odp_set_nsh(packet, a, false);
        break;
    }

    case OVS_KEY_ATTR_IPV4:
        ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
        packet_set_ipv4(packet, ipv4_key->ipv4_src,
                        ipv4_key->ipv4_dst, ipv4_key->ipv4_tos,
                        ipv4_key->ipv4_ttl);
        break;

    case OVS_KEY_ATTR_IPV6:
        ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));
        packet_set_ipv6(packet, &ipv6_key->ipv6_src, &ipv6_key->ipv6_dst,
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
            packet_set_nd(packet, &nd_key->nd_target, nd_key->nd_sll,
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
    case OVS_KEY_ATTR_PACKET_TYPE:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
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

    case OVS_KEY_ATTR_NSH: {
        odp_set_nsh(packet, a, true);
        break;
    }

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
    case OVS_KEY_ATTR_PACKET_TYPE:
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
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

    if (!steal) {
        /* The 'subactions' may modify the packet, but the modification
         * should not propagate beyond this sample action. Make a copy
         * the packet in case we don't own the packet, so that the
         * 'subactions' are only applid to the clone.  'odp_execute_actions'
         * will free the clone.  */
        packet = dp_packet_clone(packet);
    }
    dp_packet_batch_init_packet(&pb, packet);
    odp_execute_actions(dp, &pb, true, nl_attr_get(subactions),
                        nl_attr_get_size(subactions), dp_execute_action);
}

static void
odp_execute_clone(void *dp, struct dp_packet_batch *batch, bool steal,
                   const struct nlattr *actions,
                   odp_execute_cb dp_execute_action)
{
    if (!steal) {
        /* The 'actions' may modify the packet, but the modification
         * should not propagate beyond this clone action. Make a copy
         * the packet in case we don't own the packet, so that the
         * 'actions' are only applied to the clone.  'odp_execute_actions'
         * will free the clone.  */
        struct dp_packet_batch clone_pkt_batch;
        dp_packet_batch_clone(&clone_pkt_batch, batch);
        dp_packet_batch_reset_cutlen(batch);
        odp_execute_actions(dp, &clone_pkt_batch, true, nl_attr_get(actions),
                        nl_attr_get_size(actions), dp_execute_action);
    }
    else {
        odp_execute_actions(dp, batch, true, nl_attr_get(actions),
                            nl_attr_get_size(actions), dp_execute_action);
    }
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
    case OVS_ACTION_ATTR_METER:
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
    case OVS_ACTION_ATTR_PUSH_ETH:
    case OVS_ACTION_ATTR_POP_ETH:
    case OVS_ACTION_ATTR_CLONE:
    case OVS_ACTION_ATTR_PUSH_NSH:
    case OVS_ACTION_ATTR_POP_NSH:
        return false;

    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    return false;
}

/* Executes all of the 'actions_len' bytes of datapath actions in 'actions' on
 * the packets in 'batch'.  If 'steal' is true, possibly modifies and
 * definitely free the packets in 'batch', otherwise leaves 'batch' unchanged.
 *
 * Some actions (e.g. output actions) can only be executed by a datapath.  This
 * function implements those actions by passing the action and the packets to
 * 'dp_execute_action' (along with 'dp').  If 'dp_execute_action' is passed a
 * true 'may_steal' parameter then it may possibly modify and must definitely
 * free the packets passed into it, otherwise it must leave them unchanged. */
void
odp_execute_actions(void *dp, struct dp_packet_batch *batch, bool steal,
                    const struct nlattr *actions, size_t actions_len,
                    odp_execute_cb dp_execute_action)
{
    struct dp_packet *packet;
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        bool last_action = (left <= NLA_ALIGN(a->nla_len));

        if (requires_datapath_assistance(a)) {
            if (dp_execute_action) {
                /* Allow 'dp_execute_action' to steal the packet data if we do
                 * not need it any more. */
                bool may_steal = steal && last_action;

                dp_execute_action(dp, batch, a, may_steal);

                if (last_action || batch->count == 0) {
                    /* We do not need to free the packets.
                     * Either dp_execute_actions() has stolen them
                     * or the batch is freed due to errors. In either
                     * case we do not need to execute further actions.
                     */
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

                DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                    /* RSS hash can be used here instead of 5tuple for
                     * performance reasons. */
                    if (dp_packet_rss_valid(packet)) {
                        hash = dp_packet_get_rss_hash(packet);
                        hash = hash_int(hash, hash_act->hash_basis);
                    } else {
                        flow_extract(packet, &flow);
                        hash = flow_hash_5tuple(&flow, hash_act->hash_basis);
                    }
                    packet->md.dp_hash = hash;
                }
            } else {
                /* Assert on unknown hash algorithm.  */
                OVS_NOT_REACHED();
            }
            break;
        }

        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);

            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                eth_push_vlan(packet, vlan->vlan_tpid, vlan->vlan_tci);
            }
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN:
            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                eth_pop_vlan(packet);
            }
            break;

        case OVS_ACTION_ATTR_PUSH_MPLS: {
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);

            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                push_mpls(packet, mpls->mpls_ethertype, mpls->mpls_lse);
            }
            break;
         }

        case OVS_ACTION_ATTR_POP_MPLS:
            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                pop_mpls(packet, nl_attr_get_be16(a));
            }
            break;

        case OVS_ACTION_ATTR_SET:
            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                odp_execute_set_action(packet, nl_attr_get(a));
            }
            break;

        case OVS_ACTION_ATTR_SET_MASKED:
            DP_PACKET_BATCH_FOR_EACH(packet, batch) {
                odp_execute_masked_set_action(packet, nl_attr_get(a));
            }
            break;

        case OVS_ACTION_ATTR_SAMPLE:
            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                odp_execute_sample(dp, packet, steal && last_action, a,
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
            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                dp_packet_set_cutlen(packet, trunc->max_len);
            }
            break;
        }

        case OVS_ACTION_ATTR_CLONE:
            odp_execute_clone(dp, batch, steal && last_action, a,
                                                dp_execute_action);
            if (last_action) {
                /* We do not need to free the packets. odp_execute_clone() has
                 * stolen them.  */
                return;
            }
            break;
        case OVS_ACTION_ATTR_METER:
            /* Not implemented yet. */
            break;
        case OVS_ACTION_ATTR_PUSH_ETH: {
            const struct ovs_action_push_eth *eth = nl_attr_get(a);

            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                push_eth(packet, &eth->addresses.eth_dst,
                         &eth->addresses.eth_src);
            }
            break;
        }

        case OVS_ACTION_ATTR_POP_ETH:
            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                pop_eth(packet);
            }
            break;

        case OVS_ACTION_ATTR_PUSH_NSH: {
            uint32_t buffer[NSH_HDR_MAX_LEN / 4];
            struct nsh_hdr *nsh_hdr = ALIGNED_CAST(struct nsh_hdr *, buffer);
            nsh_reset_ver_flags_ttl_len(nsh_hdr);
            odp_nsh_hdr_from_attr(nl_attr_get(a), nsh_hdr, NSH_HDR_MAX_LEN);
            DP_PACKET_BATCH_FOR_EACH (packet, batch) {
                push_nsh(packet, nsh_hdr);
            }
            break;
        }
        case OVS_ACTION_ATTR_POP_NSH: {
            size_t i;
            const size_t num = dp_packet_batch_size(batch);

            DP_PACKET_BATCH_REFILL_FOR_EACH (i, num, packet, batch) {
                if (pop_nsh(packet)) {
                    dp_packet_batch_refill(batch, packet, i);
                } else {
                    dp_packet_delete(packet);
                }
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

    dp_packet_delete_batch(batch, steal);
}
