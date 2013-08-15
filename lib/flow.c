/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <sys/types.h>
#include "flow.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "byte-order.h"
#include "coverage.h"
#include "csum.h"
#include "dynamic-string.h"
#include "hash.h"
#include "match.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "unaligned.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(flow);

COVERAGE_DEFINE(flow_extract);
COVERAGE_DEFINE(miniflow_malloc);

static struct arp_eth_header *
pull_arp(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, ARP_ETH_HEADER_LEN);
}

static struct ip_header *
pull_ip(struct ofpbuf *packet)
{
    if (packet->size >= IP_HEADER_LEN) {
        struct ip_header *ip = packet->data;
        int ip_len = IP_IHL(ip->ip_ihl_ver) * 4;
        if (ip_len >= IP_HEADER_LEN && packet->size >= ip_len) {
            return ofpbuf_pull(packet, ip_len);
        }
    }
    return NULL;
}

static struct tcp_header *
pull_tcp(struct ofpbuf *packet)
{
    if (packet->size >= TCP_HEADER_LEN) {
        struct tcp_header *tcp = packet->data;
        int tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;
        if (tcp_len >= TCP_HEADER_LEN && packet->size >= tcp_len) {
            return ofpbuf_pull(packet, tcp_len);
        }
    }
    return NULL;
}

static struct udp_header *
pull_udp(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, UDP_HEADER_LEN);
}

static struct icmp_header *
pull_icmp(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, ICMP_HEADER_LEN);
}

static struct icmp6_hdr *
pull_icmpv6(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, sizeof(struct icmp6_hdr));
}

static void
parse_vlan(struct ofpbuf *b, struct flow *flow)
{
    struct qtag_prefix {
        ovs_be16 eth_type;      /* ETH_TYPE_VLAN */
        ovs_be16 tci;
    };

    if (b->size >= sizeof(struct qtag_prefix) + sizeof(ovs_be16)) {
        struct qtag_prefix *qp = ofpbuf_pull(b, sizeof *qp);
        flow->vlan_tci = qp->tci | htons(VLAN_CFI);
    }
}

static ovs_be16
parse_ethertype(struct ofpbuf *b)
{
    struct llc_snap_header *llc;
    ovs_be16 proto;

    proto = *(ovs_be16 *) ofpbuf_pull(b, sizeof proto);
    if (ntohs(proto) >= ETH_TYPE_MIN) {
        return proto;
    }

    if (b->size < sizeof *llc) {
        return htons(FLOW_DL_TYPE_NONE);
    }

    llc = b->data;
    if (llc->llc.llc_dsap != LLC_DSAP_SNAP
        || llc->llc.llc_ssap != LLC_SSAP_SNAP
        || llc->llc.llc_cntl != LLC_CNTL_SNAP
        || memcmp(llc->snap.snap_org, SNAP_ORG_ETHERNET,
                  sizeof llc->snap.snap_org)) {
        return htons(FLOW_DL_TYPE_NONE);
    }

    ofpbuf_pull(b, sizeof *llc);
    return llc->snap.snap_type;
}

static int
parse_ipv6(struct ofpbuf *packet, struct flow *flow)
{
    const struct ovs_16aligned_ip6_hdr *nh;
    ovs_be32 tc_flow;
    int nexthdr;

    nh = ofpbuf_try_pull(packet, sizeof *nh);
    if (!nh) {
        return EINVAL;
    }

    nexthdr = nh->ip6_nxt;

    memcpy(&flow->ipv6_src, &nh->ip6_src, sizeof flow->ipv6_src);
    memcpy(&flow->ipv6_dst, &nh->ip6_dst, sizeof flow->ipv6_dst);

    tc_flow = get_16aligned_be32(&nh->ip6_flow);
    flow->nw_tos = ntohl(tc_flow) >> 20;
    flow->ipv6_label = tc_flow & htonl(IPV6_LABEL_MASK);
    flow->nw_ttl = nh->ip6_hlim;
    flow->nw_proto = IPPROTO_NONE;

    while (1) {
        if ((nexthdr != IPPROTO_HOPOPTS)
                && (nexthdr != IPPROTO_ROUTING)
                && (nexthdr != IPPROTO_DSTOPTS)
                && (nexthdr != IPPROTO_AH)
                && (nexthdr != IPPROTO_FRAGMENT)) {
            /* It's either a terminal header (e.g., TCP, UDP) or one we
             * don't understand.  In either case, we're done with the
             * packet, so use it to fill in 'nw_proto'. */
            break;
        }

        /* We only verify that at least 8 bytes of the next header are
         * available, but many of these headers are longer.  Ensure that
         * accesses within the extension header are within those first 8
         * bytes. All extension headers are required to be at least 8
         * bytes. */
        if (packet->size < 8) {
            return EINVAL;
        }

        if ((nexthdr == IPPROTO_HOPOPTS)
                || (nexthdr == IPPROTO_ROUTING)
                || (nexthdr == IPPROTO_DSTOPTS)) {
            /* These headers, while different, have the fields we care about
             * in the same location and with the same interpretation. */
            const struct ip6_ext *ext_hdr = packet->data;
            nexthdr = ext_hdr->ip6e_nxt;
            if (!ofpbuf_try_pull(packet, (ext_hdr->ip6e_len + 1) * 8)) {
                return EINVAL;
            }
        } else if (nexthdr == IPPROTO_AH) {
            /* A standard AH definition isn't available, but the fields
             * we care about are in the same location as the generic
             * option header--only the header length is calculated
             * differently. */
            const struct ip6_ext *ext_hdr = packet->data;
            nexthdr = ext_hdr->ip6e_nxt;
            if (!ofpbuf_try_pull(packet, (ext_hdr->ip6e_len + 2) * 4)) {
               return EINVAL;
            }
        } else if (nexthdr == IPPROTO_FRAGMENT) {
            const struct ovs_16aligned_ip6_frag *frag_hdr = packet->data;

            nexthdr = frag_hdr->ip6f_nxt;
            if (!ofpbuf_try_pull(packet, sizeof *frag_hdr)) {
                return EINVAL;
            }

            /* We only process the first fragment. */
            if (frag_hdr->ip6f_offlg != htons(0)) {
                flow->nw_frag = FLOW_NW_FRAG_ANY;
                if ((frag_hdr->ip6f_offlg & IP6F_OFF_MASK) != htons(0)) {
                    flow->nw_frag |= FLOW_NW_FRAG_LATER;
                    nexthdr = IPPROTO_FRAGMENT;
                    break;
                }
            }
        }
    }

    flow->nw_proto = nexthdr;
    return 0;
}

static void
parse_tcp(struct ofpbuf *packet, struct ofpbuf *b, struct flow *flow)
{
    const struct tcp_header *tcp = pull_tcp(b);
    if (tcp) {
        flow->tp_src = tcp->tcp_src;
        flow->tp_dst = tcp->tcp_dst;
        packet->l7 = b->data;
    }
}

static void
parse_udp(struct ofpbuf *packet, struct ofpbuf *b, struct flow *flow)
{
    const struct udp_header *udp = pull_udp(b);
    if (udp) {
        flow->tp_src = udp->udp_src;
        flow->tp_dst = udp->udp_dst;
        packet->l7 = b->data;
    }
}

static bool
parse_icmpv6(struct ofpbuf *b, struct flow *flow)
{
    const struct icmp6_hdr *icmp = pull_icmpv6(b);

    if (!icmp) {
        return false;
    }

    /* The ICMPv6 type and code fields use the 16-bit transport port
     * fields, so we need to store them in 16-bit network byte order. */
    flow->tp_src = htons(icmp->icmp6_type);
    flow->tp_dst = htons(icmp->icmp6_code);

    if (icmp->icmp6_code == 0 &&
        (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT ||
         icmp->icmp6_type == ND_NEIGHBOR_ADVERT)) {
        const struct in6_addr *nd_target;

        nd_target = ofpbuf_try_pull(b, sizeof *nd_target);
        if (!nd_target) {
            return false;
        }
        flow->nd_target = *nd_target;

        while (b->size >= 8) {
            /* The minimum size of an option is 8 bytes, which also is
             * the size of Ethernet link-layer options. */
            const struct nd_opt_hdr *nd_opt = b->data;
            int opt_len = nd_opt->nd_opt_len * 8;

            if (!opt_len || opt_len > b->size) {
                goto invalid;
            }

            /* Store the link layer address if the appropriate option is
             * provided.  It is considered an error if the same link
             * layer option is specified twice. */
            if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR
                    && opt_len == 8) {
                if (eth_addr_is_zero(flow->arp_sha)) {
                    memcpy(flow->arp_sha, nd_opt + 1, ETH_ADDR_LEN);
                } else {
                    goto invalid;
                }
            } else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR
                    && opt_len == 8) {
                if (eth_addr_is_zero(flow->arp_tha)) {
                    memcpy(flow->arp_tha, nd_opt + 1, ETH_ADDR_LEN);
                } else {
                    goto invalid;
                }
            }

            if (!ofpbuf_try_pull(b, opt_len)) {
                goto invalid;
            }
        }
    }

    return true;

invalid:
    memset(&flow->nd_target, 0, sizeof(flow->nd_target));
    memset(flow->arp_sha, 0, sizeof(flow->arp_sha));
    memset(flow->arp_tha, 0, sizeof(flow->arp_tha));

    return false;

}

/* Initializes 'flow' members from 'packet', 'skb_priority', 'tnl', and
 * 'ofp_in_port'.
 *
 * Initializes 'packet' header pointers as follows:
 *
 *    - packet->l2 to the start of the Ethernet header.
 *
 *    - packet->l3 to just past the Ethernet header, or just past the
 *      vlan_header if one is present, to the first byte of the payload of the
 *      Ethernet frame.
 *
 *    - packet->l4 to just past the IPv4 header, if one is present and has a
 *      correct length, and otherwise NULL.
 *
 *    - packet->l7 to just past the TCP or UDP or ICMP header, if one is
 *      present and has a correct length, and otherwise NULL.
 */
void
flow_extract(struct ofpbuf *packet, uint32_t skb_priority, uint32_t skb_mark,
             const struct flow_tnl *tnl, uint16_t ofp_in_port,
             struct flow *flow)
{
    struct ofpbuf b = *packet;
    struct eth_header *eth;

    COVERAGE_INC(flow_extract);

    memset(flow, 0, sizeof *flow);

    if (tnl) {
        assert(tnl != &flow->tunnel);
        flow->tunnel = *tnl;
    }
    flow->in_port = ofp_in_port;
    flow->skb_priority = skb_priority;
    flow->skb_mark = skb_mark;

    packet->l2 = b.data;
    packet->l3 = NULL;
    packet->l4 = NULL;
    packet->l7 = NULL;

    if (b.size < sizeof *eth) {
        return;
    }

    /* Link layer. */
    eth = b.data;
    memcpy(flow->dl_src, eth->eth_src, ETH_ADDR_LEN);
    memcpy(flow->dl_dst, eth->eth_dst, ETH_ADDR_LEN);

    /* dl_type, vlan_tci. */
    ofpbuf_pull(&b, ETH_ADDR_LEN * 2);
    if (eth->eth_type == htons(ETH_TYPE_VLAN)) {
        parse_vlan(&b, flow);
    }
    flow->dl_type = parse_ethertype(&b);

    /* Network layer. */
    packet->l3 = b.data;
    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        const struct ip_header *nh = pull_ip(&b);
        if (nh) {
            packet->l4 = b.data;

            flow->nw_src = get_16aligned_be32(&nh->ip_src);
            flow->nw_dst = get_16aligned_be32(&nh->ip_dst);
            flow->nw_proto = nh->ip_proto;

            flow->nw_tos = nh->ip_tos;
            if (IP_IS_FRAGMENT(nh->ip_frag_off)) {
                flow->nw_frag = FLOW_NW_FRAG_ANY;
                if (nh->ip_frag_off & htons(IP_FRAG_OFF_MASK)) {
                    flow->nw_frag |= FLOW_NW_FRAG_LATER;
                }
            }
            flow->nw_ttl = nh->ip_ttl;

            if (!(nh->ip_frag_off & htons(IP_FRAG_OFF_MASK))) {
                if (flow->nw_proto == IPPROTO_TCP) {
                    parse_tcp(packet, &b, flow);
                } else if (flow->nw_proto == IPPROTO_UDP) {
                    parse_udp(packet, &b, flow);
                } else if (flow->nw_proto == IPPROTO_ICMP) {
                    const struct icmp_header *icmp = pull_icmp(&b);
                    if (icmp) {
                        flow->tp_src = htons(icmp->icmp_type);
                        flow->tp_dst = htons(icmp->icmp_code);
                        packet->l7 = b.data;
                    }
                }
            }
        }
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        if (parse_ipv6(&b, flow)) {
            return;
        }

        packet->l4 = b.data;
        if (flow->nw_proto == IPPROTO_TCP) {
            parse_tcp(packet, &b, flow);
        } else if (flow->nw_proto == IPPROTO_UDP) {
            parse_udp(packet, &b, flow);
        } else if (flow->nw_proto == IPPROTO_ICMPV6) {
            if (parse_icmpv6(&b, flow)) {
                packet->l7 = b.data;
            }
        }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        const struct arp_eth_header *arp = pull_arp(&b);
        if (arp && arp->ar_hrd == htons(1)
            && arp->ar_pro == htons(ETH_TYPE_IP)
            && arp->ar_hln == ETH_ADDR_LEN
            && arp->ar_pln == 4) {
            /* We only match on the lower 8 bits of the opcode. */
            if (ntohs(arp->ar_op) <= 0xff) {
                flow->nw_proto = ntohs(arp->ar_op);
            }

            flow->nw_src = get_16aligned_be32(&arp->ar_spa);
            flow->nw_dst = get_16aligned_be32(&arp->ar_tpa);
            memcpy(flow->arp_sha, arp->ar_sha, ETH_ADDR_LEN);
            memcpy(flow->arp_tha, arp->ar_tha, ETH_ADDR_LEN);
        }
    }
}

/* For every bit of a field that is wildcarded in 'wildcards', sets the
 * corresponding bit in 'flow' to zero. */
void
flow_zero_wildcards(struct flow *flow, const struct flow_wildcards *wildcards)
{
    uint32_t *flow_u32 = (uint32_t *) flow;
    const uint32_t *wc_u32 = (const uint32_t *) &wildcards->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        flow_u32[i] &= wc_u32[i];
    }
}

/* Initializes 'fmd' with the metadata found in 'flow'. */
void
flow_get_metadata(const struct flow *flow, struct flow_metadata *fmd)
{
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 18);

    fmd->tun_id = flow->tunnel.tun_id;
    fmd->metadata = flow->metadata;
    memcpy(fmd->regs, flow->regs, sizeof fmd->regs);
    fmd->in_port = flow->in_port;
}

char *
flow_to_string(const struct flow *flow)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    flow_format(&ds, flow);
    return ds_cstr(&ds);
}

const char *
flow_tun_flag_to_string(uint32_t flags)
{
    switch (flags) {
    case FLOW_TNL_F_DONT_FRAGMENT:
        return "df";
    case FLOW_TNL_F_CSUM:
        return "csum";
    case FLOW_TNL_F_KEY:
        return "key";
    default:
        return NULL;
    }
}

void
format_flags(struct ds *ds, const char *(*bit_to_string)(uint32_t),
             uint32_t flags, char del)
{
    uint32_t bad = 0;

    if (!flags) {
        return;
    }
    while (flags) {
        uint32_t bit = rightmost_1bit(flags);
        const char *s;

        s = bit_to_string(bit);
        if (s) {
            ds_put_format(ds, "%s%c", s, del);
        } else {
            bad |= bit;
        }

        flags &= ~bit;
    }

    if (bad) {
        ds_put_format(ds, "0x%"PRIx32"%c", bad, del);
    }
    ds_chomp(ds, del);
}

void
flow_format(struct ds *ds, const struct flow *flow)
{
    struct match match;

    match_wc_init(&match, flow);
    match_format(&match, ds, OFP_DEFAULT_PRIORITY);
}

void
flow_print(FILE *stream, const struct flow *flow)
{
    char *s = flow_to_string(flow);
    fputs(s, stream);
    free(s);
}

/* flow_wildcards functions. */

/* Initializes 'wc' as a set of wildcards that matches every packet. */
void
flow_wildcards_init_catchall(struct flow_wildcards *wc)
{
    memset(&wc->masks, 0, sizeof wc->masks);
}

/* Initializes 'wc' as an exact-match set of wildcards; that is, 'wc' does not
 * wildcard any bits or fields. */
void
flow_wildcards_init_exact(struct flow_wildcards *wc)
{
    memset(&wc->masks, 0xff, sizeof wc->masks);
    memset(wc->masks.zeros, 0, sizeof wc->masks.zeros);
}

/* Returns true if 'wc' matches every packet, false if 'wc' fixes any bits or
 * fields. */
bool
flow_wildcards_is_catchall(const struct flow_wildcards *wc)
{
    const uint32_t *wc_u32 = (const uint32_t *) &wc->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        if (wc_u32[i]) {
            return false;
        }
    }
    return true;
}

/* Initializes 'dst' as the combination of wildcards in 'src1' and 'src2'.
 * That is, a bit or a field is wildcarded in 'dst' if it is wildcarded in
 * 'src1' or 'src2' or both.  */
void
flow_wildcards_combine(struct flow_wildcards *dst,
                       const struct flow_wildcards *src1,
                       const struct flow_wildcards *src2)
{
    uint32_t *dst_u32 = (uint32_t *) &dst->masks;
    const uint32_t *src1_u32 = (const uint32_t *) &src1->masks;
    const uint32_t *src2_u32 = (const uint32_t *) &src2->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        dst_u32[i] = src1_u32[i] & src2_u32[i];
    }
}

/* Returns a hash of the wildcards in 'wc'. */
uint32_t
flow_wildcards_hash(const struct flow_wildcards *wc, uint32_t basis)
{
    return flow_hash(&wc->masks, basis);;
}

/* Returns true if 'a' and 'b' represent the same wildcards, false if they are
 * different. */
bool
flow_wildcards_equal(const struct flow_wildcards *a,
                     const struct flow_wildcards *b)
{
    return flow_equal(&a->masks, &b->masks);
}

/* Returns true if at least one bit or field is wildcarded in 'a' but not in
 * 'b', false otherwise. */
bool
flow_wildcards_has_extra(const struct flow_wildcards *a,
                         const struct flow_wildcards *b)
{
    const uint32_t *a_u32 = (const uint32_t *) &a->masks;
    const uint32_t *b_u32 = (const uint32_t *) &b->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        if ((a_u32[i] & b_u32[i]) != b_u32[i]) {
            return true;
        }
    }
    return false;
}

/* Returns true if 'a' and 'b' are equal, except that 0-bits (wildcarded bits)
 * in 'wc' do not need to be equal in 'a' and 'b'. */
bool
flow_equal_except(const struct flow *a, const struct flow *b,
                  const struct flow_wildcards *wc)
{
    const uint32_t *a_u32 = (const uint32_t *) a;
    const uint32_t *b_u32 = (const uint32_t *) b;
    const uint32_t *wc_u32 = (const uint32_t *) &wc->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        if ((a_u32[i] ^ b_u32[i]) & wc_u32[i]) {
            return false;
        }
    }
    return true;
}

/* Sets the wildcard mask for register 'idx' in 'wc' to 'mask'.
 * (A 0-bit indicates a wildcard bit.) */
void
flow_wildcards_set_reg_mask(struct flow_wildcards *wc, int idx, uint32_t mask)
{
    wc->masks.regs[idx] = mask;
}

/* Hashes 'flow' based on its L2 through L4 protocol information. */
uint32_t
flow_hash_symmetric_l4(const struct flow *flow, uint32_t basis)
{
    struct {
        union {
            ovs_be32 ipv4_addr;
            struct in6_addr ipv6_addr;
        };
        ovs_be16 eth_type;
        ovs_be16 vlan_tci;
        ovs_be16 tp_port;
        uint8_t eth_addr[ETH_ADDR_LEN];
        uint8_t ip_proto;
    } fields;

    int i;

    memset(&fields, 0, sizeof fields);
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        fields.eth_addr[i] = flow->dl_src[i] ^ flow->dl_dst[i];
    }
    fields.vlan_tci = flow->vlan_tci & htons(VLAN_VID_MASK);
    fields.eth_type = flow->dl_type;

    /* UDP source and destination port are not taken into account because they
     * will not necessarily be symmetric in a bidirectional flow. */
    if (fields.eth_type == htons(ETH_TYPE_IP)) {
        fields.ipv4_addr = flow->nw_src ^ flow->nw_dst;
        fields.ip_proto = flow->nw_proto;
        if (fields.ip_proto == IPPROTO_TCP) {
            fields.tp_port = flow->tp_src ^ flow->tp_dst;
        }
    } else if (fields.eth_type == htons(ETH_TYPE_IPV6)) {
        const uint8_t *a = &flow->ipv6_src.s6_addr[0];
        const uint8_t *b = &flow->ipv6_dst.s6_addr[0];
        uint8_t *ipv6_addr = &fields.ipv6_addr.s6_addr[0];

        for (i=0; i<16; i++) {
            ipv6_addr[i] = a[i] ^ b[i];
        }
        fields.ip_proto = flow->nw_proto;
        if (fields.ip_proto == IPPROTO_TCP) {
            fields.tp_port = flow->tp_src ^ flow->tp_dst;
        }
    }
    return hash_bytes(&fields, sizeof fields, basis);
}

/* Hashes the portions of 'flow' designated by 'fields'. */
uint32_t
flow_hash_fields(const struct flow *flow, enum nx_hash_fields fields,
                 uint16_t basis)
{
    switch (fields) {

    case NX_HASH_FIELDS_ETH_SRC:
        return hash_bytes(flow->dl_src, sizeof flow->dl_src, basis);

    case NX_HASH_FIELDS_SYMMETRIC_L4:
        return flow_hash_symmetric_l4(flow, basis);
    }

    NOT_REACHED();
}

/* Returns a string representation of 'fields'. */
const char *
flow_hash_fields_to_str(enum nx_hash_fields fields)
{
    switch (fields) {
    case NX_HASH_FIELDS_ETH_SRC: return "eth_src";
    case NX_HASH_FIELDS_SYMMETRIC_L4: return "symmetric_l4";
    default: return "<unknown>";
    }
}

/* Returns true if the value of 'fields' is supported. Otherwise false. */
bool
flow_hash_fields_valid(enum nx_hash_fields fields)
{
    return fields == NX_HASH_FIELDS_ETH_SRC
        || fields == NX_HASH_FIELDS_SYMMETRIC_L4;
}

/* Sets the VLAN VID that 'flow' matches to 'vid', which is interpreted as an
 * OpenFlow 1.0 "dl_vlan" value:
 *
 *      - If it is in the range 0...4095, 'flow->vlan_tci' is set to match
 *        that VLAN.  Any existing PCP match is unchanged (it becomes 0 if
 *        'flow' previously matched packets without a VLAN header).
 *
 *      - If it is OFP_VLAN_NONE, 'flow->vlan_tci' is set to match a packet
 *        without a VLAN tag.
 *
 *      - Other values of 'vid' should not be used. */
void
flow_set_dl_vlan(struct flow *flow, ovs_be16 vid)
{
    if (vid == htons(OFP10_VLAN_NONE)) {
        flow->vlan_tci = htons(0);
    } else {
        vid &= htons(VLAN_VID_MASK);
        flow->vlan_tci &= ~htons(VLAN_VID_MASK);
        flow->vlan_tci |= htons(VLAN_CFI) | vid;
    }
}

/* Sets the VLAN VID that 'flow' matches to 'vid', which is interpreted as an
 * OpenFlow 1.2 "vlan_vid" value, that is, the low 13 bits of 'vlan_tci' (VID
 * plus CFI). */
void
flow_set_vlan_vid(struct flow *flow, ovs_be16 vid)
{
    ovs_be16 mask = htons(VLAN_VID_MASK | VLAN_CFI);
    flow->vlan_tci &= ~mask;
    flow->vlan_tci |= vid & mask;
}

/* Sets the VLAN PCP that 'flow' matches to 'pcp', which should be in the
 * range 0...7.
 *
 * This function has no effect on the VLAN ID that 'flow' matches.
 *
 * After calling this function, 'flow' will not match packets without a VLAN
 * header. */
void
flow_set_vlan_pcp(struct flow *flow, uint8_t pcp)
{
    pcp &= 0x07;
    flow->vlan_tci &= ~htons(VLAN_PCP_MASK);
    flow->vlan_tci |= htons((pcp << VLAN_PCP_SHIFT) | VLAN_CFI);
}

/* Puts into 'b' a packet that flow_extract() would parse as having the given
 * 'flow'.
 *
 * (This is useful only for testing, obviously, and the packet isn't really
 * valid. It hasn't got some checksums filled in, for one, and lots of fields
 * are just zeroed.) */
void
flow_compose(struct ofpbuf *b, const struct flow *flow)
{
    eth_compose(b, flow->dl_dst, flow->dl_src, ntohs(flow->dl_type), 0);
    if (flow->dl_type == htons(FLOW_DL_TYPE_NONE)) {
        struct eth_header *eth = b->l2;
        eth->eth_type = htons(b->size);
        return;
    }

    if (flow->vlan_tci & htons(VLAN_CFI)) {
        eth_push_vlan(b, flow->vlan_tci);
    }

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct ip_header *ip;

        b->l3 = ip = ofpbuf_put_zeros(b, sizeof *ip);
        ip->ip_ihl_ver = IP_IHL_VER(5, 4);
        ip->ip_tos = flow->nw_tos;
        ip->ip_proto = flow->nw_proto;
        put_16aligned_be32(&ip->ip_src, flow->nw_src);
        put_16aligned_be32(&ip->ip_dst, flow->nw_dst);

        if (flow->nw_frag & FLOW_NW_FRAG_ANY) {
            ip->ip_frag_off |= htons(IP_MORE_FRAGMENTS);
            if (flow->nw_frag & FLOW_NW_FRAG_LATER) {
                ip->ip_frag_off |= htons(100);
            }
        }
        if (!(flow->nw_frag & FLOW_NW_FRAG_ANY)
            || !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
            if (flow->nw_proto == IPPROTO_TCP) {
                struct tcp_header *tcp;

                b->l4 = tcp = ofpbuf_put_zeros(b, sizeof *tcp);
                tcp->tcp_src = flow->tp_src;
                tcp->tcp_dst = flow->tp_dst;
                tcp->tcp_ctl = TCP_CTL(0, 5);
            } else if (flow->nw_proto == IPPROTO_UDP) {
                struct udp_header *udp;

                b->l4 = udp = ofpbuf_put_zeros(b, sizeof *udp);
                udp->udp_src = flow->tp_src;
                udp->udp_dst = flow->tp_dst;
            } else if (flow->nw_proto == IPPROTO_ICMP) {
                struct icmp_header *icmp;

                b->l4 = icmp = ofpbuf_put_zeros(b, sizeof *icmp);
                icmp->icmp_type = ntohs(flow->tp_src);
                icmp->icmp_code = ntohs(flow->tp_dst);
                icmp->icmp_csum = csum(icmp, ICMP_HEADER_LEN);
            }
        }

        ip = b->l3;
        ip->ip_tot_len = htons((uint8_t *) b->data + b->size
                               - (uint8_t *) b->l3);
        ip->ip_csum = csum(ip, sizeof *ip);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        /* XXX */
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        struct arp_eth_header *arp;

        b->l3 = arp = ofpbuf_put_zeros(b, sizeof *arp);
        arp->ar_hrd = htons(1);
        arp->ar_pro = htons(ETH_TYPE_IP);
        arp->ar_hln = ETH_ADDR_LEN;
        arp->ar_pln = 4;
        arp->ar_op = htons(flow->nw_proto);

        if (flow->nw_proto == ARP_OP_REQUEST ||
            flow->nw_proto == ARP_OP_REPLY) {
            put_16aligned_be32(&arp->ar_spa, flow->nw_src);
            put_16aligned_be32(&arp->ar_tpa, flow->nw_dst);
            memcpy(arp->ar_sha, flow->arp_sha, ETH_ADDR_LEN);
            memcpy(arp->ar_tha, flow->arp_tha, ETH_ADDR_LEN);
        }
    }
}

/* Compressed flow. */

static int
miniflow_n_values(const struct miniflow *flow)
{
    int n, i;

    n = 0;
    for (i = 0; i < MINI_N_MAPS; i++) {
        n += popcount(flow->map[i]);
    }
    return n;
}

static uint32_t *
miniflow_alloc_values(struct miniflow *flow, int n)
{
    if (n <= MINI_N_INLINE) {
        return flow->inline_values;
    } else {
        COVERAGE_INC(miniflow_malloc);
        return xmalloc(n * sizeof *flow->values);
    }
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with miniflow_destroy(). */
void
miniflow_init(struct miniflow *dst, const struct flow *src)
{
    const uint32_t *src_u32 = (const uint32_t *) src;
    unsigned int ofs;
    unsigned int i;
    int n;

    /* Initialize dst->map, counting the number of nonzero elements. */
    n = 0;
    memset(dst->map, 0, sizeof dst->map);
    for (i = 0; i < FLOW_U32S; i++) {
        if (src_u32[i]) {
            dst->map[i / 32] |= 1u << (i % 32);
            n++;
        }
    }

    /* Initialize dst->values. */
    dst->values = miniflow_alloc_values(dst, n);
    ofs = 0;
    for (i = 0; i < MINI_N_MAPS; i++) {
        uint32_t map;

        for (map = dst->map[i]; map; map = zero_rightmost_1bit(map)) {
            dst->values[ofs++] = src_u32[raw_ctz(map) + i * 32];
        }
    }
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with miniflow_destroy(). */
void
miniflow_clone(struct miniflow *dst, const struct miniflow *src)
{
    int n = miniflow_n_values(src);
    memcpy(dst->map, src->map, sizeof dst->map);
    dst->values = miniflow_alloc_values(dst, n);
    memcpy(dst->values, src->values, n * sizeof *dst->values);
}

/* Frees any memory owned by 'flow'.  Does not free the storage in which 'flow'
 * itself resides; the caller is responsible for that. */
void
miniflow_destroy(struct miniflow *flow)
{
    if (flow->values != flow->inline_values) {
        free(flow->values);
    }
}

/* Initializes 'dst' as a copy of 'src'. */
void
miniflow_expand(const struct miniflow *src, struct flow *dst)
{
    uint32_t *dst_u32 = (uint32_t *) dst;
    int ofs;
    int i;

    memset(dst_u32, 0, sizeof *dst);

    ofs = 0;
    for (i = 0; i < MINI_N_MAPS; i++) {
        uint32_t map;

        for (map = src->map[i]; map; map = zero_rightmost_1bit(map)) {
            dst_u32[raw_ctz(map) + i * 32] = src->values[ofs++];
        }
    }
}

static const uint32_t *
miniflow_get__(const struct miniflow *flow, unsigned int u32_ofs)
{
    if (!(flow->map[u32_ofs / 32] & (1u << (u32_ofs % 32)))) {
        static const uint32_t zero = 0;
        return &zero;
    } else {
        const uint32_t *p = flow->values;

        BUILD_ASSERT(MINI_N_MAPS == 2);
        if (u32_ofs < 32) {
            p += popcount(flow->map[0] & ((1u << u32_ofs) - 1));
        } else {
            p += popcount(flow->map[0]);
            p += popcount(flow->map[1] & ((1u << (u32_ofs - 32)) - 1));
        }
        return p;
    }
}

/* Returns the uint32_t that would be at byte offset '4 * u32_ofs' if 'flow'
 * were expanded into a "struct flow". */
uint32_t
miniflow_get(const struct miniflow *flow, unsigned int u32_ofs)
{
    return *miniflow_get__(flow, u32_ofs);
}

/* Returns the ovs_be16 that would be at byte offset 'u8_ofs' if 'flow' were
 * expanded into a "struct flow". */
static ovs_be16
miniflow_get_be16(const struct miniflow *flow, unsigned int u8_ofs)
{
    const uint32_t *u32p = miniflow_get__(flow, u8_ofs / 4);
    const ovs_be16 *be16p = (const ovs_be16 *) u32p;
    return be16p[u8_ofs % 4 != 0];
}

/* Returns the VID within the vlan_tci member of the "struct flow" represented
 * by 'flow'. */
uint16_t
miniflow_get_vid(const struct miniflow *flow)
{
    ovs_be16 tci = miniflow_get_be16(flow, offsetof(struct flow, vlan_tci));
    return vlan_tci_to_vid(tci);
}

/* Returns true if 'a' and 'b' are the same flow, false otherwise.  */
bool
miniflow_equal(const struct miniflow *a, const struct miniflow *b)
{
    int i;

    for (i = 0; i < MINI_N_MAPS; i++) {
        if (a->map[i] != b->map[i]) {
            return false;
        }
    }

    return !memcmp(a->values, b->values,
                   miniflow_n_values(a) * sizeof *a->values);
}

/* Returns true if 'a' and 'b' are equal at the places where there are 1-bits
 * in 'mask', false if they differ. */
bool
miniflow_equal_in_minimask(const struct miniflow *a, const struct miniflow *b,
                           const struct minimask *mask)
{
    const uint32_t *p;
    int i;

    p = mask->masks.values;
    for (i = 0; i < MINI_N_MAPS; i++) {
        uint32_t map;

        for (map = mask->masks.map[i]; map; map = zero_rightmost_1bit(map)) {
            int ofs = raw_ctz(map) + i * 32;

            if ((miniflow_get(a, ofs) ^ miniflow_get(b, ofs)) & *p) {
                return false;
            }
            p++;
        }
    }

    return true;
}

/* Returns true if 'a' and 'b' are equal at the places where there are 1-bits
 * in 'mask', false if they differ. */
bool
miniflow_equal_flow_in_minimask(const struct miniflow *a, const struct flow *b,
                                const struct minimask *mask)
{
    const uint32_t *b_u32 = (const uint32_t *) b;
    const uint32_t *p;
    int i;

    p = mask->masks.values;
    for (i = 0; i < MINI_N_MAPS; i++) {
        uint32_t map;

        for (map = mask->masks.map[i]; map; map = zero_rightmost_1bit(map)) {
            int ofs = raw_ctz(map) + i * 32;

            if ((miniflow_get(a, ofs) ^ b_u32[ofs]) & *p) {
                return false;
            }
            p++;
        }
    }

    return true;
}

/* Returns a hash value for 'flow', given 'basis'. */
uint32_t
miniflow_hash(const struct miniflow *flow, uint32_t basis)
{
    BUILD_ASSERT_DECL(MINI_N_MAPS == 2);
    return hash_3words(flow->map[0], flow->map[1],
                       hash_words(flow->values, miniflow_n_values(flow),
                                  basis));
}

/* Returns a hash value for the bits of 'flow' where there are 1-bits in
 * 'mask', given 'basis'.
 *
 * The hash values returned by this function are the same as those returned by
 * flow_hash_in_minimask(), only the form of the arguments differ. */
uint32_t
miniflow_hash_in_minimask(const struct miniflow *flow,
                          const struct minimask *mask, uint32_t basis)
{
    const uint32_t *p = mask->masks.values;
    uint32_t hash;
    int i;

    hash = basis;
    for (i = 0; i < MINI_N_MAPS; i++) {
        uint32_t map;

        for (map = mask->masks.map[i]; map; map = zero_rightmost_1bit(map)) {
            int ofs = raw_ctz(map) + i * 32;

            hash = mhash_add(hash, miniflow_get(flow, ofs) & *p);
            p++;
        }
    }

    return mhash_finish(hash, p - mask->masks.values);
}

/* Returns a hash value for the bits of 'flow' where there are 1-bits in
 * 'mask', given 'basis'.
 *
 * The hash values returned by this function are the same as those returned by
 * miniflow_hash_in_minimask(), only the form of the arguments differ. */
uint32_t
flow_hash_in_minimask(const struct flow *flow, const struct minimask *mask,
                      uint32_t basis)
{
    const uint32_t *flow_u32 = (const uint32_t *) flow;
    const uint32_t *p = mask->masks.values;
    uint32_t hash;
    int i;

    hash = basis;
    for (i = 0; i < MINI_N_MAPS; i++) {
        uint32_t map;

        for (map = mask->masks.map[i]; map; map = zero_rightmost_1bit(map)) {
            int ofs = raw_ctz(map) + i * 32;

            hash = mhash_add(hash, flow_u32[ofs] & *p);
            p++;
        }
    }

    return mhash_finish(hash, p - mask->masks.values);
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with minimask_destroy(). */
void
minimask_init(struct minimask *mask, const struct flow_wildcards *wc)
{
    miniflow_init(&mask->masks, &wc->masks);
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with minimask_destroy(). */
void
minimask_clone(struct minimask *dst, const struct minimask *src)
{
    miniflow_clone(&dst->masks, &src->masks);
}

/* Initializes 'dst_' as the bit-wise "and" of 'a_' and 'b_'.
 *
 * The caller must provide room for FLOW_U32S "uint32_t"s in 'storage', for use
 * by 'dst_'.  The caller must *not* free 'dst_' with minimask_destroy(). */
void
minimask_combine(struct minimask *dst_,
                 const struct minimask *a_, const struct minimask *b_,
                 uint32_t storage[FLOW_U32S])
{
    struct miniflow *dst = &dst_->masks;
    const struct miniflow *a = &a_->masks;
    const struct miniflow *b = &b_->masks;
    int i, n;

    n = 0;
    dst->values = storage;
    for (i = 0; i < MINI_N_MAPS; i++) {
        uint32_t map;

        dst->map[i] = 0;
        for (map = a->map[i] & b->map[i]; map;
             map = zero_rightmost_1bit(map)) {
            int ofs = raw_ctz(map) + i * 32;
            uint32_t mask = miniflow_get(a, ofs) & miniflow_get(b, ofs);

            if (mask) {
                dst->map[i] |= rightmost_1bit(map);
                dst->values[n++] = mask;
            }
        }
    }
}

/* Frees any memory owned by 'mask'.  Does not free the storage in which 'mask'
 * itself resides; the caller is responsible for that. */
void
minimask_destroy(struct minimask *mask)
{
    miniflow_destroy(&mask->masks);
}

/* Initializes 'dst' as a copy of 'src'. */
void
minimask_expand(const struct minimask *mask, struct flow_wildcards *wc)
{
    miniflow_expand(&mask->masks, &wc->masks);
}

/* Returns the uint32_t that would be at byte offset '4 * u32_ofs' if 'mask'
 * were expanded into a "struct flow_wildcards". */
uint32_t
minimask_get(const struct minimask *mask, unsigned int u32_ofs)
{
    return miniflow_get(&mask->masks, u32_ofs);
}

/* Returns the VID mask within the vlan_tci member of the "struct
 * flow_wildcards" represented by 'mask'. */
uint16_t
minimask_get_vid_mask(const struct minimask *mask)
{
    return miniflow_get_vid(&mask->masks);
}

/* Returns true if 'a' and 'b' are the same flow mask, false otherwise.  */
bool
minimask_equal(const struct minimask *a, const struct minimask *b)
{
    return miniflow_equal(&a->masks, &b->masks);
}

/* Returns a hash value for 'mask', given 'basis'. */
uint32_t
minimask_hash(const struct minimask *mask, uint32_t basis)
{
    return miniflow_hash(&mask->masks, basis);
}

/* Returns true if at least one bit is wildcarded in 'a_' but not in 'b_',
 * false otherwise. */
bool
minimask_has_extra(const struct minimask *a_, const struct minimask *b_)
{
    const struct miniflow *a = &a_->masks;
    const struct miniflow *b = &b_->masks;
    int i;

    for (i = 0; i < MINI_N_MAPS; i++) {
        uint32_t map;

        for (map = a->map[i] | b->map[i]; map;
             map = zero_rightmost_1bit(map)) {
            int ofs = raw_ctz(map) + i * 32;
            uint32_t a_u32 = miniflow_get(a, ofs);
            uint32_t b_u32 = miniflow_get(b, ofs);

            if ((a_u32 & b_u32) != b_u32) {
                return true;
            }
        }
    }

    return false;
}

/* Returns true if 'mask' matches every packet, false if 'mask' fixes any bits
 * or fields. */
bool
minimask_is_catchall(const struct minimask *mask_)
{
    const struct miniflow *mask = &mask_->masks;

    BUILD_ASSERT(MINI_N_MAPS == 2);
    return !(mask->map[0] | mask->map[1]);
}
