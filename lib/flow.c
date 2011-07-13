/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>
#include "byte-order.h"
#include "coverage.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "hash.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "packets.h"
#include "unaligned.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(flow);

COVERAGE_DEFINE(flow_extract);

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
    const struct ip6_hdr *nh;
    ovs_be32 tc_flow;
    int nexthdr;

    nh = ofpbuf_try_pull(packet, sizeof *nh);
    if (!nh) {
        return EINVAL;
    }

    nexthdr = nh->ip6_nxt;

    flow->ipv6_src = nh->ip6_src;
    flow->ipv6_dst = nh->ip6_dst;

    tc_flow = get_unaligned_be32(&nh->ip6_flow);
    flow->nw_tos = (ntohl(tc_flow) >> 4) & IP_DSCP_MASK;
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
            const struct ip6_ext *ext_hdr = (struct ip6_ext *)packet->data;
            nexthdr = ext_hdr->ip6e_nxt;
            if (!ofpbuf_try_pull(packet, (ext_hdr->ip6e_len + 1) * 8)) {
                return EINVAL;
            }
        } else if (nexthdr == IPPROTO_AH) {
            /* A standard AH definition isn't available, but the fields
             * we care about are in the same location as the generic
             * option header--only the header length is calculated
             * differently. */
            const struct ip6_ext *ext_hdr = (struct ip6_ext *)packet->data;
            nexthdr = ext_hdr->ip6e_nxt;
            if (!ofpbuf_try_pull(packet, (ext_hdr->ip6e_len + 2) * 4)) {
               return EINVAL;
            }
        } else if (nexthdr == IPPROTO_FRAGMENT) {
            const struct ip6_frag *frag_hdr = (struct ip6_frag *)packet->data;

            nexthdr = frag_hdr->ip6f_nxt;
            if (!ofpbuf_try_pull(packet, sizeof *frag_hdr)) {
                return EINVAL;
            }

            /* We only process the first fragment. */
            if ((frag_hdr->ip6f_offlg & IP6F_OFF_MASK) != htons(0)) {
                nexthdr = IPPROTO_FRAGMENT;
                break;
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
    flow->icmp_type = htons(icmp->icmp6_type);
    flow->icmp_code = htons(icmp->icmp6_code);

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

/* Initializes 'flow' members from 'packet', 'tun_id', and 'ofp_in_port'.
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
int
flow_extract(struct ofpbuf *packet, ovs_be64 tun_id, uint16_t ofp_in_port,
             struct flow *flow)
{
    struct ofpbuf b = *packet;
    struct eth_header *eth;
    int retval = 0;

    COVERAGE_INC(flow_extract);

    memset(flow, 0, sizeof *flow);
    flow->tun_id = tun_id;
    flow->in_port = ofp_in_port;

    packet->l2 = b.data;
    packet->l3 = NULL;
    packet->l4 = NULL;
    packet->l7 = NULL;

    if (b.size < sizeof *eth) {
        return 0;
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
            flow->nw_src = get_unaligned_be32(&nh->ip_src);
            flow->nw_dst = get_unaligned_be32(&nh->ip_dst);
            flow->nw_tos = nh->ip_tos & IP_DSCP_MASK;
            flow->nw_proto = nh->ip_proto;
            packet->l4 = b.data;
            if (!IP_IS_FRAGMENT(nh->ip_frag_off)) {
                if (flow->nw_proto == IPPROTO_TCP) {
                    parse_tcp(packet, &b, flow);
                } else if (flow->nw_proto == IPPROTO_UDP) {
                    parse_udp(packet, &b, flow);
                } else if (flow->nw_proto == IPPROTO_ICMP) {
                    const struct icmp_header *icmp = pull_icmp(&b);
                    if (icmp) {
                        flow->icmp_type = htons(icmp->icmp_type);
                        flow->icmp_code = htons(icmp->icmp_code);
                        packet->l7 = b.data;
                    }
                }
            } else {
                retval = 1;
            }
        }
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {

        retval = parse_ipv6(&b, flow);
        if (retval) {
            return 0;
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
    } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
        const struct arp_eth_header *arp = pull_arp(&b);
        if (arp && arp->ar_hrd == htons(1)
            && arp->ar_pro == htons(ETH_TYPE_IP)
            && arp->ar_hln == ETH_ADDR_LEN
            && arp->ar_pln == 4) {
            /* We only match on the lower 8 bits of the opcode. */
            if (ntohs(arp->ar_op) <= 0xff) {
                flow->nw_proto = ntohs(arp->ar_op);
            }

            if ((flow->nw_proto == ARP_OP_REQUEST)
                || (flow->nw_proto == ARP_OP_REPLY)) {
                flow->nw_src = arp->ar_spa;
                flow->nw_dst = arp->ar_tpa;
                memcpy(flow->arp_sha, arp->ar_sha, ETH_ADDR_LEN);
                memcpy(flow->arp_tha, arp->ar_tha, ETH_ADDR_LEN);
            }
        }
    }

    return retval;
}

/* Extracts the flow stats for a packet.  The 'flow' and 'packet'
 * arguments must have been initialized through a call to flow_extract().
 */
void
flow_extract_stats(const struct flow *flow, struct ofpbuf *packet,
                   struct dpif_flow_stats *stats)
{
    memset(stats, 0, sizeof(*stats));

    if ((flow->dl_type == htons(ETH_TYPE_IP)) && packet->l4) {
        if ((flow->nw_proto == IPPROTO_TCP) && packet->l7) {
            struct tcp_header *tcp = packet->l4;
            stats->tcp_flags = TCP_FLAGS(tcp->tcp_ctl);
        }
    }

    stats->n_bytes = packet->size;
    stats->n_packets = 1;
}

char *
flow_to_string(const struct flow *flow)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    flow_format(&ds, flow);
    return ds_cstr(&ds);
}

void
flow_format(struct ds *ds, const struct flow *flow)
{
    ds_put_format(ds, "tunnel%#"PRIx64":in_port%04"PRIx16":tci(",
                  ntohll(flow->tun_id), flow->in_port);
    if (flow->vlan_tci) {
        ds_put_format(ds, "vlan%"PRIu16",pcp%d",
                      vlan_tci_to_vid(flow->vlan_tci),
                      vlan_tci_to_pcp(flow->vlan_tci));
    } else {
        ds_put_char(ds, '0');
    }
    ds_put_format(ds, ") mac"ETH_ADDR_FMT"->"ETH_ADDR_FMT
                      " type%04"PRIx16,
                  ETH_ADDR_ARGS(flow->dl_src),
                  ETH_ADDR_ARGS(flow->dl_dst),
                  ntohs(flow->dl_type));

    if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        ds_put_format(ds, " proto%"PRIu8" tos%"PRIu8" ipv6",
                      flow->nw_proto, flow->nw_tos);
        print_ipv6_addr(ds, &flow->ipv6_src);
        ds_put_cstr(ds, "->");
        print_ipv6_addr(ds, &flow->ipv6_dst);
       
    } else {
        ds_put_format(ds, " proto%"PRIu8
                          " tos%"PRIu8
                          " ip"IP_FMT"->"IP_FMT,
                      flow->nw_proto,
                      flow->nw_tos,
                      IP_ARGS(&flow->nw_src),
                      IP_ARGS(&flow->nw_dst));
    }
    if (flow->tp_src || flow->tp_dst) {
        ds_put_format(ds, " port%"PRIu16"->%"PRIu16,
                ntohs(flow->tp_src), ntohs(flow->tp_dst));
    }
    if (!eth_addr_is_zero(flow->arp_sha) || !eth_addr_is_zero(flow->arp_tha)) {
        ds_put_format(ds, " arp_ha"ETH_ADDR_FMT"->"ETH_ADDR_FMT,
                ETH_ADDR_ARGS(flow->arp_sha),
                ETH_ADDR_ARGS(flow->arp_tha));
    }
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
    wc->wildcards = FWW_ALL;
    wc->tun_id_mask = htonll(0);
    wc->nw_src_mask = htonl(0);
    wc->nw_dst_mask = htonl(0);
    wc->ipv6_src_mask = in6addr_any;
    wc->ipv6_dst_mask = in6addr_any;
    memset(wc->reg_masks, 0, sizeof wc->reg_masks);
    wc->vlan_tci_mask = htons(0);
    wc->zero = 0;
}

/* Initializes 'wc' as an exact-match set of wildcards; that is, 'wc' does not
 * wildcard any bits or fields. */
void
flow_wildcards_init_exact(struct flow_wildcards *wc)
{
    wc->wildcards = 0;
    wc->tun_id_mask = htonll(UINT64_MAX);
    wc->nw_src_mask = htonl(UINT32_MAX);
    wc->nw_dst_mask = htonl(UINT32_MAX);
    wc->ipv6_src_mask = in6addr_exact;
    wc->ipv6_dst_mask = in6addr_exact;
    memset(wc->reg_masks, 0xff, sizeof wc->reg_masks);
    wc->vlan_tci_mask = htons(UINT16_MAX);
    wc->zero = 0;
}

/* Returns true if 'wc' is exact-match, false if 'wc' wildcards any bits or
 * fields. */
bool
flow_wildcards_is_exact(const struct flow_wildcards *wc)
{
    int i;

    if (wc->wildcards
        || wc->tun_id_mask != htonll(UINT64_MAX)
        || wc->nw_src_mask != htonl(UINT32_MAX)
        || wc->nw_dst_mask != htonl(UINT32_MAX)
        || wc->vlan_tci_mask != htons(UINT16_MAX)
        || !ipv6_mask_is_exact(&wc->ipv6_src_mask)
        || !ipv6_mask_is_exact(&wc->ipv6_dst_mask)) {
        return false;
    }

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (wc->reg_masks[i] != UINT32_MAX) {
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
    int i;

    dst->wildcards = src1->wildcards | src2->wildcards;
    dst->tun_id_mask = src1->tun_id_mask & src2->tun_id_mask;
    dst->nw_src_mask = src1->nw_src_mask & src2->nw_src_mask;
    dst->nw_dst_mask = src1->nw_dst_mask & src2->nw_dst_mask;
    dst->ipv6_src_mask = ipv6_addr_bitand(&src1->ipv6_src_mask,
                                        &src2->ipv6_src_mask);
    dst->ipv6_dst_mask = ipv6_addr_bitand(&src1->ipv6_dst_mask,
                                        &src2->ipv6_dst_mask);
    for (i = 0; i < FLOW_N_REGS; i++) {
        dst->reg_masks[i] = src1->reg_masks[i] & src2->reg_masks[i];
    }
    dst->vlan_tci_mask = src1->vlan_tci_mask & src2->vlan_tci_mask;
}

/* Returns a hash of the wildcards in 'wc'. */
uint32_t
flow_wildcards_hash(const struct flow_wildcards *wc, uint32_t basis)
{
    /* If you change struct flow_wildcards and thereby trigger this
     * assertion, please check that the new struct flow_wildcards has no holes
     * in it before you update the assertion. */
    BUILD_ASSERT_DECL(sizeof *wc == 56 + FLOW_N_REGS * 4);
    return hash_bytes(wc, sizeof *wc, basis);
}

/* Returns true if 'a' and 'b' represent the same wildcards, false if they are
 * different. */
bool
flow_wildcards_equal(const struct flow_wildcards *a,
                     const struct flow_wildcards *b)
{
    int i;

    if (a->wildcards != b->wildcards
        || a->tun_id_mask != b->tun_id_mask
        || a->nw_src_mask != b->nw_src_mask
        || a->nw_dst_mask != b->nw_dst_mask
        || a->vlan_tci_mask != b->vlan_tci_mask 
        || !ipv6_addr_equals(&a->ipv6_src_mask, &b->ipv6_src_mask)
        || !ipv6_addr_equals(&a->ipv6_dst_mask, &b->ipv6_dst_mask)) {
        return false;
    }

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (a->reg_masks[i] != b->reg_masks[i]) {
            return false;
        }
    }

    return true;
}

/* Returns true if at least one bit or field is wildcarded in 'a' but not in
 * 'b', false otherwise. */
bool
flow_wildcards_has_extra(const struct flow_wildcards *a,
                         const struct flow_wildcards *b)
{
    int i;
    struct in6_addr ipv6_masked;

    for (i = 0; i < FLOW_N_REGS; i++) {
        if ((a->reg_masks[i] & b->reg_masks[i]) != b->reg_masks[i]) {
            return true;
        }
    }

    ipv6_masked = ipv6_addr_bitand(&a->ipv6_src_mask, &b->ipv6_src_mask);
    if (!ipv6_addr_equals(&ipv6_masked, &b->ipv6_src_mask)) {
        return true;
    }

    ipv6_masked = ipv6_addr_bitand(&a->ipv6_dst_mask, &b->ipv6_dst_mask);
    if (!ipv6_addr_equals(&ipv6_masked, &b->ipv6_dst_mask)) {
        return true;
    }

    return (a->wildcards & ~b->wildcards
            || (a->tun_id_mask & b->tun_id_mask) != b->tun_id_mask
            || (a->nw_src_mask & b->nw_src_mask) != b->nw_src_mask
            || (a->nw_dst_mask & b->nw_dst_mask) != b->nw_dst_mask
            || (a->vlan_tci_mask & b->vlan_tci_mask) != b->vlan_tci_mask);
}

static bool
set_nw_mask(ovs_be32 *maskp, ovs_be32 mask)
{
    if (ip_is_cidr(mask)) {
        *maskp = mask;
        return true;
    } else {
        return false;
    }
}

/* Sets the IP (or ARP) source wildcard mask to CIDR 'mask' (consisting of N
 * high-order 1-bit and 32-N low-order 0-bits).  Returns true if successful,
 * false if 'mask' is not a CIDR mask.  */
bool
flow_wildcards_set_nw_src_mask(struct flow_wildcards *wc, ovs_be32 mask)
{
    return set_nw_mask(&wc->nw_src_mask, mask);
}

/* Sets the IP (or ARP) destination wildcard mask to CIDR 'mask' (consisting of
 * N high-order 1-bit and 32-N low-order 0-bits).  Returns true if successful,
 * false if 'mask' is not a CIDR mask.  */
bool
flow_wildcards_set_nw_dst_mask(struct flow_wildcards *wc, ovs_be32 mask)
{
    return set_nw_mask(&wc->nw_dst_mask, mask);
}

static bool
set_ipv6_mask(struct in6_addr *maskp, const struct in6_addr *mask)
{
    if (ipv6_is_cidr(mask)) {
        *maskp = *mask;
        return true;
    } else {
        return false;
    }
}

/* Sets the IPv6 source wildcard mask to CIDR 'mask' (consisting of N
 * high-order 1-bit and 128-N low-order 0-bits).  Returns true if successful,
 * false if 'mask' is not a CIDR mask.  */
bool
flow_wildcards_set_ipv6_src_mask(struct flow_wildcards *wc,
                                 const struct in6_addr *mask)
{
    return set_ipv6_mask(&wc->ipv6_src_mask, mask);
}

/* Sets the IPv6 destination wildcard mask to CIDR 'mask' (consisting of
 * N high-order 1-bit and 128-N low-order 0-bits).  Returns true if
 * successful, false if 'mask' is not a CIDR mask.  */
bool
flow_wildcards_set_ipv6_dst_mask(struct flow_wildcards *wc,
                                 const struct in6_addr *mask)
{
    return set_ipv6_mask(&wc->ipv6_dst_mask, mask);
}

/* Sets the wildcard mask for register 'idx' in 'wc' to 'mask'.
 * (A 0-bit indicates a wildcard bit.) */
void
flow_wildcards_set_reg_mask(struct flow_wildcards *wc, int idx, uint32_t mask)
{
    wc->reg_masks[idx] = mask;
}

/* Returns the wildcard bitmask for the Ethernet destination address
 * that 'wc' specifies.  The bitmask has a 0 in each bit that is wildcarded
 * and a 1 in each bit that must match.  */
const uint8_t *
flow_wildcards_to_dl_dst_mask(flow_wildcards_t wc)
{
    static const uint8_t    no_wild[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const uint8_t  addr_wild[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t mcast_wild[] = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const uint8_t   all_wild[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    switch (wc & (FWW_DL_DST | FWW_ETH_MCAST)) {
    case 0:                             return no_wild;
    case FWW_DL_DST:                    return addr_wild;
    case FWW_ETH_MCAST:                 return mcast_wild;
    case FWW_DL_DST | FWW_ETH_MCAST:    return all_wild;
    }
    NOT_REACHED();
}

/* Returns true if 'mask' is a valid wildcard bitmask for the Ethernet
 * destination address.  Valid bitmasks are either all-bits-0 or all-bits-1,
 * except that the multicast bit may differ from the rest of the bits.  So,
 * there are four possible valid bitmasks:
 *
 *  - 00:00:00:00:00:00
 *  - 01:00:00:00:00:00
 *  - fe:ff:ff:ff:ff:ff
 *  - ff:ff:ff:ff:ff:ff
 *
 * All other bitmasks are invalid. */
bool
flow_wildcards_is_dl_dst_mask_valid(const uint8_t mask[ETH_ADDR_LEN])
{
    switch (mask[0]) {
    case 0x00:
    case 0x01:
        return (mask[1] | mask[2] | mask[3] | mask[4] | mask[5]) == 0x00;

    case 0xfe:
    case 0xff:
        return (mask[1] & mask[2] & mask[3] & mask[4] & mask[5]) == 0xff;

    default:
        return false;
    }
}

/* Returns 'wc' with the FWW_DL_DST and FWW_ETH_MCAST bits modified
 * appropriately to match 'mask'.
 *
 * This function will assert-fail if 'mask' is invalid.  Only 'mask' values
 * accepted by flow_wildcards_is_dl_dst_mask_valid() are allowed. */
flow_wildcards_t
flow_wildcards_set_dl_dst_mask(flow_wildcards_t wc,
                               const uint8_t mask[ETH_ADDR_LEN])
{
    assert(flow_wildcards_is_dl_dst_mask_valid(mask));

    switch (mask[0]) {
    case 0x00:
        return wc | FWW_DL_DST | FWW_ETH_MCAST;

    case 0x01:
        return (wc | FWW_DL_DST) & ~FWW_ETH_MCAST;

    case 0xfe:
        return (wc & ~FWW_DL_DST) | FWW_ETH_MCAST;

    case 0xff:
        return wc & ~(FWW_DL_DST | FWW_ETH_MCAST);

    default:
        NOT_REACHED();
    }
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
        ovs_be16 tp_addr;
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
            fields.tp_addr = flow->tp_src ^ flow->tp_dst;
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
            fields.tp_addr = flow->tp_src ^ flow->tp_dst;
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
