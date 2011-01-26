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
#include <inttypes.h>
#include <netinet/in.h>
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

/* Initializes 'flow' members from 'packet', 'tun_id', and 'in_port.
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
flow_extract(struct ofpbuf *packet, ovs_be64 tun_id, uint16_t in_port,
             struct flow *flow)
{
    struct ofpbuf b = *packet;
    struct eth_header *eth;
    int retval = 0;

    COVERAGE_INC(flow_extract);

    memset(flow, 0, sizeof *flow);
    flow->tun_id = tun_id;
    flow->in_port = in_port;

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
                if (flow->nw_proto == IP_TYPE_TCP) {
                    const struct tcp_header *tcp = pull_tcp(&b);
                    if (tcp) {
                        flow->tp_src = tcp->tcp_src;
                        flow->tp_dst = tcp->tcp_dst;
                        packet->l7 = b.data;
                    }
                } else if (flow->nw_proto == IP_TYPE_UDP) {
                    const struct udp_header *udp = pull_udp(&b);
                    if (udp) {
                        flow->tp_src = udp->udp_src;
                        flow->tp_dst = udp->udp_dst;
                        packet->l7 = b.data;
                    }
                } else if (flow->nw_proto == IP_TYPE_ICMP) {
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
        if ((flow->nw_proto == IP_TYPE_TCP) && packet->l7) {
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
                  flow->tun_id, flow->in_port);
    if (flow->vlan_tci) {
        ds_put_format(ds, "vlan%"PRIu16",pcp%d",
                      vlan_tci_to_vid(flow->vlan_tci),
                      vlan_tci_to_pcp(flow->vlan_tci));
    } else {
        ds_put_char(ds, '0');
    }
    ds_put_format(ds, ") mac"ETH_ADDR_FMT"->"ETH_ADDR_FMT
                      " type%04"PRIx16
                      " proto%"PRIu8
                      " tos%"PRIu8
                      " ip"IP_FMT"->"IP_FMT
                      " port%"PRIu16"->%"PRIu16,
                  ETH_ADDR_ARGS(flow->dl_src),
                  ETH_ADDR_ARGS(flow->dl_dst),
                  ntohs(flow->dl_type),
                  flow->nw_proto,
                  flow->nw_tos,
                  IP_ARGS(&flow->nw_src),
                  IP_ARGS(&flow->nw_dst),
                  ntohs(flow->tp_src),
                  ntohs(flow->tp_dst));
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
        || wc->vlan_tci_mask != htons(UINT16_MAX)) {
        return false;
    }

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (wc->reg_masks[i] != htonl(UINT32_MAX)) {
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
    for (i = 0; i < FLOW_N_REGS; i++) {
        dst->reg_masks[i] = src1->reg_masks[i] & src2->reg_masks[i];
    }
    dst->vlan_tci_mask = src1->vlan_tci_mask & src2->vlan_tci_mask;
}

/* Returns a hash of the wildcards in 'wc'. */
uint32_t
flow_wildcards_hash(const struct flow_wildcards *wc)
{
    /* If you change struct flow_wildcards and thereby trigger this
     * assertion, please check that the new struct flow_wildcards has no holes
     * in it before you update the assertion. */
    BUILD_ASSERT_DECL(sizeof *wc == 24 + FLOW_N_REGS * 4);
    return hash_bytes(wc, sizeof *wc, 0);
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
        || a->vlan_tci_mask != b->vlan_tci_mask) {
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

    for (i = 0; i < FLOW_N_REGS; i++) {
        if ((a->reg_masks[i] & b->reg_masks[i]) != b->reg_masks[i]) {
            return true;
        }
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

/* Sets the wildcard mask for register 'idx' in 'wc' to 'mask'.
 * (A 0-bit indicates a wildcard bit.) */
void
flow_wildcards_set_reg_mask(struct flow_wildcards *wc, int idx, uint32_t mask)
{
    wc->reg_masks[idx] = mask;
}
