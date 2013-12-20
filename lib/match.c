/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "match.h"
#include <stdlib.h>
#include "byte-order.h"
#include "dynamic-string.h"
#include "ofp-util.h"
#include "packets.h"

/* Converts the flow in 'flow' into a match in 'match', with the given
 * 'wildcards'. */
void
match_init(struct match *match,
           const struct flow *flow, const struct flow_wildcards *wc)
{
    match->flow = *flow;
    match->wc = *wc;
    match_zero_wildcarded_fields(match);
}

/* Converts a flow into a match.  It sets the wildcard masks based on
 * the packet contents.  It will not set the mask for fields that do not
 * make sense for the packet type. */
void
match_wc_init(struct match *match, const struct flow *flow)
{
    struct flow_wildcards *wc;
    int i;

    match->flow = *flow;
    wc = &match->wc;
    memset(&wc->masks, 0x0, sizeof wc->masks);

    memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);

    if (flow->nw_proto) {
        memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
    }

    if (flow->skb_priority) {
        memset(&wc->masks.skb_priority, 0xff, sizeof wc->masks.skb_priority);
    }

    if (flow->pkt_mark) {
        memset(&wc->masks.pkt_mark, 0xff, sizeof wc->masks.pkt_mark);
    }

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (flow->regs[i]) {
            memset(&wc->masks.regs[i], 0xff, sizeof wc->masks.regs[i]);
        }
    }

    if (flow->tunnel.ip_dst) {
        if (flow->tunnel.flags & FLOW_TNL_F_KEY) {
            memset(&wc->masks.tunnel.tun_id, 0xff, sizeof wc->masks.tunnel.tun_id);
        }
        memset(&wc->masks.tunnel.ip_src, 0xff, sizeof wc->masks.tunnel.ip_src);
        memset(&wc->masks.tunnel.ip_dst, 0xff, sizeof wc->masks.tunnel.ip_dst);
        memset(&wc->masks.tunnel.flags, 0xff, sizeof wc->masks.tunnel.flags);
        memset(&wc->masks.tunnel.ip_tos, 0xff, sizeof wc->masks.tunnel.ip_tos);
        memset(&wc->masks.tunnel.ip_ttl, 0xff, sizeof wc->masks.tunnel.ip_ttl);
    } else if (flow->tunnel.tun_id) {
        memset(&wc->masks.tunnel.tun_id, 0xff, sizeof wc->masks.tunnel.tun_id);
    }

    memset(&wc->masks.metadata, 0xff, sizeof wc->masks.metadata);
    memset(&wc->masks.in_port, 0xff, sizeof wc->masks.in_port);
    memset(&wc->masks.vlan_tci, 0xff, sizeof wc->masks.vlan_tci);
    memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);

    if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
        memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
        memset(&wc->masks.ipv6_label, 0xff, sizeof wc->masks.ipv6_label);
    } else if (flow->dl_type == htons(ETH_TYPE_IP) ||
               (flow->dl_type == htons(ETH_TYPE_ARP)) ||
               (flow->dl_type == htons(ETH_TYPE_RARP))) {
        memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
        memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
    } else if (eth_type_mpls(flow->dl_type)) {
        memset(&wc->masks.mpls_lse, 0xff, sizeof wc->masks.mpls_lse);
    }

    if (flow->dl_type == htons(ETH_TYPE_ARP) ||
        flow->dl_type == htons(ETH_TYPE_RARP)) {
        memset(&wc->masks.arp_sha, 0xff, sizeof wc->masks.arp_sha);
        memset(&wc->masks.arp_tha, 0xff, sizeof wc->masks.arp_tha);
    }

    if (is_ip_any(flow)) {
        memset(&wc->masks.nw_tos, 0xff, sizeof wc->masks.nw_tos);
        memset(&wc->masks.nw_ttl, 0xff, sizeof wc->masks.nw_ttl);

        if (flow->nw_frag) {
            memset(&wc->masks.nw_frag, 0xff, sizeof wc->masks.nw_frag);
            if (flow->nw_frag & FLOW_NW_FRAG_LATER) {
                /* No transport layer header in later fragments. */
                return;
            }
        }

        if (flow->nw_proto == IPPROTO_ICMP ||
            flow->nw_proto == IPPROTO_ICMPV6 ||
            (flow->tp_src || flow->tp_dst)) {
            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
            memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
        }
        if (flow->nw_proto == IPPROTO_TCP) {
            memset(&wc->masks.tcp_flags, 0xff, sizeof wc->masks.tcp_flags);
        }

        if (flow->nw_proto == IPPROTO_ICMPV6) {
            memset(&wc->masks.arp_sha, 0xff, sizeof wc->masks.arp_sha);
            memset(&wc->masks.arp_tha, 0xff, sizeof wc->masks.arp_tha);
        }
    }

    return;
}

/* Initializes 'match' as a "catch-all" match that matches every packet. */
void
match_init_catchall(struct match *match)
{
    memset(&match->flow, 0, sizeof match->flow);
    flow_wildcards_init_catchall(&match->wc);
}

/* For each bit or field wildcarded in 'match', sets the corresponding bit or
 * field in 'flow' to all-0-bits.  It is important to maintain this invariant
 * in a match that might be inserted into a classifier.
 *
 * It is never necessary to call this function directly for a match that is
 * initialized or modified only by match_*() functions.  It is useful to
 * restore the invariant in a match whose 'wc' member is modified by hand.
 */
void
match_zero_wildcarded_fields(struct match *match)
{
    flow_zero_wildcards(&match->flow, &match->wc);
}

void
match_set_reg(struct match *match, unsigned int reg_idx, uint32_t value)
{
    match_set_reg_masked(match, reg_idx, value, UINT32_MAX);
}

void
match_set_reg_masked(struct match *match, unsigned int reg_idx,
                     uint32_t value, uint32_t mask)
{
    ovs_assert(reg_idx < FLOW_N_REGS);
    flow_wildcards_set_reg_mask(&match->wc, reg_idx, mask);
    match->flow.regs[reg_idx] = value & mask;
}

void
match_set_metadata(struct match *match, ovs_be64 metadata)
{
    match_set_metadata_masked(match, metadata, OVS_BE64_MAX);
}

void
match_set_metadata_masked(struct match *match,
                          ovs_be64 metadata, ovs_be64 mask)
{
    match->wc.masks.metadata = mask;
    match->flow.metadata = metadata & mask;
}

void
match_set_tun_id(struct match *match, ovs_be64 tun_id)
{
    match_set_tun_id_masked(match, tun_id, OVS_BE64_MAX);
}

void
match_set_tun_id_masked(struct match *match, ovs_be64 tun_id, ovs_be64 mask)
{
    match->wc.masks.tunnel.tun_id = mask;
    match->flow.tunnel.tun_id = tun_id & mask;
}

void
match_set_tun_src(struct match *match, ovs_be32 src)
{
    match_set_tun_src_masked(match, src, OVS_BE32_MAX);
}

void
match_set_tun_src_masked(struct match *match, ovs_be32 src, ovs_be32 mask)
{
    match->wc.masks.tunnel.ip_src = mask;
    match->flow.tunnel.ip_src = src & mask;
}

void
match_set_tun_dst(struct match *match, ovs_be32 dst)
{
    match_set_tun_dst_masked(match, dst, OVS_BE32_MAX);
}

void
match_set_tun_dst_masked(struct match *match, ovs_be32 dst, ovs_be32 mask)
{
    match->wc.masks.tunnel.ip_dst = mask;
    match->flow.tunnel.ip_dst = dst & mask;
}

void
match_set_tun_ttl(struct match *match, uint8_t ttl)
{
    match_set_tun_ttl_masked(match, ttl, UINT8_MAX);
}

void
match_set_tun_ttl_masked(struct match *match, uint8_t ttl, uint8_t mask)
{
    match->wc.masks.tunnel.ip_ttl = mask;
    match->flow.tunnel.ip_ttl = ttl & mask;
}

void
match_set_tun_tos(struct match *match, uint8_t tos)
{
    match_set_tun_tos_masked(match, tos, UINT8_MAX);
}

void
match_set_tun_tos_masked(struct match *match, uint8_t tos, uint8_t mask)
{
    match->wc.masks.tunnel.ip_tos = mask;
    match->flow.tunnel.ip_tos = tos & mask;
}

void
match_set_tun_flags(struct match *match, uint16_t flags)
{
    match_set_tun_flags_masked(match, flags, UINT16_MAX);
}

void
match_set_tun_flags_masked(struct match *match, uint16_t flags, uint16_t mask)
{
    match->wc.masks.tunnel.flags = mask;
    match->flow.tunnel.flags = flags & mask;
}

void
match_set_in_port(struct match *match, ofp_port_t ofp_port)
{
    match->wc.masks.in_port.ofp_port = u16_to_ofp(UINT16_MAX);
    match->flow.in_port.ofp_port = ofp_port;
}

void
match_set_skb_priority(struct match *match, uint32_t skb_priority)
{
    match->wc.masks.skb_priority = UINT32_MAX;
    match->flow.skb_priority = skb_priority;
}

void
match_set_pkt_mark(struct match *match, uint32_t pkt_mark)
{
    match_set_pkt_mark_masked(match, pkt_mark, UINT32_MAX);
}

void
match_set_pkt_mark_masked(struct match *match, uint32_t pkt_mark, uint32_t mask)
{
    match->flow.pkt_mark = pkt_mark & mask;
    match->wc.masks.pkt_mark = mask;
}

void
match_set_dl_type(struct match *match, ovs_be16 dl_type)
{
    match->wc.masks.dl_type = OVS_BE16_MAX;
    match->flow.dl_type = dl_type;
}

/* Modifies 'value_src' so that the Ethernet address must match 'value_dst'
 * exactly.  'mask_dst' is set to all 1s. */
static void
set_eth(const uint8_t value_src[ETH_ADDR_LEN],
        uint8_t value_dst[ETH_ADDR_LEN],
        uint8_t mask_dst[ETH_ADDR_LEN])
{
    memcpy(value_dst, value_src, ETH_ADDR_LEN);
    memset(mask_dst, 0xff, ETH_ADDR_LEN);
}

/* Modifies 'value_src' so that the Ethernet address must match 'value_src'
 * after each byte is ANDed with the appropriate byte in 'mask_src'.
 * 'mask_dst' is set to 'mask_src' */
static void
set_eth_masked(const uint8_t value_src[ETH_ADDR_LEN],
               const uint8_t mask_src[ETH_ADDR_LEN],
               uint8_t value_dst[ETH_ADDR_LEN],
               uint8_t mask_dst[ETH_ADDR_LEN])
{
    size_t i;

    for (i = 0; i < ETH_ADDR_LEN; i++) {
        value_dst[i] = value_src[i] & mask_src[i];
        mask_dst[i] = mask_src[i];
    }
}

/* Modifies 'rule' so that the source Ethernet address must match 'dl_src'
 * exactly. */
void
match_set_dl_src(struct match *match, const uint8_t dl_src[ETH_ADDR_LEN])
{
    set_eth(dl_src, match->flow.dl_src, match->wc.masks.dl_src);
}

/* Modifies 'rule' so that the source Ethernet address must match 'dl_src'
 * after each byte is ANDed with the appropriate byte in 'mask'. */
void
match_set_dl_src_masked(struct match *match,
                        const uint8_t dl_src[ETH_ADDR_LEN],
                        const uint8_t mask[ETH_ADDR_LEN])
{
    set_eth_masked(dl_src, mask, match->flow.dl_src, match->wc.masks.dl_src);
}

/* Modifies 'match' so that the Ethernet address must match 'dl_dst'
 * exactly. */
void
match_set_dl_dst(struct match *match, const uint8_t dl_dst[ETH_ADDR_LEN])
{
    set_eth(dl_dst, match->flow.dl_dst, match->wc.masks.dl_dst);
}

/* Modifies 'match' so that the Ethernet address must match 'dl_dst' after each
 * byte is ANDed with the appropriate byte in 'mask'.
 *
 * This function will assert-fail if 'mask' is invalid.  Only 'mask' values
 * accepted by flow_wildcards_is_dl_dst_mask_valid() are allowed. */
void
match_set_dl_dst_masked(struct match *match,
                        const uint8_t dl_dst[ETH_ADDR_LEN],
                        const uint8_t mask[ETH_ADDR_LEN])
{
    set_eth_masked(dl_dst, mask, match->flow.dl_dst, match->wc.masks.dl_dst);
}

void
match_set_dl_tci(struct match *match, ovs_be16 tci)
{
    match_set_dl_tci_masked(match, tci, htons(0xffff));
}

void
match_set_dl_tci_masked(struct match *match, ovs_be16 tci, ovs_be16 mask)
{
    match->flow.vlan_tci = tci & mask;
    match->wc.masks.vlan_tci = mask;
}

/* Modifies 'match' so that the VLAN VID is wildcarded.  If the PCP is already
 * wildcarded, then 'match' will match a packet regardless of whether it has an
 * 802.1Q header or not. */
void
match_set_any_vid(struct match *match)
{
    if (match->wc.masks.vlan_tci & htons(VLAN_PCP_MASK)) {
        match->wc.masks.vlan_tci &= ~htons(VLAN_VID_MASK);
        match->flow.vlan_tci &= ~htons(VLAN_VID_MASK);
    } else {
        match_set_dl_tci_masked(match, htons(0), htons(0));
    }
}

/* Modifies 'match' depending on 'dl_vlan':
 *
 *   - If 'dl_vlan' is htons(OFP_VLAN_NONE), makes 'match' match only packets
 *     without an 802.1Q header.
 *
 *   - Otherwise, makes 'match' match only packets with an 802.1Q header whose
 *     VID equals the low 12 bits of 'dl_vlan'.
 */
void
match_set_dl_vlan(struct match *match, ovs_be16 dl_vlan)
{
    flow_set_dl_vlan(&match->flow, dl_vlan);
    if (dl_vlan == htons(OFP10_VLAN_NONE)) {
        match->wc.masks.vlan_tci = OVS_BE16_MAX;
    } else {
        match->wc.masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
    }
}

/* Sets the VLAN VID that 'match' matches to 'vid', which is interpreted as an
 * OpenFlow 1.2 "vlan_vid" value, that is, the low 13 bits of 'vlan_tci' (VID
 * plus CFI). */
void
match_set_vlan_vid(struct match *match, ovs_be16 vid)
{
    match_set_vlan_vid_masked(match, vid, htons(VLAN_VID_MASK | VLAN_CFI));
}


/* Sets the VLAN VID that 'flow' matches to 'vid', which is interpreted as an
 * OpenFlow 1.2 "vlan_vid" value, that is, the low 13 bits of 'vlan_tci' (VID
 * plus CFI), with the corresponding 'mask'. */
void
match_set_vlan_vid_masked(struct match *match, ovs_be16 vid, ovs_be16 mask)
{
    ovs_be16 pcp_mask = htons(VLAN_PCP_MASK);
    ovs_be16 vid_mask = htons(VLAN_VID_MASK | VLAN_CFI);

    mask &= vid_mask;
    flow_set_vlan_vid(&match->flow, vid & mask);
    match->wc.masks.vlan_tci = mask | (match->wc.masks.vlan_tci & pcp_mask);
}

/* Modifies 'match' so that the VLAN PCP is wildcarded.  If the VID is already
 * wildcarded, then 'match' will match a packet regardless of whether it has an
 * 802.1Q header or not. */
void
match_set_any_pcp(struct match *match)
{
    if (match->wc.masks.vlan_tci & htons(VLAN_VID_MASK)) {
        match->wc.masks.vlan_tci &= ~htons(VLAN_PCP_MASK);
        match->flow.vlan_tci &= ~htons(VLAN_PCP_MASK);
    } else {
        match_set_dl_tci_masked(match, htons(0), htons(0));
    }
}

/* Modifies 'match' so that it matches only packets with an 802.1Q header whose
 * PCP equals the low 3 bits of 'dl_vlan_pcp'. */
void
match_set_dl_vlan_pcp(struct match *match, uint8_t dl_vlan_pcp)
{
    flow_set_vlan_pcp(&match->flow, dl_vlan_pcp);
    match->wc.masks.vlan_tci |= htons(VLAN_CFI | VLAN_PCP_MASK);
}

/* Modifies 'match' so that the MPLS label is wildcarded. */
void
match_set_any_mpls_label(struct match *match)
{
    match->wc.masks.mpls_lse &= ~htonl(MPLS_LABEL_MASK);
    flow_set_mpls_label(&match->flow, htonl(0));
}

/* Modifies 'match' so that it matches only packets with an MPLS header whose
 * label equals the low 20 bits of 'mpls_label'. */
void
match_set_mpls_label(struct match *match, ovs_be32 mpls_label)
{
    match->wc.masks.mpls_lse |= htonl(MPLS_LABEL_MASK);
    flow_set_mpls_label(&match->flow, mpls_label);
}

/* Modifies 'match' so that the MPLS TC is wildcarded. */
void
match_set_any_mpls_tc(struct match *match)
{
    match->wc.masks.mpls_lse &= ~htonl(MPLS_TC_MASK);
    flow_set_mpls_tc(&match->flow, 0);
}

/* Modifies 'match' so that it matches only packets with an MPLS header whose
 * Traffic Class equals the low 3 bits of 'mpls_tc'. */
void
match_set_mpls_tc(struct match *match, uint8_t mpls_tc)
{
    match->wc.masks.mpls_lse |= htonl(MPLS_TC_MASK);
    flow_set_mpls_tc(&match->flow, mpls_tc);
}

/* Modifies 'match' so that the MPLS stack flag is wildcarded. */
void
match_set_any_mpls_bos(struct match *match)
{
    match->wc.masks.mpls_lse &= ~htonl(MPLS_BOS_MASK);
    flow_set_mpls_bos(&match->flow, 0);
}

/* Modifies 'match' so that it matches only packets with an MPLS header whose
 * Stack Flag equals the lower bit of 'mpls_bos' */
void
match_set_mpls_bos(struct match *match, uint8_t mpls_bos)
{
    match->wc.masks.mpls_lse |= htonl(MPLS_BOS_MASK);
    flow_set_mpls_bos(&match->flow, mpls_bos);
}

void
match_set_tp_src(struct match *match, ovs_be16 tp_src)
{
    match_set_tp_src_masked(match, tp_src, OVS_BE16_MAX);
}

void
match_set_tp_src_masked(struct match *match, ovs_be16 port, ovs_be16 mask)
{
    match->flow.tp_src = port & mask;
    match->wc.masks.tp_src = mask;
}

void
match_set_tp_dst(struct match *match, ovs_be16 tp_dst)
{
    match_set_tp_dst_masked(match, tp_dst, OVS_BE16_MAX);
}

void
match_set_tp_dst_masked(struct match *match, ovs_be16 port, ovs_be16 mask)
{
    match->flow.tp_dst = port & mask;
    match->wc.masks.tp_dst = mask;
}

void
match_set_tcp_flags(struct match *match, ovs_be16 flags)
{
    match_set_tcp_flags_masked(match, flags, OVS_BE16_MAX);
}

void
match_set_tcp_flags_masked(struct match *match, ovs_be16 flags, ovs_be16 mask)
{
    match->flow.tcp_flags = flags & mask;
    match->wc.masks.tcp_flags = mask;
}

void
match_set_nw_proto(struct match *match, uint8_t nw_proto)
{
    match->flow.nw_proto = nw_proto;
    match->wc.masks.nw_proto = UINT8_MAX;
}

void
match_set_nw_src(struct match *match, ovs_be32 nw_src)
{
    match->flow.nw_src = nw_src;
    match->wc.masks.nw_src = OVS_BE32_MAX;
}

void
match_set_nw_src_masked(struct match *match,
                        ovs_be32 nw_src, ovs_be32 mask)
{
    match->flow.nw_src = nw_src & mask;
    match->wc.masks.nw_src = mask;
}

void
match_set_nw_dst(struct match *match, ovs_be32 nw_dst)
{
    match->flow.nw_dst = nw_dst;
    match->wc.masks.nw_dst = OVS_BE32_MAX;
}

void
match_set_nw_dst_masked(struct match *match, ovs_be32 ip, ovs_be32 mask)
{
    match->flow.nw_dst = ip & mask;
    match->wc.masks.nw_dst = mask;
}

void
match_set_nw_dscp(struct match *match, uint8_t nw_dscp)
{
    match->wc.masks.nw_tos |= IP_DSCP_MASK;
    match->flow.nw_tos &= ~IP_DSCP_MASK;
    match->flow.nw_tos |= nw_dscp & IP_DSCP_MASK;
}

void
match_set_nw_ecn(struct match *match, uint8_t nw_ecn)
{
    match->wc.masks.nw_tos |= IP_ECN_MASK;
    match->flow.nw_tos &= ~IP_ECN_MASK;
    match->flow.nw_tos |= nw_ecn & IP_ECN_MASK;
}

void
match_set_nw_ttl(struct match *match, uint8_t nw_ttl)
{
    match->wc.masks.nw_ttl = UINT8_MAX;
    match->flow.nw_ttl = nw_ttl;
}

void
match_set_nw_frag(struct match *match, uint8_t nw_frag)
{
    match->wc.masks.nw_frag |= FLOW_NW_FRAG_MASK;
    match->flow.nw_frag = nw_frag;
}

void
match_set_nw_frag_masked(struct match *match,
                         uint8_t nw_frag, uint8_t mask)
{
    match->flow.nw_frag = nw_frag & mask;
    match->wc.masks.nw_frag = mask;
}

void
match_set_icmp_type(struct match *match, uint8_t icmp_type)
{
    match_set_tp_src(match, htons(icmp_type));
}

void
match_set_icmp_code(struct match *match, uint8_t icmp_code)
{
    match_set_tp_dst(match, htons(icmp_code));
}

void
match_set_arp_sha(struct match *match, const uint8_t sha[ETH_ADDR_LEN])
{
    memcpy(match->flow.arp_sha, sha, ETH_ADDR_LEN);
    memset(match->wc.masks.arp_sha, UINT8_MAX, ETH_ADDR_LEN);
}

void
match_set_arp_sha_masked(struct match *match,
                         const uint8_t arp_sha[ETH_ADDR_LEN],
                         const uint8_t mask[ETH_ADDR_LEN])
{
    set_eth_masked(arp_sha, mask,
                   match->flow.arp_sha, match->wc.masks.arp_sha);
}

void
match_set_arp_tha(struct match *match, const uint8_t tha[ETH_ADDR_LEN])
{
    memcpy(match->flow.arp_tha, tha, ETH_ADDR_LEN);
    memset(match->wc.masks.arp_tha, UINT8_MAX, ETH_ADDR_LEN);
}

void
match_set_arp_tha_masked(struct match *match,
                         const uint8_t arp_tha[ETH_ADDR_LEN],
                         const uint8_t mask[ETH_ADDR_LEN])
{
    set_eth_masked(arp_tha, mask,
                   match->flow.arp_tha, match->wc.masks.arp_tha);
}

void
match_set_ipv6_src(struct match *match, const struct in6_addr *src)
{
    match->flow.ipv6_src = *src;
    match->wc.masks.ipv6_src = in6addr_exact;
}

void
match_set_ipv6_src_masked(struct match *match, const struct in6_addr *src,
                          const struct in6_addr *mask)
{
    match->flow.ipv6_src = ipv6_addr_bitand(src, mask);
    match->wc.masks.ipv6_src = *mask;
}

void
match_set_ipv6_dst(struct match *match, const struct in6_addr *dst)
{
    match->flow.ipv6_dst = *dst;
    match->wc.masks.ipv6_dst = in6addr_exact;
}

void
match_set_ipv6_dst_masked(struct match *match, const struct in6_addr *dst,
                          const struct in6_addr *mask)
{
    match->flow.ipv6_dst = ipv6_addr_bitand(dst, mask);
    match->wc.masks.ipv6_dst = *mask;
}

void
match_set_ipv6_label(struct match *match, ovs_be32 ipv6_label)
{
    match->wc.masks.ipv6_label = OVS_BE32_MAX;
    match->flow.ipv6_label = ipv6_label;
}


void
match_set_ipv6_label_masked(struct match *match, ovs_be32 ipv6_label,
                            ovs_be32 mask)
{
    match->flow.ipv6_label = ipv6_label & mask;
    match->wc.masks.ipv6_label = mask;
}

void
match_set_nd_target(struct match *match, const struct in6_addr *target)
{
    match->flow.nd_target = *target;
    match->wc.masks.nd_target = in6addr_exact;
}

void
match_set_nd_target_masked(struct match *match,
                           const struct in6_addr *target,
                           const struct in6_addr *mask)
{
    match->flow.nd_target = ipv6_addr_bitand(target, mask);
    match->wc.masks.nd_target = *mask;
}

/* Returns true if 'a' and 'b' wildcard the same fields and have the same
 * values for fixed fields, otherwise false. */
bool
match_equal(const struct match *a, const struct match *b)
{
    return (flow_wildcards_equal(&a->wc, &b->wc)
            && flow_equal(&a->flow, &b->flow));
}

/* Returns a hash value for the flow and wildcards in 'match', starting from
 * 'basis'. */
uint32_t
match_hash(const struct match *match, uint32_t basis)
{
    return flow_wildcards_hash(&match->wc, flow_hash(&match->flow, basis));
}

static void
format_eth_masked(struct ds *s, const char *name, const uint8_t eth[6],
                  const uint8_t mask[6])
{
    if (!eth_addr_is_zero(mask)) {
        ds_put_format(s, "%s=", name);
        eth_format_masked(eth, mask, s);
        ds_put_char(s, ',');
    }
}

static void
format_ip_netmask(struct ds *s, const char *name, ovs_be32 ip,
                  ovs_be32 netmask)
{
    if (netmask) {
        ds_put_format(s, "%s=", name);
        ip_format_masked(ip, netmask, s);
        ds_put_char(s, ',');
    }
}

static void
format_ipv6_netmask(struct ds *s, const char *name,
                    const struct in6_addr *addr,
                    const struct in6_addr *netmask)
{
    if (!ipv6_mask_is_any(netmask)) {
        ds_put_format(s, "%s=", name);
        print_ipv6_masked(s, addr, netmask);
        ds_put_char(s, ',');
    }
}

static void
format_be16_masked(struct ds *s, const char *name,
                   ovs_be16 value, ovs_be16 mask)
{
    if (mask != htons(0)) {
        ds_put_format(s, "%s=", name);
        if (mask == OVS_BE16_MAX) {
            ds_put_format(s, "%"PRIu16, ntohs(value));
        } else {
            ds_put_format(s, "0x%"PRIx16"/0x%"PRIx16,
                          ntohs(value), ntohs(mask));
        }
        ds_put_char(s, ',');
    }
}

static void
format_uint32_masked(struct ds *s, const char *name,
                   uint32_t value, uint32_t mask)
{
    if (mask) {
        ds_put_format(s, "%s=%#"PRIx32, name, value);
        if (mask != UINT32_MAX) {
            ds_put_format(s, "/%#"PRIx32, mask);
        }
        ds_put_char(s, ',');
    }
}

static void
format_be64_masked(struct ds *s, const char *name,
                   ovs_be64 value, ovs_be64 mask)
{
    if (mask != htonll(0)) {
        ds_put_format(s, "%s=%#"PRIx64, name, ntohll(value));
        if (mask != OVS_BE64_MAX) {
            ds_put_format(s, "/%#"PRIx64, ntohll(mask));
        }
        ds_put_char(s, ',');
    }
}

static void
format_flow_tunnel(struct ds *s, const struct match *match)
{
    const struct flow_wildcards *wc = &match->wc;
    const struct flow_tnl *tnl = &match->flow.tunnel;

    format_be64_masked(s, "tun_id", tnl->tun_id, wc->masks.tunnel.tun_id);
    format_ip_netmask(s, "tun_src", tnl->ip_src, wc->masks.tunnel.ip_src);
    format_ip_netmask(s, "tun_dst", tnl->ip_dst, wc->masks.tunnel.ip_dst);

    if (wc->masks.tunnel.ip_tos) {
        ds_put_format(s, "tun_tos=%"PRIx8",", tnl->ip_tos);
    }
    if (wc->masks.tunnel.ip_ttl) {
        ds_put_format(s, "tun_ttl=%"PRIu8",", tnl->ip_ttl);
    }
    if (wc->masks.tunnel.flags) {
        format_flags(s, flow_tun_flag_to_string, tnl->flags, '|');
        ds_put_char(s, ',');
    }
}

/* Appends a string representation of 'match' to 's'.  If 'priority' is
 * different from OFP_DEFAULT_PRIORITY, includes it in 's'. */
void
match_format(const struct match *match, struct ds *s, unsigned int priority)
{
    const struct flow_wildcards *wc = &match->wc;
    size_t start_len = s->length;
    const struct flow *f = &match->flow;
    bool skip_type = false;
    bool skip_proto = false;

    int i;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 23);

    if (priority != OFP_DEFAULT_PRIORITY) {
        ds_put_format(s, "priority=%u,", priority);
    }

    format_uint32_masked(s, "pkt_mark", f->pkt_mark, wc->masks.pkt_mark);

    if (wc->masks.skb_priority) {
        ds_put_format(s, "skb_priority=%#"PRIx32",", f->skb_priority);
    }

    if (wc->masks.dl_type) {
        skip_type = true;
        if (f->dl_type == htons(ETH_TYPE_IP)) {
            if (wc->masks.nw_proto) {
                skip_proto = true;
                if (f->nw_proto == IPPROTO_ICMP) {
                    ds_put_cstr(s, "icmp,");
                } else if (f->nw_proto == IPPROTO_TCP) {
                    ds_put_cstr(s, "tcp,");
                } else if (f->nw_proto == IPPROTO_UDP) {
                    ds_put_cstr(s, "udp,");
                } else if (f->nw_proto == IPPROTO_SCTP) {
                    ds_put_cstr(s, "sctp,");
                } else {
                    ds_put_cstr(s, "ip,");
                    skip_proto = false;
                }
            } else {
                ds_put_cstr(s, "ip,");
            }
        } else if (f->dl_type == htons(ETH_TYPE_IPV6)) {
            if (wc->masks.nw_proto) {
                skip_proto = true;
                if (f->nw_proto == IPPROTO_ICMPV6) {
                    ds_put_cstr(s, "icmp6,");
                } else if (f->nw_proto == IPPROTO_TCP) {
                    ds_put_cstr(s, "tcp6,");
                } else if (f->nw_proto == IPPROTO_UDP) {
                    ds_put_cstr(s, "udp6,");
                } else if (f->nw_proto == IPPROTO_SCTP) {
                    ds_put_cstr(s, "sctp6,");
                } else {
                    ds_put_cstr(s, "ipv6,");
                    skip_proto = false;
                }
            } else {
                ds_put_cstr(s, "ipv6,");
            }
        } else if (f->dl_type == htons(ETH_TYPE_ARP)) {
            ds_put_cstr(s, "arp,");
        } else if (f->dl_type == htons(ETH_TYPE_RARP)) {
            ds_put_cstr(s, "rarp,");
        } else if (f->dl_type == htons(ETH_TYPE_MPLS)) {
            ds_put_cstr(s, "mpls,");
        } else if (f->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            ds_put_cstr(s, "mplsm,");
        } else {
            skip_type = false;
        }
    }
    for (i = 0; i < FLOW_N_REGS; i++) {
        #define REGNAME_LEN 20
        char regname[REGNAME_LEN];
        if (snprintf(regname, REGNAME_LEN, "reg%d", i) >= REGNAME_LEN) {
            strcpy(regname, "reg?");
        }
        format_uint32_masked(s, regname, f->regs[i], wc->masks.regs[i]);
    }

    format_flow_tunnel(s, match);

    format_be64_masked(s, "metadata", f->metadata, wc->masks.metadata);

    if (wc->masks.in_port.ofp_port) {
        ds_put_cstr(s, "in_port=");
        ofputil_format_port(f->in_port.ofp_port, s);
        ds_put_char(s, ',');
    }
    if (wc->masks.vlan_tci) {
        ovs_be16 vid_mask = wc->masks.vlan_tci & htons(VLAN_VID_MASK);
        ovs_be16 pcp_mask = wc->masks.vlan_tci & htons(VLAN_PCP_MASK);
        ovs_be16 cfi = wc->masks.vlan_tci & htons(VLAN_CFI);

        if (cfi && f->vlan_tci & htons(VLAN_CFI)
            && (!vid_mask || vid_mask == htons(VLAN_VID_MASK))
            && (!pcp_mask || pcp_mask == htons(VLAN_PCP_MASK))
            && (vid_mask || pcp_mask)) {
            if (vid_mask) {
                ds_put_format(s, "dl_vlan=%"PRIu16",",
                              vlan_tci_to_vid(f->vlan_tci));
            }
            if (pcp_mask) {
                ds_put_format(s, "dl_vlan_pcp=%d,",
                              vlan_tci_to_pcp(f->vlan_tci));
            }
        } else if (wc->masks.vlan_tci == htons(0xffff)) {
            ds_put_format(s, "vlan_tci=0x%04"PRIx16",", ntohs(f->vlan_tci));
        } else {
            ds_put_format(s, "vlan_tci=0x%04"PRIx16"/0x%04"PRIx16",",
                          ntohs(f->vlan_tci), ntohs(wc->masks.vlan_tci));
        }
    }
    format_eth_masked(s, "dl_src", f->dl_src, wc->masks.dl_src);
    format_eth_masked(s, "dl_dst", f->dl_dst, wc->masks.dl_dst);
    if (!skip_type && wc->masks.dl_type) {
        ds_put_format(s, "dl_type=0x%04"PRIx16",", ntohs(f->dl_type));
    }
    if (f->dl_type == htons(ETH_TYPE_IPV6)) {
        format_ipv6_netmask(s, "ipv6_src", &f->ipv6_src, &wc->masks.ipv6_src);
        format_ipv6_netmask(s, "ipv6_dst", &f->ipv6_dst, &wc->masks.ipv6_dst);
        if (wc->masks.ipv6_label) {
            if (wc->masks.ipv6_label == OVS_BE32_MAX) {
                ds_put_format(s, "ipv6_label=0x%05"PRIx32",",
                              ntohl(f->ipv6_label));
            } else {
                ds_put_format(s, "ipv6_label=0x%05"PRIx32"/0x%05"PRIx32",",
                              ntohl(f->ipv6_label),
                              ntohl(wc->masks.ipv6_label));
            }
        }
    } else if (f->dl_type == htons(ETH_TYPE_ARP) ||
               f->dl_type == htons(ETH_TYPE_RARP)) {
        format_ip_netmask(s, "arp_spa", f->nw_src, wc->masks.nw_src);
        format_ip_netmask(s, "arp_tpa", f->nw_dst, wc->masks.nw_dst);
    } else {
        format_ip_netmask(s, "nw_src", f->nw_src, wc->masks.nw_src);
        format_ip_netmask(s, "nw_dst", f->nw_dst, wc->masks.nw_dst);
    }
    if (!skip_proto && wc->masks.nw_proto) {
        if (f->dl_type == htons(ETH_TYPE_ARP) ||
            f->dl_type == htons(ETH_TYPE_RARP)) {
            ds_put_format(s, "arp_op=%"PRIu8",", f->nw_proto);
        } else {
            ds_put_format(s, "nw_proto=%"PRIu8",", f->nw_proto);
        }
    }
    if (f->dl_type == htons(ETH_TYPE_ARP) ||
        f->dl_type == htons(ETH_TYPE_RARP)) {
        format_eth_masked(s, "arp_sha", f->arp_sha, wc->masks.arp_sha);
        format_eth_masked(s, "arp_tha", f->arp_tha, wc->masks.arp_tha);
    }
    if (wc->masks.nw_tos & IP_DSCP_MASK) {
        ds_put_format(s, "nw_tos=%"PRIu8",", f->nw_tos & IP_DSCP_MASK);
    }
    if (wc->masks.nw_tos & IP_ECN_MASK) {
        ds_put_format(s, "nw_ecn=%"PRIu8",", f->nw_tos & IP_ECN_MASK);
    }
    if (wc->masks.nw_ttl) {
        ds_put_format(s, "nw_ttl=%"PRIu8",", f->nw_ttl);
    }
    if (wc->masks.mpls_lse & htonl(MPLS_LABEL_MASK)) {
        ds_put_format(s, "mpls_label=%"PRIu32",",
                 mpls_lse_to_label(f->mpls_lse));
    }
    if (wc->masks.mpls_lse & htonl(MPLS_TC_MASK)) {
        ds_put_format(s, "mpls_tc=%"PRIu8",",
                 mpls_lse_to_tc(f->mpls_lse));
    }
    if (wc->masks.mpls_lse & htonl(MPLS_TTL_MASK)) {
        ds_put_format(s, "mpls_ttl=%"PRIu8",",
                 mpls_lse_to_ttl(f->mpls_lse));
    }
    if (wc->masks.mpls_lse & htonl(MPLS_BOS_MASK)) {
        ds_put_format(s, "mpls_bos=%"PRIu8",",
                 mpls_lse_to_bos(f->mpls_lse));
    }
    switch (wc->masks.nw_frag) {
    case FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER:
        ds_put_format(s, "nw_frag=%s,",
                      f->nw_frag & FLOW_NW_FRAG_ANY
                      ? (f->nw_frag & FLOW_NW_FRAG_LATER ? "later" : "first")
                      : (f->nw_frag & FLOW_NW_FRAG_LATER ? "<error>" : "no"));
        break;

    case FLOW_NW_FRAG_ANY:
        ds_put_format(s, "nw_frag=%s,",
                      f->nw_frag & FLOW_NW_FRAG_ANY ? "yes" : "no");
        break;

    case FLOW_NW_FRAG_LATER:
        ds_put_format(s, "nw_frag=%s,",
                      f->nw_frag & FLOW_NW_FRAG_LATER ? "later" : "not_later");
        break;
    }
    if (f->dl_type == htons(ETH_TYPE_IP) &&
        f->nw_proto == IPPROTO_ICMP) {
        format_be16_masked(s, "icmp_type", f->tp_src, wc->masks.tp_src);
        format_be16_masked(s, "icmp_code", f->tp_dst, wc->masks.tp_dst);
    } else if (f->dl_type == htons(ETH_TYPE_IPV6) &&
               f->nw_proto == IPPROTO_ICMPV6) {
        format_be16_masked(s, "icmp_type", f->tp_src, wc->masks.tp_src);
        format_be16_masked(s, "icmp_code", f->tp_dst, wc->masks.tp_dst);
        format_ipv6_netmask(s, "nd_target", &f->nd_target,
                            &wc->masks.nd_target);
        format_eth_masked(s, "nd_sll", f->arp_sha, wc->masks.arp_sha);
        format_eth_masked(s, "nd_tll", f->arp_tha, wc->masks.arp_tha);
    } else {
        format_be16_masked(s, "tp_src", f->tp_src, wc->masks.tp_src);
        format_be16_masked(s, "tp_dst", f->tp_dst, wc->masks.tp_dst);
    }
    if (is_ip_any(f) && f->nw_proto == IPPROTO_TCP && wc->masks.tcp_flags) {
        uint16_t mask = TCP_FLAGS(wc->masks.tcp_flags);
        if (mask == TCP_FLAGS(OVS_BE16_MAX)) {
            ds_put_format(s, "tcp_flags=0x%03"PRIx16",", ntohs(f->tcp_flags));
        } else {
            format_flags_masked(s, "tcp_flags", packet_tcp_flag_to_string,
                                ntohs(f->tcp_flags), mask);
        }
    }

    if (s->length > start_len && ds_last(s) == ',') {
        s->length--;
    }
}

/* Converts 'match' to a string and returns the string.  If 'priority' is
 * different from OFP_DEFAULT_PRIORITY, includes it in the string.  The caller
 * must free the string (with free()). */
char *
match_to_string(const struct match *match, unsigned int priority)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    match_format(match, &s, priority);
    return ds_steal_cstr(&s);
}

void
match_print(const struct match *match)
{
    char *s = match_to_string(match, OFP_DEFAULT_PRIORITY);
    puts(s);
    free(s);
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with minimatch_destroy(). */
void
minimatch_init(struct minimatch *dst, const struct match *src)
{
    minimask_init(&dst->mask, &src->wc);
    miniflow_init_with_minimask(&dst->flow, &src->flow, &dst->mask);
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with minimatch_destroy(). */
void
minimatch_clone(struct minimatch *dst, const struct minimatch *src)
{
    miniflow_clone(&dst->flow, &src->flow);
    minimask_clone(&dst->mask, &src->mask);
}

/* Initializes 'dst' with the data in 'src', destroying 'src'.  The caller must
 * eventually free 'dst' with minimatch_destroy(). */
void
minimatch_move(struct minimatch *dst, struct minimatch *src)
{
    miniflow_move(&dst->flow, &src->flow);
    minimask_move(&dst->mask, &src->mask);
}

/* Frees any memory owned by 'match'.  Does not free the storage in which
 * 'match' itself resides; the caller is responsible for that. */
void
minimatch_destroy(struct minimatch *match)
{
    miniflow_destroy(&match->flow);
    minimask_destroy(&match->mask);
}

/* Initializes 'dst' as a copy of 'src'. */
void
minimatch_expand(const struct minimatch *src, struct match *dst)
{
    miniflow_expand(&src->flow, &dst->flow);
    minimask_expand(&src->mask, &dst->wc);
}

/* Returns true if 'a' and 'b' match the same packets, false otherwise.  */
bool
minimatch_equal(const struct minimatch *a, const struct minimatch *b)
{
    return (miniflow_equal(&a->flow, &b->flow)
            && minimask_equal(&a->mask, &b->mask));
}

/* Returns a hash value for 'match', given 'basis'. */
uint32_t
minimatch_hash(const struct minimatch *match, uint32_t basis)
{
    return miniflow_hash(&match->flow, minimask_hash(&match->mask, basis));
}

/* Returns true if 'target' satisifies 'match', that is, if each bit for which
 * 'match' specifies a particular value has the correct value in 'target'.
 *
 * This function is equivalent to miniflow_equal_flow_in_minimask(&match->flow,
 * target, &match->mask) but it is faster because of the invariant that
 * match->flow.map and match->mask.map are the same. */
bool
minimatch_matches_flow(const struct minimatch *match,
                       const struct flow *target)
{
    const uint32_t *target_u32 = (const uint32_t *) target;
    const uint32_t *flowp = match->flow.values;
    const uint32_t *maskp = match->mask.masks.values;
    uint64_t map;

    for (map = match->flow.map; map; map = zero_rightmost_1bit(map)) {
        if ((*flowp++ ^ target_u32[raw_ctz(map)]) & *maskp++) {
            return false;
        }
    }

    return true;
}

/* Returns a hash value for the bits of range [start, end) in 'minimatch',
 * given 'basis'.
 *
 * The hash values returned by this function are the same as those returned by
 * flow_hash_in_minimask_range(), only the form of the arguments differ. */
uint32_t
minimatch_hash_range(const struct minimatch *match, uint8_t start, uint8_t end,
                     uint32_t *basis)
{
    unsigned int offset;
    const uint32_t *p, *q;
    uint32_t hash = *basis;
    int n, i;

    n = count_1bits(miniflow_get_map_in_range(&match->mask.masks, start, end,
                                              &offset));
    q = match->mask.masks.values + offset;
    p = match->flow.values + offset;

    for (i = 0; i < n; i++) {
        hash = mhash_add(hash, p[i] & q[i]);
    }
    *basis = hash; /* Allow continuation from the unfinished value. */
    return mhash_finish(hash, (offset + n) * 4);
}

/* Appends a string representation of 'match' to 's'.  If 'priority' is
 * different from OFP_DEFAULT_PRIORITY, includes it in 's'. */
void
minimatch_format(const struct minimatch *match, struct ds *s,
                 unsigned int priority)
{
    struct match megamatch;

    minimatch_expand(match, &megamatch);
    match_format(&megamatch, s, priority);
}

/* Converts 'match' to a string and returns the string.  If 'priority' is
 * different from OFP_DEFAULT_PRIORITY, includes it in the string.  The caller
 * must free the string (with free()). */
char *
minimatch_to_string(const struct minimatch *match, unsigned int priority)
{
    struct match megamatch;

    minimatch_expand(match, &megamatch);
    return match_to_string(&megamatch, priority);
}
