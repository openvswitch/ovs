/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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
#include "openvswitch/match.h"
#include <stdlib.h>
#include "flow.h"
#include "byte-order.h"
#include "colors.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-port.h"
#include "packets.h"
#include "tun-metadata.h"
#include "openvswitch/nsh.h"

/* Converts the flow in 'flow' into a match in 'match', with the given
 * 'wildcards'. */
void
match_init(struct match *match,
           const struct flow *flow, const struct flow_wildcards *wc)
{
    match->flow = *flow;
    match->wc = *wc;
    match_zero_wildcarded_fields(match);
    memset(&match->tun_md, 0, sizeof match->tun_md);
}

/* Converts a flow into a match.  It sets the wildcard masks based on
 * the packet contents.  It will not set the mask for fields that do not
 * make sense for the packet type. */
void
match_wc_init(struct match *match, const struct flow *flow)
{
    match->flow = *flow;

    flow_wildcards_init_for_packet(&match->wc, flow);
    WC_MASK_FIELD(&match->wc, regs);
    WC_MASK_FIELD(&match->wc, metadata);

    memset(&match->tun_md, 0, sizeof match->tun_md);
}

/* Initializes 'match' as a "catch-all" match that matches every packet. */
void
match_init_catchall(struct match *match)
{
    memset(&match->flow, 0, sizeof match->flow);
    flow_wildcards_init_catchall(&match->wc);
    memset(&match->tun_md, 0, sizeof match->tun_md);
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
match_set_dp_hash(struct match *match, uint32_t value)
{
    match_set_dp_hash_masked(match, value, UINT32_MAX);
}

void
match_set_dp_hash_masked(struct match *match, uint32_t value, uint32_t mask)
{
    match->wc.masks.dp_hash = mask;
    match->flow.dp_hash = value & mask;
}

void
match_set_recirc_id(struct match *match, uint32_t value)
{
    match->flow.recirc_id = value;
    match->wc.masks.recirc_id = UINT32_MAX;
}

void
match_set_conj_id(struct match *match, uint32_t value)
{
    match->flow.conj_id = value;
    match->wc.masks.conj_id = UINT32_MAX;
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
match_set_xreg(struct match *match, unsigned int xreg_idx, uint64_t value)
{
    match_set_xreg_masked(match, xreg_idx, value, UINT64_MAX);
}

void
match_set_xreg_masked(struct match *match, unsigned int xreg_idx,
                      uint64_t value, uint64_t mask)
{
    ovs_assert(xreg_idx < FLOW_N_XREGS);
    flow_wildcards_set_xreg_mask(&match->wc, xreg_idx, mask);
    flow_set_xreg(&match->flow, xreg_idx, value & mask);
}

void
match_set_xxreg(struct match *match, unsigned int xxreg_idx, ovs_u128 value)
{
    match_set_xxreg_masked(match, xxreg_idx, value, OVS_U128_MAX);
}

void
match_set_xxreg_masked(struct match *match, unsigned int xxreg_idx,
                      ovs_u128 value, ovs_u128 mask)
{
    ovs_assert(xxreg_idx < FLOW_N_XXREGS);
    flow_wildcards_set_xxreg_mask(&match->wc, xxreg_idx, mask);
    flow_set_xxreg(&match->flow, xxreg_idx, ovs_u128_and(value, mask));
}

void
match_set_actset_output(struct match *match, ofp_port_t actset_output)
{
    match->wc.masks.actset_output = u16_to_ofp(UINT16_MAX);
    match->flow.actset_output = actset_output;
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
match_set_tun_ipv6_src(struct match *match, const struct in6_addr *src)
{
    match->flow.tunnel.ipv6_src = *src;
    match->wc.masks.tunnel.ipv6_src = in6addr_exact;
}

void
match_set_tun_ipv6_src_masked(struct match *match, const struct in6_addr *src,
                              const struct in6_addr *mask)
{
    match->flow.tunnel.ipv6_src = ipv6_addr_bitand(src, mask);
    match->wc.masks.tunnel.ipv6_src = *mask;
}

void
match_set_tun_ipv6_dst(struct match *match, const struct in6_addr *dst)
{
    match->flow.tunnel.ipv6_dst = *dst;
    match->wc.masks.tunnel.ipv6_dst = in6addr_exact;
}

void
match_set_tun_ipv6_dst_masked(struct match *match, const struct in6_addr *dst,
                              const struct in6_addr *mask)
{
    match->flow.tunnel.ipv6_dst = ipv6_addr_bitand(dst, mask);
    match->wc.masks.tunnel.ipv6_dst = *mask;
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
    mask &= FLOW_TNL_PUB_F_MASK;

    match->wc.masks.tunnel.flags = mask;
    match->flow.tunnel.flags = flags & mask;
}

void
match_set_tun_tp_dst(struct match *match, ovs_be16 tp_dst)
{
    match_set_tun_tp_dst_masked(match, tp_dst, OVS_BE16_MAX);
}

void
match_set_tun_tp_dst_masked(struct match *match, ovs_be16 port, ovs_be16 mask)
{
    match->wc.masks.tunnel.tp_dst = mask;
    match->flow.tunnel.tp_dst = port & mask;
}

void
match_set_tun_gbp_id_masked(struct match *match, ovs_be16 gbp_id, ovs_be16 mask)
{
    match->wc.masks.tunnel.gbp_id = mask;
    match->flow.tunnel.gbp_id = gbp_id & mask;
}

void
match_set_tun_gbp_id(struct match *match, ovs_be16 gbp_id)
{
    match_set_tun_gbp_id_masked(match, gbp_id, OVS_BE16_MAX);
}

void
match_set_tun_gbp_flags_masked(struct match *match, uint8_t flags, uint8_t mask)
{
    match->wc.masks.tunnel.gbp_flags = mask;
    match->flow.tunnel.gbp_flags = flags & mask;
}

void
match_set_tun_gbp_flags(struct match *match, uint8_t flags)
{
    match_set_tun_gbp_flags_masked(match, flags, UINT8_MAX);
}

void
match_set_tun_erspan_ver_masked(struct match *match, uint8_t ver, uint8_t mask)
{
    match->wc.masks.tunnel.erspan_ver = ver;
    match->flow.tunnel.erspan_ver = ver & mask;
}

void
match_set_tun_erspan_ver(struct match *match, uint8_t ver)
{
    match_set_tun_erspan_ver_masked(match, ver, UINT8_MAX);
}

void
match_set_tun_erspan_idx_masked(struct match *match, uint32_t erspan_idx,
                                uint32_t mask)
{
    match->wc.masks.tunnel.erspan_idx = mask;
    match->flow.tunnel.erspan_idx = erspan_idx & mask;
}

void
match_set_tun_erspan_idx(struct match *match, uint32_t erspan_idx)
{
    match_set_tun_erspan_idx_masked(match, erspan_idx, UINT32_MAX);
}

void
match_set_tun_erspan_dir_masked(struct match *match, uint8_t dir,
                                uint8_t mask)
{
    match->wc.masks.tunnel.erspan_dir = dir;
    match->flow.tunnel.erspan_dir = dir & mask;
}

void
match_set_tun_erspan_dir(struct match *match, uint8_t dir)
{
    match_set_tun_erspan_dir_masked(match, dir, UINT8_MAX);
}

void
match_set_tun_erspan_hwid_masked(struct match *match, uint8_t hwid,
                                 uint8_t mask)
{
    match->wc.masks.tunnel.erspan_hwid = hwid;
    match->flow.tunnel.erspan_hwid = hwid & mask;
}

void
match_set_tun_erspan_hwid(struct match *match, uint8_t hwid)
{
    match_set_tun_erspan_hwid_masked(match, hwid, UINT8_MAX);
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
match_set_ct_state(struct match *match, uint32_t ct_state)
{
    match_set_ct_state_masked(match, ct_state, UINT32_MAX);
}

void
match_set_ct_state_masked(struct match *match, uint32_t ct_state, uint32_t mask)
{
    match->flow.ct_state = ct_state & mask & UINT8_MAX;
    match->wc.masks.ct_state = mask & UINT8_MAX;
}

void
match_set_ct_zone(struct match *match, uint16_t ct_zone)
{
    match->flow.ct_zone = ct_zone;
    match->wc.masks.ct_zone = UINT16_MAX;
}

void
match_set_ct_mark(struct match *match, uint32_t ct_mark)
{
    match_set_ct_mark_masked(match, ct_mark, UINT32_MAX);
}

void
match_set_ct_mark_masked(struct match *match, uint32_t ct_mark,
                           uint32_t mask)
{
    match->flow.ct_mark = ct_mark & mask;
    match->wc.masks.ct_mark = mask;
}

void
match_set_ct_label(struct match *match, ovs_u128 ct_label)
{
    ovs_u128 mask;

    mask.u64.lo = UINT64_MAX;
    mask.u64.hi = UINT64_MAX;
    match_set_ct_label_masked(match, ct_label, mask);
}

void
match_set_ct_label_masked(struct match *match, ovs_u128 value, ovs_u128 mask)
{
    match->flow.ct_label.u64.lo = value.u64.lo & mask.u64.lo;
    match->flow.ct_label.u64.hi = value.u64.hi & mask.u64.hi;
    match->wc.masks.ct_label = mask;
}

void
match_set_ct_nw_src(struct match *match, ovs_be32 ct_nw_src)
{
    match->flow.ct_nw_src = ct_nw_src;
    match->wc.masks.ct_nw_src = OVS_BE32_MAX;
}

void
match_set_ct_nw_src_masked(struct match *match, ovs_be32 ct_nw_src,
                           ovs_be32 mask)
{
    match->flow.ct_nw_src = ct_nw_src & mask;
    match->wc.masks.ct_nw_src = mask;
}

void
match_set_ct_nw_dst(struct match *match, ovs_be32 ct_nw_dst)
{
    match->flow.ct_nw_dst = ct_nw_dst;
    match->wc.masks.ct_nw_dst = OVS_BE32_MAX;
}

void
match_set_ct_nw_dst_masked(struct match *match, ovs_be32 ct_nw_dst,
                           ovs_be32 mask)
{
    match->flow.ct_nw_dst = ct_nw_dst & mask;
    match->wc.masks.ct_nw_dst = mask;
}

void
match_set_ct_nw_proto(struct match *match, uint8_t ct_nw_proto)
{
    match->flow.ct_nw_proto = ct_nw_proto;
    match->wc.masks.ct_nw_proto = UINT8_MAX;
}

void
match_set_ct_tp_src(struct match *match, ovs_be16 ct_tp_src)
{
    match_set_ct_tp_src_masked(match, ct_tp_src, OVS_BE16_MAX);
}

void
match_set_ct_tp_src_masked(struct match *match, ovs_be16 port, ovs_be16 mask)
{
    match->flow.ct_tp_src = port & mask;
    match->wc.masks.ct_tp_src = mask;
}

void
match_set_ct_tp_dst(struct match *match, ovs_be16 ct_tp_dst)
{
    match_set_ct_tp_dst_masked(match, ct_tp_dst, OVS_BE16_MAX);
}

void
match_set_ct_tp_dst_masked(struct match *match, ovs_be16 port, ovs_be16 mask)
{
    match->flow.ct_tp_dst = port & mask;
    match->wc.masks.ct_tp_dst = mask;
}

void
match_set_ct_ipv6_src(struct match *match, const struct in6_addr *src)
{
    match->flow.ct_ipv6_src = *src;
    match->wc.masks.ct_ipv6_src = in6addr_exact;
}

void
match_set_ct_ipv6_src_masked(struct match *match, const struct in6_addr *src,
                             const struct in6_addr *mask)
{
    match->flow.ct_ipv6_src = ipv6_addr_bitand(src, mask);
    match->wc.masks.ct_ipv6_src = *mask;
}

void
match_set_ct_ipv6_dst(struct match *match, const struct in6_addr *dst)
{
    match->flow.ct_ipv6_dst = *dst;
    match->wc.masks.ct_ipv6_dst = in6addr_exact;
}

void
match_set_ct_ipv6_dst_masked(struct match *match, const struct in6_addr *dst,
                             const struct in6_addr *mask)
{
    match->flow.ct_ipv6_dst = ipv6_addr_bitand(dst, mask);
    match->wc.masks.ct_ipv6_dst = *mask;
}

void
match_set_packet_type(struct match *match, ovs_be32 packet_type)
{
    match->flow.packet_type = packet_type;
    match->wc.masks.packet_type = OVS_BE32_MAX;
}

/* If 'match' does not match on any packet type, make it match on Ethernet
 * packets (the default packet type, as specified by OpenFlow). */
void
match_set_default_packet_type(struct match *match)
{
    if (!match->wc.masks.packet_type) {
        match_set_packet_type(match, htonl(PT_ETH));
    }
}

/* Returns true if 'match' matches only Ethernet packets (the default packet
 * type, as specified by OpenFlow). */
bool
match_has_default_packet_type(const struct match *match)
{
    return (match->flow.packet_type == htonl(PT_ETH)
            && match->wc.masks.packet_type == OVS_BE32_MAX);
}

/* A match on 'field' is being added to or has been added to 'match'.  If
 * 'field' is a data field, and 'match' does not already match on packet_type,
 * this function make it match on the Ethernet packet_type.
 *
 * This function is useful because OpenFlow implicitly applies to Ethernet
 * packets when there's no explicit packet_type, but matching on a metadata
 * field doesn't imply anything about the packet_type and falsely inferring
 * that it does can cause harm.  A flow that matches only on metadata fields,
 * for example, should be able to match more than just Ethernet flows.  There
 * are also important reasons that a catch-all match (one with no field matches
 * at all) should not imply a packet_type(0,0) match.  For example, a "flow
 * dump" request that matches on no fields should return every flow in the
 * switch, not just the flows that match on Ethernet.  As a second example,
 * OpenFlow 1.2+ special-cases "table miss" flows, that is catch-all flows with
 * priority 0, and inferring a match on packet_type(0,0) causes such a flow not
 * to be a table miss flow.  */
void
match_add_ethernet_prereq(struct match *match, const struct mf_field *field)
{
    if (field->prereqs != MFP_NONE) {
        match_set_default_packet_type(match);
    }
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
set_eth(const struct eth_addr value_src,
        struct eth_addr *value_dst,
        struct eth_addr *mask_dst)
{
    *value_dst = value_src;
    *mask_dst = eth_addr_exact;
}

/* Modifies 'value_src' so that the Ethernet address must match 'value_src'
 * after each byte is ANDed with the appropriate byte in 'mask_src'.
 * 'mask_dst' is set to 'mask_src' */
static void
set_eth_masked(const struct eth_addr value_src,
               const struct eth_addr mask_src,
               struct eth_addr *value_dst, struct eth_addr *mask_dst)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(value_dst->be16); i++) {
        value_dst->be16[i] = value_src.be16[i] & mask_src.be16[i];
    }
    *mask_dst = mask_src;
}

/* Modifies 'rule' so that the source Ethernet address must match 'dl_src'
 * exactly. */
void
match_set_dl_src(struct match *match, const struct eth_addr dl_src)
{
    set_eth(dl_src, &match->flow.dl_src, &match->wc.masks.dl_src);
}

/* Modifies 'rule' so that the source Ethernet address must match 'dl_src'
 * after each byte is ANDed with the appropriate byte in 'mask'. */
void
match_set_dl_src_masked(struct match *match,
                        const struct eth_addr dl_src,
                        const struct eth_addr mask)
{
    set_eth_masked(dl_src, mask, &match->flow.dl_src, &match->wc.masks.dl_src);
}

/* Modifies 'match' so that the Ethernet address must match 'dl_dst'
 * exactly. */
void
match_set_dl_dst(struct match *match, const struct eth_addr dl_dst)
{
    set_eth(dl_dst, &match->flow.dl_dst, &match->wc.masks.dl_dst);
}

/* Modifies 'match' so that the Ethernet address must match 'dl_dst' after each
 * byte is ANDed with the appropriate byte in 'mask'.
 *
 * This function will assert-fail if 'mask' is invalid.  Only 'mask' values
 * accepted by flow_wildcards_is_dl_dst_mask_valid() are allowed. */
void
match_set_dl_dst_masked(struct match *match,
                        const struct eth_addr dl_dst,
                        const struct eth_addr mask)
{
    set_eth_masked(dl_dst, mask, &match->flow.dl_dst, &match->wc.masks.dl_dst);
}

void
match_set_dl_tci(struct match *match, ovs_be16 tci)
{
    match_set_dl_tci_masked(match, tci, htons(0xffff));
}

void
match_set_dl_tci_masked(struct match *match, ovs_be16 tci, ovs_be16 mask)
{
    match->flow.vlans[0].tci = tci & mask;
    match->wc.masks.vlans[0].tci = mask;
}

/* Modifies 'match' so that the VLAN VID is wildcarded.  If the PCP is already
 * wildcarded, then 'match' will match a packet regardless of whether it has an
 * 802.1Q header or not. */
void
match_set_any_vid(struct match *match)
{
    if (match->wc.masks.vlans[0].tci & htons(VLAN_PCP_MASK)) {
        match->wc.masks.vlans[0].tci &= ~htons(VLAN_VID_MASK);
        match->flow.vlans[0].tci &= ~htons(VLAN_VID_MASK);
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
match_set_dl_vlan(struct match *match, ovs_be16 dl_vlan, int id)
{
    flow_set_dl_vlan(&match->flow, dl_vlan, id);
    if (dl_vlan == htons(OFP10_VLAN_NONE)) {
        match->wc.masks.vlans[id].tci = OVS_BE16_MAX;
    } else {
        match->wc.masks.vlans[id].tci |= htons(VLAN_VID_MASK | VLAN_CFI);
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
    match->wc.masks.vlans[0].tci =
        mask | (match->wc.masks.vlans[0].tci & pcp_mask);
}

/* Modifies 'match' so that the VLAN PCP is wildcarded.  If the VID is already
 * wildcarded, then 'match' will match a packet regardless of whether it has an
 * 802.1Q header or not. */
void
match_set_any_pcp(struct match *match)
{
    if (match->wc.masks.vlans[0].tci & htons(VLAN_VID_MASK)) {
        match->wc.masks.vlans[0].tci &= ~htons(VLAN_PCP_MASK);
        match->flow.vlans[0].tci &= ~htons(VLAN_PCP_MASK);
    } else {
        match_set_dl_tci_masked(match, htons(0), htons(0));
    }
}

/* Modifies 'match' so that it matches only packets with an 802.1Q header whose
 * PCP equals the low 3 bits of 'dl_vlan_pcp'. */
void
match_set_dl_vlan_pcp(struct match *match, uint8_t dl_vlan_pcp, int id)
{
    flow_set_vlan_pcp(&match->flow, dl_vlan_pcp, id);
    match->wc.masks.vlans[id].tci |= htons(VLAN_CFI | VLAN_PCP_MASK);
}

/* Modifies 'match' so that the MPLS label 'idx' matches 'lse' exactly. */
void
match_set_mpls_lse(struct match *match, int idx, ovs_be32 lse)
{
    match->wc.masks.mpls_lse[idx] = OVS_BE32_MAX;
    match->flow.mpls_lse[idx] = lse;
}

/* Modifies 'match' so that the MPLS label is wildcarded. */
void
match_set_any_mpls_label(struct match *match, int idx)
{
    match->wc.masks.mpls_lse[idx] &= ~htonl(MPLS_LABEL_MASK);
    flow_set_mpls_label(&match->flow, idx, htonl(0));
}

/* Modifies 'match' so that it matches only packets with an MPLS header whose
 * label equals the low 20 bits of 'mpls_label'. */
void
match_set_mpls_label(struct match *match, int idx, ovs_be32 mpls_label)
{
    match->wc.masks.mpls_lse[idx] |= htonl(MPLS_LABEL_MASK);
    flow_set_mpls_label(&match->flow, idx, mpls_label);
}

/* Modifies 'match' so that the MPLS TC is wildcarded. */
void
match_set_any_mpls_tc(struct match *match, int idx)
{
    match->wc.masks.mpls_lse[idx] &= ~htonl(MPLS_TC_MASK);
    flow_set_mpls_tc(&match->flow, idx, 0);
}

/* Modifies 'match' so that it matches only packets with an MPLS header whose
 * Traffic Class equals the low 3 bits of 'mpls_tc'. */
void
match_set_mpls_tc(struct match *match, int idx, uint8_t mpls_tc)
{
    match->wc.masks.mpls_lse[idx] |= htonl(MPLS_TC_MASK);
    flow_set_mpls_tc(&match->flow, idx, mpls_tc);
}

/* Modifies 'match' so that the MPLS stack flag is wildcarded. */
void
match_set_any_mpls_bos(struct match *match, int idx)
{
    match->wc.masks.mpls_lse[idx] &= ~htonl(MPLS_BOS_MASK);
    flow_set_mpls_bos(&match->flow, idx, 0);
}

/* Modifies 'match' so that it matches only packets with an MPLS header whose
 * Stack Flag equals the lower bit of 'mpls_bos' */
void
match_set_mpls_bos(struct match *match, int idx, uint8_t mpls_bos)
{
    match->wc.masks.mpls_lse[idx] |= htonl(MPLS_BOS_MASK);
    flow_set_mpls_bos(&match->flow, idx, mpls_bos);
}

/* Modifies 'match' so that the TTL of MPLS label 'idx' is wildcarded. */
void
match_set_any_mpls_ttl(struct match *match, int idx)
{
    match->wc.masks.mpls_lse[idx] &= ~htonl(MPLS_TTL_MASK);
    flow_set_mpls_ttl(&match->flow, idx, 0);
}

/* Modifies 'match' so that it matches only packets in which the TTL of MPLS
 * label 'idx' equals 'mpls_ttl'. */
void
match_set_mpls_ttl(struct match *match, int idx, uint8_t mpls_ttl)
{
    match->wc.masks.mpls_lse[idx] |= htonl(MPLS_TTL_MASK);
    flow_set_mpls_ttl(&match->flow, idx, mpls_ttl);
}

/* Modifies 'match' so that the MPLS LSE is wildcarded. */
void
match_set_any_mpls_lse(struct match *match, int idx)
{
    match->wc.masks.mpls_lse[idx] = htonl(0);
    flow_set_mpls_lse(&match->flow, idx, htonl(0));
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
match_set_nw_tos_masked(struct match *match, uint8_t nw_tos, uint8_t mask)
{
    match->flow.nw_tos = nw_tos & mask;
    match->wc.masks.nw_tos = mask;
}

void
match_set_nw_ttl_masked(struct match *match, uint8_t nw_ttl, uint8_t mask)
{
    match->flow.nw_ttl = nw_ttl & mask;
    match->wc.masks.nw_ttl = mask;
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
match_set_arp_sha(struct match *match, const struct eth_addr sha)
{
    match->flow.arp_sha = sha;
    match->wc.masks.arp_sha = eth_addr_exact;
}

void
match_set_arp_sha_masked(struct match *match,
                         const struct eth_addr arp_sha,
                         const struct eth_addr mask)
{
    set_eth_masked(arp_sha, mask,
                   &match->flow.arp_sha, &match->wc.masks.arp_sha);
}

void
match_set_arp_tha(struct match *match, const struct eth_addr tha)
{
    match->flow.arp_tha = tha;
    match->wc.masks.arp_tha = eth_addr_exact;
}

void
match_set_arp_tha_masked(struct match *match,
                         const struct eth_addr arp_tha,
                         const struct eth_addr mask)
{
    set_eth_masked(arp_tha, mask,
                   &match->flow.arp_tha, &match->wc.masks.arp_tha);
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

static bool
match_has_default_recirc_id(const struct match *m)
{
    return m->flow.recirc_id == 0 && (m->wc.masks.recirc_id == UINT32_MAX ||
                                      m->wc.masks.recirc_id == 0);
}

static bool
match_has_default_dp_hash(const struct match *m)
{
    return ((m->flow.dp_hash | m->wc.masks.dp_hash) == 0);
}

/* Return true if the hidden fields of the match are set to the default values.
 * The default values equals to those set up by match_init_hidden_fields(). */
bool
match_has_default_hidden_fields(const struct match *m)
{
    return match_has_default_recirc_id(m) && match_has_default_dp_hash(m);
}

void
match_init_hidden_fields(struct match *m)
{
    match_set_recirc_id(m, 0);
    match_set_dp_hash_masked(m, 0, 0);
}

static void
format_eth_masked(struct ds *s, const char *name,
                  const struct eth_addr eth, const struct eth_addr mask)
{
    if (!eth_addr_is_zero(mask)) {
        ds_put_format(s, "%s%s=%s", colors.param, name, colors.end);
        eth_format_masked(eth, &mask, s);
        ds_put_char(s, ',');
    }
}

static void
format_ip_netmask(struct ds *s, const char *name, ovs_be32 ip,
                  ovs_be32 netmask)
{
    if (netmask) {
        ds_put_format(s, "%s%s=%s", colors.param, name, colors.end);
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
        ds_put_format(s, "%s%s=%s", colors.param, name, colors.end);
        ipv6_format_masked(addr, netmask, s);
        ds_put_char(s, ',');
    }
}

static void
format_uint8_masked(struct ds *s, const char *name,
                   uint8_t value, uint8_t mask)
{
    if (mask != 0) {
        ds_put_format(s, "%s%s=%s", colors.param, name, colors.end);
        if (mask == UINT8_MAX) {
            ds_put_format(s, "%"PRIu8, value);
        } else {
            ds_put_format(s, "0x%02"PRIx8"/0x%02"PRIx8, value, mask);
        }
        ds_put_char(s, ',');
    }
}

static void
format_uint16_masked(struct ds *s, const char *name,
                   uint16_t value, uint16_t mask)
{
    if (mask != 0) {
        ds_put_format(s, "%s%s=%s", colors.param, name, colors.end);
        if (mask == UINT16_MAX) {
            ds_put_format(s, "%"PRIu16, value);
        } else {
            ds_put_format(s, "0x%"PRIx16"/0x%"PRIx16, value, mask);
        }
        ds_put_char(s, ',');
    }
}

static void
format_be16_masked(struct ds *s, const char *name,
                   ovs_be16 value, ovs_be16 mask)
{
    if (mask != htons(0)) {
        ds_put_format(s, "%s%s=%s", colors.param, name, colors.end);
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
format_be32_masked(struct ds *s, const char *name,
                   ovs_be32 value, ovs_be32 mask)
{
    if (mask != htonl(0)) {
        ds_put_format(s, "%s%s=%s", colors.param, name, colors.end);
        if (mask == OVS_BE32_MAX) {
            ds_put_format(s, "%"PRIu32, ntohl(value));
        } else {
            ds_put_format(s, "0x%08"PRIx32"/0x%08"PRIx32,
                          ntohl(value), ntohl(mask));
        }
        ds_put_char(s, ',');
    }
}

static void
format_be32_masked_hex(struct ds *s, const char *name,
                       ovs_be32 value, ovs_be32 mask)
{
    if (mask != htonl(0)) {
        ds_put_format(s, "%s%s=%s", colors.param, name, colors.end);
        if (mask == OVS_BE32_MAX) {
            ds_put_format(s, "0x%"PRIx32, ntohl(value));
        } else {
            ds_put_format(s, "0x%"PRIx32"/0x%"PRIx32,
                          ntohl(value), ntohl(mask));
        }
        ds_put_char(s, ',');
    }
}

static void
format_uint32_masked(struct ds *s, const char *name,
                   uint32_t value, uint32_t mask)
{
    if (mask) {
        ds_put_format(s, "%s%s=%s%#"PRIx32,
                      colors.param, name, colors.end, value);
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
        ds_put_format(s, "%s%s=%s%#"PRIx64,
                      colors.param, name, colors.end, ntohll(value));
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
    format_ipv6_netmask(s, "tun_ipv6_src", &tnl->ipv6_src,
                        &wc->masks.tunnel.ipv6_src);
    format_ipv6_netmask(s, "tun_ipv6_dst", &tnl->ipv6_dst,
                        &wc->masks.tunnel.ipv6_dst);

    if (wc->masks.tunnel.gbp_id) {
        format_be16_masked(s, "tun_gbp_id", tnl->gbp_id,
                           wc->masks.tunnel.gbp_id);
    }

    if (wc->masks.tunnel.gbp_flags) {
        ds_put_format(s, "tun_gbp_flags=%#"PRIx8",", tnl->gbp_flags);
    }

    if (wc->masks.tunnel.ip_tos) {
        ds_put_format(s, "tun_tos=%"PRIx8",", tnl->ip_tos);
    }
    if (wc->masks.tunnel.ip_ttl) {
        ds_put_format(s, "tun_ttl=%"PRIu8",", tnl->ip_ttl);
    }
    if (wc->masks.tunnel.erspan_ver) {
        ds_put_format(s, "tun_erspan_ver=%"PRIu8",", tnl->erspan_ver);
    }
    if (wc->masks.tunnel.erspan_idx && tnl->erspan_ver == 1) {
       ds_put_format(s, "tun_erspan_idx=%#"PRIx32",", tnl->erspan_idx); 
    }
    if (wc->masks.tunnel.erspan_dir && tnl->erspan_ver == 2) {
        ds_put_format(s, "tun_erspan_dir=%"PRIu8",", tnl->erspan_dir);
    }
    if (wc->masks.tunnel.erspan_hwid && tnl->erspan_ver == 2) {
        ds_put_format(s, "tun_erspan_hwid=%#"PRIx8",", tnl->erspan_hwid);
    }
    if (wc->masks.tunnel.flags & FLOW_TNL_F_MASK) {
        format_flags_masked(s, "tun_flags", flow_tun_flag_to_string,
                            tnl->flags & FLOW_TNL_F_MASK,
                            wc->masks.tunnel.flags & FLOW_TNL_F_MASK,
                            FLOW_TNL_F_MASK);
        ds_put_char(s, ',');
    }
    tun_metadata_match_format(s, match);
}

static void
format_ct_label_masked(struct ds *s, const ovs_u128 *key, const ovs_u128 *mask)
{
    if (!ovs_u128_is_zero(*mask)) {
        ovs_be128 value = hton128(*key);
        ds_put_format(s, "%sct_label=%s", colors.param, colors.end);
        ds_put_hex(s, &value, sizeof value);
        if (!is_all_ones(mask, sizeof(*mask))) {
            value = hton128(*mask);
            ds_put_char(s, '/');
            ds_put_hex(s, &value, sizeof value);
        }
        ds_put_char(s, ',');
    }
}

static void
format_nsh_masked(struct ds *s, const struct flow *f, const struct flow *m)
{
    ovs_be32 spi_mask = nsh_path_hdr_to_spi(m->nsh.path_hdr);
    if (spi_mask == htonl(NSH_SPI_MASK >> NSH_SPI_SHIFT)) {
        spi_mask = OVS_BE32_MAX;
    }
    format_uint8_masked(s, "nsh_flags", f->nsh.flags, m->nsh.flags);
    format_uint8_masked(s, "nsh_ttl", f->nsh.ttl, m->nsh.ttl);
    format_uint8_masked(s, "nsh_mdtype", f->nsh.mdtype, m->nsh.mdtype);
    format_uint8_masked(s, "nsh_np", f->nsh.np, m->nsh.np);

    format_be32_masked_hex(s, "nsh_spi", nsh_path_hdr_to_spi(f->nsh.path_hdr),
                           spi_mask);
    format_uint8_masked(s, "nsh_si", nsh_path_hdr_to_si(f->nsh.path_hdr),
                        nsh_path_hdr_to_si(m->nsh.path_hdr));
    if (m->nsh.mdtype == UINT8_MAX && f->nsh.mdtype == NSH_M_TYPE1) {
        format_be32_masked_hex(s, "nsh_c1", f->nsh.context[0],
                               m->nsh.context[0]);
        format_be32_masked_hex(s, "nsh_c2", f->nsh.context[1],
                               m->nsh.context[1]);
        format_be32_masked_hex(s, "nsh_c3", f->nsh.context[2],
                               m->nsh.context[2]);
        format_be32_masked_hex(s, "nsh_c4", f->nsh.context[3],
                               m->nsh.context[3]);
    }
}

/* Appends a string representation of 'match' to 's'.  If 'priority' is
 * different from OFP_DEFAULT_PRIORITY, includes it in 's'.  If 'port_map' is
 * nonnull, uses it to translate port numbers to names in output. */
void
match_format(const struct match *match,
             const struct ofputil_port_map *port_map,
             struct ds *s, int priority)
{
    const struct flow_wildcards *wc = &match->wc;
    size_t start_len = s->length;
    const struct flow *f = &match->flow;
    bool skip_type = false;
    bool skip_proto = false;
    ovs_be16 dl_type = f->dl_type;
    bool is_megaflow = false;
    int i;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 41);

    if (priority != OFP_DEFAULT_PRIORITY) {
        ds_put_format(s, "%spriority=%s%d,",
                      colors.special, colors.end, priority);
    }

    format_uint32_masked(s, "pkt_mark", f->pkt_mark, wc->masks.pkt_mark);

    if (wc->masks.recirc_id) {
        format_uint32_masked(s, "recirc_id", f->recirc_id,
                             wc->masks.recirc_id);
        is_megaflow = true;
    }

    if (wc->masks.dp_hash) {
        format_uint32_masked(s, "dp_hash", f->dp_hash,
                             wc->masks.dp_hash);
    }

    if (wc->masks.conj_id) {
        ds_put_format(s, "%sconj_id%s=%"PRIu32",",
                      colors.param, colors.end, f->conj_id);
    }

    if (wc->masks.skb_priority) {
        ds_put_format(s, "%sskb_priority=%s%#"PRIx32",",
                      colors.param, colors.end, f->skb_priority);
    }

    if (wc->masks.actset_output) {
        ds_put_format(s, "%sactset_output=%s", colors.param, colors.end);
        ofputil_format_port(f->actset_output, port_map, s);
        ds_put_char(s, ',');
    }

    if (wc->masks.ct_state) {
        if (wc->masks.ct_state == UINT8_MAX) {
            ds_put_format(s, "%sct_state=%s", colors.param, colors.end);
            if (f->ct_state) {
                format_flags(s, ct_state_to_string, f->ct_state, '|');
            } else {
                ds_put_cstr(s, "0"); /* No state. */
            }
        } else {
            format_flags_masked(s, "ct_state", ct_state_to_string,
                                f->ct_state, wc->masks.ct_state, UINT8_MAX);
        }
        ds_put_char(s, ',');
    }

    if (wc->masks.ct_zone) {
        format_uint16_masked(s, "ct_zone", f->ct_zone, wc->masks.ct_zone);
    }

    if (wc->masks.ct_mark) {
        format_uint32_masked(s, "ct_mark", f->ct_mark, wc->masks.ct_mark);
    }

    if (!ovs_u128_is_zero(wc->masks.ct_label)) {
        format_ct_label_masked(s, &f->ct_label, &wc->masks.ct_label);
    }

    format_ip_netmask(s, "ct_nw_src", f->ct_nw_src,
                      wc->masks.ct_nw_src);
    format_ipv6_netmask(s, "ct_ipv6_src", &f->ct_ipv6_src,
                        &wc->masks.ct_ipv6_src);
    format_ip_netmask(s, "ct_nw_dst", f->ct_nw_dst,
                      wc->masks.ct_nw_dst);
    format_ipv6_netmask(s, "ct_ipv6_dst", &f->ct_ipv6_dst,
                        &wc->masks.ct_ipv6_dst);
    if (wc->masks.ct_nw_proto) {
        ds_put_format(s, "%sct_nw_proto=%s%"PRIu8",",
                      colors.param, colors.end, f->ct_nw_proto);
        format_be16_masked(s, "ct_tp_src", f->ct_tp_src, wc->masks.ct_tp_src);
        format_be16_masked(s, "ct_tp_dst", f->ct_tp_dst, wc->masks.ct_tp_dst);
    }

    if (wc->masks.packet_type &&
        (!match_has_default_packet_type(match) || is_megaflow)) {
        format_packet_type_masked(s, f->packet_type, wc->masks.packet_type);
        ds_put_char(s, ',');
        if (pt_ns(f->packet_type) == OFPHTN_ETHERTYPE) {
            dl_type = pt_ns_type_be(f->packet_type);
        }
    }

    if (wc->masks.dl_type) {
        skip_type = true;
        if (dl_type == htons(ETH_TYPE_IP)) {
            if (wc->masks.nw_proto) {
                skip_proto = true;
                if (f->nw_proto == IPPROTO_ICMP) {
                    ds_put_format(s, "%sicmp%s,", colors.value, colors.end);
                } else if (f->nw_proto == IPPROTO_IGMP) {
                    ds_put_format(s, "%sigmp%s,", colors.value, colors.end);
                } else if (f->nw_proto == IPPROTO_TCP) {
                    ds_put_format(s, "%stcp%s,", colors.value, colors.end);
                } else if (f->nw_proto == IPPROTO_UDP) {
                    ds_put_format(s, "%sudp%s,", colors.value, colors.end);
                } else if (f->nw_proto == IPPROTO_SCTP) {
                    ds_put_format(s, "%ssctp%s,", colors.value, colors.end);
                } else {
                    ds_put_format(s, "%sip%s,", colors.value, colors.end);
                    skip_proto = false;
                }
            } else {
                ds_put_format(s, "%sip%s,", colors.value, colors.end);
            }
        } else if (dl_type == htons(ETH_TYPE_IPV6)) {
            if (wc->masks.nw_proto) {
                skip_proto = true;
                if (f->nw_proto == IPPROTO_ICMPV6) {
                    ds_put_format(s, "%sicmp6%s,", colors.value, colors.end);
                } else if (f->nw_proto == IPPROTO_TCP) {
                    ds_put_format(s, "%stcp6%s,", colors.value, colors.end);
                } else if (f->nw_proto == IPPROTO_UDP) {
                    ds_put_format(s, "%sudp6%s,", colors.value, colors.end);
                } else if (f->nw_proto == IPPROTO_SCTP) {
                    ds_put_format(s, "%ssctp6%s,", colors.value, colors.end);
                } else {
                    ds_put_format(s, "%sipv6%s,", colors.value, colors.end);
                    skip_proto = false;
                }
            } else {
                ds_put_format(s, "%sipv6%s,", colors.value, colors.end);
            }
        } else if (dl_type == htons(ETH_TYPE_ARP)) {
            ds_put_format(s, "%sarp%s,", colors.value, colors.end);
        } else if (dl_type == htons(ETH_TYPE_RARP)) {
            ds_put_format(s, "%srarp%s,", colors.value, colors.end);
        } else if (dl_type == htons(ETH_TYPE_MPLS)) {
            ds_put_format(s, "%smpls%s,", colors.value, colors.end);
        } else if (dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            ds_put_format(s, "%smplsm%s,", colors.value, colors.end);
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
        ds_put_format(s, "%sin_port=%s", colors.param, colors.end);
        ofputil_format_port(f->in_port.ofp_port, port_map, s);
        ds_put_char(s, ',');
    }
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        char str_i[8];

        if (!wc->masks.vlans[i].tci) {
            break;
        }

        /* Print VLAN tags as dl_vlan, dl_vlan1, dl_vlan2 ... */
        if (i == 0) {
            str_i[0] = '\0';
        } else {
            snprintf(str_i, sizeof(str_i), "%d", i);
        }
        ovs_be16 vid_mask = wc->masks.vlans[i].tci & htons(VLAN_VID_MASK);
        ovs_be16 pcp_mask = wc->masks.vlans[i].tci & htons(VLAN_PCP_MASK);
        ovs_be16 cfi = wc->masks.vlans[i].tci & htons(VLAN_CFI);

        if (cfi && f->vlans[i].tci & htons(VLAN_CFI)
            && (!vid_mask || vid_mask == htons(VLAN_VID_MASK))
            && (!pcp_mask || pcp_mask == htons(VLAN_PCP_MASK))
            && (vid_mask || pcp_mask)) {
            if (vid_mask) {
                ds_put_format(s, "%sdl_vlan%s=%s%"PRIu16",",
                              colors.param, str_i, colors.end,
                              vlan_tci_to_vid(f->vlans[i].tci));
            }
            if (pcp_mask) {
                ds_put_format(s, "%sdl_vlan_pcp%s=%s%d,",
                              colors.param, str_i, colors.end,
                              vlan_tci_to_pcp(f->vlans[i].tci));
            }
        } else if (wc->masks.vlans[i].tci == htons(0xffff)) {
            ds_put_format(s, "%svlan_tci%s=%s0x%04"PRIx16",",
                          colors.param, str_i, colors.end,
                          ntohs(f->vlans[i].tci));
        } else {
            ds_put_format(s, "%svlan_tci%s=%s0x%04"PRIx16"/0x%04"PRIx16",",
                          colors.param, str_i, colors.end,
                          ntohs(f->vlans[i].tci),
                          ntohs(wc->masks.vlans[i].tci));
        }
    }

    format_eth_masked(s, "dl_src", f->dl_src, wc->masks.dl_src);
    format_eth_masked(s, "dl_dst", f->dl_dst, wc->masks.dl_dst);

    if (!skip_type && wc->masks.dl_type) {
        ds_put_format(s, "%sdl_type=%s0x%04"PRIx16",",
                      colors.param, colors.end, ntohs(dl_type));
    }
    if (dl_type == htons(ETH_TYPE_IPV6)) {
        format_ipv6_netmask(s, "ipv6_src", &f->ipv6_src, &wc->masks.ipv6_src);
        format_ipv6_netmask(s, "ipv6_dst", &f->ipv6_dst, &wc->masks.ipv6_dst);
        if (wc->masks.ipv6_label) {
            if (wc->masks.ipv6_label == OVS_BE32_MAX) {
                ds_put_format(s, "%sipv6_label=%s0x%05"PRIx32",",
                              colors.param, colors.end,
                              ntohl(f->ipv6_label));
            } else {
                ds_put_format(s, "%sipv6_label=%s0x%05"PRIx32"/0x%05"PRIx32",",
                              colors.param, colors.end, ntohl(f->ipv6_label),
                              ntohl(wc->masks.ipv6_label));
            }
        }
    } else if (dl_type == htons(ETH_TYPE_ARP) ||
               dl_type == htons(ETH_TYPE_RARP)) {
        format_ip_netmask(s, "arp_spa", f->nw_src, wc->masks.nw_src);
        format_ip_netmask(s, "arp_tpa", f->nw_dst, wc->masks.nw_dst);
    } else if (dl_type == htons(ETH_TYPE_NSH)) {
        format_nsh_masked(s, f, &wc->masks);
    } else {
        format_ip_netmask(s, "nw_src", f->nw_src, wc->masks.nw_src);
        format_ip_netmask(s, "nw_dst", f->nw_dst, wc->masks.nw_dst);
    }
    if (!skip_proto && wc->masks.nw_proto) {
        if (dl_type == htons(ETH_TYPE_ARP) ||
            dl_type == htons(ETH_TYPE_RARP)) {
            ds_put_format(s, "%sarp_op=%s%"PRIu8",",
                          colors.param, colors.end, f->nw_proto);
        } else {
            ds_put_format(s, "%snw_proto=%s%"PRIu8",",
                          colors.param, colors.end, f->nw_proto);
        }
    }
    if (dl_type == htons(ETH_TYPE_ARP) ||
        dl_type == htons(ETH_TYPE_RARP)) {
        format_eth_masked(s, "arp_sha", f->arp_sha, wc->masks.arp_sha);
        format_eth_masked(s, "arp_tha", f->arp_tha, wc->masks.arp_tha);
    }
    if (wc->masks.nw_tos & IP_DSCP_MASK) {
        ds_put_format(s, "%snw_tos=%s%d,",
                      colors.param, colors.end, f->nw_tos & IP_DSCP_MASK);
    }
    if (wc->masks.nw_tos & IP_ECN_MASK) {
        ds_put_format(s, "%snw_ecn=%s%d,",
                      colors.param, colors.end, f->nw_tos & IP_ECN_MASK);
    }
    if (wc->masks.nw_ttl) {
        ds_put_format(s, "%snw_ttl=%s%d,",
                      colors.param, colors.end, f->nw_ttl);
    }
    if (wc->masks.mpls_lse[0] & htonl(MPLS_LABEL_MASK)) {
        ds_put_format(s, "%smpls_label=%s%"PRIu32",", colors.param,
                      colors.end, mpls_lse_to_label(f->mpls_lse[0]));
    }
    if (wc->masks.mpls_lse[0] & htonl(MPLS_TC_MASK)) {
        ds_put_format(s, "%smpls_tc=%s%"PRIu8",", colors.param, colors.end,
                      mpls_lse_to_tc(f->mpls_lse[0]));
    }
    if (wc->masks.mpls_lse[0] & htonl(MPLS_TTL_MASK)) {
        ds_put_format(s, "%smpls_ttl=%s%"PRIu8",", colors.param, colors.end,
                      mpls_lse_to_ttl(f->mpls_lse[0]));
    }
    if (wc->masks.mpls_lse[0] & htonl(MPLS_BOS_MASK)) {
        ds_put_format(s, "%smpls_bos=%s%"PRIu8",", colors.param, colors.end,
                      mpls_lse_to_bos(f->mpls_lse[0]));
    }
    format_be32_masked(s, "mpls_lse1", f->mpls_lse[1], wc->masks.mpls_lse[1]);
    format_be32_masked(s, "mpls_lse2", f->mpls_lse[2], wc->masks.mpls_lse[2]);

    switch (wc->masks.nw_frag) {
    case FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER:
        ds_put_format(s, "%snw_frag=%s%s,", colors.param, colors.end,
                      f->nw_frag & FLOW_NW_FRAG_ANY
                      ? (f->nw_frag & FLOW_NW_FRAG_LATER ? "later" : "first")
                      : (f->nw_frag & FLOW_NW_FRAG_LATER ? "<error>" : "no"));
        break;

    case FLOW_NW_FRAG_ANY:
        ds_put_format(s, "%snw_frag=%s%s,", colors.param, colors.end,
                      f->nw_frag & FLOW_NW_FRAG_ANY ? "yes" : "no");
        break;

    case FLOW_NW_FRAG_LATER:
        ds_put_format(s, "%snw_frag=%s%s,", colors.param, colors.end,
                      f->nw_frag & FLOW_NW_FRAG_LATER ? "later" : "not_later");
        break;
    }
    if (dl_type == htons(ETH_TYPE_IP) &&
        f->nw_proto == IPPROTO_ICMP) {
        format_be16_masked(s, "icmp_type", f->tp_src, wc->masks.tp_src);
        format_be16_masked(s, "icmp_code", f->tp_dst, wc->masks.tp_dst);
    } else if (dl_type == htons(ETH_TYPE_IP) &&
               f->nw_proto == IPPROTO_IGMP) {
        format_be16_masked(s, "igmp_type", f->tp_src, wc->masks.tp_src);
        format_be16_masked(s, "igmp_code", f->tp_dst, wc->masks.tp_dst);
    } else if (dl_type == htons(ETH_TYPE_IPV6) &&
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
        format_flags_masked(s, "tcp_flags", packet_tcp_flag_to_string,
                            ntohs(f->tcp_flags), TCP_FLAGS(wc->masks.tcp_flags),
                            TCP_FLAGS(OVS_BE16_MAX));
    }

    if (s->length > start_len) {
        ds_chomp(s, ',');
    }
}

/* Converts 'match' to a string and returns the string.  If 'priority' is
 * different from OFP_DEFAULT_PRIORITY, includes it in the string.  If
 * 'port_map' is nonnull, uses it to translate port numbers to names in
 * output.  The caller must free the string (with free()). */
char *
match_to_string(const struct match *match,
                const struct ofputil_port_map *port_map, int priority)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    match_format(match, port_map, &s, priority);
    return ds_steal_cstr(&s);
}

void
match_print(const struct match *match,
            const struct ofputil_port_map *port_map)
{
    char *s = match_to_string(match, port_map, OFP_DEFAULT_PRIORITY);
    puts(s);
    free(s);
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with minimatch_destroy(). */
void
minimatch_init(struct minimatch *dst, const struct match *src)
{
    struct miniflow tmp;

    miniflow_map_init(&tmp, &src->wc.masks);
    /* Allocate two consecutive miniflows. */
    miniflow_alloc(dst->flows, 2, &tmp);
    miniflow_init(dst->flow, &src->flow);
    minimask_init(dst->mask, &src->wc);

    dst->tun_md = tun_metadata_allocation_clone(&src->tun_md);
}

/* Initializes 'match' as a "catch-all" match that matches every packet. */
void
minimatch_init_catchall(struct minimatch *match)
{
    match->flows[0] = xcalloc(2, sizeof *match->flow);
    match->flows[1] = match->flows[0] + 1;
    match->tun_md = NULL;
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with minimatch_destroy(). */
void
minimatch_clone(struct minimatch *dst, const struct minimatch *src)
{
    /* Allocate two consecutive miniflows. */
    size_t data_size = miniflow_alloc(dst->flows, 2, &src->mask->masks);

    memcpy(miniflow_values(dst->flow),
           miniflow_get_values(src->flow), data_size);
    memcpy(miniflow_values(&dst->mask->masks),
           miniflow_get_values(&src->mask->masks), data_size);
    dst->tun_md = tun_metadata_allocation_clone(src->tun_md);
}

/* Initializes 'dst' with the data in 'src', destroying 'src'.  The caller must
 * eventually free 'dst' with minimatch_destroy(). */
void
minimatch_move(struct minimatch *dst, struct minimatch *src)
{
    dst->flow = src->flow;
    dst->mask = src->mask;
    dst->tun_md = src->tun_md;
}

/* Frees any memory owned by 'match'.  Does not free the storage in which
 * 'match' itself resides; the caller is responsible for that. */
void
minimatch_destroy(struct minimatch *match)
{
    free(match->flow);
    free(match->tun_md);
}

/* Initializes 'dst' as a copy of 'src'. */
void
minimatch_expand(const struct minimatch *src, struct match *dst)
{
    miniflow_expand(src->flow, &dst->flow);
    minimask_expand(src->mask, &dst->wc);
    tun_metadata_allocation_copy(&dst->tun_md, src->tun_md);
}

/* Returns true if 'a' and 'b' match the same packets, false otherwise.  */
bool
minimatch_equal(const struct minimatch *a, const struct minimatch *b)
{
    return minimask_equal(a->mask, b->mask)
        && miniflow_equal(a->flow, b->flow);
}

/* Returns a hash value for the flow and wildcards in 'match', starting from
 * 'basis'. */
uint32_t
minimatch_hash(const struct minimatch *match, uint32_t basis)
{
    size_t n_values = miniflow_n_values(match->flow);
    size_t flow_size = sizeof *match->flow + MINIFLOW_VALUES_SIZE(n_values);
    return hash_bytes(match->flow, 2 * flow_size, basis);
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
    const uint64_t *flowp = miniflow_get_values(match->flow);
    const uint64_t *maskp = miniflow_get_values(&match->mask->masks);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, match->flow->map) {
        if ((*flowp++ ^ flow_u64_value(target, idx)) & *maskp++) {
            return false;
        }
    }

    return true;
}

/* Appends a string representation of 'match' to 's'.  If 'priority' is
 * different from OFP_DEFAULT_PRIORITY, includes it in 's'.  If 'port_map' is
 * nonnull, uses it to translate port numbers to names in output. */
void
minimatch_format(const struct minimatch *match,
                 const struct tun_table *tun_table,
                 const struct ofputil_port_map *port_map,
                 struct ds *s, int priority)
{
    struct match megamatch;

    minimatch_expand(match, &megamatch);
    megamatch.flow.tunnel.metadata.tab = tun_table;

    match_format(&megamatch, port_map, s, priority);
}

/* Converts 'match' to a string and returns the string.  If 'priority' is
 * different from OFP_DEFAULT_PRIORITY, includes it in the string.  The caller
 * must free the string (with free()).  If 'port_map' is nonnull, uses it to
 * translate port numbers to names in output. */
char *
minimatch_to_string(const struct minimatch *match,
                    const struct ofputil_port_map *port_map, int priority)
{
    struct match megamatch;

    minimatch_expand(match, &megamatch);
    return match_to_string(&megamatch, port_map, priority);
}

static bool
minimatch_has_default_recirc_id(const struct minimatch *m)
{
    uint32_t flow_recirc_id = miniflow_get_recirc_id(m->flow);
    uint32_t mask_recirc_id = miniflow_get_recirc_id(&m->mask->masks);
    return flow_recirc_id == 0 && (mask_recirc_id == UINT32_MAX ||
                                   mask_recirc_id == 0);
}

static bool
minimatch_has_default_dp_hash(const struct minimatch *m)
{
    return (!miniflow_get_dp_hash(m->flow)
            && !miniflow_get_dp_hash(&m->mask->masks));
}

/* Return true if the hidden fields of the match are set to the default values.
 * The default values equals to those set up by match_init_hidden_fields(). */
bool
minimatch_has_default_hidden_fields(const struct minimatch *m)
{
    return (minimatch_has_default_recirc_id(m)
            && minimatch_has_default_dp_hash(m));
}
