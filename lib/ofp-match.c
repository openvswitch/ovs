/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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
#include "openvswitch/ofp-match.h"
#include "byte-order.h"
#include "flow.h"
#include "nx-match.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/packets.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_match);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Given the wildcard bit count in the least-significant 6 of 'wcbits', returns
 * an IP netmask with a 1 in each bit that must match and a 0 in each bit that
 * is wildcarded.
 *
 * The bits in 'wcbits' are in the format used in enum ofp_flow_wildcards: 0
 * is exact match, 1 ignores the LSB, 2 ignores the 2 least-significant bits,
 * ..., 32 and higher wildcard the entire field.  This is the *opposite* of the
 * usual convention where e.g. /24 indicates that 8 bits (not 24 bits) are
 * wildcarded. */
static ovs_be32
ofputil_wcbits_to_netmask(int wcbits)
{
    wcbits &= 0x3f;
    return wcbits < 32 ? htonl(~((1u << wcbits) - 1)) : 0;
}

/* Given the IP netmask 'netmask', returns the number of bits of the IP address
 * that it wildcards, that is, the number of 0-bits in 'netmask', a number
 * between 0 and 32 inclusive.
 *
 * If 'netmask' is not a CIDR netmask (see ip_is_cidr()), the return value will
 * still be in the valid range but isn't otherwise meaningful. */
static int
ofputil_netmask_to_wcbits(ovs_be32 netmask)
{
    return 32 - ip_count_cidr_bits(netmask);
}

/* Converts the OpenFlow 1.0 wildcards in 'ofpfw' (OFPFW10_*) into a
 * flow_wildcards in 'wc' for use in struct match.  It is the caller's
 * responsibility to handle the special case where the flow match's dl_vlan is
 * set to OFP_VLAN_NONE. */
void
ofputil_wildcard_from_ofpfw10(uint32_t ofpfw, struct flow_wildcards *wc)
{
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    /* Initialize most of wc. */
    flow_wildcards_init_catchall(wc);

    if (!(ofpfw & OFPFW10_IN_PORT)) {
        wc->masks.in_port.ofp_port = u16_to_ofp(UINT16_MAX);
    }

    if (!(ofpfw & OFPFW10_NW_TOS)) {
        wc->masks.nw_tos |= IP_DSCP_MASK;
    }

    if (!(ofpfw & OFPFW10_NW_PROTO)) {
        wc->masks.nw_proto = UINT8_MAX;
    }
    wc->masks.nw_src = ofputil_wcbits_to_netmask(ofpfw
                                                 >> OFPFW10_NW_SRC_SHIFT);
    wc->masks.nw_dst = ofputil_wcbits_to_netmask(ofpfw
                                                 >> OFPFW10_NW_DST_SHIFT);

    if (!(ofpfw & OFPFW10_TP_SRC)) {
        wc->masks.tp_src = OVS_BE16_MAX;
    }
    if (!(ofpfw & OFPFW10_TP_DST)) {
        wc->masks.tp_dst = OVS_BE16_MAX;
    }

    if (!(ofpfw & OFPFW10_DL_SRC)) {
        WC_MASK_FIELD(wc, dl_src);
    }
    if (!(ofpfw & OFPFW10_DL_DST)) {
        WC_MASK_FIELD(wc, dl_dst);
    }
    if (!(ofpfw & OFPFW10_DL_TYPE)) {
        wc->masks.dl_type = OVS_BE16_MAX;
    }

    /* VLAN TCI mask. */
    if (!(ofpfw & OFPFW10_DL_VLAN_PCP)) {
        wc->masks.vlans[0].tci |= htons(VLAN_PCP_MASK | VLAN_CFI);
    }
    if (!(ofpfw & OFPFW10_DL_VLAN)) {
        wc->masks.vlans[0].tci |= htons(VLAN_VID_MASK | VLAN_CFI);
    }
}

/* Converts the ofp10_match in 'ofmatch' into a struct match in 'match'. */
void
ofputil_match_from_ofp10_match(const struct ofp10_match *ofmatch,
                               struct match *match)
{
    uint32_t ofpfw = ntohl(ofmatch->wildcards) & OFPFW10_ALL;

    /* Initialize match->wc. */
    memset(&match->flow, 0, sizeof match->flow);
    ofputil_wildcard_from_ofpfw10(ofpfw, &match->wc);
    memset(&match->tun_md, 0, sizeof match->tun_md);

    /* If any fields, except in_port, are matched, then we also need to match
     * on the Ethernet packet_type. */
    const uint32_t ofpfw_data_bits = (OFPFW10_NW_TOS | OFPFW10_NW_PROTO
                                      | OFPFW10_TP_SRC | OFPFW10_TP_DST
                                      | OFPFW10_DL_SRC | OFPFW10_DL_DST
                                      | OFPFW10_DL_TYPE
                                      | OFPFW10_DL_VLAN | OFPFW10_DL_VLAN_PCP);
    if ((ofpfw & ofpfw_data_bits) != ofpfw_data_bits
        || ofputil_wcbits_to_netmask(ofpfw >> OFPFW10_NW_SRC_SHIFT)
        || ofputil_wcbits_to_netmask(ofpfw >> OFPFW10_NW_DST_SHIFT)) {
        match_set_default_packet_type(match);
    }

    /* Initialize most of match->flow. */
    match->flow.nw_src = ofmatch->nw_src;
    match->flow.nw_dst = ofmatch->nw_dst;
    match->flow.in_port.ofp_port = u16_to_ofp(ntohs(ofmatch->in_port));
    match->flow.dl_type = ofputil_dl_type_from_openflow(ofmatch->dl_type);
    match->flow.tp_src = ofmatch->tp_src;
    match->flow.tp_dst = ofmatch->tp_dst;
    match->flow.dl_src = ofmatch->dl_src;
    match->flow.dl_dst = ofmatch->dl_dst;
    match->flow.nw_tos = ofmatch->nw_tos & IP_DSCP_MASK;
    match->flow.nw_proto = ofmatch->nw_proto;

    /* Translate VLANs. */
    if (!(ofpfw & OFPFW10_DL_VLAN) &&
        ofmatch->dl_vlan == htons(OFP10_VLAN_NONE)) {
        /* Match only packets without 802.1Q header.
         *
         * When OFPFW10_DL_VLAN_PCP is wildcarded, this is obviously correct.
         *
         * If OFPFW10_DL_VLAN_PCP is matched, the flow match is contradictory,
         * because we can't have a specific PCP without an 802.1Q header.
         * However, older versions of OVS treated this as matching packets
         * withut an 802.1Q header, so we do here too. */
        match->flow.vlans[0].tci = htons(0);
        match->wc.masks.vlans[0].tci = htons(0xffff);
    } else {
        ovs_be16 vid, pcp, tci;
        uint16_t hpcp;

        vid = ofmatch->dl_vlan & htons(VLAN_VID_MASK);
        hpcp = (ofmatch->dl_vlan_pcp << VLAN_PCP_SHIFT) & VLAN_PCP_MASK;
        pcp = htons(hpcp);
        tci = vid | pcp | htons(VLAN_CFI);
        match->flow.vlans[0].tci = tci & match->wc.masks.vlans[0].tci;
    }

    /* Clean up. */
    match_zero_wildcarded_fields(match);
}

/* Convert 'match' into the OpenFlow 1.0 match structure 'ofmatch'. */
void
ofputil_match_to_ofp10_match(const struct match *match,
                             struct ofp10_match *ofmatch)
{
    const struct flow_wildcards *wc = &match->wc;
    uint32_t ofpfw;

    /* Figure out most OpenFlow wildcards. */
    ofpfw = 0;
    if (!wc->masks.in_port.ofp_port) {
        ofpfw |= OFPFW10_IN_PORT;
    }
    if (!wc->masks.dl_type) {
        ofpfw |= OFPFW10_DL_TYPE;
    }
    if (!wc->masks.nw_proto) {
        ofpfw |= OFPFW10_NW_PROTO;
    }
    ofpfw |= (ofputil_netmask_to_wcbits(wc->masks.nw_src)
              << OFPFW10_NW_SRC_SHIFT);
    ofpfw |= (ofputil_netmask_to_wcbits(wc->masks.nw_dst)
              << OFPFW10_NW_DST_SHIFT);
    if (!(wc->masks.nw_tos & IP_DSCP_MASK)) {
        ofpfw |= OFPFW10_NW_TOS;
    }
    if (!wc->masks.tp_src) {
        ofpfw |= OFPFW10_TP_SRC;
    }
    if (!wc->masks.tp_dst) {
        ofpfw |= OFPFW10_TP_DST;
    }
    if (eth_addr_is_zero(wc->masks.dl_src)) {
        ofpfw |= OFPFW10_DL_SRC;
    }
    if (eth_addr_is_zero(wc->masks.dl_dst)) {
        ofpfw |= OFPFW10_DL_DST;
    }

    /* Translate VLANs. */
    ofmatch->dl_vlan = htons(0);
    ofmatch->dl_vlan_pcp = 0;
    if (match->wc.masks.vlans[0].tci == htons(0)) {
        ofpfw |= OFPFW10_DL_VLAN | OFPFW10_DL_VLAN_PCP;
    } else if (match->wc.masks.vlans[0].tci & htons(VLAN_CFI)
               && !(match->flow.vlans[0].tci & htons(VLAN_CFI))) {
        ofmatch->dl_vlan = htons(OFP10_VLAN_NONE);
    } else {
        if (!(match->wc.masks.vlans[0].tci & htons(VLAN_VID_MASK))) {
            ofpfw |= OFPFW10_DL_VLAN;
        } else {
            ofmatch->dl_vlan =
                htons(vlan_tci_to_vid(match->flow.vlans[0].tci));
        }

        if (!(match->wc.masks.vlans[0].tci & htons(VLAN_PCP_MASK))) {
            ofpfw |= OFPFW10_DL_VLAN_PCP;
        } else {
            ofmatch->dl_vlan_pcp = vlan_tci_to_pcp(match->flow.vlans[0].tci);
        }
    }

    /* Compose most of the match structure. */
    ofmatch->wildcards = htonl(ofpfw);
    ofmatch->in_port = htons(ofp_to_u16(match->flow.in_port.ofp_port));
    ofmatch->dl_src = match->flow.dl_src;
    ofmatch->dl_dst = match->flow.dl_dst;
    ofmatch->dl_type = ofputil_dl_type_to_openflow(match->flow.dl_type);
    ofmatch->nw_src = match->flow.nw_src;
    ofmatch->nw_dst = match->flow.nw_dst;
    ofmatch->nw_tos = match->flow.nw_tos & IP_DSCP_MASK;
    ofmatch->nw_proto = match->flow.nw_proto;
    ofmatch->tp_src = match->flow.tp_src;
    ofmatch->tp_dst = match->flow.tp_dst;
    memset(ofmatch->pad1, '\0', sizeof ofmatch->pad1);
    memset(ofmatch->pad2, '\0', sizeof ofmatch->pad2);
}

enum ofperr
ofputil_pull_ofp11_match(struct ofpbuf *buf, const struct tun_table *tun_table,
                         const struct vl_mff_map *vl_mff_map,
                         struct match *match, uint16_t *padded_match_len)
{
    struct ofp11_match_header *omh = buf->data;
    uint16_t match_len;

    if (buf->size < sizeof *omh) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    match_len = ntohs(omh->length);

    switch (ntohs(omh->type)) {
    case OFPMT_STANDARD: {
        struct ofp11_match *om;

        if (match_len != sizeof *om || buf->size < sizeof *om) {
            return OFPERR_OFPBMC_BAD_LEN;
        }
        om = ofpbuf_pull(buf, sizeof *om);
        if (padded_match_len) {
            *padded_match_len = match_len;
        }
        return ofputil_match_from_ofp11_match(om, match);
    }

    case OFPMT_OXM:
        if (padded_match_len) {
            *padded_match_len = ROUND_UP(match_len, 8);
        }
        return oxm_pull_match(buf, false, tun_table, vl_mff_map, match);

    default:
        return OFPERR_OFPBMC_BAD_TYPE;
    }
}

/* Converts the ofp11_match in 'ofmatch' into a struct match in 'match'.
 * Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_match_from_ofp11_match(const struct ofp11_match *ofmatch,
                               struct match *match)
{
    uint16_t wc = ntohl(ofmatch->wildcards);
    bool ipv4, arp, rarp;

    match_init_catchall(match);
    match->flow.tunnel.metadata.tab = NULL;

    if (!(wc & OFPFW11_IN_PORT)) {
        ofp_port_t ofp_port;
        enum ofperr error;

        error = ofputil_port_from_ofp11(ofmatch->in_port, &ofp_port);
        if (error) {
            return OFPERR_OFPBMC_BAD_VALUE;
        }
        match_set_in_port(match, ofp_port);
    }

    struct eth_addr dl_src_mask = eth_addr_invert(ofmatch->dl_src_mask);
    struct eth_addr dl_dst_mask = eth_addr_invert(ofmatch->dl_dst_mask);
    if (!eth_addr_is_zero(dl_src_mask) || !eth_addr_is_zero(dl_dst_mask)) {
        match_set_dl_src_masked(match, ofmatch->dl_src, dl_src_mask);
        match_set_dl_dst_masked(match, ofmatch->dl_dst, dl_dst_mask);
        match_set_default_packet_type(match);
    }

    if (!(wc & OFPFW11_DL_VLAN)) {
        if (ofmatch->dl_vlan == htons(OFPVID11_NONE)) {
            /* Match only packets without a VLAN tag. */
            match->flow.vlans[0].tci = htons(0);
            match->wc.masks.vlans[0].tci = OVS_BE16_MAX;
        } else {
            if (ofmatch->dl_vlan == htons(OFPVID11_ANY)) {
                /* Match any packet with a VLAN tag regardless of VID. */
                match->flow.vlans[0].tci = htons(VLAN_CFI);
                match->wc.masks.vlans[0].tci = htons(VLAN_CFI);
            } else if (ntohs(ofmatch->dl_vlan) < 4096) {
                /* Match only packets with the specified VLAN VID. */
                match->flow.vlans[0].tci = htons(VLAN_CFI) | ofmatch->dl_vlan;
                match->wc.masks.vlans[0].tci = htons(VLAN_CFI | VLAN_VID_MASK);
            } else {
                /* Invalid VID. */
                return OFPERR_OFPBMC_BAD_VALUE;
            }

            if (!(wc & OFPFW11_DL_VLAN_PCP)) {
                if (ofmatch->dl_vlan_pcp <= 7) {
                    match->flow.vlans[0].tci |= htons(ofmatch->dl_vlan_pcp
                                                  << VLAN_PCP_SHIFT);
                    match->wc.masks.vlans[0].tci |= htons(VLAN_PCP_MASK);
                } else {
                    /* Invalid PCP. */
                    return OFPERR_OFPBMC_BAD_VALUE;
                }
            }
        }
        match_set_default_packet_type(match);
    }

    if (!(wc & OFPFW11_DL_TYPE)) {
        match_set_dl_type(match,
                          ofputil_dl_type_from_openflow(ofmatch->dl_type));
        match_set_default_packet_type(match);
    }

    ipv4 = match->flow.dl_type == htons(ETH_TYPE_IP);
    arp = match->flow.dl_type == htons(ETH_TYPE_ARP);
    rarp = match->flow.dl_type == htons(ETH_TYPE_RARP);

    if (ipv4 && !(wc & OFPFW11_NW_TOS)) {
        if (ofmatch->nw_tos & ~IP_DSCP_MASK) {
            /* Invalid TOS. */
            return OFPERR_OFPBMC_BAD_VALUE;
        }

        match_set_nw_dscp(match, ofmatch->nw_tos);
    }

    if (ipv4 || arp || rarp) {
        if (!(wc & OFPFW11_NW_PROTO)) {
            match_set_nw_proto(match, ofmatch->nw_proto);
        }
        match_set_nw_src_masked(match, ofmatch->nw_src, ~ofmatch->nw_src_mask);
        match_set_nw_dst_masked(match, ofmatch->nw_dst, ~ofmatch->nw_dst_mask);
    }

#define OFPFW11_TP_ALL (OFPFW11_TP_SRC | OFPFW11_TP_DST)
    if (ipv4 && (wc & OFPFW11_TP_ALL) != OFPFW11_TP_ALL) {
        switch (match->flow.nw_proto) {
        case IPPROTO_ICMP:
            /* "A.2.3 Flow Match Structures" in OF1.1 says:
             *
             *    The tp_src and tp_dst fields will be ignored unless the
             *    network protocol specified is as TCP, UDP or SCTP.
             *
             * but I'm pretty sure we should support ICMP too, otherwise
             * that's a regression from OF1.0. */
            if (!(wc & OFPFW11_TP_SRC)) {
                uint16_t icmp_type = ntohs(ofmatch->tp_src);
                if (icmp_type < 0x100) {
                    match_set_icmp_type(match, icmp_type);
                } else {
                    return OFPERR_OFPBMC_BAD_FIELD;
                }
            }
            if (!(wc & OFPFW11_TP_DST)) {
                uint16_t icmp_code = ntohs(ofmatch->tp_dst);
                if (icmp_code < 0x100) {
                    match_set_icmp_code(match, icmp_code);
                } else {
                    return OFPERR_OFPBMC_BAD_FIELD;
                }
            }
            break;

        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_SCTP:
            if (!(wc & (OFPFW11_TP_SRC))) {
                match_set_tp_src(match, ofmatch->tp_src);
            }
            if (!(wc & (OFPFW11_TP_DST))) {
                match_set_tp_dst(match, ofmatch->tp_dst);
            }
            break;

        default:
            /* OF1.1 says explicitly to ignore this. */
            break;
        }
    }

    if (eth_type_mpls(match->flow.dl_type)) {
        if (!(wc & OFPFW11_MPLS_LABEL)) {
            match_set_mpls_label(match, 0, ofmatch->mpls_label);
        }
        if (!(wc & OFPFW11_MPLS_TC)) {
            match_set_mpls_tc(match, 0, ofmatch->mpls_tc);
        }
    }

    match_set_metadata_masked(match, ofmatch->metadata,
                              ~ofmatch->metadata_mask);

    return 0;
}

/* Convert 'match' into the OpenFlow 1.1 match structure 'ofmatch'. */
void
ofputil_match_to_ofp11_match(const struct match *match,
                             struct ofp11_match *ofmatch)
{
    uint32_t wc = 0;

    memset(ofmatch, 0, sizeof *ofmatch);
    ofmatch->omh.type = htons(OFPMT_STANDARD);
    ofmatch->omh.length = htons(OFPMT11_STANDARD_LENGTH);

    if (!match->wc.masks.in_port.ofp_port) {
        wc |= OFPFW11_IN_PORT;
    } else {
        ofmatch->in_port = ofputil_port_to_ofp11(match->flow.in_port.ofp_port);
    }

    ofmatch->dl_src = match->flow.dl_src;
    ofmatch->dl_src_mask = eth_addr_invert(match->wc.masks.dl_src);
    ofmatch->dl_dst = match->flow.dl_dst;
    ofmatch->dl_dst_mask = eth_addr_invert(match->wc.masks.dl_dst);

    if (match->wc.masks.vlans[0].tci == htons(0)) {
        wc |= OFPFW11_DL_VLAN | OFPFW11_DL_VLAN_PCP;
    } else if (match->wc.masks.vlans[0].tci & htons(VLAN_CFI)
               && !(match->flow.vlans[0].tci & htons(VLAN_CFI))) {
        ofmatch->dl_vlan = htons(OFPVID11_NONE);
        wc |= OFPFW11_DL_VLAN_PCP;
    } else {
        if (!(match->wc.masks.vlans[0].tci & htons(VLAN_VID_MASK))) {
            ofmatch->dl_vlan = htons(OFPVID11_ANY);
        } else {
            ofmatch->dl_vlan =
                htons(vlan_tci_to_vid(match->flow.vlans[0].tci));
        }

        if (!(match->wc.masks.vlans[0].tci & htons(VLAN_PCP_MASK))) {
            wc |= OFPFW11_DL_VLAN_PCP;
        } else {
            ofmatch->dl_vlan_pcp = vlan_tci_to_pcp(match->flow.vlans[0].tci);
        }
    }

    if (!match->wc.masks.dl_type) {
        wc |= OFPFW11_DL_TYPE;
    } else {
        ofmatch->dl_type = ofputil_dl_type_to_openflow(match->flow.dl_type);
    }

    if (!(match->wc.masks.nw_tos & IP_DSCP_MASK)) {
        wc |= OFPFW11_NW_TOS;
    } else {
        ofmatch->nw_tos = match->flow.nw_tos & IP_DSCP_MASK;
    }

    if (!match->wc.masks.nw_proto) {
        wc |= OFPFW11_NW_PROTO;
    } else {
        ofmatch->nw_proto = match->flow.nw_proto;
    }

    ofmatch->nw_src = match->flow.nw_src;
    ofmatch->nw_src_mask = ~match->wc.masks.nw_src;
    ofmatch->nw_dst = match->flow.nw_dst;
    ofmatch->nw_dst_mask = ~match->wc.masks.nw_dst;

    if (!match->wc.masks.tp_src) {
        wc |= OFPFW11_TP_SRC;
    } else {
        ofmatch->tp_src = match->flow.tp_src;
    }

    if (!match->wc.masks.tp_dst) {
        wc |= OFPFW11_TP_DST;
    } else {
        ofmatch->tp_dst = match->flow.tp_dst;
    }

    if (!(match->wc.masks.mpls_lse[0] & htonl(MPLS_LABEL_MASK))) {
        wc |= OFPFW11_MPLS_LABEL;
    } else {
        ofmatch->mpls_label = htonl(mpls_lse_to_label(
                                        match->flow.mpls_lse[0]));
    }

    if (!(match->wc.masks.mpls_lse[0] & htonl(MPLS_TC_MASK))) {
        wc |= OFPFW11_MPLS_TC;
    } else {
        ofmatch->mpls_tc = mpls_lse_to_tc(match->flow.mpls_lse[0]);
    }

    ofmatch->metadata = match->flow.metadata;
    ofmatch->metadata_mask = ~match->wc.masks.metadata;

    ofmatch->wildcards = htonl(wc);
}

/* Returns the "typical" length of a match for 'protocol', for use in
 * estimating space to preallocate. */
int
ofputil_match_typical_len(enum ofputil_protocol protocol)
{
    switch (protocol) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
        return sizeof(struct ofp10_match);

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        return NXM_TYPICAL_LEN;

    case OFPUTIL_P_OF11_STD:
        return sizeof(struct ofp11_match);

    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
    case OFPUTIL_P_OF14_OXM:
    case OFPUTIL_P_OF15_OXM:
        return NXM_TYPICAL_LEN;

    default:
        OVS_NOT_REACHED();
    }
}

/* Appends to 'b' an struct ofp11_match_header followed by a match that
 * expresses 'match' properly for 'protocol', plus enough zero bytes to pad the
 * data appended out to a multiple of 8.  'protocol' must be one that is usable
 * in OpenFlow 1.1 or later.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding the padding.  Never
 * returns zero. */
int
ofputil_put_ofp11_match(struct ofpbuf *b, const struct match *match,
                        enum ofputil_protocol protocol)
{
    switch (protocol) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        OVS_NOT_REACHED();

    case OFPUTIL_P_OF11_STD: {
        struct ofp11_match *om;

        /* Make sure that no padding is needed. */
        BUILD_ASSERT_DECL(sizeof *om % 8 == 0);

        om = ofpbuf_put_uninit(b, sizeof *om);
        ofputil_match_to_ofp11_match(match, om);
        return sizeof *om;
    }

    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
    case OFPUTIL_P_OF14_OXM:
    case OFPUTIL_P_OF15_OXM:
        return oxm_put_match(b, match,
                             ofputil_protocol_to_ofp_version(protocol));
    }

    OVS_NOT_REACHED();
}

/* Given a 'dl_type' value in the format used in struct flow, returns the
 * corresponding 'dl_type' value for use in an ofp10_match or ofp11_match
 * structure. */
ovs_be16
ofputil_dl_type_to_openflow(ovs_be16 flow_dl_type)
{
    return (flow_dl_type == htons(FLOW_DL_TYPE_NONE)
            ? htons(OFP_DL_TYPE_NOT_ETH_TYPE)
            : flow_dl_type);
}

/* Given a 'dl_type' value in the format used in an ofp10_match or ofp11_match
 * structure, returns the corresponding 'dl_type' value for use in struct
 * flow. */
ovs_be16
ofputil_dl_type_from_openflow(ovs_be16 ofp_dl_type)
{
    return (ofp_dl_type == htons(OFP_DL_TYPE_NOT_ETH_TYPE)
            ? htons(FLOW_DL_TYPE_NONE)
            : ofp_dl_type);
}

static void
encode_tlv_table_mappings(struct ofpbuf *b, struct ovs_list *mappings)
{
    struct ofputil_tlv_map *map;

    LIST_FOR_EACH (map, list_node, mappings) {
        struct nx_tlv_map *nx_map;

        nx_map = ofpbuf_put_zeros(b, sizeof *nx_map);
        nx_map->option_class = htons(map->option_class);
        nx_map->option_type = map->option_type;
        nx_map->option_len = map->option_len;
        nx_map->index = htons(map->index);
    }
}

struct ofpbuf *
ofputil_encode_tlv_table_mod(enum ofp_version ofp_version,
                                struct ofputil_tlv_table_mod *ttm)
{
    struct ofpbuf *b;
    struct nx_tlv_table_mod *nx_ttm;

    b = ofpraw_alloc(OFPRAW_NXT_TLV_TABLE_MOD, ofp_version, 0);
    nx_ttm = ofpbuf_put_zeros(b, sizeof *nx_ttm);
    nx_ttm->command = htons(ttm->command);
    encode_tlv_table_mappings(b, &ttm->mappings);

    return b;
}

static enum ofperr
decode_tlv_table_mappings(struct ofpbuf *msg, unsigned int max_fields,
                             struct ovs_list *mappings)
{
    ovs_list_init(mappings);

    while (msg->size) {
        struct nx_tlv_map *nx_map;
        struct ofputil_tlv_map *map;

        nx_map = ofpbuf_pull(msg, sizeof *nx_map);
        map = xmalloc(sizeof *map);
        ovs_list_push_back(mappings, &map->list_node);

        map->option_class = ntohs(nx_map->option_class);
        map->option_type = nx_map->option_type;

        map->option_len = nx_map->option_len;
        if (map->option_len % 4 || map->option_len > TLV_MAX_OPT_SIZE) {
            VLOG_WARN_RL(&rl, "tlv table option length (%u) is not a "
                         "valid option size", map->option_len);
            ofputil_uninit_tlv_table(mappings);
            return OFPERR_NXTTMFC_BAD_OPT_LEN;
        }

        map->index = ntohs(nx_map->index);
        if (map->index >= max_fields) {
            VLOG_WARN_RL(&rl, "tlv table field index (%u) is too large "
                         "(max %u)", map->index, max_fields - 1);
            ofputil_uninit_tlv_table(mappings);
            return OFPERR_NXTTMFC_BAD_FIELD_IDX;
        }
    }

    return 0;
}

enum ofperr
ofputil_decode_tlv_table_mod(const struct ofp_header *oh,
                                struct ofputil_tlv_table_mod *ttm)
{
    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&msg);

    struct nx_tlv_table_mod *nx_ttm = ofpbuf_pull(&msg, sizeof *nx_ttm);
    ttm->command = ntohs(nx_ttm->command);
    if (ttm->command > NXTTMC_CLEAR) {
        VLOG_WARN_RL(&rl, "tlv table mod command (%u) is out of range",
                     ttm->command);
        return OFPERR_NXTTMFC_BAD_COMMAND;
    }

    return decode_tlv_table_mappings(&msg, TUN_METADATA_NUM_OPTS,
                                        &ttm->mappings);
}

static void
print_tlv_table(struct ds *s, const struct ovs_list *mappings)
{
    struct ofputil_tlv_map *map;

    ds_put_cstr(s, " mapping table:\n");
    ds_put_cstr(s, "  class  type  length  match field\n");
    ds_put_cstr(s, " ------  ----  ------  --------------");

    LIST_FOR_EACH (map, list_node, mappings) {
        ds_put_format(s, "\n %#6"PRIx16"  %#4"PRIx8"  %6"PRIu8"  "
                      "tun_metadata%"PRIu16,
                      map->option_class, map->option_type, map->option_len,
                      map->index);
    }
}

void
ofputil_format_tlv_table_mod(struct ds *s,
                             const struct ofputil_tlv_table_mod *ttm)
{
    ds_put_cstr(s, "\n ");

    switch (ttm->command) {
    case NXTTMC_ADD:
        ds_put_cstr(s, "ADD");
        break;
    case NXTTMC_DELETE:
        ds_put_cstr(s, "DEL");
        break;
    case NXTTMC_CLEAR:
        ds_put_cstr(s, "CLEAR");
        break;
    }

    if (ttm->command != NXTTMC_CLEAR) {
        print_tlv_table(s, &ttm->mappings);
    }
}

struct ofpbuf *
ofputil_encode_tlv_table_reply(const struct ofp_header *oh,
                                  struct ofputil_tlv_table_reply *ttr)
{
    struct ofpbuf *b;
    struct nx_tlv_table_reply *nx_ttr;

    b = ofpraw_alloc_reply(OFPRAW_NXT_TLV_TABLE_REPLY, oh, 0);
    nx_ttr = ofpbuf_put_zeros(b, sizeof *nx_ttr);
    nx_ttr->max_option_space = htonl(ttr->max_option_space);
    nx_ttr->max_fields = htons(ttr->max_fields);

    encode_tlv_table_mappings(b, &ttr->mappings);

    return b;
}

/* Decodes the NXT_TLV_TABLE_REPLY message in 'oh' into '*ttr'.  Returns 0
 * if successful, otherwise an ofperr.
 *
 * The decoder verifies that the indexes in 'ttr->mappings' are less than
 * 'ttr->max_fields', but the caller must ensure, if necessary, that they are
 * less than TUN_METADATA_NUM_OPTS. */
enum ofperr
ofputil_decode_tlv_table_reply(const struct ofp_header *oh,
                                  struct ofputil_tlv_table_reply *ttr)
{
    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&msg);

    struct nx_tlv_table_reply *nx_ttr = ofpbuf_pull(&msg, sizeof *nx_ttr);
    ttr->max_option_space = ntohl(nx_ttr->max_option_space);
    ttr->max_fields = ntohs(nx_ttr->max_fields);

    return decode_tlv_table_mappings(&msg, ttr->max_fields, &ttr->mappings);
}

char * OVS_WARN_UNUSED_RESULT
parse_ofp_tlv_table_mod_str(struct ofputil_tlv_table_mod *ttm,
                               uint16_t command, const char *s,
                               enum ofputil_protocol *usable_protocols)
{
    *usable_protocols = OFPUTIL_P_NXM_OXM_ANY;

    ttm->command = command;
    ovs_list_init(&ttm->mappings);

    while (*s) {
        struct ofputil_tlv_map *map = xmalloc(sizeof *map);
        int n;

        if (*s == ',') {
            s++;
        }

        ovs_list_push_back(&ttm->mappings, &map->list_node);

        if (!ovs_scan(s, "{class=%"SCNi16",type=%"SCNi8",len=%"SCNi8"}"
                      "->tun_metadata%"SCNi16"%n",
                      &map->option_class, &map->option_type, &map->option_len,
                      &map->index, &n)) {
            ofputil_uninit_tlv_table(&ttm->mappings);
            return xstrdup("invalid tlv mapping");
        }

        s += n;
    }

    return NULL;
}

void
ofputil_format_tlv_table_reply(struct ds *s,
                               const struct ofputil_tlv_table_reply *ttr)
{
    ds_put_char(s, '\n');

    const struct ofputil_tlv_map *map;
    int allocated_space = 0;
    LIST_FOR_EACH (map, list_node, &ttr->mappings) {
        allocated_space += map->option_len;
    }

    ds_put_format(s, " max option space=%"PRIu32" max fields=%"PRIu16"\n",
                  ttr->max_option_space, ttr->max_fields);
    ds_put_format(s, " allocated option space=%d\n", allocated_space);
    ds_put_char(s, '\n');
    print_tlv_table(s, &ttr->mappings);
}

void
ofputil_uninit_tlv_table(struct ovs_list *mappings)
{
    struct ofputil_tlv_map *map;

    LIST_FOR_EACH_POP (map, list_node, mappings) {
        free(map);
    }
}

static void
ofputil_normalize_match__(struct match *match, bool may_log)
{
    enum {
        MAY_NW_ADDR     = 1 << 0, /* nw_src, nw_dst */
        MAY_TP_ADDR     = 1 << 1, /* tp_src, tp_dst */
        MAY_NW_PROTO    = 1 << 2, /* nw_proto */
        MAY_IPVx        = 1 << 3, /* tos, frag, ttl */
        MAY_ARP_SHA     = 1 << 4, /* arp_sha */
        MAY_ARP_THA     = 1 << 5, /* arp_tha */
        MAY_IPV6        = 1 << 6, /* ipv6_src, ipv6_dst, ipv6_label */
        MAY_ND_TARGET   = 1 << 7, /* nd_target */
        MAY_MPLS        = 1 << 8, /* mpls label and tc */
        MAY_ETHER       = 1 << 9, /* dl_src, dl_dst */
    } may_match;

    struct flow_wildcards wc = match->wc;
    ovs_be16 dl_type;

    /* Figure out what fields may be matched. */
    /* Check the packet_type first and extract dl_type. */
    if (wc.masks.packet_type == 0 || match_has_default_packet_type(match)) {
        may_match = MAY_ETHER;
        dl_type = match->flow.dl_type;
    } else if (wc.masks.packet_type == OVS_BE32_MAX &&
               pt_ns(match->flow.packet_type) == OFPHTN_ETHERTYPE) {
        may_match = 0;
        dl_type = pt_ns_type_be(match->flow.packet_type);
    } else {
        may_match = 0;
        dl_type = 0;
    }
    if (dl_type == htons(ETH_TYPE_IP)) {
        may_match |= MAY_NW_PROTO | MAY_IPVx | MAY_NW_ADDR;
        if (match->flow.nw_proto == IPPROTO_TCP ||
            match->flow.nw_proto == IPPROTO_UDP ||
            match->flow.nw_proto == IPPROTO_SCTP ||
            match->flow.nw_proto == IPPROTO_ICMP) {
            may_match |= MAY_TP_ADDR;
        }
    } else if (dl_type == htons(ETH_TYPE_IPV6)) {
        may_match |= MAY_NW_PROTO | MAY_IPVx | MAY_IPV6;
        if (match->flow.nw_proto == IPPROTO_TCP ||
            match->flow.nw_proto == IPPROTO_UDP ||
            match->flow.nw_proto == IPPROTO_SCTP) {
            may_match |= MAY_TP_ADDR;
        } else if (match->flow.nw_proto == IPPROTO_ICMPV6) {
            may_match |= MAY_TP_ADDR;
            if (match->flow.tp_src == htons(ND_NEIGHBOR_SOLICIT)) {
                may_match |= MAY_ND_TARGET | MAY_ARP_SHA;
            } else if (match->flow.tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                may_match |= MAY_ND_TARGET | MAY_ARP_THA;
            }
        }
    } else if (dl_type == htons(ETH_TYPE_ARP) ||
               dl_type == htons(ETH_TYPE_RARP)) {
        may_match |= MAY_NW_PROTO | MAY_NW_ADDR | MAY_ARP_SHA | MAY_ARP_THA;
    } else if (eth_type_mpls(dl_type)) {
        may_match |= MAY_MPLS;
    }

    /* Clear the fields that may not be matched. */
    if (!(may_match & MAY_ETHER)) {
        wc.masks.dl_src = wc.masks.dl_dst = eth_addr_zero;
    }
    if (!(may_match & MAY_NW_ADDR)) {
        wc.masks.nw_src = wc.masks.nw_dst = htonl(0);
    }
    if (!(may_match & MAY_TP_ADDR)) {
        wc.masks.tp_src = wc.masks.tp_dst = htons(0);
    }
    if (!(may_match & MAY_NW_PROTO)) {
        wc.masks.nw_proto = 0;
    }
    if (!(may_match & MAY_IPVx)) {
        wc.masks.nw_tos = 0;
        wc.masks.nw_ttl = 0;
    }
    if (!(may_match & MAY_ARP_SHA)) {
        WC_UNMASK_FIELD(&wc, arp_sha);
    }
    if (!(may_match & MAY_ARP_THA)) {
        WC_UNMASK_FIELD(&wc, arp_tha);
    }
    if (!(may_match & MAY_IPV6)) {
        wc.masks.ipv6_src = wc.masks.ipv6_dst = in6addr_any;
        wc.masks.ipv6_label = htonl(0);
    }
    if (!(may_match & MAY_ND_TARGET)) {
        wc.masks.nd_target = in6addr_any;
    }
    if (!(may_match & MAY_MPLS)) {
        memset(wc.masks.mpls_lse, 0, sizeof wc.masks.mpls_lse);
    }

    /* Log any changes. */
    if (!flow_wildcards_equal(&wc, &match->wc)) {
        bool log = may_log && !VLOG_DROP_INFO(&rl);
        char *pre = (log
                     ? match_to_string(match, NULL, OFP_DEFAULT_PRIORITY)
                     : NULL);

        match->wc = wc;
        match_zero_wildcarded_fields(match);

        if (log) {
            char *post = match_to_string(match, NULL, OFP_DEFAULT_PRIORITY);
            VLOG_INFO("normalization changed ofp_match, details:");
            VLOG_INFO(" pre: %s", pre);
            VLOG_INFO("post: %s", post);
            free(pre);
            free(post);
        }
    }
}

/* "Normalizes" the wildcards in 'match'.  That means:
 *
 *    1. If the type of level N is known, then only the valid fields for that
 *       level may be specified.  For example, ARP does not have a TOS field,
 *       so nw_tos must be wildcarded if 'match' specifies an ARP flow.
 *       Similarly, IPv4 does not have any IPv6 addresses, so ipv6_src and
 *       ipv6_dst (and other fields) must be wildcarded if 'match' specifies an
 *       IPv4 flow.
 *
 *    2. If the type of level N is not known (or not understood by Open
 *       vSwitch), then no fields at all for that level may be specified.  For
 *       example, Open vSwitch does not understand SCTP, an L4 protocol, so the
 *       L4 fields tp_src and tp_dst must be wildcarded if 'match' specifies an
 *       SCTP flow.
 *
 * If this function changes 'match', it logs a rate-limited informational
 * message. */
void
ofputil_normalize_match(struct match *match)
{
    ofputil_normalize_match__(match, true);
}

/* Same as ofputil_normalize_match() without the logging.  Thus, this function
 * is suitable for a program's internal use, whereas ofputil_normalize_match()
 * sense for use on flows received from elsewhere (so that a bug in the program
 * that sent them can be reported and corrected). */
void
ofputil_normalize_match_quiet(struct match *match)
{
    ofputil_normalize_match__(match, false);
}

static void OVS_PRINTF_FORMAT(5, 6)
print_wild(struct ds *string, const char *leader, int is_wild,
           int verbosity, const char *format, ...)
{
    if (is_wild && verbosity < 2) {
        return;
    }
    ds_put_cstr(string, leader);
    if (!is_wild) {
        va_list args;

        va_start(args, format);
        ds_put_format_valist(string, format, args);
        va_end(args);
    } else {
        ds_put_char(string, '*');
    }
    ds_put_char(string, ',');
}

static void
print_wild_port(struct ds *string, const char *leader, int is_wild,
                int verbosity, ofp_port_t port,
                const struct ofputil_port_map *port_map)
{
    if (is_wild && verbosity < 2) {
        return;
    }
    ds_put_cstr(string, leader);
    if (!is_wild) {
        ofputil_format_port(port, port_map, string);
    } else {
        ds_put_char(string, '*');
    }
    ds_put_char(string, ',');
}

static void
print_ip_netmask(struct ds *string, const char *leader, ovs_be32 ip,
                 uint32_t wild_bits, int verbosity)
{
    if (wild_bits >= 32 && verbosity < 2) {
        return;
    }
    ds_put_cstr(string, leader);
    if (wild_bits < 32) {
        ds_put_format(string, IP_FMT, IP_ARGS(ip));
        if (wild_bits) {
            ds_put_format(string, "/%d", 32 - wild_bits);
        }
    } else {
        ds_put_char(string, '*');
    }
    ds_put_char(string, ',');
}

void
ofp10_match_print(struct ds *f, const struct ofp10_match *om,
                  const struct ofputil_port_map *port_map, int verbosity)
{
    char *s = ofp10_match_to_string(om, port_map, verbosity);
    ds_put_cstr(f, s);
    free(s);
}

char *
ofp10_match_to_string(const struct ofp10_match *om,
                      const struct ofputil_port_map *port_map, int verbosity)
{
    struct ds f = DS_EMPTY_INITIALIZER;
    uint32_t w = ntohl(om->wildcards);
    bool skip_type = false;
    bool skip_proto = false;

    if (!(w & OFPFW10_DL_TYPE)) {
        skip_type = true;
        if (om->dl_type == htons(ETH_TYPE_IP)) {
            if (!(w & OFPFW10_NW_PROTO)) {
                skip_proto = true;
                if (om->nw_proto == IPPROTO_ICMP) {
                    ds_put_cstr(&f, "icmp,");
                } else if (om->nw_proto == IPPROTO_TCP) {
                    ds_put_cstr(&f, "tcp,");
                } else if (om->nw_proto == IPPROTO_UDP) {
                    ds_put_cstr(&f, "udp,");
                } else if (om->nw_proto == IPPROTO_SCTP) {
                    ds_put_cstr(&f, "sctp,");
                } else {
                    ds_put_cstr(&f, "ip,");
                    skip_proto = false;
                }
            } else {
                ds_put_cstr(&f, "ip,");
            }
        } else if (om->dl_type == htons(ETH_TYPE_ARP)) {
            ds_put_cstr(&f, "arp,");
        } else if (om->dl_type == htons(ETH_TYPE_RARP)){
            ds_put_cstr(&f, "rarp,");
        } else if (om->dl_type == htons(ETH_TYPE_MPLS)) {
            ds_put_cstr(&f, "mpls,");
        } else if (om->dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
            ds_put_cstr(&f, "mplsm,");
        } else {
            skip_type = false;
        }
    }
    print_wild_port(&f, "in_port=", w & OFPFW10_IN_PORT, verbosity,
                    u16_to_ofp(ntohs(om->in_port)), port_map);
    print_wild(&f, "dl_vlan=", w & OFPFW10_DL_VLAN, verbosity,
               "%d", ntohs(om->dl_vlan));
    print_wild(&f, "dl_vlan_pcp=", w & OFPFW10_DL_VLAN_PCP, verbosity,
               "%d", om->dl_vlan_pcp);
    print_wild(&f, "dl_src=", w & OFPFW10_DL_SRC, verbosity,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_src));
    print_wild(&f, "dl_dst=", w & OFPFW10_DL_DST, verbosity,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_dst));
    if (!skip_type) {
        print_wild(&f, "dl_type=", w & OFPFW10_DL_TYPE, verbosity,
                   "0x%04x", ntohs(om->dl_type));
    }
    print_ip_netmask(&f, "nw_src=", om->nw_src,
                     (w & OFPFW10_NW_SRC_MASK) >> OFPFW10_NW_SRC_SHIFT,
                     verbosity);
    print_ip_netmask(&f, "nw_dst=", om->nw_dst,
                     (w & OFPFW10_NW_DST_MASK) >> OFPFW10_NW_DST_SHIFT,
                     verbosity);
    if (!skip_proto) {
        if (om->dl_type == htons(ETH_TYPE_ARP) ||
            om->dl_type == htons(ETH_TYPE_RARP)) {
            print_wild(&f, "arp_op=", w & OFPFW10_NW_PROTO, verbosity,
                       "%u", om->nw_proto);
        } else {
            print_wild(&f, "nw_proto=", w & OFPFW10_NW_PROTO, verbosity,
                       "%u", om->nw_proto);
        }
    }
    print_wild(&f, "nw_tos=", w & OFPFW10_NW_TOS, verbosity,
               "%u", om->nw_tos);
    if (om->nw_proto == IPPROTO_ICMP) {
        print_wild(&f, "icmp_type=", w & OFPFW10_ICMP_TYPE, verbosity,
                   "%d", ntohs(om->tp_src));
        print_wild(&f, "icmp_code=", w & OFPFW10_ICMP_CODE, verbosity,
                   "%d", ntohs(om->tp_dst));
    } else {
        print_wild(&f, "tp_src=", w & OFPFW10_TP_SRC, verbosity,
                   "%d", ntohs(om->tp_src));
        print_wild(&f, "tp_dst=", w & OFPFW10_TP_DST, verbosity,
                   "%d", ntohs(om->tp_dst));
    }
    ds_chomp(&f, ',');
    return ds_cstr(&f);
}

