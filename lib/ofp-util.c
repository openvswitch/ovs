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
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include "bitmap.h"
#include "bundle.h"
#include "byte-order.h"
#include "classifier.h"
#include "learn.h"
#include "multipath.h"
#include "netdev.h"
#include "nx-match.h"
#include "id-pool.h"
#include "openflow/netronome-ext.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/type-props.h"
#include "openvswitch/vlog.h"
#include "openflow/intel-ext.h"
#include "packets.h"
#include "random.h"
#include "tun-metadata.h"
#include "unaligned.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(ofp_util);

/* Rate limit for OpenFlow message parse errors.  These always indicate a bug
 * in the peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit bad_ofmsg_rl = VLOG_RATE_LIMIT_INIT(1, 5);

static enum ofputil_table_vacancy ofputil_decode_table_vacancy(
    ovs_be32 config, enum ofp_version);
static enum ofputil_table_eviction ofputil_decode_table_eviction(
    ovs_be32 config, enum ofp_version);
static ovs_be32 ofputil_encode_table_config(enum ofputil_table_miss,
                                            enum ofputil_table_eviction,
                                            enum ofputil_table_vacancy,
                                            enum ofp_version);

/* Given the wildcard bit count in the least-significant 6 of 'wcbits', returns
 * an IP netmask with a 1 in each bit that must match and a 0 in each bit that
 * is wildcarded.
 *
 * The bits in 'wcbits' are in the format used in enum ofp_flow_wildcards: 0
 * is exact match, 1 ignores the LSB, 2 ignores the 2 least-significant bits,
 * ..., 32 and higher wildcard the entire field.  This is the *opposite* of the
 * usual convention where e.g. /24 indicates that 8 bits (not 24 bits) are
 * wildcarded. */
ovs_be32
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
int
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
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 40);

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
    case OFPUTIL_P_OF16_OXM:
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
    case OFPUTIL_P_OF16_OXM:
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

/* Protocols. */

struct proto_abbrev {
    enum ofputil_protocol protocol;
    const char *name;
};

/* Most users really don't care about some of the differences between
 * protocols.  These abbreviations help with that. */
static const struct proto_abbrev proto_abbrevs[] = {
    { OFPUTIL_P_ANY,          "any" },
    { OFPUTIL_P_OF10_STD_ANY, "OpenFlow10" },
    { OFPUTIL_P_OF10_NXM_ANY, "NXM" },
    { OFPUTIL_P_ANY_OXM,      "OXM" },
};
#define N_PROTO_ABBREVS ARRAY_SIZE(proto_abbrevs)

enum ofputil_protocol ofputil_flow_dump_protocols[] = {
    OFPUTIL_P_OF16_OXM,
    OFPUTIL_P_OF15_OXM,
    OFPUTIL_P_OF14_OXM,
    OFPUTIL_P_OF13_OXM,
    OFPUTIL_P_OF12_OXM,
    OFPUTIL_P_OF11_STD,
    OFPUTIL_P_OF10_NXM,
    OFPUTIL_P_OF10_STD,
};
size_t ofputil_n_flow_dump_protocols = ARRAY_SIZE(ofputil_flow_dump_protocols);

/* Returns the set of ofputil_protocols that are supported with the given
 * OpenFlow 'version'.  'version' should normally be an 8-bit OpenFlow version
 * identifier (e.g. 0x01 for OpenFlow 1.0, 0x02 for OpenFlow 1.1).  Returns 0
 * if 'version' is not supported or outside the valid range.  */
enum ofputil_protocol
ofputil_protocols_from_ofp_version(enum ofp_version version)
{
    switch (version) {
    case OFP10_VERSION:
        return OFPUTIL_P_OF10_STD_ANY | OFPUTIL_P_OF10_NXM_ANY;
    case OFP11_VERSION:
        return OFPUTIL_P_OF11_STD;
    case OFP12_VERSION:
        return OFPUTIL_P_OF12_OXM;
    case OFP13_VERSION:
        return OFPUTIL_P_OF13_OXM;
    case OFP14_VERSION:
        return OFPUTIL_P_OF14_OXM;
    case OFP15_VERSION:
        return OFPUTIL_P_OF15_OXM;
    case OFP16_VERSION:
        return OFPUTIL_P_OF16_OXM;
    default:
        return 0;
    }
}

/* Returns the ofputil_protocol that is initially in effect on an OpenFlow
 * connection that has negotiated the given 'version'.  'version' should
 * normally be an 8-bit OpenFlow version identifier (e.g. 0x01 for OpenFlow
 * 1.0, 0x02 for OpenFlow 1.1).  Returns 0 if 'version' is not supported or
 * outside the valid range.  */
enum ofputil_protocol
ofputil_protocol_from_ofp_version(enum ofp_version version)
{
    return rightmost_1bit(ofputil_protocols_from_ofp_version(version));
}

/* Returns the OpenFlow protocol version number (e.g. OFP10_VERSION,
 * etc.) that corresponds to 'protocol'. */
enum ofp_version
ofputil_protocol_to_ofp_version(enum ofputil_protocol protocol)
{
    switch (protocol) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        return OFP10_VERSION;
    case OFPUTIL_P_OF11_STD:
        return OFP11_VERSION;
    case OFPUTIL_P_OF12_OXM:
        return OFP12_VERSION;
    case OFPUTIL_P_OF13_OXM:
        return OFP13_VERSION;
    case OFPUTIL_P_OF14_OXM:
        return OFP14_VERSION;
    case OFPUTIL_P_OF15_OXM:
        return OFP15_VERSION;
    case OFPUTIL_P_OF16_OXM:
        return OFP16_VERSION;
    }

    OVS_NOT_REACHED();
}

/* Returns a bitmap of OpenFlow versions that are supported by at
 * least one of the 'protocols'. */
uint32_t
ofputil_protocols_to_version_bitmap(enum ofputil_protocol protocols)
{
    uint32_t bitmap = 0;

    for (; protocols; protocols = zero_rightmost_1bit(protocols)) {
        enum ofputil_protocol protocol = rightmost_1bit(protocols);

        bitmap |= 1u << ofputil_protocol_to_ofp_version(protocol);
    }

    return bitmap;
}

/* Returns the set of protocols that are supported on top of the
 * OpenFlow versions included in 'bitmap'. */
enum ofputil_protocol
ofputil_protocols_from_version_bitmap(uint32_t bitmap)
{
    enum ofputil_protocol protocols = 0;

    for (; bitmap; bitmap = zero_rightmost_1bit(bitmap)) {
        enum ofp_version version = rightmost_1bit_idx(bitmap);

        protocols |= ofputil_protocols_from_ofp_version(version);
    }

    return protocols;
}

/* Returns true if 'protocol' is a single OFPUTIL_P_* value, false
 * otherwise. */
bool
ofputil_protocol_is_valid(enum ofputil_protocol protocol)
{
    return protocol & OFPUTIL_P_ANY && is_pow2(protocol);
}

/* Returns the equivalent of 'protocol' with the Nicira flow_mod_table_id
 * extension turned on or off if 'enable' is true or false, respectively.
 *
 * This extension is only useful for protocols whose "standard" version does
 * not allow specific tables to be modified.  In particular, this is true of
 * OpenFlow 1.0.  In later versions of OpenFlow, a flow_mod request always
 * specifies a table ID and so there is no need for such an extension.  When
 * 'protocol' is such a protocol that doesn't need a flow_mod_table_id
 * extension, this function just returns its 'protocol' argument unchanged
 * regardless of the value of 'enable'.  */
enum ofputil_protocol
ofputil_protocol_set_tid(enum ofputil_protocol protocol, bool enable)
{
    switch (protocol) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
        return enable ? OFPUTIL_P_OF10_STD_TID : OFPUTIL_P_OF10_STD;

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        return enable ? OFPUTIL_P_OF10_NXM_TID : OFPUTIL_P_OF10_NXM;

    case OFPUTIL_P_OF11_STD:
        return OFPUTIL_P_OF11_STD;

    case OFPUTIL_P_OF12_OXM:
        return OFPUTIL_P_OF12_OXM;

    case OFPUTIL_P_OF13_OXM:
        return OFPUTIL_P_OF13_OXM;

    case OFPUTIL_P_OF14_OXM:
        return OFPUTIL_P_OF14_OXM;

    case OFPUTIL_P_OF15_OXM:
        return OFPUTIL_P_OF15_OXM;

    case OFPUTIL_P_OF16_OXM:
        return OFPUTIL_P_OF16_OXM;

    default:
        OVS_NOT_REACHED();
    }
}

/* Returns the "base" version of 'protocol'.  That is, if 'protocol' includes
 * some extension to a standard protocol version, the return value is the
 * standard version of that protocol without any extension.  If 'protocol' is a
 * standard protocol version, returns 'protocol' unchanged. */
enum ofputil_protocol
ofputil_protocol_to_base(enum ofputil_protocol protocol)
{
    return ofputil_protocol_set_tid(protocol, false);
}

/* Returns 'new_base' with any extensions taken from 'cur'. */
enum ofputil_protocol
ofputil_protocol_set_base(enum ofputil_protocol cur,
                          enum ofputil_protocol new_base)
{
    bool tid = (cur & OFPUTIL_P_TID) != 0;

    switch (new_base) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF10_STD, tid);

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF10_NXM, tid);

    case OFPUTIL_P_OF11_STD:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF11_STD, tid);

    case OFPUTIL_P_OF12_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF12_OXM, tid);

    case OFPUTIL_P_OF13_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF13_OXM, tid);

    case OFPUTIL_P_OF14_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF14_OXM, tid);

    case OFPUTIL_P_OF15_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF15_OXM, tid);

    case OFPUTIL_P_OF16_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF16_OXM, tid);

    default:
        OVS_NOT_REACHED();
    }
}

/* Returns a string form of 'protocol', if a simple form exists (that is, if
 * 'protocol' is either a single protocol or it is a combination of protocols
 * that have a single abbreviation).  Otherwise, returns NULL. */
const char *
ofputil_protocol_to_string(enum ofputil_protocol protocol)
{
    const struct proto_abbrev *p;

    /* Use a "switch" statement for single-bit names so that we get a compiler
     * warning if we forget any. */
    switch (protocol) {
    case OFPUTIL_P_OF10_NXM:
        return "NXM-table_id";

    case OFPUTIL_P_OF10_NXM_TID:
        return "NXM+table_id";

    case OFPUTIL_P_OF10_STD:
        return "OpenFlow10-table_id";

    case OFPUTIL_P_OF10_STD_TID:
        return "OpenFlow10+table_id";

    case OFPUTIL_P_OF11_STD:
        return "OpenFlow11";

    case OFPUTIL_P_OF12_OXM:
        return "OXM-OpenFlow12";

    case OFPUTIL_P_OF13_OXM:
        return "OXM-OpenFlow13";

    case OFPUTIL_P_OF14_OXM:
        return "OXM-OpenFlow14";

    case OFPUTIL_P_OF15_OXM:
        return "OXM-OpenFlow15";

    case OFPUTIL_P_OF16_OXM:
        return "OXM-OpenFlow16";
    }

    /* Check abbreviations. */
    for (p = proto_abbrevs; p < &proto_abbrevs[N_PROTO_ABBREVS]; p++) {
        if (protocol == p->protocol) {
            return p->name;
        }
    }

    return NULL;
}

/* Returns a string that represents 'protocols'.  The return value might be a
 * comma-separated list if 'protocols' doesn't have a simple name.  The return
 * value is "none" if 'protocols' is 0.
 *
 * The caller must free the returned string (with free()). */
char *
ofputil_protocols_to_string(enum ofputil_protocol protocols)
{
    struct ds s;

    ovs_assert(!(protocols & ~OFPUTIL_P_ANY));
    if (protocols == 0) {
        return xstrdup("none");
    }

    ds_init(&s);
    while (protocols) {
        const struct proto_abbrev *p;
        int i;

        if (s.length) {
            ds_put_char(&s, ',');
        }

        for (p = proto_abbrevs; p < &proto_abbrevs[N_PROTO_ABBREVS]; p++) {
            if ((protocols & p->protocol) == p->protocol) {
                ds_put_cstr(&s, p->name);
                protocols &= ~p->protocol;
                goto match;
            }
        }

        for (i = 0; i < CHAR_BIT * sizeof(enum ofputil_protocol); i++) {
            enum ofputil_protocol bit = 1u << i;

            if (protocols & bit) {
                ds_put_cstr(&s, ofputil_protocol_to_string(bit));
                protocols &= ~bit;
                goto match;
            }
        }
        OVS_NOT_REACHED();

    match: ;
    }
    return ds_steal_cstr(&s);
}

static enum ofputil_protocol
ofputil_protocol_from_string__(const char *s, size_t n)
{
    const struct proto_abbrev *p;
    int i;

    for (i = 0; i < CHAR_BIT * sizeof(enum ofputil_protocol); i++) {
        enum ofputil_protocol bit = 1u << i;
        const char *name = ofputil_protocol_to_string(bit);

        if (name && n == strlen(name) && !strncasecmp(s, name, n)) {
            return bit;
        }
    }

    for (p = proto_abbrevs; p < &proto_abbrevs[N_PROTO_ABBREVS]; p++) {
        if (n == strlen(p->name) && !strncasecmp(s, p->name, n)) {
            return p->protocol;
        }
    }

    return 0;
}

/* Returns the nonempty set of protocols represented by 's', which can be a
 * single protocol name or abbreviation or a comma-separated list of them.
 *
 * Aborts the program with an error message if 's' is invalid. */
enum ofputil_protocol
ofputil_protocols_from_string(const char *s)
{
    const char *orig_s = s;
    enum ofputil_protocol protocols;

    protocols = 0;
    while (*s) {
        enum ofputil_protocol p;
        size_t n;

        n = strcspn(s, ",");
        if (n == 0) {
            s++;
            continue;
        }

        p = ofputil_protocol_from_string__(s, n);
        if (!p) {
            ovs_fatal(0, "%.*s: unknown flow protocol", (int) n, s);
        }
        protocols |= p;

        s += n;
    }

    if (!protocols) {
        ovs_fatal(0, "%s: no flow protocol specified", orig_s);
    }
    return protocols;
}

enum ofp_version
ofputil_version_from_string(const char *s)
{
    if (!strcasecmp(s, "OpenFlow10")) {
        return OFP10_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow11")) {
        return OFP11_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow12")) {
        return OFP12_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow13")) {
        return OFP13_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow14")) {
        return OFP14_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow15")) {
        return OFP15_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow16")) {
        return OFP16_VERSION;
    }
    return 0;
}

static bool
is_delimiter(unsigned char c)
{
    return isspace(c) || c == ',';
}

uint32_t
ofputil_versions_from_string(const char *s)
{
    size_t i = 0;
    uint32_t bitmap = 0;

    while (s[i]) {
        size_t j;
        int version;
        char *key;

        if (is_delimiter(s[i])) {
            i++;
            continue;
        }
        j = 0;
        while (s[i + j] && !is_delimiter(s[i + j])) {
            j++;
        }
        key = xmemdup0(s + i, j);
        version = ofputil_version_from_string(key);
        if (!version) {
            VLOG_FATAL("Unknown OpenFlow version: \"%s\"", key);
        }
        free(key);
        bitmap |= 1u << version;
        i += j;
    }

    return bitmap;
}

uint32_t
ofputil_versions_from_strings(char ** const s, size_t count)
{
    uint32_t bitmap = 0;

    while (count--) {
        int version = ofputil_version_from_string(s[count]);
        if (!version) {
            VLOG_WARN("Unknown OpenFlow version: \"%s\"", s[count]);
        } else {
            bitmap |= 1u << version;
        }
    }

    return bitmap;
}

const char *
ofputil_version_to_string(enum ofp_version ofp_version)
{
    switch (ofp_version) {
    case OFP10_VERSION:
        return "OpenFlow10";
    case OFP11_VERSION:
        return "OpenFlow11";
    case OFP12_VERSION:
        return "OpenFlow12";
    case OFP13_VERSION:
        return "OpenFlow13";
    case OFP14_VERSION:
        return "OpenFlow14";
    case OFP15_VERSION:
        return "OpenFlow15";
    case OFP16_VERSION:
        return "OpenFlow16";
    default:
        OVS_NOT_REACHED();
    }
}

bool
ofputil_packet_in_format_is_valid(enum nx_packet_in_format packet_in_format)
{
    switch (packet_in_format) {
    case NXPIF_STANDARD:
    case NXPIF_NXT_PACKET_IN:
    case NXPIF_NXT_PACKET_IN2:
        return true;
    }

    return false;
}

const char *
ofputil_packet_in_format_to_string(enum nx_packet_in_format packet_in_format)
{
    switch (packet_in_format) {
    case NXPIF_STANDARD:
        return "standard";
    case NXPIF_NXT_PACKET_IN:
        return "nxt_packet_in";
    case NXPIF_NXT_PACKET_IN2:
        return "nxt_packet_in2";
    default:
        OVS_NOT_REACHED();
    }
}

int
ofputil_packet_in_format_from_string(const char *s)
{
    return (!strcmp(s, "standard") || !strcmp(s, "openflow10")
            ? NXPIF_STANDARD
            : !strcmp(s, "nxt_packet_in") || !strcmp(s, "nxm")
            ? NXPIF_NXT_PACKET_IN
            : !strcmp(s, "nxt_packet_in2")
            ? NXPIF_NXT_PACKET_IN2
            : -1);
}

void
ofputil_format_version(struct ds *msg, enum ofp_version version)
{
    ds_put_format(msg, "0x%02x", version);
}

void
ofputil_format_version_name(struct ds *msg, enum ofp_version version)
{
    ds_put_cstr(msg, ofputil_version_to_string(version));
}

static void
ofputil_format_version_bitmap__(struct ds *msg, uint32_t bitmap,
                                void (*format_version)(struct ds *msg,
                                                       enum ofp_version))
{
    while (bitmap) {
        format_version(msg, raw_ctz(bitmap));
        bitmap = zero_rightmost_1bit(bitmap);
        if (bitmap) {
            ds_put_cstr(msg, ", ");
        }
    }
}

void
ofputil_format_version_bitmap(struct ds *msg, uint32_t bitmap)
{
    ofputil_format_version_bitmap__(msg, bitmap, ofputil_format_version);
}

void
ofputil_format_version_bitmap_names(struct ds *msg, uint32_t bitmap)
{
    ofputil_format_version_bitmap__(msg, bitmap, ofputil_format_version_name);
}

static bool
ofputil_decode_hello_bitmap(const struct ofp_hello_elem_header *oheh,
                            uint32_t *allowed_versionsp)
{
    uint16_t bitmap_len = ntohs(oheh->length) - sizeof *oheh;
    const ovs_be32 *bitmap = ALIGNED_CAST(const ovs_be32 *, oheh + 1);
    uint32_t allowed_versions;

    if (!bitmap_len || bitmap_len % sizeof *bitmap) {
        return false;
    }

    /* Only use the first 32-bit element of the bitmap as that is all the
     * current implementation supports.  Subsequent elements are ignored which
     * should have no effect on session negotiation until Open vSwitch supports
     * wire-protocol versions greater than 31.
     */
    allowed_versions = ntohl(bitmap[0]);

    if (allowed_versions & 1) {
        /* There's no OpenFlow version 0. */
        VLOG_WARN_RL(&bad_ofmsg_rl, "peer claims to support invalid OpenFlow "
                     "version 0x00");
        allowed_versions &= ~1u;
    }

    if (!allowed_versions) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "peer does not support any OpenFlow "
                     "version (between 0x01 and 0x1f)");
        return false;
    }

    *allowed_versionsp = allowed_versions;
    return true;
}

static uint32_t
version_bitmap_from_version(uint8_t ofp_version)
{
    return ((ofp_version < 32 ? 1u << ofp_version : 0) - 1) << 1;
}

/* Decodes OpenFlow OFPT_HELLO message 'oh', storing into '*allowed_versions'
 * the set of OpenFlow versions for which 'oh' announces support.
 *
 * Because of how OpenFlow defines OFPT_HELLO messages, this function is always
 * successful, and thus '*allowed_versions' is always initialized.  However, it
 * returns false if 'oh' contains some data that could not be fully understood,
 * true if 'oh' was completely parsed. */
bool
ofputil_decode_hello(const struct ofp_header *oh, uint32_t *allowed_versions)
{
    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpbuf_pull(&msg, sizeof *oh);

    *allowed_versions = version_bitmap_from_version(oh->version);

    bool ok = true;
    while (msg.size) {
        const struct ofp_hello_elem_header *oheh;
        unsigned int len;

        if (msg.size < sizeof *oheh) {
            return false;
        }

        oheh = msg.data;
        len = ntohs(oheh->length);
        if (len < sizeof *oheh || !ofpbuf_try_pull(&msg, ROUND_UP(len, 8))) {
            return false;
        }

        if (oheh->type != htons(OFPHET_VERSIONBITMAP)
            || !ofputil_decode_hello_bitmap(oheh, allowed_versions)) {
            ok = false;
        }
    }

    return ok;
}

/* Returns true if 'allowed_versions' needs to be accompanied by a version
 * bitmap to be correctly expressed in an OFPT_HELLO message. */
static bool
should_send_version_bitmap(uint32_t allowed_versions)
{
    return !is_pow2((allowed_versions >> 1) + 1);
}

/* Create an OFPT_HELLO message that expresses support for the OpenFlow
 * versions in the 'allowed_versions' bitmaps and returns the message. */
struct ofpbuf *
ofputil_encode_hello(uint32_t allowed_versions)
{
    enum ofp_version ofp_version;
    struct ofpbuf *msg;

    ofp_version = leftmost_1bit_idx(allowed_versions);
    msg = ofpraw_alloc(OFPRAW_OFPT_HELLO, ofp_version, 0);

    if (should_send_version_bitmap(allowed_versions)) {
        struct ofp_hello_elem_header *oheh;
        uint16_t map_len;

        map_len = sizeof allowed_versions;
        oheh = ofpbuf_put_zeros(msg, ROUND_UP(map_len + sizeof *oheh, 8));
        oheh->type = htons(OFPHET_VERSIONBITMAP);
        oheh->length = htons(map_len + sizeof *oheh);
        *ALIGNED_CAST(ovs_be32 *, oheh + 1) = htonl(allowed_versions);

        ofpmsg_update_length(msg);
    }

    return msg;
}

/* Returns an OpenFlow message that, sent on an OpenFlow connection whose
 * protocol is 'current', at least partly transitions the protocol to 'want'.
 * Stores in '*next' the protocol that will be in effect on the OpenFlow
 * connection if the switch processes the returned message correctly.  (If
 * '*next != want' then the caller will have to iterate.)
 *
 * If 'current == want', or if it is not possible to transition from 'current'
 * to 'want' (because, for example, 'current' and 'want' use different OpenFlow
 * protocol versions), returns NULL and stores 'current' in '*next'. */
struct ofpbuf *
ofputil_encode_set_protocol(enum ofputil_protocol current,
                            enum ofputil_protocol want,
                            enum ofputil_protocol *next)
{
    enum ofp_version cur_version, want_version;
    enum ofputil_protocol cur_base, want_base;
    bool cur_tid, want_tid;

    cur_version = ofputil_protocol_to_ofp_version(current);
    want_version = ofputil_protocol_to_ofp_version(want);
    if (cur_version != want_version) {
        *next = current;
        return NULL;
    }

    cur_base = ofputil_protocol_to_base(current);
    want_base = ofputil_protocol_to_base(want);
    if (cur_base != want_base) {
        *next = ofputil_protocol_set_base(current, want_base);

        switch (want_base) {
        case OFPUTIL_P_OF10_NXM:
            return ofputil_encode_nx_set_flow_format(NXFF_NXM);

        case OFPUTIL_P_OF10_STD:
            return ofputil_encode_nx_set_flow_format(NXFF_OPENFLOW10);

        case OFPUTIL_P_OF11_STD:
        case OFPUTIL_P_OF12_OXM:
        case OFPUTIL_P_OF13_OXM:
        case OFPUTIL_P_OF14_OXM:
        case OFPUTIL_P_OF15_OXM:
        case OFPUTIL_P_OF16_OXM:
            /* There is only one variant of each OpenFlow 1.1+ protocol, and we
             * verified above that we're not trying to change versions. */
            OVS_NOT_REACHED();

        case OFPUTIL_P_OF10_STD_TID:
        case OFPUTIL_P_OF10_NXM_TID:
            OVS_NOT_REACHED();
        }
    }

    cur_tid = (current & OFPUTIL_P_TID) != 0;
    want_tid = (want & OFPUTIL_P_TID) != 0;
    if (cur_tid != want_tid) {
        *next = ofputil_protocol_set_tid(current, want_tid);
        return ofputil_make_flow_mod_table_id(want_tid);
    }

    ovs_assert(current == want);

    *next = current;
    return NULL;
}

/* Returns an NXT_SET_FLOW_FORMAT message that can be used to set the flow
 * format to 'nxff'.  */
struct ofpbuf *
ofputil_encode_nx_set_flow_format(enum nx_flow_format nxff)
{
    struct nx_set_flow_format *sff;
    struct ofpbuf *msg;

    ovs_assert(ofputil_nx_flow_format_is_valid(nxff));

    msg = ofpraw_alloc(OFPRAW_NXT_SET_FLOW_FORMAT, OFP10_VERSION, 0);
    sff = ofpbuf_put_zeros(msg, sizeof *sff);
    sff->format = htonl(nxff);

    return msg;
}

/* Returns the base protocol if 'flow_format' is a valid NXFF_* value, false
 * otherwise. */
enum ofputil_protocol
ofputil_nx_flow_format_to_protocol(enum nx_flow_format flow_format)
{
    switch (flow_format) {
    case NXFF_OPENFLOW10:
        return OFPUTIL_P_OF10_STD;

    case NXFF_NXM:
        return OFPUTIL_P_OF10_NXM;

    default:
        return 0;
    }
}

/* Returns true if 'flow_format' is a valid NXFF_* value, false otherwise. */
bool
ofputil_nx_flow_format_is_valid(enum nx_flow_format flow_format)
{
    return ofputil_nx_flow_format_to_protocol(flow_format) != 0;
}

/* Returns a string version of 'flow_format', which must be a valid NXFF_*
 * value. */
const char *
ofputil_nx_flow_format_to_string(enum nx_flow_format flow_format)
{
    switch (flow_format) {
    case NXFF_OPENFLOW10:
        return "openflow10";
    case NXFF_NXM:
        return "nxm";
    default:
        OVS_NOT_REACHED();
    }
}

struct ofpbuf *
ofputil_make_set_packet_in_format(enum ofp_version ofp_version,
                                  enum nx_packet_in_format packet_in_format)
{
    struct nx_set_packet_in_format *spif;
    struct ofpbuf *msg;

    msg = ofpraw_alloc(OFPRAW_NXT_SET_PACKET_IN_FORMAT, ofp_version, 0);
    spif = ofpbuf_put_zeros(msg, sizeof *spif);
    spif->format = htonl(packet_in_format);

    return msg;
}

/* Returns an OpenFlow message that can be used to turn the flow_mod_table_id
 * extension on or off (according to 'flow_mod_table_id'). */
struct ofpbuf *
ofputil_make_flow_mod_table_id(bool flow_mod_table_id)
{
    struct nx_flow_mod_table_id *nfmti;
    struct ofpbuf *msg;

    msg = ofpraw_alloc(OFPRAW_NXT_FLOW_MOD_TABLE_ID, OFP10_VERSION, 0);
    nfmti = ofpbuf_put_zeros(msg, sizeof *nfmti);
    nfmti->set = flow_mod_table_id;
    return msg;
}

struct ofputil_flow_mod_flag {
    uint16_t raw_flag;
    enum ofp_version min_version, max_version;
    enum ofputil_flow_mod_flags flag;
};

static const struct ofputil_flow_mod_flag ofputil_flow_mod_flags[] = {
    { OFPFF_SEND_FLOW_REM,   OFP10_VERSION, 0, OFPUTIL_FF_SEND_FLOW_REM },
    { OFPFF_CHECK_OVERLAP,   OFP10_VERSION, 0, OFPUTIL_FF_CHECK_OVERLAP },
    { OFPFF10_EMERG,         OFP10_VERSION, OFP10_VERSION,
      OFPUTIL_FF_EMERG },
    { OFPFF12_RESET_COUNTS,  OFP12_VERSION, 0, OFPUTIL_FF_RESET_COUNTS },
    { OFPFF13_NO_PKT_COUNTS, OFP13_VERSION, 0, OFPUTIL_FF_NO_PKT_COUNTS },
    { OFPFF13_NO_BYT_COUNTS, OFP13_VERSION, 0, OFPUTIL_FF_NO_BYT_COUNTS },
    { 0, 0, 0, 0 },
};

static enum ofperr
ofputil_decode_flow_mod_flags(ovs_be16 raw_flags_,
                              enum ofp_flow_mod_command command,
                              enum ofp_version version,
                              enum ofputil_flow_mod_flags *flagsp)
{
    uint16_t raw_flags = ntohs(raw_flags_);
    const struct ofputil_flow_mod_flag *f;

    *flagsp = 0;
    for (f = ofputil_flow_mod_flags; f->raw_flag; f++) {
        if (raw_flags & f->raw_flag
            && version >= f->min_version
            && (!f->max_version || version <= f->max_version)) {
            raw_flags &= ~f->raw_flag;
            *flagsp |= f->flag;
        }
    }

    /* In OF1.0 and OF1.1, "add" always resets counters, and other commands
     * never do.
     *
     * In OF1.2 and later, OFPFF12_RESET_COUNTS controls whether each command
     * resets counters. */
    if ((version == OFP10_VERSION || version == OFP11_VERSION)
        && command == OFPFC_ADD) {
        *flagsp |= OFPUTIL_FF_RESET_COUNTS;
    }

    return raw_flags ? OFPERR_OFPFMFC_BAD_FLAGS : 0;
}

static ovs_be16
ofputil_encode_flow_mod_flags(enum ofputil_flow_mod_flags flags,
                              enum ofp_version version)
{
    const struct ofputil_flow_mod_flag *f;
    uint16_t raw_flags;

    raw_flags = 0;
    for (f = ofputil_flow_mod_flags; f->raw_flag; f++) {
        if (f->flag & flags
            && version >= f->min_version
            && (!f->max_version || version <= f->max_version)) {
            raw_flags |= f->raw_flag;
        }
    }

    return htons(raw_flags);
}

/* Converts an OFPT_FLOW_MOD or NXT_FLOW_MOD message 'oh' into an abstract
 * flow_mod in 'fm'.  Returns 0 if successful, otherwise an OpenFlow error
 * code.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of 'oh''s actions.
 * The caller must initialize 'ofpacts' and retains ownership of it.
 * 'fm->ofpacts' will point into the 'ofpacts' buffer.
 *
 * Does not validate the flow_mod actions.  The caller should do that, with
 * ofpacts_check(). */
enum ofperr
ofputil_decode_flow_mod(struct ofputil_flow_mod *fm,
                        const struct ofp_header *oh,
                        enum ofputil_protocol protocol,
                        const struct tun_table *tun_table,
                        const struct vl_mff_map *vl_mff_map,
                        struct ofpbuf *ofpacts,
                        ofp_port_t max_port, uint8_t max_table)
{
    ovs_be16 raw_flags;
    enum ofperr error;
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT11_FLOW_MOD) {
        /* Standard OpenFlow 1.1+ flow_mod. */
        const struct ofp11_flow_mod *ofm;

        ofm = ofpbuf_pull(&b, sizeof *ofm);

        error = ofputil_pull_ofp11_match(&b, tun_table, vl_mff_map, &fm->match,
                                         NULL);
        if (error) {
            return error;
        }

        /* Translate the message. */
        fm->priority = ntohs(ofm->priority);
        if (ofm->command == OFPFC_ADD
            || (oh->version == OFP11_VERSION
                && (ofm->command == OFPFC_MODIFY ||
                    ofm->command == OFPFC_MODIFY_STRICT)
                && ofm->cookie_mask == htonll(0))) {
            /* In OpenFlow 1.1 only, a "modify" or "modify-strict" that does
             * not match on the cookie is treated as an "add" if there is no
             * match. */
            fm->cookie = htonll(0);
            fm->cookie_mask = htonll(0);
            fm->new_cookie = ofm->cookie;
        } else {
            fm->cookie = ofm->cookie;
            fm->cookie_mask = ofm->cookie_mask;
            fm->new_cookie = OVS_BE64_MAX;
        }
        fm->modify_cookie = false;
        fm->command = ofm->command;

        /* Get table ID.
         *
         * OF1.1 entirely forbids table_id == OFPTT_ALL.
         * OF1.2+ allows table_id == OFPTT_ALL only for deletes. */
        fm->table_id = ofm->table_id;
        if (fm->table_id == OFPTT_ALL
            && (oh->version == OFP11_VERSION
                || (ofm->command != OFPFC_DELETE &&
                    ofm->command != OFPFC_DELETE_STRICT))) {
            return OFPERR_OFPFMFC_BAD_TABLE_ID;
        }

        fm->idle_timeout = ntohs(ofm->idle_timeout);
        fm->hard_timeout = ntohs(ofm->hard_timeout);
        if (oh->version >= OFP14_VERSION && ofm->command == OFPFC_ADD) {
            fm->importance = ntohs(ofm->importance);
        } else {
            fm->importance = 0;
        }
        fm->buffer_id = ntohl(ofm->buffer_id);
        error = ofputil_port_from_ofp11(ofm->out_port, &fm->out_port);
        if (error) {
            return error;
        }

        fm->out_group = (ofm->command == OFPFC_DELETE ||
                         ofm->command == OFPFC_DELETE_STRICT
                         ? ntohl(ofm->out_group)
                         : OFPG_ANY);
        raw_flags = ofm->flags;
    } else {
        uint16_t command;

        if (raw == OFPRAW_OFPT10_FLOW_MOD) {
            /* Standard OpenFlow 1.0 flow_mod. */
            const struct ofp10_flow_mod *ofm;

            /* Get the ofp10_flow_mod. */
            ofm = ofpbuf_pull(&b, sizeof *ofm);

            /* Translate the rule. */
            ofputil_match_from_ofp10_match(&ofm->match, &fm->match);
            ofputil_normalize_match(&fm->match);

            /* OpenFlow 1.0 says that exact-match rules have to have the
             * highest possible priority. */
            fm->priority = (ofm->match.wildcards & htonl(OFPFW10_ALL)
                            ? ntohs(ofm->priority)
                            : UINT16_MAX);

            /* Translate the message. */
            command = ntohs(ofm->command);
            fm->cookie = htonll(0);
            fm->cookie_mask = htonll(0);
            fm->new_cookie = ofm->cookie;
            fm->idle_timeout = ntohs(ofm->idle_timeout);
            fm->hard_timeout = ntohs(ofm->hard_timeout);
            fm->importance = 0;
            fm->buffer_id = ntohl(ofm->buffer_id);
            fm->out_port = u16_to_ofp(ntohs(ofm->out_port));
            fm->out_group = OFPG_ANY;
            raw_flags = ofm->flags;
        } else if (raw == OFPRAW_NXT_FLOW_MOD) {
            /* Nicira extended flow_mod. */
            const struct nx_flow_mod *nfm;

            /* Dissect the message. */
            nfm = ofpbuf_pull(&b, sizeof *nfm);
            error = nx_pull_match(&b, ntohs(nfm->match_len),
                                  &fm->match, &fm->cookie, &fm->cookie_mask,
                                  false, tun_table, vl_mff_map);
            if (error) {
                return error;
            }

            /* Translate the message. */
            command = ntohs(nfm->command);
            if ((command & 0xff) == OFPFC_ADD && fm->cookie_mask) {
                /* Flow additions may only set a new cookie, not match an
                 * existing cookie. */
                return OFPERR_NXBRC_NXM_INVALID;
            }
            fm->priority = ntohs(nfm->priority);
            fm->new_cookie = nfm->cookie;
            fm->idle_timeout = ntohs(nfm->idle_timeout);
            fm->hard_timeout = ntohs(nfm->hard_timeout);
            fm->importance = 0;
            fm->buffer_id = ntohl(nfm->buffer_id);
            fm->out_port = u16_to_ofp(ntohs(nfm->out_port));
            fm->out_group = OFPG_ANY;
            raw_flags = nfm->flags;
        } else {
            OVS_NOT_REACHED();
        }

        fm->modify_cookie = fm->new_cookie != OVS_BE64_MAX;
        if (protocol & OFPUTIL_P_TID) {
            fm->command = command & 0xff;
            fm->table_id = command >> 8;
        } else {
            if (command > 0xff) {
                VLOG_WARN_RL(&bad_ofmsg_rl, "flow_mod has explicit table_id "
                             "but flow_mod_table_id extension is not enabled");
            }
            fm->command = command;
            fm->table_id = 0xff;
        }
    }

    /* Check for mismatched conntrack original direction tuple address fields
     * w.r.t. the IP version of the match. */
    if (((fm->match.wc.masks.ct_nw_src || fm->match.wc.masks.ct_nw_dst)
         && fm->match.flow.dl_type != htons(ETH_TYPE_IP))
        || ((ipv6_addr_is_set(&fm->match.wc.masks.ct_ipv6_src)
             || ipv6_addr_is_set(&fm->match.wc.masks.ct_ipv6_dst))
            && fm->match.flow.dl_type != htons(ETH_TYPE_IPV6))) {
        return OFPERR_OFPBAC_MATCH_INCONSISTENT;
    }

    if (fm->command > OFPFC_DELETE_STRICT) {
        return OFPERR_OFPFMFC_BAD_COMMAND;
    }

    fm->ofpacts_tlv_bitmap = 0;
    error = ofpacts_pull_openflow_instructions(&b, b.size, oh->version,
                                               vl_mff_map,
                                               &fm->ofpacts_tlv_bitmap,
                                               ofpacts);
    if (error) {
        return error;
    }
    fm->ofpacts = ofpacts->data;
    fm->ofpacts_len = ofpacts->size;

    error = ofputil_decode_flow_mod_flags(raw_flags, fm->command,
                                          oh->version, &fm->flags);
    if (error) {
        return error;
    }

    if (fm->flags & OFPUTIL_FF_EMERG) {
        /* We do not support the OpenFlow 1.0 emergency flow cache, which
         * is not required in OpenFlow 1.0.1 and removed from OpenFlow 1.1.
         *
         * OpenFlow 1.0 specifies the error code to use when idle_timeout
         * or hard_timeout is nonzero.  Otherwise, there is no good error
         * code, so just state that the flow table is full. */
        return (fm->hard_timeout || fm->idle_timeout
                ? OFPERR_OFPFMFC_BAD_EMERG_TIMEOUT
                : OFPERR_OFPFMFC_TABLE_FULL);
    }

    return ofpacts_check_consistency(fm->ofpacts, fm->ofpacts_len,
                                     &fm->match, max_port,
                                     fm->table_id, max_table, protocol);
}

static enum ofperr
ofputil_pull_bands(struct ofpbuf *msg, size_t len, uint16_t *n_bands,
                   struct ofpbuf *bands)
{
    const struct ofp13_meter_band_header *ombh;
    struct ofputil_meter_band *mb;
    uint16_t n = 0;

    ombh = ofpbuf_try_pull(msg, len);
    if (!ombh) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    while (len >= sizeof (struct ofp13_meter_band_drop)) {
        size_t ombh_len = ntohs(ombh->len);
        /* All supported band types have the same length. */
        if (ombh_len != sizeof (struct ofp13_meter_band_drop)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        mb = ofpbuf_put_uninit(bands, sizeof *mb);
        mb->type = ntohs(ombh->type);
        if (mb->type != OFPMBT13_DROP && mb->type != OFPMBT13_DSCP_REMARK) {
            return OFPERR_OFPMMFC_BAD_BAND;
        }
        mb->rate = ntohl(ombh->rate);
        mb->burst_size = ntohl(ombh->burst_size);
        mb->prec_level = (mb->type == OFPMBT13_DSCP_REMARK) ?
            ((struct ofp13_meter_band_dscp_remark *)ombh)->prec_level : 0;
        n++;
        len -= ombh_len;
        ombh = ALIGNED_CAST(struct ofp13_meter_band_header *,
                            (char *) ombh + ombh_len);
    }
    if (len) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    *n_bands = n;
    return 0;
}

enum ofperr
ofputil_decode_meter_mod(const struct ofp_header *oh,
                         struct ofputil_meter_mod *mm,
                         struct ofpbuf *bands)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);
    const struct ofp13_meter_mod *omm = ofpbuf_pull(&b, sizeof *omm);

    /* Translate the message. */
    mm->command = ntohs(omm->command);
    if (mm->command != OFPMC13_ADD &&
        mm->command != OFPMC13_MODIFY &&
        mm->command != OFPMC13_DELETE) {
        return OFPERR_OFPMMFC_BAD_COMMAND;
    }
    mm->meter.meter_id = ntohl(omm->meter_id);

    if (mm->command == OFPMC13_DELETE) {
        mm->meter.flags = 0;
        mm->meter.n_bands = 0;
        mm->meter.bands = NULL;
    } else {
        enum ofperr error;

        mm->meter.flags = ntohs(omm->flags);
        if (mm->meter.flags & OFPMF13_KBPS &&
            mm->meter.flags & OFPMF13_PKTPS) {
            return OFPERR_OFPMMFC_BAD_FLAGS;
        }

        error = ofputil_pull_bands(&b, b.size, &mm->meter.n_bands, bands);
        if (error) {
            return error;
        }
        mm->meter.bands = bands->data;
    }
    return 0;
}

void
ofputil_decode_meter_request(const struct ofp_header *oh, uint32_t *meter_id)
{
    const struct ofp13_meter_multipart_request *omr = ofpmsg_body(oh);
    *meter_id = ntohl(omr->meter_id);
}

struct ofpbuf *
ofputil_encode_meter_request(enum ofp_version ofp_version,
                             enum ofputil_meter_request_type type,
                             uint32_t meter_id)
{
    struct ofpbuf *msg;

    enum ofpraw raw;

    switch (type) {
    case OFPUTIL_METER_CONFIG:
        raw = OFPRAW_OFPST13_METER_CONFIG_REQUEST;
        break;
    case OFPUTIL_METER_STATS:
        raw = OFPRAW_OFPST13_METER_REQUEST;
        break;
    default:
    case OFPUTIL_METER_FEATURES:
        raw = OFPRAW_OFPST13_METER_FEATURES_REQUEST;
        break;
    }

    msg = ofpraw_alloc(raw, ofp_version, 0);

    if (type != OFPUTIL_METER_FEATURES) {
        struct ofp13_meter_multipart_request *omr;
        omr = ofpbuf_put_zeros(msg, sizeof *omr);
        omr->meter_id = htonl(meter_id);
    }
    return msg;
}

static void
ofputil_put_bands(uint16_t n_bands, const struct ofputil_meter_band *mb,
                  struct ofpbuf *msg)
{
    uint16_t n = 0;

    for (n = 0; n < n_bands; ++n) {
        /* Currently all band types have same size. */
        struct ofp13_meter_band_dscp_remark *ombh;
        size_t ombh_len = sizeof *ombh;

        ombh = ofpbuf_put_zeros(msg, ombh_len);

        ombh->type = htons(mb->type);
        ombh->len = htons(ombh_len);
        ombh->rate = htonl(mb->rate);
        ombh->burst_size = htonl(mb->burst_size);
        ombh->prec_level = mb->prec_level;

        mb++;
    }
}

/* Encode a meter stat for 'mc' and append it to 'replies'. */
void
ofputil_append_meter_config(struct ovs_list *replies,
                            const struct ofputil_meter_config *mc)
{
    struct ofpbuf *msg = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_ofs = msg->size;
    struct ofp13_meter_config *reply;

    ofpbuf_put_uninit(msg, sizeof *reply);
    ofputil_put_bands(mc->n_bands, mc->bands, msg);

    reply = ofpbuf_at_assert(msg, start_ofs, sizeof *reply);
    reply->flags = htons(mc->flags);
    reply->meter_id = htonl(mc->meter_id);
    reply->length = htons(msg->size - start_ofs);

    ofpmp_postappend(replies, start_ofs);
}

/* Encode a meter stat for 'ms' and append it to 'replies'. */
void
ofputil_append_meter_stats(struct ovs_list *replies,
                           const struct ofputil_meter_stats *ms)
{
    struct ofp13_meter_stats *reply;
    uint16_t n = 0;
    uint16_t len;

    len = sizeof *reply + ms->n_bands * sizeof(struct ofp13_meter_band_stats);
    reply = ofpmp_append(replies, len);

    reply->meter_id = htonl(ms->meter_id);
    reply->len = htons(len);
    memset(reply->pad, 0, sizeof reply->pad);
    reply->flow_count = htonl(ms->flow_count);
    reply->packet_in_count = htonll(ms->packet_in_count);
    reply->byte_in_count = htonll(ms->byte_in_count);
    reply->duration_sec = htonl(ms->duration_sec);
    reply->duration_nsec = htonl(ms->duration_nsec);

    for (n = 0; n < ms->n_bands; ++n) {
        const struct ofputil_meter_band_stats *src = &ms->bands[n];
        struct ofp13_meter_band_stats *dst = &reply->band_stats[n];

        dst->packet_band_count = htonll(src->packet_count);
        dst->byte_band_count = htonll(src->byte_count);
    }
}

/* Converts an OFPMP_METER_CONFIG reply in 'msg' into an abstract
 * ofputil_meter_config in 'mc', with mc->bands pointing to bands decoded into
 * 'bands'.  The caller must have initialized 'bands' and retains ownership of
 * it across the call.
 *
 * Multiple OFPST13_METER_CONFIG replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  'bands' is cleared for each reply.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_meter_config(struct ofpbuf *msg,
                            struct ofputil_meter_config *mc,
                            struct ofpbuf *bands)
{
    const struct ofp13_meter_config *omc;
    enum ofperr err;

    /* Pull OpenFlow headers for the first call. */
    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    omc = ofpbuf_try_pull(msg, sizeof *omc);
    if (!omc) {
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "OFPMP_METER_CONFIG reply has %"PRIu32" leftover bytes at end",
                     msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    ofpbuf_clear(bands);
    err = ofputil_pull_bands(msg, ntohs(omc->length) - sizeof *omc,
                             &mc->n_bands, bands);
    if (err) {
        return err;
    }
    mc->meter_id = ntohl(omc->meter_id);
    mc->flags = ntohs(omc->flags);
    mc->bands = bands->data;

    return 0;
}

static enum ofperr
ofputil_pull_band_stats(struct ofpbuf *msg, size_t len, uint16_t *n_bands,
                        struct ofpbuf *bands)
{
    const struct ofp13_meter_band_stats *ombs;
    struct ofputil_meter_band_stats *mbs;
    uint16_t n, i;

    ombs = ofpbuf_try_pull(msg, len);
    if (!ombs) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    n = len / sizeof *ombs;
    if (len != n * sizeof *ombs) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    mbs = ofpbuf_put_uninit(bands, len);

    for (i = 0; i < n; ++i) {
        mbs[i].packet_count = ntohll(ombs[i].packet_band_count);
        mbs[i].byte_count = ntohll(ombs[i].byte_band_count);
    }
    *n_bands = n;
    return 0;
}

/* Converts an OFPMP_METER reply in 'msg' into an abstract
 * ofputil_meter_stats in 'ms', with ms->bands pointing to band stats
 * decoded into 'bands'.
 *
 * Multiple OFPMP_METER replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  'bands' is cleared for each reply.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_meter_stats(struct ofpbuf *msg,
                           struct ofputil_meter_stats *ms,
                           struct ofpbuf *bands)
{
    const struct ofp13_meter_stats *oms;
    enum ofperr err;

    /* Pull OpenFlow headers for the first call. */
    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    oms = ofpbuf_try_pull(msg, sizeof *oms);
    if (!oms) {
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "OFPMP_METER reply has %"PRIu32" leftover bytes at end",
                     msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    ofpbuf_clear(bands);
    err = ofputil_pull_band_stats(msg, ntohs(oms->len) - sizeof *oms,
                                  &ms->n_bands, bands);
    if (err) {
        return err;
    }
    ms->meter_id = ntohl(oms->meter_id);
    ms->flow_count = ntohl(oms->flow_count);
    ms->packet_in_count = ntohll(oms->packet_in_count);
    ms->byte_in_count = ntohll(oms->byte_in_count);
    ms->duration_sec = ntohl(oms->duration_sec);
    ms->duration_nsec = ntohl(oms->duration_nsec);
    ms->bands = bands->data;

    return 0;
}

void
ofputil_decode_meter_features(const struct ofp_header *oh,
                              struct ofputil_meter_features *mf)
{
    const struct ofp13_meter_features *omf = ofpmsg_body(oh);

    mf->max_meters = ntohl(omf->max_meter);
    mf->band_types = ntohl(omf->band_types);
    mf->capabilities = ntohl(omf->capabilities);
    mf->max_bands = omf->max_bands;
    mf->max_color = omf->max_color;
}

struct ofpbuf *
ofputil_encode_meter_features_reply(const struct ofputil_meter_features *mf,
                                    const struct ofp_header *request)
{
    struct ofpbuf *reply;
    struct ofp13_meter_features *omf;

    reply = ofpraw_alloc_stats_reply(request, 0);
    omf = ofpbuf_put_zeros(reply, sizeof *omf);

    omf->max_meter = htonl(mf->max_meters);
    omf->band_types = htonl(mf->band_types);
    omf->capabilities = htonl(mf->capabilities);
    omf->max_bands = mf->max_bands;
    omf->max_color = mf->max_color;

    return reply;
}

struct ofpbuf *
ofputil_encode_meter_mod(enum ofp_version ofp_version,
                         const struct ofputil_meter_mod *mm)
{
    struct ofpbuf *msg;

    struct ofp13_meter_mod *omm;

    msg = ofpraw_alloc(OFPRAW_OFPT13_METER_MOD, ofp_version,
                       NXM_TYPICAL_LEN + mm->meter.n_bands * 16);
    omm = ofpbuf_put_zeros(msg, sizeof *omm);
    omm->command = htons(mm->command);
    if (mm->command != OFPMC13_DELETE) {
        omm->flags = htons(mm->meter.flags);
    }
    omm->meter_id = htonl(mm->meter.meter_id);

    ofputil_put_bands(mm->meter.n_bands, mm->meter.bands, msg);

    ofpmsg_update_length(msg);
    return msg;
}

static ovs_be16
ofputil_tid_command(const struct ofputil_flow_mod *fm,
                    enum ofputil_protocol protocol)
{
    return htons(protocol & OFPUTIL_P_TID
                 ? (fm->command & 0xff) | (fm->table_id << 8)
                 : fm->command);
}

/* Converts 'fm' into an OFPT_FLOW_MOD or NXT_FLOW_MOD message according to
 * 'protocol' and returns the message. */
struct ofpbuf *
ofputil_encode_flow_mod(const struct ofputil_flow_mod *fm,
                        enum ofputil_protocol protocol)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);
    ovs_be16 raw_flags = ofputil_encode_flow_mod_flags(fm->flags, version);
    struct ofpbuf *msg;

    switch (protocol) {
    case OFPUTIL_P_OF11_STD:
    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
    case OFPUTIL_P_OF14_OXM:
    case OFPUTIL_P_OF15_OXM:
    case OFPUTIL_P_OF16_OXM: {
        struct ofp11_flow_mod *ofm;
        int tailroom;

        tailroom = ofputil_match_typical_len(protocol) + fm->ofpacts_len;
        msg = ofpraw_alloc(OFPRAW_OFPT11_FLOW_MOD, version, tailroom);
        ofm = ofpbuf_put_zeros(msg, sizeof *ofm);
        if ((protocol == OFPUTIL_P_OF11_STD
             && (fm->command == OFPFC_MODIFY ||
                 fm->command == OFPFC_MODIFY_STRICT)
             && fm->cookie_mask == htonll(0))
            || fm->command == OFPFC_ADD) {
            ofm->cookie = fm->new_cookie;
        } else {
            ofm->cookie = fm->cookie & fm->cookie_mask;
        }
        ofm->cookie_mask = fm->cookie_mask;
        if (fm->table_id != OFPTT_ALL
            || (protocol != OFPUTIL_P_OF11_STD
                && (fm->command == OFPFC_DELETE ||
                    fm->command == OFPFC_DELETE_STRICT))) {
            ofm->table_id = fm->table_id;
        } else {
            ofm->table_id = 0;
        }
        ofm->command = fm->command;
        ofm->idle_timeout = htons(fm->idle_timeout);
        ofm->hard_timeout = htons(fm->hard_timeout);
        ofm->priority = htons(fm->priority);
        ofm->buffer_id = htonl(fm->buffer_id);
        ofm->out_port = ofputil_port_to_ofp11(fm->out_port);
        ofm->out_group = htonl(fm->out_group);
        ofm->flags = raw_flags;
        if (version >= OFP14_VERSION && fm->command == OFPFC_ADD) {
            ofm->importance = htons(fm->importance);
        } else {
            ofm->importance = 0;
        }
        ofputil_put_ofp11_match(msg, &fm->match, protocol);
        ofpacts_put_openflow_instructions(fm->ofpacts, fm->ofpacts_len, msg,
                                          version);
        break;
    }

    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID: {
        struct ofp10_flow_mod *ofm;

        msg = ofpraw_alloc(OFPRAW_OFPT10_FLOW_MOD, OFP10_VERSION,
                           fm->ofpacts_len);
        ofm = ofpbuf_put_zeros(msg, sizeof *ofm);
        ofputil_match_to_ofp10_match(&fm->match, &ofm->match);
        ofm->cookie = fm->new_cookie;
        ofm->command = ofputil_tid_command(fm, protocol);
        ofm->idle_timeout = htons(fm->idle_timeout);
        ofm->hard_timeout = htons(fm->hard_timeout);
        ofm->priority = htons(fm->priority);
        ofm->buffer_id = htonl(fm->buffer_id);
        ofm->out_port = htons(ofp_to_u16(fm->out_port));
        ofm->flags = raw_flags;
        ofpacts_put_openflow_actions(fm->ofpacts, fm->ofpacts_len, msg,
                                     version);
        break;
    }

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID: {
        struct nx_flow_mod *nfm;
        int match_len;

        msg = ofpraw_alloc(OFPRAW_NXT_FLOW_MOD, OFP10_VERSION,
                           NXM_TYPICAL_LEN + fm->ofpacts_len);
        nfm = ofpbuf_put_zeros(msg, sizeof *nfm);
        nfm->command = ofputil_tid_command(fm, protocol);
        nfm->cookie = fm->new_cookie;
        match_len = nx_put_match(msg, &fm->match, fm->cookie, fm->cookie_mask);
        nfm = msg->msg;
        nfm->idle_timeout = htons(fm->idle_timeout);
        nfm->hard_timeout = htons(fm->hard_timeout);
        nfm->priority = htons(fm->priority);
        nfm->buffer_id = htonl(fm->buffer_id);
        nfm->out_port = htons(ofp_to_u16(fm->out_port));
        nfm->flags = raw_flags;
        nfm->match_len = htons(match_len);
        ofpacts_put_openflow_actions(fm->ofpacts, fm->ofpacts_len, msg,
                                     version);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    ofpmsg_update_length(msg);
    return msg;
}

static enum ofperr
ofputil_decode_ofpst10_flow_request(struct ofputil_flow_stats_request *fsr,
                                    const struct ofp10_flow_stats_request *ofsr,
                                    bool aggregate)
{
    fsr->aggregate = aggregate;
    ofputil_match_from_ofp10_match(&ofsr->match, &fsr->match);
    fsr->out_port = u16_to_ofp(ntohs(ofsr->out_port));
    fsr->out_group = OFPG_ANY;
    fsr->table_id = ofsr->table_id;
    fsr->cookie = fsr->cookie_mask = htonll(0);

    return 0;
}

static enum ofperr
ofputil_decode_ofpst11_flow_request(struct ofputil_flow_stats_request *fsr,
                                    struct ofpbuf *b, bool aggregate,
                                    const struct tun_table *tun_table,
                                    const struct vl_mff_map *vl_mff_map)
{
    const struct ofp11_flow_stats_request *ofsr;
    enum ofperr error;

    ofsr = ofpbuf_pull(b, sizeof *ofsr);
    fsr->aggregate = aggregate;
    fsr->table_id = ofsr->table_id;
    error = ofputil_port_from_ofp11(ofsr->out_port, &fsr->out_port);
    if (error) {
        return error;
    }
    fsr->out_group = ntohl(ofsr->out_group);
    fsr->cookie = ofsr->cookie;
    fsr->cookie_mask = ofsr->cookie_mask;
    error = ofputil_pull_ofp11_match(b, tun_table, vl_mff_map, &fsr->match,
                                     NULL);
    if (error) {
        return error;
    }

    return 0;
}

static enum ofperr
ofputil_decode_nxst_flow_request(struct ofputil_flow_stats_request *fsr,
                                 struct ofpbuf *b, bool aggregate,
                                 const struct tun_table *tun_table,
                                 const struct vl_mff_map *vl_mff_map)
{
    const struct nx_flow_stats_request *nfsr;
    enum ofperr error;

    nfsr = ofpbuf_pull(b, sizeof *nfsr);
    error = nx_pull_match(b, ntohs(nfsr->match_len), &fsr->match,
                          &fsr->cookie, &fsr->cookie_mask, false, tun_table,
                          vl_mff_map);
    if (error) {
        return error;
    }
    if (b->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    fsr->aggregate = aggregate;
    fsr->out_port = u16_to_ofp(ntohs(nfsr->out_port));
    fsr->out_group = OFPG_ANY;
    fsr->table_id = nfsr->table_id;

    return 0;
}

/* Constructs and returns an OFPT_QUEUE_GET_CONFIG request for the specified
 * 'port' and 'queue', suitable for OpenFlow version 'version'.
 *
 * 'queue' is honored only for OpenFlow 1.4 and later; older versions always
 * request all queues. */
struct ofpbuf *
ofputil_encode_queue_get_config_request(enum ofp_version version,
                                        ofp_port_t port,
                                        uint32_t queue)
{
    struct ofpbuf *request;

    if (version == OFP10_VERSION) {
        struct ofp10_queue_get_config_request *qgcr10;

        request = ofpraw_alloc(OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST,
                               version, 0);
        qgcr10 = ofpbuf_put_zeros(request, sizeof *qgcr10);
        qgcr10->port = htons(ofp_to_u16(port));
    } else if (version < OFP14_VERSION) {
        struct ofp11_queue_get_config_request *qgcr11;

        request = ofpraw_alloc(OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST,
                               version, 0);
        qgcr11 = ofpbuf_put_zeros(request, sizeof *qgcr11);
        qgcr11->port = ofputil_port_to_ofp11(port);
    } else {
        struct ofp14_queue_desc_request *qdr14;

        request = ofpraw_alloc(OFPRAW_OFPST14_QUEUE_DESC_REQUEST,
                               version, 0);
        qdr14 = ofpbuf_put_zeros(request, sizeof *qdr14);
        qdr14->port = ofputil_port_to_ofp11(port);
        qdr14->queue = htonl(queue);
    }

    return request;
}

/* Parses OFPT_QUEUE_GET_CONFIG request 'oh', storing the port specified by the
 * request into '*port'.  Returns 0 if successful, otherwise an OpenFlow error
 * code. */
enum ofperr
ofputil_decode_queue_get_config_request(const struct ofp_header *oh,
                                        ofp_port_t *port, uint32_t *queue)
{
    const struct ofp10_queue_get_config_request *qgcr10;
    const struct ofp11_queue_get_config_request *qgcr11;
    const struct ofp14_queue_desc_request *qdr14;
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);

    switch ((int) raw) {
    case OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST:
        qgcr10 = b.data;
        *port = u16_to_ofp(ntohs(qgcr10->port));
        *queue = OFPQ_ALL;
        break;

    case OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST:
        qgcr11 = b.data;
        *queue = OFPQ_ALL;
        enum ofperr error = ofputil_port_from_ofp11(qgcr11->port, port);
        if (error || *port == OFPP_ANY) {
            return error;
        }
        break;

    case OFPRAW_OFPST14_QUEUE_DESC_REQUEST:
        qdr14 = b.data;
        *queue = ntohl(qdr14->queue);
        return ofputil_port_from_ofp11(qdr14->port, port);

    default:
        OVS_NOT_REACHED();
    }

    return (ofp_to_u16(*port) < ofp_to_u16(OFPP_MAX)
            ? 0
            : OFPERR_OFPQOFC_BAD_PORT);
}

/* Constructs and returns the beginning of a reply to
 * OFPT_QUEUE_GET_CONFIG_REQUEST or OFPMP_QUEUE_DESC request 'oh'.  The caller
 * may append information about individual queues with
 * ofputil_append_queue_get_config_reply(). */
void
ofputil_start_queue_get_config_reply(const struct ofp_header *request,
                                     struct ovs_list *replies)
{
    struct ofpbuf *reply;
    enum ofperr error;
    ofp_port_t port;
    uint32_t queue;

    error = ofputil_decode_queue_get_config_request(request, &port, &queue);
    ovs_assert(!error);

    enum ofpraw raw = ofpraw_decode_assert(request);
    switch ((int) raw) {
    case OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST:
        reply = ofpraw_alloc_reply(OFPRAW_OFPT10_QUEUE_GET_CONFIG_REPLY,
                                   request, 0);
        struct ofp10_queue_get_config_reply *qgcr10
            = ofpbuf_put_zeros(reply, sizeof *qgcr10);
        qgcr10->port = htons(ofp_to_u16(port));
        break;

    case OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST:
        reply = ofpraw_alloc_reply(OFPRAW_OFPT11_QUEUE_GET_CONFIG_REPLY,
                                   request, 0);
        struct ofp11_queue_get_config_reply *qgcr11
            = ofpbuf_put_zeros(reply, sizeof *qgcr11);
        qgcr11->port = ofputil_port_to_ofp11(port);
        break;

    case OFPRAW_OFPST14_QUEUE_DESC_REQUEST:
        reply = ofpraw_alloc_stats_reply(request, 0);
        break;

    default:
        OVS_NOT_REACHED();
    }

    ovs_list_init(replies);
    ovs_list_push_back(replies, &reply->list_node);
}

static void
put_ofp10_queue_rate(struct ofpbuf *reply,
                     enum ofp10_queue_properties property, uint16_t rate)
{
    if (rate != UINT16_MAX) {
        struct ofp10_queue_prop_rate *oqpr;

        oqpr = ofpbuf_put_zeros(reply, sizeof *oqpr);
        oqpr->prop_header.property = htons(property);
        oqpr->prop_header.len = htons(sizeof *oqpr);
        oqpr->rate = htons(rate);
    }
}

static void
put_ofp14_queue_rate(struct ofpbuf *reply,
                     enum ofp14_queue_desc_prop_type type, uint16_t rate)
{
    if (rate != UINT16_MAX) {
        ofpprop_put_u16(reply, type, rate);
    }
}

void
ofputil_append_queue_get_config_reply(const struct ofputil_queue_config *qc,
                                      struct ovs_list *replies)
{
    enum ofp_version ofp_version = ofpmp_version(replies);
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_ofs = reply->size;
    size_t len_ofs;
    ovs_be16 *len;

    if (ofp_version < OFP14_VERSION) {
        if (ofp_version < OFP12_VERSION) {
            struct ofp10_packet_queue *opq10;

            opq10 = ofpbuf_put_zeros(reply, sizeof *opq10);
            opq10->queue_id = htonl(qc->queue);
            len_ofs = (char *) &opq10->len - (char *) reply->data;
        } else {
            struct ofp12_packet_queue *opq12;

            opq12 = ofpbuf_put_zeros(reply, sizeof *opq12);
            opq12->port = ofputil_port_to_ofp11(qc->port);
            opq12->queue_id = htonl(qc->queue);
            len_ofs = (char *) &opq12->len - (char *) reply->data;
        }

        put_ofp10_queue_rate(reply, OFPQT10_MIN_RATE, qc->min_rate);
        put_ofp10_queue_rate(reply, OFPQT11_MAX_RATE, qc->max_rate);
    } else {
        struct ofp14_queue_desc *oqd = ofpbuf_put_zeros(reply, sizeof *oqd);
        oqd->port_no = ofputil_port_to_ofp11(qc->port);
        oqd->queue_id = htonl(qc->queue);
        len_ofs = (char *) &oqd->len - (char *) reply->data;
        put_ofp14_queue_rate(reply, OFPQDPT14_MIN_RATE, qc->min_rate);
        put_ofp14_queue_rate(reply, OFPQDPT14_MAX_RATE, qc->max_rate);
    }

    len = ofpbuf_at(reply, len_ofs, sizeof *len);
    *len = htons(reply->size - start_ofs);

    if (ofp_version >= OFP14_VERSION) {
        ofpmp_postappend(replies, start_ofs);
    }
}

static enum ofperr
parse_ofp10_queue_rate(const struct ofp10_queue_prop_header *hdr,
                       uint16_t *rate)
{
    const struct ofp10_queue_prop_rate *oqpr;

    if (hdr->len == htons(sizeof *oqpr)) {
        oqpr = (const struct ofp10_queue_prop_rate *) hdr;
        *rate = ntohs(oqpr->rate);
        return 0;
    } else {
        return OFPERR_OFPBRC_BAD_LEN;
    }
}

static int
ofputil_pull_queue_get_config_reply10(struct ofpbuf *msg,
                                      struct ofputil_queue_config *queue)
{
    const struct ofp_header *oh = msg->header;
    unsigned int opq_len;       /* Length of protocol-specific queue header. */
    unsigned int len;           /* Total length of queue + properties. */

    /* Obtain the port number from the message header. */
    if (oh->version == OFP10_VERSION) {
        const struct ofp10_queue_get_config_reply *oqgcr10 = msg->msg;
        queue->port = u16_to_ofp(ntohs(oqgcr10->port));
    } else {
        const struct ofp11_queue_get_config_reply *oqgcr11 = msg->msg;
        enum ofperr error = ofputil_port_from_ofp11(oqgcr11->port,
                                                    &queue->port);
        if (error) {
            return error;
        }
    }

    /* Pull off the queue header and get the queue number and length. */
    if (oh->version < OFP12_VERSION) {
        const struct ofp10_packet_queue *opq10;
        opq10 = ofpbuf_try_pull(msg, sizeof *opq10);
        if (!opq10) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        queue->queue = ntohl(opq10->queue_id);
        len = ntohs(opq10->len);
        opq_len = sizeof *opq10;
    } else {
        const struct ofp12_packet_queue *opq12;
        opq12 = ofpbuf_try_pull(msg, sizeof *opq12);
        if (!opq12) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        queue->queue = ntohl(opq12->queue_id);
        len = ntohs(opq12->len);
        opq_len = sizeof *opq12;
    }

    /* Length check. */
    if (len < opq_len || len > msg->size + opq_len || len % 8) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= opq_len;

    /* Pull properties.  The format of these properties differs from used in
     * OF1.4+ so we can't use the common property functions. */
    while (len > 0) {
        const struct ofp10_queue_prop_header *hdr;
        unsigned int property;
        unsigned int prop_len;
        enum ofperr error = 0;

        hdr = ofpbuf_at_assert(msg, 0, sizeof *hdr);
        prop_len = ntohs(hdr->len);
        if (prop_len < sizeof *hdr || prop_len > len || prop_len % 8) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        property = ntohs(hdr->property);
        switch (property) {
        case OFPQT10_MIN_RATE:
            error = parse_ofp10_queue_rate(hdr, &queue->min_rate);
            break;

        case OFPQT11_MAX_RATE:
            error = parse_ofp10_queue_rate(hdr, &queue->max_rate);
            break;

        default:
            VLOG_INFO_RL(&bad_ofmsg_rl, "unknown queue property %u", property);
            break;
        }
        if (error) {
            return error;
        }

        ofpbuf_pull(msg, prop_len);
        len -= prop_len;
    }
    return 0;
}

static int
ofputil_pull_queue_get_config_reply14(struct ofpbuf *msg,
                                      struct ofputil_queue_config *queue)
{
    struct ofp14_queue_desc *oqd14 = ofpbuf_try_pull(msg, sizeof *oqd14);
    if (!oqd14) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    enum ofperr error = ofputil_port_from_ofp11(oqd14->port_no, &queue->port);
    if (error) {
        return error;
    }
    queue->queue = ntohl(oqd14->queue_id);

    /* Length check. */
    unsigned int len = ntohs(oqd14->len);
    if (len < sizeof *oqd14 || len > msg->size + sizeof *oqd14 || len % 8) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= sizeof *oqd14;

    struct ofpbuf properties = ofpbuf_const_initializer(ofpbuf_pull(msg, len),
                                                        len);
    while (properties.size > 0) {
        struct ofpbuf payload;
        uint64_t type;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPQDPT14_MIN_RATE:
            error = ofpprop_parse_u16(&payload, &queue->min_rate);
            break;

        case OFPQDPT14_MAX_RATE:
            error = ofpprop_parse_u16(&payload, &queue->max_rate);
            break;

        default:
            error = OFPPROP_UNKNOWN(true, "queue desc", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

/* Decodes information about a queue from the OFPT_QUEUE_GET_CONFIG_REPLY in
 * 'reply' and stores it in '*queue'.  ofputil_decode_queue_get_config_reply()
 * must already have pulled off the main header.
 *
 * This function returns EOF if the last queue has already been decoded, 0 if a
 * queue was successfully decoded into '*queue', or an ofperr if there was a
 * problem decoding 'reply'. */
int
ofputil_pull_queue_get_config_reply(struct ofpbuf *msg,
                                    struct ofputil_queue_config *queue)
{
    enum ofpraw raw;
    if (!msg->header) {
        /* Pull OpenFlow header. */
        raw = ofpraw_pull_assert(msg);

        /* Pull protocol-specific ofp_queue_get_config_reply header (OF1.4
         * doesn't have one at all). */
        if (raw == OFPRAW_OFPT10_QUEUE_GET_CONFIG_REPLY) {
            ofpbuf_pull(msg, sizeof(struct ofp10_queue_get_config_reply));
        } else if (raw == OFPRAW_OFPT11_QUEUE_GET_CONFIG_REPLY) {
            ofpbuf_pull(msg, sizeof(struct ofp11_queue_get_config_reply));
        } else {
            ovs_assert(raw == OFPRAW_OFPST14_QUEUE_DESC_REPLY);
        }
    } else {
        raw = ofpraw_decode_assert(msg->header);
    }

    queue->min_rate = UINT16_MAX;
    queue->max_rate = UINT16_MAX;

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST14_QUEUE_DESC_REPLY) {
        return ofputil_pull_queue_get_config_reply14(msg, queue);
    } else {
        return ofputil_pull_queue_get_config_reply10(msg, queue);
    }
}

/* Converts an OFPST_FLOW, OFPST_AGGREGATE, NXST_FLOW, or NXST_AGGREGATE
 * request 'oh', into an abstract flow_stats_request in 'fsr'.  Returns 0 if
 * successful, otherwise an OpenFlow error code.
 *
 * 'vl_mff_map' is an optional parameter that is used to validate the length
 * of variable length mf_fields in 'match'. If it is not provided, the
 * default mf_fields with maximum length will be used. */
enum ofperr
ofputil_decode_flow_stats_request(struct ofputil_flow_stats_request *fsr,
                                  const struct ofp_header *oh,
                                  const struct tun_table *tun_table,
                                  const struct vl_mff_map *vl_mff_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    switch ((int) raw) {
    case OFPRAW_OFPST10_FLOW_REQUEST:
        return ofputil_decode_ofpst10_flow_request(fsr, b.data, false);

    case OFPRAW_OFPST10_AGGREGATE_REQUEST:
        return ofputil_decode_ofpst10_flow_request(fsr, b.data, true);

    case OFPRAW_OFPST11_FLOW_REQUEST:
        return ofputil_decode_ofpst11_flow_request(fsr, &b, false, tun_table,
                                                   vl_mff_map);

    case OFPRAW_OFPST11_AGGREGATE_REQUEST:
        return ofputil_decode_ofpst11_flow_request(fsr, &b, true, tun_table,
                                                   vl_mff_map);

    case OFPRAW_NXST_FLOW_REQUEST:
        return ofputil_decode_nxst_flow_request(fsr, &b, false, tun_table,
                                                vl_mff_map);

    case OFPRAW_NXST_AGGREGATE_REQUEST:
        return ofputil_decode_nxst_flow_request(fsr, &b, true, tun_table,
                                                vl_mff_map);

    default:
        /* Hey, the caller lied. */
        OVS_NOT_REACHED();
    }
}

/* Converts abstract flow_stats_request 'fsr' into an OFPST_FLOW,
 * OFPST_AGGREGATE, NXST_FLOW, or NXST_AGGREGATE request 'oh' according to
 * 'protocol', and returns the message. */
struct ofpbuf *
ofputil_encode_flow_stats_request(const struct ofputil_flow_stats_request *fsr,
                                  enum ofputil_protocol protocol)
{
    struct ofpbuf *msg;
    enum ofpraw raw;

    switch (protocol) {
    case OFPUTIL_P_OF11_STD:
    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
    case OFPUTIL_P_OF14_OXM:
    case OFPUTIL_P_OF15_OXM:
    case OFPUTIL_P_OF16_OXM: {
        struct ofp11_flow_stats_request *ofsr;

        raw = (fsr->aggregate
               ? OFPRAW_OFPST11_AGGREGATE_REQUEST
               : OFPRAW_OFPST11_FLOW_REQUEST);
        msg = ofpraw_alloc(raw, ofputil_protocol_to_ofp_version(protocol),
                           ofputil_match_typical_len(protocol));
        ofsr = ofpbuf_put_zeros(msg, sizeof *ofsr);
        ofsr->table_id = fsr->table_id;
        ofsr->out_port = ofputil_port_to_ofp11(fsr->out_port);
        ofsr->out_group = htonl(fsr->out_group);
        ofsr->cookie = fsr->cookie;
        ofsr->cookie_mask = fsr->cookie_mask;
        ofputil_put_ofp11_match(msg, &fsr->match, protocol);
        break;
    }

    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID: {
        struct ofp10_flow_stats_request *ofsr;

        raw = (fsr->aggregate
               ? OFPRAW_OFPST10_AGGREGATE_REQUEST
               : OFPRAW_OFPST10_FLOW_REQUEST);
        msg = ofpraw_alloc(raw, OFP10_VERSION, 0);
        ofsr = ofpbuf_put_zeros(msg, sizeof *ofsr);
        ofputil_match_to_ofp10_match(&fsr->match, &ofsr->match);
        ofsr->table_id = fsr->table_id;
        ofsr->out_port = htons(ofp_to_u16(fsr->out_port));
        break;
    }

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID: {
        struct nx_flow_stats_request *nfsr;
        int match_len;

        raw = (fsr->aggregate
               ? OFPRAW_NXST_AGGREGATE_REQUEST
               : OFPRAW_NXST_FLOW_REQUEST);
        msg = ofpraw_alloc(raw, OFP10_VERSION, NXM_TYPICAL_LEN);
        ofpbuf_put_zeros(msg, sizeof *nfsr);
        match_len = nx_put_match(msg, &fsr->match,
                                 fsr->cookie, fsr->cookie_mask);

        nfsr = msg->msg;
        nfsr->out_port = htons(ofp_to_u16(fsr->out_port));
        nfsr->match_len = htons(match_len);
        nfsr->table_id = fsr->table_id;
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    return msg;
}

/* Converts an OFPST_FLOW or NXST_FLOW reply in 'msg' into an abstract
 * ofputil_flow_stats in 'fs'.
 *
 * Multiple OFPST_FLOW or NXST_FLOW replies can be packed into a single
 * OpenFlow message.  Calling this function multiple times for a single 'msg'
 * iterates through the replies.  The caller must initially leave 'msg''s layer
 * pointers null and not modify them between calls.
 *
 * Most switches don't send the values needed to populate fs->idle_age and
 * fs->hard_age, so those members will usually be set to 0.  If the switch from
 * which 'msg' originated is known to implement NXT_FLOW_AGE, then pass
 * 'flow_age_extension' as true so that the contents of 'msg' determine the
 * 'idle_age' and 'hard_age' members in 'fs'.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of the flow stats
 * reply's actions.  The caller must initialize 'ofpacts' and retains ownership
 * of it.  'fs->ofpacts' will point into the 'ofpacts' buffer.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_flow_stats_reply(struct ofputil_flow_stats *fs,
                                struct ofpbuf *msg,
                                bool flow_age_extension,
                                struct ofpbuf *ofpacts)
{
    const struct ofp_header *oh;
    size_t instructions_len;
    enum ofperr error;
    enum ofpraw raw;

    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }
    oh = msg->header;

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST11_FLOW_REPLY
               || raw == OFPRAW_OFPST13_FLOW_REPLY) {
        const struct ofp11_flow_stats *ofs;
        size_t length;
        uint16_t padded_match_len;

        ofs = ofpbuf_try_pull(msg, sizeof *ofs);
        if (!ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply has %"PRIu32" leftover "
                         "bytes at end", msg->size);
            return EINVAL;
        }

        length = ntohs(ofs->length);
        if (length < sizeof *ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply claims invalid "
                         "length %"PRIuSIZE, length);
            return EINVAL;
        }

        if (ofputil_pull_ofp11_match(msg, NULL, NULL, &fs->match,
                                     &padded_match_len)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply bad match");
            return EINVAL;
        }
        instructions_len = length - sizeof *ofs - padded_match_len;

        fs->priority = ntohs(ofs->priority);
        fs->table_id = ofs->table_id;
        fs->duration_sec = ntohl(ofs->duration_sec);
        fs->duration_nsec = ntohl(ofs->duration_nsec);
        fs->idle_timeout = ntohs(ofs->idle_timeout);
        fs->hard_timeout = ntohs(ofs->hard_timeout);
        if (oh->version >= OFP14_VERSION) {
            fs->importance = ntohs(ofs->importance);
        } else {
            fs->importance = 0;
        }
        if (raw == OFPRAW_OFPST13_FLOW_REPLY) {
            error = ofputil_decode_flow_mod_flags(ofs->flags, -1, oh->version,
                                                  &fs->flags);
            if (error) {
                return error;
            }
        } else {
            fs->flags = 0;
        }
        fs->idle_age = -1;
        fs->hard_age = -1;
        fs->cookie = ofs->cookie;
        fs->packet_count = ntohll(ofs->packet_count);
        fs->byte_count = ntohll(ofs->byte_count);
    } else if (raw == OFPRAW_OFPST10_FLOW_REPLY) {
        const struct ofp10_flow_stats *ofs;
        size_t length;

        ofs = ofpbuf_try_pull(msg, sizeof *ofs);
        if (!ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply has %"PRIu32" leftover "
                         "bytes at end", msg->size);
            return EINVAL;
        }

        length = ntohs(ofs->length);
        if (length < sizeof *ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply claims invalid "
                         "length %"PRIuSIZE, length);
            return EINVAL;
        }
        instructions_len = length - sizeof *ofs;

        fs->cookie = get_32aligned_be64(&ofs->cookie);
        ofputil_match_from_ofp10_match(&ofs->match, &fs->match);
        fs->priority = ntohs(ofs->priority);
        fs->table_id = ofs->table_id;
        fs->duration_sec = ntohl(ofs->duration_sec);
        fs->duration_nsec = ntohl(ofs->duration_nsec);
        fs->idle_timeout = ntohs(ofs->idle_timeout);
        fs->hard_timeout = ntohs(ofs->hard_timeout);
        fs->importance = 0;
        fs->idle_age = -1;
        fs->hard_age = -1;
        fs->packet_count = ntohll(get_32aligned_be64(&ofs->packet_count));
        fs->byte_count = ntohll(get_32aligned_be64(&ofs->byte_count));
        fs->flags = 0;
    } else if (raw == OFPRAW_NXST_FLOW_REPLY) {
        const struct nx_flow_stats *nfs;
        size_t match_len, length;

        nfs = ofpbuf_try_pull(msg, sizeof *nfs);
        if (!nfs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW reply has %"PRIu32" leftover "
                         "bytes at end", msg->size);
            return EINVAL;
        }

        length = ntohs(nfs->length);
        match_len = ntohs(nfs->match_len);
        if (length < sizeof *nfs + ROUND_UP(match_len, 8)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW reply with match_len=%"PRIuSIZE" "
                         "claims invalid length %"PRIuSIZE, match_len, length);
            return EINVAL;
        }
        if (nx_pull_match(msg, match_len, &fs->match, NULL, NULL, false, NULL,
                          NULL)) {
            return EINVAL;
        }
        instructions_len = length - sizeof *nfs - ROUND_UP(match_len, 8);

        fs->cookie = nfs->cookie;
        fs->table_id = nfs->table_id;
        fs->duration_sec = ntohl(nfs->duration_sec);
        fs->duration_nsec = ntohl(nfs->duration_nsec);
        fs->priority = ntohs(nfs->priority);
        fs->idle_timeout = ntohs(nfs->idle_timeout);
        fs->hard_timeout = ntohs(nfs->hard_timeout);
        fs->importance = 0;
        fs->idle_age = -1;
        fs->hard_age = -1;
        if (flow_age_extension) {
            if (nfs->idle_age) {
                fs->idle_age = ntohs(nfs->idle_age) - 1;
            }
            if (nfs->hard_age) {
                fs->hard_age = ntohs(nfs->hard_age) - 1;
            }
        }
        fs->packet_count = ntohll(nfs->packet_count);
        fs->byte_count = ntohll(nfs->byte_count);
        fs->flags = 0;
    } else {
        OVS_NOT_REACHED();
    }

    if (ofpacts_pull_openflow_instructions(msg, instructions_len, oh->version,
                                           NULL, NULL, ofpacts)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply bad instructions");
        return EINVAL;
    }
    fs->ofpacts = ofpacts->data;
    fs->ofpacts_len = ofpacts->size;

    return 0;
}

/* Returns 'count' unchanged except that UINT64_MAX becomes 0.
 *
 * We use this in situations where OVS internally uses UINT64_MAX to mean
 * "value unknown" but OpenFlow 1.0 does not define any unknown value. */
static uint64_t
unknown_to_zero(uint64_t count)
{
    return count != UINT64_MAX ? count : 0;
}

/* Appends an OFPST_FLOW or NXST_FLOW reply that contains the data in 'fs' to
 * those already present in the list of ofpbufs in 'replies'.  'replies' should
 * have been initialized with ofpmp_init(). */
void
ofputil_append_flow_stats_reply(const struct ofputil_flow_stats *fs,
                                struct ovs_list *replies,
                                const struct tun_table *tun_table)
{
    struct ofputil_flow_stats *fs_ = CONST_CAST(struct ofputil_flow_stats *,
                                                fs);
    const struct tun_table *orig_tun_table;
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_ofs = reply->size;
    enum ofp_version version = ofpmp_version(replies);
    enum ofpraw raw = ofpmp_decode_raw(replies);

    orig_tun_table = fs->match.flow.tunnel.metadata.tab;
    fs_->match.flow.tunnel.metadata.tab = tun_table;

    if (raw == OFPRAW_OFPST11_FLOW_REPLY || raw == OFPRAW_OFPST13_FLOW_REPLY) {
        struct ofp11_flow_stats *ofs;

        ofpbuf_put_uninit(reply, sizeof *ofs);
        oxm_put_match(reply, &fs->match, version);
        ofpacts_put_openflow_instructions(fs->ofpacts, fs->ofpacts_len, reply,
                                          version);

        ofs = ofpbuf_at_assert(reply, start_ofs, sizeof *ofs);
        ofs->length = htons(reply->size - start_ofs);
        ofs->table_id = fs->table_id;
        ofs->pad = 0;
        ofs->duration_sec = htonl(fs->duration_sec);
        ofs->duration_nsec = htonl(fs->duration_nsec);
        ofs->priority = htons(fs->priority);
        ofs->idle_timeout = htons(fs->idle_timeout);
        ofs->hard_timeout = htons(fs->hard_timeout);
        if (version >= OFP14_VERSION) {
            ofs->importance = htons(fs->importance);
        } else {
            ofs->importance = 0;
        }
        if (raw == OFPRAW_OFPST13_FLOW_REPLY) {
            ofs->flags = ofputil_encode_flow_mod_flags(fs->flags, version);
        } else {
            ofs->flags = 0;
        }
        memset(ofs->pad2, 0, sizeof ofs->pad2);
        ofs->cookie = fs->cookie;
        ofs->packet_count = htonll(unknown_to_zero(fs->packet_count));
        ofs->byte_count = htonll(unknown_to_zero(fs->byte_count));
    } else if (raw == OFPRAW_OFPST10_FLOW_REPLY) {
        struct ofp10_flow_stats *ofs;

        ofpbuf_put_uninit(reply, sizeof *ofs);
        ofpacts_put_openflow_actions(fs->ofpacts, fs->ofpacts_len, reply,
                                     version);
        ofs = ofpbuf_at_assert(reply, start_ofs, sizeof *ofs);
        ofs->length = htons(reply->size - start_ofs);
        ofs->table_id = fs->table_id;
        ofs->pad = 0;
        ofputil_match_to_ofp10_match(&fs->match, &ofs->match);
        ofs->duration_sec = htonl(fs->duration_sec);
        ofs->duration_nsec = htonl(fs->duration_nsec);
        ofs->priority = htons(fs->priority);
        ofs->idle_timeout = htons(fs->idle_timeout);
        ofs->hard_timeout = htons(fs->hard_timeout);
        memset(ofs->pad2, 0, sizeof ofs->pad2);
        put_32aligned_be64(&ofs->cookie, fs->cookie);
        put_32aligned_be64(&ofs->packet_count,
                           htonll(unknown_to_zero(fs->packet_count)));
        put_32aligned_be64(&ofs->byte_count,
                           htonll(unknown_to_zero(fs->byte_count)));
    } else if (raw == OFPRAW_NXST_FLOW_REPLY) {
        struct nx_flow_stats *nfs;
        int match_len;

        ofpbuf_put_uninit(reply, sizeof *nfs);
        match_len = nx_put_match(reply, &fs->match, 0, 0);
        ofpacts_put_openflow_actions(fs->ofpacts, fs->ofpacts_len, reply,
                                     version);
        nfs = ofpbuf_at_assert(reply, start_ofs, sizeof *nfs);
        nfs->length = htons(reply->size - start_ofs);
        nfs->table_id = fs->table_id;
        nfs->pad = 0;
        nfs->duration_sec = htonl(fs->duration_sec);
        nfs->duration_nsec = htonl(fs->duration_nsec);
        nfs->priority = htons(fs->priority);
        nfs->idle_timeout = htons(fs->idle_timeout);
        nfs->hard_timeout = htons(fs->hard_timeout);
        nfs->idle_age = htons(fs->idle_age < 0 ? 0
                              : fs->idle_age < UINT16_MAX ? fs->idle_age + 1
                              : UINT16_MAX);
        nfs->hard_age = htons(fs->hard_age < 0 ? 0
                              : fs->hard_age < UINT16_MAX ? fs->hard_age + 1
                              : UINT16_MAX);
        nfs->match_len = htons(match_len);
        nfs->cookie = fs->cookie;
        nfs->packet_count = htonll(fs->packet_count);
        nfs->byte_count = htonll(fs->byte_count);
    } else {
        OVS_NOT_REACHED();
    }

    ofpmp_postappend(replies, start_ofs);
    fs_->match.flow.tunnel.metadata.tab = orig_tun_table;
}

/* Converts abstract ofputil_aggregate_stats 'stats' into an OFPST_AGGREGATE or
 * NXST_AGGREGATE reply matching 'request', and returns the message. */
struct ofpbuf *
ofputil_encode_aggregate_stats_reply(
    const struct ofputil_aggregate_stats *stats,
    const struct ofp_header *request)
{
    struct ofp_aggregate_stats_reply *asr;
    uint64_t packet_count;
    uint64_t byte_count;
    struct ofpbuf *msg;
    enum ofpraw raw;

    ofpraw_decode(&raw, request);
    if (raw == OFPRAW_OFPST10_AGGREGATE_REQUEST) {
        packet_count = unknown_to_zero(stats->packet_count);
        byte_count = unknown_to_zero(stats->byte_count);
    } else {
        packet_count = stats->packet_count;
        byte_count = stats->byte_count;
    }

    msg = ofpraw_alloc_stats_reply(request, 0);
    asr = ofpbuf_put_zeros(msg, sizeof *asr);
    put_32aligned_be64(&asr->packet_count, htonll(packet_count));
    put_32aligned_be64(&asr->byte_count, htonll(byte_count));
    asr->flow_count = htonl(stats->flow_count);

    return msg;
}

enum ofperr
ofputil_decode_aggregate_stats_reply(struct ofputil_aggregate_stats *stats,
                                     const struct ofp_header *reply)
{
    struct ofpbuf msg = ofpbuf_const_initializer(reply, ntohs(reply->length));
    ofpraw_pull_assert(&msg);

    struct ofp_aggregate_stats_reply *asr = msg.msg;
    stats->packet_count = ntohll(get_32aligned_be64(&asr->packet_count));
    stats->byte_count = ntohll(get_32aligned_be64(&asr->byte_count));
    stats->flow_count = ntohl(asr->flow_count);

    return 0;
}

/* Converts an OFPT_FLOW_REMOVED or NXT_FLOW_REMOVED message 'oh' into an
 * abstract ofputil_flow_removed in 'fr'.  Returns 0 if successful, otherwise
 * an OpenFlow error code. */
enum ofperr
ofputil_decode_flow_removed(struct ofputil_flow_removed *fr,
                            const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT11_FLOW_REMOVED) {
        const struct ofp12_flow_removed *ofr;
        enum ofperr error;

        ofr = ofpbuf_pull(&b, sizeof *ofr);

        error = ofputil_pull_ofp11_match(&b, NULL, NULL, &fr->match, NULL);
        if (error) {
            return error;
        }

        fr->priority = ntohs(ofr->priority);
        fr->cookie = ofr->cookie;
        fr->reason = ofr->reason;
        fr->table_id = ofr->table_id;
        fr->duration_sec = ntohl(ofr->duration_sec);
        fr->duration_nsec = ntohl(ofr->duration_nsec);
        fr->idle_timeout = ntohs(ofr->idle_timeout);
        fr->hard_timeout = ntohs(ofr->hard_timeout);
        fr->packet_count = ntohll(ofr->packet_count);
        fr->byte_count = ntohll(ofr->byte_count);
    } else if (raw == OFPRAW_OFPT10_FLOW_REMOVED) {
        const struct ofp10_flow_removed *ofr;

        ofr = ofpbuf_pull(&b, sizeof *ofr);

        ofputil_match_from_ofp10_match(&ofr->match, &fr->match);
        fr->priority = ntohs(ofr->priority);
        fr->cookie = ofr->cookie;
        fr->reason = ofr->reason;
        fr->table_id = 255;
        fr->duration_sec = ntohl(ofr->duration_sec);
        fr->duration_nsec = ntohl(ofr->duration_nsec);
        fr->idle_timeout = ntohs(ofr->idle_timeout);
        fr->hard_timeout = 0;
        fr->packet_count = ntohll(ofr->packet_count);
        fr->byte_count = ntohll(ofr->byte_count);
    } else if (raw == OFPRAW_NXT_FLOW_REMOVED) {
        struct nx_flow_removed *nfr;
        enum ofperr error;

        nfr = ofpbuf_pull(&b, sizeof *nfr);
        error = nx_pull_match(&b, ntohs(nfr->match_len), &fr->match, NULL,
                              NULL, false, NULL, NULL);
        if (error) {
            return error;
        }
        if (b.size) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        fr->priority = ntohs(nfr->priority);
        fr->cookie = nfr->cookie;
        fr->reason = nfr->reason;
        fr->table_id = nfr->table_id ? nfr->table_id - 1 : 255;
        fr->duration_sec = ntohl(nfr->duration_sec);
        fr->duration_nsec = ntohl(nfr->duration_nsec);
        fr->idle_timeout = ntohs(nfr->idle_timeout);
        fr->hard_timeout = 0;
        fr->packet_count = ntohll(nfr->packet_count);
        fr->byte_count = ntohll(nfr->byte_count);
    } else {
        OVS_NOT_REACHED();
    }

    return 0;
}

/* Converts abstract ofputil_flow_removed 'fr' into an OFPT_FLOW_REMOVED or
 * NXT_FLOW_REMOVED message 'oh' according to 'protocol', and returns the
 * message. */
struct ofpbuf *
ofputil_encode_flow_removed(const struct ofputil_flow_removed *fr,
                            enum ofputil_protocol protocol)
{
    struct ofpbuf *msg;
    enum ofp_flow_removed_reason reason = fr->reason;

    if (reason == OFPRR_METER_DELETE && !(protocol & OFPUTIL_P_OF14_UP)) {
        reason = OFPRR_DELETE;
    }

    switch (protocol) {
    case OFPUTIL_P_OF11_STD:
    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
    case OFPUTIL_P_OF14_OXM:
    case OFPUTIL_P_OF15_OXM:
    case OFPUTIL_P_OF16_OXM: {
        struct ofp12_flow_removed *ofr;

        msg = ofpraw_alloc_xid(OFPRAW_OFPT11_FLOW_REMOVED,
                               ofputil_protocol_to_ofp_version(protocol),
                               htonl(0),
                               ofputil_match_typical_len(protocol));
        ofr = ofpbuf_put_zeros(msg, sizeof *ofr);
        ofr->cookie = fr->cookie;
        ofr->priority = htons(fr->priority);
        ofr->reason = reason;
        ofr->table_id = fr->table_id;
        ofr->duration_sec = htonl(fr->duration_sec);
        ofr->duration_nsec = htonl(fr->duration_nsec);
        ofr->idle_timeout = htons(fr->idle_timeout);
        ofr->hard_timeout = htons(fr->hard_timeout);
        ofr->packet_count = htonll(fr->packet_count);
        ofr->byte_count = htonll(fr->byte_count);
        ofputil_put_ofp11_match(msg, &fr->match, protocol);
        break;
    }

    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID: {
        struct ofp10_flow_removed *ofr;

        msg = ofpraw_alloc_xid(OFPRAW_OFPT10_FLOW_REMOVED, OFP10_VERSION,
                               htonl(0), 0);
        ofr = ofpbuf_put_zeros(msg, sizeof *ofr);
        ofputil_match_to_ofp10_match(&fr->match, &ofr->match);
        ofr->cookie = fr->cookie;
        ofr->priority = htons(fr->priority);
        ofr->reason = reason;
        ofr->duration_sec = htonl(fr->duration_sec);
        ofr->duration_nsec = htonl(fr->duration_nsec);
        ofr->idle_timeout = htons(fr->idle_timeout);
        ofr->packet_count = htonll(unknown_to_zero(fr->packet_count));
        ofr->byte_count = htonll(unknown_to_zero(fr->byte_count));
        break;
    }

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID: {
        struct nx_flow_removed *nfr;
        int match_len;

        msg = ofpraw_alloc_xid(OFPRAW_NXT_FLOW_REMOVED, OFP10_VERSION,
                               htonl(0), NXM_TYPICAL_LEN);
        ofpbuf_put_zeros(msg, sizeof *nfr);
        match_len = nx_put_match(msg, &fr->match, 0, 0);

        nfr = msg->msg;
        nfr->cookie = fr->cookie;
        nfr->priority = htons(fr->priority);
        nfr->reason = reason;
        nfr->table_id = fr->table_id + 1;
        nfr->duration_sec = htonl(fr->duration_sec);
        nfr->duration_nsec = htonl(fr->duration_nsec);
        nfr->idle_timeout = htons(fr->idle_timeout);
        nfr->match_len = htons(match_len);
        nfr->packet_count = htonll(fr->packet_count);
        nfr->byte_count = htonll(fr->byte_count);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    return msg;
}

/* The caller has done basic initialization of '*pin'; the other output
 * arguments needs to be initialized. */
static enum ofperr
decode_nx_packet_in2(const struct ofp_header *oh, bool loose,
                     const struct tun_table *tun_table,
                     const struct vl_mff_map *vl_mff_map,
                     struct ofputil_packet_in *pin,
                     size_t *total_len, uint32_t *buffer_id,
                     struct ofpbuf *continuation)
{
    *total_len = 0;
    *buffer_id = UINT32_MAX;

    struct ofpbuf properties;
    ofpbuf_use_const(&properties, oh, ntohs(oh->length));
    ofpraw_pull_assert(&properties);

    while (properties.size > 0) {
        struct ofpbuf payload;
        uint64_t type;

        enum ofperr error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case NXPINT_PACKET:
            pin->packet = payload.msg;
            pin->packet_len = ofpbuf_msgsize(&payload);
            break;

        case NXPINT_FULL_LEN: {
            uint32_t u32;
            error = ofpprop_parse_u32(&payload, &u32);
            *total_len = u32;
            break;
        }

        case NXPINT_BUFFER_ID:
            error = ofpprop_parse_u32(&payload, buffer_id);
            break;

        case NXPINT_TABLE_ID:
            error = ofpprop_parse_u8(&payload, &pin->table_id);
            break;

        case NXPINT_COOKIE:
            error = ofpprop_parse_be64(&payload, &pin->cookie);
            break;

        case NXPINT_REASON: {
            uint8_t reason;
            error = ofpprop_parse_u8(&payload, &reason);
            pin->reason = reason;
            break;
        }

        case NXPINT_METADATA:
            error = oxm_decode_match(payload.msg, ofpbuf_msgsize(&payload),
                                     loose, tun_table, vl_mff_map,
                                     &pin->flow_metadata);
            break;

        case NXPINT_USERDATA:
            pin->userdata = payload.msg;
            pin->userdata_len = ofpbuf_msgsize(&payload);
            break;

        case NXPINT_CONTINUATION:
            if (continuation) {
                error = ofpprop_parse_nested(&payload, continuation);
            }
            break;

        default:
            error = OFPPROP_UNKNOWN(loose, "NX_PACKET_IN2", type);
            break;
        }
        if (error) {
            return error;
        }
    }

    if (!pin->packet_len) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "NXT_PACKET_IN2 lacks packet");
        return OFPERR_OFPBRC_BAD_LEN;
    } else if (!*total_len) {
        *total_len = pin->packet_len;
    } else if (*total_len < pin->packet_len) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "NXT_PACKET_IN2 claimed full_len < len");
        return OFPERR_OFPBRC_BAD_LEN;
    }

    return 0;
}

/* Decodes the packet-in message starting at 'oh' into '*pin'.  Populates
 * 'pin->packet' and 'pin->packet_len' with the part of the packet actually
 * included in the message.  If 'total_lenp' is nonnull, populates
 * '*total_lenp' with the original length of the packet (which is larger than
 * 'packet->len' if only part of the packet was included).  If 'buffer_idp' is
 * nonnull, stores the packet's buffer ID in '*buffer_idp' (UINT32_MAX if it
 * was not buffered).
 *
 * Populates 'continuation', if nonnull, with the continuation data from the
 * packet-in (an empty buffer, if 'oh' did not contain continuation data).  The
 * format of this data is supposed to be opaque to anything other than
 * ovs-vswitchd, so that in any other process the only reasonable use of this
 * data is to be copied into an NXT_RESUME message via ofputil_encode_resume().
 *
 * This function points 'pin->packet' into 'oh', so the caller should not free
 * it separately from the original OpenFlow message.  This is also true for
 * 'pin->userdata' (which could also end up NULL if there is no userdata).
 *
 * 'vl_mff_map' is an optional parameter that is used to validate the length
 * of variable length mf_fields in 'match'. If it is not provided, the
 * default mf_fields with maximum length will be used.
 *
 * Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
ofputil_decode_packet_in(const struct ofp_header *oh, bool loose,
                         const struct tun_table *tun_table,
                         const struct vl_mff_map *vl_mff_map,
                         struct ofputil_packet_in *pin,
                         size_t *total_lenp, uint32_t *buffer_idp,
                         struct ofpbuf *continuation)
{
    uint32_t buffer_id;
    size_t total_len;

    memset(pin, 0, sizeof *pin);
    pin->cookie = OVS_BE64_MAX;
    if (continuation) {
        ofpbuf_use_const(continuation, NULL, 0);
    }

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT13_PACKET_IN || raw == OFPRAW_OFPT12_PACKET_IN) {
        const struct ofp12_packet_in *opi = ofpbuf_pull(&b, sizeof *opi);
        const ovs_be64 *cookie = (raw == OFPRAW_OFPT13_PACKET_IN
                                  ? ofpbuf_pull(&b, sizeof *cookie)
                                  : NULL);
        enum ofperr error = oxm_pull_match_loose(&b, false, tun_table,
                                                 &pin->flow_metadata);
        if (error) {
            return error;
        }

        if (!ofpbuf_try_pull(&b, 2)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        pin->reason = opi->reason;
        pin->table_id = opi->table_id;
        buffer_id = ntohl(opi->buffer_id);
        total_len = ntohs(opi->total_len);
        if (cookie) {
            pin->cookie = *cookie;
        }

        pin->packet = b.data;
        pin->packet_len = b.size;
    } else if (raw == OFPRAW_OFPT10_PACKET_IN) {
        const struct ofp10_packet_in *opi;

        opi = ofpbuf_pull(&b, offsetof(struct ofp10_packet_in, data));

        pin->packet = CONST_CAST(uint8_t *, opi->data);
        pin->packet_len = b.size;

        match_init_catchall(&pin->flow_metadata);
        match_set_in_port(&pin->flow_metadata,
                          u16_to_ofp(ntohs(opi->in_port)));
        pin->reason = opi->reason;
        buffer_id = ntohl(opi->buffer_id);
        total_len = ntohs(opi->total_len);
    } else if (raw == OFPRAW_OFPT11_PACKET_IN) {
        const struct ofp11_packet_in *opi;
        ofp_port_t in_port;
        enum ofperr error;

        opi = ofpbuf_pull(&b, sizeof *opi);

        pin->packet = b.data;
        pin->packet_len = b.size;

        buffer_id = ntohl(opi->buffer_id);
        error = ofputil_port_from_ofp11(opi->in_port, &in_port);
        if (error) {
            return error;
        }
        match_init_catchall(&pin->flow_metadata);
        match_set_in_port(&pin->flow_metadata, in_port);
        total_len = ntohs(opi->total_len);
        pin->reason = opi->reason;
        pin->table_id = opi->table_id;
    } else if (raw == OFPRAW_NXT_PACKET_IN) {
        const struct nx_packet_in *npi;
        int error;

        npi = ofpbuf_pull(&b, sizeof *npi);
        error = nx_pull_match_loose(&b, ntohs(npi->match_len),
                                    &pin->flow_metadata, NULL, NULL, false,
                                    NULL);
        if (error) {
            return error;
        }

        if (!ofpbuf_try_pull(&b, 2)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        pin->reason = npi->reason;
        pin->table_id = npi->table_id;
        pin->cookie = npi->cookie;

        buffer_id = ntohl(npi->buffer_id);
        total_len = ntohs(npi->total_len);

        pin->packet = b.data;
        pin->packet_len = b.size;
    } else if (raw == OFPRAW_NXT_PACKET_IN2 || raw == OFPRAW_NXT_RESUME) {
        enum ofperr error = decode_nx_packet_in2(oh, loose, tun_table,
                                                 vl_mff_map, pin, &total_len,
                                                 &buffer_id, continuation);
        if (error) {
            return error;
        }
    } else {
        OVS_NOT_REACHED();
    }

    if (total_lenp) {
        *total_lenp = total_len;
    }
    if (buffer_idp) {
        *buffer_idp = buffer_id;
    }

    return 0;
}

static int
encode_packet_in_reason(enum ofp_packet_in_reason reason,
                        enum ofp_version version)
{
    switch (reason) {
    case OFPR_NO_MATCH:
    case OFPR_ACTION:
    case OFPR_INVALID_TTL:
        return reason;

    case OFPR_ACTION_SET:
    case OFPR_GROUP:
    case OFPR_PACKET_OUT:
        return version < OFP14_VERSION ? OFPR_ACTION : reason;

    case OFPR_EXPLICIT_MISS:
        return version < OFP13_VERSION ? OFPR_ACTION : OFPR_NO_MATCH;

    case OFPR_IMPLICIT_MISS:
        return OFPR_NO_MATCH;

    case OFPR_N_REASONS:
    default:
        OVS_NOT_REACHED();
    }
}

/* Only NXT_PACKET_IN2 (not NXT_RESUME) should include NXCPT_USERDATA, so this
 * function omits it.  The caller can add it itself if desired. */
static void
ofputil_put_packet_in(const struct ofputil_packet_in *pin,
                      enum ofp_version version, size_t include_bytes,
                      struct ofpbuf *msg)
{
    /* Add packet properties. */
    ofpprop_put(msg, NXPINT_PACKET, pin->packet, include_bytes);
    if (include_bytes != pin->packet_len) {
        ofpprop_put_u32(msg, NXPINT_FULL_LEN, pin->packet_len);
    }

    /* Add flow properties. */
    ofpprop_put_u8(msg, NXPINT_TABLE_ID, pin->table_id);
    if (pin->cookie != OVS_BE64_MAX) {
        ofpprop_put_be64(msg, NXPINT_COOKIE, pin->cookie);
    }

    /* Add other properties. */
    ofpprop_put_u8(msg, NXPINT_REASON,
                   encode_packet_in_reason(pin->reason, version));

    size_t start = ofpprop_start(msg, NXPINT_METADATA);
    oxm_put_raw(msg, &pin->flow_metadata, version);
    ofpprop_end(msg, start);
}

static void
put_actions_property(struct ofpbuf *msg, uint64_t prop_type,
                     enum ofp_version version,
                     const struct ofpact *actions, size_t actions_len)
{
    if (actions_len) {
        size_t start = ofpprop_start_nested(msg, prop_type);
        ofpacts_put_openflow_actions(actions, actions_len, msg, version);
        ofpprop_end(msg, start);
    }
}

enum nx_continuation_prop_type {
    NXCPT_BRIDGE = 0x8000,
    NXCPT_STACK,
    NXCPT_MIRRORS,
    NXCPT_CONNTRACKED,
    NXCPT_TABLE_ID,
    NXCPT_COOKIE,
    NXCPT_ACTIONS,
    NXCPT_ACTION_SET,
};

/* Only NXT_PACKET_IN2 (not NXT_RESUME) should include NXCPT_USERDATA, so this
 * function omits it.  The caller can add it itself if desired. */
static void
ofputil_put_packet_in_private(const struct ofputil_packet_in_private *pin,
                              enum ofp_version version, size_t include_bytes,
                              struct ofpbuf *msg)
{
    ofputil_put_packet_in(&pin->base, version, include_bytes, msg);

    size_t continuation_ofs = ofpprop_start_nested(msg, NXPINT_CONTINUATION);
    size_t inner_ofs = msg->size;

    if (!uuid_is_zero(&pin->bridge)) {
        ofpprop_put_uuid(msg, NXCPT_BRIDGE, &pin->bridge);
    }

    struct ofpbuf pin_stack;
    ofpbuf_use_const(&pin_stack, pin->stack, pin->stack_size);

    while (pin_stack.size) {
        uint8_t len;
        uint8_t *val = nx_stack_pop(&pin_stack, &len);
        ofpprop_put(msg, NXCPT_STACK, val, len);
    }

    if (pin->mirrors) {
        ofpprop_put_u32(msg, NXCPT_MIRRORS, pin->mirrors);
    }

    if (pin->conntracked) {
        ofpprop_put_flag(msg, NXCPT_CONNTRACKED);
    }

    if (pin->actions_len) {
        /* Divide 'pin->actions' into groups that begins with an
         * unroll_xlate action.  For each group, emit a NXCPT_TABLE_ID and
         * NXCPT_COOKIE property (if either has changed; each is initially
         * assumed 0), then a NXCPT_ACTIONS property with the grouped
         * actions.
         *
         * The alternative is to make OFPACT_UNROLL_XLATE public.  We can
         * always do that later, since this is a private property. */
        const struct ofpact *const end = ofpact_end(pin->actions,
                                                    pin->actions_len);
        const struct ofpact_unroll_xlate *unroll = NULL;
        uint8_t table_id = 0;
        ovs_be64 cookie = 0;

        const struct ofpact *a;
        for (a = pin->actions; ; a = ofpact_next(a)) {
            if (a == end || a->type == OFPACT_UNROLL_XLATE) {
                if (unroll) {
                    if (table_id != unroll->rule_table_id) {
                        ofpprop_put_u8(msg, NXCPT_TABLE_ID,
                                       unroll->rule_table_id);
                        table_id = unroll->rule_table_id;
                    }
                    if (cookie != unroll->rule_cookie) {
                        ofpprop_put_be64(msg, NXCPT_COOKIE,
                                         unroll->rule_cookie);
                        cookie = unroll->rule_cookie;
                    }
                }

                const struct ofpact *start
                    = unroll ? ofpact_next(&unroll->ofpact) : pin->actions;
                put_actions_property(msg, NXCPT_ACTIONS, version,
                                     start, (a - start) * sizeof *a);

                if (a == end) {
                    break;
                }
                unroll = ofpact_get_UNROLL_XLATE(a);
            }
        }
    }

    if (pin->action_set_len) {
        size_t start = ofpprop_start_nested(msg, NXCPT_ACTION_SET);
        ofpacts_put_openflow_actions(pin->action_set,
                                     pin->action_set_len, msg, version);
        ofpprop_end(msg, start);
    }

    if (msg->size > inner_ofs) {
        ofpprop_end(msg, continuation_ofs);
    } else {
        msg->size = continuation_ofs;
    }
}

static struct ofpbuf *
ofputil_encode_ofp10_packet_in(const struct ofputil_packet_in *pin)
{
    struct ofp10_packet_in *opi;
    struct ofpbuf *msg;

    msg = ofpraw_alloc_xid(OFPRAW_OFPT10_PACKET_IN, OFP10_VERSION,
                           htonl(0), pin->packet_len);
    opi = ofpbuf_put_zeros(msg, offsetof(struct ofp10_packet_in, data));
    opi->total_len = htons(pin->packet_len);
    opi->in_port = htons(ofp_to_u16(pin->flow_metadata.flow.in_port.ofp_port));
    opi->reason = encode_packet_in_reason(pin->reason, OFP10_VERSION);
    opi->buffer_id = htonl(UINT32_MAX);

    return msg;
}

static struct ofpbuf *
ofputil_encode_nx_packet_in(const struct ofputil_packet_in *pin,
                            enum ofp_version version)
{
    struct nx_packet_in *npi;
    struct ofpbuf *msg;
    size_t match_len;

    /* The final argument is just an estimate of the space required. */
    msg = ofpraw_alloc_xid(OFPRAW_NXT_PACKET_IN, version,
                           htonl(0), NXM_TYPICAL_LEN + 2 + pin->packet_len);
    ofpbuf_put_zeros(msg, sizeof *npi);
    match_len = nx_put_match(msg, &pin->flow_metadata, 0, 0);
    ofpbuf_put_zeros(msg, 2);

    npi = msg->msg;
    npi->buffer_id = htonl(UINT32_MAX);
    npi->total_len = htons(pin->packet_len);
    npi->reason = encode_packet_in_reason(pin->reason, version);
    npi->table_id = pin->table_id;
    npi->cookie = pin->cookie;
    npi->match_len = htons(match_len);

    return msg;
}

static struct ofpbuf *
ofputil_encode_nx_packet_in2(const struct ofputil_packet_in_private *pin,
                             enum ofp_version version, size_t include_bytes)
{
    /* 'extra' is just an estimate of the space required. */
    size_t extra = (pin->base.packet_len
                    + NXM_TYPICAL_LEN   /* flow_metadata */
                    + pin->stack_size * 4
                    + pin->actions_len
                    + pin->action_set_len
                    + 256);     /* fudge factor */
    struct ofpbuf *msg = ofpraw_alloc_xid(OFPRAW_NXT_PACKET_IN2, version,
                                          htonl(0), extra);

    ofputil_put_packet_in_private(pin, version, include_bytes, msg);
    if (pin->base.userdata_len) {
        ofpprop_put(msg, NXPINT_USERDATA, pin->base.userdata,
                    pin->base.userdata_len);
    }

    ofpmsg_update_length(msg);
    return msg;
}

static struct ofpbuf *
ofputil_encode_ofp11_packet_in(const struct ofputil_packet_in *pin)
{
    struct ofp11_packet_in *opi;
    struct ofpbuf *msg;

    msg = ofpraw_alloc_xid(OFPRAW_OFPT11_PACKET_IN, OFP11_VERSION,
                           htonl(0), pin->packet_len);
    opi = ofpbuf_put_zeros(msg, sizeof *opi);
    opi->buffer_id = htonl(UINT32_MAX);
    opi->in_port = ofputil_port_to_ofp11(
        pin->flow_metadata.flow.in_port.ofp_port);
    opi->in_phy_port = opi->in_port;
    opi->total_len = htons(pin->packet_len);
    opi->reason = encode_packet_in_reason(pin->reason, OFP11_VERSION);
    opi->table_id = pin->table_id;

    return msg;
}

static struct ofpbuf *
ofputil_encode_ofp12_packet_in(const struct ofputil_packet_in *pin,
                               enum ofp_version version)
{
    enum ofpraw raw = (version >= OFP13_VERSION
                       ? OFPRAW_OFPT13_PACKET_IN
                       : OFPRAW_OFPT12_PACKET_IN);
    struct ofpbuf *msg;

    /* The final argument is just an estimate of the space required. */
    msg = ofpraw_alloc_xid(raw, version,
                           htonl(0), NXM_TYPICAL_LEN + 2 + pin->packet_len);

    struct ofp12_packet_in *opi = ofpbuf_put_zeros(msg, sizeof *opi);
    opi->buffer_id = htonl(UINT32_MAX);
    opi->total_len = htons(pin->packet_len);
    opi->reason = encode_packet_in_reason(pin->reason, version);
    opi->table_id = pin->table_id;

    if (version >= OFP13_VERSION) {
        ovs_be64 cookie = pin->cookie;
        ofpbuf_put(msg, &cookie, sizeof cookie);
    }

    oxm_put_match(msg, &pin->flow_metadata, version);
    ofpbuf_put_zeros(msg, 2);

    return msg;
}

/* Converts abstract ofputil_packet_in_private 'pin' into a PACKET_IN message
 * for 'protocol', using the packet-in format specified by 'packet_in_format'.
 *
 * This function is really meant only for use by ovs-vswitchd.  To any other
 * code, the "continuation" data, i.e. the data that is in struct
 * ofputil_packet_in_private but not in struct ofputil_packet_in, is supposed
 * to be opaque (and it might change from one OVS version to another).  Thus,
 * if any other code wants to encode a packet-in, it should use a non-"private"
 * version of this function.  (Such a version doesn't currently exist because
 * only ovs-vswitchd currently wants to encode packet-ins.  If you need one,
 * write it...) */
struct ofpbuf *
ofputil_encode_packet_in_private(const struct ofputil_packet_in_private *pin,
                                 enum ofputil_protocol protocol,
                                 enum nx_packet_in_format packet_in_format)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);

    struct ofpbuf *msg;
    switch (packet_in_format) {
    case NXPIF_STANDARD:
        switch (protocol) {
        case OFPUTIL_P_OF10_STD:
        case OFPUTIL_P_OF10_STD_TID:
        case OFPUTIL_P_OF10_NXM:
        case OFPUTIL_P_OF10_NXM_TID:
            msg = ofputil_encode_ofp10_packet_in(&pin->base);
            break;

        case OFPUTIL_P_OF11_STD:
            msg = ofputil_encode_ofp11_packet_in(&pin->base);
            break;

        case OFPUTIL_P_OF12_OXM:
        case OFPUTIL_P_OF13_OXM:
        case OFPUTIL_P_OF14_OXM:
        case OFPUTIL_P_OF15_OXM:
        case OFPUTIL_P_OF16_OXM:
            msg = ofputil_encode_ofp12_packet_in(&pin->base, version);
            break;

        default:
            OVS_NOT_REACHED();
        }
        break;

    case NXPIF_NXT_PACKET_IN:
        msg = ofputil_encode_nx_packet_in(&pin->base, version);
        break;

    case NXPIF_NXT_PACKET_IN2:
        return ofputil_encode_nx_packet_in2(pin, version,
                                            pin->base.packet_len);

    default:
        OVS_NOT_REACHED();
    }

    ofpbuf_put(msg, pin->base.packet, pin->base.packet_len);
    ofpmsg_update_length(msg);
    return msg;
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFPUTIL_PACKET_IN_REASON_BUFSIZE. */
const char *
ofputil_packet_in_reason_to_string(enum ofp_packet_in_reason reason,
                                   char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPR_NO_MATCH:
        return "no_match";
    case OFPR_ACTION:
        return "action";
    case OFPR_INVALID_TTL:
        return "invalid_ttl";
    case OFPR_ACTION_SET:
        return "action_set";
    case OFPR_GROUP:
        return "group";
    case OFPR_PACKET_OUT:
        return "packet_out";
    case OFPR_EXPLICIT_MISS:
    case OFPR_IMPLICIT_MISS:
        return "";

    case OFPR_N_REASONS:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

bool
ofputil_packet_in_reason_from_string(const char *s,
                                     enum ofp_packet_in_reason *reason)
{
    int i;

    for (i = 0; i < OFPR_N_REASONS; i++) {
        char reasonbuf[OFPUTIL_PACKET_IN_REASON_BUFSIZE];
        const char *reason_s;

        reason_s = ofputil_packet_in_reason_to_string(i, reasonbuf,
                                                      sizeof reasonbuf);
        if (!strcasecmp(s, reason_s)) {
            *reason = i;
            return true;
        }
    }
    return false;
}

/* Returns a newly allocated NXT_RESUME message for 'pin', with the given
 * 'continuation', for 'protocol'.  This message is suitable for resuming the
 * pipeline traveral of the packet represented by 'pin', if sent to the switch
 * from which 'pin' was received. */
struct ofpbuf *
ofputil_encode_resume(const struct ofputil_packet_in *pin,
                      const struct ofpbuf *continuation,
                      enum ofputil_protocol protocol)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);
    size_t extra = pin->packet_len + NXM_TYPICAL_LEN + continuation->size;
    struct ofpbuf *msg = ofpraw_alloc_xid(OFPRAW_NXT_RESUME, version,
                                          0, extra);
    ofputil_put_packet_in(pin, version, pin->packet_len, msg);
    ofpprop_put_nested(msg, NXPINT_CONTINUATION, continuation);
    ofpmsg_update_length(msg);
    return msg;
}

static enum ofperr
parse_stack_prop(const struct ofpbuf *property, struct ofpbuf *stack)
{
    unsigned int len = ofpbuf_msgsize(property);
    if (len > sizeof(union mf_subvalue)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "NXCPT_STACK property has bad length %u",
                     len);
        return OFPERR_OFPBPC_BAD_LEN;
    }
    nx_stack_push_bottom(stack, property->msg, len);
    return 0;
}

static enum ofperr
parse_actions_property(struct ofpbuf *property, enum ofp_version version,
                       struct ofpbuf *ofpacts)
{
    if (!ofpbuf_try_pull(property, ROUND_UP(ofpbuf_headersize(property), 8))) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "actions property has bad length %"PRIu32,
                     property->size);
        return OFPERR_OFPBPC_BAD_LEN;
    }

    return ofpacts_pull_openflow_actions(property, property->size,
                                         version, NULL, NULL, ofpacts);
}

/* This is like ofputil_decode_packet_in(), except that it decodes the
 * continuation data into 'pin'.  The format of this data is supposed to be
 * opaque to any process other than ovs-vswitchd, so this function should not
 * be used outside ovs-vswitchd.
 *
 * 'vl_mff_map' is an optional parameter that is used to validate the length
 * of variable length mf_fields in 'match'. If it is not provided, the
 * default mf_fields with maximum length will be used.
 *
 * When successful, 'pin' contains some dynamically allocated data.  Call
 * ofputil_packet_in_private_destroy() to free this data. */
enum ofperr
ofputil_decode_packet_in_private(const struct ofp_header *oh, bool loose,
                                 const struct tun_table *tun_table,
                                 const struct vl_mff_map *vl_mff_map,
                                 struct ofputil_packet_in_private *pin,
                                 size_t *total_len, uint32_t *buffer_id)
{
    memset(pin, 0, sizeof *pin);

    struct ofpbuf continuation;
    enum ofperr error;
    error = ofputil_decode_packet_in(oh, loose, tun_table, vl_mff_map,
                                     &pin->base, total_len, buffer_id,
                                     &continuation);
    if (error) {
        return error;
    }

    struct ofpbuf actions, action_set;
    ofpbuf_init(&actions, 0);
    ofpbuf_init(&action_set, 0);

    uint8_t table_id = 0;
    ovs_be64 cookie = 0;

    struct ofpbuf stack;
    ofpbuf_init(&stack, 0);

    while (continuation.size > 0) {
        struct ofpbuf payload;
        uint64_t type;

        error = ofpprop_pull(&continuation, &payload, &type);
        if (error) {
            break;
        }

        switch (type) {
        case NXCPT_BRIDGE:
            error = ofpprop_parse_uuid(&payload, &pin->bridge);
            break;

        case NXCPT_STACK:
            error = parse_stack_prop(&payload, &stack);
            break;

        case NXCPT_MIRRORS:
            error = ofpprop_parse_u32(&payload, &pin->mirrors);
            break;

        case NXCPT_CONNTRACKED:
            pin->conntracked = true;
            break;

        case NXCPT_TABLE_ID:
            error = ofpprop_parse_u8(&payload, &table_id);
            break;

        case NXCPT_COOKIE:
            error = ofpprop_parse_be64(&payload, &cookie);
            break;

        case NXCPT_ACTIONS: {
            struct ofpact_unroll_xlate *unroll
                = ofpact_put_UNROLL_XLATE(&actions);
            unroll->rule_table_id = table_id;
            unroll->rule_cookie = cookie;
            error = parse_actions_property(&payload, oh->version, &actions);
            break;
        }

        case NXCPT_ACTION_SET:
            error = parse_actions_property(&payload, oh->version, &action_set);
            break;

        default:
            error = OFPPROP_UNKNOWN(loose, "continuation", type);
            break;
        }
        if (error) {
            break;
        }
    }

    pin->actions_len = actions.size;
    pin->actions = ofpbuf_steal_data(&actions);
    pin->action_set_len = action_set.size;
    pin->action_set = ofpbuf_steal_data(&action_set);
    pin->stack_size = stack.size;
    pin->stack = ofpbuf_steal_data(&stack);

    if (error) {
        ofputil_packet_in_private_destroy(pin);
    }

    return error;
}

/* Frees data in 'pin' that is dynamically allocated by
 * ofputil_decode_packet_in_private().
 *
 * 'pin->base' contains some pointer members that
 * ofputil_decode_packet_in_private() doesn't initialize to newly allocated
 * data, so this function doesn't free those. */
void
ofputil_packet_in_private_destroy(struct ofputil_packet_in_private *pin)
{
    if (pin) {
        free(pin->stack);
        free(pin->actions);
        free(pin->action_set);
    }
}

/* Converts an OFPT_PACKET_OUT in 'opo' into an abstract ofputil_packet_out in
 * 'po'.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of the packet out
 * message's actions.  The caller must initialize 'ofpacts' and retains
 * ownership of it.  'po->ofpacts' will point into the 'ofpacts' buffer.
 *
 * 'po->packet' refers to the packet data in 'oh', so the buffer containing
 * 'oh' must not be destroyed while 'po' is being used.
 *
 * Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_packet_out(struct ofputil_packet_out *po,
                          const struct ofp_header *oh,
                          const struct tun_table *tun_table,
                          struct ofpbuf *ofpacts)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);

    ofpbuf_clear(ofpacts);
    match_init_catchall(&po->flow_metadata);
    if (raw == OFPRAW_OFPT15_PACKET_OUT) {
        enum ofperr error;
        const struct ofp15_packet_out *opo = ofpbuf_pull(&b, sizeof *opo);

        po->buffer_id = ntohl(opo->buffer_id);
        error = oxm_pull_match_loose(&b, true, tun_table, &po->flow_metadata);
        if (error) {
            return error;
        }

        if (!po->flow_metadata.wc.masks.in_port.ofp_port) {
            return OFPERR_OFPBRC_BAD_PORT;
        }

        error = ofpacts_pull_openflow_actions(&b, ntohs(opo->actions_len),
                                              oh->version, NULL, NULL,
                                              ofpacts);
        if (error) {
            return error;
        }
    } else if (raw == OFPRAW_OFPT11_PACKET_OUT) {
        enum ofperr error;
        ofp_port_t in_port;
        const struct ofp11_packet_out *opo = ofpbuf_pull(&b, sizeof *opo);

        po->buffer_id = ntohl(opo->buffer_id);
        error = ofputil_port_from_ofp11(opo->in_port, &in_port);
        if (error) {
            return error;
        }
        match_set_packet_type(&po->flow_metadata, htonl(PT_ETH));
        match_set_in_port(&po->flow_metadata, in_port);

        error = ofpacts_pull_openflow_actions(&b, ntohs(opo->actions_len),
                                              oh->version, NULL, NULL,
                                              ofpacts);
        if (error) {
            return error;
        }
    } else if (raw == OFPRAW_OFPT10_PACKET_OUT) {
        enum ofperr error;
        const struct ofp10_packet_out *opo = ofpbuf_pull(&b, sizeof *opo);

        po->buffer_id = ntohl(opo->buffer_id);
        match_set_packet_type(&po->flow_metadata, htonl(PT_ETH));
        match_set_in_port(&po->flow_metadata, u16_to_ofp(ntohs(opo->in_port)));

        error = ofpacts_pull_openflow_actions(&b, ntohs(opo->actions_len),
                                              oh->version, NULL, NULL,
                                              ofpacts);
        if (error) {
            return error;
        }
    } else {
        OVS_NOT_REACHED();
    }

    ofp_port_t in_port = po->flow_metadata.flow.in_port.ofp_port;
    if (ofp_to_u16(in_port) >= ofp_to_u16(OFPP_MAX)
        && in_port != OFPP_LOCAL
        && in_port != OFPP_NONE
        && in_port != OFPP_CONTROLLER) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "packet-out has bad input port %#"PRIx32,
                     po->flow_metadata.flow.in_port.ofp_port);
        return OFPERR_OFPBRC_BAD_PORT;
    }

    po->ofpacts = ofpacts->data;
    po->ofpacts_len = ofpacts->size;

    if (po->buffer_id == UINT32_MAX) {
        po->packet = b.data;
        po->packet_len = b.size;
    } else {
        po->packet = NULL;
        po->packet_len = 0;
    }

    return 0;
}

/* ofputil_phy_port */

/* NETDEV_F_* to and from OFPPF_* and OFPPF10_*. */
BUILD_ASSERT_DECL((int) NETDEV_F_10MB_HD    == OFPPF_10MB_HD);  /* bit 0 */
BUILD_ASSERT_DECL((int) NETDEV_F_10MB_FD    == OFPPF_10MB_FD);  /* bit 1 */
BUILD_ASSERT_DECL((int) NETDEV_F_100MB_HD   == OFPPF_100MB_HD); /* bit 2 */
BUILD_ASSERT_DECL((int) NETDEV_F_100MB_FD   == OFPPF_100MB_FD); /* bit 3 */
BUILD_ASSERT_DECL((int) NETDEV_F_1GB_HD     == OFPPF_1GB_HD);   /* bit 4 */
BUILD_ASSERT_DECL((int) NETDEV_F_1GB_FD     == OFPPF_1GB_FD);   /* bit 5 */
BUILD_ASSERT_DECL((int) NETDEV_F_10GB_FD    == OFPPF_10GB_FD);  /* bit 6 */

/* NETDEV_F_ bits 11...15 are OFPPF10_ bits 7...11: */
BUILD_ASSERT_DECL((int) NETDEV_F_COPPER == (OFPPF10_COPPER << 4));
BUILD_ASSERT_DECL((int) NETDEV_F_FIBER == (OFPPF10_FIBER << 4));
BUILD_ASSERT_DECL((int) NETDEV_F_AUTONEG == (OFPPF10_AUTONEG << 4));
BUILD_ASSERT_DECL((int) NETDEV_F_PAUSE == (OFPPF10_PAUSE << 4));
BUILD_ASSERT_DECL((int) NETDEV_F_PAUSE_ASYM == (OFPPF10_PAUSE_ASYM << 4));

static enum netdev_features
netdev_port_features_from_ofp10(ovs_be32 ofp10_)
{
    uint32_t ofp10 = ntohl(ofp10_);
    return (ofp10 & 0x7f) | ((ofp10 & 0xf80) << 4);
}

static ovs_be32
netdev_port_features_to_ofp10(enum netdev_features features)
{
    return htonl((features & 0x7f) | ((features & 0xf800) >> 4));
}

BUILD_ASSERT_DECL((int) NETDEV_F_10MB_HD    == OFPPF_10MB_HD);     /* bit 0 */
BUILD_ASSERT_DECL((int) NETDEV_F_10MB_FD    == OFPPF_10MB_FD);     /* bit 1 */
BUILD_ASSERT_DECL((int) NETDEV_F_100MB_HD   == OFPPF_100MB_HD);    /* bit 2 */
BUILD_ASSERT_DECL((int) NETDEV_F_100MB_FD   == OFPPF_100MB_FD);    /* bit 3 */
BUILD_ASSERT_DECL((int) NETDEV_F_1GB_HD     == OFPPF_1GB_HD);      /* bit 4 */
BUILD_ASSERT_DECL((int) NETDEV_F_1GB_FD     == OFPPF_1GB_FD);      /* bit 5 */
BUILD_ASSERT_DECL((int) NETDEV_F_10GB_FD    == OFPPF_10GB_FD);     /* bit 6 */
BUILD_ASSERT_DECL((int) NETDEV_F_40GB_FD    == OFPPF11_40GB_FD);   /* bit 7 */
BUILD_ASSERT_DECL((int) NETDEV_F_100GB_FD   == OFPPF11_100GB_FD);  /* bit 8 */
BUILD_ASSERT_DECL((int) NETDEV_F_1TB_FD     == OFPPF11_1TB_FD);    /* bit 9 */
BUILD_ASSERT_DECL((int) NETDEV_F_OTHER      == OFPPF11_OTHER);     /* bit 10 */
BUILD_ASSERT_DECL((int) NETDEV_F_COPPER     == OFPPF11_COPPER);    /* bit 11 */
BUILD_ASSERT_DECL((int) NETDEV_F_FIBER      == OFPPF11_FIBER);     /* bit 12 */
BUILD_ASSERT_DECL((int) NETDEV_F_AUTONEG    == OFPPF11_AUTONEG);   /* bit 13 */
BUILD_ASSERT_DECL((int) NETDEV_F_PAUSE      == OFPPF11_PAUSE);     /* bit 14 */
BUILD_ASSERT_DECL((int) NETDEV_F_PAUSE_ASYM == OFPPF11_PAUSE_ASYM);/* bit 15 */

static enum netdev_features
netdev_port_features_from_ofp11(ovs_be32 ofp11)
{
    return ntohl(ofp11) & 0xffff;
}

static ovs_be32
netdev_port_features_to_ofp11(enum netdev_features features)
{
    return htonl(features & 0xffff);
}

static enum ofperr
ofputil_decode_ofp10_phy_port(struct ofputil_phy_port *pp,
                              const struct ofp10_phy_port *opp)
{
    pp->port_no = u16_to_ofp(ntohs(opp->port_no));
    pp->hw_addr = opp->hw_addr;
    ovs_strlcpy_arrays(pp->name, opp->name);

    pp->config = ntohl(opp->config) & OFPPC10_ALL;
    pp->state = ntohl(opp->state) & OFPPS10_ALL;

    pp->curr = netdev_port_features_from_ofp10(opp->curr);
    pp->advertised = netdev_port_features_from_ofp10(opp->advertised);
    pp->supported = netdev_port_features_from_ofp10(opp->supported);
    pp->peer = netdev_port_features_from_ofp10(opp->peer);

    pp->curr_speed = netdev_features_to_bps(pp->curr, 0) / 1000;
    pp->max_speed = netdev_features_to_bps(pp->supported, 0) / 1000;

    return 0;
}

static enum ofperr
ofputil_decode_ofp11_port(struct ofputil_phy_port *pp,
                          const struct ofp11_port *op)
{
    enum ofperr error;

    error = ofputil_port_from_ofp11(op->port_no, &pp->port_no);
    if (error) {
        return error;
    }
    pp->hw_addr = op->hw_addr;
    ovs_strlcpy_arrays(pp->name, op->name);

    pp->config = ntohl(op->config) & OFPPC11_ALL;
    pp->state = ntohl(op->state) & OFPPS11_ALL;

    pp->curr = netdev_port_features_from_ofp11(op->curr);
    pp->advertised = netdev_port_features_from_ofp11(op->advertised);
    pp->supported = netdev_port_features_from_ofp11(op->supported);
    pp->peer = netdev_port_features_from_ofp11(op->peer);

    pp->curr_speed = ntohl(op->curr_speed);
    pp->max_speed = ntohl(op->max_speed);

    return 0;
}

static enum ofperr
parse_ofp14_port_ethernet_property(const struct ofpbuf *payload,
                                   struct ofputil_phy_port *pp)
{
    struct ofp14_port_desc_prop_ethernet *eth = payload->data;

    if (payload->size != sizeof *eth) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    pp->curr = netdev_port_features_from_ofp11(eth->curr);
    pp->advertised = netdev_port_features_from_ofp11(eth->advertised);
    pp->supported = netdev_port_features_from_ofp11(eth->supported);
    pp->peer = netdev_port_features_from_ofp11(eth->peer);

    pp->curr_speed = ntohl(eth->curr_speed);
    pp->max_speed = ntohl(eth->max_speed);

    return 0;
}

static enum ofperr
ofputil_pull_ofp14_port_properties(const void *props, size_t len,
                                   struct ofputil_phy_port *pp)
{
    struct ofpbuf properties = ofpbuf_const_initializer(props, len);
    while (properties.size > 0) {
        struct ofpbuf payload;
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPPDPT14_ETHERNET:
            error = parse_ofp14_port_ethernet_property(&payload, pp);
            break;

        default:
            error = OFPPROP_UNKNOWN(true, "port", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

static enum ofperr
ofputil_pull_ofp14_port(struct ofputil_phy_port *pp, struct ofpbuf *msg)
{
    const struct ofp14_port *op = ofpbuf_try_pull(msg, sizeof *op);
    if (!op) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    size_t len = ntohs(op->length);
    if (len < sizeof *op || len - sizeof *op > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= sizeof *op;

    enum ofperr error = ofputil_port_from_ofp11(op->port_no, &pp->port_no);
    if (error) {
        return error;
    }
    pp->hw_addr = op->hw_addr;
    ovs_strlcpy_arrays(pp->name, op->name);

    pp->config = ntohl(op->config) & OFPPC11_ALL;
    pp->state = ntohl(op->state) & OFPPS11_ALL;

    return ofputil_pull_ofp14_port_properties(ofpbuf_pull(msg, len), len, pp);
}

static enum ofperr
ofputil_pull_ofp16_port(struct ofputil_phy_port *pp, struct ofpbuf *msg)
{
    const struct ofp16_port *op = ofpbuf_try_pull(msg, sizeof *op);
    if (!op) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    size_t len = ntohs(op->length);
    if (len < sizeof *op || len - sizeof *op > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= sizeof *op;

    enum ofperr error = ofputil_port_from_ofp11(op->port_no, &pp->port_no);
    if (error) {
        return error;
    }
    pp->hw_addr = op->hw_addr;
    pp->hw_addr64 = op->hw_addr64;
    ovs_strlcpy_arrays(pp->name, op->name);

    pp->config = ntohl(op->config) & OFPPC11_ALL;
    pp->state = ntohl(op->state) & OFPPS11_ALL;

    return ofputil_pull_ofp14_port_properties(ofpbuf_pull(msg, len), len, pp);
}

static void
ofputil_encode_ofp10_phy_port(const struct ofputil_phy_port *pp,
                              struct ofp10_phy_port *opp)
{
    memset(opp, 0, sizeof *opp);

    opp->port_no = htons(ofp_to_u16(pp->port_no));
    opp->hw_addr = pp->hw_addr;
    ovs_strlcpy_arrays(opp->name, pp->name);

    opp->config = htonl(pp->config & OFPPC10_ALL);
    opp->state = htonl(pp->state & OFPPS10_ALL);

    opp->curr = netdev_port_features_to_ofp10(pp->curr);
    opp->advertised = netdev_port_features_to_ofp10(pp->advertised);
    opp->supported = netdev_port_features_to_ofp10(pp->supported);
    opp->peer = netdev_port_features_to_ofp10(pp->peer);
}

static void
ofputil_encode_ofp11_port(const struct ofputil_phy_port *pp,
                          struct ofp11_port *op)
{
    memset(op, 0, sizeof *op);

    op->port_no = ofputil_port_to_ofp11(pp->port_no);
    op->hw_addr = pp->hw_addr;
    ovs_strlcpy_arrays(op->name, pp->name);

    op->config = htonl(pp->config & OFPPC11_ALL);
    op->state = htonl(pp->state & OFPPS11_ALL);

    op->curr = netdev_port_features_to_ofp11(pp->curr);
    op->advertised = netdev_port_features_to_ofp11(pp->advertised);
    op->supported = netdev_port_features_to_ofp11(pp->supported);
    op->peer = netdev_port_features_to_ofp11(pp->peer);

    op->curr_speed = htonl(pp->curr_speed);
    op->max_speed = htonl(pp->max_speed);
}

static void
ofputil_encode_ofp14_port_ethernet_prop(
    const struct ofputil_phy_port *pp,
    struct ofp14_port_desc_prop_ethernet *eth)
{
    eth->curr = netdev_port_features_to_ofp11(pp->curr);
    eth->advertised = netdev_port_features_to_ofp11(pp->advertised);
    eth->supported = netdev_port_features_to_ofp11(pp->supported);
    eth->peer = netdev_port_features_to_ofp11(pp->peer);
    eth->curr_speed = htonl(pp->curr_speed);
    eth->max_speed = htonl(pp->max_speed);
}

static void
ofputil_put_ofp14_port(const struct ofputil_phy_port *pp, struct ofpbuf *b)
{
    struct ofp14_port *op;
    struct ofp14_port_desc_prop_ethernet *eth;

    ofpbuf_prealloc_tailroom(b, sizeof *op + sizeof *eth);

    op = ofpbuf_put_zeros(b, sizeof *op);
    op->port_no = ofputil_port_to_ofp11(pp->port_no);
    op->length = htons(sizeof *op + sizeof *eth);
    op->hw_addr = pp->hw_addr;
    ovs_strlcpy_arrays(op->name, pp->name);
    op->config = htonl(pp->config & OFPPC11_ALL);
    op->state = htonl(pp->state & OFPPS11_ALL);

    eth = ofpprop_put_zeros(b, OFPPDPT14_ETHERNET, sizeof *eth);
    ofputil_encode_ofp14_port_ethernet_prop(pp, eth);
}

static void
ofputil_put_ofp16_port(const struct ofputil_phy_port *pp, struct ofpbuf *b)
{
    struct ofp16_port *op;
    struct ofp14_port_desc_prop_ethernet *eth;

    ofpbuf_prealloc_tailroom(b, sizeof *op + sizeof *eth);

    op = ofpbuf_put_zeros(b, sizeof *op);
    op->port_no = ofputil_port_to_ofp11(pp->port_no);
    op->length = htons(sizeof *op + sizeof *eth);
    op->hw_addr = pp->hw_addr;
    op->hw_addr64 = pp->hw_addr64;
    ovs_strlcpy_arrays(op->name, pp->name);
    op->config = htonl(pp->config & OFPPC11_ALL);
    op->state = htonl(pp->state & OFPPS11_ALL);

    eth = ofpprop_put_zeros(b, OFPPDPT14_ETHERNET, sizeof *eth);
    ofputil_encode_ofp14_port_ethernet_prop(pp, eth);
}

static void
ofputil_put_phy_port(enum ofp_version ofp_version,
                     const struct ofputil_phy_port *pp, struct ofpbuf *b)
{
    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_phy_port *opp = ofpbuf_put_uninit(b, sizeof *opp);
        ofputil_encode_ofp10_phy_port(pp, opp);
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_port *op = ofpbuf_put_uninit(b, sizeof *op);
        ofputil_encode_ofp11_port(pp, op);
        break;
    }

    case OFP14_VERSION:
    case OFP15_VERSION:
        ofputil_put_ofp14_port(pp, b);
        break;
    case OFP16_VERSION:
        ofputil_put_ofp16_port(pp, b);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

enum ofperr
ofputil_decode_port_desc_stats_request(const struct ofp_header *request,
                                       ofp_port_t *port)
{
    struct ofpbuf b = ofpbuf_const_initializer(request,
                                               ntohs(request->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPST10_PORT_DESC_REQUEST) {
        *port = OFPP_ANY;
        return 0;
    } else if (raw == OFPRAW_OFPST15_PORT_DESC_REQUEST) {
        ovs_be32 *ofp11_port;

        ofp11_port = ofpbuf_pull(&b, sizeof *ofp11_port);
        return ofputil_port_from_ofp11(*ofp11_port, port);
    } else {
        OVS_NOT_REACHED();
    }
}

struct ofpbuf *
ofputil_encode_port_desc_stats_request(enum ofp_version ofp_version,
                                       ofp_port_t port)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        request = ofpraw_alloc(OFPRAW_OFPST10_PORT_DESC_REQUEST,
                               ofp_version, 0);
        break;
    case OFP15_VERSION:
    case OFP16_VERSION:{
        struct ofp15_port_desc_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST15_PORT_DESC_REQUEST,
                               ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->port_no = ofputil_port_to_ofp11(port);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

void
ofputil_append_port_desc_stats_reply(const struct ofputil_phy_port *pp,
                                     struct ovs_list *replies)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_ofs = reply->size;

    ofputil_put_phy_port(ofpmp_version(replies), pp, reply);
    ofpmp_postappend(replies, start_ofs);
}

/* ofputil_switch_config */

/* Decodes 'oh', which must be an OFPT_GET_CONFIG_REPLY or OFPT_SET_CONFIG
 * message, into 'config'.  Returns false if 'oh' contained any flags that
 * aren't specified in its version of OpenFlow, true otherwise. */
static bool
ofputil_decode_switch_config(const struct ofp_header *oh,
                             struct ofputil_switch_config *config)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    const struct ofp_switch_config *osc = ofpbuf_pull(&b, sizeof *osc);
    config->frag = ntohs(osc->flags) & OFPC_FRAG_MASK;
    config->miss_send_len = ntohs(osc->miss_send_len);

    ovs_be16 valid_mask = htons(OFPC_FRAG_MASK);
    if (oh->version < OFP13_VERSION) {
        const ovs_be16 ttl_bit = htons(OFPC_INVALID_TTL_TO_CONTROLLER);
        valid_mask |= ttl_bit;
        config->invalid_ttl_to_controller = (osc->flags & ttl_bit) != 0;
    } else {
        config->invalid_ttl_to_controller = -1;
    }

    return !(osc->flags & ~valid_mask);
}

void
ofputil_decode_get_config_reply(const struct ofp_header *oh,
                                struct ofputil_switch_config *config)
{
    ofputil_decode_switch_config(oh, config);
}

enum ofperr
ofputil_decode_set_config(const struct ofp_header *oh,
                          struct ofputil_switch_config *config)
{
    return (ofputil_decode_switch_config(oh, config)
            ? 0
            : OFPERR_OFPSCFC_BAD_FLAGS);
}

static struct ofpbuf *
ofputil_put_switch_config(const struct ofputil_switch_config *config,
                          struct ofpbuf *b)
{
    const struct ofp_header *oh = b->data;
    struct ofp_switch_config *osc = ofpbuf_put_zeros(b, sizeof *osc);
    osc->flags = htons(config->frag);
    if (config->invalid_ttl_to_controller > 0 && oh->version < OFP13_VERSION) {
        osc->flags |= htons(OFPC_INVALID_TTL_TO_CONTROLLER);
    }
    osc->miss_send_len = htons(config->miss_send_len);
    return b;
}

struct ofpbuf *
ofputil_encode_get_config_reply(const struct ofp_header *request,
                                const struct ofputil_switch_config *config)
{
    struct ofpbuf *b = ofpraw_alloc_reply(OFPRAW_OFPT_GET_CONFIG_REPLY,
                                          request, 0);
    return ofputil_put_switch_config(config, b);
}

struct ofpbuf *
ofputil_encode_set_config(const struct ofputil_switch_config *config,
                          enum ofp_version version)
{
    struct ofpbuf *b = ofpraw_alloc(OFPRAW_OFPT_SET_CONFIG, version, 0);
    return ofputil_put_switch_config(config, b);
}

/* ofputil_switch_features */

#define OFPC_COMMON (OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS | \
                     OFPC_IP_REASM | OFPC_QUEUE_STATS)
BUILD_ASSERT_DECL((int) OFPUTIL_C_FLOW_STATS == OFPC_FLOW_STATS);
BUILD_ASSERT_DECL((int) OFPUTIL_C_TABLE_STATS == OFPC_TABLE_STATS);
BUILD_ASSERT_DECL((int) OFPUTIL_C_PORT_STATS == OFPC_PORT_STATS);
BUILD_ASSERT_DECL((int) OFPUTIL_C_IP_REASM == OFPC_IP_REASM);
BUILD_ASSERT_DECL((int) OFPUTIL_C_QUEUE_STATS == OFPC_QUEUE_STATS);
BUILD_ASSERT_DECL((int) OFPUTIL_C_ARP_MATCH_IP == OFPC_ARP_MATCH_IP);
BUILD_ASSERT_DECL((int) OFPUTIL_C_PORT_BLOCKED == OFPC12_PORT_BLOCKED);
BUILD_ASSERT_DECL((int) OFPUTIL_C_BUNDLES == OFPC14_BUNDLES);
BUILD_ASSERT_DECL((int) OFPUTIL_C_FLOW_MONITORING == OFPC14_FLOW_MONITORING);

static uint32_t
ofputil_capabilities_mask(enum ofp_version ofp_version)
{
    /* Handle capabilities whose bit is unique for all OpenFlow versions */
    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
        return OFPC_COMMON | OFPC_ARP_MATCH_IP;
    case OFP12_VERSION:
    case OFP13_VERSION:
        return OFPC_COMMON | OFPC12_PORT_BLOCKED;
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        return OFPC_COMMON | OFPC12_PORT_BLOCKED | OFPC14_BUNDLES
            | OFPC14_FLOW_MONITORING;
    default:
        /* Caller needs to check osf->header.version itself */
        return 0;
    }
}

/* Pulls an OpenFlow "switch_features" structure from 'b' and decodes it into
 * an abstract representation in '*features', readying 'b' to iterate over the
 * OpenFlow port structures following 'osf' with later calls to
 * ofputil_pull_phy_port().  Returns 0 if successful, otherwise an OFPERR_*
 * value.  */
enum ofperr
ofputil_pull_switch_features(struct ofpbuf *b,
                             struct ofputil_switch_features *features)
{
    const struct ofp_header *oh = b->data;
    enum ofpraw raw = ofpraw_pull_assert(b);
    const struct ofp_switch_features *osf = ofpbuf_pull(b, sizeof *osf);
    features->datapath_id = ntohll(osf->datapath_id);
    features->n_buffers = ntohl(osf->n_buffers);
    features->n_tables = osf->n_tables;
    features->auxiliary_id = 0;

    features->capabilities = ntohl(osf->capabilities) &
        ofputil_capabilities_mask(oh->version);

    if (raw == OFPRAW_OFPT10_FEATURES_REPLY) {
        if (osf->capabilities & htonl(OFPC10_STP)) {
            features->capabilities |= OFPUTIL_C_STP;
        }
        features->ofpacts = ofpact_bitmap_from_openflow(osf->actions,
                                                        OFP10_VERSION);
    } else if (raw == OFPRAW_OFPT11_FEATURES_REPLY
               || raw == OFPRAW_OFPT13_FEATURES_REPLY) {
        if (osf->capabilities & htonl(OFPC11_GROUP_STATS)) {
            features->capabilities |= OFPUTIL_C_GROUP_STATS;
        }
        features->ofpacts = 0;
        if (raw == OFPRAW_OFPT13_FEATURES_REPLY) {
            features->auxiliary_id = osf->auxiliary_id;
        }
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
    }

    return 0;
}

/* In OpenFlow 1.0, 1.1, and 1.2, an OFPT_FEATURES_REPLY message lists all the
 * switch's ports, unless there are too many to fit.  In OpenFlow 1.3 and
 * later, an OFPT_FEATURES_REPLY does not list ports at all.
 *
 * Given a buffer 'b' that contains a Features Reply message, this message
 * checks if it contains a complete list of the switch's ports.  Returns true,
 * if so.  Returns false if the list is missing (OF1.3+) or incomplete
 * (OF1.0/1.1/1.2), and in the latter case removes all of the ports from the
 * message.
 *
 * When this function returns false, the caller should send an OFPST_PORT_DESC
 * stats request to get the ports. */
bool
ofputil_switch_features_has_ports(struct ofpbuf *b)
{
    struct ofp_header *oh = b->data;
    size_t phy_port_size;

    if (oh->version >= OFP13_VERSION) {
        /* OpenFlow 1.3+ never has ports in the feature reply. */
        return false;
    }

    phy_port_size = (oh->version == OFP10_VERSION
                     ? sizeof(struct ofp10_phy_port)
                     : sizeof(struct ofp11_port));
    if (ntohs(oh->length) + phy_port_size <= UINT16_MAX) {
        /* There's room for additional ports in the feature reply.
         * Assume that the list is complete. */
        return true;
    }

    /* The feature reply has no room for more ports.  Probably the list is
     * truncated.  Drop the ports and tell the caller to retrieve them with
     * OFPST_PORT_DESC. */
    b->size = sizeof *oh + sizeof(struct ofp_switch_features);
    ofpmsg_update_length(b);
    return false;
}

/* Returns a buffer owned by the caller that encodes 'features' in the format
 * required by 'protocol' with the given 'xid'.  The caller should append port
 * information to the buffer with subsequent calls to
 * ofputil_put_switch_features_port(). */
struct ofpbuf *
ofputil_encode_switch_features(const struct ofputil_switch_features *features,
                               enum ofputil_protocol protocol, ovs_be32 xid)
{
    struct ofp_switch_features *osf;
    struct ofpbuf *b;
    enum ofp_version version;
    enum ofpraw raw;

    version = ofputil_protocol_to_ofp_version(protocol);
    switch (version) {
    case OFP10_VERSION:
        raw = OFPRAW_OFPT10_FEATURES_REPLY;
        break;
    case OFP11_VERSION:
    case OFP12_VERSION:
        raw = OFPRAW_OFPT11_FEATURES_REPLY;
        break;
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        raw = OFPRAW_OFPT13_FEATURES_REPLY;
        break;
    default:
        OVS_NOT_REACHED();
    }
    b = ofpraw_alloc_xid(raw, version, xid, 0);
    osf = ofpbuf_put_zeros(b, sizeof *osf);
    osf->datapath_id = htonll(features->datapath_id);
    osf->n_buffers = htonl(features->n_buffers);
    osf->n_tables = features->n_tables;

    osf->capabilities = htonl(features->capabilities &
                              ofputil_capabilities_mask(version));
    switch (version) {
    case OFP10_VERSION:
        if (features->capabilities & OFPUTIL_C_STP) {
            osf->capabilities |= htonl(OFPC10_STP);
        }
        osf->actions = ofpact_bitmap_to_openflow(features->ofpacts,
                                                 OFP10_VERSION);
        break;
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        osf->auxiliary_id = features->auxiliary_id;
        /* fall through */
    case OFP11_VERSION:
    case OFP12_VERSION:
        if (features->capabilities & OFPUTIL_C_GROUP_STATS) {
            osf->capabilities |= htonl(OFPC11_GROUP_STATS);
        }
        break;
    default:
        OVS_NOT_REACHED();
    }

    return b;
}

/* Encodes 'pp' into the format required by the switch_features message already
 * in 'b', which should have been returned by ofputil_encode_switch_features(),
 * and appends the encoded version to 'b'. */
void
ofputil_put_switch_features_port(const struct ofputil_phy_port *pp,
                                 struct ofpbuf *b)
{
    const struct ofp_header *oh = b->data;

    if (oh->version < OFP13_VERSION) {
        /* Try adding a port description to the message, but drop it again if
         * the buffer overflows.  (This possibility for overflow is why
         * OpenFlow 1.3+ moved port descriptions into a multipart message.)  */
        size_t start_ofs = b->size;
        ofputil_put_phy_port(oh->version, pp, b);
        if (b->size > UINT16_MAX) {
            b->size = start_ofs;
        }
    }
}

/* ofputil_port_status */

/* Decodes the OpenFlow "port status" message in '*ops' into an abstract form
 * in '*ps'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_port_status(const struct ofp_header *oh,
                           struct ofputil_port_status *ps)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    const struct ofp_port_status *ops = ofpbuf_pull(&b, sizeof *ops);
    if (ops->reason != OFPPR_ADD &&
        ops->reason != OFPPR_DELETE &&
        ops->reason != OFPPR_MODIFY) {
        return OFPERR_NXBRC_BAD_REASON;
    }
    ps->reason = ops->reason;

    int retval = ofputil_pull_phy_port(oh->version, &b, &ps->desc);
    ovs_assert(retval != EOF);
    return retval;
}

/* Converts the abstract form of a "port status" message in '*ps' into an
 * OpenFlow message suitable for 'protocol', and returns that encoded form in
 * a buffer owned by the caller. */
struct ofpbuf *
ofputil_encode_port_status(const struct ofputil_port_status *ps,
                           enum ofputil_protocol protocol)
{
    struct ofp_port_status *ops;
    struct ofpbuf *b;
    enum ofp_version version;
    enum ofpraw raw;

    version = ofputil_protocol_to_ofp_version(protocol);
    switch (version) {
    case OFP10_VERSION:
        raw = OFPRAW_OFPT10_PORT_STATUS;
        break;

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
        raw = OFPRAW_OFPT11_PORT_STATUS;
        break;

    case OFP14_VERSION:
    case OFP15_VERSION:
        raw = OFPRAW_OFPT14_PORT_STATUS;
        break;

    case OFP16_VERSION:
        raw = OFPRAW_OFPT16_PORT_STATUS;
        break;

    default:
        OVS_NOT_REACHED();
    }

    b = ofpraw_alloc_xid(raw, version, htonl(0), 0);
    ops = ofpbuf_put_zeros(b, sizeof *ops);
    ops->reason = ps->reason;
    ofputil_put_phy_port(version, &ps->desc, b);
    ofpmsg_update_length(b);
    return b;
}

/* ofputil_port_mod */

static enum ofperr
parse_port_mod_ethernet_property(struct ofpbuf *property,
                                 struct ofputil_port_mod *pm)
{
    ovs_be32 advertise;
    enum ofperr error;

    error = ofpprop_parse_be32(property, &advertise);
    if (!error) {
        pm->advertise = netdev_port_features_from_ofp11(advertise);
    }
    return error;
}

static enum ofperr
ofputil_decode_ofp10_port_mod(const struct ofp10_port_mod *opm,
                              struct ofputil_port_mod *pm)
{
    pm->port_no = u16_to_ofp(ntohs(opm->port_no));
    pm->hw_addr = opm->hw_addr;
    pm->config = ntohl(opm->config) & OFPPC10_ALL;
    pm->mask = ntohl(opm->mask) & OFPPC10_ALL;
    pm->advertise = netdev_port_features_from_ofp10(opm->advertise);
    return 0;
}

static enum ofperr
ofputil_decode_ofp11_port_mod(const struct ofp11_port_mod *opm,
                              struct ofputil_port_mod *pm)
{
    enum ofperr error;

    error = ofputil_port_from_ofp11(opm->port_no, &pm->port_no);
    if (error) {
        return error;
    }

    pm->hw_addr = opm->hw_addr;
    pm->config = ntohl(opm->config) & OFPPC11_ALL;
    pm->mask = ntohl(opm->mask) & OFPPC11_ALL;
    pm->advertise = netdev_port_features_from_ofp11(opm->advertise);

    return 0;
}

static enum ofperr
ofputil_decode_ofp14_port_mod_properties(struct ofpbuf *b, bool loose,
                                         struct ofputil_port_mod *pm)
{
    while (b->size > 0) {
        struct ofpbuf property;
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull(b, &property, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPPMPT14_ETHERNET:
            error = parse_port_mod_ethernet_property(&property, pm);
            break;

        default:
            error = OFPPROP_UNKNOWN(loose, "port_mod", type);
            break;
        }

        if (error) {
            return error;
        }
    }
    return 0;
}

static enum ofperr
ofputil_decode_ofp14_port_mod(struct ofpbuf *b, bool loose,
                              struct ofputil_port_mod *pm)
{
    const struct ofp14_port_mod *opm = ofpbuf_pull(b, sizeof *opm);
    enum ofperr error = ofputil_port_from_ofp11(opm->port_no, &pm->port_no);
    if (error) {
        return error;
    }

    pm->hw_addr = opm->hw_addr;
    pm->config = ntohl(opm->config) & OFPPC11_ALL;
    pm->mask = ntohl(opm->mask) & OFPPC11_ALL;

    return ofputil_decode_ofp14_port_mod_properties(b, loose, pm);
}

static enum ofperr
ofputil_decode_ofp16_port_mod(struct ofpbuf *b, bool loose,
                              struct ofputil_port_mod *pm)
{
    const struct ofp16_port_mod *opm = ofpbuf_pull(b, sizeof *opm);
    enum ofperr error = ofputil_port_from_ofp11(opm->port_no, &pm->port_no);
    if (error) {
        return error;
    }

    pm->hw_addr = opm->hw_addr;
    pm->hw_addr64 = opm->hw_addr64;
    pm->config = ntohl(opm->config) & OFPPC11_ALL;
    pm->mask = ntohl(opm->mask) & OFPPC11_ALL;

    return ofputil_decode_ofp14_port_mod_properties(b, loose, pm);
}

/* Decodes the OpenFlow "port mod" message in '*oh' into an abstract form in
 * '*pm'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_port_mod(const struct ofp_header *oh,
                        struct ofputil_port_mod *pm, bool loose)
{
    memset(pm, 0, sizeof *pm);

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);

    enum ofperr error;
    if (raw == OFPRAW_OFPT10_PORT_MOD) {
        error = ofputil_decode_ofp10_port_mod(b.data, pm);
    } else if (raw == OFPRAW_OFPT11_PORT_MOD) {
        error = ofputil_decode_ofp11_port_mod(b.data, pm);
    } else if (raw == OFPRAW_OFPT14_PORT_MOD) {
        error = ofputil_decode_ofp14_port_mod(&b, loose, pm);
    } else if (raw == OFPRAW_OFPT16_PORT_MOD) {
        error = ofputil_decode_ofp16_port_mod(&b, loose, pm);
    } else {
        error = OFPERR_OFPBRC_BAD_TYPE;
    }

    pm->config &= pm->mask;
    return error;
}

/* Converts the abstract form of a "port mod" message in '*pm' into an OpenFlow
 * message suitable for 'protocol', and returns that encoded form in a buffer
 * owned by the caller. */
struct ofpbuf *
ofputil_encode_port_mod(const struct ofputil_port_mod *pm,
                        enum ofputil_protocol protocol)
{
    enum ofp_version ofp_version = ofputil_protocol_to_ofp_version(protocol);
    struct ofpbuf *b;

    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_port_mod *opm;

        b = ofpraw_alloc(OFPRAW_OFPT10_PORT_MOD, ofp_version, 0);
        opm = ofpbuf_put_zeros(b, sizeof *opm);
        opm->port_no = htons(ofp_to_u16(pm->port_no));
        opm->hw_addr = pm->hw_addr;
        opm->config = htonl(pm->config & OFPPC10_ALL);
        opm->mask = htonl(pm->mask & OFPPC10_ALL);
        opm->advertise = netdev_port_features_to_ofp10(pm->advertise);
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_port_mod *opm;

        b = ofpraw_alloc(OFPRAW_OFPT11_PORT_MOD, ofp_version, 0);
        opm = ofpbuf_put_zeros(b, sizeof *opm);
        opm->port_no = ofputil_port_to_ofp11(pm->port_no);
        opm->hw_addr = pm->hw_addr;
        opm->config = htonl(pm->config & OFPPC11_ALL);
        opm->mask = htonl(pm->mask & OFPPC11_ALL);
        opm->advertise = netdev_port_features_to_ofp11(pm->advertise);
        break;
    }
    case OFP14_VERSION:
    case OFP15_VERSION: {
        struct ofp14_port_mod *opm;

        b = ofpraw_alloc(OFPRAW_OFPT14_PORT_MOD, ofp_version, 0);
        opm = ofpbuf_put_zeros(b, sizeof *opm);
        opm->port_no = ofputil_port_to_ofp11(pm->port_no);
        opm->hw_addr = pm->hw_addr;
        opm->config = htonl(pm->config & OFPPC11_ALL);
        opm->mask = htonl(pm->mask & OFPPC11_ALL);

        if (pm->advertise) {
            ofpprop_put_be32(b, OFPPMPT14_ETHERNET,
                             netdev_port_features_to_ofp11(pm->advertise));
        }
        break;
    }
    case OFP16_VERSION: {
        struct ofp16_port_mod *opm;

        b = ofpraw_alloc(OFPRAW_OFPT16_PORT_MOD, ofp_version, 0);
        opm = ofpbuf_put_zeros(b, sizeof *opm);
        opm->port_no = ofputil_port_to_ofp11(pm->port_no);
        opm->hw_addr = pm->hw_addr;
        opm->hw_addr64 = pm->hw_addr64;
        opm->config = htonl(pm->config & OFPPC11_ALL);
        opm->mask = htonl(pm->mask & OFPPC11_ALL);

        if (pm->advertise) {
            ofpprop_put_be32(b, OFPPMPT14_ETHERNET,
                             netdev_port_features_to_ofp11(pm->advertise));
        }
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return b;
}

/* Table features. */

static enum ofperr
pull_table_feature_property(struct ofpbuf *msg, struct ofpbuf *payload,
                            uint64_t *typep)
{
    enum ofperr error;

    error = ofpprop_pull(msg, payload, typep);
    if (payload && !error) {
        ofpbuf_pull(payload, (char *)payload->msg - (char *)payload->header);
    }
    return error;
}

static enum ofperr
parse_action_bitmap(struct ofpbuf *payload, enum ofp_version ofp_version,
                    uint64_t *ofpacts)
{
    uint32_t types = 0;

    while (payload->size > 0) {
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull__(payload, NULL, 1, 0x10000, &type);
        if (error) {
            return error;
        }
        if (type < CHAR_BIT * sizeof types) {
            types |= 1u << type;
        }
    }

    *ofpacts = ofpact_bitmap_from_openflow(htonl(types), ofp_version);
    return 0;
}

static enum ofperr
parse_instruction_ids(struct ofpbuf *payload, bool loose, uint32_t *insts)
{
    *insts = 0;
    while (payload->size > 0) {
        enum ovs_instruction_type inst;
        enum ofperr error;
        uint64_t ofpit;

        /* OF1.3 and OF1.4 aren't clear about padding in the instruction IDs.
         * It seems clear that they aren't padded to 8 bytes, though, because
         * both standards say that "non-experimenter instructions are 4 bytes"
         * and do not mention any padding before the first instruction ID.
         * (There wouldn't be any point in padding to 8 bytes if the IDs were
         * aligned on an odd 4-byte boundary.)
         *
         * Anyway, we just assume they're all glommed together on byte
         * boundaries. */
        error = ofpprop_pull__(payload, NULL, 1, 0x10000, &ofpit);
        if (error) {
            return error;
        }

        error = ovs_instruction_type_from_inst_type(&inst, ofpit);
        if (!error) {
            *insts |= 1u << inst;
        } else if (!loose) {
            return error;
        }
    }
    return 0;
}

static enum ofperr
parse_table_features_next_table(struct ofpbuf *payload,
                                unsigned long int *next_tables)
{
    size_t i;

    memset(next_tables, 0, bitmap_n_bytes(255));
    for (i = 0; i < payload->size; i++) {
        uint8_t id = ((const uint8_t *) payload->data)[i];
        if (id >= 255) {
            return OFPERR_OFPBPC_BAD_VALUE;
        }
        bitmap_set1(next_tables, id);
    }
    return 0;
}

static enum ofperr
parse_oxms(struct ofpbuf *payload, bool loose,
           struct mf_bitmap *exactp, struct mf_bitmap *maskedp)
{
    struct mf_bitmap exact = MF_BITMAP_INITIALIZER;
    struct mf_bitmap masked = MF_BITMAP_INITIALIZER;

    while (payload->size > 0) {
        const struct mf_field *field;
        enum ofperr error;
        bool hasmask;

        error = nx_pull_header(payload, NULL, &field, &hasmask);
        if (!error) {
            bitmap_set1(hasmask ? masked.bm : exact.bm, field->id);
        } else if (error != OFPERR_OFPBMC_BAD_FIELD || !loose) {
            return error;
        }
    }
    if (exactp) {
        *exactp = exact;
    } else if (!bitmap_is_all_zeros(exact.bm, MFF_N_IDS)) {
        return OFPERR_OFPBMC_BAD_MASK;
    }
    if (maskedp) {
        *maskedp = masked;
    } else if (!bitmap_is_all_zeros(masked.bm, MFF_N_IDS)) {
        return OFPERR_OFPBMC_BAD_MASK;
    }
    return 0;
}

/* Converts an OFPMP_TABLE_FEATURES request or reply in 'msg' into an abstract
 * ofputil_table_features in 'tf'.
 *
 * If 'loose' is true, this function ignores properties and values that it does
 * not understand, as a controller would want to do when interpreting
 * capabilities provided by a switch.  If 'loose' is false, this function
 * treats unknown properties and values as an error, as a switch would want to
 * do when interpreting a configuration request made by a controller.
 *
 * A single OpenFlow message can specify features for multiple tables.  Calling
 * this function multiple times for a single 'msg' iterates through the tables
 * in the message.  The caller must initially leave 'msg''s layer pointers null
 * and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no tables were left in this 'msg', otherwise
 * a positive "enum ofperr" value. */
int
ofputil_decode_table_features(struct ofpbuf *msg,
                              struct ofputil_table_features *tf, bool loose)
{
    memset(tf, 0, sizeof *tf);

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    const struct ofp_header *oh = msg->header;
    struct ofp13_table_features *otf = msg->data;
    if (msg->size < sizeof *otf) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    unsigned int len = ntohs(otf->length);
    if (len < sizeof *otf || len % 8 || len > msg->size) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    tf->table_id = otf->table_id;
    if (tf->table_id == OFPTT_ALL) {
        return OFPERR_OFPTFFC_BAD_TABLE;
    }

    ovs_strlcpy_arrays(tf->name, otf->name);
    tf->metadata_match = otf->metadata_match;
    tf->metadata_write = otf->metadata_write;
    tf->miss_config = OFPUTIL_TABLE_MISS_DEFAULT;
    if (oh->version >= OFP14_VERSION) {
        uint32_t caps = ntohl(otf->capabilities);
        tf->supports_eviction = (caps & OFPTC14_EVICTION) != 0;
        tf->supports_vacancy_events = (caps & OFPTC14_VACANCY_EVENTS) != 0;
    } else {
        tf->supports_eviction = -1;
        tf->supports_vacancy_events = -1;
    }
    tf->max_entries = ntohl(otf->max_entries);

    struct ofpbuf properties = ofpbuf_const_initializer(ofpbuf_pull(msg, len),
                                                        len);
    ofpbuf_pull(&properties, sizeof *otf);
    while (properties.size > 0) {
        struct ofpbuf payload;
        enum ofperr error;
        uint64_t type;

        error = pull_table_feature_property(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch ((enum ofp13_table_feature_prop_type) type) {
        case OFPTFPT13_INSTRUCTIONS:
            error = parse_instruction_ids(&payload, loose,
                                          &tf->nonmiss.instructions);
            break;
        case OFPTFPT13_INSTRUCTIONS_MISS:
            error = parse_instruction_ids(&payload, loose,
                                          &tf->miss.instructions);
            break;

        case OFPTFPT13_NEXT_TABLES:
            error = parse_table_features_next_table(&payload,
                                                    tf->nonmiss.next);
            break;
        case OFPTFPT13_NEXT_TABLES_MISS:
            error = parse_table_features_next_table(&payload, tf->miss.next);
            break;

        case OFPTFPT13_WRITE_ACTIONS:
            error = parse_action_bitmap(&payload, oh->version,
                                        &tf->nonmiss.write.ofpacts);
            break;
        case OFPTFPT13_WRITE_ACTIONS_MISS:
            error = parse_action_bitmap(&payload, oh->version,
                                        &tf->miss.write.ofpacts);
            break;

        case OFPTFPT13_APPLY_ACTIONS:
            error = parse_action_bitmap(&payload, oh->version,
                                        &tf->nonmiss.apply.ofpacts);
            break;
        case OFPTFPT13_APPLY_ACTIONS_MISS:
            error = parse_action_bitmap(&payload, oh->version,
                                        &tf->miss.apply.ofpacts);
            break;

        case OFPTFPT13_MATCH:
            error = parse_oxms(&payload, loose, &tf->match, &tf->mask);
            break;
        case OFPTFPT13_WILDCARDS:
            error = parse_oxms(&payload, loose, &tf->wildcard, NULL);
            break;

        case OFPTFPT13_WRITE_SETFIELD:
            error = parse_oxms(&payload, loose,
                               &tf->nonmiss.write.set_fields, NULL);
            break;
        case OFPTFPT13_WRITE_SETFIELD_MISS:
            error = parse_oxms(&payload, loose,
                               &tf->miss.write.set_fields, NULL);
            break;
        case OFPTFPT13_APPLY_SETFIELD:
            error = parse_oxms(&payload, loose,
                               &tf->nonmiss.apply.set_fields, NULL);
            break;
        case OFPTFPT13_APPLY_SETFIELD_MISS:
            error = parse_oxms(&payload, loose,
                               &tf->miss.apply.set_fields, NULL);
            break;

        case OFPTFPT13_EXPERIMENTER:
        case OFPTFPT13_EXPERIMENTER_MISS:
        default:
            error = OFPPROP_UNKNOWN(loose, "table features", type);
            break;
        }
        if (error) {
            return error;
        }
    }

    /* Fix inconsistencies:
     *
     *     - Turn on 'match' bits that are set in 'mask', because maskable
     *       fields are matchable.
     *
     *     - Turn on 'wildcard' bits that are set in 'mask', because a field
     *       that is arbitrarily maskable can be wildcarded entirely.
     *
     *     - Turn off 'wildcard' bits that are not in 'match', because a field
     *       must be matchable for it to be meaningfully wildcarded. */
    bitmap_or(tf->match.bm, tf->mask.bm, MFF_N_IDS);
    bitmap_or(tf->wildcard.bm, tf->mask.bm, MFF_N_IDS);
    bitmap_and(tf->wildcard.bm, tf->match.bm, MFF_N_IDS);

    return 0;
}

/* Encodes and returns a request to obtain the table features of a switch.
 * The message is encoded for OpenFlow version 'ofp_version'. */
struct ofpbuf *
ofputil_encode_table_features_request(enum ofp_version ofp_version)
{
    struct ofpbuf *request = NULL;

    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
    case OFP12_VERSION:
        ovs_fatal(0, "dump-table-features needs OpenFlow 1.3 or later "
                     "(\'-O OpenFlow13\')");
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        request = ofpraw_alloc(OFPRAW_OFPST13_TABLE_FEATURES_REQUEST,
                               ofp_version, 0);
        break;
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

static void
put_fields_property(struct ofpbuf *reply,
                    const struct mf_bitmap *fields,
                    const struct mf_bitmap *masks,
                    enum ofp13_table_feature_prop_type property,
                    enum ofp_version version)
{
    size_t start_ofs;
    int field;

    start_ofs = ofpprop_start(reply, property);
    BITMAP_FOR_EACH_1 (field, MFF_N_IDS, fields->bm) {
        nx_put_header(reply, field, version,
                      masks && bitmap_is_set(masks->bm, field));
    }
    ofpprop_end(reply, start_ofs);
}

static void
put_table_action_features(struct ofpbuf *reply,
                          const struct ofputil_table_action_features *taf,
                          enum ofp13_table_feature_prop_type actions_type,
                          enum ofp13_table_feature_prop_type set_fields_type,
                          int miss_offset, enum ofp_version version)
{
    ofpprop_put_bitmap(reply, actions_type + miss_offset,
                       ntohl(ofpact_bitmap_to_openflow(taf->ofpacts,
                                                       version)));
    put_fields_property(reply, &taf->set_fields, NULL,
                        set_fields_type + miss_offset, version);
}

static void
put_table_instruction_features(
    struct ofpbuf *reply, const struct ofputil_table_instruction_features *tif,
    int miss_offset, enum ofp_version version)
{
    size_t start_ofs;
    uint8_t table_id;

    ofpprop_put_bitmap(reply, OFPTFPT13_INSTRUCTIONS + miss_offset,
                       ntohl(ovsinst_bitmap_to_openflow(tif->instructions,
                                                        version)));

    start_ofs = ofpprop_start(reply, OFPTFPT13_NEXT_TABLES + miss_offset);
    BITMAP_FOR_EACH_1 (table_id, 255, tif->next) {
        ofpbuf_put(reply, &table_id, 1);
    }
    ofpprop_end(reply, start_ofs);

    put_table_action_features(reply, &tif->write,
                              OFPTFPT13_WRITE_ACTIONS,
                              OFPTFPT13_WRITE_SETFIELD, miss_offset, version);
    put_table_action_features(reply, &tif->apply,
                              OFPTFPT13_APPLY_ACTIONS,
                              OFPTFPT13_APPLY_SETFIELD, miss_offset, version);
}

void
ofputil_append_table_features_reply(const struct ofputil_table_features *tf,
                                    struct ovs_list *replies)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    enum ofp_version version = ofpmp_version(replies);
    size_t start_ofs = reply->size;
    struct ofp13_table_features *otf;

    otf = ofpbuf_put_zeros(reply, sizeof *otf);
    otf->table_id = tf->table_id;
    ovs_strlcpy_arrays(otf->name, tf->name);
    otf->metadata_match = tf->metadata_match;
    otf->metadata_write = tf->metadata_write;
    if (version >= OFP14_VERSION) {
        if (tf->supports_eviction) {
            otf->capabilities |= htonl(OFPTC14_EVICTION);
        }
        if (tf->supports_vacancy_events) {
            otf->capabilities |= htonl(OFPTC14_VACANCY_EVENTS);
        }
    }
    otf->max_entries = htonl(tf->max_entries);

    put_table_instruction_features(reply, &tf->nonmiss, 0, version);
    put_table_instruction_features(reply, &tf->miss, 1, version);

    put_fields_property(reply, &tf->match, &tf->mask,
                        OFPTFPT13_MATCH, version);
    put_fields_property(reply, &tf->wildcard, NULL,
                        OFPTFPT13_WILDCARDS, version);

    otf = ofpbuf_at_assert(reply, start_ofs, sizeof *otf);
    otf->length = htons(reply->size - start_ofs);
    ofpmp_postappend(replies, start_ofs);
}

static enum ofperr
parse_table_desc_vacancy_property(struct ofpbuf *property,
                                  struct ofputil_table_desc *td)
{
    struct ofp14_table_mod_prop_vacancy *otv = property->data;

    if (property->size != sizeof *otv) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    td->table_vacancy.vacancy_down = otv->vacancy_down;
    td->table_vacancy.vacancy_up = otv->vacancy_up;
    td->table_vacancy.vacancy = otv->vacancy;
    return 0;
}

/* Decodes the next OpenFlow "table desc" message (of possibly several) from
 * 'msg' into an abstract form in '*td'.  Returns 0 if successful, EOF if the
 * last "table desc" in 'msg' was already decoded, otherwise an OFPERR_*
 * value. */
int
ofputil_decode_table_desc(struct ofpbuf *msg,
                          struct ofputil_table_desc *td,
                          enum ofp_version version)
{
    memset(td, 0, sizeof *td);

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    struct ofp14_table_desc *otd = ofpbuf_try_pull(msg, sizeof *otd);
    if (!otd) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFP14_TABLE_DESC reply has %"PRIu32" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    td->table_id = otd->table_id;
    size_t length = ntohs(otd->length);
    if (length < sizeof *otd || length - sizeof *otd > msg->size) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFP14_TABLE_DESC reply claims invalid "
                     "length %"PRIuSIZE, length);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    length -= sizeof *otd;

    td->eviction = ofputil_decode_table_eviction(otd->config, version);
    td->vacancy = ofputil_decode_table_vacancy(otd->config, version);
    td->eviction_flags = UINT32_MAX;

    struct ofpbuf properties = ofpbuf_const_initializer(
        ofpbuf_pull(msg, length), length);
    while (properties.size > 0) {
        struct ofpbuf payload;
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPTMPT14_EVICTION:
            error = ofpprop_parse_u32(&payload, &td->eviction_flags);
            break;

        case OFPTMPT14_VACANCY:
            error = parse_table_desc_vacancy_property(&payload, td);
            break;

        default:
            error = OFPPROP_UNKNOWN(true, "table_desc", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

/* Encodes and returns a request to obtain description of tables of a switch.
 * The message is encoded for OpenFlow version 'ofp_version'. */
struct ofpbuf *
ofputil_encode_table_desc_request(enum ofp_version ofp_version)
{
    struct ofpbuf *request = NULL;

    if (ofp_version >= OFP14_VERSION) {
        request = ofpraw_alloc(OFPRAW_OFPST14_TABLE_DESC_REQUEST,
                               ofp_version, 0);
    } else {
        ovs_fatal(0, "dump-table-desc needs OpenFlow 1.4 or later "
                  "(\'-O OpenFlow14\')");
    }

    return request;
}

/* Function to append Table desc information in a reply list. */
void
ofputil_append_table_desc_reply(const struct ofputil_table_desc *td,
                                struct ovs_list *replies,
                                enum ofp_version version)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_otd;
    struct ofp14_table_desc *otd;

    start_otd = reply->size;
    ofpbuf_put_zeros(reply, sizeof *otd);
    if (td->eviction_flags != UINT32_MAX) {
        ofpprop_put_u32(reply, OFPTMPT14_EVICTION, td->eviction_flags);
    }
    if (td->vacancy == OFPUTIL_TABLE_VACANCY_ON) {
        struct ofp14_table_mod_prop_vacancy *otv;

        otv = ofpprop_put_zeros(reply, OFPTMPT14_VACANCY, sizeof *otv);
        otv->vacancy_down = td->table_vacancy.vacancy_down;
        otv->vacancy_up = td->table_vacancy.vacancy_up;
        otv->vacancy = td->table_vacancy.vacancy;
    }

    otd = ofpbuf_at_assert(reply, start_otd, sizeof *otd);
    otd->length = htons(reply->size - start_otd);
    otd->table_id = td->table_id;
    otd->config = ofputil_encode_table_config(OFPUTIL_TABLE_MISS_DEFAULT,
                                              td->eviction, td->vacancy,
                                              version);
    ofpmp_postappend(replies, start_otd);
}

/* This function parses Vacancy property, and decodes the
 * ofp14_table_mod_prop_vacancy in ofputil_table_mod.
 * Returns OFPERR_OFPBPC_BAD_VALUE error code when vacancy_down is
 * greater than vacancy_up and also when current vacancy has non-zero
 * value. Returns 0 on success. */
static enum ofperr
parse_table_mod_vacancy_property(struct ofpbuf *property,
                                 struct ofputil_table_mod *tm)
{
    struct ofp14_table_mod_prop_vacancy *otv = property->data;

    if (property->size != sizeof *otv) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    tm->table_vacancy.vacancy_down = otv->vacancy_down;
    tm->table_vacancy.vacancy_up = otv->vacancy_up;
    if (tm->table_vacancy.vacancy_down > tm->table_vacancy.vacancy_up) {
        OFPPROP_LOG(&bad_ofmsg_rl, false,
                    "Value of vacancy_down is greater than vacancy_up");
        return OFPERR_OFPBPC_BAD_VALUE;
    }
    if (tm->table_vacancy.vacancy_down > 100 ||
        tm->table_vacancy.vacancy_up > 100) {
        OFPPROP_LOG(&bad_ofmsg_rl, false, "Vacancy threshold percentage "
                    "should not be greater than 100");
        return OFPERR_OFPBPC_BAD_VALUE;
    }
    tm->table_vacancy.vacancy = otv->vacancy;
    if (tm->table_vacancy.vacancy) {
        OFPPROP_LOG(&bad_ofmsg_rl, false,
                    "Vacancy value should be zero for table-mod messages");
        return OFPERR_OFPBPC_BAD_VALUE;
    }
    return 0;
}

/* Given 'config', taken from an OpenFlow 'version' message that specifies
 * table configuration (a table mod, table stats, or table features message),
 * returns the table vacancy configuration that it specifies.
 *
 * Only OpenFlow 1.4 and later specify table vacancy configuration this way,
 * so for other 'version' this function always returns
 * OFPUTIL_TABLE_VACANCY_DEFAULT. */
static enum ofputil_table_vacancy
ofputil_decode_table_vacancy(ovs_be32 config, enum ofp_version version)
{
    return (version < OFP14_VERSION ? OFPUTIL_TABLE_VACANCY_DEFAULT
            : config & htonl(OFPTC14_VACANCY_EVENTS) ? OFPUTIL_TABLE_VACANCY_ON
            : OFPUTIL_TABLE_VACANCY_OFF);
}

/* Given 'config', taken from an OpenFlow 'version' message that specifies
 * table configuration (a table mod, table stats, or table features message),
 * returns the table eviction configuration that it specifies.
 *
 * Only OpenFlow 1.4 and later specify table eviction configuration this way,
 * so for other 'version' values this function always returns
 * OFPUTIL_TABLE_EVICTION_DEFAULT. */
static enum ofputil_table_eviction
ofputil_decode_table_eviction(ovs_be32 config, enum ofp_version version)
{
    return (version < OFP14_VERSION ? OFPUTIL_TABLE_EVICTION_DEFAULT
            : config & htonl(OFPTC14_EVICTION) ? OFPUTIL_TABLE_EVICTION_ON
            : OFPUTIL_TABLE_EVICTION_OFF);
}

/* Returns a bitmap of OFPTC* values suitable for 'config' fields in various
 * OpenFlow messages of the given 'version', based on the provided 'miss' and
 * 'eviction' values. */
static ovs_be32
ofputil_encode_table_config(enum ofputil_table_miss miss,
                            enum ofputil_table_eviction eviction,
                            enum ofputil_table_vacancy vacancy,
                            enum ofp_version version)
{
    uint32_t config = 0;
    /* Search for "OFPTC_* Table Configuration" in the documentation for more
     * information on the crazy evolution of this field. */
    switch (version) {
    case OFP10_VERSION:
        /* OpenFlow 1.0 didn't have such a field, any value ought to do. */
        return htonl(0);

    case OFP11_VERSION:
    case OFP12_VERSION:
        /* OpenFlow 1.1 and 1.2 define only OFPTC11_TABLE_MISS_*. */
        switch (miss) {
        case OFPUTIL_TABLE_MISS_DEFAULT:
            /* Really this shouldn't be used for encoding (the caller should
             * provide a specific value) but I can't imagine that defaulting to
             * the fall-through case here will hurt. */
        case OFPUTIL_TABLE_MISS_CONTROLLER:
        default:
            return htonl(OFPTC11_TABLE_MISS_CONTROLLER);
        case OFPUTIL_TABLE_MISS_CONTINUE:
            return htonl(OFPTC11_TABLE_MISS_CONTINUE);
        case OFPUTIL_TABLE_MISS_DROP:
            return htonl(OFPTC11_TABLE_MISS_DROP);
        }
        OVS_NOT_REACHED();

    case OFP13_VERSION:
        /* OpenFlow 1.3 removed OFPTC11_TABLE_MISS_* and didn't define any new
         * flags, so this is correct. */
        return htonl(0);

    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        /* OpenFlow 1.4 introduced OFPTC14_EVICTION and
         * OFPTC14_VACANCY_EVENTS. */
        if (eviction == OFPUTIL_TABLE_EVICTION_ON) {
            config |= OFPTC14_EVICTION;
        }
        if (vacancy == OFPUTIL_TABLE_VACANCY_ON) {
            config |= OFPTC14_VACANCY_EVENTS;
        }
        return htonl(config);
    }

    OVS_NOT_REACHED();
}

/* Given 'config', taken from an OpenFlow 'version' message that specifies
 * table configuration (a table mod, table stats, or table features message),
 * returns the table miss configuration that it specifies.
 *
 * Only OpenFlow 1.1 and 1.2 specify table miss configurations this way, so for
 * other 'version' values this function always returns
 * OFPUTIL_TABLE_MISS_DEFAULT. */
static enum ofputil_table_miss
ofputil_decode_table_miss(ovs_be32 config_, enum ofp_version version)
{
    uint32_t config = ntohl(config_);

    if (version == OFP11_VERSION || version == OFP12_VERSION) {
        switch (config & OFPTC11_TABLE_MISS_MASK) {
        case OFPTC11_TABLE_MISS_CONTROLLER:
            return OFPUTIL_TABLE_MISS_CONTROLLER;

        case OFPTC11_TABLE_MISS_CONTINUE:
            return OFPUTIL_TABLE_MISS_CONTINUE;

        case OFPTC11_TABLE_MISS_DROP:
            return OFPUTIL_TABLE_MISS_DROP;

        default:
            VLOG_WARN_RL(&bad_ofmsg_rl, "bad table miss config %d", config);
            return OFPUTIL_TABLE_MISS_CONTROLLER;
        }
    } else {
        return OFPUTIL_TABLE_MISS_DEFAULT;
    }
}

/* Decodes the OpenFlow "table mod" message in '*oh' into an abstract form in
 * '*pm'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_table_mod(const struct ofp_header *oh,
                         struct ofputil_table_mod *pm)
{
    memset(pm, 0, sizeof *pm);
    pm->miss = OFPUTIL_TABLE_MISS_DEFAULT;
    pm->eviction = OFPUTIL_TABLE_EVICTION_DEFAULT;
    pm->eviction_flags = UINT32_MAX;
    pm->vacancy = OFPUTIL_TABLE_VACANCY_DEFAULT;

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT11_TABLE_MOD) {
        const struct ofp11_table_mod *otm = b.data;

        pm->table_id = otm->table_id;
        pm->miss = ofputil_decode_table_miss(otm->config, oh->version);
    } else if (raw == OFPRAW_OFPT14_TABLE_MOD) {
        const struct ofp14_table_mod *otm = ofpbuf_pull(&b, sizeof *otm);

        pm->table_id = otm->table_id;
        pm->miss = ofputil_decode_table_miss(otm->config, oh->version);
        pm->eviction = ofputil_decode_table_eviction(otm->config, oh->version);
        pm->vacancy = ofputil_decode_table_vacancy(otm->config, oh->version);
        while (b.size > 0) {
            struct ofpbuf property;
            enum ofperr error;
            uint64_t type;

            error = ofpprop_pull(&b, &property, &type);
            if (error) {
                return error;
            }

            switch (type) {
            case OFPTMPT14_EVICTION:
                error = ofpprop_parse_u32(&property, &pm->eviction);
                break;

            case OFPTMPT14_VACANCY:
                error = parse_table_mod_vacancy_property(&property, pm);
                break;

            default:
                error = OFPERR_OFPBRC_BAD_TYPE;
                break;
            }

            if (error) {
                return error;
            }
        }
    } else {
        return OFPERR_OFPBRC_BAD_TYPE;
    }

    return 0;
}

/* Converts the abstract form of a "table mod" message in '*tm' into an
 * OpenFlow message suitable for 'protocol', and returns that encoded form in a
 * buffer owned by the caller. */
struct ofpbuf *
ofputil_encode_table_mod(const struct ofputil_table_mod *tm,
                        enum ofputil_protocol protocol)
{
    enum ofp_version ofp_version = ofputil_protocol_to_ofp_version(protocol);
    struct ofpbuf *b;

    switch (ofp_version) {
    case OFP10_VERSION: {
        ovs_fatal(0, "table mod needs OpenFlow 1.1 or later "
                     "(\'-O OpenFlow11\')");
        break;
    }
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_table_mod *otm;

        b = ofpraw_alloc(OFPRAW_OFPT11_TABLE_MOD, ofp_version, 0);
        otm = ofpbuf_put_zeros(b, sizeof *otm);
        otm->table_id = tm->table_id;
        otm->config = ofputil_encode_table_config(tm->miss, tm->eviction,
                                                  tm->vacancy, ofp_version);
        break;
    }
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp14_table_mod *otm;

        b = ofpraw_alloc(OFPRAW_OFPT14_TABLE_MOD, ofp_version, 0);
        otm = ofpbuf_put_zeros(b, sizeof *otm);
        otm->table_id = tm->table_id;
        otm->config = ofputil_encode_table_config(tm->miss, tm->eviction,
                                                  tm->vacancy, ofp_version);

        if (tm->eviction_flags != UINT32_MAX) {
            ofpprop_put_u32(b, OFPTMPT14_EVICTION, tm->eviction_flags);
        }
        if (tm->vacancy == OFPUTIL_TABLE_VACANCY_ON) {
            struct ofp14_table_mod_prop_vacancy *otv;

            otv = ofpprop_put_zeros(b, OFPTMPT14_VACANCY, sizeof *otv);
            otv->vacancy_down = tm->table_vacancy.vacancy_down;
            otv->vacancy_up = tm->table_vacancy.vacancy_up;
        }
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return b;
}

/* ofputil_role_request */

/* Decodes the OpenFlow "role request" or "role reply" message in '*oh' into
 * an abstract form in '*rr'.  Returns 0 if successful, otherwise an
 * OFPERR_* value. */
enum ofperr
ofputil_decode_role_message(const struct ofp_header *oh,
                            struct ofputil_role_request *rr)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT12_ROLE_REQUEST ||
        raw == OFPRAW_OFPT12_ROLE_REPLY) {
        const struct ofp12_role_request *orr = b.msg;

        if (orr->role != htonl(OFPCR12_ROLE_NOCHANGE) &&
            orr->role != htonl(OFPCR12_ROLE_EQUAL) &&
            orr->role != htonl(OFPCR12_ROLE_MASTER) &&
            orr->role != htonl(OFPCR12_ROLE_SLAVE)) {
            return OFPERR_OFPRRFC_BAD_ROLE;
        }

        rr->role = ntohl(orr->role);
        if (raw == OFPRAW_OFPT12_ROLE_REQUEST
            ? orr->role == htonl(OFPCR12_ROLE_NOCHANGE)
            : orr->generation_id == OVS_BE64_MAX) {
            rr->have_generation_id = false;
            rr->generation_id = 0;
        } else {
            rr->have_generation_id = true;
            rr->generation_id = ntohll(orr->generation_id);
        }
    } else if (raw == OFPRAW_NXT_ROLE_REQUEST ||
               raw == OFPRAW_NXT_ROLE_REPLY) {
        const struct nx_role_request *nrr = b.msg;

        BUILD_ASSERT(NX_ROLE_OTHER + 1 == OFPCR12_ROLE_EQUAL);
        BUILD_ASSERT(NX_ROLE_MASTER + 1 == OFPCR12_ROLE_MASTER);
        BUILD_ASSERT(NX_ROLE_SLAVE + 1 == OFPCR12_ROLE_SLAVE);

        if (nrr->role != htonl(NX_ROLE_OTHER) &&
            nrr->role != htonl(NX_ROLE_MASTER) &&
            nrr->role != htonl(NX_ROLE_SLAVE)) {
            return OFPERR_OFPRRFC_BAD_ROLE;
        }

        rr->role = ntohl(nrr->role) + 1;
        rr->have_generation_id = false;
        rr->generation_id = 0;
    } else {
        OVS_NOT_REACHED();
    }

    return 0;
}

/* Returns an encoded form of a role reply suitable for the "request" in a
 * buffer owned by the caller. */
struct ofpbuf *
ofputil_encode_role_reply(const struct ofp_header *request,
                          const struct ofputil_role_request *rr)
{
    struct ofpbuf *buf;
    enum ofpraw raw;

    raw = ofpraw_decode_assert(request);
    if (raw == OFPRAW_OFPT12_ROLE_REQUEST) {
        struct ofp12_role_request *orr;

        buf = ofpraw_alloc_reply(OFPRAW_OFPT12_ROLE_REPLY, request, 0);
        orr = ofpbuf_put_zeros(buf, sizeof *orr);

        orr->role = htonl(rr->role);
        orr->generation_id = htonll(rr->have_generation_id
                                    ? rr->generation_id
                                    : UINT64_MAX);
    } else if (raw == OFPRAW_NXT_ROLE_REQUEST) {
        struct nx_role_request *nrr;

        BUILD_ASSERT(NX_ROLE_OTHER == OFPCR12_ROLE_EQUAL - 1);
        BUILD_ASSERT(NX_ROLE_MASTER == OFPCR12_ROLE_MASTER - 1);
        BUILD_ASSERT(NX_ROLE_SLAVE == OFPCR12_ROLE_SLAVE - 1);

        buf = ofpraw_alloc_reply(OFPRAW_NXT_ROLE_REPLY, request, 0);
        nrr = ofpbuf_put_zeros(buf, sizeof *nrr);
        nrr->role = htonl(rr->role - 1);
    } else {
        OVS_NOT_REACHED();
    }

    return buf;
}

/* Encodes "role status" message 'status' for sending in the given
 * 'protocol'.  Returns the role status message, if 'protocol' supports them,
 * otherwise a null pointer. */
struct ofpbuf *
ofputil_encode_role_status(const struct ofputil_role_status *status,
                           enum ofputil_protocol protocol)
{
    enum ofp_version version;

    version = ofputil_protocol_to_ofp_version(protocol);
    if (version >= OFP14_VERSION) {
        struct ofp14_role_status *rstatus;
        struct ofpbuf *buf;

        buf = ofpraw_alloc_xid(OFPRAW_OFPT14_ROLE_STATUS, version, htonl(0),
                               0);
        rstatus = ofpbuf_put_zeros(buf, sizeof *rstatus);
        rstatus->role = htonl(status->role);
        rstatus->reason = status->reason;
        rstatus->generation_id = htonll(status->generation_id);

        return buf;
    } else {
        return NULL;
    }
}

enum ofperr
ofputil_decode_role_status(const struct ofp_header *oh,
                           struct ofputil_role_status *rs)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    ovs_assert(raw == OFPRAW_OFPT14_ROLE_STATUS);

    const struct ofp14_role_status *r = b.msg;
    if (r->role != htonl(OFPCR12_ROLE_NOCHANGE) &&
        r->role != htonl(OFPCR12_ROLE_EQUAL) &&
        r->role != htonl(OFPCR12_ROLE_MASTER) &&
        r->role != htonl(OFPCR12_ROLE_SLAVE)) {
        return OFPERR_OFPRRFC_BAD_ROLE;
    }

    rs->role = ntohl(r->role);
    rs->generation_id = ntohll(r->generation_id);
    rs->reason = r->reason;

    return 0;
}

/* Encodes 'rf' according to 'protocol', and returns the encoded message.
 * 'protocol' must be for OpenFlow 1.4 or later. */
struct ofpbuf *
ofputil_encode_requestforward(const struct ofputil_requestforward *rf,
                              enum ofputil_protocol protocol)
{
    enum ofp_version ofp_version = ofputil_protocol_to_ofp_version(protocol);
    struct ofpbuf *inner;

    switch (rf->reason) {
    case OFPRFR_GROUP_MOD:
        inner = ofputil_encode_group_mod(ofp_version, rf->group_mod);
        break;

    case OFPRFR_METER_MOD:
        inner = ofputil_encode_meter_mod(ofp_version, rf->meter_mod);
        break;

    case OFPRFR_N_REASONS:
    default:
        OVS_NOT_REACHED();
    }

    struct ofp_header *inner_oh = inner->data;
    inner_oh->xid = rf->xid;
    inner_oh->length = htons(inner->size);

    struct ofpbuf *outer = ofpraw_alloc_xid(OFPRAW_OFPT14_REQUESTFORWARD,
                                            ofp_version, htonl(0),
                                            inner->size);
    ofpbuf_put(outer, inner->data, inner->size);
    ofpbuf_delete(inner);

    return outer;
}

/* Decodes OFPT_REQUESTFORWARD message 'outer'.  On success, puts the decoded
 * form into '*rf' and returns 0, and the caller is later responsible for
 * freeing the content of 'rf', with ofputil_destroy_requestforward(rf).  On
 * failure, returns an ofperr and '*rf' is indeterminate. */
enum ofperr
ofputil_decode_requestforward(const struct ofp_header *outer,
                              struct ofputil_requestforward *rf)
{
    struct ofpbuf b = ofpbuf_const_initializer(outer, ntohs(outer->length));

    /* Skip past outer message. */
    enum ofpraw outer_raw = ofpraw_pull_assert(&b);
    ovs_assert(outer_raw == OFPRAW_OFPT14_REQUESTFORWARD);

    /* Validate inner message. */
    if (b.size < sizeof(struct ofp_header)) {
        return OFPERR_OFPBFC_MSG_BAD_LEN;
    }
    const struct ofp_header *inner = b.data;
    unsigned int inner_len = ntohs(inner->length);
    if (inner_len < sizeof(struct ofp_header) || inner_len > b.size) {
        return OFPERR_OFPBFC_MSG_BAD_LEN;
    }
    if (inner->version != outer->version) {
        return OFPERR_OFPBRC_BAD_VERSION;
    }

    /* Parse inner message. */
    enum ofptype type;
    enum ofperr error = ofptype_decode(&type, inner);
    if (error) {
        return error;
    }

    rf->xid = inner->xid;
    if (type == OFPTYPE_GROUP_MOD) {
        rf->reason = OFPRFR_GROUP_MOD;
        rf->group_mod = xmalloc(sizeof *rf->group_mod);
        error = ofputil_decode_group_mod(inner, rf->group_mod);
        if (error) {
            free(rf->group_mod);
            return error;
        }
    } else if (type == OFPTYPE_METER_MOD) {
        rf->reason = OFPRFR_METER_MOD;
        rf->meter_mod = xmalloc(sizeof *rf->meter_mod);
        ofpbuf_init(&rf->bands, 64);
        error = ofputil_decode_meter_mod(inner, rf->meter_mod, &rf->bands);
        if (error) {
            free(rf->meter_mod);
            ofpbuf_uninit(&rf->bands);
            return error;
        }
    } else {
        return OFPERR_OFPBFC_MSG_UNSUP;
    }

    return 0;
}

/* Frees the content of 'rf', which should have been initialized through a
 * successful call to ofputil_decode_requestforward(). */
void
ofputil_destroy_requestforward(struct ofputil_requestforward *rf)
{
    if (!rf) {
        return;
    }

    switch (rf->reason) {
    case OFPRFR_GROUP_MOD:
        ofputil_uninit_group_mod(rf->group_mod);
        free(rf->group_mod);
        break;

    case OFPRFR_METER_MOD:
        ofpbuf_uninit(&rf->bands);
        free(rf->meter_mod);
        break;

    case OFPRFR_N_REASONS:
        OVS_NOT_REACHED();
    }
}

/* Table stats. */

/* OpenFlow 1.0 and 1.1 don't distinguish between a field that cannot be
 * matched and a field that must be wildcarded.  This function returns a bitmap
 * that contains both kinds of fields. */
static struct mf_bitmap
wild_or_nonmatchable_fields(const struct ofputil_table_features *features)
{
    struct mf_bitmap wc = features->match;
    bitmap_not(wc.bm, MFF_N_IDS);
    bitmap_or(wc.bm, features->wildcard.bm, MFF_N_IDS);
    return wc;
}

struct ofp10_wc_map {
    enum ofp10_flow_wildcards wc10;
    enum mf_field_id mf;
};

static const struct ofp10_wc_map ofp10_wc_map[] = {
    { OFPFW10_IN_PORT,     MFF_IN_PORT },
    { OFPFW10_DL_VLAN,     MFF_VLAN_VID },
    { OFPFW10_DL_SRC,      MFF_ETH_SRC },
    { OFPFW10_DL_DST,      MFF_ETH_DST},
    { OFPFW10_DL_TYPE,     MFF_ETH_TYPE },
    { OFPFW10_NW_PROTO,    MFF_IP_PROTO },
    { OFPFW10_TP_SRC,      MFF_TCP_SRC },
    { OFPFW10_TP_DST,      MFF_TCP_DST },
    { OFPFW10_NW_SRC_MASK, MFF_IPV4_SRC },
    { OFPFW10_NW_DST_MASK, MFF_IPV4_DST },
    { OFPFW10_DL_VLAN_PCP, MFF_VLAN_PCP },
    { OFPFW10_NW_TOS,      MFF_IP_DSCP },
};

static ovs_be32
mf_bitmap_to_of10(const struct mf_bitmap *fields)
{
    const struct ofp10_wc_map *p;
    uint32_t wc10 = 0;

    for (p = ofp10_wc_map; p < &ofp10_wc_map[ARRAY_SIZE(ofp10_wc_map)]; p++) {
        if (bitmap_is_set(fields->bm, p->mf)) {
            wc10 |= p->wc10;
        }
    }
    return htonl(wc10);
}

static struct mf_bitmap
mf_bitmap_from_of10(ovs_be32 wc10_)
{
    struct mf_bitmap fields = MF_BITMAP_INITIALIZER;
    const struct ofp10_wc_map *p;
    uint32_t wc10 = ntohl(wc10_);

    for (p = ofp10_wc_map; p < &ofp10_wc_map[ARRAY_SIZE(ofp10_wc_map)]; p++) {
        if (wc10 & p->wc10) {
            bitmap_set1(fields.bm, p->mf);
        }
    }
    return fields;
}

static void
ofputil_put_ofp10_table_stats(const struct ofputil_table_stats *stats,
                              const struct ofputil_table_features *features,
                              struct ofpbuf *buf)
{
    struct mf_bitmap wc = wild_or_nonmatchable_fields(features);
    struct ofp10_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = features->table_id;
    ovs_strlcpy_arrays(out->name, features->name);
    out->wildcards = mf_bitmap_to_of10(&wc);
    out->max_entries = htonl(features->max_entries);
    out->active_count = htonl(stats->active_count);
    put_32aligned_be64(&out->lookup_count, htonll(stats->lookup_count));
    put_32aligned_be64(&out->matched_count, htonll(stats->matched_count));
}

struct ofp11_wc_map {
    enum ofp11_flow_match_fields wc11;
    enum mf_field_id mf;
};

static const struct ofp11_wc_map ofp11_wc_map[] = {
    { OFPFMF11_IN_PORT,     MFF_IN_PORT },
    { OFPFMF11_DL_VLAN,     MFF_VLAN_VID },
    { OFPFMF11_DL_VLAN_PCP, MFF_VLAN_PCP },
    { OFPFMF11_DL_TYPE,     MFF_ETH_TYPE },
    { OFPFMF11_NW_TOS,      MFF_IP_DSCP },
    { OFPFMF11_NW_PROTO,    MFF_IP_PROTO },
    { OFPFMF11_TP_SRC,      MFF_TCP_SRC },
    { OFPFMF11_TP_DST,      MFF_TCP_DST },
    { OFPFMF11_MPLS_LABEL,  MFF_MPLS_LABEL },
    { OFPFMF11_MPLS_TC,     MFF_MPLS_TC },
    /* I don't know what OFPFMF11_TYPE means. */
    { OFPFMF11_DL_SRC,      MFF_ETH_SRC },
    { OFPFMF11_DL_DST,      MFF_ETH_DST },
    { OFPFMF11_NW_SRC,      MFF_IPV4_SRC },
    { OFPFMF11_NW_DST,      MFF_IPV4_DST },
    { OFPFMF11_METADATA,    MFF_METADATA },
};

static ovs_be32
mf_bitmap_to_of11(const struct mf_bitmap *fields)
{
    const struct ofp11_wc_map *p;
    uint32_t wc11 = 0;

    for (p = ofp11_wc_map; p < &ofp11_wc_map[ARRAY_SIZE(ofp11_wc_map)]; p++) {
        if (bitmap_is_set(fields->bm, p->mf)) {
            wc11 |= p->wc11;
        }
    }
    return htonl(wc11);
}

static struct mf_bitmap
mf_bitmap_from_of11(ovs_be32 wc11_)
{
    struct mf_bitmap fields = MF_BITMAP_INITIALIZER;
    const struct ofp11_wc_map *p;
    uint32_t wc11 = ntohl(wc11_);

    for (p = ofp11_wc_map; p < &ofp11_wc_map[ARRAY_SIZE(ofp11_wc_map)]; p++) {
        if (wc11 & p->wc11) {
            bitmap_set1(fields.bm, p->mf);
        }
    }
    return fields;
}

static void
ofputil_put_ofp11_table_stats(const struct ofputil_table_stats *stats,
                              const struct ofputil_table_features *features,
                              struct ofpbuf *buf)
{
    struct mf_bitmap wc = wild_or_nonmatchable_fields(features);
    struct ofp11_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = features->table_id;
    ovs_strlcpy_arrays(out->name, features->name);
    out->wildcards = mf_bitmap_to_of11(&wc);
    out->match = mf_bitmap_to_of11(&features->match);
    out->instructions = ovsinst_bitmap_to_openflow(
        features->nonmiss.instructions, OFP11_VERSION);
    out->write_actions = ofpact_bitmap_to_openflow(
        features->nonmiss.write.ofpacts, OFP11_VERSION);
    out->apply_actions = ofpact_bitmap_to_openflow(
        features->nonmiss.apply.ofpacts, OFP11_VERSION);
    out->config = htonl(features->miss_config);
    out->max_entries = htonl(features->max_entries);
    out->active_count = htonl(stats->active_count);
    out->lookup_count = htonll(stats->lookup_count);
    out->matched_count = htonll(stats->matched_count);
}

static void
ofputil_put_ofp12_table_stats(const struct ofputil_table_stats *stats,
                              const struct ofputil_table_features *features,
                              struct ofpbuf *buf)
{
    struct ofp12_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = features->table_id;
    ovs_strlcpy_arrays(out->name, features->name);
    out->match = oxm_bitmap_from_mf_bitmap(&features->match, OFP12_VERSION);
    out->wildcards = oxm_bitmap_from_mf_bitmap(&features->wildcard,
                                             OFP12_VERSION);
    out->write_actions = ofpact_bitmap_to_openflow(
        features->nonmiss.write.ofpacts, OFP12_VERSION);
    out->apply_actions = ofpact_bitmap_to_openflow(
        features->nonmiss.apply.ofpacts, OFP12_VERSION);
    out->write_setfields = oxm_bitmap_from_mf_bitmap(
        &features->nonmiss.write.set_fields, OFP12_VERSION);
    out->apply_setfields = oxm_bitmap_from_mf_bitmap(
        &features->nonmiss.apply.set_fields, OFP12_VERSION);
    out->metadata_match = features->metadata_match;
    out->metadata_write = features->metadata_write;
    out->instructions = ovsinst_bitmap_to_openflow(
        features->nonmiss.instructions, OFP12_VERSION);
    out->config = ofputil_encode_table_config(features->miss_config,
                                              OFPUTIL_TABLE_EVICTION_DEFAULT,
                                              OFPUTIL_TABLE_VACANCY_DEFAULT,
                                              OFP12_VERSION);
    out->max_entries = htonl(features->max_entries);
    out->active_count = htonl(stats->active_count);
    out->lookup_count = htonll(stats->lookup_count);
    out->matched_count = htonll(stats->matched_count);
}

static void
ofputil_put_ofp13_table_stats(const struct ofputil_table_stats *stats,
                              struct ofpbuf *buf)
{
    struct ofp13_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = stats->table_id;
    out->active_count = htonl(stats->active_count);
    out->lookup_count = htonll(stats->lookup_count);
    out->matched_count = htonll(stats->matched_count);
}

struct ofpbuf *
ofputil_encode_table_stats_reply(const struct ofp_header *request)
{
    return ofpraw_alloc_stats_reply(request, 0);
}

void
ofputil_append_table_stats_reply(struct ofpbuf *reply,
                                 const struct ofputil_table_stats *stats,
                                 const struct ofputil_table_features *features)
{
    struct ofp_header *oh = reply->header;

    ovs_assert(stats->table_id == features->table_id);

    switch ((enum ofp_version) oh->version) {
    case OFP10_VERSION:
        ofputil_put_ofp10_table_stats(stats, features, reply);
        break;

    case OFP11_VERSION:
        ofputil_put_ofp11_table_stats(stats, features, reply);
        break;

    case OFP12_VERSION:
        ofputil_put_ofp12_table_stats(stats, features, reply);
        break;

    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        ofputil_put_ofp13_table_stats(stats, reply);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static int
ofputil_decode_ofp10_table_stats(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    struct ofp10_table_stats *ots;

    ots = ofpbuf_try_pull(msg, sizeof *ots);
    if (!ots) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    features->table_id = ots->table_id;
    ovs_strlcpy_arrays(features->name, ots->name);
    features->max_entries = ntohl(ots->max_entries);
    features->match = features->wildcard = mf_bitmap_from_of10(ots->wildcards);

    stats->table_id = ots->table_id;
    stats->active_count = ntohl(ots->active_count);
    stats->lookup_count = ntohll(get_32aligned_be64(&ots->lookup_count));
    stats->matched_count = ntohll(get_32aligned_be64(&ots->matched_count));

    return 0;
}

static int
ofputil_decode_ofp11_table_stats(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    struct ofp11_table_stats *ots;

    ots = ofpbuf_try_pull(msg, sizeof *ots);
    if (!ots) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    features->table_id = ots->table_id;
    ovs_strlcpy_arrays(features->name, ots->name);
    features->max_entries = ntohl(ots->max_entries);
    features->nonmiss.instructions = ovsinst_bitmap_from_openflow(
        ots->instructions, OFP11_VERSION);
    features->nonmiss.write.ofpacts = ofpact_bitmap_from_openflow(
        ots->write_actions, OFP11_VERSION);
    features->nonmiss.apply.ofpacts = ofpact_bitmap_from_openflow(
        ots->write_actions, OFP11_VERSION);
    features->miss = features->nonmiss;
    features->miss_config = ofputil_decode_table_miss(ots->config,
                                                      OFP11_VERSION);
    features->match = mf_bitmap_from_of11(ots->match);
    features->wildcard = mf_bitmap_from_of11(ots->wildcards);
    bitmap_or(features->match.bm, features->wildcard.bm, MFF_N_IDS);

    stats->table_id = ots->table_id;
    stats->active_count = ntohl(ots->active_count);
    stats->lookup_count = ntohll(ots->lookup_count);
    stats->matched_count = ntohll(ots->matched_count);

    return 0;
}

static int
ofputil_decode_ofp12_table_stats(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    struct ofp12_table_stats *ots;

    ots = ofpbuf_try_pull(msg, sizeof *ots);
    if (!ots) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    features->table_id = ots->table_id;
    ovs_strlcpy_arrays(features->name, ots->name);
    features->metadata_match = ots->metadata_match;
    features->metadata_write = ots->metadata_write;
    features->miss_config = ofputil_decode_table_miss(ots->config,
                                                      OFP12_VERSION);
    features->max_entries = ntohl(ots->max_entries);

    features->nonmiss.instructions = ovsinst_bitmap_from_openflow(
        ots->instructions, OFP12_VERSION);
    features->nonmiss.write.ofpacts = ofpact_bitmap_from_openflow(
        ots->write_actions, OFP12_VERSION);
    features->nonmiss.apply.ofpacts = ofpact_bitmap_from_openflow(
        ots->apply_actions, OFP12_VERSION);
    features->nonmiss.write.set_fields = oxm_bitmap_to_mf_bitmap(
        ots->write_setfields, OFP12_VERSION);
    features->nonmiss.apply.set_fields = oxm_bitmap_to_mf_bitmap(
        ots->apply_setfields, OFP12_VERSION);
    features->miss = features->nonmiss;

    features->match = oxm_bitmap_to_mf_bitmap(ots->match, OFP12_VERSION);
    features->wildcard = oxm_bitmap_to_mf_bitmap(ots->wildcards,
                                                 OFP12_VERSION);
    bitmap_or(features->match.bm, features->wildcard.bm, MFF_N_IDS);

    stats->table_id = ots->table_id;
    stats->active_count = ntohl(ots->active_count);
    stats->lookup_count = ntohll(ots->lookup_count);
    stats->matched_count = ntohll(ots->matched_count);

    return 0;
}

static int
ofputil_decode_ofp13_table_stats(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    struct ofp13_table_stats *ots;

    ots = ofpbuf_try_pull(msg, sizeof *ots);
    if (!ots) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    features->table_id = ots->table_id;

    stats->table_id = ots->table_id;
    stats->active_count = ntohl(ots->active_count);
    stats->lookup_count = ntohll(ots->lookup_count);
    stats->matched_count = ntohll(ots->matched_count);

    return 0;
}

int
ofputil_decode_table_stats_reply(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    const struct ofp_header *oh;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }
    oh = msg->header;

    if (!msg->size) {
        return EOF;
    }

    memset(stats, 0, sizeof *stats);
    memset(features, 0, sizeof *features);
    features->supports_eviction = -1;
    features->supports_vacancy_events = -1;

    switch ((enum ofp_version) oh->version) {
    case OFP10_VERSION:
        return ofputil_decode_ofp10_table_stats(msg, stats, features);

    case OFP11_VERSION:
        return ofputil_decode_ofp11_table_stats(msg, stats, features);

    case OFP12_VERSION:
        return ofputil_decode_ofp12_table_stats(msg, stats, features);

    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        return ofputil_decode_ofp13_table_stats(msg, stats, features);

    default:
        OVS_NOT_REACHED();
    }
}

/* ofputil_flow_monitor_request */

/* Converts an NXST_FLOW_MONITOR request in 'msg' into an abstract
 * ofputil_flow_monitor_request in 'rq'.
 *
 * Multiple NXST_FLOW_MONITOR requests can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the requests.  The caller must initially leave 'msg''s layer
 * pointers null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no requests were left in this 'msg',
 * otherwise an OFPERR_* value. */
int
ofputil_decode_flow_monitor_request(struct ofputil_flow_monitor_request *rq,
                                    struct ofpbuf *msg)
{
    struct nx_flow_monitor_request *nfmr;
    uint16_t flags;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    nfmr = ofpbuf_try_pull(msg, sizeof *nfmr);
    if (!nfmr) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW_MONITOR request has %"PRIu32" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    flags = ntohs(nfmr->flags);
    if (!(flags & (NXFMF_ADD | NXFMF_DELETE | NXFMF_MODIFY))
        || flags & ~(NXFMF_INITIAL | NXFMF_ADD | NXFMF_DELETE
                     | NXFMF_MODIFY | NXFMF_ACTIONS | NXFMF_OWN)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW_MONITOR has bad flags %#"PRIx16,
                     flags);
        return OFPERR_OFPMOFC_BAD_FLAGS;
    }

    if (!is_all_zeros(nfmr->zeros, sizeof nfmr->zeros)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    rq->id = ntohl(nfmr->id);
    rq->flags = flags;
    rq->out_port = u16_to_ofp(ntohs(nfmr->out_port));
    rq->table_id = nfmr->table_id;

    return nx_pull_match(msg, ntohs(nfmr->match_len), &rq->match, NULL,
                         NULL, false, NULL, NULL);
}

void
ofputil_append_flow_monitor_request(
    const struct ofputil_flow_monitor_request *rq, struct ofpbuf *msg)
{
    struct nx_flow_monitor_request *nfmr;
    size_t start_ofs;
    int match_len;

    if (!msg->size) {
        ofpraw_put(OFPRAW_NXST_FLOW_MONITOR_REQUEST, OFP10_VERSION, msg);
    }

    start_ofs = msg->size;
    ofpbuf_put_zeros(msg, sizeof *nfmr);
    match_len = nx_put_match(msg, &rq->match, htonll(0), htonll(0));

    nfmr = ofpbuf_at_assert(msg, start_ofs, sizeof *nfmr);
    nfmr->id = htonl(rq->id);
    nfmr->flags = htons(rq->flags);
    nfmr->out_port = htons(ofp_to_u16(rq->out_port));
    nfmr->match_len = htons(match_len);
    nfmr->table_id = rq->table_id;
}

/* Converts an NXST_FLOW_MONITOR reply (also known as a flow update) in 'msg'
 * into an abstract ofputil_flow_update in 'update'.  The caller must have
 * initialized update->match to point to space allocated for a match.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of the update's
 * actions (except for NXFME_ABBREV, which never includes actions).  The caller
 * must initialize 'ofpacts' and retains ownership of it.  'update->ofpacts'
 * will point into the 'ofpacts' buffer.
 *
 * Multiple flow updates can be packed into a single OpenFlow message.  Calling
 * this function multiple times for a single 'msg' iterates through the
 * updates.  The caller must initially leave 'msg''s layer pointers null and
 * not modify them between calls.
 *
 * Returns 0 if successful, EOF if no updates were left in this 'msg',
 * otherwise an OFPERR_* value. */
int
ofputil_decode_flow_update(struct ofputil_flow_update *update,
                           struct ofpbuf *msg, struct ofpbuf *ofpacts)
{
    struct nx_flow_update_header *nfuh;
    unsigned int length;
    struct ofp_header *oh;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    ofpbuf_clear(ofpacts);
    if (!msg->size) {
        return EOF;
    }

    if (msg->size < sizeof(struct nx_flow_update_header)) {
        goto bad_len;
    }

    oh = msg->header;

    nfuh = msg->data;
    update->event = ntohs(nfuh->event);
    length = ntohs(nfuh->length);
    if (length > msg->size || length % 8) {
        goto bad_len;
    }

    if (update->event == NXFME_ABBREV) {
        struct nx_flow_update_abbrev *nfua;

        if (length != sizeof *nfua) {
            goto bad_len;
        }

        nfua = ofpbuf_pull(msg, sizeof *nfua);
        update->xid = nfua->xid;
        return 0;
    } else if (update->event == NXFME_ADDED
               || update->event == NXFME_DELETED
               || update->event == NXFME_MODIFIED) {
        struct nx_flow_update_full *nfuf;
        unsigned int actions_len;
        unsigned int match_len;
        enum ofperr error;

        if (length < sizeof *nfuf) {
            goto bad_len;
        }

        nfuf = ofpbuf_pull(msg, sizeof *nfuf);
        match_len = ntohs(nfuf->match_len);
        if (sizeof *nfuf + match_len > length) {
            goto bad_len;
        }

        update->reason = ntohs(nfuf->reason);
        update->idle_timeout = ntohs(nfuf->idle_timeout);
        update->hard_timeout = ntohs(nfuf->hard_timeout);
        update->table_id = nfuf->table_id;
        update->cookie = nfuf->cookie;
        update->priority = ntohs(nfuf->priority);

        error = nx_pull_match(msg, match_len, &update->match, NULL, NULL,
                              false, NULL, NULL);
        if (error) {
            return error;
        }

        actions_len = length - sizeof *nfuf - ROUND_UP(match_len, 8);
        error = ofpacts_pull_openflow_actions(msg, actions_len, oh->version,
                                              NULL, NULL, ofpacts);
        if (error) {
            return error;
        }

        update->ofpacts = ofpacts->data;
        update->ofpacts_len = ofpacts->size;
        return 0;
    } else {
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "NXST_FLOW_MONITOR reply has bad event %"PRIu16,
                     ntohs(nfuh->event));
        return OFPERR_NXBRC_FM_BAD_EVENT;
    }

bad_len:
    VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW_MONITOR reply has %"PRIu32" "
                 "leftover bytes at end", msg->size);
    return OFPERR_OFPBRC_BAD_LEN;
}

uint32_t
ofputil_decode_flow_monitor_cancel(const struct ofp_header *oh)
{
    const struct nx_flow_monitor_cancel *cancel = ofpmsg_body(oh);

    return ntohl(cancel->id);
}

struct ofpbuf *
ofputil_encode_flow_monitor_cancel(uint32_t id)
{
    struct nx_flow_monitor_cancel *nfmc;
    struct ofpbuf *msg;

    msg = ofpraw_alloc(OFPRAW_NXT_FLOW_MONITOR_CANCEL, OFP10_VERSION, 0);
    nfmc = ofpbuf_put_uninit(msg, sizeof *nfmc);
    nfmc->id = htonl(id);
    return msg;
}

void
ofputil_start_flow_update(struct ovs_list *replies)
{
    struct ofpbuf *msg;

    msg = ofpraw_alloc_xid(OFPRAW_NXST_FLOW_MONITOR_REPLY, OFP10_VERSION,
                           htonl(0), 1024);

    ovs_list_init(replies);
    ovs_list_push_back(replies, &msg->list_node);
}

void
ofputil_append_flow_update(const struct ofputil_flow_update *update,
                           struct ovs_list *replies,
                           const struct tun_table *tun_table)
{
    struct ofputil_flow_update *update_ =
        CONST_CAST(struct ofputil_flow_update *, update);
    const struct tun_table *orig_tun_table;
    enum ofp_version version = ofpmp_version(replies);
    struct nx_flow_update_header *nfuh;
    struct ofpbuf *msg;
    size_t start_ofs;

    orig_tun_table = update->match.flow.tunnel.metadata.tab;
    update_->match.flow.tunnel.metadata.tab = tun_table;

    msg = ofpbuf_from_list(ovs_list_back(replies));
    start_ofs = msg->size;

    if (update->event == NXFME_ABBREV) {
        struct nx_flow_update_abbrev *nfua;

        nfua = ofpbuf_put_zeros(msg, sizeof *nfua);
        nfua->xid = update->xid;
    } else {
        struct nx_flow_update_full *nfuf;
        int match_len;

        ofpbuf_put_zeros(msg, sizeof *nfuf);
        match_len = nx_put_match(msg, &update->match, htonll(0), htonll(0));
        ofpacts_put_openflow_actions(update->ofpacts, update->ofpacts_len, msg,
                                     version);
        nfuf = ofpbuf_at_assert(msg, start_ofs, sizeof *nfuf);
        nfuf->reason = htons(update->reason);
        nfuf->priority = htons(update->priority);
        nfuf->idle_timeout = htons(update->idle_timeout);
        nfuf->hard_timeout = htons(update->hard_timeout);
        nfuf->match_len = htons(match_len);
        nfuf->table_id = update->table_id;
        nfuf->cookie = update->cookie;
    }

    nfuh = ofpbuf_at_assert(msg, start_ofs, sizeof *nfuh);
    nfuh->length = htons(msg->size - start_ofs);
    nfuh->event = htons(update->event);

    ofpmp_postappend(replies, start_ofs);
    update_->match.flow.tunnel.metadata.tab = orig_tun_table;
}

struct ofpbuf *
ofputil_encode_packet_out(const struct ofputil_packet_out *po,
                          enum ofputil_protocol protocol)
{
    enum ofp_version ofp_version = ofputil_protocol_to_ofp_version(protocol);
    struct ofpbuf *msg;
    size_t size;

    size = po->ofpacts_len;
    if (po->buffer_id == UINT32_MAX) {
        size += po->packet_len;
    }

    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_packet_out *opo;
        size_t actions_ofs;

        msg = ofpraw_alloc(OFPRAW_OFPT10_PACKET_OUT, OFP10_VERSION, size);
        ofpbuf_put_zeros(msg, sizeof *opo);
        actions_ofs = msg->size;
        ofpacts_put_openflow_actions(po->ofpacts, po->ofpacts_len, msg,
                                     ofp_version);

        opo = msg->msg;
        opo->buffer_id = htonl(po->buffer_id);
        opo->in_port =htons(ofp_to_u16(
                                po->flow_metadata.flow.in_port.ofp_port));
        opo->actions_len = htons(msg->size - actions_ofs);
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION: {
        struct ofp11_packet_out *opo;
        size_t len;

        msg = ofpraw_alloc(OFPRAW_OFPT11_PACKET_OUT, ofp_version, size);
        ofpbuf_put_zeros(msg, sizeof *opo);
        len = ofpacts_put_openflow_actions(po->ofpacts, po->ofpacts_len, msg,
                                           ofp_version);
        opo = msg->msg;
        opo->buffer_id = htonl(po->buffer_id);
        opo->in_port =
            ofputil_port_to_ofp11(po->flow_metadata.flow.in_port.ofp_port);
        opo->actions_len = htons(len);
        break;
    }

    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp15_packet_out *opo;
        size_t len;

        /* The final argument is just an estimate of the space required. */
        msg = ofpraw_alloc(OFPRAW_OFPT15_PACKET_OUT, ofp_version,
                           size + NXM_TYPICAL_LEN);
        ofpbuf_put_zeros(msg, sizeof *opo);
        oxm_put_match(msg, &po->flow_metadata, ofp_version);
        len = ofpacts_put_openflow_actions(po->ofpacts, po->ofpacts_len, msg,
                                           ofp_version);
        opo = msg->msg;
        opo->buffer_id = htonl(po->buffer_id);
        opo->actions_len = htons(len);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    if (po->buffer_id == UINT32_MAX) {
        ofpbuf_put(msg, po->packet, po->packet_len);
    }

    ofpmsg_update_length(msg);

    return msg;
}

/* Creates and returns an OFPT_ECHO_REQUEST message with an empty payload. */
struct ofpbuf *
make_echo_request(enum ofp_version ofp_version)
{
    return ofpraw_alloc_xid(OFPRAW_OFPT_ECHO_REQUEST, ofp_version,
                            htonl(0), 0);
}

/* Creates and returns an OFPT_ECHO_REPLY message matching the
 * OFPT_ECHO_REQUEST message in 'rq'. */
struct ofpbuf *
make_echo_reply(const struct ofp_header *rq)
{
    struct ofpbuf rq_buf = ofpbuf_const_initializer(rq, ntohs(rq->length));
    ofpraw_pull_assert(&rq_buf);

    struct ofpbuf *reply = ofpraw_alloc_reply(OFPRAW_OFPT_ECHO_REPLY,
                                              rq, rq_buf.size);
    ofpbuf_put(reply, rq_buf.data, rq_buf.size);
    return reply;
}

struct ofpbuf *
ofputil_encode_barrier_request(enum ofp_version ofp_version)
{
    enum ofpraw type;

    switch (ofp_version) {
    case OFP16_VERSION:
    case OFP15_VERSION:
    case OFP14_VERSION:
    case OFP13_VERSION:
    case OFP12_VERSION:
    case OFP11_VERSION:
        type = OFPRAW_OFPT11_BARRIER_REQUEST;
        break;

    case OFP10_VERSION:
        type = OFPRAW_OFPT10_BARRIER_REQUEST;
        break;

    default:
        OVS_NOT_REACHED();
    }

    return ofpraw_alloc(type, ofp_version, 0);
}

const char *
ofputil_frag_handling_to_string(enum ofputil_frag_handling frag)
{
    switch (frag) {
    case OFPUTIL_FRAG_NORMAL:   return "normal";
    case OFPUTIL_FRAG_DROP:     return "drop";
    case OFPUTIL_FRAG_REASM:    return "reassemble";
    case OFPUTIL_FRAG_NX_MATCH: return "nx-match";
    }

    OVS_NOT_REACHED();
}

bool
ofputil_frag_handling_from_string(const char *s,
                                  enum ofputil_frag_handling *frag)
{
    if (!strcasecmp(s, "normal")) {
        *frag = OFPUTIL_FRAG_NORMAL;
    } else if (!strcasecmp(s, "drop")) {
        *frag = OFPUTIL_FRAG_DROP;
    } else if (!strcasecmp(s, "reassemble")) {
        *frag = OFPUTIL_FRAG_REASM;
    } else if (!strcasecmp(s, "nx-match")) {
        *frag = OFPUTIL_FRAG_NX_MATCH;
    } else {
        return false;
    }
    return true;
}

/* Converts the OpenFlow 1.1+ port number 'ofp11_port' into an OpenFlow 1.0
 * port number and stores the latter in '*ofp10_port', for the purpose of
 * decoding OpenFlow 1.1+ protocol messages.  Returns 0 if successful,
 * otherwise an OFPERR_* number.  On error, stores OFPP_NONE in '*ofp10_port'.
 *
 * See the definition of OFP11_MAX for an explanation of the mapping. */
enum ofperr
ofputil_port_from_ofp11(ovs_be32 ofp11_port, ofp_port_t *ofp10_port)
{
    uint32_t ofp11_port_h = ntohl(ofp11_port);

    if (ofp11_port_h < ofp_to_u16(OFPP_MAX)) {
        *ofp10_port = u16_to_ofp(ofp11_port_h);
        return 0;
    } else if (ofp11_port_h >= ofp11_to_u32(OFPP11_MAX)) {
        *ofp10_port = u16_to_ofp(ofp11_port_h - OFPP11_OFFSET);
        return 0;
    } else {
        *ofp10_port = OFPP_NONE;
        VLOG_WARN_RL(&bad_ofmsg_rl, "port %"PRIu32" is outside the supported "
                     "range 0 through %d or 0x%"PRIx32" through 0x%"PRIx32,
                     ofp11_port_h, ofp_to_u16(OFPP_MAX) - 1,
                     ofp11_to_u32(OFPP11_MAX), UINT32_MAX);
        return OFPERR_OFPBAC_BAD_OUT_PORT;
    }
}

/* Returns the OpenFlow 1.1+ port number equivalent to the OpenFlow 1.0 port
 * number 'ofp10_port', for encoding OpenFlow 1.1+ protocol messages.
 *
 * See the definition of OFP11_MAX for an explanation of the mapping. */
ovs_be32
ofputil_port_to_ofp11(ofp_port_t ofp10_port)
{
    return htonl(ofp_to_u16(ofp10_port) < ofp_to_u16(OFPP_MAX)
                 ? ofp_to_u16(ofp10_port)
                 : ofp_to_u16(ofp10_port) + OFPP11_OFFSET);
}

#define OFPUTIL_NAMED_PORTS                     \
        OFPUTIL_NAMED_PORT(IN_PORT)             \
        OFPUTIL_NAMED_PORT(TABLE)               \
        OFPUTIL_NAMED_PORT(NORMAL)              \
        OFPUTIL_NAMED_PORT(FLOOD)               \
        OFPUTIL_NAMED_PORT(ALL)                 \
        OFPUTIL_NAMED_PORT(CONTROLLER)          \
        OFPUTIL_NAMED_PORT(LOCAL)               \
        OFPUTIL_NAMED_PORT(ANY)                 \
        OFPUTIL_NAMED_PORT(UNSET)

/* For backwards compatibility, so that "none" is recognized as OFPP_ANY */
#define OFPUTIL_NAMED_PORTS_WITH_NONE           \
        OFPUTIL_NAMED_PORTS                     \
        OFPUTIL_NAMED_PORT(NONE)

/* Stores the port number represented by 's' into '*portp'.  's' may be an
 * integer or, for reserved ports, the standard OpenFlow name for the port
 * (e.g. "LOCAL").  If 'port_map' is nonnull, also accepts names in it (quoted
 * or unquoted).
 *
 * Returns true if successful, false if 's' is not a valid OpenFlow port number
 * or name.  The caller should issue an error message in this case, because
 * this function usually does not.  (This gives the caller an opportunity to
 * look up the port name another way, e.g. by contacting the switch and listing
 * the names of all its ports).
 *
 * This function accepts OpenFlow 1.0 port numbers.  It also accepts a subset
 * of OpenFlow 1.1+ port numbers, mapping those port numbers into the 16-bit
 * range as described in include/openflow/openflow-1.1.h. */
bool
ofputil_port_from_string(const char *s,
                         const struct ofputil_port_map *port_map,
                         ofp_port_t *portp)
{
    unsigned int port32; /* int is at least 32 bits wide. */

    if (*s == '-') {
        VLOG_WARN("Negative value %s is not a valid port number.", s);
        return false;
    }
    *portp = 0;
    if (str_to_uint(s, 10, &port32)) {
        if (port32 < ofp_to_u16(OFPP_MAX)) {
            /* Pass. */
        } else if (port32 < ofp_to_u16(OFPP_FIRST_RESV)) {
            VLOG_WARN("port %u is a reserved OF1.0 port number that will "
                      "be translated to %u when talking to an OF1.1 or "
                      "later controller", port32, port32 + OFPP11_OFFSET);
        } else if (port32 <= ofp_to_u16(OFPP_LAST_RESV)) {
            char name[OFP10_MAX_PORT_NAME_LEN];

            ofputil_port_to_string(u16_to_ofp(port32), NULL,
                                   name, sizeof name);
            VLOG_WARN_ONCE("referring to port %s as %"PRIu32" is deprecated "
                           "for compatibility with OpenFlow 1.1 and later",
                           name, port32);
        } else if (port32 < ofp11_to_u32(OFPP11_MAX)) {
            VLOG_WARN("port %u is outside the supported range 0 through "
                      "%x or 0x%x through 0x%"PRIx32, port32,
                      UINT16_MAX, ofp11_to_u32(OFPP11_MAX), UINT32_MAX);
            return false;
        } else {
            port32 -= OFPP11_OFFSET;
        }

        *portp = u16_to_ofp(port32);
        return true;
    } else {
        struct pair {
            const char *name;
            ofp_port_t value;
        };
        static const struct pair pairs[] = {
#define OFPUTIL_NAMED_PORT(NAME) {#NAME, OFPP_##NAME},
            OFPUTIL_NAMED_PORTS_WITH_NONE
#undef OFPUTIL_NAMED_PORT
        };
        const struct pair *p;

        for (p = pairs; p < &pairs[ARRAY_SIZE(pairs)]; p++) {
            if (!strcasecmp(s, p->name)) {
                *portp = p->value;
                return true;
            }
        }

        ofp_port_t ofp_port = OFPP_NONE;
        if (s[0] != '"') {
            ofp_port = ofputil_port_map_get_number(port_map, s);
        } else {
            size_t length = strlen(s);
            char *name = NULL;
            if (length > 1
                && s[length - 1] == '"'
                && json_string_unescape(s + 1, length - 2, &name)) {
                ofp_port = ofputil_port_map_get_number(port_map, name);
            }
            free(name);
        }
        if (ofp_port != OFPP_NONE) {
            *portp = ofp_port;
            return true;
        }

        return false;
    }
}

const char *
ofputil_port_get_reserved_name(ofp_port_t port)
{
    switch (port) {
#define OFPUTIL_NAMED_PORT(NAME) case OFPP_##NAME: return #NAME;
        OFPUTIL_NAMED_PORTS
#undef OFPUTIL_NAMED_PORT

    default:
        return NULL;
    }
}

/* A port name doesn't need to be quoted if it is alphanumeric and starts with
 * a letter. */
static bool
port_name_needs_quotes(const char *port_name)
{
    if (!isalpha((unsigned char) port_name[0])) {
        return true;
    }

    for (const char *p = port_name + 1; *p; p++) {
        if (!isalnum((unsigned char) *p)) {
            return true;
        }
    }
    return false;
}

static void
put_port_name(const char *port_name, struct ds *s)
{
    if (port_name_needs_quotes(port_name)) {
        json_string_escape(port_name, s);
    } else {
        ds_put_cstr(s, port_name);
    }
}

/* Appends to 's' a string representation of the OpenFlow port number 'port'.
 * Most ports' string representation is just the port number, but for special
 * ports, e.g. OFPP_LOCAL, it is the name, e.g. "LOCAL". */
void
ofputil_format_port(ofp_port_t port, const struct ofputil_port_map *port_map,
                    struct ds *s)
{
    const char *reserved_name = ofputil_port_get_reserved_name(port);
    if (reserved_name) {
        ds_put_cstr(s, reserved_name);
        return;
    }

    const char *port_name = ofputil_port_map_get_name(port_map, port);
    if (port_name) {
        put_port_name(port_name, s);
        return;
    }

    ds_put_format(s, "%"PRIu32, port);
}

/* Puts in the 'bufsize' byte in 'namebuf' a null-terminated string
 * representation of OpenFlow port number 'port'.  Most ports are represented
 * as just the port number, but special ports, e.g. OFPP_LOCAL, are represented
 * by name, e.g. "LOCAL". */
void
ofputil_port_to_string(ofp_port_t port,
                       const struct ofputil_port_map *port_map,
                       char *namebuf, size_t bufsize)
{
    const char *reserved_name = ofputil_port_get_reserved_name(port);
    if (reserved_name) {
        ovs_strlcpy(namebuf, reserved_name, bufsize);
        return;
    }

    const char *port_name = ofputil_port_map_get_name(port_map, port);
    if (port_name) {
        struct ds s = DS_EMPTY_INITIALIZER;
        put_port_name(port_name, &s);
        ovs_strlcpy(namebuf, ds_cstr(&s), bufsize);
        ds_destroy(&s);
        return;
    }

    snprintf(namebuf, bufsize, "%"PRIu32, port);
}

/* ofputil_port_map.  */
struct ofputil_port_map_node {
    struct hmap_node name_node;
    struct hmap_node number_node;
    ofp_port_t ofp_port;        /* Port number. */
    char *name;                 /* Port name. */

    /* OpenFlow doesn't require port names to be unique, although that's the
     * only sensible way.  However, even in Open vSwitch it's possible for two
     * ports to appear to have the same name if their names are longer than the
     * maximum length supported by a given version of OpenFlow.  So, we guard
     * against duplicate names to avoid giving unexpected results in this
     * corner case.
     *
     * OpenFlow does require port numbers to be unique.  We check for duplicate
     * ports numbers just in case a switch has a bug. */
    bool duplicate;
};

void
ofputil_port_map_init(struct ofputil_port_map *map)
{
    hmap_init(&map->by_name);
    hmap_init(&map->by_number);
}

static struct ofputil_port_map_node *
ofputil_port_map_find_by_name(const struct ofputil_port_map *map,
                              const char *name)
{
    struct ofputil_port_map_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, name_node, hash_string(name, 0),
                             &map->by_name) {
        if (!strcmp(name, node->name)) {
            return node;
        }
    }
    return NULL;
}

static struct ofputil_port_map_node *
ofputil_port_map_find_by_number(const struct ofputil_port_map *map,
                                ofp_port_t ofp_port)
{
    struct ofputil_port_map_node *node;

    HMAP_FOR_EACH_IN_BUCKET (node, number_node, hash_ofp_port(ofp_port),
                             &map->by_number) {
        if (node->ofp_port == ofp_port) {
            return node;
        }
    }
    return NULL;
}

void
ofputil_port_map_put(struct ofputil_port_map *map,
                     ofp_port_t ofp_port, const char *name)
{
    struct ofputil_port_map_node *node;

    /* Look for duplicate name. */
    node = ofputil_port_map_find_by_name(map, name);
    if (node) {
        if (node->ofp_port != ofp_port) {
            node->duplicate = true;
        }
        return;
    }

    /* Look for duplicate number. */
    node = ofputil_port_map_find_by_number(map, ofp_port);
    if (node) {
        node->duplicate = true;
        return;
    }

    /* Add new node. */
    node = xmalloc(sizeof *node);
    hmap_insert(&map->by_number, &node->number_node, hash_ofp_port(ofp_port));
    hmap_insert(&map->by_name, &node->name_node, hash_string(name, 0));
    node->ofp_port = ofp_port;
    node->name = xstrdup(name);
    node->duplicate = false;
}

const char *
ofputil_port_map_get_name(const struct ofputil_port_map *map,
                          ofp_port_t ofp_port)
{
    struct ofputil_port_map_node *node
        = map ? ofputil_port_map_find_by_number(map, ofp_port) : NULL;
    return node && !node->duplicate ? node->name : NULL;
}

ofp_port_t
ofputil_port_map_get_number(const struct ofputil_port_map *map,
                            const char *name)
{
    struct ofputil_port_map_node *node
        = map ? ofputil_port_map_find_by_name(map, name) : NULL;
    return node && !node->duplicate ? node->ofp_port : OFPP_NONE;
}

void
ofputil_port_map_destroy(struct ofputil_port_map *map)
{
    if (map) {
        struct ofputil_port_map_node *node, *next;

        HMAP_FOR_EACH_SAFE (node, next, name_node, &map->by_name) {
            hmap_remove(&map->by_name, &node->name_node);
            hmap_remove(&map->by_number, &node->number_node);
            free(node->name);
            free(node);
        }
        hmap_destroy(&map->by_name);
        hmap_destroy(&map->by_number);
    }
}

/* Stores the group id represented by 's' into '*group_idp'.  's' may be an
 * integer or, for reserved group IDs, the standard OpenFlow name for the group
 * (either "ANY" or "ALL").
 *
 * Returns true if successful, false if 's' is not a valid OpenFlow group ID or
 * name. */
bool
ofputil_group_from_string(const char *s, uint32_t *group_idp)
{
    if (!strcasecmp(s, "any")) {
        *group_idp = OFPG_ANY;
    } else if (!strcasecmp(s, "all")) {
        *group_idp = OFPG_ALL;
    } else if (!str_to_uint(s, 10, group_idp)) {
        VLOG_WARN("%s is not a valid group ID.  (Valid group IDs are "
                  "32-bit nonnegative integers or the keywords ANY or "
                  "ALL.)", s);
        return false;
    }

    return true;
}

/* Appends to 's' a string representation of the OpenFlow group ID 'group_id'.
 * Most groups' string representation is just the number, but for special
 * groups, e.g. OFPG_ALL, it is the name, e.g. "ALL". */
void
ofputil_format_group(uint32_t group_id, struct ds *s)
{
    char name[MAX_GROUP_NAME_LEN];

    ofputil_group_to_string(group_id, name, sizeof name);
    ds_put_cstr(s, name);
}


/* Puts in the 'bufsize' byte in 'namebuf' a null-terminated string
 * representation of OpenFlow group ID 'group_id'.  Most group are represented
 * as just their number, but special groups, e.g. OFPG_ALL, are represented
 * by name, e.g. "ALL". */
void
ofputil_group_to_string(uint32_t group_id,
                        char namebuf[MAX_GROUP_NAME_LEN + 1], size_t bufsize)
{
    switch (group_id) {
    case OFPG_ALL:
        ovs_strlcpy(namebuf, "ALL", bufsize);
        break;

    case OFPG_ANY:
        ovs_strlcpy(namebuf, "ANY", bufsize);
        break;

    default:
        snprintf(namebuf, bufsize, "%"PRIu32, group_id);
        break;
    }
}

/* Given a buffer 'b' that contains an array of OpenFlow ports of type
 * 'ofp_version', tries to pull the first element from the array.  If
 * successful, initializes '*pp' with an abstract representation of the
 * port and returns 0.  If no ports remain to be decoded, returns EOF.
 * On an error, returns a positive OFPERR_* value. */
int
ofputil_pull_phy_port(enum ofp_version ofp_version, struct ofpbuf *b,
                      struct ofputil_phy_port *pp)
{
    memset(pp, 0, sizeof *pp);

    switch (ofp_version) {
    case OFP10_VERSION: {
        const struct ofp10_phy_port *opp = ofpbuf_try_pull(b, sizeof *opp);
        return opp ? ofputil_decode_ofp10_phy_port(pp, opp) : EOF;
    }
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        const struct ofp11_port *op = ofpbuf_try_pull(b, sizeof *op);
        return op ? ofputil_decode_ofp11_port(pp, op) : EOF;
    }
    case OFP14_VERSION:
    case OFP15_VERSION:
        return b->size ? ofputil_pull_ofp14_port(pp, b) : EOF;
    case OFP16_VERSION:
        return b->size ? ofputil_pull_ofp16_port(pp, b) : EOF;
    default:
        OVS_NOT_REACHED();
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
        bool log = may_log && !VLOG_DROP_INFO(&bad_ofmsg_rl);
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

static size_t
parse_value(const char *s, const char *delimiters)
{
    size_t n = 0;

    /* Iterate until we reach a delimiter.
     *
     * strchr(s, '\0') returns s+strlen(s), so this test handles the null
     * terminator at the end of 's'.  */
    while (!strchr(delimiters, s[n])) {
        if (s[n] == '(') {
            int level = 0;
            do {
                switch (s[n]) {
                case '\0':
                    return n;
                case '(':
                    level++;
                    break;
                case ')':
                    level--;
                    break;
                }
                n++;
            } while (level > 0);
        } else {
            n++;
        }
    }
    return n;
}

/* Parses a key or a key-value pair from '*stringp'.
 *
 * On success: Stores the key into '*keyp'.  Stores the value, if present, into
 * '*valuep', otherwise an empty string.  Advances '*stringp' past the end of
 * the key-value pair, preparing it for another call.  '*keyp' and '*valuep'
 * are substrings of '*stringp' created by replacing some of its bytes by null
 * terminators.  Returns true.
 *
 * If '*stringp' is just white space or commas, sets '*keyp' and '*valuep' to
 * NULL and returns false. */
bool
ofputil_parse_key_value(char **stringp, char **keyp, char **valuep)
{
    /* Skip white space and delimiters.  If that brings us to the end of the
     * input string, we are done and there are no more key-value pairs. */
    *stringp += strspn(*stringp, ", \t\r\n");
    if (**stringp == '\0') {
        *keyp = *valuep = NULL;
        return false;
    }

    /* Extract the key and the delimiter that ends the key-value pair or begins
     * the value.  Advance the input position past the key and delimiter. */
    char *key = *stringp;
    size_t key_len = strcspn(key, ":=(, \t\r\n");
    char key_delim = key[key_len];
    key[key_len] = '\0';
    *stringp += key_len + (key_delim != '\0');

    /* Figure out what delimiter ends the value:
     *
     *     - If key_delim is ":" or "=", the value extends until white space
     *       or a comma.
     *
     *     - If key_delim is "(", the value extends until ")".
     *
     * If there is no value, we are done. */
    const char *value_delims;
    if (key_delim == ':' || key_delim == '=') {
        value_delims = ", \t\r\n";
    } else if (key_delim == '(') {
        value_delims = ")";
    } else {
        *keyp = key;
        *valuep = key + key_len; /* Empty string. */
        return true;
    }

    /* Extract the value.  Advance the input position past the value and
     * delimiter. */
    char *value = *stringp;
    size_t value_len = parse_value(value, value_delims);
    char value_delim = value[value_len];
    value[value_len] = '\0';
    *stringp += value_len + (value_delim != '\0');

    *keyp = key;
    *valuep = value;
    return true;
}

/* Encode a dump ports request for 'port', the encoded message
 * will be for OpenFlow version 'ofp_version'. Returns message
 * as a struct ofpbuf. Returns encoded message on success, NULL on error */
struct ofpbuf *
ofputil_encode_dump_ports_request(enum ofp_version ofp_version, ofp_port_t port)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_port_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST10_PORT_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->port_no = htons(ofp_to_u16(port));
        break;
    }
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp11_port_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST11_PORT_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->port_no = ofputil_port_to_ofp11(port);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

static void
ofputil_port_stats_to_ofp10(const struct ofputil_port_stats *ops,
                            struct ofp10_port_stats *ps10)
{
    ps10->port_no = htons(ofp_to_u16(ops->port_no));
    memset(ps10->pad, 0, sizeof ps10->pad);
    put_32aligned_be64(&ps10->rx_packets, htonll(ops->stats.rx_packets));
    put_32aligned_be64(&ps10->tx_packets, htonll(ops->stats.tx_packets));
    put_32aligned_be64(&ps10->rx_bytes, htonll(ops->stats.rx_bytes));
    put_32aligned_be64(&ps10->tx_bytes, htonll(ops->stats.tx_bytes));
    put_32aligned_be64(&ps10->rx_dropped, htonll(ops->stats.rx_dropped));
    put_32aligned_be64(&ps10->tx_dropped, htonll(ops->stats.tx_dropped));
    put_32aligned_be64(&ps10->rx_errors, htonll(ops->stats.rx_errors));
    put_32aligned_be64(&ps10->tx_errors, htonll(ops->stats.tx_errors));
    put_32aligned_be64(&ps10->rx_frame_err, htonll(ops->stats.rx_frame_errors));
    put_32aligned_be64(&ps10->rx_over_err, htonll(ops->stats.rx_over_errors));
    put_32aligned_be64(&ps10->rx_crc_err, htonll(ops->stats.rx_crc_errors));
    put_32aligned_be64(&ps10->collisions, htonll(ops->stats.collisions));
}

static void
ofputil_port_stats_to_ofp11(const struct ofputil_port_stats *ops,
                            struct ofp11_port_stats *ps11)
{
    ps11->port_no = ofputil_port_to_ofp11(ops->port_no);
    memset(ps11->pad, 0, sizeof ps11->pad);
    ps11->rx_packets = htonll(ops->stats.rx_packets);
    ps11->tx_packets = htonll(ops->stats.tx_packets);
    ps11->rx_bytes = htonll(ops->stats.rx_bytes);
    ps11->tx_bytes = htonll(ops->stats.tx_bytes);
    ps11->rx_dropped = htonll(ops->stats.rx_dropped);
    ps11->tx_dropped = htonll(ops->stats.tx_dropped);
    ps11->rx_errors = htonll(ops->stats.rx_errors);
    ps11->tx_errors = htonll(ops->stats.tx_errors);
    ps11->rx_frame_err = htonll(ops->stats.rx_frame_errors);
    ps11->rx_over_err = htonll(ops->stats.rx_over_errors);
    ps11->rx_crc_err = htonll(ops->stats.rx_crc_errors);
    ps11->collisions = htonll(ops->stats.collisions);
}

static void
ofputil_port_stats_to_ofp13(const struct ofputil_port_stats *ops,
                            struct ofp13_port_stats *ps13)
{
    ofputil_port_stats_to_ofp11(ops, &ps13->ps);
    ps13->duration_sec = htonl(ops->duration_sec);
    ps13->duration_nsec = htonl(ops->duration_nsec);
}

static void
ofputil_append_ofp14_port_stats(const struct ofputil_port_stats *ops,
                                struct ovs_list *replies)
{
    struct ofp14_port_stats_prop_ethernet *eth;
    struct intel_port_stats_rfc2819 *stats_rfc2819;
    struct intel_port_custom_stats *stats_custom;
    struct ofp14_port_stats *ps14;
    struct ofpbuf *reply;
    uint16_t i;
    ovs_be64 counter_value;
    size_t custom_stats_start, start_ofs;

    reply = ofpbuf_from_list(ovs_list_back(replies));
    start_ofs = reply->size;

    ps14 = ofpbuf_put_uninit(reply, sizeof *ps14);

    memset(ps14->pad, 0, sizeof ps14->pad);
    ps14->port_no = ofputil_port_to_ofp11(ops->port_no);
    ps14->duration_sec = htonl(ops->duration_sec);
    ps14->duration_nsec = htonl(ops->duration_nsec);
    ps14->rx_packets = htonll(ops->stats.rx_packets);
    ps14->tx_packets = htonll(ops->stats.tx_packets);
    ps14->rx_bytes = htonll(ops->stats.rx_bytes);
    ps14->tx_bytes = htonll(ops->stats.tx_bytes);
    ps14->rx_dropped = htonll(ops->stats.rx_dropped);
    ps14->tx_dropped = htonll(ops->stats.tx_dropped);
    ps14->rx_errors = htonll(ops->stats.rx_errors);
    ps14->tx_errors = htonll(ops->stats.tx_errors);

    eth = ofpprop_put_zeros(reply, OFPPSPT14_ETHERNET, sizeof *eth);
    eth->rx_frame_err = htonll(ops->stats.rx_frame_errors);
    eth->rx_over_err = htonll(ops->stats.rx_over_errors);
    eth->rx_crc_err = htonll(ops->stats.rx_crc_errors);
    eth->collisions = htonll(ops->stats.collisions);

    uint64_t prop_type_stats = OFPPROP_EXP(INTEL_VENDOR_ID,
                                     INTEL_PORT_STATS_RFC2819);

    stats_rfc2819 = ofpprop_put_zeros(reply, prop_type_stats,
                                      sizeof *stats_rfc2819);

    memset(stats_rfc2819->pad, 0, sizeof stats_rfc2819->pad);
    stats_rfc2819->rx_1_to_64_packets = htonll(ops->stats.rx_1_to_64_packets);
    stats_rfc2819->rx_65_to_127_packets =
        htonll(ops->stats.rx_65_to_127_packets);
    stats_rfc2819->rx_128_to_255_packets =
        htonll(ops->stats.rx_128_to_255_packets);
    stats_rfc2819->rx_256_to_511_packets =
        htonll(ops->stats.rx_256_to_511_packets);
    stats_rfc2819->rx_512_to_1023_packets =
        htonll(ops->stats.rx_512_to_1023_packets);
    stats_rfc2819->rx_1024_to_1522_packets =
        htonll(ops->stats.rx_1024_to_1522_packets);
    stats_rfc2819->rx_1523_to_max_packets =
        htonll(ops->stats.rx_1523_to_max_packets);

    stats_rfc2819->tx_1_to_64_packets = htonll(ops->stats.tx_1_to_64_packets);
    stats_rfc2819->tx_65_to_127_packets =
        htonll(ops->stats.tx_65_to_127_packets);
    stats_rfc2819->tx_128_to_255_packets =
        htonll(ops->stats.tx_128_to_255_packets);
    stats_rfc2819->tx_256_to_511_packets =
        htonll(ops->stats.tx_256_to_511_packets);
    stats_rfc2819->tx_512_to_1023_packets =
        htonll(ops->stats.tx_512_to_1023_packets);
    stats_rfc2819->tx_1024_to_1522_packets =
        htonll(ops->stats.tx_1024_to_1522_packets);
    stats_rfc2819->tx_1523_to_max_packets =
        htonll(ops->stats.tx_1523_to_max_packets);

    stats_rfc2819->tx_multicast_packets =
        htonll(ops->stats.tx_multicast_packets);
    stats_rfc2819->rx_broadcast_packets =
        htonll(ops->stats.rx_broadcast_packets);
    stats_rfc2819->tx_broadcast_packets =
        htonll(ops->stats.tx_broadcast_packets);
    stats_rfc2819->rx_undersized_errors =
        htonll(ops->stats.rx_undersized_errors);
    stats_rfc2819->rx_oversize_errors =
        htonll(ops->stats.rx_oversize_errors);
    stats_rfc2819->rx_fragmented_errors =
        htonll(ops->stats.rx_fragmented_errors);
    stats_rfc2819->rx_jabber_errors =
        htonll(ops->stats.rx_jabber_errors);

    if (ops->custom_stats.counters && ops->custom_stats.size) {
        custom_stats_start = reply->size;

        uint64_t prop_type_custom = OFPPROP_EXP(INTEL_VENDOR_ID,
                                                INTEL_PORT_STATS_CUSTOM);

        stats_custom = ofpprop_put_zeros(reply, prop_type_custom,
                                         sizeof *stats_custom);

        stats_custom->stats_array_size = htons(ops->custom_stats.size);

        for (i = 0; i < ops->custom_stats.size; i++) {
            uint8_t counter_size = strlen(ops->custom_stats.counters[i].name);
            /* Counter name size */
            ofpbuf_put(reply, &counter_size, sizeof(counter_size));
            /* Counter name */
            ofpbuf_put(reply, ops->custom_stats.counters[i].name,
                       counter_size);
            /* Counter value */
            counter_value = htonll(ops->custom_stats.counters[i].value);
            ofpbuf_put(reply, &counter_value,
                       sizeof(ops->custom_stats.counters[i].value));
        }

        ofpprop_end(reply, custom_stats_start);
    }

    ps14 = ofpbuf_at_assert(reply, start_ofs, sizeof *ps14);
    ps14->length = htons(reply->size - start_ofs);

    ofpmp_postappend(replies, start_ofs);
}

/* Encode a ports stat for 'ops' and append it to 'replies'. */
void
ofputil_append_port_stat(struct ovs_list *replies,
                         const struct ofputil_port_stats *ops)
{
    switch (ofpmp_version(replies)) {
    case OFP13_VERSION: {
        struct ofp13_port_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_port_stats_to_ofp13(ops, reply);
        break;
    }
    case OFP12_VERSION:
    case OFP11_VERSION: {
        struct ofp11_port_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_port_stats_to_ofp11(ops, reply);
        break;
    }

    case OFP10_VERSION: {
        struct ofp10_port_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_port_stats_to_ofp10(ops, reply);
        break;
    }

    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        ofputil_append_ofp14_port_stats(ops, replies);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static enum ofperr
ofputil_port_stats_from_ofp10(struct ofputil_port_stats *ops,
                              const struct ofp10_port_stats *ps10)
{

    ops->port_no = u16_to_ofp(ntohs(ps10->port_no));
    ops->stats.rx_packets = ntohll(get_32aligned_be64(&ps10->rx_packets));
    ops->stats.tx_packets = ntohll(get_32aligned_be64(&ps10->tx_packets));
    ops->stats.rx_bytes = ntohll(get_32aligned_be64(&ps10->rx_bytes));
    ops->stats.tx_bytes = ntohll(get_32aligned_be64(&ps10->tx_bytes));
    ops->stats.rx_dropped = ntohll(get_32aligned_be64(&ps10->rx_dropped));
    ops->stats.tx_dropped = ntohll(get_32aligned_be64(&ps10->tx_dropped));
    ops->stats.rx_errors = ntohll(get_32aligned_be64(&ps10->rx_errors));
    ops->stats.tx_errors = ntohll(get_32aligned_be64(&ps10->tx_errors));
    ops->stats.rx_frame_errors =
        ntohll(get_32aligned_be64(&ps10->rx_frame_err));
    ops->stats.rx_over_errors = ntohll(get_32aligned_be64(&ps10->rx_over_err));
    ops->stats.rx_crc_errors = ntohll(get_32aligned_be64(&ps10->rx_crc_err));
    ops->stats.collisions = ntohll(get_32aligned_be64(&ps10->collisions));
    ops->duration_sec = ops->duration_nsec = UINT32_MAX;

    return 0;
}

static enum ofperr
ofputil_port_stats_from_ofp11(struct ofputil_port_stats *ops,
                              const struct ofp11_port_stats *ps11)
{
    enum ofperr error;

    error = ofputil_port_from_ofp11(ps11->port_no, &ops->port_no);
    if (error) {
        return error;
    }

    ops->stats.rx_packets = ntohll(ps11->rx_packets);
    ops->stats.tx_packets = ntohll(ps11->tx_packets);
    ops->stats.rx_bytes = ntohll(ps11->rx_bytes);
    ops->stats.tx_bytes = ntohll(ps11->tx_bytes);
    ops->stats.rx_dropped = ntohll(ps11->rx_dropped);
    ops->stats.tx_dropped = ntohll(ps11->tx_dropped);
    ops->stats.rx_errors = ntohll(ps11->rx_errors);
    ops->stats.tx_errors = ntohll(ps11->tx_errors);
    ops->stats.rx_frame_errors = ntohll(ps11->rx_frame_err);
    ops->stats.rx_over_errors = ntohll(ps11->rx_over_err);
    ops->stats.rx_crc_errors = ntohll(ps11->rx_crc_err);
    ops->stats.collisions = ntohll(ps11->collisions);
    ops->duration_sec = ops->duration_nsec = UINT32_MAX;

    return 0;
}

static enum ofperr
ofputil_port_stats_from_ofp13(struct ofputil_port_stats *ops,
                              const struct ofp13_port_stats *ps13)
{
    enum ofperr error = ofputil_port_stats_from_ofp11(ops, &ps13->ps);
    if (!error) {
        ops->duration_sec = ntohl(ps13->duration_sec);
        ops->duration_nsec = ntohl(ps13->duration_nsec);
    }
    return error;
}

static enum ofperr
parse_ofp14_port_stats_ethernet_property(const struct ofpbuf *payload,
                                         struct ofputil_port_stats *ops)
{
    const struct ofp14_port_stats_prop_ethernet *eth = payload->data;

    if (payload->size != sizeof *eth) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    ops->stats.rx_frame_errors = ntohll(eth->rx_frame_err);
    ops->stats.rx_over_errors = ntohll(eth->rx_over_err);
    ops->stats.rx_crc_errors = ntohll(eth->rx_crc_err);
    ops->stats.collisions = ntohll(eth->collisions);

    return 0;
}

static enum ofperr
parse_intel_port_stats_rfc2819_property(const struct ofpbuf *payload,
                                        struct ofputil_port_stats *ops)
{
    const struct intel_port_stats_rfc2819 *rfc2819 = payload->data;

    if (payload->size != sizeof *rfc2819) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    ops->stats.rx_1_to_64_packets = ntohll(rfc2819->rx_1_to_64_packets);
    ops->stats.rx_65_to_127_packets = ntohll(rfc2819->rx_65_to_127_packets);
    ops->stats.rx_128_to_255_packets = ntohll(rfc2819->rx_128_to_255_packets);
    ops->stats.rx_256_to_511_packets = ntohll(rfc2819->rx_256_to_511_packets);
    ops->stats.rx_512_to_1023_packets =
        ntohll(rfc2819->rx_512_to_1023_packets);
    ops->stats.rx_1024_to_1522_packets =
        ntohll(rfc2819->rx_1024_to_1522_packets);
    ops->stats.rx_1523_to_max_packets =
        ntohll(rfc2819->rx_1523_to_max_packets);

    ops->stats.tx_1_to_64_packets = ntohll(rfc2819->tx_1_to_64_packets);
    ops->stats.tx_65_to_127_packets = ntohll(rfc2819->tx_65_to_127_packets);
    ops->stats.tx_128_to_255_packets = ntohll(rfc2819->tx_128_to_255_packets);
    ops->stats.tx_256_to_511_packets = ntohll(rfc2819->tx_256_to_511_packets);
    ops->stats.tx_512_to_1023_packets =
        ntohll(rfc2819->tx_512_to_1023_packets);
    ops->stats.tx_1024_to_1522_packets =
        ntohll(rfc2819->tx_1024_to_1522_packets);
    ops->stats.tx_1523_to_max_packets =
        ntohll(rfc2819->tx_1523_to_max_packets);

    ops->stats.tx_multicast_packets = ntohll(rfc2819->tx_multicast_packets);
    ops->stats.rx_broadcast_packets = ntohll(rfc2819->rx_broadcast_packets);
    ops->stats.tx_broadcast_packets = ntohll(rfc2819->tx_broadcast_packets);
    ops->stats.rx_undersized_errors = ntohll(rfc2819->rx_undersized_errors);

    ops->stats.rx_oversize_errors = ntohll(rfc2819->rx_oversize_errors);
    ops->stats.rx_fragmented_errors = ntohll(rfc2819->rx_fragmented_errors);
    ops->stats.rx_jabber_errors = ntohll(rfc2819->rx_jabber_errors);

    return 0;
}

static enum ofperr
parse_intel_port_custom_property(const struct ofpbuf *payload,
                                 struct ofputil_port_stats *ops)
{
    const struct intel_port_custom_stats *custom_stats = payload->data;

    ops->custom_stats.size = ntohs(custom_stats->stats_array_size);

    ops->custom_stats.counters = xcalloc(ops->custom_stats.size,
                                         sizeof *ops->custom_stats.counters);

    uint16_t msg_size = ntohs(custom_stats->length);
    uint16_t current_len = sizeof *custom_stats;
    uint8_t *current = (uint8_t *)payload->data + current_len;
    uint8_t string_size = 0;
    uint8_t value_size = 0;
    ovs_be64 counter_value = 0;

    for (int i = 0; i < ops->custom_stats.size; i++) {
        current_len += string_size + value_size;
        current += string_size + value_size;

        value_size = sizeof(uint64_t);
        /* Counter name size */
        string_size = *current;

        /* Buffer overrun check */
        if (current_len + string_size + value_size > msg_size) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "Custom statistics buffer overrun! "
                         "Further message parsing is aborted.");
            break;
        }

        current++;
        current_len++;

        /* Counter name. */
        struct netdev_custom_counter *c = &ops->custom_stats.counters[i];
        size_t len = MIN(string_size, sizeof c->name - 1);
        memcpy(c->name, current, len);
        c->name[len] = '\0';
        memcpy(&counter_value, current + string_size, value_size);

        /* Counter value. */
        c->value = ntohll(counter_value);
    }

    return 0;
}

static enum ofperr
parse_intel_port_stats_property(const struct ofpbuf *payload,
                                uint32_t exp_type,
                                struct ofputil_port_stats *ops)
{
    enum ofperr error;

    switch (exp_type) {
    case INTEL_PORT_STATS_RFC2819:
        error = parse_intel_port_stats_rfc2819_property(payload, ops);
        break;
    case INTEL_PORT_STATS_CUSTOM:
        error = parse_intel_port_custom_property(payload, ops);
        break;
    default:
        error = OFPERR_OFPBPC_BAD_EXP_TYPE;
        break;
    }

    return error;
}

static enum ofperr
ofputil_pull_ofp14_port_stats(struct ofputil_port_stats *ops,
                              struct ofpbuf *msg)
{
    const struct ofp14_port_stats *ps14 = ofpbuf_try_pull(msg, sizeof *ps14);
    if (!ps14) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    size_t len = ntohs(ps14->length);
    if (len < sizeof *ps14 || len - sizeof *ps14 > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= sizeof *ps14;

    enum ofperr error = ofputil_port_from_ofp11(ps14->port_no, &ops->port_no);
    if (error) {
        return error;
    }

    ops->duration_sec = ntohl(ps14->duration_sec);
    ops->duration_nsec = ntohl(ps14->duration_nsec);
    ops->stats.rx_packets = ntohll(ps14->rx_packets);
    ops->stats.tx_packets = ntohll(ps14->tx_packets);
    ops->stats.rx_bytes = ntohll(ps14->rx_bytes);
    ops->stats.tx_bytes = ntohll(ps14->tx_bytes);
    ops->stats.rx_dropped = ntohll(ps14->rx_dropped);
    ops->stats.tx_dropped = ntohll(ps14->tx_dropped);
    ops->stats.rx_errors = ntohll(ps14->rx_errors);
    ops->stats.tx_errors = ntohll(ps14->tx_errors);


    struct ofpbuf properties = ofpbuf_const_initializer(ofpbuf_pull(msg, len),
                                                        len);
    while (properties.size > 0) {
        struct ofpbuf payload;
        uint64_t type = 0;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }
        switch (type) {
        case OFPPSPT14_ETHERNET:
            error = parse_ofp14_port_stats_ethernet_property(&payload, ops);
            break;
        case OFPPROP_EXP(INTEL_VENDOR_ID, INTEL_PORT_STATS_RFC2819):
            error = parse_intel_port_stats_property(&payload,
                                                    INTEL_PORT_STATS_RFC2819,
                                                    ops);
            break;
        case OFPPROP_EXP(INTEL_VENDOR_ID, INTEL_PORT_STATS_CUSTOM):
            error = parse_intel_port_stats_property(&payload,
                                                    INTEL_PORT_STATS_CUSTOM,
                                                    ops);
            break;
        default:
            error = OFPPROP_UNKNOWN(true, "port stats", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

/* Returns the number of port stats elements in OFPTYPE_PORT_STATS_REPLY
 * message 'oh'. */
size_t
ofputil_count_port_stats(const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    for (size_t n = 0; ; n++) {
        struct ofputil_port_stats ps;
        if (ofputil_decode_port_stats(&ps, &b)) {
            return n;
        }
    }
}

/* Converts an OFPST_PORT_STATS reply in 'msg' into an abstract
 * ofputil_port_stats in 'ps'.
 *
 * Multiple OFPST_PORT_STATS replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  The caller must initially leave 'msg''s layer pointers
 * null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_port_stats(struct ofputil_port_stats *ps, struct ofpbuf *msg)
{
    enum ofperr error;
    enum ofpraw raw;

    memset(&(ps->stats), 0xFF, sizeof (ps->stats));
    memset(&(ps->custom_stats), 0, sizeof (ps->custom_stats));

    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST14_PORT_REPLY) {
        return ofputil_pull_ofp14_port_stats(ps, msg);
    } else if (raw == OFPRAW_OFPST13_PORT_REPLY) {
        const struct ofp13_port_stats *ps13;
        ps13 = ofpbuf_try_pull(msg, sizeof *ps13);
        if (!ps13) {
            goto bad_len;
        }
        return ofputil_port_stats_from_ofp13(ps, ps13);
    } else if (raw == OFPRAW_OFPST11_PORT_REPLY) {
        const struct ofp11_port_stats *ps11;

        ps11 = ofpbuf_try_pull(msg, sizeof *ps11);
        if (!ps11) {
            goto bad_len;
        }
        return ofputil_port_stats_from_ofp11(ps, ps11);
    } else if (raw == OFPRAW_OFPST10_PORT_REPLY) {
        const struct ofp10_port_stats *ps10;

        ps10 = ofpbuf_try_pull(msg, sizeof *ps10);
        if (!ps10) {
            goto bad_len;
        }
        return ofputil_port_stats_from_ofp10(ps, ps10);
    } else {
        OVS_NOT_REACHED();
    }

 bad_len:
    VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_PORT reply has %"PRIu32" leftover "
                 "bytes at end", msg->size);
    return OFPERR_OFPBRC_BAD_LEN;
}

/* Parse a port status request message into a 16 bit OpenFlow 1.0
 * port number and stores the latter in '*ofp10_port'.
 * Returns 0 if successful, otherwise an OFPERR_* number. */
enum ofperr
ofputil_decode_port_stats_request(const struct ofp_header *request,
                                  ofp_port_t *ofp10_port)
{
    switch ((enum ofp_version)request->version) {
    case OFP16_VERSION:
    case OFP15_VERSION:
    case OFP14_VERSION:
    case OFP13_VERSION:
    case OFP12_VERSION:
    case OFP11_VERSION: {
        const struct ofp11_port_stats_request *psr11 = ofpmsg_body(request);
        return ofputil_port_from_ofp11(psr11->port_no, ofp10_port);
    }

    case OFP10_VERSION: {
        const struct ofp10_port_stats_request *psr10 = ofpmsg_body(request);
        *ofp10_port = u16_to_ofp(ntohs(psr10->port_no));
        return 0;
    }

    default:
        OVS_NOT_REACHED();
    }
}

static void
ofputil_ipfix_stats_to_reply(const struct ofputil_ipfix_stats *ois,
                            struct nx_ipfix_stats_reply *reply)
{
    reply->collector_set_id = htonl(ois->collector_set_id);
    reply->total_flows = htonll(ois->total_flows);
    reply->current_flows = htonll(ois->current_flows);
    reply->pkts = htonll(ois->pkts);
    reply->ipv4_pkts = htonll(ois->ipv4_pkts);
    reply->ipv6_pkts = htonll(ois->ipv6_pkts);
    reply->error_pkts = htonll(ois->error_pkts);
    reply->ipv4_error_pkts = htonll(ois->ipv4_error_pkts);
    reply->ipv6_error_pkts = htonll(ois->ipv6_error_pkts);
    reply->tx_pkts = htonll(ois->tx_pkts);
    reply->tx_errors = htonll(ois->tx_errors);
    memset(reply->pad, 0, sizeof reply->pad);
}

/* Encode a ipfix stat for 'ois' and append it to 'replies'. */
void
ofputil_append_ipfix_stat(struct ovs_list *replies,
                         const struct ofputil_ipfix_stats *ois)
{
    struct nx_ipfix_stats_reply *reply = ofpmp_append(replies, sizeof *reply);
    ofputil_ipfix_stats_to_reply(ois, reply);
}

static enum ofperr
ofputil_ipfix_stats_from_nx(struct ofputil_ipfix_stats *is,
                            const struct nx_ipfix_stats_reply *reply)
{
    is->collector_set_id = ntohl(reply->collector_set_id);
    is->total_flows = ntohll(reply->total_flows);
    is->current_flows = ntohll(reply->current_flows);
    is->pkts = ntohll(reply->pkts);
    is->ipv4_pkts = ntohll(reply->ipv4_pkts);
    is->ipv6_pkts = ntohll(reply->ipv6_pkts);
    is->error_pkts = ntohll(reply->error_pkts);
    is->ipv4_error_pkts = ntohll(reply->ipv4_error_pkts);
    is->ipv6_error_pkts = ntohll(reply->ipv6_error_pkts);
    is->tx_pkts = ntohll(reply->tx_pkts);
    is->tx_errors = ntohll(reply->tx_errors);

    return 0;
}

int
ofputil_pull_ipfix_stats(struct ofputil_ipfix_stats *is, struct ofpbuf *msg)
{
    enum ofperr error;
    enum ofpraw raw;

    memset(is, 0xFF, sizeof (*is));

    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_NXST_IPFIX_BRIDGE_REPLY ||
               raw == OFPRAW_NXST_IPFIX_FLOW_REPLY) {
        struct nx_ipfix_stats_reply *reply;

        reply = ofpbuf_try_pull(msg, sizeof *reply);
        return ofputil_ipfix_stats_from_nx(is, reply);
    } else {
        OVS_NOT_REACHED();
    }
}


/* Returns the number of ipfix stats elements in
 * OFPTYPE_IPFIX_BRIDGE_STATS_REPLY or OFPTYPE_IPFIX_FLOW_STATS_REPLY
 * message 'oh'. */
size_t
ofputil_count_ipfix_stats(const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    return b.size / sizeof(struct ofputil_ipfix_stats);
}

/* Frees all of the "struct ofputil_bucket"s in the 'buckets' list. */
void
ofputil_bucket_list_destroy(struct ovs_list *buckets)
{
    struct ofputil_bucket *bucket;

    LIST_FOR_EACH_POP (bucket, list_node, buckets) {
        free(bucket->ofpacts);
        free(bucket);
    }
}

/* Clones 'bucket' and its ofpacts data */
static struct ofputil_bucket *
ofputil_bucket_clone_data(const struct ofputil_bucket *bucket)
{
    struct ofputil_bucket *new;

    new = xmemdup(bucket, sizeof *bucket);
    new->ofpacts = xmemdup(bucket->ofpacts, bucket->ofpacts_len);

    return new;
}

/* Clones each of the buckets in the list 'src' appending them
 * in turn to 'dest' which should be an initialised list.
 * An exception is that if the pointer value of a bucket in 'src'
 * matches 'skip' then it is not cloned or appended to 'dest'.
 * This allows all of 'src' or 'all of 'src' except 'skip' to
 * be cloned and appended to 'dest'. */
void
ofputil_bucket_clone_list(struct ovs_list *dest, const struct ovs_list *src,
                          const struct ofputil_bucket *skip)
{
    struct ofputil_bucket *bucket;

    LIST_FOR_EACH (bucket, list_node, src) {
        struct ofputil_bucket *new_bucket;

        if (bucket == skip) {
            continue;
        }

        new_bucket = ofputil_bucket_clone_data(bucket);
        ovs_list_push_back(dest, &new_bucket->list_node);
    }
}

/* Find a bucket in the list 'buckets' whose bucket id is 'bucket_id'
 * Returns the first bucket found or NULL if no buckets are found. */
struct ofputil_bucket *
ofputil_bucket_find(const struct ovs_list *buckets, uint32_t bucket_id)
{
    struct ofputil_bucket *bucket;

    if (bucket_id > OFPG15_BUCKET_MAX) {
        return NULL;
    }

    LIST_FOR_EACH (bucket, list_node, buckets) {
        if (bucket->bucket_id == bucket_id) {
            return bucket;
        }
    }

    return NULL;
}

/* Returns true if more than one bucket in the list 'buckets'
 * have the same bucket id. Returns false otherwise. */
bool
ofputil_bucket_check_duplicate_id(const struct ovs_list *buckets)
{
    struct ofputil_bucket *i, *j;

    LIST_FOR_EACH (i, list_node, buckets) {
        LIST_FOR_EACH_REVERSE (j, list_node, buckets) {
            if (i == j) {
                break;
            }
            if (i->bucket_id == j->bucket_id) {
                return true;
            }
        }
    }

    return false;
}

/* Returns the bucket at the front of the list 'buckets'.
 * Undefined if 'buckets is empty. */
struct ofputil_bucket *
ofputil_bucket_list_front(const struct ovs_list *buckets)
{
    static struct ofputil_bucket *bucket;

    ASSIGN_CONTAINER(bucket, ovs_list_front(buckets), list_node);

    return bucket;
}

/* Returns the bucket at the back of the list 'buckets'.
 * Undefined if 'buckets is empty. */
struct ofputil_bucket *
ofputil_bucket_list_back(const struct ovs_list *buckets)
{
    static struct ofputil_bucket *bucket;

    ASSIGN_CONTAINER(bucket, ovs_list_back(buckets), list_node);

    return bucket;
}

/* Returns an OpenFlow group stats request for OpenFlow version 'ofp_version',
 * that requests stats for group 'group_id'.  (Use OFPG_ALL to request stats
 * for all groups.)
 *
 * Group statistics include packet and byte counts for each group. */
struct ofpbuf *
ofputil_encode_group_stats_request(enum ofp_version ofp_version,
                                   uint32_t group_id)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION:
        ovs_fatal(0, "dump-group-stats needs OpenFlow 1.1 or later "
                     "(\'-O OpenFlow11\')");
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp11_group_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST11_GROUP_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->group_id = htonl(group_id);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

void
ofputil_uninit_group_desc(struct ofputil_group_desc *gd)
{
    ofputil_bucket_list_destroy(&gd->buckets);
    ofputil_group_properties_destroy(&gd->props);
}

/* Decodes the OpenFlow group description request in 'oh', returning the group
 * whose description is requested, or OFPG_ALL if stats for all groups was
 * requested. */
uint32_t
ofputil_decode_group_desc_request(const struct ofp_header *oh)
{
    struct ofpbuf request = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&request);
    if (raw == OFPRAW_OFPST11_GROUP_DESC_REQUEST) {
        return OFPG_ALL;
    } else if (raw == OFPRAW_OFPST15_GROUP_DESC_REQUEST) {
        ovs_be32 *group_id = ofpbuf_pull(&request, sizeof *group_id);
        return ntohl(*group_id);
    } else {
        OVS_NOT_REACHED();
    }
}

/* Returns an OpenFlow group description request for OpenFlow version
 * 'ofp_version', that requests stats for group 'group_id'.  Use OFPG_ALL to
 * request stats for all groups (OpenFlow 1.4 and earlier always request all
 * groups).
 *
 * Group descriptions include the bucket and action configuration for each
 * group. */
struct ofpbuf *
ofputil_encode_group_desc_request(enum ofp_version ofp_version,
                                  uint32_t group_id)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION:
        ovs_fatal(0, "dump-groups needs OpenFlow 1.1 or later "
                     "(\'-O OpenFlow11\')");
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        request = ofpraw_alloc(OFPRAW_OFPST11_GROUP_DESC_REQUEST,
                               ofp_version, 0);
        break;
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp15_group_desc_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST15_GROUP_DESC_REQUEST,
                               ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->group_id = htonl(group_id);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

static void
ofputil_group_bucket_counters_to_ofp11(const struct ofputil_group_stats *gs,
                                    struct ofp11_bucket_counter bucket_cnts[])
{
    int i;

    for (i = 0; i < gs->n_buckets; i++) {
       bucket_cnts[i].packet_count = htonll(gs->bucket_stats[i].packet_count);
       bucket_cnts[i].byte_count = htonll(gs->bucket_stats[i].byte_count);
    }
}

static void
ofputil_group_stats_to_ofp11(const struct ofputil_group_stats *gs,
                             struct ofp11_group_stats *gs11, size_t length,
                             struct ofp11_bucket_counter bucket_cnts[])
{
    memset(gs11, 0, sizeof *gs11);
    gs11->length = htons(length);
    gs11->group_id = htonl(gs->group_id);
    gs11->ref_count = htonl(gs->ref_count);
    gs11->packet_count = htonll(gs->packet_count);
    gs11->byte_count = htonll(gs->byte_count);
    ofputil_group_bucket_counters_to_ofp11(gs, bucket_cnts);
}

static void
ofputil_group_stats_to_ofp13(const struct ofputil_group_stats *gs,
                             struct ofp13_group_stats *gs13, size_t length,
                             struct ofp11_bucket_counter bucket_cnts[])
{
    ofputil_group_stats_to_ofp11(gs, &gs13->gs, length, bucket_cnts);
    gs13->duration_sec = htonl(gs->duration_sec);
    gs13->duration_nsec = htonl(gs->duration_nsec);

}

/* Encodes 'gs' properly for the format of the list of group statistics
 * replies already begun in 'replies' and appends it to the list.  'replies'
 * must have originally been initialized with ofpmp_init(). */
void
ofputil_append_group_stats(struct ovs_list *replies,
                           const struct ofputil_group_stats *gs)
{
    size_t bucket_counter_size;
    struct ofp11_bucket_counter *bucket_counters;
    size_t length;

    bucket_counter_size = gs->n_buckets * sizeof(struct ofp11_bucket_counter);

    switch (ofpmp_version(replies)) {
    case OFP11_VERSION:
    case OFP12_VERSION:{
            struct ofp11_group_stats *gs11;

            length = sizeof *gs11 + bucket_counter_size;
            gs11 = ofpmp_append(replies, length);
            bucket_counters = (struct ofp11_bucket_counter *)(gs11 + 1);
            ofputil_group_stats_to_ofp11(gs, gs11, length, bucket_counters);
            break;
        }

    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
            struct ofp13_group_stats *gs13;

            length = sizeof *gs13 + bucket_counter_size;
            gs13 = ofpmp_append(replies, length);
            bucket_counters = (struct ofp11_bucket_counter *)(gs13 + 1);
            ofputil_group_stats_to_ofp13(gs, gs13, length, bucket_counters);
            break;
        }

    case OFP10_VERSION:
    default:
        OVS_NOT_REACHED();
    }
}
/* Returns an OpenFlow group features request for OpenFlow version
 * 'ofp_version'. */
struct ofpbuf *
ofputil_encode_group_features_request(enum ofp_version ofp_version)
{
    struct ofpbuf *request = NULL;

    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
        ovs_fatal(0, "dump-group-features needs OpenFlow 1.2 or later "
                     "(\'-O OpenFlow12\')");
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        request = ofpraw_alloc(OFPRAW_OFPST12_GROUP_FEATURES_REQUEST,
                               ofp_version, 0);
        break;
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

/* Returns a OpenFlow message that encodes 'features' properly as a reply to
 * group features request 'request'. */
struct ofpbuf *
ofputil_encode_group_features_reply(
    const struct ofputil_group_features *features,
    const struct ofp_header *request)
{
    struct ofp12_group_features_stats *ogf;
    struct ofpbuf *reply;
    int i;

    reply = ofpraw_alloc_xid(OFPRAW_OFPST12_GROUP_FEATURES_REPLY,
                             request->version, request->xid, 0);
    ogf = ofpbuf_put_zeros(reply, sizeof *ogf);
    ogf->types = htonl(features->types);
    ogf->capabilities = htonl(features->capabilities);
    for (i = 0; i < OFPGT12_N_TYPES; i++) {
        ogf->max_groups[i] = htonl(features->max_groups[i]);
        ogf->actions[i] = ofpact_bitmap_to_openflow(features->ofpacts[i],
                                                    request->version);
    }

    return reply;
}

/* Decodes group features reply 'oh' into 'features'. */
void
ofputil_decode_group_features_reply(const struct ofp_header *oh,
                                    struct ofputil_group_features *features)
{
    const struct ofp12_group_features_stats *ogf = ofpmsg_body(oh);
    int i;

    features->types = ntohl(ogf->types);
    features->capabilities = ntohl(ogf->capabilities);
    for (i = 0; i < OFPGT12_N_TYPES; i++) {
        features->max_groups[i] = ntohl(ogf->max_groups[i]);
        features->ofpacts[i] = ofpact_bitmap_from_openflow(
            ogf->actions[i], oh->version);
    }
}

/* Parse a group status request message into a 32 bit OpenFlow 1.1
 * group ID and stores the latter in '*group_id'.
 * Returns 0 if successful, otherwise an OFPERR_* number. */
enum ofperr
ofputil_decode_group_stats_request(const struct ofp_header *request,
                                   uint32_t *group_id)
{
    const struct ofp11_group_stats_request *gsr11 = ofpmsg_body(request);
    *group_id = ntohl(gsr11->group_id);
    return 0;
}

/* Converts a group stats reply in 'msg' into an abstract ofputil_group_stats
 * in 'gs'.  Assigns freshly allocated memory to gs->bucket_stats for the
 * caller to eventually free.
 *
 * Multiple group stats replies can be packed into a single OpenFlow message.
 * Calling this function multiple times for a single 'msg' iterates through the
 * replies.  The caller must initially leave 'msg''s layer pointers null and
 * not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_group_stats_reply(struct ofpbuf *msg,
                                 struct ofputil_group_stats *gs)
{
    struct ofp11_bucket_counter *obc;
    struct ofp11_group_stats *ogs11;
    enum ofpraw raw;
    enum ofperr error;
    size_t base_len;
    size_t length;
    size_t i;

    gs->bucket_stats = NULL;
    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
    }

    if (raw == OFPRAW_OFPST11_GROUP_REPLY) {
        base_len = sizeof *ogs11;
        ogs11 = ofpbuf_try_pull(msg, sizeof *ogs11);
        gs->duration_sec = gs->duration_nsec = UINT32_MAX;
    } else if (raw == OFPRAW_OFPST13_GROUP_REPLY) {
        struct ofp13_group_stats *ogs13;

        base_len = sizeof *ogs13;
        ogs13 = ofpbuf_try_pull(msg, sizeof *ogs13);
        if (ogs13) {
            ogs11 = &ogs13->gs;
            gs->duration_sec = ntohl(ogs13->duration_sec);
            gs->duration_nsec = ntohl(ogs13->duration_nsec);
        } else {
            ogs11 = NULL;
        }
    } else {
        OVS_NOT_REACHED();
    }

    if (!ogs11) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "%s reply has %"PRIu32" leftover bytes at end",
                     ofpraw_get_name(raw), msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    length = ntohs(ogs11->length);
    if (length < sizeof base_len) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "%s reply claims invalid length %"PRIuSIZE,
                     ofpraw_get_name(raw), length);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    gs->group_id = ntohl(ogs11->group_id);
    gs->ref_count = ntohl(ogs11->ref_count);
    gs->packet_count = ntohll(ogs11->packet_count);
    gs->byte_count = ntohll(ogs11->byte_count);

    gs->n_buckets = (length - base_len) / sizeof *obc;
    obc = ofpbuf_try_pull(msg, gs->n_buckets * sizeof *obc);
    if (!obc) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "%s reply has %"PRIu32" leftover bytes at end",
                     ofpraw_get_name(raw), msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    gs->bucket_stats = xmalloc(gs->n_buckets * sizeof *gs->bucket_stats);
    for (i = 0; i < gs->n_buckets; i++) {
        gs->bucket_stats[i].packet_count = ntohll(obc[i].packet_count);
        gs->bucket_stats[i].byte_count = ntohll(obc[i].byte_count);
    }

    return 0;
}

static void
ofputil_put_ofp11_bucket(const struct ofputil_bucket *bucket,
                         struct ofpbuf *openflow, enum ofp_version ofp_version)
{
    struct ofp11_bucket *ob;
    size_t start;

    start = openflow->size;
    ofpbuf_put_zeros(openflow, sizeof *ob);
    ofpacts_put_openflow_actions(bucket->ofpacts, bucket->ofpacts_len,
                                openflow, ofp_version);
    ob = ofpbuf_at_assert(openflow, start, sizeof *ob);
    ob->len = htons(openflow->size - start);
    ob->weight = htons(bucket->weight);
    ob->watch_port = ofputil_port_to_ofp11(bucket->watch_port);
    ob->watch_group = htonl(bucket->watch_group);
}

static void
ofputil_put_ofp15_bucket(const struct ofputil_bucket *bucket,
                         uint32_t bucket_id, enum ofp11_group_type group_type,
                         struct ofpbuf *openflow, enum ofp_version ofp_version)
{
    struct ofp15_bucket *ob;
    size_t start, actions_start, actions_len;

    start = openflow->size;
    ofpbuf_put_zeros(openflow, sizeof *ob);

    actions_start = openflow->size;
    ofpacts_put_openflow_actions(bucket->ofpacts, bucket->ofpacts_len,
                                 openflow, ofp_version);
    actions_len = openflow->size - actions_start;

    if (group_type == OFPGT11_SELECT) {
        ofpprop_put_u16(openflow, OFPGBPT15_WEIGHT, bucket->weight);
    }
    if (bucket->watch_port != OFPP_ANY) {
        ofpprop_put_be32(openflow, OFPGBPT15_WATCH_PORT,
                         ofputil_port_to_ofp11(bucket->watch_port));
    }
    if (bucket->watch_group != OFPG_ANY) {
        ofpprop_put_u32(openflow, OFPGBPT15_WATCH_GROUP, bucket->watch_group);
    }

    ob = ofpbuf_at_assert(openflow, start, sizeof *ob);
    ob->len = htons(openflow->size - start);
    ob->action_array_len = htons(actions_len);
    ob->bucket_id = htonl(bucket_id);
}

static void
ofputil_put_group_prop_ntr_selection_method(enum ofp_version ofp_version,
                                            const struct ofputil_group_props *gp,
                                            struct ofpbuf *openflow)
{
    struct ntr_group_prop_selection_method *prop;
    size_t start;

    start = openflow->size;
    ofpbuf_put_zeros(openflow, sizeof *prop);
    oxm_put_field_array(openflow, &gp->fields, ofp_version);
    prop = ofpbuf_at_assert(openflow, start, sizeof *prop);
    prop->type = htons(OFPGPT15_EXPERIMENTER);
    prop->experimenter = htonl(NTR_VENDOR_ID);
    prop->exp_type = htonl(NTRT_SELECTION_METHOD);
    strcpy(prop->selection_method, gp->selection_method);
    prop->selection_method_param = htonll(gp->selection_method_param);
    ofpprop_end(openflow, start);
}

static void
ofputil_append_ofp11_group_desc_reply(const struct ofputil_group_desc *gds,
                                      const struct ovs_list *buckets,
                                      struct ovs_list *replies,
                                      enum ofp_version version)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    struct ofp11_group_desc_stats *ogds;
    struct ofputil_bucket *bucket;
    size_t start_ogds;

    start_ogds = reply->size;
    ofpbuf_put_zeros(reply, sizeof *ogds);
    LIST_FOR_EACH (bucket, list_node, buckets) {
        ofputil_put_ofp11_bucket(bucket, reply, version);
    }
    ogds = ofpbuf_at_assert(reply, start_ogds, sizeof *ogds);
    ogds->length = htons(reply->size - start_ogds);
    ogds->type = gds->type;
    ogds->group_id = htonl(gds->group_id);

    ofpmp_postappend(replies, start_ogds);
}

static void
ofputil_append_ofp15_group_desc_reply(const struct ofputil_group_desc *gds,
                                      const struct ovs_list *buckets,
                                      struct ovs_list *replies,
                                      enum ofp_version version)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    struct ofp15_group_desc_stats *ogds;
    struct ofputil_bucket *bucket;
    size_t start_ogds, start_buckets;

    start_ogds = reply->size;
    ofpbuf_put_zeros(reply, sizeof *ogds);
    start_buckets = reply->size;
    LIST_FOR_EACH (bucket, list_node, buckets) {
        ofputil_put_ofp15_bucket(bucket, bucket->bucket_id,
                                 gds->type, reply, version);
    }
    ogds = ofpbuf_at_assert(reply, start_ogds, sizeof *ogds);
    ogds->type = gds->type;
    ogds->group_id = htonl(gds->group_id);
    ogds->bucket_list_len =  htons(reply->size - start_buckets);

    /* Add group properties */
    if (gds->props.selection_method[0]) {
        ofputil_put_group_prop_ntr_selection_method(version, &gds->props,
                                                    reply);
    }
    ogds = ofpbuf_at_assert(reply, start_ogds, sizeof *ogds);
    ogds->length = htons(reply->size - start_ogds);

    ofpmp_postappend(replies, start_ogds);
}

/* Appends a group stats reply that contains the data in 'gds' to those already
 * present in the list of ofpbufs in 'replies'.  'replies' should have been
 * initialized with ofpmp_init(). */
void
ofputil_append_group_desc_reply(const struct ofputil_group_desc *gds,
                                const struct ovs_list *buckets,
                                struct ovs_list *replies)
{
    enum ofp_version version = ofpmp_version(replies);

    switch (version)
    {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        ofputil_append_ofp11_group_desc_reply(gds, buckets, replies, version);
        break;

    case OFP15_VERSION:
    case OFP16_VERSION:
        ofputil_append_ofp15_group_desc_reply(gds, buckets, replies, version);
        break;

    case OFP10_VERSION:
    default:
        OVS_NOT_REACHED();
    }
}

static enum ofperr
ofputil_pull_ofp11_buckets(struct ofpbuf *msg, size_t buckets_length,
                           enum ofp_version version, struct ovs_list *buckets)
{
    struct ofp11_bucket *ob;
    uint32_t bucket_id = 0;

    ovs_list_init(buckets);
    while (buckets_length > 0) {
        struct ofputil_bucket *bucket;
        struct ofpbuf ofpacts;
        enum ofperr error;
        size_t ob_len;

        ob = (buckets_length >= sizeof *ob
              ? ofpbuf_try_pull(msg, sizeof *ob)
              : NULL);
        if (!ob) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "buckets end with %"PRIuSIZE" leftover bytes",
                         buckets_length);
            ofputil_bucket_list_destroy(buckets);
            return OFPERR_OFPGMFC_BAD_BUCKET;
        }

        ob_len = ntohs(ob->len);
        if (ob_len < sizeof *ob) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" is not valid", ob_len);
            ofputil_bucket_list_destroy(buckets);
            return OFPERR_OFPGMFC_BAD_BUCKET;
        } else if (ob_len > buckets_length) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" exceeds remaining buckets data size %"PRIuSIZE,
                         ob_len, buckets_length);
            ofputil_bucket_list_destroy(buckets);
            return OFPERR_OFPGMFC_BAD_BUCKET;
        }
        buckets_length -= ob_len;

        ofpbuf_init(&ofpacts, 0);
        error = ofpacts_pull_openflow_actions(msg, ob_len - sizeof *ob,
                                              version, NULL, NULL, &ofpacts);
        if (error) {
            ofpbuf_uninit(&ofpacts);
            ofputil_bucket_list_destroy(buckets);
            return error;
        }

        bucket = xzalloc(sizeof *bucket);
        bucket->weight = ntohs(ob->weight);
        error = ofputil_port_from_ofp11(ob->watch_port, &bucket->watch_port);
        if (error) {
            ofpbuf_uninit(&ofpacts);
            ofputil_bucket_list_destroy(buckets);
            free(bucket);
            return OFPERR_OFPGMFC_BAD_WATCH;
        }
        bucket->watch_group = ntohl(ob->watch_group);
        bucket->bucket_id = bucket_id++;

        bucket->ofpacts = ofpbuf_steal_data(&ofpacts);
        bucket->ofpacts_len = ofpacts.size;
        ovs_list_push_back(buckets, &bucket->list_node);
    }

    return 0;
}

static enum ofperr
ofputil_pull_ofp15_buckets(struct ofpbuf *msg, size_t buckets_length,
                           enum ofp_version version, uint8_t group_type,
                           struct ovs_list *buckets)
{
    struct ofp15_bucket *ob;

    ovs_list_init(buckets);
    while (buckets_length > 0) {
        struct ofputil_bucket *bucket = NULL;
        struct ofpbuf ofpacts;
        enum ofperr err = OFPERR_OFPGMFC_BAD_BUCKET;
        size_t ob_len, actions_len, properties_len;
        ovs_be32 watch_port = ofputil_port_to_ofp11(OFPP_ANY);
        ovs_be32 watch_group = htonl(OFPG_ANY);
        ovs_be16 weight = htons(group_type == OFPGT11_SELECT ? 1 : 0);

        ofpbuf_init(&ofpacts, 0);

        ob = ofpbuf_try_pull(msg, sizeof *ob);
        if (!ob) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "buckets end with %"PRIuSIZE
                         " leftover bytes", buckets_length);
            goto err;
        }

        ob_len = ntohs(ob->len);
        actions_len = ntohs(ob->action_array_len);

        if (ob_len < sizeof *ob) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" is not valid", ob_len);
            goto err;
        } else if (ob_len > buckets_length) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" exceeds remaining buckets data size %"
                         PRIuSIZE, ob_len, buckets_length);
            goto err;
        } else if (actions_len > ob_len - sizeof *ob) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message bucket actions "
                         "length %"PRIuSIZE" exceeds remaining bucket "
                         "data size %"PRIuSIZE, actions_len,
                         ob_len - sizeof *ob);
            goto err;
        }
        buckets_length -= ob_len;

        err = ofpacts_pull_openflow_actions(msg, actions_len, version,
                                            NULL, NULL, &ofpacts);
        if (err) {
            goto err;
        }

        properties_len = ob_len - sizeof *ob - actions_len;
        struct ofpbuf properties = ofpbuf_const_initializer(
            ofpbuf_pull(msg, properties_len), properties_len);
        while (properties.size > 0) {
            struct ofpbuf payload;
            uint64_t type;

            err = ofpprop_pull(&properties, &payload, &type);
            if (err) {
                goto err;
            }

            switch (type) {
            case OFPGBPT15_WEIGHT:
                err = ofpprop_parse_be16(&payload, &weight);
                break;

            case OFPGBPT15_WATCH_PORT:
                err = ofpprop_parse_be32(&payload, &watch_port);
                break;

            case OFPGBPT15_WATCH_GROUP:
                err = ofpprop_parse_be32(&payload, &watch_group);
                break;

            default:
                err = OFPPROP_UNKNOWN(false, "group bucket", type);
                break;
            }

            if (err) {
                goto err;
            }
        }

        bucket = xzalloc(sizeof *bucket);

        bucket->weight = ntohs(weight);
        err = ofputil_port_from_ofp11(watch_port, &bucket->watch_port);
        if (err) {
            err = OFPERR_OFPGMFC_BAD_WATCH;
            goto err;
        }
        bucket->watch_group = ntohl(watch_group);
        bucket->bucket_id = ntohl(ob->bucket_id);
        if (bucket->bucket_id > OFPG15_BUCKET_MAX) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "bucket id (%u) is out of range",
                         bucket->bucket_id);
            err = OFPERR_OFPGMFC_BAD_BUCKET;
            goto err;
        }

        bucket->ofpacts = ofpbuf_steal_data(&ofpacts);
        bucket->ofpacts_len = ofpacts.size;
        ovs_list_push_back(buckets, &bucket->list_node);

        continue;

    err:
        free(bucket);
        ofpbuf_uninit(&ofpacts);
        ofputil_bucket_list_destroy(buckets);
        return err;
    }

    if (ofputil_bucket_check_duplicate_id(buckets)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "Duplicate bucket id");
        ofputil_bucket_list_destroy(buckets);
        return OFPERR_OFPGMFC_BAD_BUCKET;
    }

    return 0;
}

static void
ofputil_init_group_properties(struct ofputil_group_props *gp)
{
    memset(gp, 0, sizeof *gp);
}

void
ofputil_group_properties_copy(struct ofputil_group_props *to,
                              const struct ofputil_group_props *from)
{
    *to = *from;
    to->fields.values = xmemdup(from->fields.values, from->fields.values_size);
}

void
ofputil_group_properties_destroy(struct ofputil_group_props *gp)
{
    free(gp->fields.values);
}

static enum ofperr
parse_group_prop_ntr_selection_method(struct ofpbuf *payload,
                                      enum ofp11_group_type group_type,
                                      enum ofp15_group_mod_command group_cmd,
                                      struct ofputil_group_props *gp)
{
    struct ntr_group_prop_selection_method *prop = payload->data;
    size_t fields_len, method_len;
    enum ofperr error;

    switch (group_type) {
    case OFPGT11_SELECT:
        break;
    case OFPGT11_ALL:
    case OFPGT11_INDIRECT:
    case OFPGT11_FF:
        OFPPROP_LOG(&bad_ofmsg_rl, false, "ntr selection method property is "
                    "only allowed for select groups");
        return OFPERR_OFPBPC_BAD_VALUE;
    default:
        OVS_NOT_REACHED();
    }

    switch (group_cmd) {
    case OFPGC15_ADD:
    case OFPGC15_MODIFY:
    case OFPGC15_ADD_OR_MOD:
        break;
    case OFPGC15_DELETE:
    case OFPGC15_INSERT_BUCKET:
    case OFPGC15_REMOVE_BUCKET:
        OFPPROP_LOG(&bad_ofmsg_rl, false, "ntr selection method property is "
                    "only allowed for add and delete group modifications");
        return OFPERR_OFPBPC_BAD_VALUE;
    default:
        OVS_NOT_REACHED();
    }

    if (payload->size < sizeof *prop) {
        OFPPROP_LOG(&bad_ofmsg_rl, false, "ntr selection method property "
                    "length %u is not valid", payload->size);
        return OFPERR_OFPBPC_BAD_LEN;
    }

    method_len = strnlen(prop->selection_method, NTR_MAX_SELECTION_METHOD_LEN);

    if (method_len == NTR_MAX_SELECTION_METHOD_LEN) {
        OFPPROP_LOG(&bad_ofmsg_rl, false,
                    "ntr selection method is not null terminated");
        return OFPERR_OFPBPC_BAD_VALUE;
    }

    if (strcmp("hash", prop->selection_method)
        && strcmp("dp_hash", prop->selection_method)) {
        OFPPROP_LOG(&bad_ofmsg_rl, false,
                    "ntr selection method '%s' is not supported",
                    prop->selection_method);
        return OFPERR_OFPBPC_BAD_VALUE;
    }
    /* 'method_len' is now non-zero. */

    strcpy(gp->selection_method, prop->selection_method);
    gp->selection_method_param = ntohll(prop->selection_method_param);

    ofpbuf_pull(payload, sizeof *prop);

    fields_len = ntohs(prop->length) - sizeof *prop;
    if (fields_len && strcmp("hash", gp->selection_method)) {
        OFPPROP_LOG(&bad_ofmsg_rl, false, "ntr selection method %s "
                    "does not support fields", gp->selection_method);
        return OFPERR_OFPBPC_BAD_VALUE;
    }

    error = oxm_pull_field_array(payload->data, fields_len,
                                 &gp->fields);
    if (error) {
        OFPPROP_LOG(&bad_ofmsg_rl, false,
                    "ntr selection method fields are invalid");
        return error;
    }

    return 0;
}

static enum ofperr
parse_ofp15_group_properties(struct ofpbuf *msg,
                             enum ofp11_group_type group_type,
                             enum ofp15_group_mod_command group_cmd,
                             struct ofputil_group_props *gp,
                             size_t properties_len)
{
    struct ofpbuf properties = ofpbuf_const_initializer(
        ofpbuf_pull(msg, properties_len), properties_len);
    while (properties.size > 0) {
        struct ofpbuf payload;
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPPROP_EXP(NTR_VENDOR_ID, NTRT_SELECTION_METHOD):
        case OFPPROP_EXP(NTR_COMPAT_VENDOR_ID, NTRT_SELECTION_METHOD):
            error = parse_group_prop_ntr_selection_method(&payload, group_type,
                                                          group_cmd, gp);
            break;

        default:
            error = OFPPROP_UNKNOWN(false, "group", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

static int
ofputil_decode_ofp11_group_desc_reply(struct ofputil_group_desc *gd,
                                      struct ofpbuf *msg,
                                      enum ofp_version version)
{
    struct ofp11_group_desc_stats *ogds;
    size_t length;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    ogds = ofpbuf_try_pull(msg, sizeof *ogds);
    if (!ogds) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST11_GROUP_DESC reply has %"PRIu32" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    gd->type = ogds->type;
    gd->group_id = ntohl(ogds->group_id);

    length = ntohs(ogds->length);
    if (length < sizeof *ogds || length - sizeof *ogds > msg->size) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST11_GROUP_DESC reply claims invalid "
                     "length %"PRIuSIZE, length);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    return ofputil_pull_ofp11_buckets(msg, length - sizeof *ogds, version,
                                      &gd->buckets);
}

static int
ofputil_decode_ofp15_group_desc_reply(struct ofputil_group_desc *gd,
                                      struct ofpbuf *msg,
                                      enum ofp_version version)
{
    struct ofp15_group_desc_stats *ogds;
    uint16_t length, bucket_list_len;
    int error;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    ogds = ofpbuf_try_pull(msg, sizeof *ogds);
    if (!ogds) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST11_GROUP_DESC reply has %"PRIu32" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    gd->type = ogds->type;
    gd->group_id = ntohl(ogds->group_id);

    length = ntohs(ogds->length);
    if (length < sizeof *ogds || length - sizeof *ogds > msg->size) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST11_GROUP_DESC reply claims invalid "
                     "length %u", length);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    bucket_list_len = ntohs(ogds->bucket_list_len);
    if (length < bucket_list_len + sizeof *ogds) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST11_GROUP_DESC reply claims invalid "
                     "bucket list length %u", bucket_list_len);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    error = ofputil_pull_ofp15_buckets(msg, bucket_list_len, version, gd->type,
                                       &gd->buckets);
    if (error) {
        return error;
    }

    /* By definition group desc messages don't have a group mod command.
     * However, parse_group_prop_ntr_selection_method() checks to make sure
     * that the command is OFPGC15_ADD or OFPGC15_DELETE to guard
     * against group mod messages with other commands supplying
     * a NTR selection method group experimenter property.
     * Such properties are valid for group desc replies so
     * claim that the group mod command is OFPGC15_ADD to
     * satisfy the check in parse_group_prop_ntr_selection_method() */
    error = parse_ofp15_group_properties(
        msg, gd->type, OFPGC15_ADD, &gd->props,
        length - sizeof *ogds - bucket_list_len);
    if (error) {
        ofputil_bucket_list_destroy(&gd->buckets);
    }
    return error;
}

/* Converts a group description reply in 'msg' into an abstract
 * ofputil_group_desc in 'gd'.
 *
 * Multiple group description replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  The caller must initially leave 'msg''s layer pointers
 * null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_group_desc_reply(struct ofputil_group_desc *gd,
                                struct ofpbuf *msg, enum ofp_version version)
{
    ofputil_init_group_properties(&gd->props);

    switch (version)
    {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        return ofputil_decode_ofp11_group_desc_reply(gd, msg, version);

    case OFP15_VERSION:
    case OFP16_VERSION:
        return ofputil_decode_ofp15_group_desc_reply(gd, msg, version);

    case OFP10_VERSION:
    default:
        OVS_NOT_REACHED();
    }
}

void
ofputil_uninit_group_mod(struct ofputil_group_mod *gm)
{
    ofputil_bucket_list_destroy(&gm->buckets);
    ofputil_group_properties_destroy(&gm->props);
}

static struct ofpbuf *
ofputil_encode_ofp11_group_mod(enum ofp_version ofp_version,
                               const struct ofputil_group_mod *gm)
{
    struct ofpbuf *b;
    struct ofp11_group_mod *ogm;
    size_t start_ogm;
    struct ofputil_bucket *bucket;

    b = ofpraw_alloc(OFPRAW_OFPT11_GROUP_MOD, ofp_version, 0);
    start_ogm = b->size;
    ofpbuf_put_zeros(b, sizeof *ogm);

    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
        ofputil_put_ofp11_bucket(bucket, b, ofp_version);
    }
    ogm = ofpbuf_at_assert(b, start_ogm, sizeof *ogm);
    ogm->command = htons(gm->command);
    ogm->type = gm->type;
    ogm->group_id = htonl(gm->group_id);

    return b;
}

static struct ofpbuf *
ofputil_encode_ofp15_group_mod(enum ofp_version ofp_version,
                               const struct ofputil_group_mod *gm)
{
    struct ofpbuf *b;
    struct ofp15_group_mod *ogm;
    size_t start_ogm;
    struct ofputil_bucket *bucket;
    struct id_pool *bucket_ids = NULL;

    b = ofpraw_alloc(OFPRAW_OFPT15_GROUP_MOD, ofp_version, 0);
    start_ogm = b->size;
    ofpbuf_put_zeros(b, sizeof *ogm);

    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
        uint32_t bucket_id;

        /* Generate a bucket id if none was supplied */
        if (bucket->bucket_id > OFPG15_BUCKET_MAX) {
            if (!bucket_ids) {
                const struct ofputil_bucket *bkt;

                bucket_ids = id_pool_create(0, OFPG15_BUCKET_MAX + 1);

                /* Mark all bucket_ids that are present in gm
                 * as used in the pool. */
                LIST_FOR_EACH_REVERSE (bkt, list_node, &gm->buckets) {
                    if (bkt == bucket) {
                        break;
                    }
                    if (bkt->bucket_id <= OFPG15_BUCKET_MAX) {
                        id_pool_add(bucket_ids, bkt->bucket_id);
                    }
                }
            }

            if (!id_pool_alloc_id(bucket_ids, &bucket_id)) {
                OVS_NOT_REACHED();
            }
        } else {
            bucket_id = bucket->bucket_id;
        }

        ofputil_put_ofp15_bucket(bucket, bucket_id, gm->type, b, ofp_version);
    }
    ogm = ofpbuf_at_assert(b, start_ogm, sizeof *ogm);
    ogm->command = htons(gm->command);
    ogm->type = gm->type;
    ogm->group_id = htonl(gm->group_id);
    ogm->command_bucket_id = htonl(gm->command_bucket_id);
    ogm->bucket_array_len = htons(b->size - start_ogm - sizeof *ogm);

    /* Add group properties */
    if (gm->props.selection_method[0]) {
        ofputil_put_group_prop_ntr_selection_method(ofp_version, &gm->props, b);
    }

    id_pool_destroy(bucket_ids);
    return b;
}

static void
bad_group_cmd(enum ofp15_group_mod_command cmd)
{
    const char *opt_version;
    const char *version;
    const char *cmd_str;

    switch (cmd) {
    case OFPGC15_ADD:
    case OFPGC15_MODIFY:
    case OFPGC15_ADD_OR_MOD:
    case OFPGC15_DELETE:
        version = "1.1";
        opt_version = "11";
        break;

    case OFPGC15_INSERT_BUCKET:
    case OFPGC15_REMOVE_BUCKET:
        version = "1.5";
        opt_version = "15";
        break;

    default:
        OVS_NOT_REACHED();
    }

    switch (cmd) {
    case OFPGC15_ADD:
        cmd_str = "add-group";
        break;

    case OFPGC15_MODIFY:
    case OFPGC15_ADD_OR_MOD:
        cmd_str = "mod-group";
        break;

    case OFPGC15_DELETE:
        cmd_str = "del-group";
        break;

    case OFPGC15_INSERT_BUCKET:
        cmd_str = "insert-bucket";
        break;

    case OFPGC15_REMOVE_BUCKET:
        cmd_str = "remove-bucket";
        break;

    default:
        OVS_NOT_REACHED();
    }

    ovs_fatal(0, "%s needs OpenFlow %s or later (\'-O OpenFlow%s\')",
              cmd_str, version, opt_version);

}

/* Converts abstract group mod 'gm' into a message for OpenFlow version
 * 'ofp_version' and returns the message. */
struct ofpbuf *
ofputil_encode_group_mod(enum ofp_version ofp_version,
                         const struct ofputil_group_mod *gm)
{

    switch (ofp_version) {
    case OFP10_VERSION:
        bad_group_cmd(gm->command);
        /* fall through */

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        if (gm->command > OFPGC11_DELETE && gm->command != OFPGC11_ADD_OR_MOD) {
            bad_group_cmd(gm->command);
        }
        return ofputil_encode_ofp11_group_mod(ofp_version, gm);

    case OFP15_VERSION:
    case OFP16_VERSION:
        return ofputil_encode_ofp15_group_mod(ofp_version, gm);

    default:
        OVS_NOT_REACHED();
    }
}

static enum ofperr
ofputil_pull_ofp11_group_mod(struct ofpbuf *msg, enum ofp_version ofp_version,
                             struct ofputil_group_mod *gm)
{
    const struct ofp11_group_mod *ogm;
    enum ofperr error;

    ogm = ofpbuf_pull(msg, sizeof *ogm);
    gm->command = ntohs(ogm->command);
    gm->type = ogm->type;
    gm->group_id = ntohl(ogm->group_id);
    gm->command_bucket_id = OFPG15_BUCKET_ALL;

    error = ofputil_pull_ofp11_buckets(msg, msg->size, ofp_version,
                                       &gm->buckets);

    /* OF1.3.5+ prescribes an error when an OFPGC_DELETE includes buckets. */
    if (!error
        && ofp_version >= OFP13_VERSION
        && gm->command == OFPGC11_DELETE
        && !ovs_list_is_empty(&gm->buckets)) {
        error = OFPERR_OFPGMFC_INVALID_GROUP;
        ofputil_bucket_list_destroy(&gm->buckets);
    }

    return error;
}

static enum ofperr
ofputil_pull_ofp15_group_mod(struct ofpbuf *msg, enum ofp_version ofp_version,
                             struct ofputil_group_mod *gm)
{
    const struct ofp15_group_mod *ogm;
    uint16_t bucket_list_len;
    enum ofperr error = OFPERR_OFPGMFC_BAD_BUCKET;

    ogm = ofpbuf_pull(msg, sizeof *ogm);
    gm->command = ntohs(ogm->command);
    gm->type = ogm->type;
    gm->group_id = ntohl(ogm->group_id);

    gm->command_bucket_id = ntohl(ogm->command_bucket_id);
    switch (gm->command) {
    case OFPGC15_REMOVE_BUCKET:
        if (gm->command_bucket_id == OFPG15_BUCKET_ALL) {
            error = 0;
        }
        /* Fall through */
    case OFPGC15_INSERT_BUCKET:
        if (gm->command_bucket_id <= OFPG15_BUCKET_MAX ||
            gm->command_bucket_id == OFPG15_BUCKET_FIRST
            || gm->command_bucket_id == OFPG15_BUCKET_LAST) {
            error = 0;
        }
        break;

    case OFPGC11_ADD:
    case OFPGC11_MODIFY:
    case OFPGC11_ADD_OR_MOD:
    case OFPGC11_DELETE:
    default:
        if (gm->command_bucket_id == OFPG15_BUCKET_ALL) {
            error = 0;
        }
        break;
    }
    if (error) {
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "group command bucket id (%u) is out of range",
                     gm->command_bucket_id);
        return OFPERR_OFPGMFC_BAD_BUCKET;
    }

    bucket_list_len = ntohs(ogm->bucket_array_len);
    if (bucket_list_len > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    error = ofputil_pull_ofp15_buckets(msg, bucket_list_len, ofp_version,
                                       gm->type, &gm->buckets);
    if (error) {
        return error;
    }

    error = parse_ofp15_group_properties(msg, gm->type, gm->command,
                                         &gm->props, msg->size);
    if (error) {
        ofputil_bucket_list_destroy(&gm->buckets);
    }
    return error;
}

static enum ofperr
ofputil_check_group_mod(const struct ofputil_group_mod *gm)
{
    switch (gm->type) {
    case OFPGT11_INDIRECT:
        if (gm->command != OFPGC11_DELETE
            && !ovs_list_is_singleton(&gm->buckets) ) {
            return OFPERR_OFPGMFC_INVALID_GROUP;
        }
        break;
    case OFPGT11_ALL:
    case OFPGT11_SELECT:
    case OFPGT11_FF:
        break;
    default:
        return OFPERR_OFPGMFC_BAD_TYPE;
    }

    switch (gm->command) {
    case OFPGC11_ADD:
    case OFPGC11_MODIFY:
    case OFPGC11_ADD_OR_MOD:
    case OFPGC11_DELETE:
    case OFPGC15_INSERT_BUCKET:
        break;
    case OFPGC15_REMOVE_BUCKET:
        if (!ovs_list_is_empty(&gm->buckets)) {
            return OFPERR_OFPGMFC_BAD_BUCKET;
        }
        break;
    default:
        return OFPERR_OFPGMFC_BAD_COMMAND;
    }

    struct ofputil_bucket *bucket;
    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
        if (bucket->weight && gm->type != OFPGT11_SELECT) {
            return OFPERR_OFPGMFC_INVALID_GROUP;
        }

        switch (gm->type) {
        case OFPGT11_ALL:
        case OFPGT11_INDIRECT:
            if (ofputil_bucket_has_liveness(bucket)) {
                return OFPERR_OFPGMFC_WATCH_UNSUPPORTED;
            }
            break;
        case OFPGT11_SELECT:
            break;
        case OFPGT11_FF:
            if (!ofputil_bucket_has_liveness(bucket)) {
                return OFPERR_OFPGMFC_INVALID_GROUP;
            }
            break;
        default:
            /* Returning BAD TYPE to be consistent
             * though gm->type has been checked already. */
            return OFPERR_OFPGMFC_BAD_TYPE;
        }
    }

    return 0;
}

/* Converts OpenFlow group mod message 'oh' into an abstract group mod in
 * 'gm'.  Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
ofputil_decode_group_mod(const struct ofp_header *oh,
                         struct ofputil_group_mod *gm)
{
    ofputil_init_group_properties(&gm->props);

    enum ofp_version ofp_version = oh->version;
    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&msg);

    enum ofperr err;
    switch (ofp_version)
    {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        err = ofputil_pull_ofp11_group_mod(&msg, ofp_version, gm);
        break;

    case OFP15_VERSION:
    case OFP16_VERSION:
        err = ofputil_pull_ofp15_group_mod(&msg, ofp_version, gm);
        break;

    case OFP10_VERSION:
    default:
        OVS_NOT_REACHED();
    }
    if (err) {
        return err;
    }

    err = ofputil_check_group_mod(gm);
    if (err) {
        ofputil_uninit_group_mod(gm);
    }
    return err;
}

/* Destroys 'bms'. */
void
ofputil_free_bundle_msgs(struct ofputil_bundle_msg *bms, size_t n_bms)
{
    for (size_t i = 0; i < n_bms; i++) {
        switch ((int)bms[i].type) {
        case OFPTYPE_FLOW_MOD:
            free(CONST_CAST(struct ofpact *, bms[i].fm.ofpacts));
            break;
        case OFPTYPE_GROUP_MOD:
            ofputil_uninit_group_mod(&bms[i].gm);
            break;
        case OFPTYPE_PACKET_OUT:
            free(bms[i].po.ofpacts);
            free(CONST_CAST(void *, bms[i].po.packet));
            break;
        default:
            break;
        }
    }
    free(bms);
}

void
ofputil_encode_bundle_msgs(const struct ofputil_bundle_msg *bms,
                           size_t n_bms, struct ovs_list *requests,
                           enum ofputil_protocol protocol)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);

    for (size_t i = 0; i < n_bms; i++) {
        struct ofpbuf *request = NULL;

        switch ((int)bms[i].type) {
        case OFPTYPE_FLOW_MOD:
            request = ofputil_encode_flow_mod(&bms[i].fm, protocol);
            break;
        case OFPTYPE_GROUP_MOD:
            request = ofputil_encode_group_mod(version, &bms[i].gm);
            break;
        case OFPTYPE_PACKET_OUT:
            request = ofputil_encode_packet_out(&bms[i].po, protocol);
            break;
        default:
            break;
        }
        if (request) {
            ovs_list_push_back(requests, &request->list_node);
        }
    }
}

/* Parse a queue status request message into 'oqsr'.
 * Returns 0 if successful, otherwise an OFPERR_* number. */
enum ofperr
ofputil_decode_queue_stats_request(const struct ofp_header *request,
                                   struct ofputil_queue_stats_request *oqsr)
{
    switch ((enum ofp_version)request->version) {
    case OFP16_VERSION:
    case OFP15_VERSION:
    case OFP14_VERSION:
    case OFP13_VERSION:
    case OFP12_VERSION:
    case OFP11_VERSION: {
        const struct ofp11_queue_stats_request *qsr11 = ofpmsg_body(request);
        oqsr->queue_id = ntohl(qsr11->queue_id);
        return ofputil_port_from_ofp11(qsr11->port_no, &oqsr->port_no);
    }

    case OFP10_VERSION: {
        const struct ofp10_queue_stats_request *qsr10 = ofpmsg_body(request);
        oqsr->queue_id = ntohl(qsr10->queue_id);
        oqsr->port_no = u16_to_ofp(ntohs(qsr10->port_no));
        /* OF 1.0 uses OFPP_ALL for OFPP_ANY */
        if (oqsr->port_no == OFPP_ALL) {
            oqsr->port_no = OFPP_ANY;
        }
        return 0;
    }

    default:
        OVS_NOT_REACHED();
    }
}

/* Encode a queue stats request for 'oqsr', the encoded message
 * will be for OpenFlow version 'ofp_version'. Returns message
 * as a struct ofpbuf. Returns encoded message on success, NULL on error. */
struct ofpbuf *
ofputil_encode_queue_stats_request(enum ofp_version ofp_version,
                                   const struct ofputil_queue_stats_request *oqsr)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp11_queue_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST11_QUEUE_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->port_no = ofputil_port_to_ofp11(oqsr->port_no);
        req->queue_id = htonl(oqsr->queue_id);
        break;
    }
    case OFP10_VERSION: {
        struct ofp10_queue_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST10_QUEUE_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        /* OpenFlow 1.0 needs OFPP_ALL instead of OFPP_ANY */
        req->port_no = htons(ofp_to_u16(oqsr->port_no == OFPP_ANY
                                        ? OFPP_ALL : oqsr->port_no));
        req->queue_id = htonl(oqsr->queue_id);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

/* Returns the number of queue stats elements in OFPTYPE_QUEUE_STATS_REPLY
 * message 'oh'. */
size_t
ofputil_count_queue_stats(const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    for (size_t n = 0; ; n++) {
        struct ofputil_queue_stats qs;
        if (ofputil_decode_queue_stats(&qs, &b)) {
            return n;
        }
    }
}

static enum ofperr
ofputil_queue_stats_from_ofp10(struct ofputil_queue_stats *oqs,
                               const struct ofp10_queue_stats *qs10)
{
    oqs->port_no = u16_to_ofp(ntohs(qs10->port_no));
    oqs->queue_id = ntohl(qs10->queue_id);
    oqs->tx_bytes = ntohll(get_32aligned_be64(&qs10->tx_bytes));
    oqs->tx_packets = ntohll(get_32aligned_be64(&qs10->tx_packets));
    oqs->tx_errors = ntohll(get_32aligned_be64(&qs10->tx_errors));
    oqs->duration_sec = oqs->duration_nsec = UINT32_MAX;

    return 0;
}

static enum ofperr
ofputil_queue_stats_from_ofp11(struct ofputil_queue_stats *oqs,
                               const struct ofp11_queue_stats *qs11)
{
    enum ofperr error;

    error = ofputil_port_from_ofp11(qs11->port_no, &oqs->port_no);
    if (error) {
        return error;
    }

    oqs->queue_id = ntohl(qs11->queue_id);
    oqs->tx_bytes = ntohll(qs11->tx_bytes);
    oqs->tx_packets = ntohll(qs11->tx_packets);
    oqs->tx_errors = ntohll(qs11->tx_errors);
    oqs->duration_sec = oqs->duration_nsec = UINT32_MAX;

    return 0;
}

static enum ofperr
ofputil_queue_stats_from_ofp13(struct ofputil_queue_stats *oqs,
                               const struct ofp13_queue_stats *qs13)
{
    enum ofperr error = ofputil_queue_stats_from_ofp11(oqs, &qs13->qs);
    if (!error) {
        oqs->duration_sec = ntohl(qs13->duration_sec);
        oqs->duration_nsec = ntohl(qs13->duration_nsec);
    }

    return error;
}

static enum ofperr
ofputil_pull_ofp14_queue_stats(struct ofputil_queue_stats *oqs,
                               struct ofpbuf *msg)
{
    const struct ofp14_queue_stats *qs14;
    size_t len;

    qs14 = ofpbuf_try_pull(msg, sizeof *qs14);
    if (!qs14) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    len = ntohs(qs14->length);
    if (len < sizeof *qs14 || len - sizeof *qs14 > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    ofpbuf_pull(msg, len - sizeof *qs14);

    /* No properties yet defined, so ignore them for now. */

    return ofputil_queue_stats_from_ofp13(oqs, &qs14->qs);
}

/* Converts an OFPST_QUEUE_STATS reply in 'msg' into an abstract
 * ofputil_queue_stats in 'qs'.
 *
 * Multiple OFPST_QUEUE_STATS replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  The caller must initially leave 'msg''s layer pointers
 * null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_queue_stats(struct ofputil_queue_stats *qs, struct ofpbuf *msg)
{
    enum ofperr error;
    enum ofpraw raw;

    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST14_QUEUE_REPLY) {
        return ofputil_pull_ofp14_queue_stats(qs, msg);
    } else if (raw == OFPRAW_OFPST13_QUEUE_REPLY) {
        const struct ofp13_queue_stats *qs13;

        qs13 = ofpbuf_try_pull(msg, sizeof *qs13);
        if (!qs13) {
            goto bad_len;
        }
        return ofputil_queue_stats_from_ofp13(qs, qs13);
    } else if (raw == OFPRAW_OFPST11_QUEUE_REPLY) {
        const struct ofp11_queue_stats *qs11;

        qs11 = ofpbuf_try_pull(msg, sizeof *qs11);
        if (!qs11) {
            goto bad_len;
        }
        return ofputil_queue_stats_from_ofp11(qs, qs11);
    } else if (raw == OFPRAW_OFPST10_QUEUE_REPLY) {
        const struct ofp10_queue_stats *qs10;

        qs10 = ofpbuf_try_pull(msg, sizeof *qs10);
        if (!qs10) {
            goto bad_len;
        }
        return ofputil_queue_stats_from_ofp10(qs, qs10);
    } else {
        OVS_NOT_REACHED();
    }

 bad_len:
    VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_QUEUE reply has %"PRIu32" leftover "
                 "bytes at end", msg->size);
    return OFPERR_OFPBRC_BAD_LEN;
}

static void
ofputil_queue_stats_to_ofp10(const struct ofputil_queue_stats *oqs,
                             struct ofp10_queue_stats *qs10)
{
    qs10->port_no = htons(ofp_to_u16(oqs->port_no));
    memset(qs10->pad, 0, sizeof qs10->pad);
    qs10->queue_id = htonl(oqs->queue_id);
    put_32aligned_be64(&qs10->tx_bytes, htonll(oqs->tx_bytes));
    put_32aligned_be64(&qs10->tx_packets, htonll(oqs->tx_packets));
    put_32aligned_be64(&qs10->tx_errors, htonll(oqs->tx_errors));
}

static void
ofputil_queue_stats_to_ofp11(const struct ofputil_queue_stats *oqs,
                             struct ofp11_queue_stats *qs11)
{
    qs11->port_no = ofputil_port_to_ofp11(oqs->port_no);
    qs11->queue_id = htonl(oqs->queue_id);
    qs11->tx_bytes = htonll(oqs->tx_bytes);
    qs11->tx_packets = htonll(oqs->tx_packets);
    qs11->tx_errors = htonll(oqs->tx_errors);
}

static void
ofputil_queue_stats_to_ofp13(const struct ofputil_queue_stats *oqs,
                             struct ofp13_queue_stats *qs13)
{
    ofputil_queue_stats_to_ofp11(oqs, &qs13->qs);
    if (oqs->duration_sec != UINT32_MAX) {
        qs13->duration_sec = htonl(oqs->duration_sec);
        qs13->duration_nsec = htonl(oqs->duration_nsec);
    } else {
        qs13->duration_sec = OVS_BE32_MAX;
        qs13->duration_nsec = OVS_BE32_MAX;
    }
}

static void
ofputil_queue_stats_to_ofp14(const struct ofputil_queue_stats *oqs,
                             struct ofp14_queue_stats *qs14)
{
    qs14->length = htons(sizeof *qs14);
    memset(qs14->pad, 0, sizeof qs14->pad);
    ofputil_queue_stats_to_ofp13(oqs, &qs14->qs);
}


/* Encode a queue stat for 'oqs' and append it to 'replies'. */
void
ofputil_append_queue_stat(struct ovs_list *replies,
                          const struct ofputil_queue_stats *oqs)
{
    switch (ofpmp_version(replies)) {
    case OFP13_VERSION: {
        struct ofp13_queue_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_queue_stats_to_ofp13(oqs, reply);
        break;
    }

    case OFP12_VERSION:
    case OFP11_VERSION: {
        struct ofp11_queue_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_queue_stats_to_ofp11(oqs, reply);
        break;
    }

    case OFP10_VERSION: {
        struct ofp10_queue_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_queue_stats_to_ofp10(oqs, reply);
        break;
    }

    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp14_queue_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_queue_stats_to_ofp14(oqs, reply);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }
}

enum ofperr
ofputil_decode_bundle_ctrl(const struct ofp_header *oh,
                           struct ofputil_bundle_ctrl_msg *msg)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    ovs_assert(raw == OFPRAW_OFPT14_BUNDLE_CONTROL
               || raw == OFPRAW_ONFT13_BUNDLE_CONTROL);

    const struct ofp14_bundle_ctrl_msg *m = b.msg;
    msg->bundle_id = ntohl(m->bundle_id);
    msg->type = ntohs(m->type);
    msg->flags = ntohs(m->flags);

    return 0;
}

struct ofpbuf *
ofputil_encode_bundle_ctrl_request(enum ofp_version ofp_version,
                                   struct ofputil_bundle_ctrl_msg *bc)
{
    struct ofpbuf *request;
    struct ofp14_bundle_ctrl_msg *m;

    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
    case OFP12_VERSION:
        ovs_fatal(0, "bundles need OpenFlow 1.3 or later "
                     "(\'-O OpenFlow14\')");
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        request = ofpraw_alloc(ofp_version == OFP13_VERSION
                               ? OFPRAW_ONFT13_BUNDLE_CONTROL
                               : OFPRAW_OFPT14_BUNDLE_CONTROL, ofp_version, 0);
        m = ofpbuf_put_zeros(request, sizeof *m);

        m->bundle_id = htonl(bc->bundle_id);
        m->type = htons(bc->type);
        m->flags = htons(bc->flags);
        break;
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

struct ofpbuf *
ofputil_encode_bundle_ctrl_reply(const struct ofp_header *oh,
                                 struct ofputil_bundle_ctrl_msg *msg)
{
    struct ofpbuf *buf;
    struct ofp14_bundle_ctrl_msg *m;

    buf = ofpraw_alloc_reply(oh->version == OFP13_VERSION
                             ? OFPRAW_ONFT13_BUNDLE_CONTROL
                             : OFPRAW_OFPT14_BUNDLE_CONTROL, oh, 0);
    m = ofpbuf_put_zeros(buf, sizeof *m);

    m->bundle_id = htonl(msg->bundle_id);
    m->type = htons(msg->type);
    m->flags = htons(msg->flags);

    return buf;
}

/* Return true for bundlable state change requests, false for other messages.
 */
static bool
ofputil_is_bundlable(enum ofptype type)
{
    switch (type) {
        /* Minimum required by OpenFlow 1.4. */
    case OFPTYPE_PORT_MOD:
    case OFPTYPE_FLOW_MOD:
        /* Other supported types. */
    case OFPTYPE_GROUP_MOD:
    case OFPTYPE_PACKET_OUT:
        return true;

        /* Nice to have later. */
    case OFPTYPE_FLOW_MOD_TABLE_ID:
    case OFPTYPE_TABLE_MOD:
    case OFPTYPE_METER_MOD:
    case OFPTYPE_NXT_TLV_TABLE_MOD:

        /* Not to be bundlable. */
    case OFPTYPE_ECHO_REQUEST:
    case OFPTYPE_FEATURES_REQUEST:
    case OFPTYPE_GET_CONFIG_REQUEST:
    case OFPTYPE_SET_CONFIG:
    case OFPTYPE_BARRIER_REQUEST:
    case OFPTYPE_ROLE_REQUEST:
    case OFPTYPE_ECHO_REPLY:
    case OFPTYPE_SET_FLOW_FORMAT:
    case OFPTYPE_SET_PACKET_IN_FORMAT:
    case OFPTYPE_SET_CONTROLLER_ID:
    case OFPTYPE_FLOW_AGE:
    case OFPTYPE_FLOW_MONITOR_CANCEL:
    case OFPTYPE_SET_ASYNC_CONFIG:
    case OFPTYPE_GET_ASYNC_REQUEST:
    case OFPTYPE_DESC_STATS_REQUEST:
    case OFPTYPE_FLOW_STATS_REQUEST:
    case OFPTYPE_AGGREGATE_STATS_REQUEST:
    case OFPTYPE_TABLE_STATS_REQUEST:
    case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
    case OFPTYPE_TABLE_DESC_REQUEST:
    case OFPTYPE_PORT_STATS_REQUEST:
    case OFPTYPE_QUEUE_STATS_REQUEST:
    case OFPTYPE_PORT_DESC_STATS_REQUEST:
    case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
    case OFPTYPE_METER_STATS_REQUEST:
    case OFPTYPE_METER_CONFIG_STATS_REQUEST:
    case OFPTYPE_METER_FEATURES_STATS_REQUEST:
    case OFPTYPE_GROUP_STATS_REQUEST:
    case OFPTYPE_GROUP_DESC_STATS_REQUEST:
    case OFPTYPE_GROUP_FEATURES_STATS_REQUEST:
    case OFPTYPE_QUEUE_GET_CONFIG_REQUEST:
    case OFPTYPE_BUNDLE_CONTROL:
    case OFPTYPE_BUNDLE_ADD_MESSAGE:
    case OFPTYPE_HELLO:
    case OFPTYPE_ERROR:
    case OFPTYPE_FEATURES_REPLY:
    case OFPTYPE_GET_CONFIG_REPLY:
    case OFPTYPE_PACKET_IN:
    case OFPTYPE_FLOW_REMOVED:
    case OFPTYPE_PORT_STATUS:
    case OFPTYPE_BARRIER_REPLY:
    case OFPTYPE_QUEUE_GET_CONFIG_REPLY:
    case OFPTYPE_DESC_STATS_REPLY:
    case OFPTYPE_FLOW_STATS_REPLY:
    case OFPTYPE_QUEUE_STATS_REPLY:
    case OFPTYPE_PORT_STATS_REPLY:
    case OFPTYPE_TABLE_STATS_REPLY:
    case OFPTYPE_AGGREGATE_STATS_REPLY:
    case OFPTYPE_PORT_DESC_STATS_REPLY:
    case OFPTYPE_ROLE_REPLY:
    case OFPTYPE_FLOW_MONITOR_PAUSED:
    case OFPTYPE_FLOW_MONITOR_RESUMED:
    case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
    case OFPTYPE_GET_ASYNC_REPLY:
    case OFPTYPE_GROUP_STATS_REPLY:
    case OFPTYPE_GROUP_DESC_STATS_REPLY:
    case OFPTYPE_GROUP_FEATURES_STATS_REPLY:
    case OFPTYPE_METER_STATS_REPLY:
    case OFPTYPE_METER_CONFIG_STATS_REPLY:
    case OFPTYPE_METER_FEATURES_STATS_REPLY:
    case OFPTYPE_TABLE_FEATURES_STATS_REPLY:
    case OFPTYPE_TABLE_DESC_REPLY:
    case OFPTYPE_ROLE_STATUS:
    case OFPTYPE_REQUESTFORWARD:
    case OFPTYPE_TABLE_STATUS:
    case OFPTYPE_NXT_TLV_TABLE_REQUEST:
    case OFPTYPE_NXT_TLV_TABLE_REPLY:
    case OFPTYPE_NXT_RESUME:
    case OFPTYPE_IPFIX_BRIDGE_STATS_REQUEST:
    case OFPTYPE_IPFIX_BRIDGE_STATS_REPLY:
    case OFPTYPE_IPFIX_FLOW_STATS_REQUEST:
    case OFPTYPE_IPFIX_FLOW_STATS_REPLY:
    case OFPTYPE_CT_FLUSH_ZONE:
        break;
    }

    return false;
}

enum ofperr
ofputil_decode_bundle_add(const struct ofp_header *oh,
                          struct ofputil_bundle_add_msg *msg,
                          enum ofptype *typep)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));

    /* Pull the outer ofp_header. */
    enum ofpraw raw = ofpraw_pull_assert(&b);
    ovs_assert(raw == OFPRAW_OFPT14_BUNDLE_ADD_MESSAGE
               || raw == OFPRAW_ONFT13_BUNDLE_ADD_MESSAGE);

    /* Pull the bundle_ctrl header. */
    const struct ofp14_bundle_ctrl_msg *m = ofpbuf_pull(&b, sizeof *m);
    msg->bundle_id = ntohl(m->bundle_id);
    msg->flags = ntohs(m->flags);

    /* Pull the inner ofp_header. */
    if (b.size < sizeof(struct ofp_header)) {
        return OFPERR_OFPBFC_MSG_BAD_LEN;
    }
    msg->msg = b.data;
    if (msg->msg->version != oh->version) {
        return OFPERR_OFPBFC_BAD_VERSION;
    }
    size_t inner_len = ntohs(msg->msg->length);
    if (inner_len < sizeof(struct ofp_header) || inner_len > b.size) {
        return OFPERR_OFPBFC_MSG_BAD_LEN;
    }
    if (msg->msg->xid != oh->xid) {
        return OFPERR_OFPBFC_MSG_BAD_XID;
    }

    /* Reject unbundlable messages. */
    enum ofptype type;
    enum ofperr error = ofptype_decode(&type, msg->msg);
    if (error) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFPT14_BUNDLE_ADD_MESSAGE contained "
                     "message is unparsable (%s)", ofperr_get_name(error));
        return OFPERR_OFPBFC_MSG_UNSUP; /* 'error' would be confusing. */
    }

    if (!ofputil_is_bundlable(type)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "%s message not allowed inside "
                     "OFPT14_BUNDLE_ADD_MESSAGE", ofptype_get_name(type));
        return OFPERR_OFPBFC_MSG_UNSUP;
    }
    if (typep) {
        *typep = type;
    }

    return 0;
}

struct ofpbuf *
ofputil_encode_bundle_add(enum ofp_version ofp_version,
                          struct ofputil_bundle_add_msg *msg)
{
    struct ofpbuf *request;
    struct ofp14_bundle_ctrl_msg *m;

    /* Must use the same xid as the embedded message. */
    request = ofpraw_alloc_xid(ofp_version == OFP13_VERSION
                               ? OFPRAW_ONFT13_BUNDLE_ADD_MESSAGE
                               : OFPRAW_OFPT14_BUNDLE_ADD_MESSAGE, ofp_version,
                               msg->msg->xid, ntohs(msg->msg->length));
    m = ofpbuf_put_zeros(request, sizeof *m);

    m->bundle_id = htonl(msg->bundle_id);
    m->flags = htons(msg->flags);
    ofpbuf_put(request, msg->msg, ntohs(msg->msg->length));

    ofpmsg_update_length(request);
    return request;
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
            VLOG_WARN_RL(&bad_ofmsg_rl,
                         "tlv table option length (%u) is not a valid option size",
                         map->option_len);
            ofputil_uninit_tlv_table(mappings);
            return OFPERR_NXTTMFC_BAD_OPT_LEN;
        }

        map->index = ntohs(nx_map->index);
        if (map->index >= max_fields) {
            VLOG_WARN_RL(&bad_ofmsg_rl,
                         "tlv table field index (%u) is too large (max %u)",
                         map->index, max_fields - 1);
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
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "tlv table mod command (%u) is out of range",
                     ttm->command);
        return OFPERR_NXTTMFC_BAD_COMMAND;
    }

    return decode_tlv_table_mappings(&msg, TUN_METADATA_NUM_OPTS,
                                        &ttm->mappings);
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

void
ofputil_uninit_tlv_table(struct ovs_list *mappings)
{
    struct ofputil_tlv_map *map;

    LIST_FOR_EACH_POP (map, list_node, mappings) {
        free(map);
    }
}

const char *
ofputil_async_msg_type_to_string(enum ofputil_async_msg_type type)
{
    switch (type) {
    case OAM_PACKET_IN:      return "PACKET_IN";
    case OAM_PORT_STATUS:    return "PORT_STATUS";
    case OAM_FLOW_REMOVED:   return "FLOW_REMOVED";
    case OAM_ROLE_STATUS:    return "ROLE_STATUS";
    case OAM_TABLE_STATUS:   return "TABLE_STATUS";
    case OAM_REQUESTFORWARD: return "REQUESTFORWARD";

    case OAM_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

struct ofp14_async_prop {
    uint64_t prop_type;
    enum ofputil_async_msg_type oam;
    bool master;
    uint32_t allowed10, allowed14;
};

#define AP_PAIR(SLAVE_PROP_TYPE, OAM, A10, A14) \
    { SLAVE_PROP_TYPE,       OAM, false, A10, (A14) ? (A14) : (A10) },  \
    { (SLAVE_PROP_TYPE + 1), OAM, true,  A10, (A14) ? (A14) : (A10) }

static const struct ofp14_async_prop async_props[] = {
    AP_PAIR( 0, OAM_PACKET_IN,      OFPR10_BITS, OFPR14_BITS),
    AP_PAIR( 2, OAM_PORT_STATUS,    (1 << OFPPR_N_REASONS) - 1, 0),
    AP_PAIR( 4, OAM_FLOW_REMOVED,   (1 << OVS_OFPRR_NONE) - 1, 0),
    AP_PAIR( 6, OAM_ROLE_STATUS,    (1 << OFPCRR_N_REASONS) - 1, 0),
    AP_PAIR( 8, OAM_TABLE_STATUS,   OFPTR_BITS, 0),
    AP_PAIR(10, OAM_REQUESTFORWARD, (1 << OFPRFR_N_REASONS) - 1, 0),
};

#define FOR_EACH_ASYNC_PROP(VAR)                                \
    for (const struct ofp14_async_prop *VAR = async_props;      \
         VAR < &async_props[ARRAY_SIZE(async_props)]; VAR++)

static const struct ofp14_async_prop *
get_ofp14_async_config_prop_by_prop_type(uint64_t prop_type)
{
    FOR_EACH_ASYNC_PROP (ap) {
        if (prop_type == ap->prop_type) {
            return ap;
        }
    }
    return NULL;
}

static const struct ofp14_async_prop *
get_ofp14_async_config_prop_by_oam(enum ofputil_async_msg_type oam,
                                   bool master)
{
    FOR_EACH_ASYNC_PROP (ap) {
        if (ap->oam == oam && ap->master == master) {
            return ap;
        }
    }
    return NULL;
}

static uint32_t
ofp14_async_prop_allowed(const struct ofp14_async_prop *prop,
                         enum ofp_version version)
{
    return version >= OFP14_VERSION ? prop->allowed14 : prop->allowed10;
}

static ovs_be32
encode_async_mask(const struct ofputil_async_cfg *src,
                  const struct ofp14_async_prop *ap,
                  enum ofp_version version)
{
    uint32_t mask = ap->master ? src->master[ap->oam] : src->slave[ap->oam];
    return htonl(mask & ofp14_async_prop_allowed(ap, version));
}

static enum ofperr
decode_async_mask(ovs_be32 src,
                  const struct ofp14_async_prop *ap, enum ofp_version version,
                  bool loose, struct ofputil_async_cfg *dst)
{
    uint32_t mask = ntohl(src);
    uint32_t allowed = ofp14_async_prop_allowed(ap, version);
    if (mask & ~allowed) {
        OFPPROP_LOG(&bad_ofmsg_rl, loose,
                    "bad value %#x for %s (allowed mask %#x)",
                    mask, ofputil_async_msg_type_to_string(ap->oam),
                    allowed);
        mask &= allowed;
        if (!loose) {
            return OFPERR_OFPACFC_INVALID;
        }
    }

    if (ap->oam == OAM_PACKET_IN) {
        if (mask & (1u << OFPR_NO_MATCH)) {
            mask |= 1u << OFPR_EXPLICIT_MISS;
            if (version < OFP13_VERSION) {
                mask |= 1u << OFPR_IMPLICIT_MISS;
            }
        }
    }

    uint32_t *array = ap->master ? dst->master : dst->slave;
    array[ap->oam] = mask;
    return 0;
}

static enum ofperr
parse_async_tlv(const struct ofpbuf *property,
                const struct ofp14_async_prop *ap,
                struct ofputil_async_cfg *ac,
                enum ofp_version version, bool loose)
{
    enum ofperr error;
    ovs_be32 mask;

    error  = ofpprop_parse_be32(property, &mask);
    if (error) {
        return error;
    }

    if (ofpprop_is_experimenter(ap->prop_type)) {
        /* For experimenter properties, whether a property is for the master or
         * slave role is indicated by both 'type' and 'exp_type' in struct
         * ofp_prop_experimenter.  Check that these are consistent. */
        const struct ofp_prop_experimenter *ope = property->data;
        bool should_be_master = ope->type == htons(0xffff);
        if (should_be_master != ap->master) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "async property type %#"PRIx16" "
                         "indicates %s role but exp_type %"PRIu32" indicates "
                         "%s role",
                         ntohs(ope->type),
                         should_be_master ? "master" : "slave",
                         ntohl(ope->exp_type),
                         ap->master ? "master" : "slave");
            return OFPERR_OFPBPC_BAD_EXP_TYPE;
        }
    }

    return decode_async_mask(mask, ap, version, loose, ac);
}

static void
decode_legacy_async_masks(const ovs_be32 masks[2],
                          enum ofputil_async_msg_type oam,
                          enum ofp_version version,
                          struct ofputil_async_cfg *dst)
{
    for (int i = 0; i < 2; i++) {
        bool master = i == 0;
        const struct ofp14_async_prop *ap
            = get_ofp14_async_config_prop_by_oam(oam, master);
        decode_async_mask(masks[i], ap, version, true, dst);
    }
}

/* Decodes the OpenFlow "set async config" request and "get async config
 * reply" message in '*oh' into an abstract form in 'ac'.
 *
 * Some versions of the "set async config" request change only some of the
 * settings and leave the others alone.  This function uses 'basis' as the
 * initial state for decoding these.  Other versions of the request change all
 * the settings; this function ignores 'basis' when decoding these.
 *
 * If 'loose' is true, this function ignores properties and values that it does
 * not understand, as a controller would want to do when interpreting
 * capabilities provided by a switch.  If 'loose' is false, this function
 * treats unknown properties and values as an error, as a switch would want to
 * do when interpreting a configuration request made by a controller.
 *
 * Returns 0 if successful, otherwise an OFPERR_* value.
 *
 * Returns error code OFPERR_OFPACFC_INVALID if the value of mask is not in
 * the valid range of mask.
 *
 * Returns error code OFPERR_OFPACFC_UNSUPPORTED if the configuration is not
 * supported.*/
enum ofperr
ofputil_decode_set_async_config(const struct ofp_header *oh, bool loose,
                                const struct ofputil_async_cfg *basis,
                                struct ofputil_async_cfg *ac)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);

    if (raw == OFPRAW_OFPT13_SET_ASYNC ||
        raw == OFPRAW_NXT_SET_ASYNC_CONFIG ||
        raw == OFPRAW_OFPT13_GET_ASYNC_REPLY) {
        const struct nx_async_config *msg = ofpmsg_body(oh);

        *ac = OFPUTIL_ASYNC_CFG_INIT;
        decode_legacy_async_masks(msg->packet_in_mask, OAM_PACKET_IN,
                                  oh->version, ac);
        decode_legacy_async_masks(msg->port_status_mask, OAM_PORT_STATUS,
                                  oh->version, ac);
        decode_legacy_async_masks(msg->flow_removed_mask, OAM_FLOW_REMOVED,
                                  oh->version, ac);
    } else if (raw == OFPRAW_OFPT14_SET_ASYNC ||
               raw == OFPRAW_OFPT14_GET_ASYNC_REPLY ||
               raw == OFPRAW_NXT_SET_ASYNC_CONFIG2) {
        *ac = *basis;
        while (b.size > 0) {
            struct ofpbuf property;
            enum ofperr error;
            uint64_t type;

            error = ofpprop_pull__(&b, &property, 8, 0xfffe, &type);
            if (error) {
                return error;
            }

            const struct ofp14_async_prop *ap
                = get_ofp14_async_config_prop_by_prop_type(type);
            error = (ap
                     ? parse_async_tlv(&property, ap, ac, oh->version, loose)
                     : OFPPROP_UNKNOWN(loose, "async config", type));
            if (error) {
                /* Most messages use OFPBPC_BAD_TYPE but async has its own (who
                 * knows why, it's OpenFlow. */
                if (error == OFPERR_OFPBPC_BAD_TYPE) {
                    error = OFPERR_OFPACFC_UNSUPPORTED;
                }
                return error;
            }
        }
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
    }
    return 0;
}

static void
encode_legacy_async_masks(const struct ofputil_async_cfg *ac,
                          enum ofputil_async_msg_type oam,
                          enum ofp_version version,
                          ovs_be32 masks[2])
{
    for (int i = 0; i < 2; i++) {
        bool master = i == 0;
        const struct ofp14_async_prop *ap
            = get_ofp14_async_config_prop_by_oam(oam, master);
        masks[i] = encode_async_mask(ac, ap, version);
    }
}

static void
ofputil_put_async_config__(const struct ofputil_async_cfg *ac,
                           struct ofpbuf *buf, bool tlv,
                           enum ofp_version version, uint32_t oams)
{
    if (!tlv) {
        struct nx_async_config *msg = ofpbuf_put_zeros(buf, sizeof *msg);
        encode_legacy_async_masks(ac, OAM_PACKET_IN, version,
                                  msg->packet_in_mask);
        encode_legacy_async_masks(ac, OAM_PORT_STATUS, version,
                                  msg->port_status_mask);
        encode_legacy_async_masks(ac, OAM_FLOW_REMOVED, version,
                                  msg->flow_removed_mask);
    } else {
        FOR_EACH_ASYNC_PROP (ap) {
            if (oams & (1u << ap->oam)) {
                size_t ofs = buf->size;
                ofpprop_put_be32(buf, ap->prop_type,
                                 encode_async_mask(ac, ap, version));

                /* For experimenter properties, we need to use type 0xfffe for
                 * master and 0xffff for slaves. */
                if (ofpprop_is_experimenter(ap->prop_type)) {
                    struct ofp_prop_experimenter *ope
                        = ofpbuf_at_assert(buf, ofs, sizeof *ope);
                    ope->type = ap->master ? htons(0xffff) : htons(0xfffe);
                }
            }
        }
    }
}

/* Encodes and returns a reply to the OFPT_GET_ASYNC_REQUEST in 'oh' that
 * states that the asynchronous message configuration is 'ac'. */
struct ofpbuf *
ofputil_encode_get_async_reply(const struct ofp_header *oh,
                               const struct ofputil_async_cfg *ac)
{
    enum ofpraw raw = (oh->version < OFP14_VERSION
                       ? OFPRAW_OFPT13_GET_ASYNC_REPLY
                       : OFPRAW_OFPT14_GET_ASYNC_REPLY);
    struct ofpbuf *reply = ofpraw_alloc_reply(raw, oh, 0);
    ofputil_put_async_config__(ac, reply,
                               raw == OFPRAW_OFPT14_GET_ASYNC_REPLY,
                               oh->version, UINT32_MAX);
    return reply;
}

/* Encodes and returns a message, in a format appropriate for OpenFlow version
 * 'ofp_version', that sets the asynchronous message configuration to 'ac'.
 *
 * Specify 'oams' as a bitmap of OAM_* that indicate the asynchronous messages
 * to configure.  OF1.0 through OF1.3 can't natively configure a subset of
 * messages, so more messages than requested may be configured.  OF1.0 through
 * OF1.3 also can't configure OVS extension OAM_* values, so if 'oam' includes
 * any extensions then this function encodes an Open vSwitch extension message
 * that does support configuring OVS extension OAM_*. */
struct ofpbuf *
ofputil_encode_set_async_config(const struct ofputil_async_cfg *ac,
                                uint32_t oams, enum ofp_version ofp_version)
{
    enum ofpraw raw = (ofp_version >= OFP14_VERSION ? OFPRAW_OFPT14_SET_ASYNC
                       : oams & OAM_EXTENSIONS ? OFPRAW_NXT_SET_ASYNC_CONFIG2
                       : ofp_version >= OFP13_VERSION ? OFPRAW_OFPT13_SET_ASYNC
                       : OFPRAW_NXT_SET_ASYNC_CONFIG);
    struct ofpbuf *request = ofpraw_alloc(raw, ofp_version, 0);
    ofputil_put_async_config__(ac, request,
                               (raw == OFPRAW_OFPT14_SET_ASYNC ||
                                raw == OFPRAW_NXT_SET_ASYNC_CONFIG2),
                               ofp_version, oams);
    return request;
}

struct ofputil_async_cfg
ofputil_async_cfg_default(enum ofp_version version)
{
    /* We enable all of the OF1.4 reasons regardless of 'version' because the
     * reasons added in OF1.4 just are just refinements of the OFPR_ACTION
     * introduced in OF1.0, breaking it into more specific categories.  When we
     * encode these for earlier OpenFlow versions, we translate them into
     * OFPR_ACTION.  */
    uint32_t pin = OFPR14_BITS & ~(1u << OFPR_INVALID_TTL);
    pin |= 1u << OFPR_EXPLICIT_MISS;
    if (version <= OFP12_VERSION) {
        pin |= 1u << OFPR_IMPLICIT_MISS;
    }

    struct ofputil_async_cfg oac = {
        .master[OAM_PACKET_IN] = pin,
        .master[OAM_PORT_STATUS] = OFPPR_BITS,
        .slave[OAM_PORT_STATUS] = OFPPR_BITS
    };

    if (version >= OFP14_VERSION) {
        oac.master[OAM_FLOW_REMOVED] = OFPRR14_BITS;
    } else if (version == OFP13_VERSION) {
        oac.master[OAM_FLOW_REMOVED] = OFPRR13_BITS;
    } else {
        oac.master[OAM_FLOW_REMOVED] = OFPRR10_BITS;
    }

    return oac;
}

static void
ofputil_put_ofp14_table_desc(const struct ofputil_table_desc *td,
                             struct ofpbuf *b, enum ofp_version version)
{
    struct ofp14_table_desc *otd;
    struct ofp14_table_mod_prop_vacancy *otv;
    size_t start_otd;

    start_otd = b->size;
    ofpbuf_put_zeros(b, sizeof *otd);

    ofpprop_put_u32(b, OFPTMPT14_EVICTION, td->eviction_flags);

    otv = ofpbuf_put_zeros(b, sizeof *otv);
    otv->type = htons(OFPTMPT14_VACANCY);
    otv->length = htons(sizeof *otv);
    otv->vacancy_down = td->table_vacancy.vacancy_down;
    otv->vacancy_up = td->table_vacancy.vacancy_up;
    otv->vacancy = td->table_vacancy.vacancy;

    otd = ofpbuf_at_assert(b, start_otd, sizeof *otd);
    otd->length = htons(b->size - start_otd);
    otd->table_id = td->table_id;
    otd->config = ofputil_encode_table_config(OFPUTIL_TABLE_MISS_DEFAULT,
                                              td->eviction, td->vacancy,
                                              version);
}

/* Converts the abstract form of a "table status" message in '*ts' into an
 * OpenFlow message suitable for 'protocol', and returns that encoded form in
 * a buffer owned by the caller. */
struct ofpbuf *
ofputil_encode_table_status(const struct ofputil_table_status *ts,
                            enum ofputil_protocol protocol)
{
    enum ofp_version version;
    struct ofpbuf *b;

    version = ofputil_protocol_to_ofp_version(protocol);
    if (version >= OFP14_VERSION) {
        enum ofpraw raw;
        struct ofp14_table_status *ots;

        raw = OFPRAW_OFPT14_TABLE_STATUS;
        b = ofpraw_alloc_xid(raw, version, htonl(0), 0);
        ots = ofpbuf_put_zeros(b, sizeof *ots);
        ots->reason = ts->reason;
        ofputil_put_ofp14_table_desc(&ts->desc, b, version);
        ofpmsg_update_length(b);
        return b;
    } else {
        return NULL;
    }
}

/* Decodes the OpenFlow "table status" message in '*ots' into an abstract form
 * in '*ts'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_table_status(const struct ofp_header *oh,
                            struct ofputil_table_status *ts)
{
    const struct ofp14_table_status *ots;
    struct ofpbuf b;
    enum ofperr error;
    enum ofpraw raw;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);
    ots = ofpbuf_pull(&b, sizeof *ots);

    if (raw == OFPRAW_OFPT14_TABLE_STATUS) {
        if (ots->reason != OFPTR_VACANCY_DOWN
            && ots->reason != OFPTR_VACANCY_UP) {
            return OFPERR_OFPBPC_BAD_VALUE;
        }
        ts->reason = ots->reason;

        error = ofputil_decode_table_desc(&b, &ts->desc, oh->version);
        return error;
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
    }

    return 0;
}
