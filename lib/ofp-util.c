/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "ofp-print.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include "bundle.h"
#include "byte-order.h"
#include "classifier.h"
#include "dynamic-string.h"
#include "learn.h"
#include "meta-flow.h"
#include "multipath.h"
#include "netdev.h"
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-msgs.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "random.h"
#include "unaligned.h"
#include "type-props.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_util);

/* Rate limit for OpenFlow message parse errors.  These always indicate a bug
 * in the peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit bad_ofmsg_rl = VLOG_RATE_LIMIT_INIT(1, 5);

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
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 23);

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
        memset(wc->masks.dl_src, 0xff, ETH_ADDR_LEN);
    }
    if (!(ofpfw & OFPFW10_DL_DST)) {
        memset(wc->masks.dl_dst, 0xff, ETH_ADDR_LEN);
    }
    if (!(ofpfw & OFPFW10_DL_TYPE)) {
        wc->masks.dl_type = OVS_BE16_MAX;
    }

    /* VLAN TCI mask. */
    if (!(ofpfw & OFPFW10_DL_VLAN_PCP)) {
        wc->masks.vlan_tci |= htons(VLAN_PCP_MASK | VLAN_CFI);
    }
    if (!(ofpfw & OFPFW10_DL_VLAN)) {
        wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
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

    /* Initialize most of match->flow. */
    match->flow.nw_src = ofmatch->nw_src;
    match->flow.nw_dst = ofmatch->nw_dst;
    match->flow.in_port.ofp_port = u16_to_ofp(ntohs(ofmatch->in_port));
    match->flow.dl_type = ofputil_dl_type_from_openflow(ofmatch->dl_type);
    match->flow.tp_src = ofmatch->tp_src;
    match->flow.tp_dst = ofmatch->tp_dst;
    memcpy(match->flow.dl_src, ofmatch->dl_src, ETH_ADDR_LEN);
    memcpy(match->flow.dl_dst, ofmatch->dl_dst, ETH_ADDR_LEN);
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
        match->flow.vlan_tci = htons(0);
        match->wc.masks.vlan_tci = htons(0xffff);
    } else {
        ovs_be16 vid, pcp, tci;

        vid = ofmatch->dl_vlan & htons(VLAN_VID_MASK);
        pcp = htons((ofmatch->dl_vlan_pcp << VLAN_PCP_SHIFT) & VLAN_PCP_MASK);
        tci = vid | pcp | htons(VLAN_CFI);
        match->flow.vlan_tci = tci & match->wc.masks.vlan_tci;
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
    if (match->wc.masks.vlan_tci == htons(0)) {
        ofpfw |= OFPFW10_DL_VLAN | OFPFW10_DL_VLAN_PCP;
    } else if (match->wc.masks.vlan_tci & htons(VLAN_CFI)
               && !(match->flow.vlan_tci & htons(VLAN_CFI))) {
        ofmatch->dl_vlan = htons(OFP10_VLAN_NONE);
        ofpfw |= OFPFW10_DL_VLAN_PCP;
    } else {
        if (!(match->wc.masks.vlan_tci & htons(VLAN_VID_MASK))) {
            ofpfw |= OFPFW10_DL_VLAN;
        } else {
            ofmatch->dl_vlan = htons(vlan_tci_to_vid(match->flow.vlan_tci));
        }

        if (!(match->wc.masks.vlan_tci & htons(VLAN_PCP_MASK))) {
            ofpfw |= OFPFW10_DL_VLAN_PCP;
        } else {
            ofmatch->dl_vlan_pcp = vlan_tci_to_pcp(match->flow.vlan_tci);
        }
    }

    /* Compose most of the match structure. */
    ofmatch->wildcards = htonl(ofpfw);
    ofmatch->in_port = htons(ofp_to_u16(match->flow.in_port.ofp_port));
    memcpy(ofmatch->dl_src, match->flow.dl_src, ETH_ADDR_LEN);
    memcpy(ofmatch->dl_dst, match->flow.dl_dst, ETH_ADDR_LEN);
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
ofputil_pull_ofp11_match(struct ofpbuf *buf, struct match *match,
                         uint16_t *padded_match_len)
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
        return oxm_pull_match(buf, match);

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
    uint8_t dl_src_mask[ETH_ADDR_LEN];
    uint8_t dl_dst_mask[ETH_ADDR_LEN];
    bool ipv4, arp, rarp;
    int i;

    match_init_catchall(match);

    if (!(wc & OFPFW11_IN_PORT)) {
        ofp_port_t ofp_port;
        enum ofperr error;

        error = ofputil_port_from_ofp11(ofmatch->in_port, &ofp_port);
        if (error) {
            return OFPERR_OFPBMC_BAD_VALUE;
        }
        match_set_in_port(match, ofp_port);
    }

    for (i = 0; i < ETH_ADDR_LEN; i++) {
        dl_src_mask[i] = ~ofmatch->dl_src_mask[i];
    }
    match_set_dl_src_masked(match, ofmatch->dl_src, dl_src_mask);

    for (i = 0; i < ETH_ADDR_LEN; i++) {
        dl_dst_mask[i] = ~ofmatch->dl_dst_mask[i];
    }
    match_set_dl_dst_masked(match, ofmatch->dl_dst, dl_dst_mask);

    if (!(wc & OFPFW11_DL_VLAN)) {
        if (ofmatch->dl_vlan == htons(OFPVID11_NONE)) {
            /* Match only packets without a VLAN tag. */
            match->flow.vlan_tci = htons(0);
            match->wc.masks.vlan_tci = OVS_BE16_MAX;
        } else {
            if (ofmatch->dl_vlan == htons(OFPVID11_ANY)) {
                /* Match any packet with a VLAN tag regardless of VID. */
                match->flow.vlan_tci = htons(VLAN_CFI);
                match->wc.masks.vlan_tci = htons(VLAN_CFI);
            } else if (ntohs(ofmatch->dl_vlan) < 4096) {
                /* Match only packets with the specified VLAN VID. */
                match->flow.vlan_tci = htons(VLAN_CFI) | ofmatch->dl_vlan;
                match->wc.masks.vlan_tci = htons(VLAN_CFI | VLAN_VID_MASK);
            } else {
                /* Invalid VID. */
                return OFPERR_OFPBMC_BAD_VALUE;
            }

            if (!(wc & OFPFW11_DL_VLAN_PCP)) {
                if (ofmatch->dl_vlan_pcp <= 7) {
                    match->flow.vlan_tci |= htons(ofmatch->dl_vlan_pcp
                                                  << VLAN_PCP_SHIFT);
                    match->wc.masks.vlan_tci |= htons(VLAN_PCP_MASK);
                } else {
                    /* Invalid PCP. */
                    return OFPERR_OFPBMC_BAD_VALUE;
                }
            }
        }
    }

    if (!(wc & OFPFW11_DL_TYPE)) {
        match_set_dl_type(match,
                          ofputil_dl_type_from_openflow(ofmatch->dl_type));
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
            match_set_mpls_label(match, ofmatch->mpls_label);
        }
        if (!(wc & OFPFW11_MPLS_TC)) {
            match_set_mpls_tc(match, ofmatch->mpls_tc);
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
    int i;

    memset(ofmatch, 0, sizeof *ofmatch);
    ofmatch->omh.type = htons(OFPMT_STANDARD);
    ofmatch->omh.length = htons(OFPMT11_STANDARD_LENGTH);

    if (!match->wc.masks.in_port.ofp_port) {
        wc |= OFPFW11_IN_PORT;
    } else {
        ofmatch->in_port = ofputil_port_to_ofp11(match->flow.in_port.ofp_port);
    }

    memcpy(ofmatch->dl_src, match->flow.dl_src, ETH_ADDR_LEN);
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        ofmatch->dl_src_mask[i] = ~match->wc.masks.dl_src[i];
    }

    memcpy(ofmatch->dl_dst, match->flow.dl_dst, ETH_ADDR_LEN);
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        ofmatch->dl_dst_mask[i] = ~match->wc.masks.dl_dst[i];
    }

    if (match->wc.masks.vlan_tci == htons(0)) {
        wc |= OFPFW11_DL_VLAN | OFPFW11_DL_VLAN_PCP;
    } else if (match->wc.masks.vlan_tci & htons(VLAN_CFI)
               && !(match->flow.vlan_tci & htons(VLAN_CFI))) {
        ofmatch->dl_vlan = htons(OFPVID11_NONE);
        wc |= OFPFW11_DL_VLAN_PCP;
    } else {
        if (!(match->wc.masks.vlan_tci & htons(VLAN_VID_MASK))) {
            ofmatch->dl_vlan = htons(OFPVID11_ANY);
        } else {
            ofmatch->dl_vlan = htons(vlan_tci_to_vid(match->flow.vlan_tci));
        }

        if (!(match->wc.masks.vlan_tci & htons(VLAN_PCP_MASK))) {
            wc |= OFPFW11_DL_VLAN_PCP;
        } else {
            ofmatch->dl_vlan_pcp = vlan_tci_to_pcp(match->flow.vlan_tci);
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

    if (!(match->wc.masks.mpls_lse & htonl(MPLS_LABEL_MASK))) {
        wc |= OFPFW11_MPLS_LABEL;
    } else {
        ofmatch->mpls_label = htonl(mpls_lse_to_label(match->flow.mpls_lse));
    }

    if (!(match->wc.masks.mpls_lse & htonl(MPLS_TC_MASK))) {
        wc |= OFPFW11_MPLS_TC;
    } else {
        ofmatch->mpls_tc = mpls_lse_to_tc(match->flow.mpls_lse);
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
        return oxm_put_match(b, match);
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

static int
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
    default:
        OVS_NOT_REACHED();
    }
}

bool
ofputil_packet_in_format_is_valid(enum nx_packet_in_format packet_in_format)
{
    switch (packet_in_format) {
    case NXPIF_OPENFLOW10:
    case NXPIF_NXM:
        return true;
    }

    return false;
}

const char *
ofputil_packet_in_format_to_string(enum nx_packet_in_format packet_in_format)
{
    switch (packet_in_format) {
    case NXPIF_OPENFLOW10:
        return "openflow10";
    case NXPIF_NXM:
        return "nxm";
    default:
        OVS_NOT_REACHED();
    }
}

int
ofputil_packet_in_format_from_string(const char *s)
{
    return (!strcmp(s, "openflow10") ? NXPIF_OPENFLOW10
            : !strcmp(s, "nxm") ? NXPIF_NXM
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
     * should have no effect on session negotiation until Open vSwtich supports
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
    struct ofpbuf msg;
    bool ok = true;

    ofpbuf_use_const(&msg, oh, ntohs(oh->length));
    ofpbuf_pull(&msg, sizeof *oh);

    *allowed_versions = version_bitmap_from_version(oh->version);
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
                        struct ofpbuf *ofpacts,
                        ofp_port_t max_port, uint8_t max_table)
{
    ovs_be16 raw_flags;
    enum ofperr error;
    struct ofpbuf b;
    enum ofpraw raw;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT11_FLOW_MOD) {
        /* Standard OpenFlow 1.1+ flow_mod. */
        const struct ofp11_flow_mod *ofm;

        ofm = ofpbuf_pull(&b, sizeof *ofm);

        error = ofputil_pull_ofp11_match(&b, &fm->match, NULL);
        if (error) {
            return error;
        }

        error = ofpacts_pull_openflow_instructions(&b, b.size, oh->version,
                                                   ofpacts);
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
        fm->buffer_id = ntohl(ofm->buffer_id);
        error = ofputil_port_from_ofp11(ofm->out_port, &fm->out_port);
        if (error) {
            return error;
        }
        fm->out_group = ntohl(ofm->out_group);

        if ((ofm->command == OFPFC_DELETE
             || ofm->command == OFPFC_DELETE_STRICT)
            && ofm->out_group != htonl(OFPG_ANY)) {
            return OFPERR_OFPFMFC_UNKNOWN;
        }
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

            /* Now get the actions. */
            error = ofpacts_pull_openflow_actions(&b, b.size, oh->version,
                                                  ofpacts);
            if (error) {
                return error;
            }

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
            fm->buffer_id = ntohl(ofm->buffer_id);
            fm->out_port = u16_to_ofp(ntohs(ofm->out_port));
            fm->out_group = OFPG11_ANY;
            raw_flags = ofm->flags;
        } else if (raw == OFPRAW_NXT_FLOW_MOD) {
            /* Nicira extended flow_mod. */
            const struct nx_flow_mod *nfm;

            /* Dissect the message. */
            nfm = ofpbuf_pull(&b, sizeof *nfm);
            error = nx_pull_match(&b, ntohs(nfm->match_len),
                                  &fm->match, &fm->cookie, &fm->cookie_mask);
            if (error) {
                return error;
            }
            error = ofpacts_pull_openflow_actions(&b, b.size, oh->version,
                                                  ofpacts);
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
            fm->buffer_id = ntohl(nfm->buffer_id);
            fm->out_port = u16_to_ofp(ntohs(nfm->out_port));
            fm->out_group = OFPG11_ANY;
            raw_flags = nfm->flags;
        } else {
            OVS_NOT_REACHED();
        }

        fm->modify_cookie = fm->new_cookie != OVS_BE64_MAX;
        if (protocol & OFPUTIL_P_TID) {
            fm->command = command & 0xff;
            fm->table_id = command >> 8;
        } else {
            fm->command = command;
            fm->table_id = 0xff;
        }
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
                                     &fm->match.flow, max_port,
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
    const struct ofp13_meter_mod *omm;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);
    omm = ofpbuf_pull(&b, sizeof *omm);

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
        mm->meter.bands = bands->data;

        error = ofputil_pull_bands(&b, b.size, &mm->meter.n_bands, bands);
        if (error) {
            return error;
        }
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
ofputil_append_meter_config(struct list *replies,
                            const struct ofputil_meter_config *mc)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));
    size_t start_ofs = msg->size;
    struct ofp13_meter_config *reply = ofpbuf_put_uninit(msg, sizeof *reply);
    reply->flags = htons(mc->flags);
    reply->meter_id = htonl(mc->meter_id);

    ofputil_put_bands(mc->n_bands, mc->bands, msg);

    reply->length = htons(msg->size - start_ofs);

    ofpmp_postappend(replies, start_ofs);
}

/* Encode a meter stat for 'ms' and append it to 'replies'. */
void
ofputil_append_meter_stats(struct list *replies,
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
    if (!msg->l2) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    omc = ofpbuf_try_pull(msg, sizeof *omc);
    if (!omc) {
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "OFPMP_METER_CONFIG reply has %"PRIuSIZE" leftover bytes at end",
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
    if (!msg->l2) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    oms = ofpbuf_try_pull(msg, sizeof *oms);
    if (!oms) {
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "OFPMP_METER reply has %"PRIuSIZE" leftover bytes at end",
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
    case OFPUTIL_P_OF13_OXM: {
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
            ofm->cookie = fm->cookie;
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
        nfm = msg->l3;
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
    fsr->out_group = OFPG11_ANY;
    fsr->table_id = ofsr->table_id;
    fsr->cookie = fsr->cookie_mask = htonll(0);

    return 0;
}

static enum ofperr
ofputil_decode_ofpst11_flow_request(struct ofputil_flow_stats_request *fsr,
                                    struct ofpbuf *b, bool aggregate)
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
    error = ofputil_pull_ofp11_match(b, &fsr->match, NULL);
    if (error) {
        return error;
    }

    return 0;
}

static enum ofperr
ofputil_decode_nxst_flow_request(struct ofputil_flow_stats_request *fsr,
                                 struct ofpbuf *b, bool aggregate)
{
    const struct nx_flow_stats_request *nfsr;
    enum ofperr error;

    nfsr = ofpbuf_pull(b, sizeof *nfsr);
    error = nx_pull_match(b, ntohs(nfsr->match_len), &fsr->match,
                          &fsr->cookie, &fsr->cookie_mask);
    if (error) {
        return error;
    }
    if (b->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    fsr->aggregate = aggregate;
    fsr->out_port = u16_to_ofp(ntohs(nfsr->out_port));
    fsr->out_group = OFPG11_ANY;
    fsr->table_id = nfsr->table_id;

    return 0;
}

/* Constructs and returns an OFPT_QUEUE_GET_CONFIG request for the specified
 * 'port', suitable for OpenFlow version 'version'. */
struct ofpbuf *
ofputil_encode_queue_get_config_request(enum ofp_version version,
                                        ofp_port_t port)
{
    struct ofpbuf *request;

    if (version == OFP10_VERSION) {
        struct ofp10_queue_get_config_request *qgcr10;

        request = ofpraw_alloc(OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST,
                               version, 0);
        qgcr10 = ofpbuf_put_zeros(request, sizeof *qgcr10);
        qgcr10->port = htons(ofp_to_u16(port));
    } else {
        struct ofp11_queue_get_config_request *qgcr11;

        request = ofpraw_alloc(OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST,
                               version, 0);
        qgcr11 = ofpbuf_put_zeros(request, sizeof *qgcr11);
        qgcr11->port = ofputil_port_to_ofp11(port);
    }

    return request;
}

/* Parses OFPT_QUEUE_GET_CONFIG request 'oh', storing the port specified by the
 * request into '*port'.  Returns 0 if successful, otherwise an OpenFlow error
 * code. */
enum ofperr
ofputil_decode_queue_get_config_request(const struct ofp_header *oh,
                                        ofp_port_t *port)
{
    const struct ofp10_queue_get_config_request *qgcr10;
    const struct ofp11_queue_get_config_request *qgcr11;
    enum ofpraw raw;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);

    switch ((int) raw) {
    case OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST:
        qgcr10 = b.data;
        *port = u16_to_ofp(ntohs(qgcr10->port));
        return 0;

    case OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST:
        qgcr11 = b.data;
        return ofputil_port_from_ofp11(qgcr11->port, port);
    }

    OVS_NOT_REACHED();
}

/* Constructs and returns the beginning of a reply to
 * OFPT_QUEUE_GET_CONFIG_REQUEST 'oh'.  The caller may append information about
 * individual queues with ofputil_append_queue_get_config_reply(). */
struct ofpbuf *
ofputil_encode_queue_get_config_reply(const struct ofp_header *oh)
{
    struct ofp10_queue_get_config_reply *qgcr10;
    struct ofp11_queue_get_config_reply *qgcr11;
    struct ofpbuf *reply;
    enum ofperr error;
    struct ofpbuf b;
    enum ofpraw raw;
    ofp_port_t port;

    error = ofputil_decode_queue_get_config_request(oh, &port);
    ovs_assert(!error);

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);

    switch ((int) raw) {
    case OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST:
        reply = ofpraw_alloc_reply(OFPRAW_OFPT10_QUEUE_GET_CONFIG_REPLY,
                                   oh, 0);
        qgcr10 = ofpbuf_put_zeros(reply, sizeof *qgcr10);
        qgcr10->port = htons(ofp_to_u16(port));
        break;

    case OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST:
        reply = ofpraw_alloc_reply(OFPRAW_OFPT11_QUEUE_GET_CONFIG_REPLY,
                                   oh, 0);
        qgcr11 = ofpbuf_put_zeros(reply, sizeof *qgcr11);
        qgcr11->port = ofputil_port_to_ofp11(port);
        break;

    default:
        OVS_NOT_REACHED();
    }

    return reply;
}

static void
put_queue_rate(struct ofpbuf *reply, enum ofp_queue_properties property,
               uint16_t rate)
{
    if (rate != UINT16_MAX) {
        struct ofp_queue_prop_rate *oqpr;

        oqpr = ofpbuf_put_zeros(reply, sizeof *oqpr);
        oqpr->prop_header.property = htons(property);
        oqpr->prop_header.len = htons(sizeof *oqpr);
        oqpr->rate = htons(rate);
    }
}

/* Appends a queue description for 'queue_id' to the
 * OFPT_QUEUE_GET_CONFIG_REPLY already in 'oh'. */
void
ofputil_append_queue_get_config_reply(struct ofpbuf *reply,
                                      const struct ofputil_queue_config *oqc)
{
    const struct ofp_header *oh = reply->data;
    size_t start_ofs, len_ofs;
    ovs_be16 *len;

    start_ofs = reply->size;
    if (oh->version < OFP12_VERSION) {
        struct ofp10_packet_queue *opq10;

        opq10 = ofpbuf_put_zeros(reply, sizeof *opq10);
        opq10->queue_id = htonl(oqc->queue_id);
        len_ofs = (char *) &opq10->len - (char *) reply->data;
    } else {
        struct ofp11_queue_get_config_reply *qgcr11;
        struct ofp12_packet_queue *opq12;
        ovs_be32 port;

        qgcr11 = reply->l3;
        port = qgcr11->port;

        opq12 = ofpbuf_put_zeros(reply, sizeof *opq12);
        opq12->port = port;
        opq12->queue_id = htonl(oqc->queue_id);
        len_ofs = (char *) &opq12->len - (char *) reply->data;
    }

    put_queue_rate(reply, OFPQT_MIN_RATE, oqc->min_rate);
    put_queue_rate(reply, OFPQT_MAX_RATE, oqc->max_rate);

    len = ofpbuf_at(reply, len_ofs, sizeof *len);
    *len = htons(reply->size - start_ofs);
}

/* Decodes the initial part of an OFPT_QUEUE_GET_CONFIG_REPLY from 'reply' and
 * stores in '*port' the port that the reply is about.  The caller may call
 * ofputil_pull_queue_get_config_reply() to obtain information about individual
 * queues included in the reply.  Returns 0 if successful, otherwise an
 * ofperr.*/
enum ofperr
ofputil_decode_queue_get_config_reply(struct ofpbuf *reply, ofp_port_t *port)
{
    const struct ofp10_queue_get_config_reply *qgcr10;
    const struct ofp11_queue_get_config_reply *qgcr11;
    enum ofpraw raw;

    raw = ofpraw_pull_assert(reply);
    switch ((int) raw) {
    case OFPRAW_OFPT10_QUEUE_GET_CONFIG_REPLY:
        qgcr10 = ofpbuf_pull(reply, sizeof *qgcr10);
        *port = u16_to_ofp(ntohs(qgcr10->port));
        return 0;

    case OFPRAW_OFPT11_QUEUE_GET_CONFIG_REPLY:
        qgcr11 = ofpbuf_pull(reply, sizeof *qgcr11);
        return ofputil_port_from_ofp11(qgcr11->port, port);
    }

    OVS_NOT_REACHED();
}

static enum ofperr
parse_queue_rate(const struct ofp_queue_prop_header *hdr, uint16_t *rate)
{
    const struct ofp_queue_prop_rate *oqpr;

    if (hdr->len == htons(sizeof *oqpr)) {
        oqpr = (const struct ofp_queue_prop_rate *) hdr;
        *rate = ntohs(oqpr->rate);
        return 0;
    } else {
        return OFPERR_OFPBRC_BAD_LEN;
    }
}

/* Decodes information about a queue from the OFPT_QUEUE_GET_CONFIG_REPLY in
 * 'reply' and stores it in '*queue'.  ofputil_decode_queue_get_config_reply()
 * must already have pulled off the main header.
 *
 * This function returns EOF if the last queue has already been decoded, 0 if a
 * queue was successfully decoded into '*queue', or an ofperr if there was a
 * problem decoding 'reply'. */
int
ofputil_pull_queue_get_config_reply(struct ofpbuf *reply,
                                    struct ofputil_queue_config *queue)
{
    const struct ofp_header *oh;
    unsigned int opq_len;
    unsigned int len;

    if (!reply->size) {
        return EOF;
    }

    queue->min_rate = UINT16_MAX;
    queue->max_rate = UINT16_MAX;

    oh = reply->l2;
    if (oh->version < OFP12_VERSION) {
        const struct ofp10_packet_queue *opq10;

        opq10 = ofpbuf_try_pull(reply, sizeof *opq10);
        if (!opq10) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        queue->queue_id = ntohl(opq10->queue_id);
        len = ntohs(opq10->len);
        opq_len = sizeof *opq10;
    } else {
        const struct ofp12_packet_queue *opq12;

        opq12 = ofpbuf_try_pull(reply, sizeof *opq12);
        if (!opq12) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        queue->queue_id = ntohl(opq12->queue_id);
        len = ntohs(opq12->len);
        opq_len = sizeof *opq12;
    }

    if (len < opq_len || len > reply->size + opq_len || len % 8) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= opq_len;

    while (len > 0) {
        const struct ofp_queue_prop_header *hdr;
        unsigned int property;
        unsigned int prop_len;
        enum ofperr error = 0;

        hdr = ofpbuf_at_assert(reply, 0, sizeof *hdr);
        prop_len = ntohs(hdr->len);
        if (prop_len < sizeof *hdr || prop_len > reply->size || prop_len % 8) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        property = ntohs(hdr->property);
        switch (property) {
        case OFPQT_MIN_RATE:
            error = parse_queue_rate(hdr, &queue->min_rate);
            break;

        case OFPQT_MAX_RATE:
            error = parse_queue_rate(hdr, &queue->max_rate);
            break;

        default:
            VLOG_INFO_RL(&bad_ofmsg_rl, "unknown queue property %u", property);
            break;
        }
        if (error) {
            return error;
        }

        ofpbuf_pull(reply, prop_len);
        len -= prop_len;
    }
    return 0;
}

/* Converts an OFPST_FLOW, OFPST_AGGREGATE, NXST_FLOW, or NXST_AGGREGATE
 * request 'oh', into an abstract flow_stats_request in 'fsr'.  Returns 0 if
 * successful, otherwise an OpenFlow error code. */
enum ofperr
ofputil_decode_flow_stats_request(struct ofputil_flow_stats_request *fsr,
                                  const struct ofp_header *oh)
{
    enum ofpraw raw;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);
    switch ((int) raw) {
    case OFPRAW_OFPST10_FLOW_REQUEST:
        return ofputil_decode_ofpst10_flow_request(fsr, b.data, false);

    case OFPRAW_OFPST10_AGGREGATE_REQUEST:
        return ofputil_decode_ofpst10_flow_request(fsr, b.data, true);

    case OFPRAW_OFPST11_FLOW_REQUEST:
        return ofputil_decode_ofpst11_flow_request(fsr, &b, false);

    case OFPRAW_OFPST11_AGGREGATE_REQUEST:
        return ofputil_decode_ofpst11_flow_request(fsr, &b, true);

    case OFPRAW_NXST_FLOW_REQUEST:
        return ofputil_decode_nxst_flow_request(fsr, &b, false);

    case OFPRAW_NXST_AGGREGATE_REQUEST:
        return ofputil_decode_nxst_flow_request(fsr, &b, true);

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
    case OFPUTIL_P_OF13_OXM: {
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

        nfsr = msg->l3;
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
    enum ofperr error;
    enum ofpraw raw;

    error = (msg->l2
             ? ofpraw_decode(&raw, msg->l2)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }
    oh = msg->l2;

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST11_FLOW_REPLY
               || raw == OFPRAW_OFPST13_FLOW_REPLY) {
        const struct ofp11_flow_stats *ofs;
        size_t length;
        uint16_t padded_match_len;

        ofs = ofpbuf_try_pull(msg, sizeof *ofs);
        if (!ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply has %"PRIuSIZE" leftover "
                         "bytes at end", msg->size);
            return EINVAL;
        }

        length = ntohs(ofs->length);
        if (length < sizeof *ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply claims invalid "
                         "length %"PRIuSIZE, length);
            return EINVAL;
        }

        if (ofputil_pull_ofp11_match(msg, &fs->match, &padded_match_len)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply bad match");
            return EINVAL;
        }

        if (ofpacts_pull_openflow_instructions(msg, length - sizeof *ofs -
                                               padded_match_len, oh->version,
                                               ofpacts)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply bad instructions");
            return EINVAL;
        }

        fs->priority = ntohs(ofs->priority);
        fs->table_id = ofs->table_id;
        fs->duration_sec = ntohl(ofs->duration_sec);
        fs->duration_nsec = ntohl(ofs->duration_nsec);
        fs->idle_timeout = ntohs(ofs->idle_timeout);
        fs->hard_timeout = ntohs(ofs->hard_timeout);
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
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply has %"PRIuSIZE" leftover "
                         "bytes at end", msg->size);
            return EINVAL;
        }

        length = ntohs(ofs->length);
        if (length < sizeof *ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply claims invalid "
                         "length %"PRIuSIZE, length);
            return EINVAL;
        }

        if (ofpacts_pull_openflow_actions(msg, length - sizeof *ofs,
                                          oh->version, ofpacts)) {
            return EINVAL;
        }

        fs->cookie = get_32aligned_be64(&ofs->cookie);
        ofputil_match_from_ofp10_match(&ofs->match, &fs->match);
        fs->priority = ntohs(ofs->priority);
        fs->table_id = ofs->table_id;
        fs->duration_sec = ntohl(ofs->duration_sec);
        fs->duration_nsec = ntohl(ofs->duration_nsec);
        fs->idle_timeout = ntohs(ofs->idle_timeout);
        fs->hard_timeout = ntohs(ofs->hard_timeout);
        fs->idle_age = -1;
        fs->hard_age = -1;
        fs->packet_count = ntohll(get_32aligned_be64(&ofs->packet_count));
        fs->byte_count = ntohll(get_32aligned_be64(&ofs->byte_count));
        fs->flags = 0;
    } else if (raw == OFPRAW_NXST_FLOW_REPLY) {
        const struct nx_flow_stats *nfs;
        size_t match_len, actions_len, length;

        nfs = ofpbuf_try_pull(msg, sizeof *nfs);
        if (!nfs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW reply has %"PRIuSIZE" leftover "
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
        if (nx_pull_match(msg, match_len, &fs->match, NULL, NULL)) {
            return EINVAL;
        }

        actions_len = length - sizeof *nfs - ROUND_UP(match_len, 8);
        if (ofpacts_pull_openflow_actions(msg, actions_len, oh->version,
                                          ofpacts)) {
            return EINVAL;
        }

        fs->cookie = nfs->cookie;
        fs->table_id = nfs->table_id;
        fs->duration_sec = ntohl(nfs->duration_sec);
        fs->duration_nsec = ntohl(nfs->duration_nsec);
        fs->priority = ntohs(nfs->priority);
        fs->idle_timeout = ntohs(nfs->idle_timeout);
        fs->hard_timeout = ntohs(nfs->hard_timeout);
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
                                struct list *replies)
{
    struct ofpbuf *reply = ofpbuf_from_list(list_back(replies));
    size_t start_ofs = reply->size;
    enum ofpraw raw;
    enum ofp_version version = ((struct ofp_header *)reply->data)->version;

    ofpraw_decode_partial(&raw, reply->data, reply->size);
    if (raw == OFPRAW_OFPST11_FLOW_REPLY || raw == OFPRAW_OFPST13_FLOW_REPLY) {
        struct ofp11_flow_stats *ofs;

        ofpbuf_put_uninit(reply, sizeof *ofs);
        oxm_put_match(reply, &fs->match);
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
    struct ofp_aggregate_stats_reply *asr;
    struct ofpbuf msg;

    ofpbuf_use_const(&msg, reply, ntohs(reply->length));
    ofpraw_pull_assert(&msg);

    asr = msg.l3;
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
    enum ofpraw raw;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT11_FLOW_REMOVED) {
        const struct ofp12_flow_removed *ofr;
        enum ofperr error;

        ofr = ofpbuf_pull(&b, sizeof *ofr);

        error = ofputil_pull_ofp11_match(&b, &fr->match, NULL);
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
        error = nx_pull_match(&b, ntohs(nfr->match_len), &fr->match,
                              NULL, NULL);
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

    switch (protocol) {
    case OFPUTIL_P_OF11_STD:
    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM: {
        struct ofp12_flow_removed *ofr;

        msg = ofpraw_alloc_xid(OFPRAW_OFPT11_FLOW_REMOVED,
                               ofputil_protocol_to_ofp_version(protocol),
                               htonl(0),
                               ofputil_match_typical_len(protocol));
        ofr = ofpbuf_put_zeros(msg, sizeof *ofr);
        ofr->cookie = fr->cookie;
        ofr->priority = htons(fr->priority);
        ofr->reason = fr->reason;
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
        ofr->reason = fr->reason;
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
        nfr = ofpbuf_put_zeros(msg, sizeof *nfr);
        match_len = nx_put_match(msg, &fr->match, 0, 0);

        nfr = msg->l3;
        nfr->cookie = fr->cookie;
        nfr->priority = htons(fr->priority);
        nfr->reason = fr->reason;
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

static void
ofputil_decode_packet_in_finish(struct ofputil_packet_in *pin,
                                struct match *match, struct ofpbuf *b)
{
    pin->packet = b->data;
    pin->packet_len = b->size;

    pin->fmd.in_port = match->flow.in_port.ofp_port;
    pin->fmd.tun_id = match->flow.tunnel.tun_id;
    pin->fmd.tun_src = match->flow.tunnel.ip_src;
    pin->fmd.tun_dst = match->flow.tunnel.ip_dst;
    pin->fmd.metadata = match->flow.metadata;
    memcpy(pin->fmd.regs, match->flow.regs, sizeof pin->fmd.regs);
    pin->fmd.pkt_mark = match->flow.pkt_mark;
}

enum ofperr
ofputil_decode_packet_in(struct ofputil_packet_in *pin,
                         const struct ofp_header *oh)
{
    enum ofpraw raw;
    struct ofpbuf b;

    memset(pin, 0, sizeof *pin);
    pin->cookie = OVS_BE64_MAX;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT13_PACKET_IN || raw == OFPRAW_OFPT12_PACKET_IN) {
        const struct ofp13_packet_in *opi;
        struct match match;
        int error;
        size_t packet_in_size;

        if (raw == OFPRAW_OFPT12_PACKET_IN) {
            packet_in_size = sizeof (struct ofp12_packet_in);
        } else {
            packet_in_size = sizeof (struct ofp13_packet_in);
        }

        opi = ofpbuf_pull(&b, packet_in_size);
        error = oxm_pull_match_loose(&b, &match);
        if (error) {
            return error;
        }

        if (!ofpbuf_try_pull(&b, 2)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        pin->reason = opi->pi.reason;
        pin->table_id = opi->pi.table_id;
        pin->buffer_id = ntohl(opi->pi.buffer_id);
        pin->total_len = ntohs(opi->pi.total_len);

        if (raw == OFPRAW_OFPT13_PACKET_IN) {
            pin->cookie = opi->cookie;
        }

        ofputil_decode_packet_in_finish(pin, &match, &b);
    } else if (raw == OFPRAW_OFPT10_PACKET_IN) {
        const struct ofp10_packet_in *opi;

        opi = ofpbuf_pull(&b, offsetof(struct ofp10_packet_in, data));

        pin->packet = opi->data;
        pin->packet_len = b.size;

        pin->fmd.in_port = u16_to_ofp(ntohs(opi->in_port));
        pin->reason = opi->reason;
        pin->buffer_id = ntohl(opi->buffer_id);
        pin->total_len = ntohs(opi->total_len);
    } else if (raw == OFPRAW_OFPT11_PACKET_IN) {
        const struct ofp11_packet_in *opi;
        enum ofperr error;

        opi = ofpbuf_pull(&b, sizeof *opi);

        pin->packet = b.data;
        pin->packet_len = b.size;

        pin->buffer_id = ntohl(opi->buffer_id);
        error = ofputil_port_from_ofp11(opi->in_port, &pin->fmd.in_port);
        if (error) {
            return error;
        }
        pin->total_len = ntohs(opi->total_len);
        pin->reason = opi->reason;
        pin->table_id = opi->table_id;
    } else if (raw == OFPRAW_NXT_PACKET_IN) {
        const struct nx_packet_in *npi;
        struct match match;
        int error;

        npi = ofpbuf_pull(&b, sizeof *npi);
        error = nx_pull_match_loose(&b, ntohs(npi->match_len), &match, NULL,
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

        pin->buffer_id = ntohl(npi->buffer_id);
        pin->total_len = ntohs(npi->total_len);

        ofputil_decode_packet_in_finish(pin, &match, &b);
    } else {
        OVS_NOT_REACHED();
    }

    return 0;
}

static void
ofputil_packet_in_to_match(const struct ofputil_packet_in *pin,
                           struct match *match)
{
    int i;

    match_init_catchall(match);
    if (pin->fmd.tun_id != htonll(0)) {
        match_set_tun_id(match, pin->fmd.tun_id);
    }
    if (pin->fmd.tun_src != htonl(0)) {
        match_set_tun_src(match, pin->fmd.tun_src);
    }
    if (pin->fmd.tun_dst != htonl(0)) {
        match_set_tun_dst(match, pin->fmd.tun_dst);
    }
    if (pin->fmd.metadata != htonll(0)) {
        match_set_metadata(match, pin->fmd.metadata);
    }

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (pin->fmd.regs[i]) {
            match_set_reg(match, i, pin->fmd.regs[i]);
        }
    }

    if (pin->fmd.pkt_mark != 0) {
        match_set_pkt_mark(match, pin->fmd.pkt_mark);
    }

    match_set_in_port(match, pin->fmd.in_port);
}

static struct ofpbuf *
ofputil_encode_ofp10_packet_in(const struct ofputil_packet_in *pin)
{
    struct ofp10_packet_in *opi;
    struct ofpbuf *packet;

    packet = ofpraw_alloc_xid(OFPRAW_OFPT10_PACKET_IN, OFP10_VERSION,
                              htonl(0), pin->packet_len);
    opi = ofpbuf_put_zeros(packet, offsetof(struct ofp10_packet_in, data));
    opi->total_len = htons(pin->total_len);
    opi->in_port = htons(ofp_to_u16(pin->fmd.in_port));
    opi->reason = pin->reason;
    opi->buffer_id = htonl(pin->buffer_id);

    ofpbuf_put(packet, pin->packet, pin->packet_len);

    return packet;
}

static struct ofpbuf *
ofputil_encode_nx_packet_in(const struct ofputil_packet_in *pin)
{
    struct nx_packet_in *npi;
    struct ofpbuf *packet;
    struct match match;
    size_t match_len;

    ofputil_packet_in_to_match(pin, &match);

    /* The final argument is just an estimate of the space required. */
    packet = ofpraw_alloc_xid(OFPRAW_NXT_PACKET_IN, OFP10_VERSION,
                              htonl(0), (sizeof(struct flow_metadata) * 2
                                         + 2 + pin->packet_len));
    ofpbuf_put_zeros(packet, sizeof *npi);
    match_len = nx_put_match(packet, &match, 0, 0);
    ofpbuf_put_zeros(packet, 2);
    ofpbuf_put(packet, pin->packet, pin->packet_len);

    npi = packet->l3;
    npi->buffer_id = htonl(pin->buffer_id);
    npi->total_len = htons(pin->total_len);
    npi->reason = pin->reason;
    npi->table_id = pin->table_id;
    npi->cookie = pin->cookie;
    npi->match_len = htons(match_len);

    return packet;
}

static struct ofpbuf *
ofputil_encode_ofp11_packet_in(const struct ofputil_packet_in *pin)
{
    struct ofp11_packet_in *opi;
    struct ofpbuf *packet;

    packet = ofpraw_alloc_xid(OFPRAW_OFPT11_PACKET_IN, OFP11_VERSION,
                              htonl(0), pin->packet_len);
    opi = ofpbuf_put_zeros(packet, sizeof *opi);
    opi->buffer_id = htonl(pin->buffer_id);
    opi->in_port = ofputil_port_to_ofp11(pin->fmd.in_port);
    opi->in_phy_port = opi->in_port;
    opi->total_len = htons(pin->total_len);
    opi->reason = pin->reason;
    opi->table_id = pin->table_id;

    ofpbuf_put(packet, pin->packet, pin->packet_len);

    return packet;
}

static struct ofpbuf *
ofputil_encode_ofp12_packet_in(const struct ofputil_packet_in *pin,
                               enum ofputil_protocol protocol)
{
    struct ofp13_packet_in *opi;
    struct match match;
    enum ofpraw packet_in_raw;
    enum ofp_version packet_in_version;
    size_t packet_in_size;
    struct ofpbuf *packet;

    if (protocol == OFPUTIL_P_OF12_OXM) {
        packet_in_raw = OFPRAW_OFPT12_PACKET_IN;
        packet_in_version = OFP12_VERSION;
        packet_in_size = sizeof (struct ofp12_packet_in);
    } else {
        packet_in_raw = OFPRAW_OFPT13_PACKET_IN;
        packet_in_version = OFP13_VERSION;
        packet_in_size = sizeof (struct ofp13_packet_in);
    }

    ofputil_packet_in_to_match(pin, &match);

    /* The final argument is just an estimate of the space required. */
    packet = ofpraw_alloc_xid(packet_in_raw, packet_in_version,
                              htonl(0), (sizeof(struct flow_metadata) * 2
                                         + 2 + pin->packet_len));
    ofpbuf_put_zeros(packet, packet_in_size);
    oxm_put_match(packet, &match);
    ofpbuf_put_zeros(packet, 2);
    ofpbuf_put(packet, pin->packet, pin->packet_len);

    opi = packet->l3;
    opi->pi.buffer_id = htonl(pin->buffer_id);
    opi->pi.total_len = htons(pin->total_len);
    opi->pi.reason = pin->reason;
    opi->pi.table_id = pin->table_id;
    if (protocol == OFPUTIL_P_OF13_OXM) {
        opi->cookie = pin->cookie;
    }

    return packet;
}

/* Converts abstract ofputil_packet_in 'pin' into a PACKET_IN message
 * in the format specified by 'packet_in_format'.  */
struct ofpbuf *
ofputil_encode_packet_in(const struct ofputil_packet_in *pin,
                         enum ofputil_protocol protocol,
                         enum nx_packet_in_format packet_in_format)
{
    struct ofpbuf *packet;

    switch (protocol) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        packet = (packet_in_format == NXPIF_NXM
                  ? ofputil_encode_nx_packet_in(pin)
                  : ofputil_encode_ofp10_packet_in(pin));
        break;

    case OFPUTIL_P_OF11_STD:
        packet = ofputil_encode_ofp11_packet_in(pin);
        break;

    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
        packet = ofputil_encode_ofp12_packet_in(pin, protocol);
        break;

    default:
        OVS_NOT_REACHED();
    }

    ofpmsg_update_length(packet);
    return packet;
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

/* Converts an OFPT_PACKET_OUT in 'opo' into an abstract ofputil_packet_out in
 * 'po'.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of the packet out
 * message's actions.  The caller must initialize 'ofpacts' and retains
 * ownership of it.  'po->ofpacts' will point into the 'ofpacts' buffer.
 *
 * Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_packet_out(struct ofputil_packet_out *po,
                          const struct ofp_header *oh,
                          struct ofpbuf *ofpacts)
{
    enum ofpraw raw;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);

    if (raw == OFPRAW_OFPT11_PACKET_OUT) {
        enum ofperr error;
        const struct ofp11_packet_out *opo = ofpbuf_pull(&b, sizeof *opo);

        po->buffer_id = ntohl(opo->buffer_id);
        error = ofputil_port_from_ofp11(opo->in_port, &po->in_port);
        if (error) {
            return error;
        }

        error = ofpacts_pull_openflow_actions(&b, ntohs(opo->actions_len),
                                              oh->version, ofpacts);
        if (error) {
            return error;
        }
    } else if (raw == OFPRAW_OFPT10_PACKET_OUT) {
        enum ofperr error;
        const struct ofp10_packet_out *opo = ofpbuf_pull(&b, sizeof *opo);

        po->buffer_id = ntohl(opo->buffer_id);
        po->in_port = u16_to_ofp(ntohs(opo->in_port));

        error = ofpacts_pull_openflow_actions(&b, ntohs(opo->actions_len),
                                              oh->version, ofpacts);
        if (error) {
            return error;
        }
    } else {
        OVS_NOT_REACHED();
    }

    if (ofp_to_u16(po->in_port) >= ofp_to_u16(OFPP_MAX)
        && po->in_port != OFPP_LOCAL
        && po->in_port != OFPP_NONE && po->in_port != OFPP_CONTROLLER) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "packet-out has bad input port %#"PRIx16,
                     po->in_port);
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
    memset(pp, 0, sizeof *pp);

    pp->port_no = u16_to_ofp(ntohs(opp->port_no));
    memcpy(pp->hw_addr, opp->hw_addr, OFP_ETH_ALEN);
    ovs_strlcpy(pp->name, opp->name, OFP_MAX_PORT_NAME_LEN);

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

    memset(pp, 0, sizeof *pp);

    error = ofputil_port_from_ofp11(op->port_no, &pp->port_no);
    if (error) {
        return error;
    }
    memcpy(pp->hw_addr, op->hw_addr, OFP_ETH_ALEN);
    ovs_strlcpy(pp->name, op->name, OFP_MAX_PORT_NAME_LEN);

    pp->config = ntohl(op->config) & OFPPC11_ALL;
    pp->state = ntohl(op->state) & OFPPC11_ALL;

    pp->curr = netdev_port_features_from_ofp11(op->curr);
    pp->advertised = netdev_port_features_from_ofp11(op->advertised);
    pp->supported = netdev_port_features_from_ofp11(op->supported);
    pp->peer = netdev_port_features_from_ofp11(op->peer);

    pp->curr_speed = ntohl(op->curr_speed);
    pp->max_speed = ntohl(op->max_speed);

    return 0;
}

static size_t
ofputil_get_phy_port_size(enum ofp_version ofp_version)
{
    switch (ofp_version) {
    case OFP10_VERSION:
        return sizeof(struct ofp10_phy_port);
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
        return sizeof(struct ofp11_port);
    default:
        OVS_NOT_REACHED();
    }
}

static void
ofputil_encode_ofp10_phy_port(const struct ofputil_phy_port *pp,
                              struct ofp10_phy_port *opp)
{
    memset(opp, 0, sizeof *opp);

    opp->port_no = htons(ofp_to_u16(pp->port_no));
    memcpy(opp->hw_addr, pp->hw_addr, ETH_ADDR_LEN);
    ovs_strlcpy(opp->name, pp->name, OFP_MAX_PORT_NAME_LEN);

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
    memcpy(op->hw_addr, pp->hw_addr, ETH_ADDR_LEN);
    ovs_strlcpy(op->name, pp->name, OFP_MAX_PORT_NAME_LEN);

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
ofputil_put_phy_port(enum ofp_version ofp_version,
                     const struct ofputil_phy_port *pp, struct ofpbuf *b)
{
    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_phy_port *opp;
        if (b->size + sizeof *opp <= UINT16_MAX) {
            opp = ofpbuf_put_uninit(b, sizeof *opp);
            ofputil_encode_ofp10_phy_port(pp, opp);
        }
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_port *op;
        if (b->size + sizeof *op <= UINT16_MAX) {
            op = ofpbuf_put_uninit(b, sizeof *op);
            ofputil_encode_ofp11_port(pp, op);
        }
        break;
    }

    default:
        OVS_NOT_REACHED();
    }
}

void
ofputil_append_port_desc_stats_reply(enum ofp_version ofp_version,
                                     const struct ofputil_phy_port *pp,
                                     struct list *replies)
{
    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_phy_port *opp;

        opp = ofpmp_append(replies, sizeof *opp);
        ofputil_encode_ofp10_phy_port(pp, opp);
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_port *op;

        op = ofpmp_append(replies, sizeof *op);
        ofputil_encode_ofp11_port(pp, op);
        break;
    }

    default:
      OVS_NOT_REACHED();
    }
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

struct ofputil_action_bit_translation {
    enum ofputil_action_bitmap ofputil_bit;
    int of_bit;
};

static const struct ofputil_action_bit_translation of10_action_bits[] = {
    { OFPUTIL_A_OUTPUT,       OFPAT10_OUTPUT },
    { OFPUTIL_A_SET_VLAN_VID, OFPAT10_SET_VLAN_VID },
    { OFPUTIL_A_SET_VLAN_PCP, OFPAT10_SET_VLAN_PCP },
    { OFPUTIL_A_STRIP_VLAN,   OFPAT10_STRIP_VLAN },
    { OFPUTIL_A_SET_DL_SRC,   OFPAT10_SET_DL_SRC },
    { OFPUTIL_A_SET_DL_DST,   OFPAT10_SET_DL_DST },
    { OFPUTIL_A_SET_NW_SRC,   OFPAT10_SET_NW_SRC },
    { OFPUTIL_A_SET_NW_DST,   OFPAT10_SET_NW_DST },
    { OFPUTIL_A_SET_NW_TOS,   OFPAT10_SET_NW_TOS },
    { OFPUTIL_A_SET_TP_SRC,   OFPAT10_SET_TP_SRC },
    { OFPUTIL_A_SET_TP_DST,   OFPAT10_SET_TP_DST },
    { OFPUTIL_A_ENQUEUE,      OFPAT10_ENQUEUE },
    { 0, 0 },
};

static enum ofputil_action_bitmap
decode_action_bits(ovs_be32 of_actions,
                   const struct ofputil_action_bit_translation *x)
{
    enum ofputil_action_bitmap ofputil_actions;

    ofputil_actions = 0;
    for (; x->ofputil_bit; x++) {
        if (of_actions & htonl(1u << x->of_bit)) {
            ofputil_actions |= x->ofputil_bit;
        }
    }
    return ofputil_actions;
}

static uint32_t
ofputil_capabilities_mask(enum ofp_version ofp_version)
{
    /* Handle capabilities whose bit is unique for all Open Flow versions */
    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
        return OFPC_COMMON | OFPC_ARP_MATCH_IP;
    case OFP12_VERSION:
    case OFP13_VERSION:
        return OFPC_COMMON | OFPC12_PORT_BLOCKED;
    default:
        /* Caller needs to check osf->header.version itself */
        return 0;
    }
}

/* Decodes an OpenFlow 1.0 or 1.1 "switch_features" structure 'osf' into an
 * abstract representation in '*features'.  Initializes '*b' to iterate over
 * the OpenFlow port structures following 'osf' with later calls to
 * ofputil_pull_phy_port().  Returns 0 if successful, otherwise an
 * OFPERR_* value.  */
enum ofperr
ofputil_decode_switch_features(const struct ofp_header *oh,
                               struct ofputil_switch_features *features,
                               struct ofpbuf *b)
{
    const struct ofp_switch_features *osf;
    enum ofpraw raw;

    ofpbuf_use_const(b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(b);

    osf = ofpbuf_pull(b, sizeof *osf);
    features->datapath_id = ntohll(osf->datapath_id);
    features->n_buffers = ntohl(osf->n_buffers);
    features->n_tables = osf->n_tables;
    features->auxiliary_id = 0;

    features->capabilities = ntohl(osf->capabilities) &
        ofputil_capabilities_mask(oh->version);

    if (b->size % ofputil_get_phy_port_size(oh->version)) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    if (raw == OFPRAW_OFPT10_FEATURES_REPLY) {
        if (osf->capabilities & htonl(OFPC10_STP)) {
            features->capabilities |= OFPUTIL_C_STP;
        }
        features->actions = decode_action_bits(osf->actions, of10_action_bits);
    } else if (raw == OFPRAW_OFPT11_FEATURES_REPLY
               || raw == OFPRAW_OFPT13_FEATURES_REPLY) {
        if (osf->capabilities & htonl(OFPC11_GROUP_STATS)) {
            features->capabilities |= OFPUTIL_C_GROUP_STATS;
        }
        features->actions = 0;
        if (raw == OFPRAW_OFPT13_FEATURES_REPLY) {
            features->auxiliary_id = osf->auxiliary_id;
        }
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
    }

    return 0;
}

/* Returns true if the maximum number of ports are in 'oh'. */
static bool
max_ports_in_features(const struct ofp_header *oh)
{
    size_t pp_size = ofputil_get_phy_port_size(oh->version);
    return ntohs(oh->length) + pp_size > UINT16_MAX;
}

/* Given a buffer 'b' that contains a Features Reply message, checks if
 * it contains the maximum number of ports that will fit.  If so, it
 * returns true and removes the ports from the message.  The caller
 * should then send an OFPST_PORT_DESC stats request to get the ports,
 * since the switch may have more ports than could be represented in the
 * Features Reply.  Otherwise, returns false.
 */
bool
ofputil_switch_features_ports_trunc(struct ofpbuf *b)
{
    struct ofp_header *oh = b->data;

    if (max_ports_in_features(oh)) {
        /* Remove all the ports. */
        b->size = (sizeof(struct ofp_header)
                   + sizeof(struct ofp_switch_features));
        ofpmsg_update_length(b);

        return true;
    }

    return false;
}

static ovs_be32
encode_action_bits(enum ofputil_action_bitmap ofputil_actions,
                   const struct ofputil_action_bit_translation *x)
{
    uint32_t of_actions;

    of_actions = 0;
    for (; x->ofputil_bit; x++) {
        if (ofputil_actions & x->ofputil_bit) {
            of_actions |= 1 << x->of_bit;
        }
    }
    return htonl(of_actions);
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

    osf->capabilities = htonl(features->capabilities & OFPC_COMMON);
    osf->capabilities = htonl(features->capabilities &
                              ofputil_capabilities_mask(version));
    switch (version) {
    case OFP10_VERSION:
        if (features->capabilities & OFPUTIL_C_STP) {
            osf->capabilities |= htonl(OFPC10_STP);
        }
        osf->actions = encode_action_bits(features->actions, of10_action_bits);
        break;
    case OFP13_VERSION:
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
        ofputil_put_phy_port(oh->version, pp, b);
    }
}

/* ofputil_port_status */

/* Decodes the OpenFlow "port status" message in '*ops' into an abstract form
 * in '*ps'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_port_status(const struct ofp_header *oh,
                           struct ofputil_port_status *ps)
{
    const struct ofp_port_status *ops;
    struct ofpbuf b;
    int retval;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);
    ops = ofpbuf_pull(&b, sizeof *ops);

    if (ops->reason != OFPPR_ADD &&
        ops->reason != OFPPR_DELETE &&
        ops->reason != OFPPR_MODIFY) {
        return OFPERR_NXBRC_BAD_REASON;
    }
    ps->reason = ops->reason;

    retval = ofputil_pull_phy_port(oh->version, &b, &ps->desc);
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

/* Decodes the OpenFlow "port mod" message in '*oh' into an abstract form in
 * '*pm'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_port_mod(const struct ofp_header *oh,
                        struct ofputil_port_mod *pm)
{
    enum ofpraw raw;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);

    if (raw == OFPRAW_OFPT10_PORT_MOD) {
        const struct ofp10_port_mod *opm = b.data;

        pm->port_no = u16_to_ofp(ntohs(opm->port_no));
        memcpy(pm->hw_addr, opm->hw_addr, ETH_ADDR_LEN);
        pm->config = ntohl(opm->config) & OFPPC10_ALL;
        pm->mask = ntohl(opm->mask) & OFPPC10_ALL;
        pm->advertise = netdev_port_features_from_ofp10(opm->advertise);
    } else if (raw == OFPRAW_OFPT11_PORT_MOD) {
        const struct ofp11_port_mod *opm = b.data;
        enum ofperr error;

        error = ofputil_port_from_ofp11(opm->port_no, &pm->port_no);
        if (error) {
            return error;
        }

        memcpy(pm->hw_addr, opm->hw_addr, ETH_ADDR_LEN);
        pm->config = ntohl(opm->config) & OFPPC11_ALL;
        pm->mask = ntohl(opm->mask) & OFPPC11_ALL;
        pm->advertise = netdev_port_features_from_ofp11(opm->advertise);
    } else {
        return OFPERR_OFPBRC_BAD_TYPE;
    }

    pm->config &= pm->mask;
    return 0;
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
        memcpy(opm->hw_addr, pm->hw_addr, ETH_ADDR_LEN);
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
        memcpy(opm->hw_addr, pm->hw_addr, ETH_ADDR_LEN);
        opm->config = htonl(pm->config & OFPPC11_ALL);
        opm->mask = htonl(pm->mask & OFPPC11_ALL);
        opm->advertise = netdev_port_features_to_ofp11(pm->advertise);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return b;
}

/* ofputil_table_mod */

/* Decodes the OpenFlow "table mod" message in '*oh' into an abstract form in
 * '*pm'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_table_mod(const struct ofp_header *oh,
                         struct ofputil_table_mod *pm)
{
    enum ofpraw raw;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);

    if (raw == OFPRAW_OFPT11_TABLE_MOD) {
        const struct ofp11_table_mod *otm = b.data;

        pm->table_id = otm->table_id;
        pm->config = ntohl(otm->config);
    } else {
        return OFPERR_OFPBRC_BAD_TYPE;
    }

    return 0;
}

/* Converts the abstract form of a "table mod" message in '*pm' into an OpenFlow
 * message suitable for 'protocol', and returns that encoded form in a buffer
 * owned by the caller. */
struct ofpbuf *
ofputil_encode_table_mod(const struct ofputil_table_mod *pm,
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
        otm->table_id = pm->table_id;
        otm->config = htonl(pm->config);
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
    struct ofpbuf b;
    enum ofpraw raw;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);

    if (raw == OFPRAW_OFPT12_ROLE_REQUEST ||
        raw == OFPRAW_OFPT12_ROLE_REPLY) {
        const struct ofp12_role_request *orr = b.l3;

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
        const struct nx_role_request *nrr = b.l3;

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

struct ofpbuf *
ofputil_encode_role_status(const struct ofputil_role_status *status,
                           enum ofputil_protocol protocol)
{
    struct ofpbuf *buf;
    enum ofp_version version;
    struct ofp14_role_status *rstatus;

    version = ofputil_protocol_to_ofp_version(protocol);
    buf = ofpraw_alloc_xid(OFPRAW_OFPT14_ROLE_STATUS, version, htonl(0), 0);
    rstatus = ofpbuf_put_zeros(buf, sizeof *rstatus);
    rstatus->role = htonl(status->role);
    rstatus->reason = status->reason;
    rstatus->generation_id = htonll(status->generation_id);

    return buf;
}

enum ofperr
ofputil_decode_role_status(const struct ofp_header *oh,
                           struct ofputil_role_status *rs)
{
    struct ofpbuf b;
    enum ofpraw raw;
    const struct ofp14_role_status *r;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);
    ovs_assert(raw == OFPRAW_OFPT14_ROLE_STATUS);

    r = b.l3;
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

/* Table stats. */

static void
ofputil_put_ofp10_table_stats(const struct ofp12_table_stats *in,
                              struct ofpbuf *buf)
{
    struct wc_map {
        enum ofp10_flow_wildcards wc10;
        enum oxm12_ofb_match_fields mf12;
    };

    static const struct wc_map wc_map[] = {
        { OFPFW10_IN_PORT,     OFPXMT12_OFB_IN_PORT },
        { OFPFW10_DL_VLAN,     OFPXMT12_OFB_VLAN_VID },
        { OFPFW10_DL_SRC,      OFPXMT12_OFB_ETH_SRC },
        { OFPFW10_DL_DST,      OFPXMT12_OFB_ETH_DST},
        { OFPFW10_DL_TYPE,     OFPXMT12_OFB_ETH_TYPE },
        { OFPFW10_NW_PROTO,    OFPXMT12_OFB_IP_PROTO },
        { OFPFW10_TP_SRC,      OFPXMT12_OFB_TCP_SRC },
        { OFPFW10_TP_DST,      OFPXMT12_OFB_TCP_DST },
        { OFPFW10_NW_SRC_MASK, OFPXMT12_OFB_IPV4_SRC },
        { OFPFW10_NW_DST_MASK, OFPXMT12_OFB_IPV4_DST },
        { OFPFW10_DL_VLAN_PCP, OFPXMT12_OFB_VLAN_PCP },
        { OFPFW10_NW_TOS,      OFPXMT12_OFB_IP_DSCP },
    };

    struct ofp10_table_stats *out;
    const struct wc_map *p;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = in->table_id;
    ovs_strlcpy(out->name, in->name, sizeof out->name);
    out->wildcards = 0;
    for (p = wc_map; p < &wc_map[ARRAY_SIZE(wc_map)]; p++) {
        if (in->wildcards & htonll(1ULL << p->mf12)) {
            out->wildcards |= htonl(p->wc10);
        }
    }
    out->max_entries = in->max_entries;
    out->active_count = in->active_count;
    put_32aligned_be64(&out->lookup_count, in->lookup_count);
    put_32aligned_be64(&out->matched_count, in->matched_count);
}

static ovs_be32
oxm12_to_ofp11_flow_match_fields(ovs_be64 oxm12)
{
    struct map {
        enum ofp11_flow_match_fields fmf11;
        enum oxm12_ofb_match_fields mf12;
    };

    static const struct map map[] = {
        { OFPFMF11_IN_PORT,     OFPXMT12_OFB_IN_PORT },
        { OFPFMF11_DL_VLAN,     OFPXMT12_OFB_VLAN_VID },
        { OFPFMF11_DL_VLAN_PCP, OFPXMT12_OFB_VLAN_PCP },
        { OFPFMF11_DL_TYPE,     OFPXMT12_OFB_ETH_TYPE },
        { OFPFMF11_NW_TOS,      OFPXMT12_OFB_IP_DSCP },
        { OFPFMF11_NW_PROTO,    OFPXMT12_OFB_IP_PROTO },
        { OFPFMF11_TP_SRC,      OFPXMT12_OFB_TCP_SRC },
        { OFPFMF11_TP_DST,      OFPXMT12_OFB_TCP_DST },
        { OFPFMF11_MPLS_LABEL,  OFPXMT12_OFB_MPLS_LABEL },
        { OFPFMF11_MPLS_TC,     OFPXMT12_OFB_MPLS_TC },
        /* I don't know what OFPFMF11_TYPE means. */
        { OFPFMF11_DL_SRC,      OFPXMT12_OFB_ETH_SRC },
        { OFPFMF11_DL_DST,      OFPXMT12_OFB_ETH_DST },
        { OFPFMF11_NW_SRC,      OFPXMT12_OFB_IPV4_SRC },
        { OFPFMF11_NW_DST,      OFPXMT12_OFB_IPV4_DST },
        { OFPFMF11_METADATA,    OFPXMT12_OFB_METADATA },
    };

    const struct map *p;
    uint32_t fmf11;

    fmf11 = 0;
    for (p = map; p < &map[ARRAY_SIZE(map)]; p++) {
        if (oxm12 & htonll(1ULL << p->mf12)) {
            fmf11 |= p->fmf11;
        }
    }
    return htonl(fmf11);
}

static void
ofputil_put_ofp11_table_stats(const struct ofp12_table_stats *in,
                              struct ofpbuf *buf)
{
    struct ofp11_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = in->table_id;
    ovs_strlcpy(out->name, in->name, sizeof out->name);
    out->wildcards = oxm12_to_ofp11_flow_match_fields(in->wildcards);
    out->match = oxm12_to_ofp11_flow_match_fields(in->match);
    out->instructions = in->instructions;
    out->write_actions = in->write_actions;
    out->apply_actions = in->apply_actions;
    out->config = in->config;
    out->max_entries = in->max_entries;
    out->active_count = in->active_count;
    out->lookup_count = in->lookup_count;
    out->matched_count = in->matched_count;
}

static void
ofputil_put_ofp12_table_stats(const struct ofp12_table_stats *in,
                              struct ofpbuf *buf)
{
    struct ofp12_table_stats *out = ofpbuf_put(buf, in, sizeof *in);

    /* Trim off OF1.3-only capabilities. */
    out->match &= htonll(OFPXMT12_MASK);
    out->wildcards &= htonll(OFPXMT12_MASK);
    out->write_setfields &= htonll(OFPXMT12_MASK);
    out->apply_setfields &= htonll(OFPXMT12_MASK);
}

static void
ofputil_put_ofp13_table_stats(const struct ofp12_table_stats *in,
                              struct ofpbuf *buf)
{
    struct ofp13_table_stats *out;

    /* OF 1.3 splits table features off the ofp_table_stats,
     * so there is not much here. */

    out = ofpbuf_put_uninit(buf, sizeof *out);
    out->table_id = in->table_id;
    out->active_count = in->active_count;
    out->lookup_count = in->lookup_count;
    out->matched_count = in->matched_count;
}

struct ofpbuf *
ofputil_encode_table_stats_reply(const struct ofp12_table_stats stats[], int n,
                                 const struct ofp_header *request)
{
    struct ofpbuf *reply;
    int i;

    reply = ofpraw_alloc_stats_reply(request, n * sizeof *stats);

    for (i = 0; i < n; i++) {
        switch ((enum ofp_version) request->version) {
        case OFP10_VERSION:
            ofputil_put_ofp10_table_stats(&stats[i], reply);
            break;

        case OFP11_VERSION:
            ofputil_put_ofp11_table_stats(&stats[i], reply);
            break;

        case OFP12_VERSION:
            ofputil_put_ofp12_table_stats(&stats[i], reply);
            break;

        case OFP13_VERSION:
            ofputil_put_ofp13_table_stats(&stats[i], reply);
            break;

        default:
            OVS_NOT_REACHED();
        }
    }

    return reply;
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

    if (!msg->l2) {
        msg->l2 = msg->data;
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    nfmr = ofpbuf_try_pull(msg, sizeof *nfmr);
    if (!nfmr) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW_MONITOR request has %"PRIuSIZE" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    flags = ntohs(nfmr->flags);
    if (!(flags & (NXFMF_ADD | NXFMF_DELETE | NXFMF_MODIFY))
        || flags & ~(NXFMF_INITIAL | NXFMF_ADD | NXFMF_DELETE
                     | NXFMF_MODIFY | NXFMF_ACTIONS | NXFMF_OWN)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW_MONITOR has bad flags %#"PRIx16,
                     flags);
        return OFPERR_NXBRC_FM_BAD_FLAGS;
    }

    if (!is_all_zeros(nfmr->zeros, sizeof nfmr->zeros)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    rq->id = ntohl(nfmr->id);
    rq->flags = flags;
    rq->out_port = u16_to_ofp(ntohs(nfmr->out_port));
    rq->table_id = nfmr->table_id;

    return nx_pull_match(msg, ntohs(nfmr->match_len), &rq->match, NULL, NULL);
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

    if (!msg->l2) {
        msg->l2 = msg->data;
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    if (msg->size < sizeof(struct nx_flow_update_header)) {
        goto bad_len;
    }

    oh = msg->l2;

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

        error = nx_pull_match(msg, match_len, update->match, NULL, NULL);
        if (error) {
            return error;
        }

        actions_len = length - sizeof *nfuf - ROUND_UP(match_len, 8);
        error = ofpacts_pull_openflow_actions(msg, actions_len, oh->version,
                                              ofpacts);
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
    VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW_MONITOR reply has %"PRIuSIZE" "
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
ofputil_start_flow_update(struct list *replies)
{
    struct ofpbuf *msg;

    msg = ofpraw_alloc_xid(OFPRAW_NXST_FLOW_MONITOR_REPLY, OFP10_VERSION,
                           htonl(0), 1024);

    list_init(replies);
    list_push_back(replies, &msg->list_node);
}

void
ofputil_append_flow_update(const struct ofputil_flow_update *update,
                           struct list *replies)
{
    struct nx_flow_update_header *nfuh;
    struct ofpbuf *msg;
    size_t start_ofs;
    enum ofp_version version;

    msg = ofpbuf_from_list(list_back(replies));
    start_ofs = msg->size;
    version = ((struct ofp_header *)msg->l2)->version;

    if (update->event == NXFME_ABBREV) {
        struct nx_flow_update_abbrev *nfua;

        nfua = ofpbuf_put_zeros(msg, sizeof *nfua);
        nfua->xid = update->xid;
    } else {
        struct nx_flow_update_full *nfuf;
        int match_len;

        ofpbuf_put_zeros(msg, sizeof *nfuf);
        match_len = nx_put_match(msg, update->match, htonll(0), htonll(0));
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

        opo = msg->l3;
        opo->buffer_id = htonl(po->buffer_id);
        opo->in_port = htons(ofp_to_u16(po->in_port));
        opo->actions_len = htons(msg->size - actions_ofs);
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_packet_out *opo;
        size_t len;

        msg = ofpraw_alloc(OFPRAW_OFPT11_PACKET_OUT, ofp_version, size);
        ofpbuf_put_zeros(msg, sizeof *opo);
        len = ofpacts_put_openflow_actions(po->ofpacts, po->ofpacts_len, msg,
                                           ofp_version);
        opo = msg->l3;
        opo->buffer_id = htonl(po->buffer_id);
        opo->in_port = ofputil_port_to_ofp11(po->in_port);
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
    struct ofpbuf rq_buf;
    struct ofpbuf *reply;

    ofpbuf_use_const(&rq_buf, rq, ntohs(rq->length));
    ofpraw_pull_assert(&rq_buf);

    reply = ofpraw_alloc_reply(OFPRAW_OFPT_ECHO_REPLY, rq, rq_buf.size);
    ofpbuf_put(reply, rq_buf.data, rq_buf.size);
    return reply;
}

struct ofpbuf *
ofputil_encode_barrier_request(enum ofp_version ofp_version)
{
    enum ofpraw type;

    switch (ofp_version) {
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
ofputil_frag_handling_to_string(enum ofp_config_flags flags)
{
    switch (flags & OFPC_FRAG_MASK) {
    case OFPC_FRAG_NORMAL:   return "normal";
    case OFPC_FRAG_DROP:     return "drop";
    case OFPC_FRAG_REASM:    return "reassemble";
    case OFPC_FRAG_NX_MATCH: return "nx-match";
    }

    OVS_NOT_REACHED();
}

bool
ofputil_frag_handling_from_string(const char *s, enum ofp_config_flags *flags)
{
    if (!strcasecmp(s, "normal")) {
        *flags = OFPC_FRAG_NORMAL;
    } else if (!strcasecmp(s, "drop")) {
        *flags = OFPC_FRAG_DROP;
    } else if (!strcasecmp(s, "reassemble")) {
        *flags = OFPC_FRAG_REASM;
    } else if (!strcasecmp(s, "nx-match")) {
        *flags = OFPC_FRAG_NX_MATCH;
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
        OFPUTIL_NAMED_PORT(ANY)

/* For backwards compatibility, so that "none" is recognized as OFPP_ANY */
#define OFPUTIL_NAMED_PORTS_WITH_NONE           \
        OFPUTIL_NAMED_PORTS                     \
        OFPUTIL_NAMED_PORT(NONE)

/* Stores the port number represented by 's' into '*portp'.  's' may be an
 * integer or, for reserved ports, the standard OpenFlow name for the port
 * (e.g. "LOCAL").
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
ofputil_port_from_string(const char *s, ofp_port_t *portp)
{
    uint32_t port32;

    *portp = 0;
    if (str_to_uint(s, 10, &port32)) {
        if (port32 < ofp_to_u16(OFPP_MAX)) {
            /* Pass. */
        } else if (port32 < ofp_to_u16(OFPP_FIRST_RESV)) {
            VLOG_WARN("port %u is a reserved OF1.0 port number that will "
                      "be translated to %u when talking to an OF1.1 or "
                      "later controller", port32, port32 + OFPP11_OFFSET);
        } else if (port32 <= ofp_to_u16(OFPP_LAST_RESV)) {
            char name[OFP_MAX_PORT_NAME_LEN];

            ofputil_port_to_string(u16_to_ofp(port32), name, sizeof name);
            VLOG_WARN_ONCE("referring to port %s as %"PRIu32" is deprecated "
                           "for compatibility with OpenFlow 1.1 and later",
                           name, port32);
        } else if (port32 < ofp11_to_u32(OFPP11_MAX)) {
            VLOG_WARN("port %u is outside the supported range 0 through "
                      "%"PRIx16" or 0x%x through 0x%"PRIx32, port32,
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
        return false;
    }
}

/* Appends to 's' a string representation of the OpenFlow port number 'port'.
 * Most ports' string representation is just the port number, but for special
 * ports, e.g. OFPP_LOCAL, it is the name, e.g. "LOCAL". */
void
ofputil_format_port(ofp_port_t port, struct ds *s)
{
    char name[OFP_MAX_PORT_NAME_LEN];

    ofputil_port_to_string(port, name, sizeof name);
    ds_put_cstr(s, name);
}

/* Puts in the 'bufsize' byte in 'namebuf' a null-terminated string
 * representation of OpenFlow port number 'port'.  Most ports are represented
 * as just the port number, but special ports, e.g. OFPP_LOCAL, are represented
 * by name, e.g. "LOCAL". */
void
ofputil_port_to_string(ofp_port_t port,
                       char namebuf[OFP_MAX_PORT_NAME_LEN], size_t bufsize)
{
    switch (port) {
#define OFPUTIL_NAMED_PORT(NAME)                        \
        case OFPP_##NAME:                               \
            ovs_strlcpy(namebuf, #NAME, bufsize);       \
            break;
        OFPUTIL_NAMED_PORTS
#undef OFPUTIL_NAMED_PORT

    default:
        snprintf(namebuf, bufsize, "%"PRIu16, port);
        break;
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
        *group_idp = OFPG11_ANY;
    } else if (!strcasecmp(s, "all")) {
        *group_idp = OFPG11_ALL;
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
 * groups, e.g. OFPG11_ALL, it is the name, e.g. "ALL". */
void
ofputil_format_group(uint32_t group_id, struct ds *s)
{
    char name[MAX_GROUP_NAME_LEN];

    ofputil_group_to_string(group_id, name, sizeof name);
    ds_put_cstr(s, name);
}


/* Puts in the 'bufsize' byte in 'namebuf' a null-terminated string
 * representation of OpenFlow group ID 'group_id'.  Most group are represented
 * as just their number, but special groups, e.g. OFPG11_ALL, are represented
 * by name, e.g. "ALL". */
void
ofputil_group_to_string(uint32_t group_id,
                        char namebuf[MAX_GROUP_NAME_LEN + 1], size_t bufsize)
{
    switch (group_id) {
    case OFPG11_ALL:
        ovs_strlcpy(namebuf, "ALL", bufsize);
        break;

    case OFPG11_ANY:
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
    default:
        OVS_NOT_REACHED();
    }
}

/* Given a buffer 'b' that contains an array of OpenFlow ports of type
 * 'ofp_version', returns the number of elements. */
size_t ofputil_count_phy_ports(uint8_t ofp_version, struct ofpbuf *b)
{
    return b->size / ofputil_get_phy_port_size(ofp_version);
}

/* ofp-util.def lists the mapping from names to action. */
static const char *const names[OFPUTIL_N_ACTIONS] = {
    NULL,
#define OFPAT10_ACTION(ENUM, STRUCT, NAME)             NAME,
#define OFPAT11_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) NAME,
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)   NAME,
#include "ofp-util.def"
};

/* Returns the 'enum ofputil_action_code' corresponding to 'name' (e.g. if
 * 'name' is "output" then the return value is OFPUTIL_OFPAT10_OUTPUT), or -1
 * if 'name' is not the name of any action. */
int
ofputil_action_code_from_name(const char *name)
{
    const char *const *p;

    for (p = names; p < &names[ARRAY_SIZE(names)]; p++) {
        if (*p && !strcasecmp(name, *p)) {
            return p - names;
        }
    }
    return -1;
}

/* Returns name corresponding to the 'enum ofputil_action_code',
 * or "Unkonwn action", if the name is not available. */
const char *
ofputil_action_name_from_code(enum ofputil_action_code code)
{
    return code < (int)OFPUTIL_N_ACTIONS && names[code] ? names[code]
        : "Unknown action";
}

/* Appends an action of the type specified by 'code' to 'buf' and returns the
 * action.  Initializes the parts of 'action' that identify it as having type
 * <ENUM> and length 'sizeof *action' and zeros the rest.  For actions that
 * have variable length, the length used and cleared is that of struct
 * <STRUCT>.  */
void *
ofputil_put_action(enum ofputil_action_code code, struct ofpbuf *buf)
{
    switch (code) {
    case OFPUTIL_ACTION_INVALID:
        OVS_NOT_REACHED();

#define OFPAT10_ACTION(ENUM, STRUCT, NAME)                  \
    case OFPUTIL_##ENUM: return ofputil_put_##ENUM(buf);
#define OFPAT11_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)      \
    case OFPUTIL_##ENUM: return ofputil_put_##ENUM(buf);
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)        \
    case OFPUTIL_##ENUM: return ofputil_put_##ENUM(buf);
#include "ofp-util.def"
    }
    OVS_NOT_REACHED();
}

#define OFPAT10_ACTION(ENUM, STRUCT, NAME)                        \
    void                                                        \
    ofputil_init_##ENUM(struct STRUCT *s)                       \
    {                                                           \
        memset(s, 0, sizeof *s);                                \
        s->type = htons(ENUM);                                  \
        s->len = htons(sizeof *s);                              \
    }                                                           \
                                                                \
    struct STRUCT *                                             \
    ofputil_put_##ENUM(struct ofpbuf *buf)                      \
    {                                                           \
        struct STRUCT *s = ofpbuf_put_uninit(buf, sizeof *s);   \
        ofputil_init_##ENUM(s);                                 \
        return s;                                               \
    }
#define OFPAT11_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) \
    OFPAT10_ACTION(ENUM, STRUCT, NAME)
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)            \
    void                                                        \
    ofputil_init_##ENUM(struct STRUCT *s)                       \
    {                                                           \
        memset(s, 0, sizeof *s);                                \
        s->type = htons(OFPAT10_VENDOR);                        \
        s->len = htons(sizeof *s);                              \
        s->vendor = htonl(NX_VENDOR_ID);                        \
        s->subtype = htons(ENUM);                               \
    }                                                           \
                                                                \
    struct STRUCT *                                             \
    ofputil_put_##ENUM(struct ofpbuf *buf)                      \
    {                                                           \
        struct STRUCT *s = ofpbuf_put_uninit(buf, sizeof *s);   \
        ofputil_init_##ENUM(s);                                 \
        return s;                                               \
    }
#include "ofp-util.def"

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
    } may_match;

    struct flow_wildcards wc;

    /* Figure out what fields may be matched. */
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        may_match = MAY_NW_PROTO | MAY_IPVx | MAY_NW_ADDR;
        if (match->flow.nw_proto == IPPROTO_TCP ||
            match->flow.nw_proto == IPPROTO_UDP ||
            match->flow.nw_proto == IPPROTO_SCTP ||
            match->flow.nw_proto == IPPROTO_ICMP) {
            may_match |= MAY_TP_ADDR;
        }
    } else if (match->flow.dl_type == htons(ETH_TYPE_IPV6)) {
        may_match = MAY_NW_PROTO | MAY_IPVx | MAY_IPV6;
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
    } else if (match->flow.dl_type == htons(ETH_TYPE_ARP) ||
               match->flow.dl_type == htons(ETH_TYPE_RARP)) {
        may_match = MAY_NW_PROTO | MAY_NW_ADDR | MAY_ARP_SHA | MAY_ARP_THA;
    } else if (eth_type_mpls(match->flow.dl_type)) {
        may_match = MAY_MPLS;
    } else {
        may_match = 0;
    }

    /* Clear the fields that may not be matched. */
    wc = match->wc;
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
        memset(wc.masks.arp_sha, 0, ETH_ADDR_LEN);
    }
    if (!(may_match & MAY_ARP_THA)) {
        memset(wc.masks.arp_tha, 0, ETH_ADDR_LEN);
    }
    if (!(may_match & MAY_IPV6)) {
        wc.masks.ipv6_src = wc.masks.ipv6_dst = in6addr_any;
        wc.masks.ipv6_label = htonl(0);
    }
    if (!(may_match & MAY_ND_TARGET)) {
        wc.masks.nd_target = in6addr_any;
    }
    if (!(may_match & MAY_MPLS)) {
        wc.masks.mpls_lse = htonl(0);
    }

    /* Log any changes. */
    if (!flow_wildcards_equal(&wc, &match->wc)) {
        bool log = may_log && !VLOG_DROP_INFO(&bad_ofmsg_rl);
        char *pre = log ? match_to_string(match, OFP_DEFAULT_PRIORITY) : NULL;

        match->wc = wc;
        match_zero_wildcarded_fields(match);

        if (log) {
            char *post = match_to_string(match, OFP_DEFAULT_PRIORITY);
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
    char *pos, *key, *value;
    size_t key_len;

    pos = *stringp;
    pos += strspn(pos, ", \t\r\n");
    if (*pos == '\0') {
        *keyp = *valuep = NULL;
        return false;
    }

    key = pos;
    key_len = strcspn(pos, ":=(, \t\r\n");
    if (key[key_len] == ':' || key[key_len] == '=') {
        /* The value can be separated by a colon. */
        size_t value_len;

        value = key + key_len + 1;
        value_len = strcspn(value, ", \t\r\n");
        pos = value + value_len + (value[value_len] != '\0');
        value[value_len] = '\0';
    } else if (key[key_len] == '(') {
        /* The value can be surrounded by balanced parentheses.  The outermost
         * set of parentheses is removed. */
        int level = 1;
        size_t value_len;

        value = key + key_len + 1;
        for (value_len = 0; level > 0; value_len++) {
            switch (value[value_len]) {
            case '\0':
                level = 0;
                break;

            case '(':
                level++;
                break;

            case ')':
                level--;
                break;
            }
        }
        value[value_len - 1] = '\0';
        pos = value + value_len;
    } else {
        /* There might be no value at all. */
        value = key + key_len;  /* Will become the empty string below. */
        pos = key + key_len + (key[key_len] != '\0');
    }
    key[key_len] = '\0';

    *stringp = pos;
    *keyp = key;
    *valuep = value;
    return true;
}

/* Encode a dump ports request for 'port', the encoded message
 * will be for Open Flow version 'ofp_version'. Returns message
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
    case OFP13_VERSION: {
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


/* Encode a ports stat for 'ops' and append it to 'replies'. */
void
ofputil_append_port_stat(struct list *replies,
                         const struct ofputil_port_stats *ops)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));
    struct ofp_header *oh = msg->data;

    switch ((enum ofp_version)oh->version) {
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

    default:
        OVS_NOT_REACHED();
    }
}

static enum ofperr
ofputil_port_stats_from_ofp10(struct ofputil_port_stats *ops,
                              const struct ofp10_port_stats *ps10)
{
    memset(ops, 0, sizeof *ops);

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

    memset(ops, 0, sizeof *ops);
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

static size_t
ofputil_get_port_stats_size(enum ofp_version ofp_version)
{
    switch (ofp_version) {
    case OFP10_VERSION:
        return sizeof(struct ofp10_port_stats);
    case OFP11_VERSION:
    case OFP12_VERSION:
        return sizeof(struct ofp11_port_stats);
    case OFP13_VERSION:
        return sizeof(struct ofp13_port_stats);
    default:
        OVS_NOT_REACHED();
    }
}

/* Returns the number of port stats elements in OFPTYPE_PORT_STATS_REPLY
 * message 'oh'. */
size_t
ofputil_count_port_stats(const struct ofp_header *oh)
{
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    return b.size / ofputil_get_port_stats_size(oh->version);
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

    error = (msg->l2
             ? ofpraw_decode(&raw, msg->l2)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
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
    VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_PORT reply has %"PRIuSIZE" leftover "
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

/* Frees all of the "struct ofputil_bucket"s in the 'buckets' list. */
void
ofputil_bucket_list_destroy(struct list *buckets)
{
    struct ofputil_bucket *bucket, *next_bucket;

    LIST_FOR_EACH_SAFE (bucket, next_bucket, list_node, buckets) {
        list_remove(&bucket->list_node);
        free(bucket->ofpacts);
        free(bucket);
    }
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
    case OFP13_VERSION: {
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

/* Returns an OpenFlow group description request for OpenFlow version
 * 'ofp_version', that requests stats for group 'group_id'.  (Use OFPG_ALL to
 * request stats for all groups.)
 *
 * Group descriptions include the bucket and action configuration for each
 * group. */
struct ofpbuf *
ofputil_encode_group_desc_request(enum ofp_version ofp_version)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION:
        ovs_fatal(0, "dump-groups needs OpenFlow 1.1 or later "
                     "(\'-O OpenFlow11\')");
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        request = ofpraw_alloc(OFPRAW_OFPST11_GROUP_DESC_REQUEST, ofp_version, 0);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

static void *
ofputil_group_stats_to_ofp11(const struct ofputil_group_stats *ogs,
                             size_t base_len, struct list *replies)
{
    struct ofp11_bucket_counter *bc11;
    struct ofp11_group_stats *gs11;
    size_t length;
    int i;

    length = base_len + sizeof(struct ofp11_bucket_counter) * ogs->n_buckets;

    gs11 = ofpmp_append(replies, length);
    memset(gs11, 0, base_len);
    gs11->length = htons(length);
    gs11->group_id = htonl(ogs->group_id);
    gs11->ref_count = htonl(ogs->ref_count);
    gs11->packet_count = htonll(ogs->packet_count);
    gs11->byte_count = htonll(ogs->byte_count);

    bc11 = (void *) (((uint8_t *) gs11) + base_len);
    for (i = 0; i < ogs->n_buckets; i++) {
        const struct bucket_counter *obc = &ogs->bucket_stats[i];

        bc11[i].packet_count = htonll(obc->packet_count);
        bc11[i].byte_count = htonll(obc->byte_count);
    }

    return gs11;
}

static void
ofputil_append_of13_group_stats(const struct ofputil_group_stats *ogs,
                                struct list *replies)
{
    struct ofp13_group_stats *gs13;

    gs13 = ofputil_group_stats_to_ofp11(ogs, sizeof *gs13, replies);
    gs13->duration_sec = htonl(ogs->duration_sec);
    gs13->duration_nsec = htonl(ogs->duration_nsec);
}

/* Encodes 'ogs' properly for the format of the list of group statistics
 * replies already begun in 'replies' and appends it to the list.  'replies'
 * must have originally been initialized with ofpmp_init(). */
void
ofputil_append_group_stats(struct list *replies,
                           const struct ofputil_group_stats *ogs)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));
    struct ofp_header *oh = msg->data;

    switch ((enum ofp_version)oh->version) {
    case OFP11_VERSION:
    case OFP12_VERSION:
        ofputil_group_stats_to_ofp11(ogs, sizeof(struct ofp11_group_stats),
                                     replies);
        break;

    case OFP13_VERSION:
        ofputil_append_of13_group_stats(ogs, replies);
        break;

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
    case OFP13_VERSION: {
        request = ofpraw_alloc(OFPRAW_OFPST12_GROUP_FEATURES_REQUEST,
                                        ofp_version, 0);
        break;
    }
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

    reply = ofpraw_alloc_xid(OFPRAW_OFPST12_GROUP_FEATURES_REPLY,
                             request->version, request->xid, 0);
    ogf = ofpbuf_put_zeros(reply, sizeof *ogf);
    ogf->types = htonl(features->types);
    ogf->capabilities = htonl(features->capabilities);
    ogf->max_groups[0] = htonl(features->max_groups[0]);
    ogf->max_groups[1] = htonl(features->max_groups[1]);
    ogf->max_groups[2] = htonl(features->max_groups[2]);
    ogf->max_groups[3] = htonl(features->max_groups[3]);
    ogf->actions[0] = htonl(features->actions[0]);
    ogf->actions[1] = htonl(features->actions[1]);
    ogf->actions[2] = htonl(features->actions[2]);
    ogf->actions[3] = htonl(features->actions[3]);

    return reply;
}

/* Decodes group features reply 'oh' into 'features'. */
void
ofputil_decode_group_features_reply(const struct ofp_header *oh,
                                    struct ofputil_group_features *features)
{
    const struct ofp12_group_features_stats *ogf = ofpmsg_body(oh);

    features->types = ntohl(ogf->types);
    features->capabilities = ntohl(ogf->capabilities);
    features->max_groups[0] = ntohl(ogf->max_groups[0]);
    features->max_groups[1] = ntohl(ogf->max_groups[1]);
    features->max_groups[2] = ntohl(ogf->max_groups[2]);
    features->max_groups[3] = ntohl(ogf->max_groups[3]);
    features->actions[0] = ntohl(ogf->actions[0]);
    features->actions[1] = ntohl(ogf->actions[1]);
    features->actions[2] = ntohl(ogf->actions[2]);
    features->actions[3] = ntohl(ogf->actions[3]);
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
    error = (msg->l2
             ? ofpraw_decode(&raw, msg->l2)
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
        VLOG_WARN_RL(&bad_ofmsg_rl, "%s reply has %"PRIuSIZE" leftover bytes at end",
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
        VLOG_WARN_RL(&bad_ofmsg_rl, "%s reply has %"PRIuSIZE" leftover bytes at end",
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

/* Appends a group stats reply that contains the data in 'gds' to those already
 * present in the list of ofpbufs in 'replies'.  'replies' should have been
 * initialized with ofpmp_init(). */
void
ofputil_append_group_desc_reply(const struct ofputil_group_desc *gds,
                                struct list *buckets,
                                struct list *replies)
{
    struct ofpbuf *reply = ofpbuf_from_list(list_back(replies));
    struct ofp11_group_desc_stats *ogds;
    struct ofputil_bucket *bucket;
    size_t start_ogds;
    enum ofp_version version = ((struct ofp_header *)reply->data)->version;

    start_ogds = reply->size;
    ofpbuf_put_zeros(reply, sizeof *ogds);
    LIST_FOR_EACH (bucket, list_node, buckets) {
        struct ofp11_bucket *ob;
        size_t start_ob;

        start_ob = reply->size;
        ofpbuf_put_zeros(reply, sizeof *ob);
        ofpacts_put_openflow_actions(bucket->ofpacts, bucket->ofpacts_len,
                                     reply, version);
        ob = ofpbuf_at_assert(reply, start_ob, sizeof *ob);
        ob->len = htons(reply->size - start_ob);
        ob->weight = htons(bucket->weight);
        ob->watch_port = ofputil_port_to_ofp11(bucket->watch_port);
        ob->watch_group = htonl(bucket->watch_group);
    }
    ogds = ofpbuf_at_assert(reply, start_ogds, sizeof *ogds);
    ogds->length = htons(reply->size - start_ogds);
    ogds->type = gds->type;
    ogds->group_id = htonl(gds->group_id);

    ofpmp_postappend(replies, start_ogds);
}

static enum ofperr
ofputil_pull_buckets(struct ofpbuf *msg, size_t buckets_length,
                     enum ofp_version version, struct list *buckets)
{
    struct ofp11_bucket *ob;

    list_init(buckets);
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
        }

        ob_len = ntohs(ob->len);
        if (ob_len < sizeof *ob) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" is not valid", ob_len);
            return OFPERR_OFPGMFC_BAD_BUCKET;
        } else if (ob_len > buckets_length) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" exceeds remaining buckets data size %"PRIuSIZE,
                         ob_len, buckets_length);
            return OFPERR_OFPGMFC_BAD_BUCKET;
        }
        buckets_length -= ob_len;

        ofpbuf_init(&ofpacts, 0);
        error = ofpacts_pull_openflow_actions(msg, ob_len - sizeof *ob,
                                              version, &ofpacts);
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
            return OFPERR_OFPGMFC_BAD_WATCH;
        }
        bucket->watch_group = ntohl(ob->watch_group);
        bucket->ofpacts = ofpbuf_steal_data(&ofpacts);
        bucket->ofpacts_len = ofpacts.size;
        list_push_back(buckets, &bucket->list_node);
    }

    return 0;
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
    struct ofp11_group_desc_stats *ogds;
    size_t length;

    if (!msg->l2) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    ogds = ofpbuf_try_pull(msg, sizeof *ogds);
    if (!ogds) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST11_GROUP_DESC reply has %"PRIuSIZE" "
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

    return ofputil_pull_buckets(msg, length - sizeof *ogds, version,
                                &gd->buckets);
}

/* Converts abstract group mod 'gm' into a message for OpenFlow version
 * 'ofp_version' and returns the message. */
struct ofpbuf *
ofputil_encode_group_mod(enum ofp_version ofp_version,
                         const struct ofputil_group_mod *gm)
{
    struct ofpbuf *b;
    struct ofp11_group_mod *ogm;
    size_t start_ogm;
    size_t start_bucket;
    struct ofputil_bucket *bucket;
    struct ofp11_bucket *ob;

    switch (ofp_version) {
    case OFP10_VERSION: {
        if (gm->command == OFPGC11_ADD) {
            ovs_fatal(0, "add-group needs OpenFlow 1.1 or later "
                         "(\'-O OpenFlow11\')");
        } else if (gm->command == OFPGC11_MODIFY) {
            ovs_fatal(0, "mod-group needs OpenFlow 1.1 or later "
                         "(\'-O OpenFlow11\')");
        } else {
            ovs_fatal(0, "del-groups needs OpenFlow 1.1 or later "
                         "(\'-O OpenFlow11\')");
        }
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        b = ofpraw_alloc(OFPRAW_OFPT11_GROUP_MOD, ofp_version, 0);
        start_ogm = b->size;
        ofpbuf_put_zeros(b, sizeof *ogm);

        LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
            start_bucket = b->size;
            ofpbuf_put_zeros(b, sizeof *ob);
            if (bucket->ofpacts && bucket->ofpacts_len) {
                ofpacts_put_openflow_actions(bucket->ofpacts,
                                             bucket->ofpacts_len, b,
                                             ofp_version);
            }
            ob = ofpbuf_at_assert(b, start_bucket, sizeof *ob);
            ob->len = htons(b->size - start_bucket);;
            ob->weight = htons(bucket->weight);
            ob->watch_port = ofputil_port_to_ofp11(bucket->watch_port);
            ob->watch_group = htonl(bucket->watch_group);
        }
        ogm = ofpbuf_at_assert(b, start_ogm, sizeof *ogm);
        ogm->command = htons(gm->command);
        ogm->type = gm->type;
        ogm->group_id = htonl(gm->group_id);

        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    return b;
}

/* Converts OpenFlow group mod message 'oh' into an abstract group mod in
 * 'gm'.  Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
ofputil_decode_group_mod(const struct ofp_header *oh,
                         struct ofputil_group_mod *gm)
{
    const struct ofp11_group_mod *ogm;
    struct ofpbuf msg;
    struct ofputil_bucket *bucket;
    enum ofperr err;

    ofpbuf_use_const(&msg, oh, ntohs(oh->length));
    ofpraw_pull_assert(&msg);

    ogm = ofpbuf_pull(&msg, sizeof *ogm);
    gm->command = ntohs(ogm->command);
    gm->type = ogm->type;
    gm->group_id = ntohl(ogm->group_id);

    err = ofputil_pull_buckets(&msg, msg.size, oh->version, &gm->buckets);
    if (err) {
        return err;
    }

    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
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
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

/* Parse a queue status request message into 'oqsr'.
 * Returns 0 if successful, otherwise an OFPERR_* number. */
enum ofperr
ofputil_decode_queue_stats_request(const struct ofp_header *request,
                                   struct ofputil_queue_stats_request *oqsr)
{
    switch ((enum ofp_version)request->version) {
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

/* Encode a queue statsrequest for 'oqsr', the encoded message
 * will be fore Open Flow version 'ofp_version'. Returns message
 * as a struct ofpbuf. Returns encoded message on success, NULL on error */
struct ofpbuf *
ofputil_encode_queue_stats_request(enum ofp_version ofp_version,
                                   const struct ofputil_queue_stats_request *oqsr)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
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

static size_t
ofputil_get_queue_stats_size(enum ofp_version ofp_version)
{
    switch (ofp_version) {
    case OFP10_VERSION:
        return sizeof(struct ofp10_queue_stats);
    case OFP11_VERSION:
    case OFP12_VERSION:
        return sizeof(struct ofp11_queue_stats);
    case OFP13_VERSION:
        return sizeof(struct ofp13_queue_stats);
    default:
        OVS_NOT_REACHED();
    }
}

/* Returns the number of queue stats elements in OFPTYPE_QUEUE_STATS_REPLY
 * message 'oh'. */
size_t
ofputil_count_queue_stats(const struct ofp_header *oh)
{
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    return b.size / ofputil_get_queue_stats_size(oh->version);
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

    error = (msg->l2
             ? ofpraw_decode(&raw, msg->l2)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
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
    VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_QUEUE reply has %"PRIuSIZE" leftover "
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

/* Encode a queue stat for 'oqs' and append it to 'replies'. */
void
ofputil_append_queue_stat(struct list *replies,
                          const struct ofputil_queue_stats *oqs)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));
    struct ofp_header *oh = msg->data;

    switch ((enum ofp_version)oh->version) {
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

    default:
        OVS_NOT_REACHED();
    }
}
