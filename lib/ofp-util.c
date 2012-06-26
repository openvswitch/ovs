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
#include "ofp-print.h"
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include "autopath.h"
#include "bundle.h"
#include "byte-order.h"
#include "classifier.h"
#include "dynamic-string.h"
#include "learn.h"
#include "meta-flow.h"
#include "multipath.h"
#include "netdev.h"
#include "nx-match.h"
#include "ofp-errors.h"
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

/* A list of the FWW_* and OFPFW10_ bits that have the same value, meaning, and
 * name. */
#define WC_INVARIANT_LIST \
    WC_INVARIANT_BIT(IN_PORT) \
    WC_INVARIANT_BIT(DL_TYPE) \
    WC_INVARIANT_BIT(NW_PROTO)

/* Verify that all of the invariant bits (as defined on WC_INVARIANT_LIST)
 * actually have the same names and values. */
#define WC_INVARIANT_BIT(NAME) BUILD_ASSERT_DECL(FWW_##NAME == OFPFW10_##NAME);
    WC_INVARIANT_LIST
#undef WC_INVARIANT_BIT

/* WC_INVARIANTS is the invariant bits (as defined on WC_INVARIANT_LIST) all
 * OR'd together. */
static const flow_wildcards_t WC_INVARIANTS = 0
#define WC_INVARIANT_BIT(NAME) | FWW_##NAME
    WC_INVARIANT_LIST
#undef WC_INVARIANT_BIT
;

/* Converts the OpenFlow 1.0 wildcards in 'ofpfw' (OFPFW10_*) into a
 * flow_wildcards in 'wc' for use in struct cls_rule.  It is the caller's
 * responsibility to handle the special case where the flow match's dl_vlan is
 * set to OFP_VLAN_NONE. */
void
ofputil_wildcard_from_ofpfw10(uint32_t ofpfw, struct flow_wildcards *wc)
{
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 12);

    /* Initialize most of rule->wc. */
    flow_wildcards_init_catchall(wc);
    wc->wildcards = (OVS_FORCE flow_wildcards_t) ofpfw & WC_INVARIANTS;

    /* Wildcard fields that aren't defined by ofp10_match or tun_id. */
    wc->wildcards |= (FWW_ARP_SHA | FWW_ARP_THA | FWW_NW_ECN | FWW_NW_TTL
                      | FWW_IPV6_LABEL);

    if (ofpfw & OFPFW10_NW_TOS) {
        /* OpenFlow 1.0 defines a TOS wildcard, but it's much later in
         * the enum than we can use. */
        wc->wildcards |= FWW_NW_DSCP;
    }

    wc->nw_src_mask = ofputil_wcbits_to_netmask(ofpfw >> OFPFW10_NW_SRC_SHIFT);
    wc->nw_dst_mask = ofputil_wcbits_to_netmask(ofpfw >> OFPFW10_NW_DST_SHIFT);

    if (!(ofpfw & OFPFW10_TP_SRC)) {
        wc->tp_src_mask = htons(UINT16_MAX);
    }
    if (!(ofpfw & OFPFW10_TP_DST)) {
        wc->tp_dst_mask = htons(UINT16_MAX);
    }

    if (!(ofpfw & OFPFW10_DL_SRC)) {
        memset(wc->dl_src_mask, 0xff, ETH_ADDR_LEN);
    }
    if (!(ofpfw & OFPFW10_DL_DST)) {
        memset(wc->dl_dst_mask, 0xff, ETH_ADDR_LEN);
    }

    /* VLAN TCI mask. */
    if (!(ofpfw & OFPFW10_DL_VLAN_PCP)) {
        wc->vlan_tci_mask |= htons(VLAN_PCP_MASK | VLAN_CFI);
    }
    if (!(ofpfw & OFPFW10_DL_VLAN)) {
        wc->vlan_tci_mask |= htons(VLAN_VID_MASK | VLAN_CFI);
    }
}

/* Converts the ofp10_match in 'match' into a cls_rule in 'rule', with the
 * given 'priority'. */
void
ofputil_cls_rule_from_ofp10_match(const struct ofp10_match *match,
                                  unsigned int priority, struct cls_rule *rule)
{
    uint32_t ofpfw = ntohl(match->wildcards) & OFPFW10_ALL;

    /* Initialize rule->priority, rule->wc. */
    rule->priority = !ofpfw ? UINT16_MAX : priority;
    ofputil_wildcard_from_ofpfw10(ofpfw, &rule->wc);

    /* Initialize most of rule->flow. */
    rule->flow.nw_src = match->nw_src;
    rule->flow.nw_dst = match->nw_dst;
    rule->flow.in_port = ntohs(match->in_port);
    rule->flow.dl_type = ofputil_dl_type_from_openflow(match->dl_type);
    rule->flow.tp_src = match->tp_src;
    rule->flow.tp_dst = match->tp_dst;
    memcpy(rule->flow.dl_src, match->dl_src, ETH_ADDR_LEN);
    memcpy(rule->flow.dl_dst, match->dl_dst, ETH_ADDR_LEN);
    rule->flow.nw_tos = match->nw_tos & IP_DSCP_MASK;
    rule->flow.nw_proto = match->nw_proto;

    /* Translate VLANs. */
    if (!(ofpfw & OFPFW10_DL_VLAN) && match->dl_vlan == htons(OFP_VLAN_NONE)) {
        /* Match only packets without 802.1Q header.
         *
         * When OFPFW10_DL_VLAN_PCP is wildcarded, this is obviously correct.
         *
         * If OFPFW10_DL_VLAN_PCP is matched, the flow match is contradictory,
         * because we can't have a specific PCP without an 802.1Q header.
         * However, older versions of OVS treated this as matching packets
         * withut an 802.1Q header, so we do here too. */
        rule->flow.vlan_tci = htons(0);
        rule->wc.vlan_tci_mask = htons(0xffff);
    } else {
        ovs_be16 vid, pcp, tci;

        vid = match->dl_vlan & htons(VLAN_VID_MASK);
        pcp = htons((match->dl_vlan_pcp << VLAN_PCP_SHIFT) & VLAN_PCP_MASK);
        tci = vid | pcp | htons(VLAN_CFI);
        rule->flow.vlan_tci = tci & rule->wc.vlan_tci_mask;
    }

    /* Clean up. */
    cls_rule_zero_wildcarded_fields(rule);
}

/* Convert 'rule' into the OpenFlow 1.0 match structure 'match'. */
void
ofputil_cls_rule_to_ofp10_match(const struct cls_rule *rule,
                                struct ofp10_match *match)
{
    const struct flow_wildcards *wc = &rule->wc;
    uint32_t ofpfw;

    /* Figure out most OpenFlow wildcards. */
    ofpfw = (OVS_FORCE uint32_t) (wc->wildcards & WC_INVARIANTS);
    ofpfw |= (ofputil_netmask_to_wcbits(wc->nw_src_mask)
              << OFPFW10_NW_SRC_SHIFT);
    ofpfw |= (ofputil_netmask_to_wcbits(wc->nw_dst_mask)
              << OFPFW10_NW_DST_SHIFT);
    if (wc->wildcards & FWW_NW_DSCP) {
        ofpfw |= OFPFW10_NW_TOS;
    }
    if (!wc->tp_src_mask) {
        ofpfw |= OFPFW10_TP_SRC;
    }
    if (!wc->tp_dst_mask) {
        ofpfw |= OFPFW10_TP_DST;
    }
    if (eth_addr_is_zero(wc->dl_src_mask)) {
        ofpfw |= OFPFW10_DL_SRC;
    }
    if (eth_addr_is_zero(wc->dl_dst_mask)) {
        ofpfw |= OFPFW10_DL_DST;
    }

    /* Translate VLANs. */
    match->dl_vlan = htons(0);
    match->dl_vlan_pcp = 0;
    if (rule->wc.vlan_tci_mask == htons(0)) {
        ofpfw |= OFPFW10_DL_VLAN | OFPFW10_DL_VLAN_PCP;
    } else if (rule->wc.vlan_tci_mask & htons(VLAN_CFI)
               && !(rule->flow.vlan_tci & htons(VLAN_CFI))) {
        match->dl_vlan = htons(OFP_VLAN_NONE);
    } else {
        if (!(rule->wc.vlan_tci_mask & htons(VLAN_VID_MASK))) {
            ofpfw |= OFPFW10_DL_VLAN;
        } else {
            match->dl_vlan = htons(vlan_tci_to_vid(rule->flow.vlan_tci));
        }

        if (!(rule->wc.vlan_tci_mask & htons(VLAN_PCP_MASK))) {
            ofpfw |= OFPFW10_DL_VLAN_PCP;
        } else {
            match->dl_vlan_pcp = vlan_tci_to_pcp(rule->flow.vlan_tci);
        }
    }

    /* Compose most of the match structure. */
    match->wildcards = htonl(ofpfw);
    match->in_port = htons(rule->flow.in_port);
    memcpy(match->dl_src, rule->flow.dl_src, ETH_ADDR_LEN);
    memcpy(match->dl_dst, rule->flow.dl_dst, ETH_ADDR_LEN);
    match->dl_type = ofputil_dl_type_to_openflow(rule->flow.dl_type);
    match->nw_src = rule->flow.nw_src;
    match->nw_dst = rule->flow.nw_dst;
    match->nw_tos = rule->flow.nw_tos & IP_DSCP_MASK;
    match->nw_proto = rule->flow.nw_proto;
    match->tp_src = rule->flow.tp_src;
    match->tp_dst = rule->flow.tp_dst;
    memset(match->pad1, '\0', sizeof match->pad1);
    memset(match->pad2, '\0', sizeof match->pad2);
}

/* Converts the ofp11_match in 'match' into a cls_rule in 'rule', with the
 * given 'priority'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_cls_rule_from_ofp11_match(const struct ofp11_match *match,
                                  unsigned int priority,
                                  struct cls_rule *rule)
{
    uint16_t wc = ntohl(match->wildcards);
    uint8_t dl_src_mask[ETH_ADDR_LEN];
    uint8_t dl_dst_mask[ETH_ADDR_LEN];
    bool ipv4, arp;
    int i;

    cls_rule_init_catchall(rule, priority);

    if (!(wc & OFPFW11_IN_PORT)) {
        uint16_t ofp_port;
        enum ofperr error;

        error = ofputil_port_from_ofp11(match->in_port, &ofp_port);
        if (error) {
            return OFPERR_OFPBMC_BAD_VALUE;
        }
        cls_rule_set_in_port(rule, ofp_port);
    }

    for (i = 0; i < ETH_ADDR_LEN; i++) {
        dl_src_mask[i] = ~match->dl_src_mask[i];
    }
    cls_rule_set_dl_src_masked(rule, match->dl_src, dl_src_mask);

    for (i = 0; i < ETH_ADDR_LEN; i++) {
        dl_dst_mask[i] = ~match->dl_dst_mask[i];
    }
    cls_rule_set_dl_dst_masked(rule, match->dl_dst, dl_dst_mask);

    if (!(wc & OFPFW11_DL_VLAN)) {
        if (match->dl_vlan == htons(OFPVID11_NONE)) {
            /* Match only packets without a VLAN tag. */
            rule->flow.vlan_tci = htons(0);
            rule->wc.vlan_tci_mask = htons(UINT16_MAX);
        } else {
            if (match->dl_vlan == htons(OFPVID11_ANY)) {
                /* Match any packet with a VLAN tag regardless of VID. */
                rule->flow.vlan_tci = htons(VLAN_CFI);
                rule->wc.vlan_tci_mask = htons(VLAN_CFI);
            } else if (ntohs(match->dl_vlan) < 4096) {
                /* Match only packets with the specified VLAN VID. */
                rule->flow.vlan_tci = htons(VLAN_CFI) | match->dl_vlan;
                rule->wc.vlan_tci_mask = htons(VLAN_CFI | VLAN_VID_MASK);
            } else {
                /* Invalid VID. */
                return OFPERR_OFPBMC_BAD_VALUE;
            }

            if (!(wc & OFPFW11_DL_VLAN_PCP)) {
                if (match->dl_vlan_pcp <= 7) {
                    rule->flow.vlan_tci |= htons(match->dl_vlan_pcp
                                                 << VLAN_PCP_SHIFT);
                    rule->wc.vlan_tci_mask |= htons(VLAN_PCP_MASK);
                } else {
                    /* Invalid PCP. */
                    return OFPERR_OFPBMC_BAD_VALUE;
                }
            }
        }
    }

    if (!(wc & OFPFW11_DL_TYPE)) {
        cls_rule_set_dl_type(rule,
                             ofputil_dl_type_from_openflow(match->dl_type));
    }

    ipv4 = rule->flow.dl_type == htons(ETH_TYPE_IP);
    arp = rule->flow.dl_type == htons(ETH_TYPE_ARP);

    if (ipv4 && !(wc & OFPFW11_NW_TOS)) {
        if (match->nw_tos & ~IP_DSCP_MASK) {
            /* Invalid TOS. */
            return OFPERR_OFPBMC_BAD_VALUE;
        }

        cls_rule_set_nw_dscp(rule, match->nw_tos);
    }

    if (ipv4 || arp) {
        if (!(wc & OFPFW11_NW_PROTO)) {
            cls_rule_set_nw_proto(rule, match->nw_proto);
        }
        cls_rule_set_nw_src_masked(rule, match->nw_src, ~match->nw_src_mask);
        cls_rule_set_nw_dst_masked(rule, match->nw_dst, ~match->nw_dst_mask);
    }

#define OFPFW11_TP_ALL (OFPFW11_TP_SRC | OFPFW11_TP_DST)
    if (ipv4 && (wc & OFPFW11_TP_ALL) != OFPFW11_TP_ALL) {
        switch (rule->flow.nw_proto) {
        case IPPROTO_ICMP:
            /* "A.2.3 Flow Match Structures" in OF1.1 says:
             *
             *    The tp_src and tp_dst fields will be ignored unless the
             *    network protocol specified is as TCP, UDP or SCTP.
             *
             * but I'm pretty sure we should support ICMP too, otherwise
             * that's a regression from OF1.0. */
            if (!(wc & OFPFW11_TP_SRC)) {
                uint16_t icmp_type = ntohs(match->tp_src);
                if (icmp_type < 0x100) {
                    cls_rule_set_icmp_type(rule, icmp_type);
                } else {
                    return OFPERR_OFPBMC_BAD_FIELD;
                }
            }
            if (!(wc & OFPFW11_TP_DST)) {
                uint16_t icmp_code = ntohs(match->tp_dst);
                if (icmp_code < 0x100) {
                    cls_rule_set_icmp_code(rule, icmp_code);
                } else {
                    return OFPERR_OFPBMC_BAD_FIELD;
                }
            }
            break;

        case IPPROTO_TCP:
        case IPPROTO_UDP:
            if (!(wc & (OFPFW11_TP_SRC))) {
                cls_rule_set_tp_src(rule, match->tp_src);
            }
            if (!(wc & (OFPFW11_TP_DST))) {
                cls_rule_set_tp_dst(rule, match->tp_dst);
            }
            break;

        case IPPROTO_SCTP:
            /* We don't support SCTP and it seems that we should tell the
             * controller, since OF1.1 implementations are supposed to. */
            return OFPERR_OFPBMC_BAD_FIELD;

        default:
            /* OF1.1 says explicitly to ignore this. */
            break;
        }
    }

    if (rule->flow.dl_type == htons(ETH_TYPE_MPLS) ||
        rule->flow.dl_type == htons(ETH_TYPE_MPLS_MCAST)) {
        enum { OFPFW11_MPLS_ALL = OFPFW11_MPLS_LABEL | OFPFW11_MPLS_TC };

        if ((wc & OFPFW11_MPLS_ALL) != OFPFW11_MPLS_ALL) {
            /* MPLS not supported. */
            return OFPERR_OFPBMC_BAD_TAG;
        }
    }

    if (match->metadata_mask != htonll(UINT64_MAX)) {
        cls_rule_set_metadata_masked(rule, match->metadata,
                                     ~match->metadata_mask);
    }

    return 0;
}

/* Convert 'rule' into the OpenFlow 1.1 match structure 'match'. */
void
ofputil_cls_rule_to_ofp11_match(const struct cls_rule *rule,
                                struct ofp11_match *match)
{
    uint32_t wc = 0;
    int i;

    memset(match, 0, sizeof *match);
    match->omh.type = htons(OFPMT_STANDARD);
    match->omh.length = htons(OFPMT11_STANDARD_LENGTH);

    if (rule->wc.wildcards & FWW_IN_PORT) {
        wc |= OFPFW11_IN_PORT;
    } else {
        match->in_port = ofputil_port_to_ofp11(rule->flow.in_port);
    }


    memcpy(match->dl_src, rule->flow.dl_src, ETH_ADDR_LEN);
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        match->dl_src_mask[i] = ~rule->wc.dl_src_mask[i];
    }

    memcpy(match->dl_dst, rule->flow.dl_dst, ETH_ADDR_LEN);
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        match->dl_dst_mask[i] = ~rule->wc.dl_dst_mask[i];
    }

    if (rule->wc.vlan_tci_mask == htons(0)) {
        wc |= OFPFW11_DL_VLAN | OFPFW11_DL_VLAN_PCP;
    } else if (rule->wc.vlan_tci_mask & htons(VLAN_CFI)
               && !(rule->flow.vlan_tci & htons(VLAN_CFI))) {
        match->dl_vlan = htons(OFPVID11_NONE);
        wc |= OFPFW11_DL_VLAN_PCP;
    } else {
        if (!(rule->wc.vlan_tci_mask & htons(VLAN_VID_MASK))) {
            match->dl_vlan = htons(OFPVID11_ANY);
        } else {
            match->dl_vlan = htons(vlan_tci_to_vid(rule->flow.vlan_tci));
        }

        if (!(rule->wc.vlan_tci_mask & htons(VLAN_PCP_MASK))) {
            wc |= OFPFW11_DL_VLAN_PCP;
        } else {
            match->dl_vlan_pcp = vlan_tci_to_pcp(rule->flow.vlan_tci);
        }
    }

    if (rule->wc.wildcards & FWW_DL_TYPE) {
        wc |= OFPFW11_DL_TYPE;
    } else {
        match->dl_type = ofputil_dl_type_to_openflow(rule->flow.dl_type);
    }

    if (rule->wc.wildcards & FWW_NW_DSCP) {
        wc |= OFPFW11_NW_TOS;
    } else {
        match->nw_tos = rule->flow.nw_tos & IP_DSCP_MASK;
    }

    if (rule->wc.wildcards & FWW_NW_PROTO) {
        wc |= OFPFW11_NW_PROTO;
    } else {
        match->nw_proto = rule->flow.nw_proto;
    }

    match->nw_src = rule->flow.nw_src;
    match->nw_src_mask = ~rule->wc.nw_src_mask;
    match->nw_dst = rule->flow.nw_dst;
    match->nw_dst_mask = ~rule->wc.nw_dst_mask;

    if (!rule->wc.tp_src_mask) {
        wc |= OFPFW11_TP_SRC;
    } else {
        match->tp_src = rule->flow.tp_src;
    }

    if (!rule->wc.tp_dst_mask) {
        wc |= OFPFW11_TP_DST;
    } else {
        match->tp_dst = rule->flow.tp_dst;
    }

    /* MPLS not supported. */
    wc |= OFPFW11_MPLS_LABEL;
    wc |= OFPFW11_MPLS_TC;

    match->metadata = rule->flow.metadata;
    match->metadata_mask = ~rule->wc.metadata_mask;

    match->wildcards = htonl(wc);
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

/* Returns a transaction ID to use for an outgoing OpenFlow message. */
static ovs_be32
alloc_xid(void)
{
    static uint32_t next_xid = 1;
    return htonl(next_xid++);
}

/* Basic parsing of OpenFlow messages. */

struct ofputil_msg_type {
    enum ofputil_msg_code code; /* OFPUTIL_*. */
    uint8_t ofp_version;        /* An OpenFlow version or 0 for "any". */
    uint32_t value;             /* OFPT_*, OFPST_*, NXT_*, or NXST_*. */
    const char *name;           /* e.g. "OFPT_FLOW_REMOVED". */
    unsigned int min_size;      /* Minimum total message size in bytes. */
    /* 0 if 'min_size' is the exact size that the message must be.  Otherwise,
     * the message may exceed 'min_size' by an even multiple of this value. */
    unsigned int extra_multiple;
};

/* Represents a malformed OpenFlow message. */
static const struct ofputil_msg_type ofputil_invalid_type = {
    OFPUTIL_MSG_INVALID, 0, 0, "OFPUTIL_MSG_INVALID", 0, 0
};

struct ofputil_msg_category {
    const char *name;           /* e.g. "OpenFlow message" */
    const struct ofputil_msg_type *types;
    size_t n_types;
    enum ofperr missing_error;  /* Error value for missing type. */
};

static enum ofperr
ofputil_check_length(const struct ofputil_msg_type *type, unsigned int size)
{
    switch (type->extra_multiple) {
    case 0:
        if (size != type->min_size) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "received %s with incorrect "
                         "length %u (expected length %u)",
                         type->name, size, type->min_size);
            return OFPERR_OFPBRC_BAD_LEN;
        }
        return 0;

    case 1:
        if (size < type->min_size) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "received %s with incorrect "
                         "length %u (expected length at least %u bytes)",
                         type->name, size, type->min_size);
            return OFPERR_OFPBRC_BAD_LEN;
        }
        return 0;

    default:
        if (size < type->min_size
            || (size - type->min_size) % type->extra_multiple) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "received %s with incorrect "
                         "length %u (must be exactly %u bytes or longer "
                         "by an integer multiple of %u bytes)",
                         type->name, size,
                         type->min_size, type->extra_multiple);
            return OFPERR_OFPBRC_BAD_LEN;
        }
        return 0;
    }
}

static enum ofperr
ofputil_lookup_openflow_message(const struct ofputil_msg_category *cat,
                                uint8_t version, uint32_t value,
                                const struct ofputil_msg_type **typep)
{
    const struct ofputil_msg_type *type;

    for (type = cat->types; type < &cat->types[cat->n_types]; type++) {
        if (type->value == value
            && (!type->ofp_version || version == type->ofp_version)) {
            *typep = type;
            return 0;
        }
    }

    VLOG_WARN_RL(&bad_ofmsg_rl, "received %s of unknown type %"PRIu32,
                 cat->name, value);
    return cat->missing_error;
}

static enum ofperr
ofputil_decode_vendor(const struct ofp_header *oh, size_t length,
                      const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type nxt_messages[] = {
        { OFPUTIL_NXT_ROLE_REQUEST, OFP10_VERSION,
          NXT_ROLE_REQUEST, "NXT_ROLE_REQUEST",
          sizeof(struct nx_role_request), 0 },

        { OFPUTIL_NXT_ROLE_REPLY, OFP10_VERSION,
          NXT_ROLE_REPLY, "NXT_ROLE_REPLY",
          sizeof(struct nx_role_request), 0 },

        { OFPUTIL_NXT_SET_FLOW_FORMAT, OFP10_VERSION,
          NXT_SET_FLOW_FORMAT, "NXT_SET_FLOW_FORMAT",
          sizeof(struct nx_set_flow_format), 0 },

        { OFPUTIL_NXT_SET_PACKET_IN_FORMAT, OFP10_VERSION,
          NXT_SET_PACKET_IN_FORMAT, "NXT_SET_PACKET_IN_FORMAT",
          sizeof(struct nx_set_packet_in_format), 0 },

        { OFPUTIL_NXT_PACKET_IN, OFP10_VERSION,
          NXT_PACKET_IN, "NXT_PACKET_IN",
          sizeof(struct nx_packet_in), 1 },

        { OFPUTIL_NXT_FLOW_MOD, OFP10_VERSION,
          NXT_FLOW_MOD, "NXT_FLOW_MOD",
          sizeof(struct nx_flow_mod), 8 },

        { OFPUTIL_NXT_FLOW_REMOVED, OFP10_VERSION,
          NXT_FLOW_REMOVED, "NXT_FLOW_REMOVED",
          sizeof(struct nx_flow_removed), 8 },

        { OFPUTIL_NXT_FLOW_MOD_TABLE_ID, OFP10_VERSION,
          NXT_FLOW_MOD_TABLE_ID, "NXT_FLOW_MOD_TABLE_ID",
          sizeof(struct nx_flow_mod_table_id), 0 },

        { OFPUTIL_NXT_FLOW_AGE, OFP10_VERSION,
          NXT_FLOW_AGE, "NXT_FLOW_AGE",
          sizeof(struct nicira_header), 0 },

        { OFPUTIL_NXT_SET_ASYNC_CONFIG, OFP10_VERSION,
          NXT_SET_ASYNC_CONFIG, "NXT_SET_ASYNC_CONFIG",
          sizeof(struct nx_async_config), 0 },

        { OFPUTIL_NXT_SET_CONTROLLER_ID, OFP10_VERSION,
          NXT_SET_CONTROLLER_ID, "NXT_SET_CONTROLLER_ID",
          sizeof(struct nx_controller_id), 0 },
    };

    static const struct ofputil_msg_category nxt_category = {
        "Nicira extension message",
        nxt_messages, ARRAY_SIZE(nxt_messages),
        OFPERR_OFPBRC_BAD_SUBTYPE
    };

    const struct ofp_vendor_header *ovh;
    const struct nicira_header *nh;

    if (length < sizeof(struct ofp_vendor_header)) {
        if (length == ntohs(oh->length)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "truncated vendor message");
        }
        return OFPERR_OFPBRC_BAD_LEN;
    }

    ovh = (const struct ofp_vendor_header *) oh;
    if (ovh->vendor != htonl(NX_VENDOR_ID)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "received vendor message for unknown "
                     "vendor %"PRIx32, ntohl(ovh->vendor));
        return OFPERR_OFPBRC_BAD_VENDOR;
    }

    if (length < sizeof(struct nicira_header)) {
        if (length == ntohs(oh->length)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "received Nicira vendor message of "
                         "length %u (expected at least %zu)",
                         ntohs(ovh->header.length),
                         sizeof(struct nicira_header));
        }
        return OFPERR_OFPBRC_BAD_LEN;
    }

    nh = (const struct nicira_header *) oh;
    return ofputil_lookup_openflow_message(&nxt_category, oh->version,
                                           ntohl(nh->subtype), typep);
}

static enum ofperr
check_nxstats_msg(const struct ofp_header *oh, size_t length)
{
    const struct ofp_stats_msg *osm = (const struct ofp_stats_msg *) oh;
    ovs_be32 vendor;

    if (length < sizeof(struct ofp_vendor_stats_msg)) {
        if (length == ntohs(oh->length)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "truncated vendor stats message");
        }
        return OFPERR_OFPBRC_BAD_LEN;
    }

    memcpy(&vendor, osm + 1, sizeof vendor);
    if (vendor != htonl(NX_VENDOR_ID)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "received vendor stats message for "
                     "unknown vendor %"PRIx32, ntohl(vendor));
        return OFPERR_OFPBRC_BAD_VENDOR;
    }

    if (length < sizeof(struct nicira_stats_msg)) {
        if (length == ntohs(osm->header.length)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "truncated Nicira stats message");
        }
        return OFPERR_OFPBRC_BAD_LEN;
    }

    return 0;
}

static enum ofperr
ofputil_decode_nxst_request(const struct ofp_header *oh, size_t length,
                            const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type nxst_requests[] = {
        { OFPUTIL_NXST_FLOW_REQUEST, OFP10_VERSION,
          NXST_FLOW, "NXST_FLOW request",
          sizeof(struct nx_flow_stats_request), 8 },

        { OFPUTIL_NXST_AGGREGATE_REQUEST, OFP10_VERSION,
          NXST_AGGREGATE, "NXST_AGGREGATE request",
          sizeof(struct nx_aggregate_stats_request), 8 },
    };

    static const struct ofputil_msg_category nxst_request_category = {
        "Nicira extension statistics request",
        nxst_requests, ARRAY_SIZE(nxst_requests),
        OFPERR_OFPBRC_BAD_SUBTYPE
    };

    const struct nicira_stats_msg *nsm;
    enum ofperr error;

    error = check_nxstats_msg(oh, length);
    if (error) {
        return error;
    }

    nsm = (struct nicira_stats_msg *) oh;
    return ofputil_lookup_openflow_message(&nxst_request_category, oh->version,
                                           ntohl(nsm->subtype), typep);
}

static enum ofperr
ofputil_decode_nxst_reply(const struct ofp_header *oh, size_t length,
                          const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type nxst_replies[] = {
        { OFPUTIL_NXST_FLOW_REPLY, OFP10_VERSION,
          NXST_FLOW, "NXST_FLOW reply",
          sizeof(struct nicira_stats_msg), 8 },

        { OFPUTIL_NXST_AGGREGATE_REPLY, OFP10_VERSION,
          NXST_AGGREGATE, "NXST_AGGREGATE reply",
          sizeof(struct nx_aggregate_stats_reply), 0 },
    };

    static const struct ofputil_msg_category nxst_reply_category = {
        "Nicira extension statistics reply",
        nxst_replies, ARRAY_SIZE(nxst_replies),
        OFPERR_OFPBRC_BAD_SUBTYPE
    };

    const struct nicira_stats_msg *nsm;
    enum ofperr error;

    error = check_nxstats_msg(oh, length);
    if (error) {
        return error;
    }

    nsm = (struct nicira_stats_msg *) oh;
    return ofputil_lookup_openflow_message(&nxst_reply_category, oh->version,
                                           ntohl(nsm->subtype), typep);
}

static enum ofperr
check_stats_msg(const struct ofp_header *oh, size_t length)
{
    if (length < sizeof(struct ofp_stats_msg)) {
        if (length == ntohs(oh->length)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "truncated stats message");
        }
        return OFPERR_OFPBRC_BAD_LEN;
    }

    return 0;
}

static enum ofperr
ofputil_decode_ofpst_request(const struct ofp_header *oh, size_t length,
                             const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type ofpst_requests[] = {
        { OFPUTIL_OFPST_DESC_REQUEST, OFP10_VERSION,
          OFPST_DESC, "OFPST_DESC request",
          sizeof(struct ofp_stats_msg), 0 },

        { OFPUTIL_OFPST_FLOW_REQUEST, OFP10_VERSION,
          OFPST_FLOW, "OFPST_FLOW request",
          sizeof(struct ofp_flow_stats_request), 0 },

        { OFPUTIL_OFPST_AGGREGATE_REQUEST, OFP10_VERSION,
          OFPST_AGGREGATE, "OFPST_AGGREGATE request",
          sizeof(struct ofp_flow_stats_request), 0 },

        { OFPUTIL_OFPST_TABLE_REQUEST, OFP10_VERSION,
          OFPST_TABLE, "OFPST_TABLE request",
          sizeof(struct ofp_stats_msg), 0 },

        { OFPUTIL_OFPST_PORT_REQUEST, OFP10_VERSION,
          OFPST_PORT, "OFPST_PORT request",
          sizeof(struct ofp_port_stats_request), 0 },

        { OFPUTIL_OFPST_QUEUE_REQUEST, OFP10_VERSION,
          OFPST_QUEUE, "OFPST_QUEUE request",
          sizeof(struct ofp_queue_stats_request), 0 },

        { OFPUTIL_OFPST_PORT_DESC_REQUEST, OFP10_VERSION,
          OFPST_PORT_DESC, "OFPST_PORT_DESC request",
          sizeof(struct ofp_stats_msg), 0 },

        { 0, 0,
          OFPST_VENDOR, "OFPST_VENDOR request",
          sizeof(struct ofp_vendor_stats_msg), 1 },
    };

    static const struct ofputil_msg_category ofpst_request_category = {
        "OpenFlow statistics",
        ofpst_requests, ARRAY_SIZE(ofpst_requests),
        OFPERR_OFPBRC_BAD_STAT
    };

    const struct ofp_stats_msg *request = (const struct ofp_stats_msg *) oh;
    enum ofperr error;

    error = check_stats_msg(oh, length);
    if (error) {
        return error;
    }

    error = ofputil_lookup_openflow_message(&ofpst_request_category,
                                            oh->version, ntohs(request->type),
                                            typep);
    if (!error && request->type == htons(OFPST_VENDOR)) {
        error = ofputil_decode_nxst_request(oh, length, typep);
    }
    return error;
}

static enum ofperr
ofputil_decode_ofpst_reply(const struct ofp_header *oh, size_t length,
                           const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type ofpst_replies[] = {
        { OFPUTIL_OFPST_DESC_REPLY, OFP10_VERSION,
          OFPST_DESC, "OFPST_DESC reply",
          sizeof(struct ofp_desc_stats), 0 },

        { OFPUTIL_OFPST_FLOW_REPLY, OFP10_VERSION,
          OFPST_FLOW, "OFPST_FLOW reply",
          sizeof(struct ofp_stats_msg), 1 },

        { OFPUTIL_OFPST_AGGREGATE_REPLY, OFP10_VERSION,
          OFPST_AGGREGATE, "OFPST_AGGREGATE reply",
          sizeof(struct ofp_aggregate_stats_reply), 0 },

        { OFPUTIL_OFPST_TABLE_REPLY, OFP10_VERSION,
          OFPST_TABLE, "OFPST_TABLE reply",
          sizeof(struct ofp_stats_msg), sizeof(struct ofp_table_stats) },

        { OFPUTIL_OFPST_PORT_REPLY, OFP10_VERSION,
          OFPST_PORT, "OFPST_PORT reply",
          sizeof(struct ofp_stats_msg), sizeof(struct ofp_port_stats) },

        { OFPUTIL_OFPST_QUEUE_REPLY, OFP10_VERSION,
          OFPST_QUEUE, "OFPST_QUEUE reply",
          sizeof(struct ofp_stats_msg), sizeof(struct ofp_queue_stats) },

        { OFPUTIL_OFPST_PORT_DESC_REPLY, OFP10_VERSION,
          OFPST_PORT_DESC, "OFPST_PORT_DESC reply",
          sizeof(struct ofp_stats_msg), sizeof(struct ofp10_phy_port) },

        { 0, 0,
          OFPST_VENDOR, "OFPST_VENDOR reply",
          sizeof(struct ofp_vendor_stats_msg), 1 },
    };

    static const struct ofputil_msg_category ofpst_reply_category = {
        "OpenFlow statistics",
        ofpst_replies, ARRAY_SIZE(ofpst_replies),
        OFPERR_OFPBRC_BAD_STAT
    };

    const struct ofp_stats_msg *reply = (const struct ofp_stats_msg *) oh;
    enum ofperr error;

    error = check_stats_msg(oh, length);
    if (error) {
        return error;
    }

    error = ofputil_lookup_openflow_message(&ofpst_reply_category, oh->version,
                                           ntohs(reply->type), typep);
    if (!error && reply->type == htons(OFPST_VENDOR)) {
        error = ofputil_decode_nxst_reply(oh, length, typep);
    }
    return error;
}

static enum ofperr
ofputil_decode_msg_type__(const struct ofp_header *oh, size_t length,
                          const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type ofpt_messages[] = {
        { OFPUTIL_OFPT_HELLO, OFP10_VERSION,
          OFPT_HELLO, "OFPT_HELLO",
          sizeof(struct ofp_hello), 1 },

        { OFPUTIL_OFPT_ERROR, 0,
          OFPT_ERROR, "OFPT_ERROR",
          sizeof(struct ofp_error_msg), 1 },

        { OFPUTIL_OFPT_ECHO_REQUEST, OFP10_VERSION,
          OFPT_ECHO_REQUEST, "OFPT_ECHO_REQUEST",
          sizeof(struct ofp_header), 1 },

        { OFPUTIL_OFPT_ECHO_REPLY, OFP10_VERSION,
          OFPT_ECHO_REPLY, "OFPT_ECHO_REPLY",
          sizeof(struct ofp_header), 1 },

        { OFPUTIL_OFPT_FEATURES_REQUEST, OFP10_VERSION,
          OFPT_FEATURES_REQUEST, "OFPT_FEATURES_REQUEST",
          sizeof(struct ofp_header), 0 },

        { OFPUTIL_OFPT_FEATURES_REPLY, OFP10_VERSION,
          OFPT_FEATURES_REPLY, "OFPT_FEATURES_REPLY",
          sizeof(struct ofp_switch_features), sizeof(struct ofp10_phy_port) },
        { OFPUTIL_OFPT_FEATURES_REPLY, OFP11_VERSION,
          OFPT_FEATURES_REPLY, "OFPT_FEATURES_REPLY",
          sizeof(struct ofp_switch_features), sizeof(struct ofp11_port) },

        { OFPUTIL_OFPT_GET_CONFIG_REQUEST, OFP10_VERSION,
          OFPT_GET_CONFIG_REQUEST, "OFPT_GET_CONFIG_REQUEST",
          sizeof(struct ofp_header), 0 },

        { OFPUTIL_OFPT_GET_CONFIG_REPLY, OFP10_VERSION,
          OFPT_GET_CONFIG_REPLY, "OFPT_GET_CONFIG_REPLY",
          sizeof(struct ofp_switch_config), 0 },

        { OFPUTIL_OFPT_SET_CONFIG, OFP10_VERSION,
          OFPT_SET_CONFIG, "OFPT_SET_CONFIG",
          sizeof(struct ofp_switch_config), 0 },

        { OFPUTIL_OFPT_PACKET_IN, OFP10_VERSION,
          OFPT_PACKET_IN, "OFPT_PACKET_IN",
          offsetof(struct ofp_packet_in, data), 1 },

        { OFPUTIL_OFPT_FLOW_REMOVED, OFP10_VERSION,
          OFPT_FLOW_REMOVED, "OFPT_FLOW_REMOVED",
          sizeof(struct ofp_flow_removed), 0 },

        { OFPUTIL_OFPT_PORT_STATUS, OFP10_VERSION,
          OFPT_PORT_STATUS, "OFPT_PORT_STATUS",
          sizeof(struct ofp_port_status) + sizeof(struct ofp10_phy_port), 0 },
        { OFPUTIL_OFPT_PORT_STATUS, OFP11_VERSION,
          OFPT_PORT_STATUS, "OFPT_PORT_STATUS",
          sizeof(struct ofp_port_status) + sizeof(struct ofp11_port), 0 },

        { OFPUTIL_OFPT_PACKET_OUT, OFP10_VERSION,
          OFPT10_PACKET_OUT, "OFPT_PACKET_OUT",
          sizeof(struct ofp_packet_out), 1 },

        { OFPUTIL_OFPT_FLOW_MOD, OFP10_VERSION,
          OFPT10_FLOW_MOD, "OFPT_FLOW_MOD",
          sizeof(struct ofp_flow_mod), 1 },

        { OFPUTIL_OFPT_PORT_MOD, OFP10_VERSION,
          OFPT10_PORT_MOD, "OFPT_PORT_MOD",
          sizeof(struct ofp10_port_mod), 0 },
        { OFPUTIL_OFPT_PORT_MOD, OFP11_VERSION,
          OFPT11_PORT_MOD, "OFPT_PORT_MOD",
          sizeof(struct ofp11_port_mod), 0 },

        { 0, OFP10_VERSION,
          OFPT10_STATS_REQUEST, "OFPT_STATS_REQUEST",
          sizeof(struct ofp_stats_msg), 1 },

        { 0, OFP10_VERSION,
          OFPT10_STATS_REPLY, "OFPT_STATS_REPLY",
          sizeof(struct ofp_stats_msg), 1 },

        { OFPUTIL_OFPT_BARRIER_REQUEST, OFP10_VERSION,
          OFPT10_BARRIER_REQUEST, "OFPT_BARRIER_REQUEST",
          sizeof(struct ofp_header), 0 },

        { OFPUTIL_OFPT_BARRIER_REPLY, OFP10_VERSION,
          OFPT10_BARRIER_REPLY, "OFPT_BARRIER_REPLY",
          sizeof(struct ofp_header), 0 },

        { 0, 0,
          OFPT_VENDOR, "OFPT_VENDOR",
          sizeof(struct ofp_vendor_header), 1 },
    };

    static const struct ofputil_msg_category ofpt_category = {
        "OpenFlow message",
        ofpt_messages, ARRAY_SIZE(ofpt_messages),
        OFPERR_OFPBRC_BAD_TYPE
    };

    enum ofperr error;

    error = ofputil_lookup_openflow_message(&ofpt_category, oh->version,
                                            oh->type, typep);
    if (!error) {
        switch ((oh->version << 8) | oh->type) {
        case (OFP10_VERSION << 8) | OFPT_VENDOR:
        case (OFP11_VERSION << 8) | OFPT_VENDOR:
            error = ofputil_decode_vendor(oh, length, typep);
            break;

        case (OFP10_VERSION << 8) | OFPT10_STATS_REQUEST:
        case (OFP11_VERSION << 8) | OFPT11_STATS_REQUEST:
            error = ofputil_decode_ofpst_request(oh, length, typep);
            break;

        case (OFP10_VERSION << 8) | OFPT10_STATS_REPLY:
        case (OFP11_VERSION << 8) | OFPT11_STATS_REPLY:
            error = ofputil_decode_ofpst_reply(oh, length, typep);

        default:
            break;
        }
    }
    return error;
}

/* Decodes the message type represented by 'oh'.  Returns 0 if successful or an
 * OpenFlow error code on failure.  Either way, stores in '*typep' a type
 * structure that can be inspected with the ofputil_msg_type_*() functions.
 *
 * oh->length must indicate the correct length of the message (and must be at
 * least sizeof(struct ofp_header)).
 *
 * Success indicates that 'oh' is at least as long as the minimum-length
 * message of its type. */
enum ofperr
ofputil_decode_msg_type(const struct ofp_header *oh,
                        const struct ofputil_msg_type **typep)
{
    size_t length = ntohs(oh->length);
    enum ofperr error;

    error = ofputil_decode_msg_type__(oh, length, typep);
    if (!error) {
        error = ofputil_check_length(*typep, length);
    }
    if (error) {
        *typep = &ofputil_invalid_type;
    }
    return error;
}

/* Decodes the message type represented by 'oh', of which only the first
 * 'length' bytes are available.  Returns 0 if successful or an OpenFlow error
 * code on failure.  Either way, stores in '*typep' a type structure that can
 * be inspected with the ofputil_msg_type_*() functions.  */
enum ofperr
ofputil_decode_msg_type_partial(const struct ofp_header *oh, size_t length,
                                const struct ofputil_msg_type **typep)
{
    enum ofperr error;

    error = (length >= sizeof *oh
             ? ofputil_decode_msg_type__(oh, length, typep)
             : OFPERR_OFPBRC_BAD_LEN);
    if (error) {
        *typep = &ofputil_invalid_type;
    }
    return error;
}

/* Returns an OFPUTIL_* message type code for 'type'. */
enum ofputil_msg_code
ofputil_msg_type_code(const struct ofputil_msg_type *type)
{
    return type->code;
}

/* Protocols. */

struct proto_abbrev {
    enum ofputil_protocol protocol;
    const char *name;
};

/* Most users really don't care about some of the differences between
 * protocols.  These abbreviations help with that. */
static const struct proto_abbrev proto_abbrevs[] = {
    { OFPUTIL_P_ANY,      "any" },
    { OFPUTIL_P_OF10_ANY, "OpenFlow10" },
    { OFPUTIL_P_NXM_ANY,  "NXM" },
};
#define N_PROTO_ABBREVS ARRAY_SIZE(proto_abbrevs)

enum ofputil_protocol ofputil_flow_dump_protocols[] = {
    OFPUTIL_P_NXM,
    OFPUTIL_P_OF10,
};
size_t ofputil_n_flow_dump_protocols = ARRAY_SIZE(ofputil_flow_dump_protocols);

/* Returns the ofputil_protocol that is initially in effect on an OpenFlow
 * connection that has negotiated the given 'version'.  'version' should
 * normally be an 8-bit OpenFlow version identifier (e.g. 0x01 for OpenFlow
 * 1.0, 0x02 for OpenFlow 1.1).  Returns 0 if 'version' is not supported or
 * outside the valid range.  */
enum ofputil_protocol
ofputil_protocol_from_ofp_version(int version)
{
    switch (version) {
    case OFP10_VERSION: return OFPUTIL_P_OF10;
    default: return 0;
    }
}

/* Returns the OpenFlow protocol version number (e.g. OFP10_VERSION or
 * OFP11_VERSION) that corresponds to 'protocol'. */
uint8_t
ofputil_protocol_to_ofp_version(enum ofputil_protocol protocol)
{
    switch (protocol) {
    case OFPUTIL_P_OF10:
    case OFPUTIL_P_OF10_TID:
    case OFPUTIL_P_NXM:
    case OFPUTIL_P_NXM_TID:
        return OFP10_VERSION;
    }

    NOT_REACHED();
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
    case OFPUTIL_P_OF10:
    case OFPUTIL_P_OF10_TID:
        return enable ? OFPUTIL_P_OF10_TID : OFPUTIL_P_OF10;

    case OFPUTIL_P_NXM:
    case OFPUTIL_P_NXM_TID:
        return enable ? OFPUTIL_P_NXM_TID : OFPUTIL_P_NXM;

    default:
        NOT_REACHED();
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
    case OFPUTIL_P_OF10:
    case OFPUTIL_P_OF10_TID:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF10, tid);

    case OFPUTIL_P_NXM:
    case OFPUTIL_P_NXM_TID:
        return ofputil_protocol_set_tid(OFPUTIL_P_NXM, tid);

    default:
        NOT_REACHED();
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
    case OFPUTIL_P_NXM:
        return "NXM-table_id";

    case OFPUTIL_P_NXM_TID:
        return "NXM+table_id";

    case OFPUTIL_P_OF10:
        return "OpenFlow10-table_id";

    case OFPUTIL_P_OF10_TID:
        return "OpenFlow10+table_id";
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

    assert(!(protocols & ~OFPUTIL_P_ANY));
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
        NOT_REACHED();

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
        NOT_REACHED();
    }
}

int
ofputil_packet_in_format_from_string(const char *s)
{
    return (!strcmp(s, "openflow10") ? NXPIF_OPENFLOW10
            : !strcmp(s, "nxm") ? NXPIF_NXM
            : -1);
}

static bool
regs_fully_wildcarded(const struct flow_wildcards *wc)
{
    int i;

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (wc->reg_masks[i] != 0) {
            return false;
        }
    }
    return true;
}

/* Returns a bit-mask of ofputil_protocols that can be used for sending 'rule'
 * to a switch (e.g. to add or remove a flow).  Only NXM can handle tunnel IDs,
 * registers, or fixing the Ethernet multicast bit.  Otherwise, it's better to
 * use OpenFlow 1.0 protocol for backward compatibility. */
enum ofputil_protocol
ofputil_usable_protocols(const struct cls_rule *rule)
{
    const struct flow_wildcards *wc = &rule->wc;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 12);

    /* NXM and OF1.1+ supports bitwise matching on ethernet addresses. */
    if (!eth_mask_is_exact(wc->dl_src_mask)
        && !eth_addr_is_zero(wc->dl_src_mask)) {
        return OFPUTIL_P_NXM_ANY;
    }
    if (!eth_mask_is_exact(wc->dl_dst_mask)
        && !eth_addr_is_zero(wc->dl_dst_mask)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* NXM and OF1.1+ support matching metadata. */
    if (wc->metadata_mask != htonll(0)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports matching ARP hardware addresses. */
    if (!(wc->wildcards & FWW_ARP_SHA) || !(wc->wildcards & FWW_ARP_THA)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports matching IPv6 traffic. */
    if (!(wc->wildcards & FWW_DL_TYPE)
            && (rule->flow.dl_type == htons(ETH_TYPE_IPV6))) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports matching registers. */
    if (!regs_fully_wildcarded(wc)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports matching tun_id. */
    if (wc->tun_id_mask != htonll(0)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports matching fragments. */
    if (wc->nw_frag_mask) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports matching IPv6 flow label. */
    if (!(wc->wildcards & FWW_IPV6_LABEL)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports matching IP ECN bits. */
    if (!(wc->wildcards & FWW_NW_ECN)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports matching IP TTL/hop limit. */
    if (!(wc->wildcards & FWW_NW_TTL)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports non-CIDR IPv4 address masks. */
    if (!ip_is_cidr(wc->nw_src_mask) || !ip_is_cidr(wc->nw_dst_mask)) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Only NXM supports bitwise matching on transport port. */
    if ((wc->tp_src_mask && wc->tp_src_mask != htons(UINT16_MAX)) ||
        (wc->tp_dst_mask && wc->tp_dst_mask != htons(UINT16_MAX))) {
        return OFPUTIL_P_NXM_ANY;
    }

    /* Other formats can express this rule. */
    return OFPUTIL_P_ANY;
}

/* Returns an OpenFlow message that, sent on an OpenFlow connection whose
 * protocol is 'current', at least partly transitions the protocol to 'want'.
 * Stores in '*next' the protocol that will be in effect on the OpenFlow
 * connection if the switch processes the returned message correctly.  (If
 * '*next != want' then the caller will have to iterate.)
 *
 * If 'current == want', returns NULL and stores 'current' in '*next'. */
struct ofpbuf *
ofputil_encode_set_protocol(enum ofputil_protocol current,
                            enum ofputil_protocol want,
                            enum ofputil_protocol *next)
{
    enum ofputil_protocol cur_base, want_base;
    bool cur_tid, want_tid;

    cur_base = ofputil_protocol_to_base(current);
    want_base = ofputil_protocol_to_base(want);
    if (cur_base != want_base) {
        *next = ofputil_protocol_set_base(current, want_base);

        switch (want_base) {
        case OFPUTIL_P_NXM:
            return ofputil_encode_nx_set_flow_format(NXFF_NXM);

        case OFPUTIL_P_OF10:
            return ofputil_encode_nx_set_flow_format(NXFF_OPENFLOW10);

        case OFPUTIL_P_OF10_TID:
        case OFPUTIL_P_NXM_TID:
            NOT_REACHED();
        }
    }

    cur_tid = (current & OFPUTIL_P_TID) != 0;
    want_tid = (want & OFPUTIL_P_TID) != 0;
    if (cur_tid != want_tid) {
        *next = ofputil_protocol_set_tid(current, want_tid);
        return ofputil_make_flow_mod_table_id(want_tid);
    }

    assert(current == want);

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

    assert(ofputil_nx_flow_format_is_valid(nxff));

    sff = make_nxmsg(sizeof *sff, NXT_SET_FLOW_FORMAT, &msg);
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
        return OFPUTIL_P_OF10;

    case NXFF_NXM:
        return OFPUTIL_P_NXM;

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
        NOT_REACHED();
    }
}

struct ofpbuf *
ofputil_make_set_packet_in_format(enum nx_packet_in_format packet_in_format)
{
    struct nx_set_packet_in_format *spif;
    struct ofpbuf *msg;

    spif = make_nxmsg(sizeof *spif, NXT_SET_PACKET_IN_FORMAT, &msg);
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

    nfmti = make_nxmsg(sizeof *nfmti, NXT_FLOW_MOD_TABLE_ID, &msg);
    nfmti->set = flow_mod_table_id;
    return msg;
}

/* Converts an OFPT_FLOW_MOD or NXT_FLOW_MOD message 'oh' into an abstract
 * flow_mod in 'fm'.  Returns 0 if successful, otherwise an OpenFlow error
 * code.
 *
 * Does not validate the flow_mod actions. */
enum ofperr
ofputil_decode_flow_mod(struct ofputil_flow_mod *fm,
                        const struct ofp_header *oh,
                        enum ofputil_protocol protocol)
{
    const struct ofputil_msg_type *type;
    uint16_t command;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    ofputil_decode_msg_type(oh, &type);
    if (ofputil_msg_type_code(type) == OFPUTIL_OFPT_FLOW_MOD) {
        /* Standard OpenFlow flow_mod. */
        const struct ofp_flow_mod *ofm;
        uint16_t priority;
        enum ofperr error;

        /* Dissect the message. */
        ofm = ofpbuf_pull(&b, sizeof *ofm);
        error = ofputil_pull_actions(&b, b.size, &fm->actions, &fm->n_actions);
        if (error) {
            return error;
        }

        /* Set priority based on original wildcards.  Normally we'd allow
         * ofputil_cls_rule_from_match() to do this for us, but
         * ofputil_normalize_rule() can put wildcards where the original flow
         * didn't have them. */
        priority = ntohs(ofm->priority);
        if (!(ofm->match.wildcards & htonl(OFPFW10_ALL))) {
            priority = UINT16_MAX;
        }

        /* Translate the rule. */
        ofputil_cls_rule_from_ofp10_match(&ofm->match, priority, &fm->cr);
        ofputil_normalize_rule(&fm->cr);

        /* Translate the message. */
        command = ntohs(ofm->command);
        fm->cookie = htonll(0);
        fm->cookie_mask = htonll(0);
        fm->new_cookie = ofm->cookie;
        fm->idle_timeout = ntohs(ofm->idle_timeout);
        fm->hard_timeout = ntohs(ofm->hard_timeout);
        fm->buffer_id = ntohl(ofm->buffer_id);
        fm->out_port = ntohs(ofm->out_port);
        fm->flags = ntohs(ofm->flags);
    } else if (ofputil_msg_type_code(type) == OFPUTIL_NXT_FLOW_MOD) {
        /* Nicira extended flow_mod. */
        const struct nx_flow_mod *nfm;
        enum ofperr error;

        /* Dissect the message. */
        nfm = ofpbuf_pull(&b, sizeof *nfm);
        error = nx_pull_match(&b, ntohs(nfm->match_len), ntohs(nfm->priority),
                              &fm->cr, &fm->cookie, &fm->cookie_mask);
        if (error) {
            return error;
        }
        error = ofputil_pull_actions(&b, b.size, &fm->actions, &fm->n_actions);
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
        fm->new_cookie = nfm->cookie;
        fm->idle_timeout = ntohs(nfm->idle_timeout);
        fm->hard_timeout = ntohs(nfm->hard_timeout);
        fm->buffer_id = ntohl(nfm->buffer_id);
        fm->out_port = ntohs(nfm->out_port);
        fm->flags = ntohs(nfm->flags);
    } else {
        NOT_REACHED();
    }

    if (protocol & OFPUTIL_P_TID) {
        fm->command = command & 0xff;
        fm->table_id = command >> 8;
    } else {
        fm->command = command;
        fm->table_id = 0xff;
    }

    return 0;
}

/* Converts 'fm' into an OFPT_FLOW_MOD or NXT_FLOW_MOD message according to
 * 'protocol' and returns the message. */
struct ofpbuf *
ofputil_encode_flow_mod(const struct ofputil_flow_mod *fm,
                        enum ofputil_protocol protocol)
{
    size_t actions_len = fm->n_actions * sizeof *fm->actions;
    struct ofp_flow_mod *ofm;
    struct nx_flow_mod *nfm;
    struct ofpbuf *msg;
    uint16_t command;
    int match_len;

    command = (protocol & OFPUTIL_P_TID
               ? (fm->command & 0xff) | (fm->table_id << 8)
               : fm->command);

    switch (protocol) {
    case OFPUTIL_P_OF10:
    case OFPUTIL_P_OF10_TID:
        msg = ofpbuf_new(sizeof *ofm + actions_len);
        ofm = put_openflow(sizeof *ofm, OFPT10_FLOW_MOD, msg);
        ofputil_cls_rule_to_ofp10_match(&fm->cr, &ofm->match);
        ofm->cookie = fm->new_cookie;
        ofm->command = htons(command);
        ofm->idle_timeout = htons(fm->idle_timeout);
        ofm->hard_timeout = htons(fm->hard_timeout);
        ofm->priority = htons(fm->cr.priority);
        ofm->buffer_id = htonl(fm->buffer_id);
        ofm->out_port = htons(fm->out_port);
        ofm->flags = htons(fm->flags);
        break;

    case OFPUTIL_P_NXM:
    case OFPUTIL_P_NXM_TID:
        msg = ofpbuf_new(sizeof *nfm + NXM_TYPICAL_LEN + actions_len);
        put_nxmsg(sizeof *nfm, NXT_FLOW_MOD, msg);
        nfm = msg->data;
        nfm->command = htons(command);
        nfm->cookie = fm->new_cookie;
        match_len = nx_put_match(msg, false, &fm->cr,
                                 fm->cookie, fm->cookie_mask);
        nfm = msg->data;
        nfm->idle_timeout = htons(fm->idle_timeout);
        nfm->hard_timeout = htons(fm->hard_timeout);
        nfm->priority = htons(fm->cr.priority);
        nfm->buffer_id = htonl(fm->buffer_id);
        nfm->out_port = htons(fm->out_port);
        nfm->flags = htons(fm->flags);
        nfm->match_len = htons(match_len);
        break;

    default:
        NOT_REACHED();
    }

    ofpbuf_put(msg, fm->actions, actions_len);
    update_openflow_length(msg);
    return msg;
}

/* Returns a bitmask with a 1-bit for each protocol that could be used to
 * send all of the 'n_fm's flow table modification requests in 'fms', and a
 * 0-bit for each protocol that is inadequate.
 *
 * (The return value will have at least one 1-bit.) */
enum ofputil_protocol
ofputil_flow_mod_usable_protocols(const struct ofputil_flow_mod *fms,
                                  size_t n_fms)
{
    enum ofputil_protocol usable_protocols;
    size_t i;

    usable_protocols = OFPUTIL_P_ANY;
    for (i = 0; i < n_fms; i++) {
        const struct ofputil_flow_mod *fm = &fms[i];

        usable_protocols &= ofputil_usable_protocols(&fm->cr);
        if (fm->table_id != 0xff) {
            usable_protocols &= OFPUTIL_P_TID;
        }

        /* Matching of the cookie is only supported through NXM. */
        if (fm->cookie_mask != htonll(0)) {
            usable_protocols &= OFPUTIL_P_NXM_ANY;
        }
    }
    assert(usable_protocols);

    return usable_protocols;
}

static enum ofperr
ofputil_decode_ofpst_flow_request(struct ofputil_flow_stats_request *fsr,
                                  const struct ofp_header *oh,
                                  bool aggregate)
{
    const struct ofp_flow_stats_request *ofsr =
        (const struct ofp_flow_stats_request *) oh;

    fsr->aggregate = aggregate;
    ofputil_cls_rule_from_ofp10_match(&ofsr->match, 0, &fsr->match);
    fsr->out_port = ntohs(ofsr->out_port);
    fsr->table_id = ofsr->table_id;
    fsr->cookie = fsr->cookie_mask = htonll(0);

    return 0;
}

static enum ofperr
ofputil_decode_nxst_flow_request(struct ofputil_flow_stats_request *fsr,
                                 const struct ofp_header *oh,
                                 bool aggregate)
{
    const struct nx_flow_stats_request *nfsr;
    struct ofpbuf b;
    enum ofperr error;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    nfsr = ofpbuf_pull(&b, sizeof *nfsr);
    error = nx_pull_match(&b, ntohs(nfsr->match_len), 0, &fsr->match,
                          &fsr->cookie, &fsr->cookie_mask);
    if (error) {
        return error;
    }
    if (b.size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    fsr->aggregate = aggregate;
    fsr->out_port = ntohs(nfsr->out_port);
    fsr->table_id = nfsr->table_id;

    return 0;
}

/* Converts an OFPST_FLOW, OFPST_AGGREGATE, NXST_FLOW, or NXST_AGGREGATE
 * request 'oh', into an abstract flow_stats_request in 'fsr'.  Returns 0 if
 * successful, otherwise an OpenFlow error code. */
enum ofperr
ofputil_decode_flow_stats_request(struct ofputil_flow_stats_request *fsr,
                                  const struct ofp_header *oh)
{
    const struct ofputil_msg_type *type;
    struct ofpbuf b;
    int code;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    ofputil_decode_msg_type(oh, &type);
    code = ofputil_msg_type_code(type);
    switch (code) {
    case OFPUTIL_OFPST_FLOW_REQUEST:
        return ofputil_decode_ofpst_flow_request(fsr, oh, false);

    case OFPUTIL_OFPST_AGGREGATE_REQUEST:
        return ofputil_decode_ofpst_flow_request(fsr, oh, true);

    case OFPUTIL_NXST_FLOW_REQUEST:
        return ofputil_decode_nxst_flow_request(fsr, oh, false);

    case OFPUTIL_NXST_AGGREGATE_REQUEST:
        return ofputil_decode_nxst_flow_request(fsr, oh, true);

    default:
        /* Hey, the caller lied. */
        NOT_REACHED();
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

    switch (protocol) {
    case OFPUTIL_P_OF10:
    case OFPUTIL_P_OF10_TID: {
        struct ofp_flow_stats_request *ofsr;
        int type;

        type = fsr->aggregate ? OFPST_AGGREGATE : OFPST_FLOW;
        ofsr = ofputil_make_stats_request(sizeof *ofsr, type, 0, &msg);
        ofputil_cls_rule_to_ofp10_match(&fsr->match, &ofsr->match);
        ofsr->table_id = fsr->table_id;
        ofsr->out_port = htons(fsr->out_port);
        break;
    }

    case OFPUTIL_P_NXM:
    case OFPUTIL_P_NXM_TID: {
        struct nx_flow_stats_request *nfsr;
        int match_len;
        int subtype;

        subtype = fsr->aggregate ? NXST_AGGREGATE : NXST_FLOW;
        ofputil_make_stats_request(sizeof *nfsr, OFPST_VENDOR, subtype, &msg);
        match_len = nx_put_match(msg, false, &fsr->match,
                                 fsr->cookie, fsr->cookie_mask);

        nfsr = msg->data;
        nfsr->out_port = htons(fsr->out_port);
        nfsr->match_len = htons(match_len);
        nfsr->table_id = fsr->table_id;
        break;
    }

    default:
        NOT_REACHED();
    }

    return msg;
}

/* Returns a bitmask with a 1-bit for each protocol that could be used to
 * accurately encode 'fsr', and a 0-bit for each protocol that is inadequate.
 *
 * (The return value will have at least one 1-bit.) */
enum ofputil_protocol
ofputil_flow_stats_request_usable_protocols(
    const struct ofputil_flow_stats_request *fsr)
{
    enum ofputil_protocol usable_protocols;

    usable_protocols = ofputil_usable_protocols(&fsr->match);
    if (fsr->cookie_mask != htonll(0)) {
        usable_protocols &= OFPUTIL_P_NXM_ANY;
    }
    return usable_protocols;
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
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_flow_stats_reply(struct ofputil_flow_stats *fs,
                                struct ofpbuf *msg,
                                bool flow_age_extension)
{
    const struct ofputil_msg_type *type;
    int code;

    ofputil_decode_msg_type(msg->l2 ? msg->l2 : msg->data, &type);
    code = ofputil_msg_type_code(type);
    if (!msg->l2) {
        msg->l2 = msg->data;
        if (code == OFPUTIL_OFPST_FLOW_REPLY) {
            ofpbuf_pull(msg, sizeof(struct ofp_stats_msg));
        } else if (code == OFPUTIL_NXST_FLOW_REPLY) {
            ofpbuf_pull(msg, sizeof(struct nicira_stats_msg));
        } else {
            NOT_REACHED();
        }
    }

    if (!msg->size) {
        return EOF;
    } else if (code == OFPUTIL_OFPST_FLOW_REPLY) {
        const struct ofp_flow_stats *ofs;
        size_t length;

        ofs = ofpbuf_try_pull(msg, sizeof *ofs);
        if (!ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply has %zu leftover "
                         "bytes at end", msg->size);
            return EINVAL;
        }

        length = ntohs(ofs->length);
        if (length < sizeof *ofs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "OFPST_FLOW reply claims invalid "
                         "length %zu", length);
            return EINVAL;
        }

        if (ofputil_pull_actions(msg, length - sizeof *ofs,
                                 &fs->actions, &fs->n_actions)) {
            return EINVAL;
        }

        fs->cookie = get_32aligned_be64(&ofs->cookie);
        ofputil_cls_rule_from_ofp10_match(&ofs->match, ntohs(ofs->priority),
                                          &fs->rule);
        fs->table_id = ofs->table_id;
        fs->duration_sec = ntohl(ofs->duration_sec);
        fs->duration_nsec = ntohl(ofs->duration_nsec);
        fs->idle_timeout = ntohs(ofs->idle_timeout);
        fs->hard_timeout = ntohs(ofs->hard_timeout);
        fs->idle_age = -1;
        fs->hard_age = -1;
        fs->packet_count = ntohll(get_32aligned_be64(&ofs->packet_count));
        fs->byte_count = ntohll(get_32aligned_be64(&ofs->byte_count));
    } else if (code == OFPUTIL_NXST_FLOW_REPLY) {
        const struct nx_flow_stats *nfs;
        size_t match_len, length;

        nfs = ofpbuf_try_pull(msg, sizeof *nfs);
        if (!nfs) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW reply has %zu leftover "
                         "bytes at end", msg->size);
            return EINVAL;
        }

        length = ntohs(nfs->length);
        match_len = ntohs(nfs->match_len);
        if (length < sizeof *nfs + ROUND_UP(match_len, 8)) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "NXST_FLOW reply with match_len=%zu "
                         "claims invalid length %zu", match_len, length);
            return EINVAL;
        }
        if (nx_pull_match(msg, match_len, ntohs(nfs->priority), &fs->rule,
                          NULL, NULL)) {
            return EINVAL;
        }

        if (ofputil_pull_actions(msg,
                                 length - sizeof *nfs - ROUND_UP(match_len, 8),
                                 &fs->actions, &fs->n_actions)) {
            return EINVAL;
        }

        fs->cookie = nfs->cookie;
        fs->table_id = nfs->table_id;
        fs->duration_sec = ntohl(nfs->duration_sec);
        fs->duration_nsec = ntohl(nfs->duration_nsec);
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
    } else {
        NOT_REACHED();
    }

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
 * have been initialized with ofputil_start_stats_reply(). */
void
ofputil_append_flow_stats_reply(const struct ofputil_flow_stats *fs,
                                struct list *replies)
{
    size_t act_len = fs->n_actions * sizeof *fs->actions;
    const struct ofp_stats_msg *osm;

    osm = ofpbuf_from_list(list_back(replies))->data;
    if (osm->type == htons(OFPST_FLOW)) {
        size_t len = offsetof(struct ofp_flow_stats, actions) + act_len;
        struct ofp_flow_stats *ofs;

        ofs = ofputil_append_stats_reply(len, replies);
        ofs->length = htons(len);
        ofs->table_id = fs->table_id;
        ofs->pad = 0;
        ofputil_cls_rule_to_ofp10_match(&fs->rule, &ofs->match);
        ofs->duration_sec = htonl(fs->duration_sec);
        ofs->duration_nsec = htonl(fs->duration_nsec);
        ofs->priority = htons(fs->rule.priority);
        ofs->idle_timeout = htons(fs->idle_timeout);
        ofs->hard_timeout = htons(fs->hard_timeout);
        memset(ofs->pad2, 0, sizeof ofs->pad2);
        put_32aligned_be64(&ofs->cookie, fs->cookie);
        put_32aligned_be64(&ofs->packet_count,
                           htonll(unknown_to_zero(fs->packet_count)));
        put_32aligned_be64(&ofs->byte_count,
                           htonll(unknown_to_zero(fs->byte_count)));
        memcpy(ofs->actions, fs->actions, act_len);
    } else if (osm->type == htons(OFPST_VENDOR)) {
        struct nx_flow_stats *nfs;
        struct ofpbuf *msg;
        size_t start_len;

        msg = ofputil_reserve_stats_reply(
            sizeof *nfs + NXM_MAX_LEN + act_len, replies);
        start_len = msg->size;

        nfs = ofpbuf_put_uninit(msg, sizeof *nfs);
        nfs->table_id = fs->table_id;
        nfs->pad = 0;
        nfs->duration_sec = htonl(fs->duration_sec);
        nfs->duration_nsec = htonl(fs->duration_nsec);
        nfs->priority = htons(fs->rule.priority);
        nfs->idle_timeout = htons(fs->idle_timeout);
        nfs->hard_timeout = htons(fs->hard_timeout);
        nfs->idle_age = htons(fs->idle_age < 0 ? 0
                              : fs->idle_age < UINT16_MAX ? fs->idle_age + 1
                              : UINT16_MAX);
        nfs->hard_age = htons(fs->hard_age < 0 ? 0
                              : fs->hard_age < UINT16_MAX ? fs->hard_age + 1
                              : UINT16_MAX);
        nfs->match_len = htons(nx_put_match(msg, false, &fs->rule, 0, 0));
        nfs->cookie = fs->cookie;
        nfs->packet_count = htonll(fs->packet_count);
        nfs->byte_count = htonll(fs->byte_count);
        ofpbuf_put(msg, fs->actions, act_len);
        nfs->length = htons(msg->size - start_len);
    } else {
        NOT_REACHED();
    }
}

/* Converts abstract ofputil_aggregate_stats 'stats' into an OFPST_AGGREGATE or
 * NXST_AGGREGATE reply according to 'protocol', and returns the message. */
struct ofpbuf *
ofputil_encode_aggregate_stats_reply(
    const struct ofputil_aggregate_stats *stats,
    const struct ofp_stats_msg *request)
{
    struct ofpbuf *msg;

    if (request->type == htons(OFPST_AGGREGATE)) {
        struct ofp_aggregate_stats_reply *asr;

        asr = ofputil_make_stats_reply(sizeof *asr, request, &msg);
        put_32aligned_be64(&asr->packet_count,
                           htonll(unknown_to_zero(stats->packet_count)));
        put_32aligned_be64(&asr->byte_count,
                           htonll(unknown_to_zero(stats->byte_count)));
        asr->flow_count = htonl(stats->flow_count);
    } else if (request->type == htons(OFPST_VENDOR)) {
        struct nx_aggregate_stats_reply *nasr;

        nasr = ofputil_make_stats_reply(sizeof *nasr, request, &msg);
        assert(nasr->nsm.subtype == htonl(NXST_AGGREGATE));
        nasr->packet_count = htonll(stats->packet_count);
        nasr->byte_count = htonll(stats->byte_count);
        nasr->flow_count = htonl(stats->flow_count);
    } else {
        NOT_REACHED();
    }

    return msg;
}

/* Converts an OFPT_FLOW_REMOVED or NXT_FLOW_REMOVED message 'oh' into an
 * abstract ofputil_flow_removed in 'fr'.  Returns 0 if successful, otherwise
 * an OpenFlow error code. */
enum ofperr
ofputil_decode_flow_removed(struct ofputil_flow_removed *fr,
                            const struct ofp_header *oh)
{
    const struct ofputil_msg_type *type;
    enum ofputil_msg_code code;

    ofputil_decode_msg_type(oh, &type);
    code = ofputil_msg_type_code(type);
    if (code == OFPUTIL_OFPT_FLOW_REMOVED) {
        const struct ofp_flow_removed *ofr;

        ofr = (const struct ofp_flow_removed *) oh;
        ofputil_cls_rule_from_ofp10_match(&ofr->match, ntohs(ofr->priority),
                                          &fr->rule);
        fr->cookie = ofr->cookie;
        fr->reason = ofr->reason;
        fr->duration_sec = ntohl(ofr->duration_sec);
        fr->duration_nsec = ntohl(ofr->duration_nsec);
        fr->idle_timeout = ntohs(ofr->idle_timeout);
        fr->packet_count = ntohll(ofr->packet_count);
        fr->byte_count = ntohll(ofr->byte_count);
    } else if (code == OFPUTIL_NXT_FLOW_REMOVED) {
        struct nx_flow_removed *nfr;
        struct ofpbuf b;
        int error;

        ofpbuf_use_const(&b, oh, ntohs(oh->length));

        nfr = ofpbuf_pull(&b, sizeof *nfr);
        error = nx_pull_match(&b, ntohs(nfr->match_len), ntohs(nfr->priority),
                              &fr->rule, NULL, NULL);
        if (error) {
            return error;
        }
        if (b.size) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        fr->cookie = nfr->cookie;
        fr->reason = nfr->reason;
        fr->duration_sec = ntohl(nfr->duration_sec);
        fr->duration_nsec = ntohl(nfr->duration_nsec);
        fr->idle_timeout = ntohs(nfr->idle_timeout);
        fr->packet_count = ntohll(nfr->packet_count);
        fr->byte_count = ntohll(nfr->byte_count);
    } else {
        NOT_REACHED();
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
    case OFPUTIL_P_OF10:
    case OFPUTIL_P_OF10_TID: {
        struct ofp_flow_removed *ofr;

        ofr = make_openflow_xid(sizeof *ofr, OFPT_FLOW_REMOVED, htonl(0),
                                &msg);
        ofputil_cls_rule_to_ofp10_match(&fr->rule, &ofr->match);
        ofr->cookie = fr->cookie;
        ofr->priority = htons(fr->rule.priority);
        ofr->reason = fr->reason;
        ofr->duration_sec = htonl(fr->duration_sec);
        ofr->duration_nsec = htonl(fr->duration_nsec);
        ofr->idle_timeout = htons(fr->idle_timeout);
        ofr->packet_count = htonll(unknown_to_zero(fr->packet_count));
        ofr->byte_count = htonll(unknown_to_zero(fr->byte_count));
        break;
    }

    case OFPUTIL_P_NXM:
    case OFPUTIL_P_NXM_TID: {
        struct nx_flow_removed *nfr;
        int match_len;

        make_nxmsg_xid(sizeof *nfr, NXT_FLOW_REMOVED, htonl(0), &msg);
        match_len = nx_put_match(msg, false, &fr->rule, 0, 0);

        nfr = msg->data;
        nfr->cookie = fr->cookie;
        nfr->priority = htons(fr->rule.priority);
        nfr->reason = fr->reason;
        nfr->duration_sec = htonl(fr->duration_sec);
        nfr->duration_nsec = htonl(fr->duration_nsec);
        nfr->idle_timeout = htons(fr->idle_timeout);
        nfr->match_len = htons(match_len);
        nfr->packet_count = htonll(fr->packet_count);
        nfr->byte_count = htonll(fr->byte_count);
        break;
    }

    default:
        NOT_REACHED();
    }

    return msg;
}

enum ofperr
ofputil_decode_packet_in(struct ofputil_packet_in *pin,
                         const struct ofp_header *oh)
{
    const struct ofputil_msg_type *type;
    enum ofputil_msg_code code;

    ofputil_decode_msg_type(oh, &type);
    code = ofputil_msg_type_code(type);
    memset(pin, 0, sizeof *pin);

    if (code == OFPUTIL_OFPT_PACKET_IN) {
        const struct ofp_packet_in *opi = (const struct ofp_packet_in *) oh;

        pin->packet = opi->data;
        pin->packet_len = ntohs(opi->header.length)
            - offsetof(struct ofp_packet_in, data);

        pin->fmd.in_port = ntohs(opi->in_port);
        pin->reason = opi->reason;
        pin->buffer_id = ntohl(opi->buffer_id);
        pin->total_len = ntohs(opi->total_len);
    } else if (code == OFPUTIL_NXT_PACKET_IN) {
        const struct nx_packet_in *npi;
        struct cls_rule rule;
        struct ofpbuf b;
        int error;

        ofpbuf_use_const(&b, oh, ntohs(oh->length));

        npi = ofpbuf_pull(&b, sizeof *npi);
        error = nx_pull_match_loose(&b, ntohs(npi->match_len), 0, &rule, NULL,
                                    NULL);
        if (error) {
            return error;
        }

        if (!ofpbuf_try_pull(&b, 2)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        pin->packet = b.data;
        pin->packet_len = b.size;
        pin->reason = npi->reason;
        pin->table_id = npi->table_id;
        pin->cookie = npi->cookie;

        pin->fmd.in_port = rule.flow.in_port;

        pin->fmd.tun_id = rule.flow.tun_id;
        pin->fmd.tun_id_mask = rule.wc.tun_id_mask;

        pin->fmd.metadata = rule.flow.metadata;
        pin->fmd.metadata_mask = rule.wc.metadata_mask;

        memcpy(pin->fmd.regs, rule.flow.regs, sizeof pin->fmd.regs);
        memcpy(pin->fmd.reg_masks, rule.wc.reg_masks,
               sizeof pin->fmd.reg_masks);

        pin->buffer_id = ntohl(npi->buffer_id);
        pin->total_len = ntohs(npi->total_len);
    } else {
        NOT_REACHED();
    }

    return 0;
}

/* Converts abstract ofputil_packet_in 'pin' into a PACKET_IN message
 * in the format specified by 'packet_in_format'.  */
struct ofpbuf *
ofputil_encode_packet_in(const struct ofputil_packet_in *pin,
                         enum nx_packet_in_format packet_in_format)
{
    size_t send_len = MIN(pin->send_len, pin->packet_len);
    struct ofpbuf *packet;

    /* Add OFPT_PACKET_IN. */
    if (packet_in_format == NXPIF_OPENFLOW10) {
        size_t header_len = offsetof(struct ofp_packet_in, data);
        struct ofp_packet_in *opi;

        packet = ofpbuf_new(send_len + header_len);
        opi = ofpbuf_put_zeros(packet, header_len);
        opi->header.version = OFP10_VERSION;
        opi->header.type = OFPT_PACKET_IN;
        opi->total_len = htons(pin->total_len);
        opi->in_port = htons(pin->fmd.in_port);
        opi->reason = pin->reason;
        opi->buffer_id = htonl(pin->buffer_id);

        ofpbuf_put(packet, pin->packet, send_len);
    } else if (packet_in_format == NXPIF_NXM) {
        struct nx_packet_in *npi;
        struct cls_rule rule;
        size_t match_len;
        size_t i;

        /* Estimate of required PACKET_IN length includes the NPI header, space
         * for the match (2 times sizeof the metadata seems like enough), 2
         * bytes for padding, and the packet length. */
        packet = ofpbuf_new(sizeof *npi + sizeof(struct flow_metadata) * 2
                            + 2 + send_len);

        cls_rule_init_catchall(&rule, 0);
        cls_rule_set_tun_id_masked(&rule, pin->fmd.tun_id,
                                   pin->fmd.tun_id_mask);
        cls_rule_set_metadata_masked(&rule, pin->fmd.metadata,
                                   pin->fmd.metadata_mask);


        for (i = 0; i < FLOW_N_REGS; i++) {
            cls_rule_set_reg_masked(&rule, i, pin->fmd.regs[i],
                                    pin->fmd.reg_masks[i]);
        }

        cls_rule_set_in_port(&rule, pin->fmd.in_port);

        ofpbuf_put_zeros(packet, sizeof *npi);
        match_len = nx_put_match(packet, false, &rule, 0, 0);
        ofpbuf_put_zeros(packet, 2);
        ofpbuf_put(packet, pin->packet, send_len);

        npi = packet->data;
        npi->nxh.header.version = OFP10_VERSION;
        npi->nxh.header.type = OFPT_VENDOR;
        npi->nxh.vendor = htonl(NX_VENDOR_ID);
        npi->nxh.subtype = htonl(NXT_PACKET_IN);

        npi->buffer_id = htonl(pin->buffer_id);
        npi->total_len = htons(pin->total_len);
        npi->reason = pin->reason;
        npi->table_id = pin->table_id;
        npi->cookie = pin->cookie;
        npi->match_len = htons(match_len);
    } else {
        NOT_REACHED();
    }
    update_openflow_length(packet);

    return packet;
}

const char *
ofputil_packet_in_reason_to_string(enum ofp_packet_in_reason reason)
{
    static char s[INT_STRLEN(int) + 1];

    switch (reason) {
    case OFPR_NO_MATCH:
        return "no_match";
    case OFPR_ACTION:
        return "action";
    case OFPR_INVALID_TTL:
        return "invalid_ttl";

    case OFPR_N_REASONS:
    default:
        sprintf(s, "%d", (int) reason);
        return s;
    }
}

bool
ofputil_packet_in_reason_from_string(const char *s,
                                     enum ofp_packet_in_reason *reason)
{
    int i;

    for (i = 0; i < OFPR_N_REASONS; i++) {
        if (!strcasecmp(s, ofputil_packet_in_reason_to_string(i))) {
            *reason = i;
            return true;
        }
    }
    return false;
}

enum ofperr
ofputil_decode_packet_out(struct ofputil_packet_out *po,
                          const struct ofp_packet_out *opo)
{
    enum ofperr error;
    struct ofpbuf b;

    po->buffer_id = ntohl(opo->buffer_id);
    po->in_port = ntohs(opo->in_port);
    if (po->in_port >= OFPP_MAX && po->in_port != OFPP_LOCAL
        && po->in_port != OFPP_NONE && po->in_port != OFPP_CONTROLLER) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "packet-out has bad input port %#"PRIx16,
                     po->in_port);
        return OFPERR_NXBRC_BAD_IN_PORT;
    }

    ofpbuf_use_const(&b, opo, ntohs(opo->header.length));
    ofpbuf_pull(&b, sizeof *opo);

    error = ofputil_pull_actions(&b, ntohs(opo->actions_len),
                                 &po->actions, &po->n_actions);
    if (error) {
        return error;
    }

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

    pp->port_no = ntohs(opp->port_no);
    memcpy(pp->hw_addr, opp->hw_addr, OFP_ETH_ALEN);
    ovs_strlcpy(pp->name, opp->name, OFP_MAX_PORT_NAME_LEN);

    pp->config = ntohl(opp->config) & OFPPC10_ALL;
    pp->state = ntohl(opp->state) & OFPPS10_ALL;

    pp->curr = netdev_port_features_from_ofp10(opp->curr);
    pp->advertised = netdev_port_features_from_ofp10(opp->advertised);
    pp->supported = netdev_port_features_from_ofp10(opp->supported);
    pp->peer = netdev_port_features_from_ofp10(opp->peer);

    pp->curr_speed = netdev_features_to_bps(pp->curr) / 1000;
    pp->max_speed = netdev_features_to_bps(pp->supported) / 1000;

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
ofputil_get_phy_port_size(uint8_t ofp_version)
{
    return ofp_version == OFP10_VERSION ? sizeof(struct ofp10_phy_port)
                                        : sizeof(struct ofp11_port);
}

static void
ofputil_encode_ofp10_phy_port(const struct ofputil_phy_port *pp,
                              struct ofp10_phy_port *opp)
{
    memset(opp, 0, sizeof *opp);

    opp->port_no = htons(pp->port_no);
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
ofputil_put_phy_port(uint8_t ofp_version, const struct ofputil_phy_port *pp,
                     struct ofpbuf *b)
{
    if (ofp_version == OFP10_VERSION) {
        struct ofp10_phy_port *opp;
        if (b->size + sizeof *opp <= UINT16_MAX) {
            opp = ofpbuf_put_uninit(b, sizeof *opp);
            ofputil_encode_ofp10_phy_port(pp, opp);
        }
    } else {
        struct ofp11_port *op;
        if (b->size + sizeof *op <= UINT16_MAX) {
            op = ofpbuf_put_uninit(b, sizeof *op);
            ofputil_encode_ofp11_port(pp, op);
        }
    }
}

void
ofputil_append_port_desc_stats_reply(uint8_t ofp_version,
                                     const struct ofputil_phy_port *pp,
                                     struct list *replies)
{
    if (ofp_version == OFP10_VERSION) {
        struct ofp10_phy_port *opp;

        opp = ofputil_append_stats_reply(sizeof *opp, replies);
        ofputil_encode_ofp10_phy_port(pp, opp);
    } else {
        struct ofp11_port *op;

        op = ofputil_append_stats_reply(sizeof *op, replies);
        ofputil_encode_ofp11_port(pp, op);
    }
}

/* ofputil_switch_features */

#define OFPC_COMMON (OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS | \
                     OFPC_IP_REASM | OFPC_QUEUE_STATS | OFPC_ARP_MATCH_IP)
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

static const struct ofputil_action_bit_translation of11_action_bits[] = {
    { OFPUTIL_A_OUTPUT,         OFPAT11_OUTPUT },
    { OFPUTIL_A_SET_VLAN_VID,   OFPAT11_SET_VLAN_VID },
    { OFPUTIL_A_SET_VLAN_PCP,   OFPAT11_SET_VLAN_PCP },
    { OFPUTIL_A_SET_DL_SRC,     OFPAT11_SET_DL_SRC },
    { OFPUTIL_A_SET_DL_DST,     OFPAT11_SET_DL_DST },
    { OFPUTIL_A_SET_NW_SRC,     OFPAT11_SET_NW_SRC },
    { OFPUTIL_A_SET_NW_DST,     OFPAT11_SET_NW_DST },
    { OFPUTIL_A_SET_NW_TOS,     OFPAT11_SET_NW_TOS },
    { OFPUTIL_A_SET_NW_ECN,     OFPAT11_SET_NW_ECN },
    { OFPUTIL_A_SET_TP_SRC,     OFPAT11_SET_TP_SRC },
    { OFPUTIL_A_SET_TP_DST,     OFPAT11_SET_TP_DST },
    { OFPUTIL_A_COPY_TTL_OUT,   OFPAT11_COPY_TTL_OUT },
    { OFPUTIL_A_COPY_TTL_IN,    OFPAT11_COPY_TTL_IN },
    { OFPUTIL_A_SET_MPLS_LABEL, OFPAT11_SET_MPLS_LABEL },
    { OFPUTIL_A_SET_MPLS_TC,    OFPAT11_SET_MPLS_TC },
    { OFPUTIL_A_SET_MPLS_TTL,   OFPAT11_SET_MPLS_TTL },
    { OFPUTIL_A_DEC_MPLS_TTL,   OFPAT11_DEC_MPLS_TTL },
    { OFPUTIL_A_PUSH_VLAN,      OFPAT11_PUSH_VLAN },
    { OFPUTIL_A_POP_VLAN,       OFPAT11_POP_VLAN },
    { OFPUTIL_A_PUSH_MPLS,      OFPAT11_PUSH_MPLS },
    { OFPUTIL_A_POP_MPLS,       OFPAT11_POP_MPLS },
    { OFPUTIL_A_SET_QUEUE,      OFPAT11_SET_QUEUE },
    { OFPUTIL_A_GROUP,          OFPAT11_GROUP },
    { OFPUTIL_A_SET_NW_TTL,     OFPAT11_SET_NW_TTL },
    { OFPUTIL_A_DEC_NW_TTL,     OFPAT11_DEC_NW_TTL },
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

/* Decodes an OpenFlow 1.0 or 1.1 "switch_features" structure 'osf' into an
 * abstract representation in '*features'.  Initializes '*b' to iterate over
 * the OpenFlow port structures following 'osf' with later calls to
 * ofputil_pull_phy_port().  Returns 0 if successful, otherwise an
 * OFPERR_* value.  */
enum ofperr
ofputil_decode_switch_features(const struct ofp_switch_features *osf,
                               struct ofputil_switch_features *features,
                               struct ofpbuf *b)
{
    ofpbuf_use_const(b, osf, ntohs(osf->header.length));
    ofpbuf_pull(b, sizeof *osf);

    features->datapath_id = ntohll(osf->datapath_id);
    features->n_buffers = ntohl(osf->n_buffers);
    features->n_tables = osf->n_tables;

    features->capabilities = ntohl(osf->capabilities) & OFPC_COMMON;

    if (b->size % ofputil_get_phy_port_size(osf->header.version)) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    if (osf->header.version == OFP10_VERSION) {
        if (osf->capabilities & htonl(OFPC10_STP)) {
            features->capabilities |= OFPUTIL_C_STP;
        }
        features->actions = decode_action_bits(osf->actions, of10_action_bits);
    } else if (osf->header.version == OFP11_VERSION) {
        if (osf->capabilities & htonl(OFPC11_GROUP_STATS)) {
            features->capabilities |= OFPUTIL_C_GROUP_STATS;
        }
        features->actions = decode_action_bits(osf->actions, of11_action_bits);
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
    }

    return 0;
}

/* Returns true if the maximum number of ports are in 'osf'. */
static bool
max_ports_in_features(const struct ofp_switch_features *osf)
{
    size_t pp_size = ofputil_get_phy_port_size(osf->header.version);
    return ntohs(osf->header.length) + pp_size > UINT16_MAX;
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
    struct ofp_switch_features *osf = b->data;

    if (max_ports_in_features(osf)) {
        /* Remove all the ports. */
        b->size = sizeof(*osf);
        update_openflow_length(b);

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

    osf = make_openflow_xid(sizeof *osf, OFPT_FEATURES_REPLY, xid, &b);
    osf->header.version = ofputil_protocol_to_ofp_version(protocol);
    osf->datapath_id = htonll(features->datapath_id);
    osf->n_buffers = htonl(features->n_buffers);
    osf->n_tables = features->n_tables;

    osf->capabilities = htonl(features->capabilities & OFPC_COMMON);
    if (osf->header.version == OFP10_VERSION) {
        if (features->capabilities & OFPUTIL_C_STP) {
            osf->capabilities |= htonl(OFPC10_STP);
        }
        osf->actions = encode_action_bits(features->actions, of10_action_bits);
    } else {
        if (features->capabilities & OFPUTIL_C_GROUP_STATS) {
            osf->capabilities |= htonl(OFPC11_GROUP_STATS);
        }
        osf->actions = encode_action_bits(features->actions, of11_action_bits);
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
    const struct ofp_switch_features *osf = b->data;

    ofputil_put_phy_port(osf->header.version, pp, b);
}

/* ofputil_port_status */

/* Decodes the OpenFlow "port status" message in '*ops' into an abstract form
 * in '*ps'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_port_status(const struct ofp_port_status *ops,
                           struct ofputil_port_status *ps)
{
    struct ofpbuf b;
    int retval;

    if (ops->reason != OFPPR_ADD &&
        ops->reason != OFPPR_DELETE &&
        ops->reason != OFPPR_MODIFY) {
        return OFPERR_NXBRC_BAD_REASON;
    }
    ps->reason = ops->reason;

    ofpbuf_use_const(&b, ops, ntohs(ops->header.length));
    ofpbuf_pull(&b, sizeof *ops);
    retval = ofputil_pull_phy_port(ops->header.version, &b, &ps->desc);
    assert(retval != EOF);
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

    b = ofpbuf_new(sizeof *ops + sizeof(struct ofp11_port));
    ops = put_openflow_xid(sizeof *ops, OFPT_PORT_STATUS, htonl(0), b);
    ops->header.version = ofputil_protocol_to_ofp_version(protocol);
    ops->reason = ps->reason;
    ofputil_put_phy_port(ops->header.version, &ps->desc, b);
    update_openflow_length(b);
    return b;
}

/* ofputil_port_mod */

/* Decodes the OpenFlow "port mod" message in '*oh' into an abstract form in
 * '*pm'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_port_mod(const struct ofp_header *oh,
                        struct ofputil_port_mod *pm)
{
    if (oh->version == OFP10_VERSION) {
        const struct ofp10_port_mod *opm = (const struct ofp10_port_mod *) oh;

        if (oh->length != htons(sizeof *opm)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        pm->port_no = ntohs(opm->port_no);
        memcpy(pm->hw_addr, opm->hw_addr, ETH_ADDR_LEN);
        pm->config = ntohl(opm->config) & OFPPC10_ALL;
        pm->mask = ntohl(opm->mask) & OFPPC10_ALL;
        pm->advertise = netdev_port_features_from_ofp10(opm->advertise);
    } else if (oh->version == OFP11_VERSION) {
        const struct ofp11_port_mod *opm = (const struct ofp11_port_mod *) oh;
        enum ofperr error;

        if (oh->length != htons(sizeof *opm)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        error = ofputil_port_from_ofp11(opm->port_no, &pm->port_no);
        if (error) {
            return error;
        }

        memcpy(pm->hw_addr, opm->hw_addr, ETH_ADDR_LEN);
        pm->config = ntohl(opm->config) & OFPPC11_ALL;
        pm->mask = ntohl(opm->mask) & OFPPC11_ALL;
        pm->advertise = netdev_port_features_from_ofp11(opm->advertise);
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
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
    uint8_t ofp_version = ofputil_protocol_to_ofp_version(protocol);
    struct ofpbuf *b;

    if (ofp_version == OFP10_VERSION) {
        struct ofp10_port_mod *opm;

        opm = make_openflow(sizeof *opm, OFPT10_PORT_MOD, &b);
        opm->port_no = htons(pm->port_no);
        memcpy(opm->hw_addr, pm->hw_addr, ETH_ADDR_LEN);
        opm->config = htonl(pm->config & OFPPC10_ALL);
        opm->mask = htonl(pm->mask & OFPPC10_ALL);
        opm->advertise = netdev_port_features_to_ofp10(pm->advertise);
    } else if (ofp_version == OFP11_VERSION) {
        struct ofp11_port_mod *opm;

        opm = make_openflow(sizeof *opm, OFPT11_PORT_MOD, &b);
        opm->port_no = htonl(pm->port_no);
        memcpy(opm->hw_addr, pm->hw_addr, ETH_ADDR_LEN);
        opm->config = htonl(pm->config & OFPPC11_ALL);
        opm->mask = htonl(pm->mask & OFPPC11_ALL);
        opm->advertise = netdev_port_features_to_ofp11(pm->advertise);
    } else {
        NOT_REACHED();
    }

    return b;
}

struct ofpbuf *
ofputil_encode_packet_out(const struct ofputil_packet_out *po)
{
    struct ofp_packet_out *opo;
    size_t actions_len;
    struct ofpbuf *msg;
    size_t size;

    actions_len = po->n_actions * sizeof *po->actions;
    size = sizeof *opo + actions_len;
    if (po->buffer_id == UINT32_MAX) {
        size += po->packet_len;
    }

    msg = ofpbuf_new(size);
    opo = put_openflow(sizeof *opo, OFPT10_PACKET_OUT, msg);
    opo->buffer_id = htonl(po->buffer_id);
    opo->in_port = htons(po->in_port);
    opo->actions_len = htons(actions_len);
    ofpbuf_put(msg, po->actions, actions_len);
    if (po->buffer_id == UINT32_MAX) {
        ofpbuf_put(msg, po->packet, po->packet_len);
    }
    update_openflow_length(msg);

    return msg;
}

/* Returns a string representing the message type of 'type'.  The string is the
 * enumeration constant for the type, e.g. "OFPT_HELLO".  For statistics
 * messages, the constant is followed by "request" or "reply",
 * e.g. "OFPST_AGGREGATE reply". */
const char *
ofputil_msg_type_name(const struct ofputil_msg_type *type)
{
    return type->name;
}

/* Allocates and stores in '*bufferp' a new ofpbuf with a size of
 * 'openflow_len', starting with an OpenFlow header with the given 'type' and
 * an arbitrary transaction id.  Allocated bytes beyond the header, if any, are
 * zeroed.
 *
 * The caller is responsible for freeing '*bufferp' when it is no longer
 * needed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
make_openflow(size_t openflow_len, uint8_t type, struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_openflow_xid(openflow_len, type, alloc_xid(), *bufferp);
}

/* Similar to make_openflow() but creates a Nicira vendor extension message
 * with the specific 'subtype'.  'subtype' should be in host byte order. */
void *
make_nxmsg(size_t openflow_len, uint32_t subtype, struct ofpbuf **bufferp)
{
    return make_nxmsg_xid(openflow_len, subtype, alloc_xid(), bufferp);
}

/* Allocates and stores in '*bufferp' a new ofpbuf with a size of
 * 'openflow_len', starting with an OpenFlow header with the given 'type' and
 * transaction id 'xid'.  Allocated bytes beyond the header, if any, are
 * zeroed.
 *
 * The caller is responsible for freeing '*bufferp' when it is no longer
 * needed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
make_openflow_xid(size_t openflow_len, uint8_t type, ovs_be32 xid,
                  struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_openflow_xid(openflow_len, type, xid, *bufferp);
}

/* Similar to make_openflow_xid() but creates a Nicira vendor extension message
 * with the specific 'subtype'.  'subtype' should be in host byte order. */
void *
make_nxmsg_xid(size_t openflow_len, uint32_t subtype, ovs_be32 xid,
               struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_nxmsg_xid(openflow_len, subtype, xid, *bufferp);
}

/* Appends 'openflow_len' bytes to 'buffer', starting with an OpenFlow header
 * with the given 'type' and an arbitrary transaction id.  Allocated bytes
 * beyond the header, if any, are zeroed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
put_openflow(size_t openflow_len, uint8_t type, struct ofpbuf *buffer)
{
    return put_openflow_xid(openflow_len, type, alloc_xid(), buffer);
}

/* Appends 'openflow_len' bytes to 'buffer', starting with an OpenFlow header
 * with the given 'type' and an transaction id 'xid'.  Allocated bytes beyond
 * the header, if any, are zeroed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
put_openflow_xid(size_t openflow_len, uint8_t type, ovs_be32 xid,
                 struct ofpbuf *buffer)
{
    struct ofp_header *oh;

    assert(openflow_len >= sizeof *oh);
    assert(openflow_len <= UINT16_MAX);

    oh = ofpbuf_put_uninit(buffer, openflow_len);
    oh->version = OFP10_VERSION;
    oh->type = type;
    oh->length = htons(openflow_len);
    oh->xid = xid;
    memset(oh + 1, 0, openflow_len - sizeof *oh);
    return oh;
}

/* Similar to put_openflow() but append a Nicira vendor extension message with
 * the specific 'subtype'.  'subtype' should be in host byte order. */
void *
put_nxmsg(size_t openflow_len, uint32_t subtype, struct ofpbuf *buffer)
{
    return put_nxmsg_xid(openflow_len, subtype, alloc_xid(), buffer);
}

/* Similar to put_openflow_xid() but append a Nicira vendor extension message
 * with the specific 'subtype'.  'subtype' should be in host byte order. */
void *
put_nxmsg_xid(size_t openflow_len, uint32_t subtype, ovs_be32 xid,
              struct ofpbuf *buffer)
{
    struct nicira_header *nxh;

    nxh = put_openflow_xid(openflow_len, OFPT_VENDOR, xid, buffer);
    nxh->vendor = htonl(NX_VENDOR_ID);
    nxh->subtype = htonl(subtype);
    return nxh;
}

/* Updates the 'length' field of the OpenFlow message in 'buffer' to
 * 'buffer->size'. */
void
update_openflow_length(struct ofpbuf *buffer)
{
    struct ofp_header *oh = ofpbuf_at_assert(buffer, 0, sizeof *oh);
    oh->length = htons(buffer->size);
}

static void
put_stats__(ovs_be32 xid, uint8_t ofp_type,
            ovs_be16 ofpst_type, ovs_be32 nxst_subtype,
            struct ofpbuf *msg)
{
    if (ofpst_type == htons(OFPST_VENDOR)) {
        struct nicira_stats_msg *nsm;

        nsm = put_openflow_xid(sizeof *nsm, ofp_type, xid, msg);
        nsm->vsm.osm.type = ofpst_type;
        nsm->vsm.vendor = htonl(NX_VENDOR_ID);
        nsm->subtype = nxst_subtype;
    } else {
        struct ofp_stats_msg *osm;

        osm = put_openflow_xid(sizeof *osm, ofp_type, xid, msg);
        osm->type = ofpst_type;
    }
}

/* Creates a statistics request message with total length 'openflow_len'
 * (including all headers) and the given 'ofpst_type', and stores the buffer
 * containing the new message in '*bufferp'.  If 'ofpst_type' is OFPST_VENDOR
 * then 'nxst_subtype' is used as the Nicira vendor extension statistics
 * subtype (otherwise 'nxst_subtype' is ignored).
 *
 * Initializes bytes following the headers to all-bits-zero.
 *
 * Returns the first byte of the new message. */
void *
ofputil_make_stats_request(size_t openflow_len, uint16_t ofpst_type,
                           uint32_t nxst_subtype, struct ofpbuf **bufferp)
{
    struct ofpbuf *msg;

    msg = *bufferp = ofpbuf_new(openflow_len);
    put_stats__(alloc_xid(), OFPT10_STATS_REQUEST,
                htons(ofpst_type), htonl(nxst_subtype), msg);
    ofpbuf_padto(msg, openflow_len);

    return msg->data;
}

static void
put_stats_reply__(const struct ofp_stats_msg *request, struct ofpbuf *msg)
{
    assert(request->header.type == OFPT10_STATS_REQUEST ||
           request->header.type == OFPT10_STATS_REPLY);
    put_stats__(request->header.xid, OFPT10_STATS_REPLY, request->type,
                (request->type != htons(OFPST_VENDOR)
                 ? htonl(0)
                 : ((const struct nicira_stats_msg *) request)->subtype),
                msg);
}

/* Creates a statistics reply message with total length 'openflow_len'
 * (including all headers) and the same type (either a standard OpenFlow
 * statistics type or a Nicira extension type and subtype) as 'request', and
 * stores the buffer containing the new message in '*bufferp'.
 *
 * Initializes bytes following the headers to all-bits-zero.
 *
 * Returns the first byte of the new message. */
void *
ofputil_make_stats_reply(size_t openflow_len,
                         const struct ofp_stats_msg *request,
                         struct ofpbuf **bufferp)
{
    struct ofpbuf *msg;

    msg = *bufferp = ofpbuf_new(openflow_len);
    put_stats_reply__(request, msg);
    ofpbuf_padto(msg, openflow_len);

    return msg->data;
}

/* Initializes 'replies' as a list of ofpbufs that will contain a series of
 * replies to 'request', which should be an OpenFlow or Nicira extension
 * statistics request.  Initially 'replies' will have a single reply message
 * that has only a header.  The functions ofputil_reserve_stats_reply() and
 * ofputil_append_stats_reply() may be used to add to the reply. */
void
ofputil_start_stats_reply(const struct ofp_stats_msg *request,
                          struct list *replies)
{
    struct ofpbuf *msg;

    msg = ofpbuf_new(1024);
    put_stats_reply__(request, msg);

    list_init(replies);
    list_push_back(replies, &msg->list_node);
}

/* Prepares to append up to 'len' bytes to the series of statistics replies in
 * 'replies', which should have been initialized with
 * ofputil_start_stats_reply().  Returns an ofpbuf with at least 'len' bytes of
 * tailroom.  (The 'len' bytes have not actually be allocated; the caller must
 * do so with e.g. ofpbuf_put_uninit().) */
struct ofpbuf *
ofputil_reserve_stats_reply(size_t len, struct list *replies)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));
    struct ofp_stats_msg *osm = msg->data;

    if (msg->size + len <= UINT16_MAX) {
        ofpbuf_prealloc_tailroom(msg, len);
    } else {
        osm->flags |= htons(OFPSF_REPLY_MORE);

        msg = ofpbuf_new(MAX(1024, sizeof(struct nicira_stats_msg) + len));
        put_stats_reply__(osm, msg);
        list_push_back(replies, &msg->list_node);
    }
    return msg;
}

/* Appends 'len' bytes to the series of statistics replies in 'replies', and
 * returns the first byte. */
void *
ofputil_append_stats_reply(size_t len, struct list *replies)
{
    return ofpbuf_put_uninit(ofputil_reserve_stats_reply(len, replies), len);
}

/* Returns the first byte past the ofp_stats_msg header in 'oh'. */
const void *
ofputil_stats_body(const struct ofp_header *oh)
{
    assert(oh->type == OFPT10_STATS_REQUEST || oh->type == OFPT10_STATS_REPLY);
    return (const struct ofp_stats_msg *) oh + 1;
}

/* Returns the number of bytes past the ofp_stats_msg header in 'oh'. */
size_t
ofputil_stats_body_len(const struct ofp_header *oh)
{
    assert(oh->type == OFPT10_STATS_REQUEST || oh->type == OFPT10_STATS_REPLY);
    return ntohs(oh->length) - sizeof(struct ofp_stats_msg);
}

/* Returns the first byte past the nicira_stats_msg header in 'oh'. */
const void *
ofputil_nxstats_body(const struct ofp_header *oh)
{
    assert(oh->type == OFPT10_STATS_REQUEST || oh->type == OFPT10_STATS_REPLY);
    return ((const struct nicira_stats_msg *) oh) + 1;
}

/* Returns the number of bytes past the nicira_stats_msg header in 'oh'. */
size_t
ofputil_nxstats_body_len(const struct ofp_header *oh)
{
    assert(oh->type == OFPT10_STATS_REQUEST || oh->type == OFPT10_STATS_REPLY);
    return ntohs(oh->length) - sizeof(struct nicira_stats_msg);
}

struct ofpbuf *
make_flow_mod(uint16_t command, const struct cls_rule *rule,
              size_t actions_len)
{
    struct ofp_flow_mod *ofm;
    size_t size = sizeof *ofm + actions_len;
    struct ofpbuf *out = ofpbuf_new(size);
    ofm = ofpbuf_put_zeros(out, sizeof *ofm);
    ofm->header.version = OFP10_VERSION;
    ofm->header.type = OFPT10_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->cookie = 0;
    ofm->priority = htons(MIN(rule->priority, UINT16_MAX));
    ofputil_cls_rule_to_ofp10_match(rule, &ofm->match);
    ofm->command = htons(command);
    return out;
}

struct ofpbuf *
make_add_flow(const struct cls_rule *rule, uint32_t buffer_id,
              uint16_t idle_timeout, size_t actions_len)
{
    struct ofpbuf *out = make_flow_mod(OFPFC_ADD, rule, actions_len);
    struct ofp_flow_mod *ofm = out->data;
    ofm->idle_timeout = htons(idle_timeout);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->buffer_id = htonl(buffer_id);
    return out;
}

struct ofpbuf *
make_packet_in(uint32_t buffer_id, uint16_t in_port, uint8_t reason,
               const struct ofpbuf *payload, int max_send_len)
{
    struct ofp_packet_in *opi;
    struct ofpbuf *buf;
    int send_len;

    send_len = MIN(max_send_len, payload->size);
    buf = ofpbuf_new(sizeof *opi + send_len);
    opi = put_openflow_xid(offsetof(struct ofp_packet_in, data),
                           OFPT_PACKET_IN, 0, buf);
    opi->buffer_id = htonl(buffer_id);
    opi->total_len = htons(payload->size);
    opi->in_port = htons(in_port);
    opi->reason = reason;
    ofpbuf_put(buf, payload->data, send_len);
    update_openflow_length(buf);

    return buf;
}

/* Creates and returns an OFPT_ECHO_REQUEST message with an empty payload. */
struct ofpbuf *
make_echo_request(void)
{
    struct ofp_header *rq;
    struct ofpbuf *out = ofpbuf_new(sizeof *rq);
    rq = ofpbuf_put_uninit(out, sizeof *rq);
    rq->version = OFP10_VERSION;
    rq->type = OFPT_ECHO_REQUEST;
    rq->length = htons(sizeof *rq);
    rq->xid = htonl(0);
    return out;
}

/* Creates and returns an OFPT_ECHO_REPLY message matching the
 * OFPT_ECHO_REQUEST message in 'rq'. */
struct ofpbuf *
make_echo_reply(const struct ofp_header *rq)
{
    size_t size = ntohs(rq->length);
    struct ofpbuf *out = ofpbuf_new(size);
    struct ofp_header *reply = ofpbuf_put(out, rq, size);
    reply->type = OFPT_ECHO_REPLY;
    return out;
}

struct ofpbuf *
ofputil_encode_barrier_request(void)
{
    struct ofpbuf *msg;

    make_openflow(sizeof(struct ofp_header), OFPT10_BARRIER_REQUEST, &msg);
    return msg;
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

    NOT_REACHED();
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
 * otherwise an OFPERR_* number.
 *
 * See the definition of OFP11_MAX for an explanation of the mapping. */
enum ofperr
ofputil_port_from_ofp11(ovs_be32 ofp11_port, uint16_t *ofp10_port)
{
    uint32_t ofp11_port_h = ntohl(ofp11_port);

    if (ofp11_port_h < OFPP_MAX) {
        *ofp10_port = ofp11_port_h;
        return 0;
    } else if (ofp11_port_h >= OFPP11_MAX) {
        *ofp10_port = ofp11_port_h - OFPP11_OFFSET;
        return 0;
    } else {
        VLOG_WARN_RL(&bad_ofmsg_rl, "port %"PRIu32" is outside the supported "
                     "range 0 through %d or 0x%"PRIx32" through 0x%"PRIx32,
                     ofp11_port_h, OFPP_MAX - 1,
                     (uint32_t) OFPP11_MAX, UINT32_MAX);
        return OFPERR_OFPBAC_BAD_OUT_PORT;
    }
}

/* Returns the OpenFlow 1.1+ port number equivalent to the OpenFlow 1.0 port
 * number 'ofp10_port', for encoding OpenFlow 1.1+ protocol messages.
 *
 * See the definition of OFP11_MAX for an explanation of the mapping. */
ovs_be32
ofputil_port_to_ofp11(uint16_t ofp10_port)
{
    return htonl(ofp10_port < OFPP_MAX
                 ? ofp10_port
                 : ofp10_port + OFPP11_OFFSET);
}

/* Checks that 'port' is a valid output port for the OFPAT10_OUTPUT action, given
 * that the switch will never have more than 'max_ports' ports.  Returns 0 if
 * 'port' is valid, otherwise an OpenFlow return code. */
enum ofperr
ofputil_check_output_port(uint16_t port, int max_ports)
{
    switch (port) {
    case OFPP_IN_PORT:
    case OFPP_TABLE:
    case OFPP_NORMAL:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_CONTROLLER:
    case OFPP_NONE:
    case OFPP_LOCAL:
        return 0;

    default:
        if (port < max_ports) {
            return 0;
        }
        return OFPERR_OFPBAC_BAD_OUT_PORT;
    }
}

#define OFPUTIL_NAMED_PORTS                     \
        OFPUTIL_NAMED_PORT(IN_PORT)             \
        OFPUTIL_NAMED_PORT(TABLE)               \
        OFPUTIL_NAMED_PORT(NORMAL)              \
        OFPUTIL_NAMED_PORT(FLOOD)               \
        OFPUTIL_NAMED_PORT(ALL)                 \
        OFPUTIL_NAMED_PORT(CONTROLLER)          \
        OFPUTIL_NAMED_PORT(LOCAL)               \
        OFPUTIL_NAMED_PORT(NONE)

/* Checks whether 's' is the string representation of an OpenFlow port number,
 * either as an integer or a string name (e.g. "LOCAL").  If it is, stores the
 * number in '*port' and returns true.  Otherwise, returns false. */
bool
ofputil_port_from_string(const char *name, uint16_t *port)
{
    struct pair {
        const char *name;
        uint16_t value;
    };
    static const struct pair pairs[] = {
#define OFPUTIL_NAMED_PORT(NAME) {#NAME, OFPP_##NAME},
        OFPUTIL_NAMED_PORTS
#undef OFPUTIL_NAMED_PORT
    };
    static const int n_pairs = ARRAY_SIZE(pairs);
    int i;

    if (str_to_int(name, 0, &i) && i >= 0 && i < UINT16_MAX) {
        *port = i;
        return true;
    }

    for (i = 0; i < n_pairs; i++) {
        if (!strcasecmp(name, pairs[i].name)) {
            *port = pairs[i].value;
            return true;
        }
    }
    return false;
}

/* Appends to 's' a string representation of the OpenFlow port number 'port'.
 * Most ports' string representation is just the port number, but for special
 * ports, e.g. OFPP_LOCAL, it is the name, e.g. "LOCAL". */
void
ofputil_format_port(uint16_t port, struct ds *s)
{
    const char *name;

    switch (port) {
#define OFPUTIL_NAMED_PORT(NAME) case OFPP_##NAME: name = #NAME; break;
        OFPUTIL_NAMED_PORTS
#undef OFPUTIL_NAMED_PORT

    default:
        ds_put_format(s, "%"PRIu16, port);
        return;
    }
    ds_put_cstr(s, name);
}

/* Given a buffer 'b' that contains an array of OpenFlow ports of type
 * 'ofp_version', tries to pull the first element from the array.  If
 * successful, initializes '*pp' with an abstract representation of the
 * port and returns 0.  If no ports remain to be decoded, returns EOF.
 * On an error, returns a positive OFPERR_* value. */
int
ofputil_pull_phy_port(uint8_t ofp_version, struct ofpbuf *b,
                      struct ofputil_phy_port *pp)
{
    if (ofp_version == OFP10_VERSION) {
        const struct ofp10_phy_port *opp = ofpbuf_try_pull(b, sizeof *opp);
        return opp ? ofputil_decode_ofp10_phy_port(pp, opp) : EOF;
    } else {
        const struct ofp11_port *op = ofpbuf_try_pull(b, sizeof *op);
        return op ? ofputil_decode_ofp11_port(pp, op) : EOF;
    }
}

/* Given a buffer 'b' that contains an array of OpenFlow ports of type
 * 'ofp_version', returns the number of elements. */
size_t ofputil_count_phy_ports(uint8_t ofp_version, struct ofpbuf *b)
{
    return b->size / ofputil_get_phy_port_size(ofp_version);
}

static enum ofperr
check_resubmit_table(const struct nx_action_resubmit *nar)
{
    if (nar->pad[0] || nar->pad[1] || nar->pad[2]) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    return 0;
}

static enum ofperr
check_output_reg(const struct nx_action_output_reg *naor,
                 const struct flow *flow)
{
    struct mf_subfield src;
    size_t i;

    for (i = 0; i < sizeof naor->zero; i++) {
        if (naor->zero[i]) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
    }

    nxm_decode(&src, naor->src, naor->ofs_nbits);
    return mf_check_src(&src, flow);
}

enum ofperr
validate_actions(const union ofp_action *actions, size_t n_actions,
                 const struct flow *flow, int max_ports)
{
    const union ofp_action *a;
    size_t left;

    OFPUTIL_ACTION_FOR_EACH (a, left, actions, n_actions) {
        enum ofperr error;
        uint16_t port;
        int code;

        code = ofputil_decode_action(a);
        if (code < 0) {
            error = -code;
            VLOG_WARN_RL(&bad_ofmsg_rl,
                         "action decoding error at offset %td (%s)",
                         (a - actions) * sizeof *a, ofperr_get_name(error));

            return error;
        }

        error = 0;
        switch ((enum ofputil_action_code) code) {
        case OFPUTIL_OFPAT10_OUTPUT:
            error = ofputil_check_output_port(ntohs(a->output.port),
                                              max_ports);
            break;

        case OFPUTIL_OFPAT10_SET_VLAN_VID:
            if (a->vlan_vid.vlan_vid & ~htons(0xfff)) {
                error = OFPERR_OFPBAC_BAD_ARGUMENT;
            }
            break;

        case OFPUTIL_OFPAT10_SET_VLAN_PCP:
            if (a->vlan_pcp.vlan_pcp & ~7) {
                error = OFPERR_OFPBAC_BAD_ARGUMENT;
            }
            break;

        case OFPUTIL_OFPAT10_ENQUEUE:
            port = ntohs(((const struct ofp_action_enqueue *) a)->port);
            if (port >= max_ports && port != OFPP_IN_PORT
                && port != OFPP_LOCAL) {
                error = OFPERR_OFPBAC_BAD_OUT_PORT;
            }
            break;

        case OFPUTIL_NXAST_REG_MOVE:
            error = nxm_check_reg_move((const struct nx_action_reg_move *) a,
                                       flow);
            break;

        case OFPUTIL_NXAST_REG_LOAD:
            error = nxm_check_reg_load((const struct nx_action_reg_load *) a,
                                       flow);
            break;

        case OFPUTIL_NXAST_MULTIPATH:
            error = multipath_check((const struct nx_action_multipath *) a,
                                    flow);
            break;

        case OFPUTIL_NXAST_AUTOPATH:
            error = autopath_check((const struct nx_action_autopath *) a,
                                   flow);
            break;

        case OFPUTIL_NXAST_BUNDLE:
        case OFPUTIL_NXAST_BUNDLE_LOAD:
            error = bundle_check((const struct nx_action_bundle *) a,
                                 max_ports, flow);
            break;

        case OFPUTIL_NXAST_OUTPUT_REG:
            error = check_output_reg((const struct nx_action_output_reg *) a,
                                     flow);
            break;

        case OFPUTIL_NXAST_RESUBMIT_TABLE:
            error = check_resubmit_table(
                (const struct nx_action_resubmit *) a);
            break;

        case OFPUTIL_NXAST_LEARN:
            error = learn_check((const struct nx_action_learn *) a, flow);
            break;

        case OFPUTIL_NXAST_CONTROLLER:
            if (((const struct nx_action_controller *) a)->zero) {
                error = OFPERR_NXBAC_MUST_BE_ZERO;
            }
            break;

        case OFPUTIL_OFPAT10_STRIP_VLAN:
        case OFPUTIL_OFPAT10_SET_NW_SRC:
        case OFPUTIL_OFPAT10_SET_NW_DST:
        case OFPUTIL_OFPAT10_SET_NW_TOS:
        case OFPUTIL_OFPAT10_SET_TP_SRC:
        case OFPUTIL_OFPAT10_SET_TP_DST:
        case OFPUTIL_OFPAT10_SET_DL_SRC:
        case OFPUTIL_OFPAT10_SET_DL_DST:
        case OFPUTIL_NXAST_RESUBMIT:
        case OFPUTIL_NXAST_SET_TUNNEL:
        case OFPUTIL_NXAST_SET_QUEUE:
        case OFPUTIL_NXAST_POP_QUEUE:
        case OFPUTIL_NXAST_NOTE:
        case OFPUTIL_NXAST_SET_TUNNEL64:
        case OFPUTIL_NXAST_EXIT:
        case OFPUTIL_NXAST_DEC_TTL:
        case OFPUTIL_NXAST_FIN_TIMEOUT:
            break;
        }

        if (error) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "bad action at offset %td (%s)",
                         (a - actions) * sizeof *a, ofperr_get_name(error));
            return error;
        }
    }
    if (left) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "bad action format at offset %zu",
                     (n_actions - left) * sizeof *a);
        return OFPERR_OFPBAC_BAD_LEN;
    }
    return 0;
}

struct ofputil_action {
    int code;
    unsigned int min_len;
    unsigned int max_len;
};

static const struct ofputil_action action_bad_type
    = { -OFPERR_OFPBAC_BAD_TYPE,   0, UINT_MAX };
static const struct ofputil_action action_bad_len
    = { -OFPERR_OFPBAC_BAD_LEN,    0, UINT_MAX };
static const struct ofputil_action action_bad_vendor
    = { -OFPERR_OFPBAC_BAD_VENDOR, 0, UINT_MAX };

static const struct ofputil_action *
ofputil_decode_ofpat_action(const union ofp_action *a)
{
    enum ofp10_action_type type = ntohs(a->type);

    switch (type) {
#define OFPAT10_ACTION(ENUM, STRUCT, NAME)                    \
        case ENUM: {                                        \
            static const struct ofputil_action action = {   \
                OFPUTIL_##ENUM,                             \
                sizeof(struct STRUCT),                      \
                sizeof(struct STRUCT)                       \
            };                                              \
            return &action;                                 \
        }
#include "ofp-util.def"

    case OFPAT10_VENDOR:
    default:
        return &action_bad_type;
    }
}

static const struct ofputil_action *
ofputil_decode_nxast_action(const union ofp_action *a)
{
    const struct nx_action_header *nah = (const struct nx_action_header *) a;
    enum nx_action_subtype subtype = ntohs(nah->subtype);

    switch (subtype) {
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)            \
        case ENUM: {                                            \
            static const struct ofputil_action action = {       \
                OFPUTIL_##ENUM,                                 \
                sizeof(struct STRUCT),                          \
                EXTENSIBLE ? UINT_MAX : sizeof(struct STRUCT)   \
            };                                                  \
            return &action;                                     \
        }
#include "ofp-util.def"

    case NXAST_SNAT__OBSOLETE:
    case NXAST_DROP_SPOOFED_ARP__OBSOLETE:
    default:
        return &action_bad_type;
    }
}

/* Parses 'a' to determine its type.  Returns a nonnegative OFPUTIL_OFPAT10_* or
 * OFPUTIL_NXAST_* constant if successful, otherwise a negative OFPERR_* error
 * code.
 *
 * The caller must have already verified that 'a''s length is correct (that is,
 * a->header.len is nonzero and a multiple of sizeof(union ofp_action) and no
 * longer than the amount of space allocated to 'a').
 *
 * This function verifies that 'a''s length is correct for the type of action
 * that it represents. */
int
ofputil_decode_action(const union ofp_action *a)
{
    const struct ofputil_action *action;
    uint16_t len = ntohs(a->header.len);

    if (a->type != htons(OFPAT10_VENDOR)) {
        action = ofputil_decode_ofpat_action(a);
    } else {
        switch (ntohl(a->vendor.vendor)) {
        case NX_VENDOR_ID:
            if (len < sizeof(struct nx_action_header)) {
                return -OFPERR_OFPBAC_BAD_LEN;
            }
            action = ofputil_decode_nxast_action(a);
            break;
        default:
            action = &action_bad_vendor;
            break;
        }
    }

    return (len >= action->min_len && len <= action->max_len
            ? action->code
            : -OFPERR_OFPBAC_BAD_LEN);
}

/* Parses 'a' and returns its type as an OFPUTIL_OFPAT10_* or OFPUTIL_NXAST_*
 * constant.  The caller must have already validated that 'a' is a valid action
 * understood by Open vSwitch (e.g. by a previous successful call to
 * ofputil_decode_action()). */
enum ofputil_action_code
ofputil_decode_action_unsafe(const union ofp_action *a)
{
    const struct ofputil_action *action;

    if (a->type != htons(OFPAT10_VENDOR)) {
        action = ofputil_decode_ofpat_action(a);
    } else {
        action = ofputil_decode_nxast_action(a);
    }

    return action->code;
}

/* Returns the 'enum ofputil_action_code' corresponding to 'name' (e.g. if
 * 'name' is "output" then the return value is OFPUTIL_OFPAT10_OUTPUT), or -1 if
 * 'name' is not the name of any action.
 *
 * ofp-util.def lists the mapping from names to action. */
int
ofputil_action_code_from_name(const char *name)
{
    static const char *names[OFPUTIL_N_ACTIONS] = {
#define OFPAT10_ACTION(ENUM, STRUCT, NAME)             NAME,
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) NAME,
#include "ofp-util.def"
    };

    const char **p;

    for (p = names; p < &names[ARRAY_SIZE(names)]; p++) {
        if (*p && !strcasecmp(name, *p)) {
            return p - names;
        }
    }
    return -1;
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
#define OFPAT10_ACTION(ENUM, STRUCT, NAME)                    \
    case OFPUTIL_##ENUM: return ofputil_put_##ENUM(buf);
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)        \
    case OFPUTIL_##ENUM: return ofputil_put_##ENUM(buf);
#include "ofp-util.def"
    }
    NOT_REACHED();
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

/* Returns true if 'action' outputs to 'port', false otherwise. */
bool
action_outputs_to_port(const union ofp_action *action, ovs_be16 port)
{
    switch (ofputil_decode_action(action)) {
    case OFPUTIL_OFPAT10_OUTPUT:
        return action->output.port == port;
    case OFPUTIL_OFPAT10_ENQUEUE:
        return ((const struct ofp_action_enqueue *) action)->port == port;
    case OFPUTIL_NXAST_CONTROLLER:
        return port == htons(OFPP_CONTROLLER);
    default:
        return false;
    }
}

/* "Normalizes" the wildcards in 'rule'.  That means:
 *
 *    1. If the type of level N is known, then only the valid fields for that
 *       level may be specified.  For example, ARP does not have a TOS field,
 *       so nw_tos must be wildcarded if 'rule' specifies an ARP flow.
 *       Similarly, IPv4 does not have any IPv6 addresses, so ipv6_src and
 *       ipv6_dst (and other fields) must be wildcarded if 'rule' specifies an
 *       IPv4 flow.
 *
 *    2. If the type of level N is not known (or not understood by Open
 *       vSwitch), then no fields at all for that level may be specified.  For
 *       example, Open vSwitch does not understand SCTP, an L4 protocol, so the
 *       L4 fields tp_src and tp_dst must be wildcarded if 'rule' specifies an
 *       SCTP flow.
 */
void
ofputil_normalize_rule(struct cls_rule *rule)
{
    enum {
        MAY_NW_ADDR     = 1 << 0, /* nw_src, nw_dst */
        MAY_TP_ADDR     = 1 << 1, /* tp_src, tp_dst */
        MAY_NW_PROTO    = 1 << 2, /* nw_proto */
        MAY_IPVx        = 1 << 3, /* tos, frag, ttl */
        MAY_ARP_SHA     = 1 << 4, /* arp_sha */
        MAY_ARP_THA     = 1 << 5, /* arp_tha */
        MAY_IPV6        = 1 << 6, /* ipv6_src, ipv6_dst, ipv6_label */
        MAY_ND_TARGET   = 1 << 7  /* nd_target */
    } may_match;

    struct flow_wildcards wc;

    /* Figure out what fields may be matched. */
    if (rule->flow.dl_type == htons(ETH_TYPE_IP)) {
        may_match = MAY_NW_PROTO | MAY_IPVx | MAY_NW_ADDR;
        if (rule->flow.nw_proto == IPPROTO_TCP ||
            rule->flow.nw_proto == IPPROTO_UDP ||
            rule->flow.nw_proto == IPPROTO_ICMP) {
            may_match |= MAY_TP_ADDR;
        }
    } else if (rule->flow.dl_type == htons(ETH_TYPE_IPV6)) {
        may_match = MAY_NW_PROTO | MAY_IPVx | MAY_IPV6;
        if (rule->flow.nw_proto == IPPROTO_TCP ||
            rule->flow.nw_proto == IPPROTO_UDP) {
            may_match |= MAY_TP_ADDR;
        } else if (rule->flow.nw_proto == IPPROTO_ICMPV6) {
            may_match |= MAY_TP_ADDR;
            if (rule->flow.tp_src == htons(ND_NEIGHBOR_SOLICIT)) {
                may_match |= MAY_ND_TARGET | MAY_ARP_SHA;
            } else if (rule->flow.tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                may_match |= MAY_ND_TARGET | MAY_ARP_THA;
            }
        }
    } else if (rule->flow.dl_type == htons(ETH_TYPE_ARP)) {
        may_match = MAY_NW_PROTO | MAY_NW_ADDR | MAY_ARP_SHA | MAY_ARP_THA;
    } else {
        may_match = 0;
    }

    /* Clear the fields that may not be matched. */
    wc = rule->wc;
    if (!(may_match & MAY_NW_ADDR)) {
        wc.nw_src_mask = wc.nw_dst_mask = htonl(0);
    }
    if (!(may_match & MAY_TP_ADDR)) {
        wc.tp_src_mask = wc.tp_dst_mask = htons(0);
    }
    if (!(may_match & MAY_NW_PROTO)) {
        wc.wildcards |= FWW_NW_PROTO;
    }
    if (!(may_match & MAY_IPVx)) {
        wc.wildcards |= FWW_NW_DSCP;
        wc.wildcards |= FWW_NW_ECN;
        wc.wildcards |= FWW_NW_TTL;
    }
    if (!(may_match & MAY_ARP_SHA)) {
        wc.wildcards |= FWW_ARP_SHA;
    }
    if (!(may_match & MAY_ARP_THA)) {
        wc.wildcards |= FWW_ARP_THA;
    }
    if (!(may_match & MAY_IPV6)) {
        wc.ipv6_src_mask = wc.ipv6_dst_mask = in6addr_any;
        wc.wildcards |= FWW_IPV6_LABEL;
    }
    if (!(may_match & MAY_ND_TARGET)) {
        wc.nd_target_mask = in6addr_any;
    }

    /* Log any changes. */
    if (!flow_wildcards_equal(&wc, &rule->wc)) {
        bool log = !VLOG_DROP_INFO(&bad_ofmsg_rl);
        char *pre = log ? cls_rule_to_string(rule) : NULL;

        rule->wc = wc;
        cls_rule_zero_wildcarded_fields(rule);

        if (log) {
            char *post = cls_rule_to_string(rule);
            VLOG_INFO("normalization changed ofp_match, details:");
            VLOG_INFO(" pre: %s", pre);
            VLOG_INFO("post: %s", post);
            free(pre);
            free(post);
        }
    }
}

/* Attempts to pull 'actions_len' bytes from the front of 'b'.  Returns 0 if
 * successful, otherwise an OpenFlow error.
 *
 * If successful, the first action is stored in '*actionsp' and the number of
 * "union ofp_action" size elements into '*n_actionsp'.  Otherwise NULL and 0
 * are stored, respectively.
 *
 * This function does not check that the actions are valid (the caller should
 * do so, with validate_actions()).  The caller is also responsible for making
 * sure that 'b->data' is initially aligned appropriately for "union
 * ofp_action". */
enum ofperr
ofputil_pull_actions(struct ofpbuf *b, unsigned int actions_len,
                     union ofp_action **actionsp, size_t *n_actionsp)
{
    if (actions_len % OFP_ACTION_ALIGN != 0) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message actions length %u "
                     "is not a multiple of %d", actions_len, OFP_ACTION_ALIGN);
        goto error;
    }

    *actionsp = ofpbuf_try_pull(b, actions_len);
    if (*actionsp == NULL) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "OpenFlow message actions length %u "
                     "exceeds remaining message length (%zu)",
                     actions_len, b->size);
        goto error;
    }

    *n_actionsp = actions_len / OFP_ACTION_ALIGN;
    return 0;

error:
    *actionsp = NULL;
    *n_actionsp = 0;
    return OFPERR_OFPBRC_BAD_LEN;
}

bool
ofputil_actions_equal(const union ofp_action *a, size_t n_a,
                      const union ofp_action *b, size_t n_b)
{
    return n_a == n_b && (!n_a || !memcmp(a, b, n_a * sizeof *a));
}

union ofp_action *
ofputil_actions_clone(const union ofp_action *actions, size_t n)
{
    return n ? xmemdup(actions, n * sizeof *actions) : NULL;
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
