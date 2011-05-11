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
#include "ofp-print.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include "autopath.h"
#include "byte-order.h"
#include "classifier.h"
#include "dynamic-string.h"
#include "multipath.h"
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
 * that it wildcards.  'netmask' must be a CIDR netmask (see ip_is_cidr()). */
int
ofputil_netmask_to_wcbits(ovs_be32 netmask)
{
    assert(ip_is_cidr(netmask));
#if __GNUC__ >= 4
    return netmask == htonl(0) ? 32 : __builtin_ctz(ntohl(netmask));
#else
    int wcbits;

    for (wcbits = 32; netmask; wcbits--) {
        netmask &= netmask - 1;
    }

    return wcbits;
#endif
}

/* A list of the FWW_* and OFPFW_ bits that have the same value, meaning, and
 * name. */
#define WC_INVARIANT_LIST \
    WC_INVARIANT_BIT(IN_PORT) \
    WC_INVARIANT_BIT(DL_SRC) \
    WC_INVARIANT_BIT(DL_DST) \
    WC_INVARIANT_BIT(DL_TYPE) \
    WC_INVARIANT_BIT(NW_PROTO) \
    WC_INVARIANT_BIT(TP_SRC) \
    WC_INVARIANT_BIT(TP_DST)

/* Verify that all of the invariant bits (as defined on WC_INVARIANT_LIST)
 * actually have the same names and values. */
#define WC_INVARIANT_BIT(NAME) BUILD_ASSERT_DECL(FWW_##NAME == OFPFW_##NAME);
    WC_INVARIANT_LIST
#undef WC_INVARIANT_BIT

/* WC_INVARIANTS is the invariant bits (as defined on WC_INVARIANT_LIST) all
 * OR'd together. */
enum {
    WC_INVARIANTS = 0
#define WC_INVARIANT_BIT(NAME) | FWW_##NAME
    WC_INVARIANT_LIST
#undef WC_INVARIANT_BIT
};

/* Converts the ofp_match in 'match' into a cls_rule in 'rule', with the given
 * 'priority'.
 *
 * 'flow_format' must either NXFF_OPENFLOW10 or NXFF_TUN_ID_FROM_COOKIE.  In
 * the latter case only, 'flow''s tun_id field will be taken from the high bits
 * of 'cookie', if 'match''s wildcards do not indicate that tun_id is
 * wildcarded. */
void
ofputil_cls_rule_from_match(const struct ofp_match *match,
                            unsigned int priority,
                            enum nx_flow_format flow_format,
                            ovs_be64 cookie, struct cls_rule *rule)
{
    struct flow_wildcards *wc = &rule->wc;
    unsigned int ofpfw;
    ovs_be16 vid, pcp;

    /* Initialize rule->priority. */
    ofpfw = ntohl(match->wildcards);
    ofpfw &= flow_format == NXFF_TUN_ID_FROM_COOKIE ? OVSFW_ALL : OFPFW_ALL;
    rule->priority = !ofpfw ? UINT16_MAX : priority;

    /* Initialize most of rule->wc. */
    flow_wildcards_init_catchall(wc);
    wc->wildcards = ofpfw & WC_INVARIANTS;

    /* Wildcard fields that aren't defined by ofp_match or tun_id. */
    wc->wildcards |= (FWW_ARP_SHA | FWW_ARP_THA | FWW_ND_TARGET);

    if (ofpfw & OFPFW_NW_TOS) {
        wc->wildcards |= FWW_NW_TOS;
    }
    wc->nw_src_mask = ofputil_wcbits_to_netmask(ofpfw >> OFPFW_NW_SRC_SHIFT);
    wc->nw_dst_mask = ofputil_wcbits_to_netmask(ofpfw >> OFPFW_NW_DST_SHIFT);

    if (flow_format == NXFF_TUN_ID_FROM_COOKIE && !(ofpfw & NXFW_TUN_ID)) {
        cls_rule_set_tun_id(rule, htonll(ntohll(cookie) >> 32));
    }

    if (ofpfw & OFPFW_DL_DST) {
        /* OpenFlow 1.0 OFPFW_DL_DST covers the whole Ethernet destination, but
         * Open vSwitch breaks the Ethernet destination into bits as FWW_DL_DST
         * and FWW_ETH_MCAST. */
        wc->wildcards |= FWW_ETH_MCAST;
    }

    /* Initialize most of rule->flow. */
    rule->flow.nw_src = match->nw_src;
    rule->flow.nw_dst = match->nw_dst;
    rule->flow.in_port = ntohs(match->in_port);
    rule->flow.dl_type = ofputil_dl_type_from_openflow(match->dl_type);
    rule->flow.tp_src = match->tp_src;
    rule->flow.tp_dst = match->tp_dst;
    memcpy(rule->flow.dl_src, match->dl_src, ETH_ADDR_LEN);
    memcpy(rule->flow.dl_dst, match->dl_dst, ETH_ADDR_LEN);
    rule->flow.nw_tos = match->nw_tos;
    rule->flow.nw_proto = match->nw_proto;

    /* Translate VLANs. */
    vid = match->dl_vlan & htons(VLAN_VID_MASK);
    pcp = htons((match->dl_vlan_pcp << VLAN_PCP_SHIFT) & VLAN_PCP_MASK);
    switch (ofpfw & (OFPFW_DL_VLAN | OFPFW_DL_VLAN_PCP)) {
    case OFPFW_DL_VLAN | OFPFW_DL_VLAN_PCP:
        /* Wildcard everything. */
        rule->flow.vlan_tci = htons(0);
        rule->wc.vlan_tci_mask = htons(0);
        break;

    case OFPFW_DL_VLAN_PCP:
        if (match->dl_vlan == htons(OFP_VLAN_NONE)) {
            /* Match only packets without 802.1Q header. */
            rule->flow.vlan_tci = htons(0);
            rule->wc.vlan_tci_mask = htons(0xffff);
        } else {
            /* Wildcard PCP, specific VID. */
            rule->flow.vlan_tci = vid | htons(VLAN_CFI);
            rule->wc.vlan_tci_mask = htons(VLAN_VID_MASK | VLAN_CFI);
        }
        break;

    case OFPFW_DL_VLAN:
        /* Wildcard VID, specific PCP. */
        rule->flow.vlan_tci = pcp | htons(VLAN_CFI);
        rule->wc.vlan_tci_mask = htons(VLAN_PCP_MASK | VLAN_CFI);
        break;

    case 0:
        if (match->dl_vlan == htons(OFP_VLAN_NONE)) {
            /* This case is odd, since we can't have a specific PCP without an
             * 802.1Q header.  However, older versions of OVS treated this as
             * matching packets withut an 802.1Q header, so we do here too. */
            rule->flow.vlan_tci = htons(0);
            rule->wc.vlan_tci_mask = htons(0xffff);
        } else {
            /* Specific VID and PCP. */
            rule->flow.vlan_tci = vid | pcp | htons(VLAN_CFI);
            rule->wc.vlan_tci_mask = htons(0xffff);
        }
        break;
    }

    /* Clean up. */
    cls_rule_zero_wildcarded_fields(rule);
}

/* Convert 'rule' into the OpenFlow match structure 'match'.  'flow_format'
 * must either NXFF_OPENFLOW10 or NXFF_TUN_ID_FROM_COOKIE.
 *
 * The NXFF_TUN_ID_FROM_COOKIE flow format requires modifying the flow cookie.
 * This function can help with that, if 'cookie_out' is nonnull.  For
 * NXFF_OPENFLOW10, or if the tunnel ID is wildcarded, 'cookie_in' will be
 * copied directly to '*cookie_out'.  For NXFF_TUN_ID_FROM_COOKIE when tunnel
 * ID is matched, 'cookie_in' will be modified appropriately before setting
 * '*cookie_out'.
 */
void
ofputil_cls_rule_to_match(const struct cls_rule *rule,
                          enum nx_flow_format flow_format,
                          struct ofp_match *match,
                          ovs_be64 cookie_in, ovs_be64 *cookie_out)
{
    const struct flow_wildcards *wc = &rule->wc;
    unsigned int ofpfw;

    /* Figure out most OpenFlow wildcards. */
    ofpfw = wc->wildcards & WC_INVARIANTS;
    ofpfw |= ofputil_netmask_to_wcbits(wc->nw_src_mask) << OFPFW_NW_SRC_SHIFT;
    ofpfw |= ofputil_netmask_to_wcbits(wc->nw_dst_mask) << OFPFW_NW_DST_SHIFT;
    if (wc->wildcards & FWW_NW_TOS) {
        ofpfw |= OFPFW_NW_TOS;
    }

    /* Tunnel ID. */
    if (flow_format == NXFF_TUN_ID_FROM_COOKIE) {
        if (wc->tun_id_mask == htonll(0)) {
            ofpfw |= NXFW_TUN_ID;
        } else {
            uint32_t cookie_lo = ntohll(cookie_in);
            uint32_t cookie_hi = ntohll(rule->flow.tun_id);
            cookie_in = htonll(cookie_lo | ((uint64_t) cookie_hi << 32));
        }
    }
    if (cookie_out) {
        *cookie_out = cookie_in;
    }

    /* Translate VLANs. */
    match->dl_vlan = htons(0);
    match->dl_vlan_pcp = 0;
    if (rule->wc.vlan_tci_mask == htons(0)) {
        ofpfw |= OFPFW_DL_VLAN | OFPFW_DL_VLAN_PCP;
    } else if (rule->wc.vlan_tci_mask & htons(VLAN_CFI)
               && !(rule->flow.vlan_tci & htons(VLAN_CFI))) {
        match->dl_vlan = htons(OFP_VLAN_NONE);
    } else {
        if (!(rule->wc.vlan_tci_mask & htons(VLAN_VID_MASK))) {
            ofpfw |= OFPFW_DL_VLAN;
        } else {
            match->dl_vlan = htons(vlan_tci_to_vid(rule->flow.vlan_tci));
        }

        if (!(rule->wc.vlan_tci_mask & htons(VLAN_PCP_MASK))) {
            ofpfw |= OFPFW_DL_VLAN_PCP;
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
    match->nw_tos = rule->flow.nw_tos;
    match->nw_proto = rule->flow.nw_proto;
    match->tp_src = rule->flow.tp_src;
    match->tp_dst = rule->flow.tp_dst;
    memset(match->pad1, '\0', sizeof match->pad1);
    memset(match->pad2, '\0', sizeof match->pad2);
}

/* Given a 'dl_type' value in the format used in struct flow, returns the
 * corresponding 'dl_type' value for use in an OpenFlow ofp_match structure. */
ovs_be16
ofputil_dl_type_to_openflow(ovs_be16 flow_dl_type)
{
    return (flow_dl_type == htons(FLOW_DL_TYPE_NONE)
            ? htons(OFP_DL_TYPE_NOT_ETH_TYPE)
            : flow_dl_type);
}

/* Given a 'dl_type' value in the format used in an OpenFlow ofp_match
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
    uint32_t value;             /* OFPT_*, OFPST_*, NXT_*, or NXST_*. */
    const char *name;           /* e.g. "OFPT_FLOW_REMOVED". */
    unsigned int min_size;      /* Minimum total message size in bytes. */
    /* 0 if 'min_size' is the exact size that the message must be.  Otherwise,
     * the message may exceed 'min_size' by an even multiple of this value. */
    unsigned int extra_multiple;
};

struct ofputil_msg_category {
    const char *name;           /* e.g. "OpenFlow message" */
    const struct ofputil_msg_type *types;
    size_t n_types;
    int missing_error;          /* ofp_mkerr() value for missing type. */
};

static bool
ofputil_length_ok(const struct ofputil_msg_category *cat,
                  const struct ofputil_msg_type *type,
                  unsigned int size)
{
    switch (type->extra_multiple) {
    case 0:
        if (size != type->min_size) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "received %s %s with incorrect "
                         "length %u (expected length %u)",
                         cat->name, type->name, size, type->min_size);
            return false;
        }
        return true;

    case 1:
        if (size < type->min_size) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "received %s %s with incorrect "
                         "length %u (expected length at least %u bytes)",
                         cat->name, type->name, size, type->min_size);
            return false;
        }
        return true;

    default:
        if (size < type->min_size
            || (size - type->min_size) % type->extra_multiple) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "received %s %s with incorrect "
                         "length %u (must be exactly %u bytes or longer "
                         "by an integer multiple of %u bytes)",
                         cat->name, type->name, size,
                         type->min_size, type->extra_multiple);
            return false;
        }
        return true;
    }
}

static int
ofputil_lookup_openflow_message(const struct ofputil_msg_category *cat,
                                uint32_t value, unsigned int size,
                                const struct ofputil_msg_type **typep)
{
    const struct ofputil_msg_type *type;

    for (type = cat->types; type < &cat->types[cat->n_types]; type++) {
        if (type->value == value) {
            if (!ofputil_length_ok(cat, type, size)) {
                return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }
            *typep = type;
            return 0;
        }
    }

    VLOG_WARN_RL(&bad_ofmsg_rl, "received %s of unknown type %"PRIu32,
                 cat->name, value);
    return cat->missing_error;
}

static int
ofputil_decode_vendor(const struct ofp_header *oh,
                      const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type nxt_messages[] = {
        { OFPUTIL_NXT_TUN_ID_FROM_COOKIE,
          NXT_TUN_ID_FROM_COOKIE, "NXT_TUN_ID_FROM_COOKIE",
          sizeof(struct nxt_tun_id_cookie), 0 },

        { OFPUTIL_NXT_ROLE_REQUEST,
          NXT_ROLE_REQUEST, "NXT_ROLE_REQUEST",
          sizeof(struct nx_role_request), 0 },

        { OFPUTIL_NXT_ROLE_REPLY,
          NXT_ROLE_REPLY, "NXT_ROLE_REPLY",
          sizeof(struct nx_role_request), 0 },

        { OFPUTIL_NXT_SET_FLOW_FORMAT,
          NXT_SET_FLOW_FORMAT, "NXT_SET_FLOW_FORMAT",
          sizeof(struct nxt_set_flow_format), 0 },

        { OFPUTIL_NXT_FLOW_MOD,
          NXT_FLOW_MOD, "NXT_FLOW_MOD",
          sizeof(struct nx_flow_mod), 8 },

        { OFPUTIL_NXT_FLOW_REMOVED,
          NXT_FLOW_REMOVED, "NXT_FLOW_REMOVED",
          sizeof(struct nx_flow_removed), 8 },
    };

    static const struct ofputil_msg_category nxt_category = {
        "Nicira extension message",
        nxt_messages, ARRAY_SIZE(nxt_messages),
        OFP_MKERR(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE)
    };

    const struct ofp_vendor_header *ovh;
    const struct nicira_header *nh;

    ovh = (const struct ofp_vendor_header *) oh;
    if (ovh->vendor != htonl(NX_VENDOR_ID)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "received vendor message for unknown "
                     "vendor %"PRIx32, ntohl(ovh->vendor));
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_VENDOR);
    }

    if (ntohs(ovh->header.length) < sizeof(struct nicira_header)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "received Nicira vendor message of "
                     "length %u (expected at least %zu)",
                     ntohs(ovh->header.length), sizeof(struct nicira_header));
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    nh = (const struct nicira_header *) oh;
    return ofputil_lookup_openflow_message(&nxt_category, ntohl(nh->subtype),
                                           ntohs(oh->length), typep);
}

static int
check_nxstats_msg(const struct ofp_header *oh)
{
    const struct ofp_stats_request *osr;
    ovs_be32 vendor;

    osr = (const struct ofp_stats_request *) oh;

    memcpy(&vendor, osr->body, sizeof vendor);
    if (vendor != htonl(NX_VENDOR_ID)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "received vendor stats message for "
                     "unknown vendor %"PRIx32, ntohl(vendor));
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_VENDOR);
    }

    if (ntohs(osr->header.length) < sizeof(struct nicira_stats_msg)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "truncated Nicira stats message");
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    return 0;
}

static int
ofputil_decode_nxst_request(const struct ofp_header *oh,
                            const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type nxst_requests[] = {
        { OFPUTIL_NXST_FLOW_REQUEST,
          NXST_FLOW, "NXST_FLOW request",
          sizeof(struct nx_flow_stats_request), 8 },

        { OFPUTIL_NXST_AGGREGATE_REQUEST,
          NXST_AGGREGATE, "NXST_AGGREGATE request",
          sizeof(struct nx_aggregate_stats_request), 8 },
    };

    static const struct ofputil_msg_category nxst_request_category = {
        "Nicira extension statistics request",
        nxst_requests, ARRAY_SIZE(nxst_requests),
        OFP_MKERR(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE)
    };

    const struct nicira_stats_msg *nsm;
    int error;

    error = check_nxstats_msg(oh);
    if (error) {
        return error;
    }

    nsm = (struct nicira_stats_msg *) oh;
    return ofputil_lookup_openflow_message(&nxst_request_category,
                                           ntohl(nsm->subtype),
                                           ntohs(oh->length), typep);
}

static int
ofputil_decode_nxst_reply(const struct ofp_header *oh,
                          const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type nxst_replies[] = {
        { OFPUTIL_NXST_FLOW_REPLY,
          NXST_FLOW, "NXST_FLOW reply",
          sizeof(struct nicira_stats_msg), 8 },

        { OFPUTIL_NXST_AGGREGATE_REPLY,
          NXST_AGGREGATE, "NXST_AGGREGATE reply",
          sizeof(struct nx_aggregate_stats_reply), 0 },
    };

    static const struct ofputil_msg_category nxst_reply_category = {
        "Nicira extension statistics reply",
        nxst_replies, ARRAY_SIZE(nxst_replies),
        OFP_MKERR(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE)
    };

    const struct nicira_stats_msg *nsm;
    int error;

    error = check_nxstats_msg(oh);
    if (error) {
        return error;
    }

    nsm = (struct nicira_stats_msg *) oh;
    return ofputil_lookup_openflow_message(&nxst_reply_category,
                                           ntohl(nsm->subtype),
                                           ntohs(oh->length), typep);
}

static int
ofputil_decode_ofpst_request(const struct ofp_header *oh,
                             const struct ofputil_msg_type **typep)
{
    enum { OSR_SIZE = sizeof(struct ofp_stats_request) };
    static const struct ofputil_msg_type ofpst_requests[] = {
        { OFPUTIL_OFPST_DESC_REQUEST,
          OFPST_DESC, "OFPST_DESC request",
          OSR_SIZE, 0 },

        { OFPUTIL_OFPST_FLOW_REQUEST,
          OFPST_FLOW, "OFPST_FLOW request",
          OSR_SIZE + sizeof(struct ofp_flow_stats_request), 0 },

        { OFPUTIL_OFPST_AGGREGATE_REQUEST,
          OFPST_AGGREGATE, "OFPST_AGGREGATE request",
          OSR_SIZE + sizeof(struct ofp_aggregate_stats_request), 0 },

        { OFPUTIL_OFPST_TABLE_REQUEST,
          OFPST_TABLE, "OFPST_TABLE request",
          OSR_SIZE, 0 },

        { OFPUTIL_OFPST_PORT_REQUEST,
          OFPST_PORT, "OFPST_PORT request",
          OSR_SIZE + sizeof(struct ofp_port_stats_request), 0 },

        { OFPUTIL_OFPST_QUEUE_REQUEST,
          OFPST_QUEUE, "OFPST_QUEUE request",
          OSR_SIZE + sizeof(struct ofp_queue_stats_request), 0 },

        { 0,
          OFPST_VENDOR, "OFPST_VENDOR request",
          OSR_SIZE + sizeof(uint32_t), 1 },
    };

    static const struct ofputil_msg_category ofpst_request_category = {
        "OpenFlow statistics",
        ofpst_requests, ARRAY_SIZE(ofpst_requests),
        OFP_MKERR(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT)
    };

    const struct ofp_stats_request *osr;
    int error;

    osr = (const struct ofp_stats_request *) oh;
    error = ofputil_lookup_openflow_message(&ofpst_request_category,
                                            ntohs(osr->type),
                                            ntohs(oh->length), typep);
    if (!error && osr->type == htons(OFPST_VENDOR)) {
        error = ofputil_decode_nxst_request(oh, typep);
    }
    return error;
}

static int
ofputil_decode_ofpst_reply(const struct ofp_header *oh,
                           const struct ofputil_msg_type **typep)
{
    enum { OSR_SIZE = sizeof(struct ofp_stats_reply) };
    static const struct ofputil_msg_type ofpst_replies[] = {
        { OFPUTIL_OFPST_DESC_REPLY,
          OFPST_DESC, "OFPST_DESC reply",
          OSR_SIZE + sizeof(struct ofp_desc_stats), 0 },

        { OFPUTIL_OFPST_FLOW_REPLY,
          OFPST_FLOW, "OFPST_FLOW reply",
          OSR_SIZE, 1 },

        { OFPUTIL_OFPST_AGGREGATE_REPLY,
          OFPST_AGGREGATE, "OFPST_AGGREGATE reply",
          OSR_SIZE + sizeof(struct ofp_aggregate_stats_reply), 0 },

        { OFPUTIL_OFPST_TABLE_REPLY,
          OFPST_TABLE, "OFPST_TABLE reply",
          OSR_SIZE, sizeof(struct ofp_table_stats) },

        { OFPUTIL_OFPST_PORT_REPLY,
          OFPST_PORT, "OFPST_PORT reply",
          OSR_SIZE, sizeof(struct ofp_port_stats) },

        { OFPUTIL_OFPST_QUEUE_REPLY,
          OFPST_QUEUE, "OFPST_QUEUE reply",
          OSR_SIZE, sizeof(struct ofp_queue_stats) },

        { 0,
          OFPST_VENDOR, "OFPST_VENDOR reply",
          OSR_SIZE + sizeof(uint32_t), 1 },
    };

    static const struct ofputil_msg_category ofpst_reply_category = {
        "OpenFlow statistics",
        ofpst_replies, ARRAY_SIZE(ofpst_replies),
        OFP_MKERR(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT)
    };

    const struct ofp_stats_reply *osr = (const struct ofp_stats_reply *) oh;
    int error;

    error = ofputil_lookup_openflow_message(&ofpst_reply_category,
                                           ntohs(osr->type),
                                           ntohs(oh->length), typep);
    if (!error && osr->type == htons(OFPST_VENDOR)) {
        error = ofputil_decode_nxst_reply(oh, typep);
    }
    return error;
}

/* Decodes the message type represented by 'oh'.  Returns 0 if successful or
 * an OpenFlow error code constructed with ofp_mkerr() on failure.  Either
 * way, stores in '*typep' a type structure that can be inspected with the
 * ofputil_msg_type_*() functions.
 *
 * oh->length must indicate the correct length of the message (and must be at
 * least sizeof(struct ofp_header)).
 *
 * Success indicates that 'oh' is at least as long as the minimum-length
 * message of its type. */
int
ofputil_decode_msg_type(const struct ofp_header *oh,
                        const struct ofputil_msg_type **typep)
{
    static const struct ofputil_msg_type ofpt_messages[] = {
        { OFPUTIL_OFPT_HELLO,
          OFPT_HELLO, "OFPT_HELLO",
          sizeof(struct ofp_hello), 1 },

        { OFPUTIL_OFPT_ERROR,
          OFPT_ERROR, "OFPT_ERROR",
          sizeof(struct ofp_error_msg), 1 },

        { OFPUTIL_OFPT_ECHO_REQUEST,
          OFPT_ECHO_REQUEST, "OFPT_ECHO_REQUEST",
          sizeof(struct ofp_header), 1 },

        { OFPUTIL_OFPT_ECHO_REPLY,
          OFPT_ECHO_REPLY, "OFPT_ECHO_REPLY",
          sizeof(struct ofp_header), 1 },

        { OFPUTIL_OFPT_FEATURES_REQUEST,
          OFPT_FEATURES_REQUEST, "OFPT_FEATURES_REQUEST",
          sizeof(struct ofp_header), 0 },

        { OFPUTIL_OFPT_FEATURES_REPLY,
          OFPT_FEATURES_REPLY, "OFPT_FEATURES_REPLY",
          sizeof(struct ofp_switch_features), sizeof(struct ofp_phy_port) },

        { OFPUTIL_OFPT_GET_CONFIG_REQUEST,
          OFPT_GET_CONFIG_REQUEST, "OFPT_GET_CONFIG_REQUEST",
          sizeof(struct ofp_header), 0 },

        { OFPUTIL_OFPT_GET_CONFIG_REPLY,
          OFPT_GET_CONFIG_REPLY, "OFPT_GET_CONFIG_REPLY",
          sizeof(struct ofp_switch_config), 0 },

        { OFPUTIL_OFPT_SET_CONFIG,
          OFPT_SET_CONFIG, "OFPT_SET_CONFIG",
          sizeof(struct ofp_switch_config), 0 },

        { OFPUTIL_OFPT_PACKET_IN,
          OFPT_PACKET_IN, "OFPT_PACKET_IN",
          offsetof(struct ofp_packet_in, data), 1 },

        { OFPUTIL_OFPT_FLOW_REMOVED,
          OFPT_FLOW_REMOVED, "OFPT_FLOW_REMOVED",
          sizeof(struct ofp_flow_removed), 0 },

        { OFPUTIL_OFPT_PORT_STATUS,
          OFPT_PORT_STATUS, "OFPT_PORT_STATUS",
          sizeof(struct ofp_port_status), 0 },

        { OFPUTIL_OFPT_PACKET_OUT,
          OFPT_PACKET_OUT, "OFPT_PACKET_OUT",
          sizeof(struct ofp_packet_out), 1 },

        { OFPUTIL_OFPT_FLOW_MOD,
          OFPT_FLOW_MOD, "OFPT_FLOW_MOD",
          sizeof(struct ofp_flow_mod), 1 },

        { OFPUTIL_OFPT_PORT_MOD,
          OFPT_PORT_MOD, "OFPT_PORT_MOD",
          sizeof(struct ofp_port_mod), 0 },

        { 0,
          OFPT_STATS_REQUEST, "OFPT_STATS_REQUEST",
          sizeof(struct ofp_stats_request), 1 },

        { 0,
          OFPT_STATS_REPLY, "OFPT_STATS_REPLY",
          sizeof(struct ofp_stats_reply), 1 },

        { OFPUTIL_OFPT_BARRIER_REQUEST,
          OFPT_BARRIER_REQUEST, "OFPT_BARRIER_REQUEST",
          sizeof(struct ofp_header), 0 },

        { OFPUTIL_OFPT_BARRIER_REPLY,
          OFPT_BARRIER_REPLY, "OFPT_BARRIER_REPLY",
          sizeof(struct ofp_header), 0 },

        { 0,
          OFPT_VENDOR, "OFPT_VENDOR",
          sizeof(struct ofp_vendor_header), 1 },
    };

    static const struct ofputil_msg_category ofpt_category = {
        "OpenFlow message",
        ofpt_messages, ARRAY_SIZE(ofpt_messages),
        OFP_MKERR(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE)
    };

    int error;

    error = ofputil_lookup_openflow_message(&ofpt_category, oh->type,
                                            ntohs(oh->length), typep);
    if (!error) {
        switch (oh->type) {
        case OFPT_VENDOR:
            error = ofputil_decode_vendor(oh, typep);
            break;

        case OFPT_STATS_REQUEST:
            error = ofputil_decode_ofpst_request(oh, typep);
            break;

        case OFPT_STATS_REPLY:
            error = ofputil_decode_ofpst_reply(oh, typep);

        default:
            break;
        }
    }
    if (error) {
        static const struct ofputil_msg_type ofputil_invalid_type = {
            OFPUTIL_INVALID,
            0, "OFPUTIL_INVALID",
            0, 0
        };

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

/* Flow formats. */

bool
ofputil_flow_format_is_valid(enum nx_flow_format flow_format)
{
    switch (flow_format) {
    case NXFF_OPENFLOW10:
    case NXFF_TUN_ID_FROM_COOKIE:
    case NXFF_NXM:
        return true;
    }

    return false;
}

const char *
ofputil_flow_format_to_string(enum nx_flow_format flow_format)
{
    switch (flow_format) {
    case NXFF_OPENFLOW10:
        return "openflow10";
    case NXFF_TUN_ID_FROM_COOKIE:
        return "tun_id_from_cookie";
    case NXFF_NXM:
        return "nxm";
    default:
        NOT_REACHED();
    }
}

int
ofputil_flow_format_from_string(const char *s)
{
    return (!strcmp(s, "openflow10") ? NXFF_OPENFLOW10
            : !strcmp(s, "tun_id_from_cookie") ? NXFF_TUN_ID_FROM_COOKIE
            : !strcmp(s, "nxm") ? NXFF_NXM
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

static inline bool
is_nxm_required(const struct cls_rule *rule, bool cookie_support,
                ovs_be64 cookie)
{
    const struct flow_wildcards *wc = &rule->wc;
    uint32_t cookie_hi;
    uint64_t tun_id;

    /* Only NXM supports separately wildcards the Ethernet multicast bit. */
    if (!(wc->wildcards & FWW_DL_DST) != !(wc->wildcards & FWW_ETH_MCAST)) {
        return true;
    }

    /* Only NXM supports matching ARP hardware addresses. */
    if (!(wc->wildcards & FWW_ARP_SHA) || !(wc->wildcards & FWW_ARP_THA)) {
        return true;
    }

    /* Only NXM supports matching IPv6 traffic. */
    if (!(wc->wildcards & FWW_DL_TYPE)
            && (rule->flow.dl_type == htons(ETH_TYPE_IPV6))) {
        return true;
    }

    /* Only NXM supports matching registers. */
    if (!regs_fully_wildcarded(wc)) {
        return true;
    }

    switch (wc->tun_id_mask) {
    case CONSTANT_HTONLL(0):
        /* Other formats can fully wildcard tun_id. */
        break;

    case CONSTANT_HTONLL(UINT64_MAX):
        /* Only NXM supports tunnel ID matching without a cookie. */
        if (!cookie_support) {
            return true;
        }

        /* Only NXM supports 64-bit tunnel IDs. */
        tun_id = ntohll(rule->flow.tun_id);
        if (tun_id > UINT32_MAX) {
            return true;
        }

        /* Only NXM supports a cookie whose top 32 bits conflict with the
         * tunnel ID. */
        cookie_hi = ntohll(cookie) >> 32;
        if (cookie_hi && cookie_hi != tun_id) {
            return true;
        }
        break;

    default:
        /* Only NXM supports partial matches on tunnel ID. */
        return true;
    }

    /* Other formats can express this rule. */
    return false;
}

/* Returns the minimum nx_flow_format to use for sending 'rule' to a switch
 * (e.g. to add or remove a flow).  'cookie_support' should be true if the
 * command to be sent includes a flow cookie (as OFPT_FLOW_MOD does, for
 * example) or false if the command does not (OFPST_FLOW and OFPST_AGGREGATE do
 * not, for example).  If 'cookie_support' is true, then 'cookie' should be the
 * cookie to be sent; otherwise its value is ignored.
 *
 * The "best" flow format is chosen on this basis:
 *
 *   - It must be capable of expressing the rule.  NXFF_OPENFLOW10 flows can't
 *     handle tunnel IDs.  NXFF_TUN_ID_FROM_COOKIE flows can't handle registers
 *     or fixing the Ethernet multicast bit, and can't handle tunnel IDs that
 *     conflict with the high 32 bits of the cookie or commands that don't
 *     support cookies.
 *
 *   - Otherwise, the chosen format should be as backward compatible as
 *     possible.  (NXFF_OPENFLOW10 is more backward compatible than
 *     NXFF_TUN_ID_FROM_COOKIE, which is more backward compatible than
 *     NXFF_NXM.)
 */
enum nx_flow_format
ofputil_min_flow_format(const struct cls_rule *rule, bool cookie_support,
                        ovs_be64 cookie)
{
    if (is_nxm_required(rule, cookie_support, cookie)) {
        return NXFF_NXM;
    } else if (rule->wc.tun_id_mask != htonll(0)) {
        return NXFF_TUN_ID_FROM_COOKIE;
    } else {
        return NXFF_OPENFLOW10;
    }
}

/* Returns an OpenFlow message that can be used to set the flow format to
 * 'flow_format'.  */
struct ofpbuf *
ofputil_make_set_flow_format(enum nx_flow_format flow_format)
{
    struct ofpbuf *msg;

    if (flow_format == NXFF_OPENFLOW10
        || flow_format == NXFF_TUN_ID_FROM_COOKIE) {
        struct nxt_tun_id_cookie *tic;

        tic = make_nxmsg(sizeof *tic, NXT_TUN_ID_FROM_COOKIE, &msg);
        tic->set = flow_format == NXFF_TUN_ID_FROM_COOKIE;
    } else {
        struct nxt_set_flow_format *sff;

        sff = make_nxmsg(sizeof *sff, NXT_SET_FLOW_FORMAT, &msg);
        sff->format = htonl(flow_format);
    }

    return msg;
}

/* Converts an OFPT_FLOW_MOD or NXT_FLOW_MOD message 'oh' into an abstract
 * flow_mod in 'fm'.  Returns 0 if successful, otherwise an OpenFlow error
 * code.
 *
 * For OFPT_FLOW_MOD messages, 'flow_format' should be the current flow format
 * at the time when the message was received.  Otherwise 'flow_format' is
 * ignored.
 *
 * Does not validate the flow_mod actions. */
int
ofputil_decode_flow_mod(struct flow_mod *fm, const struct ofp_header *oh,
                        enum nx_flow_format flow_format)
{
    const struct ofputil_msg_type *type;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    ofputil_decode_msg_type(oh, &type);
    if (ofputil_msg_type_code(type) == OFPUTIL_OFPT_FLOW_MOD) {
        /* Standard OpenFlow flow_mod. */
        struct ofp_match match, orig_match;
        const struct ofp_flow_mod *ofm;
        int error;

        /* Dissect the message. */
        ofm = ofpbuf_pull(&b, sizeof *ofm);
        error = ofputil_pull_actions(&b, b.size, &fm->actions, &fm->n_actions);
        if (error) {
            return error;
        }

        /* Normalize ofm->match.  If normalization actually changes anything,
         * then log the differences. */
        match = ofm->match;
        match.pad1[0] = match.pad2[0] = 0;
        orig_match = match;
        normalize_match(&match);
        if (memcmp(&match, &orig_match, sizeof orig_match)) {
            if (!VLOG_DROP_INFO(&bad_ofmsg_rl)) {
                char *old = ofp_match_to_literal_string(&orig_match);
                char *new = ofp_match_to_literal_string(&match);
                VLOG_INFO("normalization changed ofp_match, details:");
                VLOG_INFO(" pre: %s", old);
                VLOG_INFO("post: %s", new);
                free(old);
                free(new);
            }
        }

        /* Translate the message. */
        ofputil_cls_rule_from_match(&match, ntohs(ofm->priority), flow_format,
                                    ofm->cookie, &fm->cr);
        fm->cookie = ofm->cookie;
        fm->command = ntohs(ofm->command);
        fm->idle_timeout = ntohs(ofm->idle_timeout);
        fm->hard_timeout = ntohs(ofm->hard_timeout);
        fm->buffer_id = ntohl(ofm->buffer_id);
        fm->out_port = ntohs(ofm->out_port);
        fm->flags = ntohs(ofm->flags);
    } else if (ofputil_msg_type_code(type) == OFPUTIL_NXT_FLOW_MOD) {
        /* Nicira extended flow_mod. */
        const struct nx_flow_mod *nfm;
        int error;

        /* Dissect the message. */
        nfm = ofpbuf_pull(&b, sizeof *nfm);
        error = nx_pull_match(&b, ntohs(nfm->match_len), ntohs(nfm->priority),
                              &fm->cr);
        if (error) {
            return error;
        }
        error = ofputil_pull_actions(&b, b.size, &fm->actions, &fm->n_actions);
        if (error) {
            return error;
        }

        /* Translate the message. */
        fm->cookie = nfm->cookie;
        fm->command = ntohs(nfm->command);
        fm->idle_timeout = ntohs(nfm->idle_timeout);
        fm->hard_timeout = ntohs(nfm->hard_timeout);
        fm->buffer_id = ntohl(nfm->buffer_id);
        fm->out_port = ntohs(nfm->out_port);
        fm->flags = ntohs(nfm->flags);
    } else {
        NOT_REACHED();
    }

    return 0;
}

/* Converts 'fm' into an OFPT_FLOW_MOD or NXT_FLOW_MOD message according to
 * 'flow_format' and returns the message. */
struct ofpbuf *
ofputil_encode_flow_mod(const struct flow_mod *fm,
                        enum nx_flow_format flow_format)
{
    size_t actions_len = fm->n_actions * sizeof *fm->actions;
    struct ofpbuf *msg;

    if (flow_format == NXFF_OPENFLOW10
        || flow_format == NXFF_TUN_ID_FROM_COOKIE) {
        struct ofp_flow_mod *ofm;

        msg = ofpbuf_new(sizeof *ofm + actions_len);
        ofm = put_openflow(sizeof *ofm, OFPT_FLOW_MOD, msg);
        ofputil_cls_rule_to_match(&fm->cr, flow_format, &ofm->match,
                                  fm->cookie, &ofm->cookie);
        ofm->command = htons(fm->command);
        ofm->idle_timeout = htons(fm->idle_timeout);
        ofm->hard_timeout = htons(fm->hard_timeout);
        ofm->priority = htons(fm->cr.priority);
        ofm->buffer_id = htonl(fm->buffer_id);
        ofm->out_port = htons(fm->out_port);
        ofm->flags = htons(fm->flags);
    } else if (flow_format == NXFF_NXM) {
        struct nx_flow_mod *nfm;
        int match_len;

        msg = ofpbuf_new(sizeof *nfm + NXM_TYPICAL_LEN + actions_len);
        put_nxmsg(sizeof *nfm, NXT_FLOW_MOD, msg);
        match_len = nx_put_match(msg, &fm->cr);

        nfm = msg->data;
        nfm->cookie = fm->cookie;
        nfm->command = htons(fm->command);
        nfm->idle_timeout = htons(fm->idle_timeout);
        nfm->hard_timeout = htons(fm->hard_timeout);
        nfm->priority = htons(fm->cr.priority);
        nfm->buffer_id = htonl(fm->buffer_id);
        nfm->out_port = htons(fm->out_port);
        nfm->flags = htons(fm->flags);
        nfm->match_len = htons(match_len);
    } else {
        NOT_REACHED();
    }

    ofpbuf_put(msg, fm->actions, actions_len);
    update_openflow_length(msg);
    return msg;
}

static int
ofputil_decode_ofpst_flow_request(struct flow_stats_request *fsr,
                                  const struct ofp_header *oh,
                                  enum nx_flow_format flow_format,
                                  bool aggregate)
{
    const struct ofp_flow_stats_request *ofsr = ofputil_stats_body(oh);

    fsr->aggregate = aggregate;
    ofputil_cls_rule_from_match(&ofsr->match, 0, flow_format, 0, &fsr->match);
    fsr->out_port = ntohs(ofsr->out_port);
    fsr->table_id = ofsr->table_id;

    return 0;
}

static int
ofputil_decode_nxst_flow_request(struct flow_stats_request *fsr,
                                 const struct ofp_header *oh,
                                 bool aggregate)
{
    const struct nx_flow_stats_request *nfsr;
    struct ofpbuf b;
    int error;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    nfsr = ofpbuf_pull(&b, sizeof *nfsr);
    error = nx_pull_match(&b, ntohs(nfsr->match_len), 0, &fsr->match);
    if (error) {
        return error;
    }
    if (b.size) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    fsr->aggregate = aggregate;
    fsr->out_port = ntohs(nfsr->out_port);
    fsr->table_id = nfsr->table_id;

    return 0;
}

/* Converts an OFPST_FLOW, OFPST_AGGREGATE, NXST_FLOW, or NXST_AGGREGATE
 * request 'oh', received when the current flow format was 'flow_format', into
 * an abstract flow_stats_request in 'fsr'.  Returns 0 if successful, otherwise
 * an OpenFlow error code.
 *
 * For OFPST_FLOW and OFPST_AGGREGATE messages, 'flow_format' should be the
 * current flow format at the time when the message was received.  Otherwise
 * 'flow_format' is ignored. */
int
ofputil_decode_flow_stats_request(struct flow_stats_request *fsr,
                                  const struct ofp_header *oh,
                                  enum nx_flow_format flow_format)
{
    const struct ofputil_msg_type *type;
    struct ofpbuf b;
    int code;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    ofputil_decode_msg_type(oh, &type);
    code = ofputil_msg_type_code(type);
    switch (code) {
    case OFPUTIL_OFPST_FLOW_REQUEST:
        return ofputil_decode_ofpst_flow_request(fsr, oh, flow_format, false);

    case OFPUTIL_OFPST_AGGREGATE_REQUEST:
        return ofputil_decode_ofpst_flow_request(fsr, oh, flow_format, true);

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
 * 'flow_format', and returns the message. */
struct ofpbuf *
ofputil_encode_flow_stats_request(const struct flow_stats_request *fsr,
                                  enum nx_flow_format flow_format)
{
    struct ofpbuf *msg;

    if (flow_format == NXFF_OPENFLOW10
        || flow_format == NXFF_TUN_ID_FROM_COOKIE) {
        struct ofp_flow_stats_request *ofsr;
        int type;

        BUILD_ASSERT_DECL(sizeof(struct ofp_flow_stats_request)
                          == sizeof(struct ofp_aggregate_stats_request));

        type = fsr->aggregate ? OFPST_AGGREGATE : OFPST_FLOW;
        ofsr = ofputil_make_stats_request(sizeof *ofsr, type, &msg);
        ofputil_cls_rule_to_match(&fsr->match, flow_format, &ofsr->match,
                                  0, NULL);
        ofsr->table_id = fsr->table_id;
        ofsr->out_port = htons(fsr->out_port);
    } else if (flow_format == NXFF_NXM) {
        struct nx_flow_stats_request *nfsr;
        int match_len;
        int subtype;

        subtype = fsr->aggregate ? NXST_AGGREGATE : NXST_FLOW;
        ofputil_make_nxstats_request(sizeof *nfsr, subtype, &msg);
        match_len = nx_put_match(msg, &fsr->match);

        nfsr = msg->data;
        nfsr->out_port = htons(fsr->out_port);
        nfsr->match_len = htons(match_len);
        nfsr->table_id = fsr->table_id;
    } else {
        NOT_REACHED();
    }

    return msg;
}

/* Converts an OFPST_FLOW or NXST_FLOW reply in 'msg' into an abstract
 * ofputil_flow_stats in 'fs'.  For OFPST_FLOW messages, 'flow_format' should
 * be the current flow format at the time when the request corresponding to the
 * reply in 'msg' was sent.  Otherwise 'flow_format' is ignored.
 *
 * Multiple OFPST_FLOW or NXST_FLOW replies can be packed into a single
 * OpenFlow message.  Calling this function multiple times for a single 'msg'
 * iterates through the replies.  The caller must initially leave 'msg''s layer
 * pointers null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_flow_stats_reply(struct ofputil_flow_stats *fs,
                                struct ofpbuf *msg,
                                enum nx_flow_format flow_format)
{
    const struct ofputil_msg_type *type;
    int code;

    ofputil_decode_msg_type(msg->l2 ? msg->l2 : msg->data, &type);
    code = ofputil_msg_type_code(type);
    if (!msg->l2) {
        msg->l2 = msg->data;
        if (code == OFPUTIL_OFPST_FLOW_REPLY) {
            ofpbuf_pull(msg, sizeof(struct ofp_stats_reply));
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
        ofputil_cls_rule_from_match(&ofs->match, ntohs(ofs->priority),
                                    flow_format, fs->cookie, &fs->rule);
        fs->table_id = ofs->table_id;
        fs->duration_sec = ntohl(ofs->duration_sec);
        fs->duration_nsec = ntohl(ofs->duration_nsec);
        fs->idle_timeout = ntohs(ofs->idle_timeout);
        fs->hard_timeout = ntohs(ofs->hard_timeout);
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
        if (nx_pull_match(msg, match_len, ntohs(nfs->priority), &fs->rule)) {
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
        fs->packet_count = ntohll(nfs->packet_count);
        fs->byte_count = ntohll(nfs->byte_count);
    } else {
        NOT_REACHED();
    }

    return 0;
}

/* Converts an OFPT_FLOW_REMOVED or NXT_FLOW_REMOVED message 'oh', received
 * when the current flow format was 'flow_format', into an abstract
 * ofputil_flow_removed in 'fr'.  Returns 0 if successful, otherwise an
 * OpenFlow error code.
 *
 * For OFPT_FLOW_REMOVED messages, 'flow_format' should be the current flow
 * format at the time when the message was received.  Otherwise 'flow_format'
 * is ignored. */
int
ofputil_decode_flow_removed(struct ofputil_flow_removed *fr,
                            const struct ofp_header *oh,
                            enum nx_flow_format flow_format)
{
    const struct ofputil_msg_type *type;
    enum ofputil_msg_code code;

    ofputil_decode_msg_type(oh, &type);
    code = ofputil_msg_type_code(type);
    if (code == OFPUTIL_OFPT_FLOW_REMOVED) {
        const struct ofp_flow_removed *ofr;

        ofr = (const struct ofp_flow_removed *) oh;
        ofputil_cls_rule_from_match(&ofr->match, ntohs(ofr->priority),
                                    flow_format, ofr->cookie, &fr->rule);
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
                              &fr->rule);
        if (error) {
            return error;
        }
        if (b.size) {
            return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
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
 * NXT_FLOW_REMOVED message 'oh' according to 'flow_format', and returns the
 * message. */
struct ofpbuf *
ofputil_encode_flow_removed(const struct ofputil_flow_removed *fr,
                            enum nx_flow_format flow_format)
{
    struct ofpbuf *msg;

    if (flow_format == NXFF_OPENFLOW10
        || flow_format == NXFF_TUN_ID_FROM_COOKIE) {
        struct ofp_flow_removed *ofr;

        ofr = make_openflow_xid(sizeof *ofr, OFPT_FLOW_REMOVED, htonl(0),
                                &msg);
        ofputil_cls_rule_to_match(&fr->rule, flow_format, &ofr->match,
                                  fr->cookie, &ofr->cookie);
        ofr->priority = htons(fr->rule.priority);
        ofr->reason = fr->reason;
        ofr->duration_sec = htonl(fr->duration_sec);
        ofr->duration_nsec = htonl(fr->duration_nsec);
        ofr->idle_timeout = htons(fr->idle_timeout);
        ofr->packet_count = htonll(fr->packet_count);
        ofr->byte_count = htonll(fr->byte_count);
    } else if (flow_format == NXFF_NXM) {
        struct nx_flow_removed *nfr;
        int match_len;

        make_nxmsg_xid(sizeof *nfr, NXT_FLOW_REMOVED, htonl(0), &msg);
        match_len = nx_put_match(msg, &fr->rule);

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
    } else {
        NOT_REACHED();
    }

    return msg;
}

/* Converts abstract ofputil_packet_in 'pin' into an OFPT_PACKET_IN message
 * and returns the message.
 *
 * If 'rw_packet' is NULL, the caller takes ownership of the newly allocated
 * returned ofpbuf.
 *
 * If 'rw_packet' is nonnull, then it must contain the same data as
 * pin->packet.  'rw_packet' is allowed to be the same ofpbuf as pin->packet.
 * It is modified in-place into an OFPT_PACKET_IN message according to 'pin',
 * and then ofputil_encode_packet_in() returns 'rw_packet'.  If 'rw_packet' has
 * enough headroom to insert a "struct ofp_packet_in", this is more efficient
 * than ofputil_encode_packet_in() because it does not copy the packet
 * payload. */
struct ofpbuf *
ofputil_encode_packet_in(const struct ofputil_packet_in *pin,
                        struct ofpbuf *rw_packet)
{
    int total_len = pin->packet->size;
    struct ofp_packet_in *opi;

    if (rw_packet) {
        if (pin->send_len < rw_packet->size) {
            rw_packet->size = pin->send_len;
        }
    } else {
        rw_packet = ofpbuf_clone_data_with_headroom(
            pin->packet->data, MIN(pin->send_len, pin->packet->size),
            offsetof(struct ofp_packet_in, data));
    }

    /* Add OFPT_PACKET_IN. */
    opi = ofpbuf_push_zeros(rw_packet, offsetof(struct ofp_packet_in, data));
    opi->header.version = OFP_VERSION;
    opi->header.type = OFPT_PACKET_IN;
    opi->total_len = htons(total_len);
    opi->in_port = htons(pin->in_port);
    opi->reason = pin->reason;
    opi->buffer_id = htonl(pin->buffer_id);
    update_openflow_length(rw_packet);

    return rw_packet;
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
    oh->version = OFP_VERSION;
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

/* Creates an ofp_stats_request with the given 'type' and 'body_len' bytes of
 * space allocated for the 'body' member.  Returns the first byte of the 'body'
 * member. */
void *
ofputil_make_stats_request(size_t body_len, uint16_t type,
                           struct ofpbuf **bufferp)
{
    struct ofp_stats_request *osr;
    osr = make_openflow((offsetof(struct ofp_stats_request, body)
                        + body_len), OFPT_STATS_REQUEST, bufferp);
    osr->type = htons(type);
    osr->flags = htons(0);
    return osr->body;
}

/* Creates a stats request message with Nicira as vendor and the given
 * 'subtype', of total length 'openflow_len'.  Returns the message. */
void *
ofputil_make_nxstats_request(size_t openflow_len, uint32_t subtype,
                             struct ofpbuf **bufferp)
{
    struct nicira_stats_msg *nsm;

    nsm = make_openflow(openflow_len, OFPT_STATS_REQUEST, bufferp);
    nsm->type = htons(OFPST_VENDOR);
    nsm->flags = htons(0);
    nsm->vendor = htonl(NX_VENDOR_ID);
    nsm->subtype = htonl(subtype);
    return nsm;
}

/* Returns the first byte of the 'body' member of the ofp_stats_request or
 * ofp_stats_reply in 'oh'. */
const void *
ofputil_stats_body(const struct ofp_header *oh)
{
    assert(oh->type == OFPT_STATS_REQUEST || oh->type == OFPT_STATS_REPLY);
    return ((const struct ofp_stats_request *) oh)->body;
}

/* Returns the length of the 'body' member of the ofp_stats_request or
 * ofp_stats_reply in 'oh'. */
size_t
ofputil_stats_body_len(const struct ofp_header *oh)
{
    assert(oh->type == OFPT_STATS_REQUEST || oh->type == OFPT_STATS_REPLY);
    return ntohs(oh->length) - sizeof(struct ofp_stats_request);
}

/* Returns the first byte of the body of the nicira_stats_msg in 'oh'. */
const void *
ofputil_nxstats_body(const struct ofp_header *oh)
{
    assert(oh->type == OFPT_STATS_REQUEST || oh->type == OFPT_STATS_REPLY);
    return ((const struct nicira_stats_msg *) oh) + 1;
}

/* Returns the length of the body of the nicira_stats_msg in 'oh'. */
size_t
ofputil_nxstats_body_len(const struct ofp_header *oh)
{
    assert(oh->type == OFPT_STATS_REQUEST || oh->type == OFPT_STATS_REPLY);
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
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->cookie = 0;
    ofm->priority = htons(MIN(rule->priority, UINT16_MAX));
    ofputil_cls_rule_to_match(rule, NXFF_OPENFLOW10, &ofm->match, 0, NULL);
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
make_del_flow(const struct cls_rule *rule)
{
    struct ofpbuf *out = make_flow_mod(OFPFC_DELETE_STRICT, rule, 0);
    struct ofp_flow_mod *ofm = out->data;
    ofm->out_port = htons(OFPP_NONE);
    return out;
}

struct ofpbuf *
make_add_simple_flow(const struct cls_rule *rule,
                     uint32_t buffer_id, uint16_t out_port,
                     uint16_t idle_timeout)
{
    if (out_port != OFPP_NONE) {
        struct ofp_action_output *oao;
        struct ofpbuf *buffer;

        buffer = make_add_flow(rule, buffer_id, idle_timeout, sizeof *oao);
        oao = ofpbuf_put_zeros(buffer, sizeof *oao);
        oao->type = htons(OFPAT_OUTPUT);
        oao->len = htons(sizeof *oao);
        oao->port = htons(out_port);
        return buffer;
    } else {
        return make_add_flow(rule, buffer_id, idle_timeout, 0);
    }
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

struct ofpbuf *
make_packet_out(const struct ofpbuf *packet, uint32_t buffer_id,
                uint16_t in_port,
                const struct ofp_action_header *actions, size_t n_actions)
{
    size_t actions_len = n_actions * sizeof *actions;
    struct ofp_packet_out *opo;
    size_t size = sizeof *opo + actions_len + (packet ? packet->size : 0);
    struct ofpbuf *out = ofpbuf_new(size);

    opo = ofpbuf_put_uninit(out, sizeof *opo);
    opo->header.version = OFP_VERSION;
    opo->header.type = OFPT_PACKET_OUT;
    opo->header.length = htons(size);
    opo->header.xid = htonl(0);
    opo->buffer_id = htonl(buffer_id);
    opo->in_port = htons(in_port == ODPP_LOCAL ? OFPP_LOCAL : in_port);
    opo->actions_len = htons(actions_len);
    ofpbuf_put(out, actions, actions_len);
    if (packet) {
        ofpbuf_put(out, packet->data, packet->size);
    }
    return out;
}

struct ofpbuf *
make_unbuffered_packet_out(const struct ofpbuf *packet,
                           uint16_t in_port, uint16_t out_port)
{
    struct ofp_action_output action;
    action.type = htons(OFPAT_OUTPUT);
    action.len = htons(sizeof action);
    action.port = htons(out_port);
    return make_packet_out(packet, UINT32_MAX, in_port,
                           (struct ofp_action_header *) &action, 1);
}

struct ofpbuf *
make_buffered_packet_out(uint32_t buffer_id,
                         uint16_t in_port, uint16_t out_port)
{
    if (out_port != OFPP_NONE) {
        struct ofp_action_output action;
        action.type = htons(OFPAT_OUTPUT);
        action.len = htons(sizeof action);
        action.port = htons(out_port);
        return make_packet_out(NULL, buffer_id, in_port,
                               (struct ofp_action_header *) &action, 1);
    } else {
        return make_packet_out(NULL, buffer_id, in_port, NULL, 0);
    }
}

/* Creates and returns an OFPT_ECHO_REQUEST message with an empty payload. */
struct ofpbuf *
make_echo_request(void)
{
    struct ofp_header *rq;
    struct ofpbuf *out = ofpbuf_new(sizeof *rq);
    rq = ofpbuf_put_uninit(out, sizeof *rq);
    rq->version = OFP_VERSION;
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

static int
check_action_exact_len(const union ofp_action *a, unsigned int len,
                       unsigned int required_len)
{
    if (len != required_len) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "action %"PRIu16" has invalid length "
                     "%"PRIu16" (must be %u)\n",
                     ntohs(a->type), ntohs(a->header.len), required_len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    return 0;
}

static int
check_nx_action_exact_len(const struct nx_action_header *a,
                          unsigned int len, unsigned int required_len)
{
    if (len != required_len) {
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "Nicira action %"PRIu16" has invalid length %"PRIu16" "
                     "(must be %u)\n",
                     ntohs(a->subtype), ntohs(a->len), required_len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    return 0;
}

/* Checks that 'port' is a valid output port for the OFPAT_OUTPUT action, given
 * that the switch will never have more than 'max_ports' ports.  Returns 0 if
 * 'port' is valid, otherwise an ofp_mkerr() return code. */
static int
check_output_port(uint16_t port, int max_ports)
{
    switch (port) {
    case OFPP_IN_PORT:
    case OFPP_TABLE:
    case OFPP_NORMAL:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_CONTROLLER:
    case OFPP_LOCAL:
        return 0;

    default:
        if (port < max_ports) {
            return 0;
        }
        VLOG_WARN_RL(&bad_ofmsg_rl, "unknown output port %x", port);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
    }
}

/* Checks that 'action' is a valid OFPAT_ENQUEUE action, given that the switch
 * will never have more than 'max_ports' ports.  Returns 0 if 'port' is valid,
 * otherwise an ofp_mkerr() return code. */
static int
check_enqueue_action(const union ofp_action *a, unsigned int len,
                     int max_ports)
{
    const struct ofp_action_enqueue *oae;
    uint16_t port;
    int error;

    error = check_action_exact_len(a, len, 16);
    if (error) {
        return error;
    }

    oae = (const struct ofp_action_enqueue *) a;
    port = ntohs(oae->port);
    if (port < max_ports || port == OFPP_IN_PORT) {
        return 0;
    }
    VLOG_WARN_RL(&bad_ofmsg_rl, "unknown enqueue port %x", port);
    return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
}

static int
check_nicira_action(const union ofp_action *a, unsigned int len,
                    const struct flow *flow)
{
    const struct nx_action_header *nah;
    int subtype;
    int error;

    if (len < 16) {
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "Nicira vendor action only %u bytes", len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    nah = (const struct nx_action_header *) a;

    subtype = ntohs(nah->subtype);
    if (subtype > TYPE_MAXIMUM(enum nx_action_subtype)) {
        /* This is necessary because enum nx_action_subtype may be an
         * 8-bit type, so the cast below throws away the top 8 bits. */
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_VENDOR_TYPE);
    }

    switch ((enum nx_action_subtype) subtype) {
    case NXAST_RESUBMIT:
    case NXAST_SET_TUNNEL:
    case NXAST_DROP_SPOOFED_ARP:
    case NXAST_SET_QUEUE:
    case NXAST_POP_QUEUE:
        return check_nx_action_exact_len(nah, len, 16);

    case NXAST_REG_MOVE:
        error = check_nx_action_exact_len(nah, len,
                                          sizeof(struct nx_action_reg_move));
        if (error) {
            return error;
        }
        return nxm_check_reg_move((const struct nx_action_reg_move *) a, flow);

    case NXAST_REG_LOAD:
        error = check_nx_action_exact_len(nah, len,
                                          sizeof(struct nx_action_reg_load));
        if (error) {
            return error;
        }
        return nxm_check_reg_load((const struct nx_action_reg_load *) a, flow);

    case NXAST_NOTE:
        return 0;

    case NXAST_SET_TUNNEL64:
        return check_nx_action_exact_len(
            nah, len, sizeof(struct nx_action_set_tunnel64));

    case NXAST_MULTIPATH:
        error = check_nx_action_exact_len(
            nah, len, sizeof(struct nx_action_multipath));
        if (error) {
            return error;
        }
        return multipath_check((const struct nx_action_multipath *) a);

    case NXAST_AUTOPATH:
        error = check_nx_action_exact_len(
            nah, len, sizeof(struct nx_action_autopath));
        if (error) {
            return error;
        }
        return autopath_check((const struct nx_action_autopath *) a);

    case NXAST_SNAT__OBSOLETE:
    default:
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "unknown Nicira vendor action subtype %d", subtype);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_VENDOR_TYPE);
    }
}

static int
check_action(const union ofp_action *a, unsigned int len,
             const struct flow *flow, int max_ports)
{
    enum ofp_action_type type = ntohs(a->type);
    int error;

    switch (type) {
    case OFPAT_OUTPUT:
        error = check_action_exact_len(a, len, 8);
        if (error) {
            return error;
        }
        return check_output_port(ntohs(a->output.port), max_ports);

    case OFPAT_SET_VLAN_VID:
        error = check_action_exact_len(a, len, 8);
        if (error) {
            return error;
        }
        if (a->vlan_vid.vlan_vid & ~htons(0xfff)) {
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
        }
        return 0;

    case OFPAT_SET_VLAN_PCP:
        error = check_action_exact_len(a, len, 8);
        if (error) {
            return error;
        }
        if (a->vlan_vid.vlan_vid & ~7) {
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
        }
        return 0;

    case OFPAT_STRIP_VLAN:
    case OFPAT_SET_NW_SRC:
    case OFPAT_SET_NW_DST:
    case OFPAT_SET_NW_TOS:
    case OFPAT_SET_TP_SRC:
    case OFPAT_SET_TP_DST:
        return check_action_exact_len(a, len, 8);

    case OFPAT_SET_DL_SRC:
    case OFPAT_SET_DL_DST:
        return check_action_exact_len(a, len, 16);

    case OFPAT_VENDOR:
        return (a->vendor.vendor == htonl(NX_VENDOR_ID)
                ? check_nicira_action(a, len, flow)
                : ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_VENDOR));

    case OFPAT_ENQUEUE:
        return check_enqueue_action(a, len, max_ports);

    default:
        VLOG_WARN_RL(&bad_ofmsg_rl, "unknown action type %d", (int) type);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
    }
}

int
validate_actions(const union ofp_action *actions, size_t n_actions,
                 const struct flow *flow, int max_ports)
{
    size_t i;

    for (i = 0; i < n_actions; ) {
        const union ofp_action *a = &actions[i];
        unsigned int len = ntohs(a->header.len);
        unsigned int n_slots = len / OFP_ACTION_ALIGN;
        unsigned int slots_left = &actions[n_actions] - a;
        int error;

        if (n_slots > slots_left) {
            VLOG_WARN_RL(&bad_ofmsg_rl,
                         "action requires %u slots but only %u remain",
                         n_slots, slots_left);
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        } else if (!len) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "action has invalid length 0");
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        } else if (len % OFP_ACTION_ALIGN) {
            VLOG_WARN_RL(&bad_ofmsg_rl, "action length %u is not a multiple "
                         "of %d", len, OFP_ACTION_ALIGN);
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        }

        error = check_action(a, len, flow, max_ports);
        if (error) {
            return error;
        }
        i += n_slots;
    }
    return 0;
}

/* Returns true if 'action' outputs to 'port', false otherwise. */
bool
action_outputs_to_port(const union ofp_action *action, ovs_be16 port)
{
    switch (ntohs(action->type)) {
    case OFPAT_OUTPUT:
        return action->output.port == port;
    case OFPAT_ENQUEUE:
        return ((const struct ofp_action_enqueue *) action)->port == port;
    default:
        return false;
    }
}

/* The set of actions must either come from a trusted source or have been
 * previously validated with validate_actions(). */
const union ofp_action *
actions_first(struct actions_iterator *iter,
              const union ofp_action *oa, size_t n_actions)
{
    iter->pos = oa;
    iter->end = oa + n_actions;
    return actions_next(iter);
}

const union ofp_action *
actions_next(struct actions_iterator *iter)
{
    if (iter->pos != iter->end) {
        const union ofp_action *a = iter->pos;
        unsigned int len = ntohs(a->header.len);
        iter->pos += len / OFP_ACTION_ALIGN;
        return a;
    } else {
        return NULL;
    }
}

void
normalize_match(struct ofp_match *m)
{
    enum { OFPFW_NW = (OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK | OFPFW_NW_PROTO
                       | OFPFW_NW_TOS) };
    enum { OFPFW_TP = OFPFW_TP_SRC | OFPFW_TP_DST };
    uint32_t wc;

    wc = ntohl(m->wildcards) & OVSFW_ALL;
    if (wc & OFPFW_DL_TYPE) {
        m->dl_type = 0;

        /* Can't sensibly match on network or transport headers if the
         * data link type is unknown. */
        wc |= OFPFW_NW | OFPFW_TP;
        m->nw_src = m->nw_dst = m->nw_proto = m->nw_tos = 0;
        m->tp_src = m->tp_dst = 0;
    } else if (m->dl_type == htons(ETH_TYPE_IP)) {
        if (wc & OFPFW_NW_PROTO) {
            m->nw_proto = 0;

            /* Can't sensibly match on transport headers if the network
             * protocol is unknown. */
            wc |= OFPFW_TP;
            m->tp_src = m->tp_dst = 0;
        } else if (m->nw_proto == IPPROTO_TCP ||
                   m->nw_proto == IPPROTO_UDP ||
                   m->nw_proto == IPPROTO_ICMP) {
            if (wc & OFPFW_TP_SRC) {
                m->tp_src = 0;
            }
            if (wc & OFPFW_TP_DST) {
                m->tp_dst = 0;
            }
        } else {
            /* Transport layer fields will always be extracted as zeros, so we
             * can do an exact-match on those values.  */
            wc &= ~OFPFW_TP;
            m->tp_src = m->tp_dst = 0;
        }
        if (wc & OFPFW_NW_SRC_MASK) {
            m->nw_src &= ofputil_wcbits_to_netmask(wc >> OFPFW_NW_SRC_SHIFT);
        }
        if (wc & OFPFW_NW_DST_MASK) {
            m->nw_dst &= ofputil_wcbits_to_netmask(wc >> OFPFW_NW_DST_SHIFT);
        }
        if (wc & OFPFW_NW_TOS) {
            m->nw_tos = 0;
        } else {
            m->nw_tos &= IP_DSCP_MASK;
        }
    } else if (m->dl_type == htons(ETH_TYPE_ARP)) {
        if (wc & OFPFW_NW_PROTO) {
            m->nw_proto = 0;
        }
        if (wc & OFPFW_NW_SRC_MASK) {
            m->nw_src &= ofputil_wcbits_to_netmask(wc >> OFPFW_NW_SRC_SHIFT);
        }
        if (wc & OFPFW_NW_DST_MASK) {
            m->nw_dst &= ofputil_wcbits_to_netmask(wc >> OFPFW_NW_DST_SHIFT);
        }
        m->tp_src = m->tp_dst = m->nw_tos = 0;
    } else if (m->dl_type == htons(ETH_TYPE_IPV6)) {
        /* Don't normalize IPv6 traffic, since OpenFlow doesn't have a
         * way to express it. */
    } else {
        /* Network and transport layer fields will always be extracted as
         * zeros, so we can do an exact-match on those values. */
        wc &= ~(OFPFW_NW | OFPFW_TP);
        m->nw_proto = m->nw_src = m->nw_dst = m->nw_tos = 0;
        m->tp_src = m->tp_dst = 0;
    }
    if (wc & OFPFW_DL_SRC) {
        memset(m->dl_src, 0, sizeof m->dl_src);
    }
    if (wc & OFPFW_DL_DST) {
        memset(m->dl_dst, 0, sizeof m->dl_dst);
    }
    m->wildcards = htonl(wc);
}

/* Returns a string that describes 'match' in a very literal way, without
 * interpreting its contents except in a very basic fashion.  The returned
 * string is intended to be fixed-length, so that it is easy to see differences
 * between two such strings if one is put above another.  This is useful for
 * describing changes made by normalize_match().
 *
 * The caller must free the returned string (with free()). */
char *
ofp_match_to_literal_string(const struct ofp_match *match)
{
    return xasprintf("wildcards=%#10"PRIx32" "
                     " in_port=%5"PRId16" "
                     " dl_src="ETH_ADDR_FMT" "
                     " dl_dst="ETH_ADDR_FMT" "
                     " dl_vlan=%5"PRId16" "
                     " dl_vlan_pcp=%3"PRId8" "
                     " dl_type=%#6"PRIx16" "
                     " nw_tos=%#4"PRIx8" "
                     " nw_proto=%#4"PRIx16" "
                     " nw_src=%#10"PRIx32" "
                     " nw_dst=%#10"PRIx32" "
                     " tp_src=%5"PRId16" "
                     " tp_dst=%5"PRId16,
                     ntohl(match->wildcards),
                     ntohs(match->in_port),
                     ETH_ADDR_ARGS(match->dl_src),
                     ETH_ADDR_ARGS(match->dl_dst),
                     ntohs(match->dl_vlan),
                     match->dl_vlan_pcp,
                     ntohs(match->dl_type),
                     match->nw_tos,
                     match->nw_proto,
                     ntohl(match->nw_src),
                     ntohl(match->nw_dst),
                     ntohs(match->tp_src),
                     ntohs(match->tp_dst));
}

static uint32_t
vendor_code_to_id(uint8_t code)
{
    switch (code) {
#define OFPUTIL_VENDOR(NAME, VENDOR_ID) case NAME: return VENDOR_ID;
        OFPUTIL_VENDORS
#undef OFPUTIL_VENDOR
    default:
        return UINT32_MAX;
    }
}

static int
vendor_id_to_code(uint32_t id)
{
    switch (id) {
#define OFPUTIL_VENDOR(NAME, VENDOR_ID) case VENDOR_ID: return NAME;
        OFPUTIL_VENDORS
#undef OFPUTIL_VENDOR
    default:
        return -1;
    }
}

/* Creates and returns an OpenFlow message of type OFPT_ERROR with the error
 * information taken from 'error', whose encoding must be as described in the
 * large comment in ofp-util.h.  If 'oh' is nonnull, then the error will use
 * oh->xid as its transaction ID, and it will include up to the first 64 bytes
 * of 'oh'.
 *
 * Returns NULL if 'error' is not an OpenFlow error code. */
struct ofpbuf *
ofputil_encode_error_msg(int error, const struct ofp_header *oh)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    struct ofpbuf *buf;
    const void *data;
    size_t len;
    uint8_t vendor;
    uint16_t type;
    uint16_t code;
    ovs_be32 xid;

    if (!is_ofp_error(error)) {
        /* We format 'error' with strerror() here since it seems likely to be
         * a system errno value. */
        VLOG_WARN_RL(&rl, "invalid OpenFlow error code %d (%s)",
                     error, strerror(error));
        return NULL;
    }

    if (oh) {
        xid = oh->xid;
        data = oh;
        len = ntohs(oh->length);
        if (len > 64) {
            len = 64;
        }
    } else {
        xid = 0;
        data = NULL;
        len = 0;
    }

    vendor = get_ofp_err_vendor(error);
    type = get_ofp_err_type(error);
    code = get_ofp_err_code(error);
    if (vendor == OFPUTIL_VENDOR_OPENFLOW) {
        struct ofp_error_msg *oem;

        oem = make_openflow_xid(len + sizeof *oem, OFPT_ERROR, xid, &buf);
        oem->type = htons(type);
        oem->code = htons(code);
    } else {
        struct ofp_error_msg *oem;
        struct nx_vendor_error *nve;
        uint32_t vendor_id;

        vendor_id = vendor_code_to_id(vendor);
        if (vendor_id == UINT32_MAX) {
            VLOG_WARN_RL(&rl, "error %x contains invalid vendor code %d",
                         error, vendor);
            return NULL;
        }

        oem = make_openflow_xid(len + sizeof *oem + sizeof *nve,
                                OFPT_ERROR, xid, &buf);
        oem->type = htons(NXET_VENDOR);
        oem->code = htons(NXVC_VENDOR_ERROR);

        nve = (struct nx_vendor_error *)oem->data;
        nve->vendor = htonl(vendor_id);
        nve->type = htons(type);
        nve->code = htons(code);
    }

    if (len) {
        buf->size -= len;
        ofpbuf_put(buf, data, len);
    }

    return buf;
}

/* Decodes 'oh', which should be an OpenFlow OFPT_ERROR message, and returns an
 * Open vSwitch internal error code in the format described in the large
 * comment in ofp-util.h.
 *
 * If 'payload_ofs' is nonnull, on success '*payload_ofs' is set to the offset
 * to the payload starting from 'oh' and on failure it is set to 0. */
int
ofputil_decode_error_msg(const struct ofp_header *oh, size_t *payload_ofs)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    const struct ofp_error_msg *oem;
    uint16_t type, code;
    struct ofpbuf b;
    int vendor;

    if (payload_ofs) {
        *payload_ofs = 0;
    }
    if (oh->type != OFPT_ERROR) {
        return EPROTO;
    }

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    oem = ofpbuf_try_pull(&b, sizeof *oem);
    if (!oem) {
        return EPROTO;
    }

    type = ntohs(oem->type);
    code = ntohs(oem->code);
    if (type == NXET_VENDOR && code == NXVC_VENDOR_ERROR) {
        const struct nx_vendor_error *nve = ofpbuf_try_pull(&b, sizeof *nve);
        if (!nve) {
            return EPROTO;
        }

        vendor = vendor_id_to_code(ntohl(nve->vendor));
        if (vendor < 0) {
            VLOG_WARN_RL(&rl, "error contains unknown vendor ID %#"PRIx32,
                         ntohl(nve->vendor));
            return EPROTO;
        }
        type = ntohs(nve->type);
        code = ntohs(nve->code);
    } else {
        vendor = OFPUTIL_VENDOR_OPENFLOW;
    }

    if (type >= 1024) {
        VLOG_WARN_RL(&rl, "error contains type %"PRIu16" greater than "
                     "supported maximum value 1023", type);
        return EPROTO;
    }

    if (payload_ofs) {
        *payload_ofs = (uint8_t *) b.data - (uint8_t *) oh;
    }
    return ofp_mkerr_vendor(vendor, type, code);
}

void
ofputil_format_error(struct ds *s, int error)
{
    if (is_errno(error)) {
        ds_put_cstr(s, strerror(error));
    } else {
        uint16_t type = get_ofp_err_type(error);
        uint16_t code = get_ofp_err_code(error);
        const char *type_s = ofp_error_type_to_string(type);
        const char *code_s = ofp_error_code_to_string(type, code);

        ds_put_format(s, "type ");
        if (type_s) {
            ds_put_cstr(s, type_s);
        } else {
            ds_put_format(s, "%"PRIu16, type);
        }

        ds_put_cstr(s, ", code ");
        if (code_s) {
            ds_put_cstr(s, code_s);
        } else {
            ds_put_format(s, "%"PRIu16, code);
        }
    }
}

char *
ofputil_error_to_string(int error)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    ofputil_format_error(&s, error);
    return ds_steal_cstr(&s);
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
int
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
    return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
}
