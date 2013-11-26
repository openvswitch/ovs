/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
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

#include "nx-match.h"

#include <netinet/icmp6.h>

#include "classifier.h"
#include "dynamic-string.h"
#include "meta-flow.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "unaligned.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(nx_match);

/* Rate limit for nx_match parse errors.  These always indicate a bug in the
 * peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Returns the width of the data for a field with the given 'header', in
 * bytes. */
int
nxm_field_bytes(uint32_t header)
{
    unsigned int length = NXM_LENGTH(header);
    return NXM_HASMASK(header) ? length / 2 : length;
}

/* Returns the width of the data for a field with the given 'header', in
 * bits. */
int
nxm_field_bits(uint32_t header)
{
    return nxm_field_bytes(header) * 8;
}

/* nx_pull_match() and helpers. */

static uint32_t
nx_entry_ok(const void *p, unsigned int match_len)
{
    unsigned int payload_len;
    ovs_be32 header_be;
    uint32_t header;

    if (match_len < 4) {
        if (match_len) {
            VLOG_DBG_RL(&rl, "nx_match ends with partial (%u-byte) nxm_header",
                        match_len);
        }
        return 0;
    }
    memcpy(&header_be, p, 4);
    header = ntohl(header_be);

    payload_len = NXM_LENGTH(header);
    if (!payload_len) {
        VLOG_DBG_RL(&rl, "nxm_entry %08"PRIx32" has invalid payload "
                    "length 0", header);
        return 0;
    }
    if (match_len < payload_len + 4) {
        VLOG_DBG_RL(&rl, "%"PRIu32"-byte nxm_entry but only "
                    "%u bytes left in nx_match", payload_len + 4, match_len);
        return 0;
    }

    return header;
}

/* Given NXM/OXM value 'value' and mask 'mask', each 'width' bytes long,
 * checks for any 1-bit in the value where there is a 0-bit in the mask.  If it
 * finds one, logs a warning. */
static void
check_mask_consistency(const uint8_t *p, const struct mf_field *mf)
{
    unsigned int width = mf->n_bytes;
    const uint8_t *value = p + 4;
    const uint8_t *mask = p + 4 + width;
    unsigned int i;

    for (i = 0; i < width; i++) {
        if (value[i] & ~mask[i]) {
            if (!VLOG_DROP_WARN(&rl)) {
                char *s = nx_match_to_string(p, width * 2 + 4);
                VLOG_WARN_RL(&rl, "NXM/OXM entry %s has 1-bits in value for "
                             "bits wildcarded by the mask.  (Future versions "
                             "of OVS may report this as an OpenFlow error.)",
                             s);
                break;
            }
        }
    }
}

static enum ofperr
nx_pull_raw(const uint8_t *p, unsigned int match_len, bool strict,
            struct match *match, ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    uint32_t header;

    ovs_assert((cookie != NULL) == (cookie_mask != NULL));

    match_init_catchall(match);
    if (cookie) {
        *cookie = *cookie_mask = htonll(0);
    }
    if (!match_len) {
        return 0;
    }

    for (;
         (header = nx_entry_ok(p, match_len)) != 0;
         p += 4 + NXM_LENGTH(header), match_len -= 4 + NXM_LENGTH(header)) {
        const struct mf_field *mf;
        enum ofperr error;

        mf = mf_from_nxm_header(header);
        if (!mf) {
            if (strict) {
                error = OFPERR_OFPBMC_BAD_FIELD;
            } else {
                continue;
            }
        } else if (!mf_are_prereqs_ok(mf, &match->flow)) {
            error = OFPERR_OFPBMC_BAD_PREREQ;
        } else if (!mf_is_all_wild(mf, &match->wc)) {
            error = OFPERR_OFPBMC_DUP_FIELD;
        } else {
            unsigned int width = mf->n_bytes;
            union mf_value value;

            memcpy(&value, p + 4, width);
            if (!mf_is_value_valid(mf, &value)) {
                error = OFPERR_OFPBMC_BAD_VALUE;
            } else if (!NXM_HASMASK(header)) {
                error = 0;
                mf_set_value(mf, &value, match);
            } else {
                union mf_value mask;

                memcpy(&mask, p + 4 + width, width);
                if (!mf_is_mask_valid(mf, &mask)) {
                    error = OFPERR_OFPBMC_BAD_MASK;
                } else {
                    error = 0;
                    check_mask_consistency(p, mf);
                    mf_set(mf, &value, &mask, match);
                }
            }
        }

        /* Check if the match is for a cookie rather than a classifier rule. */
        if ((header == NXM_NX_COOKIE || header == NXM_NX_COOKIE_W) && cookie) {
            if (*cookie_mask) {
                error = OFPERR_OFPBMC_DUP_FIELD;
            } else {
                unsigned int width = sizeof *cookie;

                memcpy(cookie, p + 4, width);
                if (NXM_HASMASK(header)) {
                    memcpy(cookie_mask, p + 4 + width, width);
                } else {
                    *cookie_mask = OVS_BE64_MAX;
                }
                error = 0;
            }
        }

        if (error) {
            VLOG_DBG_RL(&rl, "bad nxm_entry %#08"PRIx32" (vendor=%"PRIu32", "
                        "field=%"PRIu32", hasmask=%"PRIu32", len=%"PRIu32"), "
                        "(%s)", header,
                        NXM_VENDOR(header), NXM_FIELD(header),
                        NXM_HASMASK(header), NXM_LENGTH(header),
                        ofperr_to_string(error));
            return error;
        }
    }

    return match_len ? OFPERR_OFPBMC_BAD_LEN : 0;
}

static enum ofperr
nx_pull_match__(struct ofpbuf *b, unsigned int match_len, bool strict,
                struct match *match,
                ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    uint8_t *p = NULL;

    if (match_len) {
        p = ofpbuf_try_pull(b, ROUND_UP(match_len, 8));
        if (!p) {
            VLOG_DBG_RL(&rl, "nx_match length %u, rounded up to a "
                        "multiple of 8, is longer than space in message (max "
                        "length %"PRIuSIZE")", match_len, b->size);
            return OFPERR_OFPBMC_BAD_LEN;
        }
    }

    return nx_pull_raw(p, match_len, strict, match, cookie, cookie_mask);
}

/* Parses the nx_match formatted match description in 'b' with length
 * 'match_len'.  Stores the results in 'match'.  If 'cookie' and 'cookie_mask'
 * are valid pointers, then stores the cookie and mask in them if 'b' contains
 * a "NXM_NX_COOKIE*" match.  Otherwise, stores 0 in both.
 *
 * Fails with an error upon encountering an unknown NXM header.
 *
 * Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
nx_pull_match(struct ofpbuf *b, unsigned int match_len, struct match *match,
              ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    return nx_pull_match__(b, match_len, true, match, cookie, cookie_mask);
}

/* Behaves the same as nx_pull_match(), but skips over unknown NXM headers,
 * instead of failing with an error. */
enum ofperr
nx_pull_match_loose(struct ofpbuf *b, unsigned int match_len,
                    struct match *match,
                    ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    return nx_pull_match__(b, match_len, false, match, cookie, cookie_mask);
}

static enum ofperr
oxm_pull_match__(struct ofpbuf *b, bool strict, struct match *match)
{
    struct ofp11_match_header *omh = b->data;
    uint8_t *p;
    uint16_t match_len;

    if (b->size < sizeof *omh) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    match_len = ntohs(omh->length);
    if (match_len < sizeof *omh) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    if (omh->type != htons(OFPMT_OXM)) {
        return OFPERR_OFPBMC_BAD_TYPE;
    }

    p = ofpbuf_try_pull(b, ROUND_UP(match_len, 8));
    if (!p) {
        VLOG_DBG_RL(&rl, "oxm length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %"PRIuSIZE")", match_len, b->size);
        return OFPERR_OFPBMC_BAD_LEN;
    }

    return nx_pull_raw(p + sizeof *omh, match_len - sizeof *omh,
                       strict, match, NULL, NULL);
}

/* Parses the oxm formatted match description preceded by a struct
 * ofp11_match_header in 'b'.  Stores the result in 'match'.
 *
 * Fails with an error when encountering unknown OXM headers.
 *
 * Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
oxm_pull_match(struct ofpbuf *b, struct match *match)
{
    return oxm_pull_match__(b, true, match);
}

/* Behaves the same as oxm_pull_match() with one exception.  Skips over unknown
 * OXM headers instead of failing with an error when they are encountered. */
enum ofperr
oxm_pull_match_loose(struct ofpbuf *b, struct match *match)
{
    return oxm_pull_match__(b, false, match);
}

/* nx_put_match() and helpers.
 *
 * 'put' functions whose names end in 'w' add a wildcarded field.
 * 'put' functions whose names end in 'm' add a field that might be wildcarded.
 * Other 'put' functions add exact-match fields.
 */

static void
nxm_put_header(struct ofpbuf *b, uint32_t header)
{
    ovs_be32 n_header = htonl(header);
    ofpbuf_put(b, &n_header, sizeof n_header);
}

static void
nxm_put_8(struct ofpbuf *b, uint32_t header, uint8_t value)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
}

static void
nxm_put_8m(struct ofpbuf *b, uint32_t header, uint8_t value, uint8_t mask)
{
    switch (mask) {
    case 0:
        break;

    case UINT8_MAX:
        nxm_put_8(b, header, value);
        break;

    default:
        nxm_put_header(b, NXM_MAKE_WILD_HEADER(header));
        ofpbuf_put(b, &value, sizeof value);
        ofpbuf_put(b, &mask, sizeof mask);
    }
}

static void
nxm_put_16(struct ofpbuf *b, uint32_t header, ovs_be16 value)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
}

static void
nxm_put_16w(struct ofpbuf *b, uint32_t header, ovs_be16 value, ovs_be16 mask)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
    ofpbuf_put(b, &mask, sizeof mask);
}

static void
nxm_put_16m(struct ofpbuf *b, uint32_t header, ovs_be16 value, ovs_be16 mask)
{
    switch (mask) {
    case 0:
        break;

    case OVS_BE16_MAX:
        nxm_put_16(b, header, value);
        break;

    default:
        nxm_put_16w(b, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

static void
nxm_put_32(struct ofpbuf *b, uint32_t header, ovs_be32 value)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
}

static void
nxm_put_32w(struct ofpbuf *b, uint32_t header, ovs_be32 value, ovs_be32 mask)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
    ofpbuf_put(b, &mask, sizeof mask);
}

static void
nxm_put_32m(struct ofpbuf *b, uint32_t header, ovs_be32 value, ovs_be32 mask)
{
    switch (mask) {
    case 0:
        break;

    case OVS_BE32_MAX:
        nxm_put_32(b, header, value);
        break;

    default:
        nxm_put_32w(b, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

static void
nxm_put_64(struct ofpbuf *b, uint32_t header, ovs_be64 value)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
}

static void
nxm_put_64w(struct ofpbuf *b, uint32_t header, ovs_be64 value, ovs_be64 mask)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
    ofpbuf_put(b, &mask, sizeof mask);
}

static void
nxm_put_64m(struct ofpbuf *b, uint32_t header, ovs_be64 value, ovs_be64 mask)
{
    switch (mask) {
    case 0:
        break;

    case OVS_BE64_MAX:
        nxm_put_64(b, header, value);
        break;

    default:
        nxm_put_64w(b, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

static void
nxm_put_eth(struct ofpbuf *b, uint32_t header,
            const uint8_t value[ETH_ADDR_LEN])
{
    nxm_put_header(b, header);
    ofpbuf_put(b, value, ETH_ADDR_LEN);
}

static void
nxm_put_eth_masked(struct ofpbuf *b, uint32_t header,
                   const uint8_t value[ETH_ADDR_LEN],
                   const uint8_t mask[ETH_ADDR_LEN])
{
    if (!eth_addr_is_zero(mask)) {
        if (eth_mask_is_exact(mask)) {
            nxm_put_eth(b, header, value);
        } else {
            nxm_put_header(b, NXM_MAKE_WILD_HEADER(header));
            ofpbuf_put(b, value, ETH_ADDR_LEN);
            ofpbuf_put(b, mask, ETH_ADDR_LEN);
        }
    }
}

static void
nxm_put_ipv6(struct ofpbuf *b, uint32_t header,
             const struct in6_addr *value, const struct in6_addr *mask)
{
    if (ipv6_mask_is_any(mask)) {
        return;
    } else if (ipv6_mask_is_exact(mask)) {
        nxm_put_header(b, header);
        ofpbuf_put(b, value, sizeof *value);
    } else {
        nxm_put_header(b, NXM_MAKE_WILD_HEADER(header));
        ofpbuf_put(b, value, sizeof *value);
        ofpbuf_put(b, mask, sizeof *mask);
    }
}

static void
nxm_put_frag(struct ofpbuf *b, const struct match *match)
{
    uint8_t nw_frag = match->flow.nw_frag;
    uint8_t nw_frag_mask = match->wc.masks.nw_frag;

    switch (nw_frag_mask) {
    case 0:
        break;

    case FLOW_NW_FRAG_MASK:
        nxm_put_8(b, NXM_NX_IP_FRAG, nw_frag);
        break;

    default:
        nxm_put_8m(b, NXM_NX_IP_FRAG, nw_frag,
                   nw_frag_mask & FLOW_NW_FRAG_MASK);
        break;
    }
}

static void
nxm_put_ip(struct ofpbuf *b, const struct match *match,
           uint8_t icmp_proto, uint32_t icmp_type, uint32_t icmp_code,
           bool oxm)
{
    const struct flow *flow = &match->flow;

    nxm_put_frag(b, match);

    if (match->wc.masks.nw_tos & IP_DSCP_MASK) {
        if (oxm) {
            nxm_put_8(b, OXM_OF_IP_DSCP, flow->nw_tos >> 2);
        } else {
            nxm_put_8(b, NXM_OF_IP_TOS, flow->nw_tos & IP_DSCP_MASK);
        }
    }

    if (match->wc.masks.nw_tos & IP_ECN_MASK) {
        nxm_put_8(b, oxm ? OXM_OF_IP_ECN : NXM_NX_IP_ECN,
                  flow->nw_tos & IP_ECN_MASK);
    }

    if (!oxm && match->wc.masks.nw_ttl) {
        nxm_put_8(b, NXM_NX_IP_TTL, flow->nw_ttl);
    }

    if (match->wc.masks.nw_proto) {
        nxm_put_8(b, oxm ? OXM_OF_IP_PROTO : NXM_OF_IP_PROTO, flow->nw_proto);

        if (flow->nw_proto == IPPROTO_TCP) {
            nxm_put_16m(b, oxm ? OXM_OF_TCP_SRC : NXM_OF_TCP_SRC,
                        flow->tp_src, match->wc.masks.tp_src);
            nxm_put_16m(b, oxm ? OXM_OF_TCP_DST : NXM_OF_TCP_DST,
                        flow->tp_dst, match->wc.masks.tp_dst);
            nxm_put_16m(b, NXM_NX_TCP_FLAGS,
                        flow->tcp_flags, match->wc.masks.tcp_flags);
        } else if (flow->nw_proto == IPPROTO_UDP) {
            nxm_put_16m(b, oxm ? OXM_OF_UDP_SRC : NXM_OF_UDP_SRC,
                        flow->tp_src, match->wc.masks.tp_src);
            nxm_put_16m(b, oxm ? OXM_OF_UDP_DST : NXM_OF_UDP_DST,
                        flow->tp_dst, match->wc.masks.tp_dst);
        } else if (flow->nw_proto == IPPROTO_SCTP) {
            nxm_put_16m(b, OXM_OF_SCTP_SRC, flow->tp_src,
                        match->wc.masks.tp_src);
            nxm_put_16m(b, OXM_OF_SCTP_DST, flow->tp_dst,
                        match->wc.masks.tp_dst);
        } else if (flow->nw_proto == icmp_proto) {
            if (match->wc.masks.tp_src) {
                nxm_put_8(b, icmp_type, ntohs(flow->tp_src));
            }
            if (match->wc.masks.tp_dst) {
                nxm_put_8(b, icmp_code, ntohs(flow->tp_dst));
            }
        }
    }
}

/* Appends to 'b' the nx_match format that expresses 'match'.  For Flow Mod and
 * Flow Stats Requests messages, a 'cookie' and 'cookie_mask' may be supplied.
 * Otherwise, 'cookie_mask' should be zero.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding padding.
 *
 * If 'match' is a catch-all rule that matches every packet, then this function
 * appends nothing to 'b' and returns 0. */
static int
nx_put_raw(struct ofpbuf *b, bool oxm, const struct match *match,
           ovs_be64 cookie, ovs_be64 cookie_mask)
{
    const struct flow *flow = &match->flow;
    const size_t start_len = b->size;
    int match_len;
    int i;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 23);

    /* Metadata. */
    if (match->wc.masks.in_port.ofp_port) {
        ofp_port_t in_port = flow->in_port.ofp_port;
        if (oxm) {
            nxm_put_32(b, OXM_OF_IN_PORT, ofputil_port_to_ofp11(in_port));
        } else {
            nxm_put_16(b, NXM_OF_IN_PORT, htons(ofp_to_u16(in_port)));
        }
    }

    /* Ethernet. */
    nxm_put_eth_masked(b, oxm ? OXM_OF_ETH_SRC : NXM_OF_ETH_SRC,
                       flow->dl_src, match->wc.masks.dl_src);
    nxm_put_eth_masked(b, oxm ? OXM_OF_ETH_DST : NXM_OF_ETH_DST,
                       flow->dl_dst, match->wc.masks.dl_dst);
    nxm_put_16m(b, oxm ? OXM_OF_ETH_TYPE : NXM_OF_ETH_TYPE,
                ofputil_dl_type_to_openflow(flow->dl_type),
                match->wc.masks.dl_type);

    /* 802.1Q. */
    if (oxm) {
        ovs_be16 VID_CFI_MASK = htons(VLAN_VID_MASK | VLAN_CFI);
        ovs_be16 vid = flow->vlan_tci & VID_CFI_MASK;
        ovs_be16 mask = match->wc.masks.vlan_tci & VID_CFI_MASK;

        if (mask == htons(VLAN_VID_MASK | VLAN_CFI)) {
            nxm_put_16(b, OXM_OF_VLAN_VID, vid);
        } else if (mask) {
            nxm_put_16m(b, OXM_OF_VLAN_VID, vid, mask);
        }

        if (vid && vlan_tci_to_pcp(match->wc.masks.vlan_tci)) {
            nxm_put_8(b, OXM_OF_VLAN_PCP, vlan_tci_to_pcp(flow->vlan_tci));
        }

    } else {
        nxm_put_16m(b, NXM_OF_VLAN_TCI, flow->vlan_tci,
                    match->wc.masks.vlan_tci);
    }

    /* MPLS. */
    if (eth_type_mpls(flow->dl_type)) {
        if (match->wc.masks.mpls_lse & htonl(MPLS_TC_MASK)) {
            nxm_put_8(b, OXM_OF_MPLS_TC, mpls_lse_to_tc(flow->mpls_lse));
        }

        if (match->wc.masks.mpls_lse & htonl(MPLS_BOS_MASK)) {
            nxm_put_8(b, OXM_OF_MPLS_BOS, mpls_lse_to_bos(flow->mpls_lse));
        }

        if (match->wc.masks.mpls_lse & htonl(MPLS_LABEL_MASK)) {
            nxm_put_32(b, OXM_OF_MPLS_LABEL,
                       htonl(mpls_lse_to_label(flow->mpls_lse)));
        }
    }

    /* L3. */
    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        /* IP. */
        nxm_put_32m(b, oxm ? OXM_OF_IPV4_SRC : NXM_OF_IP_SRC,
                    flow->nw_src, match->wc.masks.nw_src);
        nxm_put_32m(b, oxm ? OXM_OF_IPV4_DST : NXM_OF_IP_DST,
                    flow->nw_dst, match->wc.masks.nw_dst);
        nxm_put_ip(b, match, IPPROTO_ICMP,
                   oxm ? OXM_OF_ICMPV4_TYPE : NXM_OF_ICMP_TYPE,
                   oxm ? OXM_OF_ICMPV4_CODE : NXM_OF_ICMP_CODE, oxm);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        /* IPv6. */
        nxm_put_ipv6(b, oxm ? OXM_OF_IPV6_SRC : NXM_NX_IPV6_SRC,
                     &flow->ipv6_src, &match->wc.masks.ipv6_src);
        nxm_put_ipv6(b, oxm ? OXM_OF_IPV6_DST : NXM_NX_IPV6_DST,
                     &flow->ipv6_dst, &match->wc.masks.ipv6_dst);
        nxm_put_ip(b, match, IPPROTO_ICMPV6,
                   oxm ? OXM_OF_ICMPV6_TYPE : NXM_NX_ICMPV6_TYPE,
                   oxm ? OXM_OF_ICMPV6_CODE : NXM_NX_ICMPV6_CODE, oxm);

        nxm_put_32m(b, oxm ? OXM_OF_IPV6_FLABEL : NXM_NX_IPV6_LABEL,
                    flow->ipv6_label, match->wc.masks.ipv6_label);

        if (flow->nw_proto == IPPROTO_ICMPV6
            && (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT) ||
                flow->tp_src == htons(ND_NEIGHBOR_ADVERT))) {
            nxm_put_ipv6(b, oxm ? OXM_OF_IPV6_ND_TARGET : NXM_NX_ND_TARGET,
                         &flow->nd_target, &match->wc.masks.nd_target);
            if (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT)) {
                nxm_put_eth_masked(b, oxm ? OXM_OF_IPV6_ND_SLL : NXM_NX_ND_SLL,
                                   flow->arp_sha, match->wc.masks.arp_sha);
            }
            if (flow->tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                nxm_put_eth_masked(b, oxm ? OXM_OF_IPV6_ND_TLL : NXM_NX_ND_TLL,
                                   flow->arp_tha, match->wc.masks.arp_tha);
            }
        }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        /* ARP. */
        if (match->wc.masks.nw_proto) {
            nxm_put_16(b, oxm ? OXM_OF_ARP_OP : NXM_OF_ARP_OP,
                       htons(flow->nw_proto));
        }
        nxm_put_32m(b, oxm ? OXM_OF_ARP_SPA : NXM_OF_ARP_SPA,
                    flow->nw_src, match->wc.masks.nw_src);
        nxm_put_32m(b, oxm ? OXM_OF_ARP_TPA : NXM_OF_ARP_TPA,
                    flow->nw_dst, match->wc.masks.nw_dst);
        nxm_put_eth_masked(b, oxm ? OXM_OF_ARP_SHA : NXM_NX_ARP_SHA,
                           flow->arp_sha, match->wc.masks.arp_sha);
        nxm_put_eth_masked(b, oxm ? OXM_OF_ARP_THA : NXM_NX_ARP_THA,
                           flow->arp_tha, match->wc.masks.arp_tha);
    }

    /* Tunnel ID. */
    nxm_put_64m(b, oxm ? OXM_OF_TUNNEL_ID : NXM_NX_TUN_ID,
                flow->tunnel.tun_id, match->wc.masks.tunnel.tun_id);

    /* Other tunnel metadata. */
    nxm_put_32m(b, NXM_NX_TUN_IPV4_SRC,
                flow->tunnel.ip_src, match->wc.masks.tunnel.ip_src);
    nxm_put_32m(b, NXM_NX_TUN_IPV4_DST,
                flow->tunnel.ip_dst, match->wc.masks.tunnel.ip_dst);

    /* Registers. */
    for (i = 0; i < FLOW_N_REGS; i++) {
        nxm_put_32m(b, NXM_NX_REG(i),
                    htonl(flow->regs[i]), htonl(match->wc.masks.regs[i]));
    }

    /* Mark. */
    nxm_put_32m(b, NXM_NX_PKT_MARK, htonl(flow->pkt_mark),
                htonl(match->wc.masks.pkt_mark));

    /* OpenFlow 1.1+ Metadata. */
    nxm_put_64m(b, OXM_OF_METADATA, flow->metadata, match->wc.masks.metadata);

    /* Cookie. */
    nxm_put_64m(b, NXM_NX_COOKIE, cookie, cookie_mask);

    match_len = b->size - start_len;
    return match_len;
}

/* Appends to 'b' the nx_match format that expresses 'match', plus enough zero
 * bytes to pad the nx_match out to a multiple of 8.  For Flow Mod and Flow
 * Stats Requests messages, a 'cookie' and 'cookie_mask' may be supplied.
 * Otherwise, 'cookie_mask' should be zero.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding padding.  The return
 * value can be zero if it appended nothing at all to 'b' (which happens if
 * 'cr' is a catch-all rule that matches every packet). */
int
nx_put_match(struct ofpbuf *b, const struct match *match,
             ovs_be64 cookie, ovs_be64 cookie_mask)
{
    int match_len = nx_put_raw(b, false, match, cookie, cookie_mask);

    ofpbuf_put_zeros(b, ROUND_UP(match_len, 8) - match_len);
    return match_len;
}


/* Appends to 'b' an struct ofp11_match_header followed by the oxm format that
 * expresses 'cr', plus enough zero bytes to pad the data appended out to a
 * multiple of 8.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding the padding.  Never
 * returns zero. */
int
oxm_put_match(struct ofpbuf *b, const struct match *match)
{
    int match_len;
    struct ofp11_match_header *omh;
    size_t start_len = b->size;
    ovs_be64 cookie = htonll(0), cookie_mask = htonll(0);

    ofpbuf_put_uninit(b, sizeof *omh);
    match_len = nx_put_raw(b, true, match, cookie, cookie_mask) + sizeof *omh;
    ofpbuf_put_zeros(b, ROUND_UP(match_len, 8) - match_len);

    omh = ofpbuf_at(b, start_len, sizeof *omh);
    omh->type = htons(OFPMT_OXM);
    omh->length = htons(match_len);

    return match_len;
}

/* nx_match_to_string() and helpers. */

static void format_nxm_field_name(struct ds *, uint32_t header);

char *
nx_match_to_string(const uint8_t *p, unsigned int match_len)
{
    uint32_t header;
    struct ds s;

    if (!match_len) {
        return xstrdup("<any>");
    }

    ds_init(&s);
    while ((header = nx_entry_ok(p, match_len)) != 0) {
        unsigned int length = NXM_LENGTH(header);
        unsigned int value_len = nxm_field_bytes(header);
        const uint8_t *value = p + 4;
        const uint8_t *mask = value + value_len;
        unsigned int i;

        if (s.length) {
            ds_put_cstr(&s, ", ");
        }

        format_nxm_field_name(&s, header);
        ds_put_char(&s, '(');

        for (i = 0; i < value_len; i++) {
            ds_put_format(&s, "%02x", value[i]);
        }
        if (NXM_HASMASK(header)) {
            ds_put_char(&s, '/');
            for (i = 0; i < value_len; i++) {
                ds_put_format(&s, "%02x", mask[i]);
            }
        }
        ds_put_char(&s, ')');

        p += 4 + length;
        match_len -= 4 + length;
    }

    if (match_len) {
        if (s.length) {
            ds_put_cstr(&s, ", ");
        }

        ds_put_format(&s, "<%u invalid bytes>", match_len);
    }

    return ds_steal_cstr(&s);
}

char *
oxm_match_to_string(const struct ofpbuf *p, unsigned int match_len)
{
    const struct ofp11_match_header *omh = p->data;
    uint16_t match_len_;
    struct ds s;

    ds_init(&s);

    if (match_len < sizeof *omh) {
        ds_put_format(&s, "<match too short: %u>", match_len);
        goto err;
    }

    if (omh->type != htons(OFPMT_OXM)) {
        ds_put_format(&s, "<bad match type field: %u>", ntohs(omh->type));
        goto err;
    }

    match_len_ = ntohs(omh->length);
    if (match_len_ < sizeof *omh) {
        ds_put_format(&s, "<match length field too short: %u>", match_len_);
        goto err;
    }

    if (match_len_ != match_len) {
        ds_put_format(&s, "<match length field incorrect: %u != %u>",
                      match_len_, match_len);
        goto err;
    }

    return nx_match_to_string(ofpbuf_at(p, sizeof *omh, 0),
                              match_len - sizeof *omh);

err:
    return ds_steal_cstr(&s);
}

static void
format_nxm_field_name(struct ds *s, uint32_t header)
{
    const struct mf_field *mf = mf_from_nxm_header(header);
    if (mf) {
        ds_put_cstr(s, IS_OXM_HEADER(header) ? mf->oxm_name : mf->nxm_name);
        if (NXM_HASMASK(header)) {
            ds_put_cstr(s, "_W");
        }
    } else if (header == NXM_NX_COOKIE) {
        ds_put_cstr(s, "NXM_NX_COOKIE");
    } else if (header == NXM_NX_COOKIE_W) {
        ds_put_cstr(s, "NXM_NX_COOKIE_W");
    } else {
        ds_put_format(s, "%d:%d", NXM_VENDOR(header), NXM_FIELD(header));
    }
}

static uint32_t
parse_nxm_field_name(const char *name, int name_len)
{
    bool wild;
    int i;

    /* Check whether it's a field name. */
    wild = name_len > 2 && !memcmp(&name[name_len - 2], "_W", 2);
    if (wild) {
        name_len -= 2;
    }

    for (i = 0; i < MFF_N_IDS; i++) {
        const struct mf_field *mf = mf_from_id(i);
        uint32_t header;

        if (mf->nxm_name &&
            !strncmp(mf->nxm_name, name, name_len) &&
            mf->nxm_name[name_len] == '\0') {
            header = mf->nxm_header;
        } else if (mf->oxm_name &&
                   !strncmp(mf->oxm_name, name, name_len) &&
                   mf->oxm_name[name_len] == '\0') {
            header = mf->oxm_header;
        } else {
            continue;
        }

        if (!wild) {
            return header;
        } else if (mf->maskable != MFM_NONE) {
            return NXM_MAKE_WILD_HEADER(header);
        }
    }

    if (!strncmp("NXM_NX_COOKIE", name, name_len) &&
        (name_len == strlen("NXM_NX_COOKIE"))) {
        if (!wild) {
            return NXM_NX_COOKIE;
        } else {
            return NXM_NX_COOKIE_W;
        }
    }

    /* Check whether it's a 32-bit field header value as hex.
     * (This isn't ordinarily useful except for testing error behavior.) */
    if (name_len == 8) {
        uint32_t header = hexits_value(name, name_len, NULL);
        if (header != UINT_MAX) {
            return header;
        }
    }

    return 0;
}

/* nx_match_from_string(). */

static int
nx_match_from_string_raw(const char *s, struct ofpbuf *b)
{
    const char *full_s = s;
    const size_t start_len = b->size;

    if (!strcmp(s, "<any>")) {
        /* Ensure that 'b->data' isn't actually null. */
        ofpbuf_prealloc_tailroom(b, 1);
        return 0;
    }

    for (s += strspn(s, ", "); *s; s += strspn(s, ", ")) {
        const char *name;
        uint32_t header;
        int name_len;
        size_t n;

        name = s;
        name_len = strcspn(s, "(");
        if (s[name_len] != '(') {
            ovs_fatal(0, "%s: missing ( at end of nx_match", full_s);
        }

        header = parse_nxm_field_name(name, name_len);
        if (!header) {
            ovs_fatal(0, "%s: unknown field `%.*s'", full_s, name_len, s);
        }

        s += name_len + 1;

        nxm_put_header(b, header);
        s = ofpbuf_put_hex(b, s, &n);
        if (n != nxm_field_bytes(header)) {
            ovs_fatal(0, "%.2s: hex digits expected", s);
        }
        if (NXM_HASMASK(header)) {
            s += strspn(s, " ");
            if (*s != '/') {
                ovs_fatal(0, "%s: missing / in masked field %.*s",
                          full_s, name_len, name);
            }
            s = ofpbuf_put_hex(b, s + 1, &n);
            if (n != nxm_field_bytes(header)) {
                ovs_fatal(0, "%.2s: hex digits expected", s);
            }
        }

        s += strspn(s, " ");
        if (*s != ')') {
            ovs_fatal(0, "%s: missing ) following field %.*s",
                      full_s, name_len, name);
        }
        s++;
    }

    return b->size - start_len;
}

int
nx_match_from_string(const char *s, struct ofpbuf *b)
{
    int match_len = nx_match_from_string_raw(s, b);
    ofpbuf_put_zeros(b, ROUND_UP(match_len, 8) - match_len);
    return match_len;
}

int
oxm_match_from_string(const char *s, struct ofpbuf *b)
{
    int match_len;
    struct ofp11_match_header *omh;
    size_t start_len = b->size;

    ofpbuf_put_uninit(b, sizeof *omh);
    match_len = nx_match_from_string_raw(s, b) + sizeof *omh;
    ofpbuf_put_zeros(b, ROUND_UP(match_len, 8) - match_len);

    omh = ofpbuf_at(b, start_len, sizeof *omh);
    omh->type = htons(OFPMT_OXM);
    omh->length = htons(match_len);

    return match_len;
}

/* Parses 's' as a "move" action, in the form described in ovs-ofctl(8), into
 * '*move'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
nxm_parse_reg_move(struct ofpact_reg_move *move, const char *s)
{
    const char *full_s = s;
    char *error;

    error = mf_parse_subfield__(&move->src, &s);
    if (error) {
        return error;
    }
    if (strncmp(s, "->", 2)) {
        return xasprintf("%s: missing `->' following source", full_s);
    }
    s += 2;
    error = mf_parse_subfield(&move->dst, s);
    if (error) {
        return error;
    }

    if (move->src.n_bits != move->dst.n_bits) {
        return xasprintf("%s: source field is %d bits wide but destination is "
                         "%d bits wide", full_s,
                         move->src.n_bits, move->dst.n_bits);
    }
    return NULL;
}

/* Parses 's' as a "load" action, in the form described in ovs-ofctl(8), into
 * '*load'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
nxm_parse_reg_load(struct ofpact_reg_load *load, const char *s)
{
    const char *full_s = s;
    uint64_t value = strtoull(s, (char **) &s, 0);
    char *error;

    if (strncmp(s, "->", 2)) {
        return xasprintf("%s: missing `->' following value", full_s);
    }
    s += 2;
    error = mf_parse_subfield(&load->dst, s);
    if (error) {
        return error;
    }

    if (load->dst.n_bits < 64 && (value >> load->dst.n_bits) != 0) {
        return xasprintf("%s: value %"PRIu64" does not fit into %d bits",
                         full_s, value, load->dst.n_bits);
    }

    load->subvalue.be64[0] = htonll(0);
    load->subvalue.be64[1] = htonll(value);
    return NULL;
}

/* nxm_format_reg_move(), nxm_format_reg_load(). */

void
nxm_format_reg_move(const struct ofpact_reg_move *move, struct ds *s)
{
    ds_put_format(s, "move:");
    mf_format_subfield(&move->src, s);
    ds_put_cstr(s, "->");
    mf_format_subfield(&move->dst, s);
}

void
nxm_format_reg_load(const struct ofpact_reg_load *load, struct ds *s)
{
    ds_put_cstr(s, "load:");
    mf_format_subvalue(&load->subvalue, s);
    ds_put_cstr(s, "->");
    mf_format_subfield(&load->dst, s);
}

enum ofperr
nxm_reg_move_from_openflow(const struct nx_action_reg_move *narm,
                           struct ofpbuf *ofpacts)
{
    struct ofpact_reg_move *move;

    move = ofpact_put_REG_MOVE(ofpacts);
    move->src.field = mf_from_nxm_header(ntohl(narm->src));
    move->src.ofs = ntohs(narm->src_ofs);
    move->src.n_bits = ntohs(narm->n_bits);
    move->dst.field = mf_from_nxm_header(ntohl(narm->dst));
    move->dst.ofs = ntohs(narm->dst_ofs);
    move->dst.n_bits = ntohs(narm->n_bits);

    return nxm_reg_move_check(move, NULL);
}

enum ofperr
nxm_reg_load_from_openflow(const struct nx_action_reg_load *narl,
                           struct ofpbuf *ofpacts)
{
    struct ofpact_reg_load *load;

    load = ofpact_put_REG_LOAD(ofpacts);
    load->dst.field = mf_from_nxm_header(ntohl(narl->dst));
    load->dst.ofs = nxm_decode_ofs(narl->ofs_nbits);
    load->dst.n_bits = nxm_decode_n_bits(narl->ofs_nbits);
    load->subvalue.be64[1] = narl->value;

    /* Reject 'narl' if a bit numbered 'n_bits' or higher is set to 1 in
     * narl->value. */
    if (load->dst.n_bits < 64 &&
        ntohll(narl->value) >> load->dst.n_bits) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return nxm_reg_load_check(load, NULL);
}

enum ofperr
nxm_reg_move_check(const struct ofpact_reg_move *move, const struct flow *flow)
{
    enum ofperr error;

    error = mf_check_src(&move->src, flow);
    if (error) {
        return error;
    }

    return mf_check_dst(&move->dst, NULL);
}

enum ofperr
nxm_reg_load_check(const struct ofpact_reg_load *load, const struct flow *flow)
{
    return mf_check_dst(&load->dst, flow);
}

void
nxm_reg_move_to_nxast(const struct ofpact_reg_move *move,
                      struct ofpbuf *openflow)
{
    struct nx_action_reg_move *narm;

    narm = ofputil_put_NXAST_REG_MOVE(openflow);
    narm->n_bits = htons(move->dst.n_bits);
    narm->src_ofs = htons(move->src.ofs);
    narm->dst_ofs = htons(move->dst.ofs);
    narm->src = htonl(move->src.field->nxm_header);
    narm->dst = htonl(move->dst.field->nxm_header);
}

void
nxm_reg_load_to_nxast(const struct ofpact_reg_load *load,
                      struct ofpbuf *openflow)
{
    struct nx_action_reg_load *narl;

    narl = ofputil_put_NXAST_REG_LOAD(openflow);
    narl->ofs_nbits = nxm_encode_ofs_nbits(load->dst.ofs, load->dst.n_bits);
    narl->dst = htonl(load->dst.field->nxm_header);
    narl->value = load->subvalue.be64[1];
}

/* nxm_execute_reg_move(), nxm_execute_reg_load(). */

void
nxm_execute_reg_move(const struct ofpact_reg_move *move,
                     struct flow *flow, struct flow_wildcards *wc)
{
    union mf_value src_value;
    union mf_value dst_value;

    mf_mask_field_and_prereqs(move->dst.field, &wc->masks);
    mf_mask_field_and_prereqs(move->src.field, &wc->masks);

    mf_get_value(move->dst.field, flow, &dst_value);
    mf_get_value(move->src.field, flow, &src_value);
    bitwise_copy(&src_value, move->src.field->n_bytes, move->src.ofs,
                 &dst_value, move->dst.field->n_bytes, move->dst.ofs,
                 move->src.n_bits);
    mf_set_flow_value(move->dst.field, &dst_value, flow);
}

void
nxm_execute_reg_load(const struct ofpact_reg_load *load, struct flow *flow,
                     struct flow_wildcards *wc)
{
    /* Since at the datapath interface we do not have set actions for
     * individual fields, but larger sets of fields for a given protocol
     * layer, the set action will in practice only ever apply to exactly
     * matched flows for the given protocol layer.  For example, if the
     * reg_load changes the IP TTL, the corresponding datapath action will
     * rewrite also the IP addresses and TOS byte.  Since these other field
     * values may not be explicitly set, they depend on the incoming flow field
     * values, and are hence all of them are set in the wildcards masks, when
     * the action is committed to the datapath.  For the rare case, where the
     * reg_load action does not actually change the value, and no other flow
     * field values are set (or loaded), the datapath action is skipped, and
     * no mask bits are set.  Such a datapath flow should, however, be
     * dependent on the specific field value, so the corresponding wildcard
     * mask bits must be set, lest the datapath flow be applied to packets
     * containing some other value in the field and the field value remain
     * unchanged regardless of the incoming value.
     *
     * We set the masks here for the whole fields, and their prerequisities.
     * Even if only the lower byte of a TCP destination port is set,
     * we set the mask for the whole field, and also the ip_proto in the IP
     * header, so that the kernel flow would not be applied on, e.g., a UDP
     * packet, or any other IP protocol in addition to TCP packets.
     */
    mf_mask_field_and_prereqs(load->dst.field, &wc->masks);
    mf_write_subfield_flow(&load->dst, &load->subvalue, flow);
}

void
nxm_reg_load(const struct mf_subfield *dst, uint64_t src_data,
             struct flow *flow, struct flow_wildcards *wc)
{
    union mf_subvalue src_subvalue;
    union mf_subvalue mask_value;
    ovs_be64 src_data_be = htonll(src_data);

    memset(&mask_value, 0xff, sizeof mask_value);
    mf_write_subfield_flow(dst, &mask_value, &wc->masks);

    bitwise_copy(&src_data_be, sizeof src_data_be, 0,
                 &src_subvalue, sizeof src_subvalue, 0,
                 sizeof src_data_be * 8);
    mf_write_subfield_flow(dst, &src_subvalue, flow);
}

/* nxm_parse_stack_action, works for both push() and pop(). */

/* Parses 's' as a "push" or "pop" action, in the form described in
 * ovs-ofctl(8), into '*stack_action'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
nxm_parse_stack_action(struct ofpact_stack *stack_action, const char *s)
{
    char *error;

    error = mf_parse_subfield__(&stack_action->subfield, &s);
    if (error) {
        return error;
    }

    if (*s != '\0') {
        return xasprintf("%s: trailing garbage following push or pop", s);
    }

    return NULL;
}

void
nxm_format_stack_push(const struct ofpact_stack *push, struct ds *s)
{
    ds_put_cstr(s, "push:");
    mf_format_subfield(&push->subfield, s);
}

void
nxm_format_stack_pop(const struct ofpact_stack *pop, struct ds *s)
{
    ds_put_cstr(s, "pop:");
    mf_format_subfield(&pop->subfield, s);
}

/* Common set for both push and pop actions. */
static void
stack_action_from_openflow__(const struct nx_action_stack *nasp,
                                    struct ofpact_stack *stack_action)
{
    stack_action->subfield.field = mf_from_nxm_header(ntohl(nasp->field));
    stack_action->subfield.ofs = ntohs(nasp->offset);
    stack_action->subfield.n_bits = ntohs(nasp->n_bits);
}

static void
nxm_stack_to_nxast__(const struct ofpact_stack *stack_action,
                            struct nx_action_stack *nasp)
{
    nasp->offset = htons(stack_action->subfield.ofs);
    nasp->n_bits = htons(stack_action->subfield.n_bits);
    nasp->field = htonl(stack_action->subfield.field->nxm_header);
}

enum ofperr
nxm_stack_push_from_openflow(const struct nx_action_stack *nasp,
                             struct ofpbuf *ofpacts)
{
    struct ofpact_stack *push;

    push = ofpact_put_STACK_PUSH(ofpacts);
    stack_action_from_openflow__(nasp, push);

    return nxm_stack_push_check(push, NULL);
}

enum ofperr
nxm_stack_pop_from_openflow(const struct nx_action_stack *nasp,
                             struct ofpbuf *ofpacts)
{
    struct ofpact_stack *pop;

    pop = ofpact_put_STACK_POP(ofpacts);
    stack_action_from_openflow__(nasp, pop);

    return nxm_stack_pop_check(pop, NULL);
}

enum ofperr
nxm_stack_push_check(const struct ofpact_stack *push,
                     const struct flow *flow)
{
    return mf_check_src(&push->subfield, flow);
}

enum ofperr
nxm_stack_pop_check(const struct ofpact_stack *pop,
                    const struct flow *flow)
{
    return mf_check_dst(&pop->subfield, flow);
}

void
nxm_stack_push_to_nxast(const struct ofpact_stack *stack,
                        struct ofpbuf *openflow)
{
    nxm_stack_to_nxast__(stack, ofputil_put_NXAST_STACK_PUSH(openflow));
}

void
nxm_stack_pop_to_nxast(const struct ofpact_stack *stack,
                       struct ofpbuf *openflow)
{
    nxm_stack_to_nxast__(stack, ofputil_put_NXAST_STACK_POP(openflow));
}

/* nxm_execute_stack_push(), nxm_execute_stack_pop(). */
static void
nx_stack_push(struct ofpbuf *stack, union mf_subvalue *v)
{
    ofpbuf_put(stack, v, sizeof *v);
}

static union mf_subvalue *
nx_stack_pop(struct ofpbuf *stack)
{
    union mf_subvalue *v = NULL;

    if (stack->size) {
        stack->size -= sizeof *v;
        v = (union mf_subvalue *) ofpbuf_tail(stack);
    }

    return v;
}

void
nxm_execute_stack_push(const struct ofpact_stack *push,
                       const struct flow *flow, struct flow_wildcards *wc,
                       struct ofpbuf *stack)
{
    union mf_subvalue mask_value;
    union mf_subvalue dst_value;

    memset(&mask_value, 0xff, sizeof mask_value);
    mf_write_subfield_flow(&push->subfield, &mask_value, &wc->masks);

    mf_read_subfield(&push->subfield, flow, &dst_value);
    nx_stack_push(stack, &dst_value);
}

void
nxm_execute_stack_pop(const struct ofpact_stack *pop,
                      struct flow *flow, struct flow_wildcards *wc,
                      struct ofpbuf *stack)
{
    union mf_subvalue *src_value;

    src_value = nx_stack_pop(stack);

    /* Only pop if stack is not empty. Otherwise, give warning. */
    if (src_value) {
        union mf_subvalue mask_value;

        memset(&mask_value, 0xff, sizeof mask_value);
        mf_write_subfield_flow(&pop->subfield, &mask_value, &wc->masks);
        mf_write_subfield_flow(&pop->subfield, src_value, flow);
    } else {
        if (!VLOG_DROP_WARN(&rl)) {
            char *flow_str = flow_to_string(flow);
            VLOG_WARN_RL(&rl, "Failed to pop from an empty stack. On flow \n"
                           " %s", flow_str);
            free(flow_str);
        }
    }
}
