/*
 * Copyright (c) 2010, 2011, 2012 Nicira, Inc.
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
            VLOG_DBG_RL(&rl, "nx_match ends with partial nxm_header");
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

static enum ofperr
nx_pull_match__(struct ofpbuf *b, unsigned int match_len, bool strict,
                uint16_t priority, struct cls_rule *rule,
                ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    uint32_t header;
    uint8_t *p;

    assert((cookie != NULL) == (cookie_mask != NULL));

    p = ofpbuf_try_pull(b, ROUND_UP(match_len, 8));
    if (!p) {
        VLOG_DBG_RL(&rl, "nx_match length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %zu)", match_len, b->size);
        return OFPERR_OFPBMC_BAD_LEN;
    }

    cls_rule_init_catchall(rule, priority);
    if (cookie) {
        *cookie = *cookie_mask = htonll(0);
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
        } else if (!mf_are_prereqs_ok(mf, &rule->flow)) {
            error = OFPERR_OFPBMC_BAD_PREREQ;
        } else if (!mf_is_all_wild(mf, &rule->wc)) {
            error = OFPERR_OFPBMC_DUP_FIELD;
        } else {
            unsigned int width = mf->n_bytes;
            union mf_value value;

            memcpy(&value, p + 4, width);
            if (!mf_is_value_valid(mf, &value)) {
                error = OFPERR_OFPBMC_BAD_VALUE;
            } else if (!NXM_HASMASK(header)) {
                error = 0;
                mf_set_value(mf, &value, rule);
            } else {
                union mf_value mask;

                memcpy(&mask, p + 4 + width, width);
                if (!mf_is_mask_valid(mf, &mask)) {
                    error = OFPERR_OFPBMC_BAD_MASK;
                } else {
                    error = 0;
                    mf_set(mf, &value, &mask, rule);
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
                    *cookie_mask = htonll(UINT64_MAX);
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

/* Parses the nx_match formatted match description in 'b' with length
 * 'match_len'.  The results are stored in 'rule', which is initialized with
 * 'priority'.  If 'cookie' and 'cookie_mask' contain valid pointers, then the
 * cookie and mask will be stored in them if a "NXM_NX_COOKIE*" match is
 * defined.  Otherwise, 0 is stored in both.
 *
 * Fails with an error when encountering unknown NXM headers.
 *
 * Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
nx_pull_match(struct ofpbuf *b, unsigned int match_len,
              uint16_t priority, struct cls_rule *rule,
              ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    return nx_pull_match__(b, match_len, true, priority, rule, cookie,
                           cookie_mask);
}

/* Behaves the same as nx_pull_match() with one exception.  Skips over unknown
 * NXM headers instead of failing with an error when they are encountered. */
enum ofperr
nx_pull_match_loose(struct ofpbuf *b, unsigned int match_len,
                    uint16_t priority, struct cls_rule *rule,
                    ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    return nx_pull_match__(b, match_len, false, priority, rule, cookie,
                           cookie_mask);
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

    case CONSTANT_HTONS(UINT16_MAX):
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

    case CONSTANT_HTONL(UINT32_MAX):
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

    case CONSTANT_HTONLL(UINT64_MAX):
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
nxm_put_eth_dst(struct ofpbuf *b,
                flow_wildcards_t wc, const uint8_t value[ETH_ADDR_LEN])
{
    switch (wc & (FWW_DL_DST | FWW_ETH_MCAST)) {
    case FWW_DL_DST | FWW_ETH_MCAST:
        break;
    default:
        nxm_put_header(b, NXM_OF_ETH_DST_W);
        ofpbuf_put(b, value, ETH_ADDR_LEN);
        ofpbuf_put(b, flow_wildcards_to_dl_dst_mask(wc), ETH_ADDR_LEN);
        break;
    case 0:
        nxm_put_eth(b, NXM_OF_ETH_DST, value);
        break;
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
nxm_put_frag(struct ofpbuf *b, const struct cls_rule *cr)
{
    uint8_t nw_frag = cr->flow.nw_frag;
    uint8_t nw_frag_mask = cr->wc.nw_frag_mask;

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
nxm_put_ip(struct ofpbuf *b, const struct cls_rule *cr,
           uint8_t icmp_proto, uint32_t icmp_type, uint32_t icmp_code)
{
    const flow_wildcards_t wc = cr->wc.wildcards;
    const struct flow *flow = &cr->flow;

    nxm_put_frag(b, cr);

    if (!(wc & FWW_NW_DSCP)) {
        nxm_put_8(b, NXM_OF_IP_TOS, flow->nw_tos & IP_DSCP_MASK);
    }

    if (!(wc & FWW_NW_ECN)) {
        nxm_put_8(b, NXM_NX_IP_ECN, flow->nw_tos & IP_ECN_MASK);
    }

    if (!(wc & FWW_NW_TTL)) {
        nxm_put_8(b, NXM_NX_IP_TTL, flow->nw_ttl);
    }

    if (!(wc & FWW_NW_PROTO)) {
        nxm_put_8(b, NXM_OF_IP_PROTO, flow->nw_proto);

        if (flow->nw_proto == IPPROTO_TCP) {
            nxm_put_16m(b, NXM_OF_TCP_SRC, flow->tp_src, cr->wc.tp_src_mask);
            nxm_put_16m(b, NXM_OF_TCP_DST, flow->tp_dst, cr->wc.tp_dst_mask);
        } else if (flow->nw_proto == IPPROTO_UDP) {
            nxm_put_16m(b, NXM_OF_UDP_SRC, flow->tp_src, cr->wc.tp_src_mask);
            nxm_put_16m(b, NXM_OF_UDP_DST, flow->tp_dst, cr->wc.tp_dst_mask);
        } else if (flow->nw_proto == icmp_proto) {
            if (cr->wc.tp_src_mask) {
                nxm_put_8(b, icmp_type, ntohs(flow->tp_src));
            }
            if (cr->wc.tp_dst_mask) {
                nxm_put_8(b, icmp_code, ntohs(flow->tp_dst));
            }
        }
    }
}

/* Appends to 'b' the nx_match format that expresses 'cr' (except for
 * 'cr->priority', because priority is not part of nx_match), plus enough
 * zero bytes to pad the nx_match out to a multiple of 8.  For Flow Mod
 * and Flow Stats Requests messages, a 'cookie' and 'cookie_mask' may be
 * supplied.  Otherwise, 'cookie_mask' should be zero.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding padding.
 *
 * If 'cr' is a catch-all rule that matches every packet, then this function
 * appends nothing to 'b' and returns 0. */
int
nx_put_match(struct ofpbuf *b, const struct cls_rule *cr,
             ovs_be64 cookie, ovs_be64 cookie_mask)
{
    const flow_wildcards_t wc = cr->wc.wildcards;
    const struct flow *flow = &cr->flow;
    const size_t start_len = b->size;
    int match_len;
    int i;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 10);

    /* Metadata. */
    if (!(wc & FWW_IN_PORT)) {
        uint16_t in_port = flow->in_port;
        nxm_put_16(b, NXM_OF_IN_PORT, htons(in_port));
    }

    /* Ethernet. */
    nxm_put_eth_dst(b, wc, flow->dl_dst);
    if (!(wc & FWW_DL_SRC)) {
        nxm_put_eth(b, NXM_OF_ETH_SRC, flow->dl_src);
    }
    if (!(wc & FWW_DL_TYPE)) {
        nxm_put_16(b, NXM_OF_ETH_TYPE,
                   ofputil_dl_type_to_openflow(flow->dl_type));
    }

    /* 802.1Q. */
    nxm_put_16m(b, NXM_OF_VLAN_TCI, flow->vlan_tci, cr->wc.vlan_tci_mask);

    /* L3. */
    if (!(wc & FWW_DL_TYPE) && flow->dl_type == htons(ETH_TYPE_IP)) {
        /* IP. */
        nxm_put_32m(b, NXM_OF_IP_SRC, flow->nw_src, cr->wc.nw_src_mask);
        nxm_put_32m(b, NXM_OF_IP_DST, flow->nw_dst, cr->wc.nw_dst_mask);
        nxm_put_ip(b, cr, IPPROTO_ICMP, NXM_OF_ICMP_TYPE, NXM_OF_ICMP_CODE);
    } else if (!(wc & FWW_DL_TYPE) && flow->dl_type == htons(ETH_TYPE_IPV6)) {
        /* IPv6. */
        nxm_put_ipv6(b, NXM_NX_IPV6_SRC, &flow->ipv6_src,
                &cr->wc.ipv6_src_mask);
        nxm_put_ipv6(b, NXM_NX_IPV6_DST, &flow->ipv6_dst,
                &cr->wc.ipv6_dst_mask);
        nxm_put_ip(b, cr,
                   IPPROTO_ICMPV6, NXM_NX_ICMPV6_TYPE, NXM_NX_ICMPV6_CODE);

        if (!(wc & FWW_IPV6_LABEL)) {
            nxm_put_32(b, NXM_NX_IPV6_LABEL, flow->ipv6_label);
        }

        if (flow->nw_proto == IPPROTO_ICMPV6
            && (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT) ||
                flow->tp_src == htons(ND_NEIGHBOR_ADVERT))) {
            nxm_put_ipv6(b, NXM_NX_ND_TARGET, &flow->nd_target,
                         &cr->wc.nd_target_mask);
            if (!(wc & FWW_ARP_SHA)
                && flow->tp_src == htons(ND_NEIGHBOR_SOLICIT)) {
                nxm_put_eth(b, NXM_NX_ND_SLL, flow->arp_sha);
            }
            if (!(wc & FWW_ARP_THA)
                && flow->tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                nxm_put_eth(b, NXM_NX_ND_TLL, flow->arp_tha);
            }
        }
    } else if (!(wc & FWW_DL_TYPE) && flow->dl_type == htons(ETH_TYPE_ARP)) {
        /* ARP. */
        if (!(wc & FWW_NW_PROTO)) {
            nxm_put_16(b, NXM_OF_ARP_OP, htons(flow->nw_proto));
        }
        nxm_put_32m(b, NXM_OF_ARP_SPA, flow->nw_src, cr->wc.nw_src_mask);
        nxm_put_32m(b, NXM_OF_ARP_TPA, flow->nw_dst, cr->wc.nw_dst_mask);
        if (!(wc & FWW_ARP_SHA)) {
            nxm_put_eth(b, NXM_NX_ARP_SHA, flow->arp_sha);
        }
        if (!(wc & FWW_ARP_THA)) {
            nxm_put_eth(b, NXM_NX_ARP_THA, flow->arp_tha);
        }
    }

    /* Tunnel ID. */
    nxm_put_64m(b, NXM_NX_TUN_ID, flow->tun_id, cr->wc.tun_id_mask);

    /* Registers. */
    for (i = 0; i < FLOW_N_REGS; i++) {
        nxm_put_32m(b, NXM_NX_REG(i),
                    htonl(flow->regs[i]), htonl(cr->wc.reg_masks[i]));
    }

    /* Cookie. */
    nxm_put_64m(b, NXM_NX_COOKIE, cookie, cookie_mask);

    match_len = b->size - start_len;
    ofpbuf_put_zeros(b, ROUND_UP(match_len, 8) - match_len);
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

static void
format_nxm_field_name(struct ds *s, uint32_t header)
{
    const struct mf_field *mf = mf_from_nxm_header(header);
    if (mf) {
        ds_put_cstr(s, mf->nxm_name);
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

        if (mf->nxm_name
            && !strncmp(mf->nxm_name, name, name_len)
            && mf->nxm_name[name_len] == '\0') {
            if (!wild) {
                return mf->nxm_header;
            } else if (mf->maskable != MFM_NONE) {
                return NXM_MAKE_WILD_HEADER(mf->nxm_header);
            }
        }
    }

    if (!strncmp("NXM_NX_COOKIE", name, name_len)
                && (name_len == strlen("NXM_NX_COOKIE"))) {
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

int
nx_match_from_string(const char *s, struct ofpbuf *b)
{
    const char *full_s = s;
    const size_t start_len = b->size;
    int match_len;

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

    match_len = b->size - start_len;
    ofpbuf_put_zeros(b, ROUND_UP(match_len, 8) - match_len);
    return match_len;
}

void
nxm_parse_reg_move(struct nx_action_reg_move *move, const char *s)
{
    const char *full_s = s;
    struct mf_subfield src, dst;

    s = mf_parse_subfield(&src, s);
    if (strncmp(s, "->", 2)) {
        ovs_fatal(0, "%s: missing `->' following source", full_s);
    }
    s += 2;
    s = mf_parse_subfield(&dst, s);
    if (*s != '\0') {
        ovs_fatal(0, "%s: trailing garbage following destination", full_s);
    }

    if (src.n_bits != dst.n_bits) {
        ovs_fatal(0, "%s: source field is %d bits wide but destination is "
                  "%d bits wide", full_s, src.n_bits, dst.n_bits);
    }

    ofputil_init_NXAST_REG_MOVE(move);
    move->n_bits = htons(src.n_bits);
    move->src_ofs = htons(src.ofs);
    move->dst_ofs = htons(dst.ofs);
    move->src = htonl(src.field->nxm_header);
    move->dst = htonl(dst.field->nxm_header);
}

void
nxm_parse_reg_load(struct nx_action_reg_load *load, const char *s)
{
    const char *full_s = s;
    struct mf_subfield dst;
    uint64_t value;

    value = strtoull(s, (char **) &s, 0);
    if (strncmp(s, "->", 2)) {
        ovs_fatal(0, "%s: missing `->' following value", full_s);
    }
    s += 2;
    s = mf_parse_subfield(&dst, s);
    if (*s != '\0') {
        ovs_fatal(0, "%s: trailing garbage following destination", full_s);
    }

    if (dst.n_bits < 64 && (value >> dst.n_bits) != 0) {
        ovs_fatal(0, "%s: value %"PRIu64" does not fit into %u bits",
                  full_s, value, dst.n_bits);
    }

    ofputil_init_NXAST_REG_LOAD(load);
    load->ofs_nbits = nxm_encode_ofs_nbits(dst.ofs, dst.n_bits);
    load->dst = htonl(dst.field->nxm_header);
    load->value = htonll(value);
}

/* nxm_format_reg_move(), nxm_format_reg_load(). */

void
nxm_format_reg_move(const struct nx_action_reg_move *move, struct ds *s)
{
    struct mf_subfield src, dst;

    nxm_decode_discrete(&src, move->src, move->src_ofs, move->n_bits);
    nxm_decode_discrete(&dst, move->dst, move->dst_ofs, move->n_bits);

    ds_put_format(s, "move:");
    mf_format_subfield(&src, s);
    ds_put_cstr(s, "->");
    mf_format_subfield(&dst, s);
}

void
nxm_format_reg_load(const struct nx_action_reg_load *load, struct ds *s)
{
    struct mf_subfield dst;

    ds_put_format(s, "load:%#"PRIx64"->", ntohll(load->value));

    nxm_decode(&dst, load->dst, load->ofs_nbits);
    mf_format_subfield(&dst, s);
}

/* nxm_check_reg_move(), nxm_check_reg_load(). */

enum ofperr
nxm_check_reg_move(const struct nx_action_reg_move *action,
                   const struct flow *flow)
{
    struct mf_subfield src;
    struct mf_subfield dst;
    int error;

    nxm_decode_discrete(&src, action->src, action->src_ofs, action->n_bits);
    error = mf_check_src(&src, flow);
    if (error) {
        return error;
    }

    nxm_decode_discrete(&dst, action->dst, action->dst_ofs, action->n_bits);
    return mf_check_dst(&dst, flow);
}

enum ofperr
nxm_check_reg_load(const struct nx_action_reg_load *action,
                   const struct flow *flow)
{
    struct mf_subfield dst;
    enum ofperr error;

    nxm_decode(&dst, action->dst, action->ofs_nbits);
    error = mf_check_dst(&dst, flow);
    if (error) {
        return error;
    }

    /* Reject 'action' if a bit numbered 'n_bits' or higher is set to 1 in
     * action->value. */
    if (dst.n_bits < 64 && ntohll(action->value) >> dst.n_bits) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return 0;
}

/* nxm_execute_reg_move(), nxm_execute_reg_load(). */

void
nxm_execute_reg_move(const struct nx_action_reg_move *action,
                     struct flow *flow)
{
    struct mf_subfield src, dst;
    union mf_value src_value;
    union mf_value dst_value;

    nxm_decode_discrete(&src, action->src, action->src_ofs, action->n_bits);
    nxm_decode_discrete(&dst, action->dst, action->dst_ofs, action->n_bits);

    mf_get_value(dst.field, flow, &dst_value);
    mf_get_value(src.field, flow, &src_value);
    bitwise_copy(&src_value, src.field->n_bytes, src.ofs,
                 &dst_value, dst.field->n_bytes, dst.ofs,
                 src.n_bits);
    mf_set_flow_value(dst.field, &dst_value, flow);
}

void
nxm_execute_reg_load(const struct nx_action_reg_load *action,
                     struct flow *flow)
{
    struct mf_subfield dst;

    nxm_decode(&dst, action->dst, action->ofs_nbits);
    mf_set_subfield_value(&dst, ntohll(action->value), flow);
}

/* Initializes 'sf->field' with the field corresponding to the given NXM
 * 'header' and 'sf->ofs' and 'sf->n_bits' decoded from 'ofs_nbits' with
 * nxm_decode_ofs() and nxm_decode_n_bits(), respectively.
 *
 * Afterward, 'sf' might be invalid in a few different ways:
 *
 *   - 'sf->field' will be NULL if 'header' is unknown.
 *
 *   - 'sf->ofs' and 'sf->n_bits' might exceed the width of sf->field.
 *
 * The caller should call mf_check_src() or mf_check_dst() to check for these
 * problems. */
void
nxm_decode(struct mf_subfield *sf, ovs_be32 header, ovs_be16 ofs_nbits)
{
    sf->field = mf_from_nxm_header(ntohl(header));
    sf->ofs = nxm_decode_ofs(ofs_nbits);
    sf->n_bits = nxm_decode_n_bits(ofs_nbits);
}

/* Initializes 'sf->field' with the field corresponding to the given NXM
 * 'header' and 'sf->ofs' and 'sf->n_bits' from 'ofs' and 'n_bits',
 * respectively.
 *
 * Afterward, 'sf' might be invalid in a few different ways:
 *
 *   - 'sf->field' will be NULL if 'header' is unknown.
 *
 *   - 'sf->ofs' and 'sf->n_bits' might exceed the width of sf->field.
 *
 * The caller should call mf_check_src() or mf_check_dst() to check for these
 * problems. */
void
nxm_decode_discrete(struct mf_subfield *sf, ovs_be32 header,
                    ovs_be16 ofs, ovs_be16 n_bits)
{
    sf->field = mf_from_nxm_header(ntohl(header));
    sf->ofs = ntohs(ofs);
    sf->n_bits = ntohs(n_bits);
}
