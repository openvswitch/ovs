/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "unaligned.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(nx_match);

/* Rate limit for nx_match parse errors.  These always indicate a bug in the
 * peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

enum {
    NXM_INVALID = OFP_MKERR_NICIRA(OFPET_BAD_REQUEST, NXBRC_NXM_INVALID),
    NXM_BAD_TYPE = OFP_MKERR_NICIRA(OFPET_BAD_REQUEST, NXBRC_NXM_BAD_TYPE),
    NXM_BAD_VALUE = OFP_MKERR_NICIRA(OFPET_BAD_REQUEST, NXBRC_NXM_BAD_VALUE),
    NXM_BAD_MASK = OFP_MKERR_NICIRA(OFPET_BAD_REQUEST, NXBRC_NXM_BAD_MASK),
    NXM_BAD_PREREQ = OFP_MKERR_NICIRA(OFPET_BAD_REQUEST, NXBRC_NXM_BAD_PREREQ),
    NXM_DUP_TYPE = OFP_MKERR_NICIRA(OFPET_BAD_REQUEST, NXBRC_NXM_DUP_TYPE),
    BAD_ARGUMENT = OFP_MKERR(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT)
};

/* For each NXM_* field, define NFI_NXM_* as consecutive integers starting from
 * zero. */
enum nxm_field_index {
#define DEFINE_FIELD(HEADER, WILDCARD, DL_TYPES, NW_PROTO, WRITABLE) \
        NFI_NXM_##HEADER,
#include "nx-match.def"
    N_NXM_FIELDS
};

struct nxm_field {
    struct hmap_node hmap_node;
    enum nxm_field_index index;       /* NFI_* value. */
    uint32_t header;                  /* NXM_* value. */
    flow_wildcards_t wildcard;        /* FWW_* bit, if exactly one. */
    ovs_be16 dl_type[N_NXM_DL_TYPES]; /* dl_type prerequisites. */
    uint8_t nw_proto;                 /* nw_proto prerequisite, if nonzero. */
    const char *name;                 /* "NXM_*" string. */
    bool writable;                    /* Writable with NXAST_REG_{MOVE,LOAD}? */
};


/* All the known fields. */
static struct nxm_field nxm_fields[N_NXM_FIELDS] = {
#define DEFINE_FIELD(HEADER, WILDCARD, DL_TYPES, NW_PROTO, WRITABLE)     \
    { HMAP_NODE_NULL_INITIALIZER, NFI_NXM_##HEADER, NXM_##HEADER, WILDCARD, \
        DL_CONVERT DL_TYPES, NW_PROTO, "NXM_" #HEADER, WRITABLE },
#define DL_CONVERT(T1, T2) { CONSTANT_HTONS(T1), CONSTANT_HTONS(T2) }
#include "nx-match.def"
};

/* Hash table of 'nxm_fields'. */
static struct hmap all_nxm_fields = HMAP_INITIALIZER(&all_nxm_fields);

static void
nxm_init(void)
{
    if (hmap_is_empty(&all_nxm_fields)) {
        int i;

        for (i = 0; i < N_NXM_FIELDS; i++) {
            struct nxm_field *f = &nxm_fields[i];
            hmap_insert(&all_nxm_fields, &f->hmap_node,
                        hash_int(f->header, 0));
        }

        /* Verify that the header values are unique (duplicate "case" values
         * cause a compile error). */
        switch (0) {
#define DEFINE_FIELD(HEADER, WILDCARD, DL_TYPE, NW_PROTO, WRITABLE)  \
        case NXM_##HEADER: break;
#include "nx-match.def"
        }
    }
}

static const struct nxm_field *
nxm_field_lookup(uint32_t header)
{
    struct nxm_field *f;

    nxm_init();

    HMAP_FOR_EACH_WITH_HASH (f, hmap_node, hash_int(header, 0),
                             &all_nxm_fields) {
        if (f->header == header) {
            return f;
        }
    }

    return NULL;
}

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

static int
parse_nx_reg(const struct nxm_field *f,
             struct flow *flow, struct flow_wildcards *wc,
             const void *value, const void *maskp)
{
    int idx = NXM_NX_REG_IDX(f->header);
    if (wc->reg_masks[idx]) {
        return NXM_DUP_TYPE;
    } else {
        flow_wildcards_set_reg_mask(wc, idx,
                                    (NXM_HASMASK(f->header)
                                     ? ntohl(get_unaligned_be32(maskp))
                                     : UINT32_MAX));
        flow->regs[idx] = ntohl(get_unaligned_be32(value));
        flow->regs[idx] &= wc->reg_masks[idx];
        return 0;
    }
}

static int
parse_nxm_entry(struct cls_rule *rule, const struct nxm_field *f,
                const void *value, const void *mask)
{
    struct flow_wildcards *wc = &rule->wc;
    struct flow *flow = &rule->flow;

    switch (f->index) {
        /* Metadata. */
    case NFI_NXM_OF_IN_PORT:
        flow->in_port = ntohs(get_unaligned_be16(value));
        return 0;

        /* Ethernet header. */
    case NFI_NXM_OF_ETH_DST:
        if ((wc->wildcards & (FWW_DL_DST | FWW_ETH_MCAST))
            != (FWW_DL_DST | FWW_ETH_MCAST)) {
            return NXM_DUP_TYPE;
        } else {
            wc->wildcards &= ~(FWW_DL_DST | FWW_ETH_MCAST);
            memcpy(flow->dl_dst, value, ETH_ADDR_LEN);
            return 0;
        }
    case NFI_NXM_OF_ETH_DST_W:
        if ((wc->wildcards & (FWW_DL_DST | FWW_ETH_MCAST))
            != (FWW_DL_DST | FWW_ETH_MCAST)) {
            return NXM_DUP_TYPE;
        } else if (flow_wildcards_is_dl_dst_mask_valid(mask)) {
            cls_rule_set_dl_dst_masked(rule, value, mask);
            return 0;
        } else {
            return NXM_BAD_MASK;
        }
    case NFI_NXM_OF_ETH_SRC:
        memcpy(flow->dl_src, value, ETH_ADDR_LEN);
        return 0;
    case NFI_NXM_OF_ETH_TYPE:
        flow->dl_type = ofputil_dl_type_from_openflow(get_unaligned_be16(value));
        return 0;

        /* 802.1Q header. */
    case NFI_NXM_OF_VLAN_TCI:
        if (wc->vlan_tci_mask) {
            return NXM_DUP_TYPE;
        } else {
            cls_rule_set_dl_tci(rule, get_unaligned_be16(value));
            return 0;
        }
    case NFI_NXM_OF_VLAN_TCI_W:
        if (wc->vlan_tci_mask) {
            return NXM_DUP_TYPE;
        } else {
            cls_rule_set_dl_tci_masked(rule, get_unaligned_be16(value),
                                       get_unaligned_be16(mask));
            return 0;
        }

        /* IP header. */
    case NFI_NXM_OF_IP_TOS:
        if (*(uint8_t *) value & 0x03) {
            return NXM_BAD_VALUE;
        } else {
            flow->nw_tos = *(uint8_t *) value;
            return 0;
        }
    case NFI_NXM_OF_IP_PROTO:
        flow->nw_proto = *(uint8_t *) value;
        return 0;

        /* IP addresses in IP and ARP headers. */
    case NFI_NXM_OF_IP_SRC:
    case NFI_NXM_OF_ARP_SPA:
        if (wc->nw_src_mask) {
            return NXM_DUP_TYPE;
        } else {
            cls_rule_set_nw_src(rule, get_unaligned_be32(value));
            return 0;
        }
    case NFI_NXM_OF_IP_SRC_W:
    case NFI_NXM_OF_ARP_SPA_W:
        if (wc->nw_src_mask) {
            return NXM_DUP_TYPE;
        } else {
            ovs_be32 ip = get_unaligned_be32(value);
            ovs_be32 netmask = get_unaligned_be32(mask);
            if (!cls_rule_set_nw_src_masked(rule, ip, netmask)) {
                return NXM_BAD_MASK;
            }
            return 0;
        }
    case NFI_NXM_OF_IP_DST:
    case NFI_NXM_OF_ARP_TPA:
        if (wc->nw_dst_mask) {
            return NXM_DUP_TYPE;
        } else {
            cls_rule_set_nw_dst(rule, get_unaligned_be32(value));
            return 0;
        }
    case NFI_NXM_OF_IP_DST_W:
    case NFI_NXM_OF_ARP_TPA_W:
        if (wc->nw_dst_mask) {
            return NXM_DUP_TYPE;
        } else {
            ovs_be32 ip = get_unaligned_be32(value);
            ovs_be32 netmask = get_unaligned_be32(mask);
            if (!cls_rule_set_nw_dst_masked(rule, ip, netmask)) {
                return NXM_BAD_MASK;
            }
            return 0;
        }

        /* IPv6 addresses. */
    case NFI_NXM_NX_IPV6_SRC:
        if (!ipv6_mask_is_any(&wc->ipv6_src_mask)) {
            return NXM_DUP_TYPE;
        } else {
            struct in6_addr ipv6;
            memcpy(&ipv6, value, sizeof ipv6);
            cls_rule_set_ipv6_src(rule, &ipv6);
            return 0;
        }
    case NFI_NXM_NX_IPV6_SRC_W:
        if (!ipv6_mask_is_any(&wc->ipv6_src_mask)) {
            return NXM_DUP_TYPE;
        } else {
            struct in6_addr ipv6, netmask;
            memcpy(&ipv6, value, sizeof ipv6);
            memcpy(&netmask, mask, sizeof netmask);
            if (!cls_rule_set_ipv6_src_masked(rule, &ipv6, &netmask)) {
                return NXM_BAD_MASK;
            }
            return 0;
        }
    case NFI_NXM_NX_IPV6_DST:
        if (!ipv6_mask_is_any(&wc->ipv6_dst_mask)) {
            return NXM_DUP_TYPE;
        } else {
            struct in6_addr ipv6;
            memcpy(&ipv6, value, sizeof ipv6);
            cls_rule_set_ipv6_dst(rule, &ipv6);
            return 0;
        }
    case NFI_NXM_NX_IPV6_DST_W:
        if (!ipv6_mask_is_any(&wc->ipv6_dst_mask)) {
            return NXM_DUP_TYPE;
        } else {
            struct in6_addr ipv6, netmask;
            memcpy(&ipv6, value, sizeof ipv6);
            memcpy(&netmask, mask, sizeof netmask);
            if (!cls_rule_set_ipv6_dst_masked(rule, &ipv6, &netmask)) {
                return NXM_BAD_MASK;
            }
            return 0;
        }

        /* TCP header. */
    case NFI_NXM_OF_TCP_SRC:
        flow->tp_src = get_unaligned_be16(value);
        return 0;
    case NFI_NXM_OF_TCP_DST:
        flow->tp_dst = get_unaligned_be16(value);
        return 0;

        /* UDP header. */
    case NFI_NXM_OF_UDP_SRC:
        flow->tp_src = get_unaligned_be16(value);
        return 0;
    case NFI_NXM_OF_UDP_DST:
        flow->tp_dst = get_unaligned_be16(value);
        return 0;

        /* ICMP header. */
    case NFI_NXM_OF_ICMP_TYPE:
        flow->tp_src = htons(*(uint8_t *) value);
        return 0;
    case NFI_NXM_OF_ICMP_CODE:
        flow->tp_dst = htons(*(uint8_t *) value);
        return 0;

        /* ICMPv6 header. */
    case NFI_NXM_NX_ICMPV6_TYPE:
        flow->tp_src = htons(*(uint8_t *) value);
        return 0;
    case NFI_NXM_NX_ICMPV6_CODE:
        flow->tp_dst = htons(*(uint8_t *) value);
        return 0;

        /* IPv6 Neighbor Discovery. */
    case NFI_NXM_NX_ND_TARGET:
        /* We've already verified that it's an ICMPv6 message. */
        if ((flow->tp_src != htons(ND_NEIGHBOR_SOLICIT))
                    && (flow->tp_src != htons(ND_NEIGHBOR_ADVERT))) {
            return NXM_BAD_PREREQ;
        }
        memcpy(&flow->nd_target, value, sizeof flow->nd_target);
        return 0;
    case NFI_NXM_NX_ND_SLL:
        /* We've already verified that it's an ICMPv6 message. */
        if (flow->tp_src != htons(ND_NEIGHBOR_SOLICIT)) {
            return NXM_BAD_PREREQ;
        }
        memcpy(flow->arp_sha, value, ETH_ADDR_LEN);
        return 0;
    case NFI_NXM_NX_ND_TLL:
        /* We've already verified that it's an ICMPv6 message. */
        if (flow->tp_src != htons(ND_NEIGHBOR_ADVERT)) {
            return NXM_BAD_PREREQ;
        }
        memcpy(flow->arp_tha, value, ETH_ADDR_LEN);
        return 0;

        /* ARP header. */
    case NFI_NXM_OF_ARP_OP:
        if (ntohs(get_unaligned_be16(value)) > 255) {
            return NXM_BAD_VALUE;
        } else {
            flow->nw_proto = ntohs(get_unaligned_be16(value));
            return 0;
        }

    case NFI_NXM_NX_ARP_SHA:
        memcpy(flow->arp_sha, value, ETH_ADDR_LEN);
        return 0;
    case NFI_NXM_NX_ARP_THA:
        memcpy(flow->arp_tha, value, ETH_ADDR_LEN);
        return 0;

        /* Tunnel ID. */
    case NFI_NXM_NX_TUN_ID:
        if (wc->tun_id_mask) {
            return NXM_DUP_TYPE;
        } else {
            cls_rule_set_tun_id(rule, get_unaligned_be64(value));
            return 0;
        }
    case NFI_NXM_NX_TUN_ID_W:
        if (wc->tun_id_mask) {
            return NXM_DUP_TYPE;
        } else {
            ovs_be64 tun_id = get_unaligned_be64(value);
            ovs_be64 tun_mask = get_unaligned_be64(mask);
            cls_rule_set_tun_id_masked(rule, tun_id, tun_mask);
            return 0;
        }

        /* Registers. */
    case NFI_NXM_NX_REG0:
    case NFI_NXM_NX_REG0_W:
#if FLOW_N_REGS >= 2
    case NFI_NXM_NX_REG1:
    case NFI_NXM_NX_REG1_W:
#endif
#if FLOW_N_REGS >= 3
    case NFI_NXM_NX_REG2:
    case NFI_NXM_NX_REG2_W:
#endif
#if FLOW_N_REGS >= 4
    case NFI_NXM_NX_REG3:
    case NFI_NXM_NX_REG3_W:
#endif
#if FLOW_N_REGS > 4
#error
#endif
        return parse_nx_reg(f, flow, wc, value, mask);

    case N_NXM_FIELDS:
        NOT_REACHED();
    }
    NOT_REACHED();
}

static bool
nxm_prereqs_ok(const struct nxm_field *field, const struct flow *flow)
{
    if (field->nw_proto && field->nw_proto != flow->nw_proto) {
        return false;
    }

    if (!field->dl_type[0]) {
        return true;
    } else if (field->dl_type[0] == flow->dl_type) {
        return true;
    } else if (field->dl_type[1] && field->dl_type[1] == flow->dl_type) {
        return true;
    }

    return false;
}

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

int
nx_pull_match(struct ofpbuf *b, unsigned int match_len, uint16_t priority,
              struct cls_rule *rule)
{
    uint32_t header;
    uint8_t *p;

    p = ofpbuf_try_pull(b, ROUND_UP(match_len, 8));
    if (!p) {
        VLOG_DBG_RL(&rl, "nx_match length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %zu)", match_len, b->size);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    cls_rule_init_catchall(rule, priority);
    while ((header = nx_entry_ok(p, match_len)) != 0) {
        unsigned length = NXM_LENGTH(header);
        const struct nxm_field *f;
        int error;

        f = nxm_field_lookup(header);
        if (!f) {
            error = NXM_BAD_TYPE;
        } else if (!nxm_prereqs_ok(f, &rule->flow)) {
            error = NXM_BAD_PREREQ;
        } else if (f->wildcard && !(rule->wc.wildcards & f->wildcard)) {
            error = NXM_DUP_TYPE;
        } else {
            /* 'hasmask' and 'length' are known to be correct at this point
             * because they are included in 'header' and nxm_field_lookup()
             * checked them already. */
            rule->wc.wildcards &= ~f->wildcard;
            error = parse_nxm_entry(rule, f, p + 4, p + 4 + length / 2);
        }
        if (error) {
            VLOG_DBG_RL(&rl, "bad nxm_entry with vendor=%"PRIu32", "
                        "field=%"PRIu32", hasmask=%"PRIu32", type=%"PRIu32" "
                        "(error %x)",
                        NXM_VENDOR(header), NXM_FIELD(header),
                        NXM_HASMASK(header), NXM_TYPE(header),
                        error);
            return error;
        }


        p += 4 + length;
        match_len -= 4 + length;
    }

    return match_len ? NXM_INVALID : 0;
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

/* Appends to 'b' the nx_match format that expresses 'cr' (except for
 * 'cr->priority', because priority is not part of nx_match), plus enough
 * zero bytes to pad the nx_match out to a multiple of 8.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding padding.
 *
 * If 'cr' is a catch-all rule that matches every packet, then this function
 * appends nothing to 'b' and returns 0. */
int
nx_put_match(struct ofpbuf *b, const struct cls_rule *cr)
{
    const flow_wildcards_t wc = cr->wc.wildcards;
    const struct flow *flow = &cr->flow;
    const size_t start_len = b->size;
    int match_len;
    int i;

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
        if (!(wc & FWW_NW_TOS)) {
            nxm_put_8(b, NXM_OF_IP_TOS, flow->nw_tos & 0xfc);
        }
        nxm_put_32m(b, NXM_OF_IP_SRC, flow->nw_src, cr->wc.nw_src_mask);
        nxm_put_32m(b, NXM_OF_IP_DST, flow->nw_dst, cr->wc.nw_dst_mask);

        if (!(wc & FWW_NW_PROTO)) {
            nxm_put_8(b, NXM_OF_IP_PROTO, flow->nw_proto);
            switch (flow->nw_proto) {
                /* TCP. */
            case IPPROTO_TCP:
                if (!(wc & FWW_TP_SRC)) {
                    nxm_put_16(b, NXM_OF_TCP_SRC, flow->tp_src);
                }
                if (!(wc & FWW_TP_DST)) {
                    nxm_put_16(b, NXM_OF_TCP_DST, flow->tp_dst);
                }
                break;

                /* UDP. */
            case IPPROTO_UDP:
                if (!(wc & FWW_TP_SRC)) {
                    nxm_put_16(b, NXM_OF_UDP_SRC, flow->tp_src);
                }
                if (!(wc & FWW_TP_DST)) {
                    nxm_put_16(b, NXM_OF_UDP_DST, flow->tp_dst);
                }
                break;

                /* ICMP. */
            case IPPROTO_ICMP:
                if (!(wc & FWW_TP_SRC)) {
                    nxm_put_8(b, NXM_OF_ICMP_TYPE, ntohs(flow->tp_src));
                }
                if (!(wc & FWW_TP_DST)) {
                    nxm_put_8(b, NXM_OF_ICMP_CODE, ntohs(flow->tp_dst));
                }
                break;
            }
        }
    } else if (!(wc & FWW_DL_TYPE) && flow->dl_type == htons(ETH_TYPE_IPV6)) {
        /* IPv6. */

        if (!(wc & FWW_NW_TOS)) {
            nxm_put_8(b, NXM_OF_IP_TOS, flow->nw_tos & 0xfc);
        }
        nxm_put_ipv6(b, NXM_NX_IPV6_SRC, &flow->ipv6_src,
                &cr->wc.ipv6_src_mask);
        nxm_put_ipv6(b, NXM_NX_IPV6_DST, &flow->ipv6_dst,
                &cr->wc.ipv6_dst_mask);

        if (!(wc & FWW_NW_PROTO)) {
            nxm_put_8(b, NXM_OF_IP_PROTO, flow->nw_proto);
            switch (flow->nw_proto) {
                /* TCP. */
            case IPPROTO_TCP:
                if (!(wc & FWW_TP_SRC)) {
                    nxm_put_16(b, NXM_OF_TCP_SRC, flow->tp_src);
                }
                if (!(wc & FWW_TP_DST)) {
                    nxm_put_16(b, NXM_OF_TCP_DST, flow->tp_dst);
                }
                break;

                /* UDP. */
            case IPPROTO_UDP:
                if (!(wc & FWW_TP_SRC)) {
                    nxm_put_16(b, NXM_OF_UDP_SRC, flow->tp_src);
                }
                if (!(wc & FWW_TP_DST)) {
                    nxm_put_16(b, NXM_OF_UDP_DST, flow->tp_dst);
                }
                break;

                /* ICMPv6. */
            case IPPROTO_ICMPV6:
                if (!(wc & FWW_TP_SRC)) {
                    nxm_put_8(b, NXM_NX_ICMPV6_TYPE, ntohs(flow->tp_src));

                    if (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT) ||
                        flow->tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                        if (!(wc & FWW_ND_TARGET)) {
                            nxm_put_ipv6(b, NXM_NX_ND_TARGET, &flow->nd_target,
                                         &in6addr_exact);
                        }
                        if (!(wc & FWW_ARP_SHA)
                            && flow->tp_src == htons(ND_NEIGHBOR_SOLICIT)) {
                            nxm_put_eth(b, NXM_NX_ND_SLL, flow->arp_sha);
                        }
                        if (!(wc & FWW_ARP_THA)
                            && flow->tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                            nxm_put_eth(b, NXM_NX_ND_TLL, flow->arp_tha);
                        }
                    }
                }
                if (!(wc & FWW_TP_DST)) {
                    nxm_put_8(b, NXM_NX_ICMPV6_CODE, ntohs(flow->tp_dst));
                }
                break;
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
    const struct nxm_field *f = nxm_field_lookup(header);
    if (f) {
        ds_put_cstr(s, f->name);
    } else {
        ds_put_format(s, "%d:%d", NXM_VENDOR(header), NXM_FIELD(header));
    }
}

static uint32_t
parse_nxm_field_name(const char *name, int name_len)
{
    const struct nxm_field *f;

    /* Check whether it's a field name. */
    for (f = nxm_fields; f < &nxm_fields[ARRAY_SIZE(nxm_fields)]; f++) {
        if (!strncmp(f->name, name, name_len) && f->name[name_len] == '\0') {
            return f->header;
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

const char *
nxm_parse_field_bits(const char *s, uint32_t *headerp, int *ofsp, int *n_bitsp)
{
    const char *full_s = s;
    const char *name;
    uint32_t header;
    int start, end;
    int name_len;
    int width;

    name = s;
    name_len = strcspn(s, "[");
    if (s[name_len] != '[') {
        ovs_fatal(0, "%s: missing [ looking for field name", full_s);
    }

    header = parse_nxm_field_name(name, name_len);
    if (!header) {
        ovs_fatal(0, "%s: unknown field `%.*s'", full_s, name_len, s);
    }
    width = nxm_field_bits(header);

    s += name_len;
    if (sscanf(s, "[%d..%d]", &start, &end) == 2) {
        /* Nothing to do. */
    } else if (sscanf(s, "[%d]", &start) == 1) {
        end = start;
    } else if (!strncmp(s, "[]", 2)) {
        start = 0;
        end = width - 1;
    } else {
        ovs_fatal(0, "%s: syntax error expecting [] or [<bit>] or "
                  "[<start>..<end>]", full_s);
    }
    s = strchr(s, ']') + 1;

    if (start > end) {
        ovs_fatal(0, "%s: starting bit %d is after ending bit %d",
                  full_s, start, end);
    } else if (start >= width) {
        ovs_fatal(0, "%s: starting bit %d is not valid because field is only "
                  "%d bits wide", full_s, start, width);
    } else if (end >= width){
        ovs_fatal(0, "%s: ending bit %d is not valid because field is only "
                  "%d bits wide", full_s, end, width);
    }

    *headerp = header;
    *ofsp = start;
    *n_bitsp = end - start + 1;

    return s;
}

void
nxm_parse_reg_move(struct nx_action_reg_move *move, const char *s)
{
    const char *full_s = s;
    uint32_t src, dst;
    int src_ofs, dst_ofs;
    int src_n_bits, dst_n_bits;

    s = nxm_parse_field_bits(s, &src, &src_ofs, &src_n_bits);
    if (strncmp(s, "->", 2)) {
        ovs_fatal(0, "%s: missing `->' following source", full_s);
    }
    s += 2;
    s = nxm_parse_field_bits(s, &dst, &dst_ofs, &dst_n_bits);
    if (*s != '\0') {
        ovs_fatal(0, "%s: trailing garbage following destination", full_s);
    }

    if (src_n_bits != dst_n_bits) {
        ovs_fatal(0, "%s: source field is %d bits wide but destination is "
                  "%d bits wide", full_s, src_n_bits, dst_n_bits);
    }

    move->type = htons(OFPAT_VENDOR);
    move->len = htons(sizeof *move);
    move->vendor = htonl(NX_VENDOR_ID);
    move->subtype = htons(NXAST_REG_MOVE);
    move->n_bits = htons(src_n_bits);
    move->src_ofs = htons(src_ofs);
    move->dst_ofs = htons(dst_ofs);
    move->src = htonl(src);
    move->dst = htonl(dst);
}

void
nxm_parse_reg_load(struct nx_action_reg_load *load, const char *s)
{
    const char *full_s = s;
    uint32_t dst;
    int ofs, n_bits;
    uint64_t value;

    value = strtoull(s, (char **) &s, 0);
    if (strncmp(s, "->", 2)) {
        ovs_fatal(0, "%s: missing `->' following value", full_s);
    }
    s += 2;
    s = nxm_parse_field_bits(s, &dst, &ofs, &n_bits);
    if (*s != '\0') {
        ovs_fatal(0, "%s: trailing garbage following destination", full_s);
    }

    if (n_bits < 64 && (value >> n_bits) != 0) {
        ovs_fatal(0, "%s: value %"PRIu64" does not fit into %d bits",
                  full_s, value, n_bits);
    }

    load->type = htons(OFPAT_VENDOR);
    load->len = htons(sizeof *load);
    load->vendor = htonl(NX_VENDOR_ID);
    load->subtype = htons(NXAST_REG_LOAD);
    load->ofs_nbits = nxm_encode_ofs_nbits(ofs, n_bits);
    load->dst = htonl(dst);
    load->value = htonll(value);
}

/* nxm_format_reg_move(), nxm_format_reg_load(). */

void
nxm_format_field_bits(struct ds *s, uint32_t header, int ofs, int n_bits)
{
    format_nxm_field_name(s, header);
    if (ofs == 0 && n_bits == nxm_field_bits(header)) {
        ds_put_cstr(s, "[]");
    } else if (n_bits == 1) {
        ds_put_format(s, "[%d]", ofs);
    } else {
        ds_put_format(s, "[%d..%d]", ofs, ofs + n_bits - 1);
    }
}

void
nxm_format_reg_move(const struct nx_action_reg_move *move, struct ds *s)
{
    int n_bits = ntohs(move->n_bits);
    int src_ofs = ntohs(move->src_ofs);
    int dst_ofs = ntohs(move->dst_ofs);
    uint32_t src = ntohl(move->src);
    uint32_t dst = ntohl(move->dst);

    ds_put_format(s, "move:");
    nxm_format_field_bits(s, src, src_ofs, n_bits);
    ds_put_cstr(s, "->");
    nxm_format_field_bits(s, dst, dst_ofs, n_bits);
}

void
nxm_format_reg_load(const struct nx_action_reg_load *load, struct ds *s)
{
    int ofs = nxm_decode_ofs(load->ofs_nbits);
    int n_bits = nxm_decode_n_bits(load->ofs_nbits);
    uint32_t dst = ntohl(load->dst);
    uint64_t value = ntohll(load->value);

    ds_put_format(s, "load:%#"PRIx64"->", value);
    nxm_format_field_bits(s, dst, ofs, n_bits);
}

/* nxm_check_reg_move(), nxm_check_reg_load(). */

static bool
field_ok(const struct nxm_field *f, const struct flow *flow, int size)
{
    return (f && !NXM_HASMASK(f->header)
            && nxm_prereqs_ok(f, flow) && size <= nxm_field_bits(f->header));
}

int
nxm_check_reg_move(const struct nx_action_reg_move *action,
                   const struct flow *flow)
{
    const struct nxm_field *src;
    const struct nxm_field *dst;

    if (action->n_bits == htons(0)) {
        return BAD_ARGUMENT;
    }

    src = nxm_field_lookup(ntohl(action->src));
    if (!field_ok(src, flow, ntohs(action->src_ofs) + ntohs(action->n_bits))) {
        return BAD_ARGUMENT;
    }

    dst = nxm_field_lookup(ntohl(action->dst));
    if (!field_ok(dst, flow, ntohs(action->dst_ofs) + ntohs(action->n_bits))) {
        return BAD_ARGUMENT;
    }

    if (!dst->writable) {
        return BAD_ARGUMENT;
    }

    return 0;
}

/* Given a flow, checks that the destination field represented by 'dst_header'
 * and 'ofs_nbits' is valid and large enough for 'min_n_bits' bits of data. */
int
nxm_dst_check(ovs_be32 dst_header, ovs_be16 ofs_nbits, size_t min_n_bits,
              const struct flow *flow)
{
    const struct nxm_field *dst;
    int ofs, n_bits;

    ofs = nxm_decode_ofs(ofs_nbits);
    n_bits = nxm_decode_n_bits(ofs_nbits);
    dst = nxm_field_lookup(ntohl(dst_header));

    if (!field_ok(dst, flow, ofs + n_bits)) {
        VLOG_WARN_RL(&rl, "invalid destination field");
    } else if (!dst->writable) {
        VLOG_WARN_RL(&rl, "destination field is not writable");
    } else if (n_bits < min_n_bits) {
        VLOG_WARN_RL(&rl, "insufficient bits in destination");
    } else {
        return 0;
    }

    return BAD_ARGUMENT;
}

int
nxm_check_reg_load(const struct nx_action_reg_load *action,
                   const struct flow *flow)
{
    int n_bits;
    int error;

    error = nxm_dst_check(action->dst, action->ofs_nbits, 0, flow);
    if (error) {
        return error;
    }

    /* Reject 'action' if a bit numbered 'n_bits' or higher is set to 1 in
     * action->value. */
    n_bits = nxm_decode_n_bits(action->ofs_nbits);
    if (n_bits < 64 && ntohll(action->value) >> n_bits) {
        return BAD_ARGUMENT;
    }

    return 0;
}

/* nxm_execute_reg_move(), nxm_execute_reg_load(). */

static uint64_t
nxm_read_field(const struct nxm_field *src, const struct flow *flow)
{
    switch (src->index) {
    case NFI_NXM_OF_IN_PORT:
        return flow->in_port;

    case NFI_NXM_OF_ETH_DST:
        return eth_addr_to_uint64(flow->dl_dst);

    case NFI_NXM_OF_ETH_SRC:
        return eth_addr_to_uint64(flow->dl_src);

    case NFI_NXM_OF_ETH_TYPE:
        return ntohs(ofputil_dl_type_to_openflow(flow->dl_type));

    case NFI_NXM_OF_VLAN_TCI:
        return ntohs(flow->vlan_tci);

    case NFI_NXM_OF_IP_TOS:
        return flow->nw_tos;

    case NFI_NXM_OF_IP_PROTO:
    case NFI_NXM_OF_ARP_OP:
        return flow->nw_proto;

    case NFI_NXM_OF_IP_SRC:
    case NFI_NXM_OF_ARP_SPA:
        return ntohl(flow->nw_src);

    case NFI_NXM_OF_IP_DST:
    case NFI_NXM_OF_ARP_TPA:
        return ntohl(flow->nw_dst);

    case NFI_NXM_OF_TCP_SRC:
    case NFI_NXM_OF_UDP_SRC:
        return ntohs(flow->tp_src);

    case NFI_NXM_OF_TCP_DST:
    case NFI_NXM_OF_UDP_DST:
        return ntohs(flow->tp_dst);

    case NFI_NXM_OF_ICMP_TYPE:
    case NFI_NXM_NX_ICMPV6_TYPE:
        return ntohs(flow->tp_src) & 0xff;

    case NFI_NXM_OF_ICMP_CODE:
    case NFI_NXM_NX_ICMPV6_CODE:
        return ntohs(flow->tp_dst) & 0xff;

    case NFI_NXM_NX_TUN_ID:
        return ntohll(flow->tun_id);

#define NXM_READ_REGISTER(IDX)                  \
    case NFI_NXM_NX_REG##IDX:                   \
        return flow->regs[IDX];                 \
    case NFI_NXM_NX_REG##IDX##_W:               \
        NOT_REACHED();

    NXM_READ_REGISTER(0);
#if FLOW_N_REGS >= 2
    NXM_READ_REGISTER(1);
#endif
#if FLOW_N_REGS >= 3
    NXM_READ_REGISTER(2);
#endif
#if FLOW_N_REGS >= 4
    NXM_READ_REGISTER(3);
#endif
#if FLOW_N_REGS > 4
#error
#endif

    case NFI_NXM_NX_ARP_SHA:
    case NFI_NXM_NX_ND_SLL:
        return eth_addr_to_uint64(flow->arp_sha);

    case NFI_NXM_NX_ARP_THA:
    case NFI_NXM_NX_ND_TLL:
        return eth_addr_to_uint64(flow->arp_tha);

    case NFI_NXM_NX_TUN_ID_W:
    case NFI_NXM_OF_ETH_DST_W:
    case NFI_NXM_OF_VLAN_TCI_W:
    case NFI_NXM_OF_IP_SRC_W:
    case NFI_NXM_OF_IP_DST_W:
    case NFI_NXM_OF_ARP_SPA_W:
    case NFI_NXM_OF_ARP_TPA_W:
    case NFI_NXM_NX_IPV6_SRC:
    case NFI_NXM_NX_IPV6_SRC_W:
    case NFI_NXM_NX_IPV6_DST:
    case NFI_NXM_NX_IPV6_DST_W:
    case NFI_NXM_NX_ND_TARGET:
    case N_NXM_FIELDS:
        NOT_REACHED();
    }

    NOT_REACHED();
}

static void
nxm_write_field(const struct nxm_field *dst, struct flow *flow,
                uint64_t new_value)
{
    switch (dst->index) {
    case NFI_NXM_OF_ETH_DST:
        eth_addr_from_uint64(new_value, flow->dl_dst);
        break;

    case NFI_NXM_OF_ETH_SRC:
        eth_addr_from_uint64(new_value, flow->dl_src);
        break;

    case NFI_NXM_OF_VLAN_TCI:
        flow->vlan_tci = htons(new_value);
        break;

    case NFI_NXM_NX_TUN_ID:
        flow->tun_id = htonll(new_value);
        break;

#define NXM_WRITE_REGISTER(IDX)                 \
    case NFI_NXM_NX_REG##IDX:                   \
        flow->regs[IDX] = new_value;            \
        break;                                  \
    case NFI_NXM_NX_REG##IDX##_W:               \
        NOT_REACHED();

    NXM_WRITE_REGISTER(0);
#if FLOW_N_REGS >= 2
    NXM_WRITE_REGISTER(1);
#endif
#if FLOW_N_REGS >= 3
    NXM_WRITE_REGISTER(2);
#endif
#if FLOW_N_REGS >= 4
    NXM_WRITE_REGISTER(3);
#endif
#if FLOW_N_REGS > 4
#error
#endif

    case NFI_NXM_OF_IP_TOS:
        flow->nw_tos = new_value & IP_DSCP_MASK;
        break;

    case NFI_NXM_OF_IP_SRC:
        flow->nw_src = htonl(new_value);
        break;

    case NFI_NXM_OF_IP_DST:
        flow->nw_dst = htonl(new_value);
        break;

    case NFI_NXM_OF_TCP_SRC:
    case NFI_NXM_OF_UDP_SRC:
        flow->tp_src = htons(new_value);
        break;

    case NFI_NXM_OF_TCP_DST:
    case NFI_NXM_OF_UDP_DST:
        flow->tp_dst = htons(new_value);
        break;

    case NFI_NXM_OF_IN_PORT:
    case NFI_NXM_OF_ETH_TYPE:
    case NFI_NXM_OF_IP_PROTO:
    case NFI_NXM_OF_ARP_OP:
    case NFI_NXM_OF_ARP_SPA:
    case NFI_NXM_OF_ARP_TPA:
    case NFI_NXM_OF_ICMP_TYPE:
    case NFI_NXM_OF_ICMP_CODE:
    case NFI_NXM_NX_TUN_ID_W:
    case NFI_NXM_OF_ETH_DST_W:
    case NFI_NXM_OF_VLAN_TCI_W:
    case NFI_NXM_OF_IP_SRC_W:
    case NFI_NXM_OF_IP_DST_W:
    case NFI_NXM_OF_ARP_SPA_W:
    case NFI_NXM_OF_ARP_TPA_W:
    case NFI_NXM_NX_ARP_SHA:
    case NFI_NXM_NX_ARP_THA:
    case NFI_NXM_NX_IPV6_SRC:
    case NFI_NXM_NX_IPV6_SRC_W:
    case NFI_NXM_NX_IPV6_DST:
    case NFI_NXM_NX_IPV6_DST_W:
    case NFI_NXM_NX_ICMPV6_TYPE:
    case NFI_NXM_NX_ICMPV6_CODE:
    case NFI_NXM_NX_ND_TARGET:
    case NFI_NXM_NX_ND_SLL:
    case NFI_NXM_NX_ND_TLL:
    case N_NXM_FIELDS:
        NOT_REACHED();
    }
}

void
nxm_execute_reg_move(const struct nx_action_reg_move *action,
                     struct flow *flow)
{
    /* Preparation. */
    int n_bits = ntohs(action->n_bits);
    uint64_t mask = n_bits == 64 ? UINT64_MAX : (UINT64_C(1) << n_bits) - 1;

    /* Get the interesting bits of the source field. */
    const struct nxm_field *src = nxm_field_lookup(ntohl(action->src));
    int src_ofs = ntohs(action->src_ofs);
    uint64_t src_data = (nxm_read_field(src, flow) >> src_ofs) & mask;

    nxm_reg_load(action->dst,
                 nxm_encode_ofs_nbits(ntohs(action->dst_ofs), n_bits),
                 src_data, flow);
}

void
nxm_execute_reg_load(const struct nx_action_reg_load *action,
                     struct flow *flow)
{
    nxm_reg_load(action->dst, action->ofs_nbits, ntohll(action->value), flow);
}

/* Calculates ofs and n_bits from the given 'ofs_nbits' parameter, and copies
 * 'src_data'[0:n_bits] to 'dst_header'[ofs:ofs+n_bits] in the given 'flow'. */
void
nxm_reg_load(ovs_be32 dst_header, ovs_be16 ofs_nbits, uint64_t src_data,
             struct flow *flow)
{
    int n_bits = nxm_decode_n_bits(ofs_nbits);
    int dst_ofs = nxm_decode_ofs(ofs_nbits);
    uint64_t mask = n_bits == 64 ? UINT64_MAX : (UINT64_C(1) << n_bits) - 1;

    /* Get remaining bits of the destination field. */
    const struct nxm_field *dst = nxm_field_lookup(ntohl(dst_header));
    uint64_t dst_data = nxm_read_field(dst, flow) & ~(mask << dst_ofs);

    /* Get the final value. */
    uint64_t new_data = dst_data | (src_data << dst_ofs);

    nxm_write_field(dst, flow, new_data);
}
