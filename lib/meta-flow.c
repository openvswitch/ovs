/*
 * Copyright (c) 2011, 2012, 2013 Nicira, Inc.
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

#include "meta-flow.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include "classifier.h"
#include "dynamic-string.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "packets.h"
#include "random.h"
#include "shash.h"
#include "socket-util.h"
#include "unaligned.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(meta_flow);

#define MF_FIELD_SIZES(MEMBER)                  \
    sizeof ((union mf_value *)0)->MEMBER,       \
    8 * sizeof ((union mf_value *)0)->MEMBER

static const struct mf_field mf_fields[MFF_N_IDS] = {
    /* ## -------- ## */
    /* ## metadata ## */
    /* ## -------- ## */

    {
        MFF_TUN_ID, "tun_id", NULL,
        MF_FIELD_SIZES(be64),
        MFM_FULLY,
        MFS_HEXADECIMAL,
        MFP_NONE,
        true,
        NXM_NX_TUN_ID, "NXM_NX_TUN_ID",
        NXM_NX_TUN_ID, "NXM_NX_TUN_ID",
    }, {
        MFF_TUN_SRC, "tun_src", NULL,
        MF_FIELD_SIZES(be32),
        MFM_NONE,
        MFS_IPV4,
        MFP_NONE,
        false,
        0, NULL,
        0, NULL,
    }, {
        MFF_TUN_DST, "tun_dst", NULL,
        MF_FIELD_SIZES(be32),
        MFM_NONE,
        MFS_IPV4,
        MFP_NONE,
        false,
        0, NULL,
        0, NULL,
    }, {
        MFF_TUN_FLAGS, "tun_flags", NULL,
        MF_FIELD_SIZES(be16),
        MFM_NONE,
        MFS_TNL_FLAGS,
        MFP_NONE,
        false,
        0, NULL,
        0, NULL,
    }, {
        MFF_TUN_TTL, "tun_ttl", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_NONE,
        false,
        0, NULL,
        0, NULL,
    }, {
        MFF_TUN_TOS, "tun_tos", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_NONE,
        false,
        0, NULL,
        0, NULL,
    }, {
        MFF_METADATA, "metadata", NULL,
        MF_FIELD_SIZES(be64),
        MFM_FULLY,
        MFS_HEXADECIMAL,
        MFP_NONE,
        true,
        OXM_OF_METADATA, "OXM_OF_METADATA",
        OXM_OF_METADATA, "OXM_OF_METADATA",
    }, {
        MFF_IN_PORT, "in_port", NULL,
        MF_FIELD_SIZES(be16),
        MFM_NONE,
        MFS_OFP_PORT,
        MFP_NONE,
        false,
        NXM_OF_IN_PORT, "NXM_OF_IN_PORT",
        OXM_OF_IN_PORT, "OXM_OF_IN_PORT",
    }, {
        MFF_SKB_PRIORITY, "skb_priority", NULL,
        MF_FIELD_SIZES(be32),
        MFM_NONE,
        MFS_HEXADECIMAL,
        MFP_NONE,
        false,
        0, NULL,
        0, NULL,
    }, {
        MFF_SKB_MARK, "skb_mark", NULL,
        MF_FIELD_SIZES(be32),
        MFM_NONE,
        MFS_HEXADECIMAL,
        MFP_NONE,
        false,
        0, NULL,
        0, NULL,
    },

#define REGISTER(IDX)                           \
    {                                           \
        MFF_REG##IDX, "reg" #IDX, NULL,         \
        MF_FIELD_SIZES(be32),                   \
        MFM_FULLY,                              \
        MFS_HEXADECIMAL,                        \
        MFP_NONE,                               \
        true,                                   \
        NXM_NX_REG(IDX), "NXM_NX_REG" #IDX,     \
        NXM_NX_REG(IDX), "NXM_NX_REG" #IDX,     \
    }
#if FLOW_N_REGS > 0
    REGISTER(0),
#endif
#if FLOW_N_REGS > 1
    REGISTER(1),
#endif
#if FLOW_N_REGS > 2
    REGISTER(2),
#endif
#if FLOW_N_REGS > 3
    REGISTER(3),
#endif
#if FLOW_N_REGS > 4
    REGISTER(4),
#endif
#if FLOW_N_REGS > 5
    REGISTER(5),
#endif
#if FLOW_N_REGS > 6
    REGISTER(6),
#endif
#if FLOW_N_REGS > 7
    REGISTER(7),
#endif
#if FLOW_N_REGS > 8
#error
#endif

    /* ## -- ## */
    /* ## L2 ## */
    /* ## -- ## */

    {
        MFF_ETH_SRC, "eth_src", "dl_src",
        MF_FIELD_SIZES(mac),
        MFM_FULLY,
        MFS_ETHERNET,
        MFP_NONE,
        true,
        NXM_OF_ETH_SRC, "NXM_OF_ETH_SRC",
        OXM_OF_ETH_SRC, "OXM_OF_ETH_SRC",
    }, {
        MFF_ETH_DST, "eth_dst", "dl_dst",
        MF_FIELD_SIZES(mac),
        MFM_FULLY,
        MFS_ETHERNET,
        MFP_NONE,
        true,
        NXM_OF_ETH_DST, "NXM_OF_ETH_DST",
        OXM_OF_ETH_DST, "OXM_OF_ETH_DST",
    }, {
        MFF_ETH_TYPE, "eth_type", "dl_type",
        MF_FIELD_SIZES(be16),
        MFM_NONE,
        MFS_HEXADECIMAL,
        MFP_NONE,
        false,
        NXM_OF_ETH_TYPE, "NXM_OF_ETH_TYPE",
        OXM_OF_ETH_TYPE, "OXM_OF_ETH_TYPE",
    },

    {
        MFF_VLAN_TCI, "vlan_tci", NULL,
        MF_FIELD_SIZES(be16),
        MFM_FULLY,
        MFS_HEXADECIMAL,
        MFP_NONE,
        true,
        NXM_OF_VLAN_TCI, "NXM_OF_VLAN_TCI",
        NXM_OF_VLAN_TCI, "NXM_OF_VLAN_TCI",
    }, {
        MFF_DL_VLAN, "dl_vlan", NULL,
        sizeof(ovs_be16), 12,
        MFM_NONE,
        MFS_DECIMAL,
        MFP_NONE,
        true,
        0, NULL,
        0, NULL,
    }, {
        MFF_VLAN_VID, "vlan_vid", NULL,
        sizeof(ovs_be16), 12,
        MFM_FULLY,
        MFS_DECIMAL,
        MFP_NONE,
        true,
        OXM_OF_VLAN_VID, "OXM_OF_VLAN_VID",
        OXM_OF_VLAN_VID, "OXM_OF_VLAN_VID",
    }, {
        MFF_DL_VLAN_PCP, "dl_vlan_pcp", NULL,
        1, 3,
        MFM_NONE,
        MFS_DECIMAL,
        MFP_NONE,
        true,
        0, NULL,
        0, NULL,
    }, {
        MFF_VLAN_PCP, "vlan_pcp", NULL,
        1, 3,
        MFM_NONE,
        MFS_DECIMAL,
        MFP_VLAN_VID,
        true,
        OXM_OF_VLAN_PCP, "OXM_OF_VLAN_PCP",
        OXM_OF_VLAN_PCP, "OXM_OF_VLAN_PCP",
    },

    /* ## -- ## */
    /* ## L3 ## */
    /* ## -- ## */

    {
        MFF_IPV4_SRC, "ip_src", "nw_src",
        MF_FIELD_SIZES(be32),
        MFM_FULLY,
        MFS_IPV4,
        MFP_IPV4,
        true,
        NXM_OF_IP_SRC, "NXM_OF_IP_SRC",
        OXM_OF_IPV4_SRC, "OXM_OF_IPV4_SRC",
    }, {
        MFF_IPV4_DST, "ip_dst", "nw_dst",
        MF_FIELD_SIZES(be32),
        MFM_FULLY,
        MFS_IPV4,
        MFP_IPV4,
        true,
        NXM_OF_IP_DST, "NXM_OF_IP_DST",
        OXM_OF_IPV4_DST, "OXM_OF_IPV4_DST",
    },

    {
        MFF_IPV6_SRC, "ipv6_src", NULL,
        MF_FIELD_SIZES(ipv6),
        MFM_FULLY,
        MFS_IPV6,
        MFP_IPV6,
        true,
        NXM_NX_IPV6_SRC, "NXM_NX_IPV6_SRC",
        OXM_OF_IPV6_SRC, "OXM_OF_IPV6_SRC",
    }, {
        MFF_IPV6_DST, "ipv6_dst", NULL,
        MF_FIELD_SIZES(ipv6),
        MFM_FULLY,
        MFS_IPV6,
        MFP_IPV6,
        true,
        NXM_NX_IPV6_DST, "NXM_NX_IPV6_DST",
        OXM_OF_IPV6_DST, "OXM_OF_IPV6_DST",
    },
    {
        MFF_IPV6_LABEL, "ipv6_label", NULL,
        4, 20,
        MFM_FULLY,
        MFS_HEXADECIMAL,
        MFP_IPV6,
        false,
        NXM_NX_IPV6_LABEL, "NXM_NX_IPV6_LABEL",
        OXM_OF_IPV6_FLABEL, "OXM_OF_IPV6_FLABEL",
    },

    {
        MFF_IP_PROTO, "nw_proto", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_IP_ANY,
        false,
        NXM_OF_IP_PROTO, "NXM_OF_IP_PROTO",
        OXM_OF_IP_PROTO, "OXM_OF_IP_PROTO",
    }, {
        MFF_IP_DSCP, "nw_tos", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_IP_ANY,
        true,
        NXM_OF_IP_TOS, "NXM_OF_IP_TOS",
        OXM_OF_IP_DSCP, "OXM_OF_IP_DSCP",
    }, {
        MFF_IP_ECN, "nw_ecn", NULL,
        1, 2,
        MFM_NONE,
        MFS_DECIMAL,
        MFP_IP_ANY,
        true,
        NXM_NX_IP_ECN, "NXM_NX_IP_ECN",
        OXM_OF_IP_ECN, "OXM_OF_IP_ECN",
    }, {
        MFF_IP_TTL, "nw_ttl", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_IP_ANY,
        true,
        NXM_NX_IP_TTL, "NXM_NX_IP_TTL",
        NXM_NX_IP_TTL, "NXM_NX_IP_TTL",
    }, {
        MFF_IP_FRAG, "ip_frag", NULL,
        1, 2,
        MFM_FULLY,
        MFS_FRAG,
        MFP_IP_ANY,
        false,
        NXM_NX_IP_FRAG, "NXM_NX_IP_FRAG",
        NXM_NX_IP_FRAG, "NXM_NX_IP_FRAG",
    },

    {
        MFF_ARP_OP, "arp_op", NULL,
        MF_FIELD_SIZES(be16),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_ARP,
        false,
        NXM_OF_ARP_OP, "NXM_OF_ARP_OP",
        OXM_OF_ARP_OP, "OXM_OF_ARP_OP",
    }, {
        MFF_ARP_SPA, "arp_spa", NULL,
        MF_FIELD_SIZES(be32),
        MFM_FULLY,
        MFS_IPV4,
        MFP_ARP,
        false,
        NXM_OF_ARP_SPA, "NXM_OF_ARP_SPA",
        OXM_OF_ARP_SPA, "OXM_OF_ARP_SPA",
    }, {
        MFF_ARP_TPA, "arp_tpa", NULL,
        MF_FIELD_SIZES(be32),
        MFM_FULLY,
        MFS_IPV4,
        MFP_ARP,
        false,
        NXM_OF_ARP_TPA, "NXM_OF_ARP_TPA",
        OXM_OF_ARP_TPA, "OXM_OF_ARP_TPA",
    }, {
        MFF_ARP_SHA, "arp_sha", NULL,
        MF_FIELD_SIZES(mac),
        MFM_FULLY,
        MFS_ETHERNET,
        MFP_ARP,
        false,
        NXM_NX_ARP_SHA, "NXM_NX_ARP_SHA",
        OXM_OF_ARP_SHA, "OXM_OF_ARP_SHA",
    }, {
        MFF_ARP_THA, "arp_tha", NULL,
        MF_FIELD_SIZES(mac),
        MFM_FULLY,
        MFS_ETHERNET,
        MFP_ARP,
        false,
        NXM_NX_ARP_THA, "NXM_NX_ARP_THA",
        OXM_OF_ARP_THA, "OXM_OF_ARP_THA",
    },

    /* ## -- ## */
    /* ## L4 ## */
    /* ## -- ## */

    {
        MFF_TCP_SRC, "tcp_src", "tp_src",
        MF_FIELD_SIZES(be16),
        MFM_FULLY,
        MFS_DECIMAL,
        MFP_TCP,
        true,
        NXM_OF_TCP_SRC, "NXM_OF_TCP_SRC",
        OXM_OF_TCP_SRC, "OXM_OF_TCP_SRC",
    }, {
        MFF_TCP_DST, "tcp_dst", "tp_dst",
        MF_FIELD_SIZES(be16),
        MFM_FULLY,
        MFS_DECIMAL,
        MFP_TCP,
        true,
        NXM_OF_TCP_DST, "NXM_OF_TCP_DST",
        OXM_OF_TCP_DST, "OXM_OF_TCP_DST",
    },

    {
        MFF_UDP_SRC, "udp_src", NULL,
        MF_FIELD_SIZES(be16),
        MFM_FULLY,
        MFS_DECIMAL,
        MFP_UDP,
        true,
        NXM_OF_UDP_SRC, "NXM_OF_UDP_SRC",
        OXM_OF_UDP_SRC, "OXM_OF_UDP_SRC",
    }, {
        MFF_UDP_DST, "udp_dst", NULL,
        MF_FIELD_SIZES(be16),
        MFM_FULLY,
        MFS_DECIMAL,
        MFP_UDP,
        true,
        NXM_OF_UDP_DST, "NXM_OF_UDP_DST",
        OXM_OF_UDP_DST, "OXM_OF_UDP_DST",
    },

    {
        MFF_ICMPV4_TYPE, "icmp_type", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_ICMPV4,
        false,
        NXM_OF_ICMP_TYPE, "NXM_OF_ICMP_TYPE",
        OXM_OF_ICMPV4_TYPE, "OXM_OF_ICMPV4_TYPE",
    }, {
        MFF_ICMPV4_CODE, "icmp_code", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_ICMPV4,
        false,
        NXM_OF_ICMP_CODE, "NXM_OF_ICMP_CODE",
        OXM_OF_ICMPV4_CODE, "OXM_OF_ICMPV4_CODE",
    },

    {
        MFF_ICMPV6_TYPE, "icmpv6_type", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_ICMPV6,
        false,
        NXM_NX_ICMPV6_TYPE, "NXM_NX_ICMPV6_TYPE",
        OXM_OF_ICMPV6_TYPE, "OXM_OF_ICMPV6_TYPE",
    }, {
        MFF_ICMPV6_CODE, "icmpv6_code", NULL,
        MF_FIELD_SIZES(u8),
        MFM_NONE,
        MFS_DECIMAL,
        MFP_ICMPV6,
        false,
        NXM_NX_ICMPV6_CODE, "NXM_NX_ICMPV6_CODE",
        OXM_OF_ICMPV6_CODE, "OXM_OF_ICMPV6_CODE",
    },

    /* ## ---- ## */
    /* ## L"5" ## */
    /* ## ---- ## */

    {
        MFF_ND_TARGET, "nd_target", NULL,
        MF_FIELD_SIZES(ipv6),
        MFM_FULLY,
        MFS_IPV6,
        MFP_ND,
        false,
        NXM_NX_ND_TARGET, "NXM_NX_ND_TARGET",
        OXM_OF_IPV6_ND_TARGET, "OXM_OF_IPV6_ND_TARGET",
    }, {
        MFF_ND_SLL, "nd_sll", NULL,
        MF_FIELD_SIZES(mac),
        MFM_FULLY,
        MFS_ETHERNET,
        MFP_ND_SOLICIT,
        false,
        NXM_NX_ND_SLL, "NXM_NX_ND_SLL",
        OXM_OF_IPV6_ND_SLL, "OXM_OF_IPV6_ND_SLL",
    }, {
        MFF_ND_TLL, "nd_tll", NULL,
        MF_FIELD_SIZES(mac),
        MFM_FULLY,
        MFS_ETHERNET,
        MFP_ND_ADVERT,
        false,
        NXM_NX_ND_TLL, "NXM_NX_ND_TLL",
        OXM_OF_IPV6_ND_TLL, "OXM_OF_IPV6_ND_TLL",
    }
};

/* Maps an NXM or OXM header value to an mf_field. */
struct nxm_field {
    struct hmap_node hmap_node; /* In 'all_fields' hmap. */
    uint32_t header;            /* NXM or OXM header value. */
    const struct mf_field *mf;
};

/* Contains 'struct nxm_field's. */
static struct hmap all_fields = HMAP_INITIALIZER(&all_fields);

/* Rate limit for parse errors.  These always indicate a bug in an OpenFlow
 * controller and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

const struct mf_field *mf_from_nxm_header__(uint32_t header);

/* Returns the field with the given 'id'. */
const struct mf_field *
mf_from_id(enum mf_field_id id)
{
    assert((unsigned int) id < MFF_N_IDS);
    return &mf_fields[id];
}

/* Returns the field with the given 'name', or a null pointer if no field has
 * that name. */
const struct mf_field *
mf_from_name(const char *name)
{
    static struct shash mf_by_name = SHASH_INITIALIZER(&mf_by_name);

    if (shash_is_empty(&mf_by_name)) {
        const struct mf_field *mf;

        for (mf = mf_fields; mf < &mf_fields[MFF_N_IDS]; mf++) {
            shash_add_once(&mf_by_name, mf->name, mf);
            if (mf->extra_name) {
                shash_add_once(&mf_by_name, mf->extra_name, mf);
            }
        }
    }

    return shash_find_data(&mf_by_name, name);
}

static void
add_nxm_field(uint32_t header, const struct mf_field *mf)
{
    struct nxm_field *f;

    f = xmalloc(sizeof *f);
    hmap_insert(&all_fields, &f->hmap_node, hash_int(header, 0));
    f->header = header;
    f->mf = mf;
}

static void
nxm_init_add_field(const struct mf_field *mf, uint32_t header)
{
    if (header) {
        assert(!mf_from_nxm_header__(header));
        add_nxm_field(header, mf);
        if (mf->maskable != MFM_NONE) {
            add_nxm_field(NXM_MAKE_WILD_HEADER(header), mf);
        }
    }
}

static void
nxm_init(void)
{
    const struct mf_field *mf;

    for (mf = mf_fields; mf < &mf_fields[MFF_N_IDS]; mf++) {
        assert(mf->id == mf - mf_fields);
        nxm_init_add_field(mf, mf->nxm_header);
        if (mf->oxm_header != mf->nxm_header) {
            nxm_init_add_field(mf, mf->oxm_header);
        }
    }
}

const struct mf_field *
mf_from_nxm_header(uint32_t header)
{
    if (hmap_is_empty(&all_fields)) {
        nxm_init();
    }
    return mf_from_nxm_header__(header);
}

const struct mf_field *
mf_from_nxm_header__(uint32_t header)
{
    const struct nxm_field *f;

    HMAP_FOR_EACH_IN_BUCKET (f, hmap_node, hash_int(header, 0), &all_fields) {
        if (f->header == header) {
            return f->mf;
        }
    }

    return NULL;
}

/* Returns true if 'wc' wildcards all the bits in field 'mf', false if 'wc'
 * specifies at least one bit in the field.
 *
 * The caller is responsible for ensuring that 'wc' corresponds to a flow that
 * meets 'mf''s prerequisites. */
bool
mf_is_all_wild(const struct mf_field *mf, const struct flow_wildcards *wc)
{
    switch (mf->id) {
    case MFF_TUN_ID:
    case MFF_TUN_SRC:
    case MFF_TUN_DST:
    case MFF_TUN_TOS:
    case MFF_TUN_TTL:
    case MFF_TUN_FLAGS:
        return !wc->masks.tunnel.tun_id;
    case MFF_METADATA:
        return !wc->masks.metadata;
    case MFF_IN_PORT:
        return !wc->masks.in_port;
    case MFF_SKB_PRIORITY:
        return !wc->masks.skb_priority;
    case MFF_SKB_MARK:
        return !wc->masks.skb_mark;
    CASE_MFF_REGS:
        return !wc->masks.regs[mf->id - MFF_REG0];

    case MFF_ETH_SRC:
        return eth_addr_is_zero(wc->masks.dl_src);
    case MFF_ETH_DST:
        return eth_addr_is_zero(wc->masks.dl_dst);
    case MFF_ETH_TYPE:
        return !wc->masks.dl_type;

    case MFF_ARP_SHA:
    case MFF_ND_SLL:
        return eth_addr_is_zero(wc->masks.arp_sha);

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        return eth_addr_is_zero(wc->masks.arp_tha);

    case MFF_VLAN_TCI:
        return !wc->masks.vlan_tci;
    case MFF_DL_VLAN:
        return !(wc->masks.vlan_tci & htons(VLAN_VID_MASK));
    case MFF_VLAN_VID:
        return !(wc->masks.vlan_tci & htons(VLAN_VID_MASK | VLAN_CFI));
    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
        return !(wc->masks.vlan_tci & htons(VLAN_PCP_MASK));

    case MFF_IPV4_SRC:
        return !wc->masks.nw_src;
    case MFF_IPV4_DST:
        return !wc->masks.nw_dst;

    case MFF_IPV6_SRC:
        return ipv6_mask_is_any(&wc->masks.ipv6_src);
    case MFF_IPV6_DST:
        return ipv6_mask_is_any(&wc->masks.ipv6_dst);

    case MFF_IPV6_LABEL:
        return !wc->masks.ipv6_label;

    case MFF_IP_PROTO:
        return !wc->masks.nw_proto;
    case MFF_IP_DSCP:
        return !(wc->masks.nw_tos & IP_DSCP_MASK);
    case MFF_IP_ECN:
        return !(wc->masks.nw_tos & IP_ECN_MASK);
    case MFF_IP_TTL:
        return !wc->masks.nw_ttl;

    case MFF_ND_TARGET:
        return ipv6_mask_is_any(&wc->masks.nd_target);

    case MFF_IP_FRAG:
        return !(wc->masks.nw_frag & FLOW_NW_FRAG_MASK);

    case MFF_ARP_OP:
        return !wc->masks.nw_proto;
    case MFF_ARP_SPA:
        return !wc->masks.nw_src;
    case MFF_ARP_TPA:
        return !wc->masks.nw_dst;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV6_TYPE:
        return !wc->masks.tp_src;
    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_CODE:
        return !wc->masks.tp_dst;

    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }
}

/* Initializes 'mask' with the wildcard bit pattern for field 'mf' within 'wc'.
 * Each bit in 'mask' will be set to 1 if the bit is significant for matching
 * purposes, or to 0 if it is wildcarded.
 *
 * The caller is responsible for ensuring that 'wc' corresponds to a flow that
 * meets 'mf''s prerequisites. */
void
mf_get_mask(const struct mf_field *mf, const struct flow_wildcards *wc,
            union mf_value *mask)
{
    mf_get_value(mf, &wc->masks, mask);
}

/* Tests whether 'mask' is a valid wildcard bit pattern for 'mf'.  Returns true
 * if the mask is valid, false otherwise. */
bool
mf_is_mask_valid(const struct mf_field *mf, const union mf_value *mask)
{
    switch (mf->maskable) {
    case MFM_NONE:
        return (is_all_zeros((const uint8_t *) mask, mf->n_bytes) ||
                is_all_ones((const uint8_t *) mask, mf->n_bytes));

    case MFM_FULLY:
        return true;
    }

    NOT_REACHED();
}

static bool
is_ip_any(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_IP) ||
            flow->dl_type == htons(ETH_TYPE_IPV6));
}

static bool
is_icmpv4(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IPPROTO_ICMP);
}

static bool
is_icmpv6(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_IPV6)
            && flow->nw_proto == IPPROTO_ICMPV6);
}

/* Returns true if 'flow' meets the prerequisites for 'mf', false otherwise. */
bool
mf_are_prereqs_ok(const struct mf_field *mf, const struct flow *flow)
{
    switch (mf->prereqs) {
    case MFP_NONE:
        return true;

    case MFP_ARP:
      return (flow->dl_type == htons(ETH_TYPE_ARP) ||
              flow->dl_type == htons(ETH_TYPE_RARP));
    case MFP_IPV4:
        return flow->dl_type == htons(ETH_TYPE_IP);
    case MFP_IPV6:
        return flow->dl_type == htons(ETH_TYPE_IPV6);
    case MFP_VLAN_VID:
        return (flow->vlan_tci & htons(VLAN_CFI)) != 0;
    case MFP_IP_ANY:
        return is_ip_any(flow);

    case MFP_TCP:
        return is_ip_any(flow) && flow->nw_proto == IPPROTO_TCP;
    case MFP_UDP:
        return is_ip_any(flow) && flow->nw_proto == IPPROTO_UDP;
    case MFP_ICMPV4:
        return is_icmpv4(flow);
    case MFP_ICMPV6:
        return is_icmpv6(flow);

    case MFP_ND:
        return (is_icmpv6(flow)
                && flow->tp_dst == htons(0)
                && (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT) ||
                    flow->tp_src == htons(ND_NEIGHBOR_ADVERT)));
    case MFP_ND_SOLICIT:
        return (is_icmpv6(flow)
                && flow->tp_dst == htons(0)
                && (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT)));
    case MFP_ND_ADVERT:
        return (is_icmpv6(flow)
                && flow->tp_dst == htons(0)
                && (flow->tp_src == htons(ND_NEIGHBOR_ADVERT)));
    }

    NOT_REACHED();
}

/* Returns true if 'value' may be a valid value *as part of a masked match*,
 * false otherwise.
 *
 * A value is not rejected just because it is not valid for the field in
 * question, but only if it doesn't make sense to test the bits in question at
 * all.  For example, the MFF_VLAN_TCI field will never have a nonzero value
 * without the VLAN_CFI bit being set, but we can't reject those values because
 * it is still legitimate to test just for those bits (see the documentation
 * for NXM_OF_VLAN_TCI in nicira-ext.h).  On the other hand, there is never a
 * reason to set the low bit of MFF_IP_DSCP to 1, so we reject that. */
bool
mf_is_value_valid(const struct mf_field *mf, const union mf_value *value)
{
    switch (mf->id) {
    case MFF_TUN_ID:
    case MFF_TUN_SRC:
    case MFF_TUN_DST:
    case MFF_TUN_TOS:
    case MFF_TUN_TTL:
    case MFF_TUN_FLAGS:
    case MFF_METADATA:
    case MFF_IN_PORT:
    case MFF_SKB_PRIORITY:
    case MFF_SKB_MARK:
    CASE_MFF_REGS:
    case MFF_ETH_SRC:
    case MFF_ETH_DST:
    case MFF_ETH_TYPE:
    case MFF_VLAN_TCI:
    case MFF_IPV4_SRC:
    case MFF_IPV4_DST:
    case MFF_IPV6_SRC:
    case MFF_IPV6_DST:
    case MFF_IP_PROTO:
    case MFF_IP_TTL:
    case MFF_ARP_SPA:
    case MFF_ARP_TPA:
    case MFF_ARP_SHA:
    case MFF_ARP_THA:
    case MFF_TCP_SRC:
    case MFF_TCP_DST:
    case MFF_UDP_SRC:
    case MFF_UDP_DST:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
    case MFF_ND_TARGET:
    case MFF_ND_SLL:
    case MFF_ND_TLL:
        return true;

    case MFF_IP_DSCP:
        return !(value->u8 & ~IP_DSCP_MASK);
    case MFF_IP_ECN:
        return !(value->u8 & ~IP_ECN_MASK);
    case MFF_IP_FRAG:
        return !(value->u8 & ~FLOW_NW_FRAG_MASK);

    case MFF_ARP_OP:
        return !(value->be16 & htons(0xff00));

    case MFF_DL_VLAN:
        return !(value->be16 & htons(VLAN_CFI | VLAN_PCP_MASK));
    case MFF_VLAN_VID:
        return !(value->be16 & htons(VLAN_PCP_MASK));

    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
        return !(value->u8 & ~(VLAN_PCP_MASK >> VLAN_PCP_SHIFT));

    case MFF_IPV6_LABEL:
        return !(value->be32 & ~htonl(IPV6_LABEL_MASK));

    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }
}

/* Copies the value of field 'mf' from 'flow' into 'value'.  The caller is
 * responsible for ensuring that 'flow' meets 'mf''s prerequisites. */
void
mf_get_value(const struct mf_field *mf, const struct flow *flow,
             union mf_value *value)
{
    switch (mf->id) {
    case MFF_TUN_ID:
        value->be64 = flow->tunnel.tun_id;
        break;
    case MFF_TUN_SRC:
        value->be32 = flow->tunnel.ip_src;
        break;
    case MFF_TUN_DST:
        value->be32 = flow->tunnel.ip_dst;
        break;
    case MFF_TUN_FLAGS:
        value->be16 = htons(flow->tunnel.flags);
        break;
    case MFF_TUN_TTL:
        value->u8 = flow->tunnel.ip_ttl;
        break;
    case MFF_TUN_TOS:
        value->u8 = flow->tunnel.ip_tos;
        break;

    case MFF_METADATA:
        value->be64 = flow->metadata;
        break;

    case MFF_IN_PORT:
        value->be16 = htons(flow->in_port);
        break;

    case MFF_SKB_PRIORITY:
        value->be32 = htonl(flow->skb_priority);
        break;

    case MFF_SKB_MARK:
        value->be32 = htonl(flow->skb_mark);
        break;

    CASE_MFF_REGS:
        value->be32 = htonl(flow->regs[mf->id - MFF_REG0]);
        break;

    case MFF_ETH_SRC:
        memcpy(value->mac, flow->dl_src, ETH_ADDR_LEN);
        break;

    case MFF_ETH_DST:
        memcpy(value->mac, flow->dl_dst, ETH_ADDR_LEN);
        break;

    case MFF_ETH_TYPE:
        value->be16 = flow->dl_type;
        break;

    case MFF_VLAN_TCI:
        value->be16 = flow->vlan_tci;
        break;

    case MFF_DL_VLAN:
        value->be16 = flow->vlan_tci & htons(VLAN_VID_MASK);
        break;
    case MFF_VLAN_VID:
        value->be16 = flow->vlan_tci & htons(VLAN_VID_MASK | VLAN_CFI);
        break;

    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
        value->u8 = vlan_tci_to_pcp(flow->vlan_tci);
        break;

    case MFF_IPV4_SRC:
        value->be32 = flow->nw_src;
        break;

    case MFF_IPV4_DST:
        value->be32 = flow->nw_dst;
        break;

    case MFF_IPV6_SRC:
        value->ipv6 = flow->ipv6_src;
        break;

    case MFF_IPV6_DST:
        value->ipv6 = flow->ipv6_dst;
        break;

    case MFF_IPV6_LABEL:
        value->be32 = flow->ipv6_label;
        break;

    case MFF_IP_PROTO:
        value->u8 = flow->nw_proto;
        break;

    case MFF_IP_DSCP:
        value->u8 = flow->nw_tos & IP_DSCP_MASK;
        break;

    case MFF_IP_ECN:
        value->u8 = flow->nw_tos & IP_ECN_MASK;
        break;

    case MFF_IP_TTL:
        value->u8 = flow->nw_ttl;
        break;

    case MFF_IP_FRAG:
        value->u8 = flow->nw_frag;
        break;

    case MFF_ARP_OP:
        value->be16 = htons(flow->nw_proto);
        break;

    case MFF_ARP_SPA:
        value->be32 = flow->nw_src;
        break;

    case MFF_ARP_TPA:
        value->be32 = flow->nw_dst;
        break;

    case MFF_ARP_SHA:
    case MFF_ND_SLL:
        memcpy(value->mac, flow->arp_sha, ETH_ADDR_LEN);
        break;

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        memcpy(value->mac, flow->arp_tha, ETH_ADDR_LEN);
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
        value->be16 = flow->tp_src;
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
        value->be16 = flow->tp_dst;
        break;

    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV6_TYPE:
        value->u8 = ntohs(flow->tp_src);
        break;

    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_CODE:
        value->u8 = ntohs(flow->tp_dst);
        break;

    case MFF_ND_TARGET:
        value->ipv6 = flow->nd_target;
        break;

    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }
}

/* Makes 'match' match field 'mf' exactly, with the value matched taken from
 * 'value'.  The caller is responsible for ensuring that 'match' meets 'mf''s
 * prerequisites. */
void
mf_set_value(const struct mf_field *mf,
             const union mf_value *value, struct match *match)
{
    switch (mf->id) {
    case MFF_TUN_ID:
        match_set_tun_id(match, value->be64);
        break;
    case MFF_TUN_SRC:
        match_set_tun_src(match, value->be32);
        break;
    case MFF_TUN_DST:
        match_set_tun_dst(match, value->be32);
        break;
    case MFF_TUN_FLAGS:
        match_set_tun_flags(match, ntohs(value->be16));
        break;
    case MFF_TUN_TOS:
        match_set_tun_tos(match, value->u8);
        break;
    case MFF_TUN_TTL:
        match_set_tun_ttl(match, value->u8);
        break;

    case MFF_METADATA:
        match_set_metadata(match, value->be64);
        break;

    case MFF_IN_PORT:
        match_set_in_port(match, ntohs(value->be16));
        break;

    case MFF_SKB_PRIORITY:
        match_set_skb_priority(match, ntohl(value->be32));
        break;

    case MFF_SKB_MARK:
        match_set_skb_mark(match, ntohl(value->be32));
        break;

    CASE_MFF_REGS:
        match_set_reg(match, mf->id - MFF_REG0, ntohl(value->be32));
        break;

    case MFF_ETH_SRC:
        match_set_dl_src(match, value->mac);
        break;

    case MFF_ETH_DST:
        match_set_dl_dst(match, value->mac);
        break;

    case MFF_ETH_TYPE:
        match_set_dl_type(match, value->be16);
        break;

    case MFF_VLAN_TCI:
        match_set_dl_tci(match, value->be16);
        break;

    case MFF_DL_VLAN:
        match_set_dl_vlan(match, value->be16);
        break;
    case MFF_VLAN_VID:
        match_set_vlan_vid(match, value->be16);
        break;

    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
        match_set_dl_vlan_pcp(match, value->u8);
        break;

    case MFF_IPV4_SRC:
        match_set_nw_src(match, value->be32);
        break;

    case MFF_IPV4_DST:
        match_set_nw_dst(match, value->be32);
        break;

    case MFF_IPV6_SRC:
        match_set_ipv6_src(match, &value->ipv6);
        break;

    case MFF_IPV6_DST:
        match_set_ipv6_dst(match, &value->ipv6);
        break;

    case MFF_IPV6_LABEL:
        match_set_ipv6_label(match, value->be32);
        break;

    case MFF_IP_PROTO:
        match_set_nw_proto(match, value->u8);
        break;

    case MFF_IP_DSCP:
        match_set_nw_dscp(match, value->u8);
        break;

    case MFF_IP_ECN:
        match_set_nw_ecn(match, value->u8);
        break;

    case MFF_IP_TTL:
        match_set_nw_ttl(match, value->u8);
        break;

    case MFF_IP_FRAG:
        match_set_nw_frag(match, value->u8);
        break;

    case MFF_ARP_OP:
        match_set_nw_proto(match, ntohs(value->be16));
        break;

    case MFF_ARP_SPA:
        match_set_nw_src(match, value->be32);
        break;

    case MFF_ARP_TPA:
        match_set_nw_dst(match, value->be32);
        break;

    case MFF_ARP_SHA:
    case MFF_ND_SLL:
        match_set_arp_sha(match, value->mac);
        break;

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        match_set_arp_tha(match, value->mac);
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
        match_set_tp_src(match, value->be16);
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
        match_set_tp_dst(match, value->be16);
        break;

    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV6_TYPE:
        match_set_icmp_type(match, value->u8);
        break;

    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_CODE:
        match_set_icmp_code(match, value->u8);
        break;

    case MFF_ND_TARGET:
        match_set_nd_target(match, &value->ipv6);
        break;

    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }
}

/* Makes 'match' match field 'mf' exactly, with the value matched taken from
 * 'value'.  The caller is responsible for ensuring that 'match' meets 'mf''s
 * prerequisites. */
void
mf_set_flow_value(const struct mf_field *mf,
                  const union mf_value *value, struct flow *flow)
{
    switch (mf->id) {
    case MFF_TUN_ID:
        flow->tunnel.tun_id = value->be64;
        break;
    case MFF_TUN_SRC:
        flow->tunnel.ip_src = value->be32;
        break;
    case MFF_TUN_DST:
        flow->tunnel.ip_dst = value->be32;
        break;
    case MFF_TUN_FLAGS:
        flow->tunnel.flags = ntohs(value->be16);
        break;
    case MFF_TUN_TOS:
        flow->tunnel.ip_tos = value->u8;
        break;
    case MFF_TUN_TTL:
        flow->tunnel.ip_ttl = value->u8;
        break;

    case MFF_METADATA:
        flow->metadata = value->be64;
        break;

    case MFF_IN_PORT:
        flow->in_port = ntohs(value->be16);
        break;

    case MFF_SKB_PRIORITY:
        flow->skb_priority = ntohl(value->be32);
        break;

    case MFF_SKB_MARK:
        flow->skb_mark = ntohl(value->be32);
        break;

    CASE_MFF_REGS:
        flow->regs[mf->id - MFF_REG0] = ntohl(value->be32);
        break;

    case MFF_ETH_SRC:
        memcpy(flow->dl_src, value->mac, ETH_ADDR_LEN);
        break;

    case MFF_ETH_DST:
        memcpy(flow->dl_dst, value->mac, ETH_ADDR_LEN);
        break;

    case MFF_ETH_TYPE:
        flow->dl_type = value->be16;
        break;

    case MFF_VLAN_TCI:
        flow->vlan_tci = value->be16;
        break;

    case MFF_DL_VLAN:
        flow_set_dl_vlan(flow, value->be16);
        break;
    case MFF_VLAN_VID:
        flow_set_vlan_vid(flow, value->be16);
        break;

    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
        flow_set_vlan_pcp(flow, value->u8);
        break;

    case MFF_IPV4_SRC:
        flow->nw_src = value->be32;
        break;

    case MFF_IPV4_DST:
        flow->nw_dst = value->be32;
        break;

    case MFF_IPV6_SRC:
        flow->ipv6_src = value->ipv6;
        break;

    case MFF_IPV6_DST:
        flow->ipv6_dst = value->ipv6;
        break;

    case MFF_IPV6_LABEL:
        flow->ipv6_label = value->be32 & ~htonl(IPV6_LABEL_MASK);
        break;

    case MFF_IP_PROTO:
        flow->nw_proto = value->u8;
        break;

    case MFF_IP_DSCP:
        flow->nw_tos &= ~IP_DSCP_MASK;
        flow->nw_tos |= value->u8 & IP_DSCP_MASK;
        break;

    case MFF_IP_ECN:
        flow->nw_tos &= ~IP_ECN_MASK;
        flow->nw_tos |= value->u8 & IP_ECN_MASK;
        break;

    case MFF_IP_TTL:
        flow->nw_ttl = value->u8;
        break;

    case MFF_IP_FRAG:
        flow->nw_frag &= value->u8;
        break;

    case MFF_ARP_OP:
        flow->nw_proto = ntohs(value->be16);
        break;

    case MFF_ARP_SPA:
        flow->nw_src = value->be32;
        break;

    case MFF_ARP_TPA:
        flow->nw_dst = value->be32;
        break;

    case MFF_ARP_SHA:
    case MFF_ND_SLL:
        memcpy(flow->arp_sha, value->mac, ETH_ADDR_LEN);
        break;

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        memcpy(flow->arp_tha, value->mac, ETH_ADDR_LEN);
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
        flow->tp_src = value->be16;
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
        flow->tp_dst = value->be16;
        break;

    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV6_TYPE:
        flow->tp_src = htons(value->u8);
        break;

    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_CODE:
        flow->tp_dst = htons(value->u8);
        break;

    case MFF_ND_TARGET:
        flow->nd_target = value->ipv6;
        break;

    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }
}

/* Returns true if 'mf' has a zero value in 'flow', false if it is nonzero.
 *
 * The caller is responsible for ensuring that 'flow' meets 'mf''s
 * prerequisites. */
bool
mf_is_zero(const struct mf_field *mf, const struct flow *flow)
{
    union mf_value value;

    mf_get_value(mf, flow, &value);
    return is_all_zeros((const uint8_t *) &value, mf->n_bytes);
}

/* Makes 'match' wildcard field 'mf'.
 *
 * The caller is responsible for ensuring that 'match' meets 'mf''s
 * prerequisites. */
void
mf_set_wild(const struct mf_field *mf, struct match *match)
{
    switch (mf->id) {
    case MFF_TUN_ID:
        match_set_tun_id_masked(match, htonll(0), htonll(0));
        break;
    case MFF_TUN_SRC:
        match_set_tun_src_masked(match, htonl(0), htonl(0));
        break;
    case MFF_TUN_DST:
        match_set_tun_dst_masked(match, htonl(0), htonl(0));
        break;
    case MFF_TUN_FLAGS:
        match_set_tun_flags_masked(match, 0, 0);
        break;
    case MFF_TUN_TOS:
        match_set_tun_tos_masked(match, 0, 0);
        break;
    case MFF_TUN_TTL:
        match_set_tun_ttl_masked(match, 0, 0);
        break;

    case MFF_METADATA:
        match_set_metadata_masked(match, htonll(0), htonll(0));
        break;

    case MFF_IN_PORT:
        match->flow.in_port = 0;
        match->wc.masks.in_port = 0;
        break;

    case MFF_SKB_PRIORITY:
        match->flow.skb_priority = 0;
        match->wc.masks.skb_priority = 0;
        break;

    case MFF_SKB_MARK:
        match->flow.skb_mark = 0;
        match->wc.masks.skb_mark = 0;
        break;

    CASE_MFF_REGS:
        match_set_reg_masked(match, mf->id - MFF_REG0, 0, 0);
        break;

    case MFF_ETH_SRC:
        memset(match->flow.dl_src, 0, ETH_ADDR_LEN);
        memset(match->wc.masks.dl_src, 0, ETH_ADDR_LEN);
        break;

    case MFF_ETH_DST:
        memset(match->flow.dl_dst, 0, ETH_ADDR_LEN);
        memset(match->wc.masks.dl_dst, 0, ETH_ADDR_LEN);
        break;

    case MFF_ETH_TYPE:
        match->flow.dl_type = htons(0);
        match->wc.masks.dl_type = htons(0);
        break;

    case MFF_VLAN_TCI:
        match_set_dl_tci_masked(match, htons(0), htons(0));
        break;

    case MFF_DL_VLAN:
    case MFF_VLAN_VID:
        match_set_any_vid(match);
        break;

    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
        match_set_any_pcp(match);
        break;

    case MFF_IPV4_SRC:
    case MFF_ARP_SPA:
        match_set_nw_src_masked(match, htonl(0), htonl(0));
        break;

    case MFF_IPV4_DST:
    case MFF_ARP_TPA:
        match_set_nw_dst_masked(match, htonl(0), htonl(0));
        break;

    case MFF_IPV6_SRC:
        memset(&match->wc.masks.ipv6_src, 0, sizeof match->wc.masks.ipv6_src);
        memset(&match->flow.ipv6_src, 0, sizeof match->flow.ipv6_src);
        break;

    case MFF_IPV6_DST:
        memset(&match->wc.masks.ipv6_dst, 0, sizeof match->wc.masks.ipv6_dst);
        memset(&match->flow.ipv6_dst, 0, sizeof match->flow.ipv6_dst);
        break;

    case MFF_IPV6_LABEL:
        match->wc.masks.ipv6_label = htonl(0);
        match->flow.ipv6_label = htonl(0);
        break;

    case MFF_IP_PROTO:
        match->wc.masks.nw_proto = 0;
        match->flow.nw_proto = 0;
        break;

    case MFF_IP_DSCP:
        match->wc.masks.nw_tos &= ~IP_DSCP_MASK;
        match->flow.nw_tos &= ~IP_DSCP_MASK;
        break;

    case MFF_IP_ECN:
        match->wc.masks.nw_tos &= ~IP_ECN_MASK;
        match->flow.nw_tos &= ~IP_ECN_MASK;
        break;

    case MFF_IP_TTL:
        match->wc.masks.nw_ttl = 0;
        match->flow.nw_ttl = 0;
        break;

    case MFF_IP_FRAG:
        match->wc.masks.nw_frag |= FLOW_NW_FRAG_MASK;
        match->flow.nw_frag &= ~FLOW_NW_FRAG_MASK;
        break;

    case MFF_ARP_OP:
        match->wc.masks.nw_proto = 0;
        match->flow.nw_proto = 0;
        break;

    case MFF_ARP_SHA:
    case MFF_ND_SLL:
        memset(match->flow.arp_sha, 0, ETH_ADDR_LEN);
        memset(match->wc.masks.arp_sha, 0, ETH_ADDR_LEN);
        break;

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        memset(match->flow.arp_tha, 0, ETH_ADDR_LEN);
        memset(match->wc.masks.arp_tha, 0, ETH_ADDR_LEN);
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV6_TYPE:
        match->wc.masks.tp_src = htons(0);
        match->flow.tp_src = htons(0);
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_CODE:
        match->wc.masks.tp_dst = htons(0);
        match->flow.tp_dst = htons(0);
        break;

    case MFF_ND_TARGET:
        memset(&match->wc.masks.nd_target, 0,
               sizeof match->wc.masks.nd_target);
        memset(&match->flow.nd_target, 0, sizeof match->flow.nd_target);
        break;

    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }
}

/* Makes 'match' match field 'mf' with the specified 'value' and 'mask'.
 * 'value' specifies a value to match and 'mask' specifies a wildcard pattern,
 * with a 1-bit indicating that the corresponding value bit must match and a
 * 0-bit indicating a don't-care.
 *
 * If 'mask' is NULL or points to all-1-bits, then this call is equivalent to
 * mf_set_value(mf, value, match).  If 'mask' points to all-0-bits, then this
 * call is equivalent to mf_set_wild(mf, match).
 *
 * 'mask' must be a valid mask for 'mf' (see mf_is_mask_valid()).  The caller
 * is responsible for ensuring that 'match' meets 'mf''s prerequisites. */
void
mf_set(const struct mf_field *mf,
       const union mf_value *value, const union mf_value *mask,
       struct match *match)
{
    if (!mask || is_all_ones((const uint8_t *) mask, mf->n_bytes)) {
        mf_set_value(mf, value, match);
        return;
    } else if (is_all_zeros((const uint8_t *) mask, mf->n_bytes)) {
        mf_set_wild(mf, match);
        return;
    }

    switch (mf->id) {
    case MFF_IN_PORT:
    case MFF_SKB_MARK:
    case MFF_SKB_PRIORITY:
    case MFF_ETH_TYPE:
    case MFF_DL_VLAN:
    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
    case MFF_IP_PROTO:
    case MFF_IP_TTL:
    case MFF_IP_DSCP:
    case MFF_IP_ECN:
    case MFF_ARP_OP:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
        NOT_REACHED();

    case MFF_TUN_ID:
        match_set_tun_id_masked(match, value->be64, mask->be64);
        break;
    case MFF_TUN_SRC:
        match_set_tun_src_masked(match, value->be32, mask->be32);
        break;
    case MFF_TUN_DST:
        match_set_tun_dst_masked(match, value->be32, mask->be32);
        break;
    case MFF_TUN_FLAGS:
        match_set_tun_flags_masked(match, ntohs(value->be16), ntohs(mask->be16));
        break;
    case MFF_TUN_TTL:
        match_set_tun_ttl_masked(match, value->u8, mask->u8);
        break;
    case MFF_TUN_TOS:
        match_set_tun_tos_masked(match, value->u8, mask->u8);
        break;

    case MFF_METADATA:
        match_set_metadata_masked(match, value->be64, mask->be64);
        break;

    CASE_MFF_REGS:
        match_set_reg_masked(match, mf->id - MFF_REG0,
                             ntohl(value->be32), ntohl(mask->be32));
        break;

    case MFF_ETH_DST:
        match_set_dl_dst_masked(match, value->mac, mask->mac);
        break;

    case MFF_ETH_SRC:
        match_set_dl_src_masked(match, value->mac, mask->mac);
        break;

    case MFF_ARP_SHA:
    case MFF_ND_SLL:
        match_set_arp_sha_masked(match, value->mac, mask->mac);
        break;

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        match_set_arp_tha_masked(match, value->mac, mask->mac);
        break;

    case MFF_VLAN_TCI:
        match_set_dl_tci_masked(match, value->be16, mask->be16);
        break;

    case MFF_VLAN_VID:
        match_set_vlan_vid_masked(match, value->be16, mask->be16);
        break;

    case MFF_IPV4_SRC:
        match_set_nw_src_masked(match, value->be32, mask->be32);
        break;

    case MFF_IPV4_DST:
        match_set_nw_dst_masked(match, value->be32, mask->be32);
        break;

    case MFF_IPV6_SRC:
        match_set_ipv6_src_masked(match, &value->ipv6, &mask->ipv6);
        break;

    case MFF_IPV6_DST:
        match_set_ipv6_dst_masked(match, &value->ipv6, &mask->ipv6);
        break;

    case MFF_IPV6_LABEL:
        if ((mask->be32 & htonl(IPV6_LABEL_MASK)) == htonl(IPV6_LABEL_MASK)) {
            mf_set_value(mf, value, match);
        } else {
            match_set_ipv6_label_masked(match, value->be32, mask->be32);
        }
        break;

    case MFF_ND_TARGET:
        match_set_nd_target_masked(match, &value->ipv6, &mask->ipv6);
        break;

    case MFF_IP_FRAG:
        match_set_nw_frag_masked(match, value->u8, mask->u8);
        break;

    case MFF_ARP_SPA:
        match_set_nw_src_masked(match, value->be32, mask->be32);
        break;

    case MFF_ARP_TPA:
        match_set_nw_dst_masked(match, value->be32, mask->be32);
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
        match_set_tp_src_masked(match, value->be16, mask->be16);
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
        match_set_tp_dst_masked(match, value->be16, mask->be16);
        break;

    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }
}

static enum ofperr
mf_check__(const struct mf_subfield *sf, const struct flow *flow,
           const char *type)
{
    if (!sf->field) {
        VLOG_WARN_RL(&rl, "unknown %s field", type);
    } else if (!sf->n_bits) {
        VLOG_WARN_RL(&rl, "zero bit %s field %s", type, sf->field->name);
    } else if (sf->ofs >= sf->field->n_bits) {
        VLOG_WARN_RL(&rl, "bit offset %d exceeds %d-bit width of %s field %s",
                     sf->ofs, sf->field->n_bits, type, sf->field->name);
    } else if (sf->ofs + sf->n_bits > sf->field->n_bits) {
        VLOG_WARN_RL(&rl, "bit offset %d and width %d exceeds %d-bit width "
                     "of %s field %s", sf->ofs, sf->n_bits,
                     sf->field->n_bits, type, sf->field->name);
    } else if (flow && !mf_are_prereqs_ok(sf->field, flow)) {
        VLOG_WARN_RL(&rl, "%s field %s lacks correct prerequisites",
                     type, sf->field->name);
    } else {
        return 0;
    }

    return OFPERR_OFPBAC_BAD_ARGUMENT;
}

/* Checks whether 'sf' is valid for reading a subfield out of 'flow'.  Returns
 * 0 if so, otherwise an OpenFlow error code (e.g. as returned by
 * ofp_mkerr()).  */
enum ofperr
mf_check_src(const struct mf_subfield *sf, const struct flow *flow)
{
    return mf_check__(sf, flow, "source");
}

/* Checks whether 'sf' is valid for writing a subfield into 'flow'.  Returns 0
 * if so, otherwise an OpenFlow error code (e.g. as returned by
 * ofp_mkerr()). */
enum ofperr
mf_check_dst(const struct mf_subfield *sf, const struct flow *flow)
{
    int error = mf_check__(sf, flow, "destination");
    if (!error && !sf->field->writable) {
        VLOG_WARN_RL(&rl, "destination field %s is not writable",
                     sf->field->name);
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    return error;
}

/* Copies the value and wildcard bit pattern for 'mf' from 'match' into the
 * 'value' and 'mask', respectively. */
void
mf_get(const struct mf_field *mf, const struct match *match,
       union mf_value *value, union mf_value *mask)
{
    mf_get_value(mf, &match->flow, value);
    mf_get_mask(mf, &match->wc, mask);
}

/* Assigns a random value for field 'mf' to 'value'. */
void
mf_random_value(const struct mf_field *mf, union mf_value *value)
{
    random_bytes(value, mf->n_bytes);

    switch (mf->id) {
    case MFF_TUN_ID:
    case MFF_TUN_SRC:
    case MFF_TUN_DST:
    case MFF_TUN_TOS:
    case MFF_TUN_TTL:
    case MFF_TUN_FLAGS:
    case MFF_METADATA:
    case MFF_IN_PORT:
    case MFF_SKB_MARK:
    case MFF_SKB_PRIORITY:
    CASE_MFF_REGS:
    case MFF_ETH_SRC:
    case MFF_ETH_DST:
    case MFF_ETH_TYPE:
    case MFF_VLAN_TCI:
    case MFF_IPV4_SRC:
    case MFF_IPV4_DST:
    case MFF_IPV6_SRC:
    case MFF_IPV6_DST:
    case MFF_IP_PROTO:
    case MFF_IP_TTL:
    case MFF_ARP_SPA:
    case MFF_ARP_TPA:
    case MFF_ARP_SHA:
    case MFF_ARP_THA:
    case MFF_TCP_SRC:
    case MFF_TCP_DST:
    case MFF_UDP_SRC:
    case MFF_UDP_DST:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
    case MFF_ND_TARGET:
    case MFF_ND_SLL:
    case MFF_ND_TLL:
        break;

    case MFF_IPV6_LABEL:
        value->be32 &= ~htonl(IPV6_LABEL_MASK);
        break;

    case MFF_IP_DSCP:
        value->u8 &= IP_DSCP_MASK;
        break;

    case MFF_IP_ECN:
        value->u8 &= IP_ECN_MASK;
        break;

    case MFF_IP_FRAG:
        value->u8 &= FLOW_NW_FRAG_MASK;
        break;

    case MFF_ARP_OP:
        value->be16 &= htons(0xff);
        break;

    case MFF_DL_VLAN:
        value->be16 &= htons(VLAN_VID_MASK);
        break;
    case MFF_VLAN_VID:
        value->be16 &= htons(VLAN_VID_MASK | VLAN_CFI);
        break;

    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
        value->u8 &= 0x07;
        break;

    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }
}

static char *
mf_from_integer_string(const struct mf_field *mf, const char *s,
                       uint8_t *valuep, uint8_t *maskp)
{
    unsigned long long int integer, mask;
    char *tail;
    int i;

    errno = 0;
    integer = strtoull(s, &tail, 0);
    if (errno || (*tail != '\0' && *tail != '/')) {
        goto syntax_error;
    }

    if (*tail == '/') {
        mask = strtoull(tail + 1, &tail, 0);
        if (errno || *tail != '\0') {
            goto syntax_error;
        }
    } else {
        mask = ULLONG_MAX;
    }

    for (i = mf->n_bytes - 1; i >= 0; i--) {
        valuep[i] = integer;
        maskp[i] = mask;
        integer >>= 8;
        mask >>= 8;
    }
    if (integer) {
        return xasprintf("%s: value too large for %u-byte field %s",
                         s, mf->n_bytes, mf->name);
    }
    return NULL;

syntax_error:
    return xasprintf("%s: bad syntax for %s", s, mf->name);
}

static char *
mf_from_ethernet_string(const struct mf_field *mf, const char *s,
                        uint8_t mac[ETH_ADDR_LEN],
                        uint8_t mask[ETH_ADDR_LEN])
{
    assert(mf->n_bytes == ETH_ADDR_LEN);

    switch (sscanf(s, ETH_ADDR_SCAN_FMT"/"ETH_ADDR_SCAN_FMT,
                   ETH_ADDR_SCAN_ARGS(mac), ETH_ADDR_SCAN_ARGS(mask))){
    case ETH_ADDR_SCAN_COUNT * 2:
        return NULL;

    case ETH_ADDR_SCAN_COUNT:
        memset(mask, 0xff, ETH_ADDR_LEN);
        return NULL;

    default:
        return xasprintf("%s: invalid Ethernet address", s);
    }
}

static char *
mf_from_ipv4_string(const struct mf_field *mf, const char *s,
                    ovs_be32 *ip, ovs_be32 *mask)
{
    int prefix;

    assert(mf->n_bytes == sizeof *ip);

    if (sscanf(s, IP_SCAN_FMT"/"IP_SCAN_FMT,
               IP_SCAN_ARGS(ip), IP_SCAN_ARGS(mask)) == IP_SCAN_COUNT * 2) {
        /* OK. */
    } else if (sscanf(s, IP_SCAN_FMT"/%d",
                      IP_SCAN_ARGS(ip), &prefix) == IP_SCAN_COUNT + 1) {
        if (prefix <= 0 || prefix > 32) {
            return xasprintf("%s: network prefix bits not between 1 and "
                             "32", s);
        } else if (prefix == 32) {
            *mask = htonl(UINT32_MAX);
        } else {
            *mask = htonl(((1u << prefix) - 1) << (32 - prefix));
        }
    } else if (sscanf(s, IP_SCAN_FMT, IP_SCAN_ARGS(ip)) == IP_SCAN_COUNT) {
        *mask = htonl(UINT32_MAX);
    } else {
        return xasprintf("%s: invalid IP address", s);
    }
    return NULL;
}

static char *
mf_from_ipv6_string(const struct mf_field *mf, const char *s,
                    struct in6_addr *value, struct in6_addr *mask)
{
    char *str = xstrdup(s);
    char *save_ptr = NULL;
    const char *name, *netmask;
    int retval;

    assert(mf->n_bytes == sizeof *value);

    name = strtok_r(str, "/", &save_ptr);
    retval = name ? lookup_ipv6(name, value) : EINVAL;
    if (retval) {
        char *err;

        err = xasprintf("%s: could not convert to IPv6 address", str);
        free(str);

        return err;
    }

    netmask = strtok_r(NULL, "/", &save_ptr);
    if (netmask) {
        if (inet_pton(AF_INET6, netmask, mask) != 1) {
            int prefix = atoi(netmask);
            if (prefix <= 0 || prefix > 128) {
                free(str);
                return xasprintf("%s: prefix bits not between 1 and 128", s);
            } else {
                *mask = ipv6_create_mask(prefix);
            }
        }
    } else {
        *mask = in6addr_exact;
    }
    free(str);

    return NULL;
}

static char *
mf_from_ofp_port_string(const struct mf_field *mf, const char *s,
                        ovs_be16 *valuep, ovs_be16 *maskp)
{
    uint16_t port;

    assert(mf->n_bytes == sizeof(ovs_be16));
    if (*s == '-') {
        return xasprintf("%s: negative values not supported for %s",
                         s, mf->name);
    } else if (ofputil_port_from_string(s, &port)) {
        *valuep = htons(port);
        *maskp = htons(UINT16_MAX);
        return NULL;
    } else {
        return mf_from_integer_string(mf, s,
                                      (uint8_t *) valuep, (uint8_t *) maskp);
    }
}

struct frag_handling {
    const char *name;
    uint8_t mask;
    uint8_t value;
};

static const struct frag_handling all_frags[] = {
#define A FLOW_NW_FRAG_ANY
#define L FLOW_NW_FRAG_LATER
    /* name               mask  value */

    { "no",               A|L,  0     },
    { "first",            A|L,  A     },
    { "later",            A|L,  A|L   },

    { "no",               A,    0     },
    { "yes",              A,    A     },

    { "not_later",        L,    0     },
    { "later",            L,    L     },
#undef A
#undef L
};

static char *
mf_from_frag_string(const char *s, uint8_t *valuep, uint8_t *maskp)
{
    const struct frag_handling *h;

    for (h = all_frags; h < &all_frags[ARRAY_SIZE(all_frags)]; h++) {
        if (!strcasecmp(s, h->name)) {
            /* We force the upper bits of the mask on to make mf_parse_value()
             * happy (otherwise it will never think it's an exact match.) */
            *maskp = h->mask | ~FLOW_NW_FRAG_MASK;
            *valuep = h->value;
            return NULL;
        }
    }

    return xasprintf("%s: unknown fragment type (valid types are \"no\", "
                     "\"yes\", \"first\", \"later\", \"not_first\"", s);
}

static int
parse_flow_tun_flags(const char *s_, const char *(*bit_to_string)(uint32_t),
                     ovs_be16 *res)
{
    uint32_t result = 0;
    char *save_ptr = NULL;
    char *name;
    int rc = 0;
    char *s = xstrdup(s_);

    for (name = strtok_r((char *)s, " |", &save_ptr); name;
         name = strtok_r(NULL, " |", &save_ptr)) {
        int name_len;
        unsigned long long int flags;
        uint32_t bit;
        int n0;

        if (sscanf(name, "%lli%n", &flags, &n0) > 0 && n0 > 0) {
            result |= flags;
            continue;
        }
        name_len = strlen(name);
        for (bit = 1; bit; bit <<= 1) {
            const char *fname = bit_to_string(bit);
            size_t len;

            if (!fname) {
                continue;
            }

            len = strlen(fname);
            if (len != name_len) {
                continue;
            }
            if (!strncmp(name, fname, len)) {
                result |= bit;
                break;
            }
        }

        if (!bit) {
            rc = -ENOENT;
            goto out;
        }
    }

    *res = htons(result);
out:
    free(s);
    return rc;
}

static char *
mf_from_tun_flags_string(const char *s, ovs_be16 *valuep, ovs_be16 *maskp)
{
    if (!parse_flow_tun_flags(s, flow_tun_flag_to_string, valuep)) {
        *maskp = htons(UINT16_MAX);
        return NULL;
    }

    return xasprintf("%s: unknown tunnel flags (valid flags are \"df\", "
                     "\"csum\", \"key\"", s);
}

/* Parses 's', a string value for field 'mf', into 'value' and 'mask'.  Returns
 * NULL if successful, otherwise a malloc()'d string describing the error. */
char *
mf_parse(const struct mf_field *mf, const char *s,
         union mf_value *value, union mf_value *mask)
{
    if (!strcasecmp(s, "any") || !strcmp(s, "*")) {
        memset(value, 0, mf->n_bytes);
        memset(mask, 0, mf->n_bytes);
        return NULL;
    }

    switch (mf->string) {
    case MFS_DECIMAL:
    case MFS_HEXADECIMAL:
        return mf_from_integer_string(mf, s,
                                      (uint8_t *) value, (uint8_t *) mask);

    case MFS_ETHERNET:
        return mf_from_ethernet_string(mf, s, value->mac, mask->mac);

    case MFS_IPV4:
        return mf_from_ipv4_string(mf, s, &value->be32, &mask->be32);

    case MFS_IPV6:
        return mf_from_ipv6_string(mf, s, &value->ipv6, &mask->ipv6);

    case MFS_OFP_PORT:
        return mf_from_ofp_port_string(mf, s, &value->be16, &mask->be16);

    case MFS_FRAG:
        return mf_from_frag_string(s, &value->u8, &mask->u8);

    case MFS_TNL_FLAGS:
        assert(mf->n_bytes == sizeof(ovs_be16));
        return mf_from_tun_flags_string(s, &value->be16, &mask->be16);
    }
    NOT_REACHED();
}

/* Parses 's', a string value for field 'mf', into 'value'.  Returns NULL if
 * successful, otherwise a malloc()'d string describing the error. */
char *
mf_parse_value(const struct mf_field *mf, const char *s, union mf_value *value)
{
    union mf_value mask;
    char *error;

    error = mf_parse(mf, s, value, &mask);
    if (error) {
        return error;
    }

    if (!is_all_ones((const uint8_t *) &mask, mf->n_bytes)) {
        return xasprintf("%s: wildcards not allowed here", s);
    }
    return NULL;
}

static void
mf_format_integer_string(const struct mf_field *mf, const uint8_t *valuep,
                         const uint8_t *maskp, struct ds *s)
{
    unsigned long long int integer;
    int i;

    assert(mf->n_bytes <= 8);

    integer = 0;
    for (i = 0; i < mf->n_bytes; i++) {
        integer = (integer << 8) | valuep[i];
    }
    if (mf->string == MFS_HEXADECIMAL) {
        ds_put_format(s, "%#llx", integer);
    } else {
        ds_put_format(s, "%lld", integer);
    }

    if (maskp) {
        unsigned long long int mask;

        mask = 0;
        for (i = 0; i < mf->n_bytes; i++) {
            mask = (mask << 8) | maskp[i];
        }

        /* I guess we could write the mask in decimal for MFS_DECIMAL but I'm
         * not sure that that a bit-mask written in decimal is ever easier to
         * understand than the same bit-mask written in hexadecimal. */
        ds_put_format(s, "/%#llx", mask);
    }
}

static void
mf_format_frag_string(uint8_t value, uint8_t mask, struct ds *s)
{
    const struct frag_handling *h;

    mask &= FLOW_NW_FRAG_MASK;
    value &= mask;

    for (h = all_frags; h < &all_frags[ARRAY_SIZE(all_frags)]; h++) {
        if (value == h->value && mask == h->mask) {
            ds_put_cstr(s, h->name);
            return;
        }
    }
    ds_put_cstr(s, "<error>");
}

static void
mf_format_tnl_flags_string(const ovs_be16 *valuep, struct ds *s)
{
    format_flags(s, flow_tun_flag_to_string, ntohs(*valuep), '|');
}

/* Appends to 's' a string representation of field 'mf' whose value is in
 * 'value' and 'mask'.  'mask' may be NULL to indicate an exact match. */
void
mf_format(const struct mf_field *mf,
          const union mf_value *value, const union mf_value *mask,
          struct ds *s)
{
    if (mask) {
        if (is_all_zeros((const uint8_t *) mask, mf->n_bytes)) {
            ds_put_cstr(s, "ANY");
            return;
        } else if (is_all_ones((const uint8_t *) mask, mf->n_bytes)) {
            mask = NULL;
        }
    }

    switch (mf->string) {
    case MFS_OFP_PORT:
        if (!mask) {
            ofputil_format_port(ntohs(value->be16), s);
            break;
        }
        /* fall through */
    case MFS_DECIMAL:
    case MFS_HEXADECIMAL:
        mf_format_integer_string(mf, (uint8_t *) value, (uint8_t *) mask, s);
        break;

    case MFS_ETHERNET:
        eth_format_masked(value->mac, mask->mac, s);
        break;

    case MFS_IPV4:
        ip_format_masked(value->be32, mask ? mask->be32 : htonl(UINT32_MAX),
                         s);
        break;

    case MFS_IPV6:
        print_ipv6_masked(s, &value->ipv6, mask ? &mask->ipv6 : NULL);
        break;

    case MFS_FRAG:
        mf_format_frag_string(value->u8, mask ? mask->u8 : UINT8_MAX, s);
        break;

    case MFS_TNL_FLAGS:
        mf_format_tnl_flags_string(&value->be16, s);
        break;

    default:
        NOT_REACHED();
    }
}

/* Makes subfield 'sf' within 'flow' exactly match the 'sf->n_bits'
 * least-significant bits in 'x'.
 */
void
mf_write_subfield_flow(const struct mf_subfield *sf,
                       const union mf_subvalue *x, struct flow *flow)
{
    const struct mf_field *field = sf->field;
    union mf_value value;

    mf_get_value(field, flow, &value);
    bitwise_copy(x, sizeof *x, 0, &value, field->n_bytes,
                 sf->ofs, sf->n_bits);
    mf_set_flow_value(field, &value, flow);
}

/* Makes subfield 'sf' within 'match' exactly match the 'sf->n_bits'
 * least-significant bits in 'x'.
 */
void
mf_write_subfield(const struct mf_subfield *sf, const union mf_subvalue *x,
                  struct match *match)
{
    const struct mf_field *field = sf->field;
    union mf_value value, mask;

    mf_get(field, match, &value, &mask);
    bitwise_copy(x, sizeof *x, 0, &value, field->n_bytes, sf->ofs, sf->n_bits);
    bitwise_one (                 &mask,  field->n_bytes, sf->ofs, sf->n_bits);
    mf_set(field, &value, &mask, match);
}

/* Initializes 'x' to the value of 'sf' within 'flow'.  'sf' must be valid for
 * reading 'flow', e.g. as checked by mf_check_src(). */
void
mf_read_subfield(const struct mf_subfield *sf, const struct flow *flow,
                 union mf_subvalue *x)
{
    union mf_value value;

    mf_get_value(sf->field, flow, &value);

    memset(x, 0, sizeof *x);
    bitwise_copy(&value, sf->field->n_bytes, sf->ofs,
                 x, sizeof *x, 0,
                 sf->n_bits);
}

/* Returns the value of 'sf' within 'flow'.  'sf' must be valid for reading
 * 'flow', e.g. as checked by mf_check_src() and sf->n_bits must be 64 or
 * less. */
uint64_t
mf_get_subfield(const struct mf_subfield *sf, const struct flow *flow)
{
    union mf_value value;

    mf_get_value(sf->field, flow, &value);
    return bitwise_get(&value, sf->field->n_bytes, sf->ofs, sf->n_bits);
}

/* Formats 'sf' into 's' in a format normally acceptable to
 * mf_parse_subfield().  (It won't be acceptable if sf->field is NULL or if
 * sf->field has no NXM name.) */
void
mf_format_subfield(const struct mf_subfield *sf, struct ds *s)
{
    if (!sf->field) {
        ds_put_cstr(s, "<unknown>");
    } else if (sf->field->nxm_name) {
        ds_put_cstr(s, sf->field->nxm_name);
    } else if (sf->field->nxm_header) {
        uint32_t header = sf->field->nxm_header;
        ds_put_format(s, "%d:%d", NXM_VENDOR(header), NXM_FIELD(header));
    } else {
        ds_put_cstr(s, sf->field->name);
    }

    if (sf->field && sf->ofs == 0 && sf->n_bits == sf->field->n_bits) {
        ds_put_cstr(s, "[]");
    } else if (sf->n_bits == 1) {
        ds_put_format(s, "[%d]", sf->ofs);
    } else {
        ds_put_format(s, "[%d..%d]", sf->ofs, sf->ofs + sf->n_bits - 1);
    }
}

static const struct mf_field *
mf_parse_subfield_name(const char *name, int name_len, bool *wild)
{
    int i;

    *wild = name_len > 2 && !memcmp(&name[name_len - 2], "_W", 2);
    if (*wild) {
        name_len -= 2;
    }

    for (i = 0; i < MFF_N_IDS; i++) {
        const struct mf_field *mf = mf_from_id(i);

        if (mf->nxm_name
            && !strncmp(mf->nxm_name, name, name_len)
            && mf->nxm_name[name_len] == '\0') {
            return mf;
        }
        if (mf->oxm_name
            && !strncmp(mf->oxm_name, name, name_len)
            && mf->oxm_name[name_len] == '\0') {
            return mf;
        }
    }

    return NULL;
}

/* Parses a subfield from the beginning of '*sp' into 'sf'.  If successful,
 * returns NULL and advances '*sp' to the first byte following the parsed
 * string.  On failure, returns a malloc()'d error message, does not modify
 * '*sp', and does not properly initialize 'sf'.
 *
 * The syntax parsed from '*sp' takes the form "header[start..end]" where
 * 'header' is the name of an NXM field and 'start' and 'end' are (inclusive)
 * bit indexes.  "..end" may be omitted to indicate a single bit.  "start..end"
 * may both be omitted (the [] are still required) to indicate an entire
 * field. */
char *
mf_parse_subfield__(struct mf_subfield *sf, const char **sp)
{
    const struct mf_field *field;
    const char *name;
    int start, end;
    const char *s;
    int name_len;
    bool wild;

    s = *sp;
    name = s;
    name_len = strcspn(s, "[");
    if (s[name_len] != '[') {
        return xasprintf("%s: missing [ looking for field name", *sp);
    }

    field = mf_parse_subfield_name(name, name_len, &wild);
    if (!field) {
        return xasprintf("%s: unknown field `%.*s'", *sp, name_len, s);
    }

    s += name_len;
    if (sscanf(s, "[%d..%d]", &start, &end) == 2) {
        /* Nothing to do. */
    } else if (sscanf(s, "[%d]", &start) == 1) {
        end = start;
    } else if (!strncmp(s, "[]", 2)) {
        start = 0;
        end = field->n_bits - 1;
    } else {
        return xasprintf("%s: syntax error expecting [] or [<bit>] or "
                         "[<start>..<end>]", *sp);
    }
    s = strchr(s, ']') + 1;

    if (start > end) {
        return xasprintf("%s: starting bit %d is after ending bit %d",
                         *sp, start, end);
    } else if (start >= field->n_bits) {
        return xasprintf("%s: starting bit %d is not valid because field is "
                         "only %d bits wide", *sp, start, field->n_bits);
    } else if (end >= field->n_bits){
        return xasprintf("%s: ending bit %d is not valid because field is "
                         "only %d bits wide", *sp, end, field->n_bits);
    }

    sf->field = field;
    sf->ofs = start;
    sf->n_bits = end - start + 1;

    *sp = s;
    return NULL;
}

/* Parses a subfield from the beginning of 's' into 'sf'.  Returns the first
 * byte in 's' following the parsed string.
 *
 * Exits with an error message if 's' has incorrect syntax.
 *
 * The syntax parsed from 's' takes the form "header[start..end]" where
 * 'header' is the name of an NXM field and 'start' and 'end' are (inclusive)
 * bit indexes.  "..end" may be omitted to indicate a single bit.  "start..end"
 * may both be omitted (the [] are still required) to indicate an entire
 * field.  */
const char *
mf_parse_subfield(struct mf_subfield *sf, const char *s)
{
    char *msg = mf_parse_subfield__(sf, &s);
    if (msg) {
        ovs_fatal(0, "%s", msg);
    }
    return s;
}

void
mf_format_subvalue(const union mf_subvalue *subvalue, struct ds *s)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(subvalue->u8); i++) {
        if (subvalue->u8[i]) {
            ds_put_format(s, "0x%"PRIx8, subvalue->u8[i]);
            for (i++; i < ARRAY_SIZE(subvalue->u8); i++) {
                ds_put_format(s, "%02"PRIx8, subvalue->u8[i]);
            }
            return;
        }
    }
    ds_put_char(s, '0');
}
