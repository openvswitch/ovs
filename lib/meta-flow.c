/*
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include <errno.h>
#include <limits.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include "classifier.h"
#include "dynamic-string.h"
#include "nx-match.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "ovs-thread.h"
#include "packets.h"
#include "random.h"
#include "shash.h"
#include "socket-util.h"
#include "tun-metadata.h"
#include "unaligned.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(meta_flow);

#define FLOW_U32OFS(FIELD)                                              \
    offsetof(struct flow, FIELD) % 4 ? -1 : offsetof(struct flow, FIELD) / 4

#define MF_FIELD_SIZES(MEMBER)                  \
    sizeof ((union mf_value *)0)->MEMBER,       \
    8 * sizeof ((union mf_value *)0)->MEMBER

extern const struct mf_field mf_fields[MFF_N_IDS]; /* Silence a warning. */

const struct mf_field mf_fields[MFF_N_IDS] = {
#include "meta-flow.inc"
};

/* Maps from an mf_field's 'name' or 'extra_name' to the mf_field. */
static struct shash mf_by_name;

/* Rate limit for parse errors.  These always indicate a bug in an OpenFlow
 * controller and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

#define MF_VALUE_EXACT_8 0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff
#define MF_VALUE_EXACT_16 MF_VALUE_EXACT_8, MF_VALUE_EXACT_8
#define MF_VALUE_EXACT_32 MF_VALUE_EXACT_16, MF_VALUE_EXACT_16
#define MF_VALUE_EXACT_64 MF_VALUE_EXACT_32, MF_VALUE_EXACT_32
#define MF_VALUE_EXACT_128 MF_VALUE_EXACT_64, MF_VALUE_EXACT_64
#define MF_VALUE_EXACT_INITIALIZER { .tun_metadata = { MF_VALUE_EXACT_128 } }

const union mf_value exact_match_mask = MF_VALUE_EXACT_INITIALIZER;

static void nxm_init(void);

/* Returns the field with the given 'name', or a null pointer if no field has
 * that name. */
const struct mf_field *
mf_from_name(const char *name)
{
    nxm_init();
    return shash_find_data(&mf_by_name, name);
}

static void
nxm_do_init(void)
{
    int i;

    shash_init(&mf_by_name);
    for (i = 0; i < MFF_N_IDS; i++) {
        const struct mf_field *mf = &mf_fields[i];

        ovs_assert(mf->id == i); /* Fields must be in the enum order. */

        shash_add_once(&mf_by_name, mf->name, mf);
        if (mf->extra_name) {
            shash_add_once(&mf_by_name, mf->extra_name, mf);
        }
    }
}

static void
nxm_init(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, nxm_do_init);
}

/* Consider the two value/mask pairs 'a_value/a_mask' and 'b_value/b_mask' as
 * restrictions on a field's value.  Then, this function initializes
 * 'dst_value/dst_mask' such that it combines the restrictions of both pairs.
 * This is not always possible, i.e. if one pair insists on a value of 0 in
 * some bit and the other pair insists on a value of 1 in that bit.  This
 * function returns false in a case where the combined restriction is
 * impossible (in which case 'dst_value/dst_mask' is not fully initialized),
 * true otherwise.
 *
 * (As usually true for value/mask pairs in OVS, any 1-bit in a value must have
 * a corresponding 1-bit in its mask.) */
bool
mf_subvalue_intersect(const union mf_subvalue *a_value,
                      const union mf_subvalue *a_mask,
                      const union mf_subvalue *b_value,
                      const union mf_subvalue *b_mask,
                      union mf_subvalue *dst_value,
                      union mf_subvalue *dst_mask)
{
    for (int i = 0; i < ARRAY_SIZE(a_value->be64); i++) {
        ovs_be64 av = a_value->be64[i];
        ovs_be64 am = a_mask->be64[i];
        ovs_be64 bv = b_value->be64[i];
        ovs_be64 bm = b_mask->be64[i];
        ovs_be64 *dv = &dst_value->be64[i];
        ovs_be64 *dm = &dst_mask->be64[i];

        if ((av ^ bv) & (am & bm)) {
            return false;
        }
        *dv = av | bv;
        *dm = am | bm;
    }
    return true;
}

/* Returns the "number of bits" in 'v', e.g. 1 if only the lowest-order bit is
 * set, 2 if the second-lowest-order bit is set, and so on. */
int
mf_subvalue_width(const union mf_subvalue *v)
{
    return 1 + bitwise_rscan(v, sizeof *v, true, sizeof *v * 8 - 1, -1);
}

/* For positive 'n', shifts the bits in 'value' 'n' bits to the left, and for
 * negative 'n', shifts the bits '-n' bits to the right. */
void
mf_subvalue_shift(union mf_subvalue *value, int n)
{
    if (n) {
        union mf_subvalue tmp;
        memset(&tmp, 0, sizeof tmp);

        if (n > 0 && n < 8 * sizeof tmp) {
            bitwise_copy(value, sizeof *value, 0,
                         &tmp, sizeof tmp, n,
                         8 * sizeof tmp - n);
        } else if (n < 0 && n > -8 * sizeof tmp) {
            bitwise_copy(value, sizeof *value, -n,
                         &tmp, sizeof tmp, 0,
                         8 * sizeof tmp + n);
        }
        *value = tmp;
    }
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
    case MFF_DP_HASH:
        return !wc->masks.dp_hash;
    case MFF_RECIRC_ID:
        return !wc->masks.recirc_id;
    case MFF_CONJ_ID:
        return !wc->masks.conj_id;
    case MFF_TUN_SRC:
        return !wc->masks.tunnel.ip_src;
    case MFF_TUN_DST:
        return !wc->masks.tunnel.ip_dst;
    case MFF_TUN_IPV6_SRC:
        return ipv6_mask_is_any(&wc->masks.tunnel.ipv6_src);
    case MFF_TUN_IPV6_DST:
        return ipv6_mask_is_any(&wc->masks.tunnel.ipv6_dst);
    case MFF_TUN_ID:
        return !wc->masks.tunnel.tun_id;
    case MFF_TUN_TOS:
        return !wc->masks.tunnel.ip_tos;
    case MFF_TUN_TTL:
        return !wc->masks.tunnel.ip_ttl;
    case MFF_TUN_FLAGS:
        return !(wc->masks.tunnel.flags & FLOW_TNL_PUB_F_MASK);
    case MFF_TUN_GBP_ID:
        return !wc->masks.tunnel.gbp_id;
    case MFF_TUN_GBP_FLAGS:
        return !wc->masks.tunnel.gbp_flags;
    CASE_MFF_TUN_METADATA:
        return !ULLONG_GET(wc->masks.tunnel.metadata.present.map,
                           mf->id - MFF_TUN_METADATA0);
    case MFF_METADATA:
        return !wc->masks.metadata;
    case MFF_IN_PORT:
    case MFF_IN_PORT_OXM:
        return !wc->masks.in_port.ofp_port;
    case MFF_SKB_PRIORITY:
        return !wc->masks.skb_priority;
    case MFF_PKT_MARK:
        return !wc->masks.pkt_mark;
    case MFF_CT_STATE:
        return !wc->masks.ct_state;
    case MFF_CT_ZONE:
        return !wc->masks.ct_zone;
    case MFF_CT_MARK:
        return !wc->masks.ct_mark;
    case MFF_CT_LABEL:
        return ovs_u128_is_zero(&wc->masks.ct_label);
    CASE_MFF_REGS:
        return !wc->masks.regs[mf->id - MFF_REG0];
    CASE_MFF_XREGS:
        return !flow_get_xreg(&wc->masks, mf->id - MFF_XREG0);
    case MFF_ACTSET_OUTPUT:
        return !wc->masks.actset_output;

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

    case MFF_MPLS_LABEL:
        return !(wc->masks.mpls_lse[0] & htonl(MPLS_LABEL_MASK));
    case MFF_MPLS_TC:
        return !(wc->masks.mpls_lse[0] & htonl(MPLS_TC_MASK));
    case MFF_MPLS_BOS:
        return !(wc->masks.mpls_lse[0] & htonl(MPLS_BOS_MASK));

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
    case MFF_IP_DSCP_SHIFTED:
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
    case MFF_SCTP_SRC:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV6_TYPE:
        return !wc->masks.tp_src;
    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_SCTP_DST:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_CODE:
        return !wc->masks.tp_dst;
    case MFF_TCP_FLAGS:
        return !wc->masks.tcp_flags;

    case MFF_N_IDS:
    default:
        OVS_NOT_REACHED();
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
        return (is_all_zeros(mask, mf->n_bytes) ||
                is_all_ones(mask, mf->n_bytes));

    case MFM_FULLY:
        return true;
    }

    OVS_NOT_REACHED();
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
    case MFP_MPLS:
        return eth_type_mpls(flow->dl_type);
    case MFP_IP_ANY:
        return is_ip_any(flow);

    case MFP_TCP:
        return is_ip_any(flow) && flow->nw_proto == IPPROTO_TCP
            && !(flow->nw_frag & FLOW_NW_FRAG_LATER);
    case MFP_UDP:
        return is_ip_any(flow) && flow->nw_proto == IPPROTO_UDP
            && !(flow->nw_frag & FLOW_NW_FRAG_LATER);
    case MFP_SCTP:
        return is_ip_any(flow) && flow->nw_proto == IPPROTO_SCTP
            && !(flow->nw_frag & FLOW_NW_FRAG_LATER);
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

    OVS_NOT_REACHED();
}

/* Set field and it's prerequisities in the mask.
 * This is only ever called for writeable 'mf's, but we do not make the
 * distinction here. */
void
mf_mask_field_and_prereqs(const struct mf_field *mf, struct flow_wildcards *wc)
{
    mf_set_flow_value(mf, &exact_match_mask, &wc->masks);

    switch (mf->prereqs) {
    case MFP_ND:
    case MFP_ND_SOLICIT:
    case MFP_ND_ADVERT:
        WC_MASK_FIELD(wc, tp_src);
        WC_MASK_FIELD(wc, tp_dst);
        /* Fall through. */
    case MFP_TCP:
    case MFP_UDP:
    case MFP_SCTP:
    case MFP_ICMPV4:
    case MFP_ICMPV6:
        /* nw_frag always unwildcarded. */
        WC_MASK_FIELD(wc, nw_proto);
        /* Fall through. */
    case MFP_ARP:
    case MFP_IPV4:
    case MFP_IPV6:
    case MFP_MPLS:
    case MFP_IP_ANY:
        /* dl_type always unwildcarded. */
        break;
    case MFP_VLAN_VID:
        WC_MASK_FIELD_MASK(wc, vlan_tci, htons(VLAN_CFI));
        break;
    case MFP_NONE:
        break;
    }
}

/* Set bits of 'bm' corresponding to the field 'mf' and it's prerequisities. */
void
mf_bitmap_set_field_and_prereqs(const struct mf_field *mf, struct mf_bitmap *bm)
{
    bitmap_set1(bm->bm, mf->id);

    switch (mf->prereqs) {
    case MFP_ND:
    case MFP_ND_SOLICIT:
    case MFP_ND_ADVERT:
        bitmap_set1(bm->bm, MFF_TCP_SRC);
        bitmap_set1(bm->bm, MFF_TCP_DST);
        /* Fall through. */
    case MFP_TCP:
    case MFP_UDP:
    case MFP_SCTP:
    case MFP_ICMPV4:
    case MFP_ICMPV6:
        /* nw_frag always unwildcarded. */
        bitmap_set1(bm->bm, MFF_IP_PROTO);
        /* Fall through. */
    case MFP_ARP:
    case MFP_IPV4:
    case MFP_IPV6:
    case MFP_MPLS:
    case MFP_IP_ANY:
        bitmap_set1(bm->bm, MFF_ETH_TYPE);
        break;
    case MFP_VLAN_VID:
        bitmap_set1(bm->bm, MFF_VLAN_TCI);
        break;
    case MFP_NONE:
        break;
    }
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
    case MFF_DP_HASH:
    case MFF_RECIRC_ID:
    case MFF_CONJ_ID:
    case MFF_TUN_ID:
    case MFF_TUN_SRC:
    case MFF_TUN_DST:
    case MFF_TUN_IPV6_SRC:
    case MFF_TUN_IPV6_DST:
    case MFF_TUN_TOS:
    case MFF_TUN_TTL:
    case MFF_TUN_GBP_ID:
    case MFF_TUN_GBP_FLAGS:
    CASE_MFF_TUN_METADATA:
    case MFF_METADATA:
    case MFF_IN_PORT:
    case MFF_SKB_PRIORITY:
    case MFF_PKT_MARK:
    case MFF_CT_ZONE:
    case MFF_CT_MARK:
    case MFF_CT_LABEL:
    CASE_MFF_REGS:
    CASE_MFF_XREGS:
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
    case MFF_SCTP_SRC:
    case MFF_SCTP_DST:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
    case MFF_ND_TARGET:
    case MFF_ND_SLL:
    case MFF_ND_TLL:
        return true;

    case MFF_IN_PORT_OXM:
    case MFF_ACTSET_OUTPUT: {
        ofp_port_t port;
        return !ofputil_port_from_ofp11(value->be32, &port);
    }

    case MFF_IP_DSCP:
        return !(value->u8 & ~IP_DSCP_MASK);
    case MFF_IP_DSCP_SHIFTED:
        return !(value->u8 & (~IP_DSCP_MASK >> 2));
    case MFF_IP_ECN:
        return !(value->u8 & ~IP_ECN_MASK);
    case MFF_IP_FRAG:
        return !(value->u8 & ~FLOW_NW_FRAG_MASK);
    case MFF_TCP_FLAGS:
        return !(value->be16 & ~htons(0x0fff));

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

    case MFF_MPLS_LABEL:
        return !(value->be32 & ~htonl(MPLS_LABEL_MASK >> MPLS_LABEL_SHIFT));

    case MFF_MPLS_TC:
        return !(value->u8 & ~(MPLS_TC_MASK >> MPLS_TC_SHIFT));

    case MFF_MPLS_BOS:
        return !(value->u8 & ~(MPLS_BOS_MASK >> MPLS_BOS_SHIFT));

    case MFF_TUN_FLAGS:
        return !(value->be16 & ~htons(FLOW_TNL_PUB_F_MASK));

    case MFF_CT_STATE:
        return !(value->be32 & ~htonl(CS_SUPPORTED_MASK));

    case MFF_N_IDS:
    default:
        OVS_NOT_REACHED();
    }
}

/* Copies the value of field 'mf' from 'flow' into 'value'.  The caller is
 * responsible for ensuring that 'flow' meets 'mf''s prerequisites. */
void
mf_get_value(const struct mf_field *mf, const struct flow *flow,
             union mf_value *value)
{
    switch (mf->id) {
    case MFF_DP_HASH:
        value->be32 = htonl(flow->dp_hash);
        break;
    case MFF_RECIRC_ID:
        value->be32 = htonl(flow->recirc_id);
        break;
    case MFF_CONJ_ID:
        value->be32 = htonl(flow->conj_id);
        break;
    case MFF_TUN_ID:
        value->be64 = flow->tunnel.tun_id;
        break;
    case MFF_TUN_SRC:
        value->be32 = flow->tunnel.ip_src;
        break;
    case MFF_TUN_DST:
        value->be32 = flow->tunnel.ip_dst;
        break;
    case MFF_TUN_IPV6_SRC:
        value->ipv6 = flow->tunnel.ipv6_src;
        break;
    case MFF_TUN_IPV6_DST:
        value->ipv6 = flow->tunnel.ipv6_dst;
        break;
    case MFF_TUN_FLAGS:
        value->be16 = htons(flow->tunnel.flags & FLOW_TNL_PUB_F_MASK);
        break;
    case MFF_TUN_GBP_ID:
        value->be16 = flow->tunnel.gbp_id;
        break;
    case MFF_TUN_GBP_FLAGS:
        value->u8 = flow->tunnel.gbp_flags;
        break;
    case MFF_TUN_TTL:
        value->u8 = flow->tunnel.ip_ttl;
        break;
    case MFF_TUN_TOS:
        value->u8 = flow->tunnel.ip_tos;
        break;
    CASE_MFF_TUN_METADATA:
        tun_metadata_read(&flow->tunnel, mf, value);
        break;

    case MFF_METADATA:
        value->be64 = flow->metadata;
        break;

    case MFF_IN_PORT:
        value->be16 = htons(ofp_to_u16(flow->in_port.ofp_port));
        break;
    case MFF_IN_PORT_OXM:
        value->be32 = ofputil_port_to_ofp11(flow->in_port.ofp_port);
        break;
    case MFF_ACTSET_OUTPUT:
        value->be32 = ofputil_port_to_ofp11(flow->actset_output);
        break;

    case MFF_SKB_PRIORITY:
        value->be32 = htonl(flow->skb_priority);
        break;

    case MFF_PKT_MARK:
        value->be32 = htonl(flow->pkt_mark);
        break;

    case MFF_CT_STATE:
        value->be32 = htonl(flow->ct_state);
        break;

    case MFF_CT_ZONE:
        value->be16 = htons(flow->ct_zone);
        break;

    case MFF_CT_MARK:
        value->be32 = htonl(flow->ct_mark);
        break;

    case MFF_CT_LABEL:
        value->be128 = hton128(flow->ct_label);
        break;

    CASE_MFF_REGS:
        value->be32 = htonl(flow->regs[mf->id - MFF_REG0]);
        break;

    CASE_MFF_XREGS:
        value->be64 = htonll(flow_get_xreg(flow, mf->id - MFF_XREG0));
        break;

    case MFF_ETH_SRC:
        value->mac = flow->dl_src;
        break;

    case MFF_ETH_DST:
        value->mac = flow->dl_dst;
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

    case MFF_MPLS_LABEL:
        value->be32 = htonl(mpls_lse_to_label(flow->mpls_lse[0]));
        break;

    case MFF_MPLS_TC:
        value->u8 = mpls_lse_to_tc(flow->mpls_lse[0]);
        break;

    case MFF_MPLS_BOS:
        value->u8 = mpls_lse_to_bos(flow->mpls_lse[0]);
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

    case MFF_IP_DSCP_SHIFTED:
        value->u8 = flow->nw_tos >> 2;
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
        value->mac = flow->arp_sha;
        break;

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        value->mac = flow->arp_tha;
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
    case MFF_SCTP_SRC:
        value->be16 = flow->tp_src;
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_SCTP_DST:
        value->be16 = flow->tp_dst;
        break;

    case MFF_TCP_FLAGS:
        value->be16 = flow->tcp_flags;
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
        OVS_NOT_REACHED();
    }
}

/* Makes 'match' match field 'mf' exactly, with the value matched taken from
 * 'value'.  The caller is responsible for ensuring that 'match' meets 'mf''s
 * prerequisites.
 *
 * If non-NULL, 'err_str' returns a malloc'ed string describing any errors
 * with the request or NULL if there is no error. The caller is reponsible
 * for freeing the string. */
void
mf_set_value(const struct mf_field *mf,
             const union mf_value *value, struct match *match, char **err_str)
{
    if (err_str) {
        *err_str = NULL;
    }

    switch (mf->id) {
    case MFF_DP_HASH:
        match_set_dp_hash(match, ntohl(value->be32));
        break;
    case MFF_RECIRC_ID:
        match_set_recirc_id(match, ntohl(value->be32));
        break;
    case MFF_CONJ_ID:
        match_set_conj_id(match, ntohl(value->be32));
        break;
    case MFF_TUN_ID:
        match_set_tun_id(match, value->be64);
        break;
    case MFF_TUN_SRC:
        match_set_tun_src(match, value->be32);
        break;
    case MFF_TUN_DST:
        match_set_tun_dst(match, value->be32);
        break;
    case MFF_TUN_IPV6_SRC:
        match_set_tun_ipv6_src(match, &value->ipv6);
        break;
    case MFF_TUN_IPV6_DST:
        match_set_tun_ipv6_dst(match, &value->ipv6);
        break;
    case MFF_TUN_FLAGS:
        match_set_tun_flags(match, ntohs(value->be16));
        break;
    case MFF_TUN_GBP_ID:
         match_set_tun_gbp_id(match, value->be16);
         break;
    case MFF_TUN_GBP_FLAGS:
         match_set_tun_gbp_flags(match, value->u8);
         break;
    case MFF_TUN_TOS:
        match_set_tun_tos(match, value->u8);
        break;
    case MFF_TUN_TTL:
        match_set_tun_ttl(match, value->u8);
        break;
    CASE_MFF_TUN_METADATA:
        tun_metadata_set_match(mf, value, NULL, match, err_str);
        break;

    case MFF_METADATA:
        match_set_metadata(match, value->be64);
        break;

    case MFF_IN_PORT:
        match_set_in_port(match, u16_to_ofp(ntohs(value->be16)));
        break;

    case MFF_IN_PORT_OXM: {
        ofp_port_t port;
        ofputil_port_from_ofp11(value->be32, &port);
        match_set_in_port(match, port);
        break;
    }
    case MFF_ACTSET_OUTPUT: {
        ofp_port_t port;
        ofputil_port_from_ofp11(value->be32, &port);
        match_set_actset_output(match, port);
        break;
    }

    case MFF_SKB_PRIORITY:
        match_set_skb_priority(match, ntohl(value->be32));
        break;

    case MFF_PKT_MARK:
        match_set_pkt_mark(match, ntohl(value->be32));
        break;

    case MFF_CT_STATE:
        match_set_ct_state(match, ntohl(value->be32));
        break;

    case MFF_CT_ZONE:
        match_set_ct_zone(match, ntohs(value->be16));
        break;

    case MFF_CT_MARK:
        match_set_ct_mark(match, ntohl(value->be32));
        break;

    case MFF_CT_LABEL:
        match_set_ct_label(match, ntoh128(value->be128));
        break;

    CASE_MFF_REGS:
        match_set_reg(match, mf->id - MFF_REG0, ntohl(value->be32));
        break;

    CASE_MFF_XREGS:
        match_set_xreg(match, mf->id - MFF_XREG0, ntohll(value->be64));
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

    case MFF_MPLS_LABEL:
        match_set_mpls_label(match, 0, value->be32);
        break;

    case MFF_MPLS_TC:
        match_set_mpls_tc(match, 0, value->u8);
        break;

    case MFF_MPLS_BOS:
        match_set_mpls_bos(match, 0, value->u8);
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

    case MFF_IP_DSCP_SHIFTED:
        match_set_nw_dscp(match, value->u8 << 2);
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
    case MFF_SCTP_SRC:
        match_set_tp_src(match, value->be16);
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_SCTP_DST:
        match_set_tp_dst(match, value->be16);
        break;

    case MFF_TCP_FLAGS:
        match_set_tcp_flags(match, value->be16);
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
        OVS_NOT_REACHED();
    }
}

/* Unwildcard 'mask' member field described by 'mf'.  The caller is
 * responsible for ensuring that 'mask' meets 'mf''s prerequisites. */
void
mf_mask_field(const struct mf_field *mf, struct flow *mask)
{
    /* For MFF_DL_VLAN, we cannot send a all 1's to flow_set_dl_vlan()
     * as that will be considered as OFP10_VLAN_NONE. So consider it as a
     * special case. For the rest, calling mf_set_flow_value() is good
     * enough. */
    if (mf->id == MFF_DL_VLAN) {
        flow_set_dl_vlan(mask, htons(VLAN_VID_MASK));
    } else {
        mf_set_flow_value(mf, &exact_match_mask, mask);
    }
}

static int
field_len(const struct mf_field *mf, const union mf_value *value_)
{
    const uint8_t *value = &value_->u8;
    int i;

    if (!mf->variable_len) {
        return mf->n_bytes;
    }

    if (!value) {
        return 0;
    }

    for (i = 0; i < mf->n_bytes; i++) {
        if (value[i] != 0) {
            break;
        }
    }

    return mf->n_bytes - i;
}

/* Returns the effective length of the field. For fixed length fields,
 * this is just the defined length. For variable length fields, it is
 * the minimum size encoding that retains the same meaning (i.e.
 * discarding leading zeros).
 *
 * 'is_masked' returns (if non-NULL) whether the original contained
 * a mask. Otherwise, a mask that is the same length as the value
 * might be misinterpreted as an exact match. */
int
mf_field_len(const struct mf_field *mf, const union mf_value *value,
             const union mf_value *mask, bool *is_masked_)
{
    int len, mask_len;
    bool is_masked = mask && !is_all_ones(mask, mf->n_bytes);

    len = field_len(mf, value);
    if (is_masked) {
        mask_len = field_len(mf, mask);
        len = MAX(len, mask_len);
    }

    if (is_masked_) {
        *is_masked_ = is_masked;
    }

    return len;
}

/* Sets 'flow' member field described by 'mf' to 'value'.  The caller is
 * responsible for ensuring that 'flow' meets 'mf''s prerequisites.*/
void
mf_set_flow_value(const struct mf_field *mf,
                  const union mf_value *value, struct flow *flow)
{
    switch (mf->id) {
    case MFF_DP_HASH:
        flow->dp_hash = ntohl(value->be32);
        break;
    case MFF_RECIRC_ID:
        flow->recirc_id = ntohl(value->be32);
        break;
    case MFF_CONJ_ID:
        flow->conj_id = ntohl(value->be32);
        break;
    case MFF_TUN_ID:
        flow->tunnel.tun_id = value->be64;
        break;
    case MFF_TUN_SRC:
        flow->tunnel.ip_src = value->be32;
        break;
    case MFF_TUN_DST:
        flow->tunnel.ip_dst = value->be32;
        break;
    case MFF_TUN_IPV6_SRC:
        flow->tunnel.ipv6_src = value->ipv6;
        break;
    case MFF_TUN_IPV6_DST:
        flow->tunnel.ipv6_dst = value->ipv6;
        break;
    case MFF_TUN_FLAGS:
        flow->tunnel.flags = (flow->tunnel.flags & ~FLOW_TNL_PUB_F_MASK) |
                             ntohs(value->be16);
        break;
    case MFF_TUN_GBP_ID:
        flow->tunnel.gbp_id = value->be16;
        break;
    case MFF_TUN_GBP_FLAGS:
        flow->tunnel.gbp_flags = value->u8;
        break;
    case MFF_TUN_TOS:
        flow->tunnel.ip_tos = value->u8;
        break;
    case MFF_TUN_TTL:
        flow->tunnel.ip_ttl = value->u8;
        break;
    CASE_MFF_TUN_METADATA:
        tun_metadata_write(&flow->tunnel, mf, value);
        break;
    case MFF_METADATA:
        flow->metadata = value->be64;
        break;

    case MFF_IN_PORT:
        flow->in_port.ofp_port = u16_to_ofp(ntohs(value->be16));
        break;

    case MFF_IN_PORT_OXM:
        ofputil_port_from_ofp11(value->be32, &flow->in_port.ofp_port);
        break;
    case MFF_ACTSET_OUTPUT:
        ofputil_port_from_ofp11(value->be32, &flow->actset_output);
        break;

    case MFF_SKB_PRIORITY:
        flow->skb_priority = ntohl(value->be32);
        break;

    case MFF_PKT_MARK:
        flow->pkt_mark = ntohl(value->be32);
        break;

    case MFF_CT_STATE:
        flow->ct_state = ntohl(value->be32);
        break;

    case MFF_CT_ZONE:
        flow->ct_zone = ntohs(value->be16);
        break;

    case MFF_CT_MARK:
        flow->ct_mark = ntohl(value->be32);
        break;

    case MFF_CT_LABEL:
        flow->ct_label = ntoh128(value->be128);
        break;

    CASE_MFF_REGS:
        flow->regs[mf->id - MFF_REG0] = ntohl(value->be32);
        break;

    CASE_MFF_XREGS:
        flow_set_xreg(flow, mf->id - MFF_XREG0, ntohll(value->be64));
        break;

    case MFF_ETH_SRC:
        flow->dl_src = value->mac;
        break;

    case MFF_ETH_DST:
        flow->dl_dst = value->mac;
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

    case MFF_MPLS_LABEL:
        flow_set_mpls_label(flow, 0, value->be32);
        break;

    case MFF_MPLS_TC:
        flow_set_mpls_tc(flow, 0, value->u8);
        break;

    case MFF_MPLS_BOS:
        flow_set_mpls_bos(flow, 0, value->u8);
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
        flow->ipv6_label = value->be32 & htonl(IPV6_LABEL_MASK);
        break;

    case MFF_IP_PROTO:
        flow->nw_proto = value->u8;
        break;

    case MFF_IP_DSCP:
        flow->nw_tos &= ~IP_DSCP_MASK;
        flow->nw_tos |= value->u8 & IP_DSCP_MASK;
        break;

    case MFF_IP_DSCP_SHIFTED:
        flow->nw_tos &= ~IP_DSCP_MASK;
        flow->nw_tos |= value->u8 << 2;
        break;

    case MFF_IP_ECN:
        flow->nw_tos &= ~IP_ECN_MASK;
        flow->nw_tos |= value->u8 & IP_ECN_MASK;
        break;

    case MFF_IP_TTL:
        flow->nw_ttl = value->u8;
        break;

    case MFF_IP_FRAG:
        flow->nw_frag = value->u8 & FLOW_NW_FRAG_MASK;
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
        flow->arp_sha = value->mac;
        break;

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        flow->arp_tha = value->mac;
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
    case MFF_SCTP_SRC:
        flow->tp_src = value->be16;
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_SCTP_DST:
        flow->tp_dst = value->be16;
        break;

    case MFF_TCP_FLAGS:
        flow->tcp_flags = value->be16;
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
        OVS_NOT_REACHED();
    }
}

/* Consider each of 'src', 'mask', and 'dst' as if they were arrays of 8*n
 * bits.  Then, for each 0 <= i < 8 * n such that mask[i] == 1, sets dst[i] =
 * src[i].  */
static void
apply_mask(const uint8_t *src, const uint8_t *mask, uint8_t *dst, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = (src[i] & mask[i]) | (dst[i] & ~mask[i]);
    }
}

/* Sets 'flow' member field described by 'field' to 'value', except that bits
 * for which 'mask' has a 0-bit keep their existing values.  The caller is
 * responsible for ensuring that 'flow' meets 'field''s prerequisites.*/
void
mf_set_flow_value_masked(const struct mf_field *field,
                         const union mf_value *value,
                         const union mf_value *mask,
                         struct flow *flow)
{
    union mf_value tmp;

    mf_get_value(field, flow, &tmp);
    apply_mask((const uint8_t *) value, (const uint8_t *) mask,
               (uint8_t *) &tmp, field->n_bytes);
    mf_set_flow_value(field, &tmp, flow);
}

bool
mf_is_tun_metadata(const struct mf_field *mf)
{
    return mf->id >= MFF_TUN_METADATA0 &&
           mf->id < MFF_TUN_METADATA0 + TUN_METADATA_NUM_OPTS;
}

/* Returns true if 'mf' has previously been set in 'flow', false if
 * it contains a non-default value.
 *
 * The caller is responsible for ensuring that 'flow' meets 'mf''s
 * prerequisites. */
bool
mf_is_set(const struct mf_field *mf, const struct flow *flow)
{
    if (!mf_is_tun_metadata(mf)) {
        union mf_value value;

        mf_get_value(mf, flow, &value);
        return !is_all_zeros(&value, mf->n_bytes);
    } else {
        return ULLONG_GET(flow->tunnel.metadata.present.map,
                          mf->id - MFF_TUN_METADATA0);
    }
}

/* Makes 'match' wildcard field 'mf'.
 *
 * The caller is responsible for ensuring that 'match' meets 'mf''s
 * prerequisites.
 *
 * If non-NULL, 'err_str' returns a malloc'ed string describing any errors
 * with the request or NULL if there is no error. The caller is reponsible
 * for freeing the string. */
void
mf_set_wild(const struct mf_field *mf, struct match *match, char **err_str)
{
    if (err_str) {
        *err_str = NULL;
    }

    switch (mf->id) {
    case MFF_DP_HASH:
        match->flow.dp_hash = 0;
        match->wc.masks.dp_hash = 0;
        break;
    case MFF_RECIRC_ID:
        match->flow.recirc_id = 0;
        match->wc.masks.recirc_id = 0;
        break;
    case MFF_CONJ_ID:
        match->flow.conj_id = 0;
        match->wc.masks.conj_id = 0;
        break;
    case MFF_TUN_ID:
        match_set_tun_id_masked(match, htonll(0), htonll(0));
        break;
    case MFF_TUN_SRC:
        match_set_tun_src_masked(match, htonl(0), htonl(0));
        break;
    case MFF_TUN_DST:
        match_set_tun_dst_masked(match, htonl(0), htonl(0));
        break;
    case MFF_TUN_IPV6_SRC:
        memset(&match->wc.masks.tunnel.ipv6_src, 0,
               sizeof match->wc.masks.tunnel.ipv6_src);
        memset(&match->flow.tunnel.ipv6_src, 0,
               sizeof match->flow.tunnel.ipv6_src);
        break;
    case MFF_TUN_IPV6_DST:
        memset(&match->wc.masks.tunnel.ipv6_dst, 0,
               sizeof match->wc.masks.tunnel.ipv6_dst);
        memset(&match->flow.tunnel.ipv6_dst, 0,
               sizeof match->flow.tunnel.ipv6_dst);
        break;
    case MFF_TUN_FLAGS:
        match_set_tun_flags_masked(match, 0, 0);
        break;
    case MFF_TUN_GBP_ID:
        match_set_tun_gbp_id_masked(match, 0, 0);
        break;
    case MFF_TUN_GBP_FLAGS:
        match_set_tun_gbp_flags_masked(match, 0, 0);
        break;
    case MFF_TUN_TOS:
        match_set_tun_tos_masked(match, 0, 0);
        break;
    case MFF_TUN_TTL:
        match_set_tun_ttl_masked(match, 0, 0);
        break;
    CASE_MFF_TUN_METADATA:
        tun_metadata_set_match(mf, NULL, NULL, match, err_str);
        break;

    case MFF_METADATA:
        match_set_metadata_masked(match, htonll(0), htonll(0));
        break;

    case MFF_IN_PORT:
    case MFF_IN_PORT_OXM:
        match->flow.in_port.ofp_port = 0;
        match->wc.masks.in_port.ofp_port = 0;
        break;
    case MFF_ACTSET_OUTPUT:
        match->flow.actset_output = 0;
        match->wc.masks.actset_output = 0;
        break;

    case MFF_SKB_PRIORITY:
        match->flow.skb_priority = 0;
        match->wc.masks.skb_priority = 0;
        break;

    case MFF_PKT_MARK:
        match->flow.pkt_mark = 0;
        match->wc.masks.pkt_mark = 0;
        break;

    case MFF_CT_STATE:
        match->flow.ct_state = 0;
        match->wc.masks.ct_state = 0;
        break;

    case MFF_CT_ZONE:
        match->flow.ct_zone = 0;
        match->wc.masks.ct_zone = 0;
        break;

    case MFF_CT_MARK:
        match->flow.ct_mark = 0;
        match->wc.masks.ct_mark = 0;
        break;

    case MFF_CT_LABEL:
        memset(&match->flow.ct_label, 0, sizeof(match->flow.ct_label));
        memset(&match->wc.masks.ct_label, 0, sizeof(match->wc.masks.ct_label));
        break;

    CASE_MFF_REGS:
        match_set_reg_masked(match, mf->id - MFF_REG0, 0, 0);
        break;

    CASE_MFF_XREGS:
        match_set_xreg_masked(match, mf->id - MFF_XREG0, 0, 0);
        break;

    case MFF_ETH_SRC:
        match->flow.dl_src = eth_addr_zero;
        match->wc.masks.dl_src = eth_addr_zero;
        break;

    case MFF_ETH_DST:
        match->flow.dl_dst = eth_addr_zero;
        match->wc.masks.dl_dst = eth_addr_zero;
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

    case MFF_MPLS_LABEL:
        match_set_any_mpls_label(match, 0);
        break;

    case MFF_MPLS_TC:
        match_set_any_mpls_tc(match, 0);
        break;

    case MFF_MPLS_BOS:
        match_set_any_mpls_bos(match, 0);
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
    case MFF_IP_DSCP_SHIFTED:
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
        match->wc.masks.nw_frag &= ~FLOW_NW_FRAG_MASK;
        match->flow.nw_frag &= ~FLOW_NW_FRAG_MASK;
        break;

    case MFF_ARP_OP:
        match->wc.masks.nw_proto = 0;
        match->flow.nw_proto = 0;
        break;

    case MFF_ARP_SHA:
    case MFF_ND_SLL:
        match->flow.arp_sha = eth_addr_zero;
        match->wc.masks.arp_sha = eth_addr_zero;
        break;

    case MFF_ARP_THA:
    case MFF_ND_TLL:
        match->flow.arp_tha = eth_addr_zero;
        match->wc.masks.arp_tha = eth_addr_zero;
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
    case MFF_SCTP_SRC:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV6_TYPE:
        match->wc.masks.tp_src = htons(0);
        match->flow.tp_src = htons(0);
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_SCTP_DST:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_CODE:
        match->wc.masks.tp_dst = htons(0);
        match->flow.tp_dst = htons(0);
        break;

    case MFF_TCP_FLAGS:
        match->wc.masks.tcp_flags = htons(0);
        match->flow.tcp_flags = htons(0);
        break;

    case MFF_ND_TARGET:
        memset(&match->wc.masks.nd_target, 0,
               sizeof match->wc.masks.nd_target);
        memset(&match->flow.nd_target, 0, sizeof match->flow.nd_target);
        break;

    case MFF_N_IDS:
    default:
        OVS_NOT_REACHED();
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
 * is responsible for ensuring that 'match' meets 'mf''s prerequisites.
 *
 * If non-NULL, 'err_str' returns a malloc'ed string describing any errors
 * with the request or NULL if there is no error. The caller is reponsible
 * for freeing the string.
 *
 * Return a set of enum ofputil_protocol bits (as an uint32_t to avoid circular
 * dependency on enum ofputil_protocol definition) indicating which OpenFlow
 * protocol versions can support this functionality. */
uint32_t
mf_set(const struct mf_field *mf,
       const union mf_value *value, const union mf_value *mask,
       struct match *match, char **err_str)
{
    if (!mask || is_all_ones(mask, mf->n_bytes)) {
        mf_set_value(mf, value, match, err_str);
        return mf->usable_protocols_exact;
    } else if (is_all_zeros(mask, mf->n_bytes) && !mf_is_tun_metadata(mf)) {
        /* Tunnel metadata matches on the existence of the field itself, so
         * it still needs to be encoded even if the value is wildcarded. */
        mf_set_wild(mf, match, err_str);
        return OFPUTIL_P_ANY;
    }

    if (err_str) {
        *err_str = NULL;
    }

    switch (mf->id) {
    case MFF_CT_ZONE:
    case MFF_RECIRC_ID:
    case MFF_CONJ_ID:
    case MFF_IN_PORT:
    case MFF_IN_PORT_OXM:
    case MFF_ACTSET_OUTPUT:
    case MFF_SKB_PRIORITY:
    case MFF_ETH_TYPE:
    case MFF_DL_VLAN:
    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
    case MFF_MPLS_LABEL:
    case MFF_MPLS_TC:
    case MFF_MPLS_BOS:
    case MFF_IP_PROTO:
    case MFF_IP_TTL:
    case MFF_IP_DSCP:
    case MFF_IP_DSCP_SHIFTED:
    case MFF_IP_ECN:
    case MFF_ARP_OP:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
        return OFPUTIL_P_NONE;

    case MFF_DP_HASH:
        match_set_dp_hash_masked(match, ntohl(value->be32), ntohl(mask->be32));
        break;
    case MFF_TUN_ID:
        match_set_tun_id_masked(match, value->be64, mask->be64);
        break;
    case MFF_TUN_SRC:
        match_set_tun_src_masked(match, value->be32, mask->be32);
        break;
    case MFF_TUN_DST:
        match_set_tun_dst_masked(match, value->be32, mask->be32);
        break;
    case MFF_TUN_IPV6_SRC:
        match_set_tun_ipv6_src_masked(match, &value->ipv6, &mask->ipv6);
        break;
    case MFF_TUN_IPV6_DST:
        match_set_tun_ipv6_dst_masked(match, &value->ipv6, &mask->ipv6);
        break;
    case MFF_TUN_FLAGS:
        match_set_tun_flags_masked(match, ntohs(value->be16), ntohs(mask->be16));
        break;
    case MFF_TUN_GBP_ID:
        match_set_tun_gbp_id_masked(match, value->be16, mask->be16);
        break;
    case MFF_TUN_GBP_FLAGS:
        match_set_tun_gbp_flags_masked(match, value->u8, mask->u8);
        break;
    case MFF_TUN_TTL:
        match_set_tun_ttl_masked(match, value->u8, mask->u8);
        break;
    case MFF_TUN_TOS:
        match_set_tun_tos_masked(match, value->u8, mask->u8);
        break;
    CASE_MFF_TUN_METADATA:
        tun_metadata_set_match(mf, value, mask, match, err_str);
        break;

    case MFF_METADATA:
        match_set_metadata_masked(match, value->be64, mask->be64);
        break;

    CASE_MFF_REGS:
        match_set_reg_masked(match, mf->id - MFF_REG0,
                             ntohl(value->be32), ntohl(mask->be32));
        break;

    CASE_MFF_XREGS:
        match_set_xreg_masked(match, mf->id - MFF_XREG0,
                              ntohll(value->be64), ntohll(mask->be64));
        break;

    case MFF_PKT_MARK:
        match_set_pkt_mark_masked(match, ntohl(value->be32),
                                  ntohl(mask->be32));
        break;

    case MFF_CT_STATE:
        match_set_ct_state_masked(match, ntohl(value->be32), ntohl(mask->be32));
        break;

    case MFF_CT_MARK:
        match_set_ct_mark_masked(match, ntohl(value->be32), ntohl(mask->be32));
        break;

    case MFF_CT_LABEL:
        match_set_ct_label_masked(match, ntoh128(value->be128),
                                  mask ? ntoh128(mask->be128) : OVS_U128_MAX);
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
            mf_set_value(mf, value, match, err_str);
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
    case MFF_SCTP_SRC:
        match_set_tp_src_masked(match, value->be16, mask->be16);
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_SCTP_DST:
        match_set_tp_dst_masked(match, value->be16, mask->be16);
        break;

    case MFF_TCP_FLAGS:
        match_set_tcp_flags_masked(match, value->be16, mask->be16);
        break;

    case MFF_N_IDS:
    default:
        OVS_NOT_REACHED();
    }

    return ((mf->usable_protocols_bitwise == mf->usable_protocols_cidr
             || ip_is_cidr(mask->be32))
            ? mf->usable_protocols_cidr
            : mf->usable_protocols_bitwise);
}

static enum ofperr
mf_check__(const struct mf_subfield *sf, const struct flow *flow,
           const char *type)
{
    if (!sf->field) {
        VLOG_WARN_RL(&rl, "unknown %s field", type);
        return OFPERR_OFPBAC_BAD_SET_TYPE;
    } else if (!sf->n_bits) {
        VLOG_WARN_RL(&rl, "zero bit %s field %s", type, sf->field->name);
        return OFPERR_OFPBAC_BAD_SET_LEN;
    } else if (sf->ofs >= sf->field->n_bits) {
        VLOG_WARN_RL(&rl, "bit offset %d exceeds %d-bit width of %s field %s",
                     sf->ofs, sf->field->n_bits, type, sf->field->name);
        return OFPERR_OFPBAC_BAD_SET_LEN;
    } else if (sf->ofs + sf->n_bits > sf->field->n_bits) {
        VLOG_WARN_RL(&rl, "bit offset %d and width %d exceeds %d-bit width "
                     "of %s field %s", sf->ofs, sf->n_bits,
                     sf->field->n_bits, type, sf->field->name);
        return OFPERR_OFPBAC_BAD_SET_LEN;
    } else if (flow && !mf_are_prereqs_ok(sf->field, flow)) {
        VLOG_WARN_RL(&rl, "%s field %s lacks correct prerequisites",
                     type, sf->field->name);
        return OFPERR_OFPBAC_MATCH_INCONSISTENT;
    } else {
        return 0;
    }
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
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
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

static char *
mf_from_integer_string(const struct mf_field *mf, const char *s,
                       uint8_t *valuep, uint8_t *maskp)
{
    char *tail;
    const char *err_str = "";
    int err;

    err = parse_int_string(s, valuep, mf->n_bytes, &tail);
    if (err || (*tail != '\0' && *tail != '/')) {
        err_str = "value";
        goto syntax_error;
    }

    if (*tail == '/') {
        err = parse_int_string(tail + 1, maskp, mf->n_bytes, &tail);
        if (err || *tail != '\0') {
            err_str = "mask";
            goto syntax_error;
        }
    } else {
        memset(maskp, 0xff, mf->n_bytes);
    }

    return NULL;

syntax_error:
    if (err == ERANGE) {
        return xasprintf("%s: %s too large for %u-byte field %s",
                         s, err_str, mf->n_bytes, mf->name);
    } else {
        return xasprintf("%s: bad syntax for %s %s", s, mf->name, err_str);
    }
}

static char *
mf_from_ethernet_string(const struct mf_field *mf, const char *s,
                        struct eth_addr *mac, struct eth_addr *mask)
{
    int n;

    ovs_assert(mf->n_bytes == ETH_ADDR_LEN);

    n = -1;
    if (ovs_scan(s, ETH_ADDR_SCAN_FMT"%n", ETH_ADDR_SCAN_ARGS(*mac), &n)
        && n == strlen(s)) {
        *mask = eth_addr_exact;
        return NULL;
    }

    n = -1;
    if (ovs_scan(s, ETH_ADDR_SCAN_FMT"/"ETH_ADDR_SCAN_FMT"%n",
                 ETH_ADDR_SCAN_ARGS(*mac), ETH_ADDR_SCAN_ARGS(*mask), &n)
        && n == strlen(s)) {
        return NULL;
    }

    return xasprintf("%s: invalid Ethernet address", s);
}

static char *
mf_from_ipv4_string(const struct mf_field *mf, const char *s,
                    ovs_be32 *ip, ovs_be32 *mask)
{
    ovs_assert(mf->n_bytes == sizeof *ip);
    return ip_parse_masked(s, ip, mask);
}

static char *
mf_from_ipv6_string(const struct mf_field *mf, const char *s,
                    struct in6_addr *ipv6, struct in6_addr *mask)
{
    ovs_assert(mf->n_bytes == sizeof *ipv6);
    return ipv6_parse_masked(s, ipv6, mask);
}

static char *
mf_from_ofp_port_string(const struct mf_field *mf, const char *s,
                        ovs_be16 *valuep, ovs_be16 *maskp)
{
    ofp_port_t port;

    ovs_assert(mf->n_bytes == sizeof(ovs_be16));

    if (ofputil_port_from_string(s, &port)) {
        *valuep = htons(ofp_to_u16(port));
        *maskp = OVS_BE16_MAX;
        return NULL;
    }
    return xasprintf("%s: port value out of range for %s", s, mf->name);
}

static char *
mf_from_ofp_port_string32(const struct mf_field *mf, const char *s,
                          ovs_be32 *valuep, ovs_be32 *maskp)
{
    ofp_port_t port;

    ovs_assert(mf->n_bytes == sizeof(ovs_be32));
    if (ofputil_port_from_string(s, &port)) {
        *valuep = ofputil_port_to_ofp11(port);
        *maskp = OVS_BE32_MAX;
        return NULL;
    }
    return xasprintf("%s: port value out of range for %s", s, mf->name);
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

static char *
parse_mf_flags(const char *s, const char *(*bit_to_string)(uint32_t),
               const char *field_name, ovs_be16 *flagsp, ovs_be16 allowed,
               ovs_be16 *maskp)
{
    int err;
    char *err_str;
    uint32_t flags, mask;

    err = parse_flags(s, bit_to_string, '\0', field_name, &err_str,
                      &flags, ntohs(allowed), maskp ? &mask : NULL);
    if (err < 0) {
        return err_str;
    }

    *flagsp = htons(flags);
    if (maskp) {
        *maskp = htons(mask);
    }

    return NULL;
}

static char *
mf_from_tcp_flags_string(const char *s, ovs_be16 *flagsp, ovs_be16 *maskp)
{
    return parse_mf_flags(s, packet_tcp_flag_to_string, "TCP", flagsp,
                          TCP_FLAGS_BE16(OVS_BE16_MAX), maskp);
}

static char *
mf_from_tun_flags_string(const char *s, ovs_be16 *flagsp, ovs_be16 *maskp)
{
    return parse_mf_flags(s, flow_tun_flag_to_string, "tunnel", flagsp,
                          htons(FLOW_TNL_PUB_F_MASK), maskp);
}

static char *
mf_from_ct_state_string(const char *s, ovs_be32 *flagsp, ovs_be32 *maskp)
{
    int err;
    char *err_str;
    uint32_t flags, mask;

    err = parse_flags(s, ct_state_to_string, '\0', "ct_state", &err_str,
                      &flags, CS_SUPPORTED_MASK, maskp ? &mask : NULL);
    if (err < 0) {
        return err_str;
    }

    *flagsp = htonl(flags);
    if (maskp) {
        *maskp = htonl(mask);
    }

    return NULL;
}

/* Parses 's', a string value for field 'mf', into 'value' and 'mask'.  Returns
 * NULL if successful, otherwise a malloc()'d string describing the error. */
char *
mf_parse(const struct mf_field *mf, const char *s,
         union mf_value *value, union mf_value *mask)
{
    char *error;

    if (!strcmp(s, "*")) {
        memset(value, 0, mf->n_bytes);
        memset(mask, 0, mf->n_bytes);
        return NULL;
    }

    switch (mf->string) {
    case MFS_DECIMAL:
    case MFS_HEXADECIMAL:
        error = mf_from_integer_string(mf, s,
                                       (uint8_t *) value, (uint8_t *) mask);
        break;

    case MFS_CT_STATE:
        ovs_assert(mf->n_bytes == sizeof(ovs_be32));
        error = mf_from_ct_state_string(s, &value->be32, &mask->be32);
        break;

    case MFS_ETHERNET:
        error = mf_from_ethernet_string(mf, s, &value->mac, &mask->mac);
        break;

    case MFS_IPV4:
        error = mf_from_ipv4_string(mf, s, &value->be32, &mask->be32);
        break;

    case MFS_IPV6:
        error = mf_from_ipv6_string(mf, s, &value->ipv6, &mask->ipv6);
        break;

    case MFS_OFP_PORT:
        error = mf_from_ofp_port_string(mf, s, &value->be16, &mask->be16);
        break;

    case MFS_OFP_PORT_OXM:
        error = mf_from_ofp_port_string32(mf, s, &value->be32, &mask->be32);
        break;

    case MFS_FRAG:
        error = mf_from_frag_string(s, &value->u8, &mask->u8);
        break;

    case MFS_TNL_FLAGS:
        ovs_assert(mf->n_bytes == sizeof(ovs_be16));
        error = mf_from_tun_flags_string(s, &value->be16, &mask->be16);
        break;

    case MFS_TCP_FLAGS:
        ovs_assert(mf->n_bytes == sizeof(ovs_be16));
        error = mf_from_tcp_flags_string(s, &value->be16, &mask->be16);
        break;

    default:
        OVS_NOT_REACHED();
    }

    if (!error && !mf_is_mask_valid(mf, mask)) {
        error = xasprintf("%s: invalid mask for field %s", s, mf->name);
    }
    return error;
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
    if (mf->string == MFS_HEXADECIMAL) {
        ds_put_hex(s, valuep, mf->n_bytes);
    } else {
        unsigned long long int integer = 0;
        int i;

        ovs_assert(mf->n_bytes <= 8);
        for (i = 0; i < mf->n_bytes; i++) {
            integer = (integer << 8) | valuep[i];
        }
        ds_put_format(s, "%lld", integer);
    }

    if (maskp) {
        /* I guess we could write the mask in decimal for MFS_DECIMAL but I'm
         * not sure that that a bit-mask written in decimal is ever easier to
         * understand than the same bit-mask written in hexadecimal. */
        ds_put_char(s, '/');
        ds_put_hex(s, maskp, mf->n_bytes);
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
mf_format_tnl_flags_string(ovs_be16 value, ovs_be16 mask, struct ds *s)
{
    format_flags_masked(s, NULL, flow_tun_flag_to_string, ntohs(value),
                        ntohs(mask) & FLOW_TNL_PUB_F_MASK, FLOW_TNL_PUB_F_MASK);
}

static void
mf_format_tcp_flags_string(ovs_be16 value, ovs_be16 mask, struct ds *s)
{
    format_flags_masked(s, NULL, packet_tcp_flag_to_string, ntohs(value),
                        TCP_FLAGS(mask), TCP_FLAGS(OVS_BE16_MAX));
}

static void
mf_format_ct_state_string(ovs_be32 value, ovs_be32 mask, struct ds *s)
{
    format_flags_masked(s, NULL, ct_state_to_string, ntohl(value),
                        ntohl(mask), UINT16_MAX);
}

/* Appends to 's' a string representation of field 'mf' whose value is in
 * 'value' and 'mask'.  'mask' may be NULL to indicate an exact match. */
void
mf_format(const struct mf_field *mf,
          const union mf_value *value, const union mf_value *mask,
          struct ds *s)
{
    if (mask) {
        if (is_all_zeros(mask, mf->n_bytes)) {
            ds_put_cstr(s, "ANY");
            return;
        } else if (is_all_ones(mask, mf->n_bytes)) {
            mask = NULL;
        }
    }

    switch (mf->string) {
    case MFS_OFP_PORT_OXM:
        if (!mask) {
            ofp_port_t port;
            ofputil_port_from_ofp11(value->be32, &port);
            ofputil_format_port(port, s);
            break;
        }
        /* fall through */
    case MFS_OFP_PORT:
        if (!mask) {
            ofputil_format_port(u16_to_ofp(ntohs(value->be16)), s);
            break;
        }
        /* fall through */
    case MFS_DECIMAL:
    case MFS_HEXADECIMAL:
        mf_format_integer_string(mf, (uint8_t *) value, (uint8_t *) mask, s);
        break;

    case MFS_CT_STATE:
        mf_format_ct_state_string(value->be32,
                                  mask ? mask->be32 : OVS_BE32_MAX, s);
        break;

    case MFS_ETHERNET:
        eth_format_masked(value->mac, mask ? &mask->mac : NULL, s);
        break;

    case MFS_IPV4:
        ip_format_masked(value->be32, mask ? mask->be32 : OVS_BE32_MAX, s);
        break;

    case MFS_IPV6:
        ipv6_format_masked(&value->ipv6, mask ? &mask->ipv6 : NULL, s);
        break;

    case MFS_FRAG:
        mf_format_frag_string(value->u8, mask ? mask->u8 : UINT8_MAX, s);
        break;

    case MFS_TNL_FLAGS:
        mf_format_tnl_flags_string(value->be16,
                                   mask ? mask->be16 : OVS_BE16_MAX, s);
        break;

    case MFS_TCP_FLAGS:
        mf_format_tcp_flags_string(value->be16,
                                   mask ? mask->be16 : OVS_BE16_MAX, s);
        break;

    default:
        OVS_NOT_REACHED();
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
    mf_set(field, &value, &mask, match, NULL);
}

/* 'v' and 'm' correspond to values of 'field'.  This function copies them into
 * 'match' in the correspond positions. */
void
mf_mask_subfield(const struct mf_field *field,
                 const union mf_subvalue *v,
                 const union mf_subvalue *m,
                 struct match *match)
{
    union mf_value value, mask;

    mf_get(field, match, &value, &mask);
    bitwise_copy(v, sizeof *v, 0, &value, field->n_bytes, 0, field->n_bits);
    bitwise_copy(m, sizeof *m, 0, &mask,  field->n_bytes, 0, field->n_bits);
    mf_set(field, &value, &mask, match, NULL);
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

void
mf_format_subvalue(const union mf_subvalue *subvalue, struct ds *s)
{
    ds_put_hex(s, subvalue->u8, sizeof subvalue->u8);
}

void
field_array_set(enum mf_field_id id, const union mf_value *value,
                struct field_array *fa)
{
    ovs_assert(id < MFF_N_IDS);
    bitmap_set1(fa->used.bm, id);
    fa->value[id] = *value;
}
