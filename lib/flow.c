/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include <sys/types.h>
#include "flow.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "byte-order.h"
#include "coverage.h"
#include "csum.h"
#include "dynamic-string.h"
#include "hash.h"
#include "jhash.h"
#include "match.h"
#include "dp-packet.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "odp-util.h"
#include "random.h"
#include "unaligned.h"

COVERAGE_DEFINE(flow_extract);
COVERAGE_DEFINE(miniflow_malloc);

/* U64 indices for segmented flow classification. */
const uint8_t flow_segment_u64s[4] = {
    FLOW_SEGMENT_1_ENDS_AT / sizeof(uint64_t),
    FLOW_SEGMENT_2_ENDS_AT / sizeof(uint64_t),
    FLOW_SEGMENT_3_ENDS_AT / sizeof(uint64_t),
    FLOW_U64S
};

/* Asserts that field 'f1' follows immediately after 'f0' in struct flow,
 * without any intervening padding. */
#define ASSERT_SEQUENTIAL(f0, f1)                       \
    BUILD_ASSERT_DECL(offsetof(struct flow, f0)         \
                      + MEMBER_SIZEOF(struct flow, f0)  \
                      == offsetof(struct flow, f1))

/* Asserts that fields 'f0' and 'f1' are in the same 32-bit aligned word within
 * struct flow. */
#define ASSERT_SAME_WORD(f0, f1)                        \
    BUILD_ASSERT_DECL(offsetof(struct flow, f0) / 4     \
                      == offsetof(struct flow, f1) / 4)

/* Asserts that 'f0' and 'f1' are both sequential and within the same 32-bit
 * aligned word in struct flow. */
#define ASSERT_SEQUENTIAL_SAME_WORD(f0, f1)     \
    ASSERT_SEQUENTIAL(f0, f1);                  \
    ASSERT_SAME_WORD(f0, f1)

/* miniflow_extract() assumes the following to be true to optimize the
 * extraction process. */
ASSERT_SEQUENTIAL_SAME_WORD(dl_type, vlan_tci);

ASSERT_SEQUENTIAL_SAME_WORD(nw_frag, nw_tos);
ASSERT_SEQUENTIAL_SAME_WORD(nw_tos, nw_ttl);
ASSERT_SEQUENTIAL_SAME_WORD(nw_ttl, nw_proto);

/* TCP flags in the middle of a BE64, zeroes in the other half. */
BUILD_ASSERT_DECL(offsetof(struct flow, tcp_flags) % 8 == 4);

#if WORDS_BIGENDIAN
#define TCP_FLAGS_BE32(tcp_ctl) ((OVS_FORCE ovs_be32)TCP_FLAGS_BE16(tcp_ctl) \
                                 << 16)
#else
#define TCP_FLAGS_BE32(tcp_ctl) ((OVS_FORCE ovs_be32)TCP_FLAGS_BE16(tcp_ctl))
#endif

ASSERT_SEQUENTIAL_SAME_WORD(tp_src, tp_dst);

/* Removes 'size' bytes from the head end of '*datap', of size '*sizep', which
 * must contain at least 'size' bytes of data.  Returns the first byte of data
 * removed. */
static inline const void *
data_pull(const void **datap, size_t *sizep, size_t size)
{
    const char *data = *datap;
    *datap = data + size;
    *sizep -= size;
    return data;
}

/* If '*datap' has at least 'size' bytes of data, removes that many bytes from
 * the head end of '*datap' and returns the first byte removed.  Otherwise,
 * returns a null pointer without modifying '*datap'. */
static inline const void *
data_try_pull(const void **datap, size_t *sizep, size_t size)
{
    return OVS_LIKELY(*sizep >= size) ? data_pull(datap, sizep, size) : NULL;
}

/* Context for pushing data to a miniflow. */
struct mf_ctx {
    struct flowmap map;
    uint64_t *data;
    uint64_t * const end;
};

/* miniflow_push_* macros allow filling in a miniflow data values in order.
 * Assertions are needed only when the layout of the struct flow is modified.
 * 'ofs' is a compile-time constant, which allows most of the code be optimized
 * away.  Some GCC versions gave warnings on ALWAYS_INLINE, so these are
 * defined as macros. */

#if (FLOW_WC_SEQ != 33)
#define MINIFLOW_ASSERT(X) ovs_assert(X)
BUILD_MESSAGE("FLOW_WC_SEQ changed: miniflow_extract() will have runtime "
               "assertions enabled. Consider updating FLOW_WC_SEQ after "
               "testing")
#else
#define MINIFLOW_ASSERT(X)
#endif

/* True if 'IDX' and higher bits are not set. */
#define ASSERT_FLOWMAP_NOT_SET(FM, IDX)                                 \
{                                                                       \
    MINIFLOW_ASSERT(!((FM)->bits[(IDX) / MAP_T_BITS] &                  \
                      (FLOWMAP_MAX << ((IDX) % MAP_T_BITS))));          \
    for (size_t i = (IDX) / MAP_T_BITS + 1; i < FLOWMAP_UNITS; i++) {   \
        MINIFLOW_ASSERT(!(FM)->bits[i]);                                \
    }                                                                   \
}

#define miniflow_set_map(MF, OFS)            \
    {                                        \
    ASSERT_FLOWMAP_NOT_SET(&MF.map, (OFS));  \
    flowmap_set(&MF.map, (OFS), 1);          \
}

#define miniflow_assert_in_map(MF, OFS)             \
    MINIFLOW_ASSERT(FLOWMAP_IS_SET(MF.map, (OFS))); \
    ASSERT_FLOWMAP_NOT_SET(&MF.map, (OFS) + 1)

#define miniflow_push_uint64_(MF, OFS, VALUE)              \
{                                                          \
    MINIFLOW_ASSERT(MF.data < MF.end && (OFS) % 8 == 0);   \
    *MF.data++ = VALUE;                                    \
    miniflow_set_map(MF, OFS / 8);                         \
}

#define miniflow_push_be64_(MF, OFS, VALUE)                     \
    miniflow_push_uint64_(MF, OFS, (OVS_FORCE uint64_t)(VALUE))

#define miniflow_push_uint32_(MF, OFS, VALUE)   \
    {                                           \
    MINIFLOW_ASSERT(MF.data < MF.end);          \
                                                \
    if ((OFS) % 8 == 0) {                       \
        miniflow_set_map(MF, OFS / 8);          \
        *(uint32_t *)MF.data = VALUE;           \
    } else if ((OFS) % 8 == 4) {                \
        miniflow_assert_in_map(MF, OFS / 8);    \
        *((uint32_t *)MF.data + 1) = VALUE;     \
        MF.data++;                              \
    }                                           \
}

#define miniflow_push_be32_(MF, OFS, VALUE)                     \
    miniflow_push_uint32_(MF, OFS, (OVS_FORCE uint32_t)(VALUE))

#define miniflow_push_uint16_(MF, OFS, VALUE)   \
{                                               \
    MINIFLOW_ASSERT(MF.data < MF.end);          \
                                                \
    if ((OFS) % 8 == 0) {                       \
        miniflow_set_map(MF, OFS / 8);          \
        *(uint16_t *)MF.data = VALUE;           \
    } else if ((OFS) % 8 == 2) {                \
        miniflow_assert_in_map(MF, OFS / 8);    \
        *((uint16_t *)MF.data + 1) = VALUE;     \
    } else if ((OFS) % 8 == 4) {                \
        miniflow_assert_in_map(MF, OFS / 8);    \
        *((uint16_t *)MF.data + 2) = VALUE;     \
    } else if ((OFS) % 8 == 6) {                \
        miniflow_assert_in_map(MF, OFS / 8);    \
        *((uint16_t *)MF.data + 3) = VALUE;     \
        MF.data++;                              \
    }                                           \
}

#define miniflow_pad_to_64_(MF, OFS)                            \
{                                                               \
    MINIFLOW_ASSERT((OFS) % 8 != 0);                            \
    miniflow_assert_in_map(MF, OFS / 8);                        \
                                                                \
    memset((uint8_t *)MF.data + (OFS) % 8, 0, 8 - (OFS) % 8);   \
    MF.data++;                                                  \
}

#define miniflow_push_be16_(MF, OFS, VALUE)                     \
    miniflow_push_uint16_(MF, OFS, (OVS_FORCE uint16_t)VALUE);

#define miniflow_set_maps(MF, OFS, N_WORDS)                     \
{                                                               \
    size_t ofs = (OFS);                                         \
    size_t n_words = (N_WORDS);                                 \
                                                                \
    MINIFLOW_ASSERT(n_words && MF.data + n_words <= MF.end);    \
    ASSERT_FLOWMAP_NOT_SET(&MF.map, ofs);                       \
    flowmap_set(&MF.map, ofs, n_words);                         \
}

/* Data at 'valuep' may be unaligned. */
#define miniflow_push_words_(MF, OFS, VALUEP, N_WORDS)          \
{                                                               \
    MINIFLOW_ASSERT((OFS) % 8 == 0);                            \
    miniflow_set_maps(MF, (OFS) / 8, (N_WORDS));                \
    memcpy(MF.data, (VALUEP), (N_WORDS) * sizeof *MF.data);     \
    MF.data += (N_WORDS);                                       \
}

/* Push 32-bit words padded to 64-bits. */
#define miniflow_push_words_32_(MF, OFS, VALUEP, N_WORDS)               \
{                                                                       \
    miniflow_set_maps(MF, (OFS) / 8, DIV_ROUND_UP(N_WORDS, 2));         \
    memcpy(MF.data, (VALUEP), (N_WORDS) * sizeof(uint32_t));            \
    MF.data += DIV_ROUND_UP(N_WORDS, 2);                                \
    if ((N_WORDS) & 1) {                                                \
        *((uint32_t *)MF.data - 1) = 0;                                 \
    }                                                                   \
}

/* Data at 'valuep' may be unaligned. */
/* MACs start 64-aligned, and must be followed by other data or padding. */
#define miniflow_push_macs_(MF, OFS, VALUEP)                    \
{                                                               \
    miniflow_set_maps(MF, (OFS) / 8, 2);                        \
    memcpy(MF.data, (VALUEP), 2 * ETH_ADDR_LEN);                \
    MF.data += 1;                   /* First word only. */      \
}

#define miniflow_push_uint32(MF, FIELD, VALUE)                      \
    miniflow_push_uint32_(MF, offsetof(struct flow, FIELD), VALUE)

#define miniflow_push_be32(MF, FIELD, VALUE)                        \
    miniflow_push_be32_(MF, offsetof(struct flow, FIELD), VALUE)

#define miniflow_push_uint16(MF, FIELD, VALUE)                      \
    miniflow_push_uint16_(MF, offsetof(struct flow, FIELD), VALUE)

#define miniflow_push_be16(MF, FIELD, VALUE)                        \
    miniflow_push_be16_(MF, offsetof(struct flow, FIELD), VALUE)

#define miniflow_pad_to_64(MF, FIELD)                       \
    miniflow_pad_to_64_(MF, offsetof(struct flow, FIELD))

#define miniflow_push_words(MF, FIELD, VALUEP, N_WORDS)                 \
    miniflow_push_words_(MF, offsetof(struct flow, FIELD), VALUEP, N_WORDS)

#define miniflow_push_words_32(MF, FIELD, VALUEP, N_WORDS)              \
    miniflow_push_words_32_(MF, offsetof(struct flow, FIELD), VALUEP, N_WORDS)

#define miniflow_push_macs(MF, FIELD, VALUEP)                       \
    miniflow_push_macs_(MF, offsetof(struct flow, FIELD), VALUEP)

/* Pulls the MPLS headers at '*datap' and returns the count of them. */
static inline int
parse_mpls(const void **datap, size_t *sizep)
{
    const struct mpls_hdr *mh;
    int count = 0;

    while ((mh = data_try_pull(datap, sizep, sizeof *mh))) {
        count++;
        if (mh->mpls_lse.lo & htons(1 << MPLS_BOS_SHIFT)) {
            break;
        }
    }
    return MIN(count, FLOW_MAX_MPLS_LABELS);
}

static inline ovs_be16
parse_vlan(const void **datap, size_t *sizep)
{
    const struct eth_header *eth = *datap;

    struct qtag_prefix {
        ovs_be16 eth_type;      /* ETH_TYPE_VLAN */
        ovs_be16 tci;
    };

    data_pull(datap, sizep, ETH_ADDR_LEN * 2);

    if (eth->eth_type == htons(ETH_TYPE_VLAN)) {
        if (OVS_LIKELY(*sizep
                       >= sizeof(struct qtag_prefix) + sizeof(ovs_be16))) {
            const struct qtag_prefix *qp = data_pull(datap, sizep, sizeof *qp);
            return qp->tci | htons(VLAN_CFI);
        }
    }
    return 0;
}

static inline ovs_be16
parse_ethertype(const void **datap, size_t *sizep)
{
    const struct llc_snap_header *llc;
    ovs_be16 proto;

    proto = *(ovs_be16 *) data_pull(datap, sizep, sizeof proto);
    if (OVS_LIKELY(ntohs(proto) >= ETH_TYPE_MIN)) {
        return proto;
    }

    if (OVS_UNLIKELY(*sizep < sizeof *llc)) {
        return htons(FLOW_DL_TYPE_NONE);
    }

    llc = *datap;
    if (OVS_UNLIKELY(llc->llc.llc_dsap != LLC_DSAP_SNAP
                     || llc->llc.llc_ssap != LLC_SSAP_SNAP
                     || llc->llc.llc_cntl != LLC_CNTL_SNAP
                     || memcmp(llc->snap.snap_org, SNAP_ORG_ETHERNET,
                               sizeof llc->snap.snap_org))) {
        return htons(FLOW_DL_TYPE_NONE);
    }

    data_pull(datap, sizep, sizeof *llc);

    if (OVS_LIKELY(ntohs(llc->snap.snap_type) >= ETH_TYPE_MIN)) {
        return llc->snap.snap_type;
    }

    return htons(FLOW_DL_TYPE_NONE);
}

static inline void
parse_icmpv6(const void **datap, size_t *sizep, const struct icmp6_hdr *icmp,
             const struct in6_addr **nd_target,
             struct eth_addr arp_buf[2])
{
    if (icmp->icmp6_code == 0 &&
        (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT ||
         icmp->icmp6_type == ND_NEIGHBOR_ADVERT)) {

        *nd_target = data_try_pull(datap, sizep, sizeof **nd_target);
        if (OVS_UNLIKELY(!*nd_target)) {
            return;
        }

        while (*sizep >= 8) {
            /* The minimum size of an option is 8 bytes, which also is
             * the size of Ethernet link-layer options. */
            const struct ovs_nd_opt *nd_opt = *datap;
            int opt_len = nd_opt->nd_opt_len * ND_OPT_LEN;

            if (!opt_len || opt_len > *sizep) {
                return;
            }

            /* Store the link layer address if the appropriate option is
             * provided.  It is considered an error if the same link
             * layer option is specified twice. */
            if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR
                && opt_len == 8) {
                if (OVS_LIKELY(eth_addr_is_zero(arp_buf[0]))) {
                    arp_buf[0] = nd_opt->nd_opt_mac;
                } else {
                    goto invalid;
                }
            } else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR
                       && opt_len == 8) {
                if (OVS_LIKELY(eth_addr_is_zero(arp_buf[1]))) {
                    arp_buf[1] = nd_opt->nd_opt_mac;
                } else {
                    goto invalid;
                }
            }

            if (OVS_UNLIKELY(!data_try_pull(datap, sizep, opt_len))) {
                return;
            }
        }
    }

    return;

invalid:
    *nd_target = NULL;
    arp_buf[0] = eth_addr_zero;
    arp_buf[1] = eth_addr_zero;
}

/* Initializes 'flow' members from 'packet' and 'md'
 *
 * Initializes 'packet' header l2 pointer to the start of the Ethernet
 * header, and the layer offsets as follows:
 *
 *    - packet->l2_5_ofs to the start of the MPLS shim header, or UINT16_MAX
 *      when there is no MPLS shim header.
 *
 *    - packet->l3_ofs to just past the Ethernet header, or just past the
 *      vlan_header if one is present, to the first byte of the payload of the
 *      Ethernet frame.  UINT16_MAX if the frame is too short to contain an
 *      Ethernet header.
 *
 *    - packet->l4_ofs to just past the IPv4 header, if one is present and
 *      has at least the content used for the fields of interest for the flow,
 *      otherwise UINT16_MAX.
 */
void
flow_extract(struct dp_packet *packet, struct flow *flow)
{
    struct {
        struct miniflow mf;
        uint64_t buf[FLOW_U64S];
    } m;

    COVERAGE_INC(flow_extract);

    miniflow_extract(packet, &m.mf);
    miniflow_expand(&m.mf, flow);
}

/* Caller is responsible for initializing 'dst' with enough storage for
 * FLOW_U64S * 8 bytes. */
void
miniflow_extract(struct dp_packet *packet, struct miniflow *dst)
{
    const struct pkt_metadata *md = &packet->md;
    const void *data = dp_packet_data(packet);
    size_t size = dp_packet_size(packet);
    uint64_t *values = miniflow_values(dst);
    struct mf_ctx mf = { FLOWMAP_EMPTY_INITIALIZER, values,
                         values + FLOW_U64S };
    const char *l2;
    ovs_be16 dl_type;
    uint8_t nw_frag, nw_tos, nw_ttl, nw_proto;

    /* Metadata. */
    if (md->tunnel.ip_dst) {
        miniflow_push_words(mf, tunnel, &md->tunnel,
                            offsetof(struct flow_tnl, metadata) /
                            sizeof(uint64_t));

        if (!(md->tunnel.flags & FLOW_TNL_F_UDPIF)) {
            if (md->tunnel.metadata.present.map) {
                miniflow_push_words(mf, tunnel.metadata, &md->tunnel.metadata,
                                    sizeof md->tunnel.metadata /
                                    sizeof(uint64_t));
            }
        } else {
            if (md->tunnel.metadata.present.len) {
                miniflow_push_words(mf, tunnel.metadata.present,
                                    &md->tunnel.metadata.present, 1);
                miniflow_push_words(mf, tunnel.metadata.opts.gnv,
                                    md->tunnel.metadata.opts.gnv,
                                    DIV_ROUND_UP(md->tunnel.metadata.present.len,
                                                 sizeof(uint64_t)));
            }
        }
    }
    if (md->skb_priority || md->pkt_mark) {
        miniflow_push_uint32(mf, skb_priority, md->skb_priority);
        miniflow_push_uint32(mf, pkt_mark, md->pkt_mark);
    }
    miniflow_push_uint32(mf, dp_hash, md->dp_hash);
    miniflow_push_uint32(mf, in_port, odp_to_u32(md->in_port.odp_port));
    if (md->recirc_id) {
        miniflow_push_uint32(mf, recirc_id, md->recirc_id);
        miniflow_pad_to_64(mf, conj_id);
    }

    /* Initialize packet's layer pointer and offsets. */
    l2 = data;
    dp_packet_reset_offsets(packet);

    /* Must have full Ethernet header to proceed. */
    if (OVS_UNLIKELY(size < sizeof(struct eth_header))) {
        goto out;
    } else {
        ovs_be16 vlan_tci;

        /* Link layer. */
        ASSERT_SEQUENTIAL(dl_dst, dl_src);
        miniflow_push_macs(mf, dl_dst, data);
        /* dl_type, vlan_tci. */
        vlan_tci = parse_vlan(&data, &size);
        dl_type = parse_ethertype(&data, &size);
        miniflow_push_be16(mf, dl_type, dl_type);
        miniflow_push_be16(mf, vlan_tci, vlan_tci);
    }

    /* Parse mpls. */
    if (OVS_UNLIKELY(eth_type_mpls(dl_type))) {
        int count;
        const void *mpls = data;

        packet->l2_5_ofs = (char *)data - l2;
        count = parse_mpls(&data, &size);
        miniflow_push_words_32(mf, mpls_lse, mpls, count);
    }

    /* Network layer. */
    packet->l3_ofs = (char *)data - l2;

    nw_frag = 0;
    if (OVS_LIKELY(dl_type == htons(ETH_TYPE_IP))) {
        const struct ip_header *nh = data;
        int ip_len;
        uint16_t tot_len;

        if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
            goto out;
        }
        ip_len = IP_IHL(nh->ip_ihl_ver) * 4;

        if (OVS_UNLIKELY(ip_len < IP_HEADER_LEN)) {
            goto out;
        }
        if (OVS_UNLIKELY(size < ip_len)) {
            goto out;
        }
        tot_len = ntohs(nh->ip_tot_len);
        if (OVS_UNLIKELY(tot_len > size)) {
            goto out;
        }
        if (OVS_UNLIKELY(size - tot_len > UINT8_MAX)) {
            goto out;
        }
        dp_packet_set_l2_pad_size(packet, size - tot_len);
        size = tot_len;   /* Never pull padding. */

        /* Push both source and destination address at once. */
        miniflow_push_words(mf, nw_src, &nh->ip_src, 1);

        miniflow_push_be32(mf, ipv6_label, 0); /* Padding for IPv4. */

        nw_tos = nh->ip_tos;
        nw_ttl = nh->ip_ttl;
        nw_proto = nh->ip_proto;
        if (OVS_UNLIKELY(IP_IS_FRAGMENT(nh->ip_frag_off))) {
            nw_frag = FLOW_NW_FRAG_ANY;
            if (nh->ip_frag_off & htons(IP_FRAG_OFF_MASK)) {
                nw_frag |= FLOW_NW_FRAG_LATER;
            }
        }
        data_pull(&data, &size, ip_len);
    } else if (dl_type == htons(ETH_TYPE_IPV6)) {
        const struct ovs_16aligned_ip6_hdr *nh;
        ovs_be32 tc_flow;
        uint16_t plen;

        if (OVS_UNLIKELY(size < sizeof *nh)) {
            goto out;
        }
        nh = data_pull(&data, &size, sizeof *nh);

        plen = ntohs(nh->ip6_plen);
        if (OVS_UNLIKELY(plen > size)) {
            goto out;
        }
        /* Jumbo Payload option not supported yet. */
        if (OVS_UNLIKELY(size - plen > UINT8_MAX)) {
            goto out;
        }
        dp_packet_set_l2_pad_size(packet, size - plen);
        size = plen;   /* Never pull padding. */

        miniflow_push_words(mf, ipv6_src, &nh->ip6_src,
                            sizeof nh->ip6_src / 8);
        miniflow_push_words(mf, ipv6_dst, &nh->ip6_dst,
                            sizeof nh->ip6_dst / 8);

        tc_flow = get_16aligned_be32(&nh->ip6_flow);
        {
            ovs_be32 label = tc_flow & htonl(IPV6_LABEL_MASK);
            miniflow_push_be32(mf, ipv6_label, label);
        }

        nw_tos = ntohl(tc_flow) >> 20;
        nw_ttl = nh->ip6_hlim;
        nw_proto = nh->ip6_nxt;

        while (1) {
            if (OVS_LIKELY((nw_proto != IPPROTO_HOPOPTS)
                           && (nw_proto != IPPROTO_ROUTING)
                           && (nw_proto != IPPROTO_DSTOPTS)
                           && (nw_proto != IPPROTO_AH)
                           && (nw_proto != IPPROTO_FRAGMENT))) {
                /* It's either a terminal header (e.g., TCP, UDP) or one we
                 * don't understand.  In either case, we're done with the
                 * packet, so use it to fill in 'nw_proto'. */
                break;
            }

            /* We only verify that at least 8 bytes of the next header are
             * available, but many of these headers are longer.  Ensure that
             * accesses within the extension header are within those first 8
             * bytes. All extension headers are required to be at least 8
             * bytes. */
            if (OVS_UNLIKELY(size < 8)) {
                goto out;
            }

            if ((nw_proto == IPPROTO_HOPOPTS)
                || (nw_proto == IPPROTO_ROUTING)
                || (nw_proto == IPPROTO_DSTOPTS)) {
                /* These headers, while different, have the fields we care
                 * about in the same location and with the same
                 * interpretation. */
                const struct ip6_ext *ext_hdr = data;
                nw_proto = ext_hdr->ip6e_nxt;
                if (OVS_UNLIKELY(!data_try_pull(&data, &size,
                                                (ext_hdr->ip6e_len + 1) * 8))) {
                    goto out;
                }
            } else if (nw_proto == IPPROTO_AH) {
                /* A standard AH definition isn't available, but the fields
                 * we care about are in the same location as the generic
                 * option header--only the header length is calculated
                 * differently. */
                const struct ip6_ext *ext_hdr = data;
                nw_proto = ext_hdr->ip6e_nxt;
                if (OVS_UNLIKELY(!data_try_pull(&data, &size,
                                                (ext_hdr->ip6e_len + 2) * 4))) {
                    goto out;
                }
            } else if (nw_proto == IPPROTO_FRAGMENT) {
                const struct ovs_16aligned_ip6_frag *frag_hdr = data;

                nw_proto = frag_hdr->ip6f_nxt;
                if (!data_try_pull(&data, &size, sizeof *frag_hdr)) {
                    goto out;
                }

                /* We only process the first fragment. */
                if (frag_hdr->ip6f_offlg != htons(0)) {
                    nw_frag = FLOW_NW_FRAG_ANY;
                    if ((frag_hdr->ip6f_offlg & IP6F_OFF_MASK) != htons(0)) {
                        nw_frag |= FLOW_NW_FRAG_LATER;
                        nw_proto = IPPROTO_FRAGMENT;
                        break;
                    }
                }
            }
        }
    } else {
        if (dl_type == htons(ETH_TYPE_ARP) ||
            dl_type == htons(ETH_TYPE_RARP)) {
            struct eth_addr arp_buf[2];
            const struct arp_eth_header *arp = (const struct arp_eth_header *)
                data_try_pull(&data, &size, ARP_ETH_HEADER_LEN);

            if (OVS_LIKELY(arp) && OVS_LIKELY(arp->ar_hrd == htons(1))
                && OVS_LIKELY(arp->ar_pro == htons(ETH_TYPE_IP))
                && OVS_LIKELY(arp->ar_hln == ETH_ADDR_LEN)
                && OVS_LIKELY(arp->ar_pln == 4)) {
                miniflow_push_be32(mf, nw_src,
                                   get_16aligned_be32(&arp->ar_spa));
                miniflow_push_be32(mf, nw_dst,
                                   get_16aligned_be32(&arp->ar_tpa));

                /* We only match on the lower 8 bits of the opcode. */
                if (OVS_LIKELY(ntohs(arp->ar_op) <= 0xff)) {
                    miniflow_push_be32(mf, ipv6_label, 0); /* Pad with ARP. */
                    miniflow_push_be32(mf, nw_frag, htonl(ntohs(arp->ar_op)));
                }

                /* Must be adjacent. */
                ASSERT_SEQUENTIAL(arp_sha, arp_tha);

                arp_buf[0] = arp->ar_sha;
                arp_buf[1] = arp->ar_tha;
                miniflow_push_macs(mf, arp_sha, arp_buf);
                miniflow_pad_to_64(mf, tcp_flags);
            }
        }
        goto out;
    }

    packet->l4_ofs = (char *)data - l2;
    miniflow_push_be32(mf, nw_frag,
                       BYTES_TO_BE32(nw_frag, nw_tos, nw_ttl, nw_proto));

    if (OVS_LIKELY(!(nw_frag & FLOW_NW_FRAG_LATER))) {
        if (OVS_LIKELY(nw_proto == IPPROTO_TCP)) {
            if (OVS_LIKELY(size >= TCP_HEADER_LEN)) {
                const struct tcp_header *tcp = data;

                miniflow_push_be32(mf, arp_tha.ea[2], 0);
                miniflow_push_be32(mf, tcp_flags,
                                   TCP_FLAGS_BE32(tcp->tcp_ctl));
                miniflow_push_be16(mf, tp_src, tcp->tcp_src);
                miniflow_push_be16(mf, tp_dst, tcp->tcp_dst);
                miniflow_pad_to_64(mf, igmp_group_ip4);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_UDP)) {
            if (OVS_LIKELY(size >= UDP_HEADER_LEN)) {
                const struct udp_header *udp = data;

                miniflow_push_be16(mf, tp_src, udp->udp_src);
                miniflow_push_be16(mf, tp_dst, udp->udp_dst);
                miniflow_pad_to_64(mf, igmp_group_ip4);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_SCTP)) {
            if (OVS_LIKELY(size >= SCTP_HEADER_LEN)) {
                const struct sctp_header *sctp = data;

                miniflow_push_be16(mf, tp_src, sctp->sctp_src);
                miniflow_push_be16(mf, tp_dst, sctp->sctp_dst);
                miniflow_pad_to_64(mf, igmp_group_ip4);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_ICMP)) {
            if (OVS_LIKELY(size >= ICMP_HEADER_LEN)) {
                const struct icmp_header *icmp = data;

                miniflow_push_be16(mf, tp_src, htons(icmp->icmp_type));
                miniflow_push_be16(mf, tp_dst, htons(icmp->icmp_code));
                miniflow_pad_to_64(mf, igmp_group_ip4);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_IGMP)) {
            if (OVS_LIKELY(size >= IGMP_HEADER_LEN)) {
                const struct igmp_header *igmp = data;

                miniflow_push_be16(mf, tp_src, htons(igmp->igmp_type));
                miniflow_push_be16(mf, tp_dst, htons(igmp->igmp_code));
                miniflow_push_be32(mf, igmp_group_ip4,
                                   get_16aligned_be32(&igmp->group));
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_ICMPV6)) {
            if (OVS_LIKELY(size >= sizeof(struct icmp6_hdr))) {
                const struct in6_addr *nd_target = NULL;
                struct eth_addr arp_buf[2] = { { { { 0 } } } };
                const struct icmp6_hdr *icmp = data_pull(&data, &size,
                                                         sizeof *icmp);
                parse_icmpv6(&data, &size, icmp, &nd_target, arp_buf);
                if (nd_target) {
                    miniflow_push_words(mf, nd_target, nd_target,
                                        sizeof *nd_target / sizeof(uint64_t));
                }
                miniflow_push_macs(mf, arp_sha, arp_buf);
                miniflow_pad_to_64(mf, tcp_flags);
                miniflow_push_be16(mf, tp_src, htons(icmp->icmp6_type));
                miniflow_push_be16(mf, tp_dst, htons(icmp->icmp6_code));
                miniflow_pad_to_64(mf, igmp_group_ip4);
            }
        }
    }
 out:
    dst->map = mf.map;
}

/* For every bit of a field that is wildcarded in 'wildcards', sets the
 * corresponding bit in 'flow' to zero. */
void
flow_zero_wildcards(struct flow *flow, const struct flow_wildcards *wildcards)
{
    uint64_t *flow_u64 = (uint64_t *) flow;
    const uint64_t *wc_u64 = (const uint64_t *) &wildcards->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        flow_u64[i] &= wc_u64[i];
    }
}

void
flow_unwildcard_tp_ports(const struct flow *flow, struct flow_wildcards *wc)
{
    if (flow->nw_proto != IPPROTO_ICMP) {
        memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
        memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
    } else {
        wc->masks.tp_src = htons(0xff);
        wc->masks.tp_dst = htons(0xff);
    }
}

/* Initializes 'flow_metadata' with the metadata found in 'flow'. */
void
flow_get_metadata(const struct flow *flow, struct match *flow_metadata)
{
    int i;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 33);

    match_init_catchall(flow_metadata);
    if (flow->tunnel.tun_id != htonll(0)) {
        match_set_tun_id(flow_metadata, flow->tunnel.tun_id);
    }
    if (flow->tunnel.flags & FLOW_TNL_PUB_F_MASK) {
        match_set_tun_flags(flow_metadata,
                            flow->tunnel.flags & FLOW_TNL_PUB_F_MASK);
    }
    if (flow->tunnel.ip_src != htonl(0)) {
        match_set_tun_src(flow_metadata, flow->tunnel.ip_src);
    }
    if (flow->tunnel.ip_dst != htonl(0)) {
        match_set_tun_dst(flow_metadata, flow->tunnel.ip_dst);
    }
    if (flow->tunnel.gbp_id != htons(0)) {
        match_set_tun_gbp_id(flow_metadata, flow->tunnel.gbp_id);
    }
    if (flow->tunnel.gbp_flags) {
        match_set_tun_gbp_flags(flow_metadata, flow->tunnel.gbp_flags);
    }
    tun_metadata_get_fmd(&flow->tunnel, flow_metadata);
    if (flow->metadata != htonll(0)) {
        match_set_metadata(flow_metadata, flow->metadata);
    }

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (flow->regs[i]) {
            match_set_reg(flow_metadata, i, flow->regs[i]);
        }
    }

    if (flow->pkt_mark != 0) {
        match_set_pkt_mark(flow_metadata, flow->pkt_mark);
    }

    match_set_in_port(flow_metadata, flow->in_port.ofp_port);
}

char *
flow_to_string(const struct flow *flow)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    flow_format(&ds, flow);
    return ds_cstr(&ds);
}

const char *
flow_tun_flag_to_string(uint32_t flags)
{
    switch (flags) {
    case FLOW_TNL_F_DONT_FRAGMENT:
        return "df";
    case FLOW_TNL_F_CSUM:
        return "csum";
    case FLOW_TNL_F_KEY:
        return "key";
    case FLOW_TNL_F_OAM:
        return "oam";
    default:
        return NULL;
    }
}

void
format_flags(struct ds *ds, const char *(*bit_to_string)(uint32_t),
             uint32_t flags, char del)
{
    uint32_t bad = 0;

    if (!flags) {
        ds_put_char(ds, '0');
        return;
    }
    while (flags) {
        uint32_t bit = rightmost_1bit(flags);
        const char *s;

        s = bit_to_string(bit);
        if (s) {
            ds_put_format(ds, "%s%c", s, del);
        } else {
            bad |= bit;
        }

        flags &= ~bit;
    }

    if (bad) {
        ds_put_format(ds, "0x%"PRIx32"%c", bad, del);
    }
    ds_chomp(ds, del);
}

void
format_flags_masked(struct ds *ds, const char *name,
                    const char *(*bit_to_string)(uint32_t), uint32_t flags,
                    uint32_t mask, uint32_t max_mask)
{
    if (name) {
        ds_put_format(ds, "%s=", name);
    }

    if (mask == max_mask) {
        format_flags(ds, bit_to_string, flags, '|');
        return;
    }

    if (!mask) {
        ds_put_cstr(ds, "0/0");
        return;
    }

    while (mask) {
        uint32_t bit = rightmost_1bit(mask);
        const char *s = bit_to_string(bit);

        ds_put_format(ds, "%s%s", (flags & bit) ? "+" : "-",
                      s ? s : "[Unknown]");
        mask &= ~bit;
    }
}

/* Scans a string 's' of flags to determine their numerical value and
 * returns the number of characters parsed using 'bit_to_string' to
 * lookup flag names. Scanning continues until the character 'end' is
 * reached.
 *
 * In the event of a failure, a negative error code will be returned. In
 * addition, if 'res_string' is non-NULL then a descriptive string will
 * be returned incorporating the identifying string 'field_name'. This
 * error string must be freed by the caller.
 *
 * Upon success, the flag values will be stored in 'res_flags' and
 * optionally 'res_mask', if it is non-NULL (if it is NULL then any masks
 * present in the original string will be considered an error). The
 * caller may restrict the acceptable set of values through the mask
 * 'allowed'. */
int
parse_flags(const char *s, const char *(*bit_to_string)(uint32_t),
            char end, const char *field_name, char **res_string,
            uint32_t *res_flags, uint32_t allowed, uint32_t *res_mask)
{
    uint32_t result = 0;
    int n;

    /* Parse masked flags in numeric format? */
    if (res_mask && ovs_scan(s, "%"SCNi32"/%"SCNi32"%n",
                             res_flags, res_mask, &n) && n > 0) {
        if (*res_flags & ~allowed || *res_mask & ~allowed) {
            goto unknown;
        }
        return n;
    }

    n = 0;

    if (res_mask && (*s == '+' || *s == '-')) {
        uint32_t flags = 0, mask = 0;

        /* Parse masked flags. */
        while (s[0] != end) {
            bool set;
            uint32_t bit;
            size_t len;

            if (s[0] == '+') {
                set = true;
            } else if (s[0] == '-') {
                set = false;
            } else {
                if (res_string) {
                    *res_string = xasprintf("%s: %s must be preceded by '+' "
                                            "(for SET) or '-' (NOT SET)", s,
                                            field_name);
                }
                return -EINVAL;
            }
            s++;
            n++;

            for (bit = 1; bit; bit <<= 1) {
                const char *fname = bit_to_string(bit);

                if (!fname) {
                    continue;
                }

                len = strlen(fname);
                if (strncmp(s, fname, len) ||
                    (s[len] != '+' && s[len] != '-' && s[len] != end)) {
                    continue;
                }

                if (mask & bit) {
                    /* bit already set. */
                    if (res_string) {
                        *res_string = xasprintf("%s: Each %s flag can be "
                                                "specified only once", s,
                                                field_name);
                    }
                    return -EINVAL;
                }
                if (!(bit & allowed)) {
                    goto unknown;
                }
                if (set) {
                   flags |= bit;
                }
                mask |= bit;
                break;
            }

            if (!bit) {
                goto unknown;
            }
            s += len;
            n += len;
        }

        *res_flags = flags;
        *res_mask = mask;
        return n;
    }

    /* Parse unmasked flags.  If a flag is present, it is set, otherwise
     * it is not set. */
    while (s[n] != end) {
        unsigned long long int flags;
        uint32_t bit;
        int n0;

        if (ovs_scan(&s[n], "%lli%n", &flags, &n0)) {
            if (flags & ~allowed) {
                goto unknown;
            }
            n += n0 + (s[n + n0] == '|');
            result |= flags;
            continue;
        }

        for (bit = 1; bit; bit <<= 1) {
            const char *name = bit_to_string(bit);
            size_t len;

            if (!name) {
                continue;
            }

            len = strlen(name);
            if (!strncmp(s + n, name, len) &&
                (s[n + len] == '|' || s[n + len] == end)) {
                if (!(bit & allowed)) {
                    goto unknown;
                }
                result |= bit;
                n += len + (s[n + len] == '|');
                break;
            }
        }

        if (!bit) {
            goto unknown;
        }
    }

    *res_flags = result;
    if (res_mask) {
        *res_mask = UINT32_MAX;
    }
    if (res_string) {
        *res_string = NULL;
    }
    return n;

unknown:
    if (res_string) {
        *res_string = xasprintf("%s: unknown %s flag(s)", s, field_name);
    }
    return -EINVAL;
}

void
flow_format(struct ds *ds, const struct flow *flow)
{
    struct match match;
    struct flow_wildcards *wc = &match.wc;

    match_wc_init(&match, flow);

    /* As this function is most often used for formatting a packet in a
     * packet-in message, skip formatting the packet context fields that are
     * all-zeroes to make the print-out easier on the eyes.  This means that a
     * missing context field implies a zero value for that field.  This is
     * similar to OpenFlow encoding of these fields, as the specification
     * states that all-zeroes context fields should not be encoded in the
     * packet-in messages. */
    if (!flow->in_port.ofp_port) {
        WC_UNMASK_FIELD(wc, in_port);
    }
    if (!flow->skb_priority) {
        WC_UNMASK_FIELD(wc, skb_priority);
    }
    if (!flow->pkt_mark) {
        WC_UNMASK_FIELD(wc, pkt_mark);
    }
    if (!flow->recirc_id) {
        WC_UNMASK_FIELD(wc, recirc_id);
    }
    if (!flow->dp_hash) {
        WC_UNMASK_FIELD(wc, dp_hash);
    }
    for (int i = 0; i < FLOW_N_REGS; i++) {
        if (!flow->regs[i]) {
            WC_UNMASK_FIELD(wc, regs[i]);
        }
    }
    if (!flow->metadata) {
        WC_UNMASK_FIELD(wc, metadata);
    }

    match_format(&match, ds, OFP_DEFAULT_PRIORITY);
}

void
flow_print(FILE *stream, const struct flow *flow)
{
    char *s = flow_to_string(flow);
    fputs(s, stream);
    free(s);
}

/* flow_wildcards functions. */

/* Initializes 'wc' as a set of wildcards that matches every packet. */
void
flow_wildcards_init_catchall(struct flow_wildcards *wc)
{
    memset(&wc->masks, 0, sizeof wc->masks);
}

/* Converts a flow into flow wildcards.  It sets the wildcard masks based on
 * the packet headers extracted to 'flow'.  It will not set the mask for fields
 * that do not make sense for the packet type.  OpenFlow-only metadata is
 * wildcarded, but other metadata is unconditionally exact-matched. */
void flow_wildcards_init_for_packet(struct flow_wildcards *wc,
                                    const struct flow *flow)
{
    memset(&wc->masks, 0x0, sizeof wc->masks);

    /* Update this function whenever struct flow changes. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 33);

    if (flow->tunnel.ip_dst) {
        if (flow->tunnel.flags & FLOW_TNL_F_KEY) {
            WC_MASK_FIELD(wc, tunnel.tun_id);
        }
        WC_MASK_FIELD(wc, tunnel.ip_src);
        WC_MASK_FIELD(wc, tunnel.ip_dst);
        WC_MASK_FIELD(wc, tunnel.flags);
        WC_MASK_FIELD(wc, tunnel.ip_tos);
        WC_MASK_FIELD(wc, tunnel.ip_ttl);
        WC_MASK_FIELD(wc, tunnel.tp_src);
        WC_MASK_FIELD(wc, tunnel.tp_dst);
        WC_MASK_FIELD(wc, tunnel.gbp_id);
        WC_MASK_FIELD(wc, tunnel.gbp_flags);

        if (!(flow->tunnel.flags & FLOW_TNL_F_UDPIF)) {
            if (flow->tunnel.metadata.present.map) {
                wc->masks.tunnel.metadata.present.map =
                                              flow->tunnel.metadata.present.map;
                WC_MASK_FIELD(wc, tunnel.metadata.opts.u8);
            }
        } else {
            WC_MASK_FIELD(wc, tunnel.metadata.present.len);
            memset(wc->masks.tunnel.metadata.opts.gnv, 0xff,
                   flow->tunnel.metadata.present.len);
        }
    } else if (flow->tunnel.tun_id) {
        WC_MASK_FIELD(wc, tunnel.tun_id);
    }

    /* metadata, regs, and conj_id wildcarded. */

    WC_MASK_FIELD(wc, skb_priority);
    WC_MASK_FIELD(wc, pkt_mark);
    WC_MASK_FIELD(wc, recirc_id);
    WC_MASK_FIELD(wc, dp_hash);
    WC_MASK_FIELD(wc, in_port);

    /* actset_output wildcarded. */

    WC_MASK_FIELD(wc, dl_dst);
    WC_MASK_FIELD(wc, dl_src);
    WC_MASK_FIELD(wc, dl_type);
    WC_MASK_FIELD(wc, vlan_tci);

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        WC_MASK_FIELD(wc, nw_src);
        WC_MASK_FIELD(wc, nw_dst);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        WC_MASK_FIELD(wc, ipv6_src);
        WC_MASK_FIELD(wc, ipv6_dst);
        WC_MASK_FIELD(wc, ipv6_label);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        WC_MASK_FIELD(wc, nw_src);
        WC_MASK_FIELD(wc, nw_dst);
        WC_MASK_FIELD(wc, nw_proto);
        WC_MASK_FIELD(wc, arp_sha);
        WC_MASK_FIELD(wc, arp_tha);
        return;
    } else if (eth_type_mpls(flow->dl_type)) {
        for (int i = 0; i < FLOW_MAX_MPLS_LABELS; i++) {
            WC_MASK_FIELD(wc, mpls_lse[i]);
            if (flow->mpls_lse[i] & htonl(MPLS_BOS_MASK)) {
                break;
            }
        }
        return;
    } else {
        return; /* Unknown ethertype. */
    }

    /* IPv4 or IPv6. */
    WC_MASK_FIELD(wc, nw_frag);
    WC_MASK_FIELD(wc, nw_tos);
    WC_MASK_FIELD(wc, nw_ttl);
    WC_MASK_FIELD(wc, nw_proto);

    /* No transport layer header in later fragments. */
    if (!(flow->nw_frag & FLOW_NW_FRAG_LATER) &&
        (flow->nw_proto == IPPROTO_ICMP ||
         flow->nw_proto == IPPROTO_ICMPV6 ||
         flow->nw_proto == IPPROTO_TCP ||
         flow->nw_proto == IPPROTO_UDP ||
         flow->nw_proto == IPPROTO_SCTP ||
         flow->nw_proto == IPPROTO_IGMP)) {
        WC_MASK_FIELD(wc, tp_src);
        WC_MASK_FIELD(wc, tp_dst);

        if (flow->nw_proto == IPPROTO_TCP) {
            WC_MASK_FIELD(wc, tcp_flags);
        } else if (flow->nw_proto == IPPROTO_ICMPV6) {
            WC_MASK_FIELD(wc, arp_sha);
            WC_MASK_FIELD(wc, arp_tha);
            WC_MASK_FIELD(wc, nd_target);
        } else if (flow->nw_proto == IPPROTO_IGMP) {
            WC_MASK_FIELD(wc, igmp_group_ip4);
        }
    }
}

/* Return a map of possible fields for a packet of the same type as 'flow'.
 * Including extra bits in the returned mask is not wrong, it is just less
 * optimal.
 *
 * This is a less precise version of flow_wildcards_init_for_packet() above. */
void
flow_wc_map(const struct flow *flow, struct flowmap *map)
{
    /* Update this function whenever struct flow changes. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 33);

    flowmap_init(map);

    if (flow->tunnel.ip_dst) {
        FLOWMAP_SET__(map, tunnel, offsetof(struct flow_tnl, metadata));
        if (!(flow->tunnel.flags & FLOW_TNL_F_UDPIF)) {
            if (flow->tunnel.metadata.present.map) {
                FLOWMAP_SET(map, tunnel.metadata);
            }
        } else {
            FLOWMAP_SET(map, tunnel.metadata.present.len);
            FLOWMAP_SET__(map, tunnel.metadata.opts.gnv,
                          flow->tunnel.metadata.present.len);
        }
    }

    /* Metadata fields that can appear on packet input. */
    FLOWMAP_SET(map, skb_priority);
    FLOWMAP_SET(map, pkt_mark);
    FLOWMAP_SET(map, recirc_id);
    FLOWMAP_SET(map, dp_hash);
    FLOWMAP_SET(map, in_port);
    FLOWMAP_SET(map, dl_dst);
    FLOWMAP_SET(map, dl_src);
    FLOWMAP_SET(map, dl_type);
    FLOWMAP_SET(map, vlan_tci);

    /* Ethertype-dependent fields. */
    if (OVS_LIKELY(flow->dl_type == htons(ETH_TYPE_IP))) {
        FLOWMAP_SET(map, nw_src);
        FLOWMAP_SET(map, nw_dst);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, nw_frag);
        FLOWMAP_SET(map, nw_tos);
        FLOWMAP_SET(map, nw_ttl);

        if (OVS_UNLIKELY(flow->nw_proto == IPPROTO_IGMP)) {
            FLOWMAP_SET(map, igmp_group_ip4);
        } else {
            FLOWMAP_SET(map, tcp_flags);
            FLOWMAP_SET(map, tp_src);
            FLOWMAP_SET(map, tp_dst);
        }
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        FLOWMAP_SET(map, ipv6_src);
        FLOWMAP_SET(map, ipv6_dst);
        FLOWMAP_SET(map, ipv6_label);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, nw_frag);
        FLOWMAP_SET(map, nw_tos);
        FLOWMAP_SET(map, nw_ttl);

        if (OVS_UNLIKELY(flow->nw_proto == IPPROTO_ICMPV6)) {
            FLOWMAP_SET(map, nd_target);
            FLOWMAP_SET(map, arp_sha);
            FLOWMAP_SET(map, arp_tha);
        } else {
            FLOWMAP_SET(map, tcp_flags);
            FLOWMAP_SET(map, tp_src);
            FLOWMAP_SET(map, tp_dst);
        }
    } else if (eth_type_mpls(flow->dl_type)) {
        FLOWMAP_SET(map, mpls_lse);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        FLOWMAP_SET(map, nw_src);
        FLOWMAP_SET(map, nw_dst);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, arp_sha);
        FLOWMAP_SET(map, arp_tha);
    }
}

/* Clear the metadata and register wildcard masks. They are not packet
 * header fields. */
void
flow_wildcards_clear_non_packet_fields(struct flow_wildcards *wc)
{
    /* Update this function whenever struct flow changes. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 33);

    memset(&wc->masks.metadata, 0, sizeof wc->masks.metadata);
    memset(&wc->masks.regs, 0, sizeof wc->masks.regs);
    wc->masks.actset_output = 0;
    wc->masks.conj_id = 0;
}

/* Returns true if 'wc' matches every packet, false if 'wc' fixes any bits or
 * fields. */
bool
flow_wildcards_is_catchall(const struct flow_wildcards *wc)
{
    const uint64_t *wc_u64 = (const uint64_t *) &wc->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        if (wc_u64[i]) {
            return false;
        }
    }
    return true;
}

/* Sets 'dst' as the bitwise AND of wildcards in 'src1' and 'src2'.
 * That is, a bit or a field is wildcarded in 'dst' if it is wildcarded
 * in 'src1' or 'src2' or both.  */
void
flow_wildcards_and(struct flow_wildcards *dst,
                   const struct flow_wildcards *src1,
                   const struct flow_wildcards *src2)
{
    uint64_t *dst_u64 = (uint64_t *) &dst->masks;
    const uint64_t *src1_u64 = (const uint64_t *) &src1->masks;
    const uint64_t *src2_u64 = (const uint64_t *) &src2->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        dst_u64[i] = src1_u64[i] & src2_u64[i];
    }
}

/* Sets 'dst' as the bitwise OR of wildcards in 'src1' and 'src2'.  That
 * is, a bit or a field is wildcarded in 'dst' if it is neither
 * wildcarded in 'src1' nor 'src2'. */
void
flow_wildcards_or(struct flow_wildcards *dst,
                  const struct flow_wildcards *src1,
                  const struct flow_wildcards *src2)
{
    uint64_t *dst_u64 = (uint64_t *) &dst->masks;
    const uint64_t *src1_u64 = (const uint64_t *) &src1->masks;
    const uint64_t *src2_u64 = (const uint64_t *) &src2->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        dst_u64[i] = src1_u64[i] | src2_u64[i];
    }
}

/* Returns a hash of the wildcards in 'wc'. */
uint32_t
flow_wildcards_hash(const struct flow_wildcards *wc, uint32_t basis)
{
    return flow_hash(&wc->masks, basis);
}

/* Returns true if 'a' and 'b' represent the same wildcards, false if they are
 * different. */
bool
flow_wildcards_equal(const struct flow_wildcards *a,
                     const struct flow_wildcards *b)
{
    return flow_equal(&a->masks, &b->masks);
}

/* Returns true if at least one bit or field is wildcarded in 'a' but not in
 * 'b', false otherwise. */
bool
flow_wildcards_has_extra(const struct flow_wildcards *a,
                         const struct flow_wildcards *b)
{
    const uint64_t *a_u64 = (const uint64_t *) &a->masks;
    const uint64_t *b_u64 = (const uint64_t *) &b->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        if ((a_u64[i] & b_u64[i]) != b_u64[i]) {
            return true;
        }
    }
    return false;
}

/* Returns true if 'a' and 'b' are equal, except that 0-bits (wildcarded bits)
 * in 'wc' do not need to be equal in 'a' and 'b'. */
bool
flow_equal_except(const struct flow *a, const struct flow *b,
                  const struct flow_wildcards *wc)
{
    const uint64_t *a_u64 = (const uint64_t *) a;
    const uint64_t *b_u64 = (const uint64_t *) b;
    const uint64_t *wc_u64 = (const uint64_t *) &wc->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        if ((a_u64[i] ^ b_u64[i]) & wc_u64[i]) {
            return false;
        }
    }
    return true;
}

/* Sets the wildcard mask for register 'idx' in 'wc' to 'mask'.
 * (A 0-bit indicates a wildcard bit.) */
void
flow_wildcards_set_reg_mask(struct flow_wildcards *wc, int idx, uint32_t mask)
{
    wc->masks.regs[idx] = mask;
}

/* Sets the wildcard mask for register 'idx' in 'wc' to 'mask'.
 * (A 0-bit indicates a wildcard bit.) */
void
flow_wildcards_set_xreg_mask(struct flow_wildcards *wc, int idx, uint64_t mask)
{
    flow_set_xreg(&wc->masks, idx, mask);
}

/* Calculates the 5-tuple hash from the given miniflow.
 * This returns the same value as flow_hash_5tuple for the corresponding
 * flow. */
uint32_t
miniflow_hash_5tuple(const struct miniflow *flow, uint32_t basis)
{
    uint32_t hash = basis;

    if (flow) {
        ovs_be16 dl_type = MINIFLOW_GET_BE16(flow, dl_type);

        hash = hash_add(hash, MINIFLOW_GET_U8(flow, nw_proto));

        /* Separate loops for better optimization. */
        if (dl_type == htons(ETH_TYPE_IPV6)) {
            struct flowmap map = FLOWMAP_EMPTY_INITIALIZER;
            uint64_t value;

            FLOWMAP_SET(&map, ipv6_src);
            FLOWMAP_SET(&map, ipv6_dst);

            MINIFLOW_FOR_EACH_IN_FLOWMAP(value, flow, map) {
                hash = hash_add64(hash, value);
            }
        } else {
            hash = hash_add(hash, MINIFLOW_GET_U32(flow, nw_src));
            hash = hash_add(hash, MINIFLOW_GET_U32(flow, nw_dst));
        }
        /* Add both ports at once. */
        hash = hash_add(hash, MINIFLOW_GET_U32(flow, tp_src));
        hash = hash_finish(hash, 42); /* Arbitrary number. */
    }
    return hash;
}

ASSERT_SEQUENTIAL_SAME_WORD(tp_src, tp_dst);
ASSERT_SEQUENTIAL(ipv6_src, ipv6_dst);

/* Calculates the 5-tuple hash from the given flow. */
uint32_t
flow_hash_5tuple(const struct flow *flow, uint32_t basis)
{
    uint32_t hash = basis;

    if (flow) {
        hash = hash_add(hash, flow->nw_proto);

        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            const uint64_t *flow_u64 = (const uint64_t *)flow;
            int ofs = offsetof(struct flow, ipv6_src) / 8;
            int end = ofs + 2 * sizeof flow->ipv6_src / 8;

            for (;ofs < end; ofs++) {
                hash = hash_add64(hash, flow_u64[ofs]);
            }
        } else {
            hash = hash_add(hash, (OVS_FORCE uint32_t) flow->nw_src);
            hash = hash_add(hash, (OVS_FORCE uint32_t) flow->nw_dst);
        }
        /* Add both ports at once. */
        hash = hash_add(hash,
                        ((const uint32_t *)flow)[offsetof(struct flow, tp_src)
                                                 / sizeof(uint32_t)]);
        hash = hash_finish(hash, 42); /* Arbitrary number. */
    }
    return hash;
}

/* Hashes 'flow' based on its L2 through L4 protocol information. */
uint32_t
flow_hash_symmetric_l4(const struct flow *flow, uint32_t basis)
{
    struct {
        union {
            ovs_be32 ipv4_addr;
            struct in6_addr ipv6_addr;
        };
        ovs_be16 eth_type;
        ovs_be16 vlan_tci;
        ovs_be16 tp_port;
        struct eth_addr eth_addr;
        uint8_t ip_proto;
    } fields;

    int i;

    memset(&fields, 0, sizeof fields);
    for (i = 0; i < ARRAY_SIZE(fields.eth_addr.be16); i++) {
        fields.eth_addr.be16[i] = flow->dl_src.be16[i] ^ flow->dl_dst.be16[i];
    }
    fields.vlan_tci = flow->vlan_tci & htons(VLAN_VID_MASK);
    fields.eth_type = flow->dl_type;

    /* UDP source and destination port are not taken into account because they
     * will not necessarily be symmetric in a bidirectional flow. */
    if (fields.eth_type == htons(ETH_TYPE_IP)) {
        fields.ipv4_addr = flow->nw_src ^ flow->nw_dst;
        fields.ip_proto = flow->nw_proto;
        if (fields.ip_proto == IPPROTO_TCP || fields.ip_proto == IPPROTO_SCTP) {
            fields.tp_port = flow->tp_src ^ flow->tp_dst;
        }
    } else if (fields.eth_type == htons(ETH_TYPE_IPV6)) {
        const uint8_t *a = &flow->ipv6_src.s6_addr[0];
        const uint8_t *b = &flow->ipv6_dst.s6_addr[0];
        uint8_t *ipv6_addr = &fields.ipv6_addr.s6_addr[0];

        for (i=0; i<16; i++) {
            ipv6_addr[i] = a[i] ^ b[i];
        }
        fields.ip_proto = flow->nw_proto;
        if (fields.ip_proto == IPPROTO_TCP || fields.ip_proto == IPPROTO_SCTP) {
            fields.tp_port = flow->tp_src ^ flow->tp_dst;
        }
    }
    return jhash_bytes(&fields, sizeof fields, basis);
}

/* Hashes 'flow' based on its L3 through L4 protocol information */
uint32_t
flow_hash_symmetric_l3l4(const struct flow *flow, uint32_t basis,
                         bool inc_udp_ports)
{
    uint32_t hash = basis;

    /* UDP source and destination port are also taken into account. */
    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        hash = hash_add(hash,
                        (OVS_FORCE uint32_t) (flow->nw_src ^ flow->nw_dst));
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        /* IPv6 addresses are 64-bit aligned inside struct flow. */
        const uint64_t *a = ALIGNED_CAST(uint64_t *, flow->ipv6_src.s6_addr);
        const uint64_t *b = ALIGNED_CAST(uint64_t *, flow->ipv6_dst.s6_addr);

        for (int i = 0; i < 4; i++) {
            hash = hash_add64(hash, a[i] ^ b[i]);
        }
    } else {
        /* Cannot hash non-IP flows */
        return 0;
    }

    hash = hash_add(hash, flow->nw_proto);
    if (flow->nw_proto == IPPROTO_TCP || flow->nw_proto == IPPROTO_SCTP ||
         (inc_udp_ports && flow->nw_proto == IPPROTO_UDP)) {
        hash = hash_add(hash,
                        (OVS_FORCE uint16_t) (flow->tp_src ^ flow->tp_dst));
    }

    return hash_finish(hash, basis);
}

/* Initialize a flow with random fields that matter for nx_hash_fields. */
void
flow_random_hash_fields(struct flow *flow)
{
    uint16_t rnd = random_uint16();

    /* Initialize to all zeros. */
    memset(flow, 0, sizeof *flow);

    eth_addr_random(&flow->dl_src);
    eth_addr_random(&flow->dl_dst);

    flow->vlan_tci = (OVS_FORCE ovs_be16) (random_uint16() & VLAN_VID_MASK);

    /* Make most of the random flows IPv4, some IPv6, and rest random. */
    flow->dl_type = rnd < 0x8000 ? htons(ETH_TYPE_IP) :
        rnd < 0xc000 ? htons(ETH_TYPE_IPV6) : (OVS_FORCE ovs_be16)rnd;

    if (dl_type_is_ip_any(flow->dl_type)) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_src = (OVS_FORCE ovs_be32)random_uint32();
            flow->nw_dst = (OVS_FORCE ovs_be32)random_uint32();
        } else {
            random_bytes(&flow->ipv6_src, sizeof flow->ipv6_src);
            random_bytes(&flow->ipv6_dst, sizeof flow->ipv6_dst);
        }
        /* Make most of IP flows TCP, some UDP or SCTP, and rest random. */
        rnd = random_uint16();
        flow->nw_proto = rnd < 0x8000 ? IPPROTO_TCP :
            rnd < 0xc000 ? IPPROTO_UDP :
            rnd < 0xd000 ? IPPROTO_SCTP : (uint8_t)rnd;
        if (flow->nw_proto == IPPROTO_TCP ||
            flow->nw_proto == IPPROTO_UDP ||
            flow->nw_proto == IPPROTO_SCTP) {
            flow->tp_src = (OVS_FORCE ovs_be16)random_uint16();
            flow->tp_dst = (OVS_FORCE ovs_be16)random_uint16();
        }
    }
}

/* Masks the fields in 'wc' that are used by the flow hash 'fields'. */
void
flow_mask_hash_fields(const struct flow *flow, struct flow_wildcards *wc,
                      enum nx_hash_fields fields)
{
    switch (fields) {
    case NX_HASH_FIELDS_ETH_SRC:
        memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
        break;

    case NX_HASH_FIELDS_SYMMETRIC_L4:
        memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
        memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
            memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
            memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
        }
        if (is_ip_any(flow)) {
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
            flow_unwildcard_tp_ports(flow, wc);
        }
        wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
        break;

    case NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP:
        if (is_ip_any(flow) && flow->nw_proto == IPPROTO_UDP) {
            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
            memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
        }
        /* no break */
    case NX_HASH_FIELDS_SYMMETRIC_L3L4:
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
            memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
            memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
        } else {
            break; /* non-IP flow */
        }

        memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
        if (flow->nw_proto == IPPROTO_TCP || flow->nw_proto == IPPROTO_SCTP) {
            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
            memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
        }
        break;

    default:
        OVS_NOT_REACHED();
    }
}

/* Hashes the portions of 'flow' designated by 'fields'. */
uint32_t
flow_hash_fields(const struct flow *flow, enum nx_hash_fields fields,
                 uint16_t basis)
{
    switch (fields) {

    case NX_HASH_FIELDS_ETH_SRC:
        return jhash_bytes(&flow->dl_src, sizeof flow->dl_src, basis);

    case NX_HASH_FIELDS_SYMMETRIC_L4:
        return flow_hash_symmetric_l4(flow, basis);

    case NX_HASH_FIELDS_SYMMETRIC_L3L4:
        return flow_hash_symmetric_l3l4(flow, basis, false);

    case NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP:
        return flow_hash_symmetric_l3l4(flow, basis, true);

    }

    OVS_NOT_REACHED();
}

/* Returns a string representation of 'fields'. */
const char *
flow_hash_fields_to_str(enum nx_hash_fields fields)
{
    switch (fields) {
    case NX_HASH_FIELDS_ETH_SRC: return "eth_src";
    case NX_HASH_FIELDS_SYMMETRIC_L4: return "symmetric_l4";
    case NX_HASH_FIELDS_SYMMETRIC_L3L4: return "symmetric_l3l4";
    case NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP: return "symmetric_l3l4+udp";
    default: return "<unknown>";
    }
}

/* Returns true if the value of 'fields' is supported. Otherwise false. */
bool
flow_hash_fields_valid(enum nx_hash_fields fields)
{
    return fields == NX_HASH_FIELDS_ETH_SRC
        || fields == NX_HASH_FIELDS_SYMMETRIC_L4
        || fields == NX_HASH_FIELDS_SYMMETRIC_L3L4
        || fields == NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP;
}

/* Returns a hash value for the bits of 'flow' that are active based on
 * 'wc', given 'basis'. */
uint32_t
flow_hash_in_wildcards(const struct flow *flow,
                       const struct flow_wildcards *wc, uint32_t basis)
{
    const uint64_t *wc_u64 = (const uint64_t *) &wc->masks;
    const uint64_t *flow_u64 = (const uint64_t *) flow;
    uint32_t hash;
    size_t i;

    hash = basis;
    for (i = 0; i < FLOW_U64S; i++) {
        hash = hash_add64(hash, flow_u64[i] & wc_u64[i]);
    }
    return hash_finish(hash, 8 * FLOW_U64S);
}

/* Sets the VLAN VID that 'flow' matches to 'vid', which is interpreted as an
 * OpenFlow 1.0 "dl_vlan" value:
 *
 *      - If it is in the range 0...4095, 'flow->vlan_tci' is set to match
 *        that VLAN.  Any existing PCP match is unchanged (it becomes 0 if
 *        'flow' previously matched packets without a VLAN header).
 *
 *      - If it is OFP_VLAN_NONE, 'flow->vlan_tci' is set to match a packet
 *        without a VLAN tag.
 *
 *      - Other values of 'vid' should not be used. */
void
flow_set_dl_vlan(struct flow *flow, ovs_be16 vid)
{
    if (vid == htons(OFP10_VLAN_NONE)) {
        flow->vlan_tci = htons(0);
    } else {
        vid &= htons(VLAN_VID_MASK);
        flow->vlan_tci &= ~htons(VLAN_VID_MASK);
        flow->vlan_tci |= htons(VLAN_CFI) | vid;
    }
}

/* Sets the VLAN VID that 'flow' matches to 'vid', which is interpreted as an
 * OpenFlow 1.2 "vlan_vid" value, that is, the low 13 bits of 'vlan_tci' (VID
 * plus CFI). */
void
flow_set_vlan_vid(struct flow *flow, ovs_be16 vid)
{
    ovs_be16 mask = htons(VLAN_VID_MASK | VLAN_CFI);
    flow->vlan_tci &= ~mask;
    flow->vlan_tci |= vid & mask;
}

/* Sets the VLAN PCP that 'flow' matches to 'pcp', which should be in the
 * range 0...7.
 *
 * This function has no effect on the VLAN ID that 'flow' matches.
 *
 * After calling this function, 'flow' will not match packets without a VLAN
 * header. */
void
flow_set_vlan_pcp(struct flow *flow, uint8_t pcp)
{
    pcp &= 0x07;
    flow->vlan_tci &= ~htons(VLAN_PCP_MASK);
    flow->vlan_tci |= htons((pcp << VLAN_PCP_SHIFT) | VLAN_CFI);
}

/* Returns the number of MPLS LSEs present in 'flow'
 *
 * Returns 0 if the 'dl_type' of 'flow' is not an MPLS ethernet type.
 * Otherwise traverses 'flow''s MPLS label stack stopping at the
 * first entry that has the BoS bit set. If no such entry exists then
 * the maximum number of LSEs that can be stored in 'flow' is returned.
 */
int
flow_count_mpls_labels(const struct flow *flow, struct flow_wildcards *wc)
{
    /* dl_type is always masked. */
    if (eth_type_mpls(flow->dl_type)) {
        int i;
        int cnt;

        cnt = 0;
        for (i = 0; i < FLOW_MAX_MPLS_LABELS; i++) {
            if (wc) {
                wc->masks.mpls_lse[i] |= htonl(MPLS_BOS_MASK);
            }
            if (flow->mpls_lse[i] & htonl(MPLS_BOS_MASK)) {
                return i + 1;
            }
            if (flow->mpls_lse[i]) {
                cnt++;
            }
        }
        return cnt;
    } else {
        return 0;
    }
}

/* Returns the number consecutive of MPLS LSEs, starting at the
 * innermost LSE, that are common in 'a' and 'b'.
 *
 * 'an' must be flow_count_mpls_labels(a).
 * 'bn' must be flow_count_mpls_labels(b).
 */
int
flow_count_common_mpls_labels(const struct flow *a, int an,
                              const struct flow *b, int bn,
                              struct flow_wildcards *wc)
{
    int min_n = MIN(an, bn);
    if (min_n == 0) {
        return 0;
    } else {
        int common_n = 0;
        int a_last = an - 1;
        int b_last = bn - 1;
        int i;

        for (i = 0; i < min_n; i++) {
            if (wc) {
                wc->masks.mpls_lse[a_last - i] = OVS_BE32_MAX;
                wc->masks.mpls_lse[b_last - i] = OVS_BE32_MAX;
            }
            if (a->mpls_lse[a_last - i] != b->mpls_lse[b_last - i]) {
                break;
            } else {
                common_n++;
            }
        }

        return common_n;
    }
}

/* Adds a new outermost MPLS label to 'flow' and changes 'flow''s Ethernet type
 * to 'mpls_eth_type', which must be an MPLS Ethertype.
 *
 * If the new label is the first MPLS label in 'flow', it is generated as;
 *
 *     - label: 2, if 'flow' is IPv6, otherwise 0.
 *
 *     - TTL: IPv4 or IPv6 TTL, if present and nonzero, otherwise 64.
 *
 *     - TC: IPv4 or IPv6 TOS, if present, otherwise 0.
 *
 *     - BoS: 1.
 *
 * If the new label is the second or later label MPLS label in 'flow', it is
 * generated as;
 *
 *     - label: Copied from outer label.
 *
 *     - TTL: Copied from outer label.
 *
 *     - TC: Copied from outer label.
 *
 *     - BoS: 0.
 *
 * 'n' must be flow_count_mpls_labels(flow).  'n' must be less than
 * FLOW_MAX_MPLS_LABELS (because otherwise flow->mpls_lse[] would overflow).
 */
void
flow_push_mpls(struct flow *flow, int n, ovs_be16 mpls_eth_type,
               struct flow_wildcards *wc)
{
    ovs_assert(eth_type_mpls(mpls_eth_type));
    ovs_assert(n < FLOW_MAX_MPLS_LABELS);

    if (n) {
        int i;

        if (wc) {
            memset(&wc->masks.mpls_lse, 0xff, sizeof *wc->masks.mpls_lse * n);
        }
        for (i = n; i >= 1; i--) {
            flow->mpls_lse[i] = flow->mpls_lse[i - 1];
        }
        flow->mpls_lse[0] = (flow->mpls_lse[1] & htonl(~MPLS_BOS_MASK));
    } else {
        int label = 0;          /* IPv4 Explicit Null. */
        int tc = 0;
        int ttl = 64;

        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            label = 2;
        }

        if (is_ip_any(flow)) {
            tc = (flow->nw_tos & IP_DSCP_MASK) >> 2;
            if (wc) {
                wc->masks.nw_tos |= IP_DSCP_MASK;
                wc->masks.nw_ttl = 0xff;
            }

            if (flow->nw_ttl) {
                ttl = flow->nw_ttl;
            }
        }

        flow->mpls_lse[0] = set_mpls_lse_values(ttl, tc, 1, htonl(label));

        /* Clear all L3 and L4 fields and dp_hash. */
        BUILD_ASSERT(FLOW_WC_SEQ == 33);
        memset((char *) flow + FLOW_SEGMENT_2_ENDS_AT, 0,
               sizeof(struct flow) - FLOW_SEGMENT_2_ENDS_AT);
        flow->dp_hash = 0;
    }
    flow->dl_type = mpls_eth_type;
}

/* Tries to remove the outermost MPLS label from 'flow'.  Returns true if
 * successful, false otherwise.  On success, sets 'flow''s Ethernet type to
 * 'eth_type'.
 *
 * 'n' must be flow_count_mpls_labels(flow). */
bool
flow_pop_mpls(struct flow *flow, int n, ovs_be16 eth_type,
              struct flow_wildcards *wc)
{
    int i;

    if (n == 0) {
        /* Nothing to pop. */
        return false;
    } else if (n == FLOW_MAX_MPLS_LABELS) {
        if (wc) {
            wc->masks.mpls_lse[n - 1] |= htonl(MPLS_BOS_MASK);
        }
        if (!(flow->mpls_lse[n - 1] & htonl(MPLS_BOS_MASK))) {
            /* Can't pop because don't know what to fill in mpls_lse[n - 1]. */
            return false;
        }
    }

    if (wc) {
        memset(&wc->masks.mpls_lse[1], 0xff,
               sizeof *wc->masks.mpls_lse * (n - 1));
    }
    for (i = 1; i < n; i++) {
        flow->mpls_lse[i - 1] = flow->mpls_lse[i];
    }
    flow->mpls_lse[n - 1] = 0;
    flow->dl_type = eth_type;
    return true;
}

/* Sets the MPLS Label that 'flow' matches to 'label', which is interpreted
 * as an OpenFlow 1.1 "mpls_label" value. */
void
flow_set_mpls_label(struct flow *flow, int idx, ovs_be32 label)
{
    set_mpls_lse_label(&flow->mpls_lse[idx], label);
}

/* Sets the MPLS TTL that 'flow' matches to 'ttl', which should be in the
 * range 0...255. */
void
flow_set_mpls_ttl(struct flow *flow, int idx, uint8_t ttl)
{
    set_mpls_lse_ttl(&flow->mpls_lse[idx], ttl);
}

/* Sets the MPLS TC that 'flow' matches to 'tc', which should be in the
 * range 0...7. */
void
flow_set_mpls_tc(struct flow *flow, int idx, uint8_t tc)
{
    set_mpls_lse_tc(&flow->mpls_lse[idx], tc);
}

/* Sets the MPLS BOS bit that 'flow' matches to which should be 0 or 1. */
void
flow_set_mpls_bos(struct flow *flow, int idx, uint8_t bos)
{
    set_mpls_lse_bos(&flow->mpls_lse[idx], bos);
}

/* Sets the entire MPLS LSE. */
void
flow_set_mpls_lse(struct flow *flow, int idx, ovs_be32 lse)
{
    flow->mpls_lse[idx] = lse;
}

static size_t
flow_compose_l4(struct dp_packet *p, const struct flow *flow)
{
    size_t l4_len = 0;

    if (!(flow->nw_frag & FLOW_NW_FRAG_ANY)
        || !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (flow->nw_proto == IPPROTO_TCP) {
            struct tcp_header *tcp;

            l4_len = sizeof *tcp;
            tcp = dp_packet_put_zeros(p, l4_len);
            tcp->tcp_src = flow->tp_src;
            tcp->tcp_dst = flow->tp_dst;
            tcp->tcp_ctl = TCP_CTL(ntohs(flow->tcp_flags), 5);
        } else if (flow->nw_proto == IPPROTO_UDP) {
            struct udp_header *udp;

            l4_len = sizeof *udp;
            udp = dp_packet_put_zeros(p, l4_len);
            udp->udp_src = flow->tp_src;
            udp->udp_dst = flow->tp_dst;
        } else if (flow->nw_proto == IPPROTO_SCTP) {
            struct sctp_header *sctp;

            l4_len = sizeof *sctp;
            sctp = dp_packet_put_zeros(p, l4_len);
            sctp->sctp_src = flow->tp_src;
            sctp->sctp_dst = flow->tp_dst;
        } else if (flow->nw_proto == IPPROTO_ICMP) {
            struct icmp_header *icmp;

            l4_len = sizeof *icmp;
            icmp = dp_packet_put_zeros(p, l4_len);
            icmp->icmp_type = ntohs(flow->tp_src);
            icmp->icmp_code = ntohs(flow->tp_dst);
            icmp->icmp_csum = csum(icmp, ICMP_HEADER_LEN);
        } else if (flow->nw_proto == IPPROTO_IGMP) {
            struct igmp_header *igmp;

            l4_len = sizeof *igmp;
            igmp = dp_packet_put_zeros(p, l4_len);
            igmp->igmp_type = ntohs(flow->tp_src);
            igmp->igmp_code = ntohs(flow->tp_dst);
            put_16aligned_be32(&igmp->group, flow->igmp_group_ip4);
            igmp->igmp_csum = csum(igmp, IGMP_HEADER_LEN);
        } else if (flow->nw_proto == IPPROTO_ICMPV6) {
            struct icmp6_hdr *icmp;

            l4_len = sizeof *icmp;
            icmp = dp_packet_put_zeros(p, l4_len);
            icmp->icmp6_type = ntohs(flow->tp_src);
            icmp->icmp6_code = ntohs(flow->tp_dst);

            if (icmp->icmp6_code == 0 &&
                (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT ||
                 icmp->icmp6_type == ND_NEIGHBOR_ADVERT)) {
                struct in6_addr *nd_target;
                struct ovs_nd_opt *nd_opt;

                l4_len += sizeof *nd_target;
                nd_target = dp_packet_put_zeros(p, sizeof *nd_target);
                *nd_target = flow->nd_target;

                if (!eth_addr_is_zero(flow->arp_sha)) {
                    l4_len += 8;
                    nd_opt = dp_packet_put_zeros(p, 8);
                    nd_opt->nd_opt_len = 1;
                    nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
                    nd_opt->nd_opt_mac = flow->arp_sha;
                }
                if (!eth_addr_is_zero(flow->arp_tha)) {
                    l4_len += 8;
                    nd_opt = dp_packet_put_zeros(p, 8);
                    nd_opt->nd_opt_len = 1;
                    nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
                    nd_opt->nd_opt_mac = flow->arp_tha;
                }
            }
            icmp->icmp6_cksum = (OVS_FORCE uint16_t)
                csum(icmp, (char *)dp_packet_tail(p) - (char *)icmp);
        }
    }
    return l4_len;
}

/* Puts into 'b' a packet that flow_extract() would parse as having the given
 * 'flow'.
 *
 * (This is useful only for testing, obviously, and the packet isn't really
 * valid. It hasn't got some checksums filled in, for one, and lots of fields
 * are just zeroed.) */
void
flow_compose(struct dp_packet *p, const struct flow *flow)
{
    size_t l4_len;

    /* eth_compose() sets l3 pointer and makes sure it is 32-bit aligned. */
    eth_compose(p, flow->dl_dst, flow->dl_src, ntohs(flow->dl_type), 0);
    if (flow->dl_type == htons(FLOW_DL_TYPE_NONE)) {
        struct eth_header *eth = dp_packet_l2(p);
        eth->eth_type = htons(dp_packet_size(p));
        return;
    }

    if (flow->vlan_tci & htons(VLAN_CFI)) {
        eth_push_vlan(p, htons(ETH_TYPE_VLAN), flow->vlan_tci);
    }

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct ip_header *ip;

        ip = dp_packet_put_zeros(p, sizeof *ip);
        ip->ip_ihl_ver = IP_IHL_VER(5, 4);
        ip->ip_tos = flow->nw_tos;
        ip->ip_ttl = flow->nw_ttl;
        ip->ip_proto = flow->nw_proto;
        put_16aligned_be32(&ip->ip_src, flow->nw_src);
        put_16aligned_be32(&ip->ip_dst, flow->nw_dst);

        if (flow->nw_frag & FLOW_NW_FRAG_ANY) {
            ip->ip_frag_off |= htons(IP_MORE_FRAGMENTS);
            if (flow->nw_frag & FLOW_NW_FRAG_LATER) {
                ip->ip_frag_off |= htons(100);
            }
        }

        dp_packet_set_l4(p, dp_packet_tail(p));

        l4_len = flow_compose_l4(p, flow);

        ip = dp_packet_l3(p);
        ip->ip_tot_len = htons(p->l4_ofs - p->l3_ofs + l4_len);
        ip->ip_csum = csum(ip, sizeof *ip);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_16aligned_ip6_hdr *nh;

        nh = dp_packet_put_zeros(p, sizeof *nh);
        put_16aligned_be32(&nh->ip6_flow, htonl(6 << 28) |
                           htonl(flow->nw_tos << 20) | flow->ipv6_label);
        nh->ip6_hlim = flow->nw_ttl;
        nh->ip6_nxt = flow->nw_proto;

        memcpy(&nh->ip6_src, &flow->ipv6_src, sizeof(nh->ip6_src));
        memcpy(&nh->ip6_dst, &flow->ipv6_dst, sizeof(nh->ip6_dst));

        dp_packet_set_l4(p, dp_packet_tail(p));

        l4_len = flow_compose_l4(p, flow);

        nh = dp_packet_l3(p);
        nh->ip6_plen = htons(l4_len);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        struct arp_eth_header *arp;

        arp = dp_packet_put_zeros(p, sizeof *arp);
        dp_packet_set_l3(p, arp);
        arp->ar_hrd = htons(1);
        arp->ar_pro = htons(ETH_TYPE_IP);
        arp->ar_hln = ETH_ADDR_LEN;
        arp->ar_pln = 4;
        arp->ar_op = htons(flow->nw_proto);

        if (flow->nw_proto == ARP_OP_REQUEST ||
            flow->nw_proto == ARP_OP_REPLY) {
            put_16aligned_be32(&arp->ar_spa, flow->nw_src);
            put_16aligned_be32(&arp->ar_tpa, flow->nw_dst);
            arp->ar_sha = flow->arp_sha;
            arp->ar_tha = flow->arp_tha;
        }
    }

    if (eth_type_mpls(flow->dl_type)) {
        int n;

        p->l2_5_ofs = p->l3_ofs;
        for (n = 1; n < FLOW_MAX_MPLS_LABELS; n++) {
            if (flow->mpls_lse[n - 1] & htonl(MPLS_BOS_MASK)) {
                break;
            }
        }
        while (n > 0) {
            push_mpls(p, flow->dl_type, flow->mpls_lse[--n]);
        }
    }
}

/* Compressed flow. */

/* Completes an initialization of 'dst' as a miniflow copy of 'src' begun by
 * the caller.  The caller must have already computed 'dst->map' properly to
 * indicate the significant uint64_t elements of 'src'.
 *
 * Normally the significant elements are the ones that are non-zero.  However,
 * when a miniflow is initialized from a (mini)mask, the values can be zeroes,
 * so that the flow and mask always have the same maps. */
void
miniflow_init(struct miniflow *dst, const struct flow *src)
{
    uint64_t *dst_u64 = miniflow_values(dst);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, dst->map) {
        *dst_u64++ = flow_u64_value(src, idx);
    }
}

/* Initialize the maps of 'flow' from 'src'. */
void
miniflow_map_init(struct miniflow *flow, const struct flow *src)
{
    /* Initialize map, counting the number of nonzero elements. */
    flowmap_init(&flow->map);
    for (size_t i = 0; i < FLOW_U64S; i++) {
        if (flow_u64_value(src, i)) {
            flowmap_set(&flow->map, i, 1);
        }
    }
}

/* Allocates 'n' count of miniflows, consecutive in memory, initializing the
 * map of each from 'src'.
 * Returns the size of the miniflow data. */
size_t
miniflow_alloc(struct miniflow *dsts[], size_t n, const struct miniflow *src)
{
    size_t n_values = miniflow_n_values(src);
    size_t data_size = MINIFLOW_VALUES_SIZE(n_values);
    struct miniflow *dst = xmalloc(n * (sizeof *src + data_size));
    size_t i;

    COVERAGE_INC(miniflow_malloc);

    for (i = 0; i < n; i++) {
        *dst = *src;   /* Copy maps. */
        dsts[i] = dst;
        dst += 1;      /* Just past the maps. */
        dst = (struct miniflow *)((uint64_t *)dst + n_values); /* Skip data. */
    }
    return data_size;
}

/* Returns a miniflow copy of 'src'.  The caller must eventually free() the
 * returned miniflow. */
struct miniflow *
miniflow_create(const struct flow *src)
{
    struct miniflow tmp;
    struct miniflow *dst;

    miniflow_map_init(&tmp, src);

    miniflow_alloc(&dst, 1, &tmp);
    miniflow_init(dst, src);
    return dst;
}

/* Initializes 'dst' as a copy of 'src'.  The caller must have allocated
 * 'dst' to have inline space for 'n_values' data in 'src'. */
void
miniflow_clone(struct miniflow *dst, const struct miniflow *src,
               size_t n_values)
{
    *dst = *src;   /* Copy maps. */
    memcpy(miniflow_values(dst), miniflow_get_values(src),
           MINIFLOW_VALUES_SIZE(n_values));
}

/* Initializes 'dst' as a copy of 'src'. */
void
miniflow_expand(const struct miniflow *src, struct flow *dst)
{
    memset(dst, 0, sizeof *dst);
    flow_union_with_miniflow(dst, src);
}

/* Returns true if 'a' and 'b' are equal miniflows, false otherwise. */
bool
miniflow_equal(const struct miniflow *a, const struct miniflow *b)
{
    const uint64_t *ap = miniflow_get_values(a);
    const uint64_t *bp = miniflow_get_values(b);

    /* This is mostly called after a matching hash, so it is highly likely that
     * the maps are equal as well. */
    if (OVS_LIKELY(flowmap_equal(a->map, b->map))) {
        return !memcmp(ap, bp, miniflow_n_values(a) * sizeof *ap);
    } else {
        size_t idx;

        FLOWMAP_FOR_EACH_INDEX (idx, flowmap_or(a->map, b->map)) {
            if ((flowmap_is_set(&a->map, idx) ? *ap++ : 0)
                != (flowmap_is_set(&b->map, idx) ? *bp++ : 0)) {
                return false;
            }
        }
    }

    return true;
}

/* Returns false if 'a' and 'b' differ at the places where there are 1-bits
 * in 'mask', true otherwise. */
bool
miniflow_equal_in_minimask(const struct miniflow *a, const struct miniflow *b,
                           const struct minimask *mask)
{
    const uint64_t *p = miniflow_get_values(&mask->masks);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        if ((miniflow_get(a, idx) ^ miniflow_get(b, idx)) & *p++) {
            return false;
        }
    }

    return true;
}

/* Returns true if 'a' and 'b' are equal at the places where there are 1-bits
 * in 'mask', false if they differ. */
bool
miniflow_equal_flow_in_minimask(const struct miniflow *a, const struct flow *b,
                                const struct minimask *mask)
{
    const uint64_t *p = miniflow_get_values(&mask->masks);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        if ((miniflow_get(a, idx) ^ flow_u64_value(b, idx)) & *p++) {
            return false;
        }
    }

    return true;
}


void
minimask_init(struct minimask *mask, const struct flow_wildcards *wc)
{
    miniflow_init(&mask->masks, &wc->masks);
}

/* Returns a minimask copy of 'wc'.  The caller must eventually free the
 * returned minimask with free(). */
struct minimask *
minimask_create(const struct flow_wildcards *wc)
{
    return (struct minimask *)miniflow_create(&wc->masks);
}

/* Initializes 'dst_' as the bit-wise "and" of 'a_' and 'b_'.
 *
 * The caller must provide room for FLOW_U64S "uint64_t"s in 'storage', which
 * must follow '*dst_' in memory, for use by 'dst_'.  The caller must *not*
 * free 'dst_' free(). */
void
minimask_combine(struct minimask *dst_,
                 const struct minimask *a_, const struct minimask *b_,
                 uint64_t storage[FLOW_U64S])
{
    struct miniflow *dst = &dst_->masks;
    uint64_t *dst_values = storage;
    const struct miniflow *a = &a_->masks;
    const struct miniflow *b = &b_->masks;
    size_t idx;

    flowmap_init(&dst->map);

    FLOWMAP_FOR_EACH_INDEX(idx, flowmap_and(a->map, b->map)) {
        /* Both 'a' and 'b' have non-zero data at 'idx'. */
        uint64_t mask = *miniflow_get__(a, idx) & *miniflow_get__(b, idx);

        if (mask) {
            flowmap_set(&dst->map, idx, 1);
            *dst_values++ = mask;
        }
    }
}

/* Initializes 'wc' as a copy of 'mask'. */
void
minimask_expand(const struct minimask *mask, struct flow_wildcards *wc)
{
    miniflow_expand(&mask->masks, &wc->masks);
}

/* Returns true if 'a' and 'b' are the same flow mask, false otherwise.
 * Minimasks may not have zero data values, so for the minimasks to be the
 * same, they need to have the same map and the same data values. */
bool
minimask_equal(const struct minimask *a, const struct minimask *b)
{
    return !memcmp(a, b, sizeof *a
                   + MINIFLOW_VALUES_SIZE(miniflow_n_values(&a->masks)));
}

/* Returns true if at least one bit matched by 'b' is wildcarded by 'a',
 * false otherwise. */
bool
minimask_has_extra(const struct minimask *a, const struct minimask *b)
{
    const uint64_t *bp = miniflow_get_values(&b->masks);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, b->masks.map) {
        uint64_t b_u64 = *bp++;

        /* 'b_u64' is non-zero, check if the data in 'a' is either zero
         * or misses some of the bits in 'b_u64'. */
        if (!MINIFLOW_IN_MAP(&a->masks, idx)
            || ((*miniflow_get__(&a->masks, idx) & b_u64) != b_u64)) {
            return true; /* 'a' wildcards some bits 'b' doesn't. */
        }
    }

    return false;
}
