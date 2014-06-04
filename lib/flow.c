/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "odp-util.h"
#include "random.h"
#include "unaligned.h"

COVERAGE_DEFINE(flow_extract);
COVERAGE_DEFINE(miniflow_malloc);

/* U32 indices for segmented flow classification. */
const uint8_t flow_segment_u32s[4] = {
    FLOW_SEGMENT_1_ENDS_AT / 4,
    FLOW_SEGMENT_2_ENDS_AT / 4,
    FLOW_SEGMENT_3_ENDS_AT / 4,
    FLOW_U32S
};

/* miniflow_extract() assumes the following to be true to optimize the
 * extraction process. */
BUILD_ASSERT_DECL(offsetof(struct flow, dl_type) + 2
                  == offsetof(struct flow, vlan_tci) &&
                  offsetof(struct flow, dl_type) / 4
                  == offsetof(struct flow, vlan_tci) / 4 );

BUILD_ASSERT_DECL(offsetof(struct flow, nw_frag) + 3
                  == offsetof(struct flow, nw_proto) &&
                  offsetof(struct flow, nw_tos) + 2
                  == offsetof(struct flow, nw_proto) &&
                  offsetof(struct flow, nw_ttl) + 1
                  == offsetof(struct flow, nw_proto) &&
                  offsetof(struct flow, nw_frag) / 4
                  == offsetof(struct flow, nw_tos) / 4 &&
                  offsetof(struct flow, nw_ttl) / 4
                  == offsetof(struct flow, nw_tos) / 4 &&
                  offsetof(struct flow, nw_proto) / 4
                  == offsetof(struct flow, nw_tos) / 4);

/* TCP flags in the first half of a BE32, zeroes in the other half. */
BUILD_ASSERT_DECL(offsetof(struct flow, tcp_flags) + 2
                  == offsetof(struct flow, pad) &&
                  offsetof(struct flow, tcp_flags) / 4
                  == offsetof(struct flow, pad) / 4);
#if WORDS_BIGENDIAN
#define TCP_FLAGS_BE32(tcp_ctl) ((OVS_FORCE ovs_be32)TCP_FLAGS_BE16(tcp_ctl) \
                                 << 16)
#else
#define TCP_FLAGS_BE32(tcp_ctl) ((OVS_FORCE ovs_be32)TCP_FLAGS_BE16(tcp_ctl))
#endif

BUILD_ASSERT_DECL(offsetof(struct flow, tp_src) + 2
                  == offsetof(struct flow, tp_dst) &&
                  offsetof(struct flow, tp_src) / 4
                  == offsetof(struct flow, tp_dst) / 4);

/* Removes 'size' bytes from the head end of '*datap', of size '*sizep', which
 * must contain at least 'size' bytes of data.  Returns the first byte of data
 * removed. */
static inline const void *
data_pull(void **datap, size_t *sizep, size_t size)
{
    char *data = (char *)*datap;
    *datap = data + size;
    *sizep -= size;
    return data;
}

/* If '*datap' has at least 'size' bytes of data, removes that many bytes from
 * the head end of '*datap' and returns the first byte removed.  Otherwise,
 * returns a null pointer without modifying '*datap'. */
static inline const void *
data_try_pull(void **datap, size_t *sizep, size_t size)
{
    return OVS_LIKELY(*sizep >= size) ? data_pull(datap, sizep, size) : NULL;
}

/* Context for pushing data to a miniflow. */
struct mf_ctx {
    uint64_t map;
    uint32_t *data;
    uint32_t * const end;
};

/* miniflow_push_* macros allow filling in a miniflow data values in order.
 * Assertions are needed only when the layout of the struct flow is modified.
 * 'ofs' is a compile-time constant, which allows most of the code be optimized
 * away.  Some GCC versions gave warnigns on ALWAYS_INLINE, so these are
 * defined as macros. */

#if (FLOW_WC_SEQ != 26)
#define MINIFLOW_ASSERT(X) ovs_assert(X)
#else
#define MINIFLOW_ASSERT(X)
#endif

#define miniflow_push_uint32_(MF, OFS, VALUE)                   \
{                                                               \
    MINIFLOW_ASSERT(MF.data < MF.end && (OFS) % 4 == 0          \
                    && !(MF.map & (UINT64_MAX << (OFS) / 4)));  \
    *MF.data++ = VALUE;                                         \
    MF.map |= UINT64_C(1) << (OFS) / 4;                         \
}

#define miniflow_push_be32_(MF, OFS, VALUE) \
    miniflow_push_uint32_(MF, OFS, (OVS_FORCE uint32_t)(VALUE))

#define miniflow_push_uint16_(MF, OFS, VALUE)                   \
{                                                               \
    MINIFLOW_ASSERT(MF.data < MF.end &&                                 \
                    (((OFS) % 4 == 0 && !(MF.map & (UINT64_MAX << (OFS) / 4))) \
                     || ((OFS) % 4 == 2 && MF.map & (UINT64_C(1) << (OFS) / 4) \
                         && !(MF.map & (UINT64_MAX << ((OFS) / 4 + 1)))))); \
                                                                        \
    if ((OFS) % 4 == 0) {                                               \
        *(uint16_t *)MF.data = VALUE;                                   \
        MF.map |= UINT64_C(1) << (OFS) / 4;                             \
    } else if ((OFS) % 4 == 2) {                                        \
        *((uint16_t *)MF.data + 1) = VALUE;                             \
        MF.data++;                                                      \
    }                                                                   \
}

#define miniflow_push_be16_(MF, OFS, VALUE)             \
    miniflow_push_uint16_(MF, OFS, (OVS_FORCE uint16_t)VALUE);

/* Data at 'valuep' may be unaligned. */
#define miniflow_push_words_(MF, OFS, VALUEP, N_WORDS)          \
{                                                               \
    int ofs32 = (OFS) / 4;                                      \
                                                                        \
    MINIFLOW_ASSERT(MF.data + (N_WORDS) <= MF.end && (OFS) % 4 == 0     \
                    && !(MF.map & (UINT64_MAX << ofs32)));              \
                                                                        \
    memcpy(MF.data, (VALUEP), (N_WORDS) * sizeof *MF.data);             \
    MF.data += (N_WORDS);                                               \
    MF.map |= ((UINT64_MAX >> (64 - (N_WORDS))) << ofs32);              \
}

#define miniflow_push_uint32(MF, FIELD, VALUE)                          \
    miniflow_push_uint32_(MF, offsetof(struct flow, FIELD), VALUE)

#define miniflow_push_be32(MF, FIELD, VALUE)                            \
    miniflow_push_be32_(MF, offsetof(struct flow, FIELD), VALUE)

#define miniflow_push_uint32_check(MF, FIELD, VALUE)                    \
    { if (OVS_LIKELY(VALUE)) {                                          \
            miniflow_push_uint32_(MF, offsetof(struct flow, FIELD), VALUE); \
        }                                                               \
    }

#define miniflow_push_be32_check(MF, FIELD, VALUE)                      \
    { if (OVS_LIKELY(VALUE)) {                                          \
            miniflow_push_be32_(MF, offsetof(struct flow, FIELD), VALUE); \
        }                                                               \
    }

#define miniflow_push_uint16(MF, FIELD, VALUE)                          \
    miniflow_push_uint16_(MF, offsetof(struct flow, FIELD), VALUE)

#define miniflow_push_be16(MF, FIELD, VALUE)                            \
    miniflow_push_be16_(MF, offsetof(struct flow, FIELD), VALUE)

#define miniflow_push_words(MF, FIELD, VALUEP, N_WORDS)                 \
    miniflow_push_words_(MF, offsetof(struct flow, FIELD), VALUEP, N_WORDS)

/* Pulls the MPLS headers at '*datap' and returns the count of them. */
static inline int
parse_mpls(void **datap, size_t *sizep)
{
    const struct mpls_hdr *mh;
    int count = 0;

    while ((mh = data_try_pull(datap, sizep, sizeof *mh))) {
        count++;
        if (mh->mpls_lse.lo & htons(1 << MPLS_BOS_SHIFT)) {
            break;
        }
    }
    return MAX(count, FLOW_MAX_MPLS_LABELS);
}

static inline ovs_be16
parse_vlan(void **datap, size_t *sizep)
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
parse_ethertype(void **datap, size_t *sizep)
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

static inline bool
parse_icmpv6(void **datap, size_t *sizep, const struct icmp6_hdr *icmp,
             const struct in6_addr **nd_target,
             uint8_t arp_buf[2][ETH_ADDR_LEN])
{
    if (icmp->icmp6_code == 0 &&
        (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT ||
         icmp->icmp6_type == ND_NEIGHBOR_ADVERT)) {

        *nd_target = data_try_pull(datap, sizep, sizeof **nd_target);
        if (OVS_UNLIKELY(!*nd_target)) {
            return false;
        }

        while (*sizep >= 8) {
            /* The minimum size of an option is 8 bytes, which also is
             * the size of Ethernet link-layer options. */
            const struct nd_opt_hdr *nd_opt = *datap;
            int opt_len = nd_opt->nd_opt_len * 8;

            if (!opt_len || opt_len > *sizep) {
                goto invalid;
            }

            /* Store the link layer address if the appropriate option is
             * provided.  It is considered an error if the same link
             * layer option is specified twice. */
            if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR
                    && opt_len == 8) {
                if (OVS_LIKELY(eth_addr_is_zero(arp_buf[0]))) {
                    memcpy(arp_buf[0], nd_opt + 1, ETH_ADDR_LEN);
                } else {
                    goto invalid;
                }
            } else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR
                    && opt_len == 8) {
                if (OVS_LIKELY(eth_addr_is_zero(arp_buf[1]))) {
                    memcpy(arp_buf[1], nd_opt + 1, ETH_ADDR_LEN);
                } else {
                    goto invalid;
                }
            }

            if (OVS_UNLIKELY(!data_try_pull(datap, sizep, opt_len))) {
                goto invalid;
            }
        }
    }

    return true;

invalid:
    return false;
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
flow_extract(struct ofpbuf *packet, const struct pkt_metadata *md,
             struct flow *flow)
{
    struct {
        struct miniflow mf;
        uint32_t buf[FLOW_U32S];
    } m;

    COVERAGE_INC(flow_extract);

    miniflow_initialize(&m.mf, m.buf);
    miniflow_extract(packet, md, &m.mf);
    miniflow_expand(&m.mf, flow);
}

/* Caller is responsible for initializing 'dst' with enough storage for
 * FLOW_U32S * 4 bytes. */
void
miniflow_extract(struct ofpbuf *packet, const struct pkt_metadata *md,
                 struct miniflow *dst)
{
    void *data = ofpbuf_data(packet);
    size_t size = ofpbuf_size(packet);
    uint32_t *values = miniflow_values(dst);
    struct mf_ctx mf = { 0, values, values + FLOW_U32S };
    char *l2;
    ovs_be16 dl_type;
    uint8_t nw_frag, nw_tos, nw_ttl, nw_proto;

    /* Metadata. */
    if (md) {
        if (md->tunnel.ip_dst) {
            miniflow_push_words(mf, tunnel, &md->tunnel,
                                sizeof md->tunnel / 4);
        }
        miniflow_push_uint32_check(mf, skb_priority, md->skb_priority);
        miniflow_push_uint32_check(mf, pkt_mark, md->pkt_mark);
        miniflow_push_uint32_check(mf, recirc_id, md->recirc_id);
        miniflow_push_uint32(mf, in_port, odp_to_u32(md->in_port.odp_port));
    }

    /* Initialize packet's layer pointer and offsets. */
    l2 = data;
    ofpbuf_set_frame(packet, data);

    /* Must have full Ethernet header to proceed. */
    if (OVS_UNLIKELY(size < sizeof(struct eth_header))) {
        goto out;
    } else {
        ovs_be16 vlan_tci;

        /* Link layer. */
        BUILD_ASSERT(offsetof(struct flow, dl_dst) + 6
                     == offsetof(struct flow, dl_src));
        miniflow_push_words(mf, dl_dst, data, ETH_ADDR_LEN * 2 / 4);
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
        miniflow_push_words(mf, mpls_lse, mpls, count);
    }

    /* Network layer. */
    packet->l3_ofs = (char *)data - l2;

    nw_frag = 0;
    if (OVS_LIKELY(dl_type == htons(ETH_TYPE_IP))) {
        const struct ip_header *nh = data;
        int ip_len;

        if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
            goto out;
        }
        ip_len = IP_IHL(nh->ip_ihl_ver) * 4;

        if (OVS_UNLIKELY(ip_len < IP_HEADER_LEN)) {
            goto out;
        }

        /* Push both source and destination address at once. */
        miniflow_push_words(mf, nw_src, &nh->ip_src, 2);

        nw_tos = nh->ip_tos;
        nw_ttl = nh->ip_ttl;
        nw_proto = nh->ip_proto;
        if (OVS_UNLIKELY(IP_IS_FRAGMENT(nh->ip_frag_off))) {
            nw_frag = FLOW_NW_FRAG_ANY;
            if (nh->ip_frag_off & htons(IP_FRAG_OFF_MASK)) {
                nw_frag |= FLOW_NW_FRAG_LATER;
            }
        }
        if (OVS_UNLIKELY(size < ip_len)) {
            goto out;
        }
        data_pull(&data, &size, ip_len);

    } else if (dl_type == htons(ETH_TYPE_IPV6)) {
        const struct ovs_16aligned_ip6_hdr *nh;
        ovs_be32 tc_flow;

        if (OVS_UNLIKELY(size < sizeof *nh)) {
            goto out;
        }
        nh = data_pull(&data, &size, sizeof *nh);

        miniflow_push_words(mf, ipv6_src, &nh->ip6_src,
                            sizeof nh->ip6_src / 4);
        miniflow_push_words(mf, ipv6_dst, &nh->ip6_dst,
                            sizeof nh->ip6_dst / 4);

        tc_flow = get_16aligned_be32(&nh->ip6_flow);
        {
            ovs_be32 label = tc_flow & htonl(IPV6_LABEL_MASK);
            miniflow_push_be32_check(mf, ipv6_label, label);
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
            uint8_t arp_buf[2][ETH_ADDR_LEN];
            const struct arp_eth_header *arp = (const struct arp_eth_header *)
                data_try_pull(&data, &size, ARP_ETH_HEADER_LEN);

            if (OVS_LIKELY(arp) && OVS_LIKELY(arp->ar_hrd == htons(1))
                && OVS_LIKELY(arp->ar_pro == htons(ETH_TYPE_IP))
                && OVS_LIKELY(arp->ar_hln == ETH_ADDR_LEN)
                && OVS_LIKELY(arp->ar_pln == 4)) {
                miniflow_push_words(mf, nw_src, &arp->ar_spa, 1);
                miniflow_push_words(mf, nw_dst, &arp->ar_tpa, 1);

                /* We only match on the lower 8 bits of the opcode. */
                if (OVS_LIKELY(ntohs(arp->ar_op) <= 0xff)) {
                    miniflow_push_be32(mf, nw_frag, htonl(ntohs(arp->ar_op)));
                }

                /* Must be adjacent. */
                BUILD_ASSERT(offsetof(struct flow, arp_sha) + 6
                             == offsetof(struct flow, arp_tha));

                memcpy(arp_buf[0], arp->ar_sha, ETH_ADDR_LEN);
                memcpy(arp_buf[1], arp->ar_tha, ETH_ADDR_LEN);
                miniflow_push_words(mf, arp_sha, arp_buf,
                                    ETH_ADDR_LEN * 2 / 4);
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

                miniflow_push_be32(mf, tcp_flags,
                                   TCP_FLAGS_BE32(tcp->tcp_ctl));
                miniflow_push_words(mf, tp_src, &tcp->tcp_src, 1);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_UDP)) {
            if (OVS_LIKELY(size >= UDP_HEADER_LEN)) {
                const struct udp_header *udp = data;

                miniflow_push_words(mf, tp_src, &udp->udp_src, 1);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_SCTP)) {
            if (OVS_LIKELY(size >= SCTP_HEADER_LEN)) {
                const struct sctp_header *sctp = data;

                miniflow_push_words(mf, tp_src, &sctp->sctp_src, 1);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_ICMP)) {
            if (OVS_LIKELY(size >= ICMP_HEADER_LEN)) {
                const struct icmp_header *icmp = data;

                miniflow_push_be16(mf, tp_src, htons(icmp->icmp_type));
                miniflow_push_be16(mf, tp_dst, htons(icmp->icmp_code));
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_ICMPV6)) {
            if (OVS_LIKELY(size >= sizeof(struct icmp6_hdr))) {
                const struct in6_addr *nd_target = NULL;
                uint8_t arp_buf[2][ETH_ADDR_LEN];
                const struct icmp6_hdr *icmp = data_pull(&data, &size,
                                                         sizeof *icmp);
                memset(arp_buf, 0, sizeof arp_buf);
                if (OVS_LIKELY(parse_icmpv6(&data, &size, icmp, &nd_target,
                                            arp_buf))) {
                    miniflow_push_words(mf, arp_sha, arp_buf,
                                             ETH_ADDR_LEN * 2 / 4);
                    if (nd_target) {
                        miniflow_push_words(mf, nd_target, nd_target,
                                            sizeof *nd_target / 4);
                    }
                    miniflow_push_be16(mf, tp_src, htons(icmp->icmp6_type));
                    miniflow_push_be16(mf, tp_dst, htons(icmp->icmp6_code));
                }
            }
        }
    }
    if (md) {
        miniflow_push_uint32_check(mf, dp_hash, md->dp_hash);
    }
 out:
    dst->map = mf.map;
}

/* For every bit of a field that is wildcarded in 'wildcards', sets the
 * corresponding bit in 'flow' to zero. */
void
flow_zero_wildcards(struct flow *flow, const struct flow_wildcards *wildcards)
{
    uint32_t *flow_u32 = (uint32_t *) flow;
    const uint32_t *wc_u32 = (const uint32_t *) &wildcards->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        flow_u32[i] &= wc_u32[i];
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

/* Initializes 'fmd' with the metadata found in 'flow'. */
void
flow_get_metadata(const struct flow *flow, struct flow_metadata *fmd)
{
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 26);

    fmd->dp_hash = flow->dp_hash;
    fmd->recirc_id = flow->recirc_id;
    fmd->tun_id = flow->tunnel.tun_id;
    fmd->tun_src = flow->tunnel.ip_src;
    fmd->tun_dst = flow->tunnel.ip_dst;
    fmd->metadata = flow->metadata;
    memcpy(fmd->regs, flow->regs, sizeof fmd->regs);
    fmd->pkt_mark = flow->pkt_mark;
    fmd->in_port = flow->in_port.ofp_port;
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
                    uint32_t mask)
{
    if (name) {
        ds_put_format(ds, "%s=", name);
    }
    while (mask) {
        uint32_t bit = rightmost_1bit(mask);
        const char *s = bit_to_string(bit);

        ds_put_format(ds, "%s%s", (flags & bit) ? "+" : "-",
                      s ? s : "[Unknown]");
        mask &= ~bit;
    }
}

void
flow_format(struct ds *ds, const struct flow *flow)
{
    struct match match;

    match_wc_init(&match, flow);
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

/* Clear the metadata and register wildcard masks. They are not packet
 * header fields. */
void
flow_wildcards_clear_non_packet_fields(struct flow_wildcards *wc)
{
    memset(&wc->masks.metadata, 0, sizeof wc->masks.metadata);
    memset(&wc->masks.regs, 0, sizeof wc->masks.regs);
}

/* Returns true if 'wc' matches every packet, false if 'wc' fixes any bits or
 * fields. */
bool
flow_wildcards_is_catchall(const struct flow_wildcards *wc)
{
    const uint32_t *wc_u32 = (const uint32_t *) &wc->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        if (wc_u32[i]) {
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
    uint32_t *dst_u32 = (uint32_t *) &dst->masks;
    const uint32_t *src1_u32 = (const uint32_t *) &src1->masks;
    const uint32_t *src2_u32 = (const uint32_t *) &src2->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        dst_u32[i] = src1_u32[i] & src2_u32[i];
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
    uint32_t *dst_u32 = (uint32_t *) &dst->masks;
    const uint32_t *src1_u32 = (const uint32_t *) &src1->masks;
    const uint32_t *src2_u32 = (const uint32_t *) &src2->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        dst_u32[i] = src1_u32[i] | src2_u32[i];
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
    const uint32_t *a_u32 = (const uint32_t *) &a->masks;
    const uint32_t *b_u32 = (const uint32_t *) &b->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        if ((a_u32[i] & b_u32[i]) != b_u32[i]) {
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
    const uint32_t *a_u32 = (const uint32_t *) a;
    const uint32_t *b_u32 = (const uint32_t *) b;
    const uint32_t *wc_u32 = (const uint32_t *) &wc->masks;
    size_t i;

    for (i = 0; i < FLOW_U32S; i++) {
        if ((a_u32[i] ^ b_u32[i]) & wc_u32[i]) {
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

/* Calculates the 5-tuple hash from the given miniflow.
 * This returns the same value as flow_hash_5tuple for the corresponding
 * flow. */
uint32_t
miniflow_hash_5tuple(const struct miniflow *flow, uint32_t basis)
{
    uint32_t hash = basis;

    if (flow) {
        ovs_be16 dl_type = MINIFLOW_GET_BE16(flow, dl_type);

        hash = mhash_add(hash, MINIFLOW_GET_U8(flow, nw_proto));

        /* Separate loops for better optimization. */
        if (dl_type == htons(ETH_TYPE_IPV6)) {
            uint64_t map = MINIFLOW_MAP(ipv6_src) | MINIFLOW_MAP(ipv6_dst)
                | MINIFLOW_MAP(tp_src); /* Covers both ports */
            uint32_t value;

            MINIFLOW_FOR_EACH_IN_MAP(value, flow, map) {
                hash = mhash_add(hash, value);
            }
        } else {
            uint64_t map = MINIFLOW_MAP(nw_src) | MINIFLOW_MAP(nw_dst)
                | MINIFLOW_MAP(tp_src); /* Covers both ports */
            uint32_t value;

            MINIFLOW_FOR_EACH_IN_MAP(value, flow, map) {
                hash = mhash_add(hash, value);
            }
        }
        hash = mhash_finish(hash, 42); /* Arbitrary number. */
    }
    return hash;
}

BUILD_ASSERT_DECL(offsetof(struct flow, tp_src) + 2
                  == offsetof(struct flow, tp_dst) &&
                  offsetof(struct flow, tp_src) / 4
                  == offsetof(struct flow, tp_dst) / 4);
BUILD_ASSERT_DECL(offsetof(struct flow, ipv6_src) + 16
                  == offsetof(struct flow, ipv6_dst));

/* Calculates the 5-tuple hash from the given flow. */
uint32_t
flow_hash_5tuple(const struct flow *flow, uint32_t basis)
{
    uint32_t hash = basis;

    if (flow) {
        const uint32_t *flow_u32 = (const uint32_t *)flow;

        hash = mhash_add(hash, flow->nw_proto);

        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            int ofs = offsetof(struct flow, ipv6_src) / 4;
            int end = ofs + 2 * sizeof flow->ipv6_src / 4;

            while (ofs < end) {
                hash = mhash_add(hash, flow_u32[ofs++]);
            }
        } else {
            hash = mhash_add(hash, (OVS_FORCE uint32_t) flow->nw_src);
            hash = mhash_add(hash, (OVS_FORCE uint32_t) flow->nw_dst);
        }
        hash = mhash_add(hash, flow_u32[offsetof(struct flow, tp_src) / 4]);

        hash = mhash_finish(hash, 42); /* Arbitrary number. */
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
        uint8_t eth_addr[ETH_ADDR_LEN];
        uint8_t ip_proto;
    } fields;

    int i;

    memset(&fields, 0, sizeof fields);
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        fields.eth_addr[i] = flow->dl_src[i] ^ flow->dl_dst[i];
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

/* Initialize a flow with random fields that matter for nx_hash_fields. */
void
flow_random_hash_fields(struct flow *flow)
{
    uint16_t rnd = random_uint16();

    /* Initialize to all zeros. */
    memset(flow, 0, sizeof *flow);

    eth_addr_random(flow->dl_src);
    eth_addr_random(flow->dl_dst);

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
        return jhash_bytes(flow->dl_src, sizeof flow->dl_src, basis);

    case NX_HASH_FIELDS_SYMMETRIC_L4:
        return flow_hash_symmetric_l4(flow, basis);
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
    default: return "<unknown>";
    }
}

/* Returns true if the value of 'fields' is supported. Otherwise false. */
bool
flow_hash_fields_valid(enum nx_hash_fields fields)
{
    return fields == NX_HASH_FIELDS_ETH_SRC
        || fields == NX_HASH_FIELDS_SYMMETRIC_L4;
}

/* Returns a hash value for the bits of 'flow' that are active based on
 * 'wc', given 'basis'. */
uint32_t
flow_hash_in_wildcards(const struct flow *flow,
                       const struct flow_wildcards *wc, uint32_t basis)
{
    const uint32_t *wc_u32 = (const uint32_t *) &wc->masks;
    const uint32_t *flow_u32 = (const uint32_t *) flow;
    uint32_t hash;
    size_t i;

    hash = basis;
    for (i = 0; i < FLOW_U32S; i++) {
        hash = mhash_add(hash, flow_u32[i] & wc_u32[i]);
    }
    return mhash_finish(hash, 4 * FLOW_U32S);
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
    if (wc) {
        wc->masks.dl_type = OVS_BE16_MAX;
    }
    if (eth_type_mpls(flow->dl_type)) {
        int i;
        int len = FLOW_MAX_MPLS_LABELS;

        for (i = 0; i < len; i++) {
            if (wc) {
                wc->masks.mpls_lse[i] |= htonl(MPLS_BOS_MASK);
            }
            if (flow->mpls_lse[i] & htonl(MPLS_BOS_MASK)) {
                return i + 1;
            }
        }

        return len;
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
 * If the new label is the second or label MPLS label in 'flow', it is
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

    memset(wc->masks.mpls_lse, 0xff, sizeof wc->masks.mpls_lse);
    if (n) {
        int i;

        for (i = n; i >= 1; i--) {
            flow->mpls_lse[i] = flow->mpls_lse[i - 1];
        }
        flow->mpls_lse[0] = (flow->mpls_lse[1]
                             & htonl(~MPLS_BOS_MASK));
    } else {
        int label = 0;          /* IPv4 Explicit Null. */
        int tc = 0;
        int ttl = 64;

        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            label = 2;
        }

        if (is_ip_any(flow)) {
            tc = (flow->nw_tos & IP_DSCP_MASK) >> 2;
            wc->masks.nw_tos |= IP_DSCP_MASK;

            if (flow->nw_ttl) {
                ttl = flow->nw_ttl;
            }
            wc->masks.nw_ttl = 0xff;
        }

        flow->mpls_lse[0] = set_mpls_lse_values(ttl, tc, 1, htonl(label));

        /* Clear all L3 and L4 fields. */
        BUILD_ASSERT(FLOW_WC_SEQ == 26);
        memset((char *) flow + FLOW_SEGMENT_2_ENDS_AT, 0,
               sizeof(struct flow) - FLOW_SEGMENT_2_ENDS_AT);
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
    } else if (n == FLOW_MAX_MPLS_LABELS
               && !(flow->mpls_lse[n - 1] & htonl(MPLS_BOS_MASK))) {
        /* Can't pop because we don't know what to fill in mpls_lse[n - 1]. */
        return false;
    }

    memset(wc->masks.mpls_lse, 0xff, sizeof wc->masks.mpls_lse);
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
flow_compose_l4(struct ofpbuf *b, const struct flow *flow)
{
    size_t l4_len = 0;

    if (!(flow->nw_frag & FLOW_NW_FRAG_ANY)
        || !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (flow->nw_proto == IPPROTO_TCP) {
            struct tcp_header *tcp;

            l4_len = sizeof *tcp;
            tcp = ofpbuf_put_zeros(b, l4_len);
            tcp->tcp_src = flow->tp_src;
            tcp->tcp_dst = flow->tp_dst;
            tcp->tcp_ctl = TCP_CTL(ntohs(flow->tcp_flags), 5);
        } else if (flow->nw_proto == IPPROTO_UDP) {
            struct udp_header *udp;

            l4_len = sizeof *udp;
            udp = ofpbuf_put_zeros(b, l4_len);
            udp->udp_src = flow->tp_src;
            udp->udp_dst = flow->tp_dst;
        } else if (flow->nw_proto == IPPROTO_SCTP) {
            struct sctp_header *sctp;

            l4_len = sizeof *sctp;
            sctp = ofpbuf_put_zeros(b, l4_len);
            sctp->sctp_src = flow->tp_src;
            sctp->sctp_dst = flow->tp_dst;
        } else if (flow->nw_proto == IPPROTO_ICMP) {
            struct icmp_header *icmp;

            l4_len = sizeof *icmp;
            icmp = ofpbuf_put_zeros(b, l4_len);
            icmp->icmp_type = ntohs(flow->tp_src);
            icmp->icmp_code = ntohs(flow->tp_dst);
            icmp->icmp_csum = csum(icmp, ICMP_HEADER_LEN);
        } else if (flow->nw_proto == IPPROTO_ICMPV6) {
            struct icmp6_hdr *icmp;

            l4_len = sizeof *icmp;
            icmp = ofpbuf_put_zeros(b, l4_len);
            icmp->icmp6_type = ntohs(flow->tp_src);
            icmp->icmp6_code = ntohs(flow->tp_dst);

            if (icmp->icmp6_code == 0 &&
                (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT ||
                 icmp->icmp6_type == ND_NEIGHBOR_ADVERT)) {
                struct in6_addr *nd_target;
                struct nd_opt_hdr *nd_opt;

                l4_len += sizeof *nd_target;
                nd_target = ofpbuf_put_zeros(b, sizeof *nd_target);
                *nd_target = flow->nd_target;

                if (!eth_addr_is_zero(flow->arp_sha)) {
                    l4_len += 8;
                    nd_opt = ofpbuf_put_zeros(b, 8);
                    nd_opt->nd_opt_len = 1;
                    nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
                    memcpy(nd_opt + 1, flow->arp_sha, ETH_ADDR_LEN);
                }
                if (!eth_addr_is_zero(flow->arp_tha)) {
                    l4_len += 8;
                    nd_opt = ofpbuf_put_zeros(b, 8);
                    nd_opt->nd_opt_len = 1;
                    nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
                    memcpy(nd_opt + 1, flow->arp_tha, ETH_ADDR_LEN);
                }
            }
            icmp->icmp6_cksum = (OVS_FORCE uint16_t)
                csum(icmp, (char *)ofpbuf_tail(b) - (char *)icmp);
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
flow_compose(struct ofpbuf *b, const struct flow *flow)
{
    size_t l4_len;

    /* eth_compose() sets l3 pointer and makes sure it is 32-bit aligned. */
    eth_compose(b, flow->dl_dst, flow->dl_src, ntohs(flow->dl_type), 0);
    if (flow->dl_type == htons(FLOW_DL_TYPE_NONE)) {
        struct eth_header *eth = ofpbuf_l2(b);
        eth->eth_type = htons(ofpbuf_size(b));
        return;
    }

    if (flow->vlan_tci & htons(VLAN_CFI)) {
        eth_push_vlan(b, htons(ETH_TYPE_VLAN), flow->vlan_tci);
    }

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct ip_header *ip;

        ip = ofpbuf_put_zeros(b, sizeof *ip);
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

        ofpbuf_set_l4(b, ofpbuf_tail(b));

        l4_len = flow_compose_l4(b, flow);

        ip = ofpbuf_l3(b);
        ip->ip_tot_len = htons(b->l4_ofs - b->l3_ofs + l4_len);
        ip->ip_csum = csum(ip, sizeof *ip);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_16aligned_ip6_hdr *nh;

        nh = ofpbuf_put_zeros(b, sizeof *nh);
        put_16aligned_be32(&nh->ip6_flow, htonl(6 << 28) |
                           htonl(flow->nw_tos << 20) | flow->ipv6_label);
        nh->ip6_hlim = flow->nw_ttl;
        nh->ip6_nxt = flow->nw_proto;

        memcpy(&nh->ip6_src, &flow->ipv6_src, sizeof(nh->ip6_src));
        memcpy(&nh->ip6_dst, &flow->ipv6_dst, sizeof(nh->ip6_dst));

        ofpbuf_set_l4(b, ofpbuf_tail(b));

        l4_len = flow_compose_l4(b, flow);

        nh = ofpbuf_l3(b);
        nh->ip6_plen = htons(l4_len);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        struct arp_eth_header *arp;

        arp = ofpbuf_put_zeros(b, sizeof *arp);
        ofpbuf_set_l3(b, arp);
        arp->ar_hrd = htons(1);
        arp->ar_pro = htons(ETH_TYPE_IP);
        arp->ar_hln = ETH_ADDR_LEN;
        arp->ar_pln = 4;
        arp->ar_op = htons(flow->nw_proto);

        if (flow->nw_proto == ARP_OP_REQUEST ||
            flow->nw_proto == ARP_OP_REPLY) {
            put_16aligned_be32(&arp->ar_spa, flow->nw_src);
            put_16aligned_be32(&arp->ar_tpa, flow->nw_dst);
            memcpy(arp->ar_sha, flow->arp_sha, ETH_ADDR_LEN);
            memcpy(arp->ar_tha, flow->arp_tha, ETH_ADDR_LEN);
        }
    }

    if (eth_type_mpls(flow->dl_type)) {
        int n;

        b->l2_5_ofs = b->l3_ofs;
        for (n = 1; n < FLOW_MAX_MPLS_LABELS; n++) {
            if (flow->mpls_lse[n - 1] & htonl(MPLS_BOS_MASK)) {
                break;
            }
        }
        while (n > 0) {
            push_mpls(b, flow->dl_type, flow->mpls_lse[--n]);
        }
    }
}

/* Compressed flow. */

static int
miniflow_n_values(const struct miniflow *flow)
{
    return count_1bits(flow->map);
}

static uint32_t *
miniflow_alloc_values(struct miniflow *flow, int n)
{
    int size = MINIFLOW_VALUES_SIZE(n);

    if (size <= sizeof flow->inline_values) {
        flow->values_inline = true;
        return flow->inline_values;
    } else {
        COVERAGE_INC(miniflow_malloc);
        flow->values_inline = false;
        flow->offline_values = xmalloc(size);
        return flow->offline_values;
    }
}

/* Completes an initialization of 'dst' as a miniflow copy of 'src' begun by
 * the caller.  The caller must have already initialized 'dst->map' properly
 * to indicate the significant uint32_t elements of 'src'.  'n' must be the
 * number of 1-bits in 'dst->map'.
 *
 * Normally the significant elements are the ones that are non-zero.  However,
 * when a miniflow is initialized from a (mini)mask, the values can be zeroes,
 * so that the flow and mask always have the same maps.
 *
 * This function initializes values (either inline if possible or with
 * malloc() otherwise) and copies the uint32_t elements of 'src' indicated by
 * 'dst->map' into it. */
static void
miniflow_init__(struct miniflow *dst, const struct flow *src, int n)
{
    const uint32_t *src_u32 = (const uint32_t *) src;
    uint32_t *dst_u32 = miniflow_alloc_values(dst, n);
    uint64_t map;

    for (map = dst->map; map; map = zero_rightmost_1bit(map)) {
        *dst_u32++ = src_u32[raw_ctz(map)];
    }
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with miniflow_destroy().
 * Always allocates offline storage. */
void
miniflow_init(struct miniflow *dst, const struct flow *src)
{
    const uint32_t *src_u32 = (const uint32_t *) src;
    unsigned int i;
    int n;

    /* Initialize dst->map, counting the number of nonzero elements. */
    n = 0;
    dst->map = 0;

    for (i = 0; i < FLOW_U32S; i++) {
        if (src_u32[i]) {
            dst->map |= UINT64_C(1) << i;
            n++;
        }
    }

    miniflow_init__(dst, src, n);
}

/* Initializes 'dst' as a copy of 'src', using 'mask->map' as 'dst''s map.  The
 * caller must eventually free 'dst' with miniflow_destroy(). */
void
miniflow_init_with_minimask(struct miniflow *dst, const struct flow *src,
                            const struct minimask *mask)
{
    dst->map = mask->masks.map;
    miniflow_init__(dst, src, miniflow_n_values(dst));
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with miniflow_destroy(). */
void
miniflow_clone(struct miniflow *dst, const struct miniflow *src)
{
    int size = MINIFLOW_VALUES_SIZE(miniflow_n_values(src));
    uint32_t *values;

    dst->map = src->map;
    if (size <= sizeof dst->inline_values) {
        dst->values_inline = true;
        values = dst->inline_values;
    } else {
        dst->values_inline = false;
        COVERAGE_INC(miniflow_malloc);
        dst->offline_values = xmalloc(size);
        values = dst->offline_values;
    }
    memcpy(values, miniflow_get_values(src), size);
}

/* Initializes 'dst' as a copy of 'src'.  The caller must have allocated
 * 'dst' to have inline space all data in 'src'. */
void
miniflow_clone_inline(struct miniflow *dst, const struct miniflow *src,
                      size_t n_values)
{
    dst->values_inline = true;
    dst->map = src->map;
    memcpy(dst->inline_values, miniflow_get_values(src),
           MINIFLOW_VALUES_SIZE(n_values));
}

/* Initializes 'dst' with the data in 'src', destroying 'src'.
 * The caller must eventually free 'dst' with miniflow_destroy().
 * 'dst' must be regularly sized miniflow, but 'src' can have
 * larger than default inline values. */
void
miniflow_move(struct miniflow *dst, struct miniflow *src)
{
    int size = MINIFLOW_VALUES_SIZE(miniflow_n_values(src));

    dst->map = src->map;
    if (size <= sizeof dst->inline_values) {
        dst->values_inline = true;
        memcpy(dst->inline_values, miniflow_get_values(src), size);
        miniflow_destroy(src);
    } else if (src->values_inline) {
        dst->values_inline = false;
        COVERAGE_INC(miniflow_malloc);
        dst->offline_values = xmalloc(size);
        memcpy(dst->offline_values, src->inline_values, size);
    } else {
        dst->values_inline = false;
        dst->offline_values = src->offline_values;
    }
}

/* Frees any memory owned by 'flow'.  Does not free the storage in which 'flow'
 * itself resides; the caller is responsible for that. */
void
miniflow_destroy(struct miniflow *flow)
{
    if (!flow->values_inline) {
        free(flow->offline_values);
    }
}

/* Initializes 'dst' as a copy of 'src'. */
void
miniflow_expand(const struct miniflow *src, struct flow *dst)
{
    memset(dst, 0, sizeof *dst);
    flow_union_with_miniflow(dst, src);
}

/* Returns the uint32_t that would be at byte offset '4 * u32_ofs' if 'flow'
 * were expanded into a "struct flow". */
static uint32_t
miniflow_get(const struct miniflow *flow, unsigned int u32_ofs)
{
    return (flow->map & UINT64_C(1) << u32_ofs)
        ? *(miniflow_get_u32_values(flow) +
            count_1bits(flow->map & ((UINT64_C(1) << u32_ofs) - 1)))
        : 0;
}

/* Returns true if 'a' and 'b' are the same flow, false otherwise.  */
bool
miniflow_equal(const struct miniflow *a, const struct miniflow *b)
{
    const uint32_t *ap = miniflow_get_u32_values(a);
    const uint32_t *bp = miniflow_get_u32_values(b);
    const uint64_t a_map = a->map;
    const uint64_t b_map = b->map;

    if (OVS_LIKELY(a_map == b_map)) {
        int count = miniflow_n_values(a);

        while (count--) {
            if (*ap++ != *bp++) {
                return false;
            }
        }
    } else {
        uint64_t map;

        for (map = a_map | b_map; map; map = zero_rightmost_1bit(map)) {
            uint64_t bit = rightmost_1bit(map);
            uint64_t a_value = a_map & bit ? *ap++ : 0;
            uint64_t b_value = b_map & bit ? *bp++ : 0;

            if (a_value != b_value) {
                return false;
            }
        }
    }

    return true;
}

/* Returns true if 'a' and 'b' are equal at the places where there are 1-bits
 * in 'mask', false if they differ. */
bool
miniflow_equal_in_minimask(const struct miniflow *a, const struct miniflow *b,
                           const struct minimask *mask)
{
    const uint32_t *p = miniflow_get_u32_values(&mask->masks);
    uint64_t map;

    for (map = mask->masks.map; map; map = zero_rightmost_1bit(map)) {
        int ofs = raw_ctz(map);

        if ((miniflow_get(a, ofs) ^ miniflow_get(b, ofs)) & *p++) {
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
    const uint32_t *b_u32 = (const uint32_t *) b;
    const uint32_t *p = miniflow_get_u32_values(&mask->masks);
    uint64_t map;

    for (map = mask->masks.map; map; map = zero_rightmost_1bit(map)) {
        int ofs = raw_ctz(map);

        if ((miniflow_get(a, ofs) ^ b_u32[ofs]) & *p++) {
            return false;
        }
    }

    return true;
}


/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with minimask_destroy(). */
void
minimask_init(struct minimask *mask, const struct flow_wildcards *wc)
{
    miniflow_init(&mask->masks, &wc->masks);
}

/* Initializes 'dst' as a copy of 'src'.  The caller must eventually free 'dst'
 * with minimask_destroy(). */
void
minimask_clone(struct minimask *dst, const struct minimask *src)
{
    miniflow_clone(&dst->masks, &src->masks);
}

/* Initializes 'dst' with the data in 'src', destroying 'src'.
 * The caller must eventually free 'dst' with minimask_destroy(). */
void
minimask_move(struct minimask *dst, struct minimask *src)
{
    miniflow_move(&dst->masks, &src->masks);
}

/* Initializes 'dst_' as the bit-wise "and" of 'a_' and 'b_'.
 *
 * The caller must provide room for FLOW_U32S "uint32_t"s in 'storage', for use
 * by 'dst_'.  The caller must *not* free 'dst_' with minimask_destroy(). */
void
minimask_combine(struct minimask *dst_,
                 const struct minimask *a_, const struct minimask *b_,
                 uint32_t storage[FLOW_U32S])
{
    struct miniflow *dst = &dst_->masks;
    uint32_t *dst_values = storage;
    const struct miniflow *a = &a_->masks;
    const struct miniflow *b = &b_->masks;
    uint64_t map;
    int n = 0;

    dst->values_inline = false;
    dst->offline_values = storage;

    dst->map = 0;
    for (map = a->map & b->map; map; map = zero_rightmost_1bit(map)) {
        int ofs = raw_ctz(map);
        uint32_t mask = miniflow_get(a, ofs) & miniflow_get(b, ofs);

        if (mask) {
            dst->map |= rightmost_1bit(map);
            dst_values[n++] = mask;
        }
    }
}

/* Frees any memory owned by 'mask'.  Does not free the storage in which 'mask'
 * itself resides; the caller is responsible for that. */
void
minimask_destroy(struct minimask *mask)
{
    miniflow_destroy(&mask->masks);
}

/* Initializes 'dst' as a copy of 'src'. */
void
minimask_expand(const struct minimask *mask, struct flow_wildcards *wc)
{
    miniflow_expand(&mask->masks, &wc->masks);
}

/* Returns the uint32_t that would be at byte offset '4 * u32_ofs' if 'mask'
 * were expanded into a "struct flow_wildcards". */
uint32_t
minimask_get(const struct minimask *mask, unsigned int u32_ofs)
{
    return miniflow_get(&mask->masks, u32_ofs);
}

/* Returns true if 'a' and 'b' are the same flow mask, false otherwise.  */
bool
minimask_equal(const struct minimask *a, const struct minimask *b)
{
    return miniflow_equal(&a->masks, &b->masks);
}

/* Returns true if at least one bit matched by 'b' is wildcarded by 'a',
 * false otherwise. */
bool
minimask_has_extra(const struct minimask *a, const struct minimask *b)
{
    const uint32_t *p = miniflow_get_u32_values(&b->masks);
    uint64_t map;

    for (map = b->masks.map; map; map = zero_rightmost_1bit(map)) {
        uint32_t a_u32 = minimask_get(a, raw_ctz(map));
        uint32_t b_u32 = *p++;

        if ((a_u32 & b_u32) != b_u32) {
            return true;
        }
    }

    return false;
}
