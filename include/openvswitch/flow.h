/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#ifndef OPENVSWITCH_FLOW_H
#define OPENVSWITCH_FLOW_H 1

#include "openflow/nicira-ext.h"
#include "openvswitch/packets.h"
#include "openvswitch/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This sequence number should be incremented whenever anything involving flows
 * or the wildcarding of flows changes.  This will cause build assertion
 * failures in places which likely need to be updated. */
#define FLOW_WC_SEQ 41

/* Number of Open vSwitch extension 32-bit registers. */
#define FLOW_N_REGS 16
BUILD_ASSERT_DECL(FLOW_N_REGS <= NXM_NX_MAX_REGS);
BUILD_ASSERT_DECL(FLOW_N_REGS % 4 == 0); /* Handle xxregs. */

/* Number of OpenFlow 1.5+ 64-bit registers.
 *
 * Each of these overlays a pair of Open vSwitch 32-bit registers, so there
 * are half as many of them.*/
#define FLOW_N_XREGS (FLOW_N_REGS / 2)

/* Number of 128-bit registers.
 *
 * Each of these overlays four Open vSwitch 32-bit registers, so there
 * are a quarter as many of them.*/
#define FLOW_N_XXREGS (FLOW_N_REGS / 4)

/* Used for struct flow's dl_type member for frames that have no Ethernet
 * type, that is, pure 802.2 frames. */
#define FLOW_DL_TYPE_NONE 0x5ff

/* Fragment bits, used for IPv4 and IPv6, always zero for non-IP flows. */
#define FLOW_NW_FRAG_ANY   (1 << 0) /* Set for any IP frag. */
#define FLOW_NW_FRAG_LATER (1 << 1) /* Set for IP frag with nonzero offset. */
#define FLOW_NW_FRAG_MASK  (FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER)

BUILD_ASSERT_DECL(FLOW_NW_FRAG_ANY == NX_IP_FRAG_ANY);
BUILD_ASSERT_DECL(FLOW_NW_FRAG_LATER == NX_IP_FRAG_LATER);

BUILD_ASSERT_DECL(FLOW_TNL_F_OAM == NX_TUN_FLAG_OAM);

const char *flow_tun_flag_to_string(uint32_t flags);

/* Maximum number of supported MPLS labels. */
#define FLOW_MAX_MPLS_LABELS 3

/* Maximum number of supported SAMPLE action nesting. */
#define FLOW_MAX_SAMPLE_NESTING 10

/* Maximum number of supported VLAN headers.
 *
 * We require this to be a multiple of 2 so that vlans[] in struct flow is a
 * multiple of 64 bits. */
#define FLOW_MAX_VLAN_HEADERS 2
BUILD_ASSERT_DECL(FLOW_MAX_VLAN_HEADERS % 2 == 0);

/* Legacy maximum VLAN headers */
#define LEGACY_MAX_VLAN_HEADERS 1

/*
 * A flow in the network.
 *
 * Must be initialized to all zeros to make any compiler-induced padding
 * zeroed.  Helps also in keeping unused fields (such as mutually exclusive
 * IPv4 and IPv6 addresses) zeroed out.
 *
 * The meaning of 'in_port' is context-dependent.  In most cases, it is a
 * 16-bit OpenFlow 1.0 port number.  In the software datapath interface (dpif)
 * layer and its implementations (e.g. dpif-netlink, dpif-netdev), it is
 * instead a 32-bit datapath port number.
 *
 * The fields are organized in four segments to facilitate staged lookup, where
 * lower layer fields are first used to determine if the later fields need to
 * be looked at.  This enables better wildcarding for datapath flows.
 *
 * NOTE: Order of the fields is significant, any change in the order must be
 * reflected in miniflow_extract()!
 */
struct flow {
    /* Metadata */
    struct flow_tnl tunnel;     /* Encapsulating tunnel parameters. */
    ovs_be64 metadata;          /* OpenFlow Metadata. */
    uint32_t regs[FLOW_N_REGS]; /* Registers. */
    uint32_t skb_priority;      /* Packet priority for QoS. */
    uint32_t pkt_mark;          /* Packet mark. */
    uint32_t dp_hash;           /* Datapath computed hash value. The exact
                                 * computation is opaque to the user space. */
    union flow_in_port in_port; /* Input port.*/
    uint32_t recirc_id;         /* Must be exact match. */
    uint8_t ct_state;           /* Connection tracking state. */
    uint8_t ct_nw_proto;        /* CT orig tuple IP protocol. */
    uint16_t ct_zone;           /* Connection tracking zone. */
    uint32_t ct_mark;           /* Connection mark.*/
    ovs_be32 packet_type;       /* OpenFlow packet type. */
    ovs_u128 ct_label;          /* Connection label. */
    uint32_t conj_id;           /* Conjunction ID. */
    ofp_port_t actset_output;   /* Output port in action set. */

    /* L2, Order the same as in the Ethernet header! (64-bit aligned) */
    struct eth_addr dl_dst;     /* Ethernet destination address. */
    struct eth_addr dl_src;     /* Ethernet source address. */
    ovs_be16 dl_type;           /* Ethernet frame type.
                                   Note: This also holds the Ethertype for L3
                                   packets of type PACKET_TYPE(1, Ethertype) */
    uint8_t pad1[2];            /* Pad to 64 bits. */
    union flow_vlan_hdr vlans[FLOW_MAX_VLAN_HEADERS]; /* VLANs */
    ovs_be32 mpls_lse[ROUND_UP(FLOW_MAX_MPLS_LABELS, 2)]; /* MPLS label stack
                                                             (with padding). */
    /* L3 (64-bit aligned) */
    ovs_be32 nw_src;            /* IPv4 source address or ARP SPA. */
    ovs_be32 nw_dst;            /* IPv4 destination address or ARP TPA. */
    ovs_be32 ct_nw_src;         /* CT orig tuple IPv4 source address. */
    ovs_be32 ct_nw_dst;         /* CT orig tuple IPv4 destination address. */
    struct in6_addr ipv6_src;   /* IPv6 source address. */
    struct in6_addr ipv6_dst;   /* IPv6 destination address. */
    struct in6_addr ct_ipv6_src; /* CT orig tuple IPv6 source address. */
    struct in6_addr ct_ipv6_dst; /* CT orig tuple IPv6 destination address. */
    ovs_be32 ipv6_label;        /* IPv6 flow label. */
    uint8_t nw_frag;            /* FLOW_FRAG_* flags. */
    uint8_t nw_tos;             /* IP ToS (including DSCP and ECN). */
    uint8_t nw_ttl;             /* IP TTL/Hop Limit. */
    uint8_t nw_proto;           /* IP protocol or low 8 bits of ARP opcode. */
    struct in6_addr nd_target;  /* IPv6 neighbor discovery (ND) target. */
    struct eth_addr arp_sha;    /* ARP/ND source hardware address. */
    struct eth_addr arp_tha;    /* ARP/ND target hardware address. */
    ovs_be16 tcp_flags;         /* TCP flags. With L3 to avoid matching L4. */
    ovs_be16 pad2;              /* Pad to 64 bits. */
    struct ovs_key_nsh nsh;     /* Network Service Header keys */

    /* L4 (64-bit aligned) */
    ovs_be16 tp_src;            /* TCP/UDP/SCTP source port/ICMP type. */
    ovs_be16 tp_dst;            /* TCP/UDP/SCTP destination port/ICMP code. */
    ovs_be16 ct_tp_src;         /* CT original tuple source port/ICMP type. */
    ovs_be16 ct_tp_dst;         /* CT original tuple dst port/ICMP code. */
    ovs_be32 igmp_group_ip4;    /* IGMP group IPv4 address.
                                 * Keep last for BUILD_ASSERT_DECL below. */
    ovs_be32 pad3;              /* Pad to 64 bits. */
};
BUILD_ASSERT_DECL(sizeof(struct flow) % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(sizeof(struct flow_tnl) % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(sizeof(struct ovs_key_nsh) % sizeof(uint64_t) == 0);

#define FLOW_U64S (sizeof(struct flow) / sizeof(uint64_t))

/* Remember to update FLOW_WC_SEQ when changing 'struct flow'. */
BUILD_ASSERT_DECL(offsetof(struct flow, igmp_group_ip4) + sizeof(uint32_t)
                  == sizeof(struct flow_tnl) + sizeof(struct ovs_key_nsh) + 300
                  && FLOW_WC_SEQ == 41);

/* Incremental points at which flow classification may be performed in
 * segments.
 * This is located here since this is dependent on the structure of the
 * struct flow defined above:
 * Each offset must be on a distinct, successive U64 boundary strictly
 * within the struct flow. */
enum {
    FLOW_SEGMENT_1_ENDS_AT = offsetof(struct flow, dl_dst),
    FLOW_SEGMENT_2_ENDS_AT = offsetof(struct flow, nw_src),
    FLOW_SEGMENT_3_ENDS_AT = offsetof(struct flow, tp_src),
};
BUILD_ASSERT_DECL(FLOW_SEGMENT_1_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(FLOW_SEGMENT_2_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(FLOW_SEGMENT_3_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(                     0 < FLOW_SEGMENT_1_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_1_ENDS_AT < FLOW_SEGMENT_2_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_2_ENDS_AT < FLOW_SEGMENT_3_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_3_ENDS_AT < sizeof(struct flow));

/* Wildcards for a flow.
 *
 * A 1-bit in each bit in 'masks' indicates that the corresponding bit of
 * the flow is significant (must match).  A 0-bit indicates that the
 * corresponding bit of the flow is wildcarded (need not match). */
struct flow_wildcards {
    struct flow masks;
};

#define WC_MASK_FIELD(WC, FIELD) \
    memset(&(WC)->masks.FIELD, 0xff, sizeof (WC)->masks.FIELD)
#define WC_MASK_FIELD_MASK(WC, FIELD, MASK)     \
    ((WC)->masks.FIELD |= (MASK))
#define WC_UNMASK_FIELD(WC, FIELD) \
    memset(&(WC)->masks.FIELD, 0, sizeof (WC)->masks.FIELD)

void flow_wildcards_init_catchall(struct flow_wildcards *);

void flow_wildcards_init_for_packet(struct flow_wildcards *,
                                    const struct flow *);

void flow_wildcards_clear_non_packet_fields(struct flow_wildcards *);

bool flow_wildcards_is_catchall(const struct flow_wildcards *);

void flow_wildcards_set_reg_mask(struct flow_wildcards *,
                                 int idx, uint32_t mask);
void flow_wildcards_set_xreg_mask(struct flow_wildcards *,
                                  int idx, uint64_t mask);
void flow_wildcards_set_xxreg_mask(struct flow_wildcards *,
                                   int idx, ovs_u128 mask);

void flow_wildcards_and(struct flow_wildcards *dst,
                        const struct flow_wildcards *src1,
                        const struct flow_wildcards *src2);
void flow_wildcards_or(struct flow_wildcards *dst,
                       const struct flow_wildcards *src1,
                       const struct flow_wildcards *src2);
bool flow_wildcards_has_extra(const struct flow_wildcards *,
                              const struct flow_wildcards *);
uint32_t flow_wildcards_hash(const struct flow_wildcards *, uint32_t basis);
bool flow_wildcards_equal(const struct flow_wildcards *,
                          const struct flow_wildcards *);

#ifdef __cplusplus
}
#endif

#endif /* flow.h */
