/* Copyright (c) 2008, 2011, 2012 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
 * Copyright (c) 2012 Horms Solutions Ltd.
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

/* OpenFlow: protocol between controller and datapath. */

#ifndef OPENFLOW_12_H
#define OPENFLOW_12_H 1

#include "openflow/openflow-1.1.h"

/*
 * OXM Class IDs.
 * The high order bit differentiate reserved classes from member classes.
 * Classes 0x0000 to 0x7FFF are member classes, allocated by ONF.
 * Classes 0x8000 to 0xFFFE are reserved classes, reserved for standardisation.
 */
enum ofp12_oxm_class {
    OFPXMC12_NXM_0          = 0x0000, /* Backward compatibility with NXM */
    OFPXMC12_NXM_1          = 0x0001, /* Backward compatibility with NXM */
    OFPXMC12_OPENFLOW_BASIC = 0x8000, /* Basic class for OpenFlow */
    OFPXMC12_EXPERIMENTER   = 0xffff, /* Experimenter class */
};

/* OXM Flow match field types for OpenFlow basic class. */
enum oxm12_ofb_match_fields {
    OFPXMT12_OFB_IN_PORT,        /* Switch input port. */
    OFPXMT12_OFB_IN_PHY_PORT,    /* Switch physical input port. */
    OFPXMT12_OFB_METADATA,       /* Metadata passed between tables. */
    OFPXMT12_OFB_ETH_DST,        /* Ethernet destination address. */
    OFPXMT12_OFB_ETH_SRC,        /* Ethernet source address. */
    OFPXMT12_OFB_ETH_TYPE,       /* Ethernet frame type. */
    OFPXMT12_OFB_VLAN_VID,       /* VLAN id. */
    OFPXMT12_OFB_VLAN_PCP,       /* VLAN priority. */
    OFPXMT12_OFB_IP_DSCP,        /* IP DSCP (6 bits in ToS field). */
    OFPXMT12_OFB_IP_ECN,         /* IP ECN (2 bits in ToS field). */
    OFPXMT12_OFB_IP_PROTO,       /* IP protocol. */
    OFPXMT12_OFB_IPV4_SRC,       /* IPv4 source address. */
    OFPXMT12_OFB_IPV4_DST,       /* IPv4 destination address. */
    OFPXMT12_OFB_TCP_SRC,        /* TCP source port. */
    OFPXMT12_OFB_TCP_DST,        /* TCP destination port. */
    OFPXMT12_OFB_UDP_SRC,        /* UDP source port. */
    OFPXMT12_OFB_UDP_DST,        /* UDP destination port. */
    OFPXMT12_OFB_SCTP_SRC,       /* SCTP source port. */
    OFPXMT12_OFB_SCTP_DST,       /* SCTP destination port. */
    OFPXMT12_OFB_ICMPV4_TYPE,    /* ICMP type. */
    OFPXMT12_OFB_ICMPV4_CODE,    /* ICMP code. */
    OFPXMT12_OFB_ARP_OP,         /* ARP opcode. */
    OFPXMT12_OFB_ARP_SPA,        /* ARP source IPv4 address. */
    OFPXMT12_OFB_ARP_TPA,        /* ARP target IPv4 address. */
    OFPXMT12_OFB_ARP_SHA,        /* ARP source hardware address. */
    OFPXMT12_OFB_ARP_THA,        /* ARP target hardware address. */
    OFPXMT12_OFB_IPV6_SRC,       /* IPv6 source address. */
    OFPXMT12_OFB_IPV6_DST,       /* IPv6 destination address. */
    OFPXMT12_OFB_IPV6_FLABEL,    /* IPv6 Flow Label */
    OFPXMT12_OFB_ICMPV6_TYPE,    /* ICMPv6 type. */
    OFPXMT12_OFB_ICMPV6_CODE,    /* ICMPv6 code. */
    OFPXMT12_OFB_IPV6_ND_TARGET, /* Target address for ND. */
    OFPXMT12_OFB_IPV6_ND_SLL,    /* Source link-layer for ND. */
    OFPXMT12_OFB_IPV6_ND_TLL,    /* Target link-layer for ND. */
    OFPXMT12_OFB_MPLS_LABEL,     /* MPLS label. */
    OFPXMT12_OFB_MPLS_TC,        /* MPLS TC. */

    /* End Marker */
    OFPXMT12_OFB_MAX,
};

#define OFPXMT12_MASK ((1ULL << OFPXMT12_OFB_MAX) - 1)

/* OXM implementation makes use of NXM as they are the same format
 * with different field definitions
 */

#define OXM_HEADER(FIELD, LENGTH) \
    NXM_HEADER(OFPXMC12_OPENFLOW_BASIC, FIELD, LENGTH)
#define OXM_HEADER_W(FIELD, LENGTH) \
    NXM_HEADER_W(OFPXMC12_OPENFLOW_BASIC, FIELD, LENGTH)

#define IS_OXM_HEADER(header) (NXM_VENDOR(header) == OFPXMC12_OPENFLOW_BASIC)

#define OXM_OF_IN_PORT        OXM_HEADER   (OFPXMT12_OFB_IN_PORT, 4)
#define OXM_OF_IN_PHY_PORT    OXM_HEADER   (OFPXMT12_OFB_IN_PHY_PORT, 4)
#define OXM_OF_METADATA       OXM_HEADER   (OFPXMT12_OFB_METADATA, 8)
#define OXM_OF_ETH_DST        OXM_HEADER   (OFPXMT12_OFB_ETH_DST, 6)
#define OXM_OF_ETH_DST_W      OXM_HEADER_W (OFPXMT12_OFB_ETH_DST, 6)
#define OXM_OF_ETH_SRC        OXM_HEADER   (OFPXMT12_OFB_ETH_SRC, 6)
#define OXM_OF_ETH_SRC_W      OXM_HEADER_W (OFPXMT12_OFB_ETH_SRC, 6)
#define OXM_OF_ETH_TYPE       OXM_HEADER   (OFPXMT12_OFB_ETH_TYPE, 2)
#define OXM_OF_VLAN_VID       OXM_HEADER   (OFPXMT12_OFB_VLAN_VID, 2)
#define OXM_OF_VLAN_VID_W     OXM_HEADER_W (OFPXMT12_OFB_VLAN_VID, 2)
#define OXM_OF_VLAN_PCP       OXM_HEADER   (OFPXMT12_OFB_VLAN_PCP, 1)
#define OXM_OF_IP_DSCP        OXM_HEADER   (OFPXMT12_OFB_IP_DSCP, 1)
#define OXM_OF_IP_ECN         OXM_HEADER   (OFPXMT12_OFB_IP_ECN, 1)
#define OXM_OF_IP_PROTO       OXM_HEADER   (OFPXMT12_OFB_IP_PROTO, 1)
#define OXM_OF_IPV4_SRC       OXM_HEADER   (OFPXMT12_OFB_IPV4_SRC, 4)
#define OXM_OF_IPV4_SRC_W     OXM_HEADER_W (OFPXMT12_OFB_IPV4_SRC, 4)
#define OXM_OF_IPV4_DST       OXM_HEADER   (OFPXMT12_OFB_IPV4_DST, 4)
#define OXM_OF_IPV4_DST_W     OXM_HEADER_W (OFPXMT12_OFB_IPV4_DST, 4)
#define OXM_OF_TCP_SRC        OXM_HEADER   (OFPXMT12_OFB_TCP_SRC, 2)
#define OXM_OF_TCP_DST        OXM_HEADER   (OFPXMT12_OFB_TCP_DST, 2)
#define OXM_OF_UDP_SRC        OXM_HEADER   (OFPXMT12_OFB_UDP_SRC, 2)
#define OXM_OF_UDP_DST        OXM_HEADER   (OFPXMT12_OFB_UDP_DST, 2)
#define OXM_OF_SCTP_SRC       OXM_HEADER   (OFPXMT12_OFB_SCTP_SRC, 2)
#define OXM_OF_SCTP_DST       OXM_HEADER   (OFPXMT12_OFB_SCTP_DST, 2)
#define OXM_OF_ICMPV4_TYPE    OXM_HEADER   (OFPXMT12_OFB_ICMPV4_TYPE, 1)
#define OXM_OF_ICMPV4_CODE    OXM_HEADER   (OFPXMT12_OFB_ICMPV4_CODE, 1)
#define OXM_OF_ARP_OP         OXM_HEADER   (OFPXMT12_OFB_ARP_OP, 2)
#define OXM_OF_ARP_SPA        OXM_HEADER   (OFPXMT12_OFB_ARP_SPA, 4)
#define OXM_OF_ARP_SPA_W      OXM_HEADER_W (OFPXMT12_OFB_ARP_SPA, 4)
#define OXM_OF_ARP_TPA        OXM_HEADER   (OFPXMT12_OFB_ARP_TPA, 4)
#define OXM_OF_ARP_TPA_W      OXM_HEADER_W (OFPXMT12_OFB_ARP_TPA, 4)
#define OXM_OF_ARP_SHA        OXM_HEADER   (OFPXMT12_OFB_ARP_SHA, 6)
#define OXM_OF_ARP_SHA_W      OXM_HEADER_W (OFPXMT12_OFB_ARP_SHA, 6)
#define OXM_OF_ARP_THA        OXM_HEADER   (OFPXMT12_OFB_ARP_THA, 6)
#define OXM_OF_ARP_THA_W      OXM_HEADER_W (OFPXMT12_OFB_ARP_THA, 6)
#define OXM_OF_IPV6_SRC       OXM_HEADER   (OFPXMT12_OFB_IPV6_SRC, 16)
#define OXM_OF_IPV6_SRC_W     OXM_HEADER_W (OFPXMT12_OFB_IPV6_SRC, 16)
#define OXM_OF_IPV6_DST       OXM_HEADER   (OFPXMT12_OFB_IPV6_DST, 16)
#define OXM_OF_IPV6_DST_W     OXM_HEADER_W (OFPXMT12_OFB_IPV6_DST, 16)
#define OXM_OF_IPV6_FLABEL    OXM_HEADER   (OFPXMT12_OFB_IPV6_FLABEL, 4)
#define OXM_OF_IPV6_FLABEL_W  OXM_HEADER_W (OFPXMT12_OFB_IPV6_FLABEL, 4)
#define OXM_OF_ICMPV6_TYPE    OXM_HEADER   (OFPXMT12_OFB_ICMPV6_TYPE, 1)
#define OXM_OF_ICMPV6_CODE    OXM_HEADER   (OFPXMT12_OFB_ICMPV6_CODE, 1)
#define OXM_OF_IPV6_ND_TARGET OXM_HEADER   (OFPXMT12_OFB_IPV6_ND_TARGET, 16)
#define OXM_OF_IPV6_ND_SLL    OXM_HEADER   (OFPXMT12_OFB_IPV6_ND_SLL, 6)
#define OXM_OF_IPV6_ND_TLL    OXM_HEADER   (OFPXMT12_OFB_IPV6_ND_TLL, 6)
#define OXM_OF_MPLS_LABEL     OXM_HEADER   (OFPXMT12_OFB_MPLS_LABEL, 4)
#define OXM_OF_MPLS_TC        OXM_HEADER   (OFPXMT12_OFB_MPLS_TC, 1)

/* The VLAN id is 12-bits, so we can use the entire 16 bits to indicate
 * special conditions.
 */
enum ofp12_vlan_id {
    OFPVID12_PRESENT = 0x1000, /* Bit that indicate that a VLAN id is set */
    OFPVID12_NONE    = 0x0000, /* No VLAN id was set. */
};

/* Header for OXM experimenter match fields. */
struct ofp12_oxm_experimenter_header {
    ovs_be32 oxm_header;   /* oxm_class = OFPXMC_EXPERIMENTER */
    ovs_be32 experimenter; /* Experimenter ID which takes the same
                              form as in struct ofp11_experimenter_header. */
};
OFP_ASSERT(sizeof(struct ofp12_oxm_experimenter_header) == 8);

enum ofp12_action_type {
    OFPAT12_SET_FIELD = 25,     /* Set a header field using OXM TLV format. */
};

enum ofp12_controller_max_len {
    OFPCML12_MAX       = 0xffe5, /* maximum max_len value which can be used
                                  * to request a specific byte length. */
    OFPCML12_NO_BUFFER = 0xffff  /* indicates that no buffering should be
                                  * applied and the whole packet is to be
                                  * sent to the controller. */
};

/* Action structure for OFPAT12_SET_FIELD. */
struct ofp12_action_set_field {
    ovs_be16 type;                  /* OFPAT12_SET_FIELD. */
    ovs_be16 len;                   /* Length is padded to 64 bits. */
    ovs_be32 dst;                   /* OXM TLV header */
    /* Followed by:
     * - Exactly ((oxm_len + 4) + 7)/8*8 - (oxm_len + 4) (between 0 and 7)
     *   bytes of all-zero bytes
     */
};
OFP_ASSERT(sizeof(struct ofp12_action_set_field) == 8);

/* OpenFlow 1.2 specific flags
 * (struct ofp12_flow_mod, member flags). */
enum ofp12_flow_mod_flags {
    OFPFF12_RESET_COUNTS  = 1 << 2   /* Reset flow packet and byte counts. */
};

/* OpenFlow 1.2 specific capabilities
 * (struct ofp_switch_features, member capabilities). */
enum ofp12_capabilities {
    OFPC12_PORT_BLOCKED   = 1 << 8   /* Switch will block looping ports. */
};

/* OpenFlow 1.2 specific types
 * (struct ofp11_stats_request/reply, member type). */
enum ofp12_stats_types {
    /* Group features.
     * The request body is empty.
     * The reply body is struct ofp12_group_features_stats. */
    OFPST12_GROUP_FEATURES = 8
};

/* OpenFlow 1.2 specific properties
 * (struct ofp_queue_prop_header member property). */
enum ofp12_queue_properties {
    OFPQT12_MIN_RATE = 1,         /* Minimum datarate guaranteed. */
    OFPQT12_MAX_RATE = 2,         /* Maximum datarate. */
    OFPQT12_EXPERIMENTER = 0xffff /* Experimenter defined property. */
};

/* Body of reply to OFPST_TABLE request. */
struct ofp12_table_stats {
    uint8_t table_id;        /* Identifier of table.  Lower numbered tables
                                are consulted first. */
    uint8_t pad[7];          /* Align to 64-bits. */
    char name[OFP_MAX_TABLE_NAME_LEN];
    ovs_be64 match;          /* Bitmap of (1 << OFPXMT_*) that indicate the
                                fields the table can match on. */
    ovs_be64 wildcards;      /* Bitmap of (1 << OFPXMT_*) wildcards that are
                                supported by the table. */
    ovs_be32 write_actions;  /* Bitmap of OFPAT_* that are supported
                                by the table with OFPIT_WRITE_ACTIONS. */
    ovs_be32 apply_actions;  /* Bitmap of OFPAT_* that are supported
                                by the table with OFPIT_APPLY_ACTIONS. */
    ovs_be64 write_setfields;/* Bitmap of (1 << OFPXMT_*) header fields that
                                can be set with OFPIT_WRITE_ACTIONS. */
    ovs_be64 apply_setfields;/* Bitmap of (1 << OFPXMT_*) header fields that
                                can be set with OFPIT_APPLY_ACTIONS. */
    ovs_be64 metadata_match; /* Bits of metadata table can match. */
    ovs_be64 metadata_write; /* Bits of metadata table can write. */
    ovs_be32 instructions;   /* Bitmap of OFPIT_* values supported. */
    ovs_be32 config;         /* Bitmap of OFPTC_* values */
    ovs_be32 max_entries;    /* Max number of entries supported. */
    ovs_be32 active_count;   /* Number of active entries. */
    ovs_be64 lookup_count;   /* Number of packets looked up in table. */
    ovs_be64 matched_count;  /* Number of packets that hit table. */
};
OFP_ASSERT(sizeof(struct ofp12_table_stats) == 128);

/* Body of reply to OFPST12_GROUP_FEATURES request. Group features. */
struct ofp12_group_features_stats {
    ovs_be32  types;           /* Bitmap of OFPGT_* values supported. */
    ovs_be32  capabilities;    /* Bitmap of OFPGFC12_* capability supported. */
    ovs_be32  max_groups[4];   /* Maximum number of groups for each type. */
    ovs_be32  actions[4];      /* Bitmaps of OFPAT_* that are supported. */
};
OFP_ASSERT(sizeof(struct ofp12_group_features_stats) == 40);

/* Group configuration flags */
enum ofp12_group_capabilities {
    OFPGFC12_SELECT_WEIGHT   = 1 << 0, /* Support weight for select groups */
    OFPGFC12_SELECT_LIVENESS = 1 << 1, /* Support liveness for select groups */
    OFPGFC12_CHAINING        = 1 << 2, /* Support chaining groups */
    OFPGFC12_CHAINING_CHECKS = 1 << 3, /* Check chaining for loops and delete */
};

/* Body for ofp12_stats_request/reply of type OFPST_EXPERIMENTER. */
struct ofp12_experimenter_stats_header {
    ovs_be32 experimenter;    /* Experimenter ID which takes the same form
                                 as in struct ofp_experimenter_header. */
    ovs_be32 exp_type;        /* Experimenter defined. */
    /* Experimenter-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp12_experimenter_stats_header) == 8);

/* Role request and reply message. */
struct ofp12_role_request {
    ovs_be32 role;            /* One of OFPCR12_ROLE_*. */
    uint8_t pad[4];           /* Align to 64 bits. */
    ovs_be64 generation_id;   /* Master Election Generation Id */
};
OFP_ASSERT(sizeof(struct ofp12_role_request) == 16);

/* Controller roles. */
enum ofp12_controller_role {
    OFPCR12_ROLE_NOCHANGE,    /* Don't change current role. */
    OFPCR12_ROLE_EQUAL,       /* Default role, full access. */
    OFPCR12_ROLE_MASTER,      /* Full access, at most one master. */
    OFPCR12_ROLE_SLAVE,       /* Read-only access. */
};

/* Packet received on port (datapath -> controller). */
struct ofp12_packet_in {
    ovs_be32 buffer_id;     /* ID assigned by datapath. */
    ovs_be16 total_len;     /* Full length of frame. */
    uint8_t reason;         /* Reason packet is being sent (one of OFPR_*) */
    uint8_t table_id;       /* ID of the table that was looked up */
    /* Followed by:
     *   - Match
     *   - Exactly 2 all-zero padding bytes, then
     *   - An Ethernet frame whose length is inferred from header.length.
     * The padding bytes preceding the Ethernet frame ensure that the IP
     * header (if any) following the Ethernet header is 32-bit aligned.
     */
    /* struct ofp12_match match; */
    /* uint8_t pad[2];         Align to 64 bit + 16 bit */
    /* uint8_t data[0];        Ethernet frame */
};
OFP_ASSERT(sizeof(struct ofp12_packet_in) == 8);

/* Flow removed (datapath -> controller). */
struct ofp12_flow_removed {
    ovs_be64 cookie;          /* Opaque controller-issued identifier. */

    ovs_be16 priority;        /* Priority level of flow entry. */
    uint8_t reason;           /* One of OFPRR_*. */
    uint8_t table_id;         /* ID of the table */

    ovs_be32 duration_sec;    /* Time flow was alive in seconds. */
    ovs_be32 duration_nsec;   /* Time flow was alive in nanoseconds beyond
                                 duration_sec. */
    ovs_be16 idle_timeout;    /* Idle timeout from original flow mod. */
    ovs_be16 hard_timeout;    /* Hard timeout from original flow mod. */
    ovs_be64 packet_count;
    ovs_be64 byte_count;
    /* struct ofp12_match match;  Description of fields. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp12_flow_removed) == 40);

#endif /* openflow/openflow-1.2.h */
