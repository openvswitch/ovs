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
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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

#ifndef OPENFLOW_COMMON_H
#define OPENFLOW_COMMON_H 1

#include "openvswitch/types.h"

#ifdef SWIG
#define OFP_ASSERT(EXPR)        /* SWIG can't handle OFP_ASSERT. */
#elif !defined(__cplusplus)
/* Build-time assertion for use in a declaration context. */
#define OFP_ASSERT(EXPR)                                                \
        extern int (*build_assert(void))[ sizeof(struct {               \
                    unsigned int build_assert_failed : (EXPR) ? 1 : -1; })]
#else /* __cplusplus */
#include <boost/static_assert.hpp>
#define OFP_ASSERT BOOST_STATIC_ASSERT
#endif /* __cplusplus */

/* Version number:
 * Non-experimental versions released: 0x01 0x02
 * Experimental versions released: 0x81 -- 0x99
 */
/* The most significant bit being set in the version field indicates an
 * experimental OpenFlow version.
 */
enum ofp_version {
    OFP10_VERSION = 0x01,
    OFP11_VERSION = 0x02,
    OFP12_VERSION = 0x03,
};

#define OFP_MAX_TABLE_NAME_LEN 32
#define OFP_MAX_PORT_NAME_LEN  16

#define OFP_TCP_PORT  6633
#define OFP_SSL_PORT  6633

#define OFP_ETH_ALEN 6          /* Bytes in an Ethernet address. */

/* Header on all OpenFlow packets. */
struct ofp_header {
    uint8_t version;    /* An OpenFlow version number, e.g. OFP10_VERSION. */
    uint8_t type;       /* One of the OFPT_ constants. */
    ovs_be16 length;    /* Length including this ofp_header. */
    ovs_be32 xid;       /* Transaction id associated with this packet.
                           Replies use the same id as was in the request
                           to facilitate pairing. */
};
OFP_ASSERT(sizeof(struct ofp_header) == 8);

/* Common flags to indicate behavior of the physical port.  These flags are
 * used in ofp_port to describe the current configuration.  They are used in
 * the ofp_port_mod message to configure the port's behavior.
 */
enum ofp_port_config {
    OFPPC_PORT_DOWN    = 1 << 0,  /* Port is administratively down. */

    OFPPC_NO_RECV      = 1 << 2,  /* Drop all packets received by port. */
    OFPPC_NO_FWD       = 1 << 5,  /* Drop packets forwarded to port. */
    OFPPC_NO_PACKET_IN = 1 << 6   /* Do not send packet-in msgs for port. */
};

/* Common current state of the physical port.  These are not configurable from
 * the controller.
 */
enum ofp_port_state {
    OFPPS_LINK_DOWN    = 1 << 0,  /* No physical link present. */
};

/* Common features of physical ports available in a datapath. */
enum ofp_port_features {
    OFPPF_10MB_HD    = 1 << 0,  /* 10 Mb half-duplex rate support. */
    OFPPF_10MB_FD    = 1 << 1,  /* 10 Mb full-duplex rate support. */
    OFPPF_100MB_HD   = 1 << 2,  /* 100 Mb half-duplex rate support. */
    OFPPF_100MB_FD   = 1 << 3,  /* 100 Mb full-duplex rate support. */
    OFPPF_1GB_HD     = 1 << 4,  /* 1 Gb half-duplex rate support. */
    OFPPF_1GB_FD     = 1 << 5,  /* 1 Gb full-duplex rate support. */
    OFPPF_10GB_FD    = 1 << 6,  /* 10 Gb full-duplex rate support. */
};

struct ofp_packet_queue {
    ovs_be32 queue_id;          /* id for the specific queue. */
    ovs_be16 len;               /* Length in bytes of this queue desc. */
    uint8_t pad[2];             /* 64-bit alignment. */
    /* struct ofp_queue_prop_header properties[0]; List of properties.  */
};
OFP_ASSERT(sizeof(struct ofp_packet_queue) == 8);

enum ofp_queue_properties {
    OFPQT_NONE = 0,       /* No property defined for queue (default). */
    OFPQT_MIN_RATE,       /* Minimum datarate guaranteed. */
                          /* Other types should be added here
                           * (i.e. max rate, precedence, etc). */
};

/* Common description for a queue. */
struct ofp_queue_prop_header {
    ovs_be16 property; /* One of OFPQT_. */
    ovs_be16 len;      /* Length of property, including this header. */
    uint8_t pad[4];    /* 64-bit alignemnt. */
};
OFP_ASSERT(sizeof(struct ofp_queue_prop_header) == 8);

/* Min-Rate queue property description. */
struct ofp_queue_prop_min_rate {
    struct ofp_queue_prop_header prop_header; /* prop: OFPQT_MIN, len: 16. */
    ovs_be16 rate;        /* In 1/10 of a percent; >1000 -> disabled. */
    uint8_t pad[6];       /* 64-bit alignment */
};
OFP_ASSERT(sizeof(struct ofp_queue_prop_min_rate) == 16);

/* Switch features. */
struct ofp_switch_features {
    ovs_be64 datapath_id;   /* Datapath unique ID.  The lower 48-bits are for
                               a MAC address, while the upper 16-bits are
                               implementer-defined. */

    ovs_be32 n_buffers;     /* Max packets buffered at once. */

    uint8_t n_tables;       /* Number of tables supported by datapath. */
    uint8_t pad[3];         /* Align to 64-bits. */

    /* Features. */
    ovs_be32 capabilities;  /* OFPC_*, OFPC10_*, OFPC11_*, OFPC12_*. */
    ovs_be32 actions;       /* Bitmap of supported "ofp_action_type"s. */

    /* Followed by an array of struct ofp10_phy_port or struct ofp11_port
     * structures.  The number is inferred from header.length. */
};
OFP_ASSERT(sizeof(struct ofp_switch_features) == 24);

/* Common capabilities supported by the datapath (struct ofp_switch_features,
 * member capabilities). */
enum ofp_capabilities {
    OFPC_FLOW_STATS     = 1 << 0,  /* Flow statistics. */
    OFPC_TABLE_STATS    = 1 << 1,  /* Table statistics. */
    OFPC_PORT_STATS     = 1 << 2,  /* Port statistics. */
    OFPC_IP_REASM       = 1 << 5,  /* Can reassemble IP fragments. */
    OFPC_QUEUE_STATS    = 1 << 6,  /* Queue statistics. */
    OFPC_ARP_MATCH_IP   = 1 << 7   /* Match IP addresses in ARP
                                      pkts. */
};

/* Why is this packet being sent to the controller? */
enum ofp_packet_in_reason {
    OFPR_NO_MATCH,          /* No matching flow. */
    OFPR_ACTION,            /* Action explicitly output to controller. */
    OFPR_INVALID_TTL        /* Packet has invalid TTL. */,
    OFPR_N_REASONS
};

enum ofp_flow_mod_command {
    OFPFC_ADD,              /* New flow. */
    OFPFC_MODIFY,           /* Modify all matching flows. */
    OFPFC_MODIFY_STRICT,    /* Modify entry strictly matching wildcards */
    OFPFC_DELETE,           /* Delete all matching flows. */
    OFPFC_DELETE_STRICT     /* Strictly match wildcards and priority. */
};

enum ofp_flow_mod_flags {
    OFPFF_SEND_FLOW_REM = 1 << 0,  /* Send flow removed message when flow
                                    * expires or is deleted. */
    OFPFF_CHECK_OVERLAP = 1 << 1,  /* Check for overlapping entries first. */
};

/* Action structure for OFPAT10_SET_VLAN_VID and OFPAT11_SET_VLAN_VID. */
struct ofp_action_vlan_vid {
    ovs_be16 type;                  /* Type. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be16 vlan_vid;              /* VLAN id. */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp_action_vlan_vid) == 8);

/* Action structure for OFPAT10_SET_VLAN_PCP and OFPAT11_SET_VLAN_PCP. */
struct ofp_action_vlan_pcp {
    ovs_be16 type;                  /* Type. */
    ovs_be16 len;                   /* Length is 8. */
    uint8_t vlan_pcp;               /* VLAN priority. */
    uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct ofp_action_vlan_pcp) == 8);

/* Action structure for OFPAT10_SET_DL_SRC/DST and OFPAT11_SET_DL_SRC/DST. */
struct ofp_action_dl_addr {
    ovs_be16 type;                  /* Type. */
    ovs_be16 len;                   /* Length is 16. */
    uint8_t dl_addr[OFP_ETH_ALEN];  /* Ethernet address. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct ofp_action_dl_addr) == 16);

/* Action structure for OFPAT10_SET_NW_SRC/DST and OFPAT11_SET_NW_SRC/DST. */
struct ofp_action_nw_addr {
    ovs_be16 type;                  /* Type. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be32 nw_addr;               /* IP address. */
};
OFP_ASSERT(sizeof(struct ofp_action_nw_addr) == 8);

/* Action structure for OFPAT10_SET_NW_TOS and OFPAT11_SET_NW_TOS. */
struct ofp_action_nw_tos {
    ovs_be16 type;                  /* Type.. */
    ovs_be16 len;                   /* Length is 8. */
    uint8_t nw_tos;                 /* DSCP in high 6 bits, rest ignored. */
    uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct ofp_action_nw_tos) == 8);

/* Action structure for OFPAT10_SET_TP_SRC/DST and OFPAT11_SET_TP_SRC/DST. */
struct ofp_action_tp_port {
    ovs_be16 type;                  /* Type. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be16 tp_port;               /* TCP/UDP port. */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp_action_tp_port) == 8);

/* Why was this flow removed? */
enum ofp_flow_removed_reason {
    OFPRR_IDLE_TIMEOUT,         /* Flow idle time exceeded idle_timeout. */
    OFPRR_HARD_TIMEOUT,         /* Time exceeded hard_timeout. */
    OFPRR_DELETE,               /* Evicted by a DELETE flow mod. */
    OFPRR_GROUP_DELETE,         /* Group was removed. */
    OFPRR_EVICTION,             /* Switch eviction to free resources. */
};

/* What changed about the physical port */
enum ofp_port_reason {
    OFPPR_ADD,              /* The port was added. */
    OFPPR_DELETE,           /* The port was removed. */
    OFPPR_MODIFY            /* Some attribute of the port has changed. */
};

/* A physical port has changed in the datapath */
struct ofp_port_status {
    uint8_t reason;          /* One of OFPPR_*. */
    uint8_t pad[7];          /* Align to 64-bits. */
    /* Followed by struct ofp10_phy_port or struct ofp11_port.  */
};
OFP_ASSERT(sizeof(struct ofp_port_status) == 8);

#define DESC_STR_LEN   256
#define SERIAL_NUM_LEN 32
/* Body of reply to OFPST_DESC request.  Each entry is a NULL-terminated ASCII
 * string. */
struct ofp_desc_stats {
    char mfr_desc[DESC_STR_LEN];       /* Manufacturer description. */
    char hw_desc[DESC_STR_LEN];        /* Hardware description. */
    char sw_desc[DESC_STR_LEN];        /* Software description. */
    char serial_num[SERIAL_NUM_LEN];   /* Serial number. */
    char dp_desc[DESC_STR_LEN];        /* Human readable description of
                                          the datapath. */
};
OFP_ASSERT(sizeof(struct ofp_desc_stats) == 1056);

/* Reply to OFPST_AGGREGATE request. */
struct ofp_aggregate_stats_reply {
    ovs_32aligned_be64 packet_count; /* Number of packets in flows. */
    ovs_32aligned_be64 byte_count;   /* Number of bytes in flows. */
    ovs_be32 flow_count;      /* Number of flows. */
    uint8_t pad[4];           /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_aggregate_stats_reply) == 24);

/* The match type indicates the match structure (set of fields that compose the
 * match) in use. The match type is placed in the type field at the beginning
 * of all match structures. The "OpenFlow Extensible Match" type corresponds
 * to OXM TLV format described below and must be supported by all OpenFlow
 * switches. Extensions that define other match types may be published on the
 * ONF wiki. Support for extensions is optional.
 */
enum ofp_match_type {
    OFPMT_STANDARD = 0,         /* The match fields defined in the ofp11_match
                                   structure apply */
    OFPMT_OXM = 1,              /* OpenFlow Extensible Match */
};

/* Group numbering. Groups can use any number up to OFPG_MAX. */
enum ofp_group {
    /* Last usable group number. */
    OFPG_MAX        = 0xffffff00,

    /* Fake groups. */
    OFPG_ALL        = 0xfffffffc,  /* All groups, for group delete commands. */
    OFPG_ANY        = 0xffffffff   /* Wildcard, for flow stats requests. */
};

#endif /* openflow/openflow-common.h */
