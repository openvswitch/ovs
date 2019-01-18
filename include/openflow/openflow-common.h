/* Copyright (c) 2008, 2011, 2012, 2013, 2014, 2016 The Board of Trustees of The Leland Stanford
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
 * Copyright (c) 2008-2015 Nicira, Inc.
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

#include <openvswitch/types.h>

#ifdef SWIG
#define OFP_ASSERT(EXPR)        /* SWIG can't handle OFP_ASSERT. */
#elif !defined(__cplusplus)
/* Build-time assertion for use in a declaration context. */
#define OFP_ASSERT(EXPR)                                                \
        extern int (*build_assert(void))[ sizeof(struct {               \
                    unsigned int build_assert_failed : (EXPR) ? 1 : -1; })]
#elif __cplusplus >= 201103L
#define OFP_ASSERT(EXPR) static_assert(EXPR, "assertion failed")
#else  /* __cplusplus < 201103L */
#include <boost/static_assert.hpp>
#define OFP_ASSERT BOOST_STATIC_ASSERT
#endif /* __cplusplus < 201103L */

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
    OFP13_VERSION = 0x04,
    OFP14_VERSION = 0x05,
    OFP15_VERSION = 0x06
};

/* Vendor (aka experimenter) IDs.
 *
 * These are used in various places in OpenFlow to identify an extension
 * defined by some vendor, as opposed to a standardized part of the core
 * OpenFlow protocol.
 *
 * Vendor IDs whose top 8 bits are 0 hold an Ethernet OUI in their low 24 bits.
 * The Open Networking Foundation assigns vendor IDs whose top 8 bits are
 * nonzero.
 *
 * A few vendor IDs are special:
 *
 *    - OF_VENDOR_ID is not a real vendor ID and does not appear in the
 *      OpenFlow protocol itself.  It can occasionally be useful within Open
 *      vSwitch to identify a standardized part of OpenFlow.
 *
 *    - ONF_VENDOR_ID is being used within the ONF "extensibility" working
 *      group to identify extensions being proposed for standardization.
 *
 * The list is sorted numerically.
 */
#define OF_VENDOR_ID    0
#define HPL_VENDOR_ID   0x000004EA /* HP Labs. */
#define NTR_VENDOR_ID   0x0000154d /* Netronome. */
#define NTR_COMPAT_VENDOR_ID   0x00001540 /* Incorrect value used in v2.4. */
#define NX_VENDOR_ID    0x00002320 /* Nicira. */
#define ONF_VENDOR_ID   0x4f4e4600 /* Open Networking Foundation. */
#define INTEL_VENDOR_ID 0x0000AA01 /* Intel */

#define OFP_MAX_TABLE_NAME_LEN 32
#define OFP_MAX_PORT_NAME_LEN  16

#define OFP_OLD_PORT  6633
#define OFP_PORT  6653

#define OFP_DEFAULT_MISS_SEND_LEN   128

/* Values below this cutoff are 802.3 packets and the two bytes
 * following MAC addresses are used as a frame length.  Otherwise, the
 * two bytes are used as the Ethernet type.
 */
#define OFP_DL_TYPE_ETH2_CUTOFF   0x0600

/* Value of dl_type to indicate that the frame does not include an
 * Ethernet type.
 */
#define OFP_DL_TYPE_NOT_ETH_TYPE  0x05ff

/* Value used in "idle_timeout" and "hard_timeout" to indicate that the entry
 * is permanent. */
#define OFP_FLOW_PERMANENT 0

/* By default, choose a priority in the middle. */
#define OFP_DEFAULT_PRIORITY 0x8000


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

/* OFPT_ERROR: Error message (datapath -> controller). */
struct ofp_error_msg {
    ovs_be16 type;
    ovs_be16 code;
    uint8_t data[0];          /* Variable-length data.  Interpreted based
                                 on the type and code. */
};
OFP_ASSERT(sizeof(struct ofp_error_msg) == 4);

enum ofp_config_flags {
    /* Handling of IP fragments. */
    OFPC_FRAG_NORMAL   = 0,  /* No special handling for fragments. */
    OFPC_FRAG_DROP     = 1,  /* Drop fragments. */
    OFPC_FRAG_REASM    = 2,  /* Reassemble (only if OFPC_IP_REASM set). */
    OFPC_FRAG_NX_MATCH = 3,  /* Make first fragments available for matching. */
    OFPC_FRAG_MASK     = 3,

    /* OFPC_INVALID_TTL_TO_CONTROLLER is deprecated in OpenFlow 1.3 */

    /* TTL processing - applicable for IP and MPLS packets. */
    OFPC_INVALID_TTL_TO_CONTROLLER = 1 << 2, /* Send packets with invalid TTL
                                                to the controller. */
};

/* Switch configuration. */
struct ofp_switch_config {
    ovs_be16 flags;             /* OFPC_* flags. */
    ovs_be16 miss_send_len;     /* Max bytes of new flow that datapath should
                                   send to the controller. */
};
OFP_ASSERT(sizeof(struct ofp_switch_config) == 4);


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

/* Generic OpenFlow property header, as used by various messages in OF1.3+, and
 * especially in OF1.4.
 *
 * The OpenFlow specs prefer to define a new structure with a specialized name
 * each time this property structure comes up: struct
 * ofp_port_desc_prop_header, struct ofp_controller_status_prop_header, struct
 * ofp_table_mod_prop_header, and more.  They're all the same, so it's easier
 * to unify them.
 */
struct ofp_prop_header {
    ovs_be16 type;
    ovs_be16 len;
    /* Followed by:
     *     - 'len - 4' bytes of payload.
     *     - PAD_SIZE(len, 8) bytes of zeros. */
};
OFP_ASSERT(sizeof(struct ofp_prop_header) == 4);

/* Generic OpenFlow experimenter property header.
 *
 * Again the OpenFlow specs define this over and over again and it's easier to
 * unify them. */
struct ofp_prop_experimenter {
    ovs_be16 type;          /* Generally 0xffff (in one case 0xfffe). */
    ovs_be16 len;           /* Length in bytes of this property. */
    ovs_be32 experimenter;  /* Experimenter ID which takes the same form as
                             * in struct ofp_experimenter_header. */
    ovs_be32 exp_type;      /* Experimenter defined. */
    /* Followed by:
     *     - 'len - 12' bytes of payload.
     *     - PAD_SIZE(len, 8) bytes of zeros. */
};
OFP_ASSERT(sizeof(struct ofp_prop_experimenter) == 12);

/* Switch features. */
struct ofp_switch_features {
    ovs_be64 datapath_id;   /* Datapath unique ID.  The lower 48-bits are for
                               a MAC address, while the upper 16-bits are
                               implementer-defined. */

    ovs_be32 n_buffers;     /* Max packets buffered at once. */

    uint8_t n_tables;       /* Number of tables supported by datapath. */
    uint8_t auxiliary_id;   /* OF 1.3: Identify auxiliary connections */
    uint8_t pad[2];         /* Align to 64-bits. */

    /* Features. */
    ovs_be32 capabilities;  /* OFPC_*, OFPC10_*, OFPC11_*, OFPC12_*. */
    ovs_be32 actions;       /* Bitmap of supported "ofp_action_type"s.
                             * DEPRECATED in OpenFlow 1.1 */

    /* Followed by an array of struct ofp10_phy_port or struct ofp11_port
     * structures.  The number is inferred from header.length.
     * REMOVED in OpenFlow 1.3 */
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
    /* Standard reasons. */
    OFPR_NO_MATCH,          /* No matching flow. */
    OFPR_ACTION,            /* Action explicitly output to controller. */
    OFPR_INVALID_TTL,       /* Packet has invalid TTL. */
    OFPR_ACTION_SET,        /* Output to controller in action set */
    OFPR_GROUP,             /* Output to controller in group bucket */
    OFPR_PACKET_OUT,        /* Output to controller in packet-out */

#define OFPR10_BITS                                                     \
    ((1u << OFPR_NO_MATCH) | (1u << OFPR_ACTION) | (1u << OFPR_INVALID_TTL))

/* From OF1.4+, OFPR_ACTION is split into four more descriptive reasons,
 * OFPR_APPLY_ACTION, OFPR_ACTION_SET, OFPR_GROUP, and OFPR_PACKET_OUT.
 * OFPR_APPLY_ACTION shares the same number as OFPR_ACTION. */
#define OFPR14_ACTION_BITS                                              \
    ((1u << OFPR_ACTION_SET) | (1u << OFPR_GROUP) | (1u << OFPR_PACKET_OUT))
#define OFPR14_BITS                                                     \
    (OFPR10_BITS | OFPR14_ACTION_BITS)

    /* Nonstandard reason--not exposed via OpenFlow. */
    OFPR_EXPLICIT_MISS,
    OFPR_IMPLICIT_MISS,

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

/* Why was this flow removed? */
enum ofp_flow_removed_reason {
    OFPRR_IDLE_TIMEOUT,         /* Flow idle time exceeded idle_timeout. */
    OFPRR_HARD_TIMEOUT,         /* Time exceeded hard_timeout. */
    OFPRR_DELETE,               /* Evicted by a DELETE flow mod. */
    OFPRR_GROUP_DELETE,         /* Group was removed. */
    OFPRR_METER_DELETE,         /* Meter was removed. */
    OFPRR_EVICTION,             /* Switch eviction to free resources. */

#define OFPRR10_BITS                            \
    ((1u << OFPRR_IDLE_TIMEOUT) |               \
     (1u << OFPRR_HARD_TIMEOUT) |               \
     (1u << OFPRR_DELETE))
#define OFPRR13_BITS                            \
    (OFPRR10_BITS |                             \
     (1u << OFPRR_GROUP_DELETE))
#define OFPRR14_BITS                            \
    (OFPRR13_BITS |                             \
     (1u << OFPRR_METER_DELETE) |               \
     (1u << OFPRR_EVICTION))

    OVS_OFPRR_NONE              /* OVS internal_use only, keep last!. */
};

/* What changed about the physical port */
enum ofp_port_reason {
    OFPPR_ADD,              /* The port was added. */
    OFPPR_DELETE,           /* The port was removed. */
    OFPPR_MODIFY,           /* Some attribute of the port has changed. */

#define OFPPR_BITS ((1u << OFPPR_ADD) |         \
                    (1u << OFPPR_DELETE) |      \
                    (1u << OFPPR_MODIFY))

    OFPPR_N_REASONS         /* Denotes number of reasons. */
};

/* A physical port has changed in the datapath */
struct ofp_port_status {
    uint8_t reason;          /* One of OFPPR_*. */
    uint8_t pad[7];          /* Align to 64-bits. */
    /* Followed by struct ofp10_phy_port, struct ofp11_port, or struct
     * ofp14_port.  */
};
OFP_ASSERT(sizeof(struct ofp_port_status) == 8);

enum ofp_stats_reply_flags {
    OFPSF_REPLY_MORE  = 1 << 0  /* More replies to follow. */
};

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

/* Group configuration flags */
enum ofp_group_capabilities {
    OFPGFC_SELECT_WEIGHT   = 1 << 0, /* Support weight for select groups */
    OFPGFC_SELECT_LIVENESS = 1 << 1, /* Support liveness for select groups */
    OFPGFC_CHAINING        = 1 << 2, /* Support chaining groups */
    OFPGFC_CHAINING_CHECKS = 1 << 3, /* Check chaining for loops and delete */
};

enum ofp_hello_elem_type {
    OFPHET_VERSIONBITMAP          = 1, /* Bitmap of version supported. */
};

/* Common header for all Hello Elements */
struct ofp_hello_elem_header {
    ovs_be16    type;        /* One of OFPHET_*. */
    ovs_be16    length;      /* Length in bytes of this element. */
};
OFP_ASSERT(sizeof(struct ofp_hello_elem_header) == 4);

/* Table numbering. Tables can use any number up to OFPT_MAX. */
enum ofp_table {
    /* Last usable table number. */
    OFPTT_MAX = 0xfe,

    /* Fake tables. */
    OFPTT_ALL = 0xff         /* Wildcard table used for table config,
                                flow stats and flow deletes. */
};

enum ofp_table_config {
    /* OpenFlow 1.1 and 1.2 defined this field as shown.
     * OpenFlow 1.3 and later mark this field as deprecated, but have not
     * reused it for any new purpose. */
    OFPTC11_TABLE_MISS_CONTROLLER = 0 << 0, /* Send to controller. */
    OFPTC11_TABLE_MISS_CONTINUE   = 1 << 0, /* Go to next table, like OF1.0. */
    OFPTC11_TABLE_MISS_DROP       = 2 << 0, /* Drop the packet. */
    OFPTC11_TABLE_MISS_MASK       = 3 << 0,

    /* OpenFlow 1.4. */
    OFPTC14_EVICTION              = 1 << 2, /* Allow table to evict flows. */
    OFPTC14_VACANCY_EVENTS        = 1 << 3, /* Enable vacancy events. */
};

/* Header and packet type name spaces. */
enum ofp_header_type_namespaces {
    OFPHTN_ONF = 0,             /* ONF namespace. */
    OFPHTN_ETHERTYPE = 1,       /* ns_type is an Ethertype. */
    OFPHTN_IP_PROTO = 2,        /* ns_type is a IP protocol number. */
    OFPHTN_UDP_TCP_PORT = 3,    /* ns_type is a TCP or UDP port. */
    OFPHTN_IPV4_OPTION = 4,     /* ns_type is an IPv4 option number. */
    OFPHTN_N_TYPES
};

#endif /* openflow/openflow-common.h */
