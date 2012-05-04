/* Copyright (c) 2008, 2011 The Board of Trustees of The Leland Stanford
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
#define OFP10_VERSION   0x01
#define OFP11_VERSION   0x02
#define OFP12_VERSION   0x03

#define OFP_MAX_TABLE_NAME_LEN 32
#define OFP_MAX_PORT_NAME_LEN  16

#define OFP_TCP_PORT  6633
#define OFP_SSL_PORT  6633

#define OFP_ETH_ALEN 6          /* Bytes in an Ethernet address. */

/* Common OpenFlow message types. */
enum ofp_type {
    /* Immutable messages. */
    OFPT_HELLO,               /* Symmetric message */
    OFPT_ERROR,               /* Symmetric message */
    OFPT_ECHO_REQUEST,        /* Symmetric message */
    OFPT_ECHO_REPLY,          /* Symmetric message */
    OFPT_VENDOR,              /* Symmetric message */

    /* Switch configuration messages. */
    OFPT_FEATURES_REQUEST,    /* Controller/switch message */
    OFPT_FEATURES_REPLY,      /* Controller/switch message */
    OFPT_GET_CONFIG_REQUEST,  /* Controller/switch message */
    OFPT_GET_CONFIG_REPLY,    /* Controller/switch message */
    OFPT_SET_CONFIG,          /* Controller/switch message */

    /* Asynchronous messages. */
    OFPT_PACKET_IN,           /* Async message */
    OFPT_FLOW_REMOVED,        /* Async message */
    OFPT_PORT_STATUS,         /* Async message */
};

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
    struct ofp_header header;
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
OFP_ASSERT(sizeof(struct ofp_switch_features) == 32);

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

/* Why was this flow removed? */
enum ofp_flow_removed_reason {
    OFPRR_IDLE_TIMEOUT,         /* Flow idle time exceeded idle_timeout. */
    OFPRR_HARD_TIMEOUT,         /* Time exceeded hard_timeout. */
    OFPRR_DELETE,               /* Evicted by a DELETE flow mod. */
    OFPRR_GROUP_DELETE          /* Group was removed. */
};

/* What changed about the physical port */
enum ofp_port_reason {
    OFPPR_ADD,              /* The port was added. */
    OFPPR_DELETE,           /* The port was removed. */
    OFPPR_MODIFY            /* Some attribute of the port has changed. */
};

/* A physical port has changed in the datapath */
struct ofp_port_status {
    struct ofp_header header;
    uint8_t reason;          /* One of OFPPR_*. */
    uint8_t pad[7];          /* Align to 64-bits. */
    /* Followed by struct ofp10_phy_port or struct ofp11_port.  */
};
OFP_ASSERT(sizeof(struct ofp_port_status) == 16);

enum ofp_stats_types {
    /* Description of this OpenFlow switch. (OFPMP_DESC)
     * The OF1.0 request is struct ofp_stats_msg.
     * The OF1.0 reply is struct ofp_desc_stats. */
    OFPST_DESC = 0,

    /* Individual flow statistics. (OFPMP_FLOW)
     * The OF1.0 request is struct ofp_flow_stats_request.
     * The OF1.0 reply body is an array of struct ofp_flow_stats. */
    OFPST_FLOW = 1,

    /* Aggregate flow statistics. (OFPMP_AGGREGATE)
     * The OF1.0 request is struct ofp_flow_stats_request.
     * The OF1.0 reply is struct ofp_aggregate_stats_reply. */
    OFPST_AGGREGATE = 2,

    /* Flow table statistics. (OFPMP_TABLE)
     * The OF1.0 request is struct ofp_stats_msg.
     * The OF1.0 reply body is an array of struct ofp_table_stats. */
    OFPST_TABLE = 3,

    /* Physical port statistics. (OFPMP_PORT_STATS)
     * The OF1.0 request is struct ofp_port_stats_request.
     * The OF1.0 reply body is an array of struct ofp_port_stats. */
    OFPST_PORT = 4,

    /* Queue statistics for a port. (OFPMP_QUEUE)
     * The OF1.0 request is struct ofp_stats_msg.
     * The OF1.0 reply body is an array of struct ofp_queue_stats. */
    OFPST_QUEUE = 5,

    /* Port description. (OFPMP_PORT_DESC)
     * This was introduced as part of OF1.3, but is useful for bridges
     * with many ports, so we support it with OF1.0, too.
     * The OF1.0 request is struct ofp_stats_msg.
     * The OF1.0 reply body is an array of struct ofp10_phy_port. */
    OFPST_PORT_DESC = 13,

    /* Vendor extension.
     * The OF1.0 request and reply begin with struct ofp_vendor_stats. */
    OFPST_VENDOR = 0xffff
};

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

#endif /* openflow/openflow-common.h */
