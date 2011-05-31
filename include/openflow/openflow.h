/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

#ifndef OPENFLOW_OPENFLOW_H
#define OPENFLOW_OPENFLOW_H 1

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
 * Non-experimental versions released: 0x01
 * Experimental versions released: 0x81 -- 0x99
 */
/* The most significant bit being set in the version field indicates an
 * experimental OpenFlow version.
 */
#define OFP_VERSION   0x01

#define OFP_MAX_TABLE_NAME_LEN 32
#define OFP_MAX_PORT_NAME_LEN  16

#define OFP_TCP_PORT  6633
#define OFP_SSL_PORT  6633

#define OFP_ETH_ALEN 6          /* Bytes in an Ethernet address. */

/* Port numbering.  Physical ports are numbered starting from 1. */
enum ofp_port {
    /* Maximum number of physical switch ports. */
    OFPP_MAX = 0xff00,

    /* Fake output "ports". */
    OFPP_IN_PORT    = 0xfff8,  /* Send the packet out the input port.  This
                                  virtual port must be explicitly used
                                  in order to send back out of the input
                                  port. */
    OFPP_TABLE      = 0xfff9,  /* Perform actions in flow table.
                                  NB: This can only be the destination
                                  port for packet-out messages. */
    OFPP_NORMAL     = 0xfffa,  /* Process with normal L2/L3 switching. */
    OFPP_FLOOD      = 0xfffb,  /* All physical ports except input port and
                                  those disabled by STP. */
    OFPP_ALL        = 0xfffc,  /* All physical ports except input port. */
    OFPP_CONTROLLER = 0xfffd,  /* Send to controller. */
    OFPP_LOCAL      = 0xfffe,  /* Local openflow "port". */
    OFPP_NONE       = 0xffff   /* Not associated with a physical port. */
};

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

    /* Controller command messages. */
    OFPT_PACKET_OUT,          /* Controller/switch message */
    OFPT_FLOW_MOD,            /* Controller/switch message */
    OFPT_PORT_MOD,            /* Controller/switch message */

    /* Statistics messages. */
    OFPT_STATS_REQUEST,       /* Controller/switch message */
    OFPT_STATS_REPLY,         /* Controller/switch message */

    /* Barrier messages. */
    OFPT_BARRIER_REQUEST,     /* Controller/switch message */
    OFPT_BARRIER_REPLY,       /* Controller/switch message */

    /* Queue Configuration messages. */
    OFPT_QUEUE_GET_CONFIG_REQUEST,  /* Controller/switch message */
    OFPT_QUEUE_GET_CONFIG_REPLY     /* Controller/switch message */
};

/* Header on all OpenFlow packets. */
struct ofp_header {
    uint8_t version;    /* OFP_VERSION. */
    uint8_t type;       /* One of the OFPT_ constants. */
    ovs_be16 length;    /* Length including this ofp_header. */
    ovs_be32 xid;       /* Transaction id associated with this packet.
                           Replies use the same id as was in the request
                           to facilitate pairing. */
};
OFP_ASSERT(sizeof(struct ofp_header) == 8);

/* OFPT_HELLO.  This message has an empty body, but implementations must
 * ignore any data included in the body, to allow for future extensions. */
struct ofp_hello {
    struct ofp_header header;
};

#define OFP_DEFAULT_MISS_SEND_LEN   128

enum ofp_config_flags {
    /* Handling of IP fragments. */
    OFPC_FRAG_NORMAL   = 0,  /* No special handling for fragments. */
    OFPC_FRAG_DROP     = 1,  /* Drop fragments. */
    OFPC_FRAG_REASM    = 2,  /* Reassemble (only if OFPC_IP_REASM set). */
    OFPC_FRAG_MASK     = 3
};

/* Switch configuration. */
struct ofp_switch_config {
    struct ofp_header header;
    ovs_be16 flags;             /* OFPC_* flags. */
    ovs_be16 miss_send_len;     /* Max bytes of new flow that datapath should
                                   send to the controller. */
};
OFP_ASSERT(sizeof(struct ofp_switch_config) == 12);

/* Capabilities supported by the datapath. */
enum ofp_capabilities {
    OFPC_FLOW_STATS     = 1 << 0,  /* Flow statistics. */
    OFPC_TABLE_STATS    = 1 << 1,  /* Table statistics. */
    OFPC_PORT_STATS     = 1 << 2,  /* Port statistics. */
    OFPC_STP            = 1 << 3,  /* 802.1d spanning tree. */
    OFPC_RESERVED       = 1 << 4,  /* Reserved, must not be set. */
    OFPC_IP_REASM       = 1 << 5,  /* Can reassemble IP fragments. */
    OFPC_QUEUE_STATS    = 1 << 6,  /* Queue statistics. */
    OFPC_ARP_MATCH_IP   = 1 << 7   /* Match IP addresses in ARP
                                      pkts. */
};

/* Flags to indicate behavior of the physical port.  These flags are
 * used in ofp_phy_port to describe the current configuration.  They are
 * used in the ofp_port_mod message to configure the port's behavior.
 */
enum ofp_port_config {
    OFPPC_PORT_DOWN    = 1 << 0,  /* Port is administratively down. */

    OFPPC_NO_STP       = 1 << 1,  /* Disable 802.1D spanning tree on port. */
    OFPPC_NO_RECV      = 1 << 2,  /* Drop all packets except 802.1D
                                     spanning tree packets. */
    OFPPC_NO_RECV_STP  = 1 << 3,  /* Drop received 802.1D STP packets. */
    OFPPC_NO_FLOOD     = 1 << 4,  /* Do not include this port when flooding. */
    OFPPC_NO_FWD       = 1 << 5,  /* Drop packets forwarded to port. */
    OFPPC_NO_PACKET_IN = 1 << 6   /* Do not send packet-in msgs for port. */
};

/* Current state of the physical port.  These are not configurable from
 * the controller.
 */
enum ofp_port_state {
    OFPPS_LINK_DOWN   = 1 << 0, /* No physical link present. */

    /* The OFPPS_STP_* bits have no effect on switch operation.  The
     * controller must adjust OFPPC_NO_RECV, OFPPC_NO_FWD, and
     * OFPPC_NO_PACKET_IN appropriately to fully implement an 802.1D spanning
     * tree. */
    OFPPS_STP_LISTEN  = 0 << 8, /* Not learning or relaying frames. */
    OFPPS_STP_LEARN   = 1 << 8, /* Learning but not relaying frames. */
    OFPPS_STP_FORWARD = 2 << 8, /* Learning and relaying frames. */
    OFPPS_STP_BLOCK   = 3 << 8, /* Not part of spanning tree. */
    OFPPS_STP_MASK    = 3 << 8  /* Bit mask for OFPPS_STP_* values. */
};

/* Features of physical ports available in a datapath. */
enum ofp_port_features {
    OFPPF_10MB_HD    = 1 << 0,  /* 10 Mb half-duplex rate support. */
    OFPPF_10MB_FD    = 1 << 1,  /* 10 Mb full-duplex rate support. */
    OFPPF_100MB_HD   = 1 << 2,  /* 100 Mb half-duplex rate support. */
    OFPPF_100MB_FD   = 1 << 3,  /* 100 Mb full-duplex rate support. */
    OFPPF_1GB_HD     = 1 << 4,  /* 1 Gb half-duplex rate support. */
    OFPPF_1GB_FD     = 1 << 5,  /* 1 Gb full-duplex rate support. */
    OFPPF_10GB_FD    = 1 << 6,  /* 10 Gb full-duplex rate support. */
    OFPPF_COPPER     = 1 << 7,  /* Copper medium. */
    OFPPF_FIBER      = 1 << 8,  /* Fiber medium. */
    OFPPF_AUTONEG    = 1 << 9,  /* Auto-negotiation. */
    OFPPF_PAUSE      = 1 << 10, /* Pause. */
    OFPPF_PAUSE_ASYM = 1 << 11  /* Asymmetric pause. */
};

/* Description of a physical port */
struct ofp_phy_port {
    ovs_be16 port_no;
    uint8_t hw_addr[OFP_ETH_ALEN];
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */

    ovs_be32 config;        /* Bitmap of OFPPC_* flags. */
    ovs_be32 state;         /* Bitmap of OFPPS_* flags. */

    /* Bitmaps of OFPPF_* that describe features.  All bits zeroed if
     * unsupported or unavailable. */
    ovs_be32 curr;          /* Current features. */
    ovs_be32 advertised;    /* Features being advertised by the port. */
    ovs_be32 supported;     /* Features supported by the port. */
    ovs_be32 peer;          /* Features advertised by peer. */
};
OFP_ASSERT(sizeof(struct ofp_phy_port) == 48);

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
    ovs_be32 capabilities;  /* Bitmap of support "ofp_capabilities". */
    ovs_be32 actions;       /* Bitmap of supported "ofp_action_type"s. */

    /* Port info.*/
    struct ofp_phy_port ports[0];  /* Port definitions.  The number of ports
                                      is inferred from the length field in
                                      the header. */
};
OFP_ASSERT(sizeof(struct ofp_switch_features) == 32);

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
    struct ofp_phy_port desc;
};
OFP_ASSERT(sizeof(struct ofp_port_status) == 64);

/* Modify behavior of the physical port */
struct ofp_port_mod {
    struct ofp_header header;
    ovs_be16 port_no;
    uint8_t hw_addr[OFP_ETH_ALEN]; /* The hardware address is not
                                      configurable.  This is used to
                                      sanity-check the request, so it must
                                      be the same as returned in an
                                      ofp_phy_port struct. */

    ovs_be32 config;        /* Bitmap of OFPPC_* flags. */
    ovs_be32 mask;          /* Bitmap of OFPPC_* flags to be changed. */

    ovs_be32 advertise;     /* Bitmap of "ofp_port_features"s.  Zero all
                               bits to prevent any action taking place. */
    uint8_t pad[4];         /* Pad to 64-bits. */
};
OFP_ASSERT(sizeof(struct ofp_port_mod) == 32);

/* Why is this packet being sent to the controller? */
enum ofp_packet_in_reason {
    OFPR_NO_MATCH,          /* No matching flow. */
    OFPR_ACTION             /* Action explicitly output to controller. */
};

/* Packet received on port (datapath -> controller). */
struct ofp_packet_in {
    struct ofp_header header;
    ovs_be32 buffer_id;     /* ID assigned by datapath. */
    ovs_be16 total_len;     /* Full length of frame. */
    ovs_be16 in_port;       /* Port on which frame was received. */
    uint8_t reason;         /* Reason packet is being sent (one of OFPR_*) */
    uint8_t pad;
    uint8_t data[0];        /* Ethernet frame, halfway through 32-bit word,
                               so the IP header is 32-bit aligned.  The
                               amount of data is inferred from the length
                               field in the header.  Because of padding,
                               offsetof(struct ofp_packet_in, data) ==
                               sizeof(struct ofp_packet_in) - 2. */
};
OFP_ASSERT(sizeof(struct ofp_packet_in) == 20);

enum ofp_action_type {
    OFPAT_OUTPUT,           /* Output to switch port. */
    OFPAT_SET_VLAN_VID,     /* Set the 802.1q VLAN id. */
    OFPAT_SET_VLAN_PCP,     /* Set the 802.1q priority. */
    OFPAT_STRIP_VLAN,       /* Strip the 802.1q header. */
    OFPAT_SET_DL_SRC,       /* Ethernet source address. */
    OFPAT_SET_DL_DST,       /* Ethernet destination address. */
    OFPAT_SET_NW_SRC,       /* IP source address. */
    OFPAT_SET_NW_DST,       /* IP destination address. */
    OFPAT_SET_NW_TOS,       /* IP ToS (DSCP field, 6 bits). */
    OFPAT_SET_TP_SRC,       /* TCP/UDP source port. */
    OFPAT_SET_TP_DST,       /* TCP/UDP destination port. */
    OFPAT_ENQUEUE,          /* Output to queue. */
    OFPAT_VENDOR = 0xffff
};

/* Action structure for OFPAT_OUTPUT, which sends packets out 'port'.
 * When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
 * number of bytes to send.  A 'max_len' of zero means no bytes of the
 * packet should be sent. */
struct ofp_action_output {
    ovs_be16 type;                  /* OFPAT_OUTPUT. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be16 port;                  /* Output port. */
    ovs_be16 max_len;               /* Max length to send to controller. */
};
OFP_ASSERT(sizeof(struct ofp_action_output) == 8);

/* The VLAN id is 12 bits, so we can use the entire 16 bits to indicate
 * special conditions.  All ones is used to match that no VLAN id was
 * set. */
#define OFP_VLAN_NONE      0xffff

/* Action structure for OFPAT_SET_VLAN_VID. */
struct ofp_action_vlan_vid {
    ovs_be16 type;                  /* OFPAT_SET_VLAN_VID. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be16 vlan_vid;              /* VLAN id. */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp_action_vlan_vid) == 8);

/* Action structure for OFPAT_SET_VLAN_PCP. */
struct ofp_action_vlan_pcp {
    ovs_be16 type;                  /* OFPAT_SET_VLAN_PCP. */
    ovs_be16 len;                   /* Length is 8. */
    uint8_t vlan_pcp;               /* VLAN priority. */
    uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct ofp_action_vlan_pcp) == 8);

/* Action structure for OFPAT_SET_DL_SRC/DST. */
struct ofp_action_dl_addr {
    ovs_be16 type;                  /* OFPAT_SET_DL_SRC/DST. */
    ovs_be16 len;                   /* Length is 16. */
    uint8_t dl_addr[OFP_ETH_ALEN];  /* Ethernet address. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct ofp_action_dl_addr) == 16);

/* Action structure for OFPAT_SET_NW_SRC/DST. */
struct ofp_action_nw_addr {
    ovs_be16 type;                  /* OFPAT_SET_TW_SRC/DST. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be32 nw_addr;               /* IP address. */
};
OFP_ASSERT(sizeof(struct ofp_action_nw_addr) == 8);

/* Action structure for OFPAT_SET_NW_TOS. */
struct ofp_action_nw_tos {
    ovs_be16 type;                  /* OFPAT_SET_TW_TOS. */
    ovs_be16 len;                   /* Length is 8. */
    uint8_t nw_tos;                 /* IP TOS (DSCP field, 6 bits). */
    uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct ofp_action_nw_tos) == 8);

/* Action structure for OFPAT_SET_TP_SRC/DST. */
struct ofp_action_tp_port {
    ovs_be16 type;                  /* OFPAT_SET_TP_SRC/DST. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be16 tp_port;               /* TCP/UDP port. */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp_action_tp_port) == 8);

/* Action header for OFPAT_VENDOR. The rest of the body is vendor-defined. */
struct ofp_action_vendor_header {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is a multiple of 8. */
    ovs_be32 vendor;                /* Vendor ID, which takes the same form
                                       as in "struct ofp_vendor_header". */
};
OFP_ASSERT(sizeof(struct ofp_action_vendor_header) == 8);

/* Action header that is common to all actions.  The length includes the
 * header and any padding used to make the action 64-bit aligned.
 * NB: The length of an action *must* always be a multiple of eight. */
struct ofp_action_header {
    ovs_be16 type;                  /* One of OFPAT_*. */
    ovs_be16 len;                   /* Length of action, including this
                                       header.  This is the length of action,
                                       including any padding to make it
                                       64-bit aligned. */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_action_header) == 8);

/* OFPAT_ENQUEUE action struct: send packets to given queue on port. */
struct ofp_action_enqueue {
    ovs_be16 type;            /* OFPAT_ENQUEUE. */
    ovs_be16 len;             /* Len is 16. */
    ovs_be16 port;            /* Port that queue belongs. Should
                                 refer to a valid physical port
                                 (i.e. < OFPP_MAX) or OFPP_IN_PORT. */
    uint8_t pad[6];           /* Pad for 64-bit alignment. */
    ovs_be32 queue_id;        /* Where to enqueue the packets. */
};
OFP_ASSERT(sizeof(struct ofp_action_enqueue) == 16);

union ofp_action {
    ovs_be16 type;
    struct ofp_action_header header;
    struct ofp_action_vendor_header vendor;
    struct ofp_action_output output;
    struct ofp_action_vlan_vid vlan_vid;
    struct ofp_action_vlan_pcp vlan_pcp;
    struct ofp_action_nw_addr nw_addr;
    struct ofp_action_nw_tos nw_tos;
    struct ofp_action_tp_port tp_port;
};
OFP_ASSERT(sizeof(union ofp_action) == 8);

/* Send packet (controller -> datapath). */
struct ofp_packet_out {
    struct ofp_header header;
    ovs_be32 buffer_id;           /* ID assigned by datapath (-1 if none). */
    ovs_be16 in_port;             /* Packet's input port (OFPP_NONE if none). */
    ovs_be16 actions_len;         /* Size of action array in bytes. */
    struct ofp_action_header actions[0]; /* Actions. */
    /* uint8_t data[0]; */        /* Packet data.  The length is inferred
                                     from the length field in the header.
                                     (Only meaningful if buffer_id == -1.) */
};
OFP_ASSERT(sizeof(struct ofp_packet_out) == 16);

enum ofp_flow_mod_command {
    OFPFC_ADD,              /* New flow. */
    OFPFC_MODIFY,           /* Modify all matching flows. */
    OFPFC_MODIFY_STRICT,    /* Modify entry strictly matching wildcards */
    OFPFC_DELETE,           /* Delete all matching flows. */
    OFPFC_DELETE_STRICT     /* Strictly match wildcards and priority. */
};

/* Flow wildcards. */
enum ofp_flow_wildcards {
    OFPFW_IN_PORT    = 1 << 0,  /* Switch input port. */
    OFPFW_DL_VLAN    = 1 << 1,  /* VLAN vid. */
    OFPFW_DL_SRC     = 1 << 2,  /* Ethernet source address. */
    OFPFW_DL_DST     = 1 << 3,  /* Ethernet destination address. */
    OFPFW_DL_TYPE    = 1 << 4,  /* Ethernet frame type. */
    OFPFW_NW_PROTO   = 1 << 5,  /* IP protocol. */
    OFPFW_TP_SRC     = 1 << 6,  /* TCP/UDP source port. */
    OFPFW_TP_DST     = 1 << 7,  /* TCP/UDP destination port. */

    /* IP source address wildcard bit count.  0 is exact match, 1 ignores the
     * LSB, 2 ignores the 2 least-significant bits, ..., 32 and higher wildcard
     * the entire field.  This is the *opposite* of the usual convention where
     * e.g. /24 indicates that 8 bits (not 24 bits) are wildcarded. */
    OFPFW_NW_SRC_SHIFT = 8,
    OFPFW_NW_SRC_BITS = 6,
    OFPFW_NW_SRC_MASK = ((1 << OFPFW_NW_SRC_BITS) - 1) << OFPFW_NW_SRC_SHIFT,
    OFPFW_NW_SRC_ALL = 32 << OFPFW_NW_SRC_SHIFT,

    /* IP destination address wildcard bit count.  Same format as source. */
    OFPFW_NW_DST_SHIFT = 14,
    OFPFW_NW_DST_BITS = 6,
    OFPFW_NW_DST_MASK = ((1 << OFPFW_NW_DST_BITS) - 1) << OFPFW_NW_DST_SHIFT,
    OFPFW_NW_DST_ALL = 32 << OFPFW_NW_DST_SHIFT,

    OFPFW_DL_VLAN_PCP = 1 << 20, /* VLAN priority. */
    OFPFW_NW_TOS = 1 << 21, /* IP ToS (DSCP field, 6 bits). */

    /* Wildcard all fields. */
    OFPFW_ALL = ((1 << 22) - 1)
};

/* The wildcards for ICMP type and code fields use the transport source
 * and destination port fields, respectively. */
#define OFPFW_ICMP_TYPE OFPFW_TP_SRC
#define OFPFW_ICMP_CODE OFPFW_TP_DST

/* Values below this cutoff are 802.3 packets and the two bytes
 * following MAC addresses are used as a frame length.  Otherwise, the
 * two bytes are used as the Ethernet type.
 */
#define OFP_DL_TYPE_ETH2_CUTOFF   0x0600

/* Value of dl_type to indicate that the frame does not include an
 * Ethernet type.
 */
#define OFP_DL_TYPE_NOT_ETH_TYPE  0x05ff

/* The VLAN id is 12-bits, so we can use the entire 16 bits to indicate
 * special conditions.  All ones indicates that no VLAN id was set.
 */
#define OFP_VLAN_NONE      0xffff

/* Fields to match against flows */
struct ofp_match {
    ovs_be32 wildcards;        /* Wildcard fields. */
    ovs_be16 in_port;          /* Input switch port. */
    uint8_t dl_src[OFP_ETH_ALEN]; /* Ethernet source address. */
    uint8_t dl_dst[OFP_ETH_ALEN]; /* Ethernet destination address. */
    ovs_be16 dl_vlan;          /* Input VLAN. */
    uint8_t dl_vlan_pcp;       /* Input VLAN priority. */
    uint8_t pad1[1];           /* Align to 64-bits. */
    ovs_be16 dl_type;          /* Ethernet frame type. */
    uint8_t nw_tos;            /* IP ToS (DSCP field, 6 bits). */
    uint8_t nw_proto;          /* IP protocol or lower 8 bits of
                                  ARP opcode. */
    uint8_t pad2[2];           /* Align to 64-bits. */
    ovs_be32 nw_src;           /* IP source address. */
    ovs_be32 nw_dst;           /* IP destination address. */
    ovs_be16 tp_src;           /* TCP/UDP source port. */
    ovs_be16 tp_dst;           /* TCP/UDP destination port. */
};
OFP_ASSERT(sizeof(struct ofp_match) == 40);

/* The match fields for ICMP type and code use the transport source and
 * destination port fields, respectively. */
#define icmp_type tp_src
#define icmp_code tp_dst

/* Value used in "idle_timeout" and "hard_timeout" to indicate that the entry
 * is permanent. */
#define OFP_FLOW_PERMANENT 0

/* By default, choose a priority in the middle. */
#define OFP_DEFAULT_PRIORITY 0x8000

enum ofp_flow_mod_flags {
    OFPFF_SEND_FLOW_REM = 1 << 0,  /* Send flow removed message when flow
                                    * expires or is deleted. */
    OFPFF_CHECK_OVERLAP = 1 << 1,  /* Check for overlapping entries first. */
    OFPFF_EMERG         = 1 << 2   /* Ramark this is for emergency. */
};

/* Flow setup and teardown (controller -> datapath). */
struct ofp_flow_mod {
    struct ofp_header header;
    struct ofp_match match;      /* Fields to match */
    ovs_be64 cookie;             /* Opaque controller-issued identifier. */

    /* Flow actions. */
    ovs_be16 command;             /* One of OFPFC_*. */
    ovs_be16 idle_timeout;        /* Idle time before discarding (seconds). */
    ovs_be16 hard_timeout;        /* Max time before discarding (seconds). */
    ovs_be16 priority;            /* Priority level of flow entry. */
    ovs_be32 buffer_id;           /* Buffered packet to apply to (or -1).
                                     Not meaningful for OFPFC_DELETE*. */
    ovs_be16 out_port;            /* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output port.  A value of OFPP_NONE
                                     indicates no restriction. */
    ovs_be16 flags;               /* One of OFPFF_*. */
    struct ofp_action_header actions[0]; /* The action length is inferred
                                            from the length field in the
                                            header. */
};
OFP_ASSERT(sizeof(struct ofp_flow_mod) == 72);

/* Why was this flow removed? */
enum ofp_flow_removed_reason {
    OFPRR_IDLE_TIMEOUT,         /* Flow idle time exceeded idle_timeout. */
    OFPRR_HARD_TIMEOUT,         /* Time exceeded hard_timeout. */
    OFPRR_DELETE                /* Evicted by a DELETE flow mod. */
};

/* Flow removed (datapath -> controller). */
struct ofp_flow_removed {
    struct ofp_header header;
    struct ofp_match match;   /* Description of fields. */
    ovs_be64 cookie;          /* Opaque controller-issued identifier. */

    ovs_be16 priority;        /* Priority level of flow entry. */
    uint8_t reason;           /* One of OFPRR_*. */
    uint8_t pad[1];           /* Align to 32-bits. */

    ovs_be32 duration_sec;    /* Time flow was alive in seconds. */
    ovs_be32 duration_nsec;   /* Time flow was alive in nanoseconds beyond
                                 duration_sec. */
    ovs_be16 idle_timeout;    /* Idle timeout from original flow mod. */
    uint8_t pad2[2];          /* Align to 64-bits. */
    ovs_be64 packet_count;
    ovs_be64 byte_count;
};
OFP_ASSERT(sizeof(struct ofp_flow_removed) == 88);

/* Values for 'type' in ofp_error_message.  These values are immutable: they
 * will not change in future versions of the protocol (although new values may
 * be added). */
enum ofp_error_type {
    OFPET_HELLO_FAILED,         /* Hello protocol failed. */
    OFPET_BAD_REQUEST,          /* Request was not understood. */
    OFPET_BAD_ACTION,           /* Error in action description. */
    OFPET_FLOW_MOD_FAILED,      /* Problem modifying flow entry. */
    OFPET_PORT_MOD_FAILED,      /* OFPT_PORT_MOD failed. */
    OFPET_QUEUE_OP_FAILED       /* Queue operation failed. */
};

/* ofp_error_msg 'code' values for OFPET_HELLO_FAILED.  'data' contains an
 * ASCII text string that may give failure details. */
enum ofp_hello_failed_code {
    OFPHFC_INCOMPATIBLE,        /* No compatible version. */
    OFPHFC_EPERM                /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_REQUEST.  'data' contains at least
 * the first 64 bytes of the failed request. */
enum ofp_bad_request_code {
    OFPBRC_BAD_VERSION,         /* ofp_header.version not supported. */
    OFPBRC_BAD_TYPE,            /* ofp_header.type not supported. */
    OFPBRC_BAD_STAT,            /* ofp_stats_msg.type not supported. */
    OFPBRC_BAD_VENDOR,          /* Vendor not supported (in ofp_vendor_header
                                 * or ofp_stats_msg). */
    OFPBRC_BAD_SUBTYPE,         /* Vendor subtype not supported. */
    OFPBRC_EPERM,               /* Permissions error. */
    OFPBRC_BAD_LEN,             /* Wrong request length for type. */
    OFPBRC_BUFFER_EMPTY,        /* Specified buffer has already been used. */
    OFPBRC_BUFFER_UNKNOWN       /* Specified buffer does not exist. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_ACTION.  'data' contains at least
 * the first 64 bytes of the failed request. */
enum ofp_bad_action_code {
    OFPBAC_BAD_TYPE,           /* Unknown action type. */
    OFPBAC_BAD_LEN,            /* Length problem in actions. */
    OFPBAC_BAD_VENDOR,         /* Unknown vendor id specified. */
    OFPBAC_BAD_VENDOR_TYPE,    /* Unknown action type for vendor id. */
    OFPBAC_BAD_OUT_PORT,       /* Problem validating output action. */
    OFPBAC_BAD_ARGUMENT,       /* Bad action argument. */
    OFPBAC_EPERM,              /* Permissions error. */
    OFPBAC_TOO_MANY,           /* Can't handle this many actions. */
    OFPBAC_BAD_QUEUE           /* Problem validating output queue. */
};

/* ofp_error_msg 'code' values for OFPET_FLOW_MOD_FAILED.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_flow_mod_failed_code {
    OFPFMFC_ALL_TABLES_FULL,    /* Flow not added because of full tables. */
    OFPFMFC_OVERLAP,            /* Attempted to add overlapping flow with
                                 * CHECK_OVERLAP flag set. */
    OFPFMFC_EPERM,              /* Permissions error. */
    OFPFMFC_BAD_EMERG_TIMEOUT,  /* Flow not added because of non-zero idle/hard
                                 * timeout. */
    OFPFMFC_BAD_COMMAND,        /* Unknown command. */
    OFPFMFC_UNSUPPORTED         /* Unsupported action list - cannot process in
                                   the order specified. */
};

/* ofp_error_msg 'code' values for OFPET_PORT_MOD_FAILED.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_port_mod_failed_code {
    OFPPMFC_BAD_PORT,            /* Specified port does not exist. */
    OFPPMFC_BAD_HW_ADDR,         /* Specified hardware address is wrong. */
};

/* ofp_error msg 'code' values for OFPET_QUEUE_OP_FAILED. 'data' contains
 * at least the first 64 bytes of the failed request */
enum ofp_queue_op_failed_code {
    OFPQOFC_BAD_PORT,           /* Invalid port (or port does not exist). */
    OFPQOFC_BAD_QUEUE,          /* Queue does not exist. */
    OFPQOFC_EPERM               /* Permissions error. */
};

/* OFPT_ERROR: Error message (datapath -> controller). */
struct ofp_error_msg {
    struct ofp_header header;

    ovs_be16 type;
    ovs_be16 code;
    uint8_t data[0];          /* Variable-length data.  Interpreted based
                                 on the type and code. */
};
OFP_ASSERT(sizeof(struct ofp_error_msg) == 12);

enum ofp_stats_types {
    /* Description of this OpenFlow switch.
     * The request is struct ofp_stats_msg.
     * The reply is struct ofp_desc_stats. */
    OFPST_DESC,

    /* Individual flow statistics.
     * The request is struct ofp_flow_stats_request.
     * The reply body is an array of struct ofp_flow_stats. */
    OFPST_FLOW,

    /* Aggregate flow statistics.
     * The request is struct ofp_flow_stats_request.
     * The reply is struct ofp_aggregate_stats_reply. */
    OFPST_AGGREGATE,

    /* Flow table statistics.
     * The request is struct ofp_stats_msg.
     * The reply body is an array of struct ofp_table_stats. */
    OFPST_TABLE,

    /* Physical port statistics.
     * The request is struct ofp_port_stats_request.
     * The reply body is an array of struct ofp_port_stats. */
    OFPST_PORT,

    /* Queue statistics for a port.
     * The request body is struct ofp_queue_stats_request.
     * The reply body is an array of struct ofp_queue_stats. */
    OFPST_QUEUE,

    /* Vendor extension.
     * The request and reply begin with "struct ofp_vendor_stats". */
    OFPST_VENDOR = 0xffff
};

/* Statistics request or reply message. */
struct ofp_stats_msg {
    struct ofp_header header;
    ovs_be16 type;              /* One of the OFPST_* constants. */
    ovs_be16 flags;             /* Requests: always 0.
                                 * Replies: 0 or OFPSF_REPLY_MORE. */
};
OFP_ASSERT(sizeof(struct ofp_stats_msg) == 12);

enum ofp_stats_reply_flags {
    OFPSF_REPLY_MORE  = 1 << 0  /* More replies to follow. */
};

#define DESC_STR_LEN   256
#define SERIAL_NUM_LEN 32
/* Reply to OFPST_DESC request.  Each entry is a NULL-terminated ASCII
 * string. */
struct ofp_desc_stats {
    struct ofp_stats_msg osm;
    char mfr_desc[DESC_STR_LEN];       /* Manufacturer description. */
    char hw_desc[DESC_STR_LEN];        /* Hardware description. */
    char sw_desc[DESC_STR_LEN];        /* Software description. */
    char serial_num[SERIAL_NUM_LEN];   /* Serial number. */
    char dp_desc[DESC_STR_LEN];        /* Human readable description of
                                          the datapath. */
};
OFP_ASSERT(sizeof(struct ofp_desc_stats) == 1068);

/* Stats request of type OFPST_AGGREGATE or OFPST_FLOW. */
struct ofp_flow_stats_request {
    struct ofp_stats_msg osm;
    struct ofp_match match;   /* Fields to match. */
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats)
                                 or 0xff for all tables. */
    uint8_t pad;              /* Align to 32 bits. */
    ovs_be16 out_port;        /* Require matching entries to include this
                                 as an output port.  A value of OFPP_NONE
                                 indicates no restriction. */
};
OFP_ASSERT(sizeof(struct ofp_flow_stats_request) == 56);

/* Body of reply to OFPST_FLOW request. */
struct ofp_flow_stats {
    ovs_be16 length;          /* Length of this entry. */
    uint8_t table_id;         /* ID of table flow came from. */
    uint8_t pad;
    struct ofp_match match;   /* Description of fields. */
    ovs_be32 duration_sec;    /* Time flow has been alive in seconds. */
    ovs_be32 duration_nsec;   /* Time flow has been alive in nanoseconds
                                 beyond duration_sec. */
    ovs_be16 priority;        /* Priority of the entry. Only meaningful
                                 when this is not an exact-match entry. */
    ovs_be16 idle_timeout;    /* Number of seconds idle before expiration. */
    ovs_be16 hard_timeout;    /* Number of seconds before expiration. */
    uint8_t pad2[6];          /* Align to 64 bits. */
    ovs_32aligned_be64 cookie;       /* Opaque controller-issued identifier. */
    ovs_32aligned_be64 packet_count; /* Number of packets in flow. */
    ovs_32aligned_be64 byte_count;   /* Number of bytes in flow. */
    struct ofp_action_header actions[0]; /* Actions. */
};
OFP_ASSERT(sizeof(struct ofp_flow_stats) == 88);

/* Reply to OFPST_AGGREGATE request. */
struct ofp_aggregate_stats_reply {
    struct ofp_stats_msg osm;
    ovs_32aligned_be64 packet_count; /* Number of packets in flows. */
    ovs_32aligned_be64 byte_count;   /* Number of bytes in flows. */
    ovs_be32 flow_count;      /* Number of flows. */
    uint8_t pad[4];           /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_aggregate_stats_reply) == 36);

/* Body of reply to OFPST_TABLE request. */
struct ofp_table_stats {
    uint8_t table_id;        /* Identifier of table.  Lower numbered tables
                                are consulted first. */
    uint8_t pad[3];          /* Align to 32-bits. */
    char name[OFP_MAX_TABLE_NAME_LEN];
    ovs_be32 wildcards;      /* Bitmap of OFPFW_* wildcards that are
                                supported by the table. */
    ovs_be32 max_entries;    /* Max number of entries supported. */
    ovs_be32 active_count;   /* Number of active entries. */
    ovs_32aligned_be64 lookup_count;  /* # of packets looked up in table. */
    ovs_32aligned_be64 matched_count; /* Number of packets that hit table. */
};
OFP_ASSERT(sizeof(struct ofp_table_stats) == 64);

/* Stats request of type OFPST_PORT. */
struct ofp_port_stats_request {
    struct ofp_stats_msg osm;
    ovs_be16 port_no;        /* OFPST_PORT message may request statistics
                                for a single port (specified with port_no)
                                or for all ports (port_no == OFPP_NONE). */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct ofp_port_stats_request) == 20);

/* Body of reply to OFPST_PORT request. If a counter is unsupported, set
 * the field to all ones. */
struct ofp_port_stats {
    ovs_be16 port_no;
    uint8_t pad[6];          /* Align to 64-bits. */
    ovs_32aligned_be64 rx_packets;     /* Number of received packets. */
    ovs_32aligned_be64 tx_packets;     /* Number of transmitted packets. */
    ovs_32aligned_be64 rx_bytes;       /* Number of received bytes. */
    ovs_32aligned_be64 tx_bytes;       /* Number of transmitted bytes. */
    ovs_32aligned_be64 rx_dropped;     /* Number of packets dropped by RX. */
    ovs_32aligned_be64 tx_dropped;     /* Number of packets dropped by TX. */
    ovs_32aligned_be64 rx_errors; /* Number of receive errors.  This is a
                                     super-set of receive errors and should be
                                     great than or equal to the sum of all
                                     rx_*_err values. */
    ovs_32aligned_be64 tx_errors; /* Number of transmit errors.  This is a
                                     super-set of transmit errors. */
    ovs_32aligned_be64 rx_frame_err; /* Number of frame alignment errors. */
    ovs_32aligned_be64 rx_over_err;  /* Number of packets with RX overrun. */
    ovs_32aligned_be64 rx_crc_err;   /* Number of CRC errors. */
    ovs_32aligned_be64 collisions;   /* Number of collisions. */
};
OFP_ASSERT(sizeof(struct ofp_port_stats) == 104);

/* All ones is used to indicate all queues in a port (for stats retrieval). */
#define OFPQ_ALL      0xffffffff

/* Body for stats request of type OFPST_QUEUE. */
struct ofp_queue_stats_request {
    struct ofp_stats_msg osm;
    ovs_be16 port_no;        /* All ports if OFPP_ALL. */
    uint8_t pad[2];          /* Align to 32-bits. */
    ovs_be32 queue_id;       /* All queues if OFPQ_ALL. */
};
OFP_ASSERT(sizeof(struct ofp_queue_stats_request) == 20);

/* Body for stats reply of type OFPST_QUEUE consists of an array of this
 * structure type. */
struct ofp_queue_stats {
    ovs_be16 port_no;
    uint8_t pad[2];          /* Align to 32-bits. */
    ovs_be32 queue_id;       /* Queue id. */
    ovs_32aligned_be64 tx_bytes;   /* Number of transmitted bytes. */
    ovs_32aligned_be64 tx_packets; /* Number of transmitted packets. */
    ovs_32aligned_be64 tx_errors;  /* # of packets dropped due to overrun. */
};
OFP_ASSERT(sizeof(struct ofp_queue_stats) == 32);

/* Vendor extension stats message. */
struct ofp_vendor_stats_msg {
    struct ofp_stats_msg osm;   /* Type OFPST_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */
    /* Followed by vendor-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp_vendor_stats_msg) == 16);

/* Vendor extension. */
struct ofp_vendor_header {
    struct ofp_header header;   /* Type OFPT_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */
    /* Vendor-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp_vendor_header) == 12);

#endif /* openflow/openflow.h */
