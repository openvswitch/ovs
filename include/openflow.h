/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
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

/* OpenFlow: protocol between controller and datapath. */

#ifndef OPENFLOW_H
#define OPENFLOW_H 1

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

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

#ifndef SWIG
#define OFP_PACKED __attribute__((packed))
#else
#define OFP_PACKED              /* SWIG doesn't understand __attribute. */
#endif

/* Maximum length of a OpenFlow packet. */
#define OFP_MAXLEN (sizeof(struct ofp_switch_features) \
        + (sizeof(struct ofp_phy_port) * OFPP_MAX) + 200)


/* The most significant bit being set in the version field indicates an
 * experimental OpenFlow version.  
 */
#define OFP_VERSION   0x85

#define OFP_MAX_TABLE_NAME_LEN 32
#define OFP_MAX_PORT_NAME_LEN  16

#define OFP_TCP_PORT  975
#define OFP_SSL_PORT  976

#define OFP_ETH_ALEN 6          /* Bytes in an Ethernet address. */

/* Port numbering.  Physical ports are numbered starting from 0. */
enum ofp_port {
    /* Maximum number of physical switch ports. */
    OFPP_MAX = 0x100,

    /* Fake output "ports". */
    OFPP_TABLE      = 0xfff9,  /* Perform actions in flow table.  
                                * NB: This can only be the destination
                                * port for packet-out messages. 
                                */
    OFPP_NORMAL     = 0xfffa,  /* Process with normal L2/L3 switching. */
    OFPP_FLOOD      = 0xfffb,  /* All physical ports except input port and 
                                  those disabled by STP. */
    OFPP_ALL        = 0xfffc,  /* All physical ports except input port. */
    OFPP_CONTROLLER = 0xfffd,  /* Send to controller. */ 
    OFPP_LOCAL      = 0xfffe,  /* Local openflow "port". */
    OFPP_NONE       = 0xffff   /* Not associated with a physical port. */
};

enum ofp_type {
    OFPT_FEATURES_REQUEST,    /*  0 Controller/switch message */
    OFPT_FEATURES_REPLY,      /*  1 Controller/switch message */
    OFPT_GET_CONFIG_REQUEST,  /*  2 Controller/switch message */
    OFPT_GET_CONFIG_REPLY,    /*  3 Controller/switch message */
    OFPT_SET_CONFIG,          /*  4 Controller/switch message */
    OFPT_PACKET_IN,           /*  5 Async message */
    OFPT_PACKET_OUT,          /*  6 Controller/switch message */
    OFPT_FLOW_MOD,            /*  7 Controller/switch message */
    OFPT_FLOW_EXPIRED,        /*  8 Async message */
    OFPT_TABLE,               /*  9 Controller/switch message */
    OFPT_PORT_MOD,            /* 10 Controller/switch message */
    OFPT_PORT_STATUS,         /* 11 Async message */
    OFPT_ERROR_MSG,           /* 12 Async message */
    OFPT_STATS_REQUEST,       /* 13 Controller/switch message */
    OFPT_STATS_REPLY,         /* 14 Controller/switch message */
    OFPT_ECHO_REQUEST,        /* 15 Symmetric message */
    OFPT_ECHO_REPLY           /* 16 Symmetric message */
};

/* Header on all OpenFlow packets. */
struct ofp_header {
    uint8_t version;    /* OFP_VERSION. */
    uint8_t type;       /* One of the OFPT_ constants. */
    uint16_t length;    /* Length including this ofp_header. */
    uint32_t xid;       /* Transactin id associated with this packet.
                           Replies use the same id as was in the request
                           to facilitate pairing. */
};
OFP_ASSERT(sizeof(struct ofp_header) == 8);

#define OFP_DEFAULT_MISS_SEND_LEN   128

enum ofp_config_flags {
    /* Tells datapath to notify the controller of expired flow entries. */
    OFPC_SEND_FLOW_EXP = 1 << 0
};

/* Switch configuration. */
struct ofp_switch_config {
    struct ofp_header header;
    uint16_t flags;             /* OFPC_* flags. */
    uint16_t miss_send_len;     /* Max bytes of new flow that datapath should
                                   send to the controller. */
};
OFP_ASSERT(sizeof(struct ofp_switch_config) == 12);

/* Capabilities supported by the datapath. */
enum ofp_capabilities {
    OFPC_FLOW_STATS   = 1 << 0, /* Flow statistics. */
    OFPC_TABLE_STATS  = 1 << 1, /* Table statistics. */
    OFPC_PORT_STATS   = 1 << 2, /* Port statistics. */
    OFPC_STP          = 1 << 3, /* 802.11d spanning tree. */
    OFPC_MULTI_PHY_TX = 1 << 4  /* Supports transmitting through multiple
                                   physical interfaces */
};

/* Flags to indicate behavior of the physical port */
enum ofp_port_flags {
    OFPPFL_NO_FLOOD  = 1 << 0, /* Do not include this port when flooding */
};

/* Features of physical ports available in a datapath. */
enum ofp_port_features {
    OFPPF_10MB_HD    = 1 << 0, /* 10 Mb half-duplex rate support. */
    OFPPF_10MB_FD    = 1 << 1, /* 10 Mb full-duplex rate support. */
    OFPPF_100MB_HD   = 1 << 2, /* 100 Mb half-duplex rate support. */
    OFPPF_100MB_FD   = 1 << 3, /* 100 Mb full-duplex rate support. */
    OFPPF_1GB_HD     = 1 << 4, /* 1 Gb half-duplex rate support. */
    OFPPF_1GB_FD     = 1 << 5, /* 1 Gb full-duplex rate support. */
    OFPPF_10GB_FD    = 1 << 6, /* 10 Gb full-duplex rate support. */
};


/* Description of a physical port */
struct ofp_phy_port {
    uint16_t port_no;
    uint8_t hw_addr[OFP_ETH_ALEN];
    uint8_t name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */
    uint32_t flags;         /* Bitmap of "ofp_port_flags". */
    uint32_t speed;         /* Current speed in Mbps */
    uint32_t features;      /* Bitmap of supported "ofp_port_features"s. */
};
OFP_ASSERT(sizeof(struct ofp_phy_port) == 36);

/* Switch features. */
struct ofp_switch_features {
    struct ofp_header header;
    uint64_t datapath_id;   /* Datapath unique ID.  Only the lower 48-bits
                               are meaningful. */

    /* Table info. */
    uint32_t n_exact;       /* Max exact-match table entries. */
    uint32_t n_compression; /* Max entries compressed on service port. */
    uint32_t n_general;     /* Max entries of arbitrary form. */

    /* Buffer limits.  A datapath that cannot buffer reports 0.*/
    uint32_t buffer_mb;     /* Space for buffering packets, in MB. */
    uint32_t n_buffers;     /* Max packets buffered at once. */

    /* Features. */
    uint32_t capabilities;  /* Bitmap of support "ofp_capabilities". */
    uint32_t actions;       /* Bitmap of supported "ofp_action_type"s. */
    uint8_t pad[4];         /* Align to 64-bits. */

    /* Port info.*/
    struct ofp_phy_port ports[0];   /* Port definitions.  The number of ports
                                      is inferred from the length field in
                                      the header. */
};
OFP_ASSERT(sizeof(struct ofp_switch_features) == 48);

/* What changed about the phsyical port */
enum ofp_port_reason {
    OFPPR_ADD,              /* The port was added */
    OFPPR_DELETE,           /* The port was removed */
    OFPPR_MOD               /* Some attribute of the port has changed */
};

/* A physical port has changed in the datapath */
struct ofp_port_status {
    struct ofp_header header;
    uint8_t reason;          /* One of OFPPR_* */
    uint8_t pad[3];          /* Align to 32-bits */
    struct ofp_phy_port desc;
};
OFP_ASSERT(sizeof(struct ofp_port_status) == 48);

/* Modify behavior of the physical port */
struct ofp_port_mod {
    struct ofp_header header;
    struct ofp_phy_port desc;
};
OFP_ASSERT(sizeof(struct ofp_port_mod) == 44);

/* Why is this packet being sent to the controller? */
enum ofp_reason {
    OFPR_NO_MATCH,          /* No matching flow. */
    OFPR_ACTION             /* Action explicitly output to controller. */
};

/* Packet received on port (datapath -> controller). */
struct ofp_packet_in {
    struct ofp_header header;
    uint32_t buffer_id;     /* ID assigned by datapath. */
    uint16_t total_len;     /* Full length of frame. */
    uint16_t in_port;       /* Port on which frame was received. */
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
    OFPAT_SET_DL_VLAN,      /* VLAN. */
    OFPAT_SET_DL_SRC,       /* Ethernet source address. */
    OFPAT_SET_DL_DST,       /* Ethernet destination address. */
    OFPAT_SET_NW_SRC,       /* IP source address. */
    OFPAT_SET_NW_DST,       /* IP destination address. */
    OFPAT_SET_TP_SRC,       /* TCP/UDP source port. */
    OFPAT_SET_TP_DST        /* TCP/UDP destination port. */
};

/* An output action sends packets out 'port'.  When the 'port' is the
 * OFPP_CONTROLLER, 'max_len' indicates the max number of bytes to
 * send.  A 'max_len' of zero means the entire packet should be sent. */
struct ofp_action_output {
    uint16_t max_len;
    uint16_t port;
};
OFP_ASSERT(sizeof(struct ofp_action_output) == 4);

/* The VLAN id is 12-bits, so we'll use the entire 16 bits to indicate
 * special conditions.  All ones is used to indicate that no VLAN id was
 * set, or if used as an action, that the VLAN header should be
 * stripped.
 */
#define OFP_VLAN_NONE      0xffff

struct ofp_action {
    uint16_t type;                       /* One of OFPAT_* */
    union {
        struct ofp_action_output output; /* OFPAT_OUTPUT: output struct. */
        uint16_t vlan_id;                /* OFPAT_SET_DL_VLAN: VLAN id. */
        uint8_t  dl_addr[OFP_ETH_ALEN];  /* OFPAT_SET_DL_SRC/DST */
        uint32_t nw_addr OFP_PACKED;     /* OFPAT_SET_NW_SRC/DST */
        uint16_t tp;                     /* OFPAT_SET_TP_SRC/DST */
    } arg;
};
OFP_ASSERT(sizeof(struct ofp_action) == 8);

/* Send packet (controller -> datapath). */
struct ofp_packet_out {
    struct ofp_header header;
    uint32_t buffer_id;     /* ID assigned by datapath (-1 if none). */
    uint16_t in_port;       /* Packet's input port (OFPP_NONE if none). */
    uint16_t out_port;      /* Output port (if buffer_id == -1). */
    union {
        struct ofp_action actions[0]; /* buffer_id != -1 */
        uint8_t data[0];              /* buffer_id == -1 */
    } u;
};
OFP_ASSERT(sizeof(struct ofp_packet_out) == 16);

enum ofp_flow_mod_command {
    OFPFC_ADD,              /* New flow. */
    OFPFC_DELETE,           /* Delete all matching flows. */
    OFPFC_DELETE_STRICT     /* Strictly match wildcards and priority. */
};

/* Flow wildcards. */
enum ofp_flow_wildcards {
    OFPFW_IN_PORT  = 1 << 0,  /* Switch input port. */
    OFPFW_DL_VLAN  = 1 << 1,  /* VLAN. */
    OFPFW_DL_SRC   = 1 << 2,  /* Ethernet source address. */
    OFPFW_DL_DST   = 1 << 3,  /* Ethernet destination address. */
    OFPFW_DL_TYPE  = 1 << 4,  /* Ethernet frame type. */
    OFPFW_NW_SRC   = 1 << 5,  /* IP source address. */
    OFPFW_NW_DST   = 1 << 6,  /* IP destination address. */
    OFPFW_NW_PROTO = 1 << 7,  /* IP protocol. */
    OFPFW_TP_SRC   = 1 << 8,  /* TCP/UDP source port. */
    OFPFW_TP_DST   = 1 << 9,  /* TCP/UDP destination port. */
    OFPFW_ALL      = (1 << 10) - 1
};

/* Values below this cutoff are 802.3 packets and the two bytes
 * following MAC addresses are used as a frame length.  Otherwise, the
 * two bytes are used as the Ethernet type.
 */
#define OFP_DL_TYPE_ETH2_CUTOFF   0x0600

/* Value of dl_type to indicate that the frame does not include an
 * Ethernet type.
 */
#define OFP_DL_TYPE_NOT_ETH_TYPE  0x05ff

/* Fields to match against flows */
struct ofp_match {
    uint16_t wildcards;        /* Wildcard fields. */
    uint16_t in_port;          /* Input switch port. */
    uint8_t dl_src[OFP_ETH_ALEN]; /* Ethernet source address. */
    uint8_t dl_dst[OFP_ETH_ALEN]; /* Ethernet destination address. */
    uint16_t dl_vlan;          /* Input VLAN. */
    uint16_t dl_type;          /* Ethernet frame type. */
    uint32_t nw_src;           /* IP source address. */
    uint32_t nw_dst;           /* IP destination address. */
    uint8_t nw_proto;          /* IP protocol. */
    uint8_t pad[3];            /* Align to 32-bits. */
    uint16_t tp_src;           /* TCP/UDP source port. */
    uint16_t tp_dst;           /* TCP/UDP destination port. */
};
OFP_ASSERT(sizeof(struct ofp_match) == 36);

/* Value used in "max_idle" to indicate that the entry is permanent */
#define OFP_FLOW_PERMANENT 0

/* By default, choose a priority in the middle */
#define OFP_DEFAULT_PRIORITY 0x8000

/* Flow setup and teardown (controller -> datapath). */
struct ofp_flow_mod {
    struct ofp_header header;
    struct ofp_match match;      /* Fields to match */

    /* Flow actions. */
    uint16_t command;             /* One of OFPFC_*. */
    uint16_t max_idle;            /* Idle time before discarding (seconds). */
    uint32_t buffer_id;           /* Buffered packet to apply to (or -1). */
    uint16_t priority;            /* Priority level of flow entry. */
    uint8_t pad[2];               /* Align to 32-bits. */
    uint32_t reserved;            /* Reserved for future use. */
    struct ofp_action actions[0]; /* The number of actions is inferred from
                                    the length field in the header. */
};
OFP_ASSERT(sizeof(struct ofp_flow_mod) == 60);

/* Flow expiration (datapath -> controller). */
struct ofp_flow_expired {
    struct ofp_header header;
    struct ofp_match match;   /* Description of fields */

    uint16_t priority;        /* Priority level of flow entry. */
    uint8_t pad[2];           /* Align to 32-bits. */

    uint32_t duration;        /* Time flow was alive in seconds. */
    uint8_t pad2[4];          /* Align to 64-bits. */
    uint64_t packet_count;    
    uint64_t byte_count;
};
OFP_ASSERT(sizeof(struct ofp_flow_expired) == 72);

/* Error message (datapath -> controller). */
struct ofp_error_msg {
    struct ofp_header header;

    uint16_t type;
    uint16_t code;
    uint8_t data[0];          /* Variable-length data.  Interpreted based 
                                 on the type and code. */
};
OFP_ASSERT(sizeof(struct ofp_error_msg) == 12);

enum ofp_stats_types {
    /* Individual flow statistics.
     * The request body is struct ofp_flow_stats_request.
     * The reply body is an array of struct ofp_flow_stats. */
    OFPST_FLOW,

    /* Aggregate flow statistics.
     * The request body is struct ofp_aggregate_stats_request.
     * The reply body is struct ofp_aggregate_stats_reply. */
    OFPST_AGGREGATE,

    /* Flow table statistics.
     * The request body is empty.
     * The reply body is an array of struct ofp_table_stats. */
    OFPST_TABLE,

    /* Physical port statistics.
     * The request body is empty.
     * The reply body is an array of struct ofp_port_stats. */
    OFPST_PORT
};

struct ofp_stats_request {
    struct ofp_header header;
    uint16_t type;              /* One of the OFPST_* constants. */
    uint16_t flags;             /* OFPSF_REQ_* flags (none yet defined). */
    uint8_t body[0];            /* Body of the request. */
};
OFP_ASSERT(sizeof(struct ofp_stats_request) == 12);

enum ofp_stats_reply_flags {
    OFPSF_REPLY_MORE  = 1 << 0, /* More replies to follow */
};

struct ofp_stats_reply {
    struct ofp_header header;
    uint16_t type;              /* One of the OFPST_* constants. */
    uint16_t flags;             /* OFPSF_REPLY_* flags. */
    uint8_t body[0];            /* Body of the reply. */
};
OFP_ASSERT(sizeof(struct ofp_stats_reply) == 12);

/* Body for ofp_stats_request of type OFPST_FLOW. */
struct ofp_flow_stats_request {
    struct ofp_match match;   /* Fields to match */
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats)
                                 or 0xff for all tables. */
    uint8_t pad[3];           /* Align to 32 bits. */
};
OFP_ASSERT(sizeof(struct ofp_flow_stats_request) == 40);

/* Body of reply to OFPST_FLOW request. */
struct ofp_flow_stats {
    uint16_t length;          /* Length of this entry. */
    uint8_t table_id;         /* ID of table flow came from. */
    uint8_t pad;
    struct ofp_match match;   /* Description of fields. */
    uint32_t duration;        /* Time flow has been alive in seconds. */
    uint16_t priority;        /* Priority of the entry. Only meaningful
                                 when this is not an exact-match entry. */
    uint16_t max_idle;        /* Number of seconds idle before expiration. */
    uint64_t packet_count;    /* Number of packets in flow. */
    uint64_t byte_count;      /* Number of bytes in flow. */
    struct ofp_action actions[0]; /* Actions. */
};
OFP_ASSERT(sizeof(struct ofp_flow_stats) == 64);

/* Body for ofp_stats_request of type OFPST_AGGREGATE. */
struct ofp_aggregate_stats_request {
    struct ofp_match match;   /* Fields to match */
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats)
                                 or 0xff for all tables. */
    uint8_t pad[3];           /* Align to 32 bits. */
};
OFP_ASSERT(sizeof(struct ofp_aggregate_stats_request) == 40);

/* Body of reply to OFPST_AGGREGATE request. */
struct ofp_aggregate_stats_reply {
    uint64_t packet_count;    /* Number of packets in flows. */
    uint64_t byte_count;      /* Number of bytes in flows. */
    uint32_t flow_count;      /* Number of flows. */
    uint8_t pad[4];           /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_aggregate_stats_reply) == 24);

/* Body of reply to OFPST_TABLE request. */
struct ofp_table_stats {
    uint8_t table_id;
    uint8_t pad[3];          /* Align to 32-bits */
    char name[OFP_MAX_TABLE_NAME_LEN];
    uint32_t max_entries;    /* Max number of entries supported */
    uint32_t active_count;   /* Number of active entries */
    uint8_t pad2[4];         /* Align to 64 bits. */
    uint64_t matched_count;  /* Number of packets that hit table */
};
OFP_ASSERT(sizeof(struct ofp_table_stats) == 56);

/* Statistics about a particular port */
struct ofp_port_stats {
    uint16_t port_no;
    uint8_t pad[6];          /* Align to 64-bits */
    uint64_t rx_count;       /* Number of received packets */
    uint64_t tx_count;       /* Number of transmitted packets */
    uint64_t drop_count;     /* Number of packets dropped by interface */
};
OFP_ASSERT(sizeof(struct ofp_port_stats) == 32);

#endif /* openflow.h */
