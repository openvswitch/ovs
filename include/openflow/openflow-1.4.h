/* Copyright (c) 2008, 2014, 2017 The Board of Trustees of The Leland Stanford
* Junior University
* Copyright (c) 2011, 2012 Open Networking Foundation
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

#ifndef OPENFLOW_14_H
#define OPENFLOW_14_H 1

#include <openflow/openflow-1.3.h>

/* OpenFlow 1.4.1+ specific capabilities
 * (struct ofp_switch_features, member capabilities). */
enum ofp14_capabilities {
    OFPC14_BUNDLES        = 1 << 9,    /* Switch supports bundles. */
    OFPC14_FLOW_MONITORING = 1 << 10,  /* Switch supports flow monitoring. */
};

/* ## ---------- ## */
/* ## ofp14_port ## */
/* ## ---------- ## */

/* Port description property types. */
enum ofp_port_desc_prop_type {
    OFPPDPT14_ETHERNET          = 0,      /* Ethernet property. */
    OFPPDPT14_OPTICAL           = 1,      /* Optical property. */
    OFPPDPT14_EXPERIMENTER      = 0xFFFF, /* Experimenter property. */
};

/* Ethernet port description property. */
struct ofp14_port_desc_prop_ethernet {
    ovs_be16         type;    /* OFPPDPT14_ETHERNET. */
    ovs_be16         length;  /* Length in bytes of this property. */
    uint8_t          pad[4];  /* Align to 64 bits. */
    /* Bitmaps of OFPPF_* that describe features.  All bits zeroed if
     * unsupported or unavailable. */
    ovs_be32 curr;          /* Current features. */
    ovs_be32 advertised;    /* Features being advertised by the port. */
    ovs_be32 supported;     /* Features supported by the port. */
    ovs_be32 peer;          /* Features advertised by peer. */

    ovs_be32 curr_speed;    /* Current port bitrate in kbps. */
    ovs_be32 max_speed;     /* Max port bitrate in kbps */
};
OFP_ASSERT(sizeof(struct ofp14_port_desc_prop_ethernet) == 32);

struct ofp14_port {
    ovs_be32 port_no;
    ovs_be16 length;
    uint8_t pad[2];
    struct eth_addr hw_addr;
    uint8_t pad2[2];                  /* Align to 64 bits. */
    char name[OFP10_MAX_PORT_NAME_LEN]; /* Null-terminated */

    ovs_be32 config;        /* Bitmap of OFPPC_* flags. */
    ovs_be32 state;         /* Bitmap of OFPPS_* flags. */

    /* Followed by 0 or more OFPPDPT14_* properties. */
};
OFP_ASSERT(sizeof(struct ofp14_port) == 40);


/* ## -------------- ## */
/* ## ofp14_port_mod ## */
/* ## -------------- ## */

enum ofp14_port_mod_prop_type {
    OFPPMPT14_ETHERNET          = 0,      /* Ethernet property. */
    OFPPMPT14_OPTICAL           = 1,      /* Optical property. */
    OFPPMPT14_EXPERIMENTER      = 0xFFFF, /* Experimenter property. */
};

struct ofp14_port_mod {
    ovs_be32 port_no;
    uint8_t pad[4];
    struct eth_addr hw_addr;
    uint8_t pad2[2];
    ovs_be32 config;        /* Bitmap of OFPPC_* flags. */
    ovs_be32 mask;          /* Bitmap of OFPPC_* flags to be changed. */
    /* Followed by 0 or more OFPPMPT14_* properties. */
};
OFP_ASSERT(sizeof(struct ofp14_port_mod) == 24);

/* ## --------------- ## */
/* ## ofp14_table_mod ## */
/* ## --------------- ## */

enum ofp14_table_mod_prop_type {
    OFPTMPT14_EVICTION               = 0x2,    /* Eviction property. */
    OFPTMPT14_VACANCY                = 0x3,    /* Vacancy property. */
    OFPTMPT14_EXPERIMENTER           = 0xFFFF, /* Experimenter property. */
};

enum ofp14_table_mod_prop_eviction_flag {
    OFPTMPEF14_OTHER           = 1 << 0,     /* Using other factors. */
    OFPTMPEF14_IMPORTANCE      = 1 << 1,     /* Using flow entry importance. */
    OFPTMPEF14_LIFETIME        = 1 << 2,     /* Using flow entry lifetime. */
};

/* What changed about the table */
enum ofp14_table_reason {
    OFPTR_VACANCY_DOWN = 3,    /* Vacancy down threshold event. */
    OFPTR_VACANCY_UP   = 4,    /* Vacancy up threshold event. */
#define OFPTR_BITS ((1u << OFPTR_VACANCY_DOWN) | (1u << OFPTR_VACANCY_UP))
};

struct ofp14_table_mod_prop_vacancy {
    ovs_be16         type;   /* OFPTMPT14_VACANCY. */
    ovs_be16         length; /* Length in bytes of this property. */
    uint8_t vacancy_down;    /* Vacancy threshold when space decreases (%). */
    uint8_t vacancy_up;      /* Vacancy threshold when space increases (%). */
    uint8_t vacancy;      /* Current vacancy (%) - only in ofp14_table_desc. */
    uint8_t pad[1];          /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp14_table_mod_prop_vacancy) == 8);

struct ofp14_table_mod {
    uint8_t table_id;     /* ID of the table, OFPTT_ALL indicates all tables */
    uint8_t pad[3];         /* Pad to 32 bits */
    ovs_be32 config;        /* Bitmap of OFPTC_* flags */
    /* Followed by 0 or more OFPTMPT14_* properties. */
};
OFP_ASSERT(sizeof(struct ofp14_table_mod) == 8);

/* Body of reply to OFPMP_TABLE_DESC request. */
struct ofp14_table_desc {
    ovs_be16 length;       /* Length is padded to 64 bits. */
    uint8_t table_id;      /* Identifier of table. Lower numbered tables
                              are consulted first. */
    uint8_t pad[1];        /* Align to 32-bits. */
    ovs_be32 config;       /* Bitmap of OFPTC_* values. */
    /* Followed by 0 or more OFPTMPT14_* properties. */
};
OFP_ASSERT(sizeof(struct ofp14_table_desc) == 8);

/* A table config has changed in the datapath */
struct ofp14_table_status {
    uint8_t reason;    /* One of OFPTR_*. */
    uint8_t pad[7];    /* Pad to 64 bits */
    /* Followed by struct ofp14_table_desc */
};
OFP_ASSERT(sizeof(struct ofp14_table_status) == 8);

/* ## ---------------- ## */
/* ## ofp14_port_stats ## */
/* ## ---------------- ## */

enum ofp14_port_stats_prop_type {
    OFPPSPT14_ETHERNET          = 0,      /* Ethernet property. */
    OFPPSPT14_OPTICAL           = 1,      /* Optical property. */
    OFPPSPT14_EXPERIMENTER      = 0xFFFF, /* Experimenter property. */
};

struct ofp14_port_stats_prop_ethernet {
    ovs_be16         type;    /* OFPPSPT14_ETHERNET. */
    ovs_be16         length;  /* Length in bytes of this property. */
    uint8_t          pad[4];  /* Align to 64 bits. */

    ovs_be64 rx_frame_err;   /* Number of frame alignment errors. */
    ovs_be64 rx_over_err;    /* Number of packets with RX overrun. */
    ovs_be64 rx_crc_err;     /* Number of CRC errors. */
    ovs_be64 collisions;     /* Number of collisions. */
};
OFP_ASSERT(sizeof(struct ofp14_port_stats_prop_ethernet) == 40);

struct ofp14_port_stats {
    ovs_be16 length;         /* Length of this entry. */
    uint8_t pad[2];          /* Align to 64 bits. */
    ovs_be32 port_no;
    ovs_be32 duration_sec;   /* Time port has been alive in seconds. */
    ovs_be32 duration_nsec;  /* Time port has been alive in nanoseconds beyond
                                duration_sec. */
    ovs_be64 rx_packets;     /* Number of received packets. */
    ovs_be64 tx_packets;     /* Number of transmitted packets. */
    ovs_be64 rx_bytes;       /* Number of received bytes. */
    ovs_be64 tx_bytes;       /* Number of transmitted bytes. */

    ovs_be64 rx_dropped;     /* Number of packets dropped by RX. */
    ovs_be64 tx_dropped;     /* Number of packets dropped by TX. */
    ovs_be64 rx_errors;      /* Number of receive errors.  This is a super-set
                                of more specific receive errors and should be
                                greater than or equal to the sum of all
                                rx_*_err values in properties. */
    ovs_be64 tx_errors;      /* Number of transmit errors.  This is a super-set
                                of more specific transmit errors and should be
                                greater than or equal to the sum of all
                                tx_*_err values (none currently defined.) */
    /* Followed by 0 or more OFPPSPT14_* properties. */
};
OFP_ASSERT(sizeof(struct ofp14_port_stats) == 80);


/* ## ----------------- ## */
/* ## ofp14_queue_stats ## */
/* ## ----------------- ## */

struct ofp14_queue_stats {
    ovs_be16 length;         /* Length of this entry. */
    uint8_t pad[6];          /* Align to 64 bits. */
    struct ofp13_queue_stats qs;
    /* Followed by 0 or more properties (none yet defined). */
};
OFP_ASSERT(sizeof(struct ofp14_queue_stats) == 48);


/* ## ---------------- ## */
/* ## ofp14_queue_desc ## */
/* ## ---------------- ## */

struct ofp14_queue_desc_request {
    ovs_be32 port;              /* All ports if OFPP_ANY. */
    ovs_be32 queue;             /* All queues if OFPQ_ALL. */
};
OFP_ASSERT(sizeof(struct ofp14_queue_desc_request) == 8);

/* Body of reply to OFPMP_QUEUE_DESC request. */
struct ofp14_queue_desc {
    ovs_be32 port_no;           /* Port this queue is attached to. */
    ovs_be32 queue_id;          /* ID for the specific queue. */
    ovs_be16 len;               /* Length in bytes of this queue desc. */
    uint8_t pad[6];             /* 64-bit alignment. */
};
OFP_ASSERT(sizeof(struct ofp14_queue_desc) == 16);

enum ofp14_queue_desc_prop_type {
    OFPQDPT14_MIN_RATE = 1,
    OFPQDPT14_MAX_RATE = 2,
    OFPQDPT14_EXPERIMENTER = 0xffff
};

/* ## -------------- ## */
/* ## Miscellaneous. ## */
/* ## -------------- ## */

/* Request forward reason */
enum ofp14_requestforward_reason {
    OFPRFR_GROUP_MOD = 0,      /* Forward group mod requests. */
    OFPRFR_METER_MOD = 1,      /* Forward meter mod requests. */
    OFPRFR_N_REASONS           /* Denotes number of reasons. */
};

/* Role status event message. */
struct ofp14_role_status {
    ovs_be32 role;              /* One of OFPCR_ROLE_*. */
    uint8_t  reason;            /* One of OFPCRR_*. */
    uint8_t  pad[3];            /* Align to 64 bits. */
    ovs_be64 generation_id;     /* Master Election Generation Id */

    /* Followed by a list of struct ofp14_role_prop_header */
};
OFP_ASSERT(sizeof(struct ofp14_role_status) == 16);

/* What changed about the controller role */
enum ofp14_controller_role_reason {
    OFPCRR_MASTER_REQUEST = 0,  /* Another controller asked to be master. */
    OFPCRR_CONFIG         = 1,  /* Configuration changed on the switch. */
    OFPCRR_EXPERIMENTER   = 2,  /* Experimenter data changed. */
    OFPCRR_N_REASONS            /* Denotes number of reasons. */
};

/* Role property types.
*/
enum ofp14_role_prop_type {
    OFPRPT_EXPERIMENTER         = 0xFFFF, /* Experimenter property. */
};

/* Group/Meter request forwarding. */
struct ofp14_requestforward {
    struct ofp_header request;  /* Request being forwarded. */
};
OFP_ASSERT(sizeof(struct ofp14_requestforward) == 8);

/* Bundle control message types */
enum ofp14_bundle_ctrl_type {
    OFPBCT_OPEN_REQUEST    = 0,
    OFPBCT_OPEN_REPLY      = 1,
    OFPBCT_CLOSE_REQUEST   = 2,
    OFPBCT_CLOSE_REPLY     = 3,
    OFPBCT_COMMIT_REQUEST  = 4,
    OFPBCT_COMMIT_REPLY    = 5,
    OFPBCT_DISCARD_REQUEST = 6,
    OFPBCT_DISCARD_REPLY   = 7,
};

/* Bundle configuration flags. */
enum ofp14_bundle_flags {
    OFPBF_ATOMIC  = 1 << 0,  /* Execute atomically. */
    OFPBF_ORDERED = 1 << 1,  /* Execute in specified order. */
};

/* Message structure for OFPT_BUNDLE_CONTROL and OFPT_BUNDLE_ADD_MESSAGE. */
struct ofp14_bundle_ctrl_msg {
    ovs_be32 bundle_id;     /* Identify the bundle. */
    ovs_be16 type;          /* OFPT_BUNDLE_CONTROL: one of OFPBCT_*.
                             * OFPT_BUNDLE_ADD_MESSAGE: not used. */
    ovs_be16 flags;         /* Bitmap of OFPBF_* flags. */
    /* Followed by:
     * - For OFPT_BUNDLE_ADD_MESSAGE only, an encapsulated OpenFlow message,
     *   beginning with an ofp_header whose xid is identical to this message's
     *   outer xid.
     * - For OFPT_BUNDLE_ADD_MESSAGE only, and only if at least one property is
     *   present, 0 to 7 bytes of padding to align on a 64-bit boundary.
     * - Zero or more properties (see struct ofp14_bundle_prop_header). */
};
OFP_ASSERT(sizeof(struct ofp14_bundle_ctrl_msg) == 8);

/* Body for ofp14_multipart_request of type OFPMP_FLOW_MONITOR.
 *
 * The OFPMP_FLOW_MONITOR request's body consists of an array of zero or more
 * instances of this structure. The request arranges to monitor the flows
 * that match the specified criteria, which are interpreted in the same way as
 * for OFPMP_FLOW.
 *
 * 'id' identifies a particular monitor for the purpose of allowing it to be
 * canceled later with OFPFMC_DELETE. 'id' must be unique among
 * existing monitors that have not already been canceled.
 */
struct ofp14_flow_monitor_request {
    ovs_be32 monitor_id;        /* Controller-assigned ID for this monitor. */
    ovs_be32 out_port;          /* Required output port, if not OFPP_ANY. */
    ovs_be32 out_group;         /* Required output port, if not OFPG_ANY. */
    ovs_be16 flags;             /* OFPMF14_*. */
    uint8_t table_id;           /* One table's ID or OFPTT_ALL (all tables). */
    uint8_t command;            /* One of OFPFMC14_*. */
    /* Followed by an ofp11_match structure. */
};
OFP_ASSERT(sizeof(struct ofp14_flow_monitor_request) == 16);

/* Flow monitor commands */
enum ofp14_flow_monitor_command {
    OFPFMC14_ADD = 0, /* New flow monitor. */
    OFPFMC14_MODIFY = 1, /* Modify existing flow monitor. */
    OFPFMC14_DELETE = 2, /* Delete/cancel existing flow monitor. */
};

/* 'flags' bits in struct of_flow_monitor_request. */
enum ofp14_flow_monitor_flags {
    /* When to send updates. */
    /* Common to NX and OpenFlow 1.4 */
    OFPFMF14_INITIAL = 1 << 0,     /* Initially matching flows. */
    OFPFMF14_ADD = 1 << 1,         /* New matching flows as they are added. */
    OFPFMF14_REMOVED = 1 << 2,     /* Old matching flows as they are removed. */
    OFPFMF14_MODIFY = 1 << 3,      /* Matching flows as they are changed. */

    /* What to include in updates. */
    /* Common to NX and OpenFlow 1.4 */
    OFPFMF14_INSTRUCTIONS = 1 << 4, /* If set, instructions are included. */
    OFPFMF14_NO_ABBREV = 1 << 5,    /* If set, include own changes in full. */
    /* OpenFlow 1.4 */
    OFPFMF14_ONLY_OWN = 1 << 6,     /* If set, don't include other controllers.
                                     */
};

#endif /* openflow/openflow-1.4.h */
