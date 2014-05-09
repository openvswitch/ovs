/* Copyright (c) 2008, 2014 The Board of Trustees of The Leland Stanford
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

#include "openflow/openflow-1.3.h"


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
    uint8_t hw_addr[OFP_ETH_ALEN];
    uint8_t pad2[2];                  /* Align to 64 bits. */
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */

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

/* Ethernet port mod property. */
struct ofp14_port_mod_prop_ethernet {
    ovs_be16      type;       /* OFPPMPT14_ETHERNET. */
    ovs_be16      length;     /* Length in bytes of this property. */
    ovs_be32      advertise;  /* Bitmap of OFPPF_*.  Zero all bits to prevent
                                 any action taking place. */
};
OFP_ASSERT(sizeof(struct ofp14_port_mod_prop_ethernet) == 8);

struct ofp14_port_mod {
    ovs_be32 port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN];
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

struct ofp14_table_mod_prop_eviction {
    ovs_be16         type;    /* OFPTMPT14_EVICTION. */
    ovs_be16         length;  /* Length in bytes of this property. */
    ovs_be32         flags;   /* Bitmap of OFPTMPEF14_* flags */
};
OFP_ASSERT(sizeof(struct ofp14_table_mod_prop_eviction) == 8);

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


/* ## -------------- ## */
/* ## Miscellaneous. ## */
/* ## -------------- ## */

/* Common header for all async config Properties */
struct ofp14_async_config_prop_header {
    ovs_be16    type;       /* One of OFPACPT_*. */
    ovs_be16    length;     /* Length in bytes of this property. */
};
OFP_ASSERT(sizeof(struct ofp14_async_config_prop_header) == 4);

/* Asynchronous message configuration.
 * OFPT_GET_ASYNC_REPLY or OFPT_SET_ASYNC.
 */
struct ofp14_async_config {
    struct ofp_header header;
    /* Async config Property list - 0 or more */
    struct ofp14_async_config_prop_header properties[0];
};
OFP_ASSERT(sizeof(struct ofp14_async_config) == 8);

/* Async Config property types.
* Low order bit cleared indicates a property for the slave role.
* Low order bit set indicates a property for the master/equal role.
*/
enum ofp14_async_config_prop_type {
    OFPACPT_PACKET_IN_SLAVE       = 0, /* Packet-in mask for slave. */
    OFPACPT_PACKET_IN_MASTER      = 1, /* Packet-in mask for master. */
    OFPACPT_PORT_STATUS_SLAVE     = 2, /* Port-status mask for slave. */
    OFPACPT_PORT_STATUS_MASTER    = 3, /* Port-status mask for master. */
    OFPACPT_FLOW_REMOVED_SLAVE    = 4, /* Flow removed mask for slave. */
    OFPACPT_FLOW_REMOVED_MASTER   = 5, /* Flow removed mask for master. */
    OFPACPT_ROLE_STATUS_SLAVE     = 6, /* Role status mask for slave. */
    OFPACPT_ROLE_STATUS_MASTER    = 7, /* Role status mask for master. */
    OFPACPT_TABLE_STATUS_SLAVE    = 8, /* Table status mask for slave. */
    OFPACPT_TABLE_STATUS_MASTER   = 9, /* Table status mask for master. */
    OFPACPT_REQUESTFORWARD_SLAVE  = 10, /* RequestForward mask for slave. */
    OFPACPT_REQUESTFORWARD_MASTER = 11, /* RequestForward mask for master. */
    OFPTFPT_EXPERIMENTER_SLAVE    = 0xFFFE, /* Experimenter for slave. */
    OFPTFPT_EXPERIMENTER_MASTER   = 0xFFFF, /* Experimenter for master. */
};

/* Various reason based properties */
struct ofp14_async_config_prop_reasons {
    /* 'type' is one of OFPACPT_PACKET_IN_*, OFPACPT_PORT_STATUS_*,
     * OFPACPT_FLOW_REMOVED_*, OFPACPT_ROLE_STATUS_*,
     * OFPACPT_TABLE_STATUS_*, OFPACPT_REQUESTFORWARD_*. */
    ovs_be16    type;
    ovs_be16    length; /* Length in bytes of this property. */
    ovs_be32    mask;   /* Bitmasks of reason values. */
};
OFP_ASSERT(sizeof(struct ofp14_async_config_prop_reasons) == 8);

/* Experimenter async config property */
struct ofp14_async_config_prop_experimenter {
    ovs_be16        type;       /* One of OFPTFPT_EXPERIMENTER_SLAVE,
                                   OFPTFPT_EXPERIMENTER_MASTER. */
    ovs_be16        length;     /* Length in bytes of this property. */
    ovs_be32        experimenter;  /* Experimenter ID which takes the same
                                      form as in struct
                                      ofp_experimenter_header. */
    ovs_be32        exp_type;      /* Experimenter defined. */
    /* Followed by:
     *   - Exactly (length - 12) bytes containing the experimenter data, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
};
OFP_ASSERT(sizeof(struct ofp14_async_config_prop_experimenter) == 12);

/* Common header for all Role Properties */
struct ofp14_role_prop_header {
    ovs_be16 type;   /* One of OFPRPT_*. */
    ovs_be16 length; /* Length in bytes of this property. */
};
OFP_ASSERT(sizeof(struct ofp14_role_prop_header) == 4);

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
};

/* Role property types.
*/
enum ofp14_role_prop_type {
    OFPRPT_EXPERIMENTER         = 0xFFFF, /* Experimenter property. */
};

/* Experimenter role property */
struct ofp14_role_prop_experimenter {
    ovs_be16        type;       /* One of OFPRPT_EXPERIMENTER. */
    ovs_be16        length;     /* Length in bytes of this property. */
    ovs_be32        experimenter; /* Experimenter ID which takes the same
                                     form as in struct
                                     ofp_experimenter_header. */
    ovs_be32        exp_type;     /* Experimenter defined. */
    /* Followed by:
     *   - Exactly (length - 12) bytes containing the experimenter data, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
};
OFP_ASSERT(sizeof(struct ofp14_role_prop_experimenter) == 12);

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

#endif /* openflow/openflow-1.4.h */
