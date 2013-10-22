/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
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
/*
 * OpenFlow 1.4 is more extensible by using TLV structures
 */

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

#endif /* openflow/openflow-1.4.h */
