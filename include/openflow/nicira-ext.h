/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks
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

#ifndef OPENFLOW_NICIRA_EXT_H
#define OPENFLOW_NICIRA_EXT_H 1

#include "openflow/openflow.h"

/* The following vendor extensions, proposed by Nicira Networks, are not yet
 * standardized, so they are not included in openflow.h.  Some of them may be
 * suitable for standardization; others we never expect to standardize. */

#define NX_VENDOR_ID 0x00002320

/* Nicira vendor-specific error messages extension.
 *
 * OpenFlow 1.0 has a set of predefined error types (OFPET_*) and codes (which
 * are specific to each type).  It does not have any provision for
 * vendor-specific error codes, and it does not even provide "generic" error
 * codes that can apply to problems not anticipated by the OpenFlow
 * specification authors.
 *
 * This extension attempts to address the problem by adding a generic "error
 * vendor extension".  The extension works as follows: use NXET_VENDOR as type
 * and NXVC_VENDOR_CODE as code, followed by struct nx_vendor_error with
 * vendor-specific details, followed by at least 64 bytes of the failed
 * request.
 *
 * It would be better to have type-specific vendor extension, e.g. so that
 * OFPET_BAD_ACTION could be used with vendor-specific code values.  But
 * OFPET_BAD_ACTION and most other standardized types already specify that
 * their 'data' values are (the start of) the OpenFlow message being replied
 * to, so there is no room to insert a vendor ID.
 *
 * Currently this extension is only implemented by Open vSwitch, but it seems
 * like a reasonable candidate for future standardization.
 */

/* This is a random number to avoid accidental collision with any other
 * vendor's extension. */
#define NXET_VENDOR 0xb0c2

/* ofp_error msg 'code' values for NXET_VENDOR. */
enum nx_vendor_code {
    NXVC_VENDOR_ERROR           /* 'data' contains struct nx_vendor_error. */
};

/* 'data' for 'type' == NXET_VENDOR, 'code' == NXVC_VENDOR_ERROR. */
struct nx_vendor_error {
    uint32_t vendor;            /* Vendor ID as in struct ofp_vendor_header. */
    uint16_t type;              /* Vendor-defined type. */
    uint16_t code;              /* Vendor-defined subtype. */
    /* Followed by at least the first 64 bytes of the failed request. */
};

/* Nicira vendor requests and replies. */

enum nicira_type {
    /* Switch status request.  The request body is an ASCII string that
     * specifies a prefix of the key names to include in the output; if it is
     * the null string, then all key-value pairs are included. */
    NXT_STATUS_REQUEST,

    /* Switch status reply.  The reply body is an ASCII string of key-value
     * pairs in the form "key=value\n". */
    NXT_STATUS_REPLY,

    /* No longer used. */
    NXT_ACT_SET_CONFIG__OBSOLETE,
    NXT_ACT_GET_CONFIG__OBSOLETE,
    NXT_COMMAND_REQUEST__OBSOLETE,
    NXT_COMMAND_REPLY__OBSOLETE,
    NXT_FLOW_END_CONFIG__OBSOLETE,
    NXT_FLOW_END__OBSOLETE,
    NXT_MGMT__OBSOLETE,

    /* Use the high 32 bits of the cookie field as the tunnel ID in the flow
     * match. */
    NXT_TUN_ID_FROM_COOKIE,

    /* Controller role support.  The request body is struct nx_role_request.
     * The reply echos the request. */
    NXT_ROLE_REQUEST,
    NXT_ROLE_REPLY,

    /* Use the upper 8 bits of the 'command' member in struct ofp_flow_mod to
     * designate the table to which a flow is to be added?  See the big comment
     * on struct nxt_flow_mod_table_id for more information. */
    NXT_FLOW_MOD_TABLE_ID
};

struct nicira_header {
    struct ofp_header header;
    uint32_t vendor;            /* NX_VENDOR_ID. */
    uint32_t subtype;           /* One of NXT_* above. */
};
OFP_ASSERT(sizeof(struct nicira_header) == 16);

struct nxt_tun_id_cookie {
    struct ofp_header header;
    uint32_t vendor;            /* NX_VENDOR_ID. */
    uint32_t subtype;           /* NXT_TUN_ID_FROM_COOKIE */
    uint8_t set;                /* Nonzero to enable, zero to disable. */
    uint8_t pad[7];
};
OFP_ASSERT(sizeof(struct nxt_tun_id_cookie) == 24);

/* This command enables or disables an Open vSwitch extension that allows a
 * controller to specify the OpenFlow table to which a flow should be added,
 * instead of having the switch decide which table is most appropriate as
 * required by OpenFlow 1.0.  By default, the extension is disabled.
 *
 * When this feature is enabled, Open vSwitch treats struct ofp_flow_mod's
 * 16-bit 'command' member as two separate fields.  The upper 8 bits are used
 * as the table ID, the lower 8 bits specify the command as usual.  A table ID
 * of 0xff is treated like a wildcarded table ID.
 *
 * The specific treatment of the table ID depends on the type of flow mod:
 *
 *    - OFPFC_ADD: Given a specific table ID, the flow is always placed in that
 *      table.  If an identical flow already exists in that table only, then it
 *      is replaced.  If the flow cannot be placed in the specified table,
 *      either because the table is full or because the table cannot support
 *      flows of the given type, the switch replies with an
 *      OFPFMFC_ALL_TABLES_FULL error.  (A controller can distinguish these
 *      cases by comparing the current and maximum number of entries reported
 *      in ofp_table_stats.)
 *
 *      If the table ID is wildcarded, the switch picks an appropriate table
 *      itself.  If an identical flow or flows already exist in some flow
 *      table, then one of them is replaced.  The choice of table might depend
 *      on the flows that are already in the switch; for example, if one table
 *      fills up then the switch might fall back to another one.
 *
 *    - OFPFC_MODIFY, OFPFC_DELETE: Given a specific table ID, only flows
 *      within that table are matched and modified or deleted.  If the table ID
 *      is wildcarded, flows within any table may be matched and modified or
 *      deleted.
 *
 *    - OFPFC_MODIFY_STRICT, OFPFC_DELETE_STRICT: Given a specific table ID,
 *      only a flow within that table may be matched and modified or deleted.
 *      If the table ID is wildcarded and exactly one flow within any table
 *      matches, then it is modified or deleted; if flows in more than one
 *      table match, then none is modified or deleted.
 */
struct nxt_flow_mod_table_id {
    struct ofp_header header;
    uint32_t vendor;            /* NX_VENDOR_ID. */
    uint32_t subtype;           /* NXT_FLOW_MOD_TABLE_ID. */
    uint8_t set;                /* Nonzero to enable, zero to disable. */
    uint8_t pad[7];
};
OFP_ASSERT(sizeof(struct nxt_flow_mod_table_id) == 24);

/* Configures the "role" of the sending controller.  The default role is:
 *
 *    - Other (NX_ROLE_OTHER), which allows the controller access to all
 *      OpenFlow features.
 *
 * The other possible roles are a related pair:
 *
 *    - Master (NX_ROLE_MASTER) is equivalent to Other, except that there may
 *      be at most one Master controller at a time: when a controller
 *      configures itself as Master, any existing Master is demoted to the
 *      Slave role.
 *
 *    - Slave (NX_ROLE_SLAVE) allows the controller read-only access to
 *      OpenFlow features.  In particular attempts to modify the flow table
 *      will be rejected with an OFPBRC_EPERM error.
 *
 *      Slave controllers also do not receive asynchronous messages
 *      (OFPT_PACKET_IN, OFPT_FLOW_REMOVED, OFPT_PORT_STATUS).
 */
struct nx_role_request {
    struct nicira_header nxh;
    uint32_t role;              /* One of NX_ROLE_*. */
};

enum nx_role {
    NX_ROLE_OTHER,              /* Default role, full access. */
    NX_ROLE_MASTER,             /* Full access, at most one. */
    NX_ROLE_SLAVE               /* Read-only access. */
};

/* Nicira vendor flow actions. */

enum nx_action_subtype {
    NXAST_SNAT__OBSOLETE,           /* No longer used. */

    /* Searches the flow table again, using a flow that is slightly modified
     * from the original lookup:
     *
     *    - The 'in_port' member of struct nx_action_resubmit is used as the
     *      flow's in_port.
     *
     *    - If NXAST_RESUBMIT is preceded by actions that affect the flow
     *      (e.g. OFPAT_SET_VLAN_VID), then the flow is updated with the new
     *      values.
     *
     * Following the lookup, the original in_port is restored.
     *
     * If the modified flow matched in the flow table, then the corresponding
     * actions are executed, except that NXAST_RESUBMIT actions found in the
     * secondary set of actions are ignored.  Afterward, actions following
     * NXAST_RESUBMIT in the original set of actions, if any, are executed; any
     * changes made to the packet (e.g. changes to VLAN) by secondary actions
     * persist when those actions are executed, although the original in_port
     * is restored.
     *
     * NXAST_RESUBMIT may be used any number of times within a set of actions.
     */
    NXAST_RESUBMIT,

    NXAST_SET_TUNNEL                /* Set encapsulating tunnel ID. */
};

/* Action structure for NXAST_RESUBMIT. */
struct nx_action_resubmit {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_RESUBMIT. */
    uint16_t in_port;               /* New in_port for checking flow table. */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct nx_action_resubmit) == 16);

/* Action structure for NXAST_SET_TUNNEL. */
struct nx_action_set_tunnel {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_SET_TUNNEL. */
    uint8_t pad[2];
    uint32_t tun_id;                /* Tunnel ID. */
};
OFP_ASSERT(sizeof(struct nx_action_set_tunnel) == 16);

/* Header for Nicira-defined actions. */
struct nx_action_header {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_*. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct nx_action_header) == 16);

/* Wildcard for tunnel ID. */
#define NXFW_TUN_ID  (1 << 25)

#define NXFW_ALL NXFW_TUN_ID
#define OVSFW_ALL (OFPFW_ALL | NXFW_ALL)

#endif /* openflow/nicira-ext.h */
