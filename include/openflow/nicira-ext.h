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

#define NICIRA_OUI_STR "002320"

/* The following vendor extensions, proposed by Nicira Networks, are not yet
 * ready for standardization (and may never be), so they are not included in
 * openflow.h. */

#define NX_VENDOR_ID 0x00002320

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
