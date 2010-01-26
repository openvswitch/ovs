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

    /* Configure an action.  Most actions do not require configuration
     * beyond that supplied in the actual action call. */
    NXT_ACT_SET_CONFIG,

    /* Get configuration of action. */
    NXT_ACT_GET_CONFIG,

    /* No longer used. */
    NXT_COMMAND_REQUEST__OBSOLETE,

    /* No longer used. */
    NXT_COMMAND_REPLY__OBSOLETE,

    /* No longer used. */
    NXT_FLOW_END_CONFIG__OBSOLETE,

    /* No longer used. */
    NXT_FLOW_END__OBSOLETE,

    /* No longer used. */
    NXT_MGMT__OBSOLETE,
};

struct nicira_header {
    struct ofp_header header;
    uint32_t vendor;            /* NX_VENDOR_ID. */
    uint32_t subtype;           /* One of NXT_* above. */
};
OFP_ASSERT(sizeof(struct nicira_header) == 16);


enum nx_action_subtype {
    NXAST_SNAT__OBSOLETE,           /* No longer used. */
    NXAST_RESUBMIT                  /* Throw against flow table again. */
};

/* Action structure for NXAST_RESUBMIT. */
struct nx_action_resubmit {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 8. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_RESUBMIT. */
    uint16_t in_port;               /* New in_port for checking flow table. */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct nx_action_resubmit) == 16);

/* Header for Nicira-defined actions. */
struct nx_action_header {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 8. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_*. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct nx_action_header) == 16);

#endif /* openflow/nicira-ext.h */
