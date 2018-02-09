/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_OFP_SWITCH_H
#define OPENVSWITCH_OFP_SWITCH_H 1

#include "openflow/openflow.h"
#include "openvswitch/ofp-protocol.h"

struct ofpbuf;
struct ofputil_phy_port;

#ifdef __cplusplus
extern "C" {
#endif

enum ofputil_capabilities {
    /* All OpenFlow versions share these capability values. */
    OFPUTIL_C_FLOW_STATS     = 1 << 0,  /* Flow statistics. */
    OFPUTIL_C_TABLE_STATS    = 1 << 1,  /* Table statistics. */
    OFPUTIL_C_PORT_STATS     = 1 << 2,  /* Port statistics. */
    OFPUTIL_C_IP_REASM       = 1 << 5,  /* Can reassemble IP fragments. */
    OFPUTIL_C_QUEUE_STATS    = 1 << 6,  /* Queue statistics. */

    /* OpenFlow 1.0 and 1.1 share this capability. */
    OFPUTIL_C_ARP_MATCH_IP   = 1 << 7,  /* Match IP addresses in ARP pkts. */

    /* OpenFlow 1.0 only. */
    OFPUTIL_C_STP            = 1 << 3,  /* 802.1d spanning tree. */

    /* OpenFlow 1.1+ only.  Note that this bit value does not match the one
     * in the OpenFlow message. */
    OFPUTIL_C_GROUP_STATS    = 1 << 4,  /* Group statistics. */

    /* OpenFlow 1.2+ only. */
    OFPUTIL_C_PORT_BLOCKED   = 1 << 8,  /* Switch will block looping ports */

    /* OpenFlow 1.4+ only. */
    OFPUTIL_C_BUNDLES         = 1 << 9,  /* Switch supports bundles. */
    OFPUTIL_C_FLOW_MONITORING = 1 << 10, /* Switch supports flow monitoring. */
};

/* Abstract ofp_switch_features. */
struct ofputil_switch_features {
    uint64_t datapath_id;       /* Datapath unique ID. */
    uint32_t n_buffers;         /* Max packets buffered at once. */
    uint8_t n_tables;           /* Number of tables supported by datapath. */
    uint8_t auxiliary_id;       /* Identify auxiliary connections */
    enum ofputil_capabilities capabilities;
    uint64_t ofpacts;           /* Bitmap of OFPACT_* bits. */
};

enum ofperr ofputil_pull_switch_features(struct ofpbuf *,
                                         struct ofputil_switch_features *);

struct ofpbuf *ofputil_encode_switch_features(
    const struct ofputil_switch_features *, enum ofputil_protocol,
    ovs_be32 xid);
void ofputil_put_switch_features_port(const struct ofputil_phy_port *,
                                      struct ofpbuf *);
bool ofputil_switch_features_has_ports(struct ofpbuf *b);

enum ofputil_frag_handling {
    OFPUTIL_FRAG_NORMAL = OFPC_FRAG_NORMAL,    /* No special handling. */
    OFPUTIL_FRAG_DROP = OFPC_FRAG_DROP,        /* Drop fragments. */
    OFPUTIL_FRAG_REASM = OFPC_FRAG_REASM,      /* Reassemble (if supported). */
    OFPUTIL_FRAG_NX_MATCH = OFPC_FRAG_NX_MATCH /* Match on frag bits. */
};

const char *ofputil_frag_handling_to_string(enum ofputil_frag_handling);
bool ofputil_frag_handling_from_string(const char *,
                                       enum ofputil_frag_handling *);

/* Abstract struct ofp_switch_config. */
struct ofputil_switch_config {
    /* Fragment handling. */
    enum ofputil_frag_handling frag;

    /* 0: Do not send packet to controller when decrementing invalid IP TTL.
     * 1: Do send packet to controller when decrementing invalid IP TTL.
     * -1: Unspecified (only OpenFlow 1.1 and 1.2 support this setting. */
    int invalid_ttl_to_controller;

    /* Maximum bytes of packet to send to controller on miss. */
    uint16_t miss_send_len;
};

void ofputil_decode_get_config_reply(const struct ofp_header *,
                                     struct ofputil_switch_config *);
struct ofpbuf *ofputil_encode_get_config_reply(
    const struct ofp_header *request, const struct ofputil_switch_config *);

enum ofperr ofputil_decode_set_config(const struct ofp_header *,
                                      struct ofputil_switch_config *);
struct ofpbuf *ofputil_encode_set_config(
    const struct ofputil_switch_config *, enum ofp_version);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-switch.h */
