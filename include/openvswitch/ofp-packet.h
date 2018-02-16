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

#ifndef OPENVSWITCH_OFP_PACKET_H
#define OPENVSWITCH_OFP_PACKET_H 1

#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-protocol.h"
#include "openvswitch/type-props.h"
#include "openvswitch/uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vl_mff_map;
struct ofputil_table_map;

/* Packet-in format.
 *
 * For any given OpenFlow version, Open vSwitch supports multiple formats for
 * "packet-in" messages.  The default is always the standard format for the
 * OpenFlow version in question, but the Open vSwitch extension request
 * NXT_SET_PACKET_IN_FORMAT can be used to set an alternative format.
 *
 * From OVS v1.1 to OVS v2.5, this request was only honored for OpenFlow 1.0.
 * Requests to set format NXPIF_NXT_PACKET_IN were accepted for OF1.1+ but they
 * had no effect.  (Requests to set formats other than NXPIF_STANDARD or
 * NXPIF_NXT_PACKET_IN were rejected with OFPBRC_EPERM.)
 *
 * From OVS v2.6 onward, this request is honored for all OpenFlow versions.
 */
enum ofputil_packet_in_format {
    OFPUTIL_PACKET_IN_STD = 0,  /* OFPT_PACKET_IN for this OpenFlow version. */
    OFPUTIL_PACKET_IN_NXT = 1,  /* NXT_PACKET_IN (since OVS v1.1). */
    OFPUTIL_PACKET_IN_NXT2 = 2, /* NXT_PACKET_IN2 (since OVS v2.6). */
};

int ofputil_packet_in_format_from_string(const char *);
const char *ofputil_packet_in_format_to_string(enum ofputil_packet_in_format);
struct ofpbuf *ofputil_encode_set_packet_in_format(
    enum ofp_version, enum ofputil_packet_in_format);
enum ofperr ofputil_decode_set_packet_in_format(
    const struct ofp_header *, enum ofputil_packet_in_format *);

/* Abstract packet-in message.
 *
 * This omits the 'total_len' and 'buffer_id' fields, which we handle
 * differently for encoding and decoding.*/
struct ofputil_packet_in {
    /* Packet data and metadata.
     *
     * On encoding, the full packet should be supplied, but depending on its
     * other parameters ofputil_encode_packet_in() might send only the first
     * part of the packet.
     *
     * On decoding, the 'len' bytes in 'packet' might only be the first part of
     * the original packet.  ofputil_decode_packet_in() reports the full
     * original length of the packet using its 'total_len' output parameter. */
    void *packet;               /* The packet. */
    size_t packet_len;          /* Length of 'packet' in bytes. */

    /* Input port and other metadata for packet. */
    struct match flow_metadata;

    /* Reason that the packet-in is being sent. */
    enum ofp_packet_in_reason reason;    /* One of OFPR_*. */

    /* Information about the OpenFlow flow that triggered the packet-in.
     *
     * A packet-in triggered by a flow table miss has no associated flow.  In
     * that case, 'cookie' is UINT64_MAX. */
    uint8_t table_id;                    /* OpenFlow table ID. */
    ovs_be64 cookie;                     /* Flow's cookie. */

    /* Arbitrary user-provided data. */
    uint8_t *userdata;
    size_t userdata_len;
};

void ofputil_packet_in_destroy(struct ofputil_packet_in *);

enum ofperr ofputil_decode_packet_in(const struct ofp_header *, bool loose,
                                     const struct tun_table *,
                                     const struct vl_mff_map *,
                                     struct ofputil_packet_in *,
                                     size_t *total_len, uint32_t *buffer_id,
                                     struct ofpbuf *continuation);

struct ofpbuf *ofputil_encode_resume(const struct ofputil_packet_in *pin,
                                     const struct ofpbuf *continuation,
                                     enum ofputil_protocol);

enum { OFPUTIL_PACKET_IN_REASON_BUFSIZE = INT_STRLEN(int) + 1 };
const char *ofputil_packet_in_reason_to_string(enum ofp_packet_in_reason,
                                               char *reasonbuf,
                                               size_t bufsize);
bool ofputil_packet_in_reason_from_string(const char *,
                                          enum ofp_packet_in_reason *);

/* A packet-in message, including continuation data.  The format of
 * continuation data is subject to change and thus it is supposed to be opaque
 * to any process other than ovs-vswitchd.  Therefore, only ovs-vswitchd should
 * use ofputil_packet_in_private and the functions that operate on it. */
struct ofputil_packet_in_private {
    struct ofputil_packet_in base;

    /* NXCPT_BRIDGE. */
    struct uuid bridge;

    /* NXCPT_STACK. */
    uint8_t *stack;
    size_t stack_size;

    /* NXCPT_MIRRORS. */
    uint32_t mirrors;

    /* NXCPT_CONNTRACKED. */
    bool conntracked;

    /* NXCPT_ACTIONS. */
    struct ofpact *actions;
    size_t actions_len;

    /* NXCPT_ACTION_SET. */
    struct ofpact *action_set;
    size_t action_set_len;
};

struct ofpbuf *ofputil_encode_packet_in_private(
    const struct ofputil_packet_in_private *,
    enum ofputil_protocol protocol,
    enum ofputil_packet_in_format);

enum ofperr ofputil_decode_packet_in_private(
    const struct ofp_header *, bool loose,
    const struct tun_table *,
    const struct vl_mff_map *,
    struct ofputil_packet_in_private *,
    size_t *total_len, uint32_t *buffer_id);

void ofputil_packet_in_private_format(
    struct ds *, const struct ofputil_packet_in_private *,
    size_t total_len, uint32_t buffer_id,
    const struct ofputil_port_map *,
    const struct ofputil_table_map *, int verbosity);

void ofputil_packet_in_private_destroy(struct ofputil_packet_in_private *);

/* Abstract packet-out message.
 *
 * ofputil_decode_packet_out() will ensure that 'in_port' is a physical port
 * (OFPP_MAX or less) or one of OFPP_LOCAL, OFPP_NONE, or OFPP_CONTROLLER. */
struct ofputil_packet_out {
    const void *packet;         /* Packet data, if buffer_id == UINT32_MAX. */
    size_t packet_len;          /* Length of packet data in bytes. */
    uint32_t buffer_id;         /* Buffer id or UINT32_MAX if no buffer. */
    struct match flow_metadata; /* Packet's input port and other metadata. */
    struct ofpact *ofpacts;     /* Actions. */
    size_t ofpacts_len;         /* Size of ofpacts in bytes. */
};

enum ofperr ofputil_decode_packet_out(struct ofputil_packet_out *,
                                      const struct ofp_header *,
                                      const struct tun_table *,
                                      struct ofpbuf *ofpacts);
struct ofpbuf *ofputil_encode_packet_out(const struct ofputil_packet_out *,
                                         enum ofputil_protocol protocol);

void ofputil_packet_out_format(struct ds *, const struct ofputil_packet_out *,
                               const struct ofputil_port_map *,
                               const struct ofputil_table_map *,
                               int verbosity);

char *parse_ofp_packet_out_str(struct ofputil_packet_out *, const char *,
                               const struct ofputil_port_map *,
                               const struct ofputil_table_map *,
                               enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif  /* ofp-packet.h */
