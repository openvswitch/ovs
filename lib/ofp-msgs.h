/*
 * Copyright (c) 2012, 2013 Nicira, Inc.
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

#ifndef OFP_MSGS_H
#define OFP_MSGS_H 1

/* OpenFlow message headers abstraction.
 *
 * OpenFlow headers are unnecessarily complicated:
 *
 *   - Some messages with the same meaning were renumbered between 1.0 and 1.1.
 *
 *   - "Statistics" (aka multipart) messages have a different format from other
 *     messages.
 *
 *   - The 1.0 header for statistics messages is an odd number of 32-bit words
 *     long, leaving 64-bit quantities in the body misaligned.  The 1.1 header
 *     for statistics added a padding word to fix this misalignment, although
 *     many statistic message bodies did not change.
 *
 *   - Vendor-defined messages have an additional header but no standard way to
 *     distinguish individual types of message within a given vendor.
 *
 * This file attempts to abstract out the differences between the various forms
 * of headers.
 */

#include "openvswitch/types.h"
#include "ofp-errors.h"
#include "util.h"

struct list;

/* Raw identifiers for OpenFlow messages.
 *
 * Some OpenFlow messages with similar meanings have multiple variants across
 * OpenFlow versions or vendor extensions.  Each variant has a different
 * OFPRAW_* enumeration constant.  More specifically, if two messages have
 * different types, different numbers, or different arguments, then they must
 * have different OFPRAW_* values.
 *
 * The comments here must follow a stylized form because the "extract-ofp-msgs"
 * program parses them at build time to generate data tables.  The syntax of
 * each comment is:
 *
 *    type versions (number): arguments.
 *
 * where the syntax of each part is:
 *
 *    - type: One of OFPT (standard OpenFlow message), OFPST (standard OpenFlow
 *      statistics message), NXT (Nicira extension message), or NXST (Nicira
 *      extension statistics message).
 *
 *      As new vendors implement extensions it will make sense to expand the
 *      dictionary of possible types.
 *
 *    - versions: The OpenFlow version or versions in which this message is
 *      supported, e.g. "1.0" or "1.1" or "1.0+".
 *
 *    - number:
 *         For OFPT, the 'type' in struct ofp_header.
 *         For OFPST, the 'type' in struct ofp_stats_msg or ofp11_stats_msg.
 *         For NXT, the 'subtype' in struct nicira_header.
 *         For NXST, the 'subtype' in struct nicira10_stats_msg or
 *           nicira11_stats_msg.
 *
 *    - arguments: The types of data that follow the OpenFlow headers (the
 *      message "body").  This can be "void" if the message has no body.
 *      Otherwise, it should be a comma-separated sequence of C types.  The
 *      last type in the sequence can end with [] if the body ends in a
 *      variable-length sequence.
 *
 *      The arguments are used to validate the lengths of messages when a
 *      header is parsed.  Any message whose length isn't valid as a length of
 *      the specified types will be rejected with OFPERR_OFPBRC_BAD_LEN.
 *
 *      A few OpenFlow messages, such as OFPT_PACKET_IN, intentionally end with
 *      only part of a structure, up to some specified member.  The syntax "up
 *      to <member>" indicates this, e.g. "struct ofp11_packet_in up to data".
 */
enum ofpraw {
/* Immutable standard messages.
 *
 * The OpenFlow standard promises to preserve these messages and their numbers
 * in future versions, so we mark them as <all>, which covers every OpenFlow
 * version numbered 0x01...0xff, rather than as OF1.0+, which covers only
 * OpenFlow versions that we otherwise implement.
 *
 * Without <all> here, then we would fail to decode "hello" messages that
 * announce a version higher than we understand, even though there still could
 * be a version in common with the peer that we do understand.  The <all>
 * keyword is less useful for the other messages, because our OpenFlow channels
 * accept only OpenFlow messages with a previously negotiated version.
 */

    /* OFPT <all> (0): uint8_t[]. */
    OFPRAW_OFPT_HELLO,

    /* OFPT <all> (1): struct ofp_error_msg, uint8_t[]. */
    OFPRAW_OFPT_ERROR,

    /* OFPT <all> (2): uint8_t[]. */
    OFPRAW_OFPT_ECHO_REQUEST,

    /* OFPT <all> (3): uint8_t[]. */
    OFPRAW_OFPT_ECHO_REPLY,

/* Other standard messages.
 *
 * The meanings of these messages can (and often do) change from one version
 * of OpenFlow to another. */

    /* OFPT 1.0+ (5): void. */
    OFPRAW_OFPT_FEATURES_REQUEST,

    /* OFPT 1.0 (6): struct ofp_switch_features, struct ofp10_phy_port[]. */
    OFPRAW_OFPT10_FEATURES_REPLY,
    /* OFPT 1.1-1.2 (6): struct ofp_switch_features, struct ofp11_port[]. */
    OFPRAW_OFPT11_FEATURES_REPLY,
    /* OFPT 1.3+ (6): struct ofp_switch_features. */
    OFPRAW_OFPT13_FEATURES_REPLY,

    /* OFPT 1.0+ (7): void. */
    OFPRAW_OFPT_GET_CONFIG_REQUEST,

    /* OFPT 1.0+ (8): struct ofp_switch_config. */
    OFPRAW_OFPT_GET_CONFIG_REPLY,

    /* OFPT 1.0+ (9): struct ofp_switch_config. */
    OFPRAW_OFPT_SET_CONFIG,

    /* OFPT 1.0 (10): struct ofp10_packet_in up to data, uint8_t[]. */
    OFPRAW_OFPT10_PACKET_IN,
    /* OFPT 1.1 (10): struct ofp11_packet_in, uint8_t[]. */
    OFPRAW_OFPT11_PACKET_IN,
    /* OFPT 1.2 (10): struct ofp12_packet_in, uint8_t[]. */
    OFPRAW_OFPT12_PACKET_IN,
    /* OFPT 1.3 (10): struct ofp13_packet_in, uint8_t[]. */
    OFPRAW_OFPT13_PACKET_IN,
    /* NXT 1.0+ (17): struct nx_packet_in, uint8_t[]. */
    OFPRAW_NXT_PACKET_IN,

    /* OFPT 1.0 (11): struct ofp10_flow_removed. */
    OFPRAW_OFPT10_FLOW_REMOVED,
    /* OFPT 1.1+ (11): struct ofp11_flow_removed, uint8_t[8][]. */
    OFPRAW_OFPT11_FLOW_REMOVED,
    /* NXT 1.0+ (14): struct nx_flow_removed, uint8_t[8][]. */
    OFPRAW_NXT_FLOW_REMOVED,

    /* OFPT 1.0 (12): struct ofp_port_status, struct ofp10_phy_port. */
    OFPRAW_OFPT10_PORT_STATUS,
    /* OFPT 1.1+ (12): struct ofp_port_status, struct ofp11_port. */
    OFPRAW_OFPT11_PORT_STATUS,

    /* OFPT 1.0 (13): struct ofp10_packet_out, uint8_t[]. */
    OFPRAW_OFPT10_PACKET_OUT,
    /* OFPT 1.1+ (13): struct ofp11_packet_out, uint8_t[]. */
    OFPRAW_OFPT11_PACKET_OUT,

    /* OFPT 1.0 (14): struct ofp10_flow_mod, struct ofp_action_header[]. */
    OFPRAW_OFPT10_FLOW_MOD,
    /* OFPT 1.1+ (14): struct ofp11_flow_mod, struct ofp11_instruction[]. */
    OFPRAW_OFPT11_FLOW_MOD,
    /* NXT 1.0+ (13): struct nx_flow_mod, uint8_t[8][]. */
    OFPRAW_NXT_FLOW_MOD,

    /* OFPT 1.1+ (15): struct ofp11_group_mod, uint8_t[8][]. */
    OFPRAW_OFPT11_GROUP_MOD,

    /* OFPT 1.0 (15): struct ofp10_port_mod. */
    OFPRAW_OFPT10_PORT_MOD,
    /* OFPT 1.1+ (16): struct ofp11_port_mod. */
    OFPRAW_OFPT11_PORT_MOD,

    /* OFPT 1.1+ (17): struct ofp11_table_mod. */
    OFPRAW_OFPT11_TABLE_MOD,

    /* OFPT 1.0 (18): void. */
    OFPRAW_OFPT10_BARRIER_REQUEST,
    /* OFPT 1.1+ (20): void. */
    OFPRAW_OFPT11_BARRIER_REQUEST,

    /* OFPT 1.0 (19): void. */
    OFPRAW_OFPT10_BARRIER_REPLY,
    /* OFPT 1.1+ (21): void. */
    OFPRAW_OFPT11_BARRIER_REPLY,

    /* OFPT 1.0 (22): struct ofp10_queue_get_config_request. */
    OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST,
    /* OFPT 1.1+ (22): struct ofp11_queue_get_config_request. */
    OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST,

    /* OFPT 1.0 (23): struct ofp10_queue_get_config_reply, uint8_t[8][]. */
    OFPRAW_OFPT10_QUEUE_GET_CONFIG_REPLY,
    /* OFPT 1.1+ (23): struct ofp11_queue_get_config_reply, uint8_t[8][]. */
    OFPRAW_OFPT11_QUEUE_GET_CONFIG_REPLY,

    /* OFPT 1.2+ (24): struct ofp12_role_request. */
    OFPRAW_OFPT12_ROLE_REQUEST,
    /* NXT 1.0+ (10): struct nx_role_request. */
    OFPRAW_NXT_ROLE_REQUEST,

    /* OFPT 1.2+ (25): struct ofp12_role_request. */
    OFPRAW_OFPT12_ROLE_REPLY,
    /* NXT 1.0+ (11): struct nx_role_request. */
    OFPRAW_NXT_ROLE_REPLY,

    /* OFPT 1.3+ (26): void. */
    OFPRAW_OFPT13_GET_ASYNC_REQUEST,
    /* OFPT 1.3+ (27): struct ofp13_async_config. */
    OFPRAW_OFPT13_GET_ASYNC_REPLY,
    /* OFPT 1.3+ (28): struct ofp13_async_config. */
    OFPRAW_OFPT13_SET_ASYNC,
    /* NXT 1.0+ (19): struct nx_async_config. */
    OFPRAW_NXT_SET_ASYNC_CONFIG,

    /* OFPT 1.3+ (29): struct ofp13_meter_mod, uint8_t[8][]. */
    OFPRAW_OFPT13_METER_MOD,

    /* OFPT 1.4+ (30): struct ofp14_role_status, uint8_t[8][]. */
    OFPRAW_OFPT14_ROLE_STATUS,

/* Standard statistics. */

    /* OFPST 1.0+ (0): void. */
    OFPRAW_OFPST_DESC_REQUEST,

    /* OFPST 1.0+ (0): struct ofp_desc_stats. */
    OFPRAW_OFPST_DESC_REPLY,

    /* OFPST 1.0 (1): struct ofp10_flow_stats_request. */
    OFPRAW_OFPST10_FLOW_REQUEST,
    /* OFPST 1.1+ (1): struct ofp11_flow_stats_request, uint8_t[8][]. */
    OFPRAW_OFPST11_FLOW_REQUEST,
    /* NXST 1.0 (0): struct nx_flow_stats_request, uint8_t[8][]. */
    OFPRAW_NXST_FLOW_REQUEST,

    /* OFPST 1.0 (1): uint8_t[]. */
    OFPRAW_OFPST10_FLOW_REPLY,
    /* OFPST 1.1-1.2 (1): uint8_t[]. */
    OFPRAW_OFPST11_FLOW_REPLY,
    /* OFPST 1.3+ (1): uint8_t[]. */
    OFPRAW_OFPST13_FLOW_REPLY,
    /* NXST 1.0 (0): uint8_t[]. */
    OFPRAW_NXST_FLOW_REPLY,

    /* OFPST 1.0 (2): struct ofp10_flow_stats_request. */
    OFPRAW_OFPST10_AGGREGATE_REQUEST,
    /* OFPST 1.1+ (2): struct ofp11_flow_stats_request, uint8_t[8][]. */
    OFPRAW_OFPST11_AGGREGATE_REQUEST,
    /* NXST 1.0 (1): struct nx_flow_stats_request, uint8_t[8][]. */
    OFPRAW_NXST_AGGREGATE_REQUEST,

    /* OFPST 1.0+ (2): struct ofp_aggregate_stats_reply. */
    OFPRAW_OFPST_AGGREGATE_REPLY,
    /* NXST 1.0 (1): struct ofp_aggregate_stats_reply. */
    OFPRAW_NXST_AGGREGATE_REPLY,

    /* OFPST 1.0+ (3): void. */
    OFPRAW_OFPST_TABLE_REQUEST,

    /* OFPST 1.0 (3): struct ofp10_table_stats[]. */
    OFPRAW_OFPST10_TABLE_REPLY,
    /* OFPST 1.1 (3): struct ofp11_table_stats[]. */
    OFPRAW_OFPST11_TABLE_REPLY,
    /* OFPST 1.2 (3): struct ofp12_table_stats[]. */
    OFPRAW_OFPST12_TABLE_REPLY,
    /* OFPST 1.3 (3): struct ofp13_table_stats[]. */
    OFPRAW_OFPST13_TABLE_REPLY,

    /* OFPST 1.0 (4): struct ofp10_port_stats_request. */
    OFPRAW_OFPST10_PORT_REQUEST,
    /* OFPST 1.1+ (4): struct ofp11_port_stats_request. */
    OFPRAW_OFPST11_PORT_REQUEST,

    /* OFPST 1.0 (4): struct ofp10_port_stats[]. */
    OFPRAW_OFPST10_PORT_REPLY,
    /* OFPST 1.1-1.2 (4): struct ofp11_port_stats[]. */
    OFPRAW_OFPST11_PORT_REPLY,
    /* OFPST 1.3+ (4): struct ofp13_port_stats[]. */
    OFPRAW_OFPST13_PORT_REPLY,

    /* OFPST 1.0 (5): struct ofp10_queue_stats_request. */
    OFPRAW_OFPST10_QUEUE_REQUEST,
    /* OFPST 1.1+ (5): struct ofp11_queue_stats_request. */
    OFPRAW_OFPST11_QUEUE_REQUEST,

    /* OFPST 1.0 (5): struct ofp10_queue_stats[]. */
    OFPRAW_OFPST10_QUEUE_REPLY,
    /* OFPST 1.1-1.2 (5): struct ofp11_queue_stats[]. */
    OFPRAW_OFPST11_QUEUE_REPLY,
    /* OFPST 1.3+ (5): struct ofp13_queue_stats[]. */
    OFPRAW_OFPST13_QUEUE_REPLY,

    /* OFPST 1.1+ (6): struct ofp11_group_stats_request. */
    OFPRAW_OFPST11_GROUP_REQUEST,

    /* OFPST 1.1-1.2 (6): uint8_t[8][]. */
    OFPRAW_OFPST11_GROUP_REPLY,
    /* OFPST 1.3 (6): uint8_t[8][]. */
    OFPRAW_OFPST13_GROUP_REPLY,

    /* OFPST 1.1+ (7): void. */
    OFPRAW_OFPST11_GROUP_DESC_REQUEST,

    /* OFPST 1.1+ (7): uint8_t[8][]. */
    OFPRAW_OFPST11_GROUP_DESC_REPLY,

    /* OFPST 1.2+ (8): void. */
    OFPRAW_OFPST12_GROUP_FEATURES_REQUEST,

    /* OFPST 1.2+ (8): struct ofp12_group_features_stats. */
    OFPRAW_OFPST12_GROUP_FEATURES_REPLY,

    /* OFPST 1.3+ (9): struct ofp13_meter_multipart_request. */
    OFPRAW_OFPST13_METER_REQUEST,

    /* OFPST 1.3+ (9): uint8_t[8][]. */
    OFPRAW_OFPST13_METER_REPLY,

    /* OFPST 1.3+ (10): struct ofp13_meter_multipart_request. */
    OFPRAW_OFPST13_METER_CONFIG_REQUEST,

    /* OFPST 1.3+ (10): uint8_t[8][]. */
    OFPRAW_OFPST13_METER_CONFIG_REPLY,

    /* OFPST 1.3+ (11): void. */
    OFPRAW_OFPST13_METER_FEATURES_REQUEST,

    /* OFPST 1.3+ (11): struct ofp13_meter_features. */
    OFPRAW_OFPST13_METER_FEATURES_REPLY,

    /* OFPST 1.3+ (12): void. */
    OFPRAW_OFPST13_TABLE_FEATURES_REQUEST,

    /* OFPST 1.3+ (12): struct ofp13_table_features, uint8_t[8][]. */
    OFPRAW_OFPST13_TABLE_FEATURES_REPLY,

    /* OFPST 1.0+ (13): void. */
    OFPRAW_OFPST_PORT_DESC_REQUEST,

    /* OFPST 1.0 (13): struct ofp10_phy_port[]. */
    OFPRAW_OFPST10_PORT_DESC_REPLY,
    /* OFPST 1.1+ (13): struct ofp11_port[]. */
    OFPRAW_OFPST11_PORT_DESC_REPLY,

/* Nicira extension messages.
 *
 * Nicira extensions that correspond to standard OpenFlow messages are listed
 * alongside the standard versions above. */

    /* NXT 1.0 (12): struct nx_set_flow_format. */
    OFPRAW_NXT_SET_FLOW_FORMAT,

    /* NXT 1.0+ (15): struct nx_flow_mod_table_id. */
    OFPRAW_NXT_FLOW_MOD_TABLE_ID,

    /* NXT 1.0+ (16): struct nx_set_packet_in_format. */
    OFPRAW_NXT_SET_PACKET_IN_FORMAT,

    /* NXT 1.0+ (18): void. */
    OFPRAW_NXT_FLOW_AGE,

    /* NXT 1.0+ (20): struct nx_controller_id. */
    OFPRAW_NXT_SET_CONTROLLER_ID,

    /* NXT 1.0+ (21): struct nx_flow_monitor_cancel. */
    OFPRAW_NXT_FLOW_MONITOR_CANCEL,

    /* NXT 1.0+ (22): void. */
    OFPRAW_NXT_FLOW_MONITOR_PAUSED,

    /* NXT 1.0+ (23): void. */
    OFPRAW_NXT_FLOW_MONITOR_RESUMED,

/* Nicira extension statistics.
 *
 * Nicira extension statistics that correspond to standard OpenFlow statistics
 * are listed alongside the standard versions above. */

    /* NXST 1.0 (2): uint8_t[8][]. */
    OFPRAW_NXST_FLOW_MONITOR_REQUEST,

    /* NXST 1.0 (2): uint8_t[8][]. */
    OFPRAW_NXST_FLOW_MONITOR_REPLY,
};

/* Decoding messages into OFPRAW_* values. */
enum ofperr ofpraw_decode(enum ofpraw *, const struct ofp_header *);
enum ofpraw ofpraw_decode_assert(const struct ofp_header *);
enum ofperr ofpraw_pull(enum ofpraw *, struct ofpbuf *);
enum ofpraw ofpraw_pull_assert(struct ofpbuf *);

enum ofperr ofpraw_decode_partial(enum ofpraw *,
                                  const struct ofp_header *, size_t length);

/* Encoding messages using OFPRAW_* values. */
struct ofpbuf *ofpraw_alloc(enum ofpraw, uint8_t ofp_version,
                            size_t extra_tailroom);
struct ofpbuf *ofpraw_alloc_xid(enum ofpraw, uint8_t ofp_version,
                                ovs_be32 xid, size_t extra_tailroom);
struct ofpbuf *ofpraw_alloc_reply(enum ofpraw,
                                  const struct ofp_header *request,
                                  size_t extra_tailroom);
struct ofpbuf *ofpraw_alloc_stats_reply(const struct ofp_header *request,
                                        size_t extra_tailroom);

void ofpraw_put(enum ofpraw, uint8_t ofp_version, struct ofpbuf *);
void ofpraw_put_xid(enum ofpraw, uint8_t ofp_version, ovs_be32 xid,
                    struct ofpbuf *);
void ofpraw_put_reply(enum ofpraw, const struct ofp_header *request,
                      struct ofpbuf *);
void ofpraw_put_stats_reply(const struct ofp_header *request, struct ofpbuf *);

/* Information about OFPRAW_* values. */
const char *ofpraw_get_name(enum ofpraw);
enum ofpraw ofpraw_stats_request_to_reply(enum ofpraw, uint8_t version);

/* Semantic identifiers for OpenFlow messages.
 *
 * Each OFPTYPE_* enumeration constant represents one or more concrete format
 * of OpenFlow message.  When two variants of a message have essentially the
 * same meaning, they are assigned a single OFPTYPE_* value.
 *
 * The comments here must follow a stylized form because the "extract-ofp-msgs"
 * program parses them at build time to generate data tables.  The format is
 * simply to list each OFPRAW_* enumeration constant for a given OFPTYPE_*,
 * each followed by a period. */
enum ofptype {
    /* Immutable messages. */
    OFPTYPE_HELLO,               /* OFPRAW_OFPT_HELLO. */
    OFPTYPE_ERROR,               /* OFPRAW_OFPT_ERROR. */
    OFPTYPE_ECHO_REQUEST,        /* OFPRAW_OFPT_ECHO_REQUEST. */
    OFPTYPE_ECHO_REPLY,          /* OFPRAW_OFPT_ECHO_REPLY. */

    /* Switch configuration messages. */
    OFPTYPE_FEATURES_REQUEST,    /* OFPRAW_OFPT_FEATURES_REQUEST. */
    OFPTYPE_FEATURES_REPLY,      /* OFPRAW_OFPT10_FEATURES_REPLY.
                                  * OFPRAW_OFPT11_FEATURES_REPLY.
                                  * OFPRAW_OFPT13_FEATURES_REPLY. */
    OFPTYPE_GET_CONFIG_REQUEST,  /* OFPRAW_OFPT_GET_CONFIG_REQUEST. */
    OFPTYPE_GET_CONFIG_REPLY,    /* OFPRAW_OFPT_GET_CONFIG_REPLY. */
    OFPTYPE_SET_CONFIG,          /* OFPRAW_OFPT_SET_CONFIG. */

    /* Asynchronous messages. */
    OFPTYPE_PACKET_IN,           /* OFPRAW_OFPT10_PACKET_IN.
                                  * OFPRAW_OFPT11_PACKET_IN.
                                  * OFPRAW_OFPT12_PACKET_IN.
                                  * OFPRAW_OFPT13_PACKET_IN.
                                  * OFPRAW_NXT_PACKET_IN. */
    OFPTYPE_FLOW_REMOVED,        /* OFPRAW_OFPT10_FLOW_REMOVED.
                                  * OFPRAW_OFPT11_FLOW_REMOVED.
                                  * OFPRAW_NXT_FLOW_REMOVED. */
    OFPTYPE_PORT_STATUS,         /* OFPRAW_OFPT10_PORT_STATUS.
                                  * OFPRAW_OFPT11_PORT_STATUS. */

    /* Controller command messages. */
    OFPTYPE_PACKET_OUT,          /* OFPRAW_OFPT10_PACKET_OUT.
                                  * OFPRAW_OFPT11_PACKET_OUT. */
    OFPTYPE_FLOW_MOD,            /* OFPRAW_OFPT10_FLOW_MOD.
                                  * OFPRAW_OFPT11_FLOW_MOD.
                                  * OFPRAW_NXT_FLOW_MOD. */
    OFPTYPE_GROUP_MOD,           /* OFPRAW_OFPT11_GROUP_MOD. */
    OFPTYPE_PORT_MOD,            /* OFPRAW_OFPT10_PORT_MOD.
                                  * OFPRAW_OFPT11_PORT_MOD. */
    OFPTYPE_TABLE_MOD,           /* OFPRAW_OFPT11_TABLE_MOD. */

    /* Barrier messages. */
    OFPTYPE_BARRIER_REQUEST,     /* OFPRAW_OFPT10_BARRIER_REQUEST.
                                  * OFPRAW_OFPT11_BARRIER_REQUEST. */
    OFPTYPE_BARRIER_REPLY,       /* OFPRAW_OFPT10_BARRIER_REPLY.
                                  * OFPRAW_OFPT11_BARRIER_REPLY. */

    /* Queue Configuration messages. */
    OFPTYPE_QUEUE_GET_CONFIG_REQUEST, /* OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST.
                                       * OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST. */
    OFPTYPE_QUEUE_GET_CONFIG_REPLY, /* OFPRAW_OFPT10_QUEUE_GET_CONFIG_REPLY.
                                     * OFPRAW_OFPT11_QUEUE_GET_CONFIG_REPLY. */

    /* Controller role change request messages. */
    OFPTYPE_ROLE_REQUEST,         /* OFPRAW_OFPT12_ROLE_REQUEST.
                                   * OFPRAW_NXT_ROLE_REQUEST. */
    OFPTYPE_ROLE_REPLY,           /* OFPRAW_OFPT12_ROLE_REPLY.
                                   * OFPRAW_NXT_ROLE_REPLY. */

    /* Asynchronous message configuration. */
    OFPTYPE_GET_ASYNC_REQUEST,    /* OFPRAW_OFPT13_GET_ASYNC_REQUEST. */
    OFPTYPE_GET_ASYNC_REPLY,      /* OFPRAW_OFPT13_GET_ASYNC_REPLY. */
    OFPTYPE_SET_ASYNC_CONFIG,     /* OFPRAW_NXT_SET_ASYNC_CONFIG.
                                   * OFPRAW_OFPT13_SET_ASYNC. */

    /* Meters and rate limiters configuration messages. */
    OFPTYPE_METER_MOD,            /* OFPRAW_OFPT13_METER_MOD. */

    /* Controller role change event messages. */
    OFPTYPE_ROLE_STATUS,          /* OFPRAW_OFPT14_ROLE_STATUS. */

    /* Statistics. */
    OFPTYPE_DESC_STATS_REQUEST,      /* OFPRAW_OFPST_DESC_REQUEST. */
    OFPTYPE_DESC_STATS_REPLY,        /* OFPRAW_OFPST_DESC_REPLY. */
    OFPTYPE_FLOW_STATS_REQUEST,      /* OFPRAW_OFPST10_FLOW_REQUEST.
                                      * OFPRAW_OFPST11_FLOW_REQUEST.
                                      * OFPRAW_NXST_FLOW_REQUEST. */
    OFPTYPE_FLOW_STATS_REPLY,        /* OFPRAW_OFPST10_FLOW_REPLY.
                                      * OFPRAW_OFPST11_FLOW_REPLY.
                                      * OFPRAW_OFPST13_FLOW_REPLY.
                                      * OFPRAW_NXST_FLOW_REPLY. */
    OFPTYPE_AGGREGATE_STATS_REQUEST, /* OFPRAW_OFPST10_AGGREGATE_REQUEST.
                                      * OFPRAW_OFPST11_AGGREGATE_REQUEST.
                                      * OFPRAW_NXST_AGGREGATE_REQUEST. */
    OFPTYPE_AGGREGATE_STATS_REPLY,   /* OFPRAW_OFPST_AGGREGATE_REPLY.
                                      * OFPRAW_NXST_AGGREGATE_REPLY. */
    OFPTYPE_TABLE_STATS_REQUEST,     /* OFPRAW_OFPST_TABLE_REQUEST. */
    OFPTYPE_TABLE_STATS_REPLY,       /* OFPRAW_OFPST10_TABLE_REPLY.
                                      * OFPRAW_OFPST11_TABLE_REPLY.
                                      * OFPRAW_OFPST12_TABLE_REPLY.
                                      * OFPRAW_OFPST13_TABLE_REPLY. */
    OFPTYPE_PORT_STATS_REQUEST,      /* OFPRAW_OFPST10_PORT_REQUEST.
                                      * OFPRAW_OFPST11_PORT_REQUEST. */
    OFPTYPE_PORT_STATS_REPLY,        /* OFPRAW_OFPST10_PORT_REPLY.
                                      * OFPRAW_OFPST11_PORT_REPLY.
                                      * OFPRAW_OFPST13_PORT_REPLY. */
    OFPTYPE_QUEUE_STATS_REQUEST,     /* OFPRAW_OFPST10_QUEUE_REQUEST.
                                      * OFPRAW_OFPST11_QUEUE_REQUEST. */
    OFPTYPE_QUEUE_STATS_REPLY,       /* OFPRAW_OFPST10_QUEUE_REPLY.
                                      * OFPRAW_OFPST11_QUEUE_REPLY.
                                      * OFPRAW_OFPST13_QUEUE_REPLY. */

    OFPTYPE_GROUP_STATS_REQUEST,     /* OFPRAW_OFPST11_GROUP_REQUEST. */

    OFPTYPE_GROUP_STATS_REPLY,       /* OFPRAW_OFPST11_GROUP_REPLY.
                                      * OFPRAW_OFPST13_GROUP_REPLY. */

    OFPTYPE_GROUP_DESC_STATS_REQUEST, /* OFPRAW_OFPST11_GROUP_DESC_REQUEST. */

    OFPTYPE_GROUP_DESC_STATS_REPLY,  /* OFPRAW_OFPST11_GROUP_DESC_REPLY. */

    OFPTYPE_GROUP_FEATURES_STATS_REQUEST, /* OFPRAW_OFPST12_GROUP_FEATURES_REQUEST. */

    OFPTYPE_GROUP_FEATURES_STATS_REPLY, /* OFPRAW_OFPST12_GROUP_FEATURES_REPLY. */

    OFPTYPE_METER_STATS_REQUEST,     /* OFPRAW_OFPST13_METER_REQUEST. */

    OFPTYPE_METER_STATS_REPLY,       /* OFPRAW_OFPST13_METER_REPLY. */

    OFPTYPE_METER_CONFIG_STATS_REQUEST, /* OFPRAW_OFPST13_METER_CONFIG_REQUEST. */

    OFPTYPE_METER_CONFIG_STATS_REPLY, /* OFPRAW_OFPST13_METER_CONFIG_REPLY. */

    OFPTYPE_METER_FEATURES_STATS_REQUEST, /* OFPRAW_OFPST13_METER_FEATURES_REQUEST. */

    OFPTYPE_METER_FEATURES_STATS_REPLY, /* OFPRAW_OFPST13_METER_FEATURES_REPLY. */

    OFPTYPE_TABLE_FEATURES_STATS_REQUEST, /* OFPRAW_OFPST13_TABLE_FEATURES_REQUEST. */

    OFPTYPE_TABLE_FEATURES_STATS_REPLY, /* OFPRAW_OFPST13_TABLE_FEATURES_REPLY. */

    OFPTYPE_PORT_DESC_STATS_REQUEST, /* OFPRAW_OFPST_PORT_DESC_REQUEST. */

    OFPTYPE_PORT_DESC_STATS_REPLY,   /* OFPRAW_OFPST10_PORT_DESC_REPLY.
                                      * OFPRAW_OFPST11_PORT_DESC_REPLY. */

    /* Nicira extensions. */
    OFPTYPE_SET_FLOW_FORMAT,      /* OFPRAW_NXT_SET_FLOW_FORMAT. */
    OFPTYPE_FLOW_MOD_TABLE_ID,    /* OFPRAW_NXT_FLOW_MOD_TABLE_ID. */
    OFPTYPE_SET_PACKET_IN_FORMAT, /* OFPRAW_NXT_SET_PACKET_IN_FORMAT. */
    OFPTYPE_FLOW_AGE,             /* OFPRAW_NXT_FLOW_AGE. */
    OFPTYPE_SET_CONTROLLER_ID,    /* OFPRAW_NXT_SET_CONTROLLER_ID. */

    /* Flow monitor extension. */
    OFPTYPE_FLOW_MONITOR_STATS_REQUEST, /* OFPRAW_NXST_FLOW_MONITOR_REQUEST. */
    OFPTYPE_FLOW_MONITOR_STATS_REPLY,   /* OFPRAW_NXST_FLOW_MONITOR_REPLY. */
    OFPTYPE_FLOW_MONITOR_CANCEL,        /* OFPRAW_NXT_FLOW_MONITOR_CANCEL. */
    OFPTYPE_FLOW_MONITOR_PAUSED,        /* OFPRAW_NXT_FLOW_MONITOR_PAUSED. */
    OFPTYPE_FLOW_MONITOR_RESUMED,       /* OFPRAW_NXT_FLOW_MONITOR_RESUMED. */
};

/* Decoding messages into OFPTYPE_* values. */
enum ofperr ofptype_decode(enum ofptype *, const struct ofp_header *);
enum ofperr ofptype_pull(enum ofptype *, struct ofpbuf *);
enum ofptype ofptype_from_ofpraw(enum ofpraw);

/* OpenFlow message properties. */
void ofpmsg_update_length(struct ofpbuf *);
const void *ofpmsg_body(const struct ofp_header *);
bool ofpmsg_is_stat_request(const struct ofp_header *);

/* Multipart messages (aka "statistics").
 *
 * Individual OpenFlow messages are limited to 64 kB in size, but some messages
 * need to be longer.  Therefore, multipart messages allow a longer message to
 * be divided into multiple parts at some convenient boundary.  For example,
 * limiting the response to a "flow dump" request to 64 kB would unreasonably
 * limit the maximum number of flows in an OpenFlow switch, so a "flow dump" is
 * expressed as a multipart request/reply pair, with the reply broken into
 * pieces between flows.
 *
 * Multipart messages always consist of a request/reply pair.
 *
 * In OpenFlow 1.0, 1.1, and 1.2, requests must always fit in a single message,
 * that is, only a multipart reply may have more than one part.  OpenFlow 1.3
 * adds one multipart request.  This code does not yet support multipart
 * requests. */

/* Encoding multipart replies.
 *
 * These functions are useful for multipart replies that might really require
 * more than one message.  A multipart message that is known in advance to fit
 * within 64 kB doesn't need any special treatment, so you might as well use
 * the ofpraw_alloc_*() functions.
 *
 * These functions work with a "struct list" of "struct ofpbuf"s, each of
 * which represents one part of a multipart message. */
void ofpmp_init(struct list *, const struct ofp_header *request);
struct ofpbuf *ofpmp_reserve(struct list *, size_t len);
void *ofpmp_append(struct list *, size_t len);
void ofpmp_postappend(struct list *, size_t start_ofs);

/* Decoding multipart replies. */
uint16_t ofpmp_flags(const struct ofp_header *);
bool ofpmp_more(const struct ofp_header *);

#endif /* ofp-msgs.h */
