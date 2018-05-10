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

#ifndef OPENVSWITCH_OFP_FLOW_H
#define OPENVSWITCH_OFP_FLOW_H 1

#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-protocol.h"

struct vl_mff_map;
struct ofputil_port_map;
struct ofputil_table_map;

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol-independent flow_mod flags. */
enum ofputil_flow_mod_flags {
    /* Flags that are maintained with a flow as part of its state.
     *
     * (OFPUTIL_FF_EMERG would be here too, if OVS supported it.) */
    OFPUTIL_FF_SEND_FLOW_REM = 1 << 0, /* All versions. */
    OFPUTIL_FF_NO_PKT_COUNTS = 1 << 1, /* OpenFlow 1.3+. */
    OFPUTIL_FF_NO_BYT_COUNTS = 1 << 2, /* OpenFlow 1.3+. */

    /* These flags primarily affects flow_mod behavior.  They are not
     * particularly useful as part of flow state.  We include them in flow
     * state only because OpenFlow implies that they should be. */
    OFPUTIL_FF_CHECK_OVERLAP = 1 << 3, /* All versions. */
    OFPUTIL_FF_RESET_COUNTS  = 1 << 4, /* OpenFlow 1.2+. */

    /* Not supported by OVS. */
    OFPUTIL_FF_EMERG         = 1 << 5, /* OpenFlow 1.0 only. */

    /* The set of flags maintained as part of a flow table entry. */
#define OFPUTIL_FF_STATE (OFPUTIL_FF_SEND_FLOW_REM      \
                          | OFPUTIL_FF_NO_PKT_COUNTS    \
                          | OFPUTIL_FF_NO_BYT_COUNTS    \
                          | OFPUTIL_FF_CHECK_OVERLAP    \
                          | OFPUTIL_FF_RESET_COUNTS)

    /* Flags that are only set by OVS for its internal use.  Cannot be set via
     * OpenFlow. */
    OFPUTIL_FF_HIDDEN_FIELDS = 1 << 6, /* Allow hidden match fields to be
                                          set or modified. */
    OFPUTIL_FF_NO_READONLY   = 1 << 7, /* Allow rules within read only tables
                                          to be modified */
};

void ofputil_flow_mod_flags_format(struct ds *, enum ofputil_flow_mod_flags);

/* Protocol-independent flow_mod.
 *
 * The handling of cookies across multiple versions of OpenFlow is a bit
 * confusing.  See the topics/design doc for the details. */
struct ofputil_flow_mod {
    struct ovs_list list_node; /* For queuing flow_mods. */

    struct minimatch match;
    int priority;

    /* Cookie matching.  The flow_mod affects only flows that have cookies that
     * bitwise match 'cookie' bits in positions where 'cookie_mask has 1-bits.
     *
     * 'cookie_mask' should be zero for OFPFC_ADD flow_mods. */
    ovs_be64 cookie;         /* Cookie bits to match. */
    ovs_be64 cookie_mask;    /* 1-bit in each 'cookie' bit to match. */

    /* Cookie changes.
     *
     * OFPFC_ADD uses 'new_cookie' as the new flow's cookie.  'new_cookie'
     * should not be UINT64_MAX.
     *
     * OFPFC_MODIFY and OFPFC_MODIFY_STRICT have two cases:
     *
     *   - If one or more matching flows exist and 'modify_cookie' is true,
     *     then the flow_mod changes the existing flows' cookies to
     *     'new_cookie'.  'new_cookie' should not be UINT64_MAX.
     *
     *   - If no matching flow exists, 'new_cookie' is not UINT64_MAX, and
     *     'cookie_mask' is 0, then the flow_mod adds a new flow with
     *     'new_cookie' as its cookie.
     */
    ovs_be64 new_cookie;     /* New cookie to install or UINT64_MAX. */
    bool modify_cookie;      /* Set cookie of existing flow to 'new_cookie'? */

    uint8_t table_id;
    uint16_t command;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint32_t buffer_id;
    ofp_port_t out_port;
    uint32_t out_group;
    enum ofputil_flow_mod_flags flags;
    uint16_t importance;     /* Eviction precedence. */
    struct ofpact *ofpacts;  /* Series of "struct ofpact"s. */
    size_t ofpacts_len;      /* Length of ofpacts, in bytes. */
    uint64_t ofpacts_tlv_bitmap; /* 1-bit for each present TLV in 'ofpacts'. */
};

enum ofperr ofputil_decode_flow_mod(struct ofputil_flow_mod *,
                                    const struct ofp_header *,
                                    enum ofputil_protocol,
                                    const struct tun_table *,
                                    const struct vl_mff_map *,
                                    struct ofpbuf *ofpacts,
                                    ofp_port_t max_port,
                                    uint8_t max_table);
struct ofpbuf *ofputil_encode_flow_mod(const struct ofputil_flow_mod *,
                                       enum ofputil_protocol);
enum ofperr ofputil_flow_mod_format(struct ds *, const struct ofp_header *,
                                    const struct ofputil_port_map *,
                                    const struct ofputil_table_map *,
                                    int verbosity);

char *parse_ofp_str(struct ofputil_flow_mod *, int command, const char *str_,
                    const struct ofputil_port_map *,
                    const struct ofputil_table_map *,
                    enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_flow_mod_str(struct ofputil_flow_mod *, const char *string,
                             const struct ofputil_port_map *,
                             const struct ofputil_table_map *,
                             int command,
                             enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_flow_mod_file(const char *file_name,
                              const struct ofputil_port_map *,
                              const struct ofputil_table_map *,
                              int command,
                              struct ofputil_flow_mod **fms, size_t *n_fms,
                              enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_exact_flow(struct flow *flow, struct flow_wildcards *wc,
                           const struct tun_table *tun_table, const char *s,
                           const struct ofputil_port_map *port_map);

/* Flow stats or aggregate stats request, independent of protocol. */
struct ofputil_flow_stats_request {
    bool aggregate;             /* Aggregate results? */
    struct match match;
    ovs_be64 cookie;
    ovs_be64 cookie_mask;
    ofp_port_t out_port;
    uint32_t out_group;
    uint8_t table_id;
};

enum ofperr ofputil_decode_flow_stats_request(
    struct ofputil_flow_stats_request *, const struct ofp_header *,
    const struct tun_table *, const struct vl_mff_map *);
struct ofpbuf *ofputil_encode_flow_stats_request(
    const struct ofputil_flow_stats_request *, enum ofputil_protocol);
char *parse_ofp_flow_stats_request_str(struct ofputil_flow_stats_request *,
                                       bool aggregate, const char *string,
                                       const struct ofputil_port_map *,
                                       const struct ofputil_table_map *,
                                       enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

void ofputil_flow_stats_request_format(
    struct ds *, const struct ofputil_flow_stats_request *,
    const struct ofputil_port_map *, const struct ofputil_table_map *);

/* Flow stats reply, independent of protocol. */
struct ofputil_flow_stats {
    struct match match;
    ovs_be64 cookie;
    uint8_t table_id;
    uint16_t priority;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    int idle_age;               /* Seconds since last packet, -1 if unknown. */
    int hard_age;               /* Seconds since last change, -1 if unknown. */
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    const struct ofpact *ofpacts;
    size_t ofpacts_len;
    enum ofputil_flow_mod_flags flags;
    uint16_t importance;        /* Eviction precedence. */
};

int ofputil_decode_flow_stats_reply(struct ofputil_flow_stats *,
                                    struct ofpbuf *msg,
                                    bool flow_age_extension,
                                    struct ofpbuf *ofpacts);
void ofputil_append_flow_stats_reply(const struct ofputil_flow_stats *,
                                     struct ovs_list *replies,
                                     const struct tun_table *);

void ofputil_flow_stats_format(struct ds *, const struct ofputil_flow_stats *,
                               const struct ofputil_port_map *,
                               const struct ofputil_table_map *,
                               bool show_stats);

/* Aggregate stats reply, independent of protocol. */
struct ofputil_aggregate_stats {
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    uint32_t flow_count;        /* Number of flows, UINT32_MAX if unknown. */
};

struct ofpbuf *ofputil_encode_aggregate_stats_reply(
    const struct ofputil_aggregate_stats *stats,
    const struct ofp_header *request);
enum ofperr ofputil_decode_aggregate_stats_reply(
    struct ofputil_aggregate_stats *,
    const struct ofp_header *reply);
void ofputil_aggregate_stats_format(struct ds *,
                                    const struct ofputil_aggregate_stats *);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-flow.h */
