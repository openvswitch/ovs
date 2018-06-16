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

#ifndef OPENVSWITCH_OFP_MONITOR_H
#define OPENVSWITCH_OFP_MONITOR_H 1

#include "openflow/openflow.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-protocol.h"
#include "openvswitch/ofpbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ofputil_table_map;

const char *ofp_flow_removed_reason_to_string(enum ofp_flow_removed_reason,
                                              char *reasonbuf, size_t bufsize);

/* Flow removed message, independent of protocol. */
struct ofputil_flow_removed {
    struct match match;
    ovs_be64 cookie;
    uint16_t priority;
    uint8_t reason;             /* One of OFPRR_*. */
    uint8_t table_id;           /* 255 if message didn't include table ID. */
    uint32_t duration_sec;      /* Duration in sec, UINT32_MAX if unknown. */
    uint32_t duration_nsec;     /* Fractional duration in nsec. */
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
};

enum ofperr ofputil_decode_flow_removed(struct ofputil_flow_removed *,
                                        const struct ofp_header *);
struct ofpbuf *ofputil_encode_flow_removed(const struct ofputil_flow_removed *,
                                           enum ofputil_protocol);
void ofputil_flow_removed_format(struct ds *,
                                 const struct ofputil_flow_removed *,
                                 const struct ofputil_port_map *,
                                 const struct ofputil_table_map *);

/* Abstract nx_flow_monitor_request. */
struct ofputil_flow_monitor_request {
    uint32_t id;
    enum nx_flow_monitor_flags flags;
    ofp_port_t out_port;
    uint8_t table_id;
    struct match match;
};

int ofputil_decode_flow_monitor_request(struct ofputil_flow_monitor_request *,
                                        struct ofpbuf *msg);
void ofputil_append_flow_monitor_request(
    const struct ofputil_flow_monitor_request *, struct ofpbuf *msg);
void ofputil_flow_monitor_request_format(
    struct ds *, const struct ofputil_flow_monitor_request *,
    const struct ofputil_port_map *, const struct ofputil_table_map *);

char *parse_flow_monitor_request(struct ofputil_flow_monitor_request *,
                                 const char *,
                                 const struct ofputil_port_map *,
                                 const struct ofputil_table_map *,
                                 enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

/* Abstract nx_flow_update. */
struct ofputil_flow_update {
    enum nx_flow_update_event event;

    /* Used only for NXFME_ADDED, NXFME_DELETED, NXFME_MODIFIED. */
    enum ofp_flow_removed_reason reason;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint8_t table_id;
    uint16_t priority;
    ovs_be64 cookie;
    struct match match;
    const struct ofpact *ofpacts;
    size_t ofpacts_len;

    /* Used only for NXFME_ABBREV. */
    ovs_be32 xid;
};

int ofputil_decode_flow_update(struct ofputil_flow_update *,
                               struct ofpbuf *msg, struct ofpbuf *ofpacts);
void ofputil_start_flow_update(struct ovs_list *replies);
void ofputil_append_flow_update(const struct ofputil_flow_update *,
                                struct ovs_list *replies,
                                const struct tun_table *);
void ofputil_flow_update_format(struct ds *,
                                const struct ofputil_flow_update *,
                                const struct ofputil_port_map *,
                                const struct ofputil_table_map *);

/* Abstract nx_flow_monitor_cancel. */
uint32_t ofputil_decode_flow_monitor_cancel(const struct ofp_header *);
struct ofpbuf *ofputil_encode_flow_monitor_cancel(uint32_t id);

struct ofputil_requestforward {
    ovs_be32 xid;
    enum ofp14_requestforward_reason reason;
    union {
        /* reason == OFPRFR_METER_MOD. */
        struct {
            struct ofputil_meter_mod *meter_mod;
            struct ofpbuf bands;
        };

        /* reason == OFPRFR_GROUP_MOD. */
        struct ofputil_group_mod *group_mod;
    };
};

struct ofpbuf *ofputil_encode_requestforward(
    const struct ofputil_requestforward *, enum ofputil_protocol);
enum ofperr ofputil_decode_requestforward(const struct ofp_header *,
                                          struct ofputil_requestforward *);
void ofputil_format_requestforward(struct ds *, enum ofp_version,
                                   const struct ofputil_requestforward *,
                                   const struct ofputil_port_map *,
                                   const struct ofputil_table_map *);
void ofputil_destroy_requestforward(struct ofputil_requestforward *);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-monitor.h */
