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

#ifndef OPENVSWITCH_OFP_METER_H
#define OPENVSWITCH_OFP_METER_H 1

#include "openflow/openflow.h"
#include "openvswitch/ofp-protocol.h"

struct ofpbuf;
struct ovs_list;

#ifdef __cplusplus
extern "C" {
#endif

/* Type for meter_id in ofproto provider interface, UINT32_MAX if invalid. */
typedef struct { uint32_t uint32; } ofproto_meter_id;

void ofputil_format_meter_id(struct ds *s, uint32_t meter_id, char separator);

/* Meter band configuration for all supported band types. */
struct ofputil_meter_band {
    uint16_t type;
    uint8_t prec_level;         /* Non-zero if type == OFPMBT_DSCP_REMARK. */
    uint32_t rate;
    uint32_t burst_size;
};

void ofputil_format_meter_band(struct ds *, enum ofp13_meter_flags,
                               const struct ofputil_meter_band *);

struct ofputil_meter_band_stats {
    uint64_t packet_count;
    uint64_t byte_count;
};

struct ofputil_meter_config {
    uint32_t meter_id;
    uint16_t flags;
    uint16_t n_bands;
    struct ofputil_meter_band *bands;
};

void ofputil_append_meter_config(struct ovs_list *replies,
                                 const struct ofputil_meter_config *);
int ofputil_decode_meter_config(struct ofpbuf *,
                                struct ofputil_meter_config *,
                                struct ofpbuf *bands);
void ofputil_format_meter_config(struct ds *,
                                 const struct ofputil_meter_config *);

struct ofputil_meter_mod {
    uint16_t command;
    struct ofputil_meter_config meter;
};

enum ofperr ofputil_decode_meter_mod(const struct ofp_header *,
                                     struct ofputil_meter_mod *,
                                     struct ofpbuf *bands);
struct ofpbuf *ofputil_encode_meter_mod(enum ofp_version,
                                        const struct ofputil_meter_mod *);
char *parse_ofp_meter_mod_str(struct ofputil_meter_mod *, const char *string,
                              int command,
                              enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;
void ofputil_format_meter_mod(struct ds *, const struct ofputil_meter_mod *);

struct ofputil_meter_stats {
    uint32_t meter_id;
    uint32_t flow_count;
    uint64_t packet_in_count;
    uint64_t byte_in_count;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint16_t n_bands;
    struct ofputil_meter_band_stats *bands;
};

void ofputil_append_meter_stats(struct ovs_list *replies,
                                const struct ofputil_meter_stats *);
int ofputil_decode_meter_stats(struct ofpbuf *,
                               struct ofputil_meter_stats *,
                               struct ofpbuf *bands);
void ofputil_format_meter_stats(struct ds *,
                                const struct ofputil_meter_stats *);

struct ofputil_meter_features {
    uint32_t max_meters;        /* Maximum number of meters. */
    uint32_t band_types;        /* Can support max 32 band types. */
    uint32_t capabilities;      /* Supported flags. */
    uint8_t  max_bands;
    uint8_t  max_color;
};

void ofputil_decode_meter_features(const struct ofp_header *,
                                   struct ofputil_meter_features *);
struct ofpbuf *ofputil_encode_meter_features_reply(const struct
                                                   ofputil_meter_features *,
                                                   const struct ofp_header *
                                                   request);
void ofputil_format_meter_features(struct ds *,
                                   const struct ofputil_meter_features *);

enum ofputil_meter_request_type {
    OFPUTIL_METER_FEATURES,
    OFPUTIL_METER_CONFIG,
    OFPUTIL_METER_STATS
};

struct ofpbuf *ofputil_encode_meter_request(enum ofp_version,
                                            enum ofputil_meter_request_type,
                                            uint32_t meter_id);
void ofputil_decode_meter_request(const struct ofp_header *,
                                  uint32_t *meter_id);


#ifdef __cplusplus
}
#endif

#endif  /* ofp-meter.h */
