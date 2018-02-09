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

#ifndef OPENVSWITCH_OFP_GROUP_H
#define OPENVSWITCH_OFP_GROUP_H 1

#include "openflow/openflow.h"
#include "openflow/netronome-ext.h"
#include "openvswitch/list.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/type-props.h"

struct ds;

#ifdef __cplusplus
extern "C" {
#endif

struct ofputil_table_map;

/* Group numbers. */
enum { MAX_GROUP_NAME_LEN = INT_STRLEN(uint32_t) };
bool ofputil_group_from_string(const char *, uint32_t *group_id);
void ofputil_format_group(uint32_t group_id, struct ds *);
void ofputil_group_to_string(uint32_t group_id,
                             char namebuf[MAX_GROUP_NAME_LEN + 1],
                             size_t bufsize);

struct bucket_counter {
    uint64_t packet_count;   /* Number of packets processed by bucket. */
    uint64_t byte_count;     /* Number of bytes processed by bucket. */
};

/* Bucket for use in groups. */
struct ofputil_bucket {
    struct ovs_list list_node;
    uint16_t weight;            /* Relative weight, for "select" groups. */
    ofp_port_t watch_port;      /* Port whose state affects whether this bucket
                                 * is live. Only required for fast failover
                                 * groups. */
    uint32_t watch_group;       /* Group whose state affects whether this
                                 * bucket is live. Only required for fast
                                 * failover groups. */
    uint32_t bucket_id;         /* Bucket Id used to identify bucket*/
    struct ofpact *ofpacts;     /* Series of "struct ofpact"s. */
    size_t ofpacts_len;         /* Length of ofpacts, in bytes. */

    struct bucket_counter stats;
};

void ofputil_bucket_list_destroy(struct ovs_list *buckets);
void ofputil_bucket_clone_list(struct ovs_list *dest,
                               const struct ovs_list *src,
                               const struct ofputil_bucket *);
struct ofputil_bucket *ofputil_bucket_find(const struct ovs_list *,
                                           uint32_t bucket_id);
bool ofputil_bucket_check_duplicate_id(const struct ovs_list *);
struct ofputil_bucket *ofputil_bucket_list_front(const struct ovs_list *);
struct ofputil_bucket *ofputil_bucket_list_back(const struct ovs_list *);

static inline bool
ofputil_bucket_has_liveness(const struct ofputil_bucket *bucket)
{
    return (bucket->watch_port != OFPP_ANY ||
            bucket->watch_group != OFPG_ANY);
}

struct ofputil_group_props {
    /* NTR selection method */
    char selection_method[NTR_MAX_SELECTION_METHOD_LEN];
    uint64_t selection_method_param;
    struct field_array fields;
};

void ofputil_group_properties_destroy(struct ofputil_group_props *);
void ofputil_group_properties_copy(struct ofputil_group_props *to,
                                   const struct ofputil_group_props *from);
/* Protocol-independent group_mod. */
struct ofputil_group_mod {
    uint16_t command;             /* One of OFPGC15_*. */
    uint8_t type;                 /* One of OFPGT11_*. */
    uint32_t group_id;            /* Group identifier. */
    uint32_t command_bucket_id;   /* Bucket Id used as part of
                                   * OFPGC15_INSERT_BUCKET and
                                   * OFPGC15_REMOVE_BUCKET commands
                                   * execution.*/
    struct ovs_list buckets;      /* Contains "struct ofputil_bucket"s. */
    struct ofputil_group_props props; /* Group properties. */
};

void ofputil_uninit_group_mod(struct ofputil_group_mod *gm);
struct ofpbuf *ofputil_encode_group_mod(enum ofp_version ofp_version,
                                        const struct ofputil_group_mod *gm);

enum ofperr ofputil_decode_group_mod(const struct ofp_header *,
                                     struct ofputil_group_mod *);

char *parse_ofp_group_mod_file(const char *file_name,
                               const struct ofputil_port_map *,
                               const struct ofputil_table_map *, int command,
                               struct ofputil_group_mod **gms, size_t *n_gms,
                               enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_group_mod_str(struct ofputil_group_mod *, int command,
                              const char *string,
                              const struct ofputil_port_map *,
                              const struct ofputil_table_map *,
                              enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

/* Group stats reply, independent of protocol. */
struct ofputil_group_stats {
    uint32_t group_id;    /* Group identifier. */
    uint32_t ref_count;
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    uint32_t duration_sec;      /* UINT32_MAX if unknown. */
    uint32_t duration_nsec;
    uint32_t n_buckets;
    struct bucket_counter *bucket_stats;
};

struct ofpbuf *ofputil_encode_group_stats_request(enum ofp_version,
                                                  uint32_t group_id);
enum ofperr ofputil_decode_group_stats_request(
    const struct ofp_header *request, uint32_t *group_id);
void ofputil_append_group_stats(struct ovs_list *replies,
                                const struct ofputil_group_stats *);

int ofputil_decode_group_stats_reply(struct ofpbuf *,
                                     struct ofputil_group_stats *);

/* Group features reply, independent of protocol.
 *
 * Only OF1.2 and later support group features replies. */
struct ofputil_group_features {
    uint32_t  types;           /* Bitmap of OFPGT_* values supported. */
    uint32_t  capabilities;    /* Bitmap of OFPGFC12_* capability supported. */
    uint32_t  max_groups[4];   /* Maximum number of groups for each type. */
    uint64_t  ofpacts[4];      /* Bitmaps of supported OFPACT_* */
};

struct ofpbuf *ofputil_encode_group_features_request(enum ofp_version);
struct ofpbuf *ofputil_encode_group_features_reply(
    const struct ofputil_group_features *, const struct ofp_header *request);
void ofputil_decode_group_features_reply(const struct ofp_header *,
                                         struct ofputil_group_features *);

/* Group desc reply, independent of protocol. */
struct ofputil_group_desc {
    uint8_t type;               /* One of OFPGT_*. */
    uint32_t group_id;          /* Group identifier. */
    struct ovs_list buckets;    /* Contains "struct ofputil_bucket"s. */
    struct ofputil_group_props props; /* Group properties. */
};

void ofputil_uninit_group_desc(struct ofputil_group_desc *gd);
uint32_t ofputil_decode_group_desc_request(const struct ofp_header *);
struct ofpbuf *ofputil_encode_group_desc_request(enum ofp_version,
                                                 uint32_t group_id);

int ofputil_decode_group_desc_reply(struct ofputil_group_desc *,
                                    struct ofpbuf *, enum ofp_version);

void ofputil_append_group_desc_reply(const struct ofputil_group_desc *,
                                     const struct ovs_list *buckets,
                                     struct ovs_list *replies);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-group.h */
