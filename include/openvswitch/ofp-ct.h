/*
 * Copyright (c) 2023, Red Hat, Inc.
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

#ifndef OPENVSWITCH_OFP_CT_H
#define OPENVSWITCH_OFP_CT_H 1

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "openflow/nicira-ext.h"

struct ds;

#ifdef __cplusplus
extern "C" {
#endif

struct ofp_ct_tuple {
    struct in6_addr src;
    struct in6_addr dst;

    union {
        ovs_be16 src_port;
        ovs_be16 icmp_id;
    };
    union {
        ovs_be16 dst_port;
        struct {
            uint8_t icmp_code;
            uint8_t icmp_type;
        };
    };
};

struct ofp_ct_match {
    uint8_t ip_proto;
    uint16_t l3_type;

    struct ofp_ct_tuple tuple_orig;
    struct ofp_ct_tuple tuple_reply;

    uint32_t mark;
    uint32_t mark_mask;

    ovs_u128 labels;
    ovs_u128 labels_mask;
};

bool ofp_ct_match_is_zero(const struct ofp_ct_match *);
bool ofp_ct_match_is_five_tuple(const struct ofp_ct_match *);

void ofp_ct_match_format(struct ds *, const struct ofp_ct_match *);
bool ofp_ct_match_parse(const char **, int argc, struct ds *,
                        struct ofp_ct_match *, bool *with_zone,
                        uint16_t *zone_id);

enum ofperr ofp_ct_match_decode(struct ofp_ct_match *, bool *with_zone,
                                uint16_t *zone_id, const struct ofp_header *);
struct ofpbuf *ofp_ct_match_encode(const struct ofp_ct_match *,
                                   uint16_t *zone_id,
                                   enum ofp_version version);

#ifdef __cplusplus
}
#endif

#endif /* ofp-ct.h */
