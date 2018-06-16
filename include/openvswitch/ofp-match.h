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

#ifndef OPENVSWITCH_OFP_MATCH_H
#define OPENVSWITCH_OFP_MATCH_H 1

#include "openflow/openflow.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-protocol.h"

struct vl_mff_map;
struct flow_wildcards;
struct match;
struct ofputil_port_map;
struct tun_table;

#ifdef __cplusplus
extern "C" {
#endif

/* Work with ofp10_match. */
void ofputil_wildcard_from_ofpfw10(uint32_t ofpfw, struct flow_wildcards *);
void ofputil_match_from_ofp10_match(const struct ofp10_match *,
                                    struct match *);
void ofputil_normalize_match(struct match *);
void ofputil_normalize_match_quiet(struct match *);
void ofputil_match_to_ofp10_match(const struct match *, struct ofp10_match *);
void ofp10_match_print(struct ds *, const struct ofp10_match *,
                       const struct ofputil_port_map *, int verbosity);
char *ofp10_match_to_string(const struct ofp10_match *,
                            const struct ofputil_port_map *, int verbosity);

/* Work with ofp11_match. */
enum ofperr ofputil_pull_ofp11_match(struct ofpbuf *, const struct tun_table *,
                                     const struct vl_mff_map *, struct match *,
                                     uint16_t *padded_match_len);
enum ofperr ofputil_match_from_ofp11_match(const struct ofp11_match *,
                                           struct match *);
int ofputil_put_ofp11_match(struct ofpbuf *, const struct match *,
                            enum ofputil_protocol);
void ofputil_match_to_ofp11_match(const struct match *, struct ofp11_match *);
int ofputil_match_typical_len(enum ofputil_protocol);

/* dl_type translation between OpenFlow and 'struct flow' format. */
ovs_be16 ofputil_dl_type_to_openflow(ovs_be16 flow_dl_type);
ovs_be16 ofputil_dl_type_from_openflow(ovs_be16 ofp_dl_type);

struct ofputil_tlv_map {
    struct ovs_list list_node;

    uint16_t option_class;
    uint8_t  option_type;
    uint8_t  option_len;
    uint16_t index;
};

struct ofputil_tlv_table_mod {
    uint16_t command;
    struct ovs_list mappings;      /* Contains "struct ofputil_tlv_map"s. */
};

struct ofputil_tlv_table_reply {
    uint32_t max_option_space;
    uint16_t max_fields;
    struct ovs_list mappings;      /* Contains "struct ofputil_tlv_map"s. */
};

struct ofpbuf *ofputil_encode_tlv_table_mod(enum ofp_version ofp_version,
                                            struct ofputil_tlv_table_mod *);
enum ofperr ofputil_decode_tlv_table_mod(const struct ofp_header *,
                                         struct ofputil_tlv_table_mod *);
void ofputil_format_tlv_table_mod(struct ds *,
                                  const struct ofputil_tlv_table_mod *);

struct ofpbuf *ofputil_encode_tlv_table_reply(
    const struct ofp_header *, struct ofputil_tlv_table_reply *);
enum ofperr ofputil_decode_tlv_table_reply(
    const struct ofp_header *, struct ofputil_tlv_table_reply *);
char *parse_ofp_tlv_table_mod_str(struct ofputil_tlv_table_mod *,
                                     uint16_t command, const char *string,
                                     enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;
void ofputil_format_tlv_table_reply(struct ds *,
                                    const struct ofputil_tlv_table_reply *);

void ofputil_uninit_tlv_table(struct ovs_list *mappings);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-match.h */
