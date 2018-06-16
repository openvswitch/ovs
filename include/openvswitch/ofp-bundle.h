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

#ifndef OPENVSWITCH_OFP_BUNDLE_H
#define OPENVSWITCH_OFP_BUNDLE_H 1

#include "openflow/openflow.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-group.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-msgs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Abstract OFPT_BUNDLE_CONTROL message. */
struct ofputil_bundle_ctrl_msg {
    uint32_t bundle_id;
    uint16_t type;
    uint16_t flags;
};

enum ofperr ofputil_decode_bundle_ctrl(const struct ofp_header *,
                                       struct ofputil_bundle_ctrl_msg *);
struct ofpbuf *ofputil_encode_bundle_ctrl_request(
    enum ofp_version, struct ofputil_bundle_ctrl_msg *);
void ofputil_format_bundle_ctrl_request(
    struct ds *, const struct ofputil_bundle_ctrl_msg *);

struct ofpbuf *ofputil_encode_bundle_ctrl_reply(
    const struct ofp_header *, struct ofputil_bundle_ctrl_msg *);

/* Abstract OFPT_BUNDLE_ADD_MESSAGE message. */
struct ofputil_bundle_add_msg {
    uint32_t bundle_id;
    uint16_t flags;
    const struct ofp_header *msg;
};

struct ofpbuf *ofputil_encode_bundle_add(enum ofp_version,
                                         struct ofputil_bundle_add_msg *);
enum ofperr ofputil_decode_bundle_add(const struct ofp_header *,
                                      struct ofputil_bundle_add_msg *,
                                      enum ofptype *);
void ofputil_format_bundle_add(struct ds *,
                               const struct ofputil_bundle_add_msg *,
                               const struct ofputil_port_map *,
                               const struct ofputil_table_map *,
                               int verbosity);


/* Bundle message as produced by ofp-parse. */
struct ofputil_bundle_msg {
    enum ofptype type;
    union {
        struct ofputil_flow_mod fm;
        struct ofputil_group_mod gm;
        struct ofputil_packet_out po;
    };
};

void ofputil_encode_bundle_msgs(const struct ofputil_bundle_msg *, size_t n,
                                struct ovs_list *requests,
                                enum ofputil_protocol);
void ofputil_free_bundle_msgs(struct ofputil_bundle_msg *, size_t n);

char *parse_ofp_bundle_file(const char *file_name,
                            const struct ofputil_port_map *,
                            const struct ofputil_table_map *,
                            struct ofputil_bundle_msg **, size_t *n_bms,
                            enum ofputil_protocol *)
    OVS_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif  /* ofp-bundle.h */
