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

#ifndef OPENVSWITCH_OFP_CONNECTION_H
#define OPENVSWITCH_OFP_CONNECTION_H 1

#include "openflow/openflow.h"
#include "openvswitch/ofp-protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Abstract ofp_role_request and reply. */
struct ofputil_role_request {
    enum ofp12_controller_role role;
    bool have_generation_id;
    uint64_t generation_id;
};

enum ofperr ofputil_decode_role_message(const struct ofp_header *,
                                        struct ofputil_role_request *);
void ofputil_format_role_message(struct ds *,
                                 const struct ofputil_role_request *);
struct ofpbuf *ofputil_encode_role_reply(const struct ofp_header *,
                                         const struct ofputil_role_request *);

/* Abstract OFPT_ROLE_STATUS. */
struct ofputil_role_status {
    enum ofp12_controller_role role;
    enum ofp14_controller_role_reason reason;
    uint64_t generation_id;
};

struct ofpbuf *ofputil_encode_role_status(const struct ofputil_role_status *,
                                          enum ofputil_protocol);
enum ofperr ofputil_decode_role_status(const struct ofp_header *,
                                       struct ofputil_role_status *);
void ofputil_format_role_status(struct ds *,
                                const struct ofputil_role_status *);

enum ofputil_async_msg_type {
    /* Standard asynchronous messages. */
    OAM_PACKET_IN,              /* OFPT_PACKET_IN or NXT_PACKET_IN. */
    OAM_PORT_STATUS,            /* OFPT_PORT_STATUS. */
    OAM_FLOW_REMOVED,           /* OFPT_FLOW_REMOVED or NXT_FLOW_REMOVED. */
    OAM_ROLE_STATUS,            /* OFPT_ROLE_STATUS. */
    OAM_TABLE_STATUS,           /* OFPT_TABLE_STATUS. */
    OAM_REQUESTFORWARD,         /* OFPT_REQUESTFORWARD. */

    /* Extension asynchronous messages (none yet--coming soon!). */
#define OAM_EXTENSIONS 0        /* Bitmap of all extensions. */

    OAM_N_TYPES
};
const char *ofputil_async_msg_type_to_string(enum ofputil_async_msg_type);

struct ofputil_async_cfg {
    uint32_t primary[OAM_N_TYPES];
    uint32_t secondary[OAM_N_TYPES];
};
#define OFPUTIL_ASYNC_CFG_INIT (struct ofputil_async_cfg) { .primary[0] = 0 }

enum ofperr ofputil_decode_set_async_config(const struct ofp_header *,
                                            bool loose,
                                            const struct ofputil_async_cfg *,
                                            struct ofputil_async_cfg *);

struct ofpbuf *ofputil_encode_get_async_reply(
    const struct ofp_header *, const struct ofputil_async_cfg *);
struct ofpbuf *ofputil_encode_set_async_config(
    const struct ofputil_async_cfg *, uint32_t oams, enum ofp_version);
void ofputil_format_set_async_config(struct ds *,
                                     const struct ofputil_async_cfg *);

struct ofputil_async_cfg ofputil_async_cfg_default(enum ofp_version);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-connection.h */
