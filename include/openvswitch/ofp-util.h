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

#ifndef OPENVSWITCH_OFP_UTIL_H
#define OPENVSWITCH_OFP_UTIL_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openvswitch/ofp-protocol.h"

struct ofp_header;

#ifdef __cplusplus
extern "C" {
#endif

bool ofputil_decode_hello(const struct ofp_header *,
                          uint32_t *allowed_versions);
struct ofpbuf *ofputil_encode_hello(uint32_t version_bitmap);

struct ofpbuf *ofputil_encode_echo_request(enum ofp_version);
struct ofpbuf *ofputil_encode_echo_reply(const struct ofp_header *);

struct ofpbuf *ofputil_encode_barrier_request(enum ofp_version);

#ifdef __cplusplus
}
#endif

#endif /* ofp-util.h */
