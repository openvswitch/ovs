/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef OPENVSWITCH_GENEVE_H
#define OPENVSWITCH_GENEVE_H 1

#include "openvswitch/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLV_MAX_OPT_SIZE 124
#define TLV_TOT_OPT_SIZE 252

#define GENEVE_CRIT_OPT_TYPE (1 << 7)

struct geneve_opt {
    ovs_be16  opt_class;
    uint8_t   type;
#ifdef WORDS_BIGENDIAN
    uint8_t   r1:1;
    uint8_t   r2:1;
    uint8_t   r3:1;
    uint8_t   length:5;
#else
    uint8_t   length:5;
    uint8_t   r3:1;
    uint8_t   r2:1;
    uint8_t   r1:1;
#endif
    /* Option data */
};

struct genevehdr {
#ifdef WORDS_BIGENDIAN
    uint8_t ver:2;
    uint8_t opt_len:6;
    uint8_t oam:1;
    uint8_t critical:1;
    uint8_t rsvd1:6;
#else
    uint8_t opt_len:6;
    uint8_t ver:2;
    uint8_t rsvd1:6;
    uint8_t critical:1;
    uint8_t oam:1;
#endif
    ovs_be16 proto_type;
    ovs_16aligned_be32 vni;
    struct geneve_opt options[];
};

#ifdef __cplusplus
}
#endif

#endif /* geneve.h */
