/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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

/* OpenFlow protocol string to flow parser. */

#ifndef OPENVSWITCH_OFP_PARSE_H
#define OPENVSWITCH_OFP_PARSE_H 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "openvswitch/compiler.h"
#include "openvswitch/ofp-protocol.h"
#include "openvswitch/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct match;
struct mf_field;
struct ofputil_port_map;

struct ofp_protocol {
    const char *name;
    uint16_t dl_type;
    uint8_t nw_proto;
};

bool ofp_parse_protocol(const char *name, const struct ofp_protocol **);

char *ofp_extract_actions(char *);
char *ofp_parse_field(const struct mf_field *, const char *,
                      const struct ofputil_port_map *, struct match *,
                      enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *str_to_u8(const char *str, const char *name, uint8_t *valuep)
    OVS_WARN_UNUSED_RESULT;
char *str_to_u16(const char *str, const char *name, uint16_t *valuep)
    OVS_WARN_UNUSED_RESULT;
char *str_to_u32(const char *str, uint32_t *valuep) OVS_WARN_UNUSED_RESULT;
char *str_to_u64(const char *str, uint64_t *valuep) OVS_WARN_UNUSED_RESULT;
char *str_to_be64(const char *str, ovs_be64 *valuep) OVS_WARN_UNUSED_RESULT;
char *str_to_mac(const char *str, struct eth_addr *mac) OVS_WARN_UNUSED_RESULT;
char *str_to_ip(const char *str, ovs_be32 *ip) OVS_WARN_UNUSED_RESULT;
char *str_to_connhelper(const char *str, uint16_t *alg) OVS_WARN_UNUSED_RESULT;

/* Handy utility for parsing flows and actions. */
bool ofputil_parse_key_value(char **stringp, char **keyp, char **valuep);

#ifdef __cplusplus
}
#endif

#endif /* ofp-parse.h */
