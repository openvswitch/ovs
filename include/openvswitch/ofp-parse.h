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
#include "openvswitch/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct flow;
struct ofpbuf;
struct ofputil_flow_mod;
struct ofputil_packet_out;
struct ofputil_flow_monitor_request;
struct ofputil_flow_stats_request;
struct ofputil_group_mod;
struct ofputil_meter_mod;
struct ofputil_table_mod;
struct ofputil_bundle_msg;
struct ofputil_tlv_table_mod;
struct simap;
enum ofputil_protocol;

char *parse_ofp_str(struct ofputil_flow_mod *, int command, const char *str_,
                    const struct ofputil_port_map *,
                    enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_flow_mod_str(struct ofputil_flow_mod *, const char *string,
                             const struct ofputil_port_map *, int command,
                             enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_packet_out_str(struct ofputil_packet_out *po, const char *str_,
                               const struct ofputil_port_map *,
                               enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_table_mod(struct ofputil_table_mod *,
                          const char *table_id, const char *flow_miss_handling,
                          uint32_t *usable_versions)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_flow_mod_file(const char *file_name,
                              const struct ofputil_port_map *, int command,
                              struct ofputil_flow_mod **fms, size_t *n_fms,
                              enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_flow_stats_request_str(struct ofputil_flow_stats_request *,
                                       bool aggregate, const char *string,
                                       const struct ofputil_port_map *,
                                       enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_exact_flow(struct flow *flow, struct flow_wildcards *wc,
                           const struct tun_table *tun_table, const char *s,
                           const struct ofputil_port_map *port_map);

char *parse_ofp_meter_mod_str(struct ofputil_meter_mod *, const char *string,
                              int command,
                              enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_flow_monitor_request(struct ofputil_flow_monitor_request *,
                                 const char *,
                                 const struct ofputil_port_map *port_map,
                                 enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_group_mod_file(const char *file_name,
                               const struct ofputil_port_map *, int command,
                               struct ofputil_group_mod **gms, size_t *n_gms,
                               enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_group_mod_str(struct ofputil_group_mod *, int command,
                              const char *string,
                              const struct ofputil_port_map *,
                              enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_bundle_file(const char *file_name,
                            const struct ofputil_port_map *,
                            struct ofputil_bundle_msg **, size_t *n_bms,
                            enum ofputil_protocol *)
    OVS_WARN_UNUSED_RESULT;

char *parse_ofp_tlv_table_mod_str(struct ofputil_tlv_table_mod *,
                                     uint16_t command, const char *string,
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
char *parse_ofp_table_vacancy(struct ofputil_table_mod *,
                              const char *flow_miss_handling)
    OVS_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* ofp-parse.h */
