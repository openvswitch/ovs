/* Copyright (c) 2015, 2016 Nicira, Inc.
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


#ifndef OFCTRL_H
#define OFCTRL_H 1

#include <stdint.h>

#include "openvswitch/meta-flow.h"
#include "ovsdb-idl.h"

struct controller_ctx;
struct ovn_extend_table;
struct hmap;
struct match;
struct ofpbuf;
struct ovsrec_bridge;
struct shash;

/* Interface for OVN main loop. */
void ofctrl_init(struct ovn_extend_table *group_table,
                 struct ovn_extend_table *meter_table);
enum mf_field_id ofctrl_run(const struct ovsrec_bridge *br_int,
                            struct shash *pending_ct_zones);
bool ofctrl_can_put(void);
void ofctrl_put(struct hmap *flow_table, struct shash *pending_ct_zones,
                int64_t nb_cfg);
void ofctrl_wait(void);
void ofctrl_destroy(void);
int64_t ofctrl_get_cur_cfg(void);

struct ovn_flow *ofctrl_dup_flow(struct ovn_flow *source);

void ofctrl_ct_flush_zone(uint16_t zone_id);

char *ofctrl_inject_pkt(const struct ovsrec_bridge *br_int,
                        const char *flow_s, const struct shash *addr_sets,
                        const struct shash *port_groups);

/* Flow table interfaces to the rest of ovn-controller. */
void ofctrl_add_flow(struct hmap *desired_flows, uint8_t table_id,
                     uint16_t priority, uint64_t cookie,
                     const struct match *, const struct ofpbuf *ofpacts);

#endif /* ovn/ofctrl.h */
