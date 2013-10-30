/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
 * limitations under the License. */

#ifndef OFPROTO_DPIF_H
#define OFPROTO_DPIF_H 1

#include <stdint.h>

#include "hmapx.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "ovs-thread.h"
#include "timer.h"
#include "util.h"
#include "ovs-thread.h"

union user_action_cookie;
struct dpif_flow_stats;
struct ofproto_dpif;
struct ofproto_packet_in;
struct ofport_dpif;
struct dpif_backer;
struct OVS_LOCKABLE rule_dpif;
struct OVS_LOCKABLE group_dpif;

/* Ofproto-dpif -- DPIF based ofproto implementation.
 *
 * Ofproto-dpif provides an ofproto implementation for those platforms which
 * implement the netdev and dpif interface defined in netdev.h and dpif.h.  The
 * most important of which is the Linux Kernel Module (dpif-linux), but
 * alternatives are supported such as a userspace only implementation
 * (dpif-netdev), and a dummy implementation used for unit testing.
 *
 * Ofproto-dpif is divided into three major chunks.
 *
 * - ofproto-dpif.c
 *   The main ofproto-dpif module is responsible for implementing the
 *   provider interface, installing and removing datapath flows, maintaining
 *   packet statistics, running protocols (BFD, LACP, STP, etc), and
 *   configuring relevant submodules.
 *
 * - ofproto-dpif-upcall.c
 *   Ofproto-dpif-upcall is responsible for retrieving upcalls from the kernel,
 *   processing miss upcalls, and handing more complex ones up to the main
 *   ofproto-dpif module.  Miss upcall processing boils down to figuring out
 *   what each packet's actions are, executing them (i.e. asking the kernel to
 *   forward it), and handing it up to ofproto-dpif to decided whether or not
 *   to install a kernel flow.
 *
 * - ofproto-dpif-xlate.c
 *   Ofproto-dpif-xlate is responsible for translating translating OpenFlow
 *   actions into datapath actions. */

void rule_dpif_lookup(struct ofproto_dpif *, const struct flow *,
                      struct flow_wildcards *, struct rule_dpif **rule);

bool rule_dpif_lookup_in_table(struct ofproto_dpif *, const struct flow *,
                               struct flow_wildcards *, uint8_t table_id,
                               struct rule_dpif **rule);

void rule_dpif_ref(struct rule_dpif *);
void rule_dpif_unref(struct rule_dpif *);

void rule_dpif_credit_stats(struct rule_dpif *rule ,
                            const struct dpif_flow_stats *);

bool rule_dpif_is_fail_open(const struct rule_dpif *);
bool rule_dpif_is_table_miss(const struct rule_dpif *);

struct rule_actions *rule_dpif_get_actions(const struct rule_dpif *);

ovs_be64 rule_dpif_get_flow_cookie(const struct rule_dpif *rule);

void rule_dpif_reduce_timeouts(struct rule_dpif *rule, uint16_t idle_timeout,
                               uint16_t hard_timeout);

void choose_miss_rule(enum ofputil_port_config,
                      struct rule_dpif *miss_rule,
                      struct rule_dpif *no_packet_in_rule,
                      struct rule_dpif **rule);

bool group_dpif_lookup(struct ofproto_dpif *ofproto, uint32_t group_id,
                       struct group_dpif **group);

void group_dpif_release(struct group_dpif *group);

void group_dpif_get_buckets(const struct group_dpif *group,
                            const struct list **buckets);
enum ofp11_group_type group_dpif_get_type(const struct group_dpif *group);

bool ofproto_has_vlan_splinters(const struct ofproto_dpif *);
ofp_port_t vsp_realdev_to_vlandev(const struct ofproto_dpif *,
                                  ofp_port_t realdev_ofp_port,
                                  ovs_be16 vlan_tci);
bool vsp_adjust_flow(const struct ofproto_dpif *, struct flow *);

int ofproto_dpif_execute_actions(struct ofproto_dpif *, const struct flow *,
                                 struct rule_dpif *, const struct ofpact *,
                                 size_t ofpacts_len, struct ofpbuf *);
void ofproto_dpif_send_packet_in(struct ofproto_dpif *,
                                 struct ofproto_packet_in *);
int ofproto_dpif_send_packet(const struct ofport_dpif *, struct ofpbuf *);
void ofproto_dpif_flow_mod(struct ofproto_dpif *, struct ofputil_flow_mod *);

struct ofport_dpif *odp_port_to_ofport(const struct dpif_backer *, odp_port_t);

#endif /* ofproto-dpif.h */
