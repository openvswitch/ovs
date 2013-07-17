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
#include "ofproto/ofproto-provider.h"
#include "ovs-thread.h"
#include "timer.h"
#include "util.h"
#include "ovs-thread.h"

union user_action_cookie;
struct ofproto_dpif;
struct ofport_dpif;
struct dpif_backer;

struct rule_dpif {
    struct rule up;

    /* These statistics:
     *
     *   - Do include packets and bytes from facets that have been deleted or
     *     whose own statistics have been folded into the rule.
     *
     *   - Do include packets and bytes sent "by hand" that were accounted to
     *     the rule without any facet being involved (this is a rare corner
     *     case in rule_execute()).
     *
     *   - Do not include packet or bytes that can be obtained from any facet's
     *     packet_count or byte_count member or that can be obtained from the
     *     datapath by, e.g., dpif_flow_get() for any subfacet.
     */
    struct ovs_mutex stats_mutex;
    uint64_t packet_count OVS_GUARDED;  /* Number of packets received. */
    uint64_t byte_count OVS_GUARDED;    /* Number of bytes received. */
};

static inline struct rule_dpif *rule_dpif_cast(const struct rule *rule)
{
    return rule ? CONTAINER_OF(rule, struct rule_dpif, up) : NULL;
}

void rule_dpif_lookup(struct ofproto_dpif *, const struct flow *,
                      struct flow_wildcards *, struct rule_dpif **rule)
    OVS_ACQ_RDLOCK((*rule)->up.evict);

bool rule_dpif_lookup_in_table(struct ofproto_dpif *, const struct flow *,
                               struct flow_wildcards *, uint8_t table_id,
                               struct rule_dpif **rule)
    OVS_ACQ_RDLOCK((*rule)->up.evict);

void rule_release(struct rule_dpif *rule) OVS_RELEASES(rule->up.evict);

void rule_credit_stats(struct rule_dpif *, const struct dpif_flow_stats *);

struct rule_dpif *choose_miss_rule(enum ofputil_port_config,
                                   struct rule_dpif *miss_rule,
                                   struct rule_dpif *no_packet_in_rule);

bool ofproto_has_vlan_splinters(const struct ofproto_dpif *);
ofp_port_t vsp_realdev_to_vlandev(const struct ofproto_dpif *,
                                  ofp_port_t realdev_ofp_port,
                                  ovs_be16 vlan_tci);
bool vsp_adjust_flow(const struct ofproto_dpif *, struct flow *);

void ofproto_dpif_send_packet_in(struct ofproto_dpif *,
                                 struct ofputil_packet_in *pin);
void ofproto_dpif_flow_mod(struct ofproto_dpif *, struct ofputil_flow_mod *);

struct ofport_dpif *odp_port_to_ofport(const struct dpif_backer *, odp_port_t);

#endif /* ofproto-dpif.h */
