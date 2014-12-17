/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#include "fail-open.h"
#include "hmapx.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "ovs-thread.h"
#include "ofproto-provider.h"
#include "timer.h"
#include "util.h"
#include "ovs-thread.h"

/* Priority for internal rules created to handle recirculation */
#define RECIRC_RULE_PRIORITY 20

union user_action_cookie;
struct dpif_flow_stats;
struct ofproto;
struct ofproto_dpif;
struct ofproto_packet_in;
struct ofport_dpif;
struct dpif_backer;
struct OVS_LOCKABLE rule_dpif;
struct OVS_LOCKABLE group_dpif;

/* Number of implemented OpenFlow tables. */
enum { N_TABLES = 255 };
enum { TBL_INTERNAL = N_TABLES - 1 };    /* Used for internal hidden rules. */
BUILD_ASSERT_DECL(N_TABLES >= 2 && N_TABLES <= 255);

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
 *   Ofproto-dpif-xlate is responsible for translating OpenFlow actions into
 *   datapath actions. */

size_t ofproto_dpif_get_max_mpls_depth(const struct ofproto_dpif *);
bool ofproto_dpif_get_enable_recirc(const struct ofproto_dpif *);
bool ofproto_dpif_get_enable_ufid(struct dpif_backer *backer);

struct rule_dpif *rule_dpif_lookup(struct ofproto_dpif *, struct flow *,
                                   struct flow_wildcards *, bool take_ref,
                                   const struct dpif_flow_stats *,
                                   uint8_t *table_id);

struct rule_dpif *rule_dpif_lookup_from_table(struct ofproto_dpif *,
                                              struct flow *,
                                              struct flow_wildcards *,
                                              bool take_ref,
                                              const struct dpif_flow_stats *,
                                              uint8_t *table_id,
                                              ofp_port_t in_port,
                                              bool may_packet_in,
                                              bool honor_table_miss);

/* If 'recirc_id' is set, starts looking up from internal table for
 * post recirculation flows or packets.  Otherwise, starts from table 0. */
static inline uint8_t
rule_dpif_lookup_get_init_table_id(const struct flow *flow)
{
    return flow->recirc_id ? TBL_INTERNAL : 0;
}

static inline void rule_dpif_ref(struct rule_dpif *);
static inline void rule_dpif_unref(struct rule_dpif *);

void rule_dpif_credit_stats(struct rule_dpif *rule ,
                            const struct dpif_flow_stats *);

static inline bool rule_dpif_is_fail_open(const struct rule_dpif *);
static inline bool rule_dpif_is_table_miss(const struct rule_dpif *);
static inline bool rule_dpif_is_internal(const struct rule_dpif *);

uint8_t rule_dpif_get_table(const struct rule_dpif *);

bool table_is_internal(uint8_t table_id);

const struct rule_actions *rule_dpif_get_actions(const struct rule_dpif *);
uint32_t rule_dpif_get_recirc_id(struct rule_dpif *);
void rule_set_recirc_id(struct rule *, uint32_t id);

ovs_be64 rule_dpif_get_flow_cookie(const struct rule_dpif *rule);

void rule_dpif_reduce_timeouts(struct rule_dpif *rule, uint16_t idle_timeout,
                               uint16_t hard_timeout);

void choose_miss_rule(enum ofputil_port_config,
                      struct rule_dpif *miss_rule,
                      struct rule_dpif *no_packet_in_rule,
                      struct rule_dpif **rule, bool take_ref);

void group_dpif_credit_stats(struct group_dpif *,
                             struct ofputil_bucket *,
                             const struct dpif_flow_stats *);
bool group_dpif_lookup(struct ofproto_dpif *ofproto, uint32_t group_id,
                       struct group_dpif **group);

void group_dpif_get_buckets(const struct group_dpif *group,
                            const struct ovs_list **buckets);
enum ofp11_group_type group_dpif_get_type(const struct group_dpif *group);

bool ofproto_has_vlan_splinters(const struct ofproto_dpif *);
ofp_port_t vsp_realdev_to_vlandev(const struct ofproto_dpif *,
                                  ofp_port_t realdev_ofp_port,
                                  ovs_be16 vlan_tci);
bool vsp_adjust_flow(const struct ofproto_dpif *, struct flow *,
                     struct ofpbuf *packet);

int ofproto_dpif_execute_actions(struct ofproto_dpif *, const struct flow *,
                                 struct rule_dpif *, const struct ofpact *,
                                 size_t ofpacts_len, struct ofpbuf *);
void ofproto_dpif_send_packet_in(struct ofproto_dpif *,
                                 struct ofproto_packet_in *);
bool ofproto_dpif_wants_packet_in_on_miss(struct ofproto_dpif *);
int ofproto_dpif_send_packet(const struct ofport_dpif *, struct ofpbuf *);
void ofproto_dpif_flow_mod(struct ofproto_dpif *, struct ofputil_flow_mod *);
struct rule_dpif *ofproto_dpif_refresh_rule(struct rule_dpif *);

struct ofport_dpif *odp_port_to_ofport(const struct dpif_backer *, odp_port_t);

/*
 * Recirculation
 * =============
 *
 * Recirculation is a technique to allow a frame to re-enter the packet
 * processing path for one or multiple times to achieve more flexible packet
 * processing in the data path. MPLS handling and selecting bond slave port
 * of a bond ports.
 *
 * Data path and user space interface
 * -----------------------------------
 *
 * Two new fields, recirc_id and dp_hash, are added to the current flow data
 * structure. They are both of type uint32_t. In addition, a new action,
 * RECIRC, are added.
 *
 * The value recirc_id is used to distinguish a packet from multiple
 * iterations of recirculation. A packet initially received is considered of
 * having recirc_id of 0. Recirc_id is managed by the user space, opaque to
 * the data path.
 *
 * On the other hand, dp_hash can only be computed by the data path, opaque to
 * the user space. In fact, user space may not able to recompute the hash
 * value. The dp_hash value should be wildcarded when for a newly received
 * packet. RECIRC action specifies whether the hash is computed. If computed,
 * how many fields to be included in the hash computation. The computed hash
 * value is stored into the dp_hash field prior to recirculation.
 *
 * The RECIRC action computes and set the dp_hash field, set the recirc_id
 * field and then reprocess the packet as if it was received on the same input
 * port. RECIRC action works like a function call; actions listed behind the
 * RECIRC action will be executed after its execution.  RECIRC action can be
 * nested, data path implementation limits the number of recirculation executed
 * to prevent unreasonable nesting depth or infinite loop.
 *
 * Both flow fields and the RECIRC action are exposed as OpenFlow fields via
 * Nicira extensions.
 *
 * Post recirculation flow
 * ------------------------
 *
 * At the OpenFlow level, post recirculation rules are always hidden from the
 * controller.  They are installed in table 254 which is set up as a hidden
 * table during boot time. Those rules are managed by the local user space
 * program only.
 *
 * To speed up the classifier look up process, recirc_id is always reflected
 * into the metadata field, since recirc_id is required to be exactly matched.
 *
 * Classifier look up always starts with table 254. A post recirculation flow
 * lookup should find its hidden rule within this table. On the other hand, A
 * newly received packet should miss all post recirculation rules because its
 * recirc_id is zero, then hit a pre-installed lower priority rule to redirect
 * classifier to look up starting from table 0:
 *
 *       * , actions=resubmit(,0)
 *
 * Post recirculation data path flows are managed like other data path flows.
 * They are created on demand. Miss handling, stats collection and revalidation
 * work the same way as regular flows.
 *
 * If the bridge which originates the recirculation is different from the bridge
 * that receives the post recirculation packet (e.g. when patch port is used),
 * the packet will be processed directly by the recirculation bridge with
 * in_port set to OFPP_NONE.  Admittedly, doing this limits the recirculation
 * bridge from matching on in_port of post recirculation packets, and will be
 * fixed in the near future.
 *
 * TODO: Always restore the correct in_port.
 *
 */

struct ofproto_dpif *ofproto_dpif_recirc_get_ofproto(const struct dpif_backer *ofproto,
                                                     uint32_t recirc_id);
uint32_t ofproto_dpif_alloc_recirc_id(struct ofproto_dpif *ofproto);
void ofproto_dpif_free_recirc_id(struct ofproto_dpif *ofproto, uint32_t recirc_id);
int ofproto_dpif_add_internal_flow(struct ofproto_dpif *,
                                   const struct match *, int priority,
                                   uint16_t idle_timeout,
                                   const struct ofpbuf *ofpacts,
                                   struct rule **rulep);
int ofproto_dpif_delete_internal_flow(struct ofproto_dpif *, struct match *,
                                      int priority);

/* struct rule_dpif has struct rule as it's first member. */
#define RULE_CAST(RULE) ((struct rule *)RULE)
#define GROUP_CAST(GROUP) ((struct ofgroup *)GROUP)

static inline struct group_dpif* group_dpif_ref(struct group_dpif *group)
{
    if (group) {
        ofproto_group_ref(GROUP_CAST(group));
    }
    return group;
}

static inline void group_dpif_unref(struct group_dpif *group)
{
    if (group) {
        ofproto_group_unref(GROUP_CAST(group));
    }
}

static inline void rule_dpif_ref(struct rule_dpif *rule)
{
    if (rule) {
        ofproto_rule_ref(RULE_CAST(rule));
    }
}

static inline bool rule_dpif_try_ref(struct rule_dpif *rule)
{
    if (rule) {
        return ofproto_rule_try_ref(RULE_CAST(rule));
    }
    return false;
}


static inline void rule_dpif_unref(struct rule_dpif *rule)
{
    if (rule) {
        ofproto_rule_unref(RULE_CAST(rule));
    }
}

static inline bool rule_dpif_is_fail_open(const struct rule_dpif *rule)
{
    return is_fail_open_rule(RULE_CAST(rule));
}

static inline bool rule_dpif_is_table_miss(const struct rule_dpif *rule)
{
    return rule_is_table_miss(RULE_CAST(rule));
}

/* Returns true if 'rule' is an internal rule, false otherwise. */
static inline bool rule_dpif_is_internal(const struct rule_dpif *rule)
{
    return RULE_CAST(rule)->table_id == TBL_INTERNAL;
}

#undef RULE_CAST

bool ovs_native_tunneling_is_on(struct ofproto_dpif *ofproto);
#endif /* ofproto-dpif.h */
