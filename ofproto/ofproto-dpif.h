/* Copyright (c) 2009-2017 Nicira, Inc.
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

/* ofproto-dpif -- DPIF based ofproto implementation.
 *
 * ofproto-dpif provides an ofproto implementation for those platforms which
 * implement the netdev and dpif interface defined in netdev.h and dpif.h.  The
 * most important of which is the Linux Kernel Module (dpif-netlink), but
 * alternatives are supported such as a userspace only implementation
 * (dpif-netdev), and a dummy implementation used for unit testing.
 *
 * ofproto-dpif is divided into three major chunks.
 *
 * - ofproto-dpif.c
 *   The main ofproto-dpif module is responsible for implementing the
 *   provider interface, installing and removing datapath flows, maintaining
 *   packet statistics, running protocols (BFD, LACP, STP, etc), and
 *   configuring relevant submodules.
 *
 * - ofproto-dpif-upcall.c
 *   ofproto-dpif-upcall is responsible for retrieving upcalls from the kernel,
 *   processing miss upcalls, and handing more complex ones up to the main
 *   ofproto-dpif module.  Miss upcall processing boils down to figuring out
 *   what each packet's actions are, executing them (i.e. asking the kernel to
 *   forward it), and handing it up to ofproto-dpif to decided whether or not
 *   to install a kernel flow.
 *
 * - ofproto-dpif-xlate.c
 *   ofproto-dpif-xlate is responsible for translating OpenFlow actions into
 *   datapath actions.
 */

#include <stdint.h>

#include "dpif.h"
#include "fail-open.h"
#include "hmapx.h"
#include "odp-util.h"
#include "id-pool.h"
#include "ovs-thread.h"
#include "ofproto-provider.h"
#include "util.h"
#include "ovs-thread.h"

struct dpif_flow_stats;
struct ofproto_async_msg;
struct ofproto_dpif;
struct uuid;
struct xlate_cache;
struct xlate_ctx;

/* Number of implemented OpenFlow tables. */
enum { N_TABLES = 255 };
enum { TBL_INTERNAL = N_TABLES - 1 };    /* Used for internal hidden rules. */
BUILD_ASSERT_DECL(N_TABLES >= 2 && N_TABLES <= 255);

struct rule_dpif {
    struct rule up;

    /* These statistics:
     *
     *   - Do include packets and bytes from datapath flows which have not
     *   recently been processed by a revalidator. */
    struct ovs_mutex stats_mutex;
    struct dpif_flow_stats stats OVS_GUARDED;

   /* In non-NULL, will point to a new rule (for which a reference is held) to
    * which all the stats updates should be forwarded. This exists only
    * transitionally when flows are replaced.
    *
    * Protected by stats_mutex.  If both 'rule->stats_mutex' and
    * 'rule->new_rule->stats_mutex' must be held together, acquire them in that
    * order, */
    struct rule_dpif *new_rule OVS_GUARDED;
    bool forward_counts OVS_GUARDED;   /* Forward counts? 'used' time will be
                                        * forwarded in all cases. */

    /* If non-zero then the recirculation id that has
     * been allocated for use with this rule.
     * The recirculation id and associated internal flow should
     * be freed when the rule is freed */
    uint32_t recirc_id;
};

struct rule_dpif *rule_dpif_lookup_from_table(struct ofproto_dpif *,
                                              ovs_version_t, struct flow *,
                                              struct flow_wildcards *,
                                              const struct dpif_flow_stats *,
                                              uint8_t *table_id,
                                              ofp_port_t in_port,
                                              bool may_packet_in,
                                              bool honor_table_miss,
                                              struct xlate_cache *);

void rule_dpif_credit_stats(struct rule_dpif *,
                            const struct dpif_flow_stats *);

void rule_set_recirc_id(struct rule *, uint32_t id);

/* Returns true if 'rule' is an internal rule, false otherwise. */
static inline bool
rule_dpif_is_internal(const struct rule_dpif *rule)
{
    return rule->up.table_id == TBL_INTERNAL;
}

/* Groups. */

enum group_selection_method {
    SEL_METHOD_DEFAULT,
    SEL_METHOD_DP_HASH,
    SEL_METHOD_HASH,
};

struct group_dpif {
    struct ofgroup up;

    /* These statistics:
     *
     *   - Do include packets and bytes from datapath flows which have not
     *   recently been processed by a revalidator. */
    struct ovs_mutex stats_mutex;
    uint64_t packet_count OVS_GUARDED;  /* Number of packets received. */
    uint64_t byte_count OVS_GUARDED;    /* Number of bytes received. */

    enum group_selection_method selection_method;
    enum ovs_hash_alg hash_alg;         /* dp_hash algorithm to be applied. */
    uint32_t hash_basis;                /* Basis for dp_hash. */
    uint32_t hash_mask;                 /* Used to mask dp_hash (2^N - 1).*/
    struct ofputil_bucket **hash_map;   /* Map hash values to buckets. */
};

void group_dpif_credit_stats(struct group_dpif *,
                             struct ofputil_bucket *,
                             const struct dpif_flow_stats *);
struct group_dpif *group_dpif_lookup(struct ofproto_dpif *,
                                     uint32_t group_id, ovs_version_t version,
                                     bool take_ref);


/* Backers.
 *
 * A "backer" is the datapath (dpif) on which an dpif-based bridge (an
 * ofproto-dpif) resides.  A backer can host several bridges, but a bridge is
 * backed by only a single dpif. */


/* DPIF_SUPPORT_FIELD(TYPE, FIELD_NAME, FIELD_DESCRIPTION)
 *
 * Each 'DPIF_SUPPORT_FIELD' defines a member in 'struct dpif_backer_support'
 * and represents support for a datapath action.
 * They are defined as macros to keep 'dpif_show_support()' in sync
 * as new fields are added.  */
#define DPIF_SUPPORT_FIELDS                                                 \
    /* True if the datapath supports masked data in OVS_ACTION_ATTR_SET     \
     * actions. */                                                          \
    DPIF_SUPPORT_FIELD(bool, masked_set_action, "Masked set action")        \
                                                                            \
    /* True if the datapath supports tnl_push and pop actions. */           \
    DPIF_SUPPORT_FIELD(bool, tnl_push_pop, "Tunnel push pop")               \
                                                                            \
    /* True if the datapath supports OVS_FLOW_ATTR_UFID. */                 \
    DPIF_SUPPORT_FIELD(bool, ufid, "Ufid")                                  \
                                                                            \
    /* True if the datapath supports OVS_ACTION_ATTR_TRUNC action. */       \
    DPIF_SUPPORT_FIELD(bool, trunc, "Truncate action")                      \
                                                                            \
    /* True if the datapath supports OVS_ACTION_ATTR_CLONE action. */       \
    DPIF_SUPPORT_FIELD(bool, clone, "Clone action")                         \
                                                                            \
    /* Maximum level of nesting allowed by OVS_ACTION_ATTR_SAMPLE action. */\
    DPIF_SUPPORT_FIELD(size_t, sample_nesting, "Sample nesting")            \
                                                                            \
    /* OVS_CT_ATTR_EVENTMASK supported by OVS_ACTION_ATTR_CT action. */     \
    DPIF_SUPPORT_FIELD(bool, ct_eventmask, "Conntrack eventmask")           \
                                                                            \
    /* True if the datapath supports OVS_ACTION_ATTR_CT_CLEAR action. */    \
    DPIF_SUPPORT_FIELD(bool, ct_clear, "Conntrack clear")                   \
                                                                            \
    /* Highest supported dp_hash algorithm. */                              \
    DPIF_SUPPORT_FIELD(size_t, max_hash_alg, "Max dp_hash algorithm")       \
                                                                            \
    /* True if the datapath supports OVS_ACTION_ATTR_CHECK_PKT_LEN. */   \
    DPIF_SUPPORT_FIELD(bool, check_pkt_len, "Check pkt length action")

/* Stores the various features which the corresponding backer supports. */
struct dpif_backer_support {
#define DPIF_SUPPORT_FIELD(TYPE, NAME, TITLE) TYPE NAME;
    DPIF_SUPPORT_FIELDS
#undef DPIF_SUPPORT_FIELD

    /* Each member represents support for related OVS_KEY_ATTR_* fields. */
    struct odp_support odp;
};

/* Reasons that we might need to revalidate every datapath flow, and
 * corresponding coverage counters.
 *
 * A value of 0 means that there is no need to revalidate.
 *
 * It would be nice to have some cleaner way to integrate with coverage
 * counters, but with only a few reasons I guess this is good enough for
 * now. */
enum revalidate_reason {
    REV_RECONFIGURE = 1,       /* Switch configuration changed. */
    REV_STP,                   /* Spanning tree protocol port status change. */
    REV_RSTP,                  /* RSTP port status change. */
    REV_BOND,                  /* Bonding changed. */
    REV_PORT_TOGGLED,          /* Port enabled or disabled by CFM, LACP, ...*/
    REV_FLOW_TABLE,            /* Flow table changed. */
    REV_MAC_LEARNING,          /* Mac learning changed. */
    REV_MCAST_SNOOPING,        /* Multicast snooping changed. */
};

/* All datapaths of a given type share a single dpif backer instance. */
struct dpif_backer {
    char *type;
    int refcount;
    struct dpif *dpif;
    struct udpif *udpif;

    struct ovs_rwlock odp_to_ofport_lock;
    struct hmap odp_to_ofport_map OVS_GUARDED; /* Contains "struct ofport"s. */

    struct simap tnl_backers;      /* Set of dpif ports backing tunnels. */

    enum revalidate_reason need_revalidate; /* Revalidate all flows. */

    bool recv_set_enable; /* Enables or disables receiving packets. */

    /* Meter. */
    struct id_pool *meter_ids;     /* Datapath meter allocation. */

    /* Connection tracking. */
    struct id_pool *tp_ids;             /* Datapath timeout policy id
                                         * allocation. */
    struct cmap ct_zones;               /* "struct ct_zone"s indexed by zone
                                         * id. */
    struct hmap ct_tps;                 /* "struct ct_timeout_policy"s indexed
                                         * by timeout policy (struct simap). */
    struct ovs_list ct_tp_kill_list;    /* A list of timeout policy to be
                                         * deleted. */

    /* Version string of the datapath stored in OVSDB. */
    char *dp_version_string;

    /* Datapath feature support. */
    struct dpif_backer_support bt_support;   /* Boot time support. Set once
                                                when vswitch starts up, then
                                                it is read only through out
                                                the life time of vswitchd. */
    struct dpif_backer_support rt_support;   /* Runtime support. Can be
                                                set to a lower level in
                                                feature than 'bt_support'. */

    struct atomic_count tnl_count;
};

/* All existing ofproto_backer instances, indexed by ofproto->up.type. */
extern struct shash all_dpif_backers;

struct ofport_dpif *odp_port_to_ofport(const struct dpif_backer *, odp_port_t);

/* A bridge based on a "dpif" datapath. */

struct ofproto_dpif {
    /* In 'all_ofproto_dpifs_by_name'. */
    struct hmap_node all_ofproto_dpifs_by_name_node;

    /* In 'all_ofproto_dpifs_by_uuid'. */
    struct hmap_node all_ofproto_dpifs_by_uuid_node;

    struct ofproto up;
    struct dpif_backer *backer;

    /* Unique identifier for this instantiation of this bridge in this running
     * process.  */
    struct uuid uuid;

    ATOMIC(ovs_version_t) tables_version;  /* For classifier lookups. */

    uint64_t dump_seq; /* Last read of udpif_dump_seq(). */

    /* Special OpenFlow rules. */
    struct rule_dpif *miss_rule; /* Sends flow table misses to controller. */
    struct rule_dpif *no_packet_in_rule; /* Drops flow table misses. */
    struct rule_dpif *drop_frags_rule; /* Used in OFPUTIL_FRAG_DROP mode. */

    /* Bridging. */
    struct netflow *netflow;
    struct dpif_sflow *sflow;
    struct dpif_ipfix *ipfix;
    struct hmap bundles;        /* Contains "struct ofbundle"s. */
    struct mac_learning *ml;
    struct mcast_snooping *ms;
    bool has_bonded_bundles;
    bool lacp_enabled;
    struct mbridge *mbridge;

    struct ovs_mutex stats_mutex;
    struct netdev_stats stats OVS_GUARDED; /* To account packets generated and
                                            * consumed in userspace. */

    /* Spanning tree. */
    struct stp *stp;
    long long int stp_last_tick;

    /* Rapid Spanning Tree. */
    struct rstp *rstp;
    long long int rstp_last_tick;

    /* Ports. */
    struct sset ports;             /* Set of standard port names. */
    struct sset ghost_ports;       /* Ports with no datapath port. */
    struct sset port_poll_set;     /* Queued names for port_poll() reply. */
    int port_poll_errno;           /* Last errno for port_poll() reply. */
    uint64_t change_seq;           /* Connectivity status changes. */

    /* Work queues. */
    struct guarded_list ams;      /* Contains "struct ofproto_async_msgs"s. */
    struct seq *ams_seq;          /* For notifying 'ams' reception. */
    uint64_t ams_seqno;
};

struct ofproto_dpif *ofproto_dpif_lookup_by_name(const char *name);
struct ofproto_dpif *ofproto_dpif_lookup_by_uuid(const struct uuid *uuid);

ovs_version_t ofproto_dpif_get_tables_version(struct ofproto_dpif *);

void ofproto_dpif_credit_table_stats(struct ofproto_dpif *, uint8_t table_id,
                                     uint64_t n_matches, uint64_t n_misses);

int ofproto_dpif_execute_actions(struct ofproto_dpif *, ovs_version_t,
                                 const struct flow *, struct rule_dpif *,
                                 const struct ofpact *, size_t ofpacts_len,
                                 struct dp_packet *);
int ofproto_dpif_execute_actions__(struct ofproto_dpif *, ovs_version_t,
                                   const struct flow *, struct rule_dpif *,
                                   const struct ofpact *, size_t ofpacts_len,
                                   int depth, int resubmits,
                                   struct dp_packet *);
void ofproto_dpif_send_async_msg(struct ofproto_dpif *,
                                 struct ofproto_async_msg *);
int ofproto_dpif_send_packet(const struct ofport_dpif *, bool oam,
                             struct dp_packet *);
enum ofperr ofproto_dpif_flow_mod_init_for_learn(
    struct ofproto_dpif *, const struct ofputil_flow_mod *,
    struct ofproto_flow_mod *);

struct ofport_dpif *ofp_port_to_ofport(const struct ofproto_dpif *,
                                       ofp_port_t);

int ofproto_dpif_add_internal_flow(struct ofproto_dpif *,
                                   struct match *, int priority,
                                   uint16_t idle_timeout,
                                   const struct ofpbuf *ofpacts,
                                   struct rule **rulep);
int ofproto_dpif_delete_internal_flow(struct ofproto_dpif *, struct match *,
                                      int priority);

bool ovs_native_tunneling_is_on(struct ofproto_dpif *);

#endif /* ofproto-dpif.h */
