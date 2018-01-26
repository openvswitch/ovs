/*
 * Copyright (c) 2009-2017 Nicira, Inc.
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

#ifndef OFPROTO_OFPROTO_PROVIDER_H
#define OFPROTO_OFPROTO_PROVIDER_H 1

/* Definitions for use within ofproto.
 *
 *
 * Thread-safety
 * =============
 *
 * Lots of ofproto data structures are only accessed from a single thread.
 * Those data structures are generally not thread-safe.
 *
 * The ofproto-dpif ofproto implementation accesses the flow table from
 * multiple threads, including modifying the flow table from multiple threads
 * via the "learn" action, so the flow table and various structures that index
 * it have been made thread-safe.  Refer to comments on individual data
 * structures for details.
 */

#include "cfm.h"
#include "classifier.h"
#include "guarded-list.h"
#include "heap.h"
#include "hindex.h"
#include "object-collection.h"
#include "ofproto/ofproto.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofp-errors.h"
#include "ovs-atomic.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "timeval.h"
#include "tun-metadata.h"
#include "versions.h"
#include "vl-mff-map.h"

struct match;
struct ofputil_flow_mod;
struct bfd_cfg;
struct meter;
struct ofoperation;
struct ofproto_packet_out;
struct smap;

extern struct ovs_mutex ofproto_mutex;

/* An OpenFlow switch.
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them. */
struct ofproto {
    struct hmap_node hmap_node; /* In global 'all_ofprotos' hmap. */
    const struct ofproto_class *ofproto_class;
    char *type;                 /* Datapath type. */
    char *name;                 /* Datapath name. */

    /* Settings. */
    uint64_t fallback_dpid;     /* Datapath ID if no better choice found. */
    uint64_t datapath_id;       /* Datapath ID. */
    bool forward_bpdu;          /* Option to allow forwarding of BPDU frames
                                 * when NORMAL action is invoked. */
    char *mfr_desc;             /* Manufacturer (NULL for default). */
    char *hw_desc;              /* Hardware (NULL for default). */
    char *sw_desc;              /* Software version (NULL for default). */
    char *serial_desc;          /* Serial number (NULL for default). */
    char *dp_desc;              /* Datapath description (NULL for default). */
    enum ofputil_frag_handling frag_handling;

    /* Datapath. */
    struct hmap ports;          /* Contains "struct ofport"s. */
    struct shash port_by_name;
    struct simap ofp_requests;  /* OpenFlow port number requests. */
    uint16_t alloc_port_no;     /* Last allocated OpenFlow port number. */
    uint16_t max_ports;         /* Max possible OpenFlow port num, plus one. */
    struct hmap ofport_usage;   /* Map ofport to last used time. */
    uint64_t change_seq;        /* Change sequence for netdev status. */

    /* Flow tables. */
    long long int eviction_group_timer; /* For rate limited reheapification. */
    struct oftable *tables;
    int n_tables;
    ovs_version_t tables_version;  /* Controls which rules are visible to
                                    * table lookups. */

    /* Rules indexed on their cookie values, in all flow tables. */
    struct hindex cookies OVS_GUARDED_BY(ofproto_mutex);
    struct hmap learned_cookies OVS_GUARDED_BY(ofproto_mutex);

    /* List of expirable flows, in all flow tables. */
    struct ovs_list expirable OVS_GUARDED_BY(ofproto_mutex);

    /* Meter table.  */
    struct ofputil_meter_features meter_features;
    struct hmap meters;             /* uint32_t indexed 'struct meter *'.  */
    uint32_t slowpath_meter_id;     /* Datapath slowpath meter.  UINT32_MAX
                                       if not defined.  */
    uint32_t controller_meter_id;   /* Datapath controller meter. UINT32_MAX
                                       if not defined.  */

    /* OpenFlow connections. */
    struct connmgr *connmgr;

    int min_mtu;                    /* Current MTU of non-internal ports. */

    /* Groups. */
    struct cmap groups;               /* Contains "struct ofgroup"s. */
    uint32_t n_groups[4] OVS_GUARDED; /* # of existing groups of each type. */
    struct ofputil_group_features ogf;

     /* Tunnel TLV mapping table. */
     OVSRCU_TYPE(struct tun_table *) metadata_tab;

    /* Variable length mf_field mapping. Stores all configured variable length
     * meta-flow fields (struct mf_field) in a switch. */
    struct vl_mff_map vl_mff_map;
};

void ofproto_init_tables(struct ofproto *, int n_tables);
void ofproto_init_max_ports(struct ofproto *, uint16_t max_ports);

struct ofproto *ofproto_lookup(const char *name);
struct ofport *ofproto_get_port(const struct ofproto *, ofp_port_t ofp_port);

/* An OpenFlow port within a "struct ofproto".
 *
 * The port's name is netdev_get_name(port->netdev).
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them. */
struct ofport {
    struct hmap_node hmap_node; /* In struct ofproto's "ports" hmap. */
    struct ofproto *ofproto;    /* The ofproto that contains this port. */
    struct netdev *netdev;
    struct ofputil_phy_port pp;
    ofp_port_t ofp_port;        /* OpenFlow port number. */
    uint64_t change_seq;
    long long int created;      /* Time created, in msec. */
    int mtu;
};

void ofproto_port_set_state(struct ofport *, enum ofputil_port_state);

/* OpenFlow table flags:
 *
 *   - "Hidden" tables are not included in OpenFlow operations that operate on
 *     "all tables".  For example, a request for flow stats on all tables will
 *     omit flows in hidden tables, table stats requests will omit the table
 *     entirely, and the switch features reply will not count the hidden table.
 *
 *     However, operations that specifically name the particular table still
 *     operate on it.  For example, flow_mods and flow stats requests on a
 *     hidden table work.
 *
 *     To avoid gaps in table IDs (which have unclear validity in OpenFlow),
 *     hidden tables must be the highest-numbered tables that a provider
 *     implements.
 *
 *   - "Read-only" tables can't be changed through OpenFlow operations.  (At
 *     the moment all flow table operations go effectively through OpenFlow, so
 *     this means that read-only tables can't be changed at all after the
 *     read-only flag is set.)
 *
 * The generic ofproto layer never sets these flags.  An ofproto provider can
 * set them if it is appropriate.
 */
enum oftable_flags {
    OFTABLE_HIDDEN = 1 << 0,   /* Hide from most OpenFlow operations. */
    OFTABLE_READONLY = 1 << 1  /* Don't allow OpenFlow controller to change
                                  this table. */
};

/* A flow table within a "struct ofproto".
 *
 *
 * Thread-safety
 * =============
 *
 * Adding or removing rules requires holding ofproto_mutex.
 *
 * Rules in 'cls' are RCU protected.  For extended access to a rule, try
 * incrementing its ref_count with ofproto_rule_try_ref(), or
 * ofproto_rule_ref(), if the rule is still known to be in 'cls'.  A rule
 * will be freed using ovsrcu_postpone() once its 'ref_count' reaches zero.
 *
 * Modifying a rule requires the rule's own mutex.
 *
 * Freeing a rule requires ofproto_mutex.  After removing the rule from the
 * classifier, release a ref_count from the rule ('cls''s reference to the
 * rule).
 *
 * Refer to the thread-safety notes on struct rule for more information.*/
struct oftable {
    enum oftable_flags flags;
    struct classifier cls;      /* Contains "struct rule"s. */
    char *name;                 /* Table name exposed via OpenFlow, or NULL. */

    /* Maximum number of flows or UINT_MAX if there is no limit besides any
     * limit imposed by resource limitations. */
    unsigned int max_flows;
    /* Current number of flows, not counting temporary duplicates nor deferred
     * deletions. */
    unsigned int n_flows;

    /* These members determine the handling of an attempt to add a flow that
     * would cause the table to have more than 'max_flows' flows.
     *
     * If 'eviction_fields' is NULL, overflows will be rejected with an error.
     *
     * If 'eviction_fields' is nonnull (regardless of whether n_eviction_fields
     * is nonzero), an overflow will cause a flow to be removed.  The flow to
     * be removed is chosen to give fairness among groups distinguished by
     * different values for the subfields within 'groups'. */
    struct mf_subfield *eviction_fields;
    size_t n_eviction_fields;

    /* Eviction groups.
     *
     * When a flow is added that would cause the table to have more than
     * 'max_flows' flows, and 'eviction_fields' is nonnull, these groups are
     * used to decide which rule to evict: the rule is chosen from the eviction
     * group that contains the greatest number of rules.*/
    uint32_t eviction_group_id_basis;
    struct hmap eviction_groups_by_id;
    struct heap eviction_groups_by_size;

    /* Flow table miss handling configuration. */
    ATOMIC(enum ofputil_table_miss) miss_config;

    /* Eviction is enabled if either the client (vswitchd) enables it or an
     * OpenFlow controller enables it; thus, a nonzero value indicates that
     * eviction is enabled.  */
#define EVICTION_CLIENT  (1 << 0)  /* Set to 1 if client enables eviction. */
#define EVICTION_OPENFLOW (1 << 1) /* Set to 1 if OpenFlow enables eviction. */
    unsigned int eviction;

    /* If zero, vacancy events are disabled.  If nonzero, this is the type of
       vacancy event that is enabled: either OFPTR_VACANCY_DOWN or
       OFPTR_VACANCY_UP.  Only one type of vacancy event can be enabled at a
       time. */
    enum ofp14_table_reason vacancy_event;

    /* Non-zero values for vacancy_up and vacancy_down indicates that vacancy
     * is enabled by table-mod, else these values are set to zero when
     * vacancy is disabled */
    uint8_t vacancy_down; /* Vacancy threshold when space decreases (%). */
    uint8_t vacancy_up;   /* Vacancy threshold when space increases (%). */

    atomic_ulong n_matched;
    atomic_ulong n_missed;
};

/* Assigns TABLE to each oftable, in turn, in OFPROTO.
 *
 * All parameters are evaluated multiple times. */
#define OFPROTO_FOR_EACH_TABLE(TABLE, OFPROTO)              \
    for ((TABLE) = (OFPROTO)->tables;                       \
         (TABLE) < &(OFPROTO)->tables[(OFPROTO)->n_tables]; \
         (TABLE)++)

/* An OpenFlow flow within a "struct ofproto".
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * the classifier rule->ofproto->tables[rule->table_id].cls.  The text below
 * calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct rule" are motivated by
 * two goals:
 *
 *    - Prevent threads that read members of "struct rule" from reading bad
 *      data due to changes by some thread concurrently modifying those
 *      members.
 *
 *    - Prevent two threads making changes to members of a given "struct rule"
 *      from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A rule 'rule' may be accessed without a risk of being freed by a thread
 * until the thread quiesces (i.e., rules are RCU protected and destructed
 * using ovsrcu_postpone()).  Code that needs to hold onto a rule for a
 * while should increment 'rule->ref_count' either with ofproto_rule_ref()
 * (if 'ofproto_mutex' is held), or with ofproto_rule_try_ref() (when some
 * other thread might remove the rule from 'cls').  ofproto_rule_try_ref()
 * will fail if the rule has already been scheduled for destruction.
 *
 * 'rule->ref_count' protects 'rule' from being freed.  It doesn't protect the
 * rule from being deleted from 'cls' (that's 'ofproto_mutex') and it doesn't
 * protect members of 'rule' from modification (that's 'rule->mutex').
 *
 * 'rule->mutex' protects the members of 'rule' from modification.  It doesn't
 * protect the rule from being deleted from 'cls' (that's 'ofproto_mutex') and
 * it doesn't prevent the rule from being freed (that's 'rule->ref_count').
 *
 * Regarding thread safety, the members of a rule fall into the following
 * categories:
 *
 *    - Immutable.  These members are marked 'const'.
 *
 *    - Members that may be safely read or written only by code holding
 *      ofproto_mutex.  These are marked OVS_GUARDED_BY(ofproto_mutex).
 *
 *    - Members that may be safely read only by code holding ofproto_mutex or
 *      'rule->mutex', and safely written only by coding holding ofproto_mutex
 *      AND 'rule->mutex'.  These are marked OVS_GUARDED.
 */
enum OVS_PACKED_ENUM rule_state {
    RULE_INITIALIZED, /* Rule has been initialized, but not inserted to the
                       * ofproto data structures.  Versioning makes sure the
                       * rule is not visible to lookups by other threads, even
                       * if the rule is added to a classifier. */
    RULE_INSERTED,    /* Rule has been inserted to ofproto data structures and
                       * may be visible to lookups by other threads. */
    RULE_REMOVED,     /* Rule has been removed from ofproto data structures,
                       * and may still be visible to lookups by other threads
                       * until they quiesce, after which the rule will be
                       * removed from the classifier as well. */
};

struct rule {
    /* Where this rule resides in an OpenFlow switch.
     *
     * These are immutable once the rule is constructed, hence 'const'. */
    struct ofproto *const ofproto; /* The ofproto that contains this rule. */
    const struct cls_rule cr;      /* In owning ofproto's classifier. */
    const uint8_t table_id;        /* Index in ofproto's 'tables' array. */

    enum rule_state state;

    /* Protects members marked OVS_GUARDED.
     * Readers only need to hold this mutex.
     * Writers must hold both this mutex AND ofproto_mutex.
     * By implication writers can read *without* taking this mutex while they
     * hold ofproto_mutex. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(ofproto_mutex);

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_count;

    /* A "flow cookie" is the OpenFlow name for a 64-bit value associated with
     * a flow. */
    const ovs_be64 flow_cookie; /* Immutable once rule is constructed. */
    struct hindex_node cookie_node OVS_GUARDED_BY(ofproto_mutex);

    enum ofputil_flow_mod_flags flags OVS_GUARDED;

    /* Timeouts. */
    uint16_t hard_timeout OVS_GUARDED; /* In seconds from ->modified. */
    uint16_t idle_timeout OVS_GUARDED; /* In seconds from ->used. */

    /* Eviction precedence. */
    const uint16_t importance;

    /* Removal reason for sending flow removed message.
     * Used only if 'flags' has OFPUTIL_FF_SEND_FLOW_REM set and if the
     * value is not OVS_OFPRR_NONE. */
    uint8_t removed_reason;

    /* Eviction groups (see comment on struct eviction_group for explanation) .
     *
     * 'eviction_group' is this rule's eviction group, or NULL if it is not in
     * any eviction group.  When 'eviction_group' is nonnull, 'evg_node' is in
     * the ->eviction_group->rules hmap. */
    struct eviction_group *eviction_group OVS_GUARDED_BY(ofproto_mutex);
    struct heap_node evg_node OVS_GUARDED_BY(ofproto_mutex);

    /* OpenFlow actions.  See struct rule_actions for more thread-safety
     * notes. */
    const struct rule_actions * const actions;

    /* In owning meter's 'rules' list.  An empty list if there is no meter. */
    struct ovs_list meter_list_node OVS_GUARDED_BY(ofproto_mutex);

    /* Flow monitors (e.g. for NXST_FLOW_MONITOR, related to struct ofmonitor).
     *
     * 'add_seqno' is the sequence number when this rule was created.
     * 'modify_seqno' is the sequence number when this rule was last modified.
     * See 'monitor_seqno' in connmgr.c for more information. */
    enum nx_flow_monitor_flags monitor_flags OVS_GUARDED_BY(ofproto_mutex);
    uint64_t add_seqno OVS_GUARDED_BY(ofproto_mutex);
    uint64_t modify_seqno OVS_GUARDED_BY(ofproto_mutex);

    /* Optimisation for flow expiry.  In ofproto's 'expirable' list if this
     * rule is expirable, otherwise empty. */
    struct ovs_list expirable OVS_GUARDED_BY(ofproto_mutex);

    /* Times.  Last so that they are more likely close to the stats managed
     * by the provider. */
    long long int created OVS_GUARDED; /* Creation time. */

    /* Must hold 'mutex' for both read/write, 'ofproto_mutex' not needed. */
    long long int modified OVS_GUARDED; /* Time of last modification. */

    /* 1-bit for each present TLV in flow match / action. */
    uint64_t match_tlv_bitmap;
    uint64_t ofpacts_tlv_bitmap;
};

void ofproto_rule_ref(struct rule *);
bool ofproto_rule_try_ref(struct rule *);
void ofproto_rule_unref(struct rule *);

static inline const struct rule_actions * rule_get_actions(const struct rule *);
static inline bool rule_is_table_miss(const struct rule *);
static inline bool rule_is_hidden(const struct rule *);

/* A set of actions within a "struct rule".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct rule_actions may be accessed without a risk of being freed by
 * code that holds 'rule->mutex' (where 'rule' is the rule for which
 * 'rule->actions == actions') or during the RCU active period.
 *
 * All members are immutable: they do not change during the rule's
 * lifetime. */
struct rule_actions {
    /* Flags.
     *
     * 'has_meter' is true if 'ofpacts' contains an OFPACT_METER action.
     *
     * 'has_learn_with_delete' is true if 'ofpacts' contains an OFPACT_LEARN
     * action whose flags include NX_LEARN_F_DELETE_LEARNED. */
    bool has_meter;
    bool has_learn_with_delete;
    bool has_groups;

    /* Actions. */
    uint32_t ofpacts_len;         /* Size of 'ofpacts', in bytes. */
    struct ofpact ofpacts[];      /* Sequence of "struct ofpacts". */
};
BUILD_ASSERT_DECL(offsetof(struct rule_actions, ofpacts) % OFPACT_ALIGNTO == 0);

const struct rule_actions *rule_actions_create(const struct ofpact *, size_t);
void rule_actions_destroy(const struct rule_actions *);
bool ofproto_rule_has_out_port(const struct rule *, ofp_port_t port)
    OVS_REQUIRES(ofproto_mutex);

#define DECL_OFPROTO_COLLECTION(TYPE, NAME)                             \
    DECL_OBJECT_COLLECTION(TYPE, NAME)                                  \
static inline void NAME##_collection_ref(struct NAME##_collection *coll)   \
{                                                                       \
    for (size_t i = 0; i < coll->collection.n; i++) {                   \
        ofproto_##NAME##_ref((TYPE)coll->collection.objs[i]);           \
    }                                                                   \
}                                                                       \
                                                                        \
static inline void NAME##_collection_unref(struct NAME##_collection *coll) \
{                                                                       \
    for (size_t i = 0; i < coll->collection.n; i++) {                   \
        ofproto_##NAME##_unref((TYPE)coll->collection.objs[i]);         \
    }                                                                   \
}

DECL_OFPROTO_COLLECTION (struct rule *, rule)

#define RULE_COLLECTION_FOR_EACH(RULE, RULES)                           \
    for (size_t i__ = 0;                                                \
         i__ < rule_collection_n(RULES)                                 \
             ? (RULE = rule_collection_rules(RULES)[i__]) != NULL : false; \
         i__++)

/* Pairwise iteration through two rule collections that must be of the same
 * size. */
#define RULE_COLLECTIONS_FOR_EACH(RULE1, RULE2, RULES1, RULES2)        \
    for (size_t i__ = 0;                                               \
         i__ < rule_collection_n(RULES1)                               \
             ? ((RULE1 = rule_collection_rules(RULES1)[i__]),          \
                (RULE2 = rule_collection_rules(RULES2)[i__]) != NULL)  \
             : false;                                                  \
         i__++)

/* Limits the number of flows allowed in the datapath. Only affects the
 * ofproto-dpif implementation. */
extern unsigned ofproto_flow_limit;

/* Maximum idle time (in ms) for flows to be cached in the datapath.
 * Revalidators may expire flows more quickly than the configured value based
 * on system load and other factors. This variable is subject to change. */
extern unsigned ofproto_max_idle;

/* Number of upcall handler and revalidator threads. Only affects the
 * ofproto-dpif implementation. */
extern size_t n_handlers, n_revalidators;

static inline struct rule *rule_from_cls_rule(const struct cls_rule *);

void ofproto_rule_expire(struct rule *rule, uint8_t reason)
    OVS_REQUIRES(ofproto_mutex);
void ofproto_rule_delete(struct ofproto *, struct rule *)
    OVS_EXCLUDED(ofproto_mutex);
void ofproto_rule_reduce_timeouts__(struct rule *rule, uint16_t idle_timeout,
                                    uint16_t hard_timeout)
    OVS_REQUIRES(ofproto_mutex) OVS_EXCLUDED(rule->mutex);
void ofproto_rule_reduce_timeouts(struct rule *rule, uint16_t idle_timeout,
                                  uint16_t hard_timeout)
    OVS_EXCLUDED(ofproto_mutex);

/* A group within a "struct ofproto", RCU-protected.
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them. */
struct ofgroup {
    struct cmap_node cmap_node; /* In ofproto's "groups" cmap. */

    /* Group versioning. */
    struct versions versions;

    /* Number of references.
     *
     * This is needed to keep track of references to the group in the xlate
     * module.
     *
     * If the main thread removes the group from an ofproto, we need to
     * guarantee that the group remains accessible to users of
     * xlate_group_actions and the xlate_cache, as the xlate_cache will not be
     * cleaned up until the corresponding datapath flows are revalidated. */
    struct ovs_refcount ref_count;

    /* No lock is needed to protect the fields below since they are not
     * modified after construction. */
    struct ofproto * const ofproto;  /* The ofproto that contains this group. */
    const uint32_t group_id;
    const enum ofp11_group_type type; /* One of OFPGT_*. */
    bool being_deleted;               /* Group removal has begun. */

    const long long int created;      /* Creation time. */
    const long long int modified;     /* Time of last modification. */

    const struct ovs_list buckets;    /* Contains "struct ofputil_bucket"s. */
    const uint32_t n_buckets;

    const struct ofputil_group_props props;

    struct rule_collection rules OVS_GUARDED;   /* Referring rules. */
};

struct ofgroup *ofproto_group_lookup(const struct ofproto *ofproto,
                                     uint32_t group_id, ovs_version_t version,
                                     bool take_ref);

void ofproto_group_ref(struct ofgroup *);
bool ofproto_group_try_ref(struct ofgroup *);
void ofproto_group_unref(struct ofgroup *);

void ofproto_group_delete_all(struct ofproto *)
    OVS_EXCLUDED(ofproto_mutex);

DECL_OFPROTO_COLLECTION (struct ofgroup *, group)

#define GROUP_COLLECTION_FOR_EACH(GROUP, GROUPS)                        \
    for (size_t i__ = 0;                                                \
         i__ < group_collection_n(GROUPS)                               \
             ? (GROUP = group_collection_groups(GROUPS)[i__]) != NULL: false; \
         i__++)

/* Pairwise iteration through two group collections that must be of the same
 * size. */
#define GROUP_COLLECTIONS_FOR_EACH(GROUP1, GROUP2, GROUPS1, GROUPS2)    \
    for (size_t i__ = 0;                                                \
         i__ < group_collection_n(GROUPS1)                              \
             ? ((GROUP1 = group_collection_groups(GROUPS1)[i__]),       \
                (GROUP2 = group_collection_groups(GROUPS2)[i__]) != NULL) \
             : false;                                                   \
         i__++)

/* ofproto class structure, to be defined by each ofproto implementation.
 *
 *
 * Data Structures
 * ===============
 *
 * These functions work primarily with four different kinds of data
 * structures:
 *
 *   - "struct ofproto", which represents an OpenFlow switch.
 *
 *   - "struct ofport", which represents a port within an ofproto.
 *
 *   - "struct rule", which represents an OpenFlow flow within an ofproto.
 *
 *   - "struct ofgroup", which represents an OpenFlow 1.1+ group within an
 *     ofproto.
 *
 * Each of these data structures contains all of the implementation-independent
 * generic state for the respective concept, called the "base" state.  None of
 * them contains any extra space for ofproto implementations to use.  Instead,
 * each implementation is expected to declare its own data structure that
 * contains an instance of the generic data structure plus additional
 * implementation-specific members, called the "derived" state.  The
 * implementation can use casts or (preferably) the CONTAINER_OF macro to
 * obtain access to derived state given only a pointer to the embedded generic
 * data structure.
 *
 *
 * Life Cycle
 * ==========
 *
 * Four stylized functions accompany each of these data structures:
 *
 *            "alloc"       "construct"       "destruct"       "dealloc"
 *            ------------  ----------------  ---------------  --------------
 *   ofproto  ->alloc       ->construct       ->destruct       ->dealloc
 *   ofport   ->port_alloc  ->port_construct  ->port_destruct  ->port_dealloc
 *   rule     ->rule_alloc  ->rule_construct  ->rule_destruct  ->rule_dealloc
 *   group    ->group_alloc ->group_construct ->group_destruct ->group_dealloc
 *
 * "ofproto", "ofport", and "group" have this exact life cycle.  The "rule"
 * data structure also follow this life cycle with some additional elaborations
 * described under "Rule Life Cycle" below.
 *
 * Any instance of a given data structure goes through the following life
 * cycle:
 *
 *   1. The client calls the "alloc" function to obtain raw memory.  If "alloc"
 *      fails, skip all the other steps.
 *
 *   2. The client initializes all of the data structure's base state.  If this
 *      fails, skip to step 7.
 *
 *   3. The client calls the "construct" function.  The implementation
 *      initializes derived state.  It may refer to the already-initialized
 *      base state.  If "construct" fails, skip to step 6.
 *
 *   4. The data structure is now initialized and in use.
 *
 *   5. When the data structure is no longer needed, the client calls the
 *      "destruct" function.  The implementation uninitializes derived state.
 *      The base state has not been uninitialized yet, so the implementation
 *      may still refer to it.
 *
 *   6. The client uninitializes all of the data structure's base state.
 *
 *   7. The client calls the "dealloc" to free the raw memory.  The
 *      implementation must not refer to base or derived state in the data
 *      structure, because it has already been uninitialized.
 *
 * Each "alloc" function allocates and returns a new instance of the respective
 * data structure.  The "alloc" function is not given any information about the
 * use of the new data structure, so it cannot perform much initialization.
 * Its purpose is just to ensure that the new data structure has enough room
 * for base and derived state.  It may return a null pointer if memory is not
 * available, in which case none of the other functions is called.
 *
 * Each "construct" function initializes derived state in its respective data
 * structure.  When "construct" is called, all of the base state has already
 * been initialized, so the "construct" function may refer to it.  The
 * "construct" function is allowed to fail, in which case the client calls the
 * "dealloc" function (but not the "destruct" function).
 *
 * Each "destruct" function uninitializes and frees derived state in its
 * respective data structure.  When "destruct" is called, the base state has
 * not yet been uninitialized, so the "destruct" function may refer to it.  The
 * "destruct" function is not allowed to fail.
 *
 * Each "dealloc" function frees raw memory that was allocated by the
 * "alloc" function.  The memory's base and derived members might not have ever
 * been initialized (but if "construct" returned successfully, then it has been
 * "destruct"ed already).  The "dealloc" function is not allowed to fail.
 *
 *
 * Conventions
 * ===========
 *
 * Most of these functions return 0 if they are successful or a positive error
 * code on failure.  Depending on the function, valid error codes are either
 * errno values or OFPERR_* OpenFlow error codes.
 *
 * Most of these functions are expected to execute synchronously, that is, to
 * block as necessary to obtain a result.  Thus, these functions may return
 * EAGAIN (or EWOULDBLOCK or EINPROGRESS) only where the function descriptions
 * explicitly say those errors are a possibility.  We may relax this
 * requirement in the future if and when we encounter performance problems. */
struct ofproto_class {
/* ## ----------------- ## */
/* ## Factory Functions ## */
/* ## ----------------- ## */

    /* Initializes provider.  The caller may pass in 'iface_hints',
     * which contains an shash of "struct iface_hint" elements indexed
     * by the interface's name.  The provider may use these hints to
     * describe the startup configuration in order to reinitialize its
     * state.  The caller owns the provided data, so a provider must
     * make copies of anything required.  An ofproto provider must
     * remove any existing state that is not described by the hint, and
     * may choose to remove it all. */
    void (*init)(const struct shash *iface_hints);

    /* Enumerates the types of all supported ofproto types into 'types'.  The
     * caller has already initialized 'types'.  The implementation should add
     * its own types to 'types' but not remove any existing ones, because other
     * ofproto classes might already have added names to it. */
    void (*enumerate_types)(struct sset *types);

    /* Enumerates the names of all existing datapath of the specified 'type'
     * into 'names' 'all_dps'.  The caller has already initialized 'names' as
     * an empty sset.
     *
     * 'type' is one of the types enumerated by ->enumerate_types().
     *
     * Returns 0 if successful, otherwise a positive errno value.
     */
    int (*enumerate_names)(const char *type, struct sset *names);

    /* Deletes the datapath with the specified 'type' and 'name'.  The caller
     * should have closed any open ofproto with this 'type' and 'name'; this
     * function is allowed to fail if that is not the case.
     *
     * 'type' is one of the types enumerated by ->enumerate_types().
     * 'name' is one of the names enumerated by ->enumerate_names() for 'type'.
     *
     * Returns 0 if successful, otherwise a positive errno value.
     */
    int (*del)(const char *type, const char *name);

    /* Returns the type to pass to netdev_open() when a datapath of type
     * 'datapath_type' has a port of type 'port_type', for a few special
     * cases when a netdev type differs from a port type.  For example,
     * when using the userspace datapath, a port of type "internal"
     * needs to be opened as "tap".
     *
     * Returns either 'type' itself or a string literal, which must not
     * be freed. */
    const char *(*port_open_type)(const char *datapath_type,
                                  const char *port_type);

/* ## ------------------------ ## */
/* ## Top-Level type Functions ## */
/* ## ------------------------ ## */

    /* Performs any periodic activity required on ofprotos of type
     * 'type'.
     *
     * An ofproto provider may implement it or not, depending on whether
     * it needs type-level maintenance.
     *
     * Returns 0 if successful, otherwise a positive errno value. */
    int (*type_run)(const char *type);

    /* Causes the poll loop to wake up when a type 'type''s 'run'
     * function needs to be called, e.g. by calling the timer or fd
     * waiting functions in poll-loop.h.
     *
     * An ofproto provider may implement it or not, depending on whether
     * it needs type-level maintenance. */
    void (*type_wait)(const char *type);

/* ## --------------------------- ## */
/* ## Top-Level ofproto Functions ## */
/* ## --------------------------- ## */

    /* Life-cycle functions for an "ofproto" (see "Life Cycle" above).
     *
     *
     * Construction
     * ============
     *
     * ->construct() should not modify any base members of the ofproto.  The
     * client will initialize the ofproto's 'ports' and 'tables' members after
     * construction is complete.
     *
     * When ->construct() is called, the client does not yet know how many flow
     * tables the datapath supports, so ofproto->n_tables will be 0 and
     * ofproto->tables will be NULL.  ->construct() should call
     * ofproto_init_tables() to allocate and initialize ofproto->n_tables and
     * ofproto->tables.  Each flow table will be initially empty, so
     * ->construct() should delete flows from the underlying datapath, if
     * necessary, rather than populating the tables.
     *
     * If the ofproto knows the maximum port number that the datapath can have,
     * then it can call ofproto_init_max_ports().  If it does so, then the
     * client will ensure that the actions it allows to be used through
     * OpenFlow do not refer to ports above that maximum number.
     *
     * Only one ofproto instance needs to be supported for any given datapath.
     * If a datapath is already open as part of one "ofproto", then another
     * attempt to "construct" the same datapath as part of another ofproto is
     * allowed to fail with an error.
     *
     * ->construct() returns 0 if successful, otherwise a positive errno
     * value.
     *
     *
     * Destruction
     * ===========
     *
     * ->destruct() must also destroy all remaining rules in the ofproto's
     * tables, by passing each remaining rule to ofproto_rule_delete(), then
     * destroy all remaining groups by calling ofproto_group_delete_all().
     *
     * The client will destroy the flow tables themselves after ->destruct()
     * returns.
     */
    struct ofproto *(*alloc)(void);
    int (*construct)(struct ofproto *ofproto);
    void (*destruct)(struct ofproto *ofproto, bool del);
    void (*dealloc)(struct ofproto *ofproto);

    /* Performs any periodic activity required by 'ofproto'.  It should:
     *
     *   - Call connmgr_send_packet_in() for each received packet that missed
     *     in the OpenFlow flow table or that had a OFPP_CONTROLLER output
     *     action.
     *
     *   - Call ofproto_rule_expire() for each OpenFlow flow that has reached
     *     its hard_timeout or idle_timeout, to expire the flow.
     *
     * Returns 0 if successful, otherwise a positive errno value. */
    int (*run)(struct ofproto *ofproto);

    /* Causes the poll loop to wake up when 'ofproto''s 'run' function needs to
     * be called, e.g. by calling the timer or fd waiting functions in
     * poll-loop.h.  */
    void (*wait)(struct ofproto *ofproto);

    /* Adds some memory usage statistics for the implementation of 'ofproto'
     * into 'usage', for use with memory_report().
     *
     * This function is optional. */
    void (*get_memory_usage)(const struct ofproto *ofproto,
                             struct simap *usage);

    /* Adds some memory usage statistics for the implementation of 'type'
     * into 'usage', for use with memory_report().
     *
     * This function is optional. */
    void (*type_get_memory_usage)(const char *type, struct simap *usage);

    /* Every "struct rule" in 'ofproto' is about to be deleted, one by one.
     * This function may prepare for that, for example by clearing state in
     * advance.  It should *not* actually delete any "struct rule"s from
     * 'ofproto', only prepare for it.
     *
     * This function is optional; it's really just for optimization in case
     * it's cheaper to delete all the flows from your hardware in a single pass
     * than to do it one by one. */
    void (*flush)(struct ofproto *ofproto);

    /* Helper for the OpenFlow OFPT_TABLE_FEATURES request.
     *
     * The 'features' array contains 'ofproto->n_tables' elements.  Each
     * element is initialized as:
     *
     *   - 'table_id' to the array index.
     *
     *   - 'name' to "table#" where # is the table ID.
     *
     *   - 'metadata_match' and 'metadata_write' to OVS_BE64_MAX.
     *
     *   - 'config' to the table miss configuration.
     *
     *   - 'max_entries' to 1,000,000.
     *
     *   - Both 'nonmiss' and 'miss' to:
     *
     *     * 'next' to all 1-bits for all later tables.
     *
     *     * 'instructions' to all instructions.
     *
     *     * 'write' and 'apply' both to:
     *
     *       - 'ofpacts': All actions.
     *
     *       - 'set_fields': All fields.
     *
     *   - 'match', 'mask', and 'wildcard' to all fields.
     *
     * If 'stats' is nonnull, it also contains 'ofproto->n_tables' elements.
     * Each element is initialized as:
     *
     *   - 'table_id' to the array index.
     *
     *   - 'active_count' to the 'n_flows' of struct ofproto for the table.
     *
     *   - 'lookup_count' and 'matched_count' to 0.
     *
     * The implementation should update any members in each element for which
     * it has better values:
     *
     *   - Any member of 'features' to better describe the implementation's
     *     capabilities.
     *
     *   - 'lookup_count' to the number of packets looked up in this flow table
     *     so far.
     *
     *   - 'matched_count' to the number of packets looked up in this flow
     *     table so far that matched one of the flow entries.
     */
    void (*query_tables)(struct ofproto *ofproto,
                         struct ofputil_table_features *features,
                         struct ofputil_table_stats *stats);

    /* Sets the current tables version the provider should use for classifier
     * lookups.  This must be called with a new version number after each set
     * of flow table changes has been completed, so that datapath revalidation
     * can be triggered. */
    void (*set_tables_version)(struct ofproto *ofproto, ovs_version_t version);

/* ## ---------------- ## */
/* ## ofport Functions ## */
/* ## ---------------- ## */

    /* Life-cycle functions for a "struct ofport" (see "Life Cycle" above).
     *
     * ->port_construct() should not modify any base members of the ofport.
     * An ofproto implementation should use the 'ofp_port' member of
     * "struct ofport" as the OpenFlow port number.
     *
     * ofports are managed by the base ofproto code.  The ofproto
     * implementation should only create and destroy them in response to calls
     * to these functions.  The base ofproto code will create and destroy
     * ofports in the following situations:
     *
     *   - Just after the ->construct() function is called, the base ofproto
     *     iterates over all of the implementation's ports, using
     *     ->port_dump_start() and related functions, and constructs an ofport
     *     for each dumped port.
     *
     *   - If ->port_poll() reports that a specific port has changed, then the
     *     base ofproto will query that port with ->port_query_by_name() and
     *     construct or destruct ofports as necessary to reflect the updated
     *     set of ports.
     *
     *   - If ->port_poll() returns ENOBUFS to report an unspecified port set
     *     change, then the base ofproto will iterate over all of the
     *     implementation's ports, in the same way as at ofproto
     *     initialization, and construct and destruct ofports to reflect all of
     *     the changes.
     *
     *   - On graceful shutdown, the base ofproto code will destruct all
     *     the ports.
     *
     * ->port_construct() returns 0 if successful, otherwise a positive errno
     * value.
     *
     *
     * ->port_destruct()
     * =================
     *
     * ->port_destruct() takes a 'del' parameter.  If the provider implements
     * the datapath itself (e.g. dpif-netdev, it can ignore 'del'.  On the
     * other hand, if the provider is an interface to an external datapath
     * (e.g. to a kernel module that implement the datapath) then 'del' should
     * influence destruction behavior in the following way:
     *
     *   - If 'del' is true, it should remove the port from the underlying
     *     implementation.  This is the common case.
     *
     *   - If 'del' is false, it should leave the port in the underlying
     *     implementation.  This is used when Open vSwitch is performing a
     *     graceful shutdown and ensures that, across Open vSwitch restarts,
     *     the underlying ports are not removed and recreated.  That makes an
     *     important difference for, e.g., "internal" ports that have
     *     configured IP addresses; without this distinction, the IP address
     *     and other configured state for the port is lost.
     */
    struct ofport *(*port_alloc)(void);
    int (*port_construct)(struct ofport *ofport);
    void (*port_destruct)(struct ofport *ofport, bool del);
    void (*port_dealloc)(struct ofport *ofport);

    /* Called after 'ofport->netdev' is replaced by a new netdev object.  If
     * the ofproto implementation uses the ofport's netdev internally, then it
     * should switch to using the new one.  The old one has been closed.
     *
     * An ofproto implementation that doesn't need to do anything in this
     * function may use a null pointer. */
    void (*port_modified)(struct ofport *ofport);

    /* Called after an OpenFlow request changes a port's configuration.
     * 'ofport->pp.config' contains the new configuration.  'old_config'
     * contains the previous configuration.
     *
     * The caller implements OFPUTIL_PC_PORT_DOWN using netdev functions to
     * turn NETDEV_UP on and off, so this function doesn't have to do anything
     * for that bit (and it won't be called if that is the only bit that
     * changes). */
    void (*port_reconfigured)(struct ofport *ofport,
                              enum ofputil_port_config old_config);

    /* Looks up a port named 'devname' in 'ofproto'.  On success, returns 0 and
     * initializes '*port' appropriately. Otherwise, returns a positive errno
     * value.
     *
     * The caller owns the data in 'port' and must free it with
     * ofproto_port_destroy() when it is no longer needed. */
    int (*port_query_by_name)(const struct ofproto *ofproto,
                              const char *devname, struct ofproto_port *port);

    /* Attempts to add 'netdev' as a port on 'ofproto'.  Returns 0 if
     * successful, otherwise a positive errno value.  The caller should
     * inform the implementation of the OpenFlow port through the
     * ->port_construct() method.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_add)(struct ofproto *ofproto, struct netdev *netdev);

    /* Deletes port number 'ofp_port' from the datapath for 'ofproto'.  Returns
     * 0 if successful, otherwise a positive errno value.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_del)(struct ofproto *ofproto, ofp_port_t ofp_port);

    /* Refreshes datapath configuration of 'port'.
     * Returns 0 if successful, otherwise a positive errno value. */
    int (*port_set_config)(const struct ofport *port, const struct smap *cfg);

    /* Get port stats */
    int (*port_get_stats)(const struct ofport *port,
                          struct netdev_stats *stats);

    /* Port iteration functions.
     *
     * The client might not be entirely in control of the ports within an
     * ofproto.  Some hardware implementations, for example, might have a fixed
     * set of ports in a datapath.  For this reason, the client needs a way to
     * iterate through all the ports that are actually in a datapath.  These
     * functions provide that functionality.
     *
     * The 'state' pointer provides the implementation a place to
     * keep track of its position.  Its format is opaque to the caller.
     *
     * The ofproto provider retains ownership of the data that it stores into
     * ->port_dump_next()'s 'port' argument.  The data must remain valid until
     * at least the next call to ->port_dump_next() or ->port_dump_done() for
     * 'state'.  The caller will not modify or free it.
     *
     * Details
     * =======
     *
     * ->port_dump_start() attempts to begin dumping the ports in 'ofproto'.
     * On success, it should return 0 and initialize '*statep' with any data
     * needed for iteration.  On failure, returns a positive errno value, and
     * the client will not call ->port_dump_next() or ->port_dump_done().
     *
     * ->port_dump_next() attempts to retrieve another port from 'ofproto' for
     * 'state'.  If there is another port, it should store the port's
     * information into 'port' and return 0.  It should return EOF if all ports
     * have already been iterated.  Otherwise, on error, it should return a
     * positive errno value.  This function will not be called again once it
     * returns nonzero once for a given iteration (but the 'port_dump_done'
     * function will be called afterward).
     *
     * ->port_dump_done() allows the implementation to release resources used
     * for iteration.  The caller might decide to stop iteration in the middle
     * by calling this function before ->port_dump_next() returns nonzero.
     *
     * Usage Example
     * =============
     *
     * int error;
     * void *state;
     *
     * error = ofproto->ofproto_class->port_dump_start(ofproto, &state);
     * if (!error) {
     *     for (;;) {
     *         struct ofproto_port port;
     *
     *         error = ofproto->ofproto_class->port_dump_next(
     *                     ofproto, state, &port);
     *         if (error) {
     *             break;
     *         }
     *         // Do something with 'port' here (without modifying or freeing
     *         // any of its data).
     *     }
     *     ofproto->ofproto_class->port_dump_done(ofproto, state);
     * }
     * // 'error' is now EOF (success) or a positive errno value (failure).
     */
    int (*port_dump_start)(const struct ofproto *ofproto, void **statep);
    int (*port_dump_next)(const struct ofproto *ofproto, void *state,
                          struct ofproto_port *port);
    int (*port_dump_done)(const struct ofproto *ofproto, void *state);

    /* Polls for changes in the set of ports in 'ofproto'.  If the set of ports
     * in 'ofproto' has changed, then this function should do one of the
     * following:
     *
     * - Preferably: store the name of the device that was added to or deleted
     *   from 'ofproto' in '*devnamep' and return 0.  The caller is responsible
     *   for freeing '*devnamep' (with free()) when it no longer needs it.
     *
     * - Alternatively: return ENOBUFS, without indicating the device that was
     *   added or deleted.
     *
     * Occasional 'false positives', in which the function returns 0 while
     * indicating a device that was not actually added or deleted or returns
     * ENOBUFS without any change, are acceptable.
     *
     * The purpose of 'port_poll' is to let 'ofproto' know about changes made
     * externally to the 'ofproto' object, e.g. by a system administrator via
     * ovs-dpctl.  Therefore, it's OK, and even preferable, for port_poll() to
     * not report changes made through calls to 'port_add' or 'port_del' on the
     * same 'ofproto' object.  (But it's OK for it to report them too, just
     * slightly less efficient.)
     *
     * If the set of ports in 'ofproto' has not changed, returns EAGAIN.  May
     * also return other positive errno values to indicate that something has
     * gone wrong.
     *
     * If the set of ports in a datapath is fixed, or if the only way that the
     * set of ports in a datapath can change is through ->port_add() and
     * ->port_del(), then this function may be a null pointer.
     */
    int (*port_poll)(const struct ofproto *ofproto, char **devnamep);

    /* Arranges for the poll loop to wake up when ->port_poll() will return a
     * value other than EAGAIN.
     *
     * If the set of ports in a datapath is fixed, or if the only way that the
     * set of ports in a datapath can change is through ->port_add() and
     * ->port_del(), or if the poll loop will always wake up anyway when
     * ->port_poll() will return a value other than EAGAIN, then this function
     * may be a null pointer.
     */
    void (*port_poll_wait)(const struct ofproto *ofproto);

    /* Checks the status of LACP negotiation for 'port'.  Returns 1 if LACP
     * partner information for 'port' is up-to-date, 0 if LACP partner
     * information is not current (generally indicating a connectivity
     * problem), or -1 if LACP is not enabled on 'port'.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support LACP.
     */
    int (*port_is_lacp_current)(const struct ofport *port);

    /* Get LACP port stats. Returns -1 if LACP is not enabled on 'port'.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support LACP.
     */
    int (*port_get_lacp_stats)(const struct ofport *port,
                               struct lacp_slave_stats *stats);

/* ## ----------------------- ## */
/* ## OpenFlow Rule Functions ## */
/* ## ----------------------- ## */

    /* Chooses an appropriate table for 'match' within 'ofproto'.  On
     * success, stores the table ID into '*table_idp' and returns 0.  On
     * failure, returns an OpenFlow error code.
     *
     * The choice of table should be a function of 'match' and 'ofproto''s
     * datapath capabilities.  It should not depend on the flows already in
     * 'ofproto''s flow tables.  Failure implies that an OpenFlow rule with
     * 'match' as its matching condition can never be inserted into 'ofproto',
     * even starting from an empty flow table.
     *
     * If multiple tables are candidates for inserting the flow, the function
     * should choose one arbitrarily (but deterministically).
     *
     * If this function is NULL then table 0 is always chosen. */
    enum ofperr (*rule_choose_table)(const struct ofproto *ofproto,
                                     const struct match *match,
                                     uint8_t *table_idp);

    /* Life-cycle functions for a "struct rule".
     *
     *
     * Rule Life Cycle
     * ===============
     *
     * The life cycle of a struct rule is an elaboration of the basic life
     * cycle described above under "Life Cycle".
     *
     * After a rule is successfully constructed, it is then inserted.  If
     * insertion is successful, then before it is later destructed, it is
     * deleted.
     *
     * You can think of a rule as having the following extra steps inserted
     * between "Life Cycle" steps 4 and 5:
     *
     *   4.1. The client inserts the rule into the flow table, making it
     *        visible in flow table lookups.
     *
     *   4.2. The client calls "rule_insert" to insert the flow.  The
     *        implementation attempts to install the flow in the underlying
     *        hardware and returns an error code indicate success or failure.
     *        On failure, go to step 5.
     *
     *   4.3. The rule is now installed in the flow table.  Eventually it will
     *        be deleted.
     *
     *   4.4. The client removes the rule from the flow table.  It is no longer
     *        visible in flow table lookups.
     *
     *   4.5. The client calls "rule_delete".  The implementation uninstalls
     *        the flow from the underlying hardware.  Deletion is not allowed
     *        to fail.
     *
     *
     * Construction
     * ============
     *
     * When ->rule_construct() is called, 'rule' is a new rule that is not yet
     * inserted into a flow table.  ->rule_construct() should initialize enough
     * of the rule's derived state for 'rule' to be suitable for inserting into
     * a flow table.  ->rule_construct() should not modify any base members of
     * struct rule.
     *
     * If ->rule_construct() fails (as indicated by returning a nonzero
     * OpenFlow error code), the ofproto base code will uninitialize and
     * deallocate 'rule'.  See "Rule Life Cycle" above for more details.
     *
     * ->rule_construct() must also:
     *
     *   - Validate that the datapath supports the matching rule in 'rule->cr'
     *     datapath.  For example, if the rule's table does not support
     *     registers, then it is an error if 'rule->cr' does not wildcard all
     *     registers.
     *
     *   - Validate that the datapath can correctly implement 'rule->ofpacts'.
     *
     * After a successful construction the rest of the rule life cycle calls
     * may not fail, so ->rule_construct() must also make sure that the rule
     * can be inserted in to the datapath.
     *
     *
     * Insertion
     * =========
     *
     * Following successful construction, the ofproto base case inserts 'rule'
     * into its flow table, then it calls ->rule_insert().  ->rule_insert()
     * must add the new rule to the datapath flow table and return only after
     * this is complete.  The 'new_rule' may be a duplicate of an 'old_rule'.
     * In this case the 'old_rule' is non-null, and the implementation should
     * forward rule statistics counts from the 'old_rule' to the 'new_rule' if
     * 'forward_counts' is 'true', 'used' timestamp is always forwarded.  This
     * may not fail.
     *
     *
     * Deletion
     * ========
     *
     * The ofproto base code removes 'rule' from its flow table before it calls
     * ->rule_delete() (if non-null).  ->rule_delete() must remove 'rule' from
     * the datapath flow table and return only after this has completed
     * successfully.
     *
     * Rule deletion must not fail.
     *
     *
     * Destruction
     * ===========
     *
     * ->rule_destruct() must uninitialize derived state.
     *
     * Rule destruction must not fail. */
    struct rule *(*rule_alloc)(void);
    enum ofperr (*rule_construct)(struct rule *rule)
        /* OVS_REQUIRES(ofproto_mutex) */;
    void (*rule_insert)(struct rule *rule, struct rule *old_rule,
                        bool forward_counts)
        /* OVS_REQUIRES(ofproto_mutex) */;
    void (*rule_delete)(struct rule *rule) /* OVS_REQUIRES(ofproto_mutex) */;
    void (*rule_destruct)(struct rule *rule);
    void (*rule_dealloc)(struct rule *rule);

    /* Obtains statistics for 'rule', storing the number of packets that have
     * matched it in '*packet_count' and the number of bytes in those packets
     * in '*byte_count'.  UINT64_MAX indicates that the packet count or byte
     * count is unknown. */
    void (*rule_get_stats)(struct rule *rule, uint64_t *packet_count,
                           uint64_t *byte_count, long long int *used)
        /* OVS_EXCLUDED(ofproto_mutex) */;

    /* Translates actions in 'opo->ofpacts', for 'opo->packet' in flow tables
     * in version 'opo->version'.  This is useful for OpenFlow OFPT_PACKET_OUT.
     *
     * This function must validate that it can correctly translate
     * 'opo->ofpacts'.  If not, then it should return an OpenFlow error code.
     *
     * 'opo->flow' reflects the flow information for 'opo->packet'.  All of the
     * information in 'opo->flow' is extracted from 'opo->packet', except for
     * 'in_port', which is assigned to the correct value for the incoming
     * packet.  'tunnel' and register values should be zeroed.  'packet''s
     * header pointers and offsets (e.g. packet->l3) are appropriately
     * initialized.  packet->l3 is aligned on a 32-bit boundary.
     *
     * Returns 0 if successful, otherwise an OpenFlow error code.
     *
     * This function may be called with 'ofproto_mutex' held. */
    enum ofperr (*packet_xlate)(struct ofproto *,
                                struct ofproto_packet_out *opo);

    /* Free resources taken by a successful packet_xlate().  If multiple
     * packet_xlate() calls have been made in sequence, the corresponding
     * packet_xlate_revert() calls have to be made in reverse order. */
    void (*packet_xlate_revert)(struct ofproto *, struct ofproto_packet_out *);

    /* Executes the datapath actions, translation side-effects, and stats as
     * produced by ->packet_xlate().  The caller retains ownership of 'opo'.
     */
    void (*packet_execute)(struct ofproto *, struct ofproto_packet_out *opo);

    /* Changes the OpenFlow IP fragment handling policy to 'frag_handling',
     * which takes one of the following values, with the corresponding
     * meanings:
     *
     *  - OFPUTIL_FRAG_NORMAL: The switch should treat IP fragments the same
     *    way as other packets, omitting TCP and UDP port numbers (always
     *    setting them to 0).
     *
     *  - OFPUTIL_FRAG_DROP: The switch should drop all IP fragments without
     *    passing them through the flow table.
     *
     *  - OFPUTIL_FRAG_REASM: The switch should reassemble IP fragments before
     *    passing packets through the flow table.
     *
     *  - OFPUTIL_FRAG_NX_MATCH (a Nicira extension): Similar to
     *    OFPUTIL_FRAG_NORMAL, except that TCP and UDP port numbers should be
     *    included in fragments with offset 0.
     *
     * Implementations are not required to support every mode.
     * OFPUTIL_FRAG_NORMAL is the default mode when an ofproto is created.
     *
     * At the time of the call to ->set_frag_handling(), the current mode is
     * available in 'ofproto->frag_handling'.  ->set_frag_handling() returns
     * true if the requested mode was set, false if it is not supported.
     *
     * Upon successful return, the caller changes 'ofproto->frag_handling' to
     * reflect the new mode.
     */
    bool (*set_frag_handling)(struct ofproto *ofproto,
                              enum ofputil_frag_handling frag_handling);

    enum ofperr (*nxt_resume)(struct ofproto *ofproto,
                              const struct ofputil_packet_in_private *);

/* ## ------------------------- ## */
/* ## OFPP_NORMAL configuration ## */
/* ## ------------------------- ## */

    /* Configures NetFlow on 'ofproto' according to the options in
     * 'netflow_options', or turns off NetFlow if 'netflow_options' is NULL.
     *
     * EOPNOTSUPP as a return value indicates that 'ofproto' does not support
     * NetFlow, as does a null pointer. */
    int (*set_netflow)(struct ofproto *ofproto,
                       const struct netflow_options *netflow_options);

    void (*get_netflow_ids)(const struct ofproto *ofproto,
                            uint8_t *engine_type, uint8_t *engine_id);

    /* Configures sFlow on 'ofproto' according to the options in
     * 'sflow_options', or turns off sFlow if 'sflow_options' is NULL.
     *
     * EOPNOTSUPP as a return value indicates that 'ofproto' does not support
     * sFlow, as does a null pointer. */
    int (*set_sflow)(struct ofproto *ofproto,
                     const struct ofproto_sflow_options *sflow_options);

    /* Configures IPFIX on 'ofproto' according to the options in
     * 'bridge_exporter_options' and the 'flow_exporters_options'
     * array, or turns off IPFIX if 'bridge_exporter_options' and
     * 'flow_exporters_options' is NULL.
     *
     * EOPNOTSUPP as a return value indicates that 'ofproto' does not support
     * IPFIX, as does a null pointer. */
    int (*set_ipfix)(
        struct ofproto *ofproto,
        const struct ofproto_ipfix_bridge_exporter_options
            *bridge_exporter_options,
        const struct ofproto_ipfix_flow_exporter_options
            *flow_exporters_options, size_t n_flow_exporters_options);

    /* Gets IPFIX stats on 'ofproto' according to the exporter of birdge
     * IPFIX or flow-based IPFIX.
     *
     * OFPERR_NXST_NOT_CONFIGURED as a return value indicates that bridge
     * IPFIX or flow-based IPFIX is not configured. */
    int (*get_ipfix_stats)(
        const struct ofproto *ofproto,
        bool bridge_ipfix, struct ovs_list *replies
        );

    /* Configures connectivity fault management on 'ofport'.
     *
     * If 'cfm_settings' is nonnull, configures CFM according to its members.
     *
     * If 'cfm_settings' is null, removes any connectivity fault management
     * configuration from 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support CFM, as does a null pointer. */
    int (*set_cfm)(struct ofport *ofport, const struct cfm_settings *s);

    /* Checks the status change of CFM on 'ofport'.  Returns true if
     * there is status change since last call or if CFM is not specified. */
    bool (*cfm_status_changed)(struct ofport *ofport);

    /* Populates 'smap' with the status of CFM on 'ofport'.  Returns 0 on
     * success, or a positive errno.  EOPNOTSUPP as a return value indicates
     * that this ofproto_class does not support CFM, as does a null pointer.
     *
     * The caller must provide and own '*status', and it must free the array
     * returned in 'status->rmps'.  '*status' is indeterminate if the return
     * value is non-zero. */
    int (*get_cfm_status)(const struct ofport *ofport,
                          struct cfm_status *status);

    /* Configures LLDP on 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support LLDP, as does a null pointer. */
    int (*set_lldp)(struct ofport *ofport, const struct smap *cfg);

    /* Checks the status of LLDP configured on 'ofport'.  Returns true if the
     * port's LLDP status was successfully stored into '*status'.  Returns
     * false if the port did not have LLDP configured, in which case '*status'
     * is indeterminate.
     *
     * The caller must provide and own '*status'.  '*status' is indeterminate
     * if the return value is non-zero. */
    bool (*get_lldp_status)(const struct ofport *ofport,
                            struct lldp_status *status);

    /* Configures Auto Attach.
     *
     * If 's' is nonnull, configures Auto Attach according to its members.
     *
     * If 's' is null, removes any Auto Attach configuration.
     */
    int (*set_aa)(struct ofproto *ofproto,
                  const struct aa_settings *s);

    /* If 's' is nonnull, this function registers a mapping associated with
     * client data pointer 'aux' in 'ofproto'.  If 'aux' is already registered
     * then this function updates its configuration to 's'.  Otherwise, this
     * function registers a new mapping.
     *
     * An implementation that does not support mapping at all may set
     * it to NULL or return EOPNOTSUPP.  An implementation that supports
     * only a subset of the functionality should implement what it can
     * and return 0.
     */
    int (*aa_mapping_set)(struct ofproto *ofproto, void *aux,
                          const struct aa_mapping_settings *s);

    /* If 's' is nonnull, this function unregisters a mapping associated with
     * client data pointer 'aux' in 'ofproto'.  If 'aux' is already registered
     * then this function updates its configuration to 's'.  Otherwise, this
     * function unregisters a new mapping.
     *
     * An implementation that does not support mapping at all may set
     * it to NULL or return EOPNOTSUPP.  An implementation that supports
     * only a subset of the functionality should implement what it can
     * and return 0.
     */
    int (*aa_mapping_unset)(struct ofproto *ofproto, void *aux);

    /*
     * Returns the a list of AutoAttach VLAN operations.  When Auto Attach is
     * enabled, the VLAN associated with an I-SID/VLAN mapping is first
     * negotiated with an Auto Attach Server.  Once an I-SID VLAN mapping
     * becomes active, the corresponding VLAN needs to be communicated to the
     * bridge in order to add the VLAN to the trunk port linking the Auto
     * Attach Client (in this case openvswitch) and the Auto Attach Server.
     *
     * The list entries are of type "struct bridge_aa_vlan".  Each entry
     * specifies the operation (add or remove), the interface on which to
     * execute the operation and the VLAN.
     */
    int (*aa_vlan_get_queued)(struct ofproto *ofproto, struct ovs_list *list);

    /*
     * Returns the current number of entries in the list of VLAN operations
     * in the Auto Attach Client (see previous function description
     * aa_vlan_get_queued).  Returns 0 if Auto Attach is disabled.
     */
    unsigned int (*aa_vlan_get_queue_size)(struct ofproto *ofproto);

    /* Configures BFD on 'ofport'.
     *
     * If 'cfg' is NULL, or 'cfg' does not contain the key value pair
     * "enable=true", removes BFD from 'ofport'.  Otherwise, configures BFD
     * according to 'cfg'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support BFD, as does a null pointer. */
    int (*set_bfd)(struct ofport *ofport, const struct smap *cfg);

    /* Checks the status change of BFD on 'ofport'.  Returns true if there
     * is status change since last call or if BFD is not specified. */
    bool (*bfd_status_changed)(struct ofport *ofport);

    /* Populates 'smap' with the status of BFD on 'ofport'.  Returns 0 on
     * success, or a positive errno.  EOPNOTSUPP as a return value indicates
     * that this ofproto_class does not support BFD, as does a null pointer. */
    int (*get_bfd_status)(struct ofport *ofport, struct smap *smap);

    /* Configures spanning tree protocol (STP) on 'ofproto' using the
     * settings defined in 's'.
     *
     * If 's' is nonnull, configures STP according to its members.
     *
     * If 's' is null, removes any STP configuration from 'ofproto'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*set_stp)(struct ofproto *ofproto,
                   const struct ofproto_stp_settings *s);

    /* Retrieves state of spanning tree protocol (STP) on 'ofproto'.
     *
     * Stores STP state for 'ofproto' in 's'.  If the 'enabled' member
     * is false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*get_stp_status)(struct ofproto *ofproto,
                          struct ofproto_stp_status *s);

    /* Configures spanning tree protocol (STP) on 'ofport' using the
     * settings defined in 's'.
     *
     * If 's' is nonnull, configures STP according to its members.  The
     * caller is responsible for assigning STP port numbers (using the
     * 'port_num' member in the range of 1 through 255, inclusive) and
     * ensuring there are no duplicates.
     *
     * If 's' is null, removes any STP configuration from 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*set_stp_port)(struct ofport *ofport,
                        const struct ofproto_port_stp_settings *s);

    /* Retrieves spanning tree protocol (STP) port status of 'ofport'.
     *
     * Stores STP state for 'ofport' in 's'.  If the 'enabled' member is
     * false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*get_stp_port_status)(struct ofport *ofport,
                               struct ofproto_port_stp_status *s);

    /* Retrieves spanning tree protocol (STP) port statistics of 'ofport'.
     *
     * Stores STP state for 'ofport' in 's'.  If the 'enabled' member is
     * false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*get_stp_port_stats)(struct ofport *ofport,
                              struct ofproto_port_stp_stats *s);

    /* Configures Rapid Spanning Tree Protocol (RSTP) on 'ofproto' using the
     * settings defined in 's'.
     *
     * If 's' is nonnull, configures RSTP according to its members.
     *
     * If 's' is null, removes any RSTP configuration from 'ofproto'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support RSTP, as does a null pointer. */
    void (*set_rstp)(struct ofproto *ofproto,
                    const struct ofproto_rstp_settings *s);

    /* Retrieves state of Rapid Spanning Tree Protocol (RSTP) on 'ofproto'.
     *
     * Stores RSTP state for 'ofproto' in 's'.  If the 'enabled' member
     * is false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support RSTP, as does a null pointer. */
    void (*get_rstp_status)(struct ofproto *ofproto,
                           struct ofproto_rstp_status *s);

    /* Configures Rapid Spanning Tree Protocol (RSTP) on 'ofport' using the
     * settings defined in 's'.
     *
     * If 's' is nonnull, configures RSTP according to its members.  The
     * caller is responsible for assigning RSTP port numbers (using the
     * 'port_num' member in the range of 1 through 255, inclusive) and
     * ensuring there are no duplicates.
     *
     * If 's' is null, removes any RSTP configuration from 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    void (*set_rstp_port)(struct ofport *ofport,
                         const struct ofproto_port_rstp_settings *s);

    /* Retrieves Rapid Spanning Tree Protocol (RSTP) port status of 'ofport'.
     *
     * Stores RSTP state for 'ofport' in 's'.  If the 'enabled' member is
     * false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support RSTP, as does a null pointer. */
    void (*get_rstp_port_status)(struct ofport *ofport,
                                struct ofproto_port_rstp_status *s);

    /* Registers meta-data associated with the 'n_qdscp' Qualities of Service
     * 'queues' attached to 'ofport'.  This data is not intended to be
     * sufficient to implement QoS.  Instead, providers may use this
     * information to implement features which require knowledge of what queues
     * exist on a port, and some basic information about them.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support QoS, as does a null pointer. */
    int (*set_queues)(struct ofport *ofport,
                      const struct ofproto_port_queue *queues, size_t n_qdscp);

    /* If 's' is nonnull, this function registers a "bundle" associated with
     * client data pointer 'aux' in 'ofproto'.  A bundle is the same concept as
     * a Port in OVSDB, that is, it consists of one or more "slave" devices
     * (Interfaces, in OVSDB) along with VLAN and LACP configuration and, if
     * there is more than one slave, a bonding configuration.  If 'aux' is
     * already registered then this function updates its configuration to 's'.
     * Otherwise, this function registers a new bundle.
     *
     * If 's' is NULL, this function unregisters the bundle registered on
     * 'ofproto' associated with client data pointer 'aux'.  If no such bundle
     * has been registered, this has no effect.
     *
     * This function affects only the behavior of the NXAST_AUTOPATH action and
     * output to the OFPP_NORMAL port.  An implementation that does not support
     * it at all may set it to NULL or return EOPNOTSUPP.  An implementation
     * that supports only a subset of the functionality should implement what
     * it can and return 0. */
    int (*bundle_set)(struct ofproto *ofproto, void *aux,
                      const struct ofproto_bundle_settings *s);

    /* If 'port' is part of any bundle, removes it from that bundle.  If the
     * bundle now has no ports, deletes the bundle.  If the bundle now has only
     * one port, deconfigures the bundle's bonding configuration. */
    void (*bundle_remove)(struct ofport *ofport);

    /* If 's' is nonnull, this function registers a mirror associated with
     * client data pointer 'aux' in 'ofproto'.  A mirror is the same concept as
     * a Mirror in OVSDB.  If 'aux' is already registered then this function
     * updates its configuration to 's'.  Otherwise, this function registers a
     * new mirror.
     *
     * If 's' is NULL, this function unregisters the mirror registered on
     * 'ofproto' associated with client data pointer 'aux'.  If no such mirror
     * has been registered, this has no effect.
     *
     * An implementation that does not support mirroring at all may set
     * it to NULL or return EOPNOTSUPP.  An implementation that supports
     * only a subset of the functionality should implement what it can
     * and return 0. */
    int (*mirror_set)(struct ofproto *ofproto, void *aux,
                      const struct ofproto_mirror_settings *s);

    /* Retrieves statistics from mirror associated with client data
     * pointer 'aux' in 'ofproto'.  Stores packet and byte counts in
     * 'packets' and 'bytes', respectively.  If a particular counter is
     * not supported, the appropriate argument is set to UINT64_MAX.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support retrieving mirror statistics. */
    int (*mirror_get_stats)(struct ofproto *ofproto, void *aux,
                            uint64_t *packets, uint64_t *bytes);

    /* Configures the VLANs whose bits are set to 1 in 'flood_vlans' as VLANs
     * on which all packets are flooded, instead of using MAC learning.  If
     * 'flood_vlans' is NULL, then MAC learning applies to all VLANs.
     *
     * This function affects only the behavior of the OFPP_NORMAL action.  An
     * implementation that does not support it may set it to NULL or return
     * EOPNOTSUPP. */
    int (*set_flood_vlans)(struct ofproto *ofproto,
                           unsigned long *flood_vlans);

    /* Returns true if 'aux' is a registered bundle that is currently in use as
     * the output for a mirror. */
    bool (*is_mirror_output_bundle)(const struct ofproto *ofproto, void *aux);

    /* When the configuration option of forward_bpdu changes, this function
     * will be invoked. */
    void (*forward_bpdu_changed)(struct ofproto *ofproto);

    /* Sets the MAC aging timeout for the OFPP_NORMAL action to 'idle_time', in
     * seconds, and the maximum number of MAC table entries to
     * 'max_entries'.
     *
     * An implementation that doesn't support configuring these features may
     * set this function to NULL or implement it as a no-op. */
    void (*set_mac_table_config)(struct ofproto *ofproto,
                                 unsigned int idle_time, size_t max_entries);

    /* Configures multicast snooping on 'ofport' using the settings
     * defined in 's'.
     *
     * If 's' is nonnull, this function updates multicast snooping
     * configuration to 's' in 'ofproto'.
     *
     * If 's' is NULL, this function disables multicast snooping
     * on 'ofproto'.
     *
     * An implementation that does not support multicast snooping may set
     * it to NULL or return EOPNOTSUPP. */
    int (*set_mcast_snooping)(struct ofproto *ofproto,
                              const struct ofproto_mcast_snooping_settings *s);

    /* Configures multicast snooping port's flood setting on 'ofproto'.
     *
     * If 's' is nonnull, this function updates multicast snooping
     * configuration to 's' in 'ofproto'.
     *
     * If 's' is NULL, this function doesn't change anything.
     *
     * An implementation that does not support multicast snooping may set
     * it to NULL or return EOPNOTSUPP. */
    int (*set_mcast_snooping_port)(struct ofproto *ofproto_, void *aux,
                          const struct ofproto_mcast_snooping_port_settings *s);

/* ## ------------------------ ## */
/* ## OpenFlow meter functions ## */
/* ## ------------------------ ## */

    /* These functions should be NULL if an implementation does not support
     * them.  They must be all null or all non-null.. */

    /* Initializes 'features' to describe the metering features supported by
     * 'ofproto'. */
    void (*meter_get_features)(const struct ofproto *ofproto,
                               struct ofputil_meter_features *features);

    /* If '*id' is UINT32_MAX, adds a new meter with the given 'config'.  On
     * success the function must store a provider meter ID other than
     * UINT32_MAX in '*id'.  All further references to the meter will be made
     * with the returned provider meter id rather than the OpenFlow meter id.
     * The caller does not try to interpret the provider meter id, giving the
     * implementation the freedom to either use the OpenFlow meter_id value
     * provided in the meter configuration, or any other value suitable for the
     * implementation.
     *
     * If '*id' is a value other than UINT32_MAX, modifies the existing meter
     * with that meter provider ID to have configuration 'config', while
     * leaving '*id' unchanged.  On failure, the existing meter configuration
     * is left intact. */
    enum ofperr (*meter_set)(struct ofproto *ofproto, ofproto_meter_id *id,
                             struct ofputil_meter_config *config);

    /* Gets the meter and meter band packet and byte counts for maximum of
     * 'n_bands' bands for the meter with provider ID 'id' within 'ofproto'.
     * The caller fills in the other stats values.  The band stats are copied
     * to memory at 'stats->bands' provided by the caller.  The number of
     * returned band stats is returned in 'stats->n_bands'. */
    enum ofperr (*meter_get)(const struct ofproto *ofproto,
                             ofproto_meter_id id,
                             struct ofputil_meter_stats *stats,
                             uint16_t n_bands);

    /* Deletes a meter, making the 'ofproto_meter_id' invalid for any
     * further calls. */
    void (*meter_del)(struct ofproto *, ofproto_meter_id);


/* ## -------------------- ## */
/* ## OpenFlow 1.1+ groups ## */
/* ## -------------------- ## */

    struct ofgroup *(*group_alloc)(void);
    enum ofperr (*group_construct)(struct ofgroup *);
    void (*group_destruct)(struct ofgroup *);
    void (*group_dealloc)(struct ofgroup *);

    void (*group_modify)(struct ofgroup *);

    enum ofperr (*group_get_stats)(const struct ofgroup *,
                                   struct ofputil_group_stats *);

/* ## --------------------- ## */
/* ## Datapath information  ## */
/* ## --------------------- ## */
    /* Retrieve the version string of the datapath. The version
     * string can be NULL if it can not be determined.
     *
     * The version retuned is read only. The caller should not
     * free it.
     *
     * This function should be NULL if an implementation does not support it.
     */
    const char *(*get_datapath_version)(const struct ofproto *);

    /* Pass custom configuration options to the 'type' datapath.
     *
     * This function should be NULL if an implementation does not support it.
     */
    void (*type_set_config)(const char *type,
                            const struct smap *other_config);

/* ## ------------------- ## */
/* ## Connection tracking ## */
/* ## ------------------- ## */
    /* Flushes the connection tracking tables. If 'zone' is not NULL,
     * only deletes connections in '*zone'. */
    void (*ct_flush)(const struct ofproto *, const uint16_t *zone);
};

extern const struct ofproto_class ofproto_dpif_class;

int ofproto_class_register(const struct ofproto_class *);
int ofproto_class_unregister(const struct ofproto_class *);

/* Criteria that flow_mod and other operations use for selecting rules on
 * which to operate. */
struct rule_criteria {
    /* An OpenFlow table or 255 for all tables. */
    uint8_t table_id;

    /* OpenFlow matching criteria.  Interpreted different in "loose" way by
     * collect_rules_loose() and "strict" way by collect_rules_strict(), as
     * defined in the OpenFlow spec. */
    struct cls_rule cr;
    ovs_version_t version;

    /* Matching criteria for the OpenFlow cookie.  Consider a bit B in a rule's
     * cookie and the corresponding bits C in 'cookie' and M in 'cookie_mask'.
     * The rule will not be selected if M is 1 and B != C.  */
    ovs_be64 cookie;
    ovs_be64 cookie_mask;

    /* Selection based on actions within a rule:
     *
     * If out_port != OFPP_ANY, selects only rules that output to out_port.
     * If out_group != OFPG_ALL, select only rules that output to out_group. */
    ofp_port_t out_port;
    uint32_t out_group;

    /* If true, collects only rules that are modifiable. */
    bool include_hidden;
    bool include_readonly;
};

/* flow_mod with execution context. */
struct ofproto_flow_mod {
    /* Allocated by 'init' phase, may be freed after 'start' phase, as these
     * are not needed for 'revert' nor 'finish'.
     *
     * This structure owns a reference to 'temp_rule' (if it is nonnull) that
     * must be eventually be released with ofproto_rule_unref().  */
    struct rule *temp_rule;
    struct rule_criteria criteria;
    struct cls_conjunction *conjs;
    size_t n_conjs;

    /* Replicate needed fields from ofputil_flow_mod to not need it after the
     * flow has been created. */
    uint16_t command;
    bool modify_cookie;
    /* Fields derived from ofputil_flow_mod. */
    bool modify_may_add_flow;
    bool modify_keep_counts;
    enum nx_flow_update_event event;

    /* These are only used during commit execution.
     * ofproto_flow_mod_uninit() does NOT clean these up. */
    ovs_version_t version;              /* Version in which changes take
                                         * effect. */
    bool learn_adds_rule;               /* Learn execution adds a rule. */
    struct rule_collection old_rules;   /* Affected rules. */
    struct rule_collection new_rules;   /* Replacement rules. */
};

void ofproto_flow_mod_uninit(struct ofproto_flow_mod *);

/* port_mod with execution context. */
struct ofproto_port_mod {
    struct ofputil_port_mod pm;
    struct ofport *port;                /* Affected port. */
};

/* flow_mod with execution context. */
struct ofproto_group_mod {
    struct ofputil_group_mod gm;

    ovs_version_t version;              /* Version in which changes take
                                         * effect. */
    struct ofgroup *new_group;          /* New group. */
    struct group_collection old_groups; /* Affected groups. */
};

/* packet_out with execution context. */
struct ofproto_packet_out {
    ovs_version_t version;
    struct dp_packet *packet;
    struct flow *flow;
    struct ofpact *ofpacts;
    size_t ofpacts_len;

    void *aux;   /* Provider private. */
};

void ofproto_packet_out_uninit(struct ofproto_packet_out *);

enum ofperr ofproto_flow_mod(struct ofproto *, const struct ofputil_flow_mod *)
    OVS_EXCLUDED(ofproto_mutex);
enum ofperr ofproto_flow_mod_init_for_learn(struct ofproto *,
                                            const struct ofputil_flow_mod *,
                                            struct ofproto_flow_mod *)
    OVS_EXCLUDED(ofproto_mutex);
enum ofperr ofproto_flow_mod_learn(struct ofproto_flow_mod *, bool keep_ref,
                                   unsigned limit, bool *below_limit)
    OVS_EXCLUDED(ofproto_mutex);
enum ofperr ofproto_flow_mod_learn_refresh(struct ofproto_flow_mod *ofm);
enum ofperr ofproto_flow_mod_learn_start(struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex);
void ofproto_flow_mod_learn_revert(struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex);
void ofproto_flow_mod_learn_finish(struct ofproto_flow_mod *ofm,
                                          struct ofproto *orig_ofproto)
    OVS_REQUIRES(ofproto_mutex);
void ofproto_add_flow(struct ofproto *, const struct match *, int priority,
                      const struct ofpact *ofpacts, size_t ofpacts_len)
    OVS_EXCLUDED(ofproto_mutex);
void ofproto_delete_flow(struct ofproto *, const struct match *, int priority)
    OVS_REQUIRES(ofproto_mutex);
void ofproto_flush_flows(struct ofproto *);

enum ofperr ofproto_check_ofpacts(struct ofproto *,
                                  const struct ofpact ofpacts[],
                                  size_t ofpacts_len)
    OVS_REQUIRES(ofproto_mutex);

static inline const struct rule_actions *
rule_get_actions(const struct rule *rule)
{
    return rule->actions;
}

/* Returns true if 'rule' is an OpenFlow 1.3 "table-miss" rule, false
 * otherwise.
 *
 * ("Table-miss" rules are special because a packet_in generated through one
 * uses OFPR_NO_MATCH as its reason, whereas packet_ins generated by any other
 * rule use OFPR_ACTION.) */
static inline bool
rule_is_table_miss(const struct rule *rule)
{
    return rule->cr.priority == 0 && cls_rule_is_catchall(&rule->cr);
}

/* Returns true if 'rule' should be hidden from the controller.
 *
 * Rules with priority higher than UINT16_MAX are set up by ofproto itself
 * (e.g. by in-band control) and are intentionally hidden from the
 * controller. */
static inline bool
rule_is_hidden(const struct rule *rule)
{
    return rule->cr.priority > UINT16_MAX;
}

static inline struct rule *
rule_from_cls_rule(const struct cls_rule *cls_rule)
{
    return cls_rule ? CONTAINER_OF(cls_rule, struct rule, cr) : NULL;
}

static inline const struct tun_table *
ofproto_get_tun_tab(const struct ofproto *ofproto)
{
    return ovsrcu_get(struct tun_table *, &ofproto->metadata_tab);
}

#endif /* ofproto/ofproto-provider.h */
