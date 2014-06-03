/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "list.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "ofproto/ofproto.h"
#include "ovs-atomic.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "shash.h"
#include "simap.h"
#include "timeval.h"

struct match;
struct ofputil_flow_mod;
struct bfd_cfg;
struct meter;

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
    char *mfr_desc;             /* Manufacturer (NULL for default)b. */
    char *hw_desc;              /* Hardware (NULL for default). */
    char *sw_desc;              /* Software version (NULL for default). */
    char *serial_desc;          /* Serial number (NULL for default). */
    char *dp_desc;              /* Datapath description (NULL for default). */
    enum ofp_config_flags frag_handling; /* One of OFPC_*.  */

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

    /* Rules indexed on their cookie values, in all flow tables. */
    struct hindex cookies OVS_GUARDED_BY(ofproto_mutex);

    /* List of expirable flows, in all flow tables. */
    struct list expirable OVS_GUARDED_BY(ofproto_mutex);

    /* Meter table.
     * OpenFlow meters start at 1.  To avoid confusion we leave the first
     * pointer in the array un-used, and index directly with the OpenFlow
     * meter_id. */
    struct ofputil_meter_features meter_features;
    struct meter **meters; /* 'meter_features.max_meter' + 1 pointers. */

    /* OpenFlow connections. */
    struct connmgr *connmgr;

    /* Flow table operation tracking.
     *
     * 'state' is meaningful only within ofproto.c, one of the enum
     * ofproto_state constants defined there.
     *
     * 'pending' is the list of "struct ofopgroup"s currently pending.
     *
     * 'n_pending' is the number of elements in 'pending'.
     *
     * 'deletions' contains pending ofoperations of type OFOPERATION_DELETE,
     * indexed on its rule's flow.*/
    int state;
    struct list pending OVS_GUARDED_BY(ofproto_mutex);
    unsigned int n_pending OVS_GUARDED_BY(ofproto_mutex);
    struct hmap deletions OVS_GUARDED_BY(ofproto_mutex);

    /* Delayed rule executions.
     *
     * We delay calls to ->ofproto_class->rule_execute() past releasing
     * ofproto_mutex during a flow_mod, because otherwise a "learn" action
     * triggered by the executing the packet would try to recursively modify
     * the flow table and reacquire the global lock. */
    struct guarded_list rule_executes; /* Contains "struct rule_execute"s. */

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
     *
     * This is deprecated.  It is only for compatibility with broken device
     * drivers in old versions of Linux that do not properly support VLANs when
     * VLAN devices are not used.  When broken device drivers are no longer in
     * widespread use, we will delete these interfaces. */
    unsigned long int *vlan_bitmap; /* 4096-bit bitmap of in-use VLANs. */
    bool vlans_changed;             /* True if new VLANs are in use. */
    int min_mtu;                    /* Current MTU of non-internal ports. */

    /* Groups. */
    struct ovs_rwlock groups_rwlock;
    struct hmap groups OVS_GUARDED;   /* Contains "struct ofgroup"s. */
    uint32_t n_groups[4] OVS_GUARDED; /* # of existing groups of each type. */
    struct ofputil_group_features ogf;
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
 * A cls->rwlock read-lock holder prevents rules from being added or deleted.
 *
 * Adding or removing rules requires holding ofproto_mutex AND the cls->rwlock
 * write-lock.
 *
 * cls->rwlock should be held only briefly.  For extended access to a rule,
 * increment its ref_count with ofproto_rule_ref().  A rule will not be freed
 * until its ref_count reaches zero.
 *
 * Modifying a rule requires the rule's own mutex.  Holding cls->rwlock (for
 * read or write) does not allow the holder to modify the rule.
 *
 * Freeing a rule requires ofproto_mutex and the cls->rwlock write-lock.  After
 * removing the rule from the classifier, release a ref_count from the rule
 * ('cls''s reference to the rule).
 *
 * Refer to the thread-safety notes on struct rule for more information.*/
struct oftable {
    enum oftable_flags flags;
    struct classifier cls;      /* Contains "struct rule"s. */
    char *name;                 /* Table name exposed via OpenFlow, or NULL. */

    /* Maximum number of flows or UINT_MAX if there is no limit besides any
     * limit imposed by resource limitations. */
    unsigned int max_flows;

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

    /* Table config: contains enum ofproto_table_config; accessed atomically. */
    atomic_uint config;
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
 * A rule 'rule' may be accessed without a risk of being freed by code that
 * holds a read-lock or write-lock on 'cls->rwlock' or that owns a reference to
 * 'rule->ref_count' (or both).  Code that needs to hold onto a rule for a
 * while should take 'cls->rwlock', find the rule it needs, increment
 * 'rule->ref_count' with ofproto_rule_ref(), and drop 'cls->rwlock'.
 *
 * 'rule->ref_count' protects 'rule' from being freed.  It doesn't protect the
 * rule from being deleted from 'cls' (that's 'cls->rwlock') and it doesn't
 * protect members of 'rule' from modification (that's 'rule->mutex').
 *
 * 'rule->mutex' protects the members of 'rule' from modification.  It doesn't
 * protect the rule from being deleted from 'cls' (that's 'cls->rwlock') and it
 * doesn't prevent the rule from being freed (that's 'rule->ref_count').
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
struct rule {
    /* Where this rule resides in an OpenFlow switch.
     *
     * These are immutable once the rule is constructed, hence 'const'. */
    struct ofproto *const ofproto; /* The ofproto that contains this rule. */
    const struct cls_rule cr;      /* In owning ofproto's classifier. */
    const uint8_t table_id;        /* Index in ofproto's 'tables' array. */

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

    /* Operation now in progress, if nonnull. */
    struct ofoperation *pending OVS_GUARDED_BY(ofproto_mutex);

    /* A "flow cookie" is the OpenFlow name for a 64-bit value associated with
     * a flow.. */
    ovs_be64 flow_cookie OVS_GUARDED;
    struct hindex_node cookie_node OVS_GUARDED_BY(ofproto_mutex);

    enum ofputil_flow_mod_flags flags OVS_GUARDED;

    /* Timeouts. */
    uint16_t hard_timeout OVS_GUARDED; /* In seconds from ->modified. */
    uint16_t idle_timeout OVS_GUARDED; /* In seconds from ->used. */

    /* Eviction groups (see comment on struct eviction_group for explanation) .
     *
     * 'eviction_group' is this rule's eviction group, or NULL if it is not in
     * any eviction group.  When 'eviction_group' is nonnull, 'evg_node' is in
     * the ->eviction_group->rules hmap. */
    struct eviction_group *eviction_group OVS_GUARDED_BY(ofproto_mutex);
    struct heap_node evg_node OVS_GUARDED_BY(ofproto_mutex);

    /* OpenFlow actions.  See struct rule_actions for more thread-safety
     * notes. */
    OVSRCU_TYPE(const struct rule_actions *) actions;

    /* In owning meter's 'rules' list.  An empty list if there is no meter. */
    struct list meter_list_node OVS_GUARDED_BY(ofproto_mutex);

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
    struct list expirable OVS_GUARDED_BY(ofproto_mutex);

    /* Times.  Last so that they are more likely close to the stats managed
     * by the provider. */
    long long int created OVS_GUARDED; /* Creation time. */

    /* Must hold 'mutex' for both read/write, 'ofproto_mutex' not needed. */
    long long int modified OVS_GUARDED; /* Time of last modification. */
};

void ofproto_rule_ref(struct rule *);
void ofproto_rule_unref(struct rule *);

static inline const struct rule_actions * rule_get_actions(const struct rule *);
static inline bool rule_is_table_miss(const struct rule *);

/* A set of actions within a "struct rule".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct rule_actions may be accessed without a risk of being
 * freed by code that holds a read-lock or write-lock on 'rule->mutex' (where
 * 'rule' is the rule for which 'rule->actions == actions') or during the RCU
 * active period. */
struct rule_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    uint32_t ofpacts_len;         /* Size of 'ofpacts', in bytes. */
    uint32_t provider_meter_id;   /* Datapath meter_id, or UINT32_MAX. */
    struct ofpact ofpacts[];      /* Sequence of "struct ofpacts". */
};
BUILD_ASSERT_DECL(offsetof(struct rule_actions, ofpacts) % OFPACT_ALIGNTO == 0);

const struct rule_actions *rule_actions_create(const struct ofproto *,
                                               const struct ofpact *, size_t);
void rule_actions_destroy(const struct rule_actions *);

/* A set of rules to which an OpenFlow operation applies. */
struct rule_collection {
    struct rule **rules;        /* The rules. */
    size_t n;                   /* Number of rules collected. */

    size_t capacity;            /* Number of rules that will fit in 'rules'. */
    struct rule *stub[64];      /* Preallocated rules to avoid malloc(). */
};

void rule_collection_init(struct rule_collection *);
void rule_collection_add(struct rule_collection *, struct rule *);
void rule_collection_ref(struct rule_collection *) OVS_REQUIRES(ofproto_mutex);
void rule_collection_unref(struct rule_collection *);
void rule_collection_destroy(struct rule_collection *);

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
void ofproto_rule_reduce_timeouts(struct rule *rule, uint16_t idle_timeout,
                                  uint16_t hard_timeout)
    OVS_EXCLUDED(ofproto_mutex);

void ofoperation_complete(struct ofoperation *, enum ofperr);

bool ofoperation_has_out_port(const struct ofoperation *, ofp_port_t out_port)
    OVS_REQUIRES(ofproto_mutex);

/* A group within a "struct ofproto".
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them. */
struct ofgroup {
    /* The rwlock is used to prevent groups from being deleted while child
     * threads are using them to xlate flows.  A read lock means the
     * group is currently being used.  A write lock means the group is
     * in the process of being deleted or updated.  Note that since
     * a read lock on the groups container is held while searching, and
     * a group is ever write locked only while holding a write lock
     * on the container, the user's of groups will never face a group
     * in the write locked state. */
    struct ovs_rwlock rwlock OVS_ACQ_AFTER(ofproto_mutex);
    struct hmap_node hmap_node; /* In struct ofproto's "groups" hmap. */
    struct ofproto *ofproto;    /* The ofproto that contains this group. */
    uint32_t group_id;
    enum ofp11_group_type type; /* One of OFPGT_*. */

    long long int created;      /* Creation time. */
    long long int modified;     /* Time of last modification. */

    struct list buckets;        /* Contains "struct ofputil_bucket"s. */
    uint32_t n_buckets;
};

bool ofproto_group_lookup(const struct ofproto *ofproto, uint32_t group_id,
                          struct ofgroup **group)
    OVS_TRY_RDLOCK(true, (*group)->rwlock);

void ofproto_group_release(struct ofgroup *group)
    OVS_RELEASES(group->rwlock);

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
 * Each "dealloc" function frees raw memory that was allocated by the the
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

    /* Enumerates the types of all support ofproto types into 'types'.  The
     * caller has already initialized 'types' and other ofproto classes might
     * already have added names to it. */
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
     * If 'ofproto' has any pending asynchronous operations, ->destruct()
     * must complete all of them by calling ofoperation_complete().
     *
     * ->destruct() must also destroy all remaining rules in the ofproto's
     * tables, by passing each remaining rule to ofproto_rule_delete(), and
     * then complete each of those deletions in turn by calling
     * ofoperation_complete().
     *
     * (Thus, there is a multi-step process for any rule currently being
     * inserted or modified at the beginning of destruction: first
     * ofoperation_complete() that operation, then ofproto_rule_delete() the
     * rule, then ofoperation_complete() the deletion operation.)
     *
     * The client will destroy the flow tables themselves after ->destruct()
     * returns.
     */
    struct ofproto *(*alloc)(void);
    int (*construct)(struct ofproto *ofproto);
    void (*destruct)(struct ofproto *ofproto);
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
     *     (But rules that are part of a pending operation, e.g. rules for
     *     which ->pending is true, may not expire.)
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

    /* Helper for the OpenFlow OFPT_FEATURES_REQUEST request.
     *
     * The implementation should store true in '*arp_match_ip' if the switch
     * supports matching IP addresses inside ARP requests and replies, false
     * otherwise.
     *
     * The implementation should store in '*actions' a bitmap of the supported
     * OpenFlow actions.  Vendor actions are not included in '*actions'. */
    void (*get_features)(struct ofproto *ofproto,
                         bool *arp_match_ip,
                         enum ofputil_action_bitmap *actions);

    /* Helper for the OpenFlow OFPST_TABLE statistics request.
     *
     * The 'ots' array contains 'ofproto->n_tables' elements.  Each element is
     * initialized as:
     *
     *   - 'table_id' to the array index.
     *
     *   - 'name' to "table#" where # is the table ID.
     *
     *   - 'match' and 'wildcards' to OFPXMT12_MASK.
     *
     *   - 'write_actions' and 'apply_actions' to OFPAT12_OUTPUT.
     *
     *   - 'write_setfields' and 'apply_setfields' to OFPXMT12_MASK.
     *
     *   - 'metadata_match' and 'metadata_write' to OVS_BE64_MAX.
     *
     *   - 'instructions' to OFPIT11_ALL.
     *
     *   - 'config' to OFPTC11_TABLE_MISS_MASK.
     *
     *   - 'max_entries' to 1,000,000.
     *
     *   - 'active_count' to the classifier_count() for the table.
     *
     *   - 'lookup_count' and 'matched_count' to 0.
     *
     * The implementation should update any members in each element for which
     * it has better values:
     *
     *   - 'name' to a more meaningful name.
     *
     *   - 'wildcards' to the set of wildcards actually supported by the table
     *     (if it doesn't support all OpenFlow wildcards).
     *
     *   - 'instructions' to set the instructions actually supported by
     *     the table.
     *
     *   - 'write_actions' to set the write actions actually supported by
     *     the table (if it doesn't support all OpenFlow actions).
     *
     *   - 'apply_actions' to set the apply actions actually supported by
     *     the table (if it doesn't support all OpenFlow actions).
     *
     *   - 'write_setfields' to set the write setfields actually supported by
     *     the table.
     *
     *   - 'apply_setfields' to set the apply setfields actually supported by
     *     the table.
     *
     *   - 'max_entries' to the maximum number of flows actually supported by
     *     the hardware.
     *
     *   - 'lookup_count' to the number of packets looked up in this flow table
     *     so far.
     *
     *   - 'matched_count' to the number of packets looked up in this flow
     *     table so far that matched one of the flow entries.
     *
     * All of the members of struct ofp12_table_stats are in network byte
     * order.
     */
    void (*get_tables)(struct ofproto *ofproto, struct ofp12_table_stats *ots);

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
     * ->port_construct() returns 0 if successful, otherwise a positive errno
     * value.
     */
    struct ofport *(*port_alloc)(void);
    int (*port_construct)(struct ofport *ofport);
    void (*port_destruct)(struct ofport *ofport);
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
     * not support LACP. */
    int (*port_is_lacp_current)(const struct ofport *port);

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
     * insertion completes successfully, then before it is later destructed, it
     * is deleted.
     *
     * You can think of a rule as having the following extra steps inserted
     * between "Life Cycle" steps 4 and 5:
     *
     *   4.1. The client inserts the rule into the flow table, making it
     *        visible in flow table lookups.
     *
     *   4.2. The client calls "rule_insert".  Immediately or eventually, the
     *        implementation calls ofoperation_complete() to indicate that the
     *        insertion completed.  If the operation failed, skip to step 5.
     *
     *   4.3. The rule is now installed in the flow table.  Eventually it will
     *        be deleted.
     *
     *   4.4. The client removes the rule from the flow table.  It is no longer
     *        visible in flow table lookups.
     *
     *   4.5. The client calls "rule_delete".  Immediately or eventually, the
     *        implementation calls ofoperation_complete() to indicate that the
     *        deletion completed.  Deletion is not allowed to fail, so it must
     *        be successful.
     *
     *
     * Asynchronous Operation Support
     * ==============================
     *
     * The "insert" and "delete" life-cycle operations on rules can operate
     * asynchronously, meaning that ->rule_insert() and ->rule_delete() only
     * need to initiate their respective operations and do not need to wait for
     * them to complete before they return.  ->rule_modify_actions() also
     * operates asynchronously.
     *
     * An ofproto implementation reports the success or failure of an
     * asynchronous operation on a rule using the rule's 'pending' member,
     * which points to a opaque "struct ofoperation" that represents the
     * ongoing operation.  When the operation completes, the ofproto
     * implementation calls ofoperation_complete(), passing the ofoperation and
     * an error indication.
     *
     * Only the following contexts may call ofoperation_complete():
     *
     *   - The function called to initiate the operation, e.g. ->rule_insert()
     *     or ->rule_delete().  This is the best choice if the operation
     *     completes quickly.
     *
     *   - The implementation's ->run() function.
     *
     *   - The implementation's ->destruct() function.
     *
     * The ofproto base code updates the flow table optimistically, assuming
     * that the operation will probably succeed:
     *
     *   - ofproto adds the rule in the flow table before calling
     *     ->rule_insert().
     *
     *   - ofproto updates the rule's actions and other properties before
     *     calling ->rule_modify_actions().
     *
     *   - ofproto removes the rule before calling ->rule_delete().
     *
     * With one exception, when an asynchronous operation completes with an
     * error, ofoperation_complete() backs out the already applied changes:
     *
     *   - If adding a rule in the flow table fails, ofproto removes the new
     *     rule.
     *
     *   - If modifying a rule fails, ofproto restores the original actions
     *     (and other properties).
     *
     *   - Removing a rule is not allowed to fail.  It must always succeed.
     *
     * The ofproto base code serializes operations: if any operation is in
     * progress on a given rule, ofproto postpones initiating any new operation
     * on that rule until the pending operation completes.  Therefore, every
     * operation must eventually complete through a call to
     * ofoperation_complete() to avoid delaying new operations indefinitely
     * (including any OpenFlow request that affects the rule in question, even
     * just to query its statistics).
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
     * ->rule_construct() may also:
     *
     *   - Validate that the datapath supports the matching rule in 'rule->cr'
     *     datapath.  For example, if the rule's table does not support
     *     registers, then it is an error if 'rule->cr' does not wildcard all
     *     registers.
     *
     *   - Validate that the datapath can correctly implement 'rule->ofpacts'.
     *
     * Some implementations might need to defer these tasks to ->rule_insert(),
     * which is also acceptable.
     *
     *
     * Insertion
     * =========
     *
     * Following successful construction, the ofproto base case inserts 'rule'
     * into its flow table, then it calls ->rule_insert().  ->rule_insert()
     * should set in motion adding the new rule to the datapath flow table.  It
     * must act as follows:
     *
     *   - If it completes insertion, either by succeeding or failing, it must
     *     call ofoperation_complete()
     *
     *   - If insertion is only partially complete, then it must return without
     *     calling ofoperation_complete().  Later, when the insertion is
     *     complete, the ->run() or ->destruct() function must call
     *     ofoperation_complete() to report success or failure.
     *
     * If ->rule_insert() fails, the ofproto base code will remove 'rule' from
     * the flow table, destruct, uninitialize, and deallocate 'rule'.  See
     * "Rule Life Cycle" above for more details.
     *
     *
     * Deletion
     * ========
     *
     * The ofproto base code removes 'rule' from its flow table before it calls
     * ->rule_delete().  ->rule_delete() should set in motion removing 'rule'
     * from the datapath flow table.  It must act as follows:
     *
     *   - If it completes deletion, it must call ofoperation_complete().
     *
     *   - If deletion is only partially complete, then it must return without
     *     calling ofoperation_complete().  Later, when the deletion is
     *     complete, the ->run() or ->destruct() function must call
     *     ofoperation_complete().
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
    void (*rule_insert)(struct rule *rule) /* OVS_REQUIRES(ofproto_mutex) */;
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

    /* Applies the actions in 'rule' to 'packet'.  (This implements sending
     * buffered packets for OpenFlow OFPT_FLOW_MOD commands.)
     *
     * Takes ownership of 'packet' (so it should eventually free it, with
     * ofpbuf_delete()).
     *
     * 'flow' reflects the flow information for 'packet'.  All of the
     * information in 'flow' is extracted from 'packet', except for
     * flow->tunnel and flow->in_port, which are assigned the correct values
     * for the incoming packet.  The register values are zeroed.  'packet''s
     * header pointers and offsets (e.g. packet->l3) are appropriately
     * initialized.  packet->l3 is aligned on a 32-bit boundary.
     *
     * The implementation should add the statistics for 'packet' into 'rule'.
     *
     * Returns 0 if successful, otherwise an OpenFlow error code. */
    enum ofperr (*rule_execute)(struct rule *rule, const struct flow *flow,
                                struct ofpbuf *packet);

    /* When ->rule_modify_actions() is called, the caller has already replaced
     * the OpenFlow actions in 'rule' by a new set.  (The original actions are
     * in rule->pending->actions.)
     *
     * ->rule_modify_actions() should set the following in motion:
     *
     *   - Validate that the datapath can correctly implement the actions now
     *     in 'rule'.
     *
     *   - Update the datapath flow table with the new actions.
     *
     *   - Only if 'reset_counters' is true, reset any packet or byte counters
     *     associated with the rule to zero, so that rule_get_stats() will not
     *     longer count those packets or bytes.
     *
     * If the operation synchronously completes, ->rule_modify_actions() may
     * call ofoperation_complete() before it returns.  Otherwise, ->run()
     * should call ofoperation_complete() later, after the operation does
     * complete.
     *
     * If the operation fails, then the base ofproto code will restore the
     * original 'actions' and 'n_actions' of 'rule'.
     *
     * ->rule_modify_actions() should not modify any base members of struct
     * rule. */
    void (*rule_modify_actions)(struct rule *rule, bool reset_counters)
        /* OVS_REQUIRES(ofproto_mutex) */;

    /* Changes the OpenFlow IP fragment handling policy to 'frag_handling',
     * which takes one of the following values, with the corresponding
     * meanings:
     *
     *  - OFPC_FRAG_NORMAL: The switch should treat IP fragments the same way
     *    as other packets, omitting TCP and UDP port numbers (always setting
     *    them to 0).
     *
     *  - OFPC_FRAG_DROP: The switch should drop all IP fragments without
     *    passing them through the flow table.
     *
     *  - OFPC_FRAG_REASM: The switch should reassemble IP fragments before
     *    passing packets through the flow table.
     *
     *  - OFPC_FRAG_NX_MATCH (a Nicira extension): Similar to OFPC_FRAG_NORMAL,
     *    except that TCP and UDP port numbers should be included in fragments
     *    with offset 0.
     *
     * Implementations are not required to support every mode.
     * OFPC_FRAG_NORMAL is the default mode when an ofproto is created.
     *
     * At the time of the call to ->set_frag_handling(), the current mode is
     * available in 'ofproto->frag_handling'.  ->set_frag_handling() returns
     * true if the requested mode was set, false if it is not supported.
     *
     * Upon successful return, the caller changes 'ofproto->frag_handling' to
     * reflect the new mode.
     */
    bool (*set_frag_handling)(struct ofproto *ofproto,
                              enum ofp_config_flags frag_handling);

    /* Implements the OpenFlow OFPT_PACKET_OUT command.  The datapath should
     * execute the 'ofpacts_len' bytes of "struct ofpacts" in 'ofpacts'.
     *
     * The caller retains ownership of 'packet' and of 'ofpacts', so
     * ->packet_out() should not modify or free them.
     *
     * This function must validate that it can correctly implement 'ofpacts'.
     * If not, then it should return an OpenFlow error code.
     *
     * 'flow' reflects the flow information for 'packet'.  All of the
     * information in 'flow' is extracted from 'packet', except for
     * flow->in_port (see below).  flow->tunnel and its register values are
     * zeroed.
     *
     * flow->in_port comes from the OpenFlow OFPT_PACKET_OUT message.  The
     * implementation should reject invalid flow->in_port values by returning
     * OFPERR_OFPBRC_BAD_PORT.  (If the implementation called
     * ofproto_init_max_ports(), then the client will reject these ports
     * itself.)  For consistency, the implementation should consider valid for
     * flow->in_port any value that could possibly be seen in a packet that it
     * passes to connmgr_send_packet_in().  Ideally, even an implementation
     * that never generates packet-ins (e.g. due to hardware limitations)
     * should still allow flow->in_port values for every possible physical port
     * and OFPP_LOCAL.  The only virtual ports (those above OFPP_MAX) that the
     * caller will ever pass in as flow->in_port, other than OFPP_LOCAL, are
     * OFPP_NONE and OFPP_CONTROLLER.  The implementation should allow both of
     * these, treating each of them as packets generated by the controller as
     * opposed to packets originating from some switch port.
     *
     * (Ordinarily the only effect of flow->in_port is on output actions that
     * involve the input port, such as actions that output to OFPP_IN_PORT,
     * OFPP_FLOOD, or OFPP_ALL.  flow->in_port can also affect Nicira extension
     * "resubmit" actions.)
     *
     * 'packet' is not matched against the OpenFlow flow table, so its
     * statistics should not be included in OpenFlow flow statistics.
     *
     * Returns 0 if successful, otherwise an OpenFlow error code. */
    enum ofperr (*packet_out)(struct ofproto *ofproto, struct ofpbuf *packet,
                              const struct flow *flow,
                              const struct ofpact *ofpacts,
                              size_t ofpacts_len);

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

    /* Checks the status of CFM configured on 'ofport' and stores port's CFM
     * status in '*status'.  If 'force' is set to true, status will be returned
     * even if there is no status change since last update.
     *
     * Returns 0 on success.  Returns a negative number if there is no status
     * change since last update and 'force' is set to false.  Returns positive
     * errno otherwise.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support CFM, as does a null pointer.
     *
     * The caller must provide and own '*status', and it must free the array
     * returned in 'status->rmps'.  '*status' is indeterminate if the return
     * value is non-zero. */
    int (*get_cfm_status)(const struct ofport *ofport, bool force,
                          struct ofproto_cfm_status *status);

    /* Configures BFD on 'ofport'.
     *
     * If 'cfg' is NULL, or 'cfg' does not contain the key value pair
     * "enable=true", removes BFD from 'ofport'.  Otherwise, configures BFD
     * according to 'cfg'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support BFD, as does a null pointer. */
    int (*set_bfd)(struct ofport *ofport, const struct smap *cfg);

    /* Populates 'smap' with the status of BFD on 'ofport'.  If 'force' is set
     * to true, status will be returned even if there is no status change since
     * last update.
     *
     * Returns 0 on success.  Returns a negative number if there is no status
     * change since last update and 'force' is set to false.  Returns a positive
     * errno otherwise.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support BFD, as does a null pointer. */
    int (*get_bfd_status)(struct ofport *ofport, bool force, struct smap *smap);

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

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

    /* If 'realdev_ofp_port' is nonzero, then this function configures 'ofport'
     * as a VLAN splinter port for VLAN 'vid', associated with the real device
     * that has OpenFlow port number 'realdev_ofp_port'.
     *
     * If 'realdev_ofp_port' is zero, then this function deconfigures 'ofport'
     * as a VLAN splinter port.
     *
     * This function should be NULL if an implementation does not support it.
     */
    int (*set_realdev)(struct ofport *ofport,
                       ofp_port_t realdev_ofp_port, int vid);

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
                             const struct ofputil_meter_config *config);

    /* Gets the meter and meter band packet and byte counts for maximum of
     * 'stats->n_bands' bands for the meter with provider ID 'id' within
     * 'ofproto'.  The caller fills in the other stats values.  The band stats
     * are copied to memory at 'stats->bands' provided by the caller.  The
     * number of returned band stats is returned in 'stats->n_bands'. */
    enum ofperr (*meter_get)(const struct ofproto *ofproto,
                             ofproto_meter_id id,
                             struct ofputil_meter_stats *stats);

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

    enum ofperr (*group_modify)(struct ofgroup *, struct ofgroup *victim);

    enum ofperr (*group_get_stats)(const struct ofgroup *,
                                   struct ofputil_group_stats *);
};

extern const struct ofproto_class ofproto_dpif_class;

int ofproto_class_register(const struct ofproto_class *);
int ofproto_class_unregister(const struct ofproto_class *);

/* ofproto_flow_mod() returns this value if the flow_mod could not be processed
 * because it overlaps with an ongoing flow table operation that has not yet
 * completed.  The caller should retry the operation later.
 *
 * ofproto.c also uses this value internally for additional (similar) purposes.
 *
 * This particular value is a good choice because it is large, so that it does
 * not collide with any errno value, but not large enough to collide with an
 * OFPERR_* value. */
enum { OFPROTO_POSTPONE = 1 << 16 };
BUILD_ASSERT_DECL(OFPROTO_POSTPONE < OFPERR_OFS);

int ofproto_flow_mod(struct ofproto *, struct ofputil_flow_mod *)
    OVS_EXCLUDED(ofproto_mutex);
void ofproto_add_flow(struct ofproto *, const struct match *,
                      unsigned int priority,
                      const struct ofpact *ofpacts, size_t ofpacts_len)
    OVS_EXCLUDED(ofproto_mutex);
bool ofproto_delete_flow(struct ofproto *,
                         const struct match *, unsigned int priority)
    OVS_EXCLUDED(ofproto_mutex);
void ofproto_flush_flows(struct ofproto *);


static inline const struct rule_actions *
rule_get_actions(const struct rule *rule)
{
    return ovsrcu_get(const struct rule_actions *, &rule->actions);
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

static inline struct rule *
rule_from_cls_rule(const struct cls_rule *cls_rule)
{
    return cls_rule ? CONTAINER_OF(cls_rule, struct rule, cr) : NULL;
}

#endif /* ofproto/ofproto-provider.h */
