/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

/* Definitions for use within ofproto. */

#include "ofproto/ofproto.h"
#include "cfm.h"
#include "classifier.h"
#include "heap.h"
#include "list.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "shash.h"
#include "timeval.h"

struct match;
struct ofpact;
struct ofputil_flow_mod;
struct simap;

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
    unsigned flow_eviction_threshold; /* Threshold at which to begin flow
                                       * table eviction. Only affects the
                                       * ofproto-dpif implementation */
    bool forward_bpdu;          /* Option to allow forwarding of BPDU frames
                                 * when NORMAL action is invoked. */
    char *mfr_desc;             /* Manufacturer. */
    char *hw_desc;              /* Hardware. */
    char *sw_desc;              /* Software version. */
    char *serial_desc;          /* Serial number. */
    char *dp_desc;              /* Datapath description. */
    enum ofp_config_flags frag_handling; /* One of OFPC_*.  */

    /* Datapath. */
    struct hmap ports;          /* Contains "struct ofport"s. */
    struct shash port_by_name;
    uint16_t max_ports;         /* Max possible OpenFlow port num, plus one. */

    /* Flow tables. */
    struct oftable *tables;
    int n_tables;

    /* OpenFlow connections. */
    struct connmgr *connmgr;

    /* Flow table operation tracking. */
    int state;                  /* Internal state. */
    struct list pending;        /* List of "struct ofopgroup"s. */
    unsigned int n_pending;     /* list_size(&pending). */
    struct hmap deletions;      /* All OFOPERATION_DELETE "ofoperation"s. */

    /* Flow table operation logging. */
    int n_add, n_delete, n_modify; /* Number of unreported ops of each kind. */
    long long int first_op, last_op; /* Range of times for unreported ops. */
    long long int next_op_report;    /* Time to report ops, or LLONG_MAX. */
    long long int op_backoff;        /* Earliest time to report ops again. */

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
     *
     * This is deprecated.  It is only for compatibility with broken device
     * drivers in old versions of Linux that do not properly support VLANs when
     * VLAN devices are not used.  When broken device drivers are no longer in
     * widespread use, we will delete these interfaces. */
    unsigned long int *vlan_bitmap; /* 4096-bit bitmap of in-use VLANs. */
    bool vlans_changed;             /* True if new VLANs are in use. */
    int min_mtu;                    /* Current MTU of non-internal ports. */
};

void ofproto_init_tables(struct ofproto *, int n_tables);
void ofproto_init_max_ports(struct ofproto *, uint16_t max_ports);

struct ofproto *ofproto_lookup(const char *name);
struct ofport *ofproto_get_port(const struct ofproto *, uint16_t ofp_port);

/* An OpenFlow port within a "struct ofproto".
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them. */
struct ofport {
    struct hmap_node hmap_node; /* In struct ofproto's "ports" hmap. */
    struct ofproto *ofproto;    /* The ofproto that contains this port. */
    struct netdev *netdev;
    struct ofputil_phy_port pp;
    uint16_t ofp_port;          /* OpenFlow port number. */
    unsigned int change_seq;
    int mtu;
};

void ofproto_port_set_state(struct ofport *, enum ofputil_port_state);

enum oftable_flags {
    OFTABLE_HIDDEN = 1 << 0,   /* Hide from most OpenFlow operations. */
    OFTABLE_READONLY = 1 << 1  /* Don't allow OpenFlow to change this table. */
};

/* A flow table within a "struct ofproto". */
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
 * should not modify them. */
struct rule {
    struct list ofproto_node;    /* Owned by ofproto base code. */
    struct ofproto *ofproto;     /* The ofproto that contains this rule. */
    struct cls_rule cr;          /* In owning ofproto's classifier. */

    struct ofoperation *pending; /* Operation now in progress, if nonnull. */

    ovs_be64 flow_cookie;        /* Controller-issued identifier. */

    long long int created;       /* Creation time. */
    long long int modified;      /* Time of last modification. */
    long long int used;          /* Last use; time created if never used. */
    uint16_t hard_timeout;       /* In seconds from ->modified. */
    uint16_t idle_timeout;       /* In seconds from ->used. */
    uint8_t table_id;            /* Index in ofproto's 'tables' array. */
    bool send_flow_removed;      /* Send a flow removed message? */

    /* Eviction groups. */
    bool evictable;              /* If false, prevents eviction. */
    struct heap_node evg_node;   /* In eviction_group's "rules" heap. */
    struct eviction_group *eviction_group; /* NULL if not in any group. */

    struct ofpact *ofpacts;      /* Sequence of "struct ofpacts". */
    unsigned int ofpacts_len;    /* Size of 'ofpacts', in bytes. */

    /* Flow monitors. */
    enum nx_flow_monitor_flags monitor_flags;
    uint64_t add_seqno;         /* Sequence number when added. */
    uint64_t modify_seqno;      /* Sequence number when changed. */
};

static inline struct rule *
rule_from_cls_rule(const struct cls_rule *cls_rule)
{
    return cls_rule ? CONTAINER_OF(cls_rule, struct rule, cr) : NULL;
}

void ofproto_rule_update_used(struct rule *, long long int used);
void ofproto_rule_expire(struct rule *, uint8_t reason);
void ofproto_rule_destroy(struct rule *);

bool ofproto_rule_has_out_port(const struct rule *, uint16_t out_port);

void ofoperation_complete(struct ofoperation *, enum ofperr);
struct rule *ofoperation_get_victim(struct ofoperation *);

bool ofoperation_has_out_port(const struct ofoperation *, uint16_t out_port);

bool ofproto_rule_is_hidden(const struct rule *);

/* ofproto class structure, to be defined by each ofproto implementation.
 *
 *
 * Data Structures
 * ===============
 *
 * These functions work primarily with three different kinds of data
 * structures:
 *
 *   - "struct ofproto", which represents an OpenFlow switch.
 *
 *   - "struct ofport", which represents a port within an ofproto.
 *
 *   - "struct rule", which represents an OpenFlow flow within an ofproto.
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
     * tables, by passing each remaining rule to ofproto_rule_destroy().  The
     * client will destroy the flow tables themselves after ->destruct()
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

    /* Performs periodic activity required by 'ofproto' that needs to be done
     * with the least possible latency.
     *
     * This is run multiple times per main loop.  An ofproto provider may
     * implement it or not, according to whether it provides a performance
     * boost for that ofproto implementation. */
    int (*run_fast)(struct ofproto *ofproto);

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
     *   - 'metadata_match' and 'metadata_write' to UINT64_MAX.
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

    /* Looks up a port named 'devname' in 'ofproto'.  On success, initializes
     * '*port' appropriately.
     *
     * The caller owns the data in 'port' and must free it with
     * ofproto_port_destroy() when it is no longer needed. */
    int (*port_query_by_name)(const struct ofproto *ofproto,
                              const char *devname, struct ofproto_port *port);

    /* Attempts to add 'netdev' as a port on 'ofproto'.  Returns 0 if
     * successful, otherwise a positive errno value.  If successful, sets
     * '*ofp_portp' to the new port's port number.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_add)(struct ofproto *ofproto, struct netdev *netdev,
                    uint16_t *ofp_portp);

    /* Deletes port number 'ofp_port' from the datapath for 'ofproto'.  Returns
     * 0 if successful, otherwise a positive errno value.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_del)(struct ofproto *ofproto, uint16_t ofp_port);

    /* Get port stats */
    int (*port_get_stats)(const struct ofport *port,
                          struct netdev_stats *stats);

    /* Port iteration functions.
     *
     * The client might not be entirely in control of the ports within an
     * ofproto.  Some hardware implementations, for example, might have a fixed
     * set of ports in a datapath, and the Linux datapath allows the system
     * administrator to externally add and remove ports with ovs-dpctl.  For
     * this reason, the client needs a way to iterate through all the ports
     * that are actually in a datapath.  These functions provide that
     * functionality.
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

    /* Life-cycle functions for a "struct rule" (see "Life Cycle" above).
     *
     *
     * Asynchronous Operation Support
     * ==============================
     *
     * The life-cycle operations on rules can operate asynchronously, meaning
     * that ->rule_construct() and ->rule_destruct() only need to initiate
     * their respective operations and do not need to wait for them to complete
     * before they return.  ->rule_modify_actions() also operates
     * asynchronously.
     *
     * An ofproto implementation reports the success or failure of an
     * asynchronous operation on a rule using the rule's 'pending' member,
     * which points to a opaque "struct ofoperation" that represents the
     * ongoing opreation.  When the operation completes, the ofproto
     * implementation calls ofoperation_complete(), passing the ofoperation and
     * an error indication.
     *
     * Only the following contexts may call ofoperation_complete():
     *
     *   - The function called to initiate the operation,
     *     e.g. ->rule_construct() or ->rule_destruct().  This is the best
     *     choice if the operation completes quickly.
     *
     *   - The implementation's ->run() function.
     *
     *   - The implementation's ->destruct() function.
     *
     * The ofproto base code updates the flow table optimistically, assuming
     * that the operation will probably succeed:
     *
     *   - ofproto adds or replaces the rule in the flow table before calling
     *     ->rule_construct().
     *
     *   - ofproto updates the rule's actions before calling
     *     ->rule_modify_actions().
     *
     *   - ofproto removes the rule before calling ->rule_destruct().
     *
     * With one exception, when an asynchronous operation completes with an
     * error, ofoperation_complete() backs out the already applied changes:
     *
     *   - If adding or replacing a rule in the flow table fails, ofproto
     *     removes the new rule or restores the original rule.
     *
     *   - If modifying a rule's actions fails, ofproto restores the original
     *     actions.
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
     * When ->rule_construct() is called, the caller has already inserted
     * 'rule' into 'rule->ofproto''s flow table numbered 'rule->table_id'.
     * There are two cases:
     *
     *   - 'rule' is a new rule in its flow table.  In this case,
     *     ofoperation_get_victim(rule) returns NULL.
     *
     *   - 'rule' is replacing an existing rule in its flow table that had the
     *     same matching criteria and priority.  In this case,
     *     ofoperation_get_victim(rule) returns the rule being replaced (the
     *     "victim" rule).
     *
     * ->rule_construct() should set the following in motion:
     *
     *   - Validate that the matching rule in 'rule->cr' is supported by the
     *     datapath.  For example, if the rule's table does not support
     *     registers, then it is an error if 'rule->cr' does not wildcard all
     *     registers.
     *
     *   - Validate that the datapath can correctly implement 'rule->ofpacts'.
     *
     *   - If the rule is valid, update the datapath flow table, adding the new
     *     rule or replacing the existing one.
     *
     *   - If 'rule' is replacing an existing rule, uninitialize any derived
     *     state for the victim rule, as in step 5 in the "Life Cycle"
     *     described above.
     *
     * (On failure, the ofproto code will roll back the insertion from the flow
     * table, either removing 'rule' or replacing it by the victim rule if
     * there is one.)
     *
     * ->rule_construct() must act in one of the following ways:
     *
     *   - If it succeeds, it must call ofoperation_complete() and return 0.
     *
     *   - If it fails, it must act in one of the following ways:
     *
     *       * Call ofoperation_complete() and return 0.
     *
     *       * Return an OpenFlow error code.  (Do not call
     *         ofoperation_complete() in this case.)
     *
     *     Either way, ->rule_destruct() will not be called for 'rule', but
     *     ->rule_dealloc() will be.
     *
     *   - If the operation is only partially complete, then it must return 0.
     *     Later, when the operation is complete, the ->run() or ->destruct()
     *     function must call ofoperation_complete() to report success or
     *     failure.
     *
     * ->rule_construct() should not modify any base members of struct rule.
     *
     *
     * Destruction
     * ===========
     *
     * When ->rule_destruct() is called, the caller has already removed 'rule'
     * from 'rule->ofproto''s flow table.  ->rule_destruct() should set in
     * motion removing 'rule' from the datapath flow table.  If removal
     * completes synchronously, it should call ofoperation_complete().
     * Otherwise, the ->run() or ->destruct() function must later call
     * ofoperation_complete() after the operation completes.
     *
     * Rule destruction must not fail. */
    struct rule *(*rule_alloc)(void);
    enum ofperr (*rule_construct)(struct rule *rule);
    void (*rule_destruct)(struct rule *rule);
    void (*rule_dealloc)(struct rule *rule);

    /* Obtains statistics for 'rule', storing the number of packets that have
     * matched it in '*packet_count' and the number of bytes in those packets
     * in '*byte_count'.  UINT64_MAX indicates that the packet count or byte
     * count is unknown. */
    void (*rule_get_stats)(struct rule *rule, uint64_t *packet_count,
                           uint64_t *byte_count);

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
     * header pointers (e.g. packet->l3) are appropriately initialized.
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
    void (*rule_modify_actions)(struct rule *rule);

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

    /* Checks the fault status of CFM configured on 'ofport'.  Returns a
     * bitmask of 'cfm_fault_reason's to indicate a CFM fault (generally
     * indicating a connectivity problem).  Returns zero if CFM is not faulted,
     * and -1 if CFM is not enabled on 'port'.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support CFM. */
    int (*get_cfm_fault)(const struct ofport *ofport);

    /* Check the operational status reported by the remote CFM endpoint of
     * 'ofp_port'  Returns 1 if operationally up, 0 if operationally down, and
     * -1 if CFM is not enabled on 'ofp_port' or does not support operational
     * status.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support CFM. */
    int (*get_cfm_opup)(const struct ofport *ofport);

    /* Gets the MPIDs of the remote maintenance points broadcasting to
     * 'ofport'.  Populates 'rmps' with a provider owned array of MPIDs, and
     * 'n_rmps' with the number of MPIDs in 'rmps'. Returns a number less than
     * 0 if CFM is not enabled of 'ofport'.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support CFM. */
    int (*get_cfm_remote_mpids)(const struct ofport *ofport,
                                const uint64_t **rmps, size_t *n_rmps);

    /* Checks the health of CFM configured on 'ofport'.  Returns an integer
     * to indicate the health percentage of the 'ofport' which is an average of
     * the health of all the remote_mps.  Returns an integer between 0 and 100
     * where 0 means that the 'ofport' is very unhealthy and 100 means the
     * 'ofport' is perfectly healthy.  Returns -1 if CFM is not enabled on
     * 'port' or if the number of remote_mpids is > 1.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support CFM. */
    int (*get_cfm_health)(const struct ofport *ofport);

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

    /* Sets the MAC aging timeout for the OFPP_NORMAL action to 'idle_time',
     * in seconds. */
    void (*set_mac_idle_time)(struct ofproto *ofproto, unsigned int idle_time);

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
     * This function should be NULL if a an implementation does not support
     * it. */
    int (*set_realdev)(struct ofport *ofport,
                       uint16_t realdev_ofp_port, int vid);
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

int ofproto_flow_mod(struct ofproto *, const struct ofputil_flow_mod *);
void ofproto_add_flow(struct ofproto *, const struct match *,
                      unsigned int priority,
                      const struct ofpact *ofpacts, size_t ofpacts_len);
bool ofproto_delete_flow(struct ofproto *,
                         const struct match *, unsigned int priority);
void ofproto_flush_flows(struct ofproto *);

#endif /* ofproto/ofproto-provider.h */
