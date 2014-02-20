/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
 * Copyright (c) 2010 Jean Tourrilhes - HP-Labs.
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

#include <config.h>
#include "ofproto.h"
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include "bitmap.h"
#include "byte-order.h"
#include "classifier.h"
#include "connectivity.h"
#include "connmgr.h"
#include "coverage.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "meta-flow.h"
#include "netdev.h"
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-msgs.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto-provider.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "pinsched.h"
#include "pktbuf.h"
#include "poll-loop.h"
#include "random.h"
#include "seq.h"
#include "shash.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto);

COVERAGE_DEFINE(ofproto_flush);
COVERAGE_DEFINE(ofproto_packet_out);
COVERAGE_DEFINE(ofproto_queue_req);
COVERAGE_DEFINE(ofproto_recv_openflow);
COVERAGE_DEFINE(ofproto_reinit_ports);
COVERAGE_DEFINE(ofproto_update_port);

enum ofproto_state {
    S_OPENFLOW,                 /* Processing OpenFlow commands. */
    S_EVICT,                    /* Evicting flows from over-limit tables. */
    S_FLUSH,                    /* Deleting all flow table rules. */
};

enum ofoperation_type {
    OFOPERATION_ADD,
    OFOPERATION_DELETE,
    OFOPERATION_MODIFY,
    OFOPERATION_REPLACE
};

/* A single OpenFlow request can execute any number of operations.  The
 * ofopgroup maintain OpenFlow state common to all of the operations, e.g. the
 * ofconn to which an error reply should be sent if necessary.
 *
 * ofproto initiates some operations internally.  These operations are still
 * assigned to groups but will not have an associated ofconn. */
struct ofopgroup {
    struct ofproto *ofproto;    /* Owning ofproto. */
    struct list ofproto_node;   /* In ofproto's "pending" list. */
    struct list ops;            /* List of "struct ofoperation"s. */
    int n_running;              /* Number of ops still pending. */

    /* Data needed to send OpenFlow reply on failure or to send a buffered
     * packet on success.
     *
     * If list_is_empty(ofconn_node) then this ofopgroup never had an
     * associated ofconn or its ofconn's connection dropped after it initiated
     * the operation.  In the latter case 'ofconn' is a wild pointer that
     * refers to freed memory, so the 'ofconn' member must be used only if
     * !list_is_empty(ofconn_node).
     */
    struct list ofconn_node;    /* In ofconn's list of pending opgroups. */
    struct ofconn *ofconn;      /* ofconn for reply (but see note above). */
    struct ofp_header *request; /* Original request (truncated at 64 bytes). */
    uint32_t buffer_id;         /* Buffer id from original request. */
};

static struct ofopgroup *ofopgroup_create_unattached(struct ofproto *);
static struct ofopgroup *ofopgroup_create(struct ofproto *, struct ofconn *,
                                          const struct ofp_header *,
                                          uint32_t buffer_id);
static void ofopgroup_submit(struct ofopgroup *);
static void ofopgroup_complete(struct ofopgroup *);

/* A single flow table operation. */
struct ofoperation {
    struct ofopgroup *group;    /* Owning group. */
    struct list group_node;     /* In ofopgroup's "ops" list. */
    struct hmap_node hmap_node; /* In ofproto's "deletions" hmap. */
    struct rule *rule;          /* Rule being operated upon. */
    enum ofoperation_type type; /* Type of operation. */

    /* OFOPERATION_MODIFY, OFOPERATION_REPLACE: The old actions, if the actions
     * are changing. */
    struct rule_actions *actions;

    /* OFOPERATION_DELETE. */
    enum ofp_flow_removed_reason reason; /* Reason flow was removed. */

    ovs_be64 flow_cookie;               /* Rule's old flow cookie. */
    uint16_t idle_timeout;              /* Rule's old idle timeout. */
    uint16_t hard_timeout;              /* Rule's old hard timeout. */
    enum ofputil_flow_mod_flags flags;  /* Rule's old flags. */
    enum ofperr error;                  /* 0 if no error. */
};

static struct ofoperation *ofoperation_create(struct ofopgroup *,
                                              struct rule *,
                                              enum ofoperation_type,
                                              enum ofp_flow_removed_reason);
static void ofoperation_destroy(struct ofoperation *);

/* oftable. */
static void oftable_init(struct oftable *);
static void oftable_destroy(struct oftable *);

static void oftable_set_name(struct oftable *, const char *name);

static void oftable_disable_eviction(struct oftable *);
static void oftable_enable_eviction(struct oftable *,
                                    const struct mf_subfield *fields,
                                    size_t n_fields);

static void oftable_remove_rule(struct rule *rule) OVS_REQUIRES(ofproto_mutex);
static void oftable_remove_rule__(struct ofproto *, struct rule *)
    OVS_REQUIRES(ofproto_mutex);
static void oftable_insert_rule(struct rule *);

/* A set of rules within a single OpenFlow table (oftable) that have the same
 * values for the oftable's eviction_fields.  A rule to be evicted, when one is
 * needed, is taken from the eviction group that contains the greatest number
 * of rules.
 *
 * An oftable owns any number of eviction groups, each of which contains any
 * number of rules.
 *
 * Membership in an eviction group is imprecise, based on the hash of the
 * oftable's eviction_fields (in the eviction_group's id_node.hash member).
 * That is, if two rules have different eviction_fields, but those
 * eviction_fields hash to the same value, then they will belong to the same
 * eviction_group anyway.
 *
 * (When eviction is not enabled on an oftable, we don't track any eviction
 * groups, to save time and space.) */
struct eviction_group {
    struct hmap_node id_node;   /* In oftable's "eviction_groups_by_id". */
    struct heap_node size_node; /* In oftable's "eviction_groups_by_size". */
    struct heap rules;          /* Contains "struct rule"s. */
};

static bool choose_rule_to_evict(struct oftable *table, struct rule **rulep);
static void ofproto_evict(struct ofproto *) OVS_EXCLUDED(ofproto_mutex);
static uint32_t rule_eviction_priority(struct rule *);
static void eviction_group_add_rule(struct rule *);
static void eviction_group_remove_rule(struct rule *);

/* Criteria that flow_mod and other operations use for selecting rules on
 * which to operate. */
struct rule_criteria {
    /* An OpenFlow table or 255 for all tables. */
    uint8_t table_id;

    /* OpenFlow matching criteria.  Interpreted different in "loose" way by
     * collect_rules_loose() and "strict" way by collect_rules_strict(), as
     * defined in the OpenFlow spec. */
    struct cls_rule cr;

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
};

static void rule_criteria_init(struct rule_criteria *, uint8_t table_id,
                               const struct match *match,
                               unsigned int priority,
                               ovs_be64 cookie, ovs_be64 cookie_mask,
                               ofp_port_t out_port, uint32_t out_group);
static void rule_criteria_destroy(struct rule_criteria *);

/* A packet that needs to be passed to rule_execute().
 *
 * (We can't do this immediately from ofopgroup_complete() because that holds
 * ofproto_mutex, which rule_execute() needs released.) */
struct rule_execute {
    struct list list_node;      /* In struct ofproto's "rule_executes" list. */
    struct rule *rule;          /* Owns a reference to the rule. */
    ofp_port_t in_port;
    struct ofpbuf *packet;      /* Owns the packet. */
};

static void run_rule_executes(struct ofproto *) OVS_EXCLUDED(ofproto_mutex);
static void destroy_rule_executes(struct ofproto *);

/* ofport. */
static void ofport_destroy__(struct ofport *) OVS_EXCLUDED(ofproto_mutex);
static void ofport_destroy(struct ofport *);

static void update_port(struct ofproto *, const char *devname);
static int init_ports(struct ofproto *);
static void reinit_ports(struct ofproto *);

static long long int ofport_get_usage(const struct ofproto *,
                                      ofp_port_t ofp_port);
static void ofport_set_usage(struct ofproto *, ofp_port_t ofp_port,
                             long long int last_used);
static void ofport_remove_usage(struct ofproto *, ofp_port_t ofp_port);

/* Ofport usage.
 *
 * Keeps track of the currently used and recently used ofport values and is
 * used to prevent immediate recycling of ofport values. */
struct ofport_usage {
    struct hmap_node hmap_node; /* In struct ofproto's "ofport_usage" hmap. */
    ofp_port_t ofp_port;        /* OpenFlow port number. */
    long long int last_used;    /* Last time the 'ofp_port' was used. LLONG_MAX
                                   represents in-use ofports. */
};

/* rule. */
static void ofproto_rule_destroy__(struct rule *);
static void ofproto_rule_send_removed(struct rule *, uint8_t reason);
static bool rule_is_modifiable(const struct rule *);

/* OpenFlow. */
static enum ofperr add_flow(struct ofproto *, struct ofconn *,
                            struct ofputil_flow_mod *,
                            const struct ofp_header *);
static enum ofperr modify_flows__(struct ofproto *, struct ofconn *,
                                  struct ofputil_flow_mod *,
                                  const struct ofp_header *,
                                  const struct rule_collection *);
static void delete_flow__(struct rule *rule, struct ofopgroup *,
                          enum ofp_flow_removed_reason)
    OVS_REQUIRES(ofproto_mutex);
static bool ofproto_group_exists__(const struct ofproto *ofproto,
                                   uint32_t group_id)
    OVS_REQ_RDLOCK(ofproto->groups_rwlock);
static bool ofproto_group_exists(const struct ofproto *ofproto,
                                 uint32_t group_id)
    OVS_EXCLUDED(ofproto->groups_rwlock);
static enum ofperr add_group(struct ofproto *, struct ofputil_group_mod *);
static bool handle_openflow(struct ofconn *, const struct ofpbuf *);
static enum ofperr handle_flow_mod__(struct ofproto *, struct ofconn *,
                                     struct ofputil_flow_mod *,
                                     const struct ofp_header *)
    OVS_EXCLUDED(ofproto_mutex);
static void calc_duration(long long int start, long long int now,
                          uint32_t *sec, uint32_t *nsec);

/* ofproto. */
static uint64_t pick_datapath_id(const struct ofproto *);
static uint64_t pick_fallback_dpid(void);
static void ofproto_destroy__(struct ofproto *);
static void update_mtu(struct ofproto *, struct ofport *);
static void meter_delete(struct ofproto *, uint32_t first, uint32_t last);

/* unixctl. */
static void ofproto_unixctl_init(void);

/* All registered ofproto classes, in probe order. */
static const struct ofproto_class **ofproto_classes;
static size_t n_ofproto_classes;
static size_t allocated_ofproto_classes;

/* Global lock that protects all flow table operations. */
struct ovs_mutex ofproto_mutex = OVS_MUTEX_INITIALIZER;

unsigned ofproto_flow_limit = OFPROTO_FLOW_LIMIT_DEFAULT;
enum ofproto_flow_miss_model flow_miss_model = OFPROTO_HANDLE_MISS_AUTO;

size_t n_handlers, n_revalidators;

/* Map from datapath name to struct ofproto, for use by unixctl commands. */
static struct hmap all_ofprotos = HMAP_INITIALIZER(&all_ofprotos);

/* Initial mappings of port to OpenFlow number mappings. */
static struct shash init_ofp_ports = SHASH_INITIALIZER(&init_ofp_ports);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* The default value of true waits for flow restore. */
static bool flow_restore_wait = true;

/* Must be called to initialize the ofproto library.
 *
 * The caller may pass in 'iface_hints', which contains an shash of
 * "iface_hint" elements indexed by the interface's name.  The provider
 * may use these hints to describe the startup configuration in order to
 * reinitialize its state.  The caller owns the provided data, so a
 * provider will make copies of anything required.  An ofproto provider
 * will remove any existing state that is not described by the hint, and
 * may choose to remove it all. */
void
ofproto_init(const struct shash *iface_hints)
{
    struct shash_node *node;
    size_t i;

    ofproto_class_register(&ofproto_dpif_class);

    /* Make a local copy, since we don't own 'iface_hints' elements. */
    SHASH_FOR_EACH(node, iface_hints) {
        const struct iface_hint *orig_hint = node->data;
        struct iface_hint *new_hint = xmalloc(sizeof *new_hint);
        const char *br_type = ofproto_normalize_type(orig_hint->br_type);

        new_hint->br_name = xstrdup(orig_hint->br_name);
        new_hint->br_type = xstrdup(br_type);
        new_hint->ofp_port = orig_hint->ofp_port;

        shash_add(&init_ofp_ports, node->name, new_hint);
    }

    for (i = 0; i < n_ofproto_classes; i++) {
        ofproto_classes[i]->init(&init_ofp_ports);
    }
}

/* 'type' should be a normalized datapath type, as returned by
 * ofproto_normalize_type().  Returns the corresponding ofproto_class
 * structure, or a null pointer if there is none registered for 'type'. */
static const struct ofproto_class *
ofproto_class_find__(const char *type)
{
    size_t i;

    for (i = 0; i < n_ofproto_classes; i++) {
        const struct ofproto_class *class = ofproto_classes[i];
        struct sset types;
        bool found;

        sset_init(&types);
        class->enumerate_types(&types);
        found = sset_contains(&types, type);
        sset_destroy(&types);

        if (found) {
            return class;
        }
    }
    VLOG_WARN("unknown datapath type %s", type);
    return NULL;
}

/* Registers a new ofproto class.  After successful registration, new ofprotos
 * of that type can be created using ofproto_create(). */
int
ofproto_class_register(const struct ofproto_class *new_class)
{
    size_t i;

    for (i = 0; i < n_ofproto_classes; i++) {
        if (ofproto_classes[i] == new_class) {
            return EEXIST;
        }
    }

    if (n_ofproto_classes >= allocated_ofproto_classes) {
        ofproto_classes = x2nrealloc(ofproto_classes,
                                     &allocated_ofproto_classes,
                                     sizeof *ofproto_classes);
    }
    ofproto_classes[n_ofproto_classes++] = new_class;
    return 0;
}

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any ofprotos.  After
 * unregistration new datapaths of that type cannot be opened using
 * ofproto_create(). */
int
ofproto_class_unregister(const struct ofproto_class *class)
{
    size_t i;

    for (i = 0; i < n_ofproto_classes; i++) {
        if (ofproto_classes[i] == class) {
            for (i++; i < n_ofproto_classes; i++) {
                ofproto_classes[i - 1] = ofproto_classes[i];
            }
            n_ofproto_classes--;
            return 0;
        }
    }
    VLOG_WARN("attempted to unregister an ofproto class that is not "
              "registered");
    return EAFNOSUPPORT;
}

/* Clears 'types' and enumerates all registered ofproto types into it.  The
 * caller must first initialize the sset. */
void
ofproto_enumerate_types(struct sset *types)
{
    size_t i;

    sset_clear(types);
    for (i = 0; i < n_ofproto_classes; i++) {
        ofproto_classes[i]->enumerate_types(types);
    }
}

/* Returns the fully spelled out name for the given ofproto 'type'.
 *
 * Normalized type string can be compared with strcmp().  Unnormalized type
 * string might be the same even if they have different spellings. */
const char *
ofproto_normalize_type(const char *type)
{
    return type && type[0] ? type : "system";
}

/* Clears 'names' and enumerates the names of all known created ofprotos with
 * the given 'type'.  The caller must first initialize the sset.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Some kinds of datapaths might not be practically enumerable.  This is not
 * considered an error. */
int
ofproto_enumerate_names(const char *type, struct sset *names)
{
    const struct ofproto_class *class = ofproto_class_find__(type);
    return class ? class->enumerate_names(type, names) : EAFNOSUPPORT;
}

int
ofproto_create(const char *datapath_name, const char *datapath_type,
               struct ofproto **ofprotop)
{
    const struct ofproto_class *class;
    struct ofproto *ofproto;
    int error;
    int i;

    *ofprotop = NULL;

    ofproto_unixctl_init();

    datapath_type = ofproto_normalize_type(datapath_type);
    class = ofproto_class_find__(datapath_type);
    if (!class) {
        VLOG_WARN("could not create datapath %s of unknown type %s",
                  datapath_name, datapath_type);
        return EAFNOSUPPORT;
    }

    ofproto = class->alloc();
    if (!ofproto) {
        VLOG_ERR("failed to allocate datapath %s of type %s",
                 datapath_name, datapath_type);
        return ENOMEM;
    }

    /* Initialize. */
    ovs_mutex_lock(&ofproto_mutex);
    memset(ofproto, 0, sizeof *ofproto);
    ofproto->ofproto_class = class;
    ofproto->name = xstrdup(datapath_name);
    ofproto->type = xstrdup(datapath_type);
    hmap_insert(&all_ofprotos, &ofproto->hmap_node,
                hash_string(ofproto->name, 0));
    ofproto->datapath_id = 0;
    ofproto->forward_bpdu = false;
    ofproto->fallback_dpid = pick_fallback_dpid();
    ofproto->mfr_desc = NULL;
    ofproto->hw_desc = NULL;
    ofproto->sw_desc = NULL;
    ofproto->serial_desc = NULL;
    ofproto->dp_desc = NULL;
    ofproto->frag_handling = OFPC_FRAG_NORMAL;
    hmap_init(&ofproto->ports);
    hmap_init(&ofproto->ofport_usage);
    shash_init(&ofproto->port_by_name);
    simap_init(&ofproto->ofp_requests);
    ofproto->max_ports = ofp_to_u16(OFPP_MAX);
    ofproto->eviction_group_timer = LLONG_MIN;
    ofproto->tables = NULL;
    ofproto->n_tables = 0;
    hindex_init(&ofproto->cookies);
    list_init(&ofproto->expirable);
    ofproto->connmgr = connmgr_create(ofproto, datapath_name, datapath_name);
    ofproto->state = S_OPENFLOW;
    list_init(&ofproto->pending);
    ofproto->n_pending = 0;
    hmap_init(&ofproto->deletions);
    guarded_list_init(&ofproto->rule_executes);
    ofproto->n_add = ofproto->n_delete = ofproto->n_modify = 0;
    ofproto->first_op = ofproto->last_op = LLONG_MIN;
    ofproto->next_op_report = LLONG_MAX;
    ofproto->op_backoff = LLONG_MIN;
    ofproto->vlan_bitmap = NULL;
    ofproto->vlans_changed = false;
    ofproto->min_mtu = INT_MAX;
    ovs_rwlock_init(&ofproto->groups_rwlock);
    hmap_init(&ofproto->groups);
    ovs_mutex_unlock(&ofproto_mutex);
    ofproto->ogf.capabilities = OFPGFC_CHAINING | OFPGFC_SELECT_LIVENESS |
                                OFPGFC_SELECT_WEIGHT;
    ofproto->ogf.max_groups[OFPGT11_ALL] = OFPG_MAX;
    ofproto->ogf.max_groups[OFPGT11_SELECT] = OFPG_MAX;
    ofproto->ogf.max_groups[OFPGT11_INDIRECT] = OFPG_MAX;
    ofproto->ogf.max_groups[OFPGT11_FF] = OFPG_MAX;
    ofproto->ogf.actions[0] =
        (1 << OFPAT11_OUTPUT) |
        (1 << OFPAT11_COPY_TTL_OUT) |
        (1 << OFPAT11_COPY_TTL_IN) |
        (1 << OFPAT11_SET_MPLS_TTL) |
        (1 << OFPAT11_DEC_MPLS_TTL) |
        (1 << OFPAT11_PUSH_VLAN) |
        (1 << OFPAT11_POP_VLAN) |
        (1 << OFPAT11_PUSH_MPLS) |
        (1 << OFPAT11_POP_MPLS) |
        (1 << OFPAT11_SET_QUEUE) |
        (1 << OFPAT11_GROUP) |
        (1 << OFPAT11_SET_NW_TTL) |
        (1 << OFPAT11_DEC_NW_TTL) |
        (1 << OFPAT12_SET_FIELD);
/* not supported:
 *      (1 << OFPAT13_PUSH_PBB) |
 *      (1 << OFPAT13_POP_PBB) */

    error = ofproto->ofproto_class->construct(ofproto);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s",
                 datapath_name, ovs_strerror(error));
        ofproto_destroy__(ofproto);
        return error;
    }

    /* Check that hidden tables, if any, are at the end. */
    ovs_assert(ofproto->n_tables);
    for (i = 0; i + 1 < ofproto->n_tables; i++) {
        enum oftable_flags flags = ofproto->tables[i].flags;
        enum oftable_flags next_flags = ofproto->tables[i + 1].flags;

        ovs_assert(!(flags & OFTABLE_HIDDEN) || next_flags & OFTABLE_HIDDEN);
    }

    ofproto->datapath_id = pick_datapath_id(ofproto);
    init_ports(ofproto);

    /* Initialize meters table. */
    if (ofproto->ofproto_class->meter_get_features) {
        ofproto->ofproto_class->meter_get_features(ofproto,
                                                   &ofproto->meter_features);
    } else {
        memset(&ofproto->meter_features, 0, sizeof ofproto->meter_features);
    }
    ofproto->meters = xzalloc((ofproto->meter_features.max_meters + 1)
                              * sizeof(struct meter *));

    *ofprotop = ofproto;
    return 0;
}

/* Must be called (only) by an ofproto implementation in its constructor
 * function.  See the large comment on 'construct' in struct ofproto_class for
 * details. */
void
ofproto_init_tables(struct ofproto *ofproto, int n_tables)
{
    struct oftable *table;

    ovs_assert(!ofproto->n_tables);
    ovs_assert(n_tables >= 1 && n_tables <= 255);

    ofproto->n_tables = n_tables;
    ofproto->tables = xmalloc(n_tables * sizeof *ofproto->tables);
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        oftable_init(table);
    }
}

/* To be optionally called (only) by an ofproto implementation in its
 * constructor function.  See the large comment on 'construct' in struct
 * ofproto_class for details.
 *
 * Sets the maximum number of ports to 'max_ports'.  The ofproto generic layer
 * will then ensure that actions passed into the ofproto implementation will
 * not refer to OpenFlow ports numbered 'max_ports' or higher.  If this
 * function is not called, there will be no such restriction.
 *
 * Reserved ports numbered OFPP_MAX and higher are special and not subject to
 * the 'max_ports' restriction. */
void
ofproto_init_max_ports(struct ofproto *ofproto, uint16_t max_ports)
{
    ovs_assert(max_ports <= ofp_to_u16(OFPP_MAX));
    ofproto->max_ports = max_ports;
}

uint64_t
ofproto_get_datapath_id(const struct ofproto *ofproto)
{
    return ofproto->datapath_id;
}

void
ofproto_set_datapath_id(struct ofproto *p, uint64_t datapath_id)
{
    uint64_t old_dpid = p->datapath_id;
    p->datapath_id = datapath_id ? datapath_id : pick_datapath_id(p);
    if (p->datapath_id != old_dpid) {
        /* Force all active connections to reconnect, since there is no way to
         * notify a controller that the datapath ID has changed. */
        ofproto_reconnect_controllers(p);
    }
}

void
ofproto_set_controllers(struct ofproto *p,
                        const struct ofproto_controller *controllers,
                        size_t n_controllers, uint32_t allowed_versions)
{
    connmgr_set_controllers(p->connmgr, controllers, n_controllers,
                            allowed_versions);
}

void
ofproto_set_fail_mode(struct ofproto *p, enum ofproto_fail_mode fail_mode)
{
    connmgr_set_fail_mode(p->connmgr, fail_mode);
}

/* Drops the connections between 'ofproto' and all of its controllers, forcing
 * them to reconnect. */
void
ofproto_reconnect_controllers(struct ofproto *ofproto)
{
    connmgr_reconnect(ofproto->connmgr);
}

/* Sets the 'n' TCP port addresses in 'extras' as ones to which 'ofproto''s
 * in-band control should guarantee access, in the same way that in-band
 * control guarantees access to OpenFlow controllers. */
void
ofproto_set_extra_in_band_remotes(struct ofproto *ofproto,
                                  const struct sockaddr_in *extras, size_t n)
{
    connmgr_set_extra_in_band_remotes(ofproto->connmgr, extras, n);
}

/* Sets the OpenFlow queue used by flows set up by in-band control on
 * 'ofproto' to 'queue_id'.  If 'queue_id' is negative, then in-band control
 * flows will use the default queue. */
void
ofproto_set_in_band_queue(struct ofproto *ofproto, int queue_id)
{
    connmgr_set_in_band_queue(ofproto->connmgr, queue_id);
}

/* Sets the number of flows at which eviction from the kernel flow table
 * will occur. */
void
ofproto_set_flow_limit(unsigned limit)
{
    ofproto_flow_limit = limit;
}

/* Sets the path for handling flow misses. */
void
ofproto_set_flow_miss_model(unsigned model)
{
    flow_miss_model = model;
}

/* If forward_bpdu is true, the NORMAL action will forward frames with
 * reserved (e.g. STP) destination Ethernet addresses. if forward_bpdu is false,
 * the NORMAL action will drop these frames. */
void
ofproto_set_forward_bpdu(struct ofproto *ofproto, bool forward_bpdu)
{
    bool old_val = ofproto->forward_bpdu;
    ofproto->forward_bpdu = forward_bpdu;
    if (old_val != ofproto->forward_bpdu) {
        if (ofproto->ofproto_class->forward_bpdu_changed) {
            ofproto->ofproto_class->forward_bpdu_changed(ofproto);
        }
    }
}

/* Sets the MAC aging timeout for the OFPP_NORMAL action on 'ofproto' to
 * 'idle_time', in seconds, and the maximum number of MAC table entries to
 * 'max_entries'. */
void
ofproto_set_mac_table_config(struct ofproto *ofproto, unsigned idle_time,
                             size_t max_entries)
{
    if (ofproto->ofproto_class->set_mac_table_config) {
        ofproto->ofproto_class->set_mac_table_config(ofproto, idle_time,
                                                     max_entries);
    }
}

void
ofproto_set_threads(size_t n_handlers_, size_t n_revalidators_)
{
    int threads = MAX(count_cpu_cores(), 2);

    n_revalidators = n_revalidators_;
    n_handlers = n_handlers_;

    if (!n_revalidators) {
        n_revalidators = n_handlers
            ? MAX(threads - (int) n_handlers, 1)
            : threads / 4 + 1;
    }

    if (!n_handlers) {
        n_handlers = MAX(threads - (int) n_revalidators, 1);
    }
}

void
ofproto_set_dp_desc(struct ofproto *p, const char *dp_desc)
{
    free(p->dp_desc);
    p->dp_desc = dp_desc ? xstrdup(dp_desc) : NULL;
}

int
ofproto_set_snoops(struct ofproto *ofproto, const struct sset *snoops)
{
    return connmgr_set_snoops(ofproto->connmgr, snoops);
}

int
ofproto_set_netflow(struct ofproto *ofproto,
                    const struct netflow_options *nf_options)
{
    if (nf_options && sset_is_empty(&nf_options->collectors)) {
        nf_options = NULL;
    }

    if (ofproto->ofproto_class->set_netflow) {
        return ofproto->ofproto_class->set_netflow(ofproto, nf_options);
    } else {
        return nf_options ? EOPNOTSUPP : 0;
    }
}

int
ofproto_set_sflow(struct ofproto *ofproto,
                  const struct ofproto_sflow_options *oso)
{
    if (oso && sset_is_empty(&oso->targets)) {
        oso = NULL;
    }

    if (ofproto->ofproto_class->set_sflow) {
        return ofproto->ofproto_class->set_sflow(ofproto, oso);
    } else {
        return oso ? EOPNOTSUPP : 0;
    }
}

int
ofproto_set_ipfix(struct ofproto *ofproto,
                  const struct ofproto_ipfix_bridge_exporter_options *bo,
                  const struct ofproto_ipfix_flow_exporter_options *fo,
                  size_t n_fo)
{
    if (ofproto->ofproto_class->set_ipfix) {
        return ofproto->ofproto_class->set_ipfix(ofproto, bo, fo, n_fo);
    } else {
        return (bo || fo) ? EOPNOTSUPP : 0;
    }
}

void
ofproto_set_flow_restore_wait(bool flow_restore_wait_db)
{
    flow_restore_wait = flow_restore_wait_db;
}

bool
ofproto_get_flow_restore_wait(void)
{
    return flow_restore_wait;
}


/* Spanning Tree Protocol (STP) configuration. */

/* Configures STP on 'ofproto' using the settings defined in 's'.  If
 * 's' is NULL, disables STP.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_set_stp(struct ofproto *ofproto,
                const struct ofproto_stp_settings *s)
{
    return (ofproto->ofproto_class->set_stp
            ? ofproto->ofproto_class->set_stp(ofproto, s)
            : EOPNOTSUPP);
}

/* Retrieves STP status of 'ofproto' and stores it in 's'.  If the
 * 'enabled' member of 's' is false, then the other members are not
 * meaningful.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_get_stp_status(struct ofproto *ofproto,
                       struct ofproto_stp_status *s)
{
    return (ofproto->ofproto_class->get_stp_status
            ? ofproto->ofproto_class->get_stp_status(ofproto, s)
            : EOPNOTSUPP);
}

/* Configures STP on 'ofp_port' of 'ofproto' using the settings defined
 * in 's'.  The caller is responsible for assigning STP port numbers
 * (using the 'port_num' member in the range of 1 through 255, inclusive)
 * and ensuring there are no duplicates.  If the 's' is NULL, then STP
 * is disabled on the port.
 *
 * Returns 0 if successful, otherwise a positive errno value.*/
int
ofproto_port_set_stp(struct ofproto *ofproto, ofp_port_t ofp_port,
                     const struct ofproto_port_stp_settings *s)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN("%s: cannot configure STP on nonexistent port %"PRIu16,
                  ofproto->name, ofp_port);
        return ENODEV;
    }

    return (ofproto->ofproto_class->set_stp_port
            ? ofproto->ofproto_class->set_stp_port(ofport, s)
            : EOPNOTSUPP);
}

/* Retrieves STP port status of 'ofp_port' on 'ofproto' and stores it in
 * 's'.  If the 'enabled' member in 's' is false, then the other members
 * are not meaningful.
 *
 * Returns 0 if successful, otherwise a positive errno value.*/
int
ofproto_port_get_stp_status(struct ofproto *ofproto, ofp_port_t ofp_port,
                            struct ofproto_port_stp_status *s)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN_RL(&rl, "%s: cannot get STP status on nonexistent "
                     "port %"PRIu16, ofproto->name, ofp_port);
        return ENODEV;
    }

    return (ofproto->ofproto_class->get_stp_port_status
            ? ofproto->ofproto_class->get_stp_port_status(ofport, s)
            : EOPNOTSUPP);
}

/* Retrieves STP port statistics of 'ofp_port' on 'ofproto' and stores it in
 * 's'.  If the 'enabled' member in 's' is false, then the other members
 * are not meaningful.
 *
 * Returns 0 if successful, otherwise a positive errno value.*/
int
ofproto_port_get_stp_stats(struct ofproto *ofproto, ofp_port_t ofp_port,
                           struct ofproto_port_stp_stats *s)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN_RL(&rl, "%s: cannot get STP stats on nonexistent "
                     "port %"PRIu16, ofproto->name, ofp_port);
        return ENODEV;
    }

    return (ofproto->ofproto_class->get_stp_port_stats
            ? ofproto->ofproto_class->get_stp_port_stats(ofport, s)
            : EOPNOTSUPP);
}

/* Queue DSCP configuration. */

/* Registers meta-data associated with the 'n_qdscp' Qualities of Service
 * 'queues' attached to 'ofport'.  This data is not intended to be sufficient
 * to implement QoS.  Instead, it is used to implement features which require
 * knowledge of what queues exist on a port, and some basic information about
 * them.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_port_set_queues(struct ofproto *ofproto, ofp_port_t ofp_port,
                        const struct ofproto_port_queue *queues,
                        size_t n_queues)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);

    if (!ofport) {
        VLOG_WARN("%s: cannot set queues on nonexistent port %"PRIu16,
                  ofproto->name, ofp_port);
        return ENODEV;
    }

    return (ofproto->ofproto_class->set_queues
            ? ofproto->ofproto_class->set_queues(ofport, queues, n_queues)
            : EOPNOTSUPP);
}

/* Connectivity Fault Management configuration. */

/* Clears the CFM configuration from 'ofp_port' on 'ofproto'. */
void
ofproto_port_clear_cfm(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    if (ofport && ofproto->ofproto_class->set_cfm) {
        ofproto->ofproto_class->set_cfm(ofport, NULL);
    }
}

/* Configures connectivity fault management on 'ofp_port' in 'ofproto'.  Takes
 * basic configuration from the configuration members in 'cfm', and the remote
 * maintenance point ID from  remote_mpid.  Ignores the statistics members of
 * 'cfm'.
 *
 * This function has no effect if 'ofproto' does not have a port 'ofp_port'. */
void
ofproto_port_set_cfm(struct ofproto *ofproto, ofp_port_t ofp_port,
                     const struct cfm_settings *s)
{
    struct ofport *ofport;
    int error;

    ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN("%s: cannot configure CFM on nonexistent port %"PRIu16,
                  ofproto->name, ofp_port);
        return;
    }

    /* XXX: For configuration simplicity, we only support one remote_mpid
     * outside of the CFM module.  It's not clear if this is the correct long
     * term solution or not. */
    error = (ofproto->ofproto_class->set_cfm
             ? ofproto->ofproto_class->set_cfm(ofport, s)
             : EOPNOTSUPP);
    if (error) {
        VLOG_WARN("%s: CFM configuration on port %"PRIu16" (%s) failed (%s)",
                  ofproto->name, ofp_port, netdev_get_name(ofport->netdev),
                  ovs_strerror(error));
    }
}

/* Configures BFD on 'ofp_port' in 'ofproto'.  This function has no effect if
 * 'ofproto' does not have a port 'ofp_port'. */
void
ofproto_port_set_bfd(struct ofproto *ofproto, ofp_port_t ofp_port,
                     const struct smap *cfg)
{
    struct ofport *ofport;
    int error;

    ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN("%s: cannot configure bfd on nonexistent port %"PRIu16,
                  ofproto->name, ofp_port);
        return;
    }

    error = (ofproto->ofproto_class->set_bfd
             ? ofproto->ofproto_class->set_bfd(ofport, cfg)
             : EOPNOTSUPP);
    if (error) {
        VLOG_WARN("%s: bfd configuration on port %"PRIu16" (%s) failed (%s)",
                  ofproto->name, ofp_port, netdev_get_name(ofport->netdev),
                  ovs_strerror(error));
    }
}

/* Populates 'status' with key value pairs indicating the status of the BFD
 * session on 'ofp_port'.  This information is intended to be populated in the
 * OVS database.  Has no effect if 'ofp_port' is not na OpenFlow port in
 * 'ofproto'. */
int
ofproto_port_get_bfd_status(struct ofproto *ofproto, ofp_port_t ofp_port,
                            struct smap *status)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->get_bfd_status
            ? ofproto->ofproto_class->get_bfd_status(ofport, status)
            : EOPNOTSUPP);
}

/* Checks the status of LACP negotiation for 'ofp_port' within ofproto.
 * Returns 1 if LACP partner information for 'ofp_port' is up-to-date,
 * 0 if LACP partner information is not current (generally indicating a
 * connectivity problem), or -1 if LACP is not enabled on 'ofp_port'. */
int
ofproto_port_is_lacp_current(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->port_is_lacp_current
            ? ofproto->ofproto_class->port_is_lacp_current(ofport)
            : -1);
}

/* Bundles. */

/* Registers a "bundle" associated with client data pointer 'aux' in 'ofproto'.
 * A bundle is the same concept as a Port in OVSDB, that is, it consists of one
 * or more "slave" devices (Interfaces, in OVSDB) along with a VLAN
 * configuration plus, if there is more than one slave, a bonding
 * configuration.
 *
 * If 'aux' is already registered then this function updates its configuration
 * to 's'.  Otherwise, this function registers a new bundle.
 *
 * Bundles only affect the NXAST_AUTOPATH action and output to the OFPP_NORMAL
 * port. */
int
ofproto_bundle_register(struct ofproto *ofproto, void *aux,
                        const struct ofproto_bundle_settings *s)
{
    return (ofproto->ofproto_class->bundle_set
            ? ofproto->ofproto_class->bundle_set(ofproto, aux, s)
            : EOPNOTSUPP);
}

/* Unregisters the bundle registered on 'ofproto' with auxiliary data 'aux'.
 * If no such bundle has been registered, this has no effect. */
int
ofproto_bundle_unregister(struct ofproto *ofproto, void *aux)
{
    return ofproto_bundle_register(ofproto, aux, NULL);
}


/* Registers a mirror associated with client data pointer 'aux' in 'ofproto'.
 * If 'aux' is already registered then this function updates its configuration
 * to 's'.  Otherwise, this function registers a new mirror. */
int
ofproto_mirror_register(struct ofproto *ofproto, void *aux,
                        const struct ofproto_mirror_settings *s)
{
    return (ofproto->ofproto_class->mirror_set
            ? ofproto->ofproto_class->mirror_set(ofproto, aux, s)
            : EOPNOTSUPP);
}

/* Unregisters the mirror registered on 'ofproto' with auxiliary data 'aux'.
 * If no mirror has been registered, this has no effect. */
int
ofproto_mirror_unregister(struct ofproto *ofproto, void *aux)
{
    return ofproto_mirror_register(ofproto, aux, NULL);
}

/* Retrieves statistics from mirror associated with client data pointer
 * 'aux' in 'ofproto'.  Stores packet and byte counts in 'packets' and
 * 'bytes', respectively.  If a particular counters is not supported,
 * the appropriate argument is set to UINT64_MAX. */
int
ofproto_mirror_get_stats(struct ofproto *ofproto, void *aux,
                         uint64_t *packets, uint64_t *bytes)
{
    if (!ofproto->ofproto_class->mirror_get_stats) {
        *packets = *bytes = UINT64_MAX;
        return EOPNOTSUPP;
    }

    return ofproto->ofproto_class->mirror_get_stats(ofproto, aux,
                                                    packets, bytes);
}

/* Configures the VLANs whose bits are set to 1 in 'flood_vlans' as VLANs on
 * which all packets are flooded, instead of using MAC learning.  If
 * 'flood_vlans' is NULL, then MAC learning applies to all VLANs.
 *
 * Flood VLANs affect only the treatment of packets output to the OFPP_NORMAL
 * port. */
int
ofproto_set_flood_vlans(struct ofproto *ofproto, unsigned long *flood_vlans)
{
    return (ofproto->ofproto_class->set_flood_vlans
            ? ofproto->ofproto_class->set_flood_vlans(ofproto, flood_vlans)
            : EOPNOTSUPP);
}

/* Returns true if 'aux' is a registered bundle that is currently in use as the
 * output for a mirror. */
bool
ofproto_is_mirror_output_bundle(const struct ofproto *ofproto, void *aux)
{
    return (ofproto->ofproto_class->is_mirror_output_bundle
            ? ofproto->ofproto_class->is_mirror_output_bundle(ofproto, aux)
            : false);
}

/* Configuration of OpenFlow tables. */

/* Returns the number of OpenFlow tables in 'ofproto'. */
int
ofproto_get_n_tables(const struct ofproto *ofproto)
{
    return ofproto->n_tables;
}

/* Configures the OpenFlow table in 'ofproto' with id 'table_id' with the
 * settings from 's'.  'table_id' must be in the range 0 through the number of
 * OpenFlow tables in 'ofproto' minus 1, inclusive.
 *
 * For read-only tables, only the name may be configured. */
void
ofproto_configure_table(struct ofproto *ofproto, int table_id,
                        const struct ofproto_table_settings *s)
{
    struct oftable *table;

    ovs_assert(table_id >= 0 && table_id < ofproto->n_tables);
    table = &ofproto->tables[table_id];

    oftable_set_name(table, s->name);

    if (table->flags & OFTABLE_READONLY) {
        return;
    }

    if (s->groups) {
        oftable_enable_eviction(table, s->groups, s->n_groups);
    } else {
        oftable_disable_eviction(table);
    }

    table->max_flows = s->max_flows;
    fat_rwlock_wrlock(&table->cls.rwlock);
    if (classifier_count(&table->cls) > table->max_flows
        && table->eviction_fields) {
        /* 'table' contains more flows than allowed.  We might not be able to
         * evict them right away because of the asynchronous nature of flow
         * table changes.  Schedule eviction for later. */
        switch (ofproto->state) {
        case S_OPENFLOW:
            ofproto->state = S_EVICT;
            break;
        case S_EVICT:
        case S_FLUSH:
            /* We're already deleting flows, nothing more to do. */
            break;
        }
    }

    classifier_set_prefix_fields(&table->cls,
                                 s->prefix_fields, s->n_prefix_fields);

    fat_rwlock_unlock(&table->cls.rwlock);
}

bool
ofproto_has_snoops(const struct ofproto *ofproto)
{
    return connmgr_has_snoops(ofproto->connmgr);
}

void
ofproto_get_snoops(const struct ofproto *ofproto, struct sset *snoops)
{
    connmgr_get_snoops(ofproto->connmgr, snoops);
}

static void
ofproto_rule_delete__(struct ofproto *ofproto, struct rule *rule,
                      uint8_t reason)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofopgroup *group;

    ovs_assert(!rule->pending);

    group = ofopgroup_create_unattached(ofproto);
    delete_flow__(rule, group, reason);
    ofopgroup_submit(group);
}

/* Deletes 'rule' from 'cls' within 'ofproto'.
 *
 * Within an ofproto implementation, this function allows an ofproto
 * implementation to destroy any rules that remain when its ->destruct()
 * function is called.  This function is not suitable for use elsewhere in an
 * ofproto implementation.
 *
 * This function implements steps 4.4 and 4.5 in the section titled "Rule Life
 * Cycle" in ofproto-provider.h. */
void
ofproto_rule_delete(struct ofproto *ofproto, struct rule *rule)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofopgroup *group;

    ovs_mutex_lock(&ofproto_mutex);
    ovs_assert(!rule->pending);

    group = ofopgroup_create_unattached(ofproto);
    ofoperation_create(group, rule, OFOPERATION_DELETE, OFPRR_DELETE);
    oftable_remove_rule__(ofproto, rule);
    ofproto->ofproto_class->rule_delete(rule);
    ofopgroup_submit(group);

    ovs_mutex_unlock(&ofproto_mutex);
}

static void
ofproto_flush__(struct ofproto *ofproto)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct oftable *table;

    if (ofproto->ofproto_class->flush) {
        ofproto->ofproto_class->flush(ofproto);
    }

    ovs_mutex_lock(&ofproto_mutex);
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        struct rule *rule, *next_rule;
        struct cls_cursor cursor;

        if (table->flags & OFTABLE_HIDDEN) {
            continue;
        }

        fat_rwlock_rdlock(&table->cls.rwlock);
        cls_cursor_init(&cursor, &table->cls, NULL);
        fat_rwlock_unlock(&table->cls.rwlock);
        CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
            if (!rule->pending) {
                ofproto_rule_delete__(ofproto, rule, OFPRR_DELETE);
            }
        }
    }
    ovs_mutex_unlock(&ofproto_mutex);
}

static void delete_group(struct ofproto *ofproto, uint32_t group_id);

static void
ofproto_destroy__(struct ofproto *ofproto)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct oftable *table;

    ovs_assert(list_is_empty(&ofproto->pending));

    destroy_rule_executes(ofproto);
    guarded_list_destroy(&ofproto->rule_executes);

    delete_group(ofproto, OFPG_ALL);
    ovs_rwlock_destroy(&ofproto->groups_rwlock);
    hmap_destroy(&ofproto->groups);

    connmgr_destroy(ofproto->connmgr);

    hmap_remove(&all_ofprotos, &ofproto->hmap_node);
    free(ofproto->name);
    free(ofproto->type);
    free(ofproto->mfr_desc);
    free(ofproto->hw_desc);
    free(ofproto->sw_desc);
    free(ofproto->serial_desc);
    free(ofproto->dp_desc);
    hmap_destroy(&ofproto->ports);
    hmap_destroy(&ofproto->ofport_usage);
    shash_destroy(&ofproto->port_by_name);
    simap_destroy(&ofproto->ofp_requests);

    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        oftable_destroy(table);
    }
    free(ofproto->tables);

    hmap_destroy(&ofproto->deletions);

    free(ofproto->vlan_bitmap);

    ofproto->ofproto_class->dealloc(ofproto);
}

void
ofproto_destroy(struct ofproto *p)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofport *ofport, *next_ofport;
    struct ofport_usage *usage, *next_usage;

    if (!p) {
        return;
    }

    if (p->meters) {
        meter_delete(p, 1, p->meter_features.max_meters);
        p->meter_features.max_meters = 0;
        free(p->meters);
        p->meters = NULL;
    }

    ofproto_flush__(p);
    HMAP_FOR_EACH_SAFE (ofport, next_ofport, hmap_node, &p->ports) {
        ofport_destroy(ofport);
    }

    HMAP_FOR_EACH_SAFE (usage, next_usage, hmap_node, &p->ofport_usage) {
        hmap_remove(&p->ofport_usage, &usage->hmap_node);
        free(usage);
    }

    p->ofproto_class->destruct(p);
    ofproto_destroy__(p);
}

/* Destroys the datapath with the respective 'name' and 'type'.  With the Linux
 * kernel datapath, for example, this destroys the datapath in the kernel, and
 * with the netdev-based datapath, it tears down the data structures that
 * represent the datapath.
 *
 * The datapath should not be currently open as an ofproto. */
int
ofproto_delete(const char *name, const char *type)
{
    const struct ofproto_class *class = ofproto_class_find__(type);
    return (!class ? EAFNOSUPPORT
            : !class->del ? EACCES
            : class->del(type, name));
}

static void
process_port_change(struct ofproto *ofproto, int error, char *devname)
{
    if (error == ENOBUFS) {
        reinit_ports(ofproto);
    } else if (!error) {
        update_port(ofproto, devname);
        free(devname);
    }
}

int
ofproto_type_run(const char *datapath_type)
{
    const struct ofproto_class *class;
    int error;

    datapath_type = ofproto_normalize_type(datapath_type);
    class = ofproto_class_find__(datapath_type);

    error = class->type_run ? class->type_run(datapath_type) : 0;
    if (error && error != EAGAIN) {
        VLOG_ERR_RL(&rl, "%s: type_run failed (%s)",
                    datapath_type, ovs_strerror(error));
    }
    return error;
}

void
ofproto_type_wait(const char *datapath_type)
{
    const struct ofproto_class *class;

    datapath_type = ofproto_normalize_type(datapath_type);
    class = ofproto_class_find__(datapath_type);

    if (class->type_wait) {
        class->type_wait(datapath_type);
    }
}

static bool
any_pending_ops(const struct ofproto *p)
    OVS_EXCLUDED(ofproto_mutex)
{
    bool b;

    ovs_mutex_lock(&ofproto_mutex);
    b = !list_is_empty(&p->pending);
    ovs_mutex_unlock(&ofproto_mutex);

    return b;
}

int
ofproto_run(struct ofproto *p)
{
    int error;
    uint64_t new_seq;

    error = p->ofproto_class->run(p);
    if (error && error != EAGAIN) {
        VLOG_ERR_RL(&rl, "%s: run failed (%s)", p->name, ovs_strerror(error));
    }

    run_rule_executes(p);

    /* Restore the eviction group heap invariant occasionally. */
    if (p->eviction_group_timer < time_msec()) {
        size_t i;

        p->eviction_group_timer = time_msec() + 1000;

        for (i = 0; i < p->n_tables; i++) {
            struct oftable *table = &p->tables[i];
            struct eviction_group *evg;
            struct cls_cursor cursor;
            struct rule *rule;

            if (!table->eviction_fields) {
                continue;
            }

            ovs_mutex_lock(&ofproto_mutex);
            HEAP_FOR_EACH (evg, size_node, &table->eviction_groups_by_size) {
                heap_rebuild(&evg->rules);
            }

            fat_rwlock_rdlock(&table->cls.rwlock);
            cls_cursor_init(&cursor, &table->cls, NULL);
            CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
                if (!rule->eviction_group
                    && (rule->idle_timeout || rule->hard_timeout)) {
                    eviction_group_add_rule(rule);
                }
            }
            fat_rwlock_unlock(&table->cls.rwlock);
            ovs_mutex_unlock(&ofproto_mutex);
        }
    }

    if (p->ofproto_class->port_poll) {
        char *devname;

        while ((error = p->ofproto_class->port_poll(p, &devname)) != EAGAIN) {
            process_port_change(p, error, devname);
        }
    }

    new_seq = seq_read(connectivity_seq_get());
    if (new_seq != p->change_seq) {
        struct sset devnames;
        const char *devname;
        struct ofport *ofport;

        /* Update OpenFlow port status for any port whose netdev has changed.
         *
         * Refreshing a given 'ofport' can cause an arbitrary ofport to be
         * destroyed, so it's not safe to update ports directly from the
         * HMAP_FOR_EACH loop, or even to use HMAP_FOR_EACH_SAFE.  Instead, we
         * need this two-phase approach. */
        sset_init(&devnames);
        HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
            sset_add(&devnames, netdev_get_name(ofport->netdev));
        }
        SSET_FOR_EACH (devname, &devnames) {
            update_port(p, devname);
        }
        sset_destroy(&devnames);

        p->change_seq = new_seq;
    }

    switch (p->state) {
    case S_OPENFLOW:
        connmgr_run(p->connmgr, handle_openflow);
        break;

    case S_EVICT:
        connmgr_run(p->connmgr, NULL);
        ofproto_evict(p);
        if (!any_pending_ops(p)) {
            p->state = S_OPENFLOW;
        }
        break;

    case S_FLUSH:
        connmgr_run(p->connmgr, NULL);
        ofproto_flush__(p);
        if (!any_pending_ops(p)) {
            connmgr_flushed(p->connmgr);
            p->state = S_OPENFLOW;
        }
        break;

    default:
        OVS_NOT_REACHED();
    }

    if (time_msec() >= p->next_op_report) {
        long long int ago = (time_msec() - p->first_op) / 1000;
        long long int interval = (p->last_op - p->first_op) / 1000;
        struct ds s;

        ds_init(&s);
        ds_put_format(&s, "%d flow_mods ",
                      p->n_add + p->n_delete + p->n_modify);
        if (interval == ago) {
            ds_put_format(&s, "in the last %lld s", ago);
        } else if (interval) {
            ds_put_format(&s, "in the %lld s starting %lld s ago",
                          interval, ago);
        } else {
            ds_put_format(&s, "%lld s ago", ago);
        }

        ds_put_cstr(&s, " (");
        if (p->n_add) {
            ds_put_format(&s, "%d adds, ", p->n_add);
        }
        if (p->n_delete) {
            ds_put_format(&s, "%d deletes, ", p->n_delete);
        }
        if (p->n_modify) {
            ds_put_format(&s, "%d modifications, ", p->n_modify);
        }
        s.length -= 2;
        ds_put_char(&s, ')');

        VLOG_INFO("%s: %s", p->name, ds_cstr(&s));
        ds_destroy(&s);

        p->n_add = p->n_delete = p->n_modify = 0;
        p->next_op_report = LLONG_MAX;
    }

    return error;
}

void
ofproto_wait(struct ofproto *p)
{
    p->ofproto_class->wait(p);
    if (p->ofproto_class->port_poll_wait) {
        p->ofproto_class->port_poll_wait(p);
    }
    seq_wait(connectivity_seq_get(), p->change_seq);

    switch (p->state) {
    case S_OPENFLOW:
        connmgr_wait(p->connmgr, true);
        break;

    case S_EVICT:
    case S_FLUSH:
        connmgr_wait(p->connmgr, false);
        if (!any_pending_ops(p)) {
            poll_immediate_wake();
        }
        break;
    }
}

bool
ofproto_is_alive(const struct ofproto *p)
{
    return connmgr_has_controllers(p->connmgr);
}

/* Adds some memory usage statistics for 'ofproto' into 'usage', for use with
 * memory_report(). */
void
ofproto_get_memory_usage(const struct ofproto *ofproto, struct simap *usage)
{
    const struct oftable *table;
    unsigned int n_rules;

    simap_increase(usage, "ports", hmap_count(&ofproto->ports));

    ovs_mutex_lock(&ofproto_mutex);
    simap_increase(usage, "ops",
                   ofproto->n_pending + hmap_count(&ofproto->deletions));
    ovs_mutex_unlock(&ofproto_mutex);

    n_rules = 0;
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        fat_rwlock_rdlock(&table->cls.rwlock);
        n_rules += classifier_count(&table->cls);
        fat_rwlock_unlock(&table->cls.rwlock);
    }
    simap_increase(usage, "rules", n_rules);

    if (ofproto->ofproto_class->get_memory_usage) {
        ofproto->ofproto_class->get_memory_usage(ofproto, usage);
    }

    connmgr_get_memory_usage(ofproto->connmgr, usage);
}

void
ofproto_type_get_memory_usage(const char *datapath_type, struct simap *usage)
{
    const struct ofproto_class *class;

    datapath_type = ofproto_normalize_type(datapath_type);
    class = ofproto_class_find__(datapath_type);

    if (class && class->type_get_memory_usage) {
        class->type_get_memory_usage(datapath_type, usage);
    }
}

void
ofproto_get_ofproto_controller_info(const struct ofproto *ofproto,
                                    struct shash *info)
{
    connmgr_get_controller_info(ofproto->connmgr, info);
}

void
ofproto_free_ofproto_controller_info(struct shash *info)
{
    connmgr_free_controller_info(info);
}

/* Makes a deep copy of 'old' into 'port'. */
void
ofproto_port_clone(struct ofproto_port *port, const struct ofproto_port *old)
{
    port->name = xstrdup(old->name);
    port->type = xstrdup(old->type);
    port->ofp_port = old->ofp_port;
}

/* Frees memory allocated to members of 'ofproto_port'.
 *
 * Do not call this function on an ofproto_port obtained from
 * ofproto_port_dump_next(): that function retains ownership of the data in the
 * ofproto_port. */
void
ofproto_port_destroy(struct ofproto_port *ofproto_port)
{
    free(ofproto_port->name);
    free(ofproto_port->type);
}

/* Initializes 'dump' to begin dumping the ports in an ofproto.
 *
 * This function provides no status indication.  An error status for the entire
 * dump operation is provided when it is completed by calling
 * ofproto_port_dump_done().
 */
void
ofproto_port_dump_start(struct ofproto_port_dump *dump,
                        const struct ofproto *ofproto)
{
    dump->ofproto = ofproto;
    dump->error = ofproto->ofproto_class->port_dump_start(ofproto,
                                                          &dump->state);
}

/* Attempts to retrieve another port from 'dump', which must have been created
 * with ofproto_port_dump_start().  On success, stores a new ofproto_port into
 * 'port' and returns true.  On failure, returns false.
 *
 * Failure might indicate an actual error or merely that the last port has been
 * dumped.  An error status for the entire dump operation is provided when it
 * is completed by calling ofproto_port_dump_done().
 *
 * The ofproto owns the data stored in 'port'.  It will remain valid until at
 * least the next time 'dump' is passed to ofproto_port_dump_next() or
 * ofproto_port_dump_done(). */
bool
ofproto_port_dump_next(struct ofproto_port_dump *dump,
                       struct ofproto_port *port)
{
    const struct ofproto *ofproto = dump->ofproto;

    if (dump->error) {
        return false;
    }

    dump->error = ofproto->ofproto_class->port_dump_next(ofproto, dump->state,
                                                         port);
    if (dump->error) {
        ofproto->ofproto_class->port_dump_done(ofproto, dump->state);
        return false;
    }
    return true;
}

/* Completes port table dump operation 'dump', which must have been created
 * with ofproto_port_dump_start().  Returns 0 if the dump operation was
 * error-free, otherwise a positive errno value describing the problem. */
int
ofproto_port_dump_done(struct ofproto_port_dump *dump)
{
    const struct ofproto *ofproto = dump->ofproto;
    if (!dump->error) {
        dump->error = ofproto->ofproto_class->port_dump_done(ofproto,
                                                             dump->state);
    }
    return dump->error == EOF ? 0 : dump->error;
}

/* Returns the type to pass to netdev_open() when a datapath of type
 * 'datapath_type' has a port of type 'port_type', for a few special
 * cases when a netdev type differs from a port type.  For example, when
 * using the userspace datapath, a port of type "internal" needs to be
 * opened as "tap".
 *
 * Returns either 'type' itself or a string literal, which must not be
 * freed. */
const char *
ofproto_port_open_type(const char *datapath_type, const char *port_type)
{
    const struct ofproto_class *class;

    datapath_type = ofproto_normalize_type(datapath_type);
    class = ofproto_class_find__(datapath_type);
    if (!class) {
        return port_type;
    }

    return (class->port_open_type
            ? class->port_open_type(datapath_type, port_type)
            : port_type);
}

/* Attempts to add 'netdev' as a port on 'ofproto'.  If 'ofp_portp' is
 * non-null and '*ofp_portp' is not OFPP_NONE, attempts to use that as
 * the port's OpenFlow port number.
 *
 * If successful, returns 0 and sets '*ofp_portp' to the new port's
 * OpenFlow port number (if 'ofp_portp' is non-null).  On failure,
 * returns a positive errno value and sets '*ofp_portp' to OFPP_NONE (if
 * 'ofp_portp' is non-null). */
int
ofproto_port_add(struct ofproto *ofproto, struct netdev *netdev,
                 ofp_port_t *ofp_portp)
{
    ofp_port_t ofp_port = ofp_portp ? *ofp_portp : OFPP_NONE;
    int error;

    error = ofproto->ofproto_class->port_add(ofproto, netdev);
    if (!error) {
        const char *netdev_name = netdev_get_name(netdev);

        simap_put(&ofproto->ofp_requests, netdev_name,
                  ofp_to_u16(ofp_port));
        update_port(ofproto, netdev_name);
    }
    if (ofp_portp) {
        *ofp_portp = OFPP_NONE;
        if (!error) {
            struct ofproto_port ofproto_port;

            error = ofproto_port_query_by_name(ofproto,
                                               netdev_get_name(netdev),
                                               &ofproto_port);
            if (!error) {
                *ofp_portp = ofproto_port.ofp_port;
                ofproto_port_destroy(&ofproto_port);
            }
        }
    }
    return error;
}

/* Looks up a port named 'devname' in 'ofproto'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * The caller owns the data in 'ofproto_port' and must free it with
 * ofproto_port_destroy() when it is no longer needed. */
int
ofproto_port_query_by_name(const struct ofproto *ofproto, const char *devname,
                           struct ofproto_port *port)
{
    int error;

    error = ofproto->ofproto_class->port_query_by_name(ofproto, devname, port);
    if (error) {
        memset(port, 0, sizeof *port);
    }
    return error;
}

/* Deletes port number 'ofp_port' from the datapath for 'ofproto'.
 * Returns 0 if successful, otherwise a positive errno. */
int
ofproto_port_del(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    const char *name = ofport ? netdev_get_name(ofport->netdev) : "<unknown>";
    struct simap_node *ofp_request_node;
    int error;

    ofp_request_node = simap_find(&ofproto->ofp_requests, name);
    if (ofp_request_node) {
        simap_delete(&ofproto->ofp_requests, ofp_request_node);
    }

    error = ofproto->ofproto_class->port_del(ofproto, ofp_port);
    if (!error && ofport) {
        /* 'name' is the netdev's name and update_port() is going to close the
         * netdev.  Just in case update_port() refers to 'name' after it
         * destroys 'ofport', make a copy of it around the update_port()
         * call. */
        char *devname = xstrdup(name);
        update_port(ofproto, devname);
        free(devname);
    }
    return error;
}

static void
flow_mod_init(struct ofputil_flow_mod *fm,
              const struct match *match, unsigned int priority,
              const struct ofpact *ofpacts, size_t ofpacts_len,
              enum ofp_flow_mod_command command)
{
    memset(fm, 0, sizeof *fm);
    fm->match = *match;
    fm->priority = priority;
    fm->cookie = 0;
    fm->new_cookie = 0;
    fm->modify_cookie = false;
    fm->table_id = 0;
    fm->command = command;
    fm->idle_timeout = 0;
    fm->hard_timeout = 0;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_ANY;
    fm->out_group = OFPG_ANY;
    fm->flags = 0;
    fm->ofpacts = CONST_CAST(struct ofpact *, ofpacts);
    fm->ofpacts_len = ofpacts_len;
}

static int
simple_flow_mod(struct ofproto *ofproto,
                const struct match *match, unsigned int priority,
                const struct ofpact *ofpacts, size_t ofpacts_len,
                enum ofp_flow_mod_command command)
{
    struct ofputil_flow_mod fm;

    flow_mod_init(&fm, match, priority, ofpacts, ofpacts_len, command);

    return handle_flow_mod__(ofproto, NULL, &fm, NULL);
}

/* Adds a flow to OpenFlow flow table 0 in 'p' that matches 'cls_rule' and
 * performs the 'n_actions' actions in 'actions'.  The new flow will not
 * timeout.
 *
 * If cls_rule->priority is in the range of priorities supported by OpenFlow
 * (0...65535, inclusive) then the flow will be visible to OpenFlow
 * controllers; otherwise, it will be hidden.
 *
 * The caller retains ownership of 'cls_rule' and 'ofpacts'.
 *
 * This is a helper function for in-band control and fail-open. */
void
ofproto_add_flow(struct ofproto *ofproto, const struct match *match,
                 unsigned int priority,
                 const struct ofpact *ofpacts, size_t ofpacts_len)
    OVS_EXCLUDED(ofproto_mutex)
{
    const struct rule *rule;
    bool must_add;

    /* First do a cheap check whether the rule we're looking for already exists
     * with the actions that we want.  If it does, then we're done. */
    fat_rwlock_rdlock(&ofproto->tables[0].cls.rwlock);
    rule = rule_from_cls_rule(classifier_find_match_exactly(
                                  &ofproto->tables[0].cls, match, priority));
    if (rule) {
        ovs_mutex_lock(&rule->mutex);
        must_add = !ofpacts_equal(rule->actions->ofpacts,
                                  rule->actions->ofpacts_len,
                                  ofpacts, ofpacts_len);
        ovs_mutex_unlock(&rule->mutex);
    } else {
        must_add = true;
    }
    fat_rwlock_unlock(&ofproto->tables[0].cls.rwlock);

    /* If there's no such rule or the rule doesn't have the actions we want,
     * fall back to a executing a full flow mod.  We can't optimize this at
     * all because we didn't take enough locks above to ensure that the flow
     * table didn't already change beneath us.  */
    if (must_add) {
        simple_flow_mod(ofproto, match, priority, ofpacts, ofpacts_len,
                        OFPFC_MODIFY_STRICT);
    }
}

/* Executes the flow modification specified in 'fm'.  Returns 0 on success, an
 * OFPERR_* OpenFlow error code on failure, or OFPROTO_POSTPONE if the
 * operation cannot be initiated now but may be retried later.
 *
 * This is a helper function for in-band control and fail-open and the "learn"
 * action. */
int
ofproto_flow_mod(struct ofproto *ofproto, struct ofputil_flow_mod *fm)
    OVS_EXCLUDED(ofproto_mutex)
{
    return handle_flow_mod__(ofproto, NULL, fm, NULL);
}

/* Searches for a rule with matching criteria exactly equal to 'target' in
 * ofproto's table 0 and, if it finds one, deletes it.
 *
 * This is a helper function for in-band control and fail-open. */
bool
ofproto_delete_flow(struct ofproto *ofproto,
                    const struct match *target, unsigned int priority)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct classifier *cls = &ofproto->tables[0].cls;
    struct rule *rule;

    /* First do a cheap check whether the rule we're looking for has already
     * been deleted.  If so, then we're done. */
    fat_rwlock_rdlock(&cls->rwlock);
    rule = rule_from_cls_rule(classifier_find_match_exactly(cls, target,
                                                            priority));
    fat_rwlock_unlock(&cls->rwlock);
    if (!rule) {
        return true;
    }

    /* Fall back to a executing a full flow mod.  We can't optimize this at all
     * because we didn't take enough locks above to ensure that the flow table
     * didn't already change beneath us.  */
    return simple_flow_mod(ofproto, target, priority, NULL, 0,
                           OFPFC_DELETE_STRICT) != OFPROTO_POSTPONE;
}

/* Starts the process of deleting all of the flows from all of ofproto's flow
 * tables and then reintroducing the flows required by in-band control and
 * fail-open.  The process will complete in a later call to ofproto_run(). */
void
ofproto_flush_flows(struct ofproto *ofproto)
{
    COVERAGE_INC(ofproto_flush);
    ofproto->state = S_FLUSH;
}

static void
reinit_ports(struct ofproto *p)
{
    struct ofproto_port_dump dump;
    struct sset devnames;
    struct ofport *ofport;
    struct ofproto_port ofproto_port;
    const char *devname;

    COVERAGE_INC(ofproto_reinit_ports);

    sset_init(&devnames);
    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        sset_add(&devnames, netdev_get_name(ofport->netdev));
    }
    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, p) {
        sset_add(&devnames, ofproto_port.name);
    }

    SSET_FOR_EACH (devname, &devnames) {
        update_port(p, devname);
    }
    sset_destroy(&devnames);
}

static ofp_port_t
alloc_ofp_port(struct ofproto *ofproto, const char *netdev_name)
{
    uint16_t port_idx;

    port_idx = simap_get(&ofproto->ofp_requests, netdev_name);
    port_idx = port_idx ? port_idx : UINT16_MAX;

    if (port_idx >= ofproto->max_ports
        || ofport_get_usage(ofproto, u16_to_ofp(port_idx)) == LLONG_MAX) {
        uint16_t lru_ofport = 0, end_port_no = ofproto->alloc_port_no;
        long long int last_used_at, lru = LLONG_MAX;

        /* Search for a free OpenFlow port number.  We try not to
         * immediately reuse them to prevent problems due to old
         * flows.
         *
         * We limit the automatically assigned port numbers to the lower half
         * of the port range, to reserve the upper half for assignment by
         * controllers. */
        for (;;) {
            if (++ofproto->alloc_port_no >= MIN(ofproto->max_ports, 32768)) {
                ofproto->alloc_port_no = 1;
            }
            last_used_at = ofport_get_usage(ofproto,
                                         u16_to_ofp(ofproto->alloc_port_no));
            if (!last_used_at) {
                port_idx = ofproto->alloc_port_no;
                break;
            } else if ( last_used_at < time_msec() - 60*60*1000) {
                /* If the port with ofport 'ofproto->alloc_port_no' was deleted
                 * more than an hour ago, consider it usable. */
                ofport_remove_usage(ofproto,
                    u16_to_ofp(ofproto->alloc_port_no));
                port_idx = ofproto->alloc_port_no;
                break;
            } else if (last_used_at < lru) {
                lru = last_used_at;
                lru_ofport = ofproto->alloc_port_no;
            }

            if (ofproto->alloc_port_no == end_port_no) {
                if (lru_ofport) {
                    port_idx = lru_ofport;
                    break;
                }
                return OFPP_NONE;
            }
        }
    }
    ofport_set_usage(ofproto, u16_to_ofp(port_idx), LLONG_MAX);
    return u16_to_ofp(port_idx);
}

static void
dealloc_ofp_port(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    if (ofp_to_u16(ofp_port) < ofproto->max_ports) {
        ofport_set_usage(ofproto, ofp_port, time_msec());
    }
}

/* Opens and returns a netdev for 'ofproto_port' in 'ofproto', or a null
 * pointer if the netdev cannot be opened.  On success, also fills in
 * 'opp'.  */
static struct netdev *
ofport_open(struct ofproto *ofproto,
            struct ofproto_port *ofproto_port,
            struct ofputil_phy_port *pp)
{
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    error = netdev_open(ofproto_port->name, ofproto_port->type, &netdev);
    if (error) {
        VLOG_WARN_RL(&rl, "%s: ignoring port %s (%"PRIu16") because netdev %s "
                     "cannot be opened (%s)",
                     ofproto->name,
                     ofproto_port->name, ofproto_port->ofp_port,
                     ofproto_port->name, ovs_strerror(error));
        return NULL;
    }

    if (ofproto_port->ofp_port == OFPP_NONE) {
        if (!strcmp(ofproto->name, ofproto_port->name)) {
            ofproto_port->ofp_port = OFPP_LOCAL;
        } else {
            ofproto_port->ofp_port = alloc_ofp_port(ofproto,
                                                    ofproto_port->name);
        }
    }
    pp->port_no = ofproto_port->ofp_port;
    netdev_get_etheraddr(netdev, pp->hw_addr);
    ovs_strlcpy(pp->name, ofproto_port->name, sizeof pp->name);
    netdev_get_flags(netdev, &flags);
    pp->config = flags & NETDEV_UP ? 0 : OFPUTIL_PC_PORT_DOWN;
    pp->state = netdev_get_carrier(netdev) ? 0 : OFPUTIL_PS_LINK_DOWN;
    netdev_get_features(netdev, &pp->curr, &pp->advertised,
                        &pp->supported, &pp->peer);
    pp->curr_speed = netdev_features_to_bps(pp->curr, 0) / 1000;
    pp->max_speed = netdev_features_to_bps(pp->supported, 0) / 1000;

    return netdev;
}

/* Returns true if most fields of 'a' and 'b' are equal.  Differences in name,
 * port number, and 'config' bits other than OFPUTIL_PS_LINK_DOWN are
 * disregarded. */
static bool
ofport_equal(const struct ofputil_phy_port *a,
             const struct ofputil_phy_port *b)
{
    return (eth_addr_equals(a->hw_addr, b->hw_addr)
            && a->state == b->state
            && !((a->config ^ b->config) & OFPUTIL_PC_PORT_DOWN)
            && a->curr == b->curr
            && a->advertised == b->advertised
            && a->supported == b->supported
            && a->peer == b->peer
            && a->curr_speed == b->curr_speed
            && a->max_speed == b->max_speed);
}

/* Adds an ofport to 'p' initialized based on the given 'netdev' and 'opp'.
 * The caller must ensure that 'p' does not have a conflicting ofport (that is,
 * one with the same name or port number). */
static void
ofport_install(struct ofproto *p,
               struct netdev *netdev, const struct ofputil_phy_port *pp)
{
    const char *netdev_name = netdev_get_name(netdev);
    struct ofport *ofport;
    int error;

    /* Create ofport. */
    ofport = p->ofproto_class->port_alloc();
    if (!ofport) {
        error = ENOMEM;
        goto error;
    }
    ofport->ofproto = p;
    ofport->netdev = netdev;
    ofport->pp = *pp;
    ofport->ofp_port = pp->port_no;
    ofport->created = time_msec();

    /* Add port to 'p'. */
    hmap_insert(&p->ports, &ofport->hmap_node,
                hash_ofp_port(ofport->ofp_port));
    shash_add(&p->port_by_name, netdev_name, ofport);

    update_mtu(p, ofport);

    /* Let the ofproto_class initialize its private data. */
    error = p->ofproto_class->port_construct(ofport);
    if (error) {
        goto error;
    }
    connmgr_send_port_status(p->connmgr, pp, OFPPR_ADD);
    return;

error:
    VLOG_WARN_RL(&rl, "%s: could not add port %s (%s)",
                 p->name, netdev_name, ovs_strerror(error));
    if (ofport) {
        ofport_destroy__(ofport);
    } else {
        netdev_close(netdev);
    }
}

/* Removes 'ofport' from 'p' and destroys it. */
static void
ofport_remove(struct ofport *ofport)
{
    connmgr_send_port_status(ofport->ofproto->connmgr, &ofport->pp,
                             OFPPR_DELETE);
    ofport_destroy(ofport);
}

/* If 'ofproto' contains an ofport named 'name', removes it from 'ofproto' and
 * destroys it. */
static void
ofport_remove_with_name(struct ofproto *ofproto, const char *name)
{
    struct ofport *port = shash_find_data(&ofproto->port_by_name, name);
    if (port) {
        ofport_remove(port);
    }
}

/* Updates 'port' with new 'pp' description.
 *
 * Does not handle a name or port number change.  The caller must implement
 * such a change as a delete followed by an add.  */
static void
ofport_modified(struct ofport *port, struct ofputil_phy_port *pp)
{
    memcpy(port->pp.hw_addr, pp->hw_addr, ETH_ADDR_LEN);
    port->pp.config = ((port->pp.config & ~OFPUTIL_PC_PORT_DOWN)
                        | (pp->config & OFPUTIL_PC_PORT_DOWN));
    port->pp.state = ((port->pp.state & ~OFPUTIL_PS_LINK_DOWN)
                      | (pp->state & OFPUTIL_PS_LINK_DOWN));
    port->pp.curr = pp->curr;
    port->pp.advertised = pp->advertised;
    port->pp.supported = pp->supported;
    port->pp.peer = pp->peer;
    port->pp.curr_speed = pp->curr_speed;
    port->pp.max_speed = pp->max_speed;

    connmgr_send_port_status(port->ofproto->connmgr, &port->pp, OFPPR_MODIFY);
}

/* Update OpenFlow 'state' in 'port' and notify controller. */
void
ofproto_port_set_state(struct ofport *port, enum ofputil_port_state state)
{
    if (port->pp.state != state) {
        port->pp.state = state;
        connmgr_send_port_status(port->ofproto->connmgr, &port->pp,
                                 OFPPR_MODIFY);
    }
}

void
ofproto_port_unregister(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *port = ofproto_get_port(ofproto, ofp_port);
    if (port) {
        if (port->ofproto->ofproto_class->set_realdev) {
            port->ofproto->ofproto_class->set_realdev(port, 0, 0);
        }
        if (port->ofproto->ofproto_class->set_stp_port) {
            port->ofproto->ofproto_class->set_stp_port(port, NULL);
        }
        if (port->ofproto->ofproto_class->set_cfm) {
            port->ofproto->ofproto_class->set_cfm(port, NULL);
        }
        if (port->ofproto->ofproto_class->bundle_remove) {
            port->ofproto->ofproto_class->bundle_remove(port);
        }
    }
}

static void
ofport_destroy__(struct ofport *port)
{
    struct ofproto *ofproto = port->ofproto;
    const char *name = netdev_get_name(port->netdev);

    hmap_remove(&ofproto->ports, &port->hmap_node);
    shash_delete(&ofproto->port_by_name,
                 shash_find(&ofproto->port_by_name, name));

    netdev_close(port->netdev);
    ofproto->ofproto_class->port_dealloc(port);
}

static void
ofport_destroy(struct ofport *port)
{
    if (port) {
        dealloc_ofp_port(port->ofproto, port->ofp_port);
        port->ofproto->ofproto_class->port_destruct(port);
        ofport_destroy__(port);
     }
}

struct ofport *
ofproto_get_port(const struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *port;

    HMAP_FOR_EACH_IN_BUCKET (port, hmap_node, hash_ofp_port(ofp_port),
                             &ofproto->ports) {
        if (port->ofp_port == ofp_port) {
            return port;
        }
    }
    return NULL;
}

static long long int
ofport_get_usage(const struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport_usage *usage;

    HMAP_FOR_EACH_IN_BUCKET (usage, hmap_node, hash_ofp_port(ofp_port),
                             &ofproto->ofport_usage) {
        if (usage->ofp_port == ofp_port) {
            return usage->last_used;
        }
    }
    return 0;
}

static void
ofport_set_usage(struct ofproto *ofproto, ofp_port_t ofp_port,
                 long long int last_used)
{
    struct ofport_usage *usage;
    HMAP_FOR_EACH_IN_BUCKET (usage, hmap_node, hash_ofp_port(ofp_port),
                             &ofproto->ofport_usage) {
        if (usage->ofp_port == ofp_port) {
            usage->last_used = last_used;
            return;
        }
    }
    ovs_assert(last_used == LLONG_MAX);

    usage = xmalloc(sizeof *usage);
    usage->ofp_port = ofp_port;
    usage->last_used = last_used;
    hmap_insert(&ofproto->ofport_usage, &usage->hmap_node,
                hash_ofp_port(ofp_port));
}

static void
ofport_remove_usage(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport_usage *usage;
    HMAP_FOR_EACH_IN_BUCKET (usage, hmap_node, hash_ofp_port(ofp_port),
                             &ofproto->ofport_usage) {
        if (usage->ofp_port == ofp_port) {
            hmap_remove(&ofproto->ofport_usage, &usage->hmap_node);
            free(usage);
            break;
        }
    }
}

int
ofproto_port_get_stats(const struct ofport *port, struct netdev_stats *stats)
{
    struct ofproto *ofproto = port->ofproto;
    int error;

    if (ofproto->ofproto_class->port_get_stats) {
        error = ofproto->ofproto_class->port_get_stats(port, stats);
    } else {
        error = EOPNOTSUPP;
    }

    return error;
}

static void
update_port(struct ofproto *ofproto, const char *name)
{
    struct ofproto_port ofproto_port;
    struct ofputil_phy_port pp;
    struct netdev *netdev;
    struct ofport *port;

    COVERAGE_INC(ofproto_update_port);

    /* Fetch 'name''s location and properties from the datapath. */
    netdev = (!ofproto_port_query_by_name(ofproto, name, &ofproto_port)
              ? ofport_open(ofproto, &ofproto_port, &pp)
              : NULL);

    if (netdev) {
        port = ofproto_get_port(ofproto, ofproto_port.ofp_port);
        if (port && !strcmp(netdev_get_name(port->netdev), name)) {
            struct netdev *old_netdev = port->netdev;

            /* 'name' hasn't changed location.  Any properties changed? */
            if (!ofport_equal(&port->pp, &pp)) {
                ofport_modified(port, &pp);
            }

            update_mtu(ofproto, port);

            /* Install the newly opened netdev in case it has changed.
             * Don't close the old netdev yet in case port_modified has to
             * remove a retained reference to it.*/
            port->netdev = netdev;

            if (port->ofproto->ofproto_class->port_modified) {
                port->ofproto->ofproto_class->port_modified(port);
            }

            netdev_close(old_netdev);
        } else {
            /* If 'port' is nonnull then its name differs from 'name' and thus
             * we should delete it.  If we think there's a port named 'name'
             * then its port number must be wrong now so delete it too. */
            if (port) {
                ofport_remove(port);
            }
            ofport_remove_with_name(ofproto, name);
            ofport_install(ofproto, netdev, &pp);
        }
    } else {
        /* Any port named 'name' is gone now. */
        ofport_remove_with_name(ofproto, name);
    }
    ofproto_port_destroy(&ofproto_port);
}

static int
init_ports(struct ofproto *p)
{
    struct ofproto_port_dump dump;
    struct ofproto_port ofproto_port;
    struct shash_node *node, *next;

    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, p) {
        const char *name = ofproto_port.name;

        if (shash_find(&p->port_by_name, name)) {
            VLOG_WARN_RL(&rl, "%s: ignoring duplicate device %s in datapath",
                         p->name, name);
        } else {
            struct ofputil_phy_port pp;
            struct netdev *netdev;

            /* Check if an OpenFlow port number had been requested. */
            node = shash_find(&init_ofp_ports, name);
            if (node) {
                const struct iface_hint *iface_hint = node->data;
                simap_put(&p->ofp_requests, name,
                          ofp_to_u16(iface_hint->ofp_port));
            }

            netdev = ofport_open(p, &ofproto_port, &pp);
            if (netdev) {
                ofport_install(p, netdev, &pp);
                if (ofp_to_u16(ofproto_port.ofp_port) < p->max_ports) {
                    p->alloc_port_no = MAX(p->alloc_port_no,
                                           ofp_to_u16(ofproto_port.ofp_port));
                }
            }
        }
    }

    SHASH_FOR_EACH_SAFE(node, next, &init_ofp_ports) {
        struct iface_hint *iface_hint = node->data;

        if (!strcmp(iface_hint->br_name, p->name)) {
            free(iface_hint->br_name);
            free(iface_hint->br_type);
            free(iface_hint);
            shash_delete(&init_ofp_ports, node);
        }
    }

    return 0;
}

/* Find the minimum MTU of all non-datapath devices attached to 'p'.
 * Returns ETH_PAYLOAD_MAX or the minimum of the ports. */
static int
find_min_mtu(struct ofproto *p)
{
    struct ofport *ofport;
    int mtu = 0;

    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        struct netdev *netdev = ofport->netdev;
        int dev_mtu;

        /* Skip any internal ports, since that's what we're trying to
         * set. */
        if (!strcmp(netdev_get_type(netdev), "internal")) {
            continue;
        }

        if (netdev_get_mtu(netdev, &dev_mtu)) {
            continue;
        }
        if (!mtu || dev_mtu < mtu) {
            mtu = dev_mtu;
        }
    }

    return mtu ? mtu: ETH_PAYLOAD_MAX;
}

/* Update MTU of all datapath devices on 'p' to the minimum of the
 * non-datapath ports in event of 'port' added or changed. */
static void
update_mtu(struct ofproto *p, struct ofport *port)
{
    struct ofport *ofport;
    struct netdev *netdev = port->netdev;
    int dev_mtu, old_min;

    if (netdev_get_mtu(netdev, &dev_mtu)) {
        port->mtu = 0;
        return;
    }
    if (!strcmp(netdev_get_type(port->netdev), "internal")) {
        if (dev_mtu > p->min_mtu) {
           if (!netdev_set_mtu(port->netdev, p->min_mtu)) {
               dev_mtu = p->min_mtu;
           }
        }
        port->mtu = dev_mtu;
        return;
    }

    /* For non-internal port find new min mtu. */
    old_min = p->min_mtu;
    port->mtu = dev_mtu;
    p->min_mtu = find_min_mtu(p);
    if (p->min_mtu == old_min) {
        return;
    }

    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        struct netdev *netdev = ofport->netdev;

        if (!strcmp(netdev_get_type(netdev), "internal")) {
            if (!netdev_set_mtu(netdev, p->min_mtu)) {
                ofport->mtu = p->min_mtu;
            }
        }
    }
}

void
ofproto_rule_ref(struct rule *rule)
{
    if (rule) {
        unsigned int orig;

        atomic_add(&rule->ref_count, 1, &orig);
        ovs_assert(orig != 0);
    }
}

void
ofproto_rule_unref(struct rule *rule)
{
    if (rule) {
        unsigned int orig;

        atomic_sub(&rule->ref_count, 1, &orig);
        if (orig == 1) {
            rule->ofproto->ofproto_class->rule_destruct(rule);
            ofproto_rule_destroy__(rule);
        } else {
            ovs_assert(orig != 0);
        }
    }
}

struct rule_actions *
rule_get_actions(const struct rule *rule)
    OVS_EXCLUDED(rule->mutex)
{
    struct rule_actions *actions;

    ovs_mutex_lock(&rule->mutex);
    actions = rule_get_actions__(rule);
    ovs_mutex_unlock(&rule->mutex);

    return actions;
}

struct rule_actions *
rule_get_actions__(const struct rule *rule)
    OVS_REQUIRES(rule->mutex)
{
    rule_actions_ref(rule->actions);
    return rule->actions;
}

static void
ofproto_rule_destroy__(struct rule *rule)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    cls_rule_destroy(CONST_CAST(struct cls_rule *, &rule->cr));
    rule_actions_unref(rule->actions);
    ovs_mutex_destroy(&rule->mutex);
    rule->ofproto->ofproto_class->rule_dealloc(rule);
}

static uint32_t get_provider_meter_id(const struct ofproto *,
                                      uint32_t of_meter_id);

/* Creates and returns a new 'struct rule_actions', with a ref_count of 1,
 * whose actions are a copy of from the 'ofpacts_len' bytes of 'ofpacts'. */
struct rule_actions *
rule_actions_create(const struct ofproto *ofproto,
                    const struct ofpact *ofpacts, size_t ofpacts_len)
{
    struct rule_actions *actions;

    actions = xmalloc(sizeof *actions);
    atomic_init(&actions->ref_count, 1);
    actions->ofpacts = xmemdup(ofpacts, ofpacts_len);
    actions->ofpacts_len = ofpacts_len;
    actions->provider_meter_id
        = get_provider_meter_id(ofproto,
                                ofpacts_get_meter(ofpacts, ofpacts_len));

    return actions;
}

/* Increments 'actions''s ref_count. */
void
rule_actions_ref(struct rule_actions *actions)
{
    if (actions) {
        unsigned int orig;

        atomic_add(&actions->ref_count, 1, &orig);
        ovs_assert(orig != 0);
    }
}

/* Decrements 'actions''s ref_count and frees 'actions' if the ref_count
 * reaches 0. */
void
rule_actions_unref(struct rule_actions *actions)
{
    if (actions) {
        unsigned int orig;

        atomic_sub(&actions->ref_count, 1, &orig);
        if (orig == 1) {
            free(actions->ofpacts);
            free(actions);
        } else {
            ovs_assert(orig != 0);
        }
    }
}

/* Returns true if 'rule' has an OpenFlow OFPAT_OUTPUT or OFPAT_ENQUEUE action
 * that outputs to 'port' (output to OFPP_FLOOD and OFPP_ALL doesn't count). */
static bool
ofproto_rule_has_out_port(const struct rule *rule, ofp_port_t port)
    OVS_REQUIRES(ofproto_mutex)
{
    return (port == OFPP_ANY
            || ofpacts_output_to_port(rule->actions->ofpacts,
                                      rule->actions->ofpacts_len, port));
}

/* Returns true if 'rule' has group and equals group_id. */
static bool
ofproto_rule_has_out_group(const struct rule *rule, uint32_t group_id)
    OVS_REQUIRES(ofproto_mutex)
{
    return (group_id == OFPG11_ANY
            || ofpacts_output_to_group(rule->actions->ofpacts,
                                       rule->actions->ofpacts_len, group_id));
}

/* Returns true if a rule related to 'op' has an OpenFlow OFPAT_OUTPUT or
 * OFPAT_ENQUEUE action that outputs to 'out_port'. */
bool
ofoperation_has_out_port(const struct ofoperation *op, ofp_port_t out_port)
    OVS_REQUIRES(ofproto_mutex)
{
    if (ofproto_rule_has_out_port(op->rule, out_port)) {
        return true;
    }

    switch (op->type) {
    case OFOPERATION_ADD:
    case OFOPERATION_DELETE:
        return false;

    case OFOPERATION_MODIFY:
    case OFOPERATION_REPLACE:
        return ofpacts_output_to_port(op->actions->ofpacts,
                                      op->actions->ofpacts_len, out_port);
    }

    OVS_NOT_REACHED();
}

static void
rule_execute_destroy(struct rule_execute *e)
{
    ofproto_rule_unref(e->rule);
    list_remove(&e->list_node);
    free(e);
}

/* Executes all "rule_execute" operations queued up in ofproto->rule_executes,
 * by passing them to the ofproto provider. */
static void
run_rule_executes(struct ofproto *ofproto)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct rule_execute *e, *next;
    struct list executes;

    guarded_list_pop_all(&ofproto->rule_executes, &executes);
    LIST_FOR_EACH_SAFE (e, next, list_node, &executes) {
        union flow_in_port in_port_;
        struct flow flow;

        in_port_.ofp_port = e->in_port;
        flow_extract(e->packet, 0, 0, NULL, &in_port_, &flow);
        ofproto->ofproto_class->rule_execute(e->rule, &flow, e->packet);

        rule_execute_destroy(e);
    }
}

/* Destroys and discards all "rule_execute" operations queued up in
 * ofproto->rule_executes. */
static void
destroy_rule_executes(struct ofproto *ofproto)
{
    struct rule_execute *e, *next;
    struct list executes;

    guarded_list_pop_all(&ofproto->rule_executes, &executes);
    LIST_FOR_EACH_SAFE (e, next, list_node, &executes) {
        ofpbuf_delete(e->packet);
        rule_execute_destroy(e);
    }
}

/* Returns true if 'rule' should be hidden from the controller.
 *
 * Rules with priority higher than UINT16_MAX are set up by ofproto itself
 * (e.g. by in-band control) and are intentionally hidden from the
 * controller. */
static bool
ofproto_rule_is_hidden(const struct rule *rule)
{
    return rule->cr.priority > UINT16_MAX;
}

static enum oftable_flags
rule_get_flags(const struct rule *rule)
{
    return rule->ofproto->tables[rule->table_id].flags;
}

static bool
rule_is_modifiable(const struct rule *rule)
{
    return !(rule_get_flags(rule) & OFTABLE_READONLY);
}

static enum ofperr
handle_echo_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    ofconn_send_reply(ofconn, make_echo_reply(oh));
    return 0;
}

static enum ofperr
handle_features_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_switch_features features;
    struct ofport *port;
    bool arp_match_ip;
    struct ofpbuf *b;
    int n_tables;
    int i;

    ofproto->ofproto_class->get_features(ofproto, &arp_match_ip,
                                         &features.actions);
    ovs_assert(features.actions & OFPUTIL_A_OUTPUT); /* sanity check */

    /* Count only non-hidden tables in the number of tables.  (Hidden tables,
     * if present, are always at the end.) */
    n_tables = ofproto->n_tables;
    for (i = 0; i < ofproto->n_tables; i++) {
        if (ofproto->tables[i].flags & OFTABLE_HIDDEN) {
            n_tables = i;
            break;
        }
    }

    features.datapath_id = ofproto->datapath_id;
    features.n_buffers = pktbuf_capacity();
    features.n_tables = n_tables;
    features.capabilities = (OFPUTIL_C_FLOW_STATS | OFPUTIL_C_TABLE_STATS |
                             OFPUTIL_C_PORT_STATS | OFPUTIL_C_QUEUE_STATS);
    if (arp_match_ip) {
        features.capabilities |= OFPUTIL_C_ARP_MATCH_IP;
    }
    /* FIXME: Fill in proper features.auxiliary_id for auxiliary connections */
    features.auxiliary_id = 0;
    b = ofputil_encode_switch_features(&features, ofconn_get_protocol(ofconn),
                                       oh->xid);
    HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
        ofputil_put_switch_features_port(&port->pp, b);
    }

    ofconn_send_reply(ofconn, b);
    return 0;
}

static enum ofperr
handle_get_config_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofp_switch_config *osc;
    enum ofp_config_flags flags;
    struct ofpbuf *buf;

    /* Send reply. */
    buf = ofpraw_alloc_reply(OFPRAW_OFPT_GET_CONFIG_REPLY, oh, 0);
    osc = ofpbuf_put_uninit(buf, sizeof *osc);
    flags = ofproto->frag_handling;
    /* OFPC_INVALID_TTL_TO_CONTROLLER is deprecated in OF 1.3 */
    if (oh->version < OFP13_VERSION
        && ofconn_get_invalid_ttl_to_controller(ofconn)) {
        flags |= OFPC_INVALID_TTL_TO_CONTROLLER;
    }
    osc->flags = htons(flags);
    osc->miss_send_len = htons(ofconn_get_miss_send_len(ofconn));
    ofconn_send_reply(ofconn, buf);

    return 0;
}

static enum ofperr
handle_set_config(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct ofp_switch_config *osc = ofpmsg_body(oh);
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    uint16_t flags = ntohs(osc->flags);

    if (ofconn_get_type(ofconn) != OFCONN_PRIMARY
        || ofconn_get_role(ofconn) != OFPCR12_ROLE_SLAVE) {
        enum ofp_config_flags cur = ofproto->frag_handling;
        enum ofp_config_flags next = flags & OFPC_FRAG_MASK;

        ovs_assert((cur & OFPC_FRAG_MASK) == cur);
        if (cur != next) {
            if (ofproto->ofproto_class->set_frag_handling(ofproto, next)) {
                ofproto->frag_handling = next;
            } else {
                VLOG_WARN_RL(&rl, "%s: unsupported fragment handling mode %s",
                             ofproto->name,
                             ofputil_frag_handling_to_string(next));
            }
        }
    }
    /* OFPC_INVALID_TTL_TO_CONTROLLER is deprecated in OF 1.3 */
    ofconn_set_invalid_ttl_to_controller(ofconn,
             (oh->version < OFP13_VERSION
              && flags & OFPC_INVALID_TTL_TO_CONTROLLER));

    ofconn_set_miss_send_len(ofconn, ntohs(osc->miss_send_len));

    return 0;
}

/* Checks whether 'ofconn' is a slave controller.  If so, returns an OpenFlow
 * error message code for the caller to propagate upward.  Otherwise, returns
 * 0.
 *
 * The log message mentions 'msg_type'. */
static enum ofperr
reject_slave_controller(struct ofconn *ofconn)
{
    if (ofconn_get_type(ofconn) == OFCONN_PRIMARY
        && ofconn_get_role(ofconn) == OFPCR12_ROLE_SLAVE) {
        return OFPERR_OFPBRC_EPERM;
    } else {
        return 0;
    }
}

/* Checks that the 'ofpacts_len' bytes of action in 'ofpacts' are appropriate
 * for 'ofproto':
 *
 *    - If they use a meter, then 'ofproto' has that meter configured.
 *
 *    - If they use any groups, then 'ofproto' has that group configured.
 *
 * Returns 0 if successful, otherwise an OpenFlow error. */
static enum ofperr
ofproto_check_ofpacts(struct ofproto *ofproto,
                      const struct ofpact ofpacts[], size_t ofpacts_len)
{
    const struct ofpact *a;
    uint32_t mid;

    mid = ofpacts_get_meter(ofpacts, ofpacts_len);
    if (mid && get_provider_meter_id(ofproto, mid) == UINT32_MAX) {
        return OFPERR_OFPMMFC_INVALID_METER;
    }

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        if (a->type == OFPACT_GROUP
            && !ofproto_group_exists(ofproto, ofpact_get_GROUP(a)->group_id)) {
            return OFPERR_OFPBAC_BAD_OUT_GROUP;
        }
    }

    return 0;
}

static enum ofperr
handle_packet_out(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofputil_packet_out po;
    struct ofpbuf *payload;
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts;
    struct flow flow;
    union flow_in_port in_port_;
    enum ofperr error;

    COVERAGE_INC(ofproto_packet_out);

    error = reject_slave_controller(ofconn);
    if (error) {
        goto exit;
    }

    /* Decode message. */
    ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    error = ofputil_decode_packet_out(&po, oh, &ofpacts);
    if (error) {
        goto exit_free_ofpacts;
    }
    if (ofp_to_u16(po.in_port) >= p->max_ports
        && ofp_to_u16(po.in_port) < ofp_to_u16(OFPP_MAX)) {
        error = OFPERR_OFPBRC_BAD_PORT;
        goto exit_free_ofpacts;
    }

    /* Get payload. */
    if (po.buffer_id != UINT32_MAX) {
        error = ofconn_pktbuf_retrieve(ofconn, po.buffer_id, &payload, NULL);
        if (error || !payload) {
            goto exit_free_ofpacts;
        }
    } else {
        /* Ensure that the L3 header is 32-bit aligned. */
        payload = ofpbuf_clone_data_with_headroom(po.packet, po.packet_len, 2);
    }

    /* Verify actions against packet, then send packet if successful. */
    in_port_.ofp_port = po.in_port;
    flow_extract(payload, 0, 0, NULL, &in_port_, &flow);
    error = ofproto_check_ofpacts(p, po.ofpacts, po.ofpacts_len);
    if (!error) {
        error = p->ofproto_class->packet_out(p, payload, &flow,
                                             po.ofpacts, po.ofpacts_len);
    }
    ofpbuf_delete(payload);

exit_free_ofpacts:
    ofpbuf_uninit(&ofpacts);
exit:
    return error;
}

static void
update_port_config(struct ofport *port,
                   enum ofputil_port_config config,
                   enum ofputil_port_config mask)
{
    enum ofputil_port_config old_config = port->pp.config;
    enum ofputil_port_config toggle;

    toggle = (config ^ port->pp.config) & mask;
    if (toggle & OFPUTIL_PC_PORT_DOWN) {
        if (config & OFPUTIL_PC_PORT_DOWN) {
            netdev_turn_flags_off(port->netdev, NETDEV_UP, NULL);
        } else {
            netdev_turn_flags_on(port->netdev, NETDEV_UP, NULL);
        }
        toggle &= ~OFPUTIL_PC_PORT_DOWN;
    }

    port->pp.config ^= toggle;
    if (port->pp.config != old_config) {
        port->ofproto->ofproto_class->port_reconfigured(port, old_config);
    }
}

static enum ofperr
handle_port_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofputil_port_mod pm;
    struct ofport *port;
    enum ofperr error;

    error = reject_slave_controller(ofconn);
    if (error) {
        return error;
    }

    error = ofputil_decode_port_mod(oh, &pm);
    if (error) {
        return error;
    }

    port = ofproto_get_port(p, pm.port_no);
    if (!port) {
        return OFPERR_OFPPMFC_BAD_PORT;
    } else if (!eth_addr_equals(port->pp.hw_addr, pm.hw_addr)) {
        return OFPERR_OFPPMFC_BAD_HW_ADDR;
    } else {
        update_port_config(port, pm.config, pm.mask);
        if (pm.advertise) {
            netdev_set_advertisements(port->netdev, pm.advertise);
        }
    }
    return 0;
}

static enum ofperr
handle_desc_stats_request(struct ofconn *ofconn,
                          const struct ofp_header *request)
{
    static const char *default_mfr_desc = "Nicira, Inc.";
    static const char *default_hw_desc = "Open vSwitch";
    static const char *default_sw_desc = VERSION;
    static const char *default_serial_desc = "None";
    static const char *default_dp_desc = "None";

    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_desc_stats *ods;
    struct ofpbuf *msg;

    msg = ofpraw_alloc_stats_reply(request, 0);
    ods = ofpbuf_put_zeros(msg, sizeof *ods);
    ovs_strlcpy(ods->mfr_desc, p->mfr_desc ? p->mfr_desc : default_mfr_desc,
                sizeof ods->mfr_desc);
    ovs_strlcpy(ods->hw_desc, p->hw_desc ? p->hw_desc : default_hw_desc,
                sizeof ods->hw_desc);
    ovs_strlcpy(ods->sw_desc, p->sw_desc ? p->sw_desc : default_sw_desc,
                sizeof ods->sw_desc);
    ovs_strlcpy(ods->serial_num,
                p->serial_desc ? p->serial_desc : default_serial_desc,
                sizeof ods->serial_num);
    ovs_strlcpy(ods->dp_desc, p->dp_desc ? p->dp_desc : default_dp_desc,
                sizeof ods->dp_desc);
    ofconn_send_reply(ofconn, msg);

    return 0;
}

static enum ofperr
handle_table_stats_request(struct ofconn *ofconn,
                           const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp12_table_stats *ots;
    struct ofpbuf *msg;
    int n_tables;
    size_t i;

    /* Set up default values.
     *
     * ofp12_table_stats is used as a generic structure as
     * it is able to hold all the fields for ofp10_table_stats
     * and ofp11_table_stats (and of course itself).
     */
    ots = xcalloc(p->n_tables, sizeof *ots);
    for (i = 0; i < p->n_tables; i++) {
        ots[i].table_id = i;
        sprintf(ots[i].name, "table%"PRIuSIZE, i);
        ots[i].match = htonll(OFPXMT13_MASK);
        ots[i].wildcards = htonll(OFPXMT13_MASK);
        ots[i].write_actions = htonl(OFPAT11_OUTPUT);
        ots[i].apply_actions = htonl(OFPAT11_OUTPUT);
        ots[i].write_setfields = htonll(OFPXMT13_MASK);
        ots[i].apply_setfields = htonll(OFPXMT13_MASK);
        ots[i].metadata_match = OVS_BE64_MAX;
        ots[i].metadata_write = OVS_BE64_MAX;
        ots[i].instructions = htonl(OFPIT11_ALL);
        ots[i].config = htonl(OFPTC11_TABLE_MISS_MASK);
        ots[i].max_entries = htonl(1000000); /* An arbitrary big number. */
        fat_rwlock_rdlock(&p->tables[i].cls.rwlock);
        ots[i].active_count = htonl(classifier_count(&p->tables[i].cls));
        fat_rwlock_unlock(&p->tables[i].cls.rwlock);
    }

    p->ofproto_class->get_tables(p, ots);

    /* Post-process the tables, dropping hidden tables. */
    n_tables = p->n_tables;
    for (i = 0; i < p->n_tables; i++) {
        const struct oftable *table = &p->tables[i];

        if (table->flags & OFTABLE_HIDDEN) {
            n_tables = i;
            break;
        }

        if (table->name) {
            ovs_strzcpy(ots[i].name, table->name, sizeof ots[i].name);
        }

        if (table->max_flows < ntohl(ots[i].max_entries)) {
            ots[i].max_entries = htonl(table->max_flows);
        }
    }

    msg = ofputil_encode_table_stats_reply(ots, n_tables, request);
    ofconn_send_reply(ofconn, msg);

    free(ots);

    return 0;
}

static void
append_port_stat(struct ofport *port, struct list *replies)
{
    struct ofputil_port_stats ops = { .port_no = port->pp.port_no };

    calc_duration(port->created, time_msec(),
                  &ops.duration_sec, &ops.duration_nsec);

    /* Intentionally ignore return value, since errors will set
     * 'stats' to all-1s, which is correct for OpenFlow, and
     * netdev_get_stats() will log errors. */
    ofproto_port_get_stats(port, &ops.stats);

    ofputil_append_port_stat(replies, &ops);
}

static enum ofperr
handle_port_stats_request(struct ofconn *ofconn,
                          const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofport *port;
    struct list replies;
    ofp_port_t port_no;
    enum ofperr error;

    error = ofputil_decode_port_stats_request(request, &port_no);
    if (error) {
        return error;
    }

    ofpmp_init(&replies, request);
    if (port_no != OFPP_ANY) {
        port = ofproto_get_port(p, port_no);
        if (port) {
            append_port_stat(port, &replies);
        }
    } else {
        HMAP_FOR_EACH (port, hmap_node, &p->ports) {
            append_port_stat(port, &replies);
        }
    }

    ofconn_send_replies(ofconn, &replies);
    return 0;
}

static enum ofperr
handle_port_desc_stats_request(struct ofconn *ofconn,
                               const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    enum ofp_version version;
    struct ofport *port;
    struct list replies;

    ofpmp_init(&replies, request);

    version = ofputil_protocol_to_ofp_version(ofconn_get_protocol(ofconn));
    HMAP_FOR_EACH (port, hmap_node, &p->ports) {
        ofputil_append_port_desc_stats_reply(version, &port->pp, &replies);
    }

    ofconn_send_replies(ofconn, &replies);
    return 0;
}

static uint32_t
hash_cookie(ovs_be64 cookie)
{
    return hash_2words((OVS_FORCE uint64_t)cookie >> 32,
                       (OVS_FORCE uint64_t)cookie);
}

static void
cookies_insert(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    hindex_insert(&ofproto->cookies, &rule->cookie_node,
                  hash_cookie(rule->flow_cookie));
}

static void
cookies_remove(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    hindex_remove(&ofproto->cookies, &rule->cookie_node);
}

static void
ofproto_rule_change_cookie(struct ofproto *ofproto, struct rule *rule,
                           ovs_be64 new_cookie)
    OVS_REQUIRES(ofproto_mutex)
{
    if (new_cookie != rule->flow_cookie) {
        cookies_remove(ofproto, rule);

        ovs_mutex_lock(&rule->mutex);
        rule->flow_cookie = new_cookie;
        ovs_mutex_unlock(&rule->mutex);

        cookies_insert(ofproto, rule);
    }
}

static void
calc_duration(long long int start, long long int now,
              uint32_t *sec, uint32_t *nsec)
{
    long long int msecs = now - start;
    *sec = msecs / 1000;
    *nsec = (msecs % 1000) * (1000 * 1000);
}

/* Checks whether 'table_id' is 0xff or a valid table ID in 'ofproto'.  Returns
 * 0 if 'table_id' is OK, otherwise an OpenFlow error code.  */
static enum ofperr
check_table_id(const struct ofproto *ofproto, uint8_t table_id)
{
    return (table_id == 0xff || table_id < ofproto->n_tables
            ? 0
            : OFPERR_OFPBRC_BAD_TABLE_ID);

}

static struct oftable *
next_visible_table(const struct ofproto *ofproto, uint8_t table_id)
{
    struct oftable *table;

    for (table = &ofproto->tables[table_id];
         table < &ofproto->tables[ofproto->n_tables];
         table++) {
        if (!(table->flags & OFTABLE_HIDDEN)) {
            return table;
        }
    }

    return NULL;
}

static struct oftable *
first_matching_table(const struct ofproto *ofproto, uint8_t table_id)
{
    if (table_id == 0xff) {
        return next_visible_table(ofproto, 0);
    } else if (table_id < ofproto->n_tables) {
        return &ofproto->tables[table_id];
    } else {
        return NULL;
    }
}

static struct oftable *
next_matching_table(const struct ofproto *ofproto,
                    const struct oftable *table, uint8_t table_id)
{
    return (table_id == 0xff
            ? next_visible_table(ofproto, (table - ofproto->tables) + 1)
            : NULL);
}

/* Assigns TABLE to each oftable, in turn, that matches TABLE_ID in OFPROTO:
 *
 *   - If TABLE_ID is 0xff, this iterates over every classifier table in
 *     OFPROTO, skipping tables marked OFTABLE_HIDDEN.
 *
 *   - If TABLE_ID is the number of a table in OFPROTO, then the loop iterates
 *     only once, for that table.  (This can be used to access tables marked
 *     OFTABLE_HIDDEN.)
 *
 *   - Otherwise, TABLE_ID isn't valid for OFPROTO, so the loop won't be
 *     entered at all.  (Perhaps you should have validated TABLE_ID with
 *     check_table_id().)
 *
 * All parameters are evaluated multiple times.
 */
#define FOR_EACH_MATCHING_TABLE(TABLE, TABLE_ID, OFPROTO)         \
    for ((TABLE) = first_matching_table(OFPROTO, TABLE_ID);       \
         (TABLE) != NULL;                                         \
         (TABLE) = next_matching_table(OFPROTO, TABLE, TABLE_ID))

/* Initializes 'criteria' in a straightforward way based on the other
 * parameters.
 *
 * For "loose" matching, the 'priority' parameter is unimportant and may be
 * supplied as 0. */
static void
rule_criteria_init(struct rule_criteria *criteria, uint8_t table_id,
                   const struct match *match, unsigned int priority,
                   ovs_be64 cookie, ovs_be64 cookie_mask,
                   ofp_port_t out_port, uint32_t out_group)
{
    criteria->table_id = table_id;
    cls_rule_init(&criteria->cr, match, priority);
    criteria->cookie = cookie;
    criteria->cookie_mask = cookie_mask;
    criteria->out_port = out_port;
    criteria->out_group = out_group;
}

static void
rule_criteria_destroy(struct rule_criteria *criteria)
{
    cls_rule_destroy(&criteria->cr);
}

void
rule_collection_init(struct rule_collection *rules)
{
    rules->rules = rules->stub;
    rules->n = 0;
    rules->capacity = ARRAY_SIZE(rules->stub);
}

void
rule_collection_add(struct rule_collection *rules, struct rule *rule)
{
    if (rules->n >= rules->capacity) {
        size_t old_size, new_size;

        old_size = rules->capacity * sizeof *rules->rules;
        rules->capacity *= 2;
        new_size = rules->capacity * sizeof *rules->rules;

        if (rules->rules == rules->stub) {
            rules->rules = xmalloc(new_size);
            memcpy(rules->rules, rules->stub, old_size);
        } else {
            rules->rules = xrealloc(rules->rules, new_size);
        }
    }

    rules->rules[rules->n++] = rule;
}

void
rule_collection_ref(struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    size_t i;

    for (i = 0; i < rules->n; i++) {
        ofproto_rule_ref(rules->rules[i]);
    }
}

void
rule_collection_unref(struct rule_collection *rules)
{
    size_t i;

    for (i = 0; i < rules->n; i++) {
        ofproto_rule_unref(rules->rules[i]);
    }
}

void
rule_collection_destroy(struct rule_collection *rules)
{
    if (rules->rules != rules->stub) {
        free(rules->rules);
    }
}

static enum ofperr
collect_rule(struct rule *rule, const struct rule_criteria *c,
             struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    /* We ordinarily want to skip hidden rules, but there has to be a way for
     * code internal to OVS to modify and delete them, so if the criteria
     * specify a priority that can only be for a hidden flow, then allow hidden
     * rules to be selected.  (This doesn't allow OpenFlow clients to meddle
     * with hidden flows because OpenFlow uses only a 16-bit field to specify
     * priority.) */
    if (ofproto_rule_is_hidden(rule) && c->cr.priority <= UINT16_MAX) {
        return 0;
    } else if (rule->pending) {
        return OFPROTO_POSTPONE;
    } else {
        if ((c->table_id == rule->table_id || c->table_id == 0xff)
            && ofproto_rule_has_out_port(rule, c->out_port)
            && ofproto_rule_has_out_group(rule, c->out_group)
            && !((rule->flow_cookie ^ c->cookie) & c->cookie_mask)) {
            rule_collection_add(rules, rule);
        }
        return 0;
    }
}

/* Searches 'ofproto' for rules that match the criteria in 'criteria'.  Matches
 * on classifiers rules are done in the "loose" way required for OpenFlow
 * OFPFC_MODIFY and OFPFC_DELETE requests.  Puts the selected rules on list
 * 'rules'.
 *
 * Hidden rules are always omitted.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
collect_rules_loose(struct ofproto *ofproto,
                    const struct rule_criteria *criteria,
                    struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table;
    enum ofperr error;

    rule_collection_init(rules);

    error = check_table_id(ofproto, criteria->table_id);
    if (error) {
        goto exit;
    }

    if (criteria->cookie_mask == OVS_BE64_MAX) {
        struct rule *rule;

        HINDEX_FOR_EACH_WITH_HASH (rule, cookie_node,
                                   hash_cookie(criteria->cookie),
                                   &ofproto->cookies) {
            if (cls_rule_is_loose_match(&rule->cr, &criteria->cr.match)) {
                error = collect_rule(rule, criteria, rules);
                if (error) {
                    break;
                }
            }
        }
    } else {
        FOR_EACH_MATCHING_TABLE (table, criteria->table_id, ofproto) {
            struct cls_cursor cursor;
            struct rule *rule;

            fat_rwlock_rdlock(&table->cls.rwlock);
            cls_cursor_init(&cursor, &table->cls, &criteria->cr);
            CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
                error = collect_rule(rule, criteria, rules);
                if (error) {
                    break;
                }
            }
            fat_rwlock_unlock(&table->cls.rwlock);
        }
    }

exit:
    if (error) {
        rule_collection_destroy(rules);
    }
    return error;
}

/* Searches 'ofproto' for rules that match the criteria in 'criteria'.  Matches
 * on classifiers rules are done in the "strict" way required for OpenFlow
 * OFPFC_MODIFY_STRICT and OFPFC_DELETE_STRICT requests.  Puts the selected
 * rules on list 'rules'.
 *
 * Hidden rules are always omitted.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
collect_rules_strict(struct ofproto *ofproto,
                     const struct rule_criteria *criteria,
                     struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table;
    int error;

    rule_collection_init(rules);

    error = check_table_id(ofproto, criteria->table_id);
    if (error) {
        goto exit;
    }

    if (criteria->cookie_mask == OVS_BE64_MAX) {
        struct rule *rule;

        HINDEX_FOR_EACH_WITH_HASH (rule, cookie_node,
                                   hash_cookie(criteria->cookie),
                                   &ofproto->cookies) {
            if (cls_rule_equal(&rule->cr, &criteria->cr)) {
                error = collect_rule(rule, criteria, rules);
                if (error) {
                    break;
                }
            }
        }
    } else {
        FOR_EACH_MATCHING_TABLE (table, criteria->table_id, ofproto) {
            struct rule *rule;

            fat_rwlock_rdlock(&table->cls.rwlock);
            rule = rule_from_cls_rule(classifier_find_rule_exactly(
                                          &table->cls, &criteria->cr));
            fat_rwlock_unlock(&table->cls.rwlock);
            if (rule) {
                error = collect_rule(rule, criteria, rules);
                if (error) {
                    break;
                }
            }
        }
    }

exit:
    if (error) {
        rule_collection_destroy(rules);
    }
    return error;
}

/* Returns 'age_ms' (a duration in milliseconds), converted to seconds and
 * forced into the range of a uint16_t. */
static int
age_secs(long long int age_ms)
{
    return (age_ms < 0 ? 0
            : age_ms >= UINT16_MAX * 1000 ? UINT16_MAX
            : (unsigned int) age_ms / 1000);
}

static enum ofperr
handle_flow_stats_request(struct ofconn *ofconn,
                          const struct ofp_header *request)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_flow_stats_request fsr;
    struct rule_criteria criteria;
    struct rule_collection rules;
    struct list replies;
    enum ofperr error;
    size_t i;

    error = ofputil_decode_flow_stats_request(&fsr, request);
    if (error) {
        return error;
    }

    rule_criteria_init(&criteria, fsr.table_id, &fsr.match, 0, fsr.cookie,
                       fsr.cookie_mask, fsr.out_port, fsr.out_group);

    ovs_mutex_lock(&ofproto_mutex);
    error = collect_rules_loose(ofproto, &criteria, &rules);
    rule_criteria_destroy(&criteria);
    if (!error) {
        rule_collection_ref(&rules);
    }
    ovs_mutex_unlock(&ofproto_mutex);

    if (error) {
        return error;
    }

    ofpmp_init(&replies, request);
    for (i = 0; i < rules.n; i++) {
        struct rule *rule = rules.rules[i];
        long long int now = time_msec();
        struct ofputil_flow_stats fs;
        long long int created, used, modified;
        struct rule_actions *actions;
        enum ofputil_flow_mod_flags flags;

        ovs_mutex_lock(&rule->mutex);
        fs.cookie = rule->flow_cookie;
        fs.idle_timeout = rule->idle_timeout;
        fs.hard_timeout = rule->hard_timeout;
        created = rule->created;
        used = rule->used;
        modified = rule->modified;
        actions = rule_get_actions__(rule);
        flags = rule->flags;
        ovs_mutex_unlock(&rule->mutex);

        minimatch_expand(&rule->cr.match, &fs.match);
        fs.table_id = rule->table_id;
        calc_duration(created, now, &fs.duration_sec, &fs.duration_nsec);
        fs.priority = rule->cr.priority;
        fs.idle_age = age_secs(now - used);
        fs.hard_age = age_secs(now - modified);
        ofproto->ofproto_class->rule_get_stats(rule, &fs.packet_count,
                                               &fs.byte_count);
        fs.ofpacts = actions->ofpacts;
        fs.ofpacts_len = actions->ofpacts_len;

        fs.flags = flags;
        ofputil_append_flow_stats_reply(&fs, &replies);

        rule_actions_unref(actions);
    }

    rule_collection_unref(&rules);
    rule_collection_destroy(&rules);

    ofconn_send_replies(ofconn, &replies);

    return 0;
}

static void
flow_stats_ds(struct rule *rule, struct ds *results)
{
    uint64_t packet_count, byte_count;
    struct rule_actions *actions;
    long long int created;

    rule->ofproto->ofproto_class->rule_get_stats(rule,
                                                 &packet_count, &byte_count);

    ovs_mutex_lock(&rule->mutex);
    actions = rule_get_actions__(rule);
    created = rule->created;
    ovs_mutex_unlock(&rule->mutex);

    if (rule->table_id != 0) {
        ds_put_format(results, "table_id=%"PRIu8", ", rule->table_id);
    }
    ds_put_format(results, "duration=%llds, ", (time_msec() - created) / 1000);
    ds_put_format(results, "n_packets=%"PRIu64", ", packet_count);
    ds_put_format(results, "n_bytes=%"PRIu64", ", byte_count);
    cls_rule_format(&rule->cr, results);
    ds_put_char(results, ',');

    ds_put_cstr(results, "actions=");
    ofpacts_format(actions->ofpacts, actions->ofpacts_len, results);

    ds_put_cstr(results, "\n");

    rule_actions_unref(actions);
}

/* Adds a pretty-printed description of all flows to 'results', including
 * hidden flows (e.g., set up by in-band control). */
void
ofproto_get_all_flows(struct ofproto *p, struct ds *results)
{
    struct oftable *table;

    OFPROTO_FOR_EACH_TABLE (table, p) {
        struct cls_cursor cursor;
        struct rule *rule;

        fat_rwlock_rdlock(&table->cls.rwlock);
        cls_cursor_init(&cursor, &table->cls, NULL);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            flow_stats_ds(rule, results);
        }
        fat_rwlock_unlock(&table->cls.rwlock);
    }
}

/* Obtains the NetFlow engine type and engine ID for 'ofproto' into
 * '*engine_type' and '*engine_id', respectively. */
void
ofproto_get_netflow_ids(const struct ofproto *ofproto,
                        uint8_t *engine_type, uint8_t *engine_id)
{
    ofproto->ofproto_class->get_netflow_ids(ofproto, engine_type, engine_id);
}

/* Checks the status of CFM configured on 'ofp_port' within 'ofproto'.  Returns
 * true if the port's CFM status was successfully stored into '*status'.
 * Returns false if the port did not have CFM configured, in which case
 * '*status' is indeterminate.
 *
 * The caller must provide and owns '*status', and must free 'status->rmps'. */
bool
ofproto_port_get_cfm_status(const struct ofproto *ofproto, ofp_port_t ofp_port,
                            struct ofproto_cfm_status *status)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport
            && ofproto->ofproto_class->get_cfm_status
            && ofproto->ofproto_class->get_cfm_status(ofport, status));
}

static enum ofperr
handle_aggregate_stats_request(struct ofconn *ofconn,
                               const struct ofp_header *oh)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_flow_stats_request request;
    struct ofputil_aggregate_stats stats;
    bool unknown_packets, unknown_bytes;
    struct rule_criteria criteria;
    struct rule_collection rules;
    struct ofpbuf *reply;
    enum ofperr error;
    size_t i;

    error = ofputil_decode_flow_stats_request(&request, oh);
    if (error) {
        return error;
    }

    rule_criteria_init(&criteria, request.table_id, &request.match, 0,
                       request.cookie, request.cookie_mask,
                       request.out_port, request.out_group);

    ovs_mutex_lock(&ofproto_mutex);
    error = collect_rules_loose(ofproto, &criteria, &rules);
    rule_criteria_destroy(&criteria);
    if (!error) {
        rule_collection_ref(&rules);
    }
    ovs_mutex_unlock(&ofproto_mutex);

    if (error) {
        return error;
    }

    memset(&stats, 0, sizeof stats);
    unknown_packets = unknown_bytes = false;
    for (i = 0; i < rules.n; i++) {
        struct rule *rule = rules.rules[i];
        uint64_t packet_count;
        uint64_t byte_count;

        ofproto->ofproto_class->rule_get_stats(rule, &packet_count,
                                               &byte_count);

        if (packet_count == UINT64_MAX) {
            unknown_packets = true;
        } else {
            stats.packet_count += packet_count;
        }

        if (byte_count == UINT64_MAX) {
            unknown_bytes = true;
        } else {
            stats.byte_count += byte_count;
        }

        stats.flow_count++;
    }
    if (unknown_packets) {
        stats.packet_count = UINT64_MAX;
    }
    if (unknown_bytes) {
        stats.byte_count = UINT64_MAX;
    }

    rule_collection_unref(&rules);
    rule_collection_destroy(&rules);

    reply = ofputil_encode_aggregate_stats_reply(&stats, oh);
    ofconn_send_reply(ofconn, reply);

    return 0;
}

struct queue_stats_cbdata {
    struct ofport *ofport;
    struct list replies;
    long long int now;
};

static void
put_queue_stats(struct queue_stats_cbdata *cbdata, uint32_t queue_id,
                const struct netdev_queue_stats *stats)
{
    struct ofputil_queue_stats oqs;

    oqs.port_no = cbdata->ofport->pp.port_no;
    oqs.queue_id = queue_id;
    oqs.tx_bytes = stats->tx_bytes;
    oqs.tx_packets = stats->tx_packets;
    oqs.tx_errors = stats->tx_errors;
    if (stats->created != LLONG_MIN) {
        calc_duration(stats->created, cbdata->now,
                      &oqs.duration_sec, &oqs.duration_nsec);
    } else {
        oqs.duration_sec = oqs.duration_nsec = UINT32_MAX;
    }
    ofputil_append_queue_stat(&cbdata->replies, &oqs);
}

static void
handle_queue_stats_dump_cb(uint32_t queue_id,
                           struct netdev_queue_stats *stats,
                           void *cbdata_)
{
    struct queue_stats_cbdata *cbdata = cbdata_;

    put_queue_stats(cbdata, queue_id, stats);
}

static enum ofperr
handle_queue_stats_for_port(struct ofport *port, uint32_t queue_id,
                            struct queue_stats_cbdata *cbdata)
{
    cbdata->ofport = port;
    if (queue_id == OFPQ_ALL) {
        netdev_dump_queue_stats(port->netdev,
                                handle_queue_stats_dump_cb, cbdata);
    } else {
        struct netdev_queue_stats stats;

        if (!netdev_get_queue_stats(port->netdev, queue_id, &stats)) {
            put_queue_stats(cbdata, queue_id, &stats);
        } else {
            return OFPERR_OFPQOFC_BAD_QUEUE;
        }
    }
    return 0;
}

static enum ofperr
handle_queue_stats_request(struct ofconn *ofconn,
                           const struct ofp_header *rq)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct queue_stats_cbdata cbdata;
    struct ofport *port;
    enum ofperr error;
    struct ofputil_queue_stats_request oqsr;

    COVERAGE_INC(ofproto_queue_req);

    ofpmp_init(&cbdata.replies, rq);
    cbdata.now = time_msec();

    error = ofputil_decode_queue_stats_request(rq, &oqsr);
    if (error) {
        return error;
    }

    if (oqsr.port_no == OFPP_ANY) {
        error = OFPERR_OFPQOFC_BAD_QUEUE;
        HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
            if (!handle_queue_stats_for_port(port, oqsr.queue_id, &cbdata)) {
                error = 0;
            }
        }
    } else {
        port = ofproto_get_port(ofproto, oqsr.port_no);
        error = (port
                 ? handle_queue_stats_for_port(port, oqsr.queue_id, &cbdata)
                 : OFPERR_OFPQOFC_BAD_PORT);
    }
    if (!error) {
        ofconn_send_replies(ofconn, &cbdata.replies);
    } else {
        ofpbuf_list_delete(&cbdata.replies);
    }

    return error;
}

static bool
is_flow_deletion_pending(const struct ofproto *ofproto,
                         const struct cls_rule *cls_rule,
                         uint8_t table_id)
    OVS_REQUIRES(ofproto_mutex)
{
    if (!hmap_is_empty(&ofproto->deletions)) {
        struct ofoperation *op;

        HMAP_FOR_EACH_WITH_HASH (op, hmap_node,
                                 cls_rule_hash(cls_rule, table_id),
                                 &ofproto->deletions) {
            if (cls_rule_equal(cls_rule, &op->rule->cr)) {
                return true;
            }
        }
    }

    return false;
}

static bool
should_evict_a_rule(struct oftable *table, unsigned int extra_space)
    OVS_REQUIRES(ofproto_mutex)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    return classifier_count(&table->cls) + extra_space > table->max_flows;
}

static enum ofperr
evict_rules_from_table(struct ofproto *ofproto, struct oftable *table,
                       unsigned int extra_space)
    OVS_REQUIRES(ofproto_mutex)
{
    while (should_evict_a_rule(table, extra_space)) {
        struct rule *rule;

        if (!choose_rule_to_evict(table, &rule)) {
            return OFPERR_OFPFMFC_TABLE_FULL;
        } else if (rule->pending) {
            return OFPROTO_POSTPONE;
        } else {
            struct ofopgroup *group = ofopgroup_create_unattached(ofproto);
            delete_flow__(rule, group, OFPRR_EVICTION);
            ofopgroup_submit(group);
        }
    }

    return 0;
}

/* Implements OFPFC_ADD and the cases for OFPFC_MODIFY and OFPFC_MODIFY_STRICT
 * in which no matching flow already exists in the flow table.
 *
 * Adds the flow specified by 'ofm', which is followed by 'n_actions'
 * ofp_actions, to the ofproto's flow table.  Returns 0 on success, an OpenFlow
 * error code on failure, or OFPROTO_POSTPONE if the operation cannot be
 * initiated now but may be retried later.
 *
 * The caller retains ownership of 'fm->ofpacts'.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static enum ofperr
add_flow(struct ofproto *ofproto, struct ofconn *ofconn,
         struct ofputil_flow_mod *fm, const struct ofp_header *request)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table;
    struct ofopgroup *group;
    struct cls_rule cr;
    struct rule *rule;
    uint8_t table_id;
    int error;

    error = check_table_id(ofproto, fm->table_id);
    if (error) {
        return error;
    }

    /* Pick table. */
    if (fm->table_id == 0xff) {
        if (ofproto->ofproto_class->rule_choose_table) {
            error = ofproto->ofproto_class->rule_choose_table(ofproto,
                                                              &fm->match,
                                                              &table_id);
            if (error) {
                return error;
            }
            ovs_assert(table_id < ofproto->n_tables);
        } else {
            table_id = 0;
        }
    } else if (fm->table_id < ofproto->n_tables) {
        table_id = fm->table_id;
    } else {
        return OFPERR_OFPBRC_BAD_TABLE_ID;
    }

    table = &ofproto->tables[table_id];

    if (table->flags & OFTABLE_READONLY) {
        return OFPERR_OFPBRC_EPERM;
    }

    cls_rule_init(&cr, &fm->match, fm->priority);

    /* Transform "add" into "modify" if there's an existing identical flow. */
    fat_rwlock_rdlock(&table->cls.rwlock);
    rule = rule_from_cls_rule(classifier_find_rule_exactly(&table->cls, &cr));
    fat_rwlock_unlock(&table->cls.rwlock);
    if (rule) {
        cls_rule_destroy(&cr);
        if (!rule_is_modifiable(rule)) {
            return OFPERR_OFPBRC_EPERM;
        } else if (rule->pending) {
            return OFPROTO_POSTPONE;
        } else {
            struct rule_collection rules;

            rule_collection_init(&rules);
            rule_collection_add(&rules, rule);
            fm->modify_cookie = true;
            error = modify_flows__(ofproto, ofconn, fm, request, &rules);
            rule_collection_destroy(&rules);

            return error;
        }
    }

    /* Serialize against pending deletion. */
    if (is_flow_deletion_pending(ofproto, &cr, table_id)) {
        cls_rule_destroy(&cr);
        return OFPROTO_POSTPONE;
    }

    /* Check for overlap, if requested. */
    if (fm->flags & OFPUTIL_FF_CHECK_OVERLAP) {
        bool overlaps;

        fat_rwlock_rdlock(&table->cls.rwlock);
        overlaps = classifier_rule_overlaps(&table->cls, &cr);
        fat_rwlock_unlock(&table->cls.rwlock);

        if (overlaps) {
            cls_rule_destroy(&cr);
            return OFPERR_OFPFMFC_OVERLAP;
        }
    }

    /* If necessary, evict an existing rule to clear out space. */
    error = evict_rules_from_table(ofproto, table, 1);
    if (error) {
        cls_rule_destroy(&cr);
        return error;
    }

    /* Allocate new rule. */
    rule = ofproto->ofproto_class->rule_alloc();
    if (!rule) {
        cls_rule_destroy(&cr);
        VLOG_WARN_RL(&rl, "%s: failed to create rule (%s)",
                     ofproto->name, ovs_strerror(error));
        return ENOMEM;
    }

    /* Initialize base state. */
    *CONST_CAST(struct ofproto **, &rule->ofproto) = ofproto;
    cls_rule_move(CONST_CAST(struct cls_rule *, &rule->cr), &cr);
    atomic_init(&rule->ref_count, 1);
    rule->pending = NULL;
    rule->flow_cookie = fm->new_cookie;
    rule->created = rule->modified = rule->used = time_msec();

    ovs_mutex_init(&rule->mutex);
    ovs_mutex_lock(&rule->mutex);
    rule->idle_timeout = fm->idle_timeout;
    rule->hard_timeout = fm->hard_timeout;
    ovs_mutex_unlock(&rule->mutex);

    *CONST_CAST(uint8_t *, &rule->table_id) = table - ofproto->tables;
    rule->flags = fm->flags & OFPUTIL_FF_STATE;
    rule->actions = rule_actions_create(ofproto, fm->ofpacts, fm->ofpacts_len);
    list_init(&rule->meter_list_node);
    rule->eviction_group = NULL;
    list_init(&rule->expirable);
    rule->monitor_flags = 0;
    rule->add_seqno = 0;
    rule->modify_seqno = 0;

    /* Construct rule, initializing derived state. */
    error = ofproto->ofproto_class->rule_construct(rule);
    if (error) {
        ofproto_rule_destroy__(rule);
        return error;
    }

    /* Insert rule. */
    oftable_insert_rule(rule);

    group = ofopgroup_create(ofproto, ofconn, request, fm->buffer_id);
    ofoperation_create(group, rule, OFOPERATION_ADD, 0);
    ofproto->ofproto_class->rule_insert(rule);
    ofopgroup_submit(group);

    return error;
}

/* OFPFC_MODIFY and OFPFC_MODIFY_STRICT. */

/* Modifies the rules listed in 'rules', changing their actions to match those
 * in 'fm'.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
modify_flows__(struct ofproto *ofproto, struct ofconn *ofconn,
               struct ofputil_flow_mod *fm, const struct ofp_header *request,
               const struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    enum ofoperation_type type;
    struct ofopgroup *group;
    enum ofperr error;
    size_t i;

    type = fm->command == OFPFC_ADD ? OFOPERATION_REPLACE : OFOPERATION_MODIFY;
    group = ofopgroup_create(ofproto, ofconn, request, fm->buffer_id);
    error = OFPERR_OFPBRC_EPERM;
    for (i = 0; i < rules->n; i++) {
        struct rule *rule = rules->rules[i];
        struct ofoperation *op;
        bool actions_changed;
        bool reset_counters;

        /* FIXME: Implement OFPFUTIL_FF_RESET_COUNTS */

        if (rule_is_modifiable(rule)) {
            /* At least one rule is modifiable, don't report EPERM error. */
            error = 0;
        } else {
            continue;
        }

        actions_changed = !ofpacts_equal(fm->ofpacts, fm->ofpacts_len,
                                         rule->actions->ofpacts,
                                         rule->actions->ofpacts_len);

        op = ofoperation_create(group, rule, type, 0);

        if (fm->modify_cookie && fm->new_cookie != OVS_BE64_MAX) {
            ofproto_rule_change_cookie(ofproto, rule, fm->new_cookie);
        }
        if (type == OFOPERATION_REPLACE) {
            ovs_mutex_lock(&rule->mutex);
            rule->idle_timeout = fm->idle_timeout;
            rule->hard_timeout = fm->hard_timeout;
            ovs_mutex_unlock(&rule->mutex);

            rule->flags = fm->flags & OFPUTIL_FF_STATE;
            if (fm->idle_timeout || fm->hard_timeout) {
                if (!rule->eviction_group) {
                    eviction_group_add_rule(rule);
                }
            } else {
                eviction_group_remove_rule(rule);
            }
        }

        reset_counters = (fm->flags & OFPUTIL_FF_RESET_COUNTS) != 0;
        if (actions_changed || reset_counters) {
            struct rule_actions *new_actions;

            op->actions = rule->actions;
            new_actions = rule_actions_create(ofproto,
                                              fm->ofpacts, fm->ofpacts_len);

            ovs_mutex_lock(&rule->mutex);
            rule->actions = new_actions;
            ovs_mutex_unlock(&rule->mutex);

            rule->ofproto->ofproto_class->rule_modify_actions(rule,
                                                              reset_counters);
        } else {
            ofoperation_complete(op, 0);
        }
    }
    ofopgroup_submit(group);

    return error;
}

static enum ofperr
modify_flows_add(struct ofproto *ofproto, struct ofconn *ofconn,
                 struct ofputil_flow_mod *fm, const struct ofp_header *request)
    OVS_REQUIRES(ofproto_mutex)
{
    if (fm->cookie_mask != htonll(0) || fm->new_cookie == OVS_BE64_MAX) {
        return 0;
    }
    return add_flow(ofproto, ofconn, fm, request);
}

/* Implements OFPFC_MODIFY.  Returns 0 on success or an OpenFlow error code on
 * failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any. */
static enum ofperr
modify_flows_loose(struct ofproto *ofproto, struct ofconn *ofconn,
                   struct ofputil_flow_mod *fm,
                   const struct ofp_header *request)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_criteria criteria;
    struct rule_collection rules;
    int error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, 0,
                       fm->cookie, fm->cookie_mask, OFPP_ANY, OFPG11_ANY);
    error = collect_rules_loose(ofproto, &criteria, &rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        error = (rules.n > 0
                 ? modify_flows__(ofproto, ofconn, fm, request, &rules)
                 : modify_flows_add(ofproto, ofconn, fm, request));
    }

    rule_collection_destroy(&rules);

    return error;
}

/* Implements OFPFC_MODIFY_STRICT.  Returns 0 on success or an OpenFlow error
 * code on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any. */
static enum ofperr
modify_flow_strict(struct ofproto *ofproto, struct ofconn *ofconn,
                   struct ofputil_flow_mod *fm,
                   const struct ofp_header *request)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_criteria criteria;
    struct rule_collection rules;
    int error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, fm->priority,
                       fm->cookie, fm->cookie_mask, OFPP_ANY, OFPG11_ANY);
    error = collect_rules_strict(ofproto, &criteria, &rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        if (rules.n == 0) {
            error =  modify_flows_add(ofproto, ofconn, fm, request);
        } else if (rules.n == 1) {
            error = modify_flows__(ofproto, ofconn, fm, request, &rules);
        }
    }

    rule_collection_destroy(&rules);

    return error;
}

/* OFPFC_DELETE implementation. */

static void
delete_flow__(struct rule *rule, struct ofopgroup *group,
              enum ofp_flow_removed_reason reason)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto *ofproto = rule->ofproto;

    ofproto_rule_send_removed(rule, reason);

    ofoperation_create(group, rule, OFOPERATION_DELETE, reason);
    oftable_remove_rule(rule);
    ofproto->ofproto_class->rule_delete(rule);
}

/* Deletes the rules listed in 'rules'.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
delete_flows__(struct ofproto *ofproto, struct ofconn *ofconn,
               const struct ofp_header *request,
               const struct rule_collection *rules,
               enum ofp_flow_removed_reason reason)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofopgroup *group;
    size_t i;

    group = ofopgroup_create(ofproto, ofconn, request, UINT32_MAX);
    for (i = 0; i < rules->n; i++) {
        delete_flow__(rules->rules[i], group, reason);
    }
    ofopgroup_submit(group);

    return 0;
}

/* Implements OFPFC_DELETE. */
static enum ofperr
delete_flows_loose(struct ofproto *ofproto, struct ofconn *ofconn,
                   const struct ofputil_flow_mod *fm,
                   const struct ofp_header *request)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_criteria criteria;
    struct rule_collection rules;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, 0,
                       fm->cookie, fm->cookie_mask,
                       fm->out_port, fm->out_group);
    error = collect_rules_loose(ofproto, &criteria, &rules);
    rule_criteria_destroy(&criteria);

    if (!error && rules.n > 0) {
        error = delete_flows__(ofproto, ofconn, request, &rules, OFPRR_DELETE);
    }
    rule_collection_destroy(&rules);

    return error;
}

/* Implements OFPFC_DELETE_STRICT. */
static enum ofperr
delete_flow_strict(struct ofproto *ofproto, struct ofconn *ofconn,
                   const struct ofputil_flow_mod *fm,
                   const struct ofp_header *request)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_criteria criteria;
    struct rule_collection rules;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, fm->priority,
                       fm->cookie, fm->cookie_mask,
                       fm->out_port, fm->out_group);
    error = collect_rules_strict(ofproto, &criteria, &rules);
    rule_criteria_destroy(&criteria);

    if (!error && rules.n > 0) {
        error = delete_flows__(ofproto, ofconn, request, &rules, OFPRR_DELETE);
    }
    rule_collection_destroy(&rules);

    return error;
}

static void
ofproto_rule_send_removed(struct rule *rule, uint8_t reason)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofputil_flow_removed fr;

    if (ofproto_rule_is_hidden(rule) ||
        !(rule->flags & OFPUTIL_FF_SEND_FLOW_REM)) {
        return;
    }

    minimatch_expand(&rule->cr.match, &fr.match);
    fr.priority = rule->cr.priority;
    fr.cookie = rule->flow_cookie;
    fr.reason = reason;
    fr.table_id = rule->table_id;
    calc_duration(rule->created, time_msec(),
                  &fr.duration_sec, &fr.duration_nsec);
    ovs_mutex_lock(&rule->mutex);
    fr.idle_timeout = rule->idle_timeout;
    fr.hard_timeout = rule->hard_timeout;
    ovs_mutex_unlock(&rule->mutex);
    rule->ofproto->ofproto_class->rule_get_stats(rule, &fr.packet_count,
                                                 &fr.byte_count);

    connmgr_send_flow_removed(rule->ofproto->connmgr, &fr);
}

/* Sends an OpenFlow "flow removed" message with the given 'reason' (either
 * OFPRR_HARD_TIMEOUT or OFPRR_IDLE_TIMEOUT), and then removes 'rule' from its
 * ofproto.
 *
 * 'rule' must not have a pending operation (that is, 'rule->pending' must be
 * NULL).
 *
 * ofproto implementation ->run() functions should use this function to expire
 * OpenFlow flows. */
void
ofproto_rule_expire(struct rule *rule, uint8_t reason)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto *ofproto = rule->ofproto;

    ovs_assert(reason == OFPRR_HARD_TIMEOUT || reason == OFPRR_IDLE_TIMEOUT
               || reason == OFPRR_DELETE || reason == OFPRR_GROUP_DELETE);

    ofproto_rule_delete__(ofproto, rule, reason);
}

/* Reduces '*timeout' to no more than 'max'.  A value of zero in either case
 * means "infinite". */
static void
reduce_timeout(uint16_t max, uint16_t *timeout)
{
    if (max && (!*timeout || *timeout > max)) {
        *timeout = max;
    }
}

/* If 'idle_timeout' is nonzero, and 'rule' has no idle timeout or an idle
 * timeout greater than 'idle_timeout', lowers 'rule''s idle timeout to
 * 'idle_timeout' seconds.  Similarly for 'hard_timeout'.
 *
 * Suitable for implementing OFPACT_FIN_TIMEOUT. */
void
ofproto_rule_reduce_timeouts(struct rule *rule,
                             uint16_t idle_timeout, uint16_t hard_timeout)
    OVS_EXCLUDED(ofproto_mutex, rule->mutex)
{
    if (!idle_timeout && !hard_timeout) {
        return;
    }

    ovs_mutex_lock(&ofproto_mutex);
    if (list_is_empty(&rule->expirable)) {
        list_insert(&rule->ofproto->expirable, &rule->expirable);
    }
    ovs_mutex_unlock(&ofproto_mutex);

    ovs_mutex_lock(&rule->mutex);
    reduce_timeout(idle_timeout, &rule->idle_timeout);
    reduce_timeout(hard_timeout, &rule->hard_timeout);
    ovs_mutex_unlock(&rule->mutex);
}

static enum ofperr
handle_flow_mod(struct ofconn *ofconn, const struct ofp_header *oh)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_flow_mod fm;
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts;
    enum ofperr error;
    long long int now;

    error = reject_slave_controller(ofconn);
    if (error) {
        goto exit;
    }

    ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    error = ofputil_decode_flow_mod(&fm, oh, ofconn_get_protocol(ofconn),
                                    &ofpacts,
                                    u16_to_ofp(ofproto->max_ports),
                                    ofproto->n_tables);
    if (!error) {
        error = ofproto_check_ofpacts(ofproto, fm.ofpacts, fm.ofpacts_len);
    }
    if (!error) {
        error = handle_flow_mod__(ofproto, ofconn, &fm, oh);
    }
    if (error) {
        goto exit_free_ofpacts;
    }

    /* Record the operation for logging a summary report. */
    switch (fm.command) {
    case OFPFC_ADD:
        ofproto->n_add++;
        break;

    case OFPFC_MODIFY:
    case OFPFC_MODIFY_STRICT:
        ofproto->n_modify++;
        break;

    case OFPFC_DELETE:
    case OFPFC_DELETE_STRICT:
        ofproto->n_delete++;
        break;
    }

    now = time_msec();
    if (ofproto->next_op_report == LLONG_MAX) {
        ofproto->first_op = now;
        ofproto->next_op_report = MAX(now + 10 * 1000,
                                      ofproto->op_backoff);
        ofproto->op_backoff = ofproto->next_op_report + 60 * 1000;
    }
    ofproto->last_op = now;

exit_free_ofpacts:
    ofpbuf_uninit(&ofpacts);
exit:
    return error;
}

static enum ofperr
handle_flow_mod__(struct ofproto *ofproto, struct ofconn *ofconn,
                  struct ofputil_flow_mod *fm, const struct ofp_header *oh)
    OVS_EXCLUDED(ofproto_mutex)
{
    enum ofperr error;

    ovs_mutex_lock(&ofproto_mutex);
    if (ofproto->n_pending < 50) {
        switch (fm->command) {
        case OFPFC_ADD:
            error = add_flow(ofproto, ofconn, fm, oh);
            break;

        case OFPFC_MODIFY:
            error = modify_flows_loose(ofproto, ofconn, fm, oh);
            break;

        case OFPFC_MODIFY_STRICT:
            error = modify_flow_strict(ofproto, ofconn, fm, oh);
            break;

        case OFPFC_DELETE:
            error = delete_flows_loose(ofproto, ofconn, fm, oh);
            break;

        case OFPFC_DELETE_STRICT:
            error = delete_flow_strict(ofproto, ofconn, fm, oh);
            break;

        default:
            if (fm->command > 0xff) {
                VLOG_WARN_RL(&rl, "%s: flow_mod has explicit table_id but "
                             "flow_mod_table_id extension is not enabled",
                             ofproto->name);
            }
            error = OFPERR_OFPFMFC_BAD_COMMAND;
            break;
        }
    } else {
        ovs_assert(!list_is_empty(&ofproto->pending));
        error = OFPROTO_POSTPONE;
    }
    ovs_mutex_unlock(&ofproto_mutex);

    run_rule_executes(ofproto);
    return error;
}

static enum ofperr
handle_role_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofputil_role_request request;
    struct ofputil_role_request reply;
    struct ofpbuf *buf;
    enum ofperr error;

    error = ofputil_decode_role_message(oh, &request);
    if (error) {
        return error;
    }

    if (request.role != OFPCR12_ROLE_NOCHANGE) {
        if (ofconn_get_role(ofconn) != request.role
            && ofconn_has_pending_opgroups(ofconn)) {
            return OFPROTO_POSTPONE;
        }

        if (request.have_generation_id
            && !ofconn_set_master_election_id(ofconn, request.generation_id)) {
                return OFPERR_OFPRRFC_STALE;
        }

        ofconn_set_role(ofconn, request.role);
    }

    reply.role = ofconn_get_role(ofconn);
    reply.have_generation_id = ofconn_get_master_election_id(
        ofconn, &reply.generation_id);
    buf = ofputil_encode_role_reply(oh, &reply);
    ofconn_send_reply(ofconn, buf);

    return 0;
}

static enum ofperr
handle_nxt_flow_mod_table_id(struct ofconn *ofconn,
                             const struct ofp_header *oh)
{
    const struct nx_flow_mod_table_id *msg = ofpmsg_body(oh);
    enum ofputil_protocol cur, next;

    cur = ofconn_get_protocol(ofconn);
    next = ofputil_protocol_set_tid(cur, msg->set != 0);
    ofconn_set_protocol(ofconn, next);

    return 0;
}

static enum ofperr
handle_nxt_set_flow_format(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct nx_set_flow_format *msg = ofpmsg_body(oh);
    enum ofputil_protocol cur, next;
    enum ofputil_protocol next_base;

    next_base = ofputil_nx_flow_format_to_protocol(ntohl(msg->format));
    if (!next_base) {
        return OFPERR_OFPBRC_EPERM;
    }

    cur = ofconn_get_protocol(ofconn);
    next = ofputil_protocol_set_base(cur, next_base);
    if (cur != next && ofconn_has_pending_opgroups(ofconn)) {
        /* Avoid sending async messages in surprising protocol. */
        return OFPROTO_POSTPONE;
    }

    ofconn_set_protocol(ofconn, next);
    return 0;
}

static enum ofperr
handle_nxt_set_packet_in_format(struct ofconn *ofconn,
                                const struct ofp_header *oh)
{
    const struct nx_set_packet_in_format *msg = ofpmsg_body(oh);
    uint32_t format;

    format = ntohl(msg->format);
    if (format != NXPIF_OPENFLOW10 && format != NXPIF_NXM) {
        return OFPERR_OFPBRC_EPERM;
    }

    if (format != ofconn_get_packet_in_format(ofconn)
        && ofconn_has_pending_opgroups(ofconn)) {
        /* Avoid sending async message in surprsing packet in format. */
        return OFPROTO_POSTPONE;
    }

    ofconn_set_packet_in_format(ofconn, format);
    return 0;
}

static enum ofperr
handle_nxt_set_async_config(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct nx_async_config *msg = ofpmsg_body(oh);
    uint32_t master[OAM_N_TYPES];
    uint32_t slave[OAM_N_TYPES];

    master[OAM_PACKET_IN] = ntohl(msg->packet_in_mask[0]);
    master[OAM_PORT_STATUS] = ntohl(msg->port_status_mask[0]);
    master[OAM_FLOW_REMOVED] = ntohl(msg->flow_removed_mask[0]);

    slave[OAM_PACKET_IN] = ntohl(msg->packet_in_mask[1]);
    slave[OAM_PORT_STATUS] = ntohl(msg->port_status_mask[1]);
    slave[OAM_FLOW_REMOVED] = ntohl(msg->flow_removed_mask[1]);

    ofconn_set_async_config(ofconn, master, slave);
    if (ofconn_get_type(ofconn) == OFCONN_SERVICE &&
        !ofconn_get_miss_send_len(ofconn)) {
        ofconn_set_miss_send_len(ofconn, OFP_DEFAULT_MISS_SEND_LEN);
    }

    return 0;
}

static enum ofperr
handle_nxt_get_async_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofpbuf *buf;
    uint32_t master[OAM_N_TYPES];
    uint32_t slave[OAM_N_TYPES];
    struct nx_async_config *msg;

    ofconn_get_async_config(ofconn, master, slave);
    buf = ofpraw_alloc_reply(OFPRAW_OFPT13_GET_ASYNC_REPLY, oh, 0);
    msg = ofpbuf_put_zeros(buf, sizeof *msg);

    msg->packet_in_mask[0] = htonl(master[OAM_PACKET_IN]);
    msg->port_status_mask[0] = htonl(master[OAM_PORT_STATUS]);
    msg->flow_removed_mask[0] = htonl(master[OAM_FLOW_REMOVED]);

    msg->packet_in_mask[1] = htonl(slave[OAM_PACKET_IN]);
    msg->port_status_mask[1] = htonl(slave[OAM_PORT_STATUS]);
    msg->flow_removed_mask[1] = htonl(slave[OAM_FLOW_REMOVED]);

    ofconn_send_reply(ofconn, buf);

    return 0;
}

static enum ofperr
handle_nxt_set_controller_id(struct ofconn *ofconn,
                             const struct ofp_header *oh)
{
    const struct nx_controller_id *nci = ofpmsg_body(oh);

    if (!is_all_zeros(nci->zero, sizeof nci->zero)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    ofconn_set_controller_id(ofconn, ntohs(nci->controller_id));
    return 0;
}

static enum ofperr
handle_barrier_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofpbuf *buf;

    if (ofconn_has_pending_opgroups(ofconn)) {
        return OFPROTO_POSTPONE;
    }

    buf = ofpraw_alloc_reply((oh->version == OFP10_VERSION
                              ? OFPRAW_OFPT10_BARRIER_REPLY
                              : OFPRAW_OFPT11_BARRIER_REPLY), oh, 0);
    ofconn_send_reply(ofconn, buf);
    return 0;
}

static void
ofproto_compose_flow_refresh_update(const struct rule *rule,
                                    enum nx_flow_monitor_flags flags,
                                    struct list *msgs)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofoperation *op = rule->pending;
    const struct rule_actions *actions;
    struct ofputil_flow_update fu;
    struct match match;

    if (op && op->type == OFOPERATION_ADD) {
        /* We'll report the final flow when the operation completes.  Reporting
         * it now would cause a duplicate report later. */
        return;
    }

    fu.event = (flags & (NXFMF_INITIAL | NXFMF_ADD)
                ? NXFME_ADDED : NXFME_MODIFIED);
    fu.reason = 0;
    ovs_mutex_lock(&rule->mutex);
    fu.idle_timeout = rule->idle_timeout;
    fu.hard_timeout = rule->hard_timeout;
    ovs_mutex_unlock(&rule->mutex);
    fu.table_id = rule->table_id;
    fu.cookie = rule->flow_cookie;
    minimatch_expand(&rule->cr.match, &match);
    fu.match = &match;
    fu.priority = rule->cr.priority;

    if (!(flags & NXFMF_ACTIONS)) {
        actions = NULL;
    } else if (!op) {
        actions = rule->actions;
    } else {
        /* An operation is in progress.  Use the previous version of the flow's
         * actions, so that when the operation commits we report the change. */
        switch (op->type) {
        case OFOPERATION_ADD:
            OVS_NOT_REACHED();

        case OFOPERATION_MODIFY:
        case OFOPERATION_REPLACE:
            actions = op->actions ? op->actions : rule->actions;
            break;

        case OFOPERATION_DELETE:
            actions = rule->actions;
            break;

        default:
            OVS_NOT_REACHED();
        }
    }
    fu.ofpacts = actions ? actions->ofpacts : NULL;
    fu.ofpacts_len = actions ? actions->ofpacts_len : 0;

    if (list_is_empty(msgs)) {
        ofputil_start_flow_update(msgs);
    }
    ofputil_append_flow_update(&fu, msgs);
}

void
ofmonitor_compose_refresh_updates(struct rule_collection *rules,
                                  struct list *msgs)
    OVS_REQUIRES(ofproto_mutex)
{
    size_t i;

    for (i = 0; i < rules->n; i++) {
        struct rule *rule = rules->rules[i];
        enum nx_flow_monitor_flags flags = rule->monitor_flags;
        rule->monitor_flags = 0;

        ofproto_compose_flow_refresh_update(rule, flags, msgs);
    }
}

static void
ofproto_collect_ofmonitor_refresh_rule(const struct ofmonitor *m,
                                       struct rule *rule, uint64_t seqno,
                                       struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    enum nx_flow_monitor_flags update;

    if (ofproto_rule_is_hidden(rule)) {
        return;
    }

    if (!(rule->pending
          ? ofoperation_has_out_port(rule->pending, m->out_port)
          : ofproto_rule_has_out_port(rule, m->out_port))) {
        return;
    }

    if (seqno) {
        if (rule->add_seqno > seqno) {
            update = NXFMF_ADD | NXFMF_MODIFY;
        } else if (rule->modify_seqno > seqno) {
            update = NXFMF_MODIFY;
        } else {
            return;
        }

        if (!(m->flags & update)) {
            return;
        }
    } else {
        update = NXFMF_INITIAL;
    }

    if (!rule->monitor_flags) {
        rule_collection_add(rules, rule);
    }
    rule->monitor_flags |= update | (m->flags & NXFMF_ACTIONS);
}

static void
ofproto_collect_ofmonitor_refresh_rules(const struct ofmonitor *m,
                                        uint64_t seqno,
                                        struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    const struct ofproto *ofproto = ofconn_get_ofproto(m->ofconn);
    const struct ofoperation *op;
    const struct oftable *table;
    struct cls_rule target;

    cls_rule_init_from_minimatch(&target, &m->match, 0);
    FOR_EACH_MATCHING_TABLE (table, m->table_id, ofproto) {
        struct cls_cursor cursor;
        struct rule *rule;

        fat_rwlock_rdlock(&table->cls.rwlock);
        cls_cursor_init(&cursor, &table->cls, &target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            ovs_assert(!rule->pending); /* XXX */
            ofproto_collect_ofmonitor_refresh_rule(m, rule, seqno, rules);
        }
        fat_rwlock_unlock(&table->cls.rwlock);
    }

    HMAP_FOR_EACH (op, hmap_node, &ofproto->deletions) {
        struct rule *rule = op->rule;

        if (((m->table_id == 0xff
              ? !(ofproto->tables[rule->table_id].flags & OFTABLE_HIDDEN)
              : m->table_id == rule->table_id))
            && cls_rule_is_loose_match(&rule->cr, &target.match)) {
            ofproto_collect_ofmonitor_refresh_rule(m, rule, seqno, rules);
        }
    }
    cls_rule_destroy(&target);
}

static void
ofproto_collect_ofmonitor_initial_rules(struct ofmonitor *m,
                                        struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    if (m->flags & NXFMF_INITIAL) {
        ofproto_collect_ofmonitor_refresh_rules(m, 0, rules);
    }
}

void
ofmonitor_collect_resume_rules(struct ofmonitor *m,
                               uint64_t seqno, struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    ofproto_collect_ofmonitor_refresh_rules(m, seqno, rules);
}

static enum ofperr
handle_flow_monitor_request(struct ofconn *ofconn, const struct ofp_header *oh)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofmonitor **monitors;
    size_t n_monitors, allocated_monitors;
    struct rule_collection rules;
    struct list replies;
    enum ofperr error;
    struct ofpbuf b;
    size_t i;

    error = 0;
    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    monitors = NULL;
    n_monitors = allocated_monitors = 0;

    ovs_mutex_lock(&ofproto_mutex);
    for (;;) {
        struct ofputil_flow_monitor_request request;
        struct ofmonitor *m;
        int retval;

        retval = ofputil_decode_flow_monitor_request(&request, &b);
        if (retval == EOF) {
            break;
        } else if (retval) {
            error = retval;
            goto error;
        }

        if (request.table_id != 0xff
            && request.table_id >= ofproto->n_tables) {
            error = OFPERR_OFPBRC_BAD_TABLE_ID;
            goto error;
        }

        error = ofmonitor_create(&request, ofconn, &m);
        if (error) {
            goto error;
        }

        if (n_monitors >= allocated_monitors) {
            monitors = x2nrealloc(monitors, &allocated_monitors,
                                  sizeof *monitors);
        }
        monitors[n_monitors++] = m;
    }

    rule_collection_init(&rules);
    for (i = 0; i < n_monitors; i++) {
        ofproto_collect_ofmonitor_initial_rules(monitors[i], &rules);
    }

    ofpmp_init(&replies, oh);
    ofmonitor_compose_refresh_updates(&rules, &replies);
    ovs_mutex_unlock(&ofproto_mutex);

    rule_collection_destroy(&rules);

    ofconn_send_replies(ofconn, &replies);
    free(monitors);

    return 0;

error:
    for (i = 0; i < n_monitors; i++) {
        ofmonitor_destroy(monitors[i]);
    }
    free(monitors);
    ovs_mutex_unlock(&ofproto_mutex);

    return error;
}

static enum ofperr
handle_flow_monitor_cancel(struct ofconn *ofconn, const struct ofp_header *oh)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofmonitor *m;
    enum ofperr error;
    uint32_t id;

    id = ofputil_decode_flow_monitor_cancel(oh);

    ovs_mutex_lock(&ofproto_mutex);
    m = ofmonitor_lookup(ofconn, id);
    if (m) {
        ofmonitor_destroy(m);
        error = 0;
    } else {
        error = OFPERR_NXBRC_FM_BAD_ID;
    }
    ovs_mutex_unlock(&ofproto_mutex);

    return error;
}

/* Meters implementation.
 *
 * Meter table entry, indexed by the OpenFlow meter_id.
 * These are always dynamically allocated to allocate enough space for
 * the bands.
 * 'created' is used to compute the duration for meter stats.
 * 'list rules' is needed so that we can delete the dependent rules when the
 * meter table entry is deleted.
 * 'provider_meter_id' is for the provider's private use.
 */
struct meter {
    long long int created;      /* Time created. */
    struct list rules;          /* List of "struct rule_dpif"s. */
    ofproto_meter_id provider_meter_id;
    uint16_t flags;             /* Meter flags. */
    uint16_t n_bands;           /* Number of meter bands. */
    struct ofputil_meter_band *bands;
};

/*
 * This is used in instruction validation at flow set-up time,
 * as flows may not use non-existing meters.
 * Return value of UINT32_MAX signifies an invalid meter.
 */
static uint32_t
get_provider_meter_id(const struct ofproto *ofproto, uint32_t of_meter_id)
{
    if (of_meter_id && of_meter_id <= ofproto->meter_features.max_meters) {
        const struct meter *meter = ofproto->meters[of_meter_id];
        if (meter) {
            return meter->provider_meter_id.uint32;
        }
    }
    return UINT32_MAX;
}

static void
meter_update(struct meter *meter, const struct ofputil_meter_config *config)
{
    free(meter->bands);

    meter->flags = config->flags;
    meter->n_bands = config->n_bands;
    meter->bands = xmemdup(config->bands,
                           config->n_bands * sizeof *meter->bands);
}

static struct meter *
meter_create(const struct ofputil_meter_config *config,
             ofproto_meter_id provider_meter_id)
{
    struct meter *meter;

    meter = xzalloc(sizeof *meter);
    meter->provider_meter_id = provider_meter_id;
    meter->created = time_msec();
    list_init(&meter->rules);

    meter_update(meter, config);

    return meter;
}

static void
meter_delete(struct ofproto *ofproto, uint32_t first, uint32_t last)
    OVS_REQUIRES(ofproto_mutex)
{
    uint32_t mid;
    for (mid = first; mid <= last; ++mid) {
        struct meter *meter = ofproto->meters[mid];
        if (meter) {
            ofproto->meters[mid] = NULL;
            ofproto->ofproto_class->meter_del(ofproto,
                                              meter->provider_meter_id);
            free(meter->bands);
            free(meter);
        }
    }
}

static enum ofperr
handle_add_meter(struct ofproto *ofproto, struct ofputil_meter_mod *mm)
{
    ofproto_meter_id provider_meter_id = { UINT32_MAX };
    struct meter **meterp = &ofproto->meters[mm->meter.meter_id];
    enum ofperr error;

    if (*meterp) {
        return OFPERR_OFPMMFC_METER_EXISTS;
    }

    error = ofproto->ofproto_class->meter_set(ofproto, &provider_meter_id,
                                              &mm->meter);
    if (!error) {
        ovs_assert(provider_meter_id.uint32 != UINT32_MAX);
        *meterp = meter_create(&mm->meter, provider_meter_id);
    }
    return error;
}

static enum ofperr
handle_modify_meter(struct ofproto *ofproto, struct ofputil_meter_mod *mm)
{
    struct meter *meter = ofproto->meters[mm->meter.meter_id];
    enum ofperr error;
    uint32_t provider_meter_id;

    if (!meter) {
        return OFPERR_OFPMMFC_UNKNOWN_METER;
    }

    provider_meter_id = meter->provider_meter_id.uint32;
    error = ofproto->ofproto_class->meter_set(ofproto,
                                              &meter->provider_meter_id,
                                              &mm->meter);
    ovs_assert(meter->provider_meter_id.uint32 == provider_meter_id);
    if (!error) {
        meter_update(meter, &mm->meter);
    }
    return error;
}

static enum ofperr
handle_delete_meter(struct ofconn *ofconn, const struct ofp_header *oh,
                    struct ofputil_meter_mod *mm)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    uint32_t meter_id = mm->meter.meter_id;
    struct rule_collection rules;
    enum ofperr error = 0;
    uint32_t first, last;

    if (meter_id == OFPM13_ALL) {
        first = 1;
        last = ofproto->meter_features.max_meters;
    } else {
        if (!meter_id || meter_id > ofproto->meter_features.max_meters) {
            return 0;
        }
        first = last = meter_id;
    }

    /* First delete the rules that use this meter.  If any of those rules are
     * currently being modified, postpone the whole operation until later. */
    rule_collection_init(&rules);
    ovs_mutex_lock(&ofproto_mutex);
    for (meter_id = first; meter_id <= last; ++meter_id) {
        struct meter *meter = ofproto->meters[meter_id];
        if (meter && !list_is_empty(&meter->rules)) {
            struct rule *rule;

            LIST_FOR_EACH (rule, meter_list_node, &meter->rules) {
                if (rule->pending) {
                    error = OFPROTO_POSTPONE;
                    goto exit;
                }
                rule_collection_add(&rules, rule);
            }
        }
    }
    if (rules.n > 0) {
        delete_flows__(ofproto, ofconn, oh, &rules, OFPRR_METER_DELETE);
    }

    /* Delete the meters. */
    meter_delete(ofproto, first, last);

exit:
    ovs_mutex_unlock(&ofproto_mutex);
    rule_collection_destroy(&rules);

    return error;
}

static enum ofperr
handle_meter_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_meter_mod mm;
    uint64_t bands_stub[256 / 8];
    struct ofpbuf bands;
    uint32_t meter_id;
    enum ofperr error;

    error = reject_slave_controller(ofconn);
    if (error) {
        return error;
    }

    ofpbuf_use_stub(&bands, bands_stub, sizeof bands_stub);

    error = ofputil_decode_meter_mod(oh, &mm, &bands);
    if (error) {
        goto exit_free_bands;
    }

    meter_id = mm.meter.meter_id;

    if (mm.command != OFPMC13_DELETE) {
        /* Fails also when meters are not implemented by the provider. */
        if (meter_id == 0 || meter_id > OFPM13_MAX) {
            error = OFPERR_OFPMMFC_INVALID_METER;
            goto exit_free_bands;
        } else if (meter_id > ofproto->meter_features.max_meters) {
            error = OFPERR_OFPMMFC_OUT_OF_METERS;
            goto exit_free_bands;
        }
        if (mm.meter.n_bands > ofproto->meter_features.max_bands) {
            error = OFPERR_OFPMMFC_OUT_OF_BANDS;
            goto exit_free_bands;
        }
    }

    switch (mm.command) {
    case OFPMC13_ADD:
        error = handle_add_meter(ofproto, &mm);
        break;

    case OFPMC13_MODIFY:
        error = handle_modify_meter(ofproto, &mm);
        break;

    case OFPMC13_DELETE:
        error = handle_delete_meter(ofconn, oh, &mm);
        break;

    default:
        error = OFPERR_OFPMMFC_BAD_COMMAND;
        break;
    }

exit_free_bands:
    ofpbuf_uninit(&bands);
    return error;
}

static enum ofperr
handle_meter_features_request(struct ofconn *ofconn,
                              const struct ofp_header *request)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_meter_features features;
    struct ofpbuf *b;

    if (ofproto->ofproto_class->meter_get_features) {
        ofproto->ofproto_class->meter_get_features(ofproto, &features);
    } else {
        memset(&features, 0, sizeof features);
    }
    b = ofputil_encode_meter_features_reply(&features, request);

    ofconn_send_reply(ofconn, b);
    return 0;
}

static enum ofperr
handle_meter_request(struct ofconn *ofconn, const struct ofp_header *request,
                     enum ofptype type)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct list replies;
    uint64_t bands_stub[256 / 8];
    struct ofpbuf bands;
    uint32_t meter_id, first, last;

    ofputil_decode_meter_request(request, &meter_id);

    if (meter_id == OFPM13_ALL) {
        first = 1;
        last = ofproto->meter_features.max_meters;
    } else {
        if (!meter_id || meter_id > ofproto->meter_features.max_meters ||
            !ofproto->meters[meter_id]) {
            return OFPERR_OFPMMFC_UNKNOWN_METER;
        }
        first = last = meter_id;
    }

    ofpbuf_use_stub(&bands, bands_stub, sizeof bands_stub);
    ofpmp_init(&replies, request);

    for (meter_id = first; meter_id <= last; ++meter_id) {
        struct meter *meter = ofproto->meters[meter_id];
        if (!meter) {
            continue; /* Skip non-existing meters. */
        }
        if (type == OFPTYPE_METER_STATS_REQUEST) {
            struct ofputil_meter_stats stats;

            stats.meter_id = meter_id;

            /* Provider sets the packet and byte counts, we do the rest. */
            stats.flow_count = list_size(&meter->rules);
            calc_duration(meter->created, time_msec(),
                          &stats.duration_sec, &stats.duration_nsec);
            stats.n_bands = meter->n_bands;
            ofpbuf_clear(&bands);
            stats.bands
                = ofpbuf_put_uninit(&bands,
                                    meter->n_bands * sizeof *stats.bands);

            if (!ofproto->ofproto_class->meter_get(ofproto,
                                                   meter->provider_meter_id,
                                                   &stats)) {
                ofputil_append_meter_stats(&replies, &stats);
            }
        } else { /* type == OFPTYPE_METER_CONFIG_REQUEST */
            struct ofputil_meter_config config;

            config.meter_id = meter_id;
            config.flags = meter->flags;
            config.n_bands = meter->n_bands;
            config.bands = meter->bands;
            ofputil_append_meter_config(&replies, &config);
        }
    }

    ofconn_send_replies(ofconn, &replies);
    ofpbuf_uninit(&bands);
    return 0;
}

bool
ofproto_group_lookup(const struct ofproto *ofproto, uint32_t group_id,
                     struct ofgroup **group)
    OVS_TRY_RDLOCK(true, (*group)->rwlock)
{
    ovs_rwlock_rdlock(&ofproto->groups_rwlock);
    HMAP_FOR_EACH_IN_BUCKET (*group, hmap_node,
                             hash_int(group_id, 0), &ofproto->groups) {
        if ((*group)->group_id == group_id) {
            ovs_rwlock_rdlock(&(*group)->rwlock);
            ovs_rwlock_unlock(&ofproto->groups_rwlock);
            return true;
        }
    }
    ovs_rwlock_unlock(&ofproto->groups_rwlock);
    return false;
}

void
ofproto_group_release(struct ofgroup *group)
    OVS_RELEASES(group->rwlock)
{
    ovs_rwlock_unlock(&group->rwlock);
}

static bool
ofproto_group_write_lookup(const struct ofproto *ofproto, uint32_t group_id,
                           struct ofgroup **group)
    OVS_TRY_WRLOCK(true, ofproto->groups_rwlock)
    OVS_TRY_WRLOCK(true, (*group)->rwlock)
{
    ovs_rwlock_wrlock(&ofproto->groups_rwlock);
    HMAP_FOR_EACH_IN_BUCKET (*group, hmap_node,
                             hash_int(group_id, 0), &ofproto->groups) {
        if ((*group)->group_id == group_id) {
            ovs_rwlock_wrlock(&(*group)->rwlock);
            return true;
        }
    }
    ovs_rwlock_unlock(&ofproto->groups_rwlock);
    return false;
}

static bool
ofproto_group_exists__(const struct ofproto *ofproto, uint32_t group_id)
    OVS_REQ_RDLOCK(ofproto->groups_rwlock)
{
    struct ofgroup *grp;

    HMAP_FOR_EACH_IN_BUCKET (grp, hmap_node,
                             hash_int(group_id, 0), &ofproto->groups) {
        if (grp->group_id == group_id) {
            return true;
        }
    }
    return false;
}

static bool
ofproto_group_exists(const struct ofproto *ofproto, uint32_t group_id)
    OVS_EXCLUDED(ofproto->groups_rwlock)
{
    bool exists;

    ovs_rwlock_rdlock(&ofproto->groups_rwlock);
    exists = ofproto_group_exists__(ofproto, group_id);
    ovs_rwlock_unlock(&ofproto->groups_rwlock);

    return exists;
}

static uint32_t
group_get_ref_count(struct ofgroup *group)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto *ofproto = group->ofproto;
    struct rule_criteria criteria;
    struct rule_collection rules;
    struct match match;
    enum ofperr error;
    uint32_t count;

    match_init_catchall(&match);
    rule_criteria_init(&criteria, 0xff, &match, 0, htonll(0), htonll(0),
                       OFPP_ANY, group->group_id);
    ovs_mutex_lock(&ofproto_mutex);
    error = collect_rules_loose(ofproto, &criteria, &rules);
    ovs_mutex_unlock(&ofproto_mutex);
    rule_criteria_destroy(&criteria);

    count = !error && rules.n < UINT32_MAX ? rules.n : UINT32_MAX;

    rule_collection_destroy(&rules);
    return count;
}

static void
append_group_stats(struct ofgroup *group, struct list *replies)
    OVS_REQ_RDLOCK(group->rwlock)
{
    struct ofputil_group_stats ogs;
    struct ofproto *ofproto = group->ofproto;
    long long int now = time_msec();
    int error;

    ogs.bucket_stats = xmalloc(group->n_buckets * sizeof *ogs.bucket_stats);

    /* Provider sets the packet and byte counts, we do the rest. */
    ogs.ref_count = group_get_ref_count(group);
    ogs.n_buckets = group->n_buckets;

    error = (ofproto->ofproto_class->group_get_stats
             ? ofproto->ofproto_class->group_get_stats(group, &ogs)
             : EOPNOTSUPP);
    if (error) {
        ogs.packet_count = UINT64_MAX;
        ogs.byte_count = UINT64_MAX;
        memset(ogs.bucket_stats, 0xff,
               ogs.n_buckets * sizeof *ogs.bucket_stats);
    }

    ogs.group_id = group->group_id;
    calc_duration(group->created, now, &ogs.duration_sec, &ogs.duration_nsec);

    ofputil_append_group_stats(replies, &ogs);

    free(ogs.bucket_stats);
}

static enum ofperr
handle_group_stats_request(struct ofconn *ofconn,
                           const struct ofp_header *request)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct list replies;
    enum ofperr error;
    struct ofgroup *group;
    uint32_t group_id;

    error = ofputil_decode_group_stats_request(request, &group_id);
    if (error) {
        return error;
    }

    ofpmp_init(&replies, request);

    if (group_id == OFPG_ALL) {
        ovs_rwlock_rdlock(&ofproto->groups_rwlock);
        HMAP_FOR_EACH (group, hmap_node, &ofproto->groups) {
            ovs_rwlock_rdlock(&group->rwlock);
            append_group_stats(group, &replies);
            ovs_rwlock_unlock(&group->rwlock);
        }
        ovs_rwlock_unlock(&ofproto->groups_rwlock);
    } else {
        if (ofproto_group_lookup(ofproto, group_id, &group)) {
            append_group_stats(group, &replies);
            ofproto_group_release(group);
        }
    }

    ofconn_send_replies(ofconn, &replies);

    return 0;
}

static enum ofperr
handle_group_desc_stats_request(struct ofconn *ofconn,
                                const struct ofp_header *request)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct list replies;
    struct ofputil_group_desc gds;
    struct ofgroup *group;

    ofpmp_init(&replies, request);

    ovs_rwlock_rdlock(&ofproto->groups_rwlock);
    HMAP_FOR_EACH (group, hmap_node, &ofproto->groups) {
        gds.group_id = group->group_id;
        gds.type = group->type;
        ofputil_append_group_desc_reply(&gds, &group->buckets, &replies);
    }
    ovs_rwlock_unlock(&ofproto->groups_rwlock);

    ofconn_send_replies(ofconn, &replies);

    return 0;
}

static enum ofperr
handle_group_features_stats_request(struct ofconn *ofconn,
                                    const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofpbuf *msg;

    msg = ofputil_encode_group_features_reply(&p->ogf, request);
    if (msg) {
        ofconn_send_reply(ofconn, msg);
    }

    return 0;
}

static enum ofperr
handle_queue_get_config_request(struct ofconn *ofconn,
                                const struct ofp_header *oh)
{
   struct ofproto *p = ofconn_get_ofproto(ofconn);
   struct netdev_queue_dump queue_dump;
   struct ofport *ofport;
   unsigned int queue_id;
   struct ofpbuf *reply;
   struct smap details;
   ofp_port_t request;
   enum ofperr error;

   error = ofputil_decode_queue_get_config_request(oh, &request);
   if (error) {
       return error;
   }

   ofport = ofproto_get_port(p, request);
   if (!ofport) {
      return OFPERR_OFPQOFC_BAD_PORT;
   }

   reply = ofputil_encode_queue_get_config_reply(oh);

   smap_init(&details);
   NETDEV_QUEUE_FOR_EACH (&queue_id, &details, &queue_dump, ofport->netdev) {
       struct ofputil_queue_config queue;

       /* None of the existing queues have compatible properties, so we
        * hard-code omitting min_rate and max_rate. */
       queue.queue_id = queue_id;
       queue.min_rate = UINT16_MAX;
       queue.max_rate = UINT16_MAX;
       ofputil_append_queue_get_config_reply(reply, &queue);
   }
   smap_destroy(&details);

   ofconn_send_reply(ofconn, reply);

   return 0;
}

/* Implements OFPGC11_ADD
 * in which no matching flow already exists in the flow table.
 *
 * Adds the flow specified by 'ofm', which is followed by 'n_actions'
 * ofp_actions, to the ofproto's flow table.  Returns 0 on success, an OpenFlow
 * error code on failure, or OFPROTO_POSTPONE if the operation cannot be
 * initiated now but may be retried later.
 *
 * Upon successful return, takes ownership of 'fm->ofpacts'.  On failure,
 * ownership remains with the caller.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static enum ofperr
add_group(struct ofproto *ofproto, struct ofputil_group_mod *gm)
{
    struct ofgroup *ofgroup;
    enum ofperr error;

    if (gm->group_id > OFPG_MAX) {
        return OFPERR_OFPGMFC_INVALID_GROUP;
    }
    if (gm->type > OFPGT11_FF) {
        return OFPERR_OFPGMFC_BAD_TYPE;
    }

    /* Allocate new group and initialize it. */
    ofgroup = ofproto->ofproto_class->group_alloc();
    if (!ofgroup) {
        VLOG_WARN_RL(&rl, "%s: failed to create group", ofproto->name);
        return OFPERR_OFPGMFC_OUT_OF_GROUPS;
    }

    ovs_rwlock_init(&ofgroup->rwlock);
    ofgroup->ofproto  = ofproto;
    ofgroup->group_id = gm->group_id;
    ofgroup->type     = gm->type;
    ofgroup->created = ofgroup->modified = time_msec();

    list_move(&ofgroup->buckets, &gm->buckets);
    ofgroup->n_buckets = list_size(&ofgroup->buckets);

    /* Construct called BEFORE any locks are held. */
    error = ofproto->ofproto_class->group_construct(ofgroup);
    if (error) {
        goto free_out;
    }

    /* We wrlock as late as possible to minimize the time we jam any other
     * threads: No visible state changes before acquiring the lock. */
    ovs_rwlock_wrlock(&ofproto->groups_rwlock);

    if (ofproto->n_groups[gm->type] >= ofproto->ogf.max_groups[gm->type]) {
        error = OFPERR_OFPGMFC_OUT_OF_GROUPS;
        goto unlock_out;
    }

    if (ofproto_group_exists__(ofproto, gm->group_id)) {
        error = OFPERR_OFPGMFC_GROUP_EXISTS;
        goto unlock_out;
    }

    if (!error) {
        /* Insert new group. */
        hmap_insert(&ofproto->groups, &ofgroup->hmap_node,
                    hash_int(ofgroup->group_id, 0));
        ofproto->n_groups[ofgroup->type]++;

        ovs_rwlock_unlock(&ofproto->groups_rwlock);
        return error;
    }

 unlock_out:
    ovs_rwlock_unlock(&ofproto->groups_rwlock);
    ofproto->ofproto_class->group_destruct(ofgroup);
 free_out:
    ofputil_bucket_list_destroy(&ofgroup->buckets);
    ofproto->ofproto_class->group_dealloc(ofgroup);

    return error;
}

/* Implements OFPFC_MODIFY.  Returns 0 on success or an OpenFlow error code on
 * failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any. */
static enum ofperr
modify_group(struct ofproto *ofproto, struct ofputil_group_mod *gm)
{
    struct ofgroup *ofgroup;
    struct ofgroup *victim;
    enum ofperr error;

    if (gm->group_id > OFPG_MAX) {
        return OFPERR_OFPGMFC_INVALID_GROUP;
    }

    if (gm->type > OFPGT11_FF) {
        return OFPERR_OFPGMFC_BAD_TYPE;
    }

    victim = ofproto->ofproto_class->group_alloc();
    if (!victim) {
        VLOG_WARN_RL(&rl, "%s: failed to allocate group", ofproto->name);
        return OFPERR_OFPGMFC_OUT_OF_GROUPS;
    }

    if (!ofproto_group_write_lookup(ofproto, gm->group_id, &ofgroup)) {
        error = OFPERR_OFPGMFC_UNKNOWN_GROUP;
        goto free_out;
    }
    /* Both group's and its container's write locks held now.
     * Also, n_groups[] is protected by ofproto->groups_rwlock. */
    if (ofgroup->type != gm->type
        && ofproto->n_groups[gm->type] >= ofproto->ogf.max_groups[gm->type]) {
        error = OFPERR_OFPGMFC_OUT_OF_GROUPS;
        goto unlock_out;
    }

    *victim = *ofgroup;
    list_move(&victim->buckets, &ofgroup->buckets);

    ofgroup->type = gm->type;
    list_move(&ofgroup->buckets, &gm->buckets);
    ofgroup->n_buckets = list_size(&ofgroup->buckets);

    error = ofproto->ofproto_class->group_modify(ofgroup, victim);
    if (!error) {
        ofputil_bucket_list_destroy(&victim->buckets);
        ofproto->n_groups[victim->type]--;
        ofproto->n_groups[ofgroup->type]++;
        ofgroup->modified = time_msec();
    } else {
        ofputil_bucket_list_destroy(&ofgroup->buckets);

        *ofgroup = *victim;
        list_move(&ofgroup->buckets, &victim->buckets);
    }

 unlock_out:
    ovs_rwlock_unlock(&ofgroup->rwlock);
    ovs_rwlock_unlock(&ofproto->groups_rwlock);
 free_out:
    ofproto->ofproto_class->group_dealloc(victim);
    return error;
}

static void
delete_group__(struct ofproto *ofproto, struct ofgroup *ofgroup)
    OVS_RELEASES(ofproto->groups_rwlock)
{
    struct match match;
    struct ofputil_flow_mod fm;

    /* Delete all flow entries containing this group in a group action */
    match_init_catchall(&match);
    flow_mod_init(&fm, &match, 0, NULL, 0, OFPFC_DELETE);
    fm.out_group = ofgroup->group_id;
    handle_flow_mod__(ofproto, NULL, &fm, NULL);

    /* Must wait until existing readers are done,
     * while holding the container's write lock at the same time. */
    ovs_rwlock_wrlock(&ofgroup->rwlock);
    hmap_remove(&ofproto->groups, &ofgroup->hmap_node);
    /* No-one can find this group any more. */
    ofproto->n_groups[ofgroup->type]--;
    ovs_rwlock_unlock(&ofproto->groups_rwlock);

    ofproto->ofproto_class->group_destruct(ofgroup);
    ofputil_bucket_list_destroy(&ofgroup->buckets);
    ovs_rwlock_unlock(&ofgroup->rwlock);
    ovs_rwlock_destroy(&ofgroup->rwlock);
    ofproto->ofproto_class->group_dealloc(ofgroup);
}

/* Implements OFPGC_DELETE. */
static void
delete_group(struct ofproto *ofproto, uint32_t group_id)
{
    struct ofgroup *ofgroup;

    ovs_rwlock_wrlock(&ofproto->groups_rwlock);
    if (group_id == OFPG_ALL) {
        for (;;) {
            struct hmap_node *node = hmap_first(&ofproto->groups);
            if (!node) {
                break;
            }
            ofgroup = CONTAINER_OF(node, struct ofgroup, hmap_node);
            delete_group__(ofproto, ofgroup);
            /* Lock for each node separately, so that we will not jam the
             * other threads for too long time. */
            ovs_rwlock_wrlock(&ofproto->groups_rwlock);
        }
    } else {
        HMAP_FOR_EACH_IN_BUCKET (ofgroup, hmap_node,
                                 hash_int(group_id, 0), &ofproto->groups) {
            if (ofgroup->group_id == group_id) {
                delete_group__(ofproto, ofgroup);
                return;
            }
        }
    }
    ovs_rwlock_unlock(&ofproto->groups_rwlock);
}

static enum ofperr
handle_group_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_group_mod gm;
    enum ofperr error;

    error = reject_slave_controller(ofconn);
    if (error) {
        return error;
    }

    error = ofputil_decode_group_mod(oh, &gm);
    if (error) {
        return error;
    }

    switch (gm.command) {
    case OFPGC11_ADD:
        return add_group(ofproto, &gm);

    case OFPGC11_MODIFY:
        return modify_group(ofproto, &gm);

    case OFPGC11_DELETE:
        delete_group(ofproto, gm.group_id);
        return 0;

    default:
        if (gm.command > OFPGC11_DELETE) {
            VLOG_WARN_RL(&rl, "%s: Invalid group_mod command type %d",
                         ofproto->name, gm.command);
        }
        return OFPERR_OFPGMFC_BAD_COMMAND;
    }
}

static enum ofperr
table_mod(struct ofproto *ofproto, const struct ofputil_table_mod *tm)
{
    /* XXX Reject all configurations because none are currently supported */
    return OFPERR_OFPTMFC_BAD_CONFIG;

    if (tm->table_id == OFPTT_ALL) {
        int i;
        for (i = 0; i < ofproto->n_tables; i++) {
            atomic_store(&ofproto->tables[i].config,
                         (unsigned int)tm->config);
        }
    } else if (!check_table_id(ofproto, tm->table_id)) {
        return OFPERR_OFPTMFC_BAD_TABLE;
    } else {
        atomic_store(&ofproto->tables[tm->table_id].config,
                     (unsigned int)tm->config);
    }

    return 0;
}

static enum ofperr
handle_table_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_table_mod tm;
    enum ofperr error;

    error = reject_slave_controller(ofconn);
    if (error) {
        return error;
    }

    error = ofputil_decode_table_mod(oh, &tm);
    if (error) {
        return error;
    }

    return table_mod(ofproto, &tm);
}

static enum ofperr
handle_openflow__(struct ofconn *ofconn, const struct ofpbuf *msg)
    OVS_EXCLUDED(ofproto_mutex)
{
    const struct ofp_header *oh = msg->data;
    enum ofptype type;
    enum ofperr error;

    error = ofptype_decode(&type, oh);
    if (error) {
        return error;
    }
    if (oh->version >= OFP13_VERSION && ofpmsg_is_stat_request(oh)
        && ofpmp_more(oh)) {
        /* We have no buffer implementation for multipart requests.
         * Report overflow for requests which consists of multiple
         * messages. */
        return OFPERR_OFPBRC_MULTIPART_BUFFER_OVERFLOW;
    }

    switch (type) {
        /* OpenFlow requests. */
    case OFPTYPE_ECHO_REQUEST:
        return handle_echo_request(ofconn, oh);

    case OFPTYPE_FEATURES_REQUEST:
        return handle_features_request(ofconn, oh);

    case OFPTYPE_GET_CONFIG_REQUEST:
        return handle_get_config_request(ofconn, oh);

    case OFPTYPE_SET_CONFIG:
        return handle_set_config(ofconn, oh);

    case OFPTYPE_PACKET_OUT:
        return handle_packet_out(ofconn, oh);

    case OFPTYPE_PORT_MOD:
        return handle_port_mod(ofconn, oh);

    case OFPTYPE_FLOW_MOD:
        return handle_flow_mod(ofconn, oh);

    case OFPTYPE_GROUP_MOD:
        return handle_group_mod(ofconn, oh);

    case OFPTYPE_TABLE_MOD:
        return handle_table_mod(ofconn, oh);

    case OFPTYPE_METER_MOD:
        return handle_meter_mod(ofconn, oh);

    case OFPTYPE_BARRIER_REQUEST:
        return handle_barrier_request(ofconn, oh);

    case OFPTYPE_ROLE_REQUEST:
        return handle_role_request(ofconn, oh);

        /* OpenFlow replies. */
    case OFPTYPE_ECHO_REPLY:
        return 0;

        /* Nicira extension requests. */
    case OFPTYPE_FLOW_MOD_TABLE_ID:
        return handle_nxt_flow_mod_table_id(ofconn, oh);

    case OFPTYPE_SET_FLOW_FORMAT:
        return handle_nxt_set_flow_format(ofconn, oh);

    case OFPTYPE_SET_PACKET_IN_FORMAT:
        return handle_nxt_set_packet_in_format(ofconn, oh);

    case OFPTYPE_SET_CONTROLLER_ID:
        return handle_nxt_set_controller_id(ofconn, oh);

    case OFPTYPE_FLOW_AGE:
        /* Nothing to do. */
        return 0;

    case OFPTYPE_FLOW_MONITOR_CANCEL:
        return handle_flow_monitor_cancel(ofconn, oh);

    case OFPTYPE_SET_ASYNC_CONFIG:
        return handle_nxt_set_async_config(ofconn, oh);

    case OFPTYPE_GET_ASYNC_REQUEST:
        return handle_nxt_get_async_request(ofconn, oh);

        /* Statistics requests. */
    case OFPTYPE_DESC_STATS_REQUEST:
        return handle_desc_stats_request(ofconn, oh);

    case OFPTYPE_FLOW_STATS_REQUEST:
        return handle_flow_stats_request(ofconn, oh);

    case OFPTYPE_AGGREGATE_STATS_REQUEST:
        return handle_aggregate_stats_request(ofconn, oh);

    case OFPTYPE_TABLE_STATS_REQUEST:
        return handle_table_stats_request(ofconn, oh);

    case OFPTYPE_PORT_STATS_REQUEST:
        return handle_port_stats_request(ofconn, oh);

    case OFPTYPE_QUEUE_STATS_REQUEST:
        return handle_queue_stats_request(ofconn, oh);

    case OFPTYPE_PORT_DESC_STATS_REQUEST:
        return handle_port_desc_stats_request(ofconn, oh);

    case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
        return handle_flow_monitor_request(ofconn, oh);

    case OFPTYPE_METER_STATS_REQUEST:
    case OFPTYPE_METER_CONFIG_STATS_REQUEST:
        return handle_meter_request(ofconn, oh, type);

    case OFPTYPE_METER_FEATURES_STATS_REQUEST:
        return handle_meter_features_request(ofconn, oh);

    case OFPTYPE_GROUP_STATS_REQUEST:
        return handle_group_stats_request(ofconn, oh);

    case OFPTYPE_GROUP_DESC_STATS_REQUEST:
        return handle_group_desc_stats_request(ofconn, oh);

    case OFPTYPE_GROUP_FEATURES_STATS_REQUEST:
        return handle_group_features_stats_request(ofconn, oh);

    case OFPTYPE_QUEUE_GET_CONFIG_REQUEST:
        return handle_queue_get_config_request(ofconn, oh);

    case OFPTYPE_HELLO:
    case OFPTYPE_ERROR:
    case OFPTYPE_FEATURES_REPLY:
    case OFPTYPE_GET_CONFIG_REPLY:
    case OFPTYPE_PACKET_IN:
    case OFPTYPE_FLOW_REMOVED:
    case OFPTYPE_PORT_STATUS:
    case OFPTYPE_BARRIER_REPLY:
    case OFPTYPE_QUEUE_GET_CONFIG_REPLY:
    case OFPTYPE_DESC_STATS_REPLY:
    case OFPTYPE_FLOW_STATS_REPLY:
    case OFPTYPE_QUEUE_STATS_REPLY:
    case OFPTYPE_PORT_STATS_REPLY:
    case OFPTYPE_TABLE_STATS_REPLY:
    case OFPTYPE_AGGREGATE_STATS_REPLY:
    case OFPTYPE_PORT_DESC_STATS_REPLY:
    case OFPTYPE_ROLE_REPLY:
    case OFPTYPE_FLOW_MONITOR_PAUSED:
    case OFPTYPE_FLOW_MONITOR_RESUMED:
    case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
    case OFPTYPE_GET_ASYNC_REPLY:
    case OFPTYPE_GROUP_STATS_REPLY:
    case OFPTYPE_GROUP_DESC_STATS_REPLY:
    case OFPTYPE_GROUP_FEATURES_STATS_REPLY:
    case OFPTYPE_METER_STATS_REPLY:
    case OFPTYPE_METER_CONFIG_STATS_REPLY:
    case OFPTYPE_METER_FEATURES_STATS_REPLY:
    case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
    case OFPTYPE_TABLE_FEATURES_STATS_REPLY:
    case OFPTYPE_ROLE_STATUS:
    default:
        if (ofpmsg_is_stat_request(oh)) {
            return OFPERR_OFPBRC_BAD_STAT;
        } else {
            return OFPERR_OFPBRC_BAD_TYPE;
        }
    }
}

static bool
handle_openflow(struct ofconn *ofconn, const struct ofpbuf *ofp_msg)
    OVS_EXCLUDED(ofproto_mutex)
{
    int error = handle_openflow__(ofconn, ofp_msg);
    if (error && error != OFPROTO_POSTPONE) {
        ofconn_send_error(ofconn, ofp_msg->data, error);
    }
    COVERAGE_INC(ofproto_recv_openflow);
    return error != OFPROTO_POSTPONE;
}

/* Asynchronous operations. */

/* Creates and returns a new ofopgroup that is not associated with any
 * OpenFlow connection.
 *
 * The caller should add operations to the returned group with
 * ofoperation_create() and then submit it with ofopgroup_submit(). */
static struct ofopgroup *
ofopgroup_create_unattached(struct ofproto *ofproto)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofopgroup *group = xzalloc(sizeof *group);
    group->ofproto = ofproto;
    list_init(&group->ofproto_node);
    list_init(&group->ops);
    list_init(&group->ofconn_node);
    return group;
}

/* Creates and returns a new ofopgroup for 'ofproto'.
 *
 * If 'ofconn' is NULL, the new ofopgroup is not associated with any OpenFlow
 * connection.  The 'request' and 'buffer_id' arguments are ignored.
 *
 * If 'ofconn' is nonnull, then the new ofopgroup is associated with 'ofconn'.
 * If the ofopgroup eventually fails, then the error reply will include
 * 'request'.  If the ofopgroup eventually succeeds, then the packet with
 * buffer id 'buffer_id' on 'ofconn' will be sent by 'ofconn''s ofproto.
 *
 * The caller should add operations to the returned group with
 * ofoperation_create() and then submit it with ofopgroup_submit(). */
static struct ofopgroup *
ofopgroup_create(struct ofproto *ofproto, struct ofconn *ofconn,
                 const struct ofp_header *request, uint32_t buffer_id)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofopgroup *group = ofopgroup_create_unattached(ofproto);
    if (ofconn) {
        size_t request_len = ntohs(request->length);

        ovs_assert(ofconn_get_ofproto(ofconn) == ofproto);

        ofconn_add_opgroup(ofconn, &group->ofconn_node);
        group->ofconn = ofconn;
        group->request = xmemdup(request, MIN(request_len, 64));
        group->buffer_id = buffer_id;
    }
    return group;
}

/* Submits 'group' for processing.
 *
 * If 'group' contains no operations (e.g. none were ever added, or all of the
 * ones that were added completed synchronously), then it is destroyed
 * immediately.  Otherwise it is added to the ofproto's list of pending
 * groups. */
static void
ofopgroup_submit(struct ofopgroup *group)
    OVS_REQUIRES(ofproto_mutex)
{
    if (!group->n_running) {
        ofopgroup_complete(group);
    } else {
        list_push_back(&group->ofproto->pending, &group->ofproto_node);
        group->ofproto->n_pending++;
    }
}

static void
ofopgroup_complete(struct ofopgroup *group)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto *ofproto = group->ofproto;

    struct ofconn *abbrev_ofconn;
    ovs_be32 abbrev_xid;

    struct ofoperation *op, *next_op;
    int error;

    ovs_assert(!group->n_running);

    error = 0;
    LIST_FOR_EACH (op, group_node, &group->ops) {
        if (op->error) {
            error = op->error;
            break;
        }
    }

    if (!error && group->ofconn && group->buffer_id != UINT32_MAX) {
        LIST_FOR_EACH (op, group_node, &group->ops) {
            if (op->type != OFOPERATION_DELETE) {
                struct ofpbuf *packet;
                ofp_port_t in_port;

                error = ofconn_pktbuf_retrieve(group->ofconn, group->buffer_id,
                                               &packet, &in_port);
                if (packet) {
                    struct rule_execute *re;

                    ovs_assert(!error);

                    ofproto_rule_ref(op->rule);

                    re = xmalloc(sizeof *re);
                    re->rule = op->rule;
                    re->in_port = in_port;
                    re->packet = packet;

                    if (!guarded_list_push_back(&ofproto->rule_executes,
                                                &re->list_node, 1024)) {
                        ofproto_rule_unref(op->rule);
                        ofpbuf_delete(re->packet);
                        free(re);
                    }
                }
                break;
            }
        }
    }

    if (!error && !list_is_empty(&group->ofconn_node)) {
        abbrev_ofconn = group->ofconn;
        abbrev_xid = group->request->xid;
    } else {
        abbrev_ofconn = NULL;
        abbrev_xid = htonl(0);
    }
    LIST_FOR_EACH_SAFE (op, next_op, group_node, &group->ops) {
        struct rule *rule = op->rule;

        /* We generally want to report the change to active OpenFlow flow
           monitors (e.g. NXST_FLOW_MONITOR).  There are three exceptions:

              - The operation failed.

              - The affected rule is not visible to controllers.

              - The operation's only effect was to update rule->modified. */
        if (!(op->error
              || ofproto_rule_is_hidden(rule)
              || (op->type == OFOPERATION_MODIFY
                  && op->actions
                  && rule->flow_cookie == op->flow_cookie))) {
            /* Check that we can just cast from ofoperation_type to
             * nx_flow_update_event. */
            enum nx_flow_update_event event_type;

            switch (op->type) {
            case OFOPERATION_ADD:
            case OFOPERATION_REPLACE:
                event_type = NXFME_ADDED;
                break;

            case OFOPERATION_DELETE:
                event_type = NXFME_DELETED;
                break;

            case OFOPERATION_MODIFY:
                event_type = NXFME_MODIFIED;
                break;

            default:
                OVS_NOT_REACHED();
            }

            ofmonitor_report(ofproto->connmgr, rule, event_type,
                             op->reason, abbrev_ofconn, abbrev_xid);
        }

        rule->pending = NULL;

        switch (op->type) {
        case OFOPERATION_ADD:
            if (!op->error) {
                uint16_t vid_mask;

                vid_mask = minimask_get_vid_mask(&rule->cr.match.mask);
                if (vid_mask == VLAN_VID_MASK) {
                    if (ofproto->vlan_bitmap) {
                        uint16_t vid = miniflow_get_vid(&rule->cr.match.flow);
                        if (!bitmap_is_set(ofproto->vlan_bitmap, vid)) {
                            bitmap_set1(ofproto->vlan_bitmap, vid);
                            ofproto->vlans_changed = true;
                        }
                    } else {
                        ofproto->vlans_changed = true;
                    }
                }
            } else {
                oftable_remove_rule(rule);
                ofproto_rule_unref(rule);
            }
            break;

        case OFOPERATION_DELETE:
            ovs_assert(!op->error);
            ofproto_rule_unref(rule);
            op->rule = NULL;
            break;

        case OFOPERATION_MODIFY:
        case OFOPERATION_REPLACE:
            if (!op->error) {
                long long int now = time_msec();

                rule->modified = now;
                if (op->type == OFOPERATION_REPLACE) {
                    rule->created = rule->used = now;
                }
            } else {
                ofproto_rule_change_cookie(ofproto, rule, op->flow_cookie);
                ovs_mutex_lock(&rule->mutex);
                rule->idle_timeout = op->idle_timeout;
                rule->hard_timeout = op->hard_timeout;
                ovs_mutex_unlock(&rule->mutex);
                if (op->actions) {
                    struct rule_actions *old_actions;

                    ovs_mutex_lock(&rule->mutex);
                    old_actions = rule->actions;
                    rule->actions = op->actions;
                    ovs_mutex_unlock(&rule->mutex);

                    op->actions = NULL;
                    rule_actions_unref(old_actions);
                }
                rule->flags = op->flags;
            }
            break;

        default:
            OVS_NOT_REACHED();
        }

        ofoperation_destroy(op);
    }

    ofmonitor_flush(ofproto->connmgr);

    if (!list_is_empty(&group->ofproto_node)) {
        ovs_assert(ofproto->n_pending > 0);
        ofproto->n_pending--;
        list_remove(&group->ofproto_node);
    }
    if (!list_is_empty(&group->ofconn_node)) {
        list_remove(&group->ofconn_node);
        if (error) {
            ofconn_send_error(group->ofconn, group->request, error);
        }
        connmgr_retry(ofproto->connmgr);
    }
    free(group->request);
    free(group);
}

/* Initiates a new operation on 'rule', of the specified 'type', within
 * 'group'.  Prior to calling, 'rule' must not have any pending operation.
 *
 * For a 'type' of OFOPERATION_DELETE, 'reason' should specify the reason that
 * the flow is being deleted.  For other 'type's, 'reason' is ignored (use 0).
 *
 * Returns the newly created ofoperation (which is also available as
 * rule->pending). */
static struct ofoperation *
ofoperation_create(struct ofopgroup *group, struct rule *rule,
                   enum ofoperation_type type,
                   enum ofp_flow_removed_reason reason)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto *ofproto = group->ofproto;
    struct ofoperation *op;

    ovs_assert(!rule->pending);

    op = rule->pending = xzalloc(sizeof *op);
    op->group = group;
    list_push_back(&group->ops, &op->group_node);
    op->rule = rule;
    op->type = type;
    op->reason = reason;
    op->flow_cookie = rule->flow_cookie;
    ovs_mutex_lock(&rule->mutex);
    op->idle_timeout = rule->idle_timeout;
    op->hard_timeout = rule->hard_timeout;
    ovs_mutex_unlock(&rule->mutex);
    op->flags = rule->flags;

    group->n_running++;

    if (type == OFOPERATION_DELETE) {
        hmap_insert(&ofproto->deletions, &op->hmap_node,
                    cls_rule_hash(&rule->cr, rule->table_id));
    }

    return op;
}

static void
ofoperation_destroy(struct ofoperation *op)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofopgroup *group = op->group;

    if (op->rule) {
        op->rule->pending = NULL;
    }
    if (op->type == OFOPERATION_DELETE) {
        hmap_remove(&group->ofproto->deletions, &op->hmap_node);
    }
    list_remove(&op->group_node);
    rule_actions_unref(op->actions);
    free(op);
}

/* Indicates that 'op' completed with status 'error', which is either 0 to
 * indicate success or an OpenFlow error code on failure.
 *
 * If 'error' is 0, indicating success, the operation will be committed
 * permanently to the flow table.
 *
 * If 'error' is nonzero, then generally the operation will be rolled back:
 *
 *   - If 'op' is an "add flow" operation, ofproto removes the new rule or
 *     restores the original rule.  The caller must have uninitialized any
 *     derived state in the new rule, as in step 5 of in the "Life Cycle" in
 *     ofproto/ofproto-provider.h.  ofoperation_complete() performs steps 6 and
 *     and 7 for the new rule, calling its ->rule_dealloc() function.
 *
 *   - If 'op' is a "modify flow" operation, ofproto restores the original
 *     actions.
 *
 *   - 'op' must not be a "delete flow" operation.  Removing a rule is not
 *     allowed to fail.  It must always succeed.
 *
 * Please see the large comment in ofproto/ofproto-provider.h titled
 * "Asynchronous Operation Support" for more information. */
void
ofoperation_complete(struct ofoperation *op, enum ofperr error)
{
    struct ofopgroup *group = op->group;

    ovs_assert(group->n_running > 0);
    ovs_assert(!error || op->type != OFOPERATION_DELETE);

    op->error = error;
    if (!--group->n_running && !list_is_empty(&group->ofproto_node)) {
        /* This function can be called from ->rule_construct(), in which case
         * ofproto_mutex is held, or it can be called from ->run(), in which
         * case ofproto_mutex is not held.  But only in the latter case can we
         * arrive here, so we can safely take ofproto_mutex now. */
        ovs_mutex_lock(&ofproto_mutex);
        ovs_assert(op->rule->pending == op);
        ofopgroup_complete(group);
        ovs_mutex_unlock(&ofproto_mutex);
    }
}

static uint64_t
pick_datapath_id(const struct ofproto *ofproto)
{
    const struct ofport *port;

    port = ofproto_get_port(ofproto, OFPP_LOCAL);
    if (port) {
        uint8_t ea[ETH_ADDR_LEN];
        int error;

        error = netdev_get_etheraddr(port->netdev, ea);
        if (!error) {
            return eth_addr_to_uint64(ea);
        }
        VLOG_WARN("%s: could not get MAC address for %s (%s)",
                  ofproto->name, netdev_get_name(port->netdev),
                  ovs_strerror(error));
    }
    return ofproto->fallback_dpid;
}

static uint64_t
pick_fallback_dpid(void)
{
    uint8_t ea[ETH_ADDR_LEN];
    eth_addr_nicira_random(ea);
    return eth_addr_to_uint64(ea);
}

/* Table overflow policy. */

/* Chooses and updates 'rulep' with a rule to evict from 'table'.  Sets 'rulep'
 * to NULL if the table is not configured to evict rules or if the table
 * contains no evictable rules.  (Rules with a readlock on their evict rwlock,
 * or with no timeouts are not evictable.) */
static bool
choose_rule_to_evict(struct oftable *table, struct rule **rulep)
    OVS_REQUIRES(ofproto_mutex)
{
    struct eviction_group *evg;

    *rulep = NULL;
    if (!table->eviction_fields) {
        return false;
    }

    /* In the common case, the outer and inner loops here will each be entered
     * exactly once:
     *
     *   - The inner loop normally "return"s in its first iteration.  If the
     *     eviction group has any evictable rules, then it always returns in
     *     some iteration.
     *
     *   - The outer loop only iterates more than once if the largest eviction
     *     group has no evictable rules.
     *
     *   - The outer loop can exit only if table's 'max_flows' is all filled up
     *     by unevictable rules. */
    HEAP_FOR_EACH (evg, size_node, &table->eviction_groups_by_size) {
        struct rule *rule;

        HEAP_FOR_EACH (rule, evg_node, &evg->rules) {
            *rulep = rule;
            return true;
        }
    }

    return false;
}

/* Searches 'ofproto' for tables that have more flows than their configured
 * maximum and that have flow eviction enabled, and evicts as many flows as
 * necessary and currently feasible from them.
 *
 * This triggers only when an OpenFlow table has N flows in it and then the
 * client configures a maximum number of flows less than N. */
static void
ofproto_evict(struct ofproto *ofproto)
{
    struct oftable *table;

    ovs_mutex_lock(&ofproto_mutex);
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        evict_rules_from_table(ofproto, table, 0);
    }
    ovs_mutex_unlock(&ofproto_mutex);
}

/* Eviction groups. */

/* Returns the priority to use for an eviction_group that contains 'n_rules'
 * rules.  The priority contains low-order random bits to ensure that eviction
 * groups with the same number of rules are prioritized randomly. */
static uint32_t
eviction_group_priority(size_t n_rules)
{
    uint16_t size = MIN(UINT16_MAX, n_rules);
    return (size << 16) | random_uint16();
}

/* Updates 'evg', an eviction_group within 'table', following a change that
 * adds or removes rules in 'evg'. */
static void
eviction_group_resized(struct oftable *table, struct eviction_group *evg)
    OVS_REQUIRES(ofproto_mutex)
{
    heap_change(&table->eviction_groups_by_size, &evg->size_node,
                eviction_group_priority(heap_count(&evg->rules)));
}

/* Destroys 'evg', an eviction_group within 'table':
 *
 *   - Removes all the rules, if any, from 'evg'.  (It doesn't destroy the
 *     rules themselves, just removes them from the eviction group.)
 *
 *   - Removes 'evg' from 'table'.
 *
 *   - Frees 'evg'. */
static void
eviction_group_destroy(struct oftable *table, struct eviction_group *evg)
    OVS_REQUIRES(ofproto_mutex)
{
    while (!heap_is_empty(&evg->rules)) {
        struct rule *rule;

        rule = CONTAINER_OF(heap_pop(&evg->rules), struct rule, evg_node);
        rule->eviction_group = NULL;
    }
    hmap_remove(&table->eviction_groups_by_id, &evg->id_node);
    heap_remove(&table->eviction_groups_by_size, &evg->size_node);
    heap_destroy(&evg->rules);
    free(evg);
}

/* Removes 'rule' from its eviction group, if any. */
static void
eviction_group_remove_rule(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    if (rule->eviction_group) {
        struct oftable *table = &rule->ofproto->tables[rule->table_id];
        struct eviction_group *evg = rule->eviction_group;

        rule->eviction_group = NULL;
        heap_remove(&evg->rules, &rule->evg_node);
        if (heap_is_empty(&evg->rules)) {
            eviction_group_destroy(table, evg);
        } else {
            eviction_group_resized(table, evg);
        }
    }
}

/* Hashes the 'rule''s values for the eviction_fields of 'rule''s table, and
 * returns the hash value. */
static uint32_t
eviction_group_hash_rule(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table = &rule->ofproto->tables[rule->table_id];
    const struct mf_subfield *sf;
    struct flow flow;
    uint32_t hash;

    hash = table->eviction_group_id_basis;
    miniflow_expand(&rule->cr.match.flow, &flow);
    for (sf = table->eviction_fields;
         sf < &table->eviction_fields[table->n_eviction_fields];
         sf++)
    {
        if (mf_are_prereqs_ok(sf->field, &flow)) {
            union mf_value value;

            mf_get_value(sf->field, &flow, &value);
            if (sf->ofs) {
                bitwise_zero(&value, sf->field->n_bytes, 0, sf->ofs);
            }
            if (sf->ofs + sf->n_bits < sf->field->n_bytes * 8) {
                unsigned int start = sf->ofs + sf->n_bits;
                bitwise_zero(&value, sf->field->n_bytes, start,
                             sf->field->n_bytes * 8 - start);
            }
            hash = hash_bytes(&value, sf->field->n_bytes, hash);
        } else {
            hash = hash_int(hash, 0);
        }
    }

    return hash;
}

/* Returns an eviction group within 'table' with the given 'id', creating one
 * if necessary. */
static struct eviction_group *
eviction_group_find(struct oftable *table, uint32_t id)
    OVS_REQUIRES(ofproto_mutex)
{
    struct eviction_group *evg;

    HMAP_FOR_EACH_WITH_HASH (evg, id_node, id, &table->eviction_groups_by_id) {
        return evg;
    }

    evg = xmalloc(sizeof *evg);
    hmap_insert(&table->eviction_groups_by_id, &evg->id_node, id);
    heap_insert(&table->eviction_groups_by_size, &evg->size_node,
                eviction_group_priority(0));
    heap_init(&evg->rules);

    return evg;
}

/* Returns an eviction priority for 'rule'.  The return value should be
 * interpreted so that higher priorities make a rule more attractive candidates
 * for eviction. */
static uint32_t
rule_eviction_priority(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    long long int hard_expiration;
    long long int idle_expiration;
    long long int expiration;
    uint32_t expiration_offset;

    /* Calculate time of expiration. */
    ovs_mutex_lock(&rule->mutex);
    hard_expiration = (rule->hard_timeout
                       ? rule->modified + rule->hard_timeout * 1000
                       : LLONG_MAX);
    idle_expiration = (rule->idle_timeout
                       ? rule->used + rule->idle_timeout * 1000
                       : LLONG_MAX);
    expiration = MIN(hard_expiration, idle_expiration);
    ovs_mutex_unlock(&rule->mutex);
    if (expiration == LLONG_MAX) {
        return 0;
    }

    /* Calculate the time of expiration as a number of (approximate) seconds
     * after program startup.
     *
     * This should work OK for program runs that last UINT32_MAX seconds or
     * less.  Therefore, please restart OVS at least once every 136 years. */
    expiration_offset = (expiration >> 10) - (time_boot_msec() >> 10);

    /* Invert the expiration offset because we're using a max-heap. */
    return UINT32_MAX - expiration_offset;
}

/* Adds 'rule' to an appropriate eviction group for its oftable's
 * configuration.  Does nothing if 'rule''s oftable doesn't have eviction
 * enabled, or if 'rule' is a permanent rule (one that will never expire on its
 * own).
 *
 * The caller must ensure that 'rule' is not already in an eviction group. */
static void
eviction_group_add_rule(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto *ofproto = rule->ofproto;
    struct oftable *table = &ofproto->tables[rule->table_id];
    bool has_timeout;

    ovs_mutex_lock(&rule->mutex);
    has_timeout = rule->hard_timeout || rule->idle_timeout;
    ovs_mutex_unlock(&rule->mutex);

    if (table->eviction_fields && has_timeout) {
        struct eviction_group *evg;

        evg = eviction_group_find(table, eviction_group_hash_rule(rule));

        rule->eviction_group = evg;
        heap_insert(&evg->rules, &rule->evg_node,
                    rule_eviction_priority(rule));
        eviction_group_resized(table, evg);
    }
}

/* oftables. */

/* Initializes 'table'. */
static void
oftable_init(struct oftable *table)
{
    memset(table, 0, sizeof *table);
    classifier_init(&table->cls, flow_segment_u32s);
    table->max_flows = UINT_MAX;
    atomic_init(&table->config, (unsigned int)OFPTC11_TABLE_MISS_CONTROLLER);
}

/* Destroys 'table', including its classifier and eviction groups.
 *
 * The caller is responsible for freeing 'table' itself. */
static void
oftable_destroy(struct oftable *table)
{
    fat_rwlock_rdlock(&table->cls.rwlock);
    ovs_assert(classifier_is_empty(&table->cls));
    fat_rwlock_unlock(&table->cls.rwlock);
    oftable_disable_eviction(table);
    classifier_destroy(&table->cls);
    free(table->name);
}

/* Changes the name of 'table' to 'name'.  If 'name' is NULL or the empty
 * string, then 'table' will use its default name.
 *
 * This only affects the name exposed for a table exposed through the OpenFlow
 * OFPST_TABLE (as printed by "ovs-ofctl dump-tables"). */
static void
oftable_set_name(struct oftable *table, const char *name)
{
    if (name && name[0]) {
        int len = strnlen(name, OFP_MAX_TABLE_NAME_LEN);
        if (!table->name || strncmp(name, table->name, len)) {
            free(table->name);
            table->name = xmemdup0(name, len);
        }
    } else {
        free(table->name);
        table->name = NULL;
    }
}

/* oftables support a choice of two policies when adding a rule would cause the
 * number of flows in the table to exceed the configured maximum number: either
 * they can refuse to add the new flow or they can evict some existing flow.
 * This function configures the former policy on 'table'. */
static void
oftable_disable_eviction(struct oftable *table)
    OVS_REQUIRES(ofproto_mutex)
{
    if (table->eviction_fields) {
        struct eviction_group *evg, *next;

        HMAP_FOR_EACH_SAFE (evg, next, id_node,
                            &table->eviction_groups_by_id) {
            eviction_group_destroy(table, evg);
        }
        hmap_destroy(&table->eviction_groups_by_id);
        heap_destroy(&table->eviction_groups_by_size);

        free(table->eviction_fields);
        table->eviction_fields = NULL;
        table->n_eviction_fields = 0;
    }
}

/* oftables support a choice of two policies when adding a rule would cause the
 * number of flows in the table to exceed the configured maximum number: either
 * they can refuse to add the new flow or they can evict some existing flow.
 * This function configures the latter policy on 'table', with fairness based
 * on the values of the 'n_fields' fields specified in 'fields'.  (Specifying
 * 'n_fields' as 0 disables fairness.) */
static void
oftable_enable_eviction(struct oftable *table,
                        const struct mf_subfield *fields, size_t n_fields)
    OVS_REQUIRES(ofproto_mutex)
{
    struct cls_cursor cursor;
    struct rule *rule;

    if (table->eviction_fields
        && n_fields == table->n_eviction_fields
        && (!n_fields
            || !memcmp(fields, table->eviction_fields,
                       n_fields * sizeof *fields))) {
        /* No change. */
        return;
    }

    oftable_disable_eviction(table);

    table->n_eviction_fields = n_fields;
    table->eviction_fields = xmemdup(fields, n_fields * sizeof *fields);

    table->eviction_group_id_basis = random_uint32();
    hmap_init(&table->eviction_groups_by_id);
    heap_init(&table->eviction_groups_by_size);

    fat_rwlock_rdlock(&table->cls.rwlock);
    cls_cursor_init(&cursor, &table->cls, NULL);
    CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
        eviction_group_add_rule(rule);
    }
    fat_rwlock_unlock(&table->cls.rwlock);
}

/* Removes 'rule' from the oftable that contains it. */
static void
oftable_remove_rule__(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    struct classifier *cls = &ofproto->tables[rule->table_id].cls;

    fat_rwlock_wrlock(&cls->rwlock);
    classifier_remove(cls, CONST_CAST(struct cls_rule *, &rule->cr));
    fat_rwlock_unlock(&cls->rwlock);

    cookies_remove(ofproto, rule);

    eviction_group_remove_rule(rule);
    if (!list_is_empty(&rule->expirable)) {
        list_remove(&rule->expirable);
    }
    if (!list_is_empty(&rule->meter_list_node)) {
        list_remove(&rule->meter_list_node);
        list_init(&rule->meter_list_node);
    }
}

static void
oftable_remove_rule(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    oftable_remove_rule__(rule->ofproto, rule);
}

/* Inserts 'rule' into its oftable, which must not already contain any rule for
 * the same cls_rule. */
static void
oftable_insert_rule(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto *ofproto = rule->ofproto;
    struct oftable *table = &ofproto->tables[rule->table_id];
    bool may_expire;

    ovs_mutex_lock(&rule->mutex);
    may_expire = rule->hard_timeout || rule->idle_timeout;
    ovs_mutex_unlock(&rule->mutex);

    if (may_expire) {
        list_insert(&ofproto->expirable, &rule->expirable);
    }

    cookies_insert(ofproto, rule);

    if (rule->actions->provider_meter_id != UINT32_MAX) {
        uint32_t meter_id = ofpacts_get_meter(rule->actions->ofpacts,
                                              rule->actions->ofpacts_len);
        struct meter *meter = ofproto->meters[meter_id];
        list_insert(&meter->rules, &rule->meter_list_node);
    }
    fat_rwlock_wrlock(&table->cls.rwlock);
    classifier_insert(&table->cls, CONST_CAST(struct cls_rule *, &rule->cr));
    fat_rwlock_unlock(&table->cls.rwlock);
    eviction_group_add_rule(rule);
}

/* unixctl commands. */

struct ofproto *
ofproto_lookup(const char *name)
{
    struct ofproto *ofproto;

    HMAP_FOR_EACH_WITH_HASH (ofproto, hmap_node, hash_string(name, 0),
                             &all_ofprotos) {
        if (!strcmp(ofproto->name, name)) {
            return ofproto;
        }
    }
    return NULL;
}

static void
ofproto_unixctl_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ofproto *ofproto;
    struct ds results;

    ds_init(&results);
    HMAP_FOR_EACH (ofproto, hmap_node, &all_ofprotos) {
        ds_put_format(&results, "%s\n", ofproto->name);
    }
    unixctl_command_reply(conn, ds_cstr(&results));
    ds_destroy(&results);
}

static void
ofproto_unixctl_init(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    unixctl_command_register("ofproto/list", "", 0, 0,
                             ofproto_unixctl_list, NULL);
}

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

/* Sets a 1-bit in the 4096-bit 'vlan_bitmap' for each VLAN ID that is matched
 * (exactly) by an OpenFlow rule in 'ofproto'. */
void
ofproto_get_vlan_usage(struct ofproto *ofproto, unsigned long int *vlan_bitmap)
{
    const struct oftable *oftable;

    free(ofproto->vlan_bitmap);
    ofproto->vlan_bitmap = bitmap_allocate(4096);
    ofproto->vlans_changed = false;

    OFPROTO_FOR_EACH_TABLE (oftable, ofproto) {
        const struct cls_subtable *table;

        fat_rwlock_rdlock(&oftable->cls.rwlock);
        HMAP_FOR_EACH (table, hmap_node, &oftable->cls.subtables) {
            if (minimask_get_vid_mask(&table->mask) == VLAN_VID_MASK) {
                const struct cls_rule *rule;

                HMAP_FOR_EACH (rule, hmap_node, &table->rules) {
                    uint16_t vid = miniflow_get_vid(&rule->match.flow);
                    bitmap_set1(vlan_bitmap, vid);
                    bitmap_set1(ofproto->vlan_bitmap, vid);
                }
            }
        }
        fat_rwlock_unlock(&oftable->cls.rwlock);
    }
}

/* Returns true if new VLANs have come into use by the flow table since the
 * last call to ofproto_get_vlan_usage().
 *
 * We don't track when old VLANs stop being used. */
bool
ofproto_has_vlan_usage_changed(const struct ofproto *ofproto)
{
    return ofproto->vlans_changed;
}

/* Configures a VLAN splinter binding between the ports identified by OpenFlow
 * port numbers 'vlandev_ofp_port' and 'realdev_ofp_port'.  If
 * 'realdev_ofp_port' is nonzero, then the VLAN device is enslaved to the real
 * device as a VLAN splinter for VLAN ID 'vid'.  If 'realdev_ofp_port' is zero,
 * then the VLAN device is un-enslaved. */
int
ofproto_port_set_realdev(struct ofproto *ofproto, ofp_port_t vlandev_ofp_port,
                         ofp_port_t realdev_ofp_port, int vid)
{
    struct ofport *ofport;
    int error;

    ovs_assert(vlandev_ofp_port != realdev_ofp_port);

    ofport = ofproto_get_port(ofproto, vlandev_ofp_port);
    if (!ofport) {
        VLOG_WARN("%s: cannot set realdev on nonexistent port %"PRIu16,
                  ofproto->name, vlandev_ofp_port);
        return EINVAL;
    }

    if (!ofproto->ofproto_class->set_realdev) {
        if (!vlandev_ofp_port) {
            return 0;
        }
        VLOG_WARN("%s: vlan splinters not supported", ofproto->name);
        return EOPNOTSUPP;
    }

    error = ofproto->ofproto_class->set_realdev(ofport, realdev_ofp_port, vid);
    if (error) {
        VLOG_WARN("%s: setting realdev on port %"PRIu16" (%s) failed (%s)",
                  ofproto->name, vlandev_ofp_port,
                  netdev_get_name(ofport->netdev), ovs_strerror(error));
    }
    return error;
}
