/*
 * Copyright (c) 2009-2015 Nicira, Inc.
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
#include "ovs-rcu.h"
#include "dp-packet.h"
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
#include "openvswitch/vlog.h"
#include "bundles.h"

VLOG_DEFINE_THIS_MODULE(ofproto);

COVERAGE_DEFINE(ofproto_flush);
COVERAGE_DEFINE(ofproto_packet_out);
COVERAGE_DEFINE(ofproto_queue_req);
COVERAGE_DEFINE(ofproto_recv_openflow);
COVERAGE_DEFINE(ofproto_reinit_ports);
COVERAGE_DEFINE(ofproto_update_port);

/* Default fields to use for prefix tries in each flow table, unless something
 * else is configured. */
const enum mf_field_id default_prefix_fields[2] =
    { MFF_IPV4_DST, MFF_IPV4_SRC };

/* oftable. */
static void oftable_init(struct oftable *);
static void oftable_destroy(struct oftable *);

static void oftable_set_name(struct oftable *, const char *name);

static enum ofperr evict_rules_from_table(struct oftable *,
                                          unsigned int extra_space)
    OVS_REQUIRES(ofproto_mutex);
static void oftable_disable_eviction(struct oftable *);
static void oftable_enable_eviction(struct oftable *,
                                    const struct mf_subfield *fields,
                                    size_t n_fields);

static void oftable_remove_rule(struct rule *rule) OVS_REQUIRES(ofproto_mutex);

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

static bool choose_rule_to_evict(struct oftable *table, struct rule **rulep)
    OVS_REQUIRES(ofproto_mutex);
static uint32_t rule_eviction_priority(struct ofproto *ofproto, struct rule *)
    OVS_REQUIRES(ofproto_mutex);;
static void eviction_group_add_rule(struct rule *)
    OVS_REQUIRES(ofproto_mutex);
static void eviction_group_remove_rule(struct rule *)
    OVS_REQUIRES(ofproto_mutex);

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

    /* If true, collects only rules that are modifiable. */
    bool include_hidden;
    bool include_readonly;
};

static void rule_criteria_init(struct rule_criteria *, uint8_t table_id,
                               const struct match *match, int priority,
                               ovs_be64 cookie, ovs_be64 cookie_mask,
                               ofp_port_t out_port, uint32_t out_group);
static void rule_criteria_require_rw(struct rule_criteria *,
                                     bool can_write_readonly);
static void rule_criteria_destroy(struct rule_criteria *);

static enum ofperr collect_rules_loose(struct ofproto *,
                                       const struct rule_criteria *,
                                       struct rule_collection *);

/* A packet that needs to be passed to rule_execute().
 *
 * (We can't do this immediately from ofopgroup_complete() because that holds
 * ofproto_mutex, which rule_execute() needs released.) */
struct rule_execute {
    struct ovs_list list_node;  /* In struct ofproto's "rule_executes" list. */
    struct rule *rule;          /* Owns a reference to the rule. */
    ofp_port_t in_port;
    struct dp_packet *packet;      /* Owns the packet. */
};

static void run_rule_executes(struct ofproto *) OVS_EXCLUDED(ofproto_mutex);
static void destroy_rule_executes(struct ofproto *);

struct learned_cookie {
    union {
        /* In struct ofproto's 'learned_cookies' hmap. */
        struct hmap_node hmap_node OVS_GUARDED_BY(ofproto_mutex);

        /* In 'dead_cookies' list when removed from hmap. */
        struct ovs_list list_node;
    } u;

    /* Key. */
    ovs_be64 cookie OVS_GUARDED_BY(ofproto_mutex);
    uint8_t table_id OVS_GUARDED_BY(ofproto_mutex);

    /* Number of references from "learn" actions.
     *
     * When this drops to 0, all of the flows in 'table_id' with the specified
     * 'cookie' are deleted. */
    int n OVS_GUARDED_BY(ofproto_mutex);
};

static const struct ofpact_learn *next_learn_with_delete(
    const struct rule_actions *, const struct ofpact_learn *start);

static void learned_cookies_inc(struct ofproto *, const struct rule_actions *)
    OVS_REQUIRES(ofproto_mutex);
static void learned_cookies_dec(struct ofproto *, const struct rule_actions *,
                                struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex);
static void learned_cookies_flush(struct ofproto *, struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex);

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
static void ofproto_rule_send_removed(struct rule *, uint8_t reason);
static bool rule_is_readonly(const struct rule *);
static void ofproto_rule_insert__(struct ofproto *, struct rule *)
    OVS_REQUIRES(ofproto_mutex);
static void ofproto_rule_remove__(struct ofproto *, struct rule *)
    OVS_REQUIRES(ofproto_mutex);

/* The source of a flow_mod request, in the code that processes flow_mods.
 *
 * A flow table modification request can be generated externally, via OpenFlow,
 * or internally through a function call.  This structure indicates the source
 * of an OpenFlow-generated flow_mod.  For an internal flow_mod, it isn't
 * meaningful and thus supplied as NULL. */
struct flow_mod_requester {
    struct ofconn *ofconn;      /* Connection on which flow_mod arrived. */
    const struct ofp_header *request;
};

/* OpenFlow. */
static enum ofperr modify_flow_check__(struct ofproto *,
                                       struct ofputil_flow_mod *,
                                       const struct rule *)
    OVS_REQUIRES(ofproto_mutex);
static void modify_flow__(struct ofproto *, struct ofputil_flow_mod *,
                          const struct flow_mod_requester *, struct rule *,
                          struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex);
static void delete_flows__(const struct rule_collection *,
                           enum ofp_flow_removed_reason,
                           const struct flow_mod_requester *)
    OVS_REQUIRES(ofproto_mutex);

static void send_buffered_packet(const struct flow_mod_requester *,
                                 uint32_t buffer_id, struct rule *)
    OVS_REQUIRES(ofproto_mutex);

static bool ofproto_group_exists__(const struct ofproto *ofproto,
                                   uint32_t group_id)
    OVS_REQ_RDLOCK(ofproto->groups_rwlock);
static bool ofproto_group_exists(const struct ofproto *ofproto,
                                 uint32_t group_id)
    OVS_EXCLUDED(ofproto->groups_rwlock);
static enum ofperr add_group(struct ofproto *, struct ofputil_group_mod *);
static void handle_openflow(struct ofconn *, const struct ofpbuf *);
static enum ofperr do_bundle_flow_mod_begin(struct ofproto *,
                                            struct ofputil_flow_mod *,
                                            struct ofp_bundle_entry *)
    OVS_REQUIRES(ofproto_mutex);
static void do_bundle_flow_mod_finish(struct ofproto *,
                                      struct ofputil_flow_mod *,
                                      const struct flow_mod_requester *,
                                      struct ofp_bundle_entry *)
    OVS_REQUIRES(ofproto_mutex);
static enum ofperr handle_flow_mod__(struct ofproto *,
                                     struct ofputil_flow_mod *,
                                     const struct flow_mod_requester *)
    OVS_EXCLUDED(ofproto_mutex);
static void calc_duration(long long int start, long long int now,
                          uint32_t *sec, uint32_t *nsec);

/* ofproto. */
static uint64_t pick_datapath_id(const struct ofproto *);
static uint64_t pick_fallback_dpid(void);
static void ofproto_destroy__(struct ofproto *);
static void update_mtu(struct ofproto *, struct ofport *);
static void meter_delete(struct ofproto *, uint32_t first, uint32_t last);
static void meter_insert_rule(struct rule *);

/* unixctl. */
static void ofproto_unixctl_init(void);

/* All registered ofproto classes, in probe order. */
static const struct ofproto_class **ofproto_classes;
static size_t n_ofproto_classes;
static size_t allocated_ofproto_classes;

/* Global lock that protects all flow table operations. */
struct ovs_mutex ofproto_mutex = OVS_MUTEX_INITIALIZER;

unsigned ofproto_flow_limit = OFPROTO_FLOW_LIMIT_DEFAULT;
unsigned ofproto_max_idle = OFPROTO_MAX_IDLE_DEFAULT;

size_t n_handlers, n_revalidators;
size_t n_dpdk_rxqs;
char *pmd_cpu_mask;

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
    hmap_init(&ofproto->learned_cookies);
    list_init(&ofproto->expirable);
    ofproto->connmgr = connmgr_create(ofproto, datapath_name, datapath_name);
    guarded_list_init(&ofproto->rule_executes);
    ofproto->vlan_bitmap = NULL;
    ofproto->vlans_changed = false;
    ofproto->min_mtu = INT_MAX;
    ovs_rwlock_init(&ofproto->groups_rwlock);
    hmap_init(&ofproto->groups);
    ovs_mutex_unlock(&ofproto_mutex);
    ofproto->ogf.types = 0xf;
    ofproto->ogf.capabilities = OFPGFC_CHAINING | OFPGFC_SELECT_LIVENESS |
                                OFPGFC_SELECT_WEIGHT;
    for (i = 0; i < 4; i++) {
        ofproto->ogf.max_groups[i] = OFPG_MAX;
        ofproto->ogf.ofpacts[i] = (UINT64_C(1) << N_OFPACTS) - 1;
    }

    error = ofproto->ofproto_class->construct(ofproto);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s",
                 datapath_name, ovs_strerror(error));
        connmgr_destroy(ofproto->connmgr);
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

/* Sets the maximum idle time for flows in the datapath before they are
 * expired. */
void
ofproto_set_max_idle(unsigned max_idle)
{
    ofproto_max_idle = max_idle;
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

/* Multicast snooping configuration. */

/* Configures multicast snooping on 'ofproto' using the settings
 * defined in 's'.  If 's' is NULL, disables multicast snooping.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_set_mcast_snooping(struct ofproto *ofproto,
                           const struct ofproto_mcast_snooping_settings *s)
{
    return (ofproto->ofproto_class->set_mcast_snooping
            ? ofproto->ofproto_class->set_mcast_snooping(ofproto, s)
            : EOPNOTSUPP);
}

/* Configures multicast snooping flood settings on 'ofp_port' of 'ofproto'.
 *
 * Returns 0 if successful, otherwise a positive errno value.*/
int
ofproto_port_set_mcast_snooping(struct ofproto *ofproto, void *aux,
                           const struct ofproto_mcast_snooping_port_settings *s)
{
    return (ofproto->ofproto_class->set_mcast_snooping_port
            ? ofproto->ofproto_class->set_mcast_snooping_port(ofproto, aux, s)
            : EOPNOTSUPP);
}

void
ofproto_set_n_dpdk_rxqs(int n_rxqs)
{
    n_dpdk_rxqs = MAX(n_rxqs, 0);
}

void
ofproto_set_cpu_mask(const char *cmask)
{
    free(pmd_cpu_mask);

    pmd_cpu_mask = cmask ? xstrdup(cmask) : NULL;
}

void
ofproto_set_threads(int n_handlers_, int n_revalidators_)
{
    int threads = MAX(count_cpu_cores(), 2);

    n_revalidators = MAX(n_revalidators_, 0);
    n_handlers = MAX(n_handlers_, 0);

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

/* Rapid Spanning Tree Protocol (RSTP) configuration. */

/* Configures RSTP on 'ofproto' using the settings defined in 's'.  If
 * 's' is NULL, disables RSTP.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_set_rstp(struct ofproto *ofproto,
                 const struct ofproto_rstp_settings *s)
{
    if (!ofproto->ofproto_class->set_rstp) {
        return EOPNOTSUPP;
    }
    ofproto->ofproto_class->set_rstp(ofproto, s);
    return 0;
}

/* Retrieves RSTP status of 'ofproto' and stores it in 's'.  If the
 * 'enabled' member of 's' is false, then the other members are not
 * meaningful.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_get_rstp_status(struct ofproto *ofproto,
                        struct ofproto_rstp_status *s)
{
    if (!ofproto->ofproto_class->get_rstp_status) {
        return EOPNOTSUPP;
    }
    ofproto->ofproto_class->get_rstp_status(ofproto, s);
    return 0;
}

/* Configures RSTP on 'ofp_port' of 'ofproto' using the settings defined
 * in 's'.  The caller is responsible for assigning RSTP port numbers
 * (using the 'port_num' member in the range of 1 through 255, inclusive)
 * and ensuring there are no duplicates.  If the 's' is NULL, then RSTP
 * is disabled on the port.
 *
 * Returns 0 if successful, otherwise a positive errno value.*/
int
ofproto_port_set_rstp(struct ofproto *ofproto, ofp_port_t ofp_port,
                      const struct ofproto_port_rstp_settings *s)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN("%s: cannot configure RSTP on nonexistent port %"PRIu16,
                ofproto->name, ofp_port);
        return ENODEV;
    }

    if (!ofproto->ofproto_class->set_rstp_port) {
        return  EOPNOTSUPP;
    }
    ofproto->ofproto_class->set_rstp_port(ofport, s);
    return 0;
}

/* Retrieves RSTP port status of 'ofp_port' on 'ofproto' and stores it in
 * 's'.  If the 'enabled' member in 's' is false, then the other members
 * are not meaningful.
 *
 * Returns 0 if successful, otherwise a positive errno value.*/
int
ofproto_port_get_rstp_status(struct ofproto *ofproto, ofp_port_t ofp_port,
                             struct ofproto_port_rstp_status *s)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN_RL(&rl, "%s: cannot get RSTP status on nonexistent "
                "port %"PRIu16, ofproto->name, ofp_port);
        return ENODEV;
    }

    if (!ofproto->ofproto_class->get_rstp_port_status) {
        return  EOPNOTSUPP;
    }
    ofproto->ofproto_class->get_rstp_port_status(ofport, s);
    return 0;
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

/* LLDP configuration. */
void
ofproto_port_set_lldp(struct ofproto *ofproto,
                      ofp_port_t ofp_port,
                      const struct smap *cfg)
{
    struct ofport *ofport;
    int error;

    ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN("%s: cannot configure LLDP on nonexistent port %"PRIu16,
                  ofproto->name, ofp_port);
        return;
    }
    error = (ofproto->ofproto_class->set_lldp
             ? ofproto->ofproto_class->set_lldp(ofport, cfg)
             : EOPNOTSUPP);
    if (error) {
        VLOG_WARN("%s: lldp configuration on port %"PRIu16" (%s) failed (%s)",
                  ofproto->name, ofp_port, netdev_get_name(ofport->netdev),
                  ovs_strerror(error));
    }
}

int
ofproto_set_aa(struct ofproto *ofproto, void *aux OVS_UNUSED,
               const struct aa_settings *s)
{
    if (!ofproto->ofproto_class->set_aa) {
        return EOPNOTSUPP;
    }
    ofproto->ofproto_class->set_aa(ofproto, s);
    return 0;
}

int
ofproto_aa_mapping_register(struct ofproto *ofproto, void *aux,
                            const struct aa_mapping_settings *s)
{
    if (!ofproto->ofproto_class->aa_mapping_set) {
        return EOPNOTSUPP;
    }
    ofproto->ofproto_class->aa_mapping_set(ofproto, aux, s);
    return 0;
}

int
ofproto_aa_mapping_unregister(struct ofproto *ofproto, void *aux)
{
    if (!ofproto->ofproto_class->aa_mapping_unset) {
        return EOPNOTSUPP;
    }
    ofproto->ofproto_class->aa_mapping_unset(ofproto, aux);
    return 0;
}

int
ofproto_aa_vlan_get_queued(struct ofproto *ofproto,
                           struct ovs_list *list)
{
    if (!ofproto->ofproto_class->aa_vlan_get_queued) {
        return EOPNOTSUPP;
    }
    ofproto->ofproto_class->aa_vlan_get_queued(ofproto, list);
    return 0;
}

unsigned int
ofproto_aa_vlan_get_queue_size(struct ofproto *ofproto)
{
    if (!ofproto->ofproto_class->aa_vlan_get_queue_size) {
        return EOPNOTSUPP;
    }
    return ofproto->ofproto_class->aa_vlan_get_queue_size(ofproto);
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

/* Checks the status change of BFD on 'ofport'.
 *
 * Returns true if 'ofproto_class' does not support 'bfd_status_changed'. */
bool
ofproto_port_bfd_status_changed(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->bfd_status_changed
            ? ofproto->ofproto_class->bfd_status_changed(ofport)
            : true);
}

/* Populates 'status' with the status of BFD on 'ofport'.  Returns 0 on
 * success.  Returns a positive errno otherwise.  Has no effect if 'ofp_port'
 * is not an OpenFlow port in 'ofproto'.
 *
 * The caller must provide and own '*status'. */
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

int
ofproto_port_get_lacp_stats(const struct ofport *port, struct lacp_slave_stats *stats)
{
    struct ofproto *ofproto = port->ofproto;
    int error;

    if (ofproto->ofproto_class->port_get_lacp_stats) {
        error = ofproto->ofproto_class->port_get_lacp_stats(port, stats);
    } else {
        error = EOPNOTSUPP;
    }

    return error;
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
 * the appropriate argument is set to UINT64_MAX.
 */
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

/* Returns the number of Controller visible OpenFlow tables
 * in 'ofproto'. This number will exclude Hidden tables.
 * This funtion's return value should be less or equal to that of
 * ofproto_get_n_tables() . */
uint8_t
ofproto_get_n_visible_tables(const struct ofproto *ofproto)
{
    uint8_t n = ofproto->n_tables;

    /* Count only non-hidden tables in the number of tables.  (Hidden tables,
     * if present, are always at the end.) */
    while(n && (ofproto->tables[n - 1].flags & OFTABLE_HIDDEN)) {
        n--;
    }

    return n;
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

    if (classifier_set_prefix_fields(&table->cls,
                                     s->prefix_fields, s->n_prefix_fields)) {
        /* XXX: Trigger revalidation. */
    }

    ovs_mutex_lock(&ofproto_mutex);
    evict_rules_from_table(table, 0);
    ovs_mutex_unlock(&ofproto_mutex);
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

/* Deletes 'rule' from 'ofproto'.
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
    /* This skips the ofmonitor and flow-removed notifications because the
     * switch is being deleted and any OpenFlow channels have been or soon will
     * be killed. */
    ovs_mutex_lock(&ofproto_mutex);
    oftable_remove_rule(rule);
    ofproto->ofproto_class->rule_delete(rule);
    ovs_mutex_unlock(&ofproto_mutex);
}

static void
ofproto_flush__(struct ofproto *ofproto)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct oftable *table;

    /* This will flush all datapath flows. */
    if (ofproto->ofproto_class->flush) {
        ofproto->ofproto_class->flush(ofproto);
    }

    /* XXX: There is a small race window here, where new datapath flows can be
     * created by upcall handlers based on the existing flow table.  We can not
     * call ofproto class flush while holding 'ofproto_mutex' to prevent this,
     * as then we could deadlock on syncing with the handler threads waiting on
     * the same mutex. */

    ovs_mutex_lock(&ofproto_mutex);
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        struct rule_collection rules;
        struct rule *rule;

        if (table->flags & OFTABLE_HIDDEN) {
            continue;
        }

        rule_collection_init(&rules);

        CLS_FOR_EACH (rule, cr, &table->cls) {
            rule_collection_add(&rules, rule);
        }
        delete_flows__(&rules, OFPRR_DELETE, NULL);
        rule_collection_destroy(&rules);
    }
    /* XXX: Concurrent handler threads may insert new learned flows based on
     * learn actions of the now deleted flows right after we release
     * 'ofproto_mutex'. */
    ovs_mutex_unlock(&ofproto_mutex);
}

static void delete_group(struct ofproto *ofproto, uint32_t group_id);

static void
ofproto_destroy__(struct ofproto *ofproto)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct oftable *table;

    destroy_rule_executes(ofproto);
    delete_group(ofproto, OFPG_ALL);

    guarded_list_destroy(&ofproto->rule_executes);
    ovs_rwlock_destroy(&ofproto->groups_rwlock);
    hmap_destroy(&ofproto->groups);

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

    ovs_assert(hindex_is_empty(&ofproto->cookies));
    hindex_destroy(&ofproto->cookies);

    ovs_assert(hmap_is_empty(&ofproto->learned_cookies));
    hmap_destroy(&ofproto->learned_cookies);

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

    /* We should not postpone this because it involves deleting a listening
     * socket which we may want to reopen soon. 'connmgr' should not be used
     * by other threads */
    connmgr_destroy(p->connmgr);

    /* Destroying rules is deferred, must have 'ofproto' around for them. */
    ovsrcu_postpone(ofproto_destroy__, p);
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
            struct rule *rule;

            if (!table->eviction_fields) {
                continue;
            }

            if (classifier_count(&table->cls) > 100000) {
                static struct vlog_rate_limit count_rl =
                    VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&count_rl, "Table %"PRIuSIZE" has an excessive"
                             " number of rules: %d", i,
                             classifier_count(&table->cls));
            }

            ovs_mutex_lock(&ofproto_mutex);
            CLS_FOR_EACH (rule, cr, &table->cls) {
                if (rule->idle_timeout || rule->hard_timeout) {
                    if (!rule->eviction_group) {
                        eviction_group_add_rule(rule);
                    } else {
                        heap_raw_change(&rule->evg_node,
                                        rule_eviction_priority(p, rule));
                    }
                }
            }

            HEAP_FOR_EACH (evg, size_node, &table->eviction_groups_by_size) {
                heap_rebuild(&evg->rules);
            }
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
            uint64_t port_change_seq;

            port_change_seq = netdev_get_change_seq(ofport->netdev);
            if (ofport->change_seq != port_change_seq) {
                ofport->change_seq = port_change_seq;
                sset_add(&devnames, netdev_get_name(ofport->netdev));
            }
        }
        SSET_FOR_EACH (devname, &devnames) {
            update_port(p, devname);
        }
        sset_destroy(&devnames);

        p->change_seq = new_seq;
    }

    connmgr_run(p->connmgr, handle_openflow);

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
    connmgr_wait(p->connmgr);
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

    n_rules = 0;
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        n_rules += classifier_count(&table->cls);
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
              const struct match *match, int priority,
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
    fm->importance = 0;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_ANY;
    fm->out_group = OFPG_ANY;
    fm->flags = 0;
    fm->ofpacts = CONST_CAST(struct ofpact *, ofpacts);
    fm->ofpacts_len = ofpacts_len;
    fm->delete_reason = OFPRR_DELETE;
}

static int
simple_flow_mod(struct ofproto *ofproto,
                const struct match *match, int priority,
                const struct ofpact *ofpacts, size_t ofpacts_len,
                enum ofp_flow_mod_command command)
{
    struct ofputil_flow_mod fm;

    flow_mod_init(&fm, match, priority, ofpacts, ofpacts_len, command);

    return handle_flow_mod__(ofproto, &fm, NULL);
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
                 int priority,
                 const struct ofpact *ofpacts, size_t ofpacts_len)
    OVS_EXCLUDED(ofproto_mutex)
{
    const struct rule *rule;
    bool must_add;

    /* First do a cheap check whether the rule we're looking for already exists
     * with the actions that we want.  If it does, then we're done. */
    rule = rule_from_cls_rule(classifier_find_match_exactly(
                                  &ofproto->tables[0].cls, match, priority));
    if (rule) {
        const struct rule_actions *actions = rule_get_actions(rule);
        must_add = !ofpacts_equal(actions->ofpacts, actions->ofpacts_len,
                                  ofpacts, ofpacts_len);
    } else {
        must_add = true;
    }

    /* If there's no such rule or the rule doesn't have the actions we want,
     * fall back to a executing a full flow mod.  We can't optimize this at
     * all because we didn't take enough locks above to ensure that the flow
     * table didn't already change beneath us.  */
    if (must_add) {
        simple_flow_mod(ofproto, match, priority, ofpacts, ofpacts_len,
                        OFPFC_MODIFY_STRICT);
    }
}

/* Executes the flow modification specified in 'fm'.  Returns 0 on success, or
 * an OFPERR_* OpenFlow error code on failure.
 *
 * This is a helper function for in-band control and fail-open and the "learn"
 * action. */
enum ofperr
ofproto_flow_mod(struct ofproto *ofproto, struct ofputil_flow_mod *fm)
    OVS_EXCLUDED(ofproto_mutex)
{
    /* Optimize for the most common case of a repeated learn action.
     * If an identical flow already exists we only need to update its
     * 'modified' time. */
    if (fm->command == OFPFC_MODIFY_STRICT && fm->table_id != OFPTT_ALL
        && !(fm->flags & OFPUTIL_FF_RESET_COUNTS)) {
        struct oftable *table = &ofproto->tables[fm->table_id];
        struct rule *rule;
        bool done = false;

        rule = rule_from_cls_rule(classifier_find_match_exactly(&table->cls,
                                                                &fm->match,
                                                                fm->priority));
        if (rule) {
            /* Reading many of the rule fields and writing on 'modified'
             * requires the rule->mutex.  Also, rule->actions may change
             * if rule->mutex is not held. */
            const struct rule_actions *actions;

            ovs_mutex_lock(&rule->mutex);
            actions = rule_get_actions(rule);
            if (rule->idle_timeout == fm->idle_timeout
                && rule->hard_timeout == fm->hard_timeout
                && rule->importance == fm->importance
                && rule->flags == (fm->flags & OFPUTIL_FF_STATE)
                && (!fm->modify_cookie || (fm->new_cookie == rule->flow_cookie))
                && ofpacts_equal(fm->ofpacts, fm->ofpacts_len,
                                 actions->ofpacts, actions->ofpacts_len)) {
                /* Rule already exists and need not change, only update the
                   modified timestamp. */
                rule->modified = time_msec();
                done = true;
            }
            ovs_mutex_unlock(&rule->mutex);
        }

        if (done) {
            return 0;
        }
    }

    return handle_flow_mod__(ofproto, fm, NULL);
}

/* Searches for a rule with matching criteria exactly equal to 'target' in
 * ofproto's table 0 and, if it finds one, deletes it.
 *
 * This is a helper function for in-band control and fail-open. */
void
ofproto_delete_flow(struct ofproto *ofproto,
                    const struct match *target, int priority)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct classifier *cls = &ofproto->tables[0].cls;
    struct rule *rule;

    /* First do a cheap check whether the rule we're looking for has already
     * been deleted.  If so, then we're done. */
    rule = rule_from_cls_rule(classifier_find_match_exactly(cls, target,
                                                            priority));
    if (!rule) {
        return;
    }

    /* Execute a flow mod.  We can't optimize this at all because we didn't
     * take enough locks above to ensure that the flow table didn't already
     * change beneath us. */
    simple_flow_mod(ofproto, target, priority, NULL, 0, OFPFC_DELETE_STRICT);
}

/* Delete all of the flows from all of ofproto's flow tables, then reintroduce
 * the flows required by in-band control and fail-open.  */
void
ofproto_flush_flows(struct ofproto *ofproto)
{
    COVERAGE_INC(ofproto_flush);
    ofproto_flush__(ofproto);
    connmgr_flushed(ofproto->connmgr);
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
 * '*pp'.  */
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
 * port number, and 'config' bits other than OFPUTIL_PC_PORT_DOWN are
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
    ofport->change_seq = netdev_get_change_seq(netdev);
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
    connmgr_send_port_status(p->connmgr, NULL, pp, OFPPR_ADD);
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
    connmgr_send_port_status(ofport->ofproto->connmgr, NULL, &ofport->pp,
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

    connmgr_send_port_status(port->ofproto->connmgr, NULL,
                             &port->pp, OFPPR_MODIFY);
}

/* Update OpenFlow 'state' in 'port' and notify controller. */
void
ofproto_port_set_state(struct ofport *port, enum ofputil_port_state state)
{
    if (port->pp.state != state) {
        port->pp.state = state;
        connmgr_send_port_status(port->ofproto->connmgr, NULL,
                                 &port->pp, OFPPR_MODIFY);
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
        if (port->ofproto->ofproto_class->set_rstp_port) {
            port->ofproto->ofproto_class->set_rstp_port(port, NULL);
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
            port->change_seq = netdev_get_change_seq(netdev);

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

static void
ofproto_rule_destroy__(struct rule *rule)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    cls_rule_destroy(CONST_CAST(struct cls_rule *, &rule->cr));
    rule_actions_destroy(rule_get_actions(rule));
    ovs_mutex_destroy(&rule->mutex);
    rule->ofproto->ofproto_class->rule_dealloc(rule);
}

/* Create a new rule based on attributes in 'fm', match in 'cr', and
 * 'table_id'.  Note that the rule is NOT inserted into a any data structures
 * yet.  Takes ownership of 'cr'. */
static enum ofperr
ofproto_rule_create(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                    struct cls_rule *cr, uint8_t table_id,
                    struct rule **rulep)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule *rule;
    enum ofperr error;

    /* Allocate new rule. */
    rule = ofproto->ofproto_class->rule_alloc();
    if (!rule) {
        cls_rule_destroy(cr);
        VLOG_WARN_RL(&rl, "%s: failed to allocate a rule.", ofproto->name);
        return OFPERR_OFPFMFC_UNKNOWN;
    }

    /* Initialize base state. */
    *CONST_CAST(struct ofproto **, &rule->ofproto) = ofproto;
    cls_rule_move(CONST_CAST(struct cls_rule *, &rule->cr), cr);
    ovs_refcount_init(&rule->ref_count);
    rule->flow_cookie = fm->new_cookie;
    rule->created = rule->modified = time_msec();

    ovs_mutex_init(&rule->mutex);
    ovs_mutex_lock(&rule->mutex);
    rule->idle_timeout = fm->idle_timeout;
    rule->hard_timeout = fm->hard_timeout;
    rule->importance = fm->importance;
    ovs_mutex_unlock(&rule->mutex);

    *CONST_CAST(uint8_t *, &rule->table_id) = table_id;
    rule->flags = fm->flags & OFPUTIL_FF_STATE;
    ovsrcu_set_hidden(&rule->actions,
                      rule_actions_create(fm->ofpacts, fm->ofpacts_len));
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

    *rulep = rule;
    return 0;
}

static void
rule_destroy_cb(struct rule *rule)
{
    rule->ofproto->ofproto_class->rule_destruct(rule);
    ofproto_rule_destroy__(rule);
}

void
ofproto_rule_ref(struct rule *rule)
{
    if (rule) {
        ovs_refcount_ref(&rule->ref_count);
    }
}

bool
ofproto_rule_try_ref(struct rule *rule)
{
    if (rule) {
        return ovs_refcount_try_ref_rcu(&rule->ref_count);
    }
    return false;
}

/* Decrements 'rule''s ref_count and schedules 'rule' to be destroyed if the
 * ref_count reaches 0.
 *
 * Use of RCU allows short term use (between RCU quiescent periods) without
 * keeping a reference.  A reference must be taken if the rule needs to
 * stay around accross the RCU quiescent periods. */
void
ofproto_rule_unref(struct rule *rule)
{
    if (rule && ovs_refcount_unref_relaxed(&rule->ref_count) == 1) {
        ovsrcu_postpone(rule_destroy_cb, rule);
    }
}

void
ofproto_group_ref(struct ofgroup *group)
{
    if (group) {
        ovs_refcount_ref(&group->ref_count);
    }
}

void
ofproto_group_unref(struct ofgroup *group)
{
    if (group && ovs_refcount_unref(&group->ref_count) == 1) {
        group->ofproto->ofproto_class->group_destruct(group);
        ofputil_bucket_list_destroy(&group->buckets);
        group->ofproto->ofproto_class->group_dealloc(group);
    }
}

static uint32_t get_provider_meter_id(const struct ofproto *,
                                      uint32_t of_meter_id);

/* Creates and returns a new 'struct rule_actions', whose actions are a copy
 * of from the 'ofpacts_len' bytes of 'ofpacts'. */
const struct rule_actions *
rule_actions_create(const struct ofpact *ofpacts, size_t ofpacts_len)
{
    struct rule_actions *actions;

    actions = xmalloc(sizeof *actions + ofpacts_len);
    actions->ofpacts_len = ofpacts_len;
    actions->has_meter = ofpacts_get_meter(ofpacts, ofpacts_len) != 0;
    memcpy(actions->ofpacts, ofpacts, ofpacts_len);

    actions->has_learn_with_delete = (next_learn_with_delete(actions, NULL)
                                      != NULL);

    return actions;
}

/* Free the actions after the RCU quiescent period is reached. */
void
rule_actions_destroy(const struct rule_actions *actions)
{
    if (actions) {
        ovsrcu_postpone(free, CONST_CAST(struct rule_actions *, actions));
    }
}

/* Returns true if 'rule' has an OpenFlow OFPAT_OUTPUT or OFPAT_ENQUEUE action
 * that outputs to 'port' (output to OFPP_FLOOD and OFPP_ALL doesn't count). */
bool
ofproto_rule_has_out_port(const struct rule *rule, ofp_port_t port)
    OVS_REQUIRES(ofproto_mutex)
{
    if (port == OFPP_ANY) {
        return true;
    } else {
        const struct rule_actions *actions = rule_get_actions(rule);
        return ofpacts_output_to_port(actions->ofpacts,
                                      actions->ofpacts_len, port);
    }
}

/* Returns true if 'rule' has group and equals group_id. */
static bool
ofproto_rule_has_out_group(const struct rule *rule, uint32_t group_id)
    OVS_REQUIRES(ofproto_mutex)
{
    if (group_id == OFPG_ANY) {
        return true;
    } else {
        const struct rule_actions *actions = rule_get_actions(rule);
        return ofpacts_output_to_group(actions->ofpacts,
                                       actions->ofpacts_len, group_id);
    }
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
    struct ovs_list executes;

    guarded_list_pop_all(&ofproto->rule_executes, &executes);
    LIST_FOR_EACH_SAFE (e, next, list_node, &executes) {
        struct flow flow;

        flow_extract(e->packet, &flow);
        flow.in_port.ofp_port = e->in_port;
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
    struct ovs_list executes;

    guarded_list_pop_all(&ofproto->rule_executes, &executes);
    LIST_FOR_EACH_SAFE (e, next, list_node, &executes) {
        dp_packet_delete(e->packet);
        rule_execute_destroy(e);
    }
}

static bool
rule_is_readonly(const struct rule *rule)
{
    const struct oftable *table = &rule->ofproto->tables[rule->table_id];
    return (table->flags & OFTABLE_READONLY) != 0;
}

static uint32_t
hash_learned_cookie(ovs_be64 cookie_, uint8_t table_id)
{
    uint64_t cookie = (OVS_FORCE uint64_t) cookie_;
    return hash_3words(cookie, cookie >> 32, table_id);
}

static void
learned_cookies_update_one__(struct ofproto *ofproto,
                             const struct ofpact_learn *learn,
                             int delta, struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex)
{
    uint32_t hash = hash_learned_cookie(learn->cookie, learn->table_id);
    struct learned_cookie *c;

    HMAP_FOR_EACH_WITH_HASH (c, u.hmap_node, hash, &ofproto->learned_cookies) {
        if (c->cookie == learn->cookie && c->table_id == learn->table_id) {
            c->n += delta;
            ovs_assert(c->n >= 0);

            if (!c->n) {
                hmap_remove(&ofproto->learned_cookies, &c->u.hmap_node);
                list_push_back(dead_cookies, &c->u.list_node);
            }

            return;
        }
    }

    ovs_assert(delta > 0);
    c = xmalloc(sizeof *c);
    hmap_insert(&ofproto->learned_cookies, &c->u.hmap_node, hash);
    c->cookie = learn->cookie;
    c->table_id = learn->table_id;
    c->n = delta;
}

static const struct ofpact_learn *
next_learn_with_delete(const struct rule_actions *actions,
                       const struct ofpact_learn *start)
{
    const struct ofpact *pos;

    for (pos = start ? ofpact_next(&start->ofpact) : actions->ofpacts;
         pos < ofpact_end(actions->ofpacts, actions->ofpacts_len);
         pos = ofpact_next(pos)) {
        if (pos->type == OFPACT_LEARN) {
            const struct ofpact_learn *learn = ofpact_get_LEARN(pos);
            if (learn->flags & NX_LEARN_F_DELETE_LEARNED) {
                return learn;
            }
        }
    }

    return NULL;
}

static void
learned_cookies_update__(struct ofproto *ofproto,
                         const struct rule_actions *actions,
                         int delta, struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex)
{
    if (actions->has_learn_with_delete) {
        const struct ofpact_learn *learn;

        for (learn = next_learn_with_delete(actions, NULL); learn;
             learn = next_learn_with_delete(actions, learn)) {
            learned_cookies_update_one__(ofproto, learn, delta, dead_cookies);
        }
    }
}

static void
learned_cookies_inc(struct ofproto *ofproto,
                    const struct rule_actions *actions)
    OVS_REQUIRES(ofproto_mutex)
{
    learned_cookies_update__(ofproto, actions, +1, NULL);
}

static void
learned_cookies_dec(struct ofproto *ofproto,
                    const struct rule_actions *actions,
                    struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex)
{
    learned_cookies_update__(ofproto, actions, -1, dead_cookies);
}

static void
learned_cookies_flush(struct ofproto *ofproto, struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex)
{
    struct learned_cookie *c;

    LIST_FOR_EACH_POP (c, u.list_node, dead_cookies) {
        struct rule_criteria criteria;
        struct rule_collection rules;
        struct match match;

        match_init_catchall(&match);
        rule_criteria_init(&criteria, c->table_id, &match, 0,
                           c->cookie, OVS_BE64_MAX, OFPP_ANY, OFPG_ANY);
        rule_criteria_require_rw(&criteria, false);
        collect_rules_loose(ofproto, &criteria, &rules);
        delete_flows__(&rules, OFPRR_DELETE, NULL);
        rule_criteria_destroy(&criteria);
        rule_collection_destroy(&rules);

        free(c);
    }
}

static enum ofperr
handle_echo_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    ofconn_send_reply(ofconn, make_echo_reply(oh));
    return 0;
}

static void
query_tables(struct ofproto *ofproto,
             struct ofputil_table_features **featuresp,
             struct ofputil_table_stats **statsp)
{
    struct mf_bitmap rw_fields = oxm_writable_fields();
    struct mf_bitmap match = oxm_matchable_fields();
    struct mf_bitmap mask = oxm_maskable_fields();

    struct ofputil_table_features *features;
    struct ofputil_table_stats *stats;
    int i;

    features = *featuresp = xcalloc(ofproto->n_tables, sizeof *features);
    for (i = 0; i < ofproto->n_tables; i++) {
        struct ofputil_table_features *f = &features[i];

        f->table_id = i;
        sprintf(f->name, "table%d", i);
        f->metadata_match = OVS_BE64_MAX;
        f->metadata_write = OVS_BE64_MAX;
        atomic_read_relaxed(&ofproto->tables[i].miss_config, &f->miss_config);
        f->max_entries = 1000000;

        bool more_tables = false;
        for (int j = i + 1; j < ofproto->n_tables; j++) {
            if (!(ofproto->tables[j].flags & OFTABLE_HIDDEN)) {
                bitmap_set1(f->nonmiss.next, j);
                more_tables = true;
            }
        }
        f->nonmiss.instructions = (1u << N_OVS_INSTRUCTIONS) - 1;
        if (!more_tables) {
            f->nonmiss.instructions &= ~(1u << OVSINST_OFPIT11_GOTO_TABLE);
        }
        f->nonmiss.write.ofpacts = (UINT64_C(1) << N_OFPACTS) - 1;
        f->nonmiss.write.set_fields = rw_fields;
        f->nonmiss.apply = f->nonmiss.write;
        f->miss = f->nonmiss;

        f->match = match;
        f->mask = mask;
        f->wildcard = match;
    }

    if (statsp) {
        stats = *statsp = xcalloc(ofproto->n_tables, sizeof *stats);
        for (i = 0; i < ofproto->n_tables; i++) {
            struct ofputil_table_stats *s = &stats[i];
            struct classifier *cls = &ofproto->tables[i].cls;

            s->table_id = i;
            s->active_count = classifier_count(cls);
            if (i == 0) {
                s->active_count -= connmgr_count_hidden_rules(
                    ofproto->connmgr);
            }
        }
    } else {
        stats = NULL;
    }

    ofproto->ofproto_class->query_tables(ofproto, features, stats);

    for (i = 0; i < ofproto->n_tables; i++) {
        const struct oftable *table = &ofproto->tables[i];
        struct ofputil_table_features *f = &features[i];

        if (table->name) {
            ovs_strzcpy(f->name, table->name, sizeof f->name);
        }

        if (table->max_flows < f->max_entries) {
            f->max_entries = table->max_flows;
        }
    }
}

static void
query_switch_features(struct ofproto *ofproto,
                      bool *arp_match_ip, uint64_t *ofpacts)
{
    struct ofputil_table_features *features, *f;

    *arp_match_ip = false;
    *ofpacts = 0;

    query_tables(ofproto, &features, NULL);
    for (f = features; f < &features[ofproto->n_tables]; f++) {
        *ofpacts |= f->nonmiss.apply.ofpacts | f->miss.apply.ofpacts;
        if (bitmap_is_set(f->match.bm, MFF_ARP_SPA) ||
            bitmap_is_set(f->match.bm, MFF_ARP_TPA)) {
            *arp_match_ip = true;
        }
    }
    free(features);

    /* Sanity check. */
    ovs_assert(*ofpacts & (UINT64_C(1) << OFPACT_OUTPUT));
}

static enum ofperr
handle_features_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_switch_features features;
    struct ofport *port;
    bool arp_match_ip;
    struct ofpbuf *b;

    query_switch_features(ofproto, &arp_match_ip, &features.ofpacts);

    features.datapath_id = ofproto->datapath_id;
    features.n_buffers = pktbuf_capacity();
    features.n_tables = ofproto_get_n_visible_tables(ofproto);
    features.capabilities = (OFPUTIL_C_FLOW_STATS | OFPUTIL_C_TABLE_STATS |
                             OFPUTIL_C_PORT_STATS | OFPUTIL_C_QUEUE_STATS |
                             OFPUTIL_C_GROUP_STATS);
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
        return OFPERR_OFPBRC_IS_SLAVE;
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
    struct dp_packet *payload;
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts;
    struct flow flow;
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
        payload = dp_packet_clone_data_with_headroom(po.packet, po.packet_len, 2);
    }

    /* Verify actions against packet, then send packet if successful. */
    flow_extract(payload, &flow);
    flow.in_port.ofp_port = po.in_port;
    error = ofproto_check_ofpacts(p, po.ofpacts, po.ofpacts_len);
    if (!error) {
        error = p->ofproto_class->packet_out(p, payload, &flow,
                                             po.ofpacts, po.ofpacts_len);
    }
    dp_packet_delete(payload);

exit_free_ofpacts:
    ofpbuf_uninit(&ofpacts);
exit:
    return error;
}

static void
update_port_config(struct ofconn *ofconn, struct ofport *port,
                   enum ofputil_port_config config,
                   enum ofputil_port_config mask)
{
    enum ofputil_port_config toggle = (config ^ port->pp.config) & mask;

    if (toggle & OFPUTIL_PC_PORT_DOWN
        && (config & OFPUTIL_PC_PORT_DOWN
            ? netdev_turn_flags_off(port->netdev, NETDEV_UP, NULL)
            : netdev_turn_flags_on(port->netdev, NETDEV_UP, NULL))) {
        /* We tried to bring the port up or down, but it failed, so don't
         * update the "down" bit. */
        toggle &= ~OFPUTIL_PC_PORT_DOWN;
    }

    if (toggle) {
        enum ofputil_port_config old_config = port->pp.config;
        port->pp.config ^= toggle;
        port->ofproto->ofproto_class->port_reconfigured(port, old_config);
        connmgr_send_port_status(port->ofproto->connmgr, ofconn, &port->pp,
                                 OFPPR_MODIFY);
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

    error = ofputil_decode_port_mod(oh, &pm, false);
    if (error) {
        return error;
    }

    port = ofproto_get_port(p, pm.port_no);
    if (!port) {
        return OFPERR_OFPPMFC_BAD_PORT;
    } else if (!eth_addr_equals(port->pp.hw_addr, pm.hw_addr)) {
        return OFPERR_OFPPMFC_BAD_HW_ADDR;
    } else {
        update_port_config(ofconn, port, pm.config, pm.mask);
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
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_table_features *features;
    struct ofputil_table_stats *stats;
    struct ofpbuf *reply;
    size_t i;

    query_tables(ofproto, &features, &stats);

    reply = ofputil_encode_table_stats_reply(request);
    for (i = 0; i < ofproto->n_tables; i++) {
        if (!(ofproto->tables[i].flags & OFTABLE_HIDDEN)) {
            ofputil_append_table_stats_reply(reply, &stats[i], &features[i]);
        }
    }
    ofconn_send_reply(ofconn, reply);

    free(features);
    free(stats);

    return 0;
}

static enum ofperr
handle_table_features_request(struct ofconn *ofconn,
                              const struct ofp_header *request)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_table_features *features;
    struct ovs_list replies;
    struct ofpbuf msg;
    size_t i;

    ofpbuf_use_const(&msg, request, ntohs(request->length));
    ofpraw_pull_assert(&msg);
    if (msg.size || ofpmp_more(request)) {
        return OFPERR_OFPTFFC_EPERM;
    }

    query_tables(ofproto, &features, NULL);

    ofpmp_init(&replies, request);
    for (i = 0; i < ofproto->n_tables; i++) {
        if (!(ofproto->tables[i].flags & OFTABLE_HIDDEN)) {
            ofputil_append_table_features_reply(&features[i], &replies);
        }
    }
    ofconn_send_replies(ofconn, &replies);

    free(features);

    return 0;
}

static void
append_port_stat(struct ofport *port, struct ovs_list *replies)
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

static void
handle_port_request(struct ofconn *ofconn,
                    const struct ofp_header *request, ofp_port_t port_no,
                    void (*cb)(struct ofport *, struct ovs_list *replies))
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofport *port;
    struct ovs_list replies;

    ofpmp_init(&replies, request);
    if (port_no != OFPP_ANY) {
        port = ofproto_get_port(ofproto, port_no);
        if (port) {
            cb(port, &replies);
        }
    } else {
        HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
            cb(port, &replies);
        }
    }

    ofconn_send_replies(ofconn, &replies);
}

static enum ofperr
handle_port_stats_request(struct ofconn *ofconn,
                          const struct ofp_header *request)
{
    ofp_port_t port_no;
    enum ofperr error;

    error = ofputil_decode_port_stats_request(request, &port_no);
    if (!error) {
        handle_port_request(ofconn, request, port_no, append_port_stat);
    }
    return error;
}

static void
append_port_desc(struct ofport *port, struct ovs_list *replies)
{
    ofputil_append_port_desc_stats_reply(&port->pp, replies);
}

static enum ofperr
handle_port_desc_stats_request(struct ofconn *ofconn,
                               const struct ofp_header *request)
{
    ofp_port_t port_no;
    enum ofperr error;

    error = ofputil_decode_port_desc_stats_request(request, &port_no);
    if (!error) {
        handle_port_request(ofconn, request, port_no, append_port_desc);
    }
    return error;
}

static uint32_t
hash_cookie(ovs_be64 cookie)
{
    return hash_uint64((OVS_FORCE uint64_t)cookie);
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
calc_duration(long long int start, long long int now,
              uint32_t *sec, uint32_t *nsec)
{
    long long int msecs = now - start;
    *sec = msecs / 1000;
    *nsec = (msecs % 1000) * (1000 * 1000);
}

/* Checks whether 'table_id' is 0xff or a valid table ID in 'ofproto'.  Returns
 * true if 'table_id' is OK, false otherwise.  */
static bool
check_table_id(const struct ofproto *ofproto, uint8_t table_id)
{
    return table_id == OFPTT_ALL || table_id < ofproto->n_tables;
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
 * By default, the criteria include flows that are read-only, on the assumption
 * that the collected flows won't be modified.  Call rule_criteria_require_rw()
 * if flows will be modified.
 *
 * For "loose" matching, the 'priority' parameter is unimportant and may be
 * supplied as 0. */
static void
rule_criteria_init(struct rule_criteria *criteria, uint8_t table_id,
                   const struct match *match, int priority,
                   ovs_be64 cookie, ovs_be64 cookie_mask,
                   ofp_port_t out_port, uint32_t out_group)
{
    criteria->table_id = table_id;
    cls_rule_init(&criteria->cr, match, priority);
    criteria->cookie = cookie;
    criteria->cookie_mask = cookie_mask;
    criteria->out_port = out_port;
    criteria->out_group = out_group;

    /* We ordinarily want to skip hidden rules, but there has to be a way for
     * code internal to OVS to modify and delete them, so if the criteria
     * specify a priority that can only be for a hidden flow, then allow hidden
     * rules to be selected.  (This doesn't allow OpenFlow clients to meddle
     * with hidden flows because OpenFlow uses only a 16-bit field to specify
     * priority.) */
    criteria->include_hidden = priority > UINT16_MAX;

    /* We assume that the criteria are being used to collect flows for reading
     * but not modification.  Thus, we should collect read-only flows. */
    criteria->include_readonly = true;
}

/* By default, criteria initialized by rule_criteria_init() will match flows
 * that are read-only, on the assumption that the collected flows won't be
 * modified.  Call this function to match only flows that are be modifiable.
 *
 * Specify 'can_write_readonly' as false in ordinary circumstances, true if the
 * caller has special privileges that allow it to modify even "read-only"
 * flows. */
static void
rule_criteria_require_rw(struct rule_criteria *criteria,
                         bool can_write_readonly)
{
    criteria->include_readonly = can_write_readonly;
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

    /* Make repeated destruction harmless. */
    rule_collection_init(rules);
}

/* Checks whether 'rule' matches 'c' and, if so, adds it to 'rules'.  This
 * function verifies most of the criteria in 'c' itself, but the caller must
 * check 'c->cr' itself.
 *
 * Rules that have already been marked as 'to_be_removed' are not collected.
 *
 * Increments '*n_readonly' if 'rule' wasn't added because it's read-only (and
 * 'c' only includes modifiable rules). */
static void
collect_rule(struct rule *rule, const struct rule_criteria *c,
             struct rule_collection *rules, size_t *n_readonly)
    OVS_REQUIRES(ofproto_mutex)
{
    if ((c->table_id == rule->table_id || c->table_id == 0xff)
        && ofproto_rule_has_out_port(rule, c->out_port)
        && ofproto_rule_has_out_group(rule, c->out_group)
        && !((rule->flow_cookie ^ c->cookie) & c->cookie_mask)
        && (!rule_is_hidden(rule) || c->include_hidden)
        && !rule->cr.to_be_removed) {
        /* Rule matches all the criteria... */
        if (!rule_is_readonly(rule) || c->include_readonly) {
            /* ...add it. */
            rule_collection_add(rules, rule);
        } else {
            /* ...except it's read-only. */
            ++*n_readonly;
        }
    }
}

/* Searches 'ofproto' for rules that match the criteria in 'criteria'.  Matches
 * on classifiers rules are done in the "loose" way required for OpenFlow
 * OFPFC_MODIFY and OFPFC_DELETE requests.  Puts the selected rules on list
 * 'rules'.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
collect_rules_loose(struct ofproto *ofproto,
                    const struct rule_criteria *criteria,
                    struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table;
    enum ofperr error = 0;
    size_t n_readonly = 0;

    rule_collection_init(rules);

    if (!check_table_id(ofproto, criteria->table_id)) {
        error = OFPERR_OFPBRC_BAD_TABLE_ID;
        goto exit;
    }

    if (criteria->cookie_mask == OVS_BE64_MAX) {
        struct rule *rule;

        HINDEX_FOR_EACH_WITH_HASH (rule, cookie_node,
                                   hash_cookie(criteria->cookie),
                                   &ofproto->cookies) {
            if (cls_rule_is_loose_match(&rule->cr, &criteria->cr.match)) {
                collect_rule(rule, criteria, rules, &n_readonly);
            }
        }
    } else {
        FOR_EACH_MATCHING_TABLE (table, criteria->table_id, ofproto) {
            struct rule *rule;

            CLS_FOR_EACH_TARGET (rule, cr, &table->cls, &criteria->cr) {
                collect_rule(rule, criteria, rules, &n_readonly);
            }
        }
    }

exit:
    if (!error && !rules->n && n_readonly) {
        /* We didn't find any rules to modify.  We did find some read-only
         * rules that we're not allowed to modify, so report that. */
        error = OFPERR_OFPBRC_EPERM;
    }
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
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
collect_rules_strict(struct ofproto *ofproto,
                     const struct rule_criteria *criteria,
                     struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table;
    size_t n_readonly = 0;
    enum ofperr error = 0;

    rule_collection_init(rules);

    if (!check_table_id(ofproto, criteria->table_id)) {
        error = OFPERR_OFPBRC_BAD_TABLE_ID;
        goto exit;
    }

    if (criteria->cookie_mask == OVS_BE64_MAX) {
        struct rule *rule;

        HINDEX_FOR_EACH_WITH_HASH (rule, cookie_node,
                                   hash_cookie(criteria->cookie),
                                   &ofproto->cookies) {
            if (cls_rule_equal(&rule->cr, &criteria->cr)) {
                collect_rule(rule, criteria, rules, &n_readonly);
            }
        }
    } else {
        FOR_EACH_MATCHING_TABLE (table, criteria->table_id, ofproto) {
            struct rule *rule;

            rule = rule_from_cls_rule(classifier_find_rule_exactly(
                                          &table->cls, &criteria->cr));
            if (rule) {
                collect_rule(rule, criteria, rules, &n_readonly);
            }
        }
    }

exit:
    if (!error && !rules->n && n_readonly) {
        /* We didn't find any rules to modify.  We did find some read-only
         * rules that we're not allowed to modify, so report that. */
        error = OFPERR_OFPBRC_EPERM;
    }
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
    struct ovs_list replies;
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
        const struct rule_actions *actions;
        enum ofputil_flow_mod_flags flags;

        ovs_mutex_lock(&rule->mutex);
        fs.cookie = rule->flow_cookie;
        fs.idle_timeout = rule->idle_timeout;
        fs.hard_timeout = rule->hard_timeout;
        fs.importance = rule->importance;
        created = rule->created;
        modified = rule->modified;
        actions = rule_get_actions(rule);
        flags = rule->flags;
        ovs_mutex_unlock(&rule->mutex);

        ofproto->ofproto_class->rule_get_stats(rule, &fs.packet_count,
                                               &fs.byte_count, &used);

        minimatch_expand(&rule->cr.match, &fs.match);
        fs.table_id = rule->table_id;
        calc_duration(created, now, &fs.duration_sec, &fs.duration_nsec);
        fs.priority = rule->cr.priority;
        fs.idle_age = age_secs(now - used);
        fs.hard_age = age_secs(now - modified);
        fs.ofpacts = actions->ofpacts;
        fs.ofpacts_len = actions->ofpacts_len;

        fs.flags = flags;
        ofputil_append_flow_stats_reply(&fs, &replies);
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
    const struct rule_actions *actions;
    long long int created, used;

    rule->ofproto->ofproto_class->rule_get_stats(rule, &packet_count,
                                                 &byte_count, &used);

    ovs_mutex_lock(&rule->mutex);
    actions = rule_get_actions(rule);
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
}

/* Adds a pretty-printed description of all flows to 'results', including
 * hidden flows (e.g., set up by in-band control). */
void
ofproto_get_all_flows(struct ofproto *p, struct ds *results)
{
    struct oftable *table;

    OFPROTO_FOR_EACH_TABLE (table, p) {
        struct rule *rule;

        CLS_FOR_EACH (rule, cr, &table->cls) {
            flow_stats_ds(rule, results);
        }
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

/* Checks the status change of CFM on 'ofport'.
 *
 * Returns true if 'ofproto_class' does not support 'cfm_status_changed'. */
bool
ofproto_port_cfm_status_changed(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->cfm_status_changed
            ? ofproto->ofproto_class->cfm_status_changed(ofport)
            : true);
}

/* Checks the status of CFM configured on 'ofp_port' within 'ofproto'.
 * Returns 0 if the port's CFM status was successfully stored into
 * '*status'.  Returns positive errno if the port did not have CFM
 * configured.
 *
 * The caller must provide and own '*status', and must free 'status->rmps'.
 * '*status' is indeterminate if the return value is non-zero. */
int
ofproto_port_get_cfm_status(const struct ofproto *ofproto, ofp_port_t ofp_port,
                            struct cfm_status *status)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->get_cfm_status
            ? ofproto->ofproto_class->get_cfm_status(ofport, status)
            : EOPNOTSUPP);
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
        long long int used;

        ofproto->ofproto_class->rule_get_stats(rule, &packet_count,
                                               &byte_count, &used);

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
    struct ovs_list replies;
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

static enum ofperr
evict_rules_from_table(struct oftable *table, unsigned int extra_space)
    OVS_REQUIRES(ofproto_mutex)
{
    enum ofperr error = 0;
    struct rule_collection rules;
    unsigned int count = classifier_count(&table->cls) + extra_space;
    unsigned int max_flows = table->max_flows;

    rule_collection_init(&rules);

    while (count-- > max_flows) {
        struct rule *rule;

        if (!choose_rule_to_evict(table, &rule)) {
            error = OFPERR_OFPFMFC_TABLE_FULL;
            break;
        } else {
            eviction_group_remove_rule(rule);
            rule_collection_add(&rules, rule);
        }
    }
    delete_flows__(&rules, OFPRR_EVICTION, NULL);
    rule_collection_destroy(&rules);

    return error;
}

static bool
is_conjunction(const struct ofpact *ofpacts, size_t ofpacts_len)
{
    return ofpacts_len > 0 && ofpacts->type == OFPACT_CONJUNCTION;
}

static void
get_conjunctions(const struct ofputil_flow_mod *fm,
                 struct cls_conjunction **conjsp, size_t *n_conjsp)
    OVS_REQUIRES(ofproto_mutex)
{
    struct cls_conjunction *conjs = NULL;
    int n_conjs = 0;

    if (is_conjunction(fm->ofpacts, fm->ofpacts_len)) {
        const struct ofpact *ofpact;
        int i;

        n_conjs = 0;
        OFPACT_FOR_EACH (ofpact, fm->ofpacts, fm->ofpacts_len) {
            n_conjs++;
        }

        conjs = xzalloc(n_conjs * sizeof *conjs);
        i = 0;
        OFPACT_FOR_EACH (ofpact, fm->ofpacts, fm->ofpacts_len) {
            struct ofpact_conjunction *oc = ofpact_get_CONJUNCTION(ofpact);
            conjs[i].clause = oc->clause;
            conjs[i].n_clauses = oc->n_clauses;
            conjs[i].id = oc->id;
            i++;
        }
    }

    *conjsp = conjs;
    *n_conjsp = n_conjs;
}

static void
set_conjunctions(struct rule *rule, const struct cls_conjunction *conjs,
                 size_t n_conjs)
    OVS_REQUIRES(ofproto_mutex)
{
    struct cls_rule *cr = CONST_CAST(struct cls_rule *, &rule->cr);

    cls_rule_set_conjunctions(cr, conjs, n_conjs);
}

/* Implements OFPFC_ADD and the cases for OFPFC_MODIFY and OFPFC_MODIFY_STRICT
 * in which no matching flow already exists in the flow table.
 *
 * Adds the flow specified by 'fm', to the ofproto's flow table.  Returns 0 on
 * success, or an OpenFlow error code on failure.
 *
 * On successful return the caller must complete the operation either by
 * calling add_flow_finish(), or add_flow_revert() if the operation needs to
 * be reverted.
 *
 * The caller retains ownership of 'fm->ofpacts'. */
static enum ofperr
add_flow_begin(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
               struct rule **rulep, bool *modify)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table;
    struct cls_rule cr;
    struct rule *rule;
    uint8_t table_id;
    enum ofperr error = 0;

    if (!check_table_id(ofproto, fm->table_id)) {
        error = OFPERR_OFPBRC_BAD_TABLE_ID;
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
    if (table->flags & OFTABLE_READONLY
        && !(fm->flags & OFPUTIL_FF_NO_READONLY)) {
        return OFPERR_OFPBRC_EPERM;
    }

    if (!(fm->flags & OFPUTIL_FF_HIDDEN_FIELDS)
        && !match_has_default_hidden_fields(&fm->match)) {
        VLOG_WARN_RL(&rl, "%s: (add_flow) only internal flows can set "
                     "non-default values to hidden fields", ofproto->name);
        return OFPERR_OFPBRC_EPERM;
    }

    cls_rule_init(&cr, &fm->match, fm->priority);

    /* Check for the existence of an identical rule.
     * This will not return rules earlier marked as 'to_be_removed'. */
    rule = rule_from_cls_rule(classifier_find_rule_exactly(&table->cls, &cr));
    if (rule) {
        /* Transform "add" into "modify" of an existing identical flow. */
        cls_rule_destroy(&cr);

        fm->modify_cookie = true;
        error = modify_flow_check__(ofproto, fm, rule);
        if (error) {
            return error;
        }

        *modify = true;
    } else {   /* New rule. */
        struct cls_conjunction *conjs;
        size_t n_conjs;

        /* Check for overlap, if requested. */
        if (fm->flags & OFPUTIL_FF_CHECK_OVERLAP
            && classifier_rule_overlaps(&table->cls, &cr)) {
            cls_rule_destroy(&cr);
            return OFPERR_OFPFMFC_OVERLAP;
        }

        /* If necessary, evict an existing rule to clear out space. */
        error = evict_rules_from_table(table, 1);
        if (error) {
            cls_rule_destroy(&cr);
            return error;
        }

        /* Allocate new rule. */
        error = ofproto_rule_create(ofproto, fm, &cr, table - ofproto->tables,
                                    &rule);
        if (error) {
            return error;
        }

        /* Insert flow to the classifier, so that later flow_mods may relate
         * to it.  This is reversible, in case later errors require this to
         * be reverted. */
        ofproto_rule_insert__(ofproto, rule);
        /* Make the new rule invisible for classifier lookups. */
        classifier_defer(&table->cls);
        get_conjunctions(fm, &conjs, &n_conjs);
        classifier_insert(&table->cls, &rule->cr, conjs, n_conjs);
        free(conjs);

        error = ofproto->ofproto_class->rule_insert(rule);
        if (error) {
            oftable_remove_rule(rule);
            ofproto_rule_unref(rule);
            return error;
        }

        *modify = false;
    }

    *rulep = rule;
    return 0;
}

/* Revert the effects of add_flow_begin().
 * 'new_rule' must be passed in as NULL, if no new rule was allocated and
 * inserted to the classifier.
 * Note: evictions cannot be reverted. */
static void
add_flow_revert(struct ofproto *ofproto, struct rule *new_rule)
    OVS_REQUIRES(ofproto_mutex)
{
    /* Old rule was not changed yet, only need to revert a new rule. */
    if (new_rule) {
        struct oftable *table = &ofproto->tables[new_rule->table_id];

        if (!classifier_remove(&table->cls, &new_rule->cr)) {
            OVS_NOT_REACHED();
        }
        classifier_publish(&table->cls);

        ofproto_rule_remove__(ofproto, new_rule);
        ofproto->ofproto_class->rule_delete(new_rule);
        ofproto_rule_unref(new_rule);
    }
}

static void
add_flow_finish(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                const struct flow_mod_requester *req,
                struct rule *rule, bool modify)
    OVS_REQUIRES(ofproto_mutex)
{
    if (modify) {
        struct ovs_list dead_cookies = OVS_LIST_INITIALIZER(&dead_cookies);

        modify_flow__(ofproto, fm, req, rule, &dead_cookies);
        learned_cookies_flush(ofproto, &dead_cookies);
    } else {
        struct oftable *table = &ofproto->tables[rule->table_id];

        cls_rule_make_visible(&rule->cr);
        classifier_publish(&table->cls);

        learned_cookies_inc(ofproto, rule_get_actions(rule));

        if (minimask_get_vid_mask(&rule->cr.match.mask) == VLAN_VID_MASK) {
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

        ofmonitor_report(ofproto->connmgr, rule, NXFME_ADDED, 0,
                         req ? req->ofconn : NULL,
                         req ? req->request->xid : 0, NULL);
    }

    send_buffered_packet(req, fm->buffer_id, rule);
}

/* OFPFC_MODIFY and OFPFC_MODIFY_STRICT. */

/* Checks if the 'rule' can be modified to match 'fm'.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
modify_flow_check__(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                    const struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    if (ofproto->ofproto_class->rule_premodify_actions) {
        return ofproto->ofproto_class->rule_premodify_actions(
            rule, fm->ofpacts, fm->ofpacts_len);
    }
    return 0;
}

/* Checks if the rules listed in 'rules' can have their actions changed to
 * match those in 'fm'.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
modify_flows_check__(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                     const struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    enum ofperr error;
    size_t i;

    if (ofproto->ofproto_class->rule_premodify_actions) {
        for (i = 0; i < rules->n; i++) {
            error = modify_flow_check__(ofproto, fm, rules->rules[i]);
            if (error) {
                return error;
            }
        }
    }

    return 0;
}

/* Modifies the 'rule', changing them to match 'fm'. */
static void
modify_flow__(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
              const struct flow_mod_requester *req, struct rule *rule,
              struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex)
{
    enum nx_flow_update_event event = fm->command == OFPFC_ADD
        ? NXFME_ADDED : NXFME_MODIFIED;

    /*  'fm' says that  */
    bool change_cookie = (fm->modify_cookie
                          && fm->new_cookie != OVS_BE64_MAX
                          && fm->new_cookie != rule->flow_cookie);

    const struct rule_actions *actions = rule_get_actions(rule);
    bool change_actions = !ofpacts_equal(fm->ofpacts, fm->ofpacts_len,
                                         actions->ofpacts,
                                         actions->ofpacts_len);

    bool reset_counters = (fm->flags & OFPUTIL_FF_RESET_COUNTS) != 0;

    long long int now = time_msec();

    if (change_cookie) {
        cookies_remove(ofproto, rule);
    }

    ovs_mutex_lock(&rule->mutex);
    if (fm->command == OFPFC_ADD) {
        rule->idle_timeout = fm->idle_timeout;
        rule->hard_timeout = fm->hard_timeout;
        rule->importance = fm->importance;
        rule->flags = fm->flags & OFPUTIL_FF_STATE;
        rule->created = now;
    }
    if (change_cookie) {
        rule->flow_cookie = fm->new_cookie;
    }
    rule->modified = now;
    ovs_mutex_unlock(&rule->mutex);

    if (change_cookie) {
        cookies_insert(ofproto, rule);
    }
    if (fm->command == OFPFC_ADD) {
        if (fm->idle_timeout || fm->hard_timeout || fm->importance) {
            if (!rule->eviction_group) {
                eviction_group_add_rule(rule);
            }
        } else {
            eviction_group_remove_rule(rule);
        }
    }

    if (change_actions) {
        /* We have to change the actions.  The rule's conjunctive match set
         * is a function of its actions, so we need to update that too.  The
         * conjunctive match set is used in the lookup process to figure
         * which (if any) collection of conjunctive sets the packet matches
         * with.  However, a rule with conjunction actions is never to be
         * returned as a classifier lookup result.  To make sure a rule with
         * conjunction actions is not returned as a lookup result, we update
         * them in a carefully chosen order:
         *
         * - If we're adding a conjunctive match set where there wasn't one
         *   before, we have to make the conjunctive match set available to
         *   lookups before the rule's actions are changed, as otherwise
         *   rule with a conjunction action could be returned as a lookup
         *   result.
         *
         * - To clear some nonempty conjunctive set, we set the rule's
         *   actions first, so that a lookup can't return a rule with
         *   conjunction actions.
         *
         * - Otherwise, order doesn't matter for changing one nonempty
         *   conjunctive match set to some other nonempty set, since the
         *   rule's actions are not seen by the classifier, and hence don't
         *   matter either before or after the change. */
        struct cls_conjunction *conjs;
        size_t n_conjs;
        get_conjunctions(fm, &conjs, &n_conjs);

        if (n_conjs) {
            set_conjunctions(rule, conjs, n_conjs);
        }
        ovsrcu_set(&rule->actions, rule_actions_create(fm->ofpacts,
                                                           fm->ofpacts_len));
        if (!conjs) {
            set_conjunctions(rule, conjs, n_conjs);
        }

        free(conjs);
    }

    if (change_actions || reset_counters) {
        ofproto->ofproto_class->rule_modify_actions(rule, reset_counters);
    }

    if (event != NXFME_MODIFIED || change_actions || change_cookie) {
        ofmonitor_report(ofproto->connmgr, rule, event, 0,
                         req ? req->ofconn : NULL, req ? req->request->xid : 0,
                         change_actions ? actions : NULL);
    }

    if (change_actions) {
        learned_cookies_inc(ofproto, rule_get_actions(rule));
        learned_cookies_dec(ofproto, actions, dead_cookies);
        rule_actions_destroy(actions);
    }
}

/* Modifies the rules listed in 'rules', changing their actions to match those
 * in 'fm'.
 *
 * 'req' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any. */
static void
modify_flows__(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
               const struct flow_mod_requester *req,
               const struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ovs_list dead_cookies = OVS_LIST_INITIALIZER(&dead_cookies);
    size_t i;

    for (i = 0; i < rules->n; i++) {
        modify_flow__(ofproto, fm, req, rules->rules[i], &dead_cookies);
    }
    learned_cookies_flush(ofproto, &dead_cookies);
}

static enum ofperr
modify_flows_begin__(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                     struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    enum ofperr error;

    if (rules->n > 0) {
        error = modify_flows_check__(ofproto, fm, rules);
    } else if (!(fm->cookie_mask != htonll(0)
                 || fm->new_cookie == OVS_BE64_MAX)) {
        bool modify;

        error = add_flow_begin(ofproto, fm, &rules->rules[0], &modify);
        if (!error) {
            ovs_assert(!modify);
        }
    } else {
        rules->rules[0] = NULL;
        error = 0;
    }
    return error;
}

/* Implements OFPFC_MODIFY.  Returns 0 on success or an OpenFlow error code on
 * failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any. */
static enum ofperr
modify_flows_begin_loose(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                         struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_criteria criteria;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, 0,
                       fm->cookie, fm->cookie_mask, OFPP_ANY, OFPG11_ANY);
    rule_criteria_require_rw(&criteria,
                             (fm->flags & OFPUTIL_FF_NO_READONLY) != 0);
    error = collect_rules_loose(ofproto, &criteria, rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        error = modify_flows_begin__(ofproto, fm, rules);
    }

    if (error) {
        rule_collection_destroy(rules);
    }
    return error;
}

static void
modify_flows_revert(struct ofproto *ofproto, struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    /* Old rules were not changed yet, only need to revert a new rule. */
    if (rules->n == 0 && rules->rules[0] != NULL) {
        add_flow_revert(ofproto, rules->rules[0]);
    }
    rule_collection_destroy(rules);
}

static void
modify_flows_finish(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                    const struct flow_mod_requester *req,
                    struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    if (rules->n > 0) {
        modify_flows__(ofproto, fm, req, rules);
        send_buffered_packet(req, fm->buffer_id, rules->rules[0]);
    } else if (rules->rules[0] != NULL) {
        add_flow_finish(ofproto, fm, req, rules->rules[0], false);
    }
    rule_collection_destroy(rules);
}

/* Implements OFPFC_MODIFY_STRICT.  Returns 0 on success or an OpenFlow error
 * code on failure. */
static enum ofperr
modify_flow_begin_strict(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                         struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_criteria criteria;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, fm->priority,
                       fm->cookie, fm->cookie_mask, OFPP_ANY, OFPG11_ANY);
    rule_criteria_require_rw(&criteria,
                             (fm->flags & OFPUTIL_FF_NO_READONLY) != 0);
    error = collect_rules_strict(ofproto, &criteria, rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        /* collect_rules_strict() can return max 1 rule. */
        error = modify_flows_begin__(ofproto, fm, rules);
    }

    if (error) {
        rule_collection_destroy(rules);
    }
    return error;
}

/* OFPFC_DELETE implementation. */

/* Deletes the rules listed in 'rules'. */
static void
delete_flows__(const struct rule_collection *rules,
               enum ofp_flow_removed_reason reason,
               const struct flow_mod_requester *req)
    OVS_REQUIRES(ofproto_mutex)
{
    if (rules->n) {
        struct ovs_list dead_cookies = OVS_LIST_INITIALIZER(&dead_cookies);
        struct ofproto *ofproto = rules->rules[0]->ofproto;
        struct rule *rule, *next;
        size_t i;

        for (i = 0, next = rules->rules[0];
             rule = next, next = (++i < rules->n) ? rules->rules[i] : NULL,
                 rule; ) {
            struct classifier *cls = &ofproto->tables[rule->table_id].cls;
            uint8_t next_table = next ? next->table_id : UINT8_MAX;

            ofproto_rule_send_removed(rule, reason);

            ofmonitor_report(ofproto->connmgr, rule, NXFME_DELETED, reason,
                             req ? req->ofconn : NULL,
                             req ? req->request->xid : 0, NULL);

            if (next_table == rule->table_id) {
                classifier_defer(cls);
            }
            classifier_remove(cls, &rule->cr);
            if (next_table != rule->table_id) {
                classifier_publish(cls);
            }
            ofproto_rule_remove__(ofproto, rule);

            ofproto->ofproto_class->rule_delete(rule);

            learned_cookies_dec(ofproto, rule_get_actions(rule),
                                &dead_cookies);

            ofproto_rule_unref(rule);
        }
        learned_cookies_flush(ofproto, &dead_cookies);
        ofmonitor_flush(ofproto->connmgr);
    }
}

/* Implements OFPFC_DELETE. */
static enum ofperr
delete_flows_begin_loose(struct ofproto *ofproto,
                         const struct ofputil_flow_mod *fm,
                         struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_criteria criteria;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, 0,
                       fm->cookie, fm->cookie_mask,
                       fm->out_port, fm->out_group);
    rule_criteria_require_rw(&criteria,
                             (fm->flags & OFPUTIL_FF_NO_READONLY) != 0);
    error = collect_rules_loose(ofproto, &criteria, rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        for (size_t i = 0; i < rules->n; i++) {
            struct rule *rule = rules->rules[i];

            CONST_CAST(struct cls_rule *, &rule->cr)->to_be_removed = true;
        }
    }

    return error;
}

static void
delete_flows_revert(struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    for (size_t i = 0; i < rules->n; i++) {
        struct rule *rule = rules->rules[i];

        CONST_CAST(struct cls_rule *, &rule->cr)->to_be_removed = false;
    }
    rule_collection_destroy(rules);
}

static void
delete_flows_finish(const struct ofputil_flow_mod *fm,
                    const struct flow_mod_requester *req,
                    struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    delete_flows__(rules, fm->delete_reason, req);
    rule_collection_destroy(rules);
}

/* Implements OFPFC_DELETE_STRICT. */
static enum ofperr
delete_flow_begin_strict(struct ofproto *ofproto,
                         const struct ofputil_flow_mod *fm,
                         struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_criteria criteria;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, fm->priority,
                       fm->cookie, fm->cookie_mask,
                       fm->out_port, fm->out_group);
    rule_criteria_require_rw(&criteria,
                             (fm->flags & OFPUTIL_FF_NO_READONLY) != 0);
    error = collect_rules_strict(ofproto, &criteria, rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        for (size_t i = 0; i < rules->n; i++) {
            struct rule *rule = rules->rules[i];

            CONST_CAST(struct cls_rule *, &rule->cr)->to_be_removed = true;
        }
    }

    return error;
}

static void
ofproto_rule_send_removed(struct rule *rule, uint8_t reason)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofputil_flow_removed fr;
    long long int used;

    if (rule_is_hidden(rule) ||
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
                                                 &fr.byte_count, &used);

    connmgr_send_flow_removed(rule->ofproto->connmgr, &fr);
}

/* Sends an OpenFlow "flow removed" message with the given 'reason' (either
 * OFPRR_HARD_TIMEOUT or OFPRR_IDLE_TIMEOUT), and then removes 'rule' from its
 * ofproto.
 *
 * ofproto implementation ->run() functions should use this function to expire
 * OpenFlow flows. */
void
ofproto_rule_expire(struct rule *rule, uint8_t reason)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_collection rules;

    rules.rules = rules.stub;
    rules.n = 1;
    rules.stub[0] = rule;
    delete_flows__(&rules, reason, NULL);
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
        struct flow_mod_requester req;

        req.ofconn = ofconn;
        req.request = oh;
        error = handle_flow_mod__(ofproto, &fm, &req);
    }
    if (error) {
        goto exit_free_ofpacts;
    }

    ofconn_report_flow_mod(ofconn, fm.command);

exit_free_ofpacts:
    ofpbuf_uninit(&ofpacts);
exit:
    return error;
}

static enum ofperr
handle_flow_mod__(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                  const struct flow_mod_requester *req)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofp_bundle_entry be;
    enum ofperr error;

    ovs_mutex_lock(&ofproto_mutex);
    error = do_bundle_flow_mod_begin(ofproto, fm, &be);
    if (!error) {
        do_bundle_flow_mod_finish(ofproto, fm, req, &be);
    }
    ofmonitor_flush(ofproto->connmgr);
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

    buf = ofpraw_alloc_reply((oh->version == OFP10_VERSION
                              ? OFPRAW_OFPT10_BARRIER_REPLY
                              : OFPRAW_OFPT11_BARRIER_REPLY), oh, 0);
    ofconn_send_reply(ofconn, buf);
    return 0;
}

static void
ofproto_compose_flow_refresh_update(const struct rule *rule,
                                    enum nx_flow_monitor_flags flags,
                                    struct ovs_list *msgs)
    OVS_REQUIRES(ofproto_mutex)
{
    const struct rule_actions *actions;
    struct ofputil_flow_update fu;
    struct match match;

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

    actions = flags & NXFMF_ACTIONS ? rule_get_actions(rule) : NULL;
    fu.ofpacts = actions ? actions->ofpacts : NULL;
    fu.ofpacts_len = actions ? actions->ofpacts_len : 0;

    if (list_is_empty(msgs)) {
        ofputil_start_flow_update(msgs);
    }
    ofputil_append_flow_update(&fu, msgs);
}

void
ofmonitor_compose_refresh_updates(struct rule_collection *rules,
                                  struct ovs_list *msgs)
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

    if (rule_is_hidden(rule)) {
        return;
    }

    if (!ofproto_rule_has_out_port(rule, m->out_port)) {
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
    const struct oftable *table;
    struct cls_rule target;

    cls_rule_init_from_minimatch(&target, &m->match, 0);
    FOR_EACH_MATCHING_TABLE (table, m->table_id, ofproto) {
        struct rule *rule;

        CLS_FOR_EACH_TARGET (rule, cr, &table->cls, &target) {
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
flow_monitor_delete(struct ofconn *ofconn, uint32_t id)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofmonitor *m;
    enum ofperr error;

    m = ofmonitor_lookup(ofconn, id);
    if (m) {
        ofmonitor_destroy(m);
        error = 0;
    } else {
        error = OFPERR_OFPMOFC_UNKNOWN_MONITOR;
    }

    return error;
}

static enum ofperr
handle_flow_monitor_request(struct ofconn *ofconn, const struct ofp_header *oh)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofmonitor **monitors;
    size_t n_monitors, allocated_monitors;
    struct rule_collection rules;
    struct ovs_list replies;
    enum ofperr error;
    struct ofpbuf b;
    size_t i;

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
    enum ofperr error;
    uint32_t id;

    id = ofputil_decode_flow_monitor_cancel(oh);

    ovs_mutex_lock(&ofproto_mutex);
    error = flow_monitor_delete(ofconn, id);
    ovs_mutex_unlock(&ofproto_mutex);

    return error;
}

/* Meters implementation.
 *
 * Meter table entry, indexed by the OpenFlow meter_id.
 * 'created' is used to compute the duration for meter stats.
 * 'list rules' is needed so that we can delete the dependent rules when the
 * meter table entry is deleted.
 * 'provider_meter_id' is for the provider's private use.
 */
struct meter {
    long long int created;      /* Time created. */
    struct ovs_list rules;      /* List of "struct rule_dpif"s. */
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

/* Finds the meter invoked by 'rule''s actions and adds 'rule' to the meter's
 * list of rules. */
static void
meter_insert_rule(struct rule *rule)
{
    const struct rule_actions *a = rule_get_actions(rule);
    uint32_t meter_id = ofpacts_get_meter(a->ofpacts, a->ofpacts_len);
    struct meter *meter = rule->ofproto->meters[meter_id];

    list_insert(&meter->rules, &rule->meter_list_node);
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
handle_delete_meter(struct ofconn *ofconn, struct ofputil_meter_mod *mm)
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
                rule_collection_add(&rules, rule);
            }
        }
    }
    delete_flows__(&rules, OFPRR_METER_DELETE, NULL);

    /* Delete the meters. */
    meter_delete(ofproto, first, last);

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
        error = handle_delete_meter(ofconn, &mm);
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
    struct ovs_list replies;
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

static bool
ofproto_group_lookup__(const struct ofproto *ofproto, uint32_t group_id,
                       struct ofgroup **group)
    OVS_REQ_RDLOCK(ofproto->groups_rwlock)
{
    HMAP_FOR_EACH_IN_BUCKET (*group, hmap_node,
                             hash_int(group_id, 0), &ofproto->groups) {
        if ((*group)->group_id == group_id) {
            return true;
        }
    }

    return false;
}

/* If the group exists, this function increments the groups's reference count.
 *
 * Make sure to call ofproto_group_unref() after no longer needing to maintain
 * a reference to the group. */
bool
ofproto_group_lookup(const struct ofproto *ofproto, uint32_t group_id,
                     struct ofgroup **group)
{
    bool found;

    ovs_rwlock_rdlock(&ofproto->groups_rwlock);
    found = ofproto_group_lookup__(ofproto, group_id, group);
    if (found) {
        ofproto_group_ref(*group);
    }
    ovs_rwlock_unlock(&ofproto->groups_rwlock);
    return found;
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
    struct ofproto *ofproto = CONST_CAST(struct ofproto *, group->ofproto);
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
append_group_stats(struct ofgroup *group, struct ovs_list *replies)
{
    struct ofputil_group_stats ogs;
    const struct ofproto *ofproto = group->ofproto;
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

static void
handle_group_request(struct ofconn *ofconn,
                     const struct ofp_header *request, uint32_t group_id,
                     void (*cb)(struct ofgroup *, struct ovs_list *replies))
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofgroup *group;
    struct ovs_list replies;

    ofpmp_init(&replies, request);
    if (group_id == OFPG_ALL) {
        ovs_rwlock_rdlock(&ofproto->groups_rwlock);
        HMAP_FOR_EACH (group, hmap_node, &ofproto->groups) {
            cb(group, &replies);
        }
        ovs_rwlock_unlock(&ofproto->groups_rwlock);
    } else {
        if (ofproto_group_lookup(ofproto, group_id, &group)) {
            cb(group, &replies);
            ofproto_group_unref(group);
        }
    }
    ofconn_send_replies(ofconn, &replies);
}

static enum ofperr
handle_group_stats_request(struct ofconn *ofconn,
                           const struct ofp_header *request)
{
    uint32_t group_id;
    enum ofperr error;

    error = ofputil_decode_group_stats_request(request, &group_id);
    if (error) {
        return error;
    }

    handle_group_request(ofconn, request, group_id, append_group_stats);
    return 0;
}

static void
append_group_desc(struct ofgroup *group, struct ovs_list *replies)
{
    struct ofputil_group_desc gds;

    gds.group_id = group->group_id;
    gds.type = group->type;
    gds.props = group->props;

    ofputil_append_group_desc_reply(&gds, &group->buckets, replies);
}

static enum ofperr
handle_group_desc_stats_request(struct ofconn *ofconn,
                                const struct ofp_header *request)
{
    handle_group_request(ofconn, request,
                         ofputil_decode_group_desc_request(request),
                         append_group_desc);
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

static enum ofperr
init_group(struct ofproto *ofproto, struct ofputil_group_mod *gm,
           struct ofgroup **ofgroup)
{
    enum ofperr error;
    const long long int now = time_msec();

    if (gm->group_id > OFPG_MAX) {
        return OFPERR_OFPGMFC_INVALID_GROUP;
    }
    if (gm->type > OFPGT11_FF) {
        return OFPERR_OFPGMFC_BAD_TYPE;
    }

    *ofgroup = ofproto->ofproto_class->group_alloc();
    if (!*ofgroup) {
        VLOG_WARN_RL(&rl, "%s: failed to allocate group", ofproto->name);
        return OFPERR_OFPGMFC_OUT_OF_GROUPS;
    }

    (*ofgroup)->ofproto = ofproto;
    *CONST_CAST(uint32_t *, &((*ofgroup)->group_id)) = gm->group_id;
    *CONST_CAST(enum ofp11_group_type *, &(*ofgroup)->type) = gm->type;
    *CONST_CAST(long long int *, &((*ofgroup)->created)) = now;
    *CONST_CAST(long long int *, &((*ofgroup)->modified)) = now;
    ovs_refcount_init(&(*ofgroup)->ref_count);

    list_move(&(*ofgroup)->buckets, &gm->buckets);
    *CONST_CAST(uint32_t *, &(*ofgroup)->n_buckets) =
        list_size(&(*ofgroup)->buckets);

    memcpy(CONST_CAST(struct ofputil_group_props *, &(*ofgroup)->props),
           &gm->props, sizeof (struct ofputil_group_props));

    /* Construct called BEFORE any locks are held. */
    error = ofproto->ofproto_class->group_construct(*ofgroup);
    if (error) {
        ofputil_bucket_list_destroy(&(*ofgroup)->buckets);
        ofproto->ofproto_class->group_dealloc(*ofgroup);
    }
    return error;
}

/* Implements the OFPGC11_ADD operation specified by 'gm', adding a group to
 * 'ofproto''s group table.  Returns 0 on success or an OpenFlow error code on
 * failure. */
static enum ofperr
add_group(struct ofproto *ofproto, struct ofputil_group_mod *gm)
{
    struct ofgroup *ofgroup;
    enum ofperr error;

    /* Allocate new group and initialize it. */
    error = init_group(ofproto, gm, &ofgroup);
    if (error) {
        return error;
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
    ofputil_bucket_list_destroy(&ofgroup->buckets);
    ofproto->ofproto_class->group_dealloc(ofgroup);

    return error;
}

/* Adds all of the buckets from 'ofgroup' to 'new_ofgroup'.  The buckets
 * already in 'new_ofgroup' will be placed just after the (copy of the) bucket
 * in 'ofgroup' with bucket ID 'command_bucket_id'.  Special
 * 'command_bucket_id' values OFPG15_BUCKET_FIRST and OFPG15_BUCKET_LAST are
 * also honored. */
static enum ofperr
copy_buckets_for_insert_bucket(const struct ofgroup *ofgroup,
                               struct ofgroup *new_ofgroup,
                               uint32_t command_bucket_id)
{
    struct ofputil_bucket *last = NULL;

    if (command_bucket_id <= OFPG15_BUCKET_MAX) {
        /* Check here to ensure that a bucket corresponding to
         * command_bucket_id exists in the old bucket list.
         *
         * The subsequent search of below of new_ofgroup covers
         * both buckets in the old bucket list and buckets added
         * by the insert buckets group mod message this function processes. */
        if (!ofputil_bucket_find(&ofgroup->buckets, command_bucket_id)) {
            return OFPERR_OFPGMFC_UNKNOWN_BUCKET;
        }

        if (!list_is_empty(&new_ofgroup->buckets)) {
            last = ofputil_bucket_list_back(&new_ofgroup->buckets);
        }
    }

    ofputil_bucket_clone_list(&new_ofgroup->buckets, &ofgroup->buckets, NULL);

    if (ofputil_bucket_check_duplicate_id(&ofgroup->buckets)) {
            VLOG_WARN_RL(&rl, "Duplicate bucket id");
            return OFPERR_OFPGMFC_BUCKET_EXISTS;
    }

    /* Rearrange list according to command_bucket_id */
    if (command_bucket_id == OFPG15_BUCKET_LAST) {
        struct ofputil_bucket *new_first;
        const struct ofputil_bucket *first;

        first = ofputil_bucket_list_front(&ofgroup->buckets);
        new_first = ofputil_bucket_find(&new_ofgroup->buckets,
                                        first->bucket_id);

        list_splice(new_ofgroup->buckets.next, &new_first->list_node,
                    &new_ofgroup->buckets);
    } else if (command_bucket_id <= OFPG15_BUCKET_MAX && last) {
        struct ofputil_bucket *after;

        /* Presence of bucket is checked above so after should never be NULL */
        after = ofputil_bucket_find(&new_ofgroup->buckets, command_bucket_id);

        list_splice(after->list_node.next, new_ofgroup->buckets.next,
                    last->list_node.next);
    }

    return 0;
}

/* Appends all of the a copy of all the buckets from 'ofgroup' to 'new_ofgroup'
 * with the exception of the bucket whose bucket id is 'command_bucket_id'.
 * Special 'command_bucket_id' values OFPG15_BUCKET_FIRST, OFPG15_BUCKET_LAST
 * and OFPG15_BUCKET_ALL are also honored. */
static enum ofperr
copy_buckets_for_remove_bucket(const struct ofgroup *ofgroup,
                               struct ofgroup *new_ofgroup,
                               uint32_t command_bucket_id)
{
    const struct ofputil_bucket *skip = NULL;

    if (command_bucket_id == OFPG15_BUCKET_ALL) {
        return 0;
    }

    if (command_bucket_id == OFPG15_BUCKET_FIRST) {
        if (!list_is_empty(&ofgroup->buckets)) {
            skip = ofputil_bucket_list_front(&ofgroup->buckets);
        }
    } else if (command_bucket_id == OFPG15_BUCKET_LAST) {
        if (!list_is_empty(&ofgroup->buckets)) {
            skip = ofputil_bucket_list_back(&ofgroup->buckets);
        }
    } else {
        skip = ofputil_bucket_find(&ofgroup->buckets, command_bucket_id);
        if (!skip) {
            return OFPERR_OFPGMFC_UNKNOWN_BUCKET;
        }
    }

    ofputil_bucket_clone_list(&new_ofgroup->buckets, &ofgroup->buckets, skip);

    return 0;
}

/* Implements OFPGC11_MODIFY, OFPGC15_INSERT_BUCKET and
 * OFPGC15_REMOVE_BUCKET.  Returns 0 on success or an OpenFlow error code
 * on failure.
 *
 * Note that the group is re-created and then replaces the old group in
 * ofproto's ofgroup hash map. Thus, the group is never altered while users of
 * the xlate module hold a pointer to the group. */
static enum ofperr
modify_group(struct ofproto *ofproto, struct ofputil_group_mod *gm)
{
    struct ofgroup *ofgroup, *new_ofgroup, *retiring;
    enum ofperr error;

    error = init_group(ofproto, gm, &new_ofgroup);
    if (error) {
        return error;
    }

    retiring = new_ofgroup;

    ovs_rwlock_wrlock(&ofproto->groups_rwlock);
    if (!ofproto_group_lookup__(ofproto, gm->group_id, &ofgroup)) {
        error = OFPERR_OFPGMFC_UNKNOWN_GROUP;
        goto out;
    }

    /* Ofproto's group write lock is held now. */
    if (ofgroup->type != gm->type
        && ofproto->n_groups[gm->type] >= ofproto->ogf.max_groups[gm->type]) {
        error = OFPERR_OFPGMFC_OUT_OF_GROUPS;
        goto out;
    }

    /* Manipulate bucket list for bucket commands */
    if (gm->command == OFPGC15_INSERT_BUCKET) {
        error = copy_buckets_for_insert_bucket(ofgroup, new_ofgroup,
                                               gm->command_bucket_id);
    } else if (gm->command == OFPGC15_REMOVE_BUCKET) {
        error = copy_buckets_for_remove_bucket(ofgroup, new_ofgroup,
                                               gm->command_bucket_id);
    }
    if (error) {
        goto out;
    }

    /* The group creation time does not change during modification. */
    *CONST_CAST(long long int *, &(new_ofgroup->created)) = ofgroup->created;
    *CONST_CAST(long long int *, &(new_ofgroup->modified)) = time_msec();

    error = ofproto->ofproto_class->group_modify(new_ofgroup);
    if (error) {
        goto out;
    }

    retiring = ofgroup;
    /* Replace ofgroup in ofproto's groups hash map with new_ofgroup. */
    hmap_remove(&ofproto->groups, &ofgroup->hmap_node);
    hmap_insert(&ofproto->groups, &new_ofgroup->hmap_node,
                hash_int(new_ofgroup->group_id, 0));
    if (ofgroup->type != new_ofgroup->type) {
        ofproto->n_groups[ofgroup->type]--;
        ofproto->n_groups[new_ofgroup->type]++;
    }

out:
    ofproto_group_unref(retiring);
    ovs_rwlock_unlock(&ofproto->groups_rwlock);
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
    fm.delete_reason = OFPRR_GROUP_DELETE;
    fm.out_group = ofgroup->group_id;
    handle_flow_mod__(ofproto, &fm, NULL);

    hmap_remove(&ofproto->groups, &ofgroup->hmap_node);
    /* No-one can find this group any more. */
    ofproto->n_groups[ofgroup->type]--;
    ovs_rwlock_unlock(&ofproto->groups_rwlock);
    ofproto_group_unref(ofgroup);
}

/* Implements OFPGC11_DELETE. */
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

    case OFPGC15_INSERT_BUCKET:
        return modify_group(ofproto, &gm);

    case OFPGC15_REMOVE_BUCKET:
        return modify_group(ofproto, &gm);

    default:
        if (gm.command > OFPGC11_DELETE) {
            VLOG_WARN_RL(&rl, "%s: Invalid group_mod command type %d",
                         ofproto->name, gm.command);
        }
        return OFPERR_OFPGMFC_BAD_COMMAND;
    }
}

enum ofputil_table_miss
ofproto_table_get_miss_config(const struct ofproto *ofproto, uint8_t table_id)
{
    enum ofputil_table_miss value;

    atomic_read_relaxed(&ofproto->tables[table_id].miss_config, &value);
    return value;
}

static enum ofperr
table_mod(struct ofproto *ofproto, const struct ofputil_table_mod *tm)
{
    if (!check_table_id(ofproto, tm->table_id)) {
        return OFPERR_OFPTMFC_BAD_TABLE;
    } else if (tm->miss_config != OFPUTIL_TABLE_MISS_DEFAULT) {
        if (tm->table_id == OFPTT_ALL) {
            int i;
            for (i = 0; i < ofproto->n_tables; i++) {
                atomic_store_relaxed(&ofproto->tables[i].miss_config,
                                     tm->miss_config);
            }
        } else {
            atomic_store_relaxed(&ofproto->tables[tm->table_id].miss_config,
                                 tm->miss_config);
        }
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
do_bundle_flow_mod_begin(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                         struct ofp_bundle_entry *be)
    OVS_REQUIRES(ofproto_mutex)
{
    switch (fm->command) {
    case OFPFC_ADD:
        return add_flow_begin(ofproto, fm, &be->rule, &be->modify);

    case OFPFC_MODIFY:
        return modify_flows_begin_loose(ofproto, fm, &be->rules);

    case OFPFC_MODIFY_STRICT:
        return modify_flow_begin_strict(ofproto, fm, &be->rules);

    case OFPFC_DELETE:
        return delete_flows_begin_loose(ofproto, fm, &be->rules);

    case OFPFC_DELETE_STRICT:
        return delete_flow_begin_strict(ofproto, fm, &be->rules);
    }

    return OFPERR_OFPFMFC_BAD_COMMAND;
}

static void
do_bundle_flow_mod_revert(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                          struct ofp_bundle_entry *be)
    OVS_REQUIRES(ofproto_mutex)
{
    switch (fm->command) {
    case OFPFC_ADD:
        add_flow_revert(ofproto, be->modify ? NULL : be->rule);
        break;

    case OFPFC_MODIFY:
    case OFPFC_MODIFY_STRICT:
        modify_flows_revert(ofproto, &be->rules);
        break;

    case OFPFC_DELETE:
    case OFPFC_DELETE_STRICT:
        delete_flows_revert(&be->rules);
        break;

    default:
        break;
    }
}

static void
do_bundle_flow_mod_finish(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                          const struct flow_mod_requester *req,
                          struct ofp_bundle_entry *be)
    OVS_REQUIRES(ofproto_mutex)
{
    switch (fm->command) {
    case OFPFC_ADD:
        add_flow_finish(ofproto, fm, req, be->rule, be->modify);
        break;

    case OFPFC_MODIFY:
    case OFPFC_MODIFY_STRICT:
        modify_flows_finish(ofproto, fm, req, &be->rules);
        break;

    case OFPFC_DELETE:
    case OFPFC_DELETE_STRICT:
        delete_flows_finish(fm, req, &be->rules);
        break;

    default:
        break;
    }
}

/* Commit phases (all while locking ofproto_mutex):
 *
 * 1. Gather resources - do not send any events or notifications.
 *
 * add: Check conflicts, check for a displaced flow. If no displaced flow
 *      exists, add the new flow, but mark it as "invisible".
 * mod: Collect affected flows, Do not modify yet.
 * del: Collect affected flows, Do not delete yet.
 *
 * 2a. Fail if any errors are found.  After this point no errors are possible.
 * No visible changes were made, so rollback is minimal (remove added invisible
 * flows, revert 'to_be_removed' status of flows).
 *
 * 2b. Commit the changes
 *
 * add: if have displaced flow, modify it, otherwise mark the new flow as
 *      "visible".
 * mod: Modify the collected flows.
 * del: Delete the collected flows.
 */
static enum ofperr
do_bundle_commit(struct ofconn *ofconn, uint32_t id, uint16_t flags)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofp_bundle *bundle;
    struct ofp_bundle_entry *be;
    enum ofperr error;

    bundle = ofconn_get_bundle(ofconn, id);

    if (!bundle) {
        return OFPERR_OFPBFC_BAD_ID;
    }
    if (bundle->flags != flags) {
        error = OFPERR_OFPBFC_BAD_FLAGS;
    } else {
        error = 0;
        ovs_mutex_lock(&ofproto_mutex);
        LIST_FOR_EACH (be, node, &bundle->msg_list) {
            if (be->type == OFPTYPE_PORT_MOD) {
                /* Not supported yet. */
                error = OFPERR_OFPBFC_MSG_FAILED;
            } else if (be->type == OFPTYPE_FLOW_MOD) {
                error = do_bundle_flow_mod_begin(ofproto, &be->fm, be);
            } else {
                OVS_NOT_REACHED();
            }
            if (error) {
                break;
            }
        }
        if (error) {
            /* Send error referring to the original message. */
            if (error) {
                ofconn_send_error(ofconn, be->ofp_msg, error);
                error = OFPERR_OFPBFC_MSG_FAILED;
            }

            /* Revert all previous entires. */
            LIST_FOR_EACH_REVERSE_CONTINUE(be, node, &bundle->msg_list) {
                if (be->type == OFPTYPE_FLOW_MOD) {
                    do_bundle_flow_mod_revert(ofproto, &be->fm, be);
                }
            }
        } else {
            /* Finish the changes. */
            LIST_FOR_EACH (be, node, &bundle->msg_list) {
                if (be->type == OFPTYPE_FLOW_MOD) {
                    struct flow_mod_requester req = { ofconn, be->ofp_msg };

                    do_bundle_flow_mod_finish(ofproto, &be->fm, &req, be);
                }
            }
        }
        ofmonitor_flush(ofproto->connmgr);
        ovs_mutex_unlock(&ofproto_mutex);

        run_rule_executes(ofproto);
    }

    /* The bundle is discarded regardless the outcome. */
    ofp_bundle_remove__(ofconn, bundle, !error);
    return error;
}

static enum ofperr
handle_bundle_control(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofputil_bundle_ctrl_msg bctrl;
    struct ofputil_bundle_ctrl_msg reply;
    struct ofpbuf *buf;
    enum ofperr error;

    error = reject_slave_controller(ofconn);
    if (error) {
        return error;
    }

    error = ofputil_decode_bundle_ctrl(oh, &bctrl);
    if (error) {
        return error;
    }
    /* Atomic updates not supported yet. */
    if (bctrl.flags & OFPBF_ATOMIC) {
        return OFPERR_OFPBFC_BAD_FLAGS;
    }
    reply.flags = 0;
    reply.bundle_id = bctrl.bundle_id;

    switch (bctrl.type) {
        case OFPBCT_OPEN_REQUEST:
        error = ofp_bundle_open(ofconn, bctrl.bundle_id, bctrl.flags);
        reply.type = OFPBCT_OPEN_REPLY;
        break;
    case OFPBCT_CLOSE_REQUEST:
        error = ofp_bundle_close(ofconn, bctrl.bundle_id, bctrl.flags);
        reply.type = OFPBCT_CLOSE_REPLY;;
        break;
    case OFPBCT_COMMIT_REQUEST:
        error = do_bundle_commit(ofconn, bctrl.bundle_id, bctrl.flags);
        reply.type = OFPBCT_COMMIT_REPLY;
        break;
    case OFPBCT_DISCARD_REQUEST:
        error = ofp_bundle_discard(ofconn, bctrl.bundle_id);
        reply.type = OFPBCT_DISCARD_REPLY;
        break;

    case OFPBCT_OPEN_REPLY:
    case OFPBCT_CLOSE_REPLY:
    case OFPBCT_COMMIT_REPLY:
    case OFPBCT_DISCARD_REPLY:
        return OFPERR_OFPBFC_BAD_TYPE;
        break;
    }

    if (!error) {
        buf = ofputil_encode_bundle_ctrl_reply(oh, &reply);
        ofconn_send_reply(ofconn, buf);
    }
    return error;
}

static enum ofperr
handle_bundle_add(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    enum ofperr error;
    struct ofputil_bundle_add_msg badd;
    struct ofp_bundle_entry *bmsg;
    enum ofptype type;

    error = reject_slave_controller(ofconn);
    if (error) {
        return error;
    }

    error = ofputil_decode_bundle_add(oh, &badd, &type);
    if (error) {
        return error;
    }

    bmsg = ofp_bundle_entry_alloc(type, badd.msg);

    if (type == OFPTYPE_PORT_MOD) {
        error = ofputil_decode_port_mod(badd.msg, &bmsg->pm, false);
    } else if (type == OFPTYPE_FLOW_MOD) {
        struct ofpbuf ofpacts;
        uint64_t ofpacts_stub[1024 / 8];

        ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
        error = ofputil_decode_flow_mod(&bmsg->fm, badd.msg,
                                        ofconn_get_protocol(ofconn),
                                        &ofpacts,
                                        u16_to_ofp(ofproto->max_ports),
                                        ofproto->n_tables);
        /* Move actions to heap. */
        bmsg->fm.ofpacts = ofpbuf_steal_data(&ofpacts);

        if (!error && bmsg->fm.ofpacts_len) {
            error = ofproto_check_ofpacts(ofproto, bmsg->fm.ofpacts,
                                          bmsg->fm.ofpacts_len);
        }
    } else {
        OVS_NOT_REACHED();
    }

    if (!error) {
        error = ofp_bundle_add_message(ofconn, badd.bundle_id, badd.flags,
                                       bmsg);
    }

    if (error) {
        ofp_bundle_entry_free(bmsg);
    }

    return error;
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

    case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
        return handle_table_features_request(ofconn, oh);

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

    case OFPTYPE_BUNDLE_CONTROL:
        return handle_bundle_control(ofconn, oh);

    case OFPTYPE_BUNDLE_ADD_MESSAGE:
        return handle_bundle_add(ofconn, oh);

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

static void
handle_openflow(struct ofconn *ofconn, const struct ofpbuf *ofp_msg)
    OVS_EXCLUDED(ofproto_mutex)
{
    enum ofperr error = handle_openflow__(ofconn, ofp_msg);

    if (error) {
        ofconn_send_error(ofconn, ofp_msg->data, error);
    }
    COVERAGE_INC(ofproto_recv_openflow);
}

/* Asynchronous operations. */

static void
send_buffered_packet(const struct flow_mod_requester *req, uint32_t buffer_id,
                     struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    if (req && req->ofconn && buffer_id != UINT32_MAX) {
        struct ofproto *ofproto = ofconn_get_ofproto(req->ofconn);
        struct dp_packet *packet;
        ofp_port_t in_port;
        enum ofperr error;

        error = ofconn_pktbuf_retrieve(req->ofconn, buffer_id, &packet,
                                       &in_port);
        if (packet) {
            struct rule_execute *re;

            ofproto_rule_ref(rule);

            re = xmalloc(sizeof *re);
            re->rule = rule;
            re->in_port = in_port;
            re->packet = packet;

            if (!guarded_list_push_back(&ofproto->rule_executes,
                                        &re->list_node, 1024)) {
                ofproto_rule_unref(rule);
                dp_packet_delete(re->packet);
                free(re);
            }
        } else {
            ofconn_send_error(req->ofconn, req->request, error);
        }
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
 * for eviction.
 * Called only if have a timeout. */
static uint32_t
rule_eviction_priority(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    long long int expiration = LLONG_MAX;
    long long int modified;
    uint32_t expiration_offset;

    /* 'modified' needs protection even when we hold 'ofproto_mutex'. */
    ovs_mutex_lock(&rule->mutex);
    modified = rule->modified;
    ovs_mutex_unlock(&rule->mutex);

    if (rule->hard_timeout) {
        expiration = modified + rule->hard_timeout * 1000;
    }
    if (rule->idle_timeout) {
        uint64_t packets, bytes;
        long long int used;
        long long int idle_expiration;

        ofproto->ofproto_class->rule_get_stats(rule, &packets, &bytes, &used);
        idle_expiration = used + rule->idle_timeout * 1000;
        expiration = MIN(expiration, idle_expiration);
    }

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

    /* Timeouts may be modified only when holding 'ofproto_mutex'.  We have it
     * so no additional protection is needed. */
    has_timeout = rule->hard_timeout || rule->idle_timeout;

    if (table->eviction_fields && has_timeout) {
        struct eviction_group *evg;

        evg = eviction_group_find(table, eviction_group_hash_rule(rule));

        rule->eviction_group = evg;
        heap_insert(&evg->rules, &rule->evg_node,
                    rule_eviction_priority(ofproto, rule));
        eviction_group_resized(table, evg);
    }
}

/* oftables. */

/* Initializes 'table'. */
static void
oftable_init(struct oftable *table)
{
    memset(table, 0, sizeof *table);
    classifier_init(&table->cls, flow_segment_u64s);
    table->max_flows = UINT_MAX;
    atomic_init(&table->miss_config, OFPUTIL_TABLE_MISS_DEFAULT);

    classifier_set_prefix_fields(&table->cls, default_prefix_fields,
                                 ARRAY_SIZE(default_prefix_fields));

    atomic_init(&table->n_matched, 0);
    atomic_init(&table->n_missed, 0);
}

/* Destroys 'table', including its classifier and eviction groups.
 *
 * The caller is responsible for freeing 'table' itself. */
static void
oftable_destroy(struct oftable *table)
{
    ovs_assert(classifier_is_empty(&table->cls));
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

    CLS_FOR_EACH (rule, cr, &table->cls) {
        eviction_group_add_rule(rule);
    }
}

/* Inserts 'rule' from the ofproto data structures BEFORE caller has inserted
 * it to the classifier. */
static void
ofproto_rule_insert__(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    const struct rule_actions *actions = rule_get_actions(rule);

    if (rule->hard_timeout || rule->idle_timeout) {
        list_insert(&ofproto->expirable, &rule->expirable);
    }
    cookies_insert(ofproto, rule);
    eviction_group_add_rule(rule);
    if (actions->has_meter) {
        meter_insert_rule(rule);
    }
}

/* Removes 'rule' from the ofproto data structures AFTER caller has removed
 * it from the classifier. */
static void
ofproto_rule_remove__(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
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
    struct classifier *cls = &rule->ofproto->tables[rule->table_id].cls;

    if (classifier_remove(cls, &rule->cr)) {
        ofproto_rule_remove__(rule->ofproto, rule);
    }
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
    struct match match;
    struct cls_rule target;
    const struct oftable *oftable;

    match_init_catchall(&match);
    match_set_vlan_vid_masked(&match, htons(VLAN_CFI), htons(VLAN_CFI));
    cls_rule_init(&target, &match, 0);

    free(ofproto->vlan_bitmap);
    ofproto->vlan_bitmap = bitmap_allocate(4096);
    ofproto->vlans_changed = false;

    OFPROTO_FOR_EACH_TABLE (oftable, ofproto) {
        struct rule *rule;

        CLS_FOR_EACH_TARGET (rule, cr, &oftable->cls, &target) {
            if (minimask_get_vid_mask(&rule->cr.match.mask) == VLAN_VID_MASK) {
                uint16_t vid = miniflow_get_vid(&rule->cr.match.flow);

                bitmap_set1(vlan_bitmap, vid);
                bitmap_set1(ofproto->vlan_bitmap, vid);
            }
        }
    }

    cls_rule_destroy(&target);
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
