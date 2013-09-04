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
#include "bitmap.h"
#include "byte-order.h"
#include "classifier.h"
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
#include "shash.h"
#include "simap.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto);

COVERAGE_DEFINE(ofproto_error);
COVERAGE_DEFINE(ofproto_flush);
COVERAGE_DEFINE(ofproto_no_packet_in);
COVERAGE_DEFINE(ofproto_packet_out);
COVERAGE_DEFINE(ofproto_queue_req);
COVERAGE_DEFINE(ofproto_recv_openflow);
COVERAGE_DEFINE(ofproto_reinit_ports);
COVERAGE_DEFINE(ofproto_uninstallable);
COVERAGE_DEFINE(ofproto_update_port);

enum ofproto_state {
    S_OPENFLOW,                 /* Processing OpenFlow commands. */
    S_EVICT,                    /* Evicting flows from over-limit tables. */
    S_FLUSH,                    /* Deleting all flow table rules. */
};

enum ofoperation_type {
    OFOPERATION_ADD,
    OFOPERATION_DELETE,
    OFOPERATION_MODIFY
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

    /* OFOPERATION_ADD. */
    struct rule *victim;        /* Rule being replaced, if any.. */

    /* OFOPERATION_MODIFY: The old actions, if the actions are changing. */
    struct ofpact *ofpacts;
    size_t ofpacts_len;

    /* OFOPERATION_DELETE. */
    enum ofp_flow_removed_reason reason; /* Reason flow was removed. */

    ovs_be64 flow_cookie;       /* Rule's old flow cookie. */
    enum ofperr error;          /* 0 if no error. */
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

static void oftable_remove_rule(struct rule *);
static struct rule *oftable_replace_rule(struct rule *);
static void oftable_substitute_rule(struct rule *old, struct rule *new);

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

static struct rule *choose_rule_to_evict(struct oftable *);
static void ofproto_evict(struct ofproto *);
static uint32_t rule_eviction_priority(struct rule *);

/* ofport. */
static void ofport_destroy__(struct ofport *);
static void ofport_destroy(struct ofport *);

static void update_port(struct ofproto *, const char *devname);
static int init_ports(struct ofproto *);
static void reinit_ports(struct ofproto *);

/* rule. */
static void ofproto_rule_destroy__(struct rule *);
static void ofproto_rule_send_removed(struct rule *, uint8_t reason);
static bool rule_is_modifiable(const struct rule *);

/* OpenFlow. */
static enum ofperr add_flow(struct ofproto *, struct ofconn *,
                            const struct ofputil_flow_mod *,
                            const struct ofp_header *);
static void delete_flow__(struct rule *, struct ofopgroup *);
static bool handle_openflow(struct ofconn *, struct ofpbuf *);
static enum ofperr handle_flow_mod__(struct ofproto *, struct ofconn *,
                                     const struct ofputil_flow_mod *,
                                     const struct ofp_header *);

/* ofproto. */
static uint64_t pick_datapath_id(const struct ofproto *);
static uint64_t pick_fallback_dpid(void);
static void ofproto_destroy__(struct ofproto *);
static void update_mtu(struct ofproto *, struct ofport *);

/* unixctl. */
static void ofproto_unixctl_init(void);

/* All registered ofproto classes, in probe order. */
static const struct ofproto_class **ofproto_classes;
static size_t n_ofproto_classes;
static size_t allocated_ofproto_classes;

/* Map from datapath name to struct ofproto, for use by unixctl commands. */
static struct hmap all_ofprotos = HMAP_INITIALIZER(&all_ofprotos);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static void
ofproto_initialize(void)
{
    static bool inited;

    if (!inited) {
        inited = true;
        ofproto_class_register(&ofproto_dpif_class);
    }
}

/* 'type' should be a normalized datapath type, as returned by
 * ofproto_normalize_type().  Returns the corresponding ofproto_class
 * structure, or a null pointer if there is none registered for 'type'. */
static const struct ofproto_class *
ofproto_class_find__(const char *type)
{
    size_t i;

    ofproto_initialize();
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

    ofproto_initialize();
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

    *ofprotop = NULL;

    ofproto_initialize();
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
    memset(ofproto, 0, sizeof *ofproto);
    ofproto->ofproto_class = class;
    ofproto->name = xstrdup(datapath_name);
    ofproto->type = xstrdup(datapath_type);
    hmap_insert(&all_ofprotos, &ofproto->hmap_node,
                hash_string(ofproto->name, 0));
    ofproto->datapath_id = 0;
    ofproto_set_flow_eviction_threshold(ofproto,
                                        OFPROTO_FLOW_EVICTION_THRESHOLD_DEFAULT);
    ofproto->forward_bpdu = false;
    ofproto->fallback_dpid = pick_fallback_dpid();
    ofproto->mfr_desc = xstrdup(DEFAULT_MFR_DESC);
    ofproto->hw_desc = xstrdup(DEFAULT_HW_DESC);
    ofproto->sw_desc = xstrdup(DEFAULT_SW_DESC);
    ofproto->serial_desc = xstrdup(DEFAULT_SERIAL_DESC);
    ofproto->dp_desc = xstrdup(DEFAULT_DP_DESC);
    ofproto->frag_handling = OFPC_FRAG_NORMAL;
    hmap_init(&ofproto->ports);
    shash_init(&ofproto->port_by_name);
    ofproto->max_ports = OFPP_MAX;
    ofproto->tables = NULL;
    ofproto->n_tables = 0;
    ofproto->connmgr = connmgr_create(ofproto, datapath_name, datapath_name);
    ofproto->state = S_OPENFLOW;
    list_init(&ofproto->pending);
    ofproto->n_pending = 0;
    hmap_init(&ofproto->deletions);
    ofproto->n_add = ofproto->n_delete = ofproto->n_modify = 0;
    ofproto->first_op = ofproto->last_op = LLONG_MIN;
    ofproto->next_op_report = LLONG_MAX;
    ofproto->op_backoff = LLONG_MIN;
    ofproto->vlan_bitmap = NULL;
    ofproto->vlans_changed = false;
    ofproto->min_mtu = INT_MAX;

    error = ofproto->ofproto_class->construct(ofproto);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s",
                 datapath_name, strerror(error));
        ofproto_destroy__(ofproto);
        return error;
    }

    assert(ofproto->n_tables);

    ofproto->datapath_id = pick_datapath_id(ofproto);
    init_ports(ofproto);

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

    assert(!ofproto->n_tables);
    assert(n_tables >= 1 && n_tables <= 255);

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
    assert(max_ports <= OFPP_MAX);
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
                        size_t n_controllers)
{
    connmgr_set_controllers(p->connmgr, controllers, n_controllers);
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
ofproto_set_flow_eviction_threshold(struct ofproto *ofproto, unsigned threshold)
{
    if (threshold < OFPROTO_FLOW_EVICTION_THRESHOLD_MIN) {
        ofproto->flow_eviction_threshold = OFPROTO_FLOW_EVICTION_THRESHOLD_MIN;
    } else {
        ofproto->flow_eviction_threshold = threshold;
    }
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
 * 'idle_time', in seconds. */
void
ofproto_set_mac_idle_time(struct ofproto *ofproto, unsigned idle_time)
{
    if (ofproto->ofproto_class->set_mac_idle_time) {
        ofproto->ofproto_class->set_mac_idle_time(ofproto, idle_time);
    }
}

void
ofproto_set_desc(struct ofproto *p,
                 const char *mfr_desc, const char *hw_desc,
                 const char *sw_desc, const char *serial_desc,
                 const char *dp_desc)
{
    struct ofp_desc_stats *ods;

    if (mfr_desc) {
        if (strlen(mfr_desc) >= sizeof ods->mfr_desc) {
            VLOG_WARN("%s: truncating mfr_desc, must be less than %zu bytes",
                      p->name, sizeof ods->mfr_desc);
        }
        free(p->mfr_desc);
        p->mfr_desc = xstrdup(mfr_desc);
    }
    if (hw_desc) {
        if (strlen(hw_desc) >= sizeof ods->hw_desc) {
            VLOG_WARN("%s: truncating hw_desc, must be less than %zu bytes",
                      p->name, sizeof ods->hw_desc);
        }
        free(p->hw_desc);
        p->hw_desc = xstrdup(hw_desc);
    }
    if (sw_desc) {
        if (strlen(sw_desc) >= sizeof ods->sw_desc) {
            VLOG_WARN("%s: truncating sw_desc, must be less than %zu bytes",
                      p->name, sizeof ods->sw_desc);
        }
        free(p->sw_desc);
        p->sw_desc = xstrdup(sw_desc);
    }
    if (serial_desc) {
        if (strlen(serial_desc) >= sizeof ods->serial_num) {
            VLOG_WARN("%s: truncating serial_desc, must be less than %zu "
                      "bytes", p->name, sizeof ods->serial_num);
        }
        free(p->serial_desc);
        p->serial_desc = xstrdup(serial_desc);
    }
    if (dp_desc) {
        if (strlen(dp_desc) >= sizeof ods->dp_desc) {
            VLOG_WARN("%s: truncating dp_desc, must be less than %zu bytes",
                      p->name, sizeof ods->dp_desc);
        }
        free(p->dp_desc);
        p->dp_desc = xstrdup(dp_desc);
    }
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
ofproto_port_set_stp(struct ofproto *ofproto, uint16_t ofp_port,
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
ofproto_port_get_stp_status(struct ofproto *ofproto, uint16_t ofp_port,
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

/* Queue DSCP configuration. */

/* Registers meta-data associated with the 'n_qdscp' Qualities of Service
 * 'queues' attached to 'ofport'.  This data is not intended to be sufficient
 * to implement QoS.  Instead, it is used to implement features which require
 * knowledge of what queues exist on a port, and some basic information about
 * them.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_port_set_queues(struct ofproto *ofproto, uint16_t ofp_port,
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
ofproto_port_clear_cfm(struct ofproto *ofproto, uint16_t ofp_port)
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
ofproto_port_set_cfm(struct ofproto *ofproto, uint16_t ofp_port,
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
                  strerror(error));
    }
}

/* Checks the status of LACP negotiation for 'ofp_port' within ofproto.
 * Returns 1 if LACP partner information for 'ofp_port' is up-to-date,
 * 0 if LACP partner information is not current (generally indicating a
 * connectivity problem), or -1 if LACP is not enabled on 'ofp_port'. */
int
ofproto_port_is_lacp_current(struct ofproto *ofproto, uint16_t ofp_port)
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

    assert(table_id >= 0 && table_id < ofproto->n_tables);
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
ofproto_flush__(struct ofproto *ofproto)
{
    struct ofopgroup *group;
    struct oftable *table;

    if (ofproto->ofproto_class->flush) {
        ofproto->ofproto_class->flush(ofproto);
    }

    group = ofopgroup_create_unattached(ofproto);
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        struct rule *rule, *next_rule;
        struct cls_cursor cursor;

        if (table->flags & OFTABLE_HIDDEN) {
            continue;
        }

        cls_cursor_init(&cursor, &table->cls, NULL);
        CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
            if (!rule->pending) {
                ofoperation_create(group, rule, OFOPERATION_DELETE,
                                   OFPRR_DELETE);
                oftable_remove_rule(rule);
                ofproto->ofproto_class->rule_destruct(rule);
            }
        }
    }
    ofopgroup_submit(group);
}

static void
ofproto_destroy__(struct ofproto *ofproto)
{
    struct oftable *table;

    assert(list_is_empty(&ofproto->pending));
    assert(!ofproto->n_pending);

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
    shash_destroy(&ofproto->port_by_name);

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
{
    struct ofport *ofport, *next_ofport;

    if (!p) {
        return;
    }

    ofproto_flush__(p);
    HMAP_FOR_EACH_SAFE (ofport, next_ofport, hmap_node, &p->ports) {
        ofport_destroy(ofport);
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
ofproto_run(struct ofproto *p)
{
    struct sset changed_netdevs;
    const char *changed_netdev;
    struct ofport *ofport;
    int error;

    error = p->ofproto_class->run(p);
    if (error && error != EAGAIN) {
        VLOG_ERR_RL(&rl, "%s: run failed (%s)", p->name, strerror(error));
    }

    if (p->ofproto_class->port_poll) {
        char *devname;

        while ((error = p->ofproto_class->port_poll(p, &devname)) != EAGAIN) {
            process_port_change(p, error, devname);
        }
    }

    /* Update OpenFlow port status for any port whose netdev has changed.
     *
     * Refreshing a given 'ofport' can cause an arbitrary ofport to be
     * destroyed, so it's not safe to update ports directly from the
     * HMAP_FOR_EACH loop, or even to use HMAP_FOR_EACH_SAFE.  Instead, we
     * need this two-phase approach. */
    sset_init(&changed_netdevs);
    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        unsigned int change_seq = netdev_change_seq(ofport->netdev);
        if (ofport->change_seq != change_seq) {
            ofport->change_seq = change_seq;
            sset_add(&changed_netdevs, netdev_get_name(ofport->netdev));
        }
    }
    SSET_FOR_EACH (changed_netdev, &changed_netdevs) {
        update_port(p, changed_netdev);
    }
    sset_destroy(&changed_netdevs);

    switch (p->state) {
    case S_OPENFLOW:
        connmgr_run(p->connmgr, handle_openflow);
        break;

    case S_EVICT:
        connmgr_run(p->connmgr, NULL);
        ofproto_evict(p);
        if (list_is_empty(&p->pending) && hmap_is_empty(&p->deletions)) {
            p->state = S_OPENFLOW;
        }
        break;

    case S_FLUSH:
        connmgr_run(p->connmgr, NULL);
        ofproto_flush__(p);
        if (list_is_empty(&p->pending) && hmap_is_empty(&p->deletions)) {
            connmgr_flushed(p->connmgr);
            p->state = S_OPENFLOW;
        }
        break;

    default:
        NOT_REACHED();
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

/* Performs periodic activity required by 'ofproto' that needs to be done
 * with the least possible latency.
 *
 * It makes sense to call this function a couple of times per poll loop, to
 * provide a significant performance boost on some benchmarks with the
 * ofproto-dpif implementation. */
int
ofproto_run_fast(struct ofproto *p)
{
    int error;

    error = p->ofproto_class->run_fast ? p->ofproto_class->run_fast(p) : 0;
    if (error && error != EAGAIN) {
        VLOG_ERR_RL(&rl, "%s: fastpath run failed (%s)",
                    p->name, strerror(error));
    }
    return error;
}

void
ofproto_wait(struct ofproto *p)
{
    struct ofport *ofport;

    p->ofproto_class->wait(p);
    if (p->ofproto_class->port_poll_wait) {
        p->ofproto_class->port_poll_wait(p);
    }

    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        if (ofport->change_seq != netdev_change_seq(ofport->netdev)) {
            poll_immediate_wake();
        }
    }

    switch (p->state) {
    case S_OPENFLOW:
        connmgr_wait(p->connmgr, true);
        break;

    case S_EVICT:
    case S_FLUSH:
        connmgr_wait(p->connmgr, false);
        if (list_is_empty(&p->pending) && hmap_is_empty(&p->deletions)) {
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
    simap_increase(usage, "ops",
                   ofproto->n_pending + hmap_count(&ofproto->deletions));

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

/* Attempts to add 'netdev' as a port on 'ofproto'.  If successful, returns 0
 * and sets '*ofp_portp' to the new port's OpenFlow port number (if 'ofp_portp'
 * is non-null).  On failure, returns a positive errno value and sets
 * '*ofp_portp' to OFPP_NONE (if 'ofp_portp' is non-null). */
int
ofproto_port_add(struct ofproto *ofproto, struct netdev *netdev,
                 uint16_t *ofp_portp)
{
    uint16_t ofp_port;
    int error;

    error = ofproto->ofproto_class->port_add(ofproto, netdev, &ofp_port);
    if (!error) {
        update_port(ofproto, netdev_get_name(netdev));
    }
    if (ofp_portp) {
        *ofp_portp = error ? OFPP_NONE : ofp_port;
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
ofproto_port_del(struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    const char *name = ofport ? netdev_get_name(ofport->netdev) : "<unknown>";
    int error;

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
{
    const struct rule *rule;

    rule = rule_from_cls_rule(classifier_find_match_exactly(
                                  &ofproto->tables[0].cls, match, priority));
    if (!rule || !ofpacts_equal(rule->ofpacts, rule->ofpacts_len,
                                ofpacts, ofpacts_len)) {
        struct ofputil_flow_mod fm;

        memset(&fm, 0, sizeof fm);
        fm.match = *match;
        fm.priority = priority;
        fm.buffer_id = UINT32_MAX;
        fm.ofpacts = xmemdup(ofpacts, ofpacts_len);
        fm.ofpacts_len = ofpacts_len;
        add_flow(ofproto, NULL, &fm, NULL);
        free(fm.ofpacts);
    }
}

/* Executes the flow modification specified in 'fm'.  Returns 0 on success, an
 * OFPERR_* OpenFlow error code on failure, or OFPROTO_POSTPONE if the
 * operation cannot be initiated now but may be retried later.
 *
 * This is a helper function for in-band control and fail-open. */
int
ofproto_flow_mod(struct ofproto *ofproto, const struct ofputil_flow_mod *fm)
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
{
    struct rule *rule;

    rule = rule_from_cls_rule(classifier_find_match_exactly(
                                  &ofproto->tables[0].cls, target, priority));
    if (!rule) {
        /* No such rule -> success. */
        return true;
    } else if (rule->pending) {
        /* An operation on the rule is already pending -> failure.
         * Caller must retry later if it's important. */
        return false;
    } else {
        /* Initiate deletion -> success. */
        struct ofopgroup *group = ofopgroup_create_unattached(ofproto);
        ofoperation_create(group, rule, OFOPERATION_DELETE, OFPRR_DELETE);
        oftable_remove_rule(rule);
        ofproto->ofproto_class->rule_destruct(rule);
        ofopgroup_submit(group);
        return true;
    }

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

/* Opens and returns a netdev for 'ofproto_port' in 'ofproto', or a null
 * pointer if the netdev cannot be opened.  On success, also fills in
 * 'opp'.  */
static struct netdev *
ofport_open(const struct ofproto *ofproto,
            const struct ofproto_port *ofproto_port,
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
                     ofproto_port->name, strerror(error));
        return NULL;
    }

    pp->port_no = ofproto_port->ofp_port;
    netdev_get_etheraddr(netdev, pp->hw_addr);
    ovs_strlcpy(pp->name, ofproto_port->name, sizeof pp->name);
    netdev_get_flags(netdev, &flags);
    pp->config = flags & NETDEV_UP ? 0 : OFPUTIL_PC_PORT_DOWN;
    pp->state = netdev_get_carrier(netdev) ? 0 : OFPUTIL_PS_LINK_DOWN;
    netdev_get_features(netdev, &pp->curr, &pp->advertised,
                        &pp->supported, &pp->peer);
    pp->curr_speed = netdev_features_to_bps(pp->curr) / 1000;
    pp->max_speed = netdev_features_to_bps(pp->supported) / 1000;

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
    ofport->change_seq = netdev_change_seq(netdev);
    ofport->pp = *pp;
    ofport->ofp_port = pp->port_no;

    /* Add port to 'p'. */
    hmap_insert(&p->ports, &ofport->hmap_node, hash_int(ofport->ofp_port, 0));
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
                 p->name, netdev_name, strerror(error));
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
    port->pp.state = pp->state;
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
ofproto_port_unregister(struct ofproto *ofproto, uint16_t ofp_port)
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
        port->ofproto->ofproto_class->port_destruct(port);
        ofport_destroy__(port);
     }
}

struct ofport *
ofproto_get_port(const struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *port;

    HMAP_FOR_EACH_IN_BUCKET (port, hmap_node,
                             hash_int(ofp_port, 0), &ofproto->ports) {
        if (port->ofp_port == ofp_port) {
            return port;
        }
    }
    return NULL;
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
            port->change_seq = netdev_change_seq(netdev);

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

    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, p) {
        uint16_t ofp_port = ofproto_port.ofp_port;
        if (ofproto_get_port(p, ofp_port)) {
            VLOG_WARN_RL(&rl, "%s: ignoring duplicate port %"PRIu16" "
                         "in datapath", p->name, ofp_port);
        } else if (shash_find(&p->port_by_name, ofproto_port.name)) {
            VLOG_WARN_RL(&rl, "%s: ignoring duplicate device %s in datapath",
                         p->name, ofproto_port.name);
        } else {
            struct ofputil_phy_port pp;
            struct netdev *netdev;

            netdev = ofport_open(p, &ofproto_port, &pp);
            if (netdev) {
                ofport_install(p, netdev, &pp);
            }
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
{
    if (rule) {
        cls_rule_destroy(&rule->cr);
        free(rule->ofpacts);
        rule->ofproto->ofproto_class->rule_dealloc(rule);
    }
}

/* This function allows an ofproto implementation to destroy any rules that
 * remain when its ->destruct() function is called.  The caller must have
 * already uninitialized any derived members of 'rule' (step 5 described in the
 * large comment in ofproto/ofproto-provider.h titled "Life Cycle").
 * This function implements steps 6 and 7.
 *
 * This function should only be called from an ofproto implementation's
 * ->destruct() function.  It is not suitable elsewhere. */
void
ofproto_rule_destroy(struct rule *rule)
{
    assert(!rule->pending);
    oftable_remove_rule(rule);
    ofproto_rule_destroy__(rule);
}

/* Returns true if 'rule' has an OpenFlow OFPAT_OUTPUT or OFPAT_ENQUEUE action
 * that outputs to 'port' (output to OFPP_FLOOD and OFPP_ALL doesn't count). */
bool
ofproto_rule_has_out_port(const struct rule *rule, uint16_t port)
{
    return (port == OFPP_NONE
            || ofpacts_output_to_port(rule->ofpacts, rule->ofpacts_len, port));
}

/* Returns true if a rule related to 'op' has an OpenFlow OFPAT_OUTPUT or
 * OFPAT_ENQUEUE action that outputs to 'out_port'. */
bool
ofoperation_has_out_port(const struct ofoperation *op, uint16_t out_port)
{
    if (ofproto_rule_has_out_port(op->rule, out_port)) {
        return true;
    }

    switch (op->type) {
    case OFOPERATION_ADD:
        return op->victim && ofproto_rule_has_out_port(op->victim, out_port);

    case OFOPERATION_DELETE:
        return false;

    case OFOPERATION_MODIFY:
        return ofpacts_output_to_port(op->ofpacts, op->ofpacts_len, out_port);
    }

    NOT_REACHED();
}

/* Executes the actions indicated by 'rule' on 'packet' and credits 'rule''s
 * statistics appropriately.
 *
 * 'packet' doesn't necessarily have to match 'rule'.  'rule' will be credited
 * with statistics for 'packet' either way.
 *
 * Takes ownership of 'packet'. */
static int
rule_execute(struct rule *rule, uint16_t in_port, struct ofpbuf *packet)
{
    struct flow flow;

    flow_extract(packet, 0, 0, NULL, in_port, &flow);
    return rule->ofproto->ofproto_class->rule_execute(rule, &flow, packet);
}

/* Returns true if 'rule' should be hidden from the controller.
 *
 * Rules with priority higher than UINT16_MAX are set up by ofproto itself
 * (e.g. by in-band control) and are intentionally hidden from the
 * controller. */
bool
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

    ofproto->ofproto_class->get_features(ofproto, &arp_match_ip,
                                         &features.actions);
    assert(features.actions & OFPUTIL_A_OUTPUT); /* sanity check */

    features.datapath_id = ofproto->datapath_id;
    features.n_buffers = pktbuf_capacity();
    features.n_tables = ofproto->n_tables;
    features.capabilities = (OFPUTIL_C_FLOW_STATS | OFPUTIL_C_TABLE_STATS |
                             OFPUTIL_C_PORT_STATS | OFPUTIL_C_QUEUE_STATS);
    if (arp_match_ip) {
        features.capabilities |= OFPUTIL_C_ARP_MATCH_IP;
    }

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
    if (ofconn_get_invalid_ttl_to_controller(ofconn)) {
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
        || ofconn_get_role(ofconn) != NX_ROLE_SLAVE) {
        enum ofp_config_flags cur = ofproto->frag_handling;
        enum ofp_config_flags next = flags & OFPC_FRAG_MASK;

        assert((cur & OFPC_FRAG_MASK) == cur);
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
    ofconn_set_invalid_ttl_to_controller(ofconn,
             (flags & OFPC_INVALID_TTL_TO_CONTROLLER));

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
        && ofconn_get_role(ofconn) == NX_ROLE_SLAVE) {
        return OFPERR_OFPBRC_EPERM;
    } else {
        return 0;
    }
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
    if (po.in_port >= p->max_ports && po.in_port < OFPP_MAX) {
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
        payload = xmalloc(sizeof *payload);
        ofpbuf_use_const(payload, po.packet, po.packet_len);
    }

    /* Verify actions against packet, then send packet if successful. */
    flow_extract(payload, 0, 0, NULL, po.in_port, &flow);
    error = ofpacts_check(po.ofpacts, po.ofpacts_len, &flow, p->max_ports);
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
            netdev_turn_flags_off(port->netdev, NETDEV_UP, true);
        } else {
            netdev_turn_flags_on(port->netdev, NETDEV_UP, true);
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
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_desc_stats *ods;
    struct ofpbuf *msg;

    msg = ofpraw_alloc_stats_reply(request, 0);
    ods = ofpbuf_put_zeros(msg, sizeof *ods);
    ovs_strlcpy(ods->mfr_desc, p->mfr_desc, sizeof ods->mfr_desc);
    ovs_strlcpy(ods->hw_desc, p->hw_desc, sizeof ods->hw_desc);
    ovs_strlcpy(ods->sw_desc, p->sw_desc, sizeof ods->sw_desc);
    ovs_strlcpy(ods->serial_num, p->serial_desc, sizeof ods->serial_num);
    ovs_strlcpy(ods->dp_desc, p->dp_desc, sizeof ods->dp_desc);
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
        sprintf(ots[i].name, "table%zu", i);
        ots[i].match = htonll(OFPXMT12_MASK);
        ots[i].wildcards = htonll(OFPXMT12_MASK);
        ots[i].write_actions = htonl(OFPAT11_OUTPUT);
        ots[i].apply_actions = htonl(OFPAT11_OUTPUT);
        ots[i].write_setfields = htonll(OFPXMT12_MASK);
        ots[i].apply_setfields = htonll(OFPXMT12_MASK);
        ots[i].metadata_match = htonll(UINT64_MAX);
        ots[i].metadata_write = htonll(UINT64_MAX);
        ots[i].instructions = htonl(OFPIT11_ALL);
        ots[i].config = htonl(OFPTC11_TABLE_MISS_MASK);
        ots[i].max_entries = htonl(1000000); /* An arbitrary big number. */
        ots[i].active_count = htonl(classifier_count(&p->tables[i].cls));
    }

    p->ofproto_class->get_tables(p, ots);

    for (i = 0; i < p->n_tables; i++) {
        const struct oftable *table = &p->tables[i];

        if (table->name) {
            ovs_strzcpy(ots[i].name, table->name, sizeof ots[i].name);
        }

        if (table->max_flows < ntohl(ots[i].max_entries)) {
            ots[i].max_entries = htonl(table->max_flows);
        }
    }

    msg = ofputil_encode_table_stats_reply(ots, p->n_tables, request);
    ofconn_send_reply(ofconn, msg);

    free(ots);

    return 0;
}

static void
append_port_stat(struct ofport *port, struct list *replies)
{
    struct ofputil_port_stats ops = { .port_no = port->pp.port_no };

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
    uint16_t port_no;
    enum ofperr error;

    error = ofputil_decode_port_stats_request(request, &port_no);
    if (error) {
        return error;
    }

    ofpmp_init(&replies, request);
    if (port_no != OFPP_NONE) {
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

static void
calc_flow_duration__(long long int start, long long int now,
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

/* Searches 'ofproto' for rules in table 'table_id' (or in all tables, if
 * 'table_id' is 0xff) that match 'match' in the "loose" way required for
 * OpenFlow OFPFC_MODIFY and OFPFC_DELETE requests and puts them on list
 * 'rules'.
 *
 * If 'out_port' is anything other than OFPP_NONE, then only rules that output
 * to 'out_port' are included.
 *
 * Hidden rules are always omitted.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
collect_rules_loose(struct ofproto *ofproto, uint8_t table_id,
                    const struct match *match,
                    ovs_be64 cookie, ovs_be64 cookie_mask,
                    uint16_t out_port, struct list *rules)
{
    struct oftable *table;
    struct cls_rule cr;
    enum ofperr error;

    error = check_table_id(ofproto, table_id);
    if (error) {
        return error;
    }

    list_init(rules);
    cls_rule_init(&cr, match, 0);
    FOR_EACH_MATCHING_TABLE (table, table_id, ofproto) {
        struct cls_cursor cursor;
        struct rule *rule;

        cls_cursor_init(&cursor, &table->cls, &cr);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            if (rule->pending) {
                error = OFPROTO_POSTPONE;
                goto exit;
            }
            if (!ofproto_rule_is_hidden(rule)
                && ofproto_rule_has_out_port(rule, out_port)
                    && !((rule->flow_cookie ^ cookie) & cookie_mask)) {
                list_push_back(rules, &rule->ofproto_node);
            }
        }
    }

exit:
    cls_rule_destroy(&cr);
    return error;
}

/* Searches 'ofproto' for rules in table 'table_id' (or in all tables, if
 * 'table_id' is 0xff) that match 'match' in the "strict" way required for
 * OpenFlow OFPFC_MODIFY_STRICT and OFPFC_DELETE_STRICT requests and puts them
 * on list 'rules'.
 *
 * If 'out_port' is anything other than OFPP_NONE, then only rules that output
 * to 'out_port' are included.
 *
 * Hidden rules are always omitted.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
collect_rules_strict(struct ofproto *ofproto, uint8_t table_id,
                     const struct match *match, unsigned int priority,
                     ovs_be64 cookie, ovs_be64 cookie_mask,
                     uint16_t out_port, struct list *rules)
{
    struct oftable *table;
    struct cls_rule cr;
    int error;

    error = check_table_id(ofproto, table_id);
    if (error) {
        return error;
    }

    list_init(rules);
    cls_rule_init(&cr, match, priority);
    FOR_EACH_MATCHING_TABLE (table, table_id, ofproto) {
        struct rule *rule;

        rule = rule_from_cls_rule(classifier_find_rule_exactly(&table->cls,
                                                               &cr));
        if (rule) {
            if (rule->pending) {
                error = OFPROTO_POSTPONE;
                goto exit;
            }
            if (!ofproto_rule_is_hidden(rule)
                && ofproto_rule_has_out_port(rule, out_port)
                    && !((rule->flow_cookie ^ cookie) & cookie_mask)) {
                list_push_back(rules, &rule->ofproto_node);
            }
        }
    }

exit:
    cls_rule_destroy(&cr);
    return 0;
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
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_flow_stats_request fsr;
    struct list replies;
    struct list rules;
    struct rule *rule;
    enum ofperr error;

    error = ofputil_decode_flow_stats_request(&fsr, request);
    if (error) {
        return error;
    }

    error = collect_rules_loose(ofproto, fsr.table_id, &fsr.match,
                                fsr.cookie, fsr.cookie_mask,
                                fsr.out_port, &rules);
    if (error) {
        return error;
    }

    ofpmp_init(&replies, request);
    LIST_FOR_EACH (rule, ofproto_node, &rules) {
        long long int now = time_msec();
        struct ofputil_flow_stats fs;

        minimatch_expand(&rule->cr.match, &fs.match);
        fs.priority = rule->cr.priority;
        fs.cookie = rule->flow_cookie;
        fs.table_id = rule->table_id;
        calc_flow_duration__(rule->created, now, &fs.duration_sec,
                             &fs.duration_nsec);
        fs.idle_timeout = rule->idle_timeout;
        fs.hard_timeout = rule->hard_timeout;
        fs.idle_age = age_secs(now - rule->used);
        fs.hard_age = age_secs(now - rule->modified);
        ofproto->ofproto_class->rule_get_stats(rule, &fs.packet_count,
                                               &fs.byte_count);
        fs.ofpacts = rule->ofpacts;
        fs.ofpacts_len = rule->ofpacts_len;
        ofputil_append_flow_stats_reply(&fs, &replies);
    }
    ofconn_send_replies(ofconn, &replies);

    return 0;
}

static void
flow_stats_ds(struct rule *rule, struct ds *results)
{
    uint64_t packet_count, byte_count;

    rule->ofproto->ofproto_class->rule_get_stats(rule,
                                                 &packet_count, &byte_count);

    if (rule->table_id != 0) {
        ds_put_format(results, "table_id=%"PRIu8", ", rule->table_id);
    }
    ds_put_format(results, "duration=%llds, ",
                  (time_msec() - rule->created) / 1000);
    ds_put_format(results, "priority=%u, ", rule->cr.priority);
    ds_put_format(results, "n_packets=%"PRIu64", ", packet_count);
    ds_put_format(results, "n_bytes=%"PRIu64", ", byte_count);
    cls_rule_format(&rule->cr, results);
    ds_put_char(results, ',');
    if (rule->ofpacts_len > 0) {
        ofpacts_format(rule->ofpacts, rule->ofpacts_len, results);
    } else {
        ds_put_cstr(results, "drop");
    }
    ds_put_cstr(results, "\n");
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

        cls_cursor_init(&cursor, &table->cls, NULL);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
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

/* Checks the fault status of CFM for 'ofp_port' within 'ofproto'.  Returns a
 * bitmask of 'cfm_fault_reason's to indicate a CFM fault (generally
 * indicating a connectivity problem).  Returns zero if CFM is not faulted,
 * and -1 if CFM is not enabled on 'ofp_port'. */
int
ofproto_port_get_cfm_fault(const struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->get_cfm_fault
            ? ofproto->ofproto_class->get_cfm_fault(ofport)
            : -1);
}

/* Checks the operational status reported by the remote CFM endpoint of
 * 'ofp_port'  Returns 1 if operationally up, 0 if operationally down, and -1
 * if CFM is not enabled on 'ofp_port' or does not support operational status.
 */
int
ofproto_port_get_cfm_opup(const struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->get_cfm_opup
            ? ofproto->ofproto_class->get_cfm_opup(ofport)
            : -1);
}

/* Gets the MPIDs of the remote maintenance points broadcasting to 'ofp_port'
 * within 'ofproto'.  Populates 'rmps' with an array of MPIDs owned by
 * 'ofproto', and 'n_rmps' with the number of MPIDs in 'rmps'.  Returns a
 * number less than 0 if CFM is not enabled on 'ofp_port'. */
int
ofproto_port_get_cfm_remote_mpids(const struct ofproto *ofproto,
                                  uint16_t ofp_port, const uint64_t **rmps,
                                  size_t *n_rmps)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);

    *rmps = NULL;
    *n_rmps = 0;
    return (ofport && ofproto->ofproto_class->get_cfm_remote_mpids
            ? ofproto->ofproto_class->get_cfm_remote_mpids(ofport, rmps,
                                                           n_rmps)
            : -1);
}

/* Checks the health of the CFM for 'ofp_port' within 'ofproto'.  Returns an
 * integer value between 0 and 100 to indicate the health of the port as a
 * percentage which is the average of cfm health of all the remote_mpids or
 * returns -1 if CFM is not enabled on 'ofport'. */
int
ofproto_port_get_cfm_health(const struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->get_cfm_health
            ? ofproto->ofproto_class->get_cfm_health(ofport)
            : -1);
}

static enum ofperr
handle_aggregate_stats_request(struct ofconn *ofconn,
                               const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofputil_flow_stats_request request;
    struct ofputil_aggregate_stats stats;
    bool unknown_packets, unknown_bytes;
    struct ofpbuf *reply;
    struct list rules;
    struct rule *rule;
    enum ofperr error;

    error = ofputil_decode_flow_stats_request(&request, oh);
    if (error) {
        return error;
    }

    error = collect_rules_loose(ofproto, request.table_id, &request.match,
                                request.cookie, request.cookie_mask,
                                request.out_port, &rules);
    if (error) {
        return error;
    }

    memset(&stats, 0, sizeof stats);
    unknown_packets = unknown_bytes = false;
    LIST_FOR_EACH (rule, ofproto_node, &rules) {
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

    reply = ofputil_encode_aggregate_stats_reply(&stats, oh);
    ofconn_send_reply(ofconn, reply);

    return 0;
}

struct queue_stats_cbdata {
    struct ofport *ofport;
    struct list replies;
};

static void
put_queue_stats(struct queue_stats_cbdata *cbdata, uint32_t queue_id,
                const struct netdev_queue_stats *stats)
{

    struct ofputil_queue_stats oqs = {
        .port_no = cbdata->ofport->pp.port_no,
        .queue_id = queue_id,
        .stats = *stats,
    };
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

    error = ofputil_decode_queue_stats_request(rq, &oqsr);
    if (error) {
        return error;
    }

    if (oqsr.port_no == OFPP_ALL) {
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

/* Implements OFPFC_ADD and the cases for OFPFC_MODIFY and OFPFC_MODIFY_STRICT
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
add_flow(struct ofproto *ofproto, struct ofconn *ofconn,
         const struct ofputil_flow_mod *fm, const struct ofp_header *request)
{
    struct oftable *table;
    struct ofopgroup *group;
    struct rule *victim;
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
            assert(table_id < ofproto->n_tables);
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

    /* Allocate new rule and initialize classifier rule. */
    rule = ofproto->ofproto_class->rule_alloc();
    if (!rule) {
        VLOG_WARN_RL(&rl, "%s: failed to create rule (%s)",
                     ofproto->name, strerror(error));
        return ENOMEM;
    }
    cls_rule_init(&rule->cr, &fm->match, fm->priority);

    /* Serialize against pending deletion. */
    if (is_flow_deletion_pending(ofproto, &rule->cr, table_id)) {
        cls_rule_destroy(&rule->cr);
        ofproto->ofproto_class->rule_dealloc(rule);
        return OFPROTO_POSTPONE;
    }

    /* Check for overlap, if requested. */
    if (fm->flags & OFPFF_CHECK_OVERLAP
        && classifier_rule_overlaps(&table->cls, &rule->cr)) {
        cls_rule_destroy(&rule->cr);
        ofproto->ofproto_class->rule_dealloc(rule);
        return OFPERR_OFPFMFC_OVERLAP;
    }

    rule->ofproto = ofproto;
    rule->pending = NULL;
    rule->flow_cookie = fm->new_cookie;
    rule->created = rule->modified = rule->used = time_msec();
    rule->idle_timeout = fm->idle_timeout;
    rule->hard_timeout = fm->hard_timeout;
    rule->table_id = table - ofproto->tables;
    rule->send_flow_removed = (fm->flags & OFPFF_SEND_FLOW_REM) != 0;
    rule->ofpacts = xmemdup(fm->ofpacts, fm->ofpacts_len);
    rule->ofpacts_len = fm->ofpacts_len;
    rule->evictable = true;
    rule->eviction_group = NULL;
    rule->monitor_flags = 0;
    rule->add_seqno = 0;
    rule->modify_seqno = 0;

    /* Insert new rule. */
    victim = oftable_replace_rule(rule);
    if (victim && !rule_is_modifiable(victim)) {
        error = OFPERR_OFPBRC_EPERM;
    } else if (victim && victim->pending) {
        error = OFPROTO_POSTPONE;
    } else {
        struct ofoperation *op;
        struct rule *evict;

        if (classifier_count(&table->cls) > table->max_flows) {
            bool was_evictable;

            was_evictable = rule->evictable;
            rule->evictable = false;
            evict = choose_rule_to_evict(table);
            rule->evictable = was_evictable;

            if (!evict) {
                error = OFPERR_OFPFMFC_TABLE_FULL;
                goto exit;
            } else if (evict->pending) {
                error = OFPROTO_POSTPONE;
                goto exit;
            }
        } else {
            evict = NULL;
        }

        group = ofopgroup_create(ofproto, ofconn, request, fm->buffer_id);
        op = ofoperation_create(group, rule, OFOPERATION_ADD, 0);
        op->victim = victim;

        error = ofproto->ofproto_class->rule_construct(rule);
        if (error) {
            op->group->n_running--;
            ofoperation_destroy(rule->pending);
        } else if (evict) {
            delete_flow__(evict, group);
        }
        ofopgroup_submit(group);
    }

exit:
    /* Back out if an error occurred. */
    if (error) {
        oftable_substitute_rule(rule, victim);
        ofproto_rule_destroy__(rule);
    }
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
               const struct ofputil_flow_mod *fm,
               const struct ofp_header *request, struct list *rules)
{
    struct ofopgroup *group;
    struct rule *rule;
    enum ofperr error;

    group = ofopgroup_create(ofproto, ofconn, request, fm->buffer_id);
    error = OFPERR_OFPBRC_EPERM;
    LIST_FOR_EACH (rule, ofproto_node, rules) {
        struct ofoperation *op;
        bool actions_changed;
        ovs_be64 new_cookie;

        if (rule_is_modifiable(rule)) {
            /* At least one rule is modifiable, don't report EPERM error. */
            error = 0;
        } else {
            continue;
        }

        actions_changed = !ofpacts_equal(fm->ofpacts, fm->ofpacts_len,
                                         rule->ofpacts, rule->ofpacts_len);
        new_cookie = (fm->new_cookie != htonll(UINT64_MAX)
                      ? fm->new_cookie
                      : rule->flow_cookie);

        op = ofoperation_create(group, rule, OFOPERATION_MODIFY, 0);
        rule->flow_cookie = new_cookie;
        if (actions_changed) {
            op->ofpacts = rule->ofpacts;
            op->ofpacts_len = rule->ofpacts_len;
            rule->ofpacts = xmemdup(fm->ofpacts, fm->ofpacts_len);
            rule->ofpacts_len = fm->ofpacts_len;
            rule->ofproto->ofproto_class->rule_modify_actions(rule);
        } else {
            ofoperation_complete(op, 0);
        }
    }
    ofopgroup_submit(group);

    return error;
}

static enum ofperr
modify_flows_add(struct ofproto *ofproto, struct ofconn *ofconn,
                 const struct ofputil_flow_mod *fm,
                 const struct ofp_header *request)
{
    if (fm->cookie_mask != htonll(0) || fm->new_cookie == htonll(UINT64_MAX)) {
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
                   const struct ofputil_flow_mod *fm,
                   const struct ofp_header *request)
{
    struct list rules;
    int error;

    error = collect_rules_loose(ofproto, fm->table_id, &fm->match,
                                fm->cookie, fm->cookie_mask,
                                OFPP_NONE, &rules);
    if (error) {
        return error;
    } else if (list_is_empty(&rules)) {
        return modify_flows_add(ofproto, ofconn, fm, request);
    } else {
        return modify_flows__(ofproto, ofconn, fm, request, &rules);
    }
}

/* Implements OFPFC_MODIFY_STRICT.  Returns 0 on success or an OpenFlow error
 * code on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any. */
static enum ofperr
modify_flow_strict(struct ofproto *ofproto, struct ofconn *ofconn,
                   const struct ofputil_flow_mod *fm,
                   const struct ofp_header *request)
{
    struct list rules;
    int error;

    error = collect_rules_strict(ofproto, fm->table_id, &fm->match,
                                 fm->priority, fm->cookie, fm->cookie_mask,
                                 OFPP_NONE, &rules);

    if (error) {
        return error;
    } else if (list_is_empty(&rules)) {
        return modify_flows_add(ofproto, ofconn, fm, request);
    } else {
        return list_is_singleton(&rules) ? modify_flows__(ofproto, ofconn,
                                                          fm, request, &rules)
                                         : 0;
    }
}

/* OFPFC_DELETE implementation. */

static void
delete_flow__(struct rule *rule, struct ofopgroup *group)
{
    struct ofproto *ofproto = rule->ofproto;

    ofproto_rule_send_removed(rule, OFPRR_DELETE);

    ofoperation_create(group, rule, OFOPERATION_DELETE, OFPRR_DELETE);
    oftable_remove_rule(rule);
    ofproto->ofproto_class->rule_destruct(rule);
}

/* Deletes the rules listed in 'rules'.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static enum ofperr
delete_flows__(struct ofproto *ofproto, struct ofconn *ofconn,
               const struct ofp_header *request, struct list *rules)
{
    struct rule *rule, *next;
    struct ofopgroup *group;

    group = ofopgroup_create(ofproto, ofconn, request, UINT32_MAX);
    LIST_FOR_EACH_SAFE (rule, next, ofproto_node, rules) {
        delete_flow__(rule, group);
    }
    ofopgroup_submit(group);

    return 0;
}

/* Implements OFPFC_DELETE. */
static enum ofperr
delete_flows_loose(struct ofproto *ofproto, struct ofconn *ofconn,
                   const struct ofputil_flow_mod *fm,
                   const struct ofp_header *request)
{
    struct list rules;
    enum ofperr error;

    error = collect_rules_loose(ofproto, fm->table_id, &fm->match,
                                fm->cookie, fm->cookie_mask,
                                fm->out_port, &rules);
    return (error ? error
            : !list_is_empty(&rules) ? delete_flows__(ofproto, ofconn, request,
                                                      &rules)
            : 0);
}

/* Implements OFPFC_DELETE_STRICT. */
static enum ofperr
delete_flow_strict(struct ofproto *ofproto, struct ofconn *ofconn,
                   const struct ofputil_flow_mod *fm,
                   const struct ofp_header *request)
{
    struct list rules;
    enum ofperr error;

    error = collect_rules_strict(ofproto, fm->table_id, &fm->match,
                                 fm->priority, fm->cookie, fm->cookie_mask,
                                 fm->out_port, &rules);
    return (error ? error
            : list_is_singleton(&rules) ? delete_flows__(ofproto, ofconn,
                                                         request, &rules)
            : 0);
}

static void
ofproto_rule_send_removed(struct rule *rule, uint8_t reason)
{
    struct ofputil_flow_removed fr;

    if (ofproto_rule_is_hidden(rule) || !rule->send_flow_removed) {
        return;
    }

    minimatch_expand(&rule->cr.match, &fr.match);
    fr.priority = rule->cr.priority;
    fr.cookie = rule->flow_cookie;
    fr.reason = reason;
    fr.table_id = rule->table_id;
    calc_flow_duration__(rule->created, time_msec(),
                         &fr.duration_sec, &fr.duration_nsec);
    fr.idle_timeout = rule->idle_timeout;
    fr.hard_timeout = rule->hard_timeout;
    rule->ofproto->ofproto_class->rule_get_stats(rule, &fr.packet_count,
                                                 &fr.byte_count);

    connmgr_send_flow_removed(rule->ofproto->connmgr, &fr);
}

void
ofproto_rule_update_used(struct rule *rule, long long int used)
{
    if (used > rule->used) {
        struct eviction_group *evg = rule->eviction_group;

        rule->used = used;
        if (evg) {
            heap_change(&evg->rules, &rule->evg_node,
                        rule_eviction_priority(rule));
        }
    }
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
{
    struct ofproto *ofproto = rule->ofproto;
    struct ofopgroup *group;

    assert(reason == OFPRR_HARD_TIMEOUT || reason == OFPRR_IDLE_TIMEOUT);

    ofproto_rule_send_removed(rule, reason);

    group = ofopgroup_create_unattached(ofproto);
    ofoperation_create(group, rule, OFOPERATION_DELETE, reason);
    oftable_remove_rule(rule);
    ofproto->ofproto_class->rule_destruct(rule);
    ofopgroup_submit(group);
}

static enum ofperr
handle_flow_mod(struct ofconn *ofconn, const struct ofp_header *oh)
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
                                    &ofpacts);
    if (error) {
        goto exit_free_ofpacts;
    }

    if (fm.flags & OFPFF10_EMERG) {
        /* We do not support the OpenFlow 1.0 emergency flow cache, which
         * is not required in OpenFlow 1.0.1 and removed from OpenFlow 1.1.
         * There is no good error code, so just state that the flow table
         * is full. */
        error = OFPERR_OFPFMFC_TABLE_FULL;
    }
    if (!error) {
        error = ofpacts_check(fm.ofpacts, fm.ofpacts_len,
                              &fm.match.flow, ofproto->max_ports);
    }
    if (!error) {
        error = handle_flow_mod__(ofconn_get_ofproto(ofconn), ofconn, &fm, oh);
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
                  const struct ofputil_flow_mod *fm,
                  const struct ofp_header *oh)
{
    if (ofproto->n_pending >= 50) {
        assert(!list_is_empty(&ofproto->pending));
        return OFPROTO_POSTPONE;
    }

    switch (fm->command) {
    case OFPFC_ADD:
        return add_flow(ofproto, ofconn, fm, oh);

    case OFPFC_MODIFY:
        return modify_flows_loose(ofproto, ofconn, fm, oh);

    case OFPFC_MODIFY_STRICT:
        return modify_flow_strict(ofproto, ofconn, fm, oh);

    case OFPFC_DELETE:
        return delete_flows_loose(ofproto, ofconn, fm, oh);

    case OFPFC_DELETE_STRICT:
        return delete_flow_strict(ofproto, ofconn, fm, oh);

    default:
        if (fm->command > 0xff) {
            VLOG_WARN_RL(&rl, "%s: flow_mod has explicit table_id but "
                         "flow_mod_table_id extension is not enabled",
                         ofproto->name);
        }
        return OFPERR_OFPFMFC_BAD_COMMAND;
    }
}

static enum ofperr
handle_role_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct nx_role_request *nrr = ofpmsg_body(oh);
    struct nx_role_request *reply;
    struct ofpbuf *buf;
    uint32_t role;

    role = ntohl(nrr->role);
    if (role != NX_ROLE_OTHER && role != NX_ROLE_MASTER
        && role != NX_ROLE_SLAVE) {
        return OFPERR_OFPRRFC_BAD_ROLE;
    }

    if (ofconn_get_role(ofconn) != role
        && ofconn_has_pending_opgroups(ofconn)) {
        return OFPROTO_POSTPONE;
    }

    ofconn_set_role(ofconn, role);

    buf = ofpraw_alloc_reply(OFPRAW_NXT_ROLE_REPLY, oh, 0);
    reply = ofpbuf_put_zeros(buf, sizeof *reply);
    reply->role = htonl(role);
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
{
    struct ofoperation *op = rule->pending;
    struct ofputil_flow_update fu;
    struct match match;

    if (op && op->type == OFOPERATION_ADD && !op->victim) {
        /* We'll report the final flow when the operation completes.  Reporting
         * it now would cause a duplicate report later. */
        return;
    }

    fu.event = (flags & (NXFMF_INITIAL | NXFMF_ADD)
                ? NXFME_ADDED : NXFME_MODIFIED);
    fu.reason = 0;
    fu.idle_timeout = rule->idle_timeout;
    fu.hard_timeout = rule->hard_timeout;
    fu.table_id = rule->table_id;
    fu.cookie = rule->flow_cookie;
    minimatch_expand(&rule->cr.match, &match);
    fu.match = &match;
    fu.priority = rule->cr.priority;
    if (!(flags & NXFMF_ACTIONS)) {
        fu.ofpacts = NULL;
        fu.ofpacts_len = 0;
    } else if (!op) {
        fu.ofpacts = rule->ofpacts;
        fu.ofpacts_len = rule->ofpacts_len;
    } else {
        /* An operation is in progress.  Use the previous version of the flow's
         * actions, so that when the operation commits we report the change. */
        switch (op->type) {
        case OFOPERATION_ADD:
            /* We already verified that there was a victim. */
            fu.ofpacts = op->victim->ofpacts;
            fu.ofpacts_len = op->victim->ofpacts_len;
            break;

        case OFOPERATION_MODIFY:
            if (op->ofpacts) {
                fu.ofpacts = op->ofpacts;
                fu.ofpacts_len = op->ofpacts_len;
            } else {
                fu.ofpacts = rule->ofpacts;
                fu.ofpacts_len = rule->ofpacts_len;
            }
            break;

        case OFOPERATION_DELETE:
            fu.ofpacts = rule->ofpacts;
            fu.ofpacts_len = rule->ofpacts_len;
            break;

        default:
            NOT_REACHED();
        }
    }

    if (list_is_empty(msgs)) {
        ofputil_start_flow_update(msgs);
    }
    ofputil_append_flow_update(&fu, msgs);
}

void
ofmonitor_compose_refresh_updates(struct list *rules, struct list *msgs)
{
    struct rule *rule;

    LIST_FOR_EACH (rule, ofproto_node, rules) {
        enum nx_flow_monitor_flags flags = rule->monitor_flags;
        rule->monitor_flags = 0;

        ofproto_compose_flow_refresh_update(rule, flags, msgs);
    }
}

static void
ofproto_collect_ofmonitor_refresh_rule(const struct ofmonitor *m,
                                       struct rule *rule, uint64_t seqno,
                                       struct list *rules)
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
        list_push_back(rules, &rule->ofproto_node);
    }
    rule->monitor_flags |= update | (m->flags & NXFMF_ACTIONS);
}

static void
ofproto_collect_ofmonitor_refresh_rules(const struct ofmonitor *m,
                                        uint64_t seqno,
                                        struct list *rules)
{
    const struct ofproto *ofproto = ofconn_get_ofproto(m->ofconn);
    const struct ofoperation *op;
    const struct oftable *table;
    struct cls_rule target;

    cls_rule_init_from_minimatch(&target, &m->match, 0);
    FOR_EACH_MATCHING_TABLE (table, m->table_id, ofproto) {
        struct cls_cursor cursor;
        struct rule *rule;

        cls_cursor_init(&cursor, &table->cls, &target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            assert(!rule->pending); /* XXX */
            ofproto_collect_ofmonitor_refresh_rule(m, rule, seqno, rules);
        }
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
                                        struct list *rules)
{
    if (m->flags & NXFMF_INITIAL) {
        ofproto_collect_ofmonitor_refresh_rules(m, 0, rules);
    }
}

void
ofmonitor_collect_resume_rules(struct ofmonitor *m,
                               uint64_t seqno, struct list *rules)
{
    ofproto_collect_ofmonitor_refresh_rules(m, seqno, rules);
}

static enum ofperr
handle_flow_monitor_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofmonitor **monitors;
    size_t n_monitors, allocated_monitors;
    struct list replies;
    enum ofperr error;
    struct list rules;
    struct ofpbuf b;
    size_t i;

    error = 0;
    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    monitors = NULL;
    n_monitors = allocated_monitors = 0;
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

    list_init(&rules);
    for (i = 0; i < n_monitors; i++) {
        ofproto_collect_ofmonitor_initial_rules(monitors[i], &rules);
    }

    ofpmp_init(&replies, oh);
    ofmonitor_compose_refresh_updates(&rules, &replies);
    ofconn_send_replies(ofconn, &replies);

    free(monitors);

    return 0;

error:
    for (i = 0; i < n_monitors; i++) {
        ofmonitor_destroy(monitors[i]);
    }
    free(monitors);
    return error;
}

static enum ofperr
handle_flow_monitor_cancel(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofmonitor *m;
    uint32_t id;

    id = ofputil_decode_flow_monitor_cancel(oh);
    m = ofmonitor_lookup(ofconn, id);
    if (!m) {
        return OFPERR_NXBRC_FM_BAD_ID;
    }

    ofmonitor_destroy(m);
    return 0;
}

static enum ofperr
handle_openflow__(struct ofconn *ofconn, const struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    enum ofptype type;
    enum ofperr error;

    error = ofptype_decode(&type, oh);
    if (error) {
        return error;
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

    case OFPTYPE_BARRIER_REQUEST:
        return handle_barrier_request(ofconn, oh);

        /* OpenFlow replies. */
    case OFPTYPE_ECHO_REPLY:
        return 0;

        /* Nicira extension requests. */
    case OFPTYPE_ROLE_REQUEST:
        return handle_role_request(ofconn, oh);

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

    case OFPTYPE_HELLO:
    case OFPTYPE_ERROR:
    case OFPTYPE_FEATURES_REPLY:
    case OFPTYPE_GET_CONFIG_REPLY:
    case OFPTYPE_PACKET_IN:
    case OFPTYPE_FLOW_REMOVED:
    case OFPTYPE_PORT_STATUS:
    case OFPTYPE_BARRIER_REPLY:
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
    default:
        return OFPERR_OFPBRC_BAD_TYPE;
    }
}

static bool
handle_openflow(struct ofconn *ofconn, struct ofpbuf *ofp_msg)
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
{
    struct ofopgroup *group = ofopgroup_create_unattached(ofproto);
    if (ofconn) {
        size_t request_len = ntohs(request->length);

        assert(ofconn_get_ofproto(ofconn) == ofproto);

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
{
    struct ofproto *ofproto = group->ofproto;

    struct ofconn *abbrev_ofconn;
    ovs_be32 abbrev_xid;

    struct ofoperation *op, *next_op;
    int error;

    assert(!group->n_running);

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
                uint16_t in_port;

                error = ofconn_pktbuf_retrieve(group->ofconn, group->buffer_id,
                                               &packet, &in_port);
                if (packet) {
                    assert(!error);
                    error = rule_execute(op->rule, in_port, packet);
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
                  && op->ofpacts
                  && rule->flow_cookie == op->flow_cookie))) {
            /* Check that we can just cast from ofoperation_type to
             * nx_flow_update_event. */
            BUILD_ASSERT_DECL((enum nx_flow_update_event) OFOPERATION_ADD
                              == NXFME_ADDED);
            BUILD_ASSERT_DECL((enum nx_flow_update_event) OFOPERATION_DELETE
                              == NXFME_DELETED);
            BUILD_ASSERT_DECL((enum nx_flow_update_event) OFOPERATION_MODIFY
                              == NXFME_MODIFIED);

            ofmonitor_report(ofproto->connmgr, rule,
                             (enum nx_flow_update_event) op->type,
                             op->reason, abbrev_ofconn, abbrev_xid);
        }

        rule->pending = NULL;

        switch (op->type) {
        case OFOPERATION_ADD:
            if (!op->error) {
                uint16_t vid_mask;

                ofproto_rule_destroy__(op->victim);
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
                oftable_substitute_rule(rule, op->victim);
                ofproto_rule_destroy__(rule);
            }
            break;

        case OFOPERATION_DELETE:
            assert(!op->error);
            ofproto_rule_destroy__(rule);
            op->rule = NULL;
            break;

        case OFOPERATION_MODIFY:
            if (!op->error) {
                rule->modified = time_msec();
            } else {
                rule->flow_cookie = op->flow_cookie;
                if (op->ofpacts) {
                    free(rule->ofpacts);
                    rule->ofpacts = op->ofpacts;
                    rule->ofpacts_len = op->ofpacts_len;
                    op->ofpacts = NULL;
                    op->ofpacts_len = 0;
                }
            }
            break;

        default:
            NOT_REACHED();
        }

        ofoperation_destroy(op);
    }

    ofmonitor_flush(ofproto->connmgr);

    if (!list_is_empty(&group->ofproto_node)) {
        assert(ofproto->n_pending > 0);
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
{
    struct ofproto *ofproto = group->ofproto;
    struct ofoperation *op;

    assert(!rule->pending);

    op = rule->pending = xzalloc(sizeof *op);
    op->group = group;
    list_push_back(&group->ops, &op->group_node);
    op->rule = rule;
    op->type = type;
    op->reason = reason;
    op->flow_cookie = rule->flow_cookie;

    group->n_running++;

    if (type == OFOPERATION_DELETE) {
        hmap_insert(&ofproto->deletions, &op->hmap_node,
                    cls_rule_hash(&rule->cr, rule->table_id));
    }

    return op;
}

static void
ofoperation_destroy(struct ofoperation *op)
{
    struct ofopgroup *group = op->group;

    if (op->rule) {
        op->rule->pending = NULL;
    }
    if (op->type == OFOPERATION_DELETE) {
        hmap_remove(&group->ofproto->deletions, &op->hmap_node);
    }
    list_remove(&op->group_node);
    free(op->ofpacts);
    free(op);
}

/* Indicates that 'op' completed with status 'error', which is either 0 to
 * indicate success or an OpenFlow error code on failure.
 *
 * If 'error' is 0, indicating success, the operation will be committed
 * permanently to the flow table.  There is one interesting subcase:
 *
 *   - If 'op' is an "add flow" operation that is replacing an existing rule in
 *     the flow table (the "victim" rule) by a new one, then the caller must
 *     have uninitialized any derived state in the victim rule, as in step 5 in
 *     the "Life Cycle" in ofproto/ofproto-provider.h.  ofoperation_complete()
 *     performs steps 6 and 7 for the victim rule, most notably by calling its
 *     ->rule_dealloc() function.
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

    assert(op->rule->pending == op);
    assert(group->n_running > 0);
    assert(!error || op->type != OFOPERATION_DELETE);

    op->error = error;
    if (!--group->n_running && !list_is_empty(&group->ofproto_node)) {
        ofopgroup_complete(group);
    }
}

struct rule *
ofoperation_get_victim(struct ofoperation *op)
{
    assert(op->type == OFOPERATION_ADD);
    return op->victim;
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
                  strerror(error));
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

/* Chooses and returns a rule to evict from 'table'.  Returns NULL if the table
 * is not configured to evict rules or if the table contains no evictable
 * rules.  (Rules with 'evictable' set to false or with no timeouts are not
 * evictable.) */
static struct rule *
choose_rule_to_evict(struct oftable *table)
{
    struct eviction_group *evg;

    if (!table->eviction_fields) {
        return NULL;
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
     *     by unevictable rules'. */
    HEAP_FOR_EACH (evg, size_node, &table->eviction_groups_by_size) {
        struct rule *rule;

        HEAP_FOR_EACH (rule, evg_node, &evg->rules) {
            if (rule->evictable) {
                return rule;
            }
        }
    }

    return NULL;
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
    struct ofopgroup *group;
    struct oftable *table;

    group = ofopgroup_create_unattached(ofproto);
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        while (classifier_count(&table->cls) > table->max_flows
               && table->eviction_fields) {
            struct rule *rule;

            rule = choose_rule_to_evict(table);
            if (!rule || rule->pending) {
                break;
            }

            ofoperation_create(group, rule,
                               OFOPERATION_DELETE, OFPRR_EVICTION);
            oftable_remove_rule(rule);
            ofproto->ofproto_class->rule_destruct(rule);
        }
    }
    ofopgroup_submit(group);
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
{
    long long int hard_expiration;
    long long int idle_expiration;
    long long int expiration;
    uint32_t expiration_offset;

    /* Calculate time of expiration. */
    hard_expiration = (rule->hard_timeout
                       ? rule->modified + rule->hard_timeout * 1000
                       : LLONG_MAX);
    idle_expiration = (rule->idle_timeout
                       ? rule->used + rule->idle_timeout * 1000
                       : LLONG_MAX);
    expiration = MIN(hard_expiration, idle_expiration);
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
{
    struct ofproto *ofproto = rule->ofproto;
    struct oftable *table = &ofproto->tables[rule->table_id];

    if (table->eviction_fields
        && (rule->hard_timeout || rule->idle_timeout)) {
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
    classifier_init(&table->cls);
    table->max_flows = UINT_MAX;
}

/* Destroys 'table', including its classifier and eviction groups.
 *
 * The caller is responsible for freeing 'table' itself. */
static void
oftable_destroy(struct oftable *table)
{
    assert(classifier_is_empty(&table->cls));
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

    cls_cursor_init(&cursor, &table->cls, NULL);
    CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
        eviction_group_add_rule(rule);
    }
}

/* Removes 'rule' from the oftable that contains it. */
static void
oftable_remove_rule(struct rule *rule)
{
    struct ofproto *ofproto = rule->ofproto;
    struct oftable *table = &ofproto->tables[rule->table_id];

    classifier_remove(&table->cls, &rule->cr);
    eviction_group_remove_rule(rule);
}

/* Inserts 'rule' into its oftable.  Removes any existing rule from 'rule''s
 * oftable that has an identical cls_rule.  Returns the rule that was removed,
 * if any, and otherwise NULL. */
static struct rule *
oftable_replace_rule(struct rule *rule)
{
    struct ofproto *ofproto = rule->ofproto;
    struct oftable *table = &ofproto->tables[rule->table_id];
    struct rule *victim;

    victim = rule_from_cls_rule(classifier_replace(&table->cls, &rule->cr));
    if (victim) {
        eviction_group_remove_rule(victim);
    }
    eviction_group_add_rule(rule);
    return victim;
}

/* Removes 'old' from its oftable then, if 'new' is nonnull, inserts 'new'. */
static void
oftable_substitute_rule(struct rule *old, struct rule *new)
{
    if (new) {
        oftable_replace_rule(new);
    } else {
        oftable_remove_rule(old);
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
    const struct oftable *oftable;

    free(ofproto->vlan_bitmap);
    ofproto->vlan_bitmap = bitmap_allocate(4096);
    ofproto->vlans_changed = false;

    OFPROTO_FOR_EACH_TABLE (oftable, ofproto) {
        const struct cls_table *table;

        HMAP_FOR_EACH (table, hmap_node, &oftable->cls.tables) {
            if (minimask_get_vid_mask(&table->mask) == VLAN_VID_MASK) {
                const struct cls_rule *rule;

                HMAP_FOR_EACH (rule, hmap_node, &table->rules) {
                    uint16_t vid = miniflow_get_vid(&rule->match.flow);
                    bitmap_set1(vlan_bitmap, vid);
                    bitmap_set1(ofproto->vlan_bitmap, vid);
                }
            }
        }
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
ofproto_port_set_realdev(struct ofproto *ofproto, uint16_t vlandev_ofp_port,
                         uint16_t realdev_ofp_port, int vid)
{
    struct ofport *ofport;
    int error;

    assert(vlandev_ofp_port != realdev_ofp_port);

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
                  netdev_get_name(ofport->netdev), strerror(error));
    }
    return error;
}
