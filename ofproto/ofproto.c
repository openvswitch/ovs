/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include "byte-order.h"
#include "classifier.h"
#include "connmgr.h"
#include "coverage.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "netdev.h"
#include "nx-match.h"
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
#include "shash.h"
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
    int error;                  /* 0 if no error yet, otherwise error code. */
};

static struct ofopgroup *ofopgroup_create(struct ofproto *);
static struct ofopgroup *ofopgroup_create_for_ofconn(struct ofconn *,
                                                     const struct ofp_header *,
                                                     uint32_t buffer_id);
static void ofopgroup_submit(struct ofopgroup *);
static void ofopgroup_destroy(struct ofopgroup *);

/* A single flow table operation. */
struct ofoperation {
    struct ofopgroup *group;    /* Owning group. */
    struct list group_node;     /* In ofopgroup's "ops" list. */
    struct hmap_node hmap_node; /* In ofproto's "deletions" hmap. */
    struct rule *rule;          /* Rule being operated upon. */
    enum ofoperation_type type; /* Type of operation. */
    int status;                 /* -1 if pending, otherwise 0 or error code. */
    struct rule *victim;        /* OFOPERATION_ADDING: Replaced rule. */
    union ofp_action *actions;  /* OFOPERATION_MODIFYING: Replaced actions. */
    int n_actions;              /* OFOPERATION_MODIFYING: # of old actions. */
    ovs_be64 flow_cookie;       /* Rule's old flow cookie. */
};

static void ofoperation_create(struct ofopgroup *, struct rule *,
                               enum ofoperation_type);
static void ofoperation_destroy(struct ofoperation *);

static void ofport_destroy__(struct ofport *);
static void ofport_destroy(struct ofport *);

static uint64_t pick_datapath_id(const struct ofproto *);
static uint64_t pick_fallback_dpid(void);

static void ofproto_destroy__(struct ofproto *);

static void ofproto_rule_destroy__(struct rule *);
static void ofproto_rule_send_removed(struct rule *, uint8_t reason);

static void ofopgroup_destroy(struct ofopgroup *);

static int add_flow(struct ofproto *, struct ofconn *, struct flow_mod *,
                    const struct ofp_header *);

/* This return value tells handle_openflow() that processing of the current
 * OpenFlow message must be postponed until some ongoing operations have
 * completed.
 *
 * This particular value is a good choice because it is negative (so it won't
 * collide with any errno value or any value returned by ofp_mkerr()) and large
 * (so it won't accidentally collide with EOF or a negative errno value). */
enum { OFPROTO_POSTPONE = -100000 };

static bool handle_openflow(struct ofconn *, struct ofpbuf *);

static void update_port(struct ofproto *, const char *devname);
static int init_ports(struct ofproto *);
static void reinit_ports(struct ofproto *);

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
                                        OFPROTO_FLOW_EVICTON_THRESHOLD_DEFAULT);
    ofproto->forward_bpdu = false;
    ofproto->fallback_dpid = pick_fallback_dpid();
    ofproto->mfr_desc = xstrdup(DEFAULT_MFR_DESC);
    ofproto->hw_desc = xstrdup(DEFAULT_HW_DESC);
    ofproto->sw_desc = xstrdup(DEFAULT_SW_DESC);
    ofproto->serial_desc = xstrdup(DEFAULT_SERIAL_DESC);
    ofproto->dp_desc = xstrdup(DEFAULT_DP_DESC);
    hmap_init(&ofproto->ports);
    shash_init(&ofproto->port_by_name);
    ofproto->tables = NULL;
    ofproto->n_tables = 0;
    ofproto->connmgr = connmgr_create(ofproto, datapath_name, datapath_name);
    ofproto->state = S_OPENFLOW;
    list_init(&ofproto->pending);
    hmap_init(&ofproto->deletions);

    error = ofproto->ofproto_class->construct(ofproto);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s",
                 datapath_name, strerror(error));
        ofproto_destroy__(ofproto);
        return error;
    }
    assert(ofproto->n_tables > 0);

    ofproto->datapath_id = pick_datapath_id(ofproto);
    VLOG_INFO("using datapath ID %016"PRIx64, ofproto->datapath_id);
    init_ports(ofproto);

    *ofprotop = ofproto;
    return 0;
}

void
ofproto_set_datapath_id(struct ofproto *p, uint64_t datapath_id)
{
    uint64_t old_dpid = p->datapath_id;
    p->datapath_id = datapath_id ? datapath_id : pick_datapath_id(p);
    if (p->datapath_id != old_dpid) {
        VLOG_INFO("datapath ID changed to %016"PRIx64, p->datapath_id);

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

void
ofproto_set_desc(struct ofproto *p,
                 const char *mfr_desc, const char *hw_desc,
                 const char *sw_desc, const char *serial_desc,
                 const char *dp_desc)
{
    struct ofp_desc_stats *ods;

    if (mfr_desc) {
        if (strlen(mfr_desc) >= sizeof ods->mfr_desc) {
            VLOG_WARN("truncating mfr_desc, must be less than %zu characters",
                    sizeof ods->mfr_desc);
        }
        free(p->mfr_desc);
        p->mfr_desc = xstrdup(mfr_desc);
    }
    if (hw_desc) {
        if (strlen(hw_desc) >= sizeof ods->hw_desc) {
            VLOG_WARN("truncating hw_desc, must be less than %zu characters",
                    sizeof ods->hw_desc);
        }
        free(p->hw_desc);
        p->hw_desc = xstrdup(hw_desc);
    }
    if (sw_desc) {
        if (strlen(sw_desc) >= sizeof ods->sw_desc) {
            VLOG_WARN("truncating sw_desc, must be less than %zu characters",
                    sizeof ods->sw_desc);
        }
        free(p->sw_desc);
        p->sw_desc = xstrdup(sw_desc);
    }
    if (serial_desc) {
        if (strlen(serial_desc) >= sizeof ods->serial_num) {
            VLOG_WARN("truncating serial_desc, must be less than %zu "
                    "characters",
                    sizeof ods->serial_num);
        }
        free(p->serial_desc);
        p->serial_desc = xstrdup(serial_desc);
    }
    if (dp_desc) {
        if (strlen(dp_desc) >= sizeof ods->dp_desc) {
            VLOG_WARN("truncating dp_desc, must be less than %zu characters",
                    sizeof ods->dp_desc);
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
 * to 's'.  Otherwise, this function registers a new mirror.
 *
 * Mirrors affect only the treatment of packets output to the OFPP_NORMAL
 * port.  */
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
ofproto_is_mirror_output_bundle(struct ofproto *ofproto, void *aux)
{
    return (ofproto->ofproto_class->is_mirror_output_bundle
            ? ofproto->ofproto_class->is_mirror_output_bundle(ofproto, aux)
            : false);
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
    struct classifier *table;
    struct ofopgroup *group;

    if (ofproto->ofproto_class->flush) {
        ofproto->ofproto_class->flush(ofproto);
    }

    group = ofopgroup_create(ofproto);
    for (table = ofproto->tables; table < &ofproto->tables[ofproto->n_tables];
         table++) {
        struct rule *rule, *next_rule;
        struct cls_cursor cursor;

        cls_cursor_init(&cursor, table, NULL);
        CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
            if (!rule->pending) {
                ofoperation_create(group, rule, OFOPERATION_DELETE);
                classifier_remove(table, &rule->cr);
                ofproto->ofproto_class->rule_destruct(rule);
            }
        }
    }
    ofopgroup_submit(group);
}

static void
ofproto_destroy__(struct ofproto *ofproto)
{
    size_t i;

    assert(list_is_empty(&ofproto->pending));

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

    for (i = 0; i < ofproto->n_tables; i++) {
        assert(classifier_is_empty(&ofproto->tables[i]));
        classifier_destroy(&ofproto->tables[i]);
    }
    free(ofproto->tables);

    hmap_destroy(&ofproto->deletions);

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
    struct ofport *ofport;
    char *devname;
    int error;

    error = p->ofproto_class->run(p);
    if (error == ENODEV) {
        /* Someone destroyed the datapath behind our back.  The caller
         * better destroy us and give up, because we're just going to
         * spin from here on out. */
        static struct vlog_rate_limit rl2 = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl2, "%s: datapath was destroyed externally",
                    p->name);
        return ENODEV;
    }

    if (p->ofproto_class->port_poll) {
        while ((error = p->ofproto_class->port_poll(p, &devname)) != EAGAIN) {
            process_port_change(p, error, devname);
        }
    }

    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        unsigned int change_seq = netdev_change_seq(ofport->netdev);
        if (ofport->change_seq != change_seq) {
            ofport->change_seq = change_seq;
            update_port(p, netdev_get_name(ofport->netdev));
        }
    }


    switch (p->state) {
    case S_OPENFLOW:
        connmgr_run(p->connmgr, handle_openflow);
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

    return 0;
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
 * The caller retains ownership of 'cls_rule' and 'actions'.
 *
 * This is a helper function for in-band control and fail-open. */
void
ofproto_add_flow(struct ofproto *ofproto, const struct cls_rule *cls_rule,
                 const union ofp_action *actions, size_t n_actions)
{
    const struct rule *rule;

    rule = rule_from_cls_rule(classifier_find_rule_exactly(
                                    &ofproto->tables[0], cls_rule));
    if (!rule || !ofputil_actions_equal(rule->actions, rule->n_actions,
                                        actions, n_actions)) {
        struct flow_mod fm;

        memset(&fm, 0, sizeof fm);
        fm.cr = *cls_rule;
        fm.buffer_id = UINT32_MAX;
        fm.actions = (union ofp_action *) actions;
        fm.n_actions = n_actions;
        add_flow(ofproto, NULL, &fm, NULL);
    }
}

/* Searches for a rule with matching criteria exactly equal to 'target' in
 * ofproto's table 0 and, if it finds one, deletes it.
 *
 * This is a helper function for in-band control and fail-open. */
bool
ofproto_delete_flow(struct ofproto *ofproto, const struct cls_rule *target)
{
    struct rule *rule;

    rule = rule_from_cls_rule(classifier_find_rule_exactly(
                                  &ofproto->tables[0], target));
    if (!rule) {
        /* No such rule -> success. */
        return true;
    } else if (rule->pending) {
        /* An operation on the rule is already pending -> failure.
         * Caller must retry later if it's important. */
        return false;
    } else {
        /* Initiate deletion -> success. */
        struct ofopgroup *group = ofopgroup_create(ofproto);
        ofoperation_create(group, rule, OFOPERATION_DELETE);
        classifier_remove(&ofproto->tables[rule->table_id], &rule->cr);
        rule->ofproto->ofproto_class->rule_destruct(rule);
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

/* Opens and returns a netdev for 'ofproto_port', or a null pointer if the
 * netdev cannot be opened.  On success, also fills in 'opp'.  */
static struct netdev *
ofport_open(const struct ofproto_port *ofproto_port, struct ofp_phy_port *opp)
{
    uint32_t curr, advertised, supported, peer;
    struct netdev_options netdev_options;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    memset(&netdev_options, 0, sizeof netdev_options);
    netdev_options.name = ofproto_port->name;
    netdev_options.type = ofproto_port->type;
    netdev_options.ethertype = NETDEV_ETH_TYPE_NONE;

    error = netdev_open(&netdev_options, &netdev);
    if (error) {
        VLOG_WARN_RL(&rl, "ignoring port %s (%"PRIu16") because netdev %s "
                     "cannot be opened (%s)",
                     ofproto_port->name, ofproto_port->ofp_port,
                     ofproto_port->name, strerror(error));
        return NULL;
    }

    netdev_get_flags(netdev, &flags);
    netdev_get_features(netdev, &curr, &advertised, &supported, &peer);

    opp->port_no = htons(ofproto_port->ofp_port);
    netdev_get_etheraddr(netdev, opp->hw_addr);
    ovs_strzcpy(opp->name, ofproto_port->name, sizeof opp->name);
    opp->config = flags & NETDEV_UP ? 0 : htonl(OFPPC_PORT_DOWN);
    opp->state = netdev_get_carrier(netdev) ? 0 : htonl(OFPPS_LINK_DOWN);
    opp->curr = htonl(curr);
    opp->advertised = htonl(advertised);
    opp->supported = htonl(supported);
    opp->peer = htonl(peer);

    return netdev;
}

/* Returns true if most fields of 'a' and 'b' are equal.  Differences in name,
 * port number, and 'config' bits other than OFPPC_PORT_DOWN are
 * disregarded. */
static bool
ofport_equal(const struct ofp_phy_port *a, const struct ofp_phy_port *b)
{
    BUILD_ASSERT_DECL(sizeof *a == 48); /* Detect ofp_phy_port changes. */
    return (!memcmp(a->hw_addr, b->hw_addr, sizeof a->hw_addr)
            && a->state == b->state
            && !((a->config ^ b->config) & htonl(OFPPC_PORT_DOWN))
            && a->curr == b->curr
            && a->advertised == b->advertised
            && a->supported == b->supported
            && a->peer == b->peer);
}

/* Adds an ofport to 'p' initialized based on the given 'netdev' and 'opp'.
 * The caller must ensure that 'p' does not have a conflicting ofport (that is,
 * one with the same name or port number). */
static void
ofport_install(struct ofproto *p,
               struct netdev *netdev, const struct ofp_phy_port *opp)
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
    ofport->opp = *opp;
    ofport->ofp_port = ntohs(opp->port_no);

    /* Add port to 'p'. */
    hmap_insert(&p->ports, &ofport->hmap_node, hash_int(ofport->ofp_port, 0));
    shash_add(&p->port_by_name, netdev_name, ofport);

    /* Let the ofproto_class initialize its private data. */
    error = p->ofproto_class->port_construct(ofport);
    if (error) {
        goto error;
    }
    connmgr_send_port_status(p->connmgr, opp, OFPPR_ADD);
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
    connmgr_send_port_status(ofport->ofproto->connmgr, &ofport->opp,
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

/* Updates 'port' within 'ofproto' with the new 'netdev' and 'opp'.
 *
 * Does not handle a name or port number change.  The caller must implement
 * such a change as a delete followed by an add.  */
static void
ofport_modified(struct ofport *port, struct ofp_phy_port *opp)
{
    memcpy(port->opp.hw_addr, opp->hw_addr, ETH_ADDR_LEN);
    port->opp.config = ((port->opp.config & ~htonl(OFPPC_PORT_DOWN))
                        | (opp->config & htonl(OFPPC_PORT_DOWN)));
    port->opp.state = opp->state;
    port->opp.curr = opp->curr;
    port->opp.advertised = opp->advertised;
    port->opp.supported = opp->supported;
    port->opp.peer = opp->peer;

    connmgr_send_port_status(port->ofproto->connmgr, &port->opp, OFPPR_MODIFY);
}

void
ofproto_port_unregister(struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *port = ofproto_get_port(ofproto, ofp_port);
    if (port) {
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

static void
update_port(struct ofproto *ofproto, const char *name)
{
    struct ofproto_port ofproto_port;
    struct ofp_phy_port opp;
    struct netdev *netdev;
    struct ofport *port;

    COVERAGE_INC(ofproto_update_port);

    /* Fetch 'name''s location and properties from the datapath. */
    netdev = (!ofproto_port_query_by_name(ofproto, name, &ofproto_port)
              ? ofport_open(&ofproto_port, &opp)
              : NULL);
    if (netdev) {
        port = ofproto_get_port(ofproto, ofproto_port.ofp_port);
        if (port && !strcmp(netdev_get_name(port->netdev), name)) {
            struct netdev *old_netdev = port->netdev;

            /* 'name' hasn't changed location.  Any properties changed? */
            if (!ofport_equal(&port->opp, &opp)) {
                ofport_modified(port, &opp);
            }

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
            ofport_install(ofproto, netdev, &opp);
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
            VLOG_WARN_RL(&rl, "ignoring duplicate port %"PRIu16" in datapath",
                         ofp_port);
        } else if (shash_find(&p->port_by_name, ofproto_port.name)) {
            VLOG_WARN_RL(&rl, "ignoring duplicate device %s in datapath",
                         ofproto_port.name);
        } else {
            struct ofp_phy_port opp;
            struct netdev *netdev;

            netdev = ofport_open(&ofproto_port, &opp);
            if (netdev) {
                ofport_install(p, netdev, &opp);
            }
        }
    }

    return 0;
}

static void
ofproto_rule_destroy__(struct rule *rule)
{
    free(rule->actions);
    rule->ofproto->ofproto_class->rule_dealloc(rule);
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
    classifier_remove(&rule->ofproto->tables[rule->table_id], &rule->cr);
    ofproto_rule_destroy__(rule);
}

/* Returns true if 'rule' has an OpenFlow OFPAT_OUTPUT or OFPAT_ENQUEUE action
 * that outputs to 'out_port' (output to OFPP_FLOOD and OFPP_ALL doesn't
 * count). */
static bool
rule_has_out_port(const struct rule *rule, uint16_t out_port)
{
    const union ofp_action *oa;
    size_t left;

    if (out_port == OFPP_NONE) {
        return true;
    }
    OFPUTIL_ACTION_FOR_EACH_UNSAFE (oa, left, rule->actions, rule->n_actions) {
        if (action_outputs_to_port(oa, htons(out_port))) {
            return true;
        }
    }
    return false;
}

/* Executes the actions indicated by 'rule' on 'packet' and credits 'rule''s
 * statistics appropriately.  'packet' must have at least sizeof(struct
 * ofp_packet_in) bytes of headroom.
 *
 * 'packet' doesn't necessarily have to match 'rule'.  'rule' will be credited
 * with statistics for 'packet' either way.
 *
 * Takes ownership of 'packet'. */
static int
rule_execute(struct rule *rule, uint16_t in_port, struct ofpbuf *packet)
{
    struct flow flow;

    assert(ofpbuf_headroom(packet) >= sizeof(struct ofp_packet_in));

    flow_extract(packet, 0, in_port, &flow);
    return rule->ofproto->ofproto_class->rule_execute(rule, &flow, packet);
}

/* Returns true if 'rule' should be hidden from the controller.
 *
 * Rules with priority higher than UINT16_MAX are set up by ofproto itself
 * (e.g. by in-band control) and are intentionally hidden from the
 * controller. */
static bool
rule_is_hidden(const struct rule *rule)
{
    return rule->cr.priority > UINT16_MAX;
}

static int
handle_echo_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    ofconn_send_reply(ofconn, make_echo_reply(oh));
    return 0;
}

static int
handle_features_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofp_switch_features *osf;
    struct ofpbuf *buf;
    struct ofport *port;
    bool arp_match_ip;
    uint32_t actions;

    ofproto->ofproto_class->get_features(ofproto, &arp_match_ip, &actions);
    assert(actions & (1 << OFPAT_OUTPUT)); /* sanity check */

    osf = make_openflow_xid(sizeof *osf, OFPT_FEATURES_REPLY, oh->xid, &buf);
    osf->datapath_id = htonll(ofproto->datapath_id);
    osf->n_buffers = htonl(pktbuf_capacity());
    osf->n_tables = ofproto->n_tables;
    osf->capabilities = htonl(OFPC_FLOW_STATS | OFPC_TABLE_STATS |
                              OFPC_PORT_STATS);
    if (arp_match_ip) {
        osf->capabilities |= htonl(OFPC_ARP_MATCH_IP);
    }
    osf->actions = htonl(actions);

    HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
        ofpbuf_put(buf, &port->opp, sizeof port->opp);
    }

    ofconn_send_reply(ofconn, buf);
    return 0;
}

static int
handle_get_config_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofpbuf *buf;
    struct ofp_switch_config *osc;
    uint16_t flags;
    bool drop_frags;

    /* Figure out flags. */
    drop_frags = ofproto->ofproto_class->get_drop_frags(ofproto);
    flags = drop_frags ? OFPC_FRAG_DROP : OFPC_FRAG_NORMAL;

    /* Send reply. */
    osc = make_openflow_xid(sizeof *osc, OFPT_GET_CONFIG_REPLY, oh->xid, &buf);
    osc->flags = htons(flags);
    osc->miss_send_len = htons(ofconn_get_miss_send_len(ofconn));
    ofconn_send_reply(ofconn, buf);

    return 0;
}

static int
handle_set_config(struct ofconn *ofconn, const struct ofp_switch_config *osc)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    uint16_t flags = ntohs(osc->flags);

    if (ofconn_get_type(ofconn) == OFCONN_PRIMARY
        && ofconn_get_role(ofconn) != NX_ROLE_SLAVE) {
        switch (flags & OFPC_FRAG_MASK) {
        case OFPC_FRAG_NORMAL:
            ofproto->ofproto_class->set_drop_frags(ofproto, false);
            break;
        case OFPC_FRAG_DROP:
            ofproto->ofproto_class->set_drop_frags(ofproto, true);
            break;
        default:
            VLOG_WARN_RL(&rl, "requested bad fragment mode (flags=%"PRIx16")",
                         osc->flags);
            break;
        }
    }

    ofconn_set_miss_send_len(ofconn, ntohs(osc->miss_send_len));

    return 0;
}

/* Checks whether 'ofconn' is a slave controller.  If so, returns an OpenFlow
 * error message code (composed with ofp_mkerr()) for the caller to propagate
 * upward.  Otherwise, returns 0.
 *
 * The log message mentions 'msg_type'. */
static int
reject_slave_controller(struct ofconn *ofconn, const char *msg_type)
{
    if (ofconn_get_type(ofconn) == OFCONN_PRIMARY
        && ofconn_get_role(ofconn) == NX_ROLE_SLAVE) {
        static struct vlog_rate_limit perm_rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&perm_rl, "rejecting %s message from slave controller",
                     msg_type);

        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    } else {
        return 0;
    }
}

static int
handle_packet_out(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_packet_out *opo;
    struct ofpbuf payload, *buffer;
    union ofp_action *ofp_actions;
    struct ofpbuf request;
    struct flow flow;
    size_t n_ofp_actions;
    uint16_t in_port;
    int error;

    COVERAGE_INC(ofproto_packet_out);

    error = reject_slave_controller(ofconn, "OFPT_PACKET_OUT");
    if (error) {
        return error;
    }

    /* Get ofp_packet_out. */
    ofpbuf_use_const(&request, oh, ntohs(oh->length));
    opo = ofpbuf_pull(&request, offsetof(struct ofp_packet_out, actions));

    /* Get actions. */
    error = ofputil_pull_actions(&request, ntohs(opo->actions_len),
                                 &ofp_actions, &n_ofp_actions);
    if (error) {
        return error;
    }

    /* Get payload. */
    if (opo->buffer_id != htonl(UINT32_MAX)) {
        error = ofconn_pktbuf_retrieve(ofconn, ntohl(opo->buffer_id),
                                       &buffer, &in_port);
        if (error || !buffer) {
            return error;
        }
        payload = *buffer;
    } else {
        payload = request;
        buffer = NULL;
    }

    /* Send out packet. */
    flow_extract(&payload, 0, ntohs(opo->in_port), &flow);
    error = p->ofproto_class->packet_out(p, &payload, &flow,
                                         ofp_actions, n_ofp_actions);
    ofpbuf_delete(buffer);

    return error;
}

static void
update_port_config(struct ofport *port, ovs_be32 config, ovs_be32 mask)
{
    ovs_be32 old_config = port->opp.config;

    mask &= config ^ port->opp.config;
    if (mask & htonl(OFPPC_PORT_DOWN)) {
        if (config & htonl(OFPPC_PORT_DOWN)) {
            netdev_turn_flags_off(port->netdev, NETDEV_UP, true);
        } else {
            netdev_turn_flags_on(port->netdev, NETDEV_UP, true);
        }
    }

    port->opp.config ^= mask & (htonl(OFPPC_NO_RECV | OFPPC_NO_RECV_STP |
                                      OFPPC_NO_FLOOD | OFPPC_NO_FWD |
                                      OFPPC_NO_PACKET_IN));
    if (port->opp.config != old_config) {
        port->ofproto->ofproto_class->port_reconfigured(port, old_config);
    }
}

static int
handle_port_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    const struct ofp_port_mod *opm = (const struct ofp_port_mod *) oh;
    struct ofport *port;
    int error;

    error = reject_slave_controller(ofconn, "OFPT_PORT_MOD");
    if (error) {
        return error;
    }

    port = ofproto_get_port(p, ntohs(opm->port_no));
    if (!port) {
        return ofp_mkerr(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT);
    } else if (memcmp(port->opp.hw_addr, opm->hw_addr, OFP_ETH_ALEN)) {
        return ofp_mkerr(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR);
    } else {
        update_port_config(port, opm->config, opm->mask);
        if (opm->advertise) {
            netdev_set_advertisements(port->netdev, ntohl(opm->advertise));
        }
    }
    return 0;
}

static int
handle_desc_stats_request(struct ofconn *ofconn,
                          const struct ofp_stats_msg *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_desc_stats *ods;
    struct ofpbuf *msg;

    ods = ofputil_make_stats_reply(sizeof *ods, request, &msg);
    ovs_strlcpy(ods->mfr_desc, p->mfr_desc, sizeof ods->mfr_desc);
    ovs_strlcpy(ods->hw_desc, p->hw_desc, sizeof ods->hw_desc);
    ovs_strlcpy(ods->sw_desc, p->sw_desc, sizeof ods->sw_desc);
    ovs_strlcpy(ods->serial_num, p->serial_desc, sizeof ods->serial_num);
    ovs_strlcpy(ods->dp_desc, p->dp_desc, sizeof ods->dp_desc);
    ofconn_send_reply(ofconn, msg);

    return 0;
}

static int
handle_table_stats_request(struct ofconn *ofconn,
                           const struct ofp_stats_msg *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_table_stats *ots;
    struct ofpbuf *msg;
    size_t i;

    ofputil_make_stats_reply(sizeof(struct ofp_stats_msg), request, &msg);

    ots = ofpbuf_put_zeros(msg, sizeof *ots * p->n_tables);
    for (i = 0; i < p->n_tables; i++) {
        ots[i].table_id = i;
        sprintf(ots[i].name, "table%zu", i);
        ots[i].wildcards = htonl(OFPFW_ALL);
        ots[i].max_entries = htonl(1000000); /* An arbitrary big number. */
        ots[i].active_count = htonl(classifier_count(&p->tables[i]));
    }

    p->ofproto_class->get_tables(p, ots);

    ofconn_send_reply(ofconn, msg);
    return 0;
}

static void
append_port_stat(struct ofport *port, struct list *replies)
{
    struct netdev_stats stats;
    struct ofp_port_stats *ops;

    /* Intentionally ignore return value, since errors will set
     * 'stats' to all-1s, which is correct for OpenFlow, and
     * netdev_get_stats() will log errors. */
    netdev_get_stats(port->netdev, &stats);

    ops = ofputil_append_stats_reply(sizeof *ops, replies);
    ops->port_no = port->opp.port_no;
    memset(ops->pad, 0, sizeof ops->pad);
    put_32aligned_be64(&ops->rx_packets, htonll(stats.rx_packets));
    put_32aligned_be64(&ops->tx_packets, htonll(stats.tx_packets));
    put_32aligned_be64(&ops->rx_bytes, htonll(stats.rx_bytes));
    put_32aligned_be64(&ops->tx_bytes, htonll(stats.tx_bytes));
    put_32aligned_be64(&ops->rx_dropped, htonll(stats.rx_dropped));
    put_32aligned_be64(&ops->tx_dropped, htonll(stats.tx_dropped));
    put_32aligned_be64(&ops->rx_errors, htonll(stats.rx_errors));
    put_32aligned_be64(&ops->tx_errors, htonll(stats.tx_errors));
    put_32aligned_be64(&ops->rx_frame_err, htonll(stats.rx_frame_errors));
    put_32aligned_be64(&ops->rx_over_err, htonll(stats.rx_over_errors));
    put_32aligned_be64(&ops->rx_crc_err, htonll(stats.rx_crc_errors));
    put_32aligned_be64(&ops->collisions, htonll(stats.collisions));
}

static int
handle_port_stats_request(struct ofconn *ofconn,
                          const struct ofp_port_stats_request *psr)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofport *port;
    struct list replies;

    ofputil_start_stats_reply(&psr->osm, &replies);
    if (psr->port_no != htons(OFPP_NONE)) {
        port = ofproto_get_port(p, ntohs(psr->port_no));
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

static void
calc_flow_duration__(long long int start, uint32_t *sec, uint32_t *nsec)
{
    long long int msecs = time_msec() - start;
    *sec = msecs / 1000;
    *nsec = (msecs % 1000) * (1000 * 1000);
}

static struct classifier *
first_matching_table(struct ofproto *ofproto, uint8_t table_id)
{
    if (table_id == 0xff) {
        return &ofproto->tables[0];
    } else if (table_id < ofproto->n_tables) {
        return &ofproto->tables[table_id];
    } else {
        /* It would probably be better to reply with an error but there doesn't
         * seem to be any appropriate value, so that might just be
         * confusing. */
        VLOG_WARN_RL(&rl, "controller asked for invalid table %"PRIu8,
                     table_id);
        return NULL;
    }
}

static struct classifier *
next_matching_table(struct ofproto *ofproto,
                    struct classifier *cls, uint8_t table_id)
{
    return (table_id == 0xff && cls != &ofproto->tables[ofproto->n_tables - 1]
            ? cls + 1
            : NULL);
}

/* Assigns CLS to each classifier table, in turn, that matches TABLE_ID in
 * OFPROTO:
 *
 *   - If TABLE_ID is 0xff, this iterates over every classifier table in
 *     OFPROTO.
 *
 *   - If TABLE_ID is the number of a table in OFPROTO, then the loop iterates
 *     only once, for that table.
 *
 *   - Otherwise, TABLE_ID isn't valid for OFPROTO, so ofproto logs a warning
 *     and does not enter the loop at all.
 *
 * All parameters are evaluated multiple times.
 */
#define FOR_EACH_MATCHING_TABLE(CLS, TABLE_ID, OFPROTO)         \
    for ((CLS) = first_matching_table(OFPROTO, TABLE_ID);       \
         (CLS) != NULL;                                         \
         (CLS) = next_matching_table(OFPROTO, CLS, TABLE_ID))

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
static int
collect_rules_loose(struct ofproto *ofproto, uint8_t table_id,
                    const struct cls_rule *match, uint16_t out_port,
                    struct list *rules)
{
    struct classifier *cls;

    list_init(rules);
    FOR_EACH_MATCHING_TABLE (cls, table_id, ofproto) {
        struct cls_cursor cursor;
        struct rule *rule;

        cls_cursor_init(&cursor, cls, match);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            if (rule->pending) {
                return OFPROTO_POSTPONE;
            }
            if (!rule_is_hidden(rule) && rule_has_out_port(rule, out_port)) {
                list_push_back(rules, &rule->ofproto_node);
            }
        }
    }
    return 0;
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
static int
collect_rules_strict(struct ofproto *ofproto, uint8_t table_id,
                     const struct cls_rule *match, uint16_t out_port,
                     struct list *rules)
{
    struct classifier *cls;

    list_init(rules);
    FOR_EACH_MATCHING_TABLE (cls, table_id, ofproto) {
        struct rule *rule;

        rule = rule_from_cls_rule(classifier_find_rule_exactly(cls, match));
        if (rule) {
            if (rule->pending) {
                return OFPROTO_POSTPONE;
            }
            if (!rule_is_hidden(rule) && rule_has_out_port(rule, out_port)) {
                list_push_back(rules, &rule->ofproto_node);
            }
        }
    }
    return 0;
}

static int
handle_flow_stats_request(struct ofconn *ofconn,
                          const struct ofp_stats_msg *osm)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct flow_stats_request fsr;
    struct list replies;
    struct list rules;
    struct rule *rule;
    int error;

    error = ofputil_decode_flow_stats_request(&fsr, &osm->header);
    if (error) {
        return error;
    }

    error = collect_rules_loose(ofproto, fsr.table_id, &fsr.match,
                                fsr.out_port, &rules);
    if (error) {
        return error;
    }

    ofputil_start_stats_reply(osm, &replies);
    LIST_FOR_EACH (rule, ofproto_node, &rules) {
        struct ofputil_flow_stats fs;

        fs.rule = rule->cr;
        fs.cookie = rule->flow_cookie;
        fs.table_id = rule->table_id;
        calc_flow_duration__(rule->created, &fs.duration_sec,
                             &fs.duration_nsec);
        fs.idle_timeout = rule->idle_timeout;
        fs.hard_timeout = rule->hard_timeout;
        ofproto->ofproto_class->rule_get_stats(rule, &fs.packet_count,
                                               &fs.byte_count);
        fs.actions = rule->actions;
        fs.n_actions = rule->n_actions;
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
    if (rule->n_actions > 0) {
        ofp_print_actions(results, rule->actions, rule->n_actions);
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
    struct classifier *cls;

    for (cls = &p->tables[0]; cls < &p->tables[p->n_tables]; cls++) {
        struct cls_cursor cursor;
        struct rule *rule;

        cls_cursor_init(&cursor, cls, NULL);
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

/* Checks the fault status of CFM for 'ofp_port' within 'ofproto'.  Returns 1
 * if CFM is faulted (generally indiciating a connectivity problem), 0 if CFM
 * is not faulted, and -1 if CFM is not enabled on 'ofp_port'. */
int
ofproto_port_get_cfm_fault(const struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->get_cfm_fault
            ? ofproto->ofproto_class->get_cfm_fault(ofport)
            : -1);
}

static int
handle_aggregate_stats_request(struct ofconn *ofconn,
                               const struct ofp_stats_msg *osm)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct flow_stats_request request;
    struct ofputil_aggregate_stats stats;
    bool unknown_packets, unknown_bytes;
    struct ofpbuf *reply;
    struct list rules;
    struct rule *rule;
    int error;

    error = ofputil_decode_flow_stats_request(&request, &osm->header);
    if (error) {
        return error;
    }

    error = collect_rules_loose(ofproto, request.table_id, &request.match,
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

    reply = ofputil_encode_aggregate_stats_reply(&stats, osm);
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
    struct ofp_queue_stats *reply;

    reply = ofputil_append_stats_reply(sizeof *reply, &cbdata->replies);
    reply->port_no = cbdata->ofport->opp.port_no;
    memset(reply->pad, 0, sizeof reply->pad);
    reply->queue_id = htonl(queue_id);
    put_32aligned_be64(&reply->tx_bytes, htonll(stats->tx_bytes));
    put_32aligned_be64(&reply->tx_packets, htonll(stats->tx_packets));
    put_32aligned_be64(&reply->tx_errors, htonll(stats->tx_errors));
}

static void
handle_queue_stats_dump_cb(uint32_t queue_id,
                           struct netdev_queue_stats *stats,
                           void *cbdata_)
{
    struct queue_stats_cbdata *cbdata = cbdata_;

    put_queue_stats(cbdata, queue_id, stats);
}

static void
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
        }
    }
}

static int
handle_queue_stats_request(struct ofconn *ofconn,
                           const struct ofp_queue_stats_request *qsr)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct queue_stats_cbdata cbdata;
    struct ofport *port;
    unsigned int port_no;
    uint32_t queue_id;

    COVERAGE_INC(ofproto_queue_req);

    ofputil_start_stats_reply(&qsr->osm, &cbdata.replies);

    port_no = ntohs(qsr->port_no);
    queue_id = ntohl(qsr->queue_id);
    if (port_no == OFPP_ALL) {
        HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
            handle_queue_stats_for_port(port, queue_id, &cbdata);
        }
    } else if (port_no < OFPP_MAX) {
        port = ofproto_get_port(ofproto, port_no);
        if (port) {
            handle_queue_stats_for_port(port, queue_id, &cbdata);
        }
    } else {
        ofpbuf_list_delete(&cbdata.replies);
        return ofp_mkerr(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }
    ofconn_send_replies(ofconn, &cbdata.replies);

    return 0;
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
 * ofp_actions, to the ofproto's flow table.  Returns 0 on success or an
 * OpenFlow error code as encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
add_flow(struct ofproto *ofproto, struct ofconn *ofconn, struct flow_mod *fm,
         const struct ofp_header *request)
{
    struct classifier *table;
    struct ofopgroup *group;
    struct rule *victim;
    struct rule *rule;
    int error;

    /* Check for overlap, if requested. */
    if (fm->flags & OFPFF_CHECK_OVERLAP) {
        struct classifier *cls;

        FOR_EACH_MATCHING_TABLE (cls, fm->table_id, ofproto) {
            if (classifier_rule_overlaps(cls, &fm->cr)) {
                return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
            }
        }
    }

    /* Pick table. */
    if (fm->table_id == 0xff) {
        uint8_t table_id;
        if (ofproto->n_tables > 1) {
            error = ofproto->ofproto_class->rule_choose_table(ofproto, &fm->cr,
                                                              &table_id);
            if (error) {
                return error;
            }
            assert(table_id < ofproto->n_tables);
            table = &ofproto->tables[table_id];
        } else {
            table = &ofproto->tables[0];
        }
    } else if (fm->table_id < ofproto->n_tables) {
        table = &ofproto->tables[fm->table_id];
    } else {
        return ofp_mkerr_nicira(OFPET_FLOW_MOD_FAILED, NXFMFC_BAD_TABLE_ID);
    }

    /* Serialize against pending deletion. */
    if (is_flow_deletion_pending(ofproto, &fm->cr, table - ofproto->tables)) {
        return OFPROTO_POSTPONE;
    }

    /* Allocate new rule. */
    rule = ofproto->ofproto_class->rule_alloc();
    if (!rule) {
        VLOG_WARN_RL(&rl, "%s: failed to create rule (%s)",
                     ofproto->name, strerror(error));
        return ENOMEM;
    }
    rule->ofproto = ofproto;
    rule->cr = fm->cr;
    rule->pending = NULL;
    rule->flow_cookie = fm->cookie;
    rule->created = time_msec();
    rule->idle_timeout = fm->idle_timeout;
    rule->hard_timeout = fm->hard_timeout;
    rule->table_id = table - ofproto->tables;
    rule->send_flow_removed = (fm->flags & OFPFF_SEND_FLOW_REM) != 0;
    rule->actions = ofputil_actions_clone(fm->actions, fm->n_actions);
    rule->n_actions = fm->n_actions;

    /* Insert new rule. */
    victim = rule_from_cls_rule(classifier_replace(table, &rule->cr));
    if (victim && victim->pending) {
        error = OFPROTO_POSTPONE;
    } else {
        group = (ofconn
                 ? ofopgroup_create_for_ofconn(ofconn, request, fm->buffer_id)
                 : ofopgroup_create(ofproto));
        ofoperation_create(group, rule, OFOPERATION_ADD);
        rule->pending->victim = victim;

        error = ofproto->ofproto_class->rule_construct(rule);
        if (error) {
            ofoperation_destroy(rule->pending);
        }
        ofopgroup_submit(group);
    }

    /* Back out if an error occurred. */
    if (error) {
        if (victim) {
            classifier_replace(table, &victim->cr);
        } else {
            classifier_remove(table, &rule->cr);
        }
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
static int
modify_flows__(struct ofconn *ofconn, const struct flow_mod *fm,
               const struct ofp_header *request, struct list *rules)
{
    struct ofopgroup *group;
    struct rule *rule;

    group = ofopgroup_create_for_ofconn(ofconn, request, fm->buffer_id);
    LIST_FOR_EACH (rule, ofproto_node, rules) {
        if (!ofputil_actions_equal(fm->actions, fm->n_actions,
                                   rule->actions, rule->n_actions)) {
            ofoperation_create(group, rule, OFOPERATION_MODIFY);
            rule->pending->actions = rule->actions;
            rule->pending->n_actions = rule->n_actions;
            rule->actions = ofputil_actions_clone(fm->actions, fm->n_actions);
            rule->n_actions = fm->n_actions;
            rule->ofproto->ofproto_class->rule_modify_actions(rule);
        }
        rule->flow_cookie = fm->cookie;
    }
    ofopgroup_submit(group);

    return 0;
}

/* Implements OFPFC_MODIFY.  Returns 0 on success or an OpenFlow error code as
 * encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any. */
static int
modify_flows_loose(struct ofconn *ofconn, struct flow_mod *fm,
                   const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct list rules;
    int error;

    error = collect_rules_loose(p, fm->table_id, &fm->cr, OFPP_NONE, &rules);
    return (error ? error
            : list_is_empty(&rules) ? add_flow(p, ofconn, fm, request)
            : modify_flows__(ofconn, fm, request, &rules));
}

/* Implements OFPFC_MODIFY_STRICT.  Returns 0 on success or an OpenFlow error
 * code as encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in fm->buffer_id,
 * if any. */
static int
modify_flow_strict(struct ofconn *ofconn, struct flow_mod *fm,
                   const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct list rules;
    int error;

    error = collect_rules_strict(p, fm->table_id, &fm->cr, OFPP_NONE, &rules);
    return (error ? error
            : list_is_empty(&rules) ? add_flow(p, ofconn, fm, request)
            : list_is_singleton(&rules) ? modify_flows__(ofconn, fm, request,
                                                         &rules)
            : 0);
}

/* OFPFC_DELETE implementation. */

/* Deletes the rules listed in 'rules'.
 *
 * Returns 0 on success, otherwise an OpenFlow error code. */
static int
delete_flows__(struct ofconn *ofconn, const struct ofp_header *request,
               struct list *rules)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct rule *rule, *next;
    struct ofopgroup *group;

    group = ofopgroup_create_for_ofconn(ofconn, request, UINT32_MAX);
    LIST_FOR_EACH_SAFE (rule, next, ofproto_node, rules) {
        ofproto_rule_send_removed(rule, OFPRR_DELETE);

        ofoperation_create(group, rule, OFOPERATION_DELETE);
        classifier_remove(&ofproto->tables[rule->table_id], &rule->cr);
        rule->ofproto->ofproto_class->rule_destruct(rule);
    }
    ofopgroup_submit(group);

    return 0;
}

/* Implements OFPFC_DELETE. */
static int
delete_flows_loose(struct ofconn *ofconn, const struct flow_mod *fm,
                   const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct list rules;
    int error;

    error = collect_rules_loose(p, fm->table_id, &fm->cr, fm->out_port,
                                &rules);
    return (error ? error
            : !list_is_empty(&rules) ? delete_flows__(ofconn, request, &rules)
            : 0);
}

/* Implements OFPFC_DELETE_STRICT. */
static int
delete_flow_strict(struct ofconn *ofconn, struct flow_mod *fm,
                   const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct list rules;
    int error;

    error = collect_rules_strict(p, fm->table_id, &fm->cr, fm->out_port,
                                 &rules);
    return (error ? error
            : list_is_singleton(&rules) ? delete_flows__(ofconn, request,
                                                         &rules)
            : 0);
}

static void
ofproto_rule_send_removed(struct rule *rule, uint8_t reason)
{
    struct ofputil_flow_removed fr;

    if (rule_is_hidden(rule) || !rule->send_flow_removed) {
        return;
    }

    fr.rule = rule->cr;
    fr.cookie = rule->flow_cookie;
    fr.reason = reason;
    calc_flow_duration__(rule->created, &fr.duration_sec, &fr.duration_nsec);
    fr.idle_timeout = rule->idle_timeout;
    rule->ofproto->ofproto_class->rule_get_stats(rule, &fr.packet_count,
                                                 &fr.byte_count);

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
{
    struct ofproto *ofproto = rule->ofproto;
    struct ofopgroup *group;

    assert(reason == OFPRR_HARD_TIMEOUT || reason == OFPRR_IDLE_TIMEOUT);

    ofproto_rule_send_removed(rule, reason);

    group = ofopgroup_create(ofproto);
    ofoperation_create(group, rule, OFOPERATION_DELETE);
    classifier_remove(&ofproto->tables[rule->table_id], &rule->cr);
    rule->ofproto->ofproto_class->rule_destruct(rule);
    ofopgroup_submit(group);
}

static int
handle_flow_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct flow_mod fm;
    int error;

    error = reject_slave_controller(ofconn, "flow_mod");
    if (error) {
        return error;
    }

    if (list_size(&ofproto->pending) >= 50) {
        return OFPROTO_POSTPONE;
    }

    error = ofputil_decode_flow_mod(&fm, oh,
                                    ofconn_get_flow_mod_table_id(ofconn));
    if (error) {
        return error;
    }

    /* We do not support the emergency flow cache.  It will hopefully get
     * dropped from OpenFlow in the near future. */
    if (fm.flags & OFPFF_EMERG) {
        /* There isn't a good fit for an error code, so just state that the
         * flow table is full. */
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_ALL_TABLES_FULL);
    }

    switch (fm.command) {
    case OFPFC_ADD:
        return add_flow(ofproto, ofconn, &fm, oh);

    case OFPFC_MODIFY:
        return modify_flows_loose(ofconn, &fm, oh);

    case OFPFC_MODIFY_STRICT:
        return modify_flow_strict(ofconn, &fm, oh);

    case OFPFC_DELETE:
        return delete_flows_loose(ofconn, &fm, oh);

    case OFPFC_DELETE_STRICT:
        return delete_flow_strict(ofconn, &fm, oh);

    default:
        if (fm.command > 0xff) {
            VLOG_WARN_RL(&rl, "flow_mod has explicit table_id but "
                         "flow_mod_table_id extension is not enabled");
        }
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
    }
}

static int
handle_role_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct nx_role_request *nrr = (struct nx_role_request *) oh;
    struct nx_role_request *reply;
    struct ofpbuf *buf;
    uint32_t role;

    if (ofconn_get_type(ofconn) != OFCONN_PRIMARY) {
        VLOG_WARN_RL(&rl, "ignoring role request on service connection");
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    }

    role = ntohl(nrr->role);
    if (role != NX_ROLE_OTHER && role != NX_ROLE_MASTER
        && role != NX_ROLE_SLAVE) {
        VLOG_WARN_RL(&rl, "received request for unknown role %"PRIu32, role);

        /* There's no good error code for this. */
        return ofp_mkerr(OFPET_BAD_REQUEST, -1);
    }

    if (ofconn_get_role(ofconn) != role
        && ofconn_has_pending_opgroups(ofconn)) {
        return OFPROTO_POSTPONE;
    }

    ofconn_set_role(ofconn, role);

    reply = make_nxmsg_xid(sizeof *reply, NXT_ROLE_REPLY, oh->xid, &buf);
    reply->role = htonl(role);
    ofconn_send_reply(ofconn, buf);

    return 0;
}

static int
handle_nxt_flow_mod_table_id(struct ofconn *ofconn,
                             const struct ofp_header *oh)
{
    const struct nxt_flow_mod_table_id *msg
        = (const struct nxt_flow_mod_table_id *) oh;

    ofconn_set_flow_mod_table_id(ofconn, msg->set != 0);
    return 0;
}

static int
handle_nxt_set_flow_format(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct nxt_set_flow_format *msg
        = (const struct nxt_set_flow_format *) oh;
    uint32_t format;

    format = ntohl(msg->format);
    if (format != NXFF_OPENFLOW10 && format != NXFF_NXM) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    }

    if (format != ofconn_get_flow_format(ofconn)
        && ofconn_has_pending_opgroups(ofconn)) {
        /* Avoid sending async messages in surprising flow format. */
        return OFPROTO_POSTPONE;
    }

    ofconn_set_flow_format(ofconn, format);
    return 0;
}

static int
handle_barrier_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofp_header *ob;
    struct ofpbuf *buf;

    if (ofconn_has_pending_opgroups(ofconn)) {
        return OFPROTO_POSTPONE;
    }

    ob = make_openflow_xid(sizeof *ob, OFPT_BARRIER_REPLY, oh->xid, &buf);
    ofconn_send_reply(ofconn, buf);
    return 0;
}

static int
handle_openflow__(struct ofconn *ofconn, const struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    const struct ofputil_msg_type *type;
    int error;

    error = ofputil_decode_msg_type(oh, &type);
    if (error) {
        return error;
    }

    switch (ofputil_msg_type_code(type)) {
        /* OpenFlow requests. */
    case OFPUTIL_OFPT_ECHO_REQUEST:
        return handle_echo_request(ofconn, oh);

    case OFPUTIL_OFPT_FEATURES_REQUEST:
        return handle_features_request(ofconn, oh);

    case OFPUTIL_OFPT_GET_CONFIG_REQUEST:
        return handle_get_config_request(ofconn, oh);

    case OFPUTIL_OFPT_SET_CONFIG:
        return handle_set_config(ofconn, msg->data);

    case OFPUTIL_OFPT_PACKET_OUT:
        return handle_packet_out(ofconn, oh);

    case OFPUTIL_OFPT_PORT_MOD:
        return handle_port_mod(ofconn, oh);

    case OFPUTIL_OFPT_FLOW_MOD:
        return handle_flow_mod(ofconn, oh);

    case OFPUTIL_OFPT_BARRIER_REQUEST:
        return handle_barrier_request(ofconn, oh);

        /* OpenFlow replies. */
    case OFPUTIL_OFPT_ECHO_REPLY:
        return 0;

        /* Nicira extension requests. */
    case OFPUTIL_NXT_ROLE_REQUEST:
        return handle_role_request(ofconn, oh);

    case OFPUTIL_NXT_FLOW_MOD_TABLE_ID:
        return handle_nxt_flow_mod_table_id(ofconn, oh);

    case OFPUTIL_NXT_SET_FLOW_FORMAT:
        return handle_nxt_set_flow_format(ofconn, oh);

    case OFPUTIL_NXT_FLOW_MOD:
        return handle_flow_mod(ofconn, oh);

        /* Statistics requests. */
    case OFPUTIL_OFPST_DESC_REQUEST:
        return handle_desc_stats_request(ofconn, msg->data);

    case OFPUTIL_OFPST_FLOW_REQUEST:
    case OFPUTIL_NXST_FLOW_REQUEST:
        return handle_flow_stats_request(ofconn, msg->data);

    case OFPUTIL_OFPST_AGGREGATE_REQUEST:
    case OFPUTIL_NXST_AGGREGATE_REQUEST:
        return handle_aggregate_stats_request(ofconn, msg->data);

    case OFPUTIL_OFPST_TABLE_REQUEST:
        return handle_table_stats_request(ofconn, msg->data);

    case OFPUTIL_OFPST_PORT_REQUEST:
        return handle_port_stats_request(ofconn, msg->data);

    case OFPUTIL_OFPST_QUEUE_REQUEST:
        return handle_queue_stats_request(ofconn, msg->data);

    case OFPUTIL_MSG_INVALID:
    case OFPUTIL_OFPT_HELLO:
    case OFPUTIL_OFPT_ERROR:
    case OFPUTIL_OFPT_FEATURES_REPLY:
    case OFPUTIL_OFPT_GET_CONFIG_REPLY:
    case OFPUTIL_OFPT_PACKET_IN:
    case OFPUTIL_OFPT_FLOW_REMOVED:
    case OFPUTIL_OFPT_PORT_STATUS:
    case OFPUTIL_OFPT_BARRIER_REPLY:
    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REQUEST:
    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REPLY:
    case OFPUTIL_OFPST_DESC_REPLY:
    case OFPUTIL_OFPST_FLOW_REPLY:
    case OFPUTIL_OFPST_QUEUE_REPLY:
    case OFPUTIL_OFPST_PORT_REPLY:
    case OFPUTIL_OFPST_TABLE_REPLY:
    case OFPUTIL_OFPST_AGGREGATE_REPLY:
    case OFPUTIL_NXT_ROLE_REPLY:
    case OFPUTIL_NXT_FLOW_REMOVED:
    case OFPUTIL_NXST_FLOW_REPLY:
    case OFPUTIL_NXST_AGGREGATE_REPLY:
    default:
        if (VLOG_IS_WARN_ENABLED()) {
            char *s = ofp_to_string(oh, ntohs(oh->length), 2);
            VLOG_DBG_RL(&rl, "OpenFlow message ignored: %s", s);
            free(s);
        }
        if (oh->type == OFPT_STATS_REQUEST || oh->type == OFPT_STATS_REPLY) {
            return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT);
        } else {
            return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
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
ofopgroup_create(struct ofproto *ofproto)
{
    struct ofopgroup *group = xzalloc(sizeof *group);
    group->ofproto = ofproto;
    list_init(&group->ofproto_node);
    list_init(&group->ops);
    list_init(&group->ofconn_node);
    return group;
}

/* Creates and returns a new ofopgroup that is associated with 'ofconn'.  If
 * the ofopgroup eventually fails, then the error reply will include 'request'.
 * If the ofopgroup eventually succeeds, then the packet with buffer id
 * 'buffer_id' on 'ofconn' will be sent by 'ofconn''s ofproto.
 *
 * The caller should add operations to the returned group with
 * ofoperation_create() and then submit it with ofopgroup_submit(). */
static struct ofopgroup *
ofopgroup_create_for_ofconn(struct ofconn *ofconn,
                            const struct ofp_header *request,
                            uint32_t buffer_id)
{
    struct ofopgroup *group = ofopgroup_create(ofconn_get_ofproto(ofconn));
    size_t request_len = ntohs(request->length);

    ofconn_add_opgroup(ofconn, &group->ofconn_node);
    group->ofconn = ofconn;
    group->request = xmemdup(request, MIN(request_len, 64));
    group->buffer_id = buffer_id;

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
    if (list_is_empty(&group->ops)) {
        ofopgroup_destroy(group);
    } else {
        list_push_back(&group->ofproto->pending, &group->ofproto_node);
    }
}

static void
ofopgroup_destroy(struct ofopgroup *group)
{
    assert(list_is_empty(&group->ops));
    if (!list_is_empty(&group->ofproto_node)) {
        list_remove(&group->ofproto_node);
    }
    if (!list_is_empty(&group->ofconn_node)) {
        list_remove(&group->ofconn_node);
        if (group->error) {
            ofconn_send_error(group->ofconn, group->request, group->error);
        }
        connmgr_retry(group->ofproto->connmgr);
    }
    free(group->request);
    free(group);
}

/* Initiates a new operation on 'rule', of the specified 'type', within
 * 'group'.  Prior to calling, 'rule' must not have any pending operation. */
static void
ofoperation_create(struct ofopgroup *group, struct rule *rule,
                   enum ofoperation_type type)
{
    struct ofoperation *op;

    assert(!rule->pending);

    op = rule->pending = xzalloc(sizeof *op);
    op->group = group;
    list_push_back(&group->ops, &op->group_node);
    op->rule = rule;
    op->type = type;
    op->status = -1;
    op->flow_cookie = rule->flow_cookie;

    if (type == OFOPERATION_DELETE) {
        hmap_insert(&op->group->ofproto->deletions, &op->hmap_node,
                    cls_rule_hash(&rule->cr, rule->table_id));
    }
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
    free(op->actions);
    free(op);

    if (list_is_empty(&group->ops) && !list_is_empty(&group->ofproto_node)) {
        ofopgroup_destroy(group);
    }
}

/* Indicates that 'op' completed with status 'error', which is either 0 to
 * indicate success or an OpenFlow error code (constructed with
 * e.g. ofp_mkerr()).
 *
 * If 'op' is a "delete flow" operation, 'error' must be 0.  That is, flow
 * deletions are not allowed to fail.
 *
 * Please see the large comment in ofproto/ofproto-provider.h titled
 * "Asynchronous Operation Support" for more information. */
void
ofoperation_complete(struct ofoperation *op, int error)
{
    struct ofopgroup *group = op->group;
    struct rule *rule = op->rule;
    struct classifier *table = &rule->ofproto->tables[rule->table_id];

    assert(rule->pending == op);
    assert(op->status < 0);
    assert(error >= 0);

    if (!error
        && !group->error
        && op->type != OFOPERATION_DELETE
        && group->ofconn
        && group->buffer_id != UINT32_MAX
        && list_is_singleton(&op->group_node)) {
        struct ofpbuf *packet;
        uint16_t in_port;

        error = ofconn_pktbuf_retrieve(group->ofconn, group->buffer_id,
                                       &packet, &in_port);
        if (packet) {
            assert(!error);
            error = rule_execute(rule, in_port, packet);
        }
    }
    if (!group->error) {
        group->error = error;
    }

    switch (op->type) {
    case OFOPERATION_ADD:
        if (!error) {
            if (op->victim) {
                ofproto_rule_destroy__(op->victim);
            }
        } else {
            if (op->victim) {
                classifier_replace(table, &op->victim->cr);
                op->victim = NULL;
            } else {
                classifier_remove(table, &rule->cr);
            }
            ofproto_rule_destroy__(rule);
        }
        op->victim = NULL;
        break;

    case OFOPERATION_DELETE:
        assert(!error);
        ofproto_rule_destroy__(rule);
        op->rule = NULL;
        break;

    case OFOPERATION_MODIFY:
        if (error) {
            free(rule->actions);
            rule->actions = op->actions;
            rule->n_actions = op->n_actions;
            op->actions = NULL;
        }
        break;

    default:
        NOT_REACHED();
    }
    ofoperation_destroy(op);
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
        VLOG_WARN("could not get MAC address for %s (%s)",
                  netdev_get_name(port->netdev), strerror(error));
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
ofproto_unixctl_list(struct unixctl_conn *conn, const char *arg OVS_UNUSED,
                     void *aux OVS_UNUSED)
{
    struct ofproto *ofproto;
    struct ds results;

    ds_init(&results);
    HMAP_FOR_EACH (ofproto, hmap_node, &all_ofprotos) {
        ds_put_format(&results, "%s\n", ofproto->name);
    }
    unixctl_command_reply(conn, 200, ds_cstr(&results));
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

    unixctl_command_register("ofproto/list", ofproto_unixctl_list, NULL);
}
