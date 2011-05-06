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
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include "autopath.h"
#include "bitmap.h"
#include "bond.h"
#include "byte-order.h"
#include "cfm.h"
#include "classifier.h"
#include "connmgr.h"
#include "coverage.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "fail-open.h"
#include "hash.h"
#include "hmap.h"
#include "hmapx.h"
#include "in-band.h"
#include "lacp.h"
#include "mac-learning.h"
#include "multipath.h"
#include "netdev.h"
#include "netflow.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofproto-sflow.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "packets.h"
#include "pinsched.h"
#include "pktbuf.h"
#include "poll-loop.h"
#include "private.h"
#include "rconn.h"
#include "shash.h"
#include "sset.h"
#include "stream-ssl.h"
#include "tag.h"
#include "timer.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "vconn.h"
#include "vlan-bitmap.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto);

COVERAGE_DEFINE(facet_changed_rule);
COVERAGE_DEFINE(facet_revalidate);
COVERAGE_DEFINE(odp_overflow);
COVERAGE_DEFINE(ofproto_agg_request);
COVERAGE_DEFINE(ofproto_costly_flags);
COVERAGE_DEFINE(ofproto_ctlr_action);
COVERAGE_DEFINE(ofproto_del_rule);
COVERAGE_DEFINE(ofproto_error);
COVERAGE_DEFINE(ofproto_expiration);
COVERAGE_DEFINE(ofproto_expired);
COVERAGE_DEFINE(ofproto_flows_req);
COVERAGE_DEFINE(ofproto_flush);
COVERAGE_DEFINE(ofproto_invalidated);
COVERAGE_DEFINE(ofproto_no_packet_in);
COVERAGE_DEFINE(ofproto_ofp2odp);
COVERAGE_DEFINE(ofproto_packet_in);
COVERAGE_DEFINE(ofproto_packet_out);
COVERAGE_DEFINE(ofproto_queue_req);
COVERAGE_DEFINE(ofproto_recv_openflow);
COVERAGE_DEFINE(ofproto_reinit_ports);
COVERAGE_DEFINE(ofproto_unexpected_rule);
COVERAGE_DEFINE(ofproto_uninstallable);
COVERAGE_DEFINE(ofproto_update_port);

/* Maximum depth of flow table recursion (due to NXAST_RESUBMIT actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 16

struct rule;

#define MAX_MIRRORS 32
typedef uint32_t mirror_mask_t;
#define MIRROR_MASK_C(X) UINT32_C(X)
BUILD_ASSERT_DECL(sizeof(mirror_mask_t) * CHAR_BIT >= MAX_MIRRORS);
struct ofmirror {
    struct ofproto *ofproto;    /* Owning ofproto. */
    size_t idx;                 /* In ofproto's "mirrors" array. */
    void *aux;                  /* Key supplied by ofproto's client. */
    char *name;                 /* Identifier for log messages. */

    /* Selection criteria. */
    struct hmapx srcs;          /* Contains "struct ofbundle *"s. */
    struct hmapx dsts;          /* Contains "struct ofbundle *"s. */
    unsigned long *vlans;       /* Bitmap of chosen VLANs, NULL selects all. */

    /* Output (mutually exclusive). */
    struct ofbundle *out;       /* Output port or NULL. */
    int out_vlan;               /* Output VLAN or -1. */
};

static void ofproto_mirror_destroy(struct ofmirror *);

/* A group of one or more OpenFlow ports. */
#define OFBUNDLE_FLOOD ((struct ofbundle *) 1)
struct ofbundle {
    struct ofproto *ofproto;    /* Owning ofproto. */
    struct hmap_node hmap_node; /* In struct ofproto's "bundles" hmap. */
    void *aux;                  /* Key supplied by ofproto's client. */
    char *name;                 /* Identifier for log messages. */

    /* Configuration. */
    struct list ports;          /* Contains "struct ofport"s. */
    int vlan;                   /* -1=trunk port, else a 12-bit VLAN ID. */
    unsigned long *trunks;      /* Bitmap of trunked VLANs, if 'vlan' == -1.
                                 * NULL if all VLANs are trunked. */
    struct lacp *lacp;          /* LACP if LACP is enabled, otherwise NULL. */
    struct bond *bond;          /* Bonding setup if more than one port,
                                 * otherwise NULL. */

    /* Status. */
    bool floodable;             /* True if no port has OFPPC_NO_FLOOD set. */

    /* Port mirroring info. */
    mirror_mask_t src_mirrors;  /* Mirrors triggered when packet received. */
    mirror_mask_t dst_mirrors;  /* Mirrors triggered when packet sent. */
    mirror_mask_t mirror_out;   /* Mirrors that output to this bundle. */
};

/* An OpenFlow port. */
struct ofport {
    struct ofproto *ofproto;    /* Owning ofproto. */
    struct hmap_node hmap_node; /* In struct ofproto's "ports" hmap. */
    struct netdev *netdev;
    struct ofp_phy_port opp;
    uint16_t odp_port;

    /* Bridging. */
    struct ofbundle *bundle;    /* Bundle that contains this port, if any. */
    struct list bundle_node;    /* In struct ofbundle's "ports" list. */
    struct cfm *cfm;            /* Connectivity Fault Management, if any. */
    tag_type tag;               /* Tag associated with this port. */
};

static void ofport_free(struct ofport *);
static void ofport_run(struct ofport *);
static void ofport_wait(struct ofport *);

struct action_xlate_ctx {
/* action_xlate_ctx_init() initializes these members. */

    /* The ofproto. */
    struct ofproto *ofproto;

    /* Flow to which the OpenFlow actions apply.  xlate_actions() will modify
     * this flow when actions change header fields. */
    struct flow flow;

    /* The packet corresponding to 'flow', or a null pointer if we are
     * revalidating without a packet to refer to. */
    const struct ofpbuf *packet;

    /* If nonnull, called just before executing a resubmit action.
     *
     * This is normally null so the client has to set it manually after
     * calling action_xlate_ctx_init(). */
    void (*resubmit_hook)(struct action_xlate_ctx *, struct rule *);

    /* If true, the speciality of 'flow' should be checked before executing
     * its actions.  If special_cb returns false on 'flow' rendered
     * uninstallable and no actions will be executed. */
    bool check_special;

/* xlate_actions() initializes and uses these members.  The client might want
 * to look at them after it returns. */

    struct ofpbuf *odp_actions; /* Datapath actions. */
    tag_type tags;              /* Tags associated with OFPP_NORMAL actions. */
    bool may_set_up_flow;       /* True ordinarily; false if the actions must
                                 * be reassessed for every packet. */
    uint16_t nf_output_iface;   /* Output interface index for NetFlow. */

/* xlate_actions() initializes and uses these members, but the client has no
 * reason to look at them. */

    int recurse;                /* Recursion level, via xlate_table_action. */
    int last_pop_priority;      /* Offset in 'odp_actions' just past most
                                 * recent ODP_ACTION_ATTR_SET_PRIORITY. */
};

static void action_xlate_ctx_init(struct action_xlate_ctx *,
                                  struct ofproto *, const struct flow *,
                                  const struct ofpbuf *);
static struct ofpbuf *xlate_actions(struct action_xlate_ctx *,
                                    const union ofp_action *in, size_t n_in);

/* An OpenFlow flow. */
struct rule {
    long long int used;         /* Time last used; time created if not used. */
    long long int created;      /* Creation time. */

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
     *     datapath by, e.g., dpif_flow_get() for any facet.
     */
    uint64_t packet_count;       /* Number of packets received. */
    uint64_t byte_count;         /* Number of bytes received. */

    ovs_be64 flow_cookie;        /* Controller-issued identifier. */

    struct cls_rule cr;          /* In owning ofproto's classifier. */
    uint16_t idle_timeout;       /* In seconds from time of last use. */
    uint16_t hard_timeout;       /* In seconds from time of creation. */
    bool send_flow_removed;      /* Send a flow removed message? */
    int n_actions;               /* Number of elements in actions[]. */
    union ofp_action *actions;   /* OpenFlow actions. */
    struct list facets;          /* List of "struct facet"s. */
};

static struct rule *rule_from_cls_rule(const struct cls_rule *);
static bool rule_is_hidden(const struct rule *);

static struct rule *rule_create(const struct cls_rule *,
                                const union ofp_action *, size_t n_actions,
                                uint16_t idle_timeout, uint16_t hard_timeout,
                                ovs_be64 flow_cookie, bool send_flow_removed);
static void rule_destroy(struct ofproto *, struct rule *);
static void rule_free(struct rule *);

static struct rule *rule_lookup(struct ofproto *, const struct flow *);
static void rule_insert(struct ofproto *, struct rule *);
static void rule_remove(struct ofproto *, struct rule *);

static void rule_send_removed(struct ofproto *, struct rule *, uint8_t reason);
static void rule_get_stats(const struct rule *, uint64_t *packets,
                           uint64_t *bytes);

/* An exact-match instantiation of an OpenFlow flow. */
struct facet {
    long long int used;         /* Time last used; time created if not used. */

    /* These statistics:
     *
     *   - Do include packets and bytes sent "by hand", e.g. with
     *     dpif_execute().
     *
     *   - Do include packets and bytes that were obtained from the datapath
     *     when a flow was deleted (e.g. dpif_flow_del()) or when its
     *     statistics were reset (e.g. dpif_flow_put() with
     *     DPIF_FP_ZERO_STATS).
     *
     *   - Do not include any packets or bytes that can currently be obtained
     *     from the datapath by, e.g., dpif_flow_get().
     */
    uint64_t packet_count;       /* Number of packets received. */
    uint64_t byte_count;         /* Number of bytes received. */

    uint64_t dp_packet_count;    /* Last known packet count in the datapath. */
    uint64_t dp_byte_count;      /* Last known byte count in the datapath. */

    uint64_t rs_packet_count;    /* Packets pushed to resubmit children. */
    uint64_t rs_byte_count;      /* Bytes pushed to resubmit children. */
    long long int rs_used;       /* Used time pushed to resubmit children. */

    /* Number of bytes passed to account_cb.  This may include bytes that can
     * currently obtained from the datapath (thus, it can be greater than
     * byte_count). */
    uint64_t accounted_bytes;

    struct hmap_node hmap_node;  /* In owning ofproto's 'facets' hmap. */
    struct list list_node;       /* In owning rule's 'facets' list. */
    struct rule *rule;           /* Owning rule. */
    struct flow flow;            /* Exact-match flow. */
    bool installed;              /* Installed in datapath? */
    bool may_install;            /* True ordinarily; false if actions must
                                  * be reassessed for every packet. */
    size_t actions_len;          /* Number of bytes in actions[]. */
    struct nlattr *actions;      /* Datapath actions. */
    tag_type tags;               /* Tags. */
    struct netflow_flow nf_flow; /* Per-flow NetFlow tracking data. */
};

static struct facet *facet_create(struct ofproto *, struct rule *,
                                  const struct flow *,
                                  const struct ofpbuf *packet);
static void facet_remove(struct ofproto *, struct facet *);
static void facet_free(struct facet *);

static struct facet *facet_lookup_valid(struct ofproto *, const struct flow *);
static bool facet_revalidate(struct ofproto *, struct facet *);

static void facet_install(struct ofproto *, struct facet *, bool zero_stats);
static void facet_uninstall(struct ofproto *, struct facet *);
static void facet_flush_stats(struct ofproto *, struct facet *);

static void facet_make_actions(struct ofproto *, struct facet *,
                               const struct ofpbuf *packet);
static void facet_update_stats(struct ofproto *, struct facet *,
                               const struct dpif_flow_stats *);
static void facet_push_stats(struct ofproto *, struct facet *);

static void send_packet_in(struct ofproto *, struct dpif_upcall *,
                           const struct flow *, bool clone);

struct ofproto {
    char *name;                 /* Datapath name. */
    struct hmap_node hmap_node; /* In global 'all_ofprotos' hmap. */

    /* Settings. */
    uint64_t datapath_id;       /* Datapath ID. */
    uint64_t fallback_dpid;     /* Datapath ID if no better choice found. */
    char *mfr_desc;             /* Manufacturer. */
    char *hw_desc;              /* Hardware. */
    char *sw_desc;              /* Software version. */
    char *serial_desc;          /* Serial number. */
    char *dp_desc;              /* Datapath description. */

    /* Datapath. */
    struct dpif *dpif;
    struct netdev_monitor *netdev_monitor;
    struct hmap ports;          /* Contains "struct ofport"s. */
    struct shash port_by_name;
    uint32_t max_ports;

    /* Bridging. */
    struct netflow *netflow;
    struct ofproto_sflow *sflow;
    struct hmap bundles;        /* Contains "struct ofbundle"s. */
    struct mac_learning *ml;
    struct ofmirror *mirrors[MAX_MIRRORS];
    bool has_bonded_bundles;

    /* Flow table. */
    struct classifier cls;
    struct timer next_expiration;

    /* Facets. */
    struct hmap facets;
    bool need_revalidate;
    struct tag_set revalidate_set;

    /* OpenFlow connections. */
    struct connmgr *connmgr;
};

/* Map from dpif name to struct ofproto, for use by unixctl commands. */
static struct hmap all_ofprotos = HMAP_INITIALIZER(&all_ofprotos);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static uint64_t pick_datapath_id(const struct ofproto *);
static uint64_t pick_fallback_dpid(void);

static void ofproto_flush_flows__(struct ofproto *);
static int ofproto_expire(struct ofproto *);
static void flow_push_stats(struct ofproto *, const struct rule *,
                            struct flow *, uint64_t packets, uint64_t bytes,
                            long long int used);

static void handle_upcall(struct ofproto *, struct dpif_upcall *);

static void handle_openflow(struct ofconn *, struct ofpbuf *);

static struct ofport *get_port(const struct ofproto *, uint16_t odp_port);
static void update_port(struct ofproto *, const char *devname);
static int init_ports(struct ofproto *);
static void reinit_ports(struct ofproto *);

static void update_learning_table(struct ofproto *,
                                  const struct flow *, int vlan,
                                  struct ofbundle *);
static bool is_admissible(struct ofproto *, const struct flow *,
                          bool have_packet, tag_type *, int *vlanp,
                          struct ofbundle **in_bundlep);

static void ofproto_unixctl_init(void);

int
ofproto_create(const char *datapath, const char *datapath_type,
               struct ofproto **ofprotop)
{
    char local_name[IF_NAMESIZE];
    struct ofproto *p;
    struct dpif *dpif;
    int error;
    int i;

    *ofprotop = NULL;

    ofproto_unixctl_init();

    /* Connect to datapath and start listening for messages. */
    error = dpif_create_and_open(datapath, datapath_type, &dpif);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s", datapath, strerror(error));
        return error;
    }
    error = dpif_recv_set_mask(dpif,
                               ((1u << DPIF_UC_MISS) |
                                (1u << DPIF_UC_ACTION) |
                                (1u << DPIF_UC_SAMPLE)));
    if (error) {
        VLOG_ERR("failed to listen on datapath %s: %s",
                 datapath, strerror(error));
        dpif_close(dpif);
        return error;
    }
    dpif_flow_flush(dpif);
    dpif_recv_purge(dpif);

    error = dpif_port_get_name(dpif, ODPP_LOCAL,
                               local_name, sizeof local_name);
    if (error) {
        VLOG_ERR("%s: cannot get name of datapath local port (%s)",
                 datapath, strerror(error));
        return error;
    }

    /* Initialize settings. */
    p = xzalloc(sizeof *p);
    p->name = xstrdup(dpif_name(dpif));
    hmap_insert(&all_ofprotos, &p->hmap_node, hash_string(p->name, 0));
    p->fallback_dpid = pick_fallback_dpid();
    p->datapath_id = p->fallback_dpid;
    p->mfr_desc = xstrdup(DEFAULT_MFR_DESC);
    p->hw_desc = xstrdup(DEFAULT_HW_DESC);
    p->sw_desc = xstrdup(DEFAULT_SW_DESC);
    p->serial_desc = xstrdup(DEFAULT_SERIAL_DESC);
    p->dp_desc = xstrdup(DEFAULT_DP_DESC);

    /* Initialize datapath. */
    p->dpif = dpif;
    p->netdev_monitor = netdev_monitor_create();
    hmap_init(&p->ports);
    shash_init(&p->port_by_name);
    p->max_ports = dpif_get_max_ports(dpif);

    /* Initialize bridging. */
    p->netflow = NULL;
    p->sflow = NULL;
    hmap_init(&p->bundles);
    p->ml = mac_learning_create();
    for (i = 0; i < MAX_MIRRORS; i++) {
        p->mirrors[i] = NULL;
    }
    p->has_bonded_bundles = false;

    /* Initialize flow table. */
    classifier_init(&p->cls);
    timer_set_duration(&p->next_expiration, 1000);

    /* Initialize facet table. */
    hmap_init(&p->facets);
    p->need_revalidate = false;
    tag_set_init(&p->revalidate_set);

    /* Pick final datapath ID. */
    p->datapath_id = pick_datapath_id(p);
    VLOG_INFO("using datapath ID %016"PRIx64, p->datapath_id);

    /* Initialize OpenFlow connections. */
    p->connmgr = connmgr_create(p, datapath, local_name);

    init_ports(p);

    *ofprotop = p;
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
    if (nf_options && !sset_is_empty(&nf_options->collectors)) {
        if (!ofproto->netflow) {
            ofproto->netflow = netflow_create();
        }
        return netflow_set_options(ofproto->netflow, nf_options);
    } else {
        netflow_destroy(ofproto->netflow);
        ofproto->netflow = NULL;
        return 0;
    }
}

void
ofproto_set_sflow(struct ofproto *ofproto,
                  const struct ofproto_sflow_options *oso)
{
    struct ofproto_sflow *os = ofproto->sflow;
    if (oso) {
        if (!os) {
            struct ofport *ofport;

            os = ofproto->sflow = ofproto_sflow_create(ofproto->dpif);
            HMAP_FOR_EACH (ofport, hmap_node, &ofproto->ports) {
                ofproto_sflow_add_port(os, ofport->odp_port,
                                       netdev_get_name(ofport->netdev));
            }
        }
        ofproto_sflow_set_options(os, oso);
    } else {
        ofproto_sflow_destroy(os);
        ofproto->sflow = NULL;
    }
}

/* Connectivity Fault Management configuration. */

/* Clears the CFM configuration from 'port_no' on 'ofproto'. */
void
ofproto_port_clear_cfm(struct ofproto *ofproto, uint32_t port_no)
{
    struct ofport *ofport = get_port(ofproto, port_no);
    if (ofport && ofport->cfm){
        cfm_destroy(ofport->cfm);
        ofport->cfm = NULL;
    }
}

/* Configures connectivity fault management on 'port_no' in 'ofproto'.  Takes
 * basic configuration from the configuration members in 'cfm', and the set of
 * remote maintenance points from the 'n_remote_mps' elements in 'remote_mps'.
 * Ignores the statistics members of 'cfm'.
 *
 * This function has no effect if 'ofproto' does not have a port 'port_no'. */
void
ofproto_port_set_cfm(struct ofproto *ofproto, uint32_t port_no,
                     const struct cfm *cfm,
                     const uint16_t *remote_mps, size_t n_remote_mps)
{
    struct ofport *ofport;

    ofport = get_port(ofproto, port_no);
    if (!ofport) {
        VLOG_WARN("%s: cannot configure CFM on nonexistent port %"PRIu32,
                  ofproto->name, port_no);
        return;
    }

    if (!ofport->cfm) {
        ofport->cfm = cfm_create();
    }

    ofport->cfm->mpid = cfm->mpid;
    ofport->cfm->interval = cfm->interval;
    memcpy(ofport->cfm->maid, cfm->maid, CCM_MAID_LEN);

    cfm_update_remote_mps(ofport->cfm, remote_mps, n_remote_mps);

    if (!cfm_configure(ofport->cfm)) {
        VLOG_WARN("%s: CFM configuration on port %"PRIu32" (%s) failed",
                  ofproto->name, port_no,
                  netdev_get_name(ofport->netdev));
        cfm_destroy(ofport->cfm);
        ofport->cfm = NULL;
    }
}

/* Returns the connectivity fault management object associated with 'port_no'
 * within 'ofproto', or a null pointer if 'ofproto' does not have a port
 * 'port_no' or if that port does not have CFM configured.  The caller must not
 * modify or destroy the returned object. */
const struct cfm *
ofproto_port_get_cfm(struct ofproto *ofproto, uint32_t port_no)
{
    struct ofport *ofport = get_port(ofproto, port_no);
    return ofport ? ofport->cfm : NULL;
}

/* Checks the status of LACP negotiation for 'ofp_port' within ofproto.
 * Returns 1 if LACP partner information for 'ofp_port' is up-to-date,
 * 0 if LACP partner information is not current (generally indicating a
 * connectivity problem), or -1 if LACP is not enabled on 'ofp_port'. */
int
ofproto_port_is_lacp_current(struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = get_port(ofproto, ofp_port_to_odp_port(ofp_port));
    return (ofport && ofport->bundle && ofport->bundle->lacp
            ? lacp_slave_is_current(ofport->bundle->lacp, ofport)
            : -1);
}

/* Bundles. */

/* Expires all MAC learning entries associated with 'port' and forces ofproto
 * to revalidate every flow. */
static void
ofproto_bundle_flush_macs(struct ofbundle *bundle)
{
    struct ofproto *ofproto = bundle->ofproto;
    struct mac_learning *ml = ofproto->ml;
    struct mac_entry *mac, *next_mac;

    ofproto->need_revalidate = true;
    LIST_FOR_EACH_SAFE (mac, next_mac, lru_node, &ml->lrus) {
        if (mac->port.p == bundle) {
            mac_learning_expire(ml, mac);
        }
    }
}

static struct ofbundle *
ofproto_bundle_lookup(const struct ofproto *ofproto, void *aux)
{
    struct ofbundle *bundle;

    HMAP_FOR_EACH_IN_BUCKET (bundle, hmap_node, hash_pointer(aux, 0),
                             &ofproto->bundles) {
        if (bundle->aux == aux) {
            return bundle;
        }
    }
    return NULL;
}

/* Looks up each of the 'n_auxes' pointers in 'auxes' as bundles and adds the
 * ones that are found to 'bundles'. */
static void
ofproto_bundle_lookup_multiple(struct ofproto *ofproto,
                               void **auxes, size_t n_auxes,
                               struct hmapx *bundles)
{
    size_t i;

    hmapx_init(bundles);
    for (i = 0; i < n_auxes; i++) {
        struct ofbundle *bundle = ofproto_bundle_lookup(ofproto, auxes[i]);
        if (bundle) {
            hmapx_add(bundles, bundle);
        }
    }
}

static void
ofproto_bundle_del_port(struct ofport *port)
{
    struct ofbundle *bundle = port->bundle;

    list_remove(&port->bundle_node);
    port->bundle = NULL;

    if (bundle->lacp) {
        lacp_slave_unregister(bundle->lacp, port);
    }
    if (bundle->bond) {
        bond_slave_unregister(bundle->bond, port);
    }

    bundle->floodable = true;
    LIST_FOR_EACH (port, bundle_node, &bundle->ports) {
        if (port->opp.config & htonl(OFPPC_NO_FLOOD)) {
            bundle->floodable = false;
        }
    }
}

static bool
ofproto_bundle_add_port(struct ofbundle *bundle, uint32_t ofp_port,
                        struct lacp_slave_settings *lacp)
{
    struct ofport *port;

    port = get_port(bundle->ofproto, ofp_port_to_odp_port(ofp_port));
    if (!port) {
        return false;
    }

    if (port->bundle != bundle) {
        if (port->bundle) {
            ofproto_bundle_del_port(port);
        }

        port->bundle = bundle;
        list_push_back(&bundle->ports, &port->bundle_node);
        if (port->opp.config & htonl(OFPPC_NO_FLOOD)) {
            bundle->floodable = false;
        }
    }

    if (lacp) {
        lacp_slave_register(bundle->lacp, port, lacp);
    }

    return true;
}

void
ofproto_bundle_register(struct ofproto *ofproto, void *aux,
                        const struct ofproto_bundle_settings *s)
{
    bool need_flush = false;
    const unsigned long *trunks;
    struct ofbundle *bundle;
    struct ofport *port;
    size_t i;
    bool ok;

    assert(s->n_slaves == 1 || s->bond != NULL);
    assert((s->lacp != NULL) == (s->lacp_slaves != NULL));

    bundle = ofproto_bundle_lookup(ofproto, aux);
    if (!bundle) {
        bundle = xmalloc(sizeof *bundle);

        bundle->ofproto = ofproto;
        hmap_insert(&ofproto->bundles, &bundle->hmap_node,
                    hash_pointer(aux, 0));
        bundle->aux = aux;
        bundle->name = NULL;

        list_init(&bundle->ports);
        bundle->vlan = -1;
        bundle->trunks = NULL;
        bundle->bond = NULL;
        bundle->lacp = NULL;

        bundle->floodable = true;

        bundle->src_mirrors = 0;
        bundle->dst_mirrors = 0;
        bundle->mirror_out = 0;
    }

    if (!bundle->name || strcmp(s->name, bundle->name)) {
        free(bundle->name);
        bundle->name = xstrdup(s->name);
    }

    /* LACP. */
    if (s->lacp) {
        if (!bundle->lacp) {
            bundle->lacp = lacp_create();
        }
        lacp_configure(bundle->lacp, s->lacp);
    } else {
        lacp_destroy(bundle->lacp);
        bundle->lacp = NULL;
    }

    /* Update set of ports. */
    ok = true;
    for (i = 0; i < s->n_slaves; i++) {
        if (!ofproto_bundle_add_port(bundle, s->slaves[i],
                                     s->lacp ? &s->lacp_slaves[i] : NULL)) {
            ok = false;
        }
    }
    if (!ok || list_size(&bundle->ports) != s->n_slaves) {
        struct ofport *next_port;

        LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
            for (i = 0; i < s->n_slaves; i++) {
                if (s->slaves[i] == odp_port_to_ofp_port(port->odp_port)) {
                    goto found;
                }
            }

            ofproto_bundle_del_port(port);
        found: ;
        }
    }
    assert(list_size(&bundle->ports) <= s->n_slaves);

    if (list_is_empty(&bundle->ports)) {
        ofproto_bundle_unregister(ofproto, aux);
        return;
    }

    /* Set VLAN tag. */
    if (s->vlan != bundle->vlan) {
        bundle->vlan = s->vlan;
        need_flush = true;
    }

    /* Get trunked VLANs. */
    trunks = s->vlan == -1 ? NULL : s->trunks;
    if (!vlan_bitmap_equal(trunks, bundle->trunks)) {
        free(bundle->trunks);
        bundle->trunks = vlan_bitmap_clone(trunks);
        need_flush = true;
    }

    /* Bonding. */
    if (!list_is_short(&bundle->ports)) {
        bundle->ofproto->has_bonded_bundles = true;
        if (bundle->bond) {
            if (bond_reconfigure(bundle->bond, s->bond)) {
                ofproto->need_revalidate = true;
            }
        } else {
            bundle->bond = bond_create(s->bond);
        }

        LIST_FOR_EACH (port, bundle_node, &bundle->ports) {
            uint16_t stable_id = (bundle->lacp
                                  ? lacp_slave_get_port_id(bundle->lacp, port)
                                  : port->odp_port);
            bond_slave_register(bundle->bond, port, stable_id, port->netdev);
        }
    } else {
        bond_destroy(bundle->bond);
        bundle->bond = NULL;
    }

    /* If we changed something that would affect MAC learning, un-learn
     * everything on this port and force flow revalidation. */
    if (need_flush) {
        ofproto_bundle_flush_macs(bundle);
    }
}

static void
ofproto_bundle_destroy(struct ofbundle *bundle)
{
    struct ofproto *ofproto;
    struct ofport *port, *next_port;
    int i;

    if (!bundle) {
        return;
    }

    ofproto = bundle->ofproto;
    for (i = 0; i < MAX_MIRRORS; i++) {
        struct ofmirror *m = ofproto->mirrors[i];
        if (m) {
            if (m->out == bundle) {
                ofproto_mirror_destroy(m);
            } else if (hmapx_find_and_delete(&m->srcs, bundle)
                       || hmapx_find_and_delete(&m->dsts, bundle)) {
                ofproto->need_revalidate = true;
            }
        }
    }

    LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
        ofproto_bundle_del_port(port);
    }

    ofproto_bundle_flush_macs(bundle);
    hmap_remove(&ofproto->bundles, &bundle->hmap_node);
    free(bundle->name);
    free(bundle->trunks);
    bond_destroy(bundle->bond);
    lacp_destroy(bundle->lacp);
    free(bundle);
}

void
ofproto_bundle_unregister(struct ofproto *ofproto, void *aux)
{
    ofproto_bundle_destroy(ofproto_bundle_lookup(ofproto, aux));
}

static void
send_pdu_cb(void *port_, const struct lacp_pdu *pdu)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 10);
    struct ofport *port = port_;
    uint8_t ea[ETH_ADDR_LEN];
    int error;

    error = netdev_get_etheraddr(port->netdev, ea);
    if (!error) {
        struct lacp_pdu *packet_pdu;
        struct ofpbuf packet;

        ofpbuf_init(&packet, 0);
        packet_pdu = eth_compose(&packet, eth_addr_lacp, ea, ETH_TYPE_LACP,
                                 sizeof *packet_pdu);
        *packet_pdu = *pdu;
        error = netdev_send(port->netdev, &packet);
        if (error) {
            VLOG_WARN_RL(&rl, "port %s: sending LACP PDU on iface %s failed "
                         "(%s)", port->bundle->name,
                         netdev_get_name(port->netdev), strerror(error));
        }
        ofpbuf_uninit(&packet);
    } else {
        VLOG_ERR_RL(&rl, "port %s: cannot obtain Ethernet address of iface "
                    "%s (%s)", port->bundle->name,
                    netdev_get_name(port->netdev), strerror(error));
    }
}

static void
ofproto_bundle_send_learning_packets(struct ofbundle *bundle)
{
    struct ofproto *ofproto = bundle->ofproto;
    int error, n_packets, n_errors;
    struct mac_entry *e;

    error = n_packets = n_errors = 0;
    LIST_FOR_EACH (e, lru_node, &ofproto->ml->lrus) {
        if (e->port.p != bundle) {
            int ret = bond_send_learning_packet(bundle->bond, e->mac, e->vlan);
            if (ret) {
                error = ret;
                n_errors++;
            }
            n_packets++;
        }
    }

    if (n_errors) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bond %s: %d errors sending %d gratuitous learning "
                     "packets, last error was: %s",
                     bundle->name, n_errors, n_packets, strerror(error));
    } else {
        VLOG_DBG("bond %s: sent %d gratuitous learning packets",
                 bundle->name, n_packets);
    }
}

static void
ofproto_bundle_run(struct ofbundle *bundle)
{
    if (bundle->lacp) {
        lacp_run(bundle->lacp, send_pdu_cb);
    }
    if (bundle->bond) {
        struct ofport *port;

        LIST_FOR_EACH (port, bundle_node, &bundle->ports) {
            bool may_enable = lacp_slave_may_enable(bundle->lacp, port);
            bond_slave_set_lacp_may_enable(bundle->bond, port, may_enable);
        }

        bond_run(bundle->bond, &bundle->ofproto->revalidate_set,
                 lacp_negotiated(bundle->lacp));
        if (bond_should_send_learning_packets(bundle->bond)) {
            ofproto_bundle_send_learning_packets(bundle);
        }
    }
}

static void
ofproto_bundle_wait(struct ofbundle *bundle)
{
    if (bundle->lacp) {
        lacp_wait(bundle->lacp);
    }
    if (bundle->bond) {
        bond_wait(bundle->bond);
    }
}

static int
ofproto_mirror_scan(struct ofproto *ofproto)
{
    int idx;

    for (idx = 0; idx < MAX_MIRRORS; idx++) {
        if (!ofproto->mirrors[idx]) {
            return idx;
        }
    }
    return -1;
}

static struct ofmirror *
ofproto_mirror_lookup(struct ofproto *ofproto, void *aux)
{
    int i;

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct ofmirror *mirror = ofproto->mirrors[i];
        if (mirror && mirror->aux == aux) {
            return mirror;
        }
    }

    return NULL;
}

void
ofproto_mirror_register(struct ofproto *ofproto, void *aux,
                        const struct ofproto_mirror_settings *s)
{
    mirror_mask_t mirror_bit;
    struct ofbundle *bundle;
    struct ofmirror *mirror;
    struct ofbundle *out;
    struct hmapx srcs;          /* Contains "struct ofbundle *"s. */
    struct hmapx dsts;          /* Contains "struct ofbundle *"s. */
    int out_vlan;

    mirror = ofproto_mirror_lookup(ofproto, aux);
    if (!mirror) {
        int idx;

        idx = ofproto_mirror_scan(ofproto);
        if (idx < 0) {
            VLOG_WARN("bridge %s: maximum of %d port mirrors reached, "
                      "cannot create %s",
                      ofproto->name, MAX_MIRRORS, s->name);
            return;
        }

        mirror = ofproto->mirrors[idx] = xzalloc(sizeof *mirror);
        mirror->ofproto = ofproto;
        mirror->idx = idx;
        mirror->out_vlan = -1;
        mirror->name = NULL;
    }

    if (!mirror->name || strcmp(s->name, mirror->name)) {
        free(mirror->name);
        mirror->name = xstrdup(s->name);
    }

    /* Get the new configuration. */
    if (s->out_bundle) {
        out = ofproto_bundle_lookup(ofproto, s->out_bundle);
        if (!out) {
            ofproto_mirror_destroy(mirror);
            return;
        }
        out_vlan = -1;
    } else {
        out = NULL;
        out_vlan = s->out_vlan;
    }
    ofproto_bundle_lookup_multiple(ofproto, s->srcs, s->n_srcs, &srcs);
    ofproto_bundle_lookup_multiple(ofproto, s->dsts, s->n_dsts, &dsts);

    /* If the configuration has not changed, do nothing. */
    if (hmapx_equals(&srcs, &mirror->srcs)
        && hmapx_equals(&dsts, &mirror->dsts)
        && vlan_bitmap_equal(mirror->vlans, s->src_vlans)
        && mirror->out == out
        && mirror->out_vlan == out_vlan)
    {
        hmapx_destroy(&srcs);
        hmapx_destroy(&dsts);
        return;
    }

    hmapx_swap(&srcs, &mirror->srcs);
    hmapx_destroy(&srcs);

    hmapx_swap(&dsts, &mirror->dsts);
    hmapx_destroy(&dsts);

    free(mirror->vlans);
    mirror->vlans = vlan_bitmap_clone(s->src_vlans);

    mirror->out = out;
    mirror->out_vlan = out_vlan;

    /* Update bundles. */
    mirror_bit = MIRROR_MASK_C(1) << mirror->idx;
    HMAP_FOR_EACH (bundle, hmap_node, &mirror->ofproto->bundles) {
        if (hmapx_contains(&mirror->srcs, bundle)) {
            bundle->src_mirrors |= mirror_bit;
        } else {
            bundle->src_mirrors &= ~mirror_bit;
        }

        if (hmapx_contains(&mirror->dsts, bundle)) {
            bundle->dst_mirrors |= mirror_bit;
        } else {
            bundle->dst_mirrors &= ~mirror_bit;
        }

        if (mirror->out == bundle) {
            bundle->mirror_out |= mirror_bit;
        } else {
            bundle->mirror_out &= ~mirror_bit;
        }
    }

    ofproto->need_revalidate = true;
    mac_learning_flush(ofproto->ml);
}

static void
ofproto_mirror_destroy(struct ofmirror *mirror)
{
    mirror_mask_t mirror_bit;
    struct ofbundle *bundle;
    struct ofproto *ofproto;

    if (!mirror) {
        return;
    }

    ofproto = mirror->ofproto;
    ofproto->need_revalidate = true;
    mac_learning_flush(ofproto->ml);

    mirror_bit = MIRROR_MASK_C(1) << mirror->idx;
    HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
        bundle->src_mirrors &= ~mirror_bit;
        bundle->dst_mirrors &= ~mirror_bit;
        bundle->mirror_out &= ~mirror_bit;
    }

    hmapx_destroy(&mirror->srcs);
    hmapx_destroy(&mirror->dsts);
    free(mirror->vlans);

    ofproto->mirrors[mirror->idx] = NULL;
    free(mirror->name);
    free(mirror);
}

void
ofproto_mirror_unregister(struct ofproto *ofproto, void *aux)
{
    ofproto_mirror_destroy(ofproto_mirror_lookup(ofproto, aux));
}

void
ofproto_set_flood_vlans(struct ofproto *ofproto, unsigned long *flood_vlans)
{
    if (mac_learning_set_flood_vlans(ofproto->ml, flood_vlans)) {
        ofproto->need_revalidate = true;
        mac_learning_flush(ofproto->ml);
    }
}

bool
ofproto_is_mirror_output_bundle(struct ofproto *ofproto, void *aux)
{
    struct ofbundle *bundle = ofproto_bundle_lookup(ofproto, aux);
    return bundle && bundle->mirror_out != 0;
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

void
ofproto_destroy(struct ofproto *p)
{
    struct ofport *ofport, *next_ofport;
    int i;

    if (!p) {
        return;
    }

    hmap_remove(&all_ofprotos, &p->hmap_node);

    for (i = 0; i < MAX_MIRRORS; i++) {
        ofproto_mirror_destroy(p->mirrors[i]);
    }
    ofproto_flush_flows__(p);
    connmgr_destroy(p->connmgr);
    classifier_destroy(&p->cls);
    hmap_destroy(&p->facets);

    dpif_close(p->dpif);

    netdev_monitor_destroy(p->netdev_monitor);
    HMAP_FOR_EACH_SAFE (ofport, next_ofport, hmap_node, &p->ports) {
        hmap_remove(&p->ports, &ofport->hmap_node);
        ofport_free(ofport);
    }
    shash_destroy(&p->port_by_name);

    netflow_destroy(p->netflow);
    ofproto_sflow_destroy(p->sflow);

    free(p->mfr_desc);
    free(p->hw_desc);
    free(p->sw_desc);
    free(p->serial_desc);
    free(p->dp_desc);

    hmap_destroy(&p->ports);

    free(p->name);
    free(p);
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
    struct ofbundle *bundle;
    struct ofport *ofport;
    char *devname;
    int error;
    int i;

    dpif_run(p->dpif);

    for (i = 0; i < 50; i++) {
        struct dpif_upcall packet;

        error = dpif_recv(p->dpif, &packet);
        if (error) {
            if (error == ENODEV) {
                /* Someone destroyed the datapath behind our back.  The caller
                 * better destroy us and give up, because we're just going to
                 * spin from here on out. */
                static struct vlog_rate_limit rl2 = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_ERR_RL(&rl2, "%s: datapath was destroyed externally",
                            p->name);
                return ENODEV;
            }
            break;
        }

        handle_upcall(p, &packet);
    }

    while ((error = dpif_port_poll(p->dpif, &devname)) != EAGAIN) {
        process_port_change(p, error, devname);
    }
    while ((error = netdev_monitor_poll(p->netdev_monitor,
                                        &devname)) != EAGAIN) {
        process_port_change(p, error, devname);
    }

    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        ofport_run(ofport);
    }

    HMAP_FOR_EACH (bundle, hmap_node, &p->bundles) {
        ofproto_bundle_run(bundle);
    }

    connmgr_run(p->connmgr, handle_openflow);

    if (timer_expired(&p->next_expiration)) {
        int delay = ofproto_expire(p);
        timer_set_duration(&p->next_expiration, delay);
        COVERAGE_INC(ofproto_expiration);
    }

    if (p->netflow) {
        netflow_run(p->netflow);
    }
    if (p->sflow) {
        ofproto_sflow_run(p->sflow);
    }

    /* Now revalidate if there's anything to do. */
    if (p->need_revalidate || !tag_set_is_empty(&p->revalidate_set)) {
        struct tag_set revalidate_set = p->revalidate_set;
        bool revalidate_all = p->need_revalidate;
        struct facet *facet, *next;

        /* Clear the revalidation flags. */
        tag_set_init(&p->revalidate_set);
        p->need_revalidate = false;

        HMAP_FOR_EACH_SAFE (facet, next, hmap_node, &p->facets) {
            if (revalidate_all
                || tag_set_intersects(&revalidate_set, facet->tags)) {
                facet_revalidate(p, facet);
            }
        }
    }

    return 0;
}

void
ofproto_wait(struct ofproto *p)
{
    struct ofbundle *bundle;
    struct ofport *ofport;

    dpif_wait(p->dpif);
    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        ofport_wait(ofport);
    }
    HMAP_FOR_EACH (bundle, hmap_node, &p->bundles) {
        ofproto_bundle_wait(bundle);
    }
    dpif_recv_wait(p->dpif);
    dpif_port_poll_wait(p->dpif);
    netdev_monitor_poll_wait(p->netdev_monitor);
    if (p->sflow) {
        ofproto_sflow_wait(p->sflow);
    }
    if (!tag_set_is_empty(&p->revalidate_set)) {
        poll_immediate_wake();
    }
    if (p->need_revalidate) {
        /* Shouldn't happen, but if it does just go around again. */
        VLOG_DBG_RL(&rl, "need revalidate in ofproto_wait_cb()");
        poll_immediate_wake();
    } else {
        timer_wait(&p->next_expiration);
    }
    connmgr_wait(p->connmgr);
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
    struct shash_node *node;

    SHASH_FOR_EACH (node, info) {
        struct ofproto_controller_info *cinfo = node->data;
        while (cinfo->pairs.n) {
            free((char *) cinfo->pairs.values[--cinfo->pairs.n]);
        }
        free(cinfo);
    }
    shash_destroy(info);
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

/* Converts a dpif_port into an ofproto_port.
 *
 * This only makes a shallow copy, so make sure that the dpif_port doesn't get
 * freed while the ofproto_port is still in use.  You can choose to free the
 * ofproto_port instead of the dpif_port. */
static void
ofproto_port_from_dpif_port(struct ofproto_port *ofproto_port,
                            struct dpif_port *dpif_port)
{
    ofproto_port->name = dpif_port->name;
    ofproto_port->type = dpif_port->type;
    ofproto_port->ofp_port = odp_port_to_ofp_port(dpif_port->port_no);
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
    struct dpif_port_dump *dpif_dump;

    dump->state = dpif_dump = xmalloc(sizeof *dpif_dump);
    dpif_port_dump_start(dpif_dump, ofproto->dpif);
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
    struct dpif_port_dump *dpif_dump = dump->state;
    struct dpif_port dpif_port;
    bool ok;

    ok = dpif_port_dump_next(dpif_dump, &dpif_port);
    if (ok) {
        ofproto_port_from_dpif_port(port, &dpif_port);
    }
    return ok;
}

/* Completes port table dump operation 'dump', which must have been created
 * with ofproto_port_dump_start().  Returns 0 if the dump operation was
 * error-free, otherwise a positive errno value describing the problem. */
int
ofproto_port_dump_done(struct ofproto_port_dump *dump)
{
    struct dpif_port_dump *dpif_dump = dump->state;
    int error = dpif_port_dump_done(dpif_dump);
    free(dpif_dump);
    return error;
}

/* Attempts to add 'netdev' as a port on 'ofproto'.  If successful, returns 0
 * and sets '*ofp_portp' to the new port's port OpenFlow number (if 'ofp_portp'
 * is non-null).  On failure, returns a positive errno value and sets
 * '*ofp_portp' to OFPP_NONE (if 'ofp_portp' is non-null). */
int
ofproto_port_add(struct ofproto *ofproto, struct netdev *netdev,
                 uint16_t *ofp_portp)
{
    uint16_t odp_port;
    int error;

    error = dpif_port_add(ofproto->dpif, netdev, &odp_port);
    if (!error) {
        update_port(ofproto, netdev_get_name(netdev));
    }
    if (ofp_portp) {
        *ofp_portp = error ? OFPP_NONE : odp_port_to_ofp_port(odp_port);
    }
    return error;
}

/* Looks up a port named 'devname' in 'ofproto'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * The caller owns the data in 'port' and must free it with
 * ofproto_port_destroy() when it is no longer needed. */
int
ofproto_port_query_by_name(const struct ofproto *ofproto, const char *devname,
                           struct ofproto_port *port)
{
    struct dpif_port dpif_port;
    int error;

    error = dpif_port_query_by_name(ofproto->dpif, devname, &dpif_port);
    if (!error) {
        ofproto_port_from_dpif_port(port, &dpif_port);
    }
    return error;
}

/* Deletes port number 'ofp_port' from the datapath for 'ofproto'.
 *
 * This is almost the same as calling dpif_port_del() directly on the
 * datapath, but it also makes 'ofproto' close its open netdev for the port
 * (if any).  This makes it possible to create a new netdev of a different
 * type under the same name, which otherwise the netdev library would refuse
 * to do because of the conflict.  (The netdev would eventually get closed on
 * the next trip through ofproto_run(), but this interface is more direct.)
 *
 * Returns 0 if successful, otherwise a positive errno. */
int
ofproto_port_del(struct ofproto *ofproto, uint16_t ofp_port)
{
    uint32_t odp_port = ofp_port_to_odp_port(ofp_port);
    struct ofport *ofport = get_port(ofproto, odp_port);
    const char *name = ofport ? netdev_get_name(ofport->netdev) : "<unknown>";
    int error;

    error = dpif_port_del(ofproto->dpif, odp_port);
    if (error) {
        VLOG_ERR("%s: failed to remove port %"PRIu16" (%s) interface (%s)",
                 ofproto->name, odp_port, name, strerror(error));
    } else if (ofport) {
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

/* Sends 'packet' out of port 'port_no' within 'p'.  If 'vlan_tci' is zero the
 * packet will not have any 802.1Q hader; if it is nonzero, then the packet
 * will be sent with the VLAN TCI specified by 'vlan_tci & ~VLAN_CFI'.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
ofproto_send_packet(struct ofproto *ofproto,
                    uint32_t port_no, uint16_t vlan_tci,
                    const struct ofpbuf *packet)
{
    struct ofpbuf odp_actions;
    int error;

    ofpbuf_init(&odp_actions, 32);
    if (vlan_tci != 0) {
        nl_msg_put_u32(&odp_actions, ODP_ACTION_ATTR_SET_DL_TCI,
                       ntohs(vlan_tci & ~VLAN_CFI));
    }
    nl_msg_put_u32(&odp_actions, ODP_ACTION_ATTR_OUTPUT, port_no);
    error = dpif_execute(ofproto->dpif, odp_actions.data, odp_actions.size,
                         packet);
    ofpbuf_uninit(&odp_actions);

    if (error) {
        VLOG_WARN_RL(&rl, "%s: failed to send packet on port %"PRIu32" (%s)",
                     ofproto->name, port_no, strerror(error));
    }
    return error;
}

/* Adds a flow to the OpenFlow flow table in 'p' that matches 'cls_rule' and
 * performs the 'n_actions' actions in 'actions'.  The new flow will not
 * timeout.
 *
 * If cls_rule->priority is in the range of priorities supported by OpenFlow
 * (0...65535, inclusive) then the flow will be visible to OpenFlow
 * controllers; otherwise, it will be hidden.
 *
 * The caller retains ownership of 'cls_rule' and 'actions'. */
void
ofproto_add_flow(struct ofproto *p, const struct cls_rule *cls_rule,
                 const union ofp_action *actions, size_t n_actions)
{
    struct rule *rule;
    rule = rule_create(cls_rule, actions, n_actions, 0, 0, 0, false);
    rule_insert(p, rule);
}

void
ofproto_delete_flow(struct ofproto *ofproto, const struct cls_rule *target)
{
    struct rule *rule;

    rule = rule_from_cls_rule(classifier_find_rule_exactly(&ofproto->cls,
                                                           target));
    if (rule) {
        rule_remove(ofproto, rule);
    }
}

static void
ofproto_flush_flows__(struct ofproto *ofproto)
{
    struct facet *facet, *next_facet;
    struct rule *rule, *next_rule;
    struct cls_cursor cursor;

    COVERAGE_INC(ofproto_flush);

    HMAP_FOR_EACH_SAFE (facet, next_facet, hmap_node, &ofproto->facets) {
        /* Mark the facet as not installed so that facet_remove() doesn't
         * bother trying to uninstall it.  There is no point in uninstalling it
         * individually since we are about to blow away all the facets with
         * dpif_flow_flush(). */
        facet->installed = false;
        facet->dp_packet_count = 0;
        facet->dp_byte_count = 0;
        facet_remove(ofproto, facet);
    }

    cls_cursor_init(&cursor, &ofproto->cls, NULL);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
        rule_remove(ofproto, rule);
    }

    dpif_flow_flush(ofproto->dpif);
}

void
ofproto_flush_flows(struct ofproto *ofproto)
{
    ofproto_flush_flows__(ofproto);
    connmgr_flushed(ofproto->connmgr);
}

static void
reinit_ports(struct ofproto *p)
{
    struct dpif_port_dump dump;
    struct sset devnames;
    struct ofport *ofport;
    struct dpif_port dpif_port;
    const char *devname;

    COVERAGE_INC(ofproto_reinit_ports);

    sset_init(&devnames);
    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        sset_add(&devnames, netdev_get_name(ofport->netdev));
    }
    DPIF_PORT_FOR_EACH (&dpif_port, &dump, p->dpif) {
        sset_add(&devnames, dpif_port.name);
    }

    SSET_FOR_EACH (devname, &devnames) {
        update_port(p, devname);
    }
    sset_destroy(&devnames);
}

/* Opens and returns a netdev for 'dpif_port', or a null pointer if the netdev
 * cannot be opened.  On success, also fills in 'opp'. */
static struct netdev *
ofport_open(const struct dpif_port *dpif_port, struct ofp_phy_port *opp)
{
    uint32_t curr, advertised, supported, peer;
    struct netdev_options netdev_options;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    memset(&netdev_options, 0, sizeof netdev_options);
    netdev_options.name = dpif_port->name;
    netdev_options.type = dpif_port->type;
    netdev_options.ethertype = NETDEV_ETH_TYPE_NONE;

    error = netdev_open(&netdev_options, &netdev);
    if (error) {
        VLOG_WARN_RL(&rl, "ignoring port %s (%"PRIu16") because netdev %s "
                     "cannot be opened (%s)",
                     dpif_port->name, dpif_port->port_no,
                     dpif_port->name, strerror(error));
        return NULL;
    }

    netdev_get_flags(netdev, &flags);
    netdev_get_features(netdev, &curr, &advertised, &supported, &peer);

    opp->port_no = htons(odp_port_to_ofp_port(dpif_port->port_no));
    netdev_get_etheraddr(netdev, opp->hw_addr);
    ovs_strzcpy(opp->name, dpif_port->name, sizeof opp->name);
    opp->config = flags & NETDEV_UP ? 0 : htonl(OFPPC_PORT_DOWN);
    opp->state = netdev_get_carrier(netdev) ? 0 : htonl(OFPPS_LINK_DOWN);
    opp->curr = htonl(curr);
    opp->advertised = htonl(advertised);
    opp->supported = htonl(supported);
    opp->peer = htonl(peer);

    return netdev;
}

static bool
ofport_conflicts(const struct ofproto *p, const struct dpif_port *dpif_port)
{
    if (get_port(p, dpif_port->port_no)) {
        VLOG_WARN_RL(&rl, "ignoring duplicate port %"PRIu16" in datapath",
                     dpif_port->port_no);
        return true;
    } else if (shash_find(&p->port_by_name, dpif_port->name)) {
        VLOG_WARN_RL(&rl, "ignoring duplicate device %s in datapath",
                     dpif_port->name);
        return true;
    } else {
        return false;
    }
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

    connmgr_send_port_status(p->connmgr, opp, OFPPR_ADD);

    /* Create ofport. */
    ofport = xmalloc(sizeof *ofport);
    ofport->ofproto = p;
    ofport->netdev = netdev;
    ofport->opp = *opp;
    ofport->odp_port = ofp_port_to_odp_port(ntohs(opp->port_no));
    ofport->bundle = NULL;
    ofport->cfm = NULL;
    ofport->tag = tag_create_random();

    /* Add port to 'p'. */
    netdev_monitor_add(p->netdev_monitor, ofport->netdev);
    hmap_insert(&p->ports, &ofport->hmap_node, hash_int(ofport->odp_port, 0));
    shash_add(&p->port_by_name, netdev_name, ofport);
    if (p->sflow) {
        ofproto_sflow_add_port(p->sflow, ofport->odp_port, netdev_name);
    }
}

/* Removes 'ofport' from 'p' and destroys it. */
static void
ofport_remove(struct ofport *ofport)
{
    connmgr_send_port_status(ofport->ofproto->connmgr, &ofport->opp,
                             OFPPR_DELETE);
    ofport_free(ofport);
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
ofport_modified(struct ofport *port,
                struct netdev *netdev, struct ofp_phy_port *opp)
{
    struct ofproto *ofproto = port->ofproto;

    if (port->bundle && port->bundle->bond) {
        bond_slave_set_netdev(port->bundle->bond, port, netdev);
    }

    memcpy(port->opp.hw_addr, opp->hw_addr, ETH_ADDR_LEN);
    port->opp.config = ((port->opp.config & ~htonl(OFPPC_PORT_DOWN))
                        | (opp->config & htonl(OFPPC_PORT_DOWN)));
    port->opp.state = opp->state;
    port->opp.curr = opp->curr;
    port->opp.advertised = opp->advertised;
    port->opp.supported = opp->supported;
    port->opp.peer = opp->peer;

    netdev_monitor_remove(ofproto->netdev_monitor, port->netdev);
    netdev_monitor_add(ofproto->netdev_monitor, netdev);

    netdev_close(port->netdev);
    port->netdev = netdev;

    connmgr_send_port_status(ofproto->connmgr, &port->opp, OFPPR_MODIFY);
}

static void
ofport_run(struct ofport *ofport)
{
    if (ofport->cfm) {
        cfm_run(ofport->cfm);

        if (cfm_should_send_ccm(ofport->cfm)) {
            struct ofpbuf packet;
            struct ccm *ccm;

            ofpbuf_init(&packet, 0);
            ccm = eth_compose(&packet, eth_addr_ccm, ofport->opp.hw_addr,
                              ETH_TYPE_CFM,  sizeof *ccm);
            cfm_compose_ccm(ofport->cfm, ccm);
            ofproto_send_packet(ofport->ofproto, ofport->odp_port, 0, &packet);
            ofpbuf_uninit(&packet);
        }
    }
}

static void
ofport_wait(struct ofport *ofport)
{
    if (ofport->cfm) {
        cfm_wait(ofport->cfm);
    }
}

static void
ofport_unregister(struct ofport *port)
{
    struct ofbundle *bundle = port->bundle;

    if (bundle) {
        ofproto_bundle_del_port(port);
        if (list_is_empty(&bundle->ports)) {
            ofproto_bundle_destroy(bundle);
        } else if (list_is_short(&bundle->ports)) {
            bond_destroy(bundle->bond);
            bundle->bond = NULL;
        }
    }

    cfm_destroy(port->cfm);
    port->cfm = NULL;
}

void
ofproto_port_unregister(struct ofproto *ofproto, uint32_t ofp_port)
{
    struct ofport *port = get_port(ofproto, ofp_port_to_odp_port(ofp_port));
    if (port) {
        ofport_unregister(port);
    }
}

static void
ofport_free(struct ofport *port)
{
    if (port) {
        struct ofproto *ofproto = port->ofproto;
        const char *name = netdev_get_name(port->netdev);

        ofport_unregister(port);

        netdev_monitor_remove(ofproto->netdev_monitor, port->netdev);
        hmap_remove(&ofproto->ports, &port->hmap_node);
        shash_delete(&ofproto->port_by_name,
                     shash_find(&ofproto->port_by_name, name));
        if (ofproto->sflow) {
            ofproto_sflow_del_port(ofproto->sflow, port->odp_port);
        }

        netdev_close(port->netdev);
        free(port);
    }
}

static struct ofport *
get_port(const struct ofproto *ofproto, uint16_t odp_port)
{
    struct ofport *port;

    HMAP_FOR_EACH_IN_BUCKET (port, hmap_node,
                             hash_int(odp_port, 0), &ofproto->ports) {
        if (port->odp_port == odp_port) {
            return port;
        }
    }
    return NULL;
}

static void
update_port(struct ofproto *ofproto, const char *name)
{
    struct dpif_port dpif_port;
    struct ofp_phy_port opp;
    struct netdev *netdev;
    struct ofport *port;

    COVERAGE_INC(ofproto_update_port);

    /* Fetch 'name''s location and properties from the datapath. */
    netdev = (!dpif_port_query_by_name(ofproto->dpif, name, &dpif_port)
              ? ofport_open(&dpif_port, &opp)
              : NULL);
    if (netdev) {
        port = get_port(ofproto, dpif_port.port_no);
        if (port && !strcmp(netdev_get_name(port->netdev), name)) {
            /* 'name' hasn't changed location.  Any properties changed? */
            if (!ofport_equal(&port->opp, &opp)) {
                ofport_modified(port, netdev, &opp);
            } else {
                netdev_close(netdev);
            }
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
    dpif_port_destroy(&dpif_port);
}

static int
init_ports(struct ofproto *p)
{
    struct dpif_port_dump dump;
    struct dpif_port dpif_port;

    DPIF_PORT_FOR_EACH (&dpif_port, &dump, p->dpif) {
        if (!ofport_conflicts(p, &dpif_port)) {
            struct ofp_phy_port opp;
            struct netdev *netdev;

            netdev = ofport_open(&dpif_port, &opp);
            if (netdev) {
                ofport_install(p, netdev, &opp);
            }
        }
    }

    return 0;
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

/* Creates and returns a new rule initialized as specified.
 *
 * The caller is responsible for inserting the rule into the classifier (with
 * rule_insert()). */
static struct rule *
rule_create(const struct cls_rule *cls_rule,
            const union ofp_action *actions, size_t n_actions,
            uint16_t idle_timeout, uint16_t hard_timeout,
            ovs_be64 flow_cookie, bool send_flow_removed)
{
    struct rule *rule = xzalloc(sizeof *rule);
    rule->cr = *cls_rule;
    rule->idle_timeout = idle_timeout;
    rule->hard_timeout = hard_timeout;
    rule->flow_cookie = flow_cookie;
    rule->used = rule->created = time_msec();
    rule->send_flow_removed = send_flow_removed;
    list_init(&rule->facets);
    if (n_actions > 0) {
        rule->n_actions = n_actions;
        rule->actions = xmemdup(actions, n_actions * sizeof *actions);
    }

    return rule;
}

static struct rule *
rule_from_cls_rule(const struct cls_rule *cls_rule)
{
    return cls_rule ? CONTAINER_OF(cls_rule, struct rule, cr) : NULL;
}

static void
rule_free(struct rule *rule)
{
    free(rule->actions);
    free(rule);
}

/* Destroys 'rule' and iterates through all of its facets and revalidates them,
 * destroying any that no longer has a rule (which is probably all of them).
 *
 * The caller must have already removed 'rule' from the classifier. */
static void
rule_destroy(struct ofproto *ofproto, struct rule *rule)
{
    struct facet *facet, *next_facet;
    LIST_FOR_EACH_SAFE (facet, next_facet, list_node, &rule->facets) {
        facet_revalidate(ofproto, facet);
    }
    rule_free(rule);
}

/* Returns true if 'rule' has an OpenFlow OFPAT_OUTPUT or OFPAT_ENQUEUE action
 * that outputs to 'out_port' (output to OFPP_FLOOD and OFPP_ALL doesn't
 * count). */
static bool
rule_has_out_port(const struct rule *rule, ovs_be16 out_port)
{
    const union ofp_action *oa;
    struct actions_iterator i;

    if (out_port == htons(OFPP_NONE)) {
        return true;
    }
    for (oa = actions_first(&i, rule->actions, rule->n_actions); oa;
         oa = actions_next(&i)) {
        if (action_outputs_to_port(oa, out_port)) {
            return true;
        }
    }
    return false;
}

/* Executes, within 'ofproto', the 'n_actions' actions in 'actions' on
 * 'packet', which arrived on 'in_port'.
 *
 * Takes ownership of 'packet'. */
static bool
execute_odp_actions(struct ofproto *ofproto, const struct flow *flow,
                    const struct nlattr *odp_actions, size_t actions_len,
                    struct ofpbuf *packet)
{
    if (actions_len == NLA_ALIGN(NLA_HDRLEN + sizeof(uint64_t))
        && odp_actions->nla_type == ODP_ACTION_ATTR_CONTROLLER) {
        /* As an optimization, avoid a round-trip from userspace to kernel to
         * userspace.  This also avoids possibly filling up kernel packet
         * buffers along the way. */
        struct dpif_upcall upcall;

        upcall.type = DPIF_UC_ACTION;
        upcall.packet = packet;
        upcall.key = NULL;
        upcall.key_len = 0;
        upcall.userdata = nl_attr_get_u64(odp_actions);
        upcall.sample_pool = 0;
        upcall.actions = NULL;
        upcall.actions_len = 0;

        send_packet_in(ofproto, &upcall, flow, false);

        return true;
    } else {
        int error;

        error = dpif_execute(ofproto->dpif, odp_actions, actions_len, packet);
        ofpbuf_delete(packet);
        return !error;
    }
}

/* Executes the actions indicated by 'facet' on 'packet' and credits 'facet''s
 * statistics appropriately.  'packet' must have at least sizeof(struct
 * ofp_packet_in) bytes of headroom.
 *
 * For correct results, 'packet' must actually be in 'facet''s flow; that is,
 * applying flow_extract() to 'packet' would yield the same flow as
 * 'facet->flow'.
 *
 * 'facet' must have accurately composed ODP actions; that is, it must not be
 * in need of revalidation.
 *
 * Takes ownership of 'packet'. */
static void
facet_execute(struct ofproto *ofproto, struct facet *facet,
              struct ofpbuf *packet)
{
    struct dpif_flow_stats stats;

    assert(ofpbuf_headroom(packet) >= sizeof(struct ofp_packet_in));

    flow_extract_stats(&facet->flow, packet, &stats);
    stats.used = time_msec();
    if (execute_odp_actions(ofproto, &facet->flow,
                            facet->actions, facet->actions_len, packet)) {
        facet_update_stats(ofproto, facet, &stats);
    }
}

/* Executes the actions indicated by 'rule' on 'packet' and credits 'rule''s
 * statistics (or the statistics for one of its facets) appropriately.
 * 'packet' must have at least sizeof(struct ofp_packet_in) bytes of headroom.
 *
 * 'packet' doesn't necessarily have to match 'rule'.  'rule' will be credited
 * with statistics for 'packet' either way.
 *
 * Takes ownership of 'packet'. */
static void
rule_execute(struct ofproto *ofproto, struct rule *rule, uint16_t in_port,
             struct ofpbuf *packet)
{
    struct action_xlate_ctx ctx;
    struct ofpbuf *odp_actions;
    struct facet *facet;
    struct flow flow;
    size_t size;

    assert(ofpbuf_headroom(packet) >= sizeof(struct ofp_packet_in));

    flow_extract(packet, 0, in_port, &flow);

    /* First look for a related facet.  If we find one, account it to that. */
    facet = facet_lookup_valid(ofproto, &flow);
    if (facet && facet->rule == rule) {
        facet_execute(ofproto, facet, packet);
        return;
    }

    /* Otherwise, if 'rule' is in fact the correct rule for 'packet', then
     * create a new facet for it and use that. */
    if (rule_lookup(ofproto, &flow) == rule) {
        facet = facet_create(ofproto, rule, &flow, packet);
        facet_execute(ofproto, facet, packet);
        facet_install(ofproto, facet, true);
        return;
    }

    /* We can't account anything to a facet.  If we were to try, then that
     * facet would have a non-matching rule, busting our invariants. */
    action_xlate_ctx_init(&ctx, ofproto, &flow, packet);
    odp_actions = xlate_actions(&ctx, rule->actions, rule->n_actions);
    size = packet->size;
    if (execute_odp_actions(ofproto, &flow, odp_actions->data,
                            odp_actions->size, packet)) {
        rule->used = time_msec();
        rule->packet_count++;
        rule->byte_count += size;
        flow_push_stats(ofproto, rule, &flow, 1, size, rule->used);
    }
    ofpbuf_delete(odp_actions);
}

/* Inserts 'rule' into 'p''s flow table. */
static void
rule_insert(struct ofproto *p, struct rule *rule)
{
    struct rule *displaced_rule;

    displaced_rule = rule_from_cls_rule(classifier_insert(&p->cls, &rule->cr));
    if (displaced_rule) {
        rule_destroy(p, displaced_rule);
    }
    p->need_revalidate = true;
}

/* Creates and returns a new facet within 'ofproto' owned by 'rule', given a
 * 'flow' and an example 'packet' within that flow.
 *
 * The caller must already have determined that no facet with an identical
 * 'flow' exists in 'ofproto' and that 'flow' is the best match for 'rule' in
 * 'ofproto''s classifier table. */
static struct facet *
facet_create(struct ofproto *ofproto, struct rule *rule,
             const struct flow *flow, const struct ofpbuf *packet)
{
    struct facet *facet;

    facet = xzalloc(sizeof *facet);
    facet->used = time_msec();
    hmap_insert(&ofproto->facets, &facet->hmap_node, flow_hash(flow, 0));
    list_push_back(&rule->facets, &facet->list_node);
    facet->rule = rule;
    facet->flow = *flow;
    netflow_flow_init(&facet->nf_flow);
    netflow_flow_update_time(ofproto->netflow, &facet->nf_flow, facet->used);

    facet_make_actions(ofproto, facet, packet);

    return facet;
}

static void
facet_free(struct facet *facet)
{
    free(facet->actions);
    free(facet);
}

/* Remove 'rule' from 'ofproto' and free up the associated memory:
 *
 *   - Removes 'rule' from the classifier.
 *
 *   - If 'rule' has facets, revalidates them (and possibly uninstalls and
 *     destroys them), via rule_destroy().
 */
static void
rule_remove(struct ofproto *ofproto, struct rule *rule)
{
    COVERAGE_INC(ofproto_del_rule);
    ofproto->need_revalidate = true;
    classifier_remove(&ofproto->cls, &rule->cr);
    rule_destroy(ofproto, rule);
}

/* Remove 'facet' from 'ofproto' and free up the associated memory:
 *
 *   - If 'facet' was installed in the datapath, uninstalls it and updates its
 *     rule's statistics, via facet_uninstall().
 *
 *   - Removes 'facet' from its rule and from ofproto->facets.
 */
static void
facet_remove(struct ofproto *ofproto, struct facet *facet)
{
    facet_uninstall(ofproto, facet);
    facet_flush_stats(ofproto, facet);
    hmap_remove(&ofproto->facets, &facet->hmap_node);
    list_remove(&facet->list_node);
    facet_free(facet);
}

/* Composes the ODP actions for 'facet' based on its rule's actions. */
static void
facet_make_actions(struct ofproto *p, struct facet *facet,
                   const struct ofpbuf *packet)
{
    const struct rule *rule = facet->rule;
    struct ofpbuf *odp_actions;
    struct action_xlate_ctx ctx;

    action_xlate_ctx_init(&ctx, p, &facet->flow, packet);
    odp_actions = xlate_actions(&ctx, rule->actions, rule->n_actions);
    facet->tags = ctx.tags;
    facet->may_install = ctx.may_set_up_flow;
    facet->nf_flow.output_iface = ctx.nf_output_iface;

    if (facet->actions_len != odp_actions->size
        || memcmp(facet->actions, odp_actions->data, odp_actions->size)) {
        free(facet->actions);
        facet->actions_len = odp_actions->size;
        facet->actions = xmemdup(odp_actions->data, odp_actions->size);
    }

    ofpbuf_delete(odp_actions);
}

static int
facet_put__(struct ofproto *ofproto, struct facet *facet,
            const struct nlattr *actions, size_t actions_len,
            struct dpif_flow_stats *stats)
{
    struct odputil_keybuf keybuf;
    enum dpif_flow_put_flags flags;
    struct ofpbuf key;

    flags = DPIF_FP_CREATE | DPIF_FP_MODIFY;
    if (stats) {
        flags |= DPIF_FP_ZERO_STATS;
        facet->dp_packet_count = 0;
        facet->dp_byte_count = 0;
    }

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, &facet->flow);

    return dpif_flow_put(ofproto->dpif, flags, key.data, key.size,
                         actions, actions_len, stats);
}

/* If 'facet' is installable, inserts or re-inserts it into 'p''s datapath.  If
 * 'zero_stats' is true, clears any existing statistics from the datapath for
 * 'facet'. */
static void
facet_install(struct ofproto *p, struct facet *facet, bool zero_stats)
{
    struct dpif_flow_stats stats;

    if (facet->may_install
        && !facet_put__(p, facet, facet->actions, facet->actions_len,
                        zero_stats ? &stats : NULL)) {
        facet->installed = true;
    }
}

static void
facet_account(struct ofproto *ofproto,
              struct facet *facet, uint64_t extra_bytes)
{
    uint64_t total_bytes, n_bytes;
    struct ofbundle *in_bundle;
    const struct nlattr *a;
    tag_type dummy = 0;
    unsigned int left;
    int vlan;

    total_bytes = facet->byte_count + extra_bytes;
    if (total_bytes <= facet->accounted_bytes) {
        return;
    }
    n_bytes = total_bytes - facet->accounted_bytes;
    facet->accounted_bytes = total_bytes;

    /* Test that 'tags' is nonzero to ensure that only flows that include an
     * OFPP_NORMAL action are used for learning and bond slave rebalancing.
     * This works because OFPP_NORMAL always sets a nonzero tag value.
     *
     * Feed information from the active flows back into the learning table to
     * ensure that table is always in sync with what is actually flowing
     * through the datapath. */
    if (!facet->tags
        || !is_admissible(ofproto, &facet->flow, false, &dummy,
                          &vlan, &in_bundle)) {
        return;
    }

    update_learning_table(ofproto, &facet->flow, vlan, in_bundle);

    if (!ofproto->has_bonded_bundles) {
        return;
    }
    NL_ATTR_FOR_EACH_UNSAFE (a, left, facet->actions, facet->actions_len) {
        if (nl_attr_type(a) == ODP_ACTION_ATTR_OUTPUT) {
            struct ofport *port = get_port(ofproto, nl_attr_get_u32(a));
            if (port && port->bundle && port->bundle->bond) {
                bond_account(port->bundle->bond, &facet->flow, vlan, n_bytes);
            }
        }
    }
}

/* If 'rule' is installed in the datapath, uninstalls it. */
static void
facet_uninstall(struct ofproto *p, struct facet *facet)
{
    if (facet->installed) {
        struct odputil_keybuf keybuf;
        struct dpif_flow_stats stats;
        struct ofpbuf key;

        ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
        odp_flow_key_from_flow(&key, &facet->flow);

        if (!dpif_flow_del(p->dpif, key.data, key.size, &stats)) {
            facet_update_stats(p, facet, &stats);
        }
        facet->installed = false;
        facet->dp_packet_count = 0;
        facet->dp_byte_count = 0;
    } else {
        assert(facet->dp_packet_count == 0);
        assert(facet->dp_byte_count == 0);
    }
}

/* Returns true if the only action for 'facet' is to send to the controller.
 * (We don't report NetFlow expiration messages for such facets because they
 * are just part of the control logic for the network, not real traffic). */
static bool
facet_is_controller_flow(struct facet *facet)
{
    return (facet
            && facet->rule->n_actions == 1
            && action_outputs_to_port(&facet->rule->actions[0],
                                      htons(OFPP_CONTROLLER)));
}

/* Folds all of 'facet''s statistics into its rule.  Also updates the
 * accounting ofhook and emits a NetFlow expiration if appropriate.  All of
 * 'facet''s statistics in the datapath should have been zeroed and folded into
 * its packet and byte counts before this function is called. */
static void
facet_flush_stats(struct ofproto *ofproto, struct facet *facet)
{
    assert(!facet->dp_byte_count);
    assert(!facet->dp_packet_count);

    facet_push_stats(ofproto, facet);
    facet_account(ofproto, facet, 0);

    if (ofproto->netflow && !facet_is_controller_flow(facet)) {
        struct ofexpired expired;
        expired.flow = facet->flow;
        expired.packet_count = facet->packet_count;
        expired.byte_count = facet->byte_count;
        expired.used = facet->used;
        netflow_expire(ofproto->netflow, &facet->nf_flow, &expired);
    }

    facet->rule->packet_count += facet->packet_count;
    facet->rule->byte_count += facet->byte_count;

    /* Reset counters to prevent double counting if 'facet' ever gets
     * reinstalled. */
    facet->packet_count = 0;
    facet->byte_count = 0;
    facet->rs_packet_count = 0;
    facet->rs_byte_count = 0;
    facet->accounted_bytes = 0;

    netflow_flow_clear(&facet->nf_flow);
}

/* Searches 'ofproto''s table of facets for one exactly equal to 'flow'.
 * Returns it if found, otherwise a null pointer.
 *
 * The returned facet might need revalidation; use facet_lookup_valid()
 * instead if that is important. */
static struct facet *
facet_find(struct ofproto *ofproto, const struct flow *flow)
{
    struct facet *facet;

    HMAP_FOR_EACH_WITH_HASH (facet, hmap_node, flow_hash(flow, 0),
                             &ofproto->facets) {
        if (flow_equal(flow, &facet->flow)) {
            return facet;
        }
    }

    return NULL;
}

/* Searches 'ofproto''s table of facets for one exactly equal to 'flow'.
 * Returns it if found, otherwise a null pointer.
 *
 * The returned facet is guaranteed to be valid. */
static struct facet *
facet_lookup_valid(struct ofproto *ofproto, const struct flow *flow)
{
    struct facet *facet = facet_find(ofproto, flow);

    /* The facet we found might not be valid, since we could be in need of
     * revalidation.  If it is not valid, don't return it. */
    if (facet
        && ofproto->need_revalidate
        && !facet_revalidate(ofproto, facet)) {
        COVERAGE_INC(ofproto_invalidated);
        return NULL;
    }

    return facet;
}

/* Re-searches 'ofproto''s classifier for a rule matching 'facet':
 *
 *   - If the rule found is different from 'facet''s current rule, moves
 *     'facet' to the new rule and recompiles its actions.
 *
 *   - If the rule found is the same as 'facet''s current rule, leaves 'facet'
 *     where it is and recompiles its actions anyway.
 *
 *   - If there is none, destroys 'facet'.
 *
 * Returns true if 'facet' still exists, false if it has been destroyed. */
static bool
facet_revalidate(struct ofproto *ofproto, struct facet *facet)
{
    struct action_xlate_ctx ctx;
    struct ofpbuf *odp_actions;
    struct rule *new_rule;
    bool actions_changed;

    COVERAGE_INC(facet_revalidate);

    /* Determine the new rule. */
    new_rule = rule_lookup(ofproto, &facet->flow);
    if (!new_rule) {
        /* No new rule, so delete the facet. */
        facet_remove(ofproto, facet);
        return false;
    }

    /* Calculate new ODP actions.
     *
     * We do not modify any 'facet' state yet, because we might need to, e.g.,
     * emit a NetFlow expiration and, if so, we need to have the old state
     * around to properly compose it. */
    action_xlate_ctx_init(&ctx, ofproto, &facet->flow, NULL);
    odp_actions = xlate_actions(&ctx, new_rule->actions, new_rule->n_actions);
    actions_changed = (facet->actions_len != odp_actions->size
                       || memcmp(facet->actions, odp_actions->data,
                                 facet->actions_len));

    /* If the ODP actions changed or the installability changed, then we need
     * to talk to the datapath. */
    if (actions_changed || ctx.may_set_up_flow != facet->installed) {
        if (ctx.may_set_up_flow) {
            struct dpif_flow_stats stats;

            facet_put__(ofproto, facet,
                        odp_actions->data, odp_actions->size, &stats);
            facet_update_stats(ofproto, facet, &stats);
        } else {
            facet_uninstall(ofproto, facet);
        }

        /* The datapath flow is gone or has zeroed stats, so push stats out of
         * 'facet' into 'rule'. */
        facet_flush_stats(ofproto, facet);
    }

    /* Update 'facet' now that we've taken care of all the old state. */
    facet->tags = ctx.tags;
    facet->nf_flow.output_iface = ctx.nf_output_iface;
    facet->may_install = ctx.may_set_up_flow;
    if (actions_changed) {
        free(facet->actions);
        facet->actions_len = odp_actions->size;
        facet->actions = xmemdup(odp_actions->data, odp_actions->size);
    }
    if (facet->rule != new_rule) {
        COVERAGE_INC(facet_changed_rule);
        list_remove(&facet->list_node);
        list_push_back(&new_rule->facets, &facet->list_node);
        facet->rule = new_rule;
        facet->used = new_rule->created;
        facet->rs_used = facet->used;
    }

    ofpbuf_delete(odp_actions);

    return true;
}

/* Bridge packet processing functions. */

struct dst {
    struct ofport *port;
    uint16_t vlan;
};

struct dst_set {
    struct dst builtin[32];
    struct dst *dsts;
    size_t n, allocated;
};

static void dst_set_init(struct dst_set *);
static void dst_set_add(struct dst_set *, const struct dst *);
static void dst_set_free(struct dst_set *);

static struct ofport *ofbundle_get_a_port(const struct ofbundle *);

static bool
set_dst(struct action_xlate_ctx *ctx, struct dst *dst,
        const struct ofbundle *in_bundle, const struct ofbundle *out_bundle)
{
    dst->vlan = (out_bundle->vlan >= 0 ? OFP_VLAN_NONE
                 : in_bundle->vlan >= 0 ? in_bundle->vlan
                 : ctx->flow.vlan_tci == 0 ? OFP_VLAN_NONE
                 : vlan_tci_to_vid(ctx->flow.vlan_tci));

    dst->port = (!out_bundle->bond
                 ? ofbundle_get_a_port(out_bundle)
                 : bond_choose_output_slave(out_bundle->bond, &ctx->flow,
                                            dst->vlan, &ctx->tags));

    return dst->port != NULL;
}

static int
mirror_mask_ffs(mirror_mask_t mask)
{
    BUILD_ASSERT_DECL(sizeof(unsigned int) >= sizeof(mask));
    return ffs(mask);
}

static void
dst_set_init(struct dst_set *set)
{
    set->dsts = set->builtin;
    set->n = 0;
    set->allocated = ARRAY_SIZE(set->builtin);
}

static void
dst_set_add(struct dst_set *set, const struct dst *dst)
{
    if (set->n >= set->allocated) {
        size_t new_allocated;
        struct dst *new_dsts;

        new_allocated = set->allocated * 2;
        new_dsts = xmalloc(new_allocated * sizeof *new_dsts);
        memcpy(new_dsts, set->dsts, set->n * sizeof *new_dsts);

        dst_set_free(set);

        set->dsts = new_dsts;
        set->allocated = new_allocated;
    }
    set->dsts[set->n++] = *dst;
}

static void
dst_set_free(struct dst_set *set)
{
    if (set->dsts != set->builtin) {
        free(set->dsts);
    }
}

static bool
dst_is_duplicate(const struct dst_set *set, const struct dst *test)
{
    size_t i;
    for (i = 0; i < set->n; i++) {
        if (set->dsts[i].vlan == test->vlan
            && set->dsts[i].port == test->port) {
            return true;
        }
    }
    return false;
}

static bool
ofbundle_trunks_vlan(const struct ofbundle *bundle, uint16_t vlan)
{
    return bundle->vlan < 0 && vlan_bitmap_contains(bundle->trunks, vlan);
}

static bool
ofbundle_includes_vlan(const struct ofbundle *bundle, uint16_t vlan)
{
    return vlan == bundle->vlan || ofbundle_trunks_vlan(bundle, vlan);
}

/* Returns an arbitrary interface within 'bundle'. */
static struct ofport *
ofbundle_get_a_port(const struct ofbundle *bundle)
{
    return CONTAINER_OF(list_front(&bundle->ports),
                        struct ofport, bundle_node);
}

static void
compose_dsts(struct action_xlate_ctx *ctx, uint16_t vlan,
             const struct ofbundle *in_bundle,
             const struct ofbundle *out_bundle, struct dst_set *set)
{
    struct dst dst;

    if (out_bundle == OFBUNDLE_FLOOD) {
        struct ofbundle *bundle;

        HMAP_FOR_EACH (bundle, hmap_node, &ctx->ofproto->bundles) {
            if (bundle != in_bundle
                && ofbundle_includes_vlan(bundle, vlan)
                && bundle->floodable
                && !bundle->mirror_out
                && set_dst(ctx, &dst, in_bundle, bundle)) {
                dst_set_add(set, &dst);
            }
        }
        ctx->nf_output_iface = NF_OUT_FLOOD;
    } else if (out_bundle && set_dst(ctx, &dst, in_bundle, out_bundle)) {
        dst_set_add(set, &dst);
        ctx->nf_output_iface = dst.port->odp_port;
    }
}

static bool
vlan_is_mirrored(const struct ofmirror *m, int vlan)
{
    return vlan_bitmap_contains(m->vlans, vlan);
}

static void
compose_mirror_dsts(struct action_xlate_ctx *ctx,
                    uint16_t vlan, const struct ofbundle *in_bundle,
                    struct dst_set *set)
{
    struct ofproto *ofproto = ctx->ofproto;
    mirror_mask_t mirrors;
    int flow_vlan;
    size_t i;

    mirrors = in_bundle->src_mirrors;
    for (i = 0; i < set->n; i++) {
        mirrors |= set->dsts[i].port->bundle->dst_mirrors;
    }

    if (!mirrors) {
        return;
    }

    flow_vlan = vlan_tci_to_vid(ctx->flow.vlan_tci);
    if (flow_vlan == 0) {
        flow_vlan = OFP_VLAN_NONE;
    }

    while (mirrors) {
        struct ofmirror *m = ofproto->mirrors[mirror_mask_ffs(mirrors) - 1];
        if (vlan_is_mirrored(m, vlan)) {
            struct dst dst;

            if (m->out) {
                if (set_dst(ctx, &dst, in_bundle, m->out)
                    && !dst_is_duplicate(set, &dst)) {
                    dst_set_add(set, &dst);
                }
            } else {
                struct ofbundle *bundle;

                HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
                    if (ofbundle_includes_vlan(bundle, m->out_vlan)
                        && set_dst(ctx, &dst, in_bundle, bundle))
                    {
                        if (bundle->vlan < 0) {
                            dst.vlan = m->out_vlan;
                        }
                        if (dst_is_duplicate(set, &dst)) {
                            continue;
                        }

                        /* Use the vlan tag on the original flow instead of
                         * the one passed in the vlan parameter.  This ensures
                         * that we compare the vlan from before any implicit
                         * tagging tags place. This is necessary because
                         * dst->vlan is the final vlan, after removing implicit
                         * tags. */
                        if (bundle == in_bundle && dst.vlan == flow_vlan) {
                            /* Don't send out input port on same VLAN. */
                            continue;
                        }
                        dst_set_add(set, &dst);
                    }
                }
            }
        }
        mirrors &= mirrors - 1;
    }
}

static void
compose_actions(struct action_xlate_ctx *ctx, uint16_t vlan,
                const struct ofbundle *in_bundle,
                const struct ofbundle *out_bundle)
{
    uint16_t initial_vlan, cur_vlan;
    const struct dst *dst;
    struct dst_set set;

    dst_set_init(&set);
    compose_dsts(ctx, vlan, in_bundle, out_bundle, &set);
    compose_mirror_dsts(ctx, vlan, in_bundle, &set);

    /* Output all the packets we can without having to change the VLAN. */
    initial_vlan = vlan_tci_to_vid(ctx->flow.vlan_tci);
    if (initial_vlan == 0) {
        initial_vlan = OFP_VLAN_NONE;
    }
    for (dst = set.dsts; dst < &set.dsts[set.n]; dst++) {
        if (dst->vlan != initial_vlan) {
            continue;
        }
        nl_msg_put_u32(ctx->odp_actions,
                       ODP_ACTION_ATTR_OUTPUT, dst->port->odp_port);
    }

    /* Then output the rest. */
    cur_vlan = initial_vlan;
    for (dst = set.dsts; dst < &set.dsts[set.n]; dst++) {
        if (dst->vlan == initial_vlan) {
            continue;
        }
        if (dst->vlan != cur_vlan) {
            if (dst->vlan == OFP_VLAN_NONE) {
                nl_msg_put_flag(ctx->odp_actions, ODP_ACTION_ATTR_STRIP_VLAN);
            } else {
                ovs_be16 tci;
                tci = htons(dst->vlan & VLAN_VID_MASK);
                tci |= ctx->flow.vlan_tci & htons(VLAN_PCP_MASK);
                nl_msg_put_be16(ctx->odp_actions,
                                ODP_ACTION_ATTR_SET_DL_TCI, tci);
            }
            cur_vlan = dst->vlan;
        }
        nl_msg_put_u32(ctx->odp_actions,
                       ODP_ACTION_ATTR_OUTPUT, dst->port->odp_port);
    }

    dst_set_free(&set);
}

/* Returns the effective vlan of a packet, taking into account both the
 * 802.1Q header and implicitly tagged ports.  A value of 0 indicates that
 * the packet is untagged and -1 indicates it has an invalid header and
 * should be dropped. */
static int
flow_get_vlan(struct ofproto *ofproto, const struct flow *flow,
              struct ofbundle *in_bundle, bool have_packet)
{
    int vlan = vlan_tci_to_vid(flow->vlan_tci);
    if (in_bundle->vlan >= 0) {
        if (vlan) {
            if (have_packet) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "bridge %s: dropping VLAN %d tagged "
                             "packet received on port %s configured with "
                             "implicit VLAN %"PRIu16,
                             ofproto->name, vlan,
                             in_bundle->name, in_bundle->vlan);
            }
            return -1;
        }
        vlan = in_bundle->vlan;
    } else {
        if (!ofbundle_includes_vlan(in_bundle, vlan)) {
            if (have_packet) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "bridge %s: dropping VLAN %d tagged "
                             "packet received on port %s not configured for "
                             "trunking VLAN %d",
                             ofproto->name, vlan, in_bundle->name, vlan);
            }
            return -1;
        }
    }

    return vlan;
}

/* A VM broadcasts a gratuitous ARP to indicate that it has resumed after
 * migration.  Older Citrix-patched Linux DomU used gratuitous ARP replies to
 * indicate this; newer upstream kernels use gratuitous ARP requests. */
static bool
is_gratuitous_arp(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_ARP)
            && eth_addr_is_broadcast(flow->dl_dst)
            && (flow->nw_proto == ARP_OP_REPLY
                || (flow->nw_proto == ARP_OP_REQUEST
                    && flow->nw_src == flow->nw_dst)));
}

static void
update_learning_table(struct ofproto *ofproto,
                      const struct flow *flow, int vlan,
                      struct ofbundle *in_bundle)
{
    struct mac_entry *mac;

    if (!mac_learning_may_learn(ofproto->ml, flow->dl_src, vlan)) {
        return;
    }

    mac = mac_learning_insert(ofproto->ml, flow->dl_src, vlan);
    if (is_gratuitous_arp(flow)) {
        /* We don't want to learn from gratuitous ARP packets that are
         * reflected back over bond slaves so we lock the learning table. */
        if (!in_bundle->bond) {
            mac_entry_set_grat_arp_lock(mac);
        } else if (mac_entry_is_grat_arp_locked(mac)) {
            return;
        }
    }

    if (mac_entry_is_new(mac) || mac->port.p != in_bundle) {
        /* The log messages here could actually be useful in debugging,
         * so keep the rate limit relatively high. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
        VLOG_DBG_RL(&rl, "bridge %s: learned that "ETH_ADDR_FMT" is "
                    "on port %s in VLAN %d",
                    ofproto->name, ETH_ADDR_ARGS(flow->dl_src),
                    in_bundle->name, vlan);

        mac->port.p = in_bundle;
        tag_set_add(&ofproto->revalidate_set,
                    mac_learning_changed(ofproto->ml, mac));
    }
}

/* Determines whether packets in 'flow' within 'br' should be forwarded or
 * dropped.  Returns true if they may be forwarded, false if they should be
 * dropped.
 *
 * If 'have_packet' is true, it indicates that the caller is processing a
 * received packet.  If 'have_packet' is false, then the caller is just
 * revalidating an existing flow because configuration has changed.  Either
 * way, 'have_packet' only affects logging (there is no point in logging errors
 * during revalidation).
 *
 * Sets '*in_portp' to the input port.  This will be a null pointer if
 * flow->in_port does not designate a known input port (in which case
 * is_admissible() returns false).
 *
 * When returning true, sets '*vlanp' to the effective VLAN of the input
 * packet, as returned by flow_get_vlan().
 *
 * May also add tags to '*tags', although the current implementation only does
 * so in one special case.
 */
static bool
is_admissible(struct ofproto *ofproto, const struct flow *flow,
              bool have_packet,
              tag_type *tags, int *vlanp, struct ofbundle **in_bundlep)
{
    struct ofport *in_port;
    struct ofbundle *in_bundle;
    int vlan;

    /* Find the port and bundle for the received packet. */
    in_port = get_port(ofproto, flow->in_port);
    *in_bundlep = in_bundle = in_port->bundle;
    if (!in_port || !in_bundle) {
        /* No interface?  Something fishy... */
        if (have_packet) {
            /* Odd.  A few possible reasons here:
             *
             * - We deleted a port but there are still a few packets queued up
             *   from it.
             *
             * - Someone externally added a port (e.g. "ovs-dpctl add-if") that
             *   we don't know about.
             *
             * - Packet arrived on the local port but the local port is not
             *   part of a bundle.
             */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_WARN_RL(&rl, "bridge %s: received packet on unknown "
                         "port %"PRIu16,
                         ofproto->name, flow->in_port);
        }
        return false;
    }
    *vlanp = vlan = flow_get_vlan(ofproto, flow, in_bundle, have_packet);
    if (vlan < 0) {
        return false;
    }

    /* Drop frames for reserved multicast addresses. */
    if (eth_addr_is_reserved(flow->dl_dst)) {
        return false;
    }

    /* Drop frames on bundles reserved for mirroring. */
    if (in_bundle->mirror_out) {
        if (have_packet) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ofproto->name, in_bundle->name);
        }
        return false;
    }

    if (in_bundle->bond) {
        struct mac_entry *mac;

        switch (bond_check_admissibility(in_bundle->bond, in_port,
                                         flow->dl_dst, tags)) {
        case BV_ACCEPT:
            break;

        case BV_DROP:
            return false;

        case BV_DROP_IF_MOVED:
            mac = mac_learning_lookup(ofproto->ml, flow->dl_src, vlan, NULL);
            if (mac && mac->port.p != in_bundle &&
                (!is_gratuitous_arp(flow)
                 || mac_entry_is_grat_arp_locked(mac))) {
                return false;
            }
            break;
        }
    }

    return true;
}

/* If the composed actions may be applied to any packet in the given 'flow',
 * returns true.  Otherwise, the actions should only be applied to 'packet', or
 * not at all, if 'packet' was NULL. */
static bool
xlate_normal(struct action_xlate_ctx *ctx)
{
    struct ofbundle *in_bundle;
    struct ofbundle *out_bundle;
    struct mac_entry *mac;
    int vlan;

    /* Check whether we should drop packets in this flow. */
    if (!is_admissible(ctx->ofproto, &ctx->flow, ctx->packet != NULL,
                       &ctx->tags, &vlan, &in_bundle)) {
        out_bundle = NULL;
        goto done;
    }

    /* Learn source MAC (but don't try to learn from revalidation). */
    if (ctx->packet) {
        update_learning_table(ctx->ofproto, &ctx->flow, vlan, in_bundle);
    }

    /* Determine output bundle. */
    mac = mac_learning_lookup(ctx->ofproto->ml, ctx->flow.dl_dst, vlan,
                              &ctx->tags);
    if (mac) {
        out_bundle = mac->port.p;
    } else if (!ctx->packet && !eth_addr_is_multicast(ctx->flow.dl_dst)) {
        /* If we are revalidating but don't have a learning entry then eject
         * the flow.  Installing a flow that floods packets opens up a window
         * of time where we could learn from a packet reflected on a bond and
         * blackhole packets before the learning table is updated to reflect
         * the correct port. */
        return false;
    } else {
        out_bundle = OFBUNDLE_FLOOD;
    }

    /* Don't send packets out their input bundles. */
    if (in_bundle == out_bundle) {
        out_bundle = NULL;
    }

done:
    if (in_bundle) {
        compose_actions(ctx, vlan, in_bundle, out_bundle);
    }

    return true;
}

static void
send_error_oh(const struct ofconn *ofconn, const struct ofp_header *oh,
              int error)
{
    struct ofpbuf *buf = ofputil_encode_error_msg(error, oh);
    if (buf) {
        COVERAGE_INC(ofproto_error);
        ofconn_send_reply(ofconn, buf);
    }
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

    osf = make_openflow_xid(sizeof *osf, OFPT_FEATURES_REPLY, oh->xid, &buf);
    osf->datapath_id = htonll(ofproto->datapath_id);
    osf->n_buffers = htonl(pktbuf_capacity());
    osf->n_tables = 2;
    osf->capabilities = htonl(OFPC_FLOW_STATS | OFPC_TABLE_STATS |
                              OFPC_PORT_STATS | OFPC_ARP_MATCH_IP);
    osf->actions = htonl((1u << OFPAT_OUTPUT) |
                         (1u << OFPAT_SET_VLAN_VID) |
                         (1u << OFPAT_SET_VLAN_PCP) |
                         (1u << OFPAT_STRIP_VLAN) |
                         (1u << OFPAT_SET_DL_SRC) |
                         (1u << OFPAT_SET_DL_DST) |
                         (1u << OFPAT_SET_NW_SRC) |
                         (1u << OFPAT_SET_NW_DST) |
                         (1u << OFPAT_SET_NW_TOS) |
                         (1u << OFPAT_SET_TP_SRC) |
                         (1u << OFPAT_SET_TP_DST) |
                         (1u << OFPAT_ENQUEUE));

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
    dpif_get_drop_frags(ofproto->dpif, &drop_frags);
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
            dpif_set_drop_frags(ofproto->dpif, false);
            break;
        case OFPC_FRAG_DROP:
            dpif_set_drop_frags(ofproto->dpif, true);
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

static void do_xlate_actions(const union ofp_action *in, size_t n_in,
                             struct action_xlate_ctx *ctx);

static void
add_output_action(struct action_xlate_ctx *ctx, uint16_t port)
{
    const struct ofport *ofport = get_port(ctx->ofproto, port);

    if (ofport) {
        if (ofport->opp.config & htonl(OFPPC_NO_FWD)) {
            /* Forwarding disabled on port. */
            return;
        }
    } else {
        /*
         * We don't have an ofport record for this port, but it doesn't hurt to
         * allow forwarding to it anyhow.  Maybe such a port will appear later
         * and we're pre-populating the flow table.
         */
    }

    nl_msg_put_u32(ctx->odp_actions, ODP_ACTION_ATTR_OUTPUT, port);
    ctx->nf_output_iface = port;
}

static struct rule *
rule_lookup(struct ofproto *ofproto, const struct flow *flow)
{
    return rule_from_cls_rule(classifier_lookup(&ofproto->cls, flow));
}

static void
xlate_table_action(struct action_xlate_ctx *ctx, uint16_t in_port)
{
    if (ctx->recurse < MAX_RESUBMIT_RECURSION) {
        uint16_t old_in_port;
        struct rule *rule;

        /* Look up a flow with 'in_port' as the input port.  Then restore the
         * original input port (otherwise OFPP_NORMAL and OFPP_IN_PORT will
         * have surprising behavior). */
        old_in_port = ctx->flow.in_port;
        ctx->flow.in_port = in_port;
        rule = rule_lookup(ctx->ofproto, &ctx->flow);
        ctx->flow.in_port = old_in_port;

        if (ctx->resubmit_hook) {
            ctx->resubmit_hook(ctx, rule);
        }

        if (rule) {
            ctx->recurse++;
            do_xlate_actions(rule->actions, rule->n_actions, ctx);
            ctx->recurse--;
        }
    } else {
        static struct vlog_rate_limit recurse_rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&recurse_rl, "NXAST_RESUBMIT recursed over %d times",
                    MAX_RESUBMIT_RECURSION);
    }
}

static void
flood_packets(struct ofproto *ofproto, uint16_t odp_in_port, ovs_be32 mask,
              uint16_t *nf_output_iface, struct ofpbuf *odp_actions)
{
    struct ofport *ofport;

    HMAP_FOR_EACH (ofport, hmap_node, &ofproto->ports) {
        uint16_t odp_port = ofport->odp_port;
        if (odp_port != odp_in_port && !(ofport->opp.config & mask)) {
            nl_msg_put_u32(odp_actions, ODP_ACTION_ATTR_OUTPUT, odp_port);
        }
    }
    *nf_output_iface = NF_OUT_FLOOD;
}

static void
xlate_output_action__(struct action_xlate_ctx *ctx,
                      uint16_t port, uint16_t max_len)
{
    uint16_t odp_port;
    uint16_t prev_nf_output_iface = ctx->nf_output_iface;

    ctx->nf_output_iface = NF_OUT_DROP;

    switch (port) {
    case OFPP_IN_PORT:
        add_output_action(ctx, ctx->flow.in_port);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->flow.in_port);
        break;
    case OFPP_NORMAL:
        xlate_normal(ctx);
        break;
    case OFPP_FLOOD:
        flood_packets(ctx->ofproto, ctx->flow.in_port, htonl(OFPPC_NO_FLOOD),
                      &ctx->nf_output_iface, ctx->odp_actions);
        break;
    case OFPP_ALL:
        flood_packets(ctx->ofproto, ctx->flow.in_port, htonl(0),
                      &ctx->nf_output_iface, ctx->odp_actions);
        break;
    case OFPP_CONTROLLER:
        nl_msg_put_u64(ctx->odp_actions, ODP_ACTION_ATTR_CONTROLLER, max_len);
        break;
    case OFPP_LOCAL:
        add_output_action(ctx, ODPP_LOCAL);
        break;
    default:
        odp_port = ofp_port_to_odp_port(port);
        if (odp_port != ctx->flow.in_port) {
            add_output_action(ctx, odp_port);
        }
        break;
    }

    if (prev_nf_output_iface == NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_FLOOD;
    } else if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = prev_nf_output_iface;
    } else if (prev_nf_output_iface != NF_OUT_DROP &&
               ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
    }
}

static void
xlate_output_action(struct action_xlate_ctx *ctx,
                    const struct ofp_action_output *oao)
{
    xlate_output_action__(ctx, ntohs(oao->port), ntohs(oao->max_len));
}

/* If the final ODP action in 'ctx' is "pop priority", drop it, as an
 * optimization, because we're going to add another action that sets the
 * priority immediately after, or because there are no actions following the
 * pop.  */
static void
remove_pop_action(struct action_xlate_ctx *ctx)
{
    if (ctx->odp_actions->size == ctx->last_pop_priority) {
        ctx->odp_actions->size -= NLA_ALIGN(NLA_HDRLEN);
        ctx->last_pop_priority = -1;
    }
}

static void
add_pop_action(struct action_xlate_ctx *ctx)
{
    if (ctx->odp_actions->size != ctx->last_pop_priority) {
        nl_msg_put_flag(ctx->odp_actions, ODP_ACTION_ATTR_POP_PRIORITY);
        ctx->last_pop_priority = ctx->odp_actions->size;
    }
}

static void
xlate_enqueue_action(struct action_xlate_ctx *ctx,
                     const struct ofp_action_enqueue *oae)
{
    uint16_t ofp_port, odp_port;
    uint32_t priority;
    int error;

    error = dpif_queue_to_priority(ctx->ofproto->dpif, ntohl(oae->queue_id),
                                   &priority);
    if (error) {
        /* Fall back to ordinary output action. */
        xlate_output_action__(ctx, ntohs(oae->port), 0);
        return;
    }

    /* Figure out ODP output port. */
    ofp_port = ntohs(oae->port);
    if (ofp_port != OFPP_IN_PORT) {
        odp_port = ofp_port_to_odp_port(ofp_port);
    } else {
        odp_port = ctx->flow.in_port;
    }

    /* Add ODP actions. */
    remove_pop_action(ctx);
    nl_msg_put_u32(ctx->odp_actions, ODP_ACTION_ATTR_SET_PRIORITY, priority);
    add_output_action(ctx, odp_port);
    add_pop_action(ctx);

    /* Update NetFlow output port. */
    if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = odp_port;
    } else if (ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
    }
}

static void
xlate_set_queue_action(struct action_xlate_ctx *ctx,
                       const struct nx_action_set_queue *nasq)
{
    uint32_t priority;
    int error;

    error = dpif_queue_to_priority(ctx->ofproto->dpif, ntohl(nasq->queue_id),
                                   &priority);
    if (error) {
        /* Couldn't translate queue to a priority, so ignore.  A warning
         * has already been logged. */
        return;
    }

    remove_pop_action(ctx);
    nl_msg_put_u32(ctx->odp_actions, ODP_ACTION_ATTR_SET_PRIORITY, priority);
}

static void
xlate_set_dl_tci(struct action_xlate_ctx *ctx)
{
    ovs_be16 tci = ctx->flow.vlan_tci;
    if (!(tci & htons(VLAN_CFI))) {
        nl_msg_put_flag(ctx->odp_actions, ODP_ACTION_ATTR_STRIP_VLAN);
    } else {
        nl_msg_put_be16(ctx->odp_actions, ODP_ACTION_ATTR_SET_DL_TCI,
                        tci & ~htons(VLAN_CFI));
    }
}

struct xlate_reg_state {
    ovs_be16 vlan_tci;
    ovs_be64 tun_id;
};

static void
save_reg_state(const struct action_xlate_ctx *ctx,
               struct xlate_reg_state *state)
{
    state->vlan_tci = ctx->flow.vlan_tci;
    state->tun_id = ctx->flow.tun_id;
}

static void
update_reg_state(struct action_xlate_ctx *ctx,
                 const struct xlate_reg_state *state)
{
    if (ctx->flow.vlan_tci != state->vlan_tci) {
        xlate_set_dl_tci(ctx);
    }
    if (ctx->flow.tun_id != state->tun_id) {
        nl_msg_put_be64(ctx->odp_actions,
                        ODP_ACTION_ATTR_SET_TUNNEL, ctx->flow.tun_id);
    }
}

static void
xlate_autopath(struct action_xlate_ctx *ctx,
               const struct nx_action_autopath *naa)
{
    uint16_t ofp_port = ntohl(naa->id);
    struct ofport *port;

    port = get_port(ctx->ofproto, ofp_port_to_odp_port(ofp_port));
    if (!port || !port->bundle) {
        ofp_port = OFPP_NONE;
    } else if (port->bundle->bond) {
        /* Autopath does not support VLAN hashing. */
        struct ofport *slave = bond_choose_output_slave(
            port->bundle->bond, &ctx->flow, OFP_VLAN_NONE, &ctx->tags);
        if (slave) {
            ofp_port = odp_port_to_ofp_port(slave->odp_port);
        }
    }
    autopath_execute(naa, &ctx->flow, ofp_port);
}

static void
xlate_nicira_action(struct action_xlate_ctx *ctx,
                    const struct nx_action_header *nah)
{
    const struct nx_action_resubmit *nar;
    const struct nx_action_set_tunnel *nast;
    const struct nx_action_set_queue *nasq;
    const struct nx_action_multipath *nam;
    const struct nx_action_autopath *naa;
    enum nx_action_subtype subtype = ntohs(nah->subtype);
    struct xlate_reg_state state;
    ovs_be64 tun_id;

    assert(nah->vendor == htonl(NX_VENDOR_ID));
    switch (subtype) {
    case NXAST_RESUBMIT:
        nar = (const struct nx_action_resubmit *) nah;
        xlate_table_action(ctx, ofp_port_to_odp_port(ntohs(nar->in_port)));
        break;

    case NXAST_SET_TUNNEL:
        nast = (const struct nx_action_set_tunnel *) nah;
        tun_id = htonll(ntohl(nast->tun_id));
        nl_msg_put_be64(ctx->odp_actions, ODP_ACTION_ATTR_SET_TUNNEL, tun_id);
        ctx->flow.tun_id = tun_id;
        break;

    case NXAST_DROP_SPOOFED_ARP:
        if (ctx->flow.dl_type == htons(ETH_TYPE_ARP)) {
            nl_msg_put_flag(ctx->odp_actions,
                            ODP_ACTION_ATTR_DROP_SPOOFED_ARP);
        }
        break;

    case NXAST_SET_QUEUE:
        nasq = (const struct nx_action_set_queue *) nah;
        xlate_set_queue_action(ctx, nasq);
        break;

    case NXAST_POP_QUEUE:
        add_pop_action(ctx);
        break;

    case NXAST_REG_MOVE:
        save_reg_state(ctx, &state);
        nxm_execute_reg_move((const struct nx_action_reg_move *) nah,
                             &ctx->flow);
        update_reg_state(ctx, &state);
        break;

    case NXAST_REG_LOAD:
        save_reg_state(ctx, &state);
        nxm_execute_reg_load((const struct nx_action_reg_load *) nah,
                             &ctx->flow);
        update_reg_state(ctx, &state);
        break;

    case NXAST_NOTE:
        /* Nothing to do. */
        break;

    case NXAST_SET_TUNNEL64:
        tun_id = ((const struct nx_action_set_tunnel64 *) nah)->tun_id;
        nl_msg_put_be64(ctx->odp_actions, ODP_ACTION_ATTR_SET_TUNNEL, tun_id);
        ctx->flow.tun_id = tun_id;
        break;

    case NXAST_MULTIPATH:
        nam = (const struct nx_action_multipath *) nah;
        multipath_execute(nam, &ctx->flow);
        break;

    case NXAST_AUTOPATH:
        naa = (const struct nx_action_autopath *) nah;
        xlate_autopath(ctx, naa);
        break;

    /* If you add a new action here that modifies flow data, don't forget to
     * update the flow key in ctx->flow at the same time. */

    case NXAST_SNAT__OBSOLETE:
    default:
        VLOG_DBG_RL(&rl, "unknown Nicira action type %d", (int) subtype);
        break;
    }
}

static void
do_xlate_actions(const union ofp_action *in, size_t n_in,
                 struct action_xlate_ctx *ctx)
{
    struct actions_iterator iter;
    const union ofp_action *ia;
    const struct ofport *port;

    port = get_port(ctx->ofproto, ctx->flow.in_port);
    if (port && port->opp.config & htonl(OFPPC_NO_RECV | OFPPC_NO_RECV_STP) &&
        port->opp.config & (eth_addr_equals(ctx->flow.dl_dst, eth_addr_stp)
                            ? htonl(OFPPC_NO_RECV_STP)
                            : htonl(OFPPC_NO_RECV))) {
        /* Drop this flow. */
        return;
    }

    for (ia = actions_first(&iter, in, n_in); ia; ia = actions_next(&iter)) {
        enum ofp_action_type type = ntohs(ia->type);
        const struct ofp_action_dl_addr *oada;

        switch (type) {
        case OFPAT_OUTPUT:
            xlate_output_action(ctx, &ia->output);
            break;

        case OFPAT_SET_VLAN_VID:
            ctx->flow.vlan_tci &= ~htons(VLAN_VID_MASK);
            ctx->flow.vlan_tci |= ia->vlan_vid.vlan_vid | htons(VLAN_CFI);
            xlate_set_dl_tci(ctx);
            break;

        case OFPAT_SET_VLAN_PCP:
            ctx->flow.vlan_tci &= ~htons(VLAN_PCP_MASK);
            ctx->flow.vlan_tci |= htons(
                (ia->vlan_pcp.vlan_pcp << VLAN_PCP_SHIFT) | VLAN_CFI);
            xlate_set_dl_tci(ctx);
            break;

        case OFPAT_STRIP_VLAN:
            ctx->flow.vlan_tci = htons(0);
            xlate_set_dl_tci(ctx);
            break;

        case OFPAT_SET_DL_SRC:
            oada = ((struct ofp_action_dl_addr *) ia);
            nl_msg_put_unspec(ctx->odp_actions, ODP_ACTION_ATTR_SET_DL_SRC,
                              oada->dl_addr, ETH_ADDR_LEN);
            memcpy(ctx->flow.dl_src, oada->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_DL_DST:
            oada = ((struct ofp_action_dl_addr *) ia);
            nl_msg_put_unspec(ctx->odp_actions, ODP_ACTION_ATTR_SET_DL_DST,
                              oada->dl_addr, ETH_ADDR_LEN);
            memcpy(ctx->flow.dl_dst, oada->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_NW_SRC:
            nl_msg_put_be32(ctx->odp_actions, ODP_ACTION_ATTR_SET_NW_SRC,
                            ia->nw_addr.nw_addr);
            ctx->flow.nw_src = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_DST:
            nl_msg_put_be32(ctx->odp_actions, ODP_ACTION_ATTR_SET_NW_DST,
                            ia->nw_addr.nw_addr);
            ctx->flow.nw_dst = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_TOS:
            nl_msg_put_u8(ctx->odp_actions, ODP_ACTION_ATTR_SET_NW_TOS,
                          ia->nw_tos.nw_tos);
            ctx->flow.nw_tos = ia->nw_tos.nw_tos;
            break;

        case OFPAT_SET_TP_SRC:
            nl_msg_put_be16(ctx->odp_actions, ODP_ACTION_ATTR_SET_TP_SRC,
                            ia->tp_port.tp_port);
            ctx->flow.tp_src = ia->tp_port.tp_port;
            break;

        case OFPAT_SET_TP_DST:
            nl_msg_put_be16(ctx->odp_actions, ODP_ACTION_ATTR_SET_TP_DST,
                            ia->tp_port.tp_port);
            ctx->flow.tp_dst = ia->tp_port.tp_port;
            break;

        case OFPAT_VENDOR:
            xlate_nicira_action(ctx, (const struct nx_action_header *) ia);
            break;

        case OFPAT_ENQUEUE:
            xlate_enqueue_action(ctx, (const struct ofp_action_enqueue *) ia);
            break;

        default:
            VLOG_DBG_RL(&rl, "unknown action type %d", (int) type);
            break;
        }
    }
}

static void
action_xlate_ctx_init(struct action_xlate_ctx *ctx,
                      struct ofproto *ofproto, const struct flow *flow,
                      const struct ofpbuf *packet)
{
    ctx->ofproto = ofproto;
    ctx->flow = *flow;
    ctx->packet = packet;
    ctx->resubmit_hook = NULL;
    ctx->check_special = true;
}

static bool
ofproto_process_special(struct ofproto *ofproto, const struct flow *flow,
                        const struct ofpbuf *packet)
{
    if (cfm_should_process_flow(flow)) {
        struct ofport *ofport = get_port(ofproto, flow->in_port);
        if (ofport && ofport->cfm) {
            cfm_process_heartbeat(ofport->cfm, packet);
        }
        return true;
    } else if (flow->dl_type == htons(ETH_TYPE_LACP)) {
        struct ofport *port = get_port(ofproto, flow->in_port);
        if (port && port->bundle && port->bundle->lacp) {
            const struct lacp_pdu *pdu = parse_lacp_packet(packet);
            if (pdu) {
                lacp_process_pdu(port->bundle->lacp, port, pdu);
            }
            return true;
        }
    }
    return false;
}

static struct ofpbuf *
xlate_actions(struct action_xlate_ctx *ctx,
              const union ofp_action *in, size_t n_in)
{
    COVERAGE_INC(ofproto_ofp2odp);

    ctx->odp_actions = ofpbuf_new(512);
    ctx->tags = 0;
    ctx->may_set_up_flow = true;
    ctx->nf_output_iface = NF_OUT_DROP;
    ctx->recurse = 0;
    ctx->last_pop_priority = -1;

    if (ctx->check_special
        && ofproto_process_special(ctx->ofproto, &ctx->flow, ctx->packet)) {
        ctx->may_set_up_flow = false;
    } else {
        do_xlate_actions(in, n_in, ctx);
    }

    remove_pop_action(ctx);

    /* Check with in-band control to see if we're allowed to set up this
     * flow. */
    if (!connmgr_may_set_up_flow(ctx->ofproto->connmgr, &ctx->flow,
                                 ctx->odp_actions->data,
                                 ctx->odp_actions->size)) {
        ctx->may_set_up_flow = false;
    }

    return ctx->odp_actions;
}

/* Checks whether 'ofconn' is a slave controller.  If so, returns an OpenFlow
 * error message code (composed with ofp_mkerr()) for the caller to propagate
 * upward.  Otherwise, returns 0.
 *
 * The log message mentions 'msg_type'. */
static int
reject_slave_controller(struct ofconn *ofconn, const const char *msg_type)
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
    struct action_xlate_ctx ctx;
    struct ofpbuf *odp_actions;
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

    /* Extract flow, check actions. */
    flow_extract(&payload, 0, ofp_port_to_odp_port(ntohs(opo->in_port)),
                 &flow);
    error = validate_actions(ofp_actions, n_ofp_actions, &flow, p->max_ports);
    if (error) {
        goto exit;
    }

    /* Send. */
    action_xlate_ctx_init(&ctx, p, &flow, &payload);
    odp_actions = xlate_actions(&ctx, ofp_actions, n_ofp_actions);
    dpif_execute(p->dpif, odp_actions->data, odp_actions->size, &payload);
    ofpbuf_delete(odp_actions);

exit:
    ofpbuf_delete(buffer);
    return 0;
}

static void
update_port_config(struct ofproto *p, struct ofport *port,
                   ovs_be32 config, ovs_be32 mask)
{
    mask &= config ^ port->opp.config;
    if (mask & htonl(OFPPC_PORT_DOWN)) {
        if (config & htonl(OFPPC_PORT_DOWN)) {
            netdev_turn_flags_off(port->netdev, NETDEV_UP, true);
        } else {
            netdev_turn_flags_on(port->netdev, NETDEV_UP, true);
        }
    }
#define REVALIDATE_BITS (OFPPC_NO_RECV | OFPPC_NO_RECV_STP |    \
                         OFPPC_NO_FWD | OFPPC_NO_FLOOD)
    if (mask & htonl(REVALIDATE_BITS)) {
        COVERAGE_INC(ofproto_costly_flags);
        port->opp.config ^= mask & htonl(REVALIDATE_BITS);
        p->need_revalidate = true;
    }
#undef REVALIDATE_BITS
    if (mask & htonl(OFPPC_NO_PACKET_IN)) {
        port->opp.config ^= htonl(OFPPC_NO_PACKET_IN);
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

    port = get_port(p, ofp_port_to_odp_port(ntohs(opm->port_no)));
    if (!port) {
        return ofp_mkerr(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT);
    } else if (memcmp(port->opp.hw_addr, opm->hw_addr, OFP_ETH_ALEN)) {
        return ofp_mkerr(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR);
    } else {
        update_port_config(p, port, opm->config, opm->mask);
        if (opm->advertise) {
            netdev_set_advertisements(port->netdev, ntohl(opm->advertise));
        }
    }
    return 0;
}

static struct ofpbuf *
make_ofp_stats_reply(ovs_be32 xid, ovs_be16 type, size_t body_len)
{
    struct ofp_stats_reply *osr;
    struct ofpbuf *msg;

    msg = ofpbuf_new(MIN(sizeof *osr + body_len, UINT16_MAX));
    osr = put_openflow_xid(sizeof *osr, OFPT_STATS_REPLY, xid, msg);
    osr->type = type;
    osr->flags = htons(0);
    return msg;
}

static struct ofpbuf *
start_ofp_stats_reply(const struct ofp_header *request, size_t body_len)
{
    const struct ofp_stats_request *osr
        = (const struct ofp_stats_request *) request;
    return make_ofp_stats_reply(osr->header.xid, osr->type, body_len);
}

static void *
append_ofp_stats_reply(size_t nbytes, struct ofconn *ofconn,
                       struct ofpbuf **msgp)
{
    struct ofpbuf *msg = *msgp;
    assert(nbytes <= UINT16_MAX - sizeof(struct ofp_stats_reply));
    if (nbytes + msg->size > UINT16_MAX) {
        struct ofp_stats_reply *reply = msg->data;
        reply->flags = htons(OFPSF_REPLY_MORE);
        *msgp = make_ofp_stats_reply(reply->header.xid, reply->type, nbytes);
        ofconn_send_reply(ofconn, msg);
    }
    return ofpbuf_put_uninit(*msgp, nbytes);
}

static struct ofpbuf *
make_nxstats_reply(ovs_be32 xid, ovs_be32 subtype, size_t body_len)
{
    struct nicira_stats_msg *nsm;
    struct ofpbuf *msg;

    msg = ofpbuf_new(MIN(sizeof *nsm + body_len, UINT16_MAX));
    nsm = put_openflow_xid(sizeof *nsm, OFPT_STATS_REPLY, xid, msg);
    nsm->type = htons(OFPST_VENDOR);
    nsm->flags = htons(0);
    nsm->vendor = htonl(NX_VENDOR_ID);
    nsm->subtype = subtype;
    return msg;
}

static struct ofpbuf *
start_nxstats_reply(const struct nicira_stats_msg *request, size_t body_len)
{
    return make_nxstats_reply(request->header.xid, request->subtype, body_len);
}

static void
append_nxstats_reply(size_t nbytes, struct ofconn *ofconn,
                     struct ofpbuf **msgp)
{
    struct ofpbuf *msg = *msgp;
    assert(nbytes <= UINT16_MAX - sizeof(struct nicira_stats_msg));
    if (nbytes + msg->size > UINT16_MAX) {
        struct nicira_stats_msg *reply = msg->data;
        reply->flags = htons(OFPSF_REPLY_MORE);
        *msgp = make_nxstats_reply(reply->header.xid, reply->subtype, nbytes);
        ofconn_send_reply(ofconn, msg);
    }
    ofpbuf_prealloc_tailroom(*msgp, nbytes);
}

static int
handle_desc_stats_request(struct ofconn *ofconn,
                          const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_desc_stats *ods;
    struct ofpbuf *msg;

    msg = start_ofp_stats_reply(request, sizeof *ods);
    ods = append_ofp_stats_reply(sizeof *ods, ofconn, &msg);
    memset(ods, 0, sizeof *ods);
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
                           const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_table_stats *ots;
    struct ofpbuf *msg;

    msg = start_ofp_stats_reply(request, sizeof *ots * 2);

    /* Classifier table. */
    ots = append_ofp_stats_reply(sizeof *ots, ofconn, &msg);
    memset(ots, 0, sizeof *ots);
    strcpy(ots->name, "classifier");
    ots->wildcards = (ofconn_get_flow_format(ofconn) == NXFF_OPENFLOW10
                      ? htonl(OFPFW_ALL) : htonl(OVSFW_ALL));
    ots->max_entries = htonl(1024 * 1024); /* An arbitrary big number. */
    ots->active_count = htonl(classifier_count(&p->cls));
    put_32aligned_be64(&ots->lookup_count, htonll(0));  /* XXX */
    put_32aligned_be64(&ots->matched_count, htonll(0)); /* XXX */

    ofconn_send_reply(ofconn, msg);
    return 0;
}

static void
append_port_stat(struct ofport *port, struct ofconn *ofconn,
                 struct ofpbuf **msgp)
{
    struct netdev_stats stats;
    struct ofp_port_stats *ops;

    /* Intentionally ignore return value, since errors will set
     * 'stats' to all-1s, which is correct for OpenFlow, and
     * netdev_get_stats() will log errors. */
    netdev_get_stats(port->netdev, &stats);

    ops = append_ofp_stats_reply(sizeof *ops, ofconn, msgp);
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
handle_port_stats_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    const struct ofp_port_stats_request *psr = ofputil_stats_body(oh);
    struct ofp_port_stats *ops;
    struct ofpbuf *msg;
    struct ofport *port;

    msg = start_ofp_stats_reply(oh, sizeof *ops * 16);
    if (psr->port_no != htons(OFPP_NONE)) {
        port = get_port(p, ofp_port_to_odp_port(ntohs(psr->port_no)));
        if (port) {
            append_port_stat(port, ofconn, &msg);
        }
    } else {
        HMAP_FOR_EACH (port, hmap_node, &p->ports) {
            append_port_stat(port, ofconn, &msg);
        }
    }

    ofconn_send_reply(ofconn, msg);
    return 0;
}

static void
calc_flow_duration__(long long int start, uint32_t *sec, uint32_t *nsec)
{
    long long int msecs = time_msec() - start;
    *sec = msecs / 1000;
    *nsec = (msecs % 1000) * (1000 * 1000);
}

static void
calc_flow_duration(long long int start, ovs_be32 *sec_be, ovs_be32 *nsec_be)
{
    uint32_t sec, nsec;

    calc_flow_duration__(start, &sec, &nsec);
    *sec_be = htonl(sec);
    *nsec_be = htonl(nsec);
}

static void
put_ofp_flow_stats(struct ofconn *ofconn, struct rule *rule,
                   ovs_be16 out_port, struct ofpbuf **replyp)
{
    struct ofp_flow_stats *ofs;
    uint64_t packet_count, byte_count;
    ovs_be64 cookie;
    size_t act_len, len;

    if (rule_is_hidden(rule) || !rule_has_out_port(rule, out_port)) {
        return;
    }

    act_len = sizeof *rule->actions * rule->n_actions;
    len = offsetof(struct ofp_flow_stats, actions) + act_len;

    rule_get_stats(rule, &packet_count, &byte_count);

    ofs = append_ofp_stats_reply(len, ofconn, replyp);
    ofs->length = htons(len);
    ofs->table_id = 0;
    ofs->pad = 0;
    ofputil_cls_rule_to_match(&rule->cr, ofconn_get_flow_format(ofconn),
                              &ofs->match, rule->flow_cookie, &cookie);
    put_32aligned_be64(&ofs->cookie, cookie);
    calc_flow_duration(rule->created, &ofs->duration_sec, &ofs->duration_nsec);
    ofs->priority = htons(rule->cr.priority);
    ofs->idle_timeout = htons(rule->idle_timeout);
    ofs->hard_timeout = htons(rule->hard_timeout);
    memset(ofs->pad2, 0, sizeof ofs->pad2);
    put_32aligned_be64(&ofs->packet_count, htonll(packet_count));
    put_32aligned_be64(&ofs->byte_count, htonll(byte_count));
    if (rule->n_actions > 0) {
        memcpy(ofs->actions, rule->actions, act_len);
    }
}

static bool
is_valid_table(uint8_t table_id)
{
    if (table_id == 0 || table_id == 0xff) {
        return true;
    } else {
        /* It would probably be better to reply with an error but there doesn't
         * seem to be any appropriate value, so that might just be
         * confusing. */
        VLOG_WARN_RL(&rl, "controller asked for invalid table %"PRIu8,
                     table_id);
        return false;
    }
}

static int
handle_flow_stats_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct ofp_flow_stats_request *fsr = ofputil_stats_body(oh);
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofpbuf *reply;

    COVERAGE_INC(ofproto_flows_req);
    reply = start_ofp_stats_reply(oh, 1024);
    if (is_valid_table(fsr->table_id)) {
        struct cls_cursor cursor;
        struct cls_rule target;
        struct rule *rule;

        ofputil_cls_rule_from_match(&fsr->match, 0, NXFF_OPENFLOW10, 0,
                                    &target);
        cls_cursor_init(&cursor, &ofproto->cls, &target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            put_ofp_flow_stats(ofconn, rule, fsr->out_port, &reply);
        }
    }
    ofconn_send_reply(ofconn, reply);

    return 0;
}

static void
put_nx_flow_stats(struct ofconn *ofconn, struct rule *rule,
                  ovs_be16 out_port, struct ofpbuf **replyp)
{
    struct nx_flow_stats *nfs;
    uint64_t packet_count, byte_count;
    size_t act_len, start_len;
    struct ofpbuf *reply;

    if (rule_is_hidden(rule) || !rule_has_out_port(rule, out_port)) {
        return;
    }

    rule_get_stats(rule, &packet_count, &byte_count);

    act_len = sizeof *rule->actions * rule->n_actions;

    append_nxstats_reply(sizeof *nfs + NXM_MAX_LEN + act_len, ofconn, replyp);
    start_len = (*replyp)->size;
    reply = *replyp;

    nfs = ofpbuf_put_uninit(reply, sizeof *nfs);
    nfs->table_id = 0;
    nfs->pad = 0;
    calc_flow_duration(rule->created, &nfs->duration_sec, &nfs->duration_nsec);
    nfs->cookie = rule->flow_cookie;
    nfs->priority = htons(rule->cr.priority);
    nfs->idle_timeout = htons(rule->idle_timeout);
    nfs->hard_timeout = htons(rule->hard_timeout);
    nfs->match_len = htons(nx_put_match(reply, &rule->cr));
    memset(nfs->pad2, 0, sizeof nfs->pad2);
    nfs->packet_count = htonll(packet_count);
    nfs->byte_count = htonll(byte_count);
    if (rule->n_actions > 0) {
        ofpbuf_put(reply, rule->actions, act_len);
    }
    nfs->length = htons(reply->size - start_len);
}

static int
handle_nxst_flow(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct nx_flow_stats_request *nfsr;
    struct cls_rule target;
    struct ofpbuf *reply;
    struct ofpbuf b;
    int error;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    /* Dissect the message. */
    nfsr = ofpbuf_pull(&b, sizeof *nfsr);
    error = nx_pull_match(&b, ntohs(nfsr->match_len), 0, &target);
    if (error) {
        return error;
    }
    if (b.size) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    COVERAGE_INC(ofproto_flows_req);
    reply = start_nxstats_reply(&nfsr->nsm, 1024);
    if (is_valid_table(nfsr->table_id)) {
        struct cls_cursor cursor;
        struct rule *rule;

        cls_cursor_init(&cursor, &ofproto->cls, &target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            put_nx_flow_stats(ofconn, rule, nfsr->out_port, &reply);
        }
    }
    ofconn_send_reply(ofconn, reply);

    return 0;
}

static void
flow_stats_ds(struct rule *rule, struct ds *results)
{
    uint64_t packet_count, byte_count;
    size_t act_len = sizeof *rule->actions * rule->n_actions;

    rule_get_stats(rule, &packet_count, &byte_count);

    ds_put_format(results, "duration=%llds, ",
                  (time_msec() - rule->created) / 1000);
    ds_put_format(results, "idle=%.3fs, ", (time_msec() - rule->used) / 1000.0);
    ds_put_format(results, "priority=%u, ", rule->cr.priority);
    ds_put_format(results, "n_packets=%"PRIu64", ", packet_count);
    ds_put_format(results, "n_bytes=%"PRIu64", ", byte_count);
    cls_rule_format(&rule->cr, results);
    ds_put_char(results, ',');
    if (act_len > 0) {
        ofp_print_actions(results, &rule->actions->header, act_len);
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
    struct cls_cursor cursor;
    struct rule *rule;

    cls_cursor_init(&cursor, &p->cls, NULL);
    CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
        flow_stats_ds(rule, results);
    }
}

/* Obtains the NetFlow engine type and engine ID for 'ofproto' into
 * '*engine_type' and '*engine_id', respectively. */
void
ofproto_get_netflow_ids(const struct ofproto *ofproto,
                        uint8_t *engine_type, uint8_t *engine_id)
{
    dpif_get_netflow_ids(ofproto->dpif, engine_type, engine_id);
}

static void
query_aggregate_stats(struct ofproto *ofproto, struct cls_rule *target,
                      ovs_be16 out_port, uint8_t table_id,
                      struct ofp_aggregate_stats_reply *oasr)
{
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    int n_flows = 0;

    COVERAGE_INC(ofproto_agg_request);

    if (is_valid_table(table_id)) {
        struct cls_cursor cursor;
        struct rule *rule;

        cls_cursor_init(&cursor, &ofproto->cls, target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            if (!rule_is_hidden(rule) && rule_has_out_port(rule, out_port)) {
                uint64_t packet_count;
                uint64_t byte_count;

                rule_get_stats(rule, &packet_count, &byte_count);

                total_packets += packet_count;
                total_bytes += byte_count;
                n_flows++;
            }
        }
    }

    oasr->flow_count = htonl(n_flows);
    put_32aligned_be64(&oasr->packet_count, htonll(total_packets));
    put_32aligned_be64(&oasr->byte_count, htonll(total_bytes));
    memset(oasr->pad, 0, sizeof oasr->pad);
}

static int
handle_aggregate_stats_request(struct ofconn *ofconn,
                               const struct ofp_header *oh)
{
    const struct ofp_aggregate_stats_request *request = ofputil_stats_body(oh);
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofp_aggregate_stats_reply *reply;
    struct cls_rule target;
    struct ofpbuf *msg;

    ofputil_cls_rule_from_match(&request->match, 0, NXFF_OPENFLOW10, 0,
                                &target);

    msg = start_ofp_stats_reply(oh, sizeof *reply);
    reply = append_ofp_stats_reply(sizeof *reply, ofconn, &msg);
    query_aggregate_stats(ofproto, &target, request->out_port,
                          request->table_id, reply);
    ofconn_send_reply(ofconn, msg);
    return 0;
}

static int
handle_nxst_aggregate(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct nx_aggregate_stats_request *request;
    struct ofp_aggregate_stats_reply *reply;
    struct cls_rule target;
    struct ofpbuf b;
    struct ofpbuf *buf;
    int error;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    /* Dissect the message. */
    request = ofpbuf_pull(&b, sizeof *request);
    error = nx_pull_match(&b, ntohs(request->match_len), 0, &target);
    if (error) {
        return error;
    }
    if (b.size) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    /* Reply. */
    COVERAGE_INC(ofproto_flows_req);
    buf = start_nxstats_reply(&request->nsm, sizeof *reply);
    reply = ofpbuf_put_uninit(buf, sizeof *reply);
    query_aggregate_stats(ofproto, &target, request->out_port,
                          request->table_id, reply);
    ofconn_send_reply(ofconn, buf);

    return 0;
}

struct queue_stats_cbdata {
    struct ofconn *ofconn;
    struct ofport *ofport;
    struct ofpbuf *msg;
};

static void
put_queue_stats(struct queue_stats_cbdata *cbdata, uint32_t queue_id,
                const struct netdev_queue_stats *stats)
{
    struct ofp_queue_stats *reply;

    reply = append_ofp_stats_reply(sizeof *reply, cbdata->ofconn, &cbdata->msg);
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
handle_queue_stats_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    const struct ofp_queue_stats_request *qsr;
    struct queue_stats_cbdata cbdata;
    struct ofport *port;
    unsigned int port_no;
    uint32_t queue_id;

    qsr = ofputil_stats_body(oh);
    if (!qsr) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    COVERAGE_INC(ofproto_queue_req);

    cbdata.ofconn = ofconn;
    cbdata.msg = start_ofp_stats_reply(oh, 128);

    port_no = ntohs(qsr->port_no);
    queue_id = ntohl(qsr->queue_id);
    if (port_no == OFPP_ALL) {
        HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
            handle_queue_stats_for_port(port, queue_id, &cbdata);
        }
    } else if (port_no < ofproto->max_ports) {
        port = get_port(ofproto, ofp_port_to_odp_port(port_no));
        if (port) {
            handle_queue_stats_for_port(port, queue_id, &cbdata);
        }
    } else {
        ofpbuf_delete(cbdata.msg);
        return ofp_mkerr(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }
    ofconn_send_reply(ofconn, cbdata.msg);

    return 0;
}

/* Updates 'facet''s used time.  Caller is responsible for calling
 * facet_push_stats() to update the flows which 'facet' resubmits into. */
static void
facet_update_time(struct ofproto *ofproto, struct facet *facet,
                  long long int used)
{
    if (used > facet->used) {
        facet->used = used;
        if (used > facet->rule->used) {
            facet->rule->used = used;
        }
        netflow_flow_update_time(ofproto->netflow, &facet->nf_flow, used);
    }
}

/* Folds the statistics from 'stats' into the counters in 'facet'.
 *
 * Because of the meaning of a facet's counters, it only makes sense to do this
 * if 'stats' are not tracked in the datapath, that is, if 'stats' represents a
 * packet that was sent by hand or if it represents statistics that have been
 * cleared out of the datapath. */
static void
facet_update_stats(struct ofproto *ofproto, struct facet *facet,
                   const struct dpif_flow_stats *stats)
{
    if (stats->n_packets || stats->used > facet->used) {
        facet_update_time(ofproto, facet, stats->used);
        facet->packet_count += stats->n_packets;
        facet->byte_count += stats->n_bytes;
        facet_push_stats(ofproto, facet);
        netflow_flow_update_flags(&facet->nf_flow, stats->tcp_flags);
    }
}

static void
facet_push_stats(struct ofproto *ofproto, struct facet *facet)
{
    uint64_t rs_packets, rs_bytes;

    assert(facet->packet_count >= facet->rs_packet_count);
    assert(facet->byte_count >= facet->rs_byte_count);
    assert(facet->used >= facet->rs_used);

    rs_packets = facet->packet_count - facet->rs_packet_count;
    rs_bytes = facet->byte_count - facet->rs_byte_count;

    if (rs_packets || rs_bytes || facet->used > facet->rs_used) {
        facet->rs_packet_count = facet->packet_count;
        facet->rs_byte_count = facet->byte_count;
        facet->rs_used = facet->used;

        flow_push_stats(ofproto, facet->rule, &facet->flow,
                        rs_packets, rs_bytes, facet->used);
    }
}

struct ofproto_push {
    struct action_xlate_ctx ctx;
    uint64_t packets;
    uint64_t bytes;
    long long int used;
};

static void
push_resubmit(struct action_xlate_ctx *ctx, struct rule *rule)
{
    struct ofproto_push *push = CONTAINER_OF(ctx, struct ofproto_push, ctx);

    if (rule) {
        rule->packet_count += push->packets;
        rule->byte_count += push->bytes;
        rule->used = MAX(push->used, rule->used);
    }
}

/* Pushes flow statistics to the rules which 'flow' resubmits into given
 * 'rule''s actions. */
static void
flow_push_stats(struct ofproto *ofproto, const struct rule *rule,
                struct flow *flow, uint64_t packets, uint64_t bytes,
                long long int used)
{
    struct ofproto_push push;

    push.packets = packets;
    push.bytes = bytes;
    push.used = used;

    action_xlate_ctx_init(&push.ctx, ofproto, flow, NULL);
    push.ctx.resubmit_hook = push_resubmit;
    ofpbuf_delete(xlate_actions(&push.ctx, rule->actions, rule->n_actions));
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
add_flow(struct ofconn *ofconn, struct flow_mod *fm)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofpbuf *packet;
    struct rule *rule;
    uint16_t in_port;
    int error;

    if (fm->flags & OFPFF_CHECK_OVERLAP
        && classifier_rule_overlaps(&p->cls, &fm->cr)) {
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
    }

    error = 0;
    if (fm->buffer_id != UINT32_MAX) {
        error = ofconn_pktbuf_retrieve(ofconn, fm->buffer_id,
                                       &packet, &in_port);
    } else {
        packet = NULL;
        in_port = UINT16_MAX;
    }

    rule = rule_create(&fm->cr, fm->actions, fm->n_actions,
                       fm->idle_timeout, fm->hard_timeout, fm->cookie,
                       fm->flags & OFPFF_SEND_FLOW_REM);
    rule_insert(p, rule);
    if (packet) {
        rule_execute(p, rule, in_port, packet);
    }
    return error;
}

static struct rule *
find_flow_strict(struct ofproto *p, const struct flow_mod *fm)
{
    return rule_from_cls_rule(classifier_find_rule_exactly(&p->cls, &fm->cr));
}

static int
send_buffered_packet(struct ofconn *ofconn,
                     struct rule *rule, uint32_t buffer_id)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofpbuf *packet;
    uint16_t in_port;
    int error;

    if (buffer_id == UINT32_MAX) {
        return 0;
    }

    error = ofconn_pktbuf_retrieve(ofconn, buffer_id, &packet, &in_port);
    if (error) {
        return error;
    }

    rule_execute(ofproto, rule, in_port, packet);

    return 0;
}

/* OFPFC_MODIFY and OFPFC_MODIFY_STRICT. */

struct modify_flows_cbdata {
    struct ofproto *ofproto;
    const struct flow_mod *fm;
    struct rule *match;
};

static int modify_flow(struct ofproto *, const struct flow_mod *,
                       struct rule *);

/* Implements OFPFC_MODIFY.  Returns 0 on success or an OpenFlow error code as
 * encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
modify_flows_loose(struct ofconn *ofconn, struct flow_mod *fm)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct rule *match = NULL;
    struct cls_cursor cursor;
    struct rule *rule;

    cls_cursor_init(&cursor, &p->cls, &fm->cr);
    CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
        if (!rule_is_hidden(rule)) {
            match = rule;
            modify_flow(p, fm, rule);
        }
    }

    if (match) {
        /* This credits the packet to whichever flow happened to match last.
         * That's weird.  Maybe we should do a lookup for the flow that
         * actually matches the packet?  Who knows. */
        send_buffered_packet(ofconn, match, fm->buffer_id);
        return 0;
    } else {
        return add_flow(ofconn, fm);
    }
}

/* Implements OFPFC_MODIFY_STRICT.  Returns 0 on success or an OpenFlow error
 * code as encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
modify_flow_strict(struct ofconn *ofconn, struct flow_mod *fm)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct rule *rule = find_flow_strict(p, fm);
    if (rule && !rule_is_hidden(rule)) {
        modify_flow(p, fm, rule);
        return send_buffered_packet(ofconn, rule, fm->buffer_id);
    } else {
        return add_flow(ofconn, fm);
    }
}

/* Implements core of OFPFC_MODIFY and OFPFC_MODIFY_STRICT where 'rule' has
 * been identified as a flow in 'p''s flow table to be modified, by changing
 * the rule's actions to match those in 'ofm' (which is followed by 'n_actions'
 * ofp_action[] structures). */
static int
modify_flow(struct ofproto *p, const struct flow_mod *fm, struct rule *rule)
{
    size_t actions_len = fm->n_actions * sizeof *rule->actions;

    rule->flow_cookie = fm->cookie;

    /* If the actions are the same, do nothing. */
    if (fm->n_actions == rule->n_actions
        && (!fm->n_actions
            || !memcmp(fm->actions, rule->actions, actions_len))) {
        return 0;
    }

    /* Replace actions. */
    free(rule->actions);
    rule->actions = fm->n_actions ? xmemdup(fm->actions, actions_len) : NULL;
    rule->n_actions = fm->n_actions;

    p->need_revalidate = true;

    return 0;
}

/* OFPFC_DELETE implementation. */

static void delete_flow(struct ofproto *, struct rule *, ovs_be16 out_port);

/* Implements OFPFC_DELETE. */
static void
delete_flows_loose(struct ofproto *p, const struct flow_mod *fm)
{
    struct rule *rule, *next_rule;
    struct cls_cursor cursor;

    cls_cursor_init(&cursor, &p->cls, &fm->cr);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
        delete_flow(p, rule, htons(fm->out_port));
    }
}

/* Implements OFPFC_DELETE_STRICT. */
static void
delete_flow_strict(struct ofproto *p, struct flow_mod *fm)
{
    struct rule *rule = find_flow_strict(p, fm);
    if (rule) {
        delete_flow(p, rule, htons(fm->out_port));
    }
}

/* Implements core of OFPFC_DELETE and OFPFC_DELETE_STRICT where 'rule' has
 * been identified as a flow to delete from 'p''s flow table, by deleting the
 * flow and sending out a OFPT_FLOW_REMOVED message to any interested
 * controller.
 *
 * Will not delete 'rule' if it is hidden.  Will delete 'rule' only if
 * 'out_port' is htons(OFPP_NONE) or if 'rule' actually outputs to the
 * specified 'out_port'. */
static void
delete_flow(struct ofproto *p, struct rule *rule, ovs_be16 out_port)
{
    if (rule_is_hidden(rule)) {
        return;
    }

    if (out_port != htons(OFPP_NONE) && !rule_has_out_port(rule, out_port)) {
        return;
    }

    rule_send_removed(p, rule, OFPRR_DELETE);
    rule_remove(p, rule);
}

static int
handle_flow_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct flow_mod fm;
    int error;

    error = reject_slave_controller(ofconn, "flow_mod");
    if (error) {
        return error;
    }

    error = ofputil_decode_flow_mod(&fm, oh, ofconn_get_flow_format(ofconn));
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

    error = validate_actions(fm.actions, fm.n_actions,
                             &fm.cr.flow, p->max_ports);
    if (error) {
        return error;
    }

    switch (fm.command) {
    case OFPFC_ADD:
        return add_flow(ofconn, &fm);

    case OFPFC_MODIFY:
        return modify_flows_loose(ofconn, &fm);

    case OFPFC_MODIFY_STRICT:
        return modify_flow_strict(ofconn, &fm);

    case OFPFC_DELETE:
        delete_flows_loose(p, &fm);
        return 0;

    case OFPFC_DELETE_STRICT:
        delete_flow_strict(p, &fm);
        return 0;

    default:
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
    }
}

static int
handle_tun_id_from_cookie(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct nxt_tun_id_cookie *msg
        = (const struct nxt_tun_id_cookie *) oh;
    enum nx_flow_format flow_format;

    flow_format = msg->set ? NXFF_TUN_ID_FROM_COOKIE : NXFF_OPENFLOW10;
    ofconn_set_flow_format(ofconn, flow_format);

    return 0;
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

    ofconn_set_role(ofconn, role);

    reply = make_nxmsg_xid(sizeof *reply, NXT_ROLE_REPLY, oh->xid, &buf);
    reply->role = htonl(role);
    ofconn_send_reply(ofconn, buf);

    return 0;
}

static int
handle_nxt_set_flow_format(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct nxt_set_flow_format *msg
        = (const struct nxt_set_flow_format *) oh;
    uint32_t format;

    format = ntohl(msg->format);
    if (format == NXFF_OPENFLOW10
        || format == NXFF_TUN_ID_FROM_COOKIE
        || format == NXFF_NXM) {
        ofconn_set_flow_format(ofconn, format);
        return 0;
    } else {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    }
}

static int
handle_barrier_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofp_header *ob;
    struct ofpbuf *buf;

    /* Currently, everything executes synchronously, so we can just
     * immediately send the barrier reply. */
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
    case OFPUTIL_NXT_TUN_ID_FROM_COOKIE:
        return handle_tun_id_from_cookie(ofconn, oh);

    case OFPUTIL_NXT_ROLE_REQUEST:
        return handle_role_request(ofconn, oh);

    case OFPUTIL_NXT_SET_FLOW_FORMAT:
        return handle_nxt_set_flow_format(ofconn, oh);

    case OFPUTIL_NXT_FLOW_MOD:
        return handle_flow_mod(ofconn, oh);

        /* OpenFlow statistics requests. */
    case OFPUTIL_OFPST_DESC_REQUEST:
        return handle_desc_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_FLOW_REQUEST:
        return handle_flow_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_AGGREGATE_REQUEST:
        return handle_aggregate_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_TABLE_REQUEST:
        return handle_table_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_PORT_REQUEST:
        return handle_port_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_QUEUE_REQUEST:
        return handle_queue_stats_request(ofconn, oh);

        /* Nicira extension statistics requests. */
    case OFPUTIL_NXST_FLOW_REQUEST:
        return handle_nxst_flow(ofconn, oh);

    case OFPUTIL_NXST_AGGREGATE_REQUEST:
        return handle_nxst_aggregate(ofconn, oh);

    case OFPUTIL_INVALID:
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

static void
handle_openflow(struct ofconn *ofconn, struct ofpbuf *ofp_msg)
{
    int error = handle_openflow__(ofconn, ofp_msg);
    if (error) {
        send_error_oh(ofconn, ofp_msg->data, error);
    }
    COVERAGE_INC(ofproto_recv_openflow);
}

static void
handle_miss_upcall(struct ofproto *p, struct dpif_upcall *upcall)
{
    struct facet *facet;
    struct flow flow;

    /* Obtain in_port and tun_id, at least. */
    odp_flow_key_to_flow(upcall->key, upcall->key_len, &flow);

    /* Set header pointers in 'flow'. */
    flow_extract(upcall->packet, flow.tun_id, flow.in_port, &flow);

    /* Handle 802.1ag and LACP. */
    if (ofproto_process_special(p, &flow, upcall->packet)) {
        ofpbuf_delete(upcall->packet);
        return;
    }

    /* Check with in-band control to see if this packet should be sent
     * to the local port regardless of the flow table. */
    if (connmgr_msg_in_hook(p->connmgr, &flow, upcall->packet)) {
        ofproto_send_packet(p, ODPP_LOCAL, 0, upcall->packet);
    }

    facet = facet_lookup_valid(p, &flow);
    if (!facet) {
        struct rule *rule = rule_lookup(p, &flow);
        if (!rule) {
            /* Don't send a packet-in if OFPPC_NO_PACKET_IN asserted. */
            struct ofport *port = get_port(p, flow.in_port);
            if (port) {
                if (port->opp.config & htonl(OFPPC_NO_PACKET_IN)) {
                    COVERAGE_INC(ofproto_no_packet_in);
                    /* XXX install 'drop' flow entry */
                    ofpbuf_delete(upcall->packet);
                    return;
                }
            } else {
                VLOG_WARN_RL(&rl, "packet-in on unknown port %"PRIu16,
                             flow.in_port);
            }

            COVERAGE_INC(ofproto_packet_in);
            send_packet_in(p, upcall, &flow, false);
            return;
        }

        facet = facet_create(p, rule, &flow, upcall->packet);
    } else if (!facet->may_install) {
        /* The facet is not installable, that is, we need to process every
         * packet, so process the current packet's actions into 'facet'. */
        facet_make_actions(p, facet, upcall->packet);
    }

    if (facet->rule->cr.priority == FAIL_OPEN_PRIORITY) {
        /*
         * Extra-special case for fail-open mode.
         *
         * We are in fail-open mode and the packet matched the fail-open rule,
         * but we are connected to a controller too.  We should send the packet
         * up to the controller in the hope that it will try to set up a flow
         * and thereby allow us to exit fail-open.
         *
         * See the top-level comment in fail-open.c for more information.
         */
        send_packet_in(p, upcall, &flow, true);
    }

    facet_execute(p, facet, upcall->packet);
    facet_install(p, facet, false);
}

static void
handle_upcall(struct ofproto *p, struct dpif_upcall *upcall)
{
    struct flow flow;

    switch (upcall->type) {
    case DPIF_UC_ACTION:
        COVERAGE_INC(ofproto_ctlr_action);
        odp_flow_key_to_flow(upcall->key, upcall->key_len, &flow);
        send_packet_in(p, upcall, &flow, false);
        break;

    case DPIF_UC_SAMPLE:
        if (p->sflow) {
            odp_flow_key_to_flow(upcall->key, upcall->key_len, &flow);
            ofproto_sflow_received(p->sflow, upcall, &flow);
        }
        ofpbuf_delete(upcall->packet);
        break;

    case DPIF_UC_MISS:
        handle_miss_upcall(p, upcall);
        break;

    case DPIF_N_UC_TYPES:
    default:
        VLOG_WARN_RL(&rl, "upcall has unexpected type %"PRIu32, upcall->type);
        break;
    }
}

/* Flow expiration. */

static int ofproto_dp_max_idle(const struct ofproto *);
static void ofproto_update_stats(struct ofproto *);
static void rule_expire(struct ofproto *, struct rule *);
static void ofproto_expire_facets(struct ofproto *, int dp_max_idle);

/* This function is called periodically by ofproto_run().  Its job is to
 * collect updates for the flows that have been installed into the datapath,
 * most importantly when they last were used, and then use that information to
 * expire flows that have not been used recently.
 *
 * Returns the number of milliseconds after which it should be called again. */
static int
ofproto_expire(struct ofproto *ofproto)
{
    struct rule *rule, *next_rule;
    struct cls_cursor cursor;
    int dp_max_idle;

    /* Update stats for each flow in the datapath. */
    ofproto_update_stats(ofproto);

    /* Expire facets that have been idle too long. */
    dp_max_idle = ofproto_dp_max_idle(ofproto);
    ofproto_expire_facets(ofproto, dp_max_idle);

    /* Expire OpenFlow flows whose idle_timeout or hard_timeout has passed. */
    cls_cursor_init(&cursor, &ofproto->cls, NULL);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
        rule_expire(ofproto, rule);
    }

    /* All outstanding data in existing flows has been accounted, so it's a
     * good time to do bond rebalancing. */
    if (ofproto->has_bonded_bundles) {
        struct ofbundle *bundle;

        HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
            if (bundle->bond) {
                bond_rebalance(bundle->bond, &ofproto->revalidate_set);
            }
        }
    }

    return MIN(dp_max_idle, 1000);
}

/* Update 'packet_count', 'byte_count', and 'used' members of installed facets.
 *
 * This function also pushes statistics updates to rules which each facet
 * resubmits into.  Generally these statistics will be accurate.  However, if a
 * facet changes the rule it resubmits into at some time in between
 * ofproto_update_stats() runs, it is possible that statistics accrued to the
 * old rule will be incorrectly attributed to the new rule.  This could be
 * avoided by calling ofproto_update_stats() whenever rules are created or
 * deleted.  However, the performance impact of making so many calls to the
 * datapath do not justify the benefit of having perfectly accurate statistics.
 */
static void
ofproto_update_stats(struct ofproto *p)
{
    const struct dpif_flow_stats *stats;
    struct dpif_flow_dump dump;
    const struct nlattr *key;
    size_t key_len;

    dpif_flow_dump_start(&dump, p->dpif);
    while (dpif_flow_dump_next(&dump, &key, &key_len, NULL, NULL, &stats)) {
        struct facet *facet;
        struct flow flow;

        if (odp_flow_key_to_flow(key, key_len, &flow)) {
            struct ds s;

            ds_init(&s);
            odp_flow_key_format(key, key_len, &s);
            VLOG_WARN_RL(&rl, "failed to convert ODP flow key to flow: %s",
                         ds_cstr(&s));
            ds_destroy(&s);

            continue;
        }
        facet = facet_find(p, &flow);

        if (facet && facet->installed) {

            if (stats->n_packets >= facet->dp_packet_count) {
                facet->packet_count += stats->n_packets - facet->dp_packet_count;
            } else {
                VLOG_WARN_RL(&rl, "unexpected packet count from the datapath");
            }

            if (stats->n_bytes >= facet->dp_byte_count) {
                facet->byte_count += stats->n_bytes - facet->dp_byte_count;
            } else {
                VLOG_WARN_RL(&rl, "unexpected byte count from datapath");
            }

            facet->dp_packet_count = stats->n_packets;
            facet->dp_byte_count = stats->n_bytes;

            facet_update_time(p, facet, stats->used);
            facet_account(p, facet, stats->n_bytes);
            facet_push_stats(p, facet);
        } else {
            /* There's a flow in the datapath that we know nothing about.
             * Delete it. */
            COVERAGE_INC(ofproto_unexpected_rule);
            dpif_flow_del(p->dpif, key, key_len, NULL);
        }
    }
    dpif_flow_dump_done(&dump);
}

/* Calculates and returns the number of milliseconds of idle time after which
 * facets should expire from the datapath and we should fold their statistics
 * into their parent rules in userspace. */
static int
ofproto_dp_max_idle(const struct ofproto *ofproto)
{
    /*
     * Idle time histogram.
     *
     * Most of the time a switch has a relatively small number of facets.  When
     * this is the case we might as well keep statistics for all of them in
     * userspace and to cache them in the kernel datapath for performance as
     * well.
     *
     * As the number of facets increases, the memory required to maintain
     * statistics about them in userspace and in the kernel becomes
     * significant.  However, with a large number of facets it is likely that
     * only a few of them are "heavy hitters" that consume a large amount of
     * bandwidth.  At this point, only heavy hitters are worth caching in the
     * kernel and maintaining in userspaces; other facets we can discard.
     *
     * The technique used to compute the idle time is to build a histogram with
     * N_BUCKETS buckets whose width is BUCKET_WIDTH msecs each.  Each facet
     * that is installed in the kernel gets dropped in the appropriate bucket.
     * After the histogram has been built, we compute the cutoff so that only
     * the most-recently-used 1% of facets (but at least 1000 flows) are kept
     * cached.  At least the most-recently-used bucket of facets is kept, so
     * actually an arbitrary number of facets can be kept in any given
     * expiration run (though the next run will delete most of those unless
     * they receive additional data).
     *
     * This requires a second pass through the facets, in addition to the pass
     * made by ofproto_update_stats(), because the former function never looks
     * at uninstallable facets.
     */
    enum { BUCKET_WIDTH = ROUND_UP(100, TIME_UPDATE_INTERVAL) };
    enum { N_BUCKETS = 5000 / BUCKET_WIDTH };
    int buckets[N_BUCKETS] = { 0 };
    struct facet *facet;
    int total, bucket;
    long long int now;
    int i;

    total = hmap_count(&ofproto->facets);
    if (total <= 1000) {
        return N_BUCKETS * BUCKET_WIDTH;
    }

    /* Build histogram. */
    now = time_msec();
    HMAP_FOR_EACH (facet, hmap_node, &ofproto->facets) {
        long long int idle = now - facet->used;
        int bucket = (idle <= 0 ? 0
                      : idle >= BUCKET_WIDTH * N_BUCKETS ? N_BUCKETS - 1
                      : (unsigned int) idle / BUCKET_WIDTH);
        buckets[bucket]++;
    }

    /* Find the first bucket whose flows should be expired. */
    for (bucket = 0; bucket < N_BUCKETS; bucket++) {
        if (buckets[bucket]) {
            int subtotal = 0;
            do {
                subtotal += buckets[bucket++];
            } while (bucket < N_BUCKETS && subtotal < MAX(1000, total / 100));
            break;
        }
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds s;

        ds_init(&s);
        ds_put_cstr(&s, "keep");
        for (i = 0; i < N_BUCKETS; i++) {
            if (i == bucket) {
                ds_put_cstr(&s, ", drop");
            }
            if (buckets[i]) {
                ds_put_format(&s, " %d:%d", i * BUCKET_WIDTH, buckets[i]);
            }
        }
        VLOG_INFO("%s: %s (msec:count)", ofproto->name, ds_cstr(&s));
        ds_destroy(&s);
    }

    return bucket * BUCKET_WIDTH;
}

static void
facet_active_timeout(struct ofproto *ofproto, struct facet *facet)
{
    if (ofproto->netflow && !facet_is_controller_flow(facet) &&
        netflow_active_timeout_expired(ofproto->netflow, &facet->nf_flow)) {
        struct ofexpired expired;

        if (facet->installed) {
            struct dpif_flow_stats stats;

            facet_put__(ofproto, facet, facet->actions, facet->actions_len,
                        &stats);
            facet_update_stats(ofproto, facet, &stats);
        }

        expired.flow = facet->flow;
        expired.packet_count = facet->packet_count;
        expired.byte_count = facet->byte_count;
        expired.used = facet->used;
        netflow_expire(ofproto->netflow, &facet->nf_flow, &expired);
    }
}

static void
ofproto_expire_facets(struct ofproto *ofproto, int dp_max_idle)
{
    long long int cutoff = time_msec() - dp_max_idle;
    struct facet *facet, *next_facet;

    HMAP_FOR_EACH_SAFE (facet, next_facet, hmap_node, &ofproto->facets) {
        facet_active_timeout(ofproto, facet);
        if (facet->used < cutoff) {
            facet_remove(ofproto, facet);
        }
    }
}

/* If 'rule' is an OpenFlow rule, that has expired according to OpenFlow rules,
 * then delete it entirely. */
static void
rule_expire(struct ofproto *ofproto, struct rule *rule)
{
    struct facet *facet, *next_facet;
    long long int now;
    uint8_t reason;

    /* Has 'rule' expired? */
    now = time_msec();
    if (rule->hard_timeout
        && now > rule->created + rule->hard_timeout * 1000) {
        reason = OFPRR_HARD_TIMEOUT;
    } else if (rule->idle_timeout && list_is_empty(&rule->facets)
               && now >rule->used + rule->idle_timeout * 1000) {
        reason = OFPRR_IDLE_TIMEOUT;
    } else {
        return;
    }

    COVERAGE_INC(ofproto_expired);

    /* Update stats.  (This is a no-op if the rule expired due to an idle
     * timeout, because that only happens when the rule has no facets left.) */
    LIST_FOR_EACH_SAFE (facet, next_facet, list_node, &rule->facets) {
        facet_remove(ofproto, facet);
    }

    /* Get rid of the rule. */
    if (!rule_is_hidden(rule)) {
        rule_send_removed(ofproto, rule, reason);
    }
    rule_remove(ofproto, rule);
}

static void
rule_send_removed(struct ofproto *p, struct rule *rule, uint8_t reason)
{
    struct ofputil_flow_removed fr;

    if (!rule->send_flow_removed) {
        return;
    }

    fr.rule = rule->cr;
    fr.cookie = rule->flow_cookie;
    fr.reason = reason;
    calc_flow_duration__(rule->created, &fr.duration_sec, &fr.duration_nsec);
    fr.idle_timeout = rule->idle_timeout;
    fr.packet_count = rule->packet_count;
    fr.byte_count = rule->byte_count;

    connmgr_send_flow_removed(p->connmgr, &fr);
}

/* Obtains statistics for 'rule' and stores them in '*packets' and '*bytes'.
 * The returned statistics include statistics for all of 'rule''s facets. */
static void
rule_get_stats(const struct rule *rule, uint64_t *packets, uint64_t *bytes)
{
    uint64_t p, b;
    struct facet *facet;

    /* Start from historical data for 'rule' itself that are no longer tracked
     * in facets.  This counts, for example, facets that have expired. */
    p = rule->packet_count;
    b = rule->byte_count;

    /* Add any statistics that are tracked by facets.  This includes
     * statistical data recently updated by ofproto_update_stats() as well as
     * stats for packets that were executed "by hand" via dpif_execute(). */
    LIST_FOR_EACH (facet, list_node, &rule->facets) {
        p += facet->packet_count;
        b += facet->byte_count;
    }

    *packets = p;
    *bytes = b;
}

/* Given 'upcall', of type DPIF_UC_ACTION or DPIF_UC_MISS, sends an
 * OFPT_PACKET_IN message to each OpenFlow controller as necessary according to
 * their individual configurations.
 *
 * If 'clone' is true, the caller retains ownership of 'upcall->packet'.
 * Otherwise, ownership is transferred to this function. */
static void
send_packet_in(struct ofproto *ofproto, struct dpif_upcall *upcall,
               const struct flow *flow, bool clone)
{
    struct ofputil_packet_in pin;

    pin.packet = upcall->packet;
    pin.in_port = odp_port_to_ofp_port(flow->in_port);
    pin.reason = upcall->type == DPIF_UC_MISS ? OFPR_NO_MATCH : OFPR_ACTION;
    pin.buffer_id = 0;          /* not yet known */
    pin.send_len = upcall->userdata;
    connmgr_send_packet_in(ofproto->connmgr, upcall, flow,
                           clone ? NULL : upcall->packet);
}

static uint64_t
pick_datapath_id(const struct ofproto *ofproto)
{
    const struct ofport *port;

    port = get_port(ofproto, ODPP_LOCAL);
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

static struct ofproto *
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

struct ofproto_trace {
    struct action_xlate_ctx ctx;
    struct flow flow;
    struct ds *result;
};

static void
trace_format_rule(struct ds *result, int level, const struct rule *rule)
{
    ds_put_char_multiple(result, '\t', level);
    if (!rule) {
        ds_put_cstr(result, "No match\n");
        return;
    }

    ds_put_format(result, "Rule: cookie=%#"PRIx64" ",
                  ntohll(rule->flow_cookie));
    cls_rule_format(&rule->cr, result);
    ds_put_char(result, '\n');

    ds_put_char_multiple(result, '\t', level);
    ds_put_cstr(result, "OpenFlow ");
    ofp_print_actions(result, (const struct ofp_action_header *) rule->actions,
                      rule->n_actions * sizeof *rule->actions);
    ds_put_char(result, '\n');
}

static void
trace_format_flow(struct ds *result, int level, const char *title,
                 struct ofproto_trace *trace)
{
    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    if (flow_equal(&trace->ctx.flow, &trace->flow)) {
        ds_put_cstr(result, "unchanged");
    } else {
        flow_format(result, &trace->ctx.flow);
        trace->flow = trace->ctx.flow;
    }
    ds_put_char(result, '\n');
}

static void
trace_resubmit(struct action_xlate_ctx *ctx, struct rule *rule)
{
    struct ofproto_trace *trace = CONTAINER_OF(ctx, struct ofproto_trace, ctx);
    struct ds *result = trace->result;

    ds_put_char(result, '\n');
    trace_format_flow(result, ctx->recurse + 1, "Resubmitted flow", trace);
    trace_format_rule(result, ctx->recurse + 1, rule);
}

static void
ofproto_unixctl_trace(struct unixctl_conn *conn, const char *args_,
                      void *aux OVS_UNUSED)
{
    char *dpname, *in_port_s, *tun_id_s, *packet_s;
    char *args = xstrdup(args_);
    char *save_ptr = NULL;
    struct ofproto *ofproto;
    struct ofpbuf packet;
    struct rule *rule;
    struct ds result;
    struct flow flow;
    uint16_t in_port;
    ovs_be64 tun_id;
    char *s;

    ofpbuf_init(&packet, strlen(args) / 2);
    ds_init(&result);

    dpname = strtok_r(args, " ", &save_ptr);
    tun_id_s = strtok_r(NULL, " ", &save_ptr);
    in_port_s = strtok_r(NULL, " ", &save_ptr);
    packet_s = strtok_r(NULL, "", &save_ptr); /* Get entire rest of line. */
    if (!dpname || !in_port_s || !packet_s) {
        unixctl_command_reply(conn, 501, "Bad command syntax");
        goto exit;
    }

    ofproto = ofproto_lookup(dpname);
    if (!ofproto) {
        unixctl_command_reply(conn, 501, "Unknown ofproto (use ofproto/list "
                              "for help)");
        goto exit;
    }

    tun_id = htonll(strtoull(tun_id_s, NULL, 0));
    in_port = ofp_port_to_odp_port(atoi(in_port_s));

    packet_s = ofpbuf_put_hex(&packet, packet_s, NULL);
    packet_s += strspn(packet_s, " ");
    if (*packet_s != '\0') {
        unixctl_command_reply(conn, 501, "Trailing garbage in command");
        goto exit;
    }
    if (packet.size < ETH_HEADER_LEN) {
        unixctl_command_reply(conn, 501, "Packet data too short for Ethernet");
        goto exit;
    }

    ds_put_cstr(&result, "Packet: ");
    s = ofp_packet_to_string(packet.data, packet.size, packet.size);
    ds_put_cstr(&result, s);
    free(s);

    flow_extract(&packet, tun_id, in_port, &flow);
    ds_put_cstr(&result, "Flow: ");
    flow_format(&result, &flow);
    ds_put_char(&result, '\n');

    rule = rule_lookup(ofproto, &flow);
    trace_format_rule(&result, 0, rule);
    if (rule) {
        struct ofproto_trace trace;
        struct ofpbuf *odp_actions;

        trace.result = &result;
        trace.flow = flow;
        action_xlate_ctx_init(&trace.ctx, ofproto, &flow, &packet);
        trace.ctx.resubmit_hook = trace_resubmit;
        odp_actions = xlate_actions(&trace.ctx,
                                    rule->actions, rule->n_actions);

        ds_put_char(&result, '\n');
        trace_format_flow(&result, 0, "Final flow", &trace);
        ds_put_cstr(&result, "Datapath actions: ");
        format_odp_actions(&result, odp_actions->data, odp_actions->size);
        ofpbuf_delete(odp_actions);
    }

    unixctl_command_reply(conn, 200, ds_cstr(&result));

exit:
    ds_destroy(&result);
    ofpbuf_uninit(&packet);
    free(args);
}

static void
ofproto_unixctl_fdb_show(struct unixctl_conn *conn,
                         const char *args, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct ofproto *ofproto;
    const struct mac_entry *e;

    ofproto = ofproto_lookup(args);
    if (!ofproto) {
        unixctl_command_reply(conn, 501, "no such bridge");
        return;
    }

    ds_put_cstr(&ds, " port  VLAN  MAC                Age\n");
    LIST_FOR_EACH (e, lru_node, &ofproto->ml->lrus) {
        struct ofbundle *bundle = e->port.p;
        ds_put_format(&ds, "%5d  %4d  "ETH_ADDR_FMT"  %3d\n",
                      ofbundle_get_a_port(bundle)->odp_port,
                      e->vlan, ETH_ADDR_ARGS(e->mac), mac_entry_age(e));
    }
    unixctl_command_reply(conn, 200, ds_cstr(&ds));
    ds_destroy(&ds);
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
    unixctl_command_register("ofproto/trace", ofproto_unixctl_trace, NULL);
    unixctl_command_register("fdb/show", ofproto_unixctl_fdb_show, NULL);
}
