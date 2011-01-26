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
#include "byte-order.h"
#include "classifier.h"
#include "coverage.h"
#include "discovery.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "fail-open.h"
#include "hash.h"
#include "hmap.h"
#include "in-band.h"
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
#include "rconn.h"
#include "shash.h"
#include "status.h"
#include "stream-ssl.h"
#include "svec.h"
#include "tag.h"
#include "timeval.h"
#include "unixctl.h"
#include "vconn.h"
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
COVERAGE_DEFINE(ofproto_ofconn_stuck);
COVERAGE_DEFINE(ofproto_ofp2odp);
COVERAGE_DEFINE(ofproto_packet_in);
COVERAGE_DEFINE(ofproto_packet_out);
COVERAGE_DEFINE(ofproto_queue_req);
COVERAGE_DEFINE(ofproto_recv_openflow);
COVERAGE_DEFINE(ofproto_reinit_ports);
COVERAGE_DEFINE(ofproto_unexpected_rule);
COVERAGE_DEFINE(ofproto_uninstallable);
COVERAGE_DEFINE(ofproto_update_port);

#include "sflow_api.h"

struct rule;

struct ofport {
    struct hmap_node hmap_node; /* In struct ofproto's "ports" hmap. */
    struct netdev *netdev;
    struct ofp_phy_port opp;    /* In host byte order. */
    uint16_t odp_port;
};

static void ofport_free(struct ofport *);
static void hton_ofp_phy_port(struct ofp_phy_port *);

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
    void (*resubmit_hook)(struct action_xlate_ctx *, const struct rule *);

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
                                 * recently added ODPAT_SET_PRIORITY. */
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
     *     statistics were reset (e.g. dpif_flow_put() with ODPPF_ZERO_STATS).
     *
     *   - Do not include any packets or bytes that can currently be obtained
     *     from the datapath by, e.g., dpif_flow_get().
     */
    uint64_t packet_count;       /* Number of packets received. */
    uint64_t byte_count;         /* Number of bytes received. */

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
    tag_type tags;               /* Tags (set only by hooks). */
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
                               const struct odp_flow_stats *);

/* ofproto supports two kinds of OpenFlow connections:
 *
 *   - "Primary" connections to ordinary OpenFlow controllers.  ofproto
 *     maintains persistent connections to these controllers and by default
 *     sends them asynchronous messages such as packet-ins.
 *
 *   - "Service" connections, e.g. from ovs-ofctl.  When these connections
 *     drop, it is the other side's responsibility to reconnect them if
 *     necessary.  ofproto does not send them asynchronous messages by default.
 *
 * Currently, active (tcp, ssl, unix) connections are always "primary"
 * connections and passive (ptcp, pssl, punix) connections are always "service"
 * connections.  There is no inherent reason for this, but it reflects the
 * common case.
 */
enum ofconn_type {
    OFCONN_PRIMARY,             /* An ordinary OpenFlow controller. */
    OFCONN_SERVICE              /* A service connection, e.g. "ovs-ofctl". */
};

/* A listener for incoming OpenFlow "service" connections. */
struct ofservice {
    struct hmap_node node;      /* In struct ofproto's "services" hmap. */
    struct pvconn *pvconn;      /* OpenFlow connection listener. */

    /* These are not used by ofservice directly.  They are settings for
     * accepted "struct ofconn"s from the pvconn. */
    int probe_interval;         /* Max idle time before probing, in seconds. */
    int rate_limit;             /* Max packet-in rate in packets per second. */
    int burst_limit;            /* Limit on accumulating packet credits. */
};

static struct ofservice *ofservice_lookup(struct ofproto *,
                                          const char *target);
static int ofservice_create(struct ofproto *,
                            const struct ofproto_controller *);
static void ofservice_reconfigure(struct ofservice *,
                                  const struct ofproto_controller *);
static void ofservice_destroy(struct ofproto *, struct ofservice *);

/* An OpenFlow connection. */
struct ofconn {
    struct ofproto *ofproto;    /* The ofproto that owns this connection. */
    struct list node;           /* In struct ofproto's "all_conns" list. */
    struct rconn *rconn;        /* OpenFlow connection. */
    enum ofconn_type type;      /* Type. */
    enum nx_flow_format flow_format; /* Currently selected flow format. */

    /* OFPT_PACKET_IN related data. */
    struct rconn_packet_counter *packet_in_counter; /* # queued on 'rconn'. */
    struct pinsched *schedulers[2]; /* Indexed by reason code; see below. */
    struct pktbuf *pktbuf;         /* OpenFlow packet buffers. */
    int miss_send_len;             /* Bytes to send of buffered packets. */

    /* Number of OpenFlow messages queued on 'rconn' as replies to OpenFlow
     * requests, and the maximum number before we stop reading OpenFlow
     * requests.  */
#define OFCONN_REPLY_MAX 100
    struct rconn_packet_counter *reply_counter;

    /* type == OFCONN_PRIMARY only. */
    enum nx_role role;           /* Role. */
    struct hmap_node hmap_node;  /* In struct ofproto's "controllers" map. */
    struct discovery *discovery; /* Controller discovery object, if enabled. */
    struct status_category *ss;  /* Switch status category. */
    enum ofproto_band band;      /* In-band or out-of-band? */
};

/* We use OFPR_NO_MATCH and OFPR_ACTION as indexes into struct ofconn's
 * "schedulers" array.  Their values are 0 and 1, and their meanings and values
 * coincide with _ODPL_MISS_NR and _ODPL_ACTION_NR, so this is convenient.  In
 * case anything ever changes, check their values here.  */
#define N_SCHEDULERS 2
BUILD_ASSERT_DECL(OFPR_NO_MATCH == 0);
BUILD_ASSERT_DECL(OFPR_NO_MATCH == _ODPL_MISS_NR);
BUILD_ASSERT_DECL(OFPR_ACTION == 1);
BUILD_ASSERT_DECL(OFPR_ACTION == _ODPL_ACTION_NR);

static struct ofconn *ofconn_create(struct ofproto *, struct rconn *,
                                    enum ofconn_type);
static void ofconn_destroy(struct ofconn *);
static void ofconn_run(struct ofconn *);
static void ofconn_wait(struct ofconn *);
static bool ofconn_receives_async_msgs(const struct ofconn *);
static char *ofconn_make_name(const struct ofproto *, const char *target);
static void ofconn_set_rate_limit(struct ofconn *, int rate, int burst);

static void queue_tx(struct ofpbuf *msg, const struct ofconn *ofconn,
                     struct rconn_packet_counter *counter);

static void send_packet_in(struct ofproto *, struct dpif_upcall *,
                           const struct flow *, bool clone);
static void do_send_packet_in(struct ofpbuf *ofp_packet_in, void *ofconn);

struct ofproto {
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

    /* Configuration. */
    struct switch_status *switch_status;
    struct fail_open *fail_open;
    struct netflow *netflow;
    struct ofproto_sflow *sflow;

    /* In-band control. */
    struct in_band *in_band;
    long long int next_in_band_update;
    struct sockaddr_in *extra_in_band_remotes;
    size_t n_extra_remotes;
    int in_band_queue;

    /* Flow table. */
    struct classifier cls;
    long long int next_expiration;

    /* Facets. */
    struct hmap facets;
    bool need_revalidate;
    struct tag_set revalidate_set;

    /* OpenFlow connections. */
    struct hmap controllers;   /* Controller "struct ofconn"s. */
    struct list all_conns;     /* Contains "struct ofconn"s. */
    enum ofproto_fail_mode fail_mode;

    /* OpenFlow listeners. */
    struct hmap services;       /* Contains "struct ofservice"s. */
    struct pvconn **snoops;
    size_t n_snoops;

    /* Hooks for ovs-vswitchd. */
    const struct ofhooks *ofhooks;
    void *aux;

    /* Used by default ofhooks. */
    struct mac_learning *ml;
};

/* Map from dpif name to struct ofproto, for use by unixctl commands. */
static struct shash all_ofprotos = SHASH_INITIALIZER(&all_ofprotos);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static const struct ofhooks default_ofhooks;

static uint64_t pick_datapath_id(const struct ofproto *);
static uint64_t pick_fallback_dpid(void);

static int ofproto_expire(struct ofproto *);

static void handle_upcall(struct ofproto *, struct dpif_upcall *);

static void handle_openflow(struct ofconn *, struct ofpbuf *);

static struct ofport *get_port(const struct ofproto *, uint16_t odp_port);
static void update_port(struct ofproto *, const char *devname);
static int init_ports(struct ofproto *);
static void reinit_ports(struct ofproto *);

static void ofproto_unixctl_init(void);

int
ofproto_create(const char *datapath, const char *datapath_type,
               const struct ofhooks *ofhooks, void *aux,
               struct ofproto **ofprotop)
{
    struct ofproto *p;
    struct dpif *dpif;
    int error;

    *ofprotop = NULL;

    ofproto_unixctl_init();

    /* Connect to datapath and start listening for messages. */
    error = dpif_open(datapath, datapath_type, &dpif);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s", datapath, strerror(error));
        return error;
    }
    error = dpif_recv_set_mask(dpif, ODPL_MISS | ODPL_ACTION | ODPL_SFLOW);
    if (error) {
        VLOG_ERR("failed to listen on datapath %s: %s",
                 datapath, strerror(error));
        dpif_close(dpif);
        return error;
    }
    dpif_flow_flush(dpif);
    dpif_recv_purge(dpif);

    /* Initialize settings. */
    p = xzalloc(sizeof *p);
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

    /* Initialize submodules. */
    p->switch_status = switch_status_create(p);
    p->fail_open = NULL;
    p->netflow = NULL;
    p->sflow = NULL;

    /* Initialize in-band control. */
    p->in_band = NULL;
    p->in_band_queue = -1;

    /* Initialize flow table. */
    classifier_init(&p->cls);
    p->next_expiration = time_msec() + 1000;

    /* Initialize facet table. */
    hmap_init(&p->facets);
    p->need_revalidate = false;
    tag_set_init(&p->revalidate_set);

    /* Initialize OpenFlow connections. */
    list_init(&p->all_conns);
    hmap_init(&p->controllers);
    hmap_init(&p->services);
    p->snoops = NULL;
    p->n_snoops = 0;

    /* Initialize hooks. */
    if (ofhooks) {
        p->ofhooks = ofhooks;
        p->aux = aux;
        p->ml = NULL;
    } else {
        p->ofhooks = &default_ofhooks;
        p->aux = p;
        p->ml = mac_learning_create();
    }

    /* Pick final datapath ID. */
    p->datapath_id = pick_datapath_id(p);
    VLOG_INFO("using datapath ID %016"PRIx64, p->datapath_id);

    shash_add_once(&all_ofprotos, dpif_name(p->dpif), p);

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

static bool
is_discovery_controller(const struct ofproto_controller *c)
{
    return !strcmp(c->target, "discover");
}

static bool
is_in_band_controller(const struct ofproto_controller *c)
{
    return is_discovery_controller(c) || c->band == OFPROTO_IN_BAND;
}

/* Creates a new controller in 'ofproto'.  Some of the settings are initially
 * drawn from 'c', but update_controller() needs to be called later to finish
 * the new ofconn's configuration. */
static void
add_controller(struct ofproto *ofproto, const struct ofproto_controller *c)
{
    struct discovery *discovery;
    struct ofconn *ofconn;

    if (is_discovery_controller(c)) {
        int error = discovery_create(c->accept_re, c->update_resolv_conf,
                                     ofproto->dpif, ofproto->switch_status,
                                     &discovery);
        if (error) {
            return;
        }
    } else {
        discovery = NULL;
    }

    ofconn = ofconn_create(ofproto, rconn_create(5, 8), OFCONN_PRIMARY);
    ofconn->pktbuf = pktbuf_create();
    ofconn->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;
    if (discovery) {
        ofconn->discovery = discovery;
    } else {
        char *name = ofconn_make_name(ofproto, c->target);
        rconn_connect(ofconn->rconn, c->target, name);
        free(name);
    }
    hmap_insert(&ofproto->controllers, &ofconn->hmap_node,
                hash_string(c->target, 0));
}

/* Reconfigures 'ofconn' to match 'c'.  This function cannot update an ofconn's
 * target or turn discovery on or off (these are done by creating new ofconns
 * and deleting old ones), but it can update the rest of an ofconn's
 * settings. */
static void
update_controller(struct ofconn *ofconn, const struct ofproto_controller *c)
{
    int probe_interval;

    ofconn->band = (is_in_band_controller(c)
                    ? OFPROTO_IN_BAND : OFPROTO_OUT_OF_BAND);

    rconn_set_max_backoff(ofconn->rconn, c->max_backoff);

    probe_interval = c->probe_interval ? MAX(c->probe_interval, 5) : 0;
    rconn_set_probe_interval(ofconn->rconn, probe_interval);

    if (ofconn->discovery) {
        discovery_set_update_resolv_conf(ofconn->discovery,
                                         c->update_resolv_conf);
        discovery_set_accept_controller_re(ofconn->discovery, c->accept_re);
    }

    ofconn_set_rate_limit(ofconn, c->rate_limit, c->burst_limit);
}

static const char *
ofconn_get_target(const struct ofconn *ofconn)
{
    return ofconn->discovery ? "discover" : rconn_get_target(ofconn->rconn);
}

static struct ofconn *
find_controller_by_target(struct ofproto *ofproto, const char *target)
{
    struct ofconn *ofconn;

    HMAP_FOR_EACH_WITH_HASH (ofconn, hmap_node,
                             hash_string(target, 0), &ofproto->controllers) {
        if (!strcmp(ofconn_get_target(ofconn), target)) {
            return ofconn;
        }
    }
    return NULL;
}

static void
update_in_band_remotes(struct ofproto *ofproto)
{
    const struct ofconn *ofconn;
    struct sockaddr_in *addrs;
    size_t max_addrs, n_addrs;
    bool discovery;
    size_t i;

    /* Allocate enough memory for as many remotes as we could possibly have. */
    max_addrs = ofproto->n_extra_remotes + hmap_count(&ofproto->controllers);
    addrs = xmalloc(max_addrs * sizeof *addrs);
    n_addrs = 0;

    /* Add all the remotes. */
    discovery = false;
    HMAP_FOR_EACH (ofconn, hmap_node, &ofproto->controllers) {
        struct sockaddr_in *sin = &addrs[n_addrs];

        if (ofconn->band == OFPROTO_OUT_OF_BAND) {
            continue;
        }

        sin->sin_addr.s_addr = rconn_get_remote_ip(ofconn->rconn);
        if (sin->sin_addr.s_addr) {
            sin->sin_port = rconn_get_remote_port(ofconn->rconn);
            n_addrs++;
        }
        if (ofconn->discovery) {
            discovery = true;
        }
    }
    for (i = 0; i < ofproto->n_extra_remotes; i++) {
        addrs[n_addrs++] = ofproto->extra_in_band_remotes[i];
    }

    /* Create or update or destroy in-band.
     *
     * Ordinarily we only enable in-band if there's at least one remote
     * address, but discovery needs the in-band rules for DHCP to be installed
     * even before we know any remote addresses. */
    if (n_addrs || discovery) {
        if (!ofproto->in_band) {
            in_band_create(ofproto, ofproto->dpif, ofproto->switch_status,
                           &ofproto->in_band);
        }
        if (ofproto->in_band) {
            in_band_set_remotes(ofproto->in_band, addrs, n_addrs);
        }
        in_band_set_queue(ofproto->in_band, ofproto->in_band_queue);
        ofproto->next_in_band_update = time_msec() + 1000;
    } else {
        in_band_destroy(ofproto->in_band);
        ofproto->in_band = NULL;
    }

    /* Clean up. */
    free(addrs);
}

static void
update_fail_open(struct ofproto *p)
{
    struct ofconn *ofconn;

    if (!hmap_is_empty(&p->controllers)
            && p->fail_mode == OFPROTO_FAIL_STANDALONE) {
        struct rconn **rconns;
        size_t n;

        if (!p->fail_open) {
            p->fail_open = fail_open_create(p, p->switch_status);
        }

        n = 0;
        rconns = xmalloc(hmap_count(&p->controllers) * sizeof *rconns);
        HMAP_FOR_EACH (ofconn, hmap_node, &p->controllers) {
            rconns[n++] = ofconn->rconn;
        }

        fail_open_set_controllers(p->fail_open, rconns, n);
        /* p->fail_open takes ownership of 'rconns'. */
    } else {
        fail_open_destroy(p->fail_open);
        p->fail_open = NULL;
    }
}

void
ofproto_set_controllers(struct ofproto *p,
                        const struct ofproto_controller *controllers,
                        size_t n_controllers)
{
    struct shash new_controllers;
    struct ofconn *ofconn, *next_ofconn;
    struct ofservice *ofservice, *next_ofservice;
    bool ss_exists;
    size_t i;

    /* Create newly configured controllers and services.
     * Create a name to ofproto_controller mapping in 'new_controllers'. */
    shash_init(&new_controllers);
    for (i = 0; i < n_controllers; i++) {
        const struct ofproto_controller *c = &controllers[i];

        if (!vconn_verify_name(c->target) || !strcmp(c->target, "discover")) {
            if (!find_controller_by_target(p, c->target)) {
                add_controller(p, c);
            }
        } else if (!pvconn_verify_name(c->target)) {
            if (!ofservice_lookup(p, c->target) && ofservice_create(p, c)) {
                continue;
            }
        } else {
            VLOG_WARN_RL(&rl, "%s: unsupported controller \"%s\"",
                         dpif_name(p->dpif), c->target);
            continue;
        }

        shash_add_once(&new_controllers, c->target, &controllers[i]);
    }

    /* Delete controllers that are no longer configured.
     * Update configuration of all now-existing controllers. */
    ss_exists = false;
    HMAP_FOR_EACH_SAFE (ofconn, next_ofconn, hmap_node, &p->controllers) {
        struct ofproto_controller *c;

        c = shash_find_data(&new_controllers, ofconn_get_target(ofconn));
        if (!c) {
            ofconn_destroy(ofconn);
        } else {
            update_controller(ofconn, c);
            if (ofconn->ss) {
                ss_exists = true;
            }
        }
    }

    /* Delete services that are no longer configured.
     * Update configuration of all now-existing services. */
    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, node, &p->services) {
        struct ofproto_controller *c;

        c = shash_find_data(&new_controllers,
                            pvconn_get_name(ofservice->pvconn));
        if (!c) {
            ofservice_destroy(p, ofservice);
        } else {
            ofservice_reconfigure(ofservice, c);
        }
    }

    shash_destroy(&new_controllers);

    update_in_band_remotes(p);
    update_fail_open(p);

    if (!hmap_is_empty(&p->controllers) && !ss_exists) {
        ofconn = CONTAINER_OF(hmap_first(&p->controllers),
                              struct ofconn, hmap_node);
        ofconn->ss = switch_status_register(p->switch_status, "remote",
                                            rconn_status_cb, ofconn->rconn);
    }
}

void
ofproto_set_fail_mode(struct ofproto *p, enum ofproto_fail_mode fail_mode)
{
    p->fail_mode = fail_mode;
    update_fail_open(p);
}

/* Drops the connections between 'ofproto' and all of its controllers, forcing
 * them to reconnect. */
void
ofproto_reconnect_controllers(struct ofproto *ofproto)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, node, &ofproto->all_conns) {
        rconn_reconnect(ofconn->rconn);
    }
}

static bool
any_extras_changed(const struct ofproto *ofproto,
                   const struct sockaddr_in *extras, size_t n)
{
    size_t i;

    if (n != ofproto->n_extra_remotes) {
        return true;
    }

    for (i = 0; i < n; i++) {
        const struct sockaddr_in *old = &ofproto->extra_in_band_remotes[i];
        const struct sockaddr_in *new = &extras[i];

        if (old->sin_addr.s_addr != new->sin_addr.s_addr ||
            old->sin_port != new->sin_port) {
            return true;
        }
    }

    return false;
}

/* Sets the 'n' TCP port addresses in 'extras' as ones to which 'ofproto''s
 * in-band control should guarantee access, in the same way that in-band
 * control guarantees access to OpenFlow controllers. */
void
ofproto_set_extra_in_band_remotes(struct ofproto *ofproto,
                                  const struct sockaddr_in *extras, size_t n)
{
    if (!any_extras_changed(ofproto, extras, n)) {
        return;
    }

    free(ofproto->extra_in_band_remotes);
    ofproto->n_extra_remotes = n;
    ofproto->extra_in_band_remotes = xmemdup(extras, n * sizeof *extras);

    update_in_band_remotes(ofproto);
}

/* Sets the OpenFlow queue used by flows set up by in-band control on
 * 'ofproto' to 'queue_id'.  If 'queue_id' is negative, then in-band control
 * flows will use the default queue. */
void
ofproto_set_in_band_queue(struct ofproto *ofproto, int queue_id)
{
    if (queue_id != ofproto->in_band_queue) {
        ofproto->in_band_queue = queue_id;
        update_in_band_remotes(ofproto);
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

static int
set_pvconns(struct pvconn ***pvconnsp, size_t *n_pvconnsp,
            const struct svec *svec)
{
    struct pvconn **pvconns = *pvconnsp;
    size_t n_pvconns = *n_pvconnsp;
    int retval = 0;
    size_t i;

    for (i = 0; i < n_pvconns; i++) {
        pvconn_close(pvconns[i]);
    }
    free(pvconns);

    pvconns = xmalloc(svec->n * sizeof *pvconns);
    n_pvconns = 0;
    for (i = 0; i < svec->n; i++) {
        const char *name = svec->names[i];
        struct pvconn *pvconn;
        int error;

        error = pvconn_open(name, &pvconn);
        if (!error) {
            pvconns[n_pvconns++] = pvconn;
        } else {
            VLOG_ERR("failed to listen on %s: %s", name, strerror(error));
            if (!retval) {
                retval = error;
            }
        }
    }

    *pvconnsp = pvconns;
    *n_pvconnsp = n_pvconns;

    return retval;
}

int
ofproto_set_snoops(struct ofproto *ofproto, const struct svec *snoops)
{
    return set_pvconns(&ofproto->snoops, &ofproto->n_snoops, snoops);
}

int
ofproto_set_netflow(struct ofproto *ofproto,
                    const struct netflow_options *nf_options)
{
    if (nf_options && nf_options->collectors.n) {
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

uint64_t
ofproto_get_datapath_id(const struct ofproto *ofproto)
{
    return ofproto->datapath_id;
}

bool
ofproto_has_primary_controller(const struct ofproto *ofproto)
{
    return !hmap_is_empty(&ofproto->controllers);
}

enum ofproto_fail_mode
ofproto_get_fail_mode(const struct ofproto *p)
{
    return p->fail_mode;
}

void
ofproto_get_snoops(const struct ofproto *ofproto, struct svec *snoops)
{
    size_t i;

    for (i = 0; i < ofproto->n_snoops; i++) {
        svec_add(snoops, pvconn_get_name(ofproto->snoops[i]));
    }
}

void
ofproto_destroy(struct ofproto *p)
{
    struct ofservice *ofservice, *next_ofservice;
    struct ofconn *ofconn, *next_ofconn;
    struct ofport *ofport, *next_ofport;
    size_t i;

    if (!p) {
        return;
    }

    shash_find_and_delete(&all_ofprotos, dpif_name(p->dpif));

    /* Destroy fail-open and in-band early, since they touch the classifier. */
    fail_open_destroy(p->fail_open);
    p->fail_open = NULL;

    in_band_destroy(p->in_band);
    p->in_band = NULL;
    free(p->extra_in_band_remotes);

    ofproto_flush_flows(p);
    classifier_destroy(&p->cls);
    hmap_destroy(&p->facets);

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, node, &p->all_conns) {
        ofconn_destroy(ofconn);
    }
    hmap_destroy(&p->controllers);

    dpif_close(p->dpif);
    netdev_monitor_destroy(p->netdev_monitor);
    HMAP_FOR_EACH_SAFE (ofport, next_ofport, hmap_node, &p->ports) {
        hmap_remove(&p->ports, &ofport->hmap_node);
        ofport_free(ofport);
    }
    shash_destroy(&p->port_by_name);

    switch_status_destroy(p->switch_status);
    netflow_destroy(p->netflow);
    ofproto_sflow_destroy(p->sflow);

    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, node, &p->services) {
        ofservice_destroy(p, ofservice);
    }
    hmap_destroy(&p->services);

    for (i = 0; i < p->n_snoops; i++) {
        pvconn_close(p->snoops[i]);
    }
    free(p->snoops);

    mac_learning_destroy(p->ml);

    free(p->mfr_desc);
    free(p->hw_desc);
    free(p->sw_desc);
    free(p->serial_desc);
    free(p->dp_desc);

    hmap_destroy(&p->ports);

    free(p);
}

int
ofproto_run(struct ofproto *p)
{
    int error = ofproto_run1(p);
    if (!error) {
        error = ofproto_run2(p, false);
    }
    return error;
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

/* Returns a "preference level" for snooping 'ofconn'.  A higher return value
 * means that 'ofconn' is more interesting for monitoring than a lower return
 * value. */
static int
snoop_preference(const struct ofconn *ofconn)
{
    switch (ofconn->role) {
    case NX_ROLE_MASTER:
        return 3;
    case NX_ROLE_OTHER:
        return 2;
    case NX_ROLE_SLAVE:
        return 1;
    default:
        /* Shouldn't happen. */
        return 0;
    }
}

/* One of ofproto's "snoop" pvconns has accepted a new connection on 'vconn'.
 * Connects this vconn to a controller. */
static void
add_snooper(struct ofproto *ofproto, struct vconn *vconn)
{
    struct ofconn *ofconn, *best;

    /* Pick a controller for monitoring. */
    best = NULL;
    LIST_FOR_EACH (ofconn, node, &ofproto->all_conns) {
        if (ofconn->type == OFCONN_PRIMARY
            && (!best || snoop_preference(ofconn) > snoop_preference(best))) {
            best = ofconn;
        }
    }

    if (best) {
        rconn_add_monitor(best->rconn, vconn);
    } else {
        VLOG_INFO_RL(&rl, "no controller connection to snoop");
        vconn_close(vconn);
    }
}

int
ofproto_run1(struct ofproto *p)
{
    struct ofconn *ofconn, *next_ofconn;
    struct ofservice *ofservice;
    char *devname;
    int error;
    int i;

    if (shash_is_empty(&p->port_by_name)) {
        init_ports(p);
    }

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
                            dpif_name(p->dpif));
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

    if (p->in_band) {
        if (time_msec() >= p->next_in_band_update) {
            update_in_band_remotes(p);
        }
        in_band_run(p->in_band);
    }

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, node, &p->all_conns) {
        ofconn_run(ofconn);
    }

    /* Fail-open maintenance.  Do this after processing the ofconns since
     * fail-open checks the status of the controller rconn. */
    if (p->fail_open) {
        fail_open_run(p->fail_open);
    }

    HMAP_FOR_EACH (ofservice, node, &p->services) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(ofservice->pvconn, OFP_VERSION, &vconn);
        if (!retval) {
            struct rconn *rconn;
            char *name;

            rconn = rconn_create(ofservice->probe_interval, 0);
            name = ofconn_make_name(p, vconn_get_name(vconn));
            rconn_connect_unreliably(rconn, vconn, name);
            free(name);

            ofconn = ofconn_create(p, rconn, OFCONN_SERVICE);
            ofconn_set_rate_limit(ofconn, ofservice->rate_limit,
                                  ofservice->burst_limit);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", strerror(retval));
        }
    }

    for (i = 0; i < p->n_snoops; i++) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(p->snoops[i], OFP_VERSION, &vconn);
        if (!retval) {
            add_snooper(p, vconn);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", strerror(retval));
        }
    }

    if (time_msec() >= p->next_expiration) {
        int delay = ofproto_expire(p);
        p->next_expiration = time_msec() + delay;
        COVERAGE_INC(ofproto_expiration);
    }

    if (p->netflow) {
        netflow_run(p->netflow);
    }
    if (p->sflow) {
        ofproto_sflow_run(p->sflow);
    }

    return 0;
}

int
ofproto_run2(struct ofproto *p, bool revalidate_all)
{
    /* Figure out what we need to revalidate now, if anything. */
    struct tag_set revalidate_set = p->revalidate_set;
    if (p->need_revalidate) {
        revalidate_all = true;
    }

    /* Clear the revalidation flags. */
    tag_set_init(&p->revalidate_set);
    p->need_revalidate = false;

    /* Now revalidate if there's anything to do. */
    if (revalidate_all || !tag_set_is_empty(&revalidate_set)) {
        struct facet *facet, *next;

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
    struct ofservice *ofservice;
    struct ofconn *ofconn;
    size_t i;

    dpif_recv_wait(p->dpif);
    dpif_port_poll_wait(p->dpif);
    netdev_monitor_poll_wait(p->netdev_monitor);
    LIST_FOR_EACH (ofconn, node, &p->all_conns) {
        ofconn_wait(ofconn);
    }
    if (p->in_band) {
        poll_timer_wait_until(p->next_in_band_update);
        in_band_wait(p->in_band);
    }
    if (p->fail_open) {
        fail_open_wait(p->fail_open);
    }
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
    } else if (p->next_expiration != LLONG_MAX) {
        poll_timer_wait_until(p->next_expiration);
    }
    HMAP_FOR_EACH (ofservice, node, &p->services) {
        pvconn_wait(ofservice->pvconn);
    }
    for (i = 0; i < p->n_snoops; i++) {
        pvconn_wait(p->snoops[i]);
    }
}

void
ofproto_revalidate(struct ofproto *ofproto, tag_type tag)
{
    tag_set_add(&ofproto->revalidate_set, tag);
}

struct tag_set *
ofproto_get_revalidate_set(struct ofproto *ofproto)
{
    return &ofproto->revalidate_set;
}

bool
ofproto_is_alive(const struct ofproto *p)
{
    return !hmap_is_empty(&p->controllers);
}

void
ofproto_get_ofproto_controller_info(const struct ofproto * ofproto,
                                    struct shash *info)
{
    const struct ofconn *ofconn;

    shash_init(info);

    HMAP_FOR_EACH (ofconn, hmap_node, &ofproto->controllers) {
        const struct rconn *rconn = ofconn->rconn;
        const int last_error = rconn_get_last_error(rconn);
        struct ofproto_controller_info *cinfo = xmalloc(sizeof *cinfo);

        shash_add(info, rconn_get_target(rconn), cinfo);

        cinfo->is_connected = rconn_is_connected(rconn);
        cinfo->role = ofconn->role;

        cinfo->pairs.n = 0;

        if (last_error == EOF) {
            cinfo->pairs.keys[cinfo->pairs.n] = "last_error";
            cinfo->pairs.values[cinfo->pairs.n++] = xstrdup("End of file");
        } else if (last_error > 0) {
            cinfo->pairs.keys[cinfo->pairs.n] = "last_error";
            cinfo->pairs.values[cinfo->pairs.n++] =
                xstrdup(strerror(last_error));
        }

        cinfo->pairs.keys[cinfo->pairs.n] = "state";
        cinfo->pairs.values[cinfo->pairs.n++] =
            xstrdup(rconn_get_state(rconn));

        cinfo->pairs.keys[cinfo->pairs.n] = "time_in_state";
        cinfo->pairs.values[cinfo->pairs.n++] =
            xasprintf("%u", rconn_get_state_elapsed(rconn));
    }
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

/* Deletes port number 'odp_port' from the datapath for 'ofproto'.
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
ofproto_port_del(struct ofproto *ofproto, uint16_t odp_port)
{
    struct ofport *ofport = get_port(ofproto, odp_port);
    const char *name = ofport ? ofport->opp.name : "<unknown>";
    int error;

    error = dpif_port_del(ofproto->dpif, odp_port);
    if (error) {
        VLOG_ERR("%s: failed to remove port %"PRIu16" (%s) interface (%s)",
                 dpif_name(ofproto->dpif), odp_port, name, strerror(error));
    } else if (ofport) {
        /* 'name' is ofport->opp.name and update_port() is going to destroy
         * 'ofport'.  Just in case update_port() refers to 'name' after it
         * destroys 'ofport', make a copy of it around the update_port()
         * call. */
        char *devname = xstrdup(name);
        update_port(ofproto, devname);
        free(devname);
    }
    return error;
}

/* Checks if 'ofproto' thinks 'odp_port' should be included in floods.  Returns
 * true if 'odp_port' exists and should be included, false otherwise. */
bool
ofproto_port_is_floodable(struct ofproto *ofproto, uint16_t odp_port)
{
    struct ofport *ofport = get_port(ofproto, odp_port);
    return ofport && !(ofport->opp.config & OFPPC_NO_FLOOD);
}

int
ofproto_send_packet(struct ofproto *p, const struct flow *flow,
                    const union ofp_action *actions, size_t n_actions,
                    const struct ofpbuf *packet)
{
    struct action_xlate_ctx ctx;
    struct ofpbuf *odp_actions;

    action_xlate_ctx_init(&ctx, p, flow, packet);
    odp_actions = xlate_actions(&ctx, actions, n_actions);

    /* XXX Should we translate the dpif_execute() errno value into an OpenFlow
     * error code? */
    dpif_execute(p->dpif, odp_actions->data, odp_actions->size, packet);

    ofpbuf_delete(odp_actions);

    return 0;
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

void
ofproto_flush_flows(struct ofproto *ofproto)
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
        facet_remove(ofproto, facet);
    }

    cls_cursor_init(&cursor, &ofproto->cls, NULL);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
        rule_remove(ofproto, rule);
    }

    dpif_flow_flush(ofproto->dpif);
    if (ofproto->in_band) {
        in_band_flushed(ofproto->in_band);
    }
    if (ofproto->fail_open) {
        fail_open_flushed(ofproto->fail_open);
    }
}

static void
reinit_ports(struct ofproto *p)
{
    struct dpif_port_dump dump;
    struct shash_node *node;
    struct shash devnames;
    struct ofport *ofport;
    struct dpif_port dpif_port;

    COVERAGE_INC(ofproto_reinit_ports);

    shash_init(&devnames);
    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        shash_add_once (&devnames, ofport->opp.name, NULL);
    }
    DPIF_PORT_FOR_EACH (&dpif_port, &dump, p->dpif) {
        shash_add_once (&devnames, dpif_port.name, NULL);
    }

    SHASH_FOR_EACH (node, &devnames) {
        update_port(p, node->name);
    }
    shash_destroy(&devnames);
}

static struct ofport *
make_ofport(const struct dpif_port *dpif_port)
{
    struct netdev_options netdev_options;
    enum netdev_flags flags;
    struct ofport *ofport;
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

    ofport = xmalloc(sizeof *ofport);
    ofport->netdev = netdev;
    ofport->odp_port = dpif_port->port_no;
    ofport->opp.port_no = odp_port_to_ofp_port(dpif_port->port_no);
    netdev_get_etheraddr(netdev, ofport->opp.hw_addr);
    ovs_strlcpy(ofport->opp.name, dpif_port->name, sizeof ofport->opp.name);

    netdev_get_flags(netdev, &flags);
    ofport->opp.config = flags & NETDEV_UP ? 0 : OFPPC_PORT_DOWN;

    ofport->opp.state = netdev_get_carrier(netdev) ? 0 : OFPPS_LINK_DOWN;

    netdev_get_features(netdev,
                        &ofport->opp.curr, &ofport->opp.advertised,
                        &ofport->opp.supported, &ofport->opp.peer);
    return ofport;
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

static int
ofport_equal(const struct ofport *a_, const struct ofport *b_)
{
    const struct ofp_phy_port *a = &a_->opp;
    const struct ofp_phy_port *b = &b_->opp;

    BUILD_ASSERT_DECL(sizeof *a == 48); /* Detect ofp_phy_port changes. */
    return (a->port_no == b->port_no
            && !memcmp(a->hw_addr, b->hw_addr, sizeof a->hw_addr)
            && !strcmp(a->name, b->name)
            && a->state == b->state
            && a->config == b->config
            && a->curr == b->curr
            && a->advertised == b->advertised
            && a->supported == b->supported
            && a->peer == b->peer);
}

static void
send_port_status(struct ofproto *p, const struct ofport *ofport,
                 uint8_t reason)
{
    /* XXX Should limit the number of queued port status change messages. */
    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, node, &p->all_conns) {
        struct ofp_port_status *ops;
        struct ofpbuf *b;

        /* Primary controllers, even slaves, should always get port status
           updates.  Otherwise obey ofconn_receives_async_msgs(). */
        if (ofconn->type != OFCONN_PRIMARY
            && !ofconn_receives_async_msgs(ofconn)) {
            continue;
        }

        ops = make_openflow_xid(sizeof *ops, OFPT_PORT_STATUS, 0, &b);
        ops->reason = reason;
        ops->desc = ofport->opp;
        hton_ofp_phy_port(&ops->desc);
        queue_tx(b, ofconn, NULL);
    }
}

static void
ofport_install(struct ofproto *p, struct ofport *ofport)
{
    const char *netdev_name = ofport->opp.name;

    netdev_monitor_add(p->netdev_monitor, ofport->netdev);
    hmap_insert(&p->ports, &ofport->hmap_node, hash_int(ofport->odp_port, 0));
    shash_add(&p->port_by_name, netdev_name, ofport);
    if (p->sflow) {
        ofproto_sflow_add_port(p->sflow, ofport->odp_port, netdev_name);
    }
}

static void
ofport_remove(struct ofproto *p, struct ofport *ofport)
{
    netdev_monitor_remove(p->netdev_monitor, ofport->netdev);
    hmap_remove(&p->ports, &ofport->hmap_node);
    shash_delete(&p->port_by_name,
                 shash_find(&p->port_by_name, ofport->opp.name));
    if (p->sflow) {
        ofproto_sflow_del_port(p->sflow, ofport->odp_port);
    }
}

static void
ofport_free(struct ofport *ofport)
{
    if (ofport) {
        netdev_close(ofport->netdev);
        free(ofport);
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
update_port(struct ofproto *p, const char *devname)
{
    struct dpif_port dpif_port;
    struct ofport *old_ofport;
    struct ofport *new_ofport;
    int error;

    COVERAGE_INC(ofproto_update_port);

    /* Query the datapath for port information. */
    error = dpif_port_query_by_name(p->dpif, devname, &dpif_port);

    /* Find the old ofport. */
    old_ofport = shash_find_data(&p->port_by_name, devname);
    if (!error) {
        if (!old_ofport) {
            /* There's no port named 'devname' but there might be a port with
             * the same port number.  This could happen if a port is deleted
             * and then a new one added in its place very quickly, or if a port
             * is renamed.  In the former case we want to send an OFPPR_DELETE
             * and an OFPPR_ADD, and in the latter case we want to send a
             * single OFPPR_MODIFY.  We can distinguish the cases by comparing
             * the old port's ifindex against the new port, or perhaps less
             * reliably but more portably by comparing the old port's MAC
             * against the new port's MAC.  However, this code isn't that smart
             * and always sends an OFPPR_MODIFY (XXX). */
            old_ofport = get_port(p, dpif_port.port_no);
        }
    } else if (error != ENOENT && error != ENODEV) {
        VLOG_WARN_RL(&rl, "dpif_port_query_by_name returned unexpected error "
                     "%s", strerror(error));
        goto exit;
    }

    /* Create a new ofport. */
    new_ofport = !error ? make_ofport(&dpif_port) : NULL;

    /* Eliminate a few pathological cases. */
    if (!old_ofport && !new_ofport) {
        goto exit;
    } else if (old_ofport && new_ofport) {
        /* Most of the 'config' bits are OpenFlow soft state, but
         * OFPPC_PORT_DOWN is maintained by the kernel.  So transfer the
         * OpenFlow bits from old_ofport.  (make_ofport() only sets
         * OFPPC_PORT_DOWN and leaves the other bits 0.)  */
        new_ofport->opp.config |= old_ofport->opp.config & ~OFPPC_PORT_DOWN;

        if (ofport_equal(old_ofport, new_ofport)) {
            /* False alarm--no change. */
            ofport_free(new_ofport);
            goto exit;
        }
    }

    /* Now deal with the normal cases. */
    if (old_ofport) {
        ofport_remove(p, old_ofport);
    }
    if (new_ofport) {
        ofport_install(p, new_ofport);
    }
    send_port_status(p, new_ofport ? new_ofport : old_ofport,
                     (!old_ofport ? OFPPR_ADD
                      : !new_ofport ? OFPPR_DELETE
                      : OFPPR_MODIFY));
    ofport_free(old_ofport);

exit:
    dpif_port_destroy(&dpif_port);
}

static int
init_ports(struct ofproto *p)
{
    struct dpif_port_dump dump;
    struct dpif_port dpif_port;

    DPIF_PORT_FOR_EACH (&dpif_port, &dump, p->dpif) {
        if (!ofport_conflicts(p, &dpif_port)) {
            struct ofport *ofport = make_ofport(&dpif_port);
            if (ofport) {
                ofport_install(p, ofport);
            }
        }
    }

    return 0;
}

static struct ofconn *
ofconn_create(struct ofproto *p, struct rconn *rconn, enum ofconn_type type)
{
    struct ofconn *ofconn = xzalloc(sizeof *ofconn);
    ofconn->ofproto = p;
    list_push_back(&p->all_conns, &ofconn->node);
    ofconn->rconn = rconn;
    ofconn->type = type;
    ofconn->flow_format = NXFF_OPENFLOW10;
    ofconn->role = NX_ROLE_OTHER;
    ofconn->packet_in_counter = rconn_packet_counter_create ();
    ofconn->pktbuf = NULL;
    ofconn->miss_send_len = 0;
    ofconn->reply_counter = rconn_packet_counter_create ();
    return ofconn;
}

static void
ofconn_destroy(struct ofconn *ofconn)
{
    if (ofconn->type == OFCONN_PRIMARY) {
        hmap_remove(&ofconn->ofproto->controllers, &ofconn->hmap_node);
    }
    discovery_destroy(ofconn->discovery);

    list_remove(&ofconn->node);
    switch_status_unregister(ofconn->ss);
    rconn_destroy(ofconn->rconn);
    rconn_packet_counter_destroy(ofconn->packet_in_counter);
    rconn_packet_counter_destroy(ofconn->reply_counter);
    pktbuf_destroy(ofconn->pktbuf);
    free(ofconn);
}

static void
ofconn_run(struct ofconn *ofconn)
{
    struct ofproto *p = ofconn->ofproto;
    int iteration;
    size_t i;

    if (ofconn->discovery) {
        char *controller_name;
        if (rconn_is_connectivity_questionable(ofconn->rconn)) {
            discovery_question_connectivity(ofconn->discovery);
        }
        if (discovery_run(ofconn->discovery, &controller_name)) {
            if (controller_name) {
                char *ofconn_name = ofconn_make_name(p, controller_name);
                rconn_connect(ofconn->rconn, controller_name, ofconn_name);
                free(ofconn_name);
            } else {
                rconn_disconnect(ofconn->rconn);
            }
        }
    }

    for (i = 0; i < N_SCHEDULERS; i++) {
        pinsched_run(ofconn->schedulers[i], do_send_packet_in, ofconn);
    }

    rconn_run(ofconn->rconn);

    if (rconn_packet_counter_read (ofconn->reply_counter) < OFCONN_REPLY_MAX) {
        /* Limit the number of iterations to prevent other tasks from
         * starving. */
        for (iteration = 0; iteration < 50; iteration++) {
            struct ofpbuf *of_msg = rconn_recv(ofconn->rconn);
            if (!of_msg) {
                break;
            }
            if (p->fail_open) {
                fail_open_maybe_recover(p->fail_open);
            }
            handle_openflow(ofconn, of_msg);
            ofpbuf_delete(of_msg);
        }
    }

    if (!ofconn->discovery && !rconn_is_alive(ofconn->rconn)) {
        ofconn_destroy(ofconn);
    }
}

static void
ofconn_wait(struct ofconn *ofconn)
{
    int i;

    if (ofconn->discovery) {
        discovery_wait(ofconn->discovery);
    }
    for (i = 0; i < N_SCHEDULERS; i++) {
        pinsched_wait(ofconn->schedulers[i]);
    }
    rconn_run_wait(ofconn->rconn);
    if (rconn_packet_counter_read (ofconn->reply_counter) < OFCONN_REPLY_MAX) {
        rconn_recv_wait(ofconn->rconn);
    } else {
        COVERAGE_INC(ofproto_ofconn_stuck);
    }
}

/* Returns true if 'ofconn' should receive asynchronous messages. */
static bool
ofconn_receives_async_msgs(const struct ofconn *ofconn)
{
    if (ofconn->type == OFCONN_PRIMARY) {
        /* Primary controllers always get asynchronous messages unless they
         * have configured themselves as "slaves".  */
        return ofconn->role != NX_ROLE_SLAVE;
    } else {
        /* Service connections don't get asynchronous messages unless they have
         * explicitly asked for them by setting a nonzero miss send length. */
        return ofconn->miss_send_len > 0;
    }
}

/* Returns a human-readable name for an OpenFlow connection between 'ofproto'
 * and 'target', suitable for use in log messages for identifying the
 * connection.
 *
 * The name is dynamically allocated.  The caller should free it (with free())
 * when it is no longer needed. */
static char *
ofconn_make_name(const struct ofproto *ofproto, const char *target)
{
    return xasprintf("%s<->%s", dpif_base_name(ofproto->dpif), target);
}

static void
ofconn_set_rate_limit(struct ofconn *ofconn, int rate, int burst)
{
    int i;

    for (i = 0; i < N_SCHEDULERS; i++) {
        struct pinsched **s = &ofconn->schedulers[i];

        if (rate > 0) {
            if (!*s) {
                *s = pinsched_create(rate, burst,
                                     ofconn->ofproto->switch_status);
            } else {
                pinsched_set_limits(*s, rate, burst);
            }
        } else {
            pinsched_destroy(*s);
            *s = NULL;
        }
    }
}

static void
ofservice_reconfigure(struct ofservice *ofservice,
                      const struct ofproto_controller *c)
{
    ofservice->probe_interval = c->probe_interval;
    ofservice->rate_limit = c->rate_limit;
    ofservice->burst_limit = c->burst_limit;
}

/* Creates a new ofservice in 'ofproto'.  Returns 0 if successful, otherwise a
 * positive errno value. */
static int
ofservice_create(struct ofproto *ofproto, const struct ofproto_controller *c)
{
    struct ofservice *ofservice;
    struct pvconn *pvconn;
    int error;

    error = pvconn_open(c->target, &pvconn);
    if (error) {
        return error;
    }

    ofservice = xzalloc(sizeof *ofservice);
    hmap_insert(&ofproto->services, &ofservice->node,
                hash_string(c->target, 0));
    ofservice->pvconn = pvconn;

    ofservice_reconfigure(ofservice, c);

    return 0;
}

static void
ofservice_destroy(struct ofproto *ofproto, struct ofservice *ofservice)
{
    hmap_remove(&ofproto->services, &ofservice->node);
    pvconn_close(ofservice->pvconn);
    free(ofservice);
}

/* Finds and returns the ofservice within 'ofproto' that has the given
 * 'target', or a null pointer if none exists. */
static struct ofservice *
ofservice_lookup(struct ofproto *ofproto, const char *target)
{
    struct ofservice *ofservice;

    HMAP_FOR_EACH_WITH_HASH (ofservice, node, hash_string(target, 0),
                             &ofproto->services) {
        if (!strcmp(pvconn_get_name(ofservice->pvconn), target)) {
            return ofservice;
        }
    }
    return NULL;
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
        && odp_actions->nla_type == ODPAT_CONTROLLER) {
        /* As an optimization, avoid a round-trip from userspace to kernel to
         * userspace.  This also avoids possibly filling up kernel packet
         * buffers along the way. */
        struct dpif_upcall upcall;

        upcall.type = _ODPL_ACTION_NR;
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
    struct odp_flow_stats stats;

    assert(ofpbuf_headroom(packet) >= sizeof(struct ofp_packet_in));

    flow_extract_stats(&facet->flow, packet, &stats);
    if (execute_odp_actions(ofproto, &facet->flow,
                            facet->actions, facet->actions_len, packet)) {
        facet_update_stats(ofproto, facet, &stats);
        facet->used = time_msec();
        netflow_flow_update_time(ofproto->netflow,
                                 &facet->nf_flow, facet->used);
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
facet_put__(struct ofproto *ofproto, struct facet *facet, int flags,
            struct odp_flow_put *put)
{
    uint32_t keybuf[ODPUTIL_FLOW_KEY_U32S];
    struct ofpbuf key;

    ofpbuf_use_stack(&key, keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, &facet->flow);
    assert(key.base == keybuf);

    memset(&put->flow.stats, 0, sizeof put->flow.stats);
    put->flow.key = key.data;
    put->flow.key_len = key.size;
    put->flow.actions = facet->actions;
    put->flow.actions_len = facet->actions_len;
    put->flow.flags = 0;
    put->flags = flags;
    return dpif_flow_put(ofproto->dpif, put);
}

/* If 'facet' is installable, inserts or re-inserts it into 'p''s datapath.  If
 * 'zero_stats' is true, clears any existing statistics from the datapath for
 * 'facet'. */
static void
facet_install(struct ofproto *p, struct facet *facet, bool zero_stats)
{
    if (facet->may_install) {
        struct odp_flow_put put;
        int flags;

        flags = ODPPF_CREATE | ODPPF_MODIFY;
        if (zero_stats) {
            flags |= ODPPF_ZERO_STATS;
        }
        if (!facet_put__(p, facet, flags, &put)) {
            facet->installed = true;
        }
    }
}

/* Ensures that the bytes in 'facet', plus 'extra_bytes', have been passed up
 * to the accounting hook function in the ofhooks structure. */
static void
facet_account(struct ofproto *ofproto,
              struct facet *facet, uint64_t extra_bytes)
{
    uint64_t total_bytes = facet->byte_count + extra_bytes;

    if (ofproto->ofhooks->account_flow_cb
        && total_bytes > facet->accounted_bytes)
    {
        ofproto->ofhooks->account_flow_cb(
            &facet->flow, facet->tags, facet->actions, facet->actions_len,
            total_bytes - facet->accounted_bytes, ofproto->aux);
        facet->accounted_bytes = total_bytes;
    }
}

/* If 'rule' is installed in the datapath, uninstalls it. */
static void
facet_uninstall(struct ofproto *p, struct facet *facet)
{
    if (facet->installed) {
        uint32_t keybuf[ODPUTIL_FLOW_KEY_U32S];
        struct odp_flow odp_flow;
        struct ofpbuf key;

        ofpbuf_use_stack(&key, keybuf, sizeof keybuf);
        odp_flow_key_from_flow(&key, &facet->flow);
        assert(key.base == keybuf);

        odp_flow.key = key.data;
        odp_flow.key_len = key.size;
        odp_flow.actions = NULL;
        odp_flow.actions_len = 0;
        odp_flow.flags = 0;
        if (!dpif_flow_del(p->dpif, &odp_flow)) {
            facet_update_stats(p, facet, &odp_flow.stats);
        }
        facet->installed = false;
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
 * accounting ofhook and emits a NetFlow expiration if appropriate.  */
static void
facet_flush_stats(struct ofproto *ofproto, struct facet *facet)
{
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
    if (actions_changed || facet->may_install != facet->installed) {
        if (facet->may_install) {
            uint32_t keybuf[ODPUTIL_FLOW_KEY_U32S];
            struct odp_flow_put put;
            struct ofpbuf key;

            ofpbuf_use_stack(&key, keybuf, sizeof keybuf);
            odp_flow_key_from_flow(&key, &facet->flow);

            memset(&put.flow.stats, 0, sizeof put.flow.stats);
            put.flow.key = key.data;
            put.flow.key_len = key.size;
            put.flow.actions = odp_actions->data;
            put.flow.actions_len = odp_actions->size;
            put.flow.flags = 0;
            put.flags = ODPPF_CREATE | ODPPF_MODIFY | ODPPF_ZERO_STATS;
            dpif_flow_put(ofproto->dpif, &put);

            facet_update_stats(ofproto, facet, &put.flow.stats);
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
    }

    ofpbuf_delete(odp_actions);

    return true;
}

static void
queue_tx(struct ofpbuf *msg, const struct ofconn *ofconn,
         struct rconn_packet_counter *counter)
{
    update_openflow_length(msg);
    if (rconn_send(ofconn->rconn, msg, counter)) {
        ofpbuf_delete(msg);
    }
}

static void
send_error_oh(const struct ofconn *ofconn, const struct ofp_header *oh,
              int error)
{
    struct ofpbuf *buf = ofputil_encode_error_msg(error, oh);
    if (buf) {
        COVERAGE_INC(ofproto_error);
        queue_tx(buf, ofconn, ofconn->reply_counter);
    }
}

static void
hton_ofp_phy_port(struct ofp_phy_port *opp)
{
    opp->port_no = htons(opp->port_no);
    opp->config = htonl(opp->config);
    opp->state = htonl(opp->state);
    opp->curr = htonl(opp->curr);
    opp->advertised = htonl(opp->advertised);
    opp->supported = htonl(opp->supported);
    opp->peer = htonl(opp->peer);
}

static int
handle_echo_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    queue_tx(make_echo_reply(oh), ofconn, ofconn->reply_counter);
    return 0;
}

static int
handle_features_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofp_switch_features *osf;
    struct ofpbuf *buf;
    struct ofport *port;

    osf = make_openflow_xid(sizeof *osf, OFPT_FEATURES_REPLY, oh->xid, &buf);
    osf->datapath_id = htonll(ofconn->ofproto->datapath_id);
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

    HMAP_FOR_EACH (port, hmap_node, &ofconn->ofproto->ports) {
        hton_ofp_phy_port(ofpbuf_put(buf, &port->opp, sizeof port->opp));
    }

    queue_tx(buf, ofconn, ofconn->reply_counter);
    return 0;
}

static int
handle_get_config_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofpbuf *buf;
    struct ofp_switch_config *osc;
    uint16_t flags;
    bool drop_frags;

    /* Figure out flags. */
    dpif_get_drop_frags(ofconn->ofproto->dpif, &drop_frags);
    flags = drop_frags ? OFPC_FRAG_DROP : OFPC_FRAG_NORMAL;

    /* Send reply. */
    osc = make_openflow_xid(sizeof *osc, OFPT_GET_CONFIG_REPLY, oh->xid, &buf);
    osc->flags = htons(flags);
    osc->miss_send_len = htons(ofconn->miss_send_len);
    queue_tx(buf, ofconn, ofconn->reply_counter);

    return 0;
}

static int
handle_set_config(struct ofconn *ofconn, const struct ofp_switch_config *osc)
{
    uint16_t flags = ntohs(osc->flags);

    if (ofconn->type == OFCONN_PRIMARY && ofconn->role != NX_ROLE_SLAVE) {
        switch (flags & OFPC_FRAG_MASK) {
        case OFPC_FRAG_NORMAL:
            dpif_set_drop_frags(ofconn->ofproto->dpif, false);
            break;
        case OFPC_FRAG_DROP:
            dpif_set_drop_frags(ofconn->ofproto->dpif, true);
            break;
        default:
            VLOG_WARN_RL(&rl, "requested bad fragment mode (flags=%"PRIx16")",
                         osc->flags);
            break;
        }
    }

    ofconn->miss_send_len = ntohs(osc->miss_send_len);

    return 0;
}

/* Maximum depth of flow table recursion (due to NXAST_RESUBMIT actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 16

static void do_xlate_actions(const union ofp_action *in, size_t n_in,
                             struct action_xlate_ctx *ctx);

static void
add_output_action(struct action_xlate_ctx *ctx, uint16_t port)
{
    const struct ofport *ofport = get_port(ctx->ofproto, port);

    if (ofport) {
        if (ofport->opp.config & OFPPC_NO_FWD) {
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

    nl_msg_put_u32(ctx->odp_actions, ODPAT_OUTPUT, port);
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
flood_packets(struct ofproto *ofproto, uint16_t odp_in_port, uint32_t mask,
              uint16_t *nf_output_iface, struct ofpbuf *odp_actions)
{
    struct ofport *ofport;

    HMAP_FOR_EACH (ofport, hmap_node, &ofproto->ports) {
        uint16_t odp_port = ofport->odp_port;
        if (odp_port != odp_in_port && !(ofport->opp.config & mask)) {
            nl_msg_put_u32(odp_actions, ODPAT_OUTPUT, odp_port);
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
        if (!ctx->ofproto->ofhooks->normal_cb(&ctx->flow, ctx->packet,
                                              ctx->odp_actions, &ctx->tags,
                                              &ctx->nf_output_iface,
                                              ctx->ofproto->aux)) {
            COVERAGE_INC(ofproto_uninstallable);
            ctx->may_set_up_flow = false;
        }
        break;
    case OFPP_FLOOD:
        flood_packets(ctx->ofproto, ctx->flow.in_port, OFPPC_NO_FLOOD,
                      &ctx->nf_output_iface, ctx->odp_actions);
        break;
    case OFPP_ALL:
        flood_packets(ctx->ofproto, ctx->flow.in_port, 0,
                      &ctx->nf_output_iface, ctx->odp_actions);
        break;
    case OFPP_CONTROLLER:
        nl_msg_put_u64(ctx->odp_actions, ODPAT_CONTROLLER, max_len);
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
        nl_msg_put_flag(ctx->odp_actions, ODPAT_POP_PRIORITY);
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
    nl_msg_put_u32(ctx->odp_actions, ODPAT_SET_PRIORITY, priority);
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
    nl_msg_put_u32(ctx->odp_actions, ODPAT_SET_PRIORITY, priority);
}

static void
xlate_set_dl_tci(struct action_xlate_ctx *ctx)
{
    ovs_be16 tci = ctx->flow.vlan_tci;
    if (!(tci & htons(VLAN_CFI))) {
        nl_msg_put_flag(ctx->odp_actions, ODPAT_STRIP_VLAN);
    } else {
        nl_msg_put_be16(ctx->odp_actions, ODPAT_SET_DL_TCI,
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
        nl_msg_put_be64(ctx->odp_actions, ODPAT_SET_TUNNEL, ctx->flow.tun_id);
    }
}

static void
xlate_nicira_action(struct action_xlate_ctx *ctx,
                    const struct nx_action_header *nah)
{
    const struct nx_action_resubmit *nar;
    const struct nx_action_set_tunnel *nast;
    const struct nx_action_set_queue *nasq;
    const struct nx_action_multipath *nam;
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
        nl_msg_put_be64(ctx->odp_actions, ODPAT_SET_TUNNEL, tun_id);
        ctx->flow.tun_id = tun_id;
        break;

    case NXAST_DROP_SPOOFED_ARP:
        if (ctx->flow.dl_type == htons(ETH_TYPE_ARP)) {
            nl_msg_put_flag(ctx->odp_actions, ODPAT_DROP_SPOOFED_ARP);
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
        nl_msg_put_be64(ctx->odp_actions, ODPAT_SET_TUNNEL, tun_id);
        ctx->flow.tun_id = tun_id;
        break;

    case NXAST_MULTIPATH:
        nam = (const struct nx_action_multipath *) nah;
        multipath_execute(nam, &ctx->flow);
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
    if (port && port->opp.config & (OFPPC_NO_RECV | OFPPC_NO_RECV_STP) &&
        port->opp.config & (eth_addr_equals(ctx->flow.dl_dst, eth_addr_stp)
                            ? OFPPC_NO_RECV_STP : OFPPC_NO_RECV)) {
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
            nl_msg_put_unspec(ctx->odp_actions, ODPAT_SET_DL_SRC,
                              oada->dl_addr, ETH_ADDR_LEN);
            memcpy(ctx->flow.dl_src, oada->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_DL_DST:
            oada = ((struct ofp_action_dl_addr *) ia);
            nl_msg_put_unspec(ctx->odp_actions, ODPAT_SET_DL_DST,
                              oada->dl_addr, ETH_ADDR_LEN);
            memcpy(ctx->flow.dl_dst, oada->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_NW_SRC:
            nl_msg_put_be32(ctx->odp_actions, ODPAT_SET_NW_SRC,
                            ia->nw_addr.nw_addr);
            ctx->flow.nw_src = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_DST:
            nl_msg_put_be32(ctx->odp_actions, ODPAT_SET_NW_DST,
                            ia->nw_addr.nw_addr);
            ctx->flow.nw_dst = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_TOS:
            nl_msg_put_u8(ctx->odp_actions, ODPAT_SET_NW_TOS,
                          ia->nw_tos.nw_tos);
            ctx->flow.nw_tos = ia->nw_tos.nw_tos;
            break;

        case OFPAT_SET_TP_SRC:
            nl_msg_put_be16(ctx->odp_actions, ODPAT_SET_TP_SRC,
                            ia->tp_port.tp_port);
            ctx->flow.tp_src = ia->tp_port.tp_port;
            break;

        case OFPAT_SET_TP_DST:
            nl_msg_put_be16(ctx->odp_actions, ODPAT_SET_TP_DST,
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
    do_xlate_actions(in, n_in, ctx);
    remove_pop_action(ctx);

    /* Check with in-band control to see if we're allowed to set up this
     * flow. */
    if (!in_band_rule_check(ctx->ofproto->in_band, &ctx->flow,
                            ctx->odp_actions->data, ctx->odp_actions->size)) {
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
    if (ofconn->type == OFCONN_PRIMARY && ofconn->role == NX_ROLE_SLAVE) {
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
    struct ofproto *p = ofconn->ofproto;
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
        error = pktbuf_retrieve(ofconn->pktbuf, ntohl(opo->buffer_id),
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
                   uint32_t config, uint32_t mask)
{
    mask &= config ^ port->opp.config;
    if (mask & OFPPC_PORT_DOWN) {
        if (config & OFPPC_PORT_DOWN) {
            netdev_turn_flags_off(port->netdev, NETDEV_UP, true);
        } else {
            netdev_turn_flags_on(port->netdev, NETDEV_UP, true);
        }
    }
#define REVALIDATE_BITS (OFPPC_NO_RECV | OFPPC_NO_RECV_STP |    \
                         OFPPC_NO_FWD | OFPPC_NO_FLOOD)
    if (mask & REVALIDATE_BITS) {
        COVERAGE_INC(ofproto_costly_flags);
        port->opp.config ^= mask & REVALIDATE_BITS;
        p->need_revalidate = true;
    }
#undef REVALIDATE_BITS
    if (mask & OFPPC_NO_PACKET_IN) {
        port->opp.config ^= OFPPC_NO_PACKET_IN;
    }
}

static int
handle_port_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn->ofproto;
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
        update_port_config(p, port, ntohl(opm->config), ntohl(opm->mask));
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
        queue_tx(msg, ofconn, ofconn->reply_counter);
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
        queue_tx(msg, ofconn, ofconn->reply_counter);
    }
    ofpbuf_prealloc_tailroom(*msgp, nbytes);
}

static int
handle_desc_stats_request(struct ofconn *ofconn,
                          const struct ofp_header *request)
{
    struct ofproto *p = ofconn->ofproto;
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
    queue_tx(msg, ofconn, ofconn->reply_counter);

    return 0;
}

static int
handle_table_stats_request(struct ofconn *ofconn,
                           const struct ofp_header *request)
{
    struct ofproto *p = ofconn->ofproto;
    struct ofp_table_stats *ots;
    struct ofpbuf *msg;

    msg = start_ofp_stats_reply(request, sizeof *ots * 2);

    /* Classifier table. */
    ots = append_ofp_stats_reply(sizeof *ots, ofconn, &msg);
    memset(ots, 0, sizeof *ots);
    strcpy(ots->name, "classifier");
    ots->wildcards = (ofconn->flow_format == NXFF_OPENFLOW10
                      ? htonl(OFPFW_ALL) : htonl(OVSFW_ALL));
    ots->max_entries = htonl(1024 * 1024); /* An arbitrary big number. */
    ots->active_count = htonl(classifier_count(&p->cls));
    ots->lookup_count = htonll(0);              /* XXX */
    ots->matched_count = htonll(0);             /* XXX */

    queue_tx(msg, ofconn, ofconn->reply_counter);
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
    ops->port_no = htons(port->opp.port_no);
    memset(ops->pad, 0, sizeof ops->pad);
    ops->rx_packets = htonll(stats.rx_packets);
    ops->tx_packets = htonll(stats.tx_packets);
    ops->rx_bytes = htonll(stats.rx_bytes);
    ops->tx_bytes = htonll(stats.tx_bytes);
    ops->rx_dropped = htonll(stats.rx_dropped);
    ops->tx_dropped = htonll(stats.tx_dropped);
    ops->rx_errors = htonll(stats.rx_errors);
    ops->tx_errors = htonll(stats.tx_errors);
    ops->rx_frame_err = htonll(stats.rx_frame_errors);
    ops->rx_over_err = htonll(stats.rx_over_errors);
    ops->rx_crc_err = htonll(stats.rx_crc_errors);
    ops->collisions = htonll(stats.collisions);
}

static int
handle_port_stats_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn->ofproto;
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

    queue_tx(msg, ofconn, ofconn->reply_counter);
    return 0;
}

/* Obtains statistic counters for 'rule' within 'p' and stores them into
 * '*packet_countp' and '*byte_countp'.  The returned statistics include
 * statistics for all of 'rule''s facets. */
static void
query_stats(struct ofproto *p, struct rule *rule,
            uint64_t *packet_countp, uint64_t *byte_countp)
{
    uint32_t keybuf[ODPUTIL_FLOW_KEY_U32S];
    uint64_t packet_count, byte_count;
    struct facet *facet;
    struct ofpbuf key;

    /* Start from historical data for 'rule' itself that are no longer tracked
     * by the datapath.  This counts, for example, facets that have expired. */
    packet_count = rule->packet_count;
    byte_count = rule->byte_count;

    /* Ask the datapath for statistics on all of the rule's facets.  (We could
     * batch up statistics requests using dpif_flow_get_multiple(), but that is
     * not yet implemented.)
     *
     * Also, add any statistics that are not tracked by the datapath for each
     * facet.  This includes, for example, statistics for packets that were
     * executed "by hand" by ofproto via dpif_execute() but must be accounted
     * to a rule. */
    ofpbuf_use_stack(&key, keybuf, sizeof keybuf);
    LIST_FOR_EACH (facet, list_node, &rule->facets) {
        struct odp_flow odp_flow;

        ofpbuf_clear(&key);
        odp_flow_key_from_flow(&key, &facet->flow);

        odp_flow.key = key.data;
        odp_flow.key_len = key.size;
        odp_flow.actions = NULL;
        odp_flow.actions_len = 0;
        odp_flow.flags = 0;
        if (!dpif_flow_get(p->dpif, &odp_flow)) {
            packet_count += odp_flow.stats.n_packets;
            byte_count += odp_flow.stats.n_bytes;
        }

        packet_count += facet->packet_count;
        byte_count += facet->byte_count;
    }

    /* Return the stats to the caller. */
    *packet_countp = packet_count;
    *byte_countp = byte_count;
}

static void
calc_flow_duration(long long int start, ovs_be32 *sec, ovs_be32 *nsec)
{
    long long int msecs = time_msec() - start;
    *sec = htonl(msecs / 1000);
    *nsec = htonl((msecs % 1000) * (1000 * 1000));
}

static void
put_ofp_flow_stats(struct ofconn *ofconn, struct rule *rule,
                   ovs_be16 out_port, struct ofpbuf **replyp)
{
    struct ofp_flow_stats *ofs;
    uint64_t packet_count, byte_count;
    size_t act_len, len;

    if (rule_is_hidden(rule) || !rule_has_out_port(rule, out_port)) {
        return;
    }

    act_len = sizeof *rule->actions * rule->n_actions;
    len = offsetof(struct ofp_flow_stats, actions) + act_len;

    query_stats(ofconn->ofproto, rule, &packet_count, &byte_count);

    ofs = append_ofp_stats_reply(len, ofconn, replyp);
    ofs->length = htons(len);
    ofs->table_id = 0;
    ofs->pad = 0;
    ofputil_cls_rule_to_match(&rule->cr, ofconn->flow_format, &ofs->match,
                              rule->flow_cookie, &ofs->cookie);
    calc_flow_duration(rule->created, &ofs->duration_sec, &ofs->duration_nsec);
    ofs->priority = htons(rule->cr.priority);
    ofs->idle_timeout = htons(rule->idle_timeout);
    ofs->hard_timeout = htons(rule->hard_timeout);
    memset(ofs->pad2, 0, sizeof ofs->pad2);
    ofs->packet_count = htonll(packet_count);
    ofs->byte_count = htonll(byte_count);
    if (rule->n_actions > 0) {
        memcpy(ofs->actions, rule->actions, act_len);
    }
}

static bool
is_valid_table(uint8_t table_id)
{
    return table_id == 0 || table_id == 0xff;
}

static int
handle_flow_stats_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct ofp_flow_stats_request *fsr = ofputil_stats_body(oh);
    struct ofpbuf *reply;

    COVERAGE_INC(ofproto_flows_req);
    reply = start_ofp_stats_reply(oh, 1024);
    if (is_valid_table(fsr->table_id)) {
        struct cls_cursor cursor;
        struct cls_rule target;
        struct rule *rule;

        ofputil_cls_rule_from_match(&fsr->match, 0, NXFF_OPENFLOW10, 0,
                                    &target);
        cls_cursor_init(&cursor, &ofconn->ofproto->cls, &target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            put_ofp_flow_stats(ofconn, rule, fsr->out_port, &reply);
        }
    }
    queue_tx(reply, ofconn, ofconn->reply_counter);

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

    query_stats(ofconn->ofproto, rule, &packet_count, &byte_count);

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

        cls_cursor_init(&cursor, &ofconn->ofproto->cls, &target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            put_nx_flow_stats(ofconn, rule, nfsr->out_port, &reply);
        }
    }
    queue_tx(reply, ofconn, ofconn->reply_counter);

    return 0;
}

static void
flow_stats_ds(struct ofproto *ofproto, struct rule *rule, struct ds *results)
{
    uint64_t packet_count, byte_count;
    size_t act_len = sizeof *rule->actions * rule->n_actions;

    query_stats(ofproto, rule, &packet_count, &byte_count);

    ds_put_format(results, "duration=%llds, ",
                  (time_msec() - rule->created) / 1000);
    ds_put_format(results, "priority=%u, ", rule->cr.priority);
    ds_put_format(results, "n_packets=%"PRIu64", ", packet_count);
    ds_put_format(results, "n_bytes=%"PRIu64", ", byte_count);
    cls_rule_format(&rule->cr, results);
    if (act_len > 0) {
        ofp_print_actions(results, &rule->actions->header, act_len);
    } else {
        ds_put_cstr(results, "drop");
    }
    ds_put_cstr(results, "\n");
}

/* Adds a pretty-printed description of all flows to 'results', including
 * those marked hidden by secchan (e.g., by in-band control). */
void
ofproto_get_all_flows(struct ofproto *p, struct ds *results)
{
    struct cls_cursor cursor;
    struct rule *rule;

    cls_cursor_init(&cursor, &p->cls, NULL);
    CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
        flow_stats_ds(p, rule, results);
    }
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

                query_stats(ofproto, rule, &packet_count, &byte_count);

                total_packets += packet_count;
                total_bytes += byte_count;
                n_flows++;
            }
        }
    }

    oasr->flow_count = htonl(n_flows);
    oasr->packet_count = htonll(total_packets);
    oasr->byte_count = htonll(total_bytes);
    memset(oasr->pad, 0, sizeof oasr->pad);
}

static int
handle_aggregate_stats_request(struct ofconn *ofconn,
                               const struct ofp_header *oh)
{
    const struct ofp_aggregate_stats_request *request = ofputil_stats_body(oh);
    struct ofp_aggregate_stats_reply *reply;
    struct cls_rule target;
    struct ofpbuf *msg;

    ofputil_cls_rule_from_match(&request->match, 0, NXFF_OPENFLOW10, 0,
                                &target);

    msg = start_ofp_stats_reply(oh, sizeof *reply);
    reply = append_ofp_stats_reply(sizeof *reply, ofconn, &msg);
    query_aggregate_stats(ofconn->ofproto, &target, request->out_port,
                          request->table_id, reply);
    queue_tx(msg, ofconn, ofconn->reply_counter);
    return 0;
}

static int
handle_nxst_aggregate(struct ofconn *ofconn, const struct ofp_header *oh)
{
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
    query_aggregate_stats(ofconn->ofproto, &target, request->out_port,
                          request->table_id, reply);
    queue_tx(buf, ofconn, ofconn->reply_counter);

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
    reply->port_no = htons(cbdata->ofport->opp.port_no);
    memset(reply->pad, 0, sizeof reply->pad);
    reply->queue_id = htonl(queue_id);
    reply->tx_bytes = htonll(stats->tx_bytes);
    reply->tx_packets = htonll(stats->tx_packets);
    reply->tx_errors = htonll(stats->tx_errors);
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
    struct ofproto *ofproto = ofconn->ofproto;
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
    queue_tx(cbdata.msg, ofconn, ofconn->reply_counter);

    return 0;
}

static long long int
msec_from_nsec(uint64_t sec, uint32_t nsec)
{
    return !sec ? 0 : sec * 1000 + nsec / 1000000;
}

static void
facet_update_time(struct ofproto *ofproto, struct facet *facet,
                  const struct odp_flow_stats *stats)
{
    long long int used = msec_from_nsec(stats->used_sec, stats->used_nsec);
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
                   const struct odp_flow_stats *stats)
{
    if (stats->n_packets) {
        facet_update_time(ofproto, facet, stats);
        facet->packet_count += stats->n_packets;
        facet->byte_count += stats->n_bytes;
        netflow_flow_update_flags(&facet->nf_flow, stats->tcp_flags);
    }
}

/* Implements OFPFC_ADD and the cases for OFPFC_MODIFY and OFPFC_MODIFY_STRICT
 * in which no matching flow already exists in the flow table.
 *
 * Adds the flow specified by 'ofm', which is followed by 'n_actions'
 * ofp_actions, to ofconn->ofproto's flow table.  Returns 0 on success or an
 * OpenFlow error code as encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
add_flow(struct ofconn *ofconn, struct flow_mod *fm)
{
    struct ofproto *p = ofconn->ofproto;
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
        error = pktbuf_retrieve(ofconn->pktbuf, fm->buffer_id,
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
    struct ofpbuf *packet;
    uint16_t in_port;
    int error;

    if (buffer_id == UINT32_MAX) {
        return 0;
    }

    error = pktbuf_retrieve(ofconn->pktbuf, buffer_id, &packet, &in_port);
    if (error) {
        return error;
    }

    rule_execute(ofconn->ofproto, rule, in_port, packet);

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
    struct ofproto *p = ofconn->ofproto;
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
    struct ofproto *p = ofconn->ofproto;
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
    struct ofproto *p = ofconn->ofproto;
    struct flow_mod fm;
    int error;

    error = reject_slave_controller(ofconn, "flow_mod");
    if (error) {
        return error;
    }

    error = ofputil_decode_flow_mod(&fm, oh, ofconn->flow_format);
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

    ofconn->flow_format = msg->set ? NXFF_TUN_ID_FROM_COOKIE : NXFF_OPENFLOW10;
    return 0;
}

static int
handle_role_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct nx_role_request *nrr = (struct nx_role_request *) oh;
    struct nx_role_request *reply;
    struct ofpbuf *buf;
    uint32_t role;

    if (ofconn->type != OFCONN_PRIMARY) {
        VLOG_WARN_RL(&rl, "ignoring role request on non-controller "
                     "connection");
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    }

    role = ntohl(nrr->role);
    if (role != NX_ROLE_OTHER && role != NX_ROLE_MASTER
        && role != NX_ROLE_SLAVE) {
        VLOG_WARN_RL(&rl, "received request for unknown role %"PRIu32, role);

        /* There's no good error code for this. */
        return ofp_mkerr(OFPET_BAD_REQUEST, -1);
    }

    if (role == NX_ROLE_MASTER) {
        struct ofconn *other;

        HMAP_FOR_EACH (other, hmap_node, &ofconn->ofproto->controllers) {
            if (other->role == NX_ROLE_MASTER) {
                other->role = NX_ROLE_SLAVE;
            }
        }
    }
    ofconn->role = role;

    reply = make_nxmsg_xid(sizeof *reply, NXT_ROLE_REPLY, oh->xid, &buf);
    reply->role = htonl(role);
    queue_tx(buf, ofconn, ofconn->reply_counter);

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
        ofconn->flow_format = format;
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
    queue_tx(buf, ofconn, ofconn->reply_counter);
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
    case OFPUTIL_NXT_STATUS_REQUEST:
        return switch_status_handle_request(
            ofconn->ofproto->switch_status, ofconn->rconn, oh);

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
    case OFPUTIL_NXT_STATUS_REPLY:
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

    /* Check with in-band control to see if this packet should be sent
     * to the local port regardless of the flow table. */
    if (in_band_msg_in_hook(p->in_band, &flow, upcall->packet)) {
        struct ofpbuf odp_actions;

        ofpbuf_init(&odp_actions, 32);
        nl_msg_put_u32(&odp_actions, ODPAT_OUTPUT, ODPP_LOCAL);
        dpif_execute(p->dpif, odp_actions.data, odp_actions.size,
                     upcall->packet);
        ofpbuf_uninit(&odp_actions);
    }

    facet = facet_lookup_valid(p, &flow);
    if (!facet) {
        struct rule *rule = rule_lookup(p, &flow);
        if (!rule) {
            /* Don't send a packet-in if OFPPC_NO_PACKET_IN asserted. */
            struct ofport *port = get_port(p, flow.in_port);
            if (port) {
                if (port->opp.config & OFPPC_NO_PACKET_IN) {
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
    case _ODPL_ACTION_NR:
        COVERAGE_INC(ofproto_ctlr_action);
        odp_flow_key_to_flow(upcall->key, upcall->key_len, &flow);
        send_packet_in(p, upcall, &flow, false);
        break;

    case _ODPL_SFLOW_NR:
        if (p->sflow) {
            odp_flow_key_to_flow(upcall->key, upcall->key_len, &flow);
            ofproto_sflow_received(p->sflow, upcall, &flow);
        }
        ofpbuf_delete(upcall->packet);
        break;

    case _ODPL_MISS_NR:
        handle_miss_upcall(p, upcall);
        break;

    default:
        VLOG_WARN_RL(&rl, "upcall has unexpected type %"PRIu32, upcall->type);
        break;
    }
}

/* Flow expiration. */

static int ofproto_dp_max_idle(const struct ofproto *);
static void ofproto_update_used(struct ofproto *);
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

    /* Update 'used' for each flow in the datapath. */
    ofproto_update_used(ofproto);

    /* Expire facets that have been idle too long. */
    dp_max_idle = ofproto_dp_max_idle(ofproto);
    ofproto_expire_facets(ofproto, dp_max_idle);

    /* Expire OpenFlow flows whose idle_timeout or hard_timeout has passed. */
    cls_cursor_init(&cursor, &ofproto->cls, NULL);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
        rule_expire(ofproto, rule);
    }

    /* Let the hook know that we're at a stable point: all outstanding data
     * in existing flows has been accounted to the account_cb.  Thus, the
     * hook can now reasonably do operations that depend on having accurate
     * flow volume accounting (currently, that's just bond rebalancing). */
    if (ofproto->ofhooks->account_checkpoint_cb) {
        ofproto->ofhooks->account_checkpoint_cb(ofproto->aux);
    }

    return MIN(dp_max_idle, 1000);
}

/* Update 'used' member of installed facets. */
static void
ofproto_update_used(struct ofproto *p)
{
    struct dpif_flow_dump dump;

    dpif_flow_dump_start(&dump, p->dpif);
    for (;;) {
        uint32_t keybuf[ODPUTIL_FLOW_KEY_U32S];
        struct facet *facet;
        struct odp_flow f;
        struct flow flow;

        memset(&f, 0, sizeof f);
        f.key = (struct nlattr *) keybuf;
        f.key_len = sizeof keybuf;
        if (!dpif_flow_dump_next(&dump, &f)) {
            break;
        }

        if (f.key_len > sizeof keybuf) {
            VLOG_WARN_RL(&rl, "ODP flow key overflowed buffer");
            continue;
        }
        if (odp_flow_key_to_flow(f.key, f.key_len, &flow)) {
            struct ds s;

            ds_init(&s);
            odp_flow_key_format(f.key, f.key_len, &s);
            VLOG_WARN_RL(&rl, "failed to convert ODP flow key to flow: %s",
                         ds_cstr(&s));
            ds_destroy(&s);

            continue;
        }
        facet = facet_find(p, &flow);

        if (facet && facet->installed) {
            facet_update_time(p, facet, &f.stats);
            facet_account(p, facet, f.stats.n_bytes);
        } else {
            /* There's a flow in the datapath that we know nothing about.
             * Delete it. */
            COVERAGE_INC(ofproto_unexpected_rule);
            dpif_flow_del(p->dpif, &f);
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
     * made by ofproto_update_used(), because the former function never looks
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
        VLOG_INFO("%s: %s (msec:count)",
                  dpif_name(ofproto->dpif), ds_cstr(&s));
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
        struct odp_flow odp_flow;

        /* Get updated flow stats.
         *
         * XXX We could avoid this call entirely if (1) ofproto_update_used()
         * updated TCP flags and (2) the dpif_flow_list_all() in
         * ofproto_update_used() zeroed TCP flags. */
        memset(&odp_flow, 0, sizeof odp_flow);
        if (facet->installed) {
            uint32_t keybuf[ODPUTIL_FLOW_KEY_U32S];
            struct ofpbuf key;

            ofpbuf_use_stack(&key, keybuf, sizeof keybuf);
            odp_flow_key_from_flow(&key, &facet->flow);

            odp_flow.key = key.data;
            odp_flow.key_len = key.size;
            odp_flow.flags = ODPFF_ZERO_TCP_FLAGS;
            dpif_flow_get(ofproto->dpif, &odp_flow);

            if (odp_flow.stats.n_packets) {
                facet_update_time(ofproto, facet, &odp_flow.stats);
                netflow_flow_update_flags(&facet->nf_flow,
                                          odp_flow.stats.tcp_flags);
            }
        }

        expired.flow = facet->flow;
        expired.packet_count = facet->packet_count +
                               odp_flow.stats.n_packets;
        expired.byte_count = facet->byte_count + odp_flow.stats.n_bytes;
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

static struct ofpbuf *
compose_ofp_flow_removed(struct ofconn *ofconn, const struct rule *rule,
                         uint8_t reason)
{
    struct ofp_flow_removed *ofr;
    struct ofpbuf *buf;

    ofr = make_openflow_xid(sizeof *ofr, OFPT_FLOW_REMOVED, htonl(0), &buf);
    ofputil_cls_rule_to_match(&rule->cr, ofconn->flow_format, &ofr->match,
                              rule->flow_cookie, &ofr->cookie);
    ofr->priority = htons(rule->cr.priority);
    ofr->reason = reason;
    calc_flow_duration(rule->created, &ofr->duration_sec, &ofr->duration_nsec);
    ofr->idle_timeout = htons(rule->idle_timeout);
    ofr->packet_count = htonll(rule->packet_count);
    ofr->byte_count = htonll(rule->byte_count);

    return buf;
}

static struct ofpbuf *
compose_nx_flow_removed(const struct rule *rule, uint8_t reason)
{
    struct nx_flow_removed *nfr;
    struct ofpbuf *buf;
    int match_len;

    make_nxmsg_xid(sizeof *nfr, NXT_FLOW_REMOVED, htonl(0), &buf);
    match_len = nx_put_match(buf, &rule->cr);

    nfr = buf->data;
    nfr->cookie = rule->flow_cookie;
    nfr->priority = htons(rule->cr.priority);
    nfr->reason = reason;
    calc_flow_duration(rule->created, &nfr->duration_sec, &nfr->duration_nsec);
    nfr->idle_timeout = htons(rule->idle_timeout);
    nfr->match_len = htons(match_len);
    nfr->packet_count = htonll(rule->packet_count);
    nfr->byte_count = htonll(rule->byte_count);

    return buf;
}

static void
rule_send_removed(struct ofproto *p, struct rule *rule, uint8_t reason)
{
    struct ofconn *ofconn;

    if (!rule->send_flow_removed) {
        return;
    }

    LIST_FOR_EACH (ofconn, node, &p->all_conns) {
        struct ofpbuf *msg;

        if (!rconn_is_connected(ofconn->rconn)
            || !ofconn_receives_async_msgs(ofconn)) {
            continue;
        }

        msg = (ofconn->flow_format == NXFF_NXM
               ? compose_nx_flow_removed(rule, reason)
               : compose_ofp_flow_removed(ofconn, rule, reason));

        /* Account flow expirations under ofconn->reply_counter, the counter
         * for replies to OpenFlow requests.  That works because preventing
         * OpenFlow requests from being processed also prevents new flows from
         * being added (and expiring).  (It also prevents processing OpenFlow
         * requests that would not add new flows, so it is imperfect.) */
        queue_tx(msg, ofconn, ofconn->reply_counter);
    }
}

/* pinsched callback for sending 'ofp_packet_in' on 'ofconn'. */
static void
do_send_packet_in(struct ofpbuf *ofp_packet_in, void *ofconn_)
{
    struct ofconn *ofconn = ofconn_;

    rconn_send_with_limit(ofconn->rconn, ofp_packet_in,
                          ofconn->packet_in_counter, 100);
}

/* Takes 'upcall', whose packet has the flow specified by 'flow', composes an
 * OpenFlow packet-in message from it, and passes it to 'ofconn''s packet
 * scheduler for sending.
 *
 * If 'clone' is true, the caller retains ownership of 'upcall->packet'.
 * Otherwise, ownership is transferred to this function. */
static void
schedule_packet_in(struct ofconn *ofconn, struct dpif_upcall *upcall,
                   const struct flow *flow, bool clone)
{
    enum { OPI_SIZE = offsetof(struct ofp_packet_in, data) };
    struct ofproto *ofproto = ofconn->ofproto;
    struct ofp_packet_in *opi;
    int total_len, send_len;
    struct ofpbuf *packet;
    uint32_t buffer_id;

    /* Get OpenFlow buffer_id. */
    if (upcall->type == _ODPL_ACTION_NR) {
        buffer_id = UINT32_MAX;
    } else if (ofproto->fail_open && fail_open_is_active(ofproto->fail_open)) {
        buffer_id = pktbuf_get_null();
    } else if (!ofconn->pktbuf) {
        buffer_id = UINT32_MAX;
    } else {
        buffer_id = pktbuf_save(ofconn->pktbuf, upcall->packet, flow->in_port);
    }

    /* Figure out how much of the packet to send. */
    total_len = send_len = upcall->packet->size;
    if (buffer_id != UINT32_MAX) {
        send_len = MIN(send_len, ofconn->miss_send_len);
    }
    if (upcall->type == _ODPL_ACTION_NR) {
        send_len = MIN(send_len, upcall->userdata);
    }

    /* Copy or steal buffer for OFPT_PACKET_IN. */
    if (clone) {
        packet = ofpbuf_clone_data_with_headroom(upcall->packet->data,
                                                 send_len, OPI_SIZE);
    } else {
        packet = upcall->packet;
        packet->size = send_len;
    }

    /* Add OFPT_PACKET_IN. */
    opi = ofpbuf_push_zeros(packet, OPI_SIZE);
    opi->header.version = OFP_VERSION;
    opi->header.type = OFPT_PACKET_IN;
    opi->total_len = htons(total_len);
    opi->in_port = htons(odp_port_to_ofp_port(flow->in_port));
    opi->reason = upcall->type == _ODPL_MISS_NR ? OFPR_NO_MATCH : OFPR_ACTION;
    opi->buffer_id = htonl(buffer_id);
    update_openflow_length(packet);

    /* Hand over to packet scheduler.  It might immediately call into
     * do_send_packet_in() or it might buffer it for a while (until a later
     * call to pinsched_run()). */
    pinsched_send(ofconn->schedulers[opi->reason], flow->in_port,
                  packet, do_send_packet_in, ofconn);
}

/* Given 'upcall', of type _ODPL_ACTION_NR or _ODPL_MISS_NR, sends an
 * OFPT_PACKET_IN message to each OpenFlow controller as necessary according to
 * their individual configurations.
 *
 * Takes ownership of 'packet'. */
static void
send_packet_in(struct ofproto *ofproto, struct dpif_upcall *upcall,
               const struct flow *flow, bool clone)
{
    struct ofconn *ofconn, *prev;

    prev = NULL;
    LIST_FOR_EACH (ofconn, node, &ofproto->all_conns) {
        if (ofconn_receives_async_msgs(ofconn)) {
            if (prev) {
                schedule_packet_in(prev, upcall, flow, true);
            }
            prev = ofconn;
        }
    }
    if (prev) {
        schedule_packet_in(prev, upcall, flow, clone);
    } else if (!clone) {
        ofpbuf_delete(upcall->packet);
    }
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

static void
ofproto_unixctl_list(struct unixctl_conn *conn, const char *arg OVS_UNUSED,
                     void *aux OVS_UNUSED)
{
    const struct shash_node *node;
    struct ds results;

    ds_init(&results);
    SHASH_FOR_EACH (node, &all_ofprotos) {
        ds_put_format(&results, "%s\n", node->name);
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
trace_resubmit(struct action_xlate_ctx *ctx, const struct rule *rule)
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

    ofproto = shash_find_data(&all_ofprotos, dpname);
    if (!ofproto) {
        unixctl_command_reply(conn, 501, "Unknown ofproto (use ofproto/list "
                              "for help)");
        goto exit;
    }

    tun_id = htonll(strtoull(tun_id_s, NULL, 10));
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
ofproto_unixctl_init(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    unixctl_command_register("ofproto/list", ofproto_unixctl_list, NULL);
    unixctl_command_register("ofproto/trace", ofproto_unixctl_trace, NULL);
}

static bool
default_normal_ofhook_cb(const struct flow *flow, const struct ofpbuf *packet,
                         struct ofpbuf *odp_actions, tag_type *tags,
                         uint16_t *nf_output_iface, void *ofproto_)
{
    struct ofproto *ofproto = ofproto_;
    int out_port;

    /* Drop frames for reserved multicast addresses. */
    if (eth_addr_is_reserved(flow->dl_dst)) {
        return true;
    }

    /* Learn source MAC (but don't try to learn from revalidation). */
    if (packet != NULL) {
        tag_type rev_tag = mac_learning_learn(ofproto->ml, flow->dl_src,
                                              0, flow->in_port,
                                              GRAT_ARP_LOCK_NONE);
        if (rev_tag) {
            /* The log messages here could actually be useful in debugging,
             * so keep the rate limit relatively high. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
            VLOG_DBG_RL(&rl, "learned that "ETH_ADDR_FMT" is on port %"PRIu16,
                        ETH_ADDR_ARGS(flow->dl_src), flow->in_port);
            ofproto_revalidate(ofproto, rev_tag);
        }
    }

    /* Determine output port. */
    out_port = mac_learning_lookup_tag(ofproto->ml, flow->dl_dst, 0, tags,
                                       NULL);
    if (out_port < 0) {
        flood_packets(ofproto, flow->in_port, OFPPC_NO_FLOOD,
                      nf_output_iface, odp_actions);
    } else if (out_port != flow->in_port) {
        nl_msg_put_u32(odp_actions, ODPAT_OUTPUT, out_port);
        *nf_output_iface = out_port;
    } else {
        /* Drop. */
    }

    return true;
}

static const struct ofhooks default_ofhooks = {
    default_normal_ofhook_cb,
    NULL,
    NULL
};
