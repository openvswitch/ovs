/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include "classifier.h"
#include "coverage.h"
#include "discovery.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "fail-open.h"
#include "in-band.h"
#include "mac-learning.h"
#include "netdev.h"
#include "netflow.h"
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
#include "port-array.h"
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
#include "xtoxll.h"

VLOG_DEFINE_THIS_MODULE(ofproto)

#include "sflow_api.h"

enum {
    TABLEID_HASH = 0,
    TABLEID_CLASSIFIER = 1
};

struct ofport {
    struct netdev *netdev;
    struct ofp_phy_port opp;    /* In host byte order. */
};

static void ofport_free(struct ofport *);
static void hton_ofp_phy_port(struct ofp_phy_port *);

static int xlate_actions(const union ofp_action *in, size_t n_in,
                         const flow_t *flow, struct ofproto *ofproto,
                         const struct ofpbuf *packet,
                         struct odp_actions *out, tag_type *tags,
                         bool *may_set_up_flow, uint16_t *nf_output_iface);

struct rule {
    struct cls_rule cr;

    uint64_t flow_cookie;       /* Controller-issued identifier.
                                   (Kept in network-byte order.) */
    uint16_t idle_timeout;      /* In seconds from time of last use. */
    uint16_t hard_timeout;      /* In seconds from time of creation. */
    bool send_flow_removed;     /* Send a flow removed message? */
    long long int used;         /* Last-used time (0 if never used). */
    long long int created;      /* Creation time. */
    uint64_t packet_count;      /* Number of packets received. */
    uint64_t byte_count;        /* Number of bytes received. */
    uint64_t accounted_bytes;   /* Number of bytes passed to account_cb. */
    tag_type tags;              /* Tags (set only by hooks). */
    struct netflow_flow nf_flow; /* Per-flow NetFlow tracking data. */

    /* If 'super' is non-NULL, this rule is a subrule, that is, it is an
     * exact-match rule (having cr.wc.wildcards of 0) generated from the
     * wildcard rule 'super'.  In this case, 'list' is an element of the
     * super-rule's list.
     *
     * If 'super' is NULL, this rule is a super-rule, and 'list' is the head of
     * a list of subrules.  A super-rule with no wildcards (where
     * cr.wc.wildcards is 0) will never have any subrules. */
    struct rule *super;
    struct list list;

    /* OpenFlow actions.
     *
     * 'n_actions' is the number of elements in the 'actions' array.  A single
     * action may take up more more than one element's worth of space.
     *
     * A subrule has no actions (it uses the super-rule's actions). */
    int n_actions;
    union ofp_action *actions;

    /* Datapath actions.
     *
     * A super-rule with wildcard fields never has ODP actions (since the
     * datapath only supports exact-match flows). */
    bool installed;             /* Installed in datapath? */
    bool may_install;           /* True ordinarily; false if actions must
                                 * be reassessed for every packet. */
    int n_odp_actions;
    union odp_action *odp_actions;
};

static inline bool
rule_is_hidden(const struct rule *rule)
{
    /* Subrules are merely an implementation detail, so hide them from the
     * controller. */
    if (rule->super != NULL) {
        return true;
    }

    /* Rules with priority higher than UINT16_MAX are set up by ofproto itself
     * (e.g. by in-band control) and are intentionally hidden from the
     * controller. */
    if (rule->cr.priority > UINT16_MAX) {
        return true;
    }

    return false;
}

static struct rule *rule_create(struct ofproto *, struct rule *super,
                                const union ofp_action *, size_t n_actions,
                                uint16_t idle_timeout, uint16_t hard_timeout,
                                uint64_t flow_cookie, bool send_flow_removed);
static void rule_free(struct rule *);
static void rule_destroy(struct ofproto *, struct rule *);
static struct rule *rule_from_cls_rule(const struct cls_rule *);
static void rule_insert(struct ofproto *, struct rule *,
                        struct ofpbuf *packet, uint16_t in_port);
static void rule_remove(struct ofproto *, struct rule *);
static bool rule_make_actions(struct ofproto *, struct rule *,
                              const struct ofpbuf *packet);
static void rule_install(struct ofproto *, struct rule *,
                         struct rule *displaced_rule);
static void rule_uninstall(struct ofproto *, struct rule *);
static void rule_post_uninstall(struct ofproto *, struct rule *);
static void send_flow_removed(struct ofproto *p, struct rule *rule,
                              long long int now, uint8_t reason);

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
static void ofconn_run(struct ofconn *, struct ofproto *);
static void ofconn_wait(struct ofconn *);
static bool ofconn_receives_async_msgs(const struct ofconn *);
static char *ofconn_make_name(const struct ofproto *, const char *target);
static void ofconn_set_rate_limit(struct ofconn *, int rate, int burst);

static void queue_tx(struct ofpbuf *msg, const struct ofconn *ofconn,
                     struct rconn_packet_counter *counter);

static void send_packet_in(struct ofproto *, struct ofpbuf *odp_msg);
static void do_send_packet_in(struct ofpbuf *odp_msg, void *ofconn);

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
    struct port_array ports;    /* Index is ODP port nr; ofport->opp.port_no is
                                 * OFP port nr. */
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

    /* Flow table. */
    struct classifier cls;
    bool need_revalidate;
    long long int next_expiration;
    struct tag_set revalidate_set;
    bool tun_id_from_cookie;

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

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static const struct ofhooks default_ofhooks;

static uint64_t pick_datapath_id(const struct ofproto *);
static uint64_t pick_fallback_dpid(void);

static void update_used(struct ofproto *);
static void update_stats(struct ofproto *, struct rule *,
                         const struct odp_flow_stats *);
static void expire_rule(struct cls_rule *, void *ofproto);
static void active_timeout(struct ofproto *ofproto, struct rule *rule);
static bool revalidate_rule(struct ofproto *p, struct rule *rule);
static void revalidate_cb(struct cls_rule *rule_, void *p_);

static void handle_odp_msg(struct ofproto *, struct ofpbuf *);

static void handle_openflow(struct ofconn *, struct ofproto *,
                            struct ofpbuf *);

static void refresh_port_groups(struct ofproto *);

static void update_port(struct ofproto *, const char *devname);
static int init_ports(struct ofproto *);
static void reinit_ports(struct ofproto *);

int
ofproto_create(const char *datapath, const char *datapath_type,
               const struct ofhooks *ofhooks, void *aux,
               struct ofproto **ofprotop)
{
    struct odp_stats stats;
    struct ofproto *p;
    struct dpif *dpif;
    int error;

    *ofprotop = NULL;

    /* Connect to datapath and start listening for messages. */
    error = dpif_open(datapath, datapath_type, &dpif);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s", datapath, strerror(error));
        return error;
    }
    error = dpif_get_dp_stats(dpif, &stats);
    if (error) {
        VLOG_ERR("failed to obtain stats for datapath %s: %s",
                 datapath, strerror(error));
        dpif_close(dpif);
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
    port_array_init(&p->ports);
    shash_init(&p->port_by_name);
    p->max_ports = stats.max_ports;

    /* Initialize submodules. */
    p->switch_status = switch_status_create(p);
    p->in_band = NULL;
    p->fail_open = NULL;
    p->netflow = NULL;
    p->sflow = NULL;

    /* Initialize flow table. */
    classifier_init(&p->cls);
    p->need_revalidate = false;
    p->next_expiration = time_msec() + 1000;
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

    HMAP_FOR_EACH_WITH_HASH (ofconn, struct ofconn, hmap_node,
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
    HMAP_FOR_EACH (ofconn, struct ofconn, hmap_node, &ofproto->controllers) {
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
        HMAP_FOR_EACH (ofconn, struct ofconn, hmap_node, &p->controllers) {
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
    HMAP_FOR_EACH_SAFE (ofconn, next_ofconn, struct ofconn, hmap_node,
                        &p->controllers) {
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
    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, struct ofservice, node,
                        &p->services) {
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

    LIST_FOR_EACH (ofconn, struct ofconn, node, &ofproto->all_conns) {
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
            unsigned int odp_port;

            os = ofproto->sflow = ofproto_sflow_create(ofproto->dpif);
            refresh_port_groups(ofproto);
            PORT_ARRAY_FOR_EACH (ofport, &ofproto->ports, odp_port) {
                ofproto_sflow_add_port(os, odp_port,
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
    struct ofport *ofport;
    unsigned int port_no;
    size_t i;

    if (!p) {
        return;
    }

    /* Destroy fail-open and in-band early, since they touch the classifier. */
    fail_open_destroy(p->fail_open);
    p->fail_open = NULL;

    in_band_destroy(p->in_band);
    p->in_band = NULL;
    free(p->extra_in_band_remotes);

    ofproto_flush_flows(p);
    classifier_destroy(&p->cls);

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, struct ofconn, node,
                        &p->all_conns) {
        ofconn_destroy(ofconn);
    }
    hmap_destroy(&p->controllers);

    dpif_close(p->dpif);
    netdev_monitor_destroy(p->netdev_monitor);
    PORT_ARRAY_FOR_EACH (ofport, &p->ports, port_no) {
        ofport_free(ofport);
    }
    shash_destroy(&p->port_by_name);

    switch_status_destroy(p->switch_status);
    netflow_destroy(p->netflow);
    ofproto_sflow_destroy(p->sflow);

    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, struct ofservice, node,
                        &p->services) {
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

    port_array_destroy(&p->ports);

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
    LIST_FOR_EACH (ofconn, struct ofconn, node, &ofproto->all_conns) {
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
        struct ofpbuf *buf;
        int error;

        error = dpif_recv(p->dpif, &buf);
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

        handle_odp_msg(p, buf);
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

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, struct ofconn, node,
                        &p->all_conns) {
        ofconn_run(ofconn, p);
    }

    /* Fail-open maintenance.  Do this after processing the ofconns since
     * fail-open checks the status of the controller rconn. */
    if (p->fail_open) {
        fail_open_run(p->fail_open);
    }

    HMAP_FOR_EACH (ofservice, struct ofservice, node, &p->services) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(ofservice->pvconn, OFP_VERSION, &vconn);
        if (!retval) {
            struct ofconn *ofconn;
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
        COVERAGE_INC(ofproto_expiration);
        p->next_expiration = time_msec() + 1000;
        update_used(p);

        classifier_for_each(&p->cls, CLS_INC_ALL, expire_rule, p);

        /* Let the hook know that we're at a stable point: all outstanding data
         * in existing flows has been accounted to the account_cb.  Thus, the
         * hook can now reasonably do operations that depend on having accurate
         * flow volume accounting (currently, that's just bond rebalancing). */
        if (p->ofhooks->account_checkpoint_cb) {
            p->ofhooks->account_checkpoint_cb(p->aux);
        }
    }

    if (p->netflow) {
        netflow_run(p->netflow);
    }
    if (p->sflow) {
        ofproto_sflow_run(p->sflow);
    }

    return 0;
}

struct revalidate_cbdata {
    struct ofproto *ofproto;
    bool revalidate_all;        /* Revalidate all exact-match rules? */
    bool revalidate_subrules;   /* Revalidate all exact-match subrules? */
    struct tag_set revalidate_set; /* Set of tags to revalidate. */
};

int
ofproto_run2(struct ofproto *p, bool revalidate_all)
{
    if (p->need_revalidate || revalidate_all
        || !tag_set_is_empty(&p->revalidate_set)) {
        struct revalidate_cbdata cbdata;
        cbdata.ofproto = p;
        cbdata.revalidate_all = revalidate_all;
        cbdata.revalidate_subrules = p->need_revalidate;
        cbdata.revalidate_set = p->revalidate_set;
        tag_set_init(&p->revalidate_set);
        COVERAGE_INC(ofproto_revalidate);
        classifier_for_each(&p->cls, CLS_INC_EXACT, revalidate_cb, &cbdata);
        p->need_revalidate = false;
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
    LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
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
    HMAP_FOR_EACH (ofservice, struct ofservice, node, &p->services) {
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

int
ofproto_send_packet(struct ofproto *p, const flow_t *flow,
                    const union ofp_action *actions, size_t n_actions,
                    const struct ofpbuf *packet)
{
    struct odp_actions odp_actions;
    int error;

    error = xlate_actions(actions, n_actions, flow, p, packet, &odp_actions,
                          NULL, NULL, NULL);
    if (error) {
        return error;
    }

    /* XXX Should we translate the dpif_execute() errno value into an OpenFlow
     * error code? */
    dpif_execute(p->dpif, flow->in_port, odp_actions.actions,
                 odp_actions.n_actions, packet);
    return 0;
}

void
ofproto_add_flow(struct ofproto *p,
                 const flow_t *flow, uint32_t wildcards, unsigned int priority,
                 const union ofp_action *actions, size_t n_actions,
                 int idle_timeout)
{
    struct rule *rule;
    rule = rule_create(p, NULL, actions, n_actions,
                       idle_timeout >= 0 ? idle_timeout : 5 /* XXX */,
                       0, 0, false);
    cls_rule_from_flow(flow, wildcards, priority, &rule->cr);
    rule_insert(p, rule, NULL, 0);
}

void
ofproto_delete_flow(struct ofproto *ofproto, const flow_t *flow,
                    uint32_t wildcards, unsigned int priority)
{
    struct rule *rule;

    rule = rule_from_cls_rule(classifier_find_rule_exactly(&ofproto->cls,
                                                           flow, wildcards,
                                                           priority));
    if (rule) {
        rule_remove(ofproto, rule);
    }
}

static void
destroy_rule(struct cls_rule *rule_, void *ofproto_)
{
    struct rule *rule = rule_from_cls_rule(rule_);
    struct ofproto *ofproto = ofproto_;

    /* Mark the flow as not installed, even though it might really be
     * installed, so that rule_remove() doesn't bother trying to uninstall it.
     * There is no point in uninstalling it individually since we are about to
     * blow away all the flows with dpif_flow_flush(). */
    rule->installed = false;

    rule_remove(ofproto, rule);
}

void
ofproto_flush_flows(struct ofproto *ofproto)
{
    COVERAGE_INC(ofproto_flush);
    classifier_for_each(&ofproto->cls, CLS_INC_ALL, destroy_rule, ofproto);
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
    struct svec devnames;
    struct ofport *ofport;
    unsigned int port_no;
    struct odp_port *odp_ports;
    size_t n_odp_ports;
    size_t i;

    svec_init(&devnames);
    PORT_ARRAY_FOR_EACH (ofport, &p->ports, port_no) {
        svec_add (&devnames, (char *) ofport->opp.name);
    }
    dpif_port_list(p->dpif, &odp_ports, &n_odp_ports);
    for (i = 0; i < n_odp_ports; i++) {
        svec_add (&devnames, odp_ports[i].devname);
    }
    free(odp_ports);

    svec_sort_unique(&devnames);
    for (i = 0; i < devnames.n; i++) {
        update_port(p, devnames.names[i]);
    }
    svec_destroy(&devnames);
}

static size_t
refresh_port_group(struct ofproto *p, unsigned int group)
{
    uint16_t *ports;
    size_t n_ports;
    struct ofport *port;
    unsigned int port_no;

    assert(group == DP_GROUP_ALL || group == DP_GROUP_FLOOD);

    ports = xmalloc(port_array_count(&p->ports) * sizeof *ports);
    n_ports = 0;
    PORT_ARRAY_FOR_EACH (port, &p->ports, port_no) {
        if (group == DP_GROUP_ALL || !(port->opp.config & OFPPC_NO_FLOOD)) {
            ports[n_ports++] = port_no;
        }
    }
    dpif_port_group_set(p->dpif, group, ports, n_ports);
    free(ports);

    return n_ports;
}

static void
refresh_port_groups(struct ofproto *p)
{
    size_t n_flood = refresh_port_group(p, DP_GROUP_FLOOD);
    size_t n_all = refresh_port_group(p, DP_GROUP_ALL);
    if (p->sflow) {
        ofproto_sflow_set_group_sizes(p->sflow, n_flood, n_all);
    }
}

static struct ofport *
make_ofport(const struct odp_port *odp_port)
{
    struct netdev_options netdev_options;
    enum netdev_flags flags;
    struct ofport *ofport;
    struct netdev *netdev;
    bool carrier;
    int error;

    memset(&netdev_options, 0, sizeof netdev_options);
    netdev_options.name = odp_port->devname;
    netdev_options.ethertype = NETDEV_ETH_TYPE_NONE;

    error = netdev_open(&netdev_options, &netdev);
    if (error) {
        VLOG_WARN_RL(&rl, "ignoring port %s (%"PRIu16") because netdev %s "
                     "cannot be opened (%s)",
                     odp_port->devname, odp_port->port,
                     odp_port->devname, strerror(error));
        return NULL;
    }

    ofport = xmalloc(sizeof *ofport);
    ofport->netdev = netdev;
    ofport->opp.port_no = odp_port_to_ofp_port(odp_port->port);
    netdev_get_etheraddr(netdev, ofport->opp.hw_addr);
    memcpy(ofport->opp.name, odp_port->devname,
           MIN(sizeof ofport->opp.name, sizeof odp_port->devname));
    ofport->opp.name[sizeof ofport->opp.name - 1] = '\0';

    netdev_get_flags(netdev, &flags);
    ofport->opp.config = flags & NETDEV_UP ? 0 : OFPPC_PORT_DOWN;

    netdev_get_carrier(netdev, &carrier);
    ofport->opp.state = carrier ? 0 : OFPPS_LINK_DOWN;

    netdev_get_features(netdev,
                        &ofport->opp.curr, &ofport->opp.advertised,
                        &ofport->opp.supported, &ofport->opp.peer);
    return ofport;
}

static bool
ofport_conflicts(const struct ofproto *p, const struct odp_port *odp_port)
{
    if (port_array_get(&p->ports, odp_port->port)) {
        VLOG_WARN_RL(&rl, "ignoring duplicate port %"PRIu16" in datapath",
                     odp_port->port);
        return true;
    } else if (shash_find(&p->port_by_name, odp_port->devname)) {
        VLOG_WARN_RL(&rl, "ignoring duplicate device %s in datapath",
                     odp_port->devname);
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
            && !strcmp((char *) a->name, (char *) b->name)
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
    LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
        struct ofp_port_status *ops;
        struct ofpbuf *b;

        if (!ofconn_receives_async_msgs(ofconn)) {
            continue;
        }

        ops = make_openflow_xid(sizeof *ops, OFPT_PORT_STATUS, 0, &b);
        ops->reason = reason;
        ops->desc = ofport->opp;
        hton_ofp_phy_port(&ops->desc);
        queue_tx(b, ofconn, NULL);
    }
    if (p->ofhooks->port_changed_cb) {
        p->ofhooks->port_changed_cb(reason, &ofport->opp, p->aux);
    }
}

static void
ofport_install(struct ofproto *p, struct ofport *ofport)
{
    uint16_t odp_port = ofp_port_to_odp_port(ofport->opp.port_no);
    const char *netdev_name = (const char *) ofport->opp.name;

    netdev_monitor_add(p->netdev_monitor, ofport->netdev);
    port_array_set(&p->ports, odp_port, ofport);
    shash_add(&p->port_by_name, netdev_name, ofport);
    if (p->sflow) {
        ofproto_sflow_add_port(p->sflow, odp_port, netdev_name);
    }
}

static void
ofport_remove(struct ofproto *p, struct ofport *ofport)
{
    uint16_t odp_port = ofp_port_to_odp_port(ofport->opp.port_no);

    netdev_monitor_remove(p->netdev_monitor, ofport->netdev);
    port_array_delete(&p->ports, odp_port);
    shash_delete(&p->port_by_name,
                 shash_find(&p->port_by_name, (char *) ofport->opp.name));
    if (p->sflow) {
        ofproto_sflow_del_port(p->sflow, odp_port);
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

static void
update_port(struct ofproto *p, const char *devname)
{
    struct odp_port odp_port;
    struct ofport *old_ofport;
    struct ofport *new_ofport;
    int error;

    COVERAGE_INC(ofproto_update_port);

    /* Query the datapath for port information. */
    error = dpif_port_query_by_name(p->dpif, devname, &odp_port);

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
            old_ofport = port_array_get(&p->ports, odp_port.port);
        }
    } else if (error != ENOENT && error != ENODEV) {
        VLOG_WARN_RL(&rl, "dpif_port_query_by_name returned unexpected error "
                     "%s", strerror(error));
        return;
    }

    /* Create a new ofport. */
    new_ofport = !error ? make_ofport(&odp_port) : NULL;

    /* Eliminate a few pathological cases. */
    if (!old_ofport && !new_ofport) {
        return;
    } else if (old_ofport && new_ofport) {
        /* Most of the 'config' bits are OpenFlow soft state, but
         * OFPPC_PORT_DOWN is maintained the kernel.  So transfer the OpenFlow
         * bits from old_ofport.  (make_ofport() only sets OFPPC_PORT_DOWN and
         * leaves the other bits 0.)  */
        new_ofport->opp.config |= old_ofport->opp.config & ~OFPPC_PORT_DOWN;

        if (ofport_equal(old_ofport, new_ofport)) {
            /* False alarm--no change. */
            ofport_free(new_ofport);
            return;
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

    /* Update port groups. */
    refresh_port_groups(p);
}

static int
init_ports(struct ofproto *p)
{
    struct odp_port *ports;
    size_t n_ports;
    size_t i;
    int error;

    error = dpif_port_list(p->dpif, &ports, &n_ports);
    if (error) {
        return error;
    }

    for (i = 0; i < n_ports; i++) {
        const struct odp_port *odp_port = &ports[i];
        if (!ofport_conflicts(p, odp_port)) {
            struct ofport *ofport = make_ofport(odp_port);
            if (ofport) {
                ofport_install(p, ofport);
            }
        }
    }
    free(ports);
    refresh_port_groups(p);
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
ofconn_run(struct ofconn *ofconn, struct ofproto *p)
{
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
            handle_openflow(ofconn, p, of_msg);
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

    HMAP_FOR_EACH_WITH_HASH (ofservice, struct ofservice, node,
                             hash_string(target, 0), &ofproto->services) {
        if (!strcmp(pvconn_get_name(ofservice->pvconn), target)) {
            return ofservice;
        }
    }
    return NULL;
}

/* Caller is responsible for initializing the 'cr' member of the returned
 * rule. */
static struct rule *
rule_create(struct ofproto *ofproto, struct rule *super,
            const union ofp_action *actions, size_t n_actions,
            uint16_t idle_timeout, uint16_t hard_timeout,
            uint64_t flow_cookie, bool send_flow_removed)
{
    struct rule *rule = xzalloc(sizeof *rule);
    rule->idle_timeout = idle_timeout;
    rule->hard_timeout = hard_timeout;
    rule->flow_cookie = flow_cookie;
    rule->used = rule->created = time_msec();
    rule->send_flow_removed = send_flow_removed;
    rule->super = super;
    if (super) {
        list_push_back(&super->list, &rule->list);
    } else {
        list_init(&rule->list);
    }
    rule->n_actions = n_actions;
    rule->actions = xmemdup(actions, n_actions * sizeof *actions);
    netflow_flow_clear(&rule->nf_flow);
    netflow_flow_update_time(ofproto->netflow, &rule->nf_flow, rule->created);

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
    free(rule->odp_actions);
    free(rule);
}

/* Destroys 'rule'.  If 'rule' is a subrule, also removes it from its
 * super-rule's list of subrules.  If 'rule' is a super-rule, also iterates
 * through all of its subrules and revalidates them, destroying any that no
 * longer has a super-rule (which is probably all of them).
 *
 * Before calling this function, the caller must make have removed 'rule' from
 * the classifier.  If 'rule' is an exact-match rule, the caller is also
 * responsible for ensuring that it has been uninstalled from the datapath. */
static void
rule_destroy(struct ofproto *ofproto, struct rule *rule)
{
    if (!rule->super) {
        struct rule *subrule, *next;
        LIST_FOR_EACH_SAFE (subrule, next, struct rule, list, &rule->list) {
            revalidate_rule(ofproto, subrule);
        }
    } else {
        list_remove(&rule->list);
    }
    rule_free(rule);
}

static bool
rule_has_out_port(const struct rule *rule, uint16_t out_port)
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
execute_odp_actions(struct ofproto *ofproto, uint16_t in_port,
                    const union odp_action *actions, size_t n_actions,
                    struct ofpbuf *packet)
{
    if (n_actions == 1 && actions[0].type == ODPAT_CONTROLLER) {
        /* As an optimization, avoid a round-trip from userspace to kernel to
         * userspace.  This also avoids possibly filling up kernel packet
         * buffers along the way. */
        struct odp_msg *msg;

        msg = ofpbuf_push_uninit(packet, sizeof *msg);
        msg->type = _ODPL_ACTION_NR;
        msg->length = sizeof(struct odp_msg) + packet->size;
        msg->port = in_port;
        msg->reserved = 0;
        msg->arg = actions[0].controller.arg;

        send_packet_in(ofproto, packet);

        return true;
    } else {
        int error;

        error = dpif_execute(ofproto->dpif, in_port,
                             actions, n_actions, packet);
        ofpbuf_delete(packet);
        return !error;
    }
}

/* Executes the actions indicated by 'rule' on 'packet', which is in flow
 * 'flow' and is considered to have arrived on ODP port 'in_port'.  'packet'
 * must have at least sizeof(struct ofp_packet_in) bytes of headroom.
 *
 * The flow that 'packet' actually contains does not need to actually match
 * 'rule'; the actions in 'rule' will be applied to it either way.  Likewise,
 * the packet and byte counters for 'rule' will be credited for the packet sent
 * out whether or not the packet actually matches 'rule'.
 *
 * If 'rule' is an exact-match rule and 'flow' actually equals the rule's flow,
 * the caller must already have accurately composed ODP actions for it given
 * 'packet' using rule_make_actions().  If 'rule' is a wildcard rule, or if
 * 'rule' is an exact-match rule but 'flow' is not the rule's flow, then this
 * function will compose a set of ODP actions based on 'rule''s OpenFlow
 * actions and apply them to 'packet'.
 *
 * Takes ownership of 'packet'. */
static void
rule_execute(struct ofproto *ofproto, struct rule *rule,
             struct ofpbuf *packet, const flow_t *flow)
{
    const union odp_action *actions;
    struct odp_flow_stats stats;
    size_t n_actions;
    struct odp_actions a;

    assert(ofpbuf_headroom(packet) >= sizeof(struct ofp_packet_in));

    /* Grab or compose the ODP actions.
     *
     * The special case for an exact-match 'rule' where 'flow' is not the
     * rule's flow is important to avoid, e.g., sending a packet out its input
     * port simply because the ODP actions were composed for the wrong
     * scenario. */
    if (rule->cr.wc.wildcards || !flow_equal(flow, &rule->cr.flow)) {
        struct rule *super = rule->super ? rule->super : rule;
        if (xlate_actions(super->actions, super->n_actions, flow, ofproto,
                          packet, &a, NULL, 0, NULL)) {
            ofpbuf_delete(packet);
            return;
        }
        actions = a.actions;
        n_actions = a.n_actions;
    } else {
        actions = rule->odp_actions;
        n_actions = rule->n_odp_actions;
    }

    /* Execute the ODP actions. */
    flow_extract_stats(flow, packet, &stats);
    if (execute_odp_actions(ofproto, flow->in_port,
                            actions, n_actions, packet)) {
        update_stats(ofproto, rule, &stats);
        rule->used = time_msec();
        netflow_flow_update_time(ofproto->netflow, &rule->nf_flow, rule->used);
    }
}

/* Inserts 'rule' into 'p''s flow table.
 *
 * If 'packet' is nonnull, takes ownership of 'packet', executes 'rule''s
 * actions on it and credits the statistics for sending the packet to 'rule'.
 * 'packet' must have at least sizeof(struct ofp_packet_in) bytes of
 * headroom. */
static void
rule_insert(struct ofproto *p, struct rule *rule, struct ofpbuf *packet,
            uint16_t in_port)
{
    struct rule *displaced_rule;

    /* Insert the rule in the classifier. */
    displaced_rule = rule_from_cls_rule(classifier_insert(&p->cls, &rule->cr));
    if (!rule->cr.wc.wildcards) {
        rule_make_actions(p, rule, packet);
    }

    /* Send the packet and credit it to the rule. */
    if (packet) {
        flow_t flow;
        flow_extract(packet, 0, in_port, &flow);
        rule_execute(p, rule, packet, &flow);
    }

    /* Install the rule in the datapath only after sending the packet, to
     * avoid packet reordering.  */
    if (rule->cr.wc.wildcards) {
        COVERAGE_INC(ofproto_add_wc_flow);
        p->need_revalidate = true;
    } else {
        rule_install(p, rule, displaced_rule);
    }

    /* Free the rule that was displaced, if any. */
    if (displaced_rule) {
        rule_destroy(p, displaced_rule);
    }
}

static struct rule *
rule_create_subrule(struct ofproto *ofproto, struct rule *rule,
                    const flow_t *flow)
{
    struct rule *subrule = rule_create(ofproto, rule, NULL, 0,
                                       rule->idle_timeout, rule->hard_timeout,
                                       0, false);
    COVERAGE_INC(ofproto_subrule_create);
    cls_rule_from_flow(flow, 0, (rule->cr.priority <= UINT16_MAX ? UINT16_MAX
                        : rule->cr.priority), &subrule->cr);
    classifier_insert_exact(&ofproto->cls, &subrule->cr);

    return subrule;
}

static void
rule_remove(struct ofproto *ofproto, struct rule *rule)
{
    if (rule->cr.wc.wildcards) {
        COVERAGE_INC(ofproto_del_wc_flow);
        ofproto->need_revalidate = true;
    } else {
        rule_uninstall(ofproto, rule);
    }
    classifier_remove(&ofproto->cls, &rule->cr);
    rule_destroy(ofproto, rule);
}

/* Returns true if the actions changed, false otherwise. */
static bool
rule_make_actions(struct ofproto *p, struct rule *rule,
                  const struct ofpbuf *packet)
{
    const struct rule *super;
    struct odp_actions a;
    size_t actions_len;

    assert(!rule->cr.wc.wildcards);

    super = rule->super ? rule->super : rule;
    rule->tags = 0;
    xlate_actions(super->actions, super->n_actions, &rule->cr.flow, p,
                  packet, &a, &rule->tags, &rule->may_install,
                  &rule->nf_flow.output_iface);

    actions_len = a.n_actions * sizeof *a.actions;
    if (rule->n_odp_actions != a.n_actions
        || memcmp(rule->odp_actions, a.actions, actions_len)) {
        COVERAGE_INC(ofproto_odp_unchanged);
        free(rule->odp_actions);
        rule->n_odp_actions = a.n_actions;
        rule->odp_actions = xmemdup(a.actions, actions_len);
        return true;
    } else {
        return false;
    }
}

static int
do_put_flow(struct ofproto *ofproto, struct rule *rule, int flags,
            struct odp_flow_put *put)
{
    memset(&put->flow.stats, 0, sizeof put->flow.stats);
    put->flow.key = rule->cr.flow;
    put->flow.actions = rule->odp_actions;
    put->flow.n_actions = rule->n_odp_actions;
    put->flow.flags = 0;
    put->flags = flags;
    return dpif_flow_put(ofproto->dpif, put);
}

static void
rule_install(struct ofproto *p, struct rule *rule, struct rule *displaced_rule)
{
    assert(!rule->cr.wc.wildcards);

    if (rule->may_install) {
        struct odp_flow_put put;
        if (!do_put_flow(p, rule,
                         ODPPF_CREATE | ODPPF_MODIFY | ODPPF_ZERO_STATS,
                         &put)) {
            rule->installed = true;
            if (displaced_rule) {
                update_stats(p, displaced_rule, &put.flow.stats);
                rule_post_uninstall(p, displaced_rule);
            }
        }
    } else if (displaced_rule) {
        rule_uninstall(p, displaced_rule);
    }
}

static void
rule_reinstall(struct ofproto *ofproto, struct rule *rule)
{
    if (rule->installed) {
        struct odp_flow_put put;
        COVERAGE_INC(ofproto_dp_missed);
        do_put_flow(ofproto, rule, ODPPF_CREATE | ODPPF_MODIFY, &put);
    } else {
        rule_install(ofproto, rule, NULL);
    }
}

static void
rule_update_actions(struct ofproto *ofproto, struct rule *rule)
{
    bool actions_changed;
    uint16_t new_out_iface, old_out_iface;

    old_out_iface = rule->nf_flow.output_iface;
    actions_changed = rule_make_actions(ofproto, rule, NULL);

    if (rule->may_install) {
        if (rule->installed) {
            if (actions_changed) {
                struct odp_flow_put put;
                do_put_flow(ofproto, rule, ODPPF_CREATE | ODPPF_MODIFY
                                           | ODPPF_ZERO_STATS, &put);
                update_stats(ofproto, rule, &put.flow.stats);

                /* Temporarily set the old output iface so that NetFlow
                 * messages have the correct output interface for the old
                 * stats. */
                new_out_iface = rule->nf_flow.output_iface;
                rule->nf_flow.output_iface = old_out_iface;
                rule_post_uninstall(ofproto, rule);
                rule->nf_flow.output_iface = new_out_iface;
            }
        } else {
            rule_install(ofproto, rule, NULL);
        }
    } else {
        rule_uninstall(ofproto, rule);
    }
}

static void
rule_account(struct ofproto *ofproto, struct rule *rule, uint64_t extra_bytes)
{
    uint64_t total_bytes = rule->byte_count + extra_bytes;

    if (ofproto->ofhooks->account_flow_cb
        && total_bytes > rule->accounted_bytes)
    {
        ofproto->ofhooks->account_flow_cb(
            &rule->cr.flow, rule->tags, rule->odp_actions, rule->n_odp_actions,
            total_bytes - rule->accounted_bytes, ofproto->aux);
        rule->accounted_bytes = total_bytes;
    }
}

static void
rule_uninstall(struct ofproto *p, struct rule *rule)
{
    assert(!rule->cr.wc.wildcards);
    if (rule->installed) {
        struct odp_flow odp_flow;

        odp_flow.key = rule->cr.flow;
        odp_flow.actions = NULL;
        odp_flow.n_actions = 0;
        odp_flow.flags = 0;
        if (!dpif_flow_del(p->dpif, &odp_flow)) {
            update_stats(p, rule, &odp_flow.stats);
        }
        rule->installed = false;

        rule_post_uninstall(p, rule);
    }
}

static bool
is_controller_rule(struct rule *rule)
{
    /* If the only action is send to the controller then don't report
     * NetFlow expiration messages since it is just part of the control
     * logic for the network and not real traffic. */

    return (rule
            && rule->super
            && rule->super->n_actions == 1
            && action_outputs_to_port(&rule->super->actions[0],
                                      htons(OFPP_CONTROLLER)));
}

static void
rule_post_uninstall(struct ofproto *ofproto, struct rule *rule)
{
    struct rule *super = rule->super;

    rule_account(ofproto, rule, 0);

    if (ofproto->netflow && !is_controller_rule(rule)) {
        struct ofexpired expired;
        expired.flow = rule->cr.flow;
        expired.packet_count = rule->packet_count;
        expired.byte_count = rule->byte_count;
        expired.used = rule->used;
        netflow_expire(ofproto->netflow, &rule->nf_flow, &expired);
    }
    if (super) {
        super->packet_count += rule->packet_count;
        super->byte_count += rule->byte_count;

        /* Reset counters to prevent double counting if the rule ever gets
         * reinstalled. */
        rule->packet_count = 0;
        rule->byte_count = 0;
        rule->accounted_bytes = 0;

        netflow_flow_clear(&rule->nf_flow);
    }
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
send_error(const struct ofconn *ofconn, const struct ofp_header *oh,
           int error, const void *data, size_t len)
{
    struct ofpbuf *buf;
    struct ofp_error_msg *oem;

    if (!(error >> 16)) {
        VLOG_WARN_RL(&rl, "not sending bad error code %d to controller",
                     error);
        return;
    }

    COVERAGE_INC(ofproto_error);
    oem = make_openflow_xid(len + sizeof *oem, OFPT_ERROR,
                            oh ? oh->xid : 0, &buf);
    oem->type = htons((unsigned int) error >> 16);
    oem->code = htons(error & 0xffff);
    memcpy(oem->data, data, len);
    queue_tx(buf, ofconn, ofconn->reply_counter);
}

static void
send_error_oh(const struct ofconn *ofconn, const struct ofp_header *oh,
              int error)
{
    size_t oh_length = ntohs(oh->length);
    send_error(ofconn, oh, error, oh, MIN(oh_length, 64));
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
handle_echo_request(struct ofconn *ofconn, struct ofp_header *oh)
{
    struct ofp_header *rq = oh;
    queue_tx(make_echo_reply(rq), ofconn, ofconn->reply_counter);
    return 0;
}

static int
handle_features_request(struct ofproto *p, struct ofconn *ofconn,
                        struct ofp_header *oh)
{
    struct ofp_switch_features *osf;
    struct ofpbuf *buf;
    unsigned int port_no;
    struct ofport *port;

    osf = make_openflow_xid(sizeof *osf, OFPT_FEATURES_REPLY, oh->xid, &buf);
    osf->datapath_id = htonll(p->datapath_id);
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

    PORT_ARRAY_FOR_EACH (port, &p->ports, port_no) {
        hton_ofp_phy_port(ofpbuf_put(buf, &port->opp, sizeof port->opp));
    }

    queue_tx(buf, ofconn, ofconn->reply_counter);
    return 0;
}

static int
handle_get_config_request(struct ofproto *p, struct ofconn *ofconn,
                          struct ofp_header *oh)
{
    struct ofpbuf *buf;
    struct ofp_switch_config *osc;
    uint16_t flags;
    bool drop_frags;

    /* Figure out flags. */
    dpif_get_drop_frags(p->dpif, &drop_frags);
    flags = drop_frags ? OFPC_FRAG_DROP : OFPC_FRAG_NORMAL;

    /* Send reply. */
    osc = make_openflow_xid(sizeof *osc, OFPT_GET_CONFIG_REPLY, oh->xid, &buf);
    osc->flags = htons(flags);
    osc->miss_send_len = htons(ofconn->miss_send_len);
    queue_tx(buf, ofconn, ofconn->reply_counter);

    return 0;
}

static int
handle_set_config(struct ofproto *p, struct ofconn *ofconn,
                  struct ofp_switch_config *osc)
{
    uint16_t flags;
    int error;

    error = check_ofp_message(&osc->header, OFPT_SET_CONFIG, sizeof *osc);
    if (error) {
        return error;
    }
    flags = ntohs(osc->flags);

    if (ofconn->type == OFCONN_PRIMARY && ofconn->role != NX_ROLE_SLAVE) {
        switch (flags & OFPC_FRAG_MASK) {
        case OFPC_FRAG_NORMAL:
            dpif_set_drop_frags(p->dpif, false);
            break;
        case OFPC_FRAG_DROP:
            dpif_set_drop_frags(p->dpif, true);
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

static void
add_output_group_action(struct odp_actions *actions, uint16_t group,
                        uint16_t *nf_output_iface)
{
    odp_actions_add(actions, ODPAT_OUTPUT_GROUP)->output_group.group = group;

    if (group == DP_GROUP_ALL || group == DP_GROUP_FLOOD) {
        *nf_output_iface = NF_OUT_FLOOD;
    }
}

static void
add_controller_action(struct odp_actions *actions, uint16_t max_len)
{
    union odp_action *a = odp_actions_add(actions, ODPAT_CONTROLLER);
    a->controller.arg = max_len;
}

struct action_xlate_ctx {
    /* Input. */
    flow_t flow;                /* Flow to which these actions correspond. */
    int recurse;                /* Recursion level, via xlate_table_action. */
    struct ofproto *ofproto;
    const struct ofpbuf *packet; /* The packet corresponding to 'flow', or a
                                  * null pointer if we are revalidating
                                  * without a packet to refer to. */

    /* Output. */
    struct odp_actions *out;    /* Datapath actions. */
    tag_type *tags;             /* Tags associated with OFPP_NORMAL actions. */
    bool may_set_up_flow;       /* True ordinarily; false if the actions must
                                 * be reassessed for every packet. */
    uint16_t nf_output_iface;   /* Output interface index for NetFlow. */
};

/* Maximum depth of flow table recursion (due to NXAST_RESUBMIT actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 8

static void do_xlate_actions(const union ofp_action *in, size_t n_in,
                             struct action_xlate_ctx *ctx);

static void
add_output_action(struct action_xlate_ctx *ctx, uint16_t port)
{
    const struct ofport *ofport = port_array_get(&ctx->ofproto->ports, port);

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

    odp_actions_add(ctx->out, ODPAT_OUTPUT)->output.port = port;
    ctx->nf_output_iface = port;
}

static struct rule *
lookup_valid_rule(struct ofproto *ofproto, const flow_t *flow)
{
    struct rule *rule;
    rule = rule_from_cls_rule(classifier_lookup(&ofproto->cls, flow));

    /* The rule we found might not be valid, since we could be in need of
     * revalidation.  If it is not valid, don't return it. */
    if (rule
        && rule->super
        && ofproto->need_revalidate
        && !revalidate_rule(ofproto, rule)) {
        COVERAGE_INC(ofproto_invalidated);
        return NULL;
    }

    return rule;
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
        rule = lookup_valid_rule(ctx->ofproto, &ctx->flow);
        ctx->flow.in_port = old_in_port;

        if (rule) {
            if (rule->super) {
                rule = rule->super;
            }

            ctx->recurse++;
            do_xlate_actions(rule->actions, rule->n_actions, ctx);
            ctx->recurse--;
        }
    } else {
        struct vlog_rate_limit recurse_rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&recurse_rl, "NXAST_RESUBMIT recursed over %d times",
                    MAX_RESUBMIT_RECURSION);
    }
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
                                              ctx->out, ctx->tags,
                                              &ctx->nf_output_iface,
                                              ctx->ofproto->aux)) {
            COVERAGE_INC(ofproto_uninstallable);
            ctx->may_set_up_flow = false;
        }
        break;
    case OFPP_FLOOD:
        add_output_group_action(ctx->out, DP_GROUP_FLOOD,
                                &ctx->nf_output_iface);
        break;
    case OFPP_ALL:
        add_output_group_action(ctx->out, DP_GROUP_ALL, &ctx->nf_output_iface);
        break;
    case OFPP_CONTROLLER:
        add_controller_action(ctx->out, max_len);
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
    size_t n = ctx->out->n_actions;
    if (n > 0 && ctx->out->actions[n - 1].type == ODPAT_POP_PRIORITY) {
        ctx->out->n_actions--;
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
    odp_actions_add(ctx->out, ODPAT_SET_PRIORITY)->priority.priority
        = priority;
    add_output_action(ctx, odp_port);
    odp_actions_add(ctx->out, ODPAT_POP_PRIORITY);

    /* Update NetFlow output port. */
    if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = odp_port;
    } else if (ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
    }
}

static void
xlate_nicira_action(struct action_xlate_ctx *ctx,
                    const struct nx_action_header *nah)
{
    const struct nx_action_resubmit *nar;
    const struct nx_action_set_tunnel *nast;
    union odp_action *oa;
    int subtype = ntohs(nah->subtype);

    assert(nah->vendor == htonl(NX_VENDOR_ID));
    switch (subtype) {
    case NXAST_RESUBMIT:
        nar = (const struct nx_action_resubmit *) nah;
        xlate_table_action(ctx, ofp_port_to_odp_port(ntohs(nar->in_port)));
        break;

    case NXAST_SET_TUNNEL:
        nast = (const struct nx_action_set_tunnel *) nah;
        oa = odp_actions_add(ctx->out, ODPAT_SET_TUNNEL);
        ctx->flow.tun_id = oa->tunnel.tun_id = nast->tun_id;
        break;

    case NXAST_DROP_SPOOFED_ARP:
        if (ctx->flow.dl_type == htons(ETH_TYPE_ARP)) {
            odp_actions_add(ctx->out, ODPAT_DROP_SPOOFED_ARP);
        }
        break;

    /* If you add a new action here that modifies flow data, don't forget to
     * update the flow key in ctx->flow at the same time. */

    default:
        VLOG_DBG_RL(&rl, "unknown Nicira action type %"PRIu16, subtype);
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

    port = port_array_get(&ctx->ofproto->ports, ctx->flow.in_port);
    if (port && port->opp.config & (OFPPC_NO_RECV | OFPPC_NO_RECV_STP) &&
        port->opp.config & (eth_addr_equals(ctx->flow.dl_dst, eth_addr_stp)
                            ? OFPPC_NO_RECV_STP : OFPPC_NO_RECV)) {
        /* Drop this flow. */
        return;
    }

    for (ia = actions_first(&iter, in, n_in); ia; ia = actions_next(&iter)) {
        uint16_t type = ntohs(ia->type);
        union odp_action *oa;

        switch (type) {
        case OFPAT_OUTPUT:
            xlate_output_action(ctx, &ia->output);
            break;

        case OFPAT_SET_VLAN_VID:
            oa = odp_actions_add(ctx->out, ODPAT_SET_VLAN_VID);
            ctx->flow.dl_vlan = oa->vlan_vid.vlan_vid = ia->vlan_vid.vlan_vid;
            break;

        case OFPAT_SET_VLAN_PCP:
            oa = odp_actions_add(ctx->out, ODPAT_SET_VLAN_PCP);
            ctx->flow.dl_vlan_pcp = oa->vlan_pcp.vlan_pcp = ia->vlan_pcp.vlan_pcp;
            break;

        case OFPAT_STRIP_VLAN:
            odp_actions_add(ctx->out, ODPAT_STRIP_VLAN);
            ctx->flow.dl_vlan = htons(OFP_VLAN_NONE);
            ctx->flow.dl_vlan_pcp = 0;
            break;

        case OFPAT_SET_DL_SRC:
            oa = odp_actions_add(ctx->out, ODPAT_SET_DL_SRC);
            memcpy(oa->dl_addr.dl_addr,
                   ((struct ofp_action_dl_addr *) ia)->dl_addr, ETH_ADDR_LEN);
            memcpy(ctx->flow.dl_src,
                   ((struct ofp_action_dl_addr *) ia)->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_DL_DST:
            oa = odp_actions_add(ctx->out, ODPAT_SET_DL_DST);
            memcpy(oa->dl_addr.dl_addr,
                   ((struct ofp_action_dl_addr *) ia)->dl_addr, ETH_ADDR_LEN);
            memcpy(ctx->flow.dl_dst,
                   ((struct ofp_action_dl_addr *) ia)->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_NW_SRC:
            oa = odp_actions_add(ctx->out, ODPAT_SET_NW_SRC);
            ctx->flow.nw_src = oa->nw_addr.nw_addr = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_DST:
            oa = odp_actions_add(ctx->out, ODPAT_SET_NW_DST);
            ctx->flow.nw_dst = oa->nw_addr.nw_addr = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_TOS:
            oa = odp_actions_add(ctx->out, ODPAT_SET_NW_TOS);
            ctx->flow.nw_tos = oa->nw_tos.nw_tos = ia->nw_tos.nw_tos;
            break;

        case OFPAT_SET_TP_SRC:
            oa = odp_actions_add(ctx->out, ODPAT_SET_TP_SRC);
            ctx->flow.tp_src = oa->tp_port.tp_port = ia->tp_port.tp_port;
            break;

        case OFPAT_SET_TP_DST:
            oa = odp_actions_add(ctx->out, ODPAT_SET_TP_DST);
            ctx->flow.tp_dst = oa->tp_port.tp_port = ia->tp_port.tp_port;
            break;

        case OFPAT_VENDOR:
            xlate_nicira_action(ctx, (const struct nx_action_header *) ia);
            break;

        case OFPAT_ENQUEUE:
            xlate_enqueue_action(ctx, (const struct ofp_action_enqueue *) ia);
            break;

        default:
            VLOG_DBG_RL(&rl, "unknown action type %"PRIu16, type);
            break;
        }
    }
}

static int
xlate_actions(const union ofp_action *in, size_t n_in,
              const flow_t *flow, struct ofproto *ofproto,
              const struct ofpbuf *packet,
              struct odp_actions *out, tag_type *tags, bool *may_set_up_flow,
              uint16_t *nf_output_iface)
{
    tag_type no_tags = 0;
    struct action_xlate_ctx ctx;
    COVERAGE_INC(ofproto_ofp2odp);
    odp_actions_init(out);
    ctx.flow = *flow;
    ctx.recurse = 0;
    ctx.ofproto = ofproto;
    ctx.packet = packet;
    ctx.out = out;
    ctx.tags = tags ? tags : &no_tags;
    ctx.may_set_up_flow = true;
    ctx.nf_output_iface = NF_OUT_DROP;
    do_xlate_actions(in, n_in, &ctx);
    remove_pop_action(&ctx);

    /* Check with in-band control to see if we're allowed to set up this
     * flow. */
    if (!in_band_rule_check(ofproto->in_band, flow, out)) {
        ctx.may_set_up_flow = false;
    }

    if (may_set_up_flow) {
        *may_set_up_flow = ctx.may_set_up_flow;
    }
    if (nf_output_iface) {
        *nf_output_iface = ctx.nf_output_iface;
    }
    if (odp_actions_overflow(out)) {
        COVERAGE_INC(odp_overflow);
        odp_actions_init(out);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_TOO_MANY);
    }
    return 0;
}

/* Checks whether 'ofconn' is a slave controller.  If so, returns an OpenFlow
 * error message code (composed with ofp_mkerr()) for the caller to propagate
 * upward.  Otherwise, returns 0.
 *
 * 'oh' is used to make log messages more informative. */
static int
reject_slave_controller(struct ofconn *ofconn, const struct ofp_header *oh)
{
    if (ofconn->type == OFCONN_PRIMARY && ofconn->role == NX_ROLE_SLAVE) {
        static struct vlog_rate_limit perm_rl = VLOG_RATE_LIMIT_INIT(1, 5);
        char *type_name;

        type_name = ofp_message_type_to_string(oh->type);
        VLOG_WARN_RL(&perm_rl, "rejecting %s message from slave controller",
                     type_name);
        free(type_name);

        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    } else {
        return 0;
    }
}

static int
handle_packet_out(struct ofproto *p, struct ofconn *ofconn,
                  struct ofp_header *oh)
{
    struct ofp_packet_out *opo;
    struct ofpbuf payload, *buffer;
    struct odp_actions actions;
    int n_actions;
    uint16_t in_port;
    flow_t flow;
    int error;

    error = reject_slave_controller(ofconn, oh);
    if (error) {
        return error;
    }

    error = check_ofp_packet_out(oh, &payload, &n_actions, p->max_ports);
    if (error) {
        return error;
    }
    opo = (struct ofp_packet_out *) oh;

    COVERAGE_INC(ofproto_packet_out);
    if (opo->buffer_id != htonl(UINT32_MAX)) {
        error = pktbuf_retrieve(ofconn->pktbuf, ntohl(opo->buffer_id),
                                &buffer, &in_port);
        if (error || !buffer) {
            return error;
        }
        payload = *buffer;
    } else {
        buffer = NULL;
    }

    flow_extract(&payload, 0, ofp_port_to_odp_port(ntohs(opo->in_port)), &flow);
    error = xlate_actions((const union ofp_action *) opo->actions, n_actions,
                          &flow, p, &payload, &actions, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    dpif_execute(p->dpif, flow.in_port, actions.actions, actions.n_actions,
                 &payload);
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
#define REVALIDATE_BITS (OFPPC_NO_RECV | OFPPC_NO_RECV_STP | OFPPC_NO_FWD)
    if (mask & REVALIDATE_BITS) {
        COVERAGE_INC(ofproto_costly_flags);
        port->opp.config ^= mask & REVALIDATE_BITS;
        p->need_revalidate = true;
    }
#undef REVALIDATE_BITS
    if (mask & OFPPC_NO_FLOOD) {
        port->opp.config ^= OFPPC_NO_FLOOD;
        refresh_port_groups(p);
    }
    if (mask & OFPPC_NO_PACKET_IN) {
        port->opp.config ^= OFPPC_NO_PACKET_IN;
    }
}

static int
handle_port_mod(struct ofproto *p, struct ofconn *ofconn,
                struct ofp_header *oh)
{
    const struct ofp_port_mod *opm;
    struct ofport *port;
    int error;

    error = reject_slave_controller(ofconn, oh);
    if (error) {
        return error;
    }
    error = check_ofp_message(oh, OFPT_PORT_MOD, sizeof *opm);
    if (error) {
        return error;
    }
    opm = (struct ofp_port_mod *) oh;

    port = port_array_get(&p->ports,
                          ofp_port_to_odp_port(ntohs(opm->port_no)));
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
make_stats_reply(uint32_t xid, uint16_t type, size_t body_len)
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
start_stats_reply(const struct ofp_stats_request *request, size_t body_len)
{
    return make_stats_reply(request->header.xid, request->type, body_len);
}

static void *
append_stats_reply(size_t nbytes, struct ofconn *ofconn, struct ofpbuf **msgp)
{
    struct ofpbuf *msg = *msgp;
    assert(nbytes <= UINT16_MAX - sizeof(struct ofp_stats_reply));
    if (nbytes + msg->size > UINT16_MAX) {
        struct ofp_stats_reply *reply = msg->data;
        reply->flags = htons(OFPSF_REPLY_MORE);
        *msgp = make_stats_reply(reply->header.xid, reply->type, nbytes);
        queue_tx(msg, ofconn, ofconn->reply_counter);
    }
    return ofpbuf_put_uninit(*msgp, nbytes);
}

static int
handle_desc_stats_request(struct ofproto *p, struct ofconn *ofconn,
                           struct ofp_stats_request *request)
{
    struct ofp_desc_stats *ods;
    struct ofpbuf *msg;

    msg = start_stats_reply(request, sizeof *ods);
    ods = append_stats_reply(sizeof *ods, ofconn, &msg);
    memset(ods, 0, sizeof *ods);
    ovs_strlcpy(ods->mfr_desc, p->mfr_desc, sizeof ods->mfr_desc);
    ovs_strlcpy(ods->hw_desc, p->hw_desc, sizeof ods->hw_desc);
    ovs_strlcpy(ods->sw_desc, p->sw_desc, sizeof ods->sw_desc);
    ovs_strlcpy(ods->serial_num, p->serial_desc, sizeof ods->serial_num);
    ovs_strlcpy(ods->dp_desc, p->dp_desc, sizeof ods->dp_desc);
    queue_tx(msg, ofconn, ofconn->reply_counter);

    return 0;
}

static void
count_subrules(struct cls_rule *cls_rule, void *n_subrules_)
{
    struct rule *rule = rule_from_cls_rule(cls_rule);
    int *n_subrules = n_subrules_;

    if (rule->super) {
        (*n_subrules)++;
    }
}

static int
handle_table_stats_request(struct ofproto *p, struct ofconn *ofconn,
                           struct ofp_stats_request *request)
{
    struct ofp_table_stats *ots;
    struct ofpbuf *msg;
    struct odp_stats dpstats;
    int n_exact, n_subrules, n_wild;

    msg = start_stats_reply(request, sizeof *ots * 2);

    /* Count rules of various kinds. */
    n_subrules = 0;
    classifier_for_each(&p->cls, CLS_INC_EXACT, count_subrules, &n_subrules);
    n_exact = classifier_count_exact(&p->cls) - n_subrules;
    n_wild = classifier_count(&p->cls) - classifier_count_exact(&p->cls);

    /* Hash table. */
    dpif_get_dp_stats(p->dpif, &dpstats);
    ots = append_stats_reply(sizeof *ots, ofconn, &msg);
    memset(ots, 0, sizeof *ots);
    ots->table_id = TABLEID_HASH;
    strcpy(ots->name, "hash");
    ots->wildcards = htonl(0);
    ots->max_entries = htonl(dpstats.max_capacity);
    ots->active_count = htonl(n_exact);
    ots->lookup_count = htonll(dpstats.n_frags + dpstats.n_hit +
                               dpstats.n_missed);
    ots->matched_count = htonll(dpstats.n_hit); /* XXX */

    /* Classifier table. */
    ots = append_stats_reply(sizeof *ots, ofconn, &msg);
    memset(ots, 0, sizeof *ots);
    ots->table_id = TABLEID_CLASSIFIER;
    strcpy(ots->name, "classifier");
    ots->wildcards = p->tun_id_from_cookie ? htonl(OVSFW_ALL)
                                           : htonl(OFPFW_ALL);
    ots->max_entries = htonl(65536);
    ots->active_count = htonl(n_wild);
    ots->lookup_count = htonll(0);              /* XXX */
    ots->matched_count = htonll(0);             /* XXX */

    queue_tx(msg, ofconn, ofconn->reply_counter);
    return 0;
}

static void
append_port_stat(struct ofport *port, uint16_t port_no, struct ofconn *ofconn,
                 struct ofpbuf **msgp)
{
    struct netdev_stats stats;
    struct ofp_port_stats *ops;

    /* Intentionally ignore return value, since errors will set
     * 'stats' to all-1s, which is correct for OpenFlow, and
     * netdev_get_stats() will log errors. */
    netdev_get_stats(port->netdev, &stats);

    ops = append_stats_reply(sizeof *ops, ofconn, msgp);
    ops->port_no = htons(odp_port_to_ofp_port(port_no));
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
handle_port_stats_request(struct ofproto *p, struct ofconn *ofconn,
                          struct ofp_stats_request *osr,
                          size_t arg_size)
{
    struct ofp_port_stats_request *psr;
    struct ofp_port_stats *ops;
    struct ofpbuf *msg;
    struct ofport *port;
    unsigned int port_no;

    if (arg_size != sizeof *psr) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    psr = (struct ofp_port_stats_request *) osr->body;

    msg = start_stats_reply(osr, sizeof *ops * 16);
    if (psr->port_no != htons(OFPP_NONE)) {
        port = port_array_get(&p->ports,
                ofp_port_to_odp_port(ntohs(psr->port_no)));
        if (port) {
            append_port_stat(port, ntohs(psr->port_no), ofconn, &msg);
        }
    } else {
        PORT_ARRAY_FOR_EACH (port, &p->ports, port_no) {
            append_port_stat(port, port_no, ofconn, &msg);
        }
    }

    queue_tx(msg, ofconn, ofconn->reply_counter);
    return 0;
}

struct flow_stats_cbdata {
    struct ofproto *ofproto;
    struct ofconn *ofconn;
    uint16_t out_port;
    struct ofpbuf *msg;
};

/* Obtains statistic counters for 'rule' within 'p' and stores them into
 * '*packet_countp' and '*byte_countp'.  If 'rule' is a wildcarded rule, the
 * returned statistic include statistics for all of 'rule''s subrules. */
static void
query_stats(struct ofproto *p, struct rule *rule,
            uint64_t *packet_countp, uint64_t *byte_countp)
{
    uint64_t packet_count, byte_count;
    struct rule *subrule;
    struct odp_flow *odp_flows;
    size_t n_odp_flows;

    /* Start from historical data for 'rule' itself that are no longer tracked
     * by the datapath.  This counts, for example, subrules that have
     * expired. */
    packet_count = rule->packet_count;
    byte_count = rule->byte_count;

    /* Prepare to ask the datapath for statistics on 'rule', or if it is
     * wildcarded then on all of its subrules.
     *
     * Also, add any statistics that are not tracked by the datapath for each
     * subrule.  This includes, for example, statistics for packets that were
     * executed "by hand" by ofproto via dpif_execute() but must be accounted
     * to a flow. */
    n_odp_flows = rule->cr.wc.wildcards ? list_size(&rule->list) : 1;
    odp_flows = xzalloc(n_odp_flows * sizeof *odp_flows);
    if (rule->cr.wc.wildcards) {
        size_t i = 0;
        LIST_FOR_EACH (subrule, struct rule, list, &rule->list) {
            odp_flows[i++].key = subrule->cr.flow;
            packet_count += subrule->packet_count;
            byte_count += subrule->byte_count;
        }
    } else {
        odp_flows[0].key = rule->cr.flow;
    }

    /* Fetch up-to-date statistics from the datapath and add them in. */
    if (!dpif_flow_get_multiple(p->dpif, odp_flows, n_odp_flows)) {
        size_t i;
        for (i = 0; i < n_odp_flows; i++) {
            struct odp_flow *odp_flow = &odp_flows[i];
            packet_count += odp_flow->stats.n_packets;
            byte_count += odp_flow->stats.n_bytes;
        }
    }
    free(odp_flows);

    /* Return the stats to the caller. */
    *packet_countp = packet_count;
    *byte_countp = byte_count;
}

static void
flow_stats_cb(struct cls_rule *rule_, void *cbdata_)
{
    struct rule *rule = rule_from_cls_rule(rule_);
    struct flow_stats_cbdata *cbdata = cbdata_;
    struct ofp_flow_stats *ofs;
    uint64_t packet_count, byte_count;
    size_t act_len, len;
    long long int tdiff = time_msec() - rule->created;
    uint32_t sec = tdiff / 1000;
    uint32_t msec = tdiff - (sec * 1000);

    if (rule_is_hidden(rule) || !rule_has_out_port(rule, cbdata->out_port)) {
        return;
    }

    act_len = sizeof *rule->actions * rule->n_actions;
    len = offsetof(struct ofp_flow_stats, actions) + act_len;

    query_stats(cbdata->ofproto, rule, &packet_count, &byte_count);

    ofs = append_stats_reply(len, cbdata->ofconn, &cbdata->msg);
    ofs->length = htons(len);
    ofs->table_id = rule->cr.wc.wildcards ? TABLEID_CLASSIFIER : TABLEID_HASH;
    ofs->pad = 0;
    flow_to_match(&rule->cr.flow, rule->cr.wc.wildcards,
                  cbdata->ofproto->tun_id_from_cookie, &ofs->match);
    ofs->duration_sec = htonl(sec);
    ofs->duration_nsec = htonl(msec * 1000000);
    ofs->cookie = rule->flow_cookie;
    ofs->priority = htons(rule->cr.priority);
    ofs->idle_timeout = htons(rule->idle_timeout);
    ofs->hard_timeout = htons(rule->hard_timeout);
    memset(ofs->pad2, 0, sizeof ofs->pad2);
    ofs->packet_count = htonll(packet_count);
    ofs->byte_count = htonll(byte_count);
    memcpy(ofs->actions, rule->actions, act_len);
}

static int
table_id_to_include(uint8_t table_id)
{
    return (table_id == TABLEID_HASH ? CLS_INC_EXACT
            : table_id == TABLEID_CLASSIFIER ? CLS_INC_WILD
            : table_id == 0xff ? CLS_INC_ALL
            : 0);
}

static int
handle_flow_stats_request(struct ofproto *p, struct ofconn *ofconn,
                          const struct ofp_stats_request *osr,
                          size_t arg_size)
{
    struct ofp_flow_stats_request *fsr;
    struct flow_stats_cbdata cbdata;
    struct cls_rule target;

    if (arg_size != sizeof *fsr) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    fsr = (struct ofp_flow_stats_request *) osr->body;

    COVERAGE_INC(ofproto_flows_req);
    cbdata.ofproto = p;
    cbdata.ofconn = ofconn;
    cbdata.out_port = fsr->out_port;
    cbdata.msg = start_stats_reply(osr, 1024);
    cls_rule_from_match(&fsr->match, 0, false, 0, &target);
    classifier_for_each_match(&p->cls, &target,
                              table_id_to_include(fsr->table_id),
                              flow_stats_cb, &cbdata);
    queue_tx(cbdata.msg, ofconn, ofconn->reply_counter);
    return 0;
}

struct flow_stats_ds_cbdata {
    struct ofproto *ofproto;
    struct ds *results;
};

static void
flow_stats_ds_cb(struct cls_rule *rule_, void *cbdata_)
{
    struct rule *rule = rule_from_cls_rule(rule_);
    struct flow_stats_ds_cbdata *cbdata = cbdata_;
    struct ds *results = cbdata->results;
    struct ofp_match match;
    uint64_t packet_count, byte_count;
    size_t act_len = sizeof *rule->actions * rule->n_actions;

    /* Don't report on subrules. */
    if (rule->super != NULL) {
        return;
    }

    query_stats(cbdata->ofproto, rule, &packet_count, &byte_count);
    flow_to_match(&rule->cr.flow, rule->cr.wc.wildcards,
                  cbdata->ofproto->tun_id_from_cookie, &match);

    ds_put_format(results, "duration=%llds, ",
                  (time_msec() - rule->created) / 1000);
    ds_put_format(results, "priority=%u, ", rule->cr.priority);
    ds_put_format(results, "n_packets=%"PRIu64", ", packet_count);
    ds_put_format(results, "n_bytes=%"PRIu64", ", byte_count);
    ofp_print_match(results, &match, true);
    ofp_print_actions(results, &rule->actions->header, act_len);
    ds_put_cstr(results, "\n");
}

/* Adds a pretty-printed description of all flows to 'results', including
 * those marked hidden by secchan (e.g., by in-band control). */
void
ofproto_get_all_flows(struct ofproto *p, struct ds *results)
{
    struct ofp_match match;
    struct cls_rule target;
    struct flow_stats_ds_cbdata cbdata;

    memset(&match, 0, sizeof match);
    match.wildcards = htonl(OVSFW_ALL);

    cbdata.ofproto = p;
    cbdata.results = results;

    cls_rule_from_match(&match, 0, false, 0, &target);
    classifier_for_each_match(&p->cls, &target, CLS_INC_ALL,
                              flow_stats_ds_cb, &cbdata);
}

struct aggregate_stats_cbdata {
    struct ofproto *ofproto;
    uint16_t out_port;
    uint64_t packet_count;
    uint64_t byte_count;
    uint32_t n_flows;
};

static void
aggregate_stats_cb(struct cls_rule *rule_, void *cbdata_)
{
    struct rule *rule = rule_from_cls_rule(rule_);
    struct aggregate_stats_cbdata *cbdata = cbdata_;
    uint64_t packet_count, byte_count;

    if (rule_is_hidden(rule) || !rule_has_out_port(rule, cbdata->out_port)) {
        return;
    }

    query_stats(cbdata->ofproto, rule, &packet_count, &byte_count);

    cbdata->packet_count += packet_count;
    cbdata->byte_count += byte_count;
    cbdata->n_flows++;
}

static int
handle_aggregate_stats_request(struct ofproto *p, struct ofconn *ofconn,
                               const struct ofp_stats_request *osr,
                               size_t arg_size)
{
    struct ofp_aggregate_stats_request *asr;
    struct ofp_aggregate_stats_reply *reply;
    struct aggregate_stats_cbdata cbdata;
    struct cls_rule target;
    struct ofpbuf *msg;

    if (arg_size != sizeof *asr) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    asr = (struct ofp_aggregate_stats_request *) osr->body;

    COVERAGE_INC(ofproto_agg_request);
    cbdata.ofproto = p;
    cbdata.out_port = asr->out_port;
    cbdata.packet_count = 0;
    cbdata.byte_count = 0;
    cbdata.n_flows = 0;
    cls_rule_from_match(&asr->match, 0, false, 0, &target);
    classifier_for_each_match(&p->cls, &target,
                              table_id_to_include(asr->table_id),
                              aggregate_stats_cb, &cbdata);

    msg = start_stats_reply(osr, sizeof *reply);
    reply = append_stats_reply(sizeof *reply, ofconn, &msg);
    reply->flow_count = htonl(cbdata.n_flows);
    reply->packet_count = htonll(cbdata.packet_count);
    reply->byte_count = htonll(cbdata.byte_count);
    queue_tx(msg, ofconn, ofconn->reply_counter);
    return 0;
}

struct queue_stats_cbdata {
    struct ofconn *ofconn;
    struct ofpbuf *msg;
    uint16_t port_no;
};

static void
put_queue_stats(struct queue_stats_cbdata *cbdata, uint32_t queue_id,
                const struct netdev_queue_stats *stats)
{
    struct ofp_queue_stats *reply;

    reply = append_stats_reply(sizeof *reply, cbdata->ofconn, &cbdata->msg);
    reply->port_no = htons(cbdata->port_no);
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
handle_queue_stats_for_port(struct ofport *port, uint16_t port_no,
                            uint32_t queue_id,
                            struct queue_stats_cbdata *cbdata)
{
    cbdata->port_no = port_no;
    if (queue_id == OFPQ_ALL) {
        netdev_dump_queue_stats(port->netdev,
                                handle_queue_stats_dump_cb, cbdata);
    } else {
        struct netdev_queue_stats stats;

        netdev_get_queue_stats(port->netdev, queue_id, &stats);
        put_queue_stats(cbdata, queue_id, &stats);
    }
}

static int
handle_queue_stats_request(struct ofproto *ofproto, struct ofconn *ofconn,
                           const struct ofp_stats_request *osr,
                           size_t arg_size)
{
    struct ofp_queue_stats_request *qsr;
    struct queue_stats_cbdata cbdata;
    struct ofport *port;
    unsigned int port_no;
    uint32_t queue_id;

    if (arg_size != sizeof *qsr) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    qsr = (struct ofp_queue_stats_request *) osr->body;

    COVERAGE_INC(ofproto_queue_req);

    cbdata.ofconn = ofconn;
    cbdata.msg = start_stats_reply(osr, 128);

    port_no = ntohs(qsr->port_no);
    queue_id = ntohl(qsr->queue_id);
    if (port_no == OFPP_ALL) {
        PORT_ARRAY_FOR_EACH (port, &ofproto->ports, port_no) {
            handle_queue_stats_for_port(port, port_no, queue_id, &cbdata);
        }
    } else if (port_no < ofproto->max_ports) {
        port = port_array_get(&ofproto->ports, port_no);
        if (port) {
            handle_queue_stats_for_port(port, port_no, queue_id, &cbdata);
        }
    } else {
        ofpbuf_delete(cbdata.msg);
        return ofp_mkerr(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }
    queue_tx(cbdata.msg, ofconn, ofconn->reply_counter);

    return 0;
}

static int
handle_stats_request(struct ofproto *p, struct ofconn *ofconn,
                     struct ofp_header *oh)
{
    struct ofp_stats_request *osr;
    size_t arg_size;
    int error;

    error = check_ofp_message_array(oh, OFPT_STATS_REQUEST, sizeof *osr,
                                    1, &arg_size);
    if (error) {
        return error;
    }
    osr = (struct ofp_stats_request *) oh;

    switch (ntohs(osr->type)) {
    case OFPST_DESC:
        return handle_desc_stats_request(p, ofconn, osr);

    case OFPST_FLOW:
        return handle_flow_stats_request(p, ofconn, osr, arg_size);

    case OFPST_AGGREGATE:
        return handle_aggregate_stats_request(p, ofconn, osr, arg_size);

    case OFPST_TABLE:
        return handle_table_stats_request(p, ofconn, osr);

    case OFPST_PORT:
        return handle_port_stats_request(p, ofconn, osr, arg_size);

    case OFPST_QUEUE:
        return handle_queue_stats_request(p, ofconn, osr, arg_size);

    case OFPST_VENDOR:
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_VENDOR);

    default:
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT);
    }
}

static long long int
msec_from_nsec(uint64_t sec, uint32_t nsec)
{
    return !sec ? 0 : sec * 1000 + nsec / 1000000;
}

static void
update_time(struct ofproto *ofproto, struct rule *rule,
            const struct odp_flow_stats *stats)
{
    long long int used = msec_from_nsec(stats->used_sec, stats->used_nsec);
    if (used > rule->used) {
        rule->used = used;
        if (rule->super && used > rule->super->used) {
            rule->super->used = used;
        }
        netflow_flow_update_time(ofproto->netflow, &rule->nf_flow, used);
    }
}

static void
update_stats(struct ofproto *ofproto, struct rule *rule,
             const struct odp_flow_stats *stats)
{
    if (stats->n_packets) {
        update_time(ofproto, rule, stats);
        rule->packet_count += stats->n_packets;
        rule->byte_count += stats->n_bytes;
        netflow_flow_update_flags(&rule->nf_flow, stats->tcp_flags);
    }
}

/* Implements OFPFC_ADD and the cases for OFPFC_MODIFY and OFPFC_MODIFY_STRICT
 * in which no matching flow already exists in the flow table.
 *
 * Adds the flow specified by 'ofm', which is followed by 'n_actions'
 * ofp_actions, to 'p''s flow table.  Returns 0 on success or an OpenFlow error
 * code as encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
add_flow(struct ofproto *p, struct ofconn *ofconn,
         const struct ofp_flow_mod *ofm, size_t n_actions)
{
    struct ofpbuf *packet;
    struct rule *rule;
    uint16_t in_port;
    int error;

    if (ofm->flags & htons(OFPFF_CHECK_OVERLAP)) {
        flow_t flow;
        uint32_t wildcards;

        flow_from_match(&ofm->match, p->tun_id_from_cookie, ofm->cookie,
                        &flow, &wildcards);
        if (classifier_rule_overlaps(&p->cls, &flow, wildcards,
                                     ntohs(ofm->priority))) {
            return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        }
    }

    rule = rule_create(p, NULL, (const union ofp_action *) ofm->actions,
                       n_actions, ntohs(ofm->idle_timeout),
                       ntohs(ofm->hard_timeout),  ofm->cookie,
                       ofm->flags & htons(OFPFF_SEND_FLOW_REM));
    cls_rule_from_match(&ofm->match, ntohs(ofm->priority),
                        p->tun_id_from_cookie, ofm->cookie, &rule->cr);

    error = 0;
    if (ofm->buffer_id != htonl(UINT32_MAX)) {
        error = pktbuf_retrieve(ofconn->pktbuf, ntohl(ofm->buffer_id),
                                &packet, &in_port);
    } else {
        packet = NULL;
        in_port = UINT16_MAX;
    }

    rule_insert(p, rule, packet, in_port);
    return error;
}

static struct rule *
find_flow_strict(struct ofproto *p, const struct ofp_flow_mod *ofm)
{
    uint32_t wildcards;
    flow_t flow;

    flow_from_match(&ofm->match, p->tun_id_from_cookie, ofm->cookie,
                    &flow, &wildcards);
    return rule_from_cls_rule(classifier_find_rule_exactly(
                                  &p->cls, &flow, wildcards,
                                  ntohs(ofm->priority)));
}

static int
send_buffered_packet(struct ofproto *ofproto, struct ofconn *ofconn,
                     struct rule *rule, const struct ofp_flow_mod *ofm)
{
    struct ofpbuf *packet;
    uint16_t in_port;
    flow_t flow;
    int error;

    if (ofm->buffer_id == htonl(UINT32_MAX)) {
        return 0;
    }

    error = pktbuf_retrieve(ofconn->pktbuf, ntohl(ofm->buffer_id),
                            &packet, &in_port);
    if (error) {
        return error;
    }

    flow_extract(packet, 0, in_port, &flow);
    rule_execute(ofproto, rule, packet, &flow);

    return 0;
}

/* OFPFC_MODIFY and OFPFC_MODIFY_STRICT. */

struct modify_flows_cbdata {
    struct ofproto *ofproto;
    const struct ofp_flow_mod *ofm;
    size_t n_actions;
    struct rule *match;
};

static int modify_flow(struct ofproto *, const struct ofp_flow_mod *,
                       size_t n_actions, struct rule *);
static void modify_flows_cb(struct cls_rule *, void *cbdata_);

/* Implements OFPFC_MODIFY.  Returns 0 on success or an OpenFlow error code as
 * encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
modify_flows_loose(struct ofproto *p, struct ofconn *ofconn,
                   const struct ofp_flow_mod *ofm, size_t n_actions)
{
    struct modify_flows_cbdata cbdata;
    struct cls_rule target;

    cbdata.ofproto = p;
    cbdata.ofm = ofm;
    cbdata.n_actions = n_actions;
    cbdata.match = NULL;

    cls_rule_from_match(&ofm->match, 0, p->tun_id_from_cookie, ofm->cookie,
                        &target);

    classifier_for_each_match(&p->cls, &target, CLS_INC_ALL,
                              modify_flows_cb, &cbdata);
    if (cbdata.match) {
        /* This credits the packet to whichever flow happened to happened to
         * match last.  That's weird.  Maybe we should do a lookup for the
         * flow that actually matches the packet?  Who knows. */
        send_buffered_packet(p, ofconn, cbdata.match, ofm);
        return 0;
    } else {
        return add_flow(p, ofconn, ofm, n_actions);
    }
}

/* Implements OFPFC_MODIFY_STRICT.  Returns 0 on success or an OpenFlow error
 * code as encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
modify_flow_strict(struct ofproto *p, struct ofconn *ofconn,
                   struct ofp_flow_mod *ofm, size_t n_actions)
{
    struct rule *rule = find_flow_strict(p, ofm);
    if (rule && !rule_is_hidden(rule)) {
        modify_flow(p, ofm, n_actions, rule);
        return send_buffered_packet(p, ofconn, rule, ofm);
    } else {
        return add_flow(p, ofconn, ofm, n_actions);
    }
}

/* Callback for modify_flows_loose(). */
static void
modify_flows_cb(struct cls_rule *rule_, void *cbdata_)
{
    struct rule *rule = rule_from_cls_rule(rule_);
    struct modify_flows_cbdata *cbdata = cbdata_;

    if (!rule_is_hidden(rule)) {
        cbdata->match = rule;
        modify_flow(cbdata->ofproto, cbdata->ofm, cbdata->n_actions, rule);
    }
}

/* Implements core of OFPFC_MODIFY and OFPFC_MODIFY_STRICT where 'rule' has
 * been identified as a flow in 'p''s flow table to be modified, by changing
 * the rule's actions to match those in 'ofm' (which is followed by 'n_actions'
 * ofp_action[] structures). */
static int
modify_flow(struct ofproto *p, const struct ofp_flow_mod *ofm,
            size_t n_actions, struct rule *rule)
{
    size_t actions_len = n_actions * sizeof *rule->actions;

    rule->flow_cookie = ofm->cookie;

    /* If the actions are the same, do nothing. */
    if (n_actions == rule->n_actions
        && !memcmp(ofm->actions, rule->actions, actions_len))
    {
        return 0;
    }

    /* Replace actions. */
    free(rule->actions);
    rule->actions = xmemdup(ofm->actions, actions_len);
    rule->n_actions = n_actions;

    /* Make sure that the datapath gets updated properly. */
    if (rule->cr.wc.wildcards) {
        COVERAGE_INC(ofproto_mod_wc_flow);
        p->need_revalidate = true;
    } else {
        rule_update_actions(p, rule);
    }

    return 0;
}

/* OFPFC_DELETE implementation. */

struct delete_flows_cbdata {
    struct ofproto *ofproto;
    uint16_t out_port;
};

static void delete_flows_cb(struct cls_rule *, void *cbdata_);
static void delete_flow(struct ofproto *, struct rule *, uint16_t out_port);

/* Implements OFPFC_DELETE. */
static void
delete_flows_loose(struct ofproto *p, const struct ofp_flow_mod *ofm)
{
    struct delete_flows_cbdata cbdata;
    struct cls_rule target;

    cbdata.ofproto = p;
    cbdata.out_port = ofm->out_port;

    cls_rule_from_match(&ofm->match, 0, p->tun_id_from_cookie, ofm->cookie,
                        &target);

    classifier_for_each_match(&p->cls, &target, CLS_INC_ALL,
                              delete_flows_cb, &cbdata);
}

/* Implements OFPFC_DELETE_STRICT. */
static void
delete_flow_strict(struct ofproto *p, struct ofp_flow_mod *ofm)
{
    struct rule *rule = find_flow_strict(p, ofm);
    if (rule) {
        delete_flow(p, rule, ofm->out_port);
    }
}

/* Callback for delete_flows_loose(). */
static void
delete_flows_cb(struct cls_rule *rule_, void *cbdata_)
{
    struct rule *rule = rule_from_cls_rule(rule_);
    struct delete_flows_cbdata *cbdata = cbdata_;

    delete_flow(cbdata->ofproto, rule, cbdata->out_port);
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
delete_flow(struct ofproto *p, struct rule *rule, uint16_t out_port)
{
    if (rule_is_hidden(rule)) {
        return;
    }

    if (out_port != htons(OFPP_NONE) && !rule_has_out_port(rule, out_port)) {
        return;
    }

    send_flow_removed(p, rule, time_msec(), OFPRR_DELETE);
    rule_remove(p, rule);
}

static int
handle_flow_mod(struct ofproto *p, struct ofconn *ofconn,
                struct ofp_flow_mod *ofm)
{
    struct ofp_match orig_match;
    size_t n_actions;
    int error;

    error = reject_slave_controller(ofconn, &ofm->header);
    if (error) {
        return error;
    }
    error = check_ofp_message_array(&ofm->header, OFPT_FLOW_MOD, sizeof *ofm,
                                    sizeof *ofm->actions, &n_actions);
    if (error) {
        return error;
    }

    /* We do not support the emergency flow cache.  It will hopefully
     * get dropped from OpenFlow in the near future. */
    if (ofm->flags & htons(OFPFF_EMERG)) {
        /* There isn't a good fit for an error code, so just state that the
         * flow table is full. */
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_ALL_TABLES_FULL);
    }

    /* Normalize ofp->match.  If normalization actually changes anything, then
     * log the differences. */
    ofm->match.pad1[0] = ofm->match.pad2[0] = 0;
    orig_match = ofm->match;
    normalize_match(&ofm->match);
    if (memcmp(&ofm->match, &orig_match, sizeof orig_match)) {
        static struct vlog_rate_limit normal_rl = VLOG_RATE_LIMIT_INIT(1, 1);
        if (!VLOG_DROP_INFO(&normal_rl)) {
            char *old = ofp_match_to_literal_string(&orig_match);
            char *new = ofp_match_to_literal_string(&ofm->match);
            VLOG_INFO("%s: normalization changed ofp_match, details:",
                      rconn_get_name(ofconn->rconn));
            VLOG_INFO(" pre: %s", old);
            VLOG_INFO("post: %s", new);
            free(old);
            free(new);
        }
    }

    if (!ofm->match.wildcards) {
        ofm->priority = htons(UINT16_MAX);
    }

    error = validate_actions((const union ofp_action *) ofm->actions,
                             n_actions, p->max_ports);
    if (error) {
        return error;
    }

    switch (ntohs(ofm->command)) {
    case OFPFC_ADD:
        return add_flow(p, ofconn, ofm, n_actions);

    case OFPFC_MODIFY:
        return modify_flows_loose(p, ofconn, ofm, n_actions);

    case OFPFC_MODIFY_STRICT:
        return modify_flow_strict(p, ofconn, ofm, n_actions);

    case OFPFC_DELETE:
        delete_flows_loose(p, ofm);
        return 0;

    case OFPFC_DELETE_STRICT:
        delete_flow_strict(p, ofm);
        return 0;

    default:
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
    }
}

static int
handle_tun_id_from_cookie(struct ofproto *p, struct nxt_tun_id_cookie *msg)
{
    int error;

    error = check_ofp_message(&msg->header, OFPT_VENDOR, sizeof *msg);
    if (error) {
        return error;
    }

    p->tun_id_from_cookie = !!msg->set;
    return 0;
}

static int
handle_role_request(struct ofproto *ofproto,
                    struct ofconn *ofconn, struct nicira_header *msg)
{
    struct nx_role_request *nrr;
    struct nx_role_request *reply;
    struct ofpbuf *buf;
    uint32_t role;

    if (ntohs(msg->header.length) != sizeof *nrr) {
        VLOG_WARN_RL(&rl, "received role request of length %u (expected %zu)",
                     ntohs(msg->header.length), sizeof *nrr);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    nrr = (struct nx_role_request *) msg;

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

        HMAP_FOR_EACH (other, struct ofconn, hmap_node,
                       &ofproto->controllers) {
            if (other->role == NX_ROLE_MASTER) {
                other->role = NX_ROLE_SLAVE;
            }
        }
    }
    ofconn->role = role;

    reply = make_openflow_xid(sizeof *reply, OFPT_VENDOR, msg->header.xid,
                              &buf);
    reply->nxh.vendor = htonl(NX_VENDOR_ID);
    reply->nxh.subtype = htonl(NXT_ROLE_REPLY);
    reply->role = htonl(role);
    queue_tx(buf, ofconn, ofconn->reply_counter);

    return 0;
}

static int
handle_vendor(struct ofproto *p, struct ofconn *ofconn, void *msg)
{
    struct ofp_vendor_header *ovh = msg;
    struct nicira_header *nh;

    if (ntohs(ovh->header.length) < sizeof(struct ofp_vendor_header)) {
        VLOG_WARN_RL(&rl, "received vendor message of length %u "
                          "(expected at least %zu)",
                   ntohs(ovh->header.length), sizeof(struct ofp_vendor_header));
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if (ovh->vendor != htonl(NX_VENDOR_ID)) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_VENDOR);
    }
    if (ntohs(ovh->header.length) < sizeof(struct nicira_header)) {
        VLOG_WARN_RL(&rl, "received Nicira vendor message of length %u "
                          "(expected at least %zu)",
                     ntohs(ovh->header.length), sizeof(struct nicira_header));
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    nh = msg;
    switch (ntohl(nh->subtype)) {
    case NXT_STATUS_REQUEST:
        return switch_status_handle_request(p->switch_status, ofconn->rconn,
                                            msg);

    case NXT_TUN_ID_FROM_COOKIE:
        return handle_tun_id_from_cookie(p, msg);

    case NXT_ROLE_REQUEST:
        return handle_role_request(p, ofconn, msg);
    }

    return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
}

static int
handle_barrier_request(struct ofconn *ofconn, struct ofp_header *oh)
{
    struct ofp_header *ob;
    struct ofpbuf *buf;

    /* Currently, everything executes synchronously, so we can just
     * immediately send the barrier reply. */
    ob = make_openflow_xid(sizeof *ob, OFPT_BARRIER_REPLY, oh->xid, &buf);
    queue_tx(buf, ofconn, ofconn->reply_counter);
    return 0;
}

static void
handle_openflow(struct ofconn *ofconn, struct ofproto *p,
                struct ofpbuf *ofp_msg)
{
    struct ofp_header *oh = ofp_msg->data;
    int error;

    COVERAGE_INC(ofproto_recv_openflow);
    switch (oh->type) {
    case OFPT_ECHO_REQUEST:
        error = handle_echo_request(ofconn, oh);
        break;

    case OFPT_ECHO_REPLY:
        error = 0;
        break;

    case OFPT_FEATURES_REQUEST:
        error = handle_features_request(p, ofconn, oh);
        break;

    case OFPT_GET_CONFIG_REQUEST:
        error = handle_get_config_request(p, ofconn, oh);
        break;

    case OFPT_SET_CONFIG:
        error = handle_set_config(p, ofconn, ofp_msg->data);
        break;

    case OFPT_PACKET_OUT:
        error = handle_packet_out(p, ofconn, ofp_msg->data);
        break;

    case OFPT_PORT_MOD:
        error = handle_port_mod(p, ofconn, oh);
        break;

    case OFPT_FLOW_MOD:
        error = handle_flow_mod(p, ofconn, ofp_msg->data);
        break;

    case OFPT_STATS_REQUEST:
        error = handle_stats_request(p, ofconn, oh);
        break;

    case OFPT_VENDOR:
        error = handle_vendor(p, ofconn, ofp_msg->data);
        break;

    case OFPT_BARRIER_REQUEST:
        error = handle_barrier_request(ofconn, oh);
        break;

    default:
        if (VLOG_IS_WARN_ENABLED()) {
            char *s = ofp_to_string(oh, ntohs(oh->length), 2);
            VLOG_DBG_RL(&rl, "OpenFlow message ignored: %s", s);
            free(s);
        }
        error = ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        break;
    }

    if (error) {
        send_error_oh(ofconn, ofp_msg->data, error);
    }
}

static void
handle_odp_miss_msg(struct ofproto *p, struct ofpbuf *packet)
{
    struct odp_msg *msg = packet->data;
    struct rule *rule;
    struct ofpbuf payload;
    flow_t flow;

    payload.data = msg + 1;
    payload.size = msg->length - sizeof *msg;
    flow_extract(&payload, msg->arg, msg->port, &flow);

    /* Check with in-band control to see if this packet should be sent
     * to the local port regardless of the flow table. */
    if (in_band_msg_in_hook(p->in_band, &flow, &payload)) {
        union odp_action action;

        memset(&action, 0, sizeof(action));
        action.output.type = ODPAT_OUTPUT;
        action.output.port = ODPP_LOCAL;
        dpif_execute(p->dpif, flow.in_port, &action, 1, &payload);
    }

    rule = lookup_valid_rule(p, &flow);
    if (!rule) {
        /* Don't send a packet-in if OFPPC_NO_PACKET_IN asserted. */
        struct ofport *port = port_array_get(&p->ports, msg->port);
        if (port) {
            if (port->opp.config & OFPPC_NO_PACKET_IN) {
                COVERAGE_INC(ofproto_no_packet_in);
                /* XXX install 'drop' flow entry */
                ofpbuf_delete(packet);
                return;
            }
        } else {
            VLOG_WARN_RL(&rl, "packet-in on unknown port %"PRIu16, msg->port);
        }

        COVERAGE_INC(ofproto_packet_in);
        send_packet_in(p, packet);
        return;
    }

    if (rule->cr.wc.wildcards) {
        rule = rule_create_subrule(p, rule, &flow);
        rule_make_actions(p, rule, packet);
    } else {
        if (!rule->may_install) {
            /* The rule is not installable, that is, we need to process every
             * packet, so process the current packet and set its actions into
             * 'subrule'. */
            rule_make_actions(p, rule, packet);
        } else {
            /* XXX revalidate rule if it needs it */
        }
    }

    if (rule->super && rule->super->cr.priority == FAIL_OPEN_PRIORITY) {
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
        send_packet_in(p, ofpbuf_clone_with_headroom(packet,
                                                     DPIF_RECV_MSG_PADDING));
    }

    ofpbuf_pull(packet, sizeof *msg);
    rule_execute(p, rule, packet, &flow);
    rule_reinstall(p, rule);
}

static void
handle_odp_msg(struct ofproto *p, struct ofpbuf *packet)
{
    struct odp_msg *msg = packet->data;

    switch (msg->type) {
    case _ODPL_ACTION_NR:
        COVERAGE_INC(ofproto_ctlr_action);
        send_packet_in(p, packet);
        break;

    case _ODPL_SFLOW_NR:
        if (p->sflow) {
            ofproto_sflow_received(p->sflow, msg);
        }
        ofpbuf_delete(packet);
        break;

    case _ODPL_MISS_NR:
        handle_odp_miss_msg(p, packet);
        break;

    default:
        VLOG_WARN_RL(&rl, "received ODP message of unexpected type %"PRIu32,
                     msg->type);
        break;
    }
}

static void
revalidate_cb(struct cls_rule *sub_, void *cbdata_)
{
    struct rule *sub = rule_from_cls_rule(sub_);
    struct revalidate_cbdata *cbdata = cbdata_;

    if (cbdata->revalidate_all
        || (cbdata->revalidate_subrules && sub->super)
        || (tag_set_intersects(&cbdata->revalidate_set, sub->tags))) {
        revalidate_rule(cbdata->ofproto, sub);
    }
}

static bool
revalidate_rule(struct ofproto *p, struct rule *rule)
{
    const flow_t *flow = &rule->cr.flow;

    COVERAGE_INC(ofproto_revalidate_rule);
    if (rule->super) {
        struct rule *super;
        super = rule_from_cls_rule(classifier_lookup_wild(&p->cls, flow));
        if (!super) {
            rule_remove(p, rule);
            return false;
        } else if (super != rule->super) {
            COVERAGE_INC(ofproto_revalidate_moved);
            list_remove(&rule->list);
            list_push_back(&super->list, &rule->list);
            rule->super = super;
            rule->hard_timeout = super->hard_timeout;
            rule->idle_timeout = super->idle_timeout;
            rule->created = super->created;
            rule->used = 0;
        }
    }

    rule_update_actions(p, rule);
    return true;
}

static struct ofpbuf *
compose_flow_removed(struct ofproto *p, const struct rule *rule,
                     long long int now, uint8_t reason)
{
    struct ofp_flow_removed *ofr;
    struct ofpbuf *buf;
    long long int tdiff = now - rule->created;
    uint32_t sec = tdiff / 1000;
    uint32_t msec = tdiff - (sec * 1000);

    ofr = make_openflow(sizeof *ofr, OFPT_FLOW_REMOVED, &buf);
    flow_to_match(&rule->cr.flow, rule->cr.wc.wildcards, p->tun_id_from_cookie,
                  &ofr->match);
    ofr->cookie = rule->flow_cookie;
    ofr->priority = htons(rule->cr.priority);
    ofr->reason = reason;
    ofr->duration_sec = htonl(sec);
    ofr->duration_nsec = htonl(msec * 1000000);
    ofr->idle_timeout = htons(rule->idle_timeout);
    ofr->packet_count = htonll(rule->packet_count);
    ofr->byte_count = htonll(rule->byte_count);

    return buf;
}

static void
uninstall_idle_flow(struct ofproto *ofproto, struct rule *rule)
{
    assert(rule->installed);
    assert(!rule->cr.wc.wildcards);

    if (rule->super) {
        rule_remove(ofproto, rule);
    } else {
        rule_uninstall(ofproto, rule);
    }
}

static void
send_flow_removed(struct ofproto *p, struct rule *rule,
                  long long int now, uint8_t reason)
{
    struct ofconn *ofconn;
    struct ofconn *prev;
    struct ofpbuf *buf = NULL;

    /* We limit the maximum number of queued flow expirations it by accounting
     * them under the counter for replies.  That works because preventing
     * OpenFlow requests from being processed also prevents new flows from
     * being added (and expiring).  (It also prevents processing OpenFlow
     * requests that would not add new flows, so it is imperfect.) */

    prev = NULL;
    LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
        if (rule->send_flow_removed && rconn_is_connected(ofconn->rconn)
            && ofconn_receives_async_msgs(ofconn)) {
            if (prev) {
                queue_tx(ofpbuf_clone(buf), prev, prev->reply_counter);
            } else {
                buf = compose_flow_removed(p, rule, now, reason);
            }
            prev = ofconn;
        }
    }
    if (prev) {
        queue_tx(buf, prev, prev->reply_counter);
    }
}


static void
expire_rule(struct cls_rule *cls_rule, void *p_)
{
    struct ofproto *p = p_;
    struct rule *rule = rule_from_cls_rule(cls_rule);
    long long int hard_expire, idle_expire, expire, now;

    hard_expire = (rule->hard_timeout
                   ? rule->created + rule->hard_timeout * 1000
                   : LLONG_MAX);
    idle_expire = (rule->idle_timeout
                   && (rule->super || list_is_empty(&rule->list))
                   ? rule->used + rule->idle_timeout * 1000
                   : LLONG_MAX);
    expire = MIN(hard_expire, idle_expire);

    now = time_msec();
    if (now < expire) {
        if (rule->installed && now >= rule->used + 5000) {
            uninstall_idle_flow(p, rule);
        } else if (!rule->cr.wc.wildcards) {
            active_timeout(p, rule);
        }

        return;
    }

    COVERAGE_INC(ofproto_expired);

    /* Update stats.  This code will be a no-op if the rule expired
     * due to an idle timeout. */
    if (rule->cr.wc.wildcards) {
        struct rule *subrule, *next;
        LIST_FOR_EACH_SAFE (subrule, next, struct rule, list, &rule->list) {
            rule_remove(p, subrule);
        }
    } else {
        rule_uninstall(p, rule);
    }

    if (!rule_is_hidden(rule)) {
        send_flow_removed(p, rule, now,
                          (now >= hard_expire
                           ? OFPRR_HARD_TIMEOUT : OFPRR_IDLE_TIMEOUT));
    }
    rule_remove(p, rule);
}

static void
active_timeout(struct ofproto *ofproto, struct rule *rule)
{
    if (ofproto->netflow && !is_controller_rule(rule) &&
        netflow_active_timeout_expired(ofproto->netflow, &rule->nf_flow)) {
        struct ofexpired expired;
        struct odp_flow odp_flow;

        /* Get updated flow stats. */
        memset(&odp_flow, 0, sizeof odp_flow);
        if (rule->installed) {
            odp_flow.key = rule->cr.flow;
            odp_flow.flags = ODPFF_ZERO_TCP_FLAGS;
            dpif_flow_get(ofproto->dpif, &odp_flow);

            if (odp_flow.stats.n_packets) {
                update_time(ofproto, rule, &odp_flow.stats);
                netflow_flow_update_flags(&rule->nf_flow,
                                          odp_flow.stats.tcp_flags);
            }
        }

        expired.flow = rule->cr.flow;
        expired.packet_count = rule->packet_count +
                               odp_flow.stats.n_packets;
        expired.byte_count = rule->byte_count + odp_flow.stats.n_bytes;
        expired.used = rule->used;

        netflow_expire(ofproto->netflow, &rule->nf_flow, &expired);

        /* Schedule us to send the accumulated records once we have
         * collected all of them. */
        poll_immediate_wake();
    }
}

static void
update_used(struct ofproto *p)
{
    struct odp_flow *flows;
    size_t n_flows;
    size_t i;
    int error;

    error = dpif_flow_list_all(p->dpif, &flows, &n_flows);
    if (error) {
        return;
    }

    for (i = 0; i < n_flows; i++) {
        struct odp_flow *f = &flows[i];
        struct rule *rule;

        rule = rule_from_cls_rule(
            classifier_find_rule_exactly(&p->cls, &f->key, 0, UINT16_MAX));
        if (!rule || !rule->installed) {
            COVERAGE_INC(ofproto_unexpected_rule);
            dpif_flow_del(p->dpif, f);
            continue;
        }

        update_time(p, rule, &f->stats);
        rule_account(p, rule, f->stats.n_bytes);
    }
    free(flows);
}

/* pinsched callback for sending 'packet' on 'ofconn'. */
static void
do_send_packet_in(struct ofpbuf *packet, void *ofconn_)
{
    struct ofconn *ofconn = ofconn_;

    rconn_send_with_limit(ofconn->rconn, packet,
                          ofconn->packet_in_counter, 100);
}

/* Takes 'packet', which has been converted with do_convert_to_packet_in(), and
 * finalizes its content for sending on 'ofconn', and passes it to 'ofconn''s
 * packet scheduler for sending.
 *
 * 'max_len' specifies the maximum number of bytes of the packet to send on
 * 'ofconn' (INT_MAX specifies no limit).
 *
 * If 'clone' is true, the caller retains ownership of 'packet'.  Otherwise,
 * ownership is transferred to this function. */
static void
schedule_packet_in(struct ofconn *ofconn, struct ofpbuf *packet, int max_len,
                   bool clone)
{
    struct ofproto *ofproto = ofconn->ofproto;
    struct ofp_packet_in *opi = packet->data;
    uint16_t in_port = ofp_port_to_odp_port(ntohs(opi->in_port));
    int send_len, trim_size;
    uint32_t buffer_id;

    /* Get buffer. */
    if (opi->reason == OFPR_ACTION) {
        buffer_id = UINT32_MAX;
    } else if (ofproto->fail_open && fail_open_is_active(ofproto->fail_open)) {
        buffer_id = pktbuf_get_null();
    } else if (!ofconn->pktbuf) {
        buffer_id = UINT32_MAX;
    } else {
        struct ofpbuf payload;
        payload.data = opi->data;
        payload.size = packet->size - offsetof(struct ofp_packet_in, data);
        buffer_id = pktbuf_save(ofconn->pktbuf, &payload, in_port);
    }

    /* Figure out how much of the packet to send. */
    send_len = ntohs(opi->total_len);
    if (buffer_id != UINT32_MAX) {
        send_len = MIN(send_len, ofconn->miss_send_len);
    }
    send_len = MIN(send_len, max_len);

    /* Adjust packet length and clone if necessary. */
    trim_size = offsetof(struct ofp_packet_in, data) + send_len;
    if (clone) {
        packet = ofpbuf_clone_data(packet->data, trim_size);
        opi = packet->data;
    } else {
        packet->size = trim_size;
    }

    /* Update packet headers. */
    opi->buffer_id = htonl(buffer_id);
    update_openflow_length(packet);

    /* Hand over to packet scheduler.  It might immediately call into
     * do_send_packet_in() or it might buffer it for a while (until a later
     * call to pinsched_run()). */
    pinsched_send(ofconn->schedulers[opi->reason], in_port,
                  packet, do_send_packet_in, ofconn);
}

/* Replace struct odp_msg header in 'packet' by equivalent struct
 * ofp_packet_in.  The odp_msg must have sufficient headroom to do so (e.g. as
 * returned by dpif_recv()).
 *
 * The conversion is not complete: the caller still needs to trim any unneeded
 * payload off the end of the buffer, set the length in the OpenFlow header,
 * and set buffer_id.  Those require us to know the controller settings and so
 * must be done on a per-controller basis.
 *
 * Returns the maximum number of bytes of the packet that should be sent to
 * the controller (INT_MAX if no limit). */
static int
do_convert_to_packet_in(struct ofpbuf *packet)
{
    struct odp_msg *msg = packet->data;
    struct ofp_packet_in *opi;
    uint8_t reason;
    uint16_t total_len;
    uint16_t in_port;
    int max_len;

    /* Extract relevant header fields */
    if (msg->type == _ODPL_ACTION_NR) {
        reason = OFPR_ACTION;
        max_len = msg->arg;
    } else {
        reason = OFPR_NO_MATCH;
        max_len = INT_MAX;
    }
    total_len = msg->length - sizeof *msg;
    in_port = odp_port_to_ofp_port(msg->port);

    /* Repurpose packet buffer by overwriting header. */
    ofpbuf_pull(packet, sizeof(struct odp_msg));
    opi = ofpbuf_push_zeros(packet, offsetof(struct ofp_packet_in, data));
    opi->header.version = OFP_VERSION;
    opi->header.type = OFPT_PACKET_IN;
    opi->total_len = htons(total_len);
    opi->in_port = htons(in_port);
    opi->reason = reason;

    return max_len;
}

/* Given 'packet' containing an odp_msg of type _ODPL_ACTION_NR or
 * _ODPL_MISS_NR, sends an OFPT_PACKET_IN message to each OpenFlow controller
 * as necessary according to their individual configurations.
 *
 * 'packet' must have sufficient headroom to convert it into a struct
 * ofp_packet_in (e.g. as returned by dpif_recv()).
 *
 * Takes ownership of 'packet'. */
static void
send_packet_in(struct ofproto *ofproto, struct ofpbuf *packet)
{
    struct ofconn *ofconn, *prev;
    int max_len;

    max_len = do_convert_to_packet_in(packet);

    prev = NULL;
    LIST_FOR_EACH (ofconn, struct ofconn, node, &ofproto->all_conns) {
        if (ofconn_receives_async_msgs(ofconn)) {
            if (prev) {
                schedule_packet_in(prev, packet, max_len, true);
            }
            prev = ofconn;
        }
    }
    if (prev) {
        schedule_packet_in(prev, packet, max_len, false);
    } else {
        ofpbuf_delete(packet);
    }
}

static uint64_t
pick_datapath_id(const struct ofproto *ofproto)
{
    const struct ofport *port;

    port = port_array_get(&ofproto->ports, ODPP_LOCAL);
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

static bool
default_normal_ofhook_cb(const flow_t *flow, const struct ofpbuf *packet,
                         struct odp_actions *actions, tag_type *tags,
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
        add_output_group_action(actions, DP_GROUP_FLOOD, nf_output_iface);
    } else if (out_port != flow->in_port) {
        odp_actions_add(actions, ODPAT_OUTPUT)->output.port = out_port;
        *nf_output_iface = out_port;
    } else {
        /* Drop. */
    }

    return true;
}

static const struct ofhooks default_ofhooks = {
    NULL,
    default_normal_ofhook_cb,
    NULL,
    NULL
};
