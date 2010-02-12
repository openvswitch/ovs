/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include "classifier.h"
#include "coverage.h"
#include "discovery.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "executer.h"
#include "fail-open.h"
#include "in-band.h"
#include "mac-learning.h"
#include "netdev.h"
#include "netflow.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openflow/openflow-mgmt.h"
#include "openvswitch/datapath-protocol.h"
#include "packets.h"
#include "pinsched.h"
#include "pktbuf.h"
#include "poll-loop.h"
#include "port-array.h"
#include "rconn.h"
#include "shash.h"
#include "status.h"
#include "stp.h"
#include "svec.h"
#include "tag.h"
#include "timeval.h"
#include "unixctl.h"
#include "vconn.h"
#include "vconn-ssl.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_ofproto
#include "vlog.h"

enum {
    DP_GROUP_FLOOD = 0,
    DP_GROUP_ALL = 1
};

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

struct ofconn {
    struct list node;
    struct rconn *rconn;
    struct pktbuf *pktbuf;
    int miss_send_len;

    struct rconn_packet_counter *packet_in_counter;

    /* Number of OpenFlow messages queued as replies to OpenFlow requests, and
     * the maximum number before we stop reading OpenFlow requests.  */
#define OFCONN_REPLY_MAX 100
    struct rconn_packet_counter *reply_counter;
};

static struct ofconn *ofconn_create(struct ofproto *, struct rconn *);
static void ofconn_destroy(struct ofconn *, struct ofproto *);
static void ofconn_run(struct ofconn *, struct ofproto *);
static void ofconn_wait(struct ofconn *);
static void queue_tx(struct ofpbuf *msg, const struct ofconn *ofconn,
                     struct rconn_packet_counter *counter);

struct ofproto {
    /* Settings. */
    uint64_t datapath_id;       /* Datapath ID. */
    uint64_t fallback_dpid;     /* Datapath ID if no better choice found. */
    uint64_t mgmt_id;           /* Management channel identifier. */
    char *manufacturer;         /* Manufacturer. */
    char *hardware;             /* Hardware. */
    char *software;             /* Software version. */
    char *serial;               /* Serial number. */
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
    struct status_category *ss_cat;
    struct in_band *in_band;
    struct discovery *discovery;
    struct fail_open *fail_open;
    struct pinsched *miss_sched, *action_sched;
    struct executer *executer;
    struct netflow *netflow;

    /* Flow table. */
    struct classifier cls;
    bool need_revalidate;
    long long int next_expiration;
    struct tag_set revalidate_set;

    /* OpenFlow connections. */
    struct list all_conns;
    struct ofconn *controller;
    struct pvconn **listeners;
    size_t n_listeners;
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
static void send_packet_in_miss(struct ofpbuf *, void *ofproto);
static void send_packet_in_action(struct ofpbuf *, void *ofproto);
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

static void refresh_port_group(struct ofproto *, unsigned int group);
static void update_port(struct ofproto *, const char *devname);
static int init_ports(struct ofproto *);
static void reinit_ports(struct ofproto *);

int
ofproto_create(const char *datapath, const struct ofhooks *ofhooks, void *aux,
               struct ofproto **ofprotop)
{
    struct odp_stats stats;
    struct ofproto *p;
    struct dpif *dpif;
    int error;

    *ofprotop = NULL;

    /* Connect to datapath and start listening for messages. */
    error = dpif_open(datapath, &dpif);
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
    error = dpif_recv_set_mask(dpif, ODPL_MISS | ODPL_ACTION);
    if (error) {
        VLOG_ERR("failed to listen on datapath %s: %s",
                 datapath, strerror(error));
        dpif_close(dpif);
        return error;
    }
    dpif_flow_flush(dpif);
    dpif_recv_purge(dpif);

    /* Initialize settings. */
    p = xcalloc(1, sizeof *p);
    p->fallback_dpid = pick_fallback_dpid();
    p->datapath_id = p->fallback_dpid;
    p->manufacturer = xstrdup("Nicira Networks, Inc.");
    p->hardware = xstrdup("Reference Implementation");
    p->software = xstrdup(VERSION BUILDNR);
    p->serial = xstrdup("None");
    p->dp_desc = xstrdup("None");

    /* Initialize datapath. */
    p->dpif = dpif;
    p->netdev_monitor = netdev_monitor_create();
    port_array_init(&p->ports);
    shash_init(&p->port_by_name);
    p->max_ports = stats.max_ports;

    /* Initialize submodules. */
    p->switch_status = switch_status_create(p);
    p->in_band = NULL;
    p->discovery = NULL;
    p->fail_open = NULL;
    p->miss_sched = p->action_sched = NULL;
    p->executer = NULL;
    p->netflow = NULL;

    /* Initialize flow table. */
    classifier_init(&p->cls);
    p->need_revalidate = false;
    p->next_expiration = time_msec() + 1000;
    tag_set_init(&p->revalidate_set);

    /* Initialize OpenFlow connections. */
    list_init(&p->all_conns);
    p->controller = ofconn_create(p, rconn_create(5, 8));
    p->controller->pktbuf = pktbuf_create();
    p->controller->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;
    p->listeners = NULL;
    p->n_listeners = 0;
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

    /* Register switch status category. */
    p->ss_cat = switch_status_register(p->switch_status, "remote",
                                       rconn_status_cb, p->controller->rconn);

    /* Almost done... */
    error = init_ports(p);
    if (error) {
        ofproto_destroy(p);
        return error;
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
        rconn_reconnect(p->controller->rconn);
    }
}

void
ofproto_set_mgmt_id(struct ofproto *p, uint64_t mgmt_id)
{
    p->mgmt_id = mgmt_id;
}

void
ofproto_set_probe_interval(struct ofproto *p, int probe_interval)
{
    probe_interval = probe_interval ? MAX(probe_interval, 5) : 0;
    rconn_set_probe_interval(p->controller->rconn, probe_interval);
    if (p->fail_open) {
        int trigger_duration = probe_interval ? probe_interval * 3 : 15;
        fail_open_set_trigger_duration(p->fail_open, trigger_duration);
    }
}

void
ofproto_set_max_backoff(struct ofproto *p, int max_backoff)
{
    rconn_set_max_backoff(p->controller->rconn, max_backoff);
}

void
ofproto_set_desc(struct ofproto *p,
                 const char *manufacturer, const char *hardware,
                 const char *software, const char *serial,
                 const char *dp_desc)
{
    if (manufacturer) {
        free(p->manufacturer);
        p->manufacturer = xstrdup(manufacturer);
    }
    if (hardware) {
        free(p->hardware);
        p->hardware = xstrdup(hardware);
    }
    if (software) {
        free(p->software);
        p->software = xstrdup(software);
    }
    if (serial) {
        free(p->serial);
        p->serial = xstrdup(serial);
    }
    if (dp_desc) {
        free(p->dp_desc);
        p->dp_desc = xstrdup(dp_desc);
    }
}

int
ofproto_set_in_band(struct ofproto *p, bool in_band)
{
    if (in_band != (p->in_band != NULL)) {
        if (in_band) {
            return in_band_create(p, p->dpif, p->switch_status,
                                  p->controller->rconn, &p->in_band);
        } else {
            ofproto_set_discovery(p, false, NULL, true);
            in_band_destroy(p->in_band);
            p->in_band = NULL;
        }
        rconn_reconnect(p->controller->rconn);
    }
    return 0;
}

int
ofproto_set_discovery(struct ofproto *p, bool discovery,
                      const char *re, bool update_resolv_conf)
{
    if (discovery != (p->discovery != NULL)) {
        if (discovery) {
            int error = ofproto_set_in_band(p, true);
            if (error) {
                return error;
            }
            error = discovery_create(re, update_resolv_conf,
                                     p->dpif, p->switch_status,
                                     &p->discovery);
            if (error) {
                return error;
            }
        } else {
            discovery_destroy(p->discovery);
            p->discovery = NULL;
        }
        rconn_disconnect(p->controller->rconn);
    } else if (discovery) {
        discovery_set_update_resolv_conf(p->discovery, update_resolv_conf);
        return discovery_set_accept_controller_re(p->discovery, re);
    }
    return 0;
}

int
ofproto_set_controller(struct ofproto *ofproto, const char *controller)
{
    if (ofproto->discovery) {
        return EINVAL;
    } else if (controller) {
        if (strcmp(rconn_get_name(ofproto->controller->rconn), controller)) {
            return rconn_connect(ofproto->controller->rconn, controller);
        } else {
            return 0;
        }
    } else {
        rconn_disconnect(ofproto->controller->rconn);
        return 0;
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
ofproto_set_listeners(struct ofproto *ofproto, const struct svec *listeners)
{
    return set_pvconns(&ofproto->listeners, &ofproto->n_listeners, listeners);
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
    if (nf_options->collectors.n) {
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
ofproto_set_failure(struct ofproto *ofproto, bool fail_open)
{
    if (fail_open) {
        struct rconn *rconn = ofproto->controller->rconn;
        int trigger_duration = rconn_get_probe_interval(rconn) * 3;
        if (!ofproto->fail_open) {
            ofproto->fail_open = fail_open_create(ofproto, trigger_duration,
                                                  ofproto->switch_status,
                                                  rconn);
        } else {
            fail_open_set_trigger_duration(ofproto->fail_open,
                                           trigger_duration);
        }
    } else {
        fail_open_destroy(ofproto->fail_open);
        ofproto->fail_open = NULL;
    }
}

void
ofproto_set_rate_limit(struct ofproto *ofproto,
                       int rate_limit, int burst_limit)
{
    if (rate_limit > 0) {
        if (!ofproto->miss_sched) {
            ofproto->miss_sched = pinsched_create(rate_limit, burst_limit,
                                                  ofproto->switch_status);
            ofproto->action_sched = pinsched_create(rate_limit, burst_limit,
                                                    NULL);
        } else {
            pinsched_set_limits(ofproto->miss_sched, rate_limit, burst_limit);
            pinsched_set_limits(ofproto->action_sched,
                                rate_limit, burst_limit);
        }
    } else {
        pinsched_destroy(ofproto->miss_sched);
        ofproto->miss_sched = NULL;
        pinsched_destroy(ofproto->action_sched);
        ofproto->action_sched = NULL;
    }
}

int
ofproto_set_stp(struct ofproto *ofproto UNUSED, bool enable_stp)
{
    /* XXX */
    if (enable_stp) {
        VLOG_WARN("STP is not yet implemented");
        return EINVAL;
    } else {
        return 0;
    }
}

int
ofproto_set_remote_execution(struct ofproto *ofproto, const char *command_acl,
                             const char *command_dir)
{
    if (command_acl) {
        if (!ofproto->executer) {
            return executer_create(command_acl, command_dir,
                                   &ofproto->executer);
        } else {
            executer_set_acl(ofproto->executer, command_acl, command_dir);
        }
    } else {
        executer_destroy(ofproto->executer);
        ofproto->executer = NULL;
    }
    return 0;
}

uint64_t
ofproto_get_datapath_id(const struct ofproto *ofproto)
{
    return ofproto->datapath_id;
}

uint64_t
ofproto_get_mgmt_id(const struct ofproto *ofproto)
{
    return ofproto->mgmt_id;
}

int
ofproto_get_probe_interval(const struct ofproto *ofproto)
{
    return rconn_get_probe_interval(ofproto->controller->rconn);
}

int
ofproto_get_max_backoff(const struct ofproto *ofproto)
{
    return rconn_get_max_backoff(ofproto->controller->rconn);
}

bool
ofproto_get_in_band(const struct ofproto *ofproto)
{
    return ofproto->in_band != NULL;
}

bool
ofproto_get_discovery(const struct ofproto *ofproto)
{
    return ofproto->discovery != NULL;
}

const char *
ofproto_get_controller(const struct ofproto *ofproto)
{
    return rconn_get_name(ofproto->controller->rconn);
}

void
ofproto_get_listeners(const struct ofproto *ofproto, struct svec *listeners)
{
    size_t i;

    for (i = 0; i < ofproto->n_listeners; i++) {
        svec_add(listeners, pvconn_get_name(ofproto->listeners[i]));
    }
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
    struct ofconn *ofconn, *next_ofconn;
    struct ofport *ofport;
    unsigned int port_no;
    size_t i;

    if (!p) {
        return;
    }

    ofproto_flush_flows(p);
    classifier_destroy(&p->cls);

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, struct ofconn, node,
                        &p->all_conns) {
        ofconn_destroy(ofconn, p);
    }

    dpif_close(p->dpif);
    netdev_monitor_destroy(p->netdev_monitor);
    PORT_ARRAY_FOR_EACH (ofport, &p->ports, port_no) {
        ofport_free(ofport);
    }
    shash_destroy(&p->port_by_name);

    switch_status_destroy(p->switch_status);
    in_band_destroy(p->in_band);
    discovery_destroy(p->discovery);
    fail_open_destroy(p->fail_open);
    pinsched_destroy(p->miss_sched);
    pinsched_destroy(p->action_sched);
    executer_destroy(p->executer);
    netflow_destroy(p->netflow);

    switch_status_unregister(p->ss_cat);

    for (i = 0; i < p->n_listeners; i++) {
        pvconn_close(p->listeners[i]);
    }
    free(p->listeners);

    for (i = 0; i < p->n_snoops; i++) {
        pvconn_close(p->snoops[i]);
    }
    free(p->snoops);

    mac_learning_destroy(p->ml);

    free(p->manufacturer);
    free(p->hardware);
    free(p->software);
    free(p->serial);
    free(p->dp_desc);

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

int
ofproto_run1(struct ofproto *p)
{
    struct ofconn *ofconn, *next_ofconn;
    char *devname;
    int error;
    int i;

    for (i = 0; i < 50; i++) {
        struct ofpbuf *buf;
        int error;

        error = dpif_recv(p->dpif, &buf);
        if (error) {
            if (error == ENODEV) {
                /* Someone destroyed the datapath behind our back.  The caller
                 * better destroy us and give up, because we're just going to
                 * spin from here on out. */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_ERR_RL(&rl, "%s: datapath was destroyed externally",
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
        in_band_run(p->in_band);
    }
    if (p->discovery) {
        char *controller_name;
        if (rconn_is_connectivity_questionable(p->controller->rconn)) {
            discovery_question_connectivity(p->discovery);
        }
        if (discovery_run(p->discovery, &controller_name)) {
            if (controller_name) {
                rconn_connect(p->controller->rconn, controller_name);
            } else {
                rconn_disconnect(p->controller->rconn);
            }
        }
    }
    pinsched_run(p->miss_sched, send_packet_in_miss, p);
    pinsched_run(p->action_sched, send_packet_in_action, p);
    if (p->executer) {
        executer_run(p->executer);
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

    for (i = 0; i < p->n_listeners; i++) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(p->listeners[i], OFP_VERSION, &vconn);
        if (!retval) {
            ofconn_create(p, rconn_new_from_vconn("passive", vconn));
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", strerror(retval));
        }
    }

    for (i = 0; i < p->n_snoops; i++) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(p->snoops[i], OFP_VERSION, &vconn);
        if (!retval) {
            rconn_add_monitor(p->controller->rconn, vconn);
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
    struct ofconn *ofconn;
    size_t i;

    dpif_recv_wait(p->dpif);
    dpif_port_poll_wait(p->dpif);
    netdev_monitor_poll_wait(p->netdev_monitor);
    LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
        ofconn_wait(ofconn);
    }
    if (p->in_band) {
        in_band_wait(p->in_band);
    }
    if (p->discovery) {
        discovery_wait(p->discovery);
    }
    if (p->fail_open) {
        fail_open_wait(p->fail_open);
    }
    pinsched_wait(p->miss_sched);
    pinsched_wait(p->action_sched);
    if (p->executer) {
        executer_wait(p->executer);
    }
    if (!tag_set_is_empty(&p->revalidate_set)) {
        poll_immediate_wake();
    }
    if (p->need_revalidate) {
        /* Shouldn't happen, but if it does just go around again. */
        VLOG_DBG_RL(&rl, "need revalidate in ofproto_wait_cb()");
        poll_immediate_wake();
    } else if (p->next_expiration != LLONG_MAX) {
        poll_timer_wait(p->next_expiration - time_msec());
    }
    for (i = 0; i < p->n_listeners; i++) {
        pvconn_wait(p->listeners[i]);
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
    return p->discovery || rconn_is_alive(p->controller->rconn);
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
    cls_rule_from_flow(&rule->cr, flow, wildcards, priority);
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

static void
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
}

static void
refresh_port_groups(struct ofproto *p)
{
    refresh_port_group(p, DP_GROUP_FLOOD);
    refresh_port_group(p, DP_GROUP_ALL);
}

static struct ofport *
make_ofport(const struct odp_port *odp_port)
{
    enum netdev_flags flags;
    struct ofport *ofport;
    struct netdev *netdev;
    bool carrier;
    int error;

    error = netdev_open(odp_port->devname, NETDEV_ETH_TYPE_NONE, &netdev);
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
    netdev_monitor_add(p->netdev_monitor, ofport->netdev);
    port_array_set(&p->ports, ofp_port_to_odp_port(ofport->opp.port_no),
                   ofport);
    shash_add(&p->port_by_name, (char *) ofport->opp.name, ofport);
}

static void
ofport_remove(struct ofproto *p, struct ofport *ofport)
{
    netdev_monitor_remove(p->netdev_monitor, ofport->netdev);
    port_array_set(&p->ports, ofp_port_to_odp_port(ofport->opp.port_no), NULL);
    shash_delete(&p->port_by_name,
                 shash_find(&p->port_by_name, (char *) ofport->opp.name));
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
ofconn_create(struct ofproto *p, struct rconn *rconn)
{
    struct ofconn *ofconn = xmalloc(sizeof *ofconn);
    list_push_back(&p->all_conns, &ofconn->node);
    ofconn->rconn = rconn;
    ofconn->pktbuf = NULL;
    ofconn->miss_send_len = 0;
    ofconn->packet_in_counter = rconn_packet_counter_create ();
    ofconn->reply_counter = rconn_packet_counter_create ();
    return ofconn;
}

static void
ofconn_destroy(struct ofconn *ofconn, struct ofproto *p)
{
    if (p->executer) {
        executer_rconn_closing(p->executer, ofconn->rconn);
    }

    list_remove(&ofconn->node);
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

    if (ofconn != p->controller && !rconn_is_alive(ofconn->rconn)) {
        ofconn_destroy(ofconn, p);
    }
}

static void
ofconn_wait(struct ofconn *ofconn)
{
    rconn_run_wait(ofconn->rconn);
    if (rconn_packet_counter_read (ofconn->reply_counter) < OFCONN_REPLY_MAX) {
        rconn_recv_wait(ofconn->rconn);
    } else {
        COVERAGE_INC(ofproto_ofconn_stuck);
    }
}

/* Caller is responsible for initializing the 'cr' member of the returned
 * rule. */
static struct rule *
rule_create(struct ofproto *ofproto, struct rule *super,
            const union ofp_action *actions, size_t n_actions,
            uint16_t idle_timeout, uint16_t hard_timeout,
            uint64_t flow_cookie, bool send_flow_removed)
{
    struct rule *rule = xcalloc(1, sizeof *rule);
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
        if (oa->type == htons(OFPAT_OUTPUT) && oa->output.port == out_port) {
            return true;
        }
    }
    return false;
}

/* Executes the actions indicated by 'rule' on 'packet', which is in flow
 * 'flow' and is considered to have arrived on ODP port 'in_port'.
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
 * actions and apply them to 'packet'. */
static void
rule_execute(struct ofproto *ofproto, struct rule *rule,
             struct ofpbuf *packet, const flow_t *flow)
{
    const union odp_action *actions;
    size_t n_actions;
    struct odp_actions a;

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
            return;
        }
        actions = a.actions;
        n_actions = a.n_actions;
    } else {
        actions = rule->odp_actions;
        n_actions = rule->n_odp_actions;
    }

    /* Execute the ODP actions. */
    if (!dpif_execute(ofproto->dpif, flow->in_port,
                      actions, n_actions, packet)) {
        struct odp_flow_stats stats;
        flow_extract_stats(flow, packet, &stats);
        update_stats(ofproto, rule, &stats);
        rule->used = time_msec();
        netflow_flow_update_time(ofproto->netflow, &rule->nf_flow, rule->used);
    }
}

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
        flow_extract(packet, in_port, &flow);
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
    cls_rule_from_flow(&subrule->cr, flow, 0,
                       (rule->cr.priority <= UINT16_MAX ? UINT16_MAX
                        : rule->cr.priority));
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
            &rule->cr.flow, rule->odp_actions, rule->n_odp_actions,
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

    if (rule && rule->super) {
        struct rule *super = rule->super;

        return super->n_actions == 1 &&
               super->actions[0].type == htons(OFPAT_OUTPUT) &&
               super->actions[0].output.port == htons(OFPP_CONTROLLER);
    }

    return false;
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
                         (1u << OFPAT_SET_TP_DST));

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

    if (ofconn == p->controller) {
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

    if ((ntohs(osc->miss_send_len) != 0) != (ofconn->miss_send_len != 0)) {
        if (ntohs(osc->miss_send_len) != 0) {
            ofconn->pktbuf = pktbuf_create();
        } else {
            pktbuf_destroy(ofconn->pktbuf);
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
add_controller_action(struct odp_actions *actions,
                      const struct ofp_action_output *oao)
{
    union odp_action *a = odp_actions_add(actions, ODPAT_CONTROLLER);
    a->controller.arg = oao->max_len ? ntohs(oao->max_len) : UINT32_MAX;
}

struct action_xlate_ctx {
    /* Input. */
    const flow_t *flow;         /* Flow to which these actions correspond. */
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
    if (!ctx->recurse) {
        struct rule *rule;
        flow_t flow;

        flow = *ctx->flow;
        flow.in_port = in_port;

        rule = lookup_valid_rule(ctx->ofproto, &flow);
        if (rule) {
            if (rule->super) {
                rule = rule->super;
            }

            ctx->recurse++;
            do_xlate_actions(rule->actions, rule->n_actions, ctx);
            ctx->recurse--;
        }
    }
}

static void
xlate_output_action(struct action_xlate_ctx *ctx,
                    const struct ofp_action_output *oao)
{
    uint16_t odp_port;
    uint16_t prev_nf_output_iface = ctx->nf_output_iface;

    ctx->nf_output_iface = NF_OUT_DROP;

    switch (ntohs(oao->port)) {
    case OFPP_IN_PORT:
        add_output_action(ctx, ctx->flow->in_port);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->flow->in_port);
        break;
    case OFPP_NORMAL:
        if (!ctx->ofproto->ofhooks->normal_cb(ctx->flow, ctx->packet,
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
        add_controller_action(ctx->out, oao);
        break;
    case OFPP_LOCAL:
        add_output_action(ctx, ODPP_LOCAL);
        break;
    default:
        odp_port = ofp_port_to_odp_port(ntohs(oao->port));
        if (odp_port != ctx->flow->in_port) {
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
xlate_nicira_action(struct action_xlate_ctx *ctx,
                    const struct nx_action_header *nah)
{
    const struct nx_action_resubmit *nar;
    int subtype = ntohs(nah->subtype);

    assert(nah->vendor == htonl(NX_VENDOR_ID));
    switch (subtype) {
    case NXAST_RESUBMIT:
        nar = (const struct nx_action_resubmit *) nah;
        xlate_table_action(ctx, ofp_port_to_odp_port(ntohs(nar->in_port)));
        break;

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

    port = port_array_get(&ctx->ofproto->ports, ctx->flow->in_port);
    if (port && port->opp.config & (OFPPC_NO_RECV | OFPPC_NO_RECV_STP) &&
        port->opp.config & (eth_addr_equals(ctx->flow->dl_dst, stp_eth_addr)
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
            oa->vlan_vid.vlan_vid = ia->vlan_vid.vlan_vid;
            break;

        case OFPAT_SET_VLAN_PCP:
            oa = odp_actions_add(ctx->out, ODPAT_SET_VLAN_PCP);
            oa->vlan_pcp.vlan_pcp = ia->vlan_pcp.vlan_pcp;
            break;

        case OFPAT_STRIP_VLAN:
            odp_actions_add(ctx->out, ODPAT_STRIP_VLAN);
            break;

        case OFPAT_SET_DL_SRC:
            oa = odp_actions_add(ctx->out, ODPAT_SET_DL_SRC);
            memcpy(oa->dl_addr.dl_addr,
                   ((struct ofp_action_dl_addr *) ia)->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_DL_DST:
            oa = odp_actions_add(ctx->out, ODPAT_SET_DL_DST);
            memcpy(oa->dl_addr.dl_addr,
                   ((struct ofp_action_dl_addr *) ia)->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_NW_SRC:
            oa = odp_actions_add(ctx->out, ODPAT_SET_NW_SRC);
            oa->nw_addr.nw_addr = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_DST:
            oa = odp_actions_add(ctx->out, ODPAT_SET_NW_DST);
            oa->nw_addr.nw_addr = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_TOS:
            oa = odp_actions_add(ctx->out, ODPAT_SET_NW_TOS);
            oa->nw_tos.nw_tos = ia->nw_tos.nw_tos;
            break;

        case OFPAT_SET_TP_SRC:
            oa = odp_actions_add(ctx->out, ODPAT_SET_TP_SRC);
            oa->tp_port.tp_port = ia->tp_port.tp_port;
            break;

        case OFPAT_SET_TP_DST:
            oa = odp_actions_add(ctx->out, ODPAT_SET_TP_DST);
            oa->tp_port.tp_port = ia->tp_port.tp_port;
            break;

        case OFPAT_VENDOR:
            xlate_nicira_action(ctx, (const struct nx_action_header *) ia);
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
    ctx.flow = flow;
    ctx.recurse = 0;
    ctx.ofproto = ofproto;
    ctx.packet = packet;
    ctx.out = out;
    ctx.tags = tags ? tags : &no_tags;
    ctx.may_set_up_flow = true;
    ctx.nf_output_iface = NF_OUT_DROP;
    do_xlate_actions(in, n_in, &ctx);

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
        odp_actions_init(out);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_TOO_MANY);
    }
    return 0;
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

    flow_extract(&payload, ofp_port_to_odp_port(ntohs(opo->in_port)), &flow);
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
        refresh_port_group(p, DP_GROUP_FLOOD);
    }
    if (mask & OFPPC_NO_PACKET_IN) {
        port->opp.config ^= OFPPC_NO_PACKET_IN;
    }
}

static int
handle_port_mod(struct ofproto *p, struct ofp_header *oh)
{
    const struct ofp_port_mod *opm;
    struct ofport *port;
    int error;

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
    strncpy(ods->mfr_desc, p->manufacturer, sizeof ods->mfr_desc);
    strncpy(ods->hw_desc, p->hardware, sizeof ods->hw_desc);
    strncpy(ods->sw_desc, p->software, sizeof ods->sw_desc);
    strncpy(ods->serial_num, p->serial, sizeof ods->serial_num);
    strncpy(ods->dp_desc, p->dp_desc, sizeof ods->dp_desc);
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
    ots->wildcards = htonl(OFPFW_ALL);
    ots->max_entries = htonl(65536);
    ots->active_count = htonl(n_wild);
    ots->lookup_count = htonll(0);              /* XXX */
    ots->matched_count = htonll(0);             /* XXX */

    queue_tx(msg, ofconn, ofconn->reply_counter);
    return 0;
}

static void
append_port_stat(struct ofport *port, uint16_t port_no, struct ofconn *ofconn, 
                 struct ofpbuf *msg)
{
    struct netdev_stats stats;
    struct ofp_port_stats *ops;

    /* Intentionally ignore return value, since errors will set 
     * 'stats' to all-1s, which is correct for OpenFlow, and 
     * netdev_get_stats() will log errors. */
    netdev_get_stats(port->netdev, &stats);

    ops = append_stats_reply(sizeof *ops, ofconn, &msg);
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
            append_port_stat(port, ntohs(psr->port_no), ofconn, msg);
        }
    } else {
        PORT_ARRAY_FOR_EACH (port, &p->ports, port_no) {
            append_port_stat(port, port_no, ofconn, msg);
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

static void
query_stats(struct ofproto *p, struct rule *rule,
            uint64_t *packet_countp, uint64_t *byte_countp)
{
    uint64_t packet_count, byte_count;
    struct rule *subrule;
    struct odp_flow *odp_flows;
    size_t n_odp_flows;

    packet_count = rule->packet_count;
    byte_count = rule->byte_count;

    n_odp_flows = rule->cr.wc.wildcards ? list_size(&rule->list) : 1;
    odp_flows = xcalloc(1, n_odp_flows * sizeof *odp_flows);
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

    packet_count = rule->packet_count;
    byte_count = rule->byte_count;
    if (!dpif_flow_get_multiple(p->dpif, odp_flows, n_odp_flows)) {
        size_t i;
        for (i = 0; i < n_odp_flows; i++) {
            struct odp_flow *odp_flow = &odp_flows[i];
            packet_count += odp_flow->stats.n_packets;
            byte_count += odp_flow->stats.n_bytes;
        }
    }
    free(odp_flows);

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
    flow_to_match(&rule->cr.flow, rule->cr.wc.wildcards, &ofs->match);
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
    cls_rule_from_match(&target, &fsr->match, 0);
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
    flow_to_match(&rule->cr.flow, rule->cr.wc.wildcards, &match);

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
    match.wildcards = htonl(OFPFW_ALL);

    cbdata.ofproto = p;
    cbdata.results = results;

    cls_rule_from_match(&target, &match, 0);
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
    cls_rule_from_match(&target, &asr->match, 0);
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
        netflow_flow_update_flags(&rule->nf_flow, stats->ip_tos,
                                  stats->tcp_flags);
    }
}

static int
add_flow(struct ofproto *p, struct ofconn *ofconn,
         struct ofp_flow_mod *ofm, size_t n_actions)
{
    struct ofpbuf *packet;
    struct rule *rule;
    uint16_t in_port;
    int error;

    if (ofm->flags & htons(OFPFF_CHECK_OVERLAP)) {
        flow_t flow;
        uint32_t wildcards;

        flow_from_match(&flow, &wildcards, &ofm->match);
        if (classifier_rule_overlaps(&p->cls, &flow, wildcards,
                                     ntohs(ofm->priority))) {
            return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        }
    }

    rule = rule_create(p, NULL, (const union ofp_action *) ofm->actions,
                       n_actions, ntohs(ofm->idle_timeout),
                       ntohs(ofm->hard_timeout),  ofm->cookie,
                       ofm->flags & htons(OFPFF_SEND_FLOW_REM));
    cls_rule_from_match(&rule->cr, &ofm->match, ntohs(ofm->priority));

    packet = NULL;
    error = 0;
    if (ofm->buffer_id != htonl(UINT32_MAX)) {
        error = pktbuf_retrieve(ofconn->pktbuf, ntohl(ofm->buffer_id),
                                &packet, &in_port);
    }

    rule_insert(p, rule, packet, in_port);
    ofpbuf_delete(packet);
    return error;
}

static int
modify_flow(struct ofproto *p, const struct ofp_flow_mod *ofm,
            size_t n_actions, uint16_t command, struct rule *rule)
{
    if (rule_is_hidden(rule)) {
        return 0;
    }

    if (command == OFPFC_DELETE) {
        long long int now = time_msec();
        send_flow_removed(p, rule, now, OFPRR_DELETE);
        rule_remove(p, rule);
    } else {
        size_t actions_len = n_actions * sizeof *rule->actions;

        if (n_actions == rule->n_actions
            && !memcmp(ofm->actions, rule->actions, actions_len))
        {
            return 0;
        }

        free(rule->actions);
        rule->actions = xmemdup(ofm->actions, actions_len);
        rule->n_actions = n_actions;
        rule->flow_cookie = ofm->cookie;

        if (rule->cr.wc.wildcards) {
            COVERAGE_INC(ofproto_mod_wc_flow);
            p->need_revalidate = true;
        } else {
            rule_update_actions(p, rule);
        }
    }

    return 0;
}

static int
modify_flows_strict(struct ofproto *p, const struct ofp_flow_mod *ofm,
                    size_t n_actions, uint16_t command)
{
    struct rule *rule;
    uint32_t wildcards;
    flow_t flow;

    flow_from_match(&flow, &wildcards, &ofm->match);
    rule = rule_from_cls_rule(classifier_find_rule_exactly(
                                  &p->cls, &flow, wildcards,
                                  ntohs(ofm->priority)));

    if (rule) {
        if (command == OFPFC_DELETE
            && ofm->out_port != htons(OFPP_NONE)
            && !rule_has_out_port(rule, ofm->out_port)) {
            return 0;
        }

        modify_flow(p, ofm, n_actions, command, rule);
    }
    return 0;
}

struct modify_flows_cbdata {
    struct ofproto *ofproto;
    const struct ofp_flow_mod *ofm;
    uint16_t out_port;
    size_t n_actions;
    uint16_t command;
};

static void
modify_flows_cb(struct cls_rule *rule_, void *cbdata_)
{
    struct rule *rule = rule_from_cls_rule(rule_);
    struct modify_flows_cbdata *cbdata = cbdata_;

    if (cbdata->out_port != htons(OFPP_NONE)
        && !rule_has_out_port(rule, cbdata->out_port)) {
        return;
    }

    modify_flow(cbdata->ofproto, cbdata->ofm, cbdata->n_actions,
                cbdata->command, rule);
}

static int
modify_flows_loose(struct ofproto *p, const struct ofp_flow_mod *ofm,
                   size_t n_actions, uint16_t command)
{
    struct modify_flows_cbdata cbdata;
    struct cls_rule target;

    cbdata.ofproto = p;
    cbdata.ofm = ofm;
    cbdata.out_port = (command == OFPFC_DELETE ? ofm->out_port
                       : htons(OFPP_NONE));
    cbdata.n_actions = n_actions;
    cbdata.command = command;

    cls_rule_from_match(&target, &ofm->match, 0);

    classifier_for_each_match(&p->cls, &target, CLS_INC_ALL,
                              modify_flows_cb, &cbdata);
    return 0;
}

static int
handle_flow_mod(struct ofproto *p, struct ofconn *ofconn,
                struct ofp_flow_mod *ofm)
{
    size_t n_actions;
    int error;

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

    normalize_match(&ofm->match);
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
        return modify_flows_loose(p, ofm, n_actions, OFPFC_MODIFY);

    case OFPFC_MODIFY_STRICT:
        return modify_flows_strict(p, ofm, n_actions, OFPFC_MODIFY);

    case OFPFC_DELETE:
        return modify_flows_loose(p, ofm, n_actions, OFPFC_DELETE);

    case OFPFC_DELETE_STRICT:
        return modify_flows_strict(p, ofm, n_actions, OFPFC_DELETE);

    default:
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
    }
}

static void
send_capability_reply(struct ofproto *p, struct ofconn *ofconn, uint32_t xid)
{
    struct ofmp_capability_reply *ocr;
    struct ofpbuf *b;
    char capabilities[] = "com.nicira.mgmt.manager=false\n";

    ocr = make_openflow_xid(sizeof(*ocr), OFPT_VENDOR, xid, &b);
    ocr->header.header.vendor = htonl(NX_VENDOR_ID);
    ocr->header.header.subtype = htonl(NXT_MGMT);
    ocr->header.type = htons(OFMPT_CAPABILITY_REPLY);

    ocr->format = htonl(OFMPCOF_SIMPLE);
    ocr->mgmt_id = htonll(p->mgmt_id);

    ofpbuf_put(b, capabilities, strlen(capabilities));

    queue_tx(b, ofconn, ofconn->reply_counter);
}

static int
handle_ofmp(struct ofproto *p, struct ofconn *ofconn, 
            struct ofmp_header *ofmph)
{
    size_t msg_len = ntohs(ofmph->header.header.length);
    if (msg_len < sizeof(*ofmph)) {
        VLOG_WARN_RL(&rl, "dropping short managment message: %zu\n", msg_len);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (ofmph->type == htons(OFMPT_CAPABILITY_REQUEST)) {
        struct ofmp_capability_request *ofmpcr;

        if (msg_len < sizeof(struct ofmp_capability_request)) {
            VLOG_WARN_RL(&rl, "dropping short capability request: %zu\n",
                    msg_len);
            return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }

        ofmpcr = (struct ofmp_capability_request *)ofmph;
        if (ofmpcr->format != htonl(OFMPCAF_SIMPLE)) {
            /* xxx Find a better type than bad subtype */
            return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
        }

        send_capability_reply(p, ofconn, ofmph->header.header.xid);
        return 0;
    } else {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
    }
}

static int
handle_vendor(struct ofproto *p, struct ofconn *ofconn, void *msg)
{
    struct ofp_vendor_header *ovh = msg;
    struct nicira_header *nh;

    if (ntohs(ovh->header.length) < sizeof(struct ofp_vendor_header)) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if (ovh->vendor != htonl(NX_VENDOR_ID)) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_VENDOR);
    }
    if (ntohs(ovh->header.length) < sizeof(struct nicira_header)) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    nh = msg;
    switch (ntohl(nh->subtype)) {
    case NXT_STATUS_REQUEST:
        return switch_status_handle_request(p->switch_status, ofconn->rconn,
                                            msg);

    case NXT_ACT_SET_CONFIG:
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE); /* XXX */

    case NXT_ACT_GET_CONFIG:
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE); /* XXX */

    case NXT_COMMAND_REQUEST:
        if (p->executer) {
            return executer_handle_request(p->executer, ofconn->rconn, msg);
        }
        break;

    case NXT_MGMT:
        return handle_ofmp(p, ofconn, msg);
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
        error = handle_port_mod(p, oh);
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
handle_odp_msg(struct ofproto *p, struct ofpbuf *packet)
{
    struct odp_msg *msg = packet->data;
    uint16_t in_port = odp_port_to_ofp_port(msg->port);
    struct rule *rule;
    struct ofpbuf payload;
    flow_t flow;

    /* Handle controller actions. */
    if (msg->type == _ODPL_ACTION_NR) {
        COVERAGE_INC(ofproto_ctlr_action);
        pinsched_send(p->action_sched, in_port, packet,
                      send_packet_in_action, p);
        return;
    }

    payload.data = msg + 1;
    payload.size = msg->length - sizeof *msg;
    flow_extract(&payload, msg->port, &flow);

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
        pinsched_send(p->miss_sched, in_port, packet, send_packet_in_miss, p);
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

    rule_execute(p, rule, &payload, &flow);
    rule_reinstall(p, rule);

    if (rule->super && rule->super->cr.priority == FAIL_OPEN_PRIORITY
        && rconn_is_connected(p->controller->rconn)) {
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
        pinsched_send(p->miss_sched, in_port, packet, send_packet_in_miss, p);
    } else {
        ofpbuf_delete(packet);
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
compose_flow_removed(const struct rule *rule, long long int now, uint8_t reason)
{
    struct ofp_flow_removed *ofr;
    struct ofpbuf *buf;
    long long int last_used = rule->used ? now - rule->used : 0;
    long long int tdiff = time_msec() - rule->created - last_used;
    uint32_t sec = tdiff / 1000;
    uint32_t msec = tdiff - (sec * 1000);

    ofr = make_openflow(sizeof *ofr, OFPT_FLOW_REMOVED, &buf);
    flow_to_match(&rule->cr.flow, rule->cr.wc.wildcards, &ofr->match);
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
        if (rule->send_flow_removed && rconn_is_connected(ofconn->rconn)) {
            if (prev) {
                queue_tx(ofpbuf_clone(buf), prev, prev->reply_counter);
            } else {
                buf = compose_flow_removed(rule, now, reason);
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
                netflow_flow_update_flags(&rule->nf_flow, odp_flow.stats.ip_tos,
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

static void
do_send_packet_in(struct ofconn *ofconn, uint32_t buffer_id,
                  const struct ofpbuf *packet, int send_len)
{
    struct odp_msg *msg = packet->data;
    struct ofpbuf payload;
    struct ofpbuf *opi;
    uint8_t reason;

    /* Extract packet payload from 'msg'. */
    payload.data = msg + 1;
    payload.size = msg->length - sizeof *msg;

    /* Construct ofp_packet_in message. */
    reason = msg->type == _ODPL_ACTION_NR ? OFPR_ACTION : OFPR_NO_MATCH;
    opi = make_packet_in(buffer_id, odp_port_to_ofp_port(msg->port), reason,
                         &payload, send_len);

    /* Send. */
    rconn_send_with_limit(ofconn->rconn, opi, ofconn->packet_in_counter, 100);
}

static void
send_packet_in_action(struct ofpbuf *packet, void *p_)
{
    struct ofproto *p = p_;
    struct ofconn *ofconn;
    struct odp_msg *msg;

    msg = packet->data;
    LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
        if (ofconn == p->controller || ofconn->miss_send_len) {
            do_send_packet_in(ofconn, UINT32_MAX, packet, msg->arg);
        }
    }
    ofpbuf_delete(packet);
}

static void
send_packet_in_miss(struct ofpbuf *packet, void *p_)
{
    struct ofproto *p = p_;
    bool in_fail_open = p->fail_open && fail_open_is_active(p->fail_open);
    struct ofconn *ofconn;
    struct ofpbuf payload;
    struct odp_msg *msg;

    msg = packet->data;
    payload.data = msg + 1;
    payload.size = msg->length - sizeof *msg;
    LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
        if (ofconn->miss_send_len) {
            struct pktbuf *pb = ofconn->pktbuf;
            uint32_t buffer_id = (in_fail_open
                                  ? pktbuf_get_null()
                                  : pktbuf_save(pb, &payload, msg->port));
            int send_len = (buffer_id != UINT32_MAX ? ofconn->miss_send_len
                            : UINT32_MAX);
            do_send_packet_in(ofconn, buffer_id, packet, send_len);
        }
    }
    ofpbuf_delete(packet);
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
    eth_addr_random(ea);
    ea[0] = 0x00;               /* Set Nicira OUI. */
    ea[1] = 0x23;
    ea[2] = 0x20;
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
                                              0, flow->in_port);
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
    out_port = mac_learning_lookup_tag(ofproto->ml, flow->dl_dst, 0, tags);
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
