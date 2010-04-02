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
#include "dynamic-string.h"
#include "fail-open.h"
#include "in-band.h"
#include "mac-learning.h"
#include "netdev.h"
#include "netflow.h"
#include "ofp-print.h"
#include "ofproto-sflow.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/xflow.h"
#include "packets.h"
#include "pinsched.h"
#include "pktbuf.h"
#include "poll-loop.h"
#include "port-array.h"
#include "rconn.h"
#include "shash.h"
#include "status.h"
#include "stp.h"
#include "stream-ssl.h"
#include "svec.h"
#include "tag.h"
#include "timeval.h"
#include "unixctl.h"
#include "vconn.h"
#include "wdp.h"
#include "xfif.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_ofproto
#include "vlog.h"

#include "sflow_api.h"

enum {
    TABLEID_HASH = 0,
    TABLEID_CLASSIFIER = 1
};

struct ofproto_rule {
    uint64_t flow_cookie;       /* Controller-issued identifier. 
                                   (Kept in network-byte order.) */
    bool send_flow_removed;     /* Send a flow removed message? */
    tag_type tags;              /* Tags (set only by hooks). */
};

static struct ofproto_rule *
ofproto_rule_cast(const struct wdp_rule *wdp_rule)
{
    return wdp_rule->client_data;
}

static void
ofproto_rule_init(struct wdp_rule *wdp_rule)
{
    wdp_rule->client_data = xzalloc(sizeof(struct ofproto_rule));
}


static inline bool
rule_is_hidden(const struct wdp_rule *rule)
{
    /* Rules with priority higher than UINT16_MAX are set up by ofproto itself
     * (e.g. by in-band control) and are intentionally hidden from the
     * controller. */
    if (rule->cr.flow.priority > UINT16_MAX) {
        return true;
    }

    return false;
}

static void delete_flow(struct ofproto *, struct wdp_rule *, uint8_t reason);

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
static void ofconn_destroy(struct ofconn *);
static void ofconn_run(struct ofconn *, struct ofproto *);
static void ofconn_wait(struct ofconn *);
static void queue_tx(struct ofpbuf *msg, const struct ofconn *ofconn,
                     struct rconn_packet_counter *counter);

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
    struct wdp *wdp;
    uint32_t max_ports;

    /* Configuration. */
    struct switch_status *switch_status;
    struct status_category *ss_cat;
    struct in_band *in_band;
    struct discovery *discovery;
    struct fail_open *fail_open;
    struct pinsched *miss_sched, *action_sched;
    struct netflow *netflow;
    struct ofproto_sflow *sflow;

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
static void send_packet_in_miss(struct wdp_packet *, void *ofproto);
static void send_packet_in_action(struct wdp_packet *, void *ofproto);

static void handle_wdp_packet(struct ofproto *, struct wdp_packet *);

static void handle_openflow(struct ofconn *, struct ofproto *,
                            struct ofpbuf *);

int
ofproto_create(const char *datapath, const char *datapath_type,
               const struct ofhooks *ofhooks, void *aux,
               struct ofproto **ofprotop)
{
    struct wdp_stats stats;
    struct ofproto *p;
    struct wdp *wdp;
    int error;

    *ofprotop = NULL;

    /* Connect to datapath and start listening for messages. */
    error = wdp_open(datapath, datapath_type, &wdp);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s", datapath, strerror(error));
        return error;
    }
    error = wdp_get_wdp_stats(wdp, &stats);
    if (error) {
        VLOG_ERR("failed to obtain stats for datapath %s: %s",
                 datapath, strerror(error));
        wdp_close(wdp);
        return error;
    }
    error = wdp_recv_set_mask(wdp, ((1 << WDP_CHAN_MISS)
                                    | (1 << WDP_CHAN_ACTION)
                                    | (1 << WDP_CHAN_SFLOW)));
    if (error) {
        VLOG_ERR("failed to listen on datapath %s: %s",
                 datapath, strerror(error));
        wdp_close(wdp);
        return error;
    }
    wdp_flow_flush(wdp);
    wdp_recv_purge(wdp);

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
    p->wdp = wdp;
    p->max_ports = stats.max_ports;

    /* Initialize submodules. */
    p->switch_status = switch_status_create(p);
    p->in_band = NULL;
    p->discovery = NULL;
    p->fail_open = NULL;
    p->miss_sched = p->action_sched = NULL;
    p->netflow = NULL;
    p->sflow = NULL;

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
ofproto_set_in_band(struct ofproto *p, bool in_band)
{
    if (in_band != (p->in_band != NULL)) {
        if (in_band) {
            return in_band_create(p, p->wdp, p->switch_status,
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
                                     p->wdp, p->switch_status,
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
            os = ofproto->sflow = ofproto_sflow_create(ofproto->wdp);
            /* XXX ofport */
        }
        ofproto_sflow_set_options(os, oso);
    } else {
        ofproto_sflow_destroy(os);
        ofproto->sflow = NULL;
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
ofproto_set_stp(struct ofproto *ofproto OVS_UNUSED, bool enable_stp)
{
    /* XXX */
    if (enable_stp) {
        VLOG_WARN("STP is not yet implemented");
        return EINVAL;
    } else {
        return 0;
    }
}

uint64_t
ofproto_get_datapath_id(const struct ofproto *ofproto)
{
    return ofproto->datapath_id;
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
    size_t i;

    if (!p) {
        return;
    }

    /* Destroy fail-open early, because it touches the classifier. */
    ofproto_set_failure(p, false);

    ofproto_flush_flows(p);

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, struct ofconn, node,
                        &p->all_conns) {
        ofconn_destroy(ofconn);
    }

    wdp_close(p->wdp);

    switch_status_destroy(p->switch_status);
    in_band_destroy(p->in_band);
    discovery_destroy(p->discovery);
    pinsched_destroy(p->miss_sched);
    pinsched_destroy(p->action_sched);
    netflow_destroy(p->netflow);
    ofproto_sflow_destroy(p->sflow);

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

    free(p->mfr_desc);
    free(p->hw_desc);
    free(p->sw_desc);
    free(p->serial_desc);
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

int
ofproto_run1(struct ofproto *p)
{
    struct ofconn *ofconn, *next_ofconn;
    int i;

    for (i = 0; i < 50; i++) {
        struct wdp_packet packet;
        int error;

        error = wdp_recv(p->wdp, &packet);
        if (error) {
            if (error == ENODEV) {
                /* Someone destroyed the datapath behind our back.  The caller
                 * better destroy us and give up, because we're just going to
                 * spin from here on out. */
                static struct vlog_rate_limit rl2 = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_ERR_RL(&rl2, "%s: datapath was destroyed externally",
                            wdp_name(p->wdp));
                return ENODEV;
            }
            break;
        }

        handle_wdp_packet(p, xmemdup(&packet, sizeof packet));
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
ofproto_run2(struct ofproto *p OVS_UNUSED, bool revalidate_all OVS_UNUSED)
{
    return 0;
}

void
ofproto_wait(struct ofproto *p)
{
    struct ofconn *ofconn;
    size_t i;

    wdp_recv_wait(p->wdp);
    wdp_port_poll_wait(p->wdp);
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
    if (p->sflow) {
        ofproto_sflow_wait(p->sflow);
    }
    for (i = 0; i < p->n_listeners; i++) {
        pvconn_wait(p->listeners[i]);
    }
    for (i = 0; i < p->n_snoops; i++) {
        pvconn_wait(p->snoops[i]);
    }
}

void
ofproto_revalidate(struct ofproto *ofproto OVS_UNUSED, tag_type tag OVS_UNUSED)
{
    //XXX tag_set_add(&ofproto->revalidate_set, tag);
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
    /* XXX Should we translate the wdp_execute() errno value into an OpenFlow
     * error code? */
    wdp_execute(p->wdp, flow->in_port, actions, n_actions, packet);
    return 0;
}

void
ofproto_add_flow(struct ofproto *p, const flow_t *flow,
                 const union ofp_action *actions, size_t n_actions,
                 int idle_timeout)
{
    struct wdp_flow_put put;
    struct wdp_rule *rule;

    put.flags = WDP_PUT_CREATE | WDP_PUT_MODIFY | WDP_PUT_ALL;
    put.flow = flow;
    put.actions = actions;
    put.n_actions = n_actions;
    put.idle_timeout = idle_timeout;
    put.hard_timeout = 0;

    if (!wdp_flow_put(p->wdp, &put, NULL, &rule)) {
        ofproto_rule_init(rule);
    }
}

void
ofproto_delete_flow(struct ofproto *ofproto, const flow_t *flow)
{
    struct wdp_rule *rule = wdp_flow_get(ofproto->wdp, flow);
    if (rule) {
        delete_flow(ofproto, rule, OFPRR_DELETE);
    }
}

void
ofproto_flush_flows(struct ofproto *ofproto)
{
    COVERAGE_INC(ofproto_flush);
    wdp_flow_flush(ofproto->wdp);
    if (ofproto->in_band) {
        in_band_flushed(ofproto->in_band);
    }
    if (ofproto->fail_open) {
        fail_open_flushed(ofproto->fail_open);
    }
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
ofconn_destroy(struct ofconn *ofconn)
{
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
        ofconn_destroy(ofconn);
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

static bool
rule_has_out_port(const struct wdp_rule *rule, uint16_t out_port)
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
    struct ofpbuf *features;
    int error;

    error = wdp_get_features(p->wdp, &features);
    if (!error) {
        struct ofp_switch_features *osf = features->data;

        update_openflow_length(features);
        osf->header.version = OFP_VERSION;
        osf->header.type = OFPT_FEATURES_REPLY;
        osf->header.xid = oh->xid;

        osf->datapath_id = htonll(p->datapath_id);
        osf->n_buffers = htonl(pktbuf_capacity());
        memset(osf->pad, 0, sizeof osf->pad);

        /* Turn on capabilities implemented by ofproto. */
        osf->capabilities |= htonl(OFPC_FLOW_STATS | OFPC_TABLE_STATS |
                                   OFPC_PORT_STATS);

        queue_tx(features, ofconn, ofconn->reply_counter);
    }
    return error;
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
    wdp_get_drop_frags(p->wdp, &drop_frags);
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
            wdp_set_drop_frags(p->wdp, false);
            break;
        case OFPC_FRAG_DROP:
            wdp_set_drop_frags(p->wdp, true);
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

static int
handle_packet_out(struct ofproto *p, struct ofconn *ofconn,
                  struct ofp_header *oh)
{
    struct ofp_packet_out *opo;
    struct ofpbuf payload, *buffer;
    struct ofp_action_header *actions;
    int n_actions;
    uint16_t in_port;
    flow_t flow;
    int error;

    error = check_ofp_packet_out(oh, &payload, &n_actions, p->max_ports);
    if (error) {
        return error;
    }
    opo = (struct ofp_packet_out *) oh;
    actions = opo->actions;

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

    flow_extract(&payload, ntohs(opo->in_port), &flow);
    wdp_execute(p->wdp, flow.in_port, (const union ofp_action *) actions,
                n_actions, &payload);
    ofpbuf_delete(buffer);

    return 0;
}

static int
handle_port_mod(struct ofproto *p, struct ofp_header *oh)
{
    const struct ofp_port_mod *opm;
    struct wdp_port *port;
    int error;

    error = check_ofp_message(oh, OFPT_PORT_MOD, sizeof *opm);
    if (error) {
        return error;
    }
    opm = (struct ofp_port_mod *) oh;

    wdp_port_query_by_number(p->wdp, ntohs(opm->port_no), &port);
    if (!port) {
        return ofp_mkerr(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT);
    } else if (memcmp(port->opp.hw_addr, opm->hw_addr, OFP_ETH_ALEN)) {
        return ofp_mkerr(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR);
    } else {
        uint32_t mask, new_config;

        mask = ntohl(opm->mask) & (OFPPC_PORT_DOWN | OFPPC_NO_STP
                                   | OFPPC_NO_RECV | OFPPC_NO_RECV_STP
                                   | OFPPC_NO_FLOOD | OFPPC_NO_FWD
                                   | OFPPC_NO_PACKET_IN);
        new_config = (port->opp.config & ~mask) | (ntohl(opm->config) & mask);
        if (new_config != port->opp.config) {
            wdp_port_set_config(p->wdp, ntohs(opm->port_no), new_config);
        }
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

static int
handle_table_stats_request(struct ofproto *p, struct ofconn *ofconn,
                           struct ofp_stats_request *request)
{
    struct ofp_table_stats *ots;
    struct ofpbuf *msg;
    struct wdp_stats dpstats;

    msg = start_stats_reply(request, sizeof *ots * 2);

    wdp_get_wdp_stats(p->wdp, &dpstats);

    /* Hash table. */
    ots = append_stats_reply(sizeof *ots, ofconn, &msg);
    memset(ots, 0, sizeof *ots);
    ots->table_id = TABLEID_HASH;
    strcpy(ots->name, "hash");
    ots->wildcards = htonl(0);
    ots->max_entries = htonl(dpstats.exact.max_capacity);
    ots->active_count = htonl(dpstats.exact.n_flows);
    ots->lookup_count = htonll(dpstats.exact.n_hit + dpstats.exact.n_missed);
    ots->matched_count = htonll(dpstats.exact.n_hit);

    /* Classifier table. */
    ots = append_stats_reply(sizeof *ots, ofconn, &msg);
    memset(ots, 0, sizeof *ots);
    ots->table_id = TABLEID_CLASSIFIER;
    strcpy(ots->name, "classifier");
    ots->wildcards = htonl(OFPFW_ALL);
    ots->max_entries = htonl(dpstats.wild.max_capacity);
    ots->active_count = htonl(dpstats.wild.n_flows);
    ots->lookup_count = htonll(dpstats.wild.n_hit + dpstats.wild.n_missed);
    ots->matched_count = htonll(dpstats.wild.n_hit);

    queue_tx(msg, ofconn, ofconn->reply_counter);
    return 0;
}

static void
append_port_stat(struct wdp_port *port, struct ofconn *ofconn,
                 struct ofpbuf *msg)
{
    struct netdev_stats stats;
    struct ofp_port_stats *ops;

    /* Intentionally ignore return value, since errors will set 
     * 'stats' to all-1s, which is correct for OpenFlow, and 
     * netdev_get_stats() will log errors. */
    netdev_get_stats(port->netdev, &stats);

    ops = append_stats_reply(sizeof *ops, ofconn, &msg);
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
handle_port_stats_request(struct ofproto *p, struct ofconn *ofconn,
                          struct ofp_stats_request *osr,
                          size_t arg_size)
{
    struct ofp_port_stats_request *psr;
    struct ofp_port_stats *ops;
    struct ofpbuf *msg;

    if (arg_size != sizeof *psr) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    psr = (struct ofp_port_stats_request *) osr->body;

    msg = start_stats_reply(osr, sizeof *ops * 16);
    if (psr->port_no != htons(OFPP_NONE)) {
        struct wdp_port *port;

        wdp_port_query_by_number(p->wdp, ntohs(psr->port_no), &port);
        if (port) {
            append_port_stat(port, ofconn, msg);
        }
    } else {
        struct wdp_port **ports;
        size_t n_ports;
        size_t i;

        wdp_port_list(p->wdp, &ports, &n_ports);
        for (i = 0; i < n_ports; i++) {
            append_port_stat(ports[i], ofconn, msg);
        }
        free(ports);
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
query_stats(struct ofproto *p, struct wdp_rule *rule,
            uint64_t *packet_countp, uint64_t *byte_countp)
{
    struct wdp_flow_stats stats;

    if (!wdp_flow_get_stats(p->wdp, rule, &stats)) {
        *packet_countp = stats.n_packets;
        *byte_countp = stats.n_bytes;
    } else {
        *packet_countp = 0;
        *byte_countp = 0;
    }
}

static void
flow_stats_cb(struct wdp_rule *rule, void *cbdata_)
{
    struct flow_stats_cbdata *cbdata = cbdata_;
    struct ofp_flow_stats *ofs;
    uint64_t packet_count, byte_count;
    size_t act_len, len;
    long long int tdiff = time_msec() - rule->created;
    uint32_t sec = tdiff / 1000;
    uint32_t msec = tdiff - (sec * 1000);

    if (rule_is_hidden(rule)
        || !rule_has_out_port(rule, cbdata->out_port)) {
        return;
    }

    act_len = sizeof *rule->actions * rule->n_actions;
    len = offsetof(struct ofp_flow_stats, actions) + act_len;

    query_stats(cbdata->ofproto, rule, &packet_count, &byte_count);

    ofs = append_stats_reply(len, cbdata->ofconn, &cbdata->msg);
    ofs->length = htons(len);
    ofs->table_id = rule->cr.flow.wildcards ? TABLEID_CLASSIFIER : TABLEID_HASH;
    ofs->pad = 0;
    flow_to_match(&rule->cr.flow, &ofs->match);
    ofs->duration_sec = htonl(sec);
    ofs->duration_nsec = htonl(msec * 1000000);
    ofs->cookie = ofproto_rule_cast(rule)->flow_cookie;
    ofs->priority = htons(rule->cr.flow.priority);
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
    flow_t target;

    if (arg_size != sizeof *fsr) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    fsr = (struct ofp_flow_stats_request *) osr->body;

    COVERAGE_INC(ofproto_flows_req);
    cbdata.ofproto = p;
    cbdata.ofconn = ofconn;
    cbdata.out_port = fsr->out_port;
    cbdata.msg = start_stats_reply(osr, 1024);
    flow_from_match(&target, 0, &fsr->match);
    wdp_flow_for_each_match(p->wdp, &target,
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
flow_stats_ds_cb(struct wdp_rule *rule, void *cbdata_)
{
    struct flow_stats_ds_cbdata *cbdata = cbdata_;
    struct ds *results = cbdata->results;
    struct ofp_match match;
    uint64_t packet_count, byte_count;
    size_t act_len = sizeof *rule->actions * rule->n_actions;

    query_stats(cbdata->ofproto, rule, &packet_count, &byte_count);
    flow_to_match(&rule->cr.flow, &match);

    ds_put_format(results, "duration=%llds, ",
                  (time_msec() - rule->created) / 1000);
    ds_put_format(results, "priority=%u, ", rule->cr.flow.priority);
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
    struct flow_stats_ds_cbdata cbdata;
    struct ofp_match match;
    flow_t target;

    memset(&match, 0, sizeof match);
    match.wildcards = htonl(OFPFW_ALL);

    cbdata.ofproto = p;
    cbdata.results = results;

    flow_from_match(&target, 0, &match);
    wdp_flow_for_each_match(p->wdp, &target, CLS_INC_ALL,
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
aggregate_stats_cb(struct wdp_rule *rule, void *cbdata_)
{
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
    struct ofpbuf *msg;
    flow_t target;

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
    flow_from_match(&target, 0, &asr->match);
    wdp_flow_for_each_match(p->wdp, &target,
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

static int
add_flow(struct ofproto *p, struct ofconn *ofconn,
         struct ofp_flow_mod *ofm, size_t n_actions)
{
    struct wdp_rule *rule;
    struct wdp_flow_put put;
    struct ofpbuf *packet;
    uint16_t in_port;
    flow_t flow;
    int error;

    flow_from_match(&flow, ntohs(ofm->priority), &ofm->match);
    if (ofm->flags & htons(OFPFF_CHECK_OVERLAP)
        && wdp_flow_overlaps(p->wdp, &flow)) {
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
    }

    put.flags = WDP_PUT_CREATE | WDP_PUT_MODIFY | WDP_PUT_ALL;
    put.flow = &flow;
    put.actions = (const union ofp_action *) ofm->actions;
    put.n_actions = n_actions;
    put.idle_timeout = ntohs(ofm->idle_timeout);
    put.hard_timeout = ntohs(ofm->hard_timeout);
    error = wdp_flow_put(p->wdp, &put, NULL, &rule);
    if (error) {
        /* XXX wdp_flow_put should return OpenFlow error code. */
        return error;
    }
    ofproto_rule_init(rule);

    if (ofm->buffer_id != htonl(UINT32_MAX)) {
        error = pktbuf_retrieve(ofconn->pktbuf, ntohl(ofm->buffer_id),
                                &packet, &in_port);
        if (!error) {
            wdp_flow_inject(p->wdp, rule, in_port, packet);
            ofpbuf_delete(packet);
        }
    }

    return 0;
}

static int
modify_flow(struct ofproto *p, const struct ofp_flow_mod *ofm,
            size_t n_actions, uint16_t command, struct wdp_rule *rule)
{
    if (rule_is_hidden(rule)) {
        return 0;
    }

    if (command == OFPFC_DELETE) {
        delete_flow(p, rule, OFPPR_DELETE);
    } else {
        const struct ofp_action_header *actions = ofm->actions;
        struct wdp_flow_put put;

        ofproto_rule_cast(rule)->flow_cookie = ofm->cookie;

        put.flags = WDP_PUT_MODIFY | WDP_PUT_ACTIONS;
        put.flow = &rule->cr.flow;
        put.actions = (const union ofp_action *) actions;
        put.n_actions = n_actions;
        put.idle_timeout = put.hard_timeout = 0;
        wdp_flow_put(p->wdp, &put, NULL, NULL);
    }

    return 0;
}

static int
modify_flows_strict(struct ofproto *p, const struct ofp_flow_mod *ofm,
                    size_t n_actions, uint16_t command)
{
    struct wdp_rule *rule;
    flow_t flow;

    flow_from_match(&flow, ntohs(ofm->priority), &ofm->match);
    rule = wdp_flow_get(p->wdp, &flow);

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
modify_flows_cb(struct wdp_rule *rule, void *cbdata_)
{
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
    flow_t target;

    cbdata.ofproto = p;
    cbdata.ofm = ofm;
    cbdata.out_port = (command == OFPFC_DELETE ? ofm->out_port
                       : htons(OFPP_NONE));
    cbdata.n_actions = n_actions;
    cbdata.command = command;

    flow_from_match(&target, 0, &ofm->match);
    wdp_flow_for_each_match(p->wdp, &target, CLS_INC_ALL,
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
handle_flow_miss(struct ofproto *p, struct wdp_packet *packet)
{
    struct wdp_rule *rule;
    flow_t flow;

    flow_extract(packet->payload, packet->in_port, &flow);
    rule = wdp_flow_match(p->wdp, &flow);
    if (!rule) {
        /* Don't send a packet-in if OFPPC_NO_PACKET_IN asserted. */
        struct wdp_port *port;

        wdp_port_query_by_number(p->wdp, packet->in_port, &port);
        if (port) {
            if (port->opp.config & OFPPC_NO_PACKET_IN) {
                COVERAGE_INC(ofproto_no_packet_in);
                wdp_packet_destroy(packet);
                return;
            }
        } else {
            VLOG_WARN_RL(&rl, "packet-in on unknown port %"PRIu16,
                         packet->in_port);
        }

        COVERAGE_INC(ofproto_packet_in);
        pinsched_send(p->miss_sched, packet->in_port, packet,
                      send_packet_in_miss, p);
        return;
    }

    wdp_flow_inject(p->wdp, rule, packet->in_port, packet->payload);

    if (rule->cr.flow.priority == FAIL_OPEN_PRIORITY
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
        pinsched_send(p->miss_sched, packet->in_port, packet,
                      send_packet_in_miss, p);
    } else {
        wdp_packet_destroy(packet);
    }
}

static void
handle_wdp_packet(struct ofproto *p, struct wdp_packet *packet)
{
    switch (packet->channel) {
    case WDP_CHAN_ACTION:
        COVERAGE_INC(ofproto_ctlr_action);
        pinsched_send(p->action_sched, packet->in_port, packet,
                      send_packet_in_action, p);
        break;

    case WDP_CHAN_SFLOW:
        /* XXX */
        wdp_packet_destroy(packet);
        break;

    case WDP_CHAN_MISS:
        handle_flow_miss(p, packet);
        break;

    case WDP_N_CHANS:
    default:
        wdp_packet_destroy(packet);
        VLOG_WARN_RL(&rl, "received message on unexpected channel %d",
                     (int) packet->channel);
        break;
    }
}

static struct ofpbuf *
compose_flow_removed(const struct wdp_rule *rule, uint8_t reason)
{
    long long int tdiff = time_msec() - rule->created;
    uint32_t sec = tdiff / 1000;
    uint32_t msec = tdiff - (sec * 1000);
    struct ofp_flow_removed *ofr;
    struct ofpbuf *buf;

    ofr = make_openflow(sizeof *ofr, OFPT_FLOW_REMOVED, &buf);
    flow_to_match(&rule->cr.flow, &ofr->match);
    ofr->cookie = ofproto_rule_cast(rule)->flow_cookie;
    ofr->priority = htons(rule->cr.flow.priority);
    ofr->reason = reason;
    ofr->duration_sec = htonl(sec);
    ofr->duration_nsec = htonl(msec * 1000000);
    ofr->idle_timeout = htons(rule->idle_timeout);

    return buf;
}

static void
delete_flow(struct ofproto *p, struct wdp_rule *rule, uint8_t reason)
{
    /* We limit the maximum number of queued flow expirations it by accounting
     * them under the counter for replies.  That works because preventing
     * OpenFlow requests from being processed also prevents new flows from
     * being added (and expiring).  (It also prevents processing OpenFlow
     * requests that would not add new flows, so it is imperfect.) */

    struct ofproto_rule *ofproto_rule = ofproto_rule_cast(rule);
    struct wdp_flow_stats stats;
    struct ofpbuf *buf;

    if (ofproto_rule->send_flow_removed) {
        /* Compose most of the ofp_flow_removed before 'rule' is destroyed. */
        buf = compose_flow_removed(rule, reason);
    } else {
        buf = NULL;
    }

    if (wdp_flow_delete(p->wdp, rule, &stats)) {
        return;
    }

    if (buf) {
        struct ofp_flow_removed *ofr;
        struct ofconn *prev = NULL;
        struct ofconn *ofconn;

        /* Compose the parts of the ofp_flow_removed that require stats. */
        ofr = buf->data;
        ofr->packet_count = htonll(stats.n_packets);
        ofr->byte_count = htonll(stats.n_bytes);

        LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
            if (rconn_is_connected(ofconn->rconn)) {
                if (prev) {
                    queue_tx(ofpbuf_clone(buf), prev, prev->reply_counter);
                }
                prev = ofconn;
            }
        }
        if (prev) {
            queue_tx(buf, prev, prev->reply_counter);
        } else {
            ofpbuf_delete(buf);
        }
    }
    free(ofproto_rule);
}

static void
do_send_packet_in(struct ofconn *ofconn, uint32_t buffer_id,
                  const struct wdp_packet *packet, int send_len)
{
    struct ofpbuf *opi;
    uint8_t reason;

    reason = packet->channel == WDP_CHAN_ACTION ? OFPR_ACTION : OFPR_NO_MATCH;
    opi = make_packet_in(buffer_id, packet->in_port, reason,
                         packet->payload, send_len);
    rconn_send_with_limit(ofconn->rconn, opi, ofconn->packet_in_counter, 100);
}

static void
send_packet_in_action(struct wdp_packet *packet, void *p_)
{
    struct ofproto *p = p_;
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
        if (ofconn == p->controller || ofconn->miss_send_len) {
            do_send_packet_in(ofconn, UINT32_MAX, packet, packet->send_len);
        }
    }
    wdp_packet_destroy(packet);
}

static void
send_packet_in_miss(struct wdp_packet *packet, void *p_)
{
    struct ofproto *p = p_;
    bool in_fail_open = p->fail_open && fail_open_is_active(p->fail_open);
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, struct ofconn, node, &p->all_conns) {
        if (ofconn->miss_send_len) {
            struct pktbuf *pb = ofconn->pktbuf;
            uint32_t buffer_id = (in_fail_open
                                  ? pktbuf_get_null()
                                  : pktbuf_save(pb, packet->payload,
                                                packet->in_port));
            int send_len = (buffer_id != UINT32_MAX ? ofconn->miss_send_len
                            : UINT32_MAX);
            do_send_packet_in(ofconn, buffer_id, packet, send_len);
        }
    }
    wdp_packet_destroy(packet);
}

static uint64_t
pick_datapath_id(const struct ofproto *ofproto)
{
    struct wdp_port *port;

    wdp_port_query_by_number(ofproto->wdp, OFPP_LOCAL, &port);
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
