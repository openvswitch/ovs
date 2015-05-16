/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include "connmgr.h"

#include <errno.h>
#include <stdlib.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "fail-open.h"
#include "in-band.h"
#include "odp-util.h"
#include "ofp-actions.h"
#include "ofp-msgs.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto-provider.h"
#include "pinsched.h"
#include "poll-loop.h"
#include "pktbuf.h"
#include "rconn.h"
#include "shash.h"
#include "simap.h"
#include "stream.h"
#include "timeval.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"

#include "bundles.h"

VLOG_DEFINE_THIS_MODULE(connmgr);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* An OpenFlow connection.
 *
 *
 * Thread-safety
 * =============
 *
 * 'ofproto_mutex' must be held whenever an ofconn is created or destroyed or,
 * more or less equivalently, whenever an ofconn is added to or removed from a
 * connmgr.  'ofproto_mutex' doesn't protect the data inside the ofconn, except
 * as specifically noted below. */
struct ofconn {
/* Configuration that persists from one connection to the next. */

    struct ovs_list node;       /* In struct connmgr's "all_conns" list. */
    struct hmap_node hmap_node; /* In struct connmgr's "controllers" map. */

    struct connmgr *connmgr;    /* Connection's manager. */
    struct rconn *rconn;        /* OpenFlow connection. */
    enum ofconn_type type;      /* Type. */
    enum ofproto_band band;     /* In-band or out-of-band? */
    bool enable_async_msgs;     /* Initially enable async messages? */

/* State that should be cleared from one connection to the next. */

    /* OpenFlow state. */
    enum ofp12_controller_role role;           /* Role. */
    enum ofputil_protocol protocol; /* Current protocol variant. */
    enum nx_packet_in_format packet_in_format; /* OFPT_PACKET_IN format. */

    /* OFPT_PACKET_IN related data. */
    struct rconn_packet_counter *packet_in_counter; /* # queued on 'rconn'. */
#define N_SCHEDULERS 2
    struct pinsched *schedulers[N_SCHEDULERS];
    struct pktbuf *pktbuf;         /* OpenFlow packet buffers. */
    int miss_send_len;             /* Bytes to send of buffered packets. */
    uint16_t controller_id;     /* Connection controller ID. */

    /* Number of OpenFlow messages queued on 'rconn' as replies to OpenFlow
     * requests, and the maximum number before we stop reading OpenFlow
     * requests.  */
#define OFCONN_REPLY_MAX 100
    struct rconn_packet_counter *reply_counter;

    /* Asynchronous message configuration in each possible roles.
     *
     * A 1-bit enables sending an asynchronous message for one possible reason
     * that the message might be generated, a 0-bit disables it. */
    uint32_t master_async_config[OAM_N_TYPES]; /* master, other */
    uint32_t slave_async_config[OAM_N_TYPES];  /* slave */

    /* Flow table operation logging. */
    int n_add, n_delete, n_modify; /* Number of unreported ops of each kind. */
    long long int first_op, last_op; /* Range of times for unreported ops. */
    long long int next_op_report;    /* Time to report ops, or LLONG_MAX. */
    long long int op_backoff;        /* Earliest time to report ops again. */

/* Flow monitors (e.g. NXST_FLOW_MONITOR). */

    /* Configuration.  Contains "struct ofmonitor"s. */
    struct hmap monitors OVS_GUARDED_BY(ofproto_mutex);

    /* Flow control.
     *
     * When too many flow monitor notifications back up in the transmit buffer,
     * we pause the transmission of further notifications.  These members track
     * the flow control state.
     *
     * When notifications are flowing, 'monitor_paused' is 0.  When
     * notifications are paused, 'monitor_paused' is the value of
     * 'monitor_seqno' at the point we paused.
     *
     * 'monitor_counter' counts the OpenFlow messages and bytes currently in
     * flight.  This value growing too large triggers pausing. */
    uint64_t monitor_paused OVS_GUARDED_BY(ofproto_mutex);
    struct rconn_packet_counter *monitor_counter OVS_GUARDED_BY(ofproto_mutex);

    /* State of monitors for a single ongoing flow_mod.
     *
     * 'updates' is a list of "struct ofpbuf"s that contain
     * NXST_FLOW_MONITOR_REPLY messages representing the changes made by the
     * current flow_mod.
     *
     * When 'updates' is nonempty, 'sent_abbrev_update' is true if 'updates'
     * contains an update event of type NXFME_ABBREV and false otherwise.. */
    struct ovs_list updates OVS_GUARDED_BY(ofproto_mutex);
    bool sent_abbrev_update OVS_GUARDED_BY(ofproto_mutex);

    /* Active bundles. Contains "struct ofp_bundle"s. */
    struct hmap bundles;
};

static struct ofconn *ofconn_create(struct connmgr *, struct rconn *,
                                    enum ofconn_type, bool enable_async_msgs)
    OVS_REQUIRES(ofproto_mutex);
static void ofconn_destroy(struct ofconn *) OVS_REQUIRES(ofproto_mutex);
static void ofconn_flush(struct ofconn *) OVS_REQUIRES(ofproto_mutex);

static void ofconn_reconfigure(struct ofconn *,
                               const struct ofproto_controller *);

static void ofconn_run(struct ofconn *,
                       void (*handle_openflow)(struct ofconn *,
                                               const struct ofpbuf *ofp_msg));
static void ofconn_wait(struct ofconn *);

static void ofconn_log_flow_mods(struct ofconn *);

static const char *ofconn_get_target(const struct ofconn *);
static char *ofconn_make_name(const struct connmgr *, const char *target);

static void ofconn_set_rate_limit(struct ofconn *, int rate, int burst);

static void ofconn_send(const struct ofconn *, struct ofpbuf *,
                        struct rconn_packet_counter *);

static void do_send_packet_ins(struct ofconn *, struct ovs_list *txq);

/* A listener for incoming OpenFlow "service" connections. */
struct ofservice {
    struct hmap_node node;      /* In struct connmgr's "services" hmap. */
    struct pvconn *pvconn;      /* OpenFlow connection listener. */

    /* These are not used by ofservice directly.  They are settings for
     * accepted "struct ofconn"s from the pvconn. */
    int probe_interval;         /* Max idle time before probing, in seconds. */
    int rate_limit;             /* Max packet-in rate in packets per second. */
    int burst_limit;            /* Limit on accumulating packet credits. */
    bool enable_async_msgs;     /* Initially enable async messages? */
    uint8_t dscp;               /* DSCP Value for controller connection */
    uint32_t allowed_versions;  /* OpenFlow protocol versions that may
                                 * be negotiated for a session. */
};

static void ofservice_reconfigure(struct ofservice *,
                                  const struct ofproto_controller *);
static int ofservice_create(struct connmgr *mgr, const char *target,
                            uint32_t allowed_versions, uint8_t dscp);
static void ofservice_destroy(struct connmgr *, struct ofservice *);
static struct ofservice *ofservice_lookup(struct connmgr *,
                                          const char *target);

/* Connection manager for an OpenFlow switch. */
struct connmgr {
    struct ofproto *ofproto;
    char *name;
    char *local_port_name;

    /* OpenFlow connections. */
    struct hmap controllers;     /* All OFCONN_PRIMARY controllers. */
    struct ovs_list all_conns;   /* All controllers. */
    uint64_t master_election_id; /* monotonically increasing sequence number
                                  * for master election */
    bool master_election_id_defined;

    /* OpenFlow listeners. */
    struct hmap services;       /* Contains "struct ofservice"s. */
    struct pvconn **snoops;
    size_t n_snoops;

    /* Fail open. */
    struct fail_open *fail_open;
    enum ofproto_fail_mode fail_mode;

    /* In-band control. */
    struct in_band *in_band;
    struct sockaddr_in *extra_in_band_remotes;
    size_t n_extra_remotes;
    int in_band_queue;
};

static void update_in_band_remotes(struct connmgr *);
static void add_snooper(struct connmgr *, struct vconn *);
static void ofmonitor_run(struct connmgr *);
static void ofmonitor_wait(struct connmgr *);

/* Creates and returns a new connection manager owned by 'ofproto'.  'name' is
 * a name for the ofproto suitable for using in log messages.
 * 'local_port_name' is the name of the local port (OFPP_LOCAL) within
 * 'ofproto'. */
struct connmgr *
connmgr_create(struct ofproto *ofproto,
               const char *name, const char *local_port_name)
{
    struct connmgr *mgr;

    mgr = xmalloc(sizeof *mgr);
    mgr->ofproto = ofproto;
    mgr->name = xstrdup(name);
    mgr->local_port_name = xstrdup(local_port_name);

    hmap_init(&mgr->controllers);
    list_init(&mgr->all_conns);
    mgr->master_election_id = 0;
    mgr->master_election_id_defined = false;

    hmap_init(&mgr->services);
    mgr->snoops = NULL;
    mgr->n_snoops = 0;

    mgr->fail_open = NULL;
    mgr->fail_mode = OFPROTO_FAIL_SECURE;

    mgr->in_band = NULL;
    mgr->extra_in_band_remotes = NULL;
    mgr->n_extra_remotes = 0;
    mgr->in_band_queue = -1;

    return mgr;
}

/* Frees 'mgr' and all of its resources. */
void
connmgr_destroy(struct connmgr *mgr)
{
    struct ofservice *ofservice, *next_ofservice;
    struct ofconn *ofconn, *next_ofconn;
    size_t i;

    if (!mgr) {
        return;
    }

    ovs_mutex_lock(&ofproto_mutex);
    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, node, &mgr->all_conns) {
        ofconn_destroy(ofconn);
    }
    ovs_mutex_unlock(&ofproto_mutex);

    hmap_destroy(&mgr->controllers);

    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, node, &mgr->services) {
        ofservice_destroy(mgr, ofservice);
    }
    hmap_destroy(&mgr->services);

    for (i = 0; i < mgr->n_snoops; i++) {
        pvconn_close(mgr->snoops[i]);
    }
    free(mgr->snoops);

    fail_open_destroy(mgr->fail_open);
    mgr->fail_open = NULL;

    in_band_destroy(mgr->in_band);
    mgr->in_band = NULL;
    free(mgr->extra_in_band_remotes);
    free(mgr->name);
    free(mgr->local_port_name);

    free(mgr);
}

/* Does all of the periodic maintenance required by 'mgr'.  Calls
 * 'handle_openflow' for each message received on an OpenFlow connection,
 * passing along the OpenFlow connection itself and the message that was sent.
 * 'handle_openflow' must not modify or free the message. */
void
connmgr_run(struct connmgr *mgr,
            void (*handle_openflow)(struct ofconn *,
                                    const struct ofpbuf *ofp_msg))
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofconn *ofconn, *next_ofconn;
    struct ofservice *ofservice;
    size_t i;

    if (mgr->in_band) {
        if (!in_band_run(mgr->in_band)) {
            in_band_destroy(mgr->in_band);
            mgr->in_band = NULL;
        }
    }

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, node, &mgr->all_conns) {
        ofconn_run(ofconn, handle_openflow);
    }
    ofmonitor_run(mgr);

    /* Fail-open maintenance.  Do this after processing the ofconns since
     * fail-open checks the status of the controller rconn. */
    if (mgr->fail_open) {
        fail_open_run(mgr->fail_open);
    }

    HMAP_FOR_EACH (ofservice, node, &mgr->services) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(ofservice->pvconn, &vconn);
        if (!retval) {
            struct rconn *rconn;
            char *name;

            /* Passing default value for creation of the rconn */
            rconn = rconn_create(ofservice->probe_interval, 0, ofservice->dscp,
                                 vconn_get_allowed_versions(vconn));
            name = ofconn_make_name(mgr, vconn_get_name(vconn));
            rconn_connect_unreliably(rconn, vconn, name);
            free(name);

            ovs_mutex_lock(&ofproto_mutex);
            ofconn = ofconn_create(mgr, rconn, OFCONN_SERVICE,
                                   ofservice->enable_async_msgs);
            ovs_mutex_unlock(&ofproto_mutex);

            ofconn_set_rate_limit(ofconn, ofservice->rate_limit,
                                  ofservice->burst_limit);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", ovs_strerror(retval));
        }
    }

    for (i = 0; i < mgr->n_snoops; i++) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(mgr->snoops[i], &vconn);
        if (!retval) {
            add_snooper(mgr, vconn);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", ovs_strerror(retval));
        }
    }
}

/* Causes the poll loop to wake up when connmgr_run() needs to run. */
void
connmgr_wait(struct connmgr *mgr)
{
    struct ofservice *ofservice;
    struct ofconn *ofconn;
    size_t i;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        ofconn_wait(ofconn);
    }
    ofmonitor_wait(mgr);
    if (mgr->in_band) {
        in_band_wait(mgr->in_band);
    }
    if (mgr->fail_open) {
        fail_open_wait(mgr->fail_open);
    }
    HMAP_FOR_EACH (ofservice, node, &mgr->services) {
        pvconn_wait(ofservice->pvconn);
    }
    for (i = 0; i < mgr->n_snoops; i++) {
        pvconn_wait(mgr->snoops[i]);
    }
}

/* Adds some memory usage statistics for 'mgr' into 'usage', for use with
 * memory_report(). */
void
connmgr_get_memory_usage(const struct connmgr *mgr, struct simap *usage)
{
    const struct ofconn *ofconn;
    unsigned int packets = 0;
    unsigned int ofconns = 0;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        int i;

        ofconns++;

        packets += rconn_count_txqlen(ofconn->rconn);
        for (i = 0; i < N_SCHEDULERS; i++) {
            struct pinsched_stats stats;

            pinsched_get_stats(ofconn->schedulers[i], &stats);
            packets += stats.n_queued;;
        }
        packets += pktbuf_count_packets(ofconn->pktbuf);
    }
    simap_increase(usage, "ofconns", ofconns);
    simap_increase(usage, "packets", packets);
}

/* Returns the ofproto that owns 'ofconn''s connmgr. */
struct ofproto *
ofconn_get_ofproto(const struct ofconn *ofconn)
{
    return ofconn->connmgr->ofproto;
}

/* OpenFlow configuration. */

static void add_controller(struct connmgr *, const char *target, uint8_t dscp,
                           uint32_t allowed_versions)
    OVS_REQUIRES(ofproto_mutex);
static struct ofconn *find_controller_by_target(struct connmgr *,
                                                const char *target);
static void update_fail_open(struct connmgr *) OVS_EXCLUDED(ofproto_mutex);
static int set_pvconns(struct pvconn ***pvconnsp, size_t *n_pvconnsp,
                       const struct sset *);

/* Returns true if 'mgr' has any configured primary controllers.
 *
 * Service controllers do not count, but configured primary controllers do
 * count whether or not they are currently connected. */
bool
connmgr_has_controllers(const struct connmgr *mgr)
{
    return !hmap_is_empty(&mgr->controllers);
}

/* Initializes 'info' and populates it with information about each configured
 * primary controller.  The keys in 'info' are the controllers' targets; the
 * data values are corresponding "struct ofproto_controller_info".
 *
 * The caller owns 'info' and everything in it and should free it when it is no
 * longer needed. */
void
connmgr_get_controller_info(struct connmgr *mgr, struct shash *info)
{
    const struct ofconn *ofconn;

    HMAP_FOR_EACH (ofconn, hmap_node, &mgr->controllers) {
        const struct rconn *rconn = ofconn->rconn;
        const char *target = rconn_get_target(rconn);

        if (!shash_find(info, target)) {
            struct ofproto_controller_info *cinfo = xmalloc(sizeof *cinfo);
            time_t now = time_now();
            time_t last_connection = rconn_get_last_connection(rconn);
            time_t last_disconnect = rconn_get_last_disconnect(rconn);
            int last_error = rconn_get_last_error(rconn);
            int i;

            shash_add(info, target, cinfo);

            cinfo->is_connected = rconn_is_connected(rconn);
            cinfo->role = ofconn->role;

            smap_init(&cinfo->pairs);
            if (last_error) {
                smap_add(&cinfo->pairs, "last_error",
                         ovs_retval_to_string(last_error));
            }

            smap_add(&cinfo->pairs, "state", rconn_get_state(rconn));

            if (last_connection != TIME_MIN) {
                smap_add_format(&cinfo->pairs, "sec_since_connect",
                                "%ld", (long int) (now - last_connection));
            }

            if (last_disconnect != TIME_MIN) {
                smap_add_format(&cinfo->pairs, "sec_since_disconnect",
                                "%ld", (long int) (now - last_disconnect));
            }

            for (i = 0; i < N_SCHEDULERS; i++) {
                if (ofconn->schedulers[i]) {
                    const char *name = i ? "miss" : "action";
                    struct pinsched_stats stats;

                    pinsched_get_stats(ofconn->schedulers[i], &stats);
                    smap_add_nocopy(&cinfo->pairs,
                                    xasprintf("packet-in-%s-backlog", name),
                                    xasprintf("%u", stats.n_queued));
                    smap_add_nocopy(&cinfo->pairs,
                                    xasprintf("packet-in-%s-bypassed", name),
                                    xasprintf("%llu", stats.n_normal));
                    smap_add_nocopy(&cinfo->pairs,
                                    xasprintf("packet-in-%s-queued", name),
                                    xasprintf("%llu", stats.n_limited));
                    smap_add_nocopy(&cinfo->pairs,
                                    xasprintf("packet-in-%s-dropped", name),
                                    xasprintf("%llu", stats.n_queue_dropped));
                }
            }
        }
    }
}

void
connmgr_free_controller_info(struct shash *info)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, info) {
        struct ofproto_controller_info *cinfo = node->data;
        smap_destroy(&cinfo->pairs);
        free(cinfo);
    }
    shash_destroy(info);
}

/* Changes 'mgr''s set of controllers to the 'n_controllers' controllers in
 * 'controllers'. */
void
connmgr_set_controllers(struct connmgr *mgr,
                        const struct ofproto_controller *controllers,
                        size_t n_controllers, uint32_t allowed_versions)
    OVS_EXCLUDED(ofproto_mutex)
{
    bool had_controllers = connmgr_has_controllers(mgr);
    struct shash new_controllers;
    struct ofconn *ofconn, *next_ofconn;
    struct ofservice *ofservice, *next_ofservice;
    size_t i;

    /* Required to add and remove ofconns.  This could probably be narrowed to
     * cover a smaller amount of code, if that yielded some benefit. */
    ovs_mutex_lock(&ofproto_mutex);

    /* Create newly configured controllers and services.
     * Create a name to ofproto_controller mapping in 'new_controllers'. */
    shash_init(&new_controllers);
    for (i = 0; i < n_controllers; i++) {
        const struct ofproto_controller *c = &controllers[i];

        if (!vconn_verify_name(c->target)) {
            bool add = false;
            ofconn = find_controller_by_target(mgr, c->target);
            if (!ofconn) {
                VLOG_INFO("%s: added primary controller \"%s\"",
                          mgr->name, c->target);
                add = true;
            } else if (rconn_get_allowed_versions(ofconn->rconn) !=
                       allowed_versions) {
                VLOG_INFO("%s: re-added primary controller \"%s\"",
                          mgr->name, c->target);
                add = true;
                ofconn_destroy(ofconn);
            }
            if (add) {
                add_controller(mgr, c->target, c->dscp, allowed_versions);
            }
        } else if (!pvconn_verify_name(c->target)) {
            bool add = false;
            ofservice = ofservice_lookup(mgr, c->target);
            if (!ofservice) {
                VLOG_INFO("%s: added service controller \"%s\"",
                          mgr->name, c->target);
                add = true;
            } else if (ofservice->allowed_versions != allowed_versions) {
                VLOG_INFO("%s: re-added service controller \"%s\"",
                          mgr->name, c->target);
                ofservice_destroy(mgr, ofservice);
                add = true;
            }
            if (add) {
                ofservice_create(mgr, c->target, allowed_versions, c->dscp);
            }
        } else {
            VLOG_WARN_RL(&rl, "%s: unsupported controller \"%s\"",
                         mgr->name, c->target);
            continue;
        }

        shash_add_once(&new_controllers, c->target, &controllers[i]);
    }

    /* Delete controllers that are no longer configured.
     * Update configuration of all now-existing controllers. */
    HMAP_FOR_EACH_SAFE (ofconn, next_ofconn, hmap_node, &mgr->controllers) {
        const char *target = ofconn_get_target(ofconn);
        struct ofproto_controller *c;

        c = shash_find_data(&new_controllers, target);
        if (!c) {
            VLOG_INFO("%s: removed primary controller \"%s\"",
                      mgr->name, target);
            ofconn_destroy(ofconn);
        } else {
            ofconn_reconfigure(ofconn, c);
        }
    }

    /* Delete services that are no longer configured.
     * Update configuration of all now-existing services. */
    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, node, &mgr->services) {
        const char *target = pvconn_get_name(ofservice->pvconn);
        struct ofproto_controller *c;

        c = shash_find_data(&new_controllers, target);
        if (!c) {
            VLOG_INFO("%s: removed service controller \"%s\"",
                      mgr->name, target);
            ofservice_destroy(mgr, ofservice);
        } else {
            ofservice_reconfigure(ofservice, c);
        }
    }

    shash_destroy(&new_controllers);

    ovs_mutex_unlock(&ofproto_mutex);

    update_in_band_remotes(mgr);
    update_fail_open(mgr);
    if (had_controllers != connmgr_has_controllers(mgr)) {
        ofproto_flush_flows(mgr->ofproto);
    }
}

/* Drops the connections between 'mgr' and all of its primary and secondary
 * controllers, forcing them to reconnect. */
void
connmgr_reconnect(const struct connmgr *mgr)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        rconn_reconnect(ofconn->rconn);
    }
}

/* Sets the "snoops" for 'mgr' to the pvconn targets listed in 'snoops'.
 *
 * A "snoop" is a pvconn to which every OpenFlow message to or from the most
 * important controller on 'mgr' is mirrored. */
int
connmgr_set_snoops(struct connmgr *mgr, const struct sset *snoops)
{
    return set_pvconns(&mgr->snoops, &mgr->n_snoops, snoops);
}

/* Adds each of the snoops currently configured on 'mgr' to 'snoops'. */
void
connmgr_get_snoops(const struct connmgr *mgr, struct sset *snoops)
{
    size_t i;

    for (i = 0; i < mgr->n_snoops; i++) {
        sset_add(snoops, pvconn_get_name(mgr->snoops[i]));
    }
}

/* Returns true if 'mgr' has at least one snoop, false if it has none. */
bool
connmgr_has_snoops(const struct connmgr *mgr)
{
    return mgr->n_snoops > 0;
}

/* Creates a new controller for 'target' in 'mgr'.  update_controller() needs
 * to be called later to finish the new ofconn's configuration. */
static void
add_controller(struct connmgr *mgr, const char *target, uint8_t dscp,
               uint32_t allowed_versions)
    OVS_REQUIRES(ofproto_mutex)
{
    char *name = ofconn_make_name(mgr, target);
    struct ofconn *ofconn;

    ofconn = ofconn_create(mgr, rconn_create(5, 8, dscp, allowed_versions),
                           OFCONN_PRIMARY, true);
    ofconn->pktbuf = pktbuf_create();
    rconn_connect(ofconn->rconn, target, name);
    hmap_insert(&mgr->controllers, &ofconn->hmap_node, hash_string(target, 0));

    free(name);
}

static struct ofconn *
find_controller_by_target(struct connmgr *mgr, const char *target)
{
    struct ofconn *ofconn;

    HMAP_FOR_EACH_WITH_HASH (ofconn, hmap_node,
                             hash_string(target, 0), &mgr->controllers) {
        if (!strcmp(ofconn_get_target(ofconn), target)) {
            return ofconn;
        }
    }
    return NULL;
}

static void
update_in_band_remotes(struct connmgr *mgr)
{
    struct sockaddr_in *addrs;
    size_t max_addrs, n_addrs;
    struct ofconn *ofconn;
    size_t i;

    /* Allocate enough memory for as many remotes as we could possibly have. */
    max_addrs = mgr->n_extra_remotes + hmap_count(&mgr->controllers);
    addrs = xmalloc(max_addrs * sizeof *addrs);
    n_addrs = 0;

    /* Add all the remotes. */
    HMAP_FOR_EACH (ofconn, hmap_node, &mgr->controllers) {
        const char *target = rconn_get_target(ofconn->rconn);
        union {
            struct sockaddr_storage ss;
            struct sockaddr_in in;
        } sa;

        if (ofconn->band == OFPROTO_IN_BAND
            && stream_parse_target_with_default_port(target, OFP_PORT, &sa.ss)
            && sa.ss.ss_family == AF_INET) {
            addrs[n_addrs++] = sa.in;
        }
    }
    for (i = 0; i < mgr->n_extra_remotes; i++) {
        addrs[n_addrs++] = mgr->extra_in_band_remotes[i];
    }

    /* Create or update or destroy in-band. */
    if (n_addrs) {
        if (!mgr->in_band) {
            in_band_create(mgr->ofproto, mgr->local_port_name, &mgr->in_band);
        }
        in_band_set_queue(mgr->in_band, mgr->in_band_queue);
    } else {
        /* in_band_run() needs a chance to delete any existing in-band flows.
         * We will destroy mgr->in_band after it's done with that. */
    }
    if (mgr->in_band) {
        in_band_set_remotes(mgr->in_band, addrs, n_addrs);
    }

    /* Clean up. */
    free(addrs);
}

static void
update_fail_open(struct connmgr *mgr)
    OVS_EXCLUDED(ofproto_mutex)
{
    if (connmgr_has_controllers(mgr)
        && mgr->fail_mode == OFPROTO_FAIL_STANDALONE) {
        if (!mgr->fail_open) {
            mgr->fail_open = fail_open_create(mgr->ofproto, mgr);
        }
    } else {
        fail_open_destroy(mgr->fail_open);
        mgr->fail_open = NULL;
    }
}

static int
set_pvconns(struct pvconn ***pvconnsp, size_t *n_pvconnsp,
            const struct sset *sset)
{
    struct pvconn **pvconns = *pvconnsp;
    size_t n_pvconns = *n_pvconnsp;
    const char *name;
    int retval = 0;
    size_t i;

    for (i = 0; i < n_pvconns; i++) {
        pvconn_close(pvconns[i]);
    }
    free(pvconns);

    pvconns = xmalloc(sset_count(sset) * sizeof *pvconns);
    n_pvconns = 0;
    SSET_FOR_EACH (name, sset) {
        struct pvconn *pvconn;
        int error;
        error = pvconn_open(name, 0, 0, &pvconn);
        if (!error) {
            pvconns[n_pvconns++] = pvconn;
        } else {
            VLOG_ERR("failed to listen on %s: %s", name, ovs_strerror(error));
            if (!retval) {
                retval = error;
            }
        }
    }

    *pvconnsp = pvconns;
    *n_pvconnsp = n_pvconns;

    return retval;
}

/* Returns a "preference level" for snooping 'ofconn'.  A higher return value
 * means that 'ofconn' is more interesting for monitoring than a lower return
 * value. */
static int
snoop_preference(const struct ofconn *ofconn)
{
    switch (ofconn->role) {
    case OFPCR12_ROLE_MASTER:
        return 3;
    case OFPCR12_ROLE_EQUAL:
        return 2;
    case OFPCR12_ROLE_SLAVE:
        return 1;
    case OFPCR12_ROLE_NOCHANGE:
    default:
        /* Shouldn't happen. */
        return 0;
    }
}

/* One of 'mgr''s "snoop" pvconns has accepted a new connection on 'vconn'.
 * Connects this vconn to a controller. */
static void
add_snooper(struct connmgr *mgr, struct vconn *vconn)
{
    struct ofconn *ofconn, *best;

    /* Pick a controller for monitoring. */
    best = NULL;
    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
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

/* Public ofconn functions. */

/* Returns the connection type, either OFCONN_PRIMARY or OFCONN_SERVICE. */
enum ofconn_type
ofconn_get_type(const struct ofconn *ofconn)
{
    return ofconn->type;
}

/* If a master election id is defined, stores it into '*idp' and returns
 * true.  Otherwise, stores UINT64_MAX into '*idp' and returns false. */
bool
ofconn_get_master_election_id(const struct ofconn *ofconn, uint64_t *idp)
{
    *idp = (ofconn->connmgr->master_election_id_defined
            ? ofconn->connmgr->master_election_id
            : UINT64_MAX);
    return ofconn->connmgr->master_election_id_defined;
}

/* Sets the master election id.
 *
 * Returns true if successful, false if the id is stale
 */
bool
ofconn_set_master_election_id(struct ofconn *ofconn, uint64_t id)
{
    if (ofconn->connmgr->master_election_id_defined
        &&
        /* Unsigned difference interpreted as a two's complement signed
         * value */
        (int64_t)(id - ofconn->connmgr->master_election_id) < 0) {
        return false;
    }
    ofconn->connmgr->master_election_id = id;
    ofconn->connmgr->master_election_id_defined = true;

    return true;
}

/* Returns the role configured for 'ofconn'.
 *
 * The default role, if no other role has been set, is OFPCR12_ROLE_EQUAL. */
enum ofp12_controller_role
ofconn_get_role(const struct ofconn *ofconn)
{
    return ofconn->role;
}

void
ofconn_send_role_status(struct ofconn *ofconn, uint32_t role, uint8_t reason)
{
    struct ofputil_role_status status;
    struct ofpbuf *buf;

    status.reason = reason;
    status.role = role;
    ofconn_get_master_election_id(ofconn, &status.generation_id);

    buf = ofputil_encode_role_status(&status, ofconn_get_protocol(ofconn));
    if (buf) {
        ofconn_send(ofconn, buf, NULL);
    }
}

/* Changes 'ofconn''s role to 'role'.  If 'role' is OFPCR12_ROLE_MASTER then
 * any existing master is demoted to a slave. */
void
ofconn_set_role(struct ofconn *ofconn, enum ofp12_controller_role role)
{
    if (role != ofconn->role && role == OFPCR12_ROLE_MASTER) {
        struct ofconn *other;

        LIST_FOR_EACH (other, node, &ofconn->connmgr->all_conns) {
            if (other->role == OFPCR12_ROLE_MASTER) {
                other->role = OFPCR12_ROLE_SLAVE;
                ofconn_send_role_status(other, OFPCR12_ROLE_SLAVE, OFPCRR_MASTER_REQUEST);
            }
        }
    }
    ofconn->role = role;
}

void
ofconn_set_invalid_ttl_to_controller(struct ofconn *ofconn, bool enable)
{
    uint32_t bit = 1u << OFPR_INVALID_TTL;
    if (enable) {
        ofconn->master_async_config[OAM_PACKET_IN] |= bit;
    } else {
        ofconn->master_async_config[OAM_PACKET_IN] &= ~bit;
    }
}

bool
ofconn_get_invalid_ttl_to_controller(struct ofconn *ofconn)
{
    uint32_t bit = 1u << OFPR_INVALID_TTL;
    return (ofconn->master_async_config[OAM_PACKET_IN] & bit) != 0;
}

/* Returns the currently configured protocol for 'ofconn', one of OFPUTIL_P_*.
 *
 * Returns OFPUTIL_P_NONE, which is not a valid protocol, if 'ofconn' hasn't
 * completed version negotiation.  This can't happen if at least one OpenFlow
 * message, other than OFPT_HELLO, has been received on the connection (such as
 * in ofproto.c's message handling code), since version negotiation is a
 * prerequisite for starting to receive messages.  This means that
 * OFPUTIL_P_NONE is a special case that most callers need not worry about. */
enum ofputil_protocol
ofconn_get_protocol(const struct ofconn *ofconn)
{
    if (ofconn->protocol == OFPUTIL_P_NONE &&
        rconn_is_connected(ofconn->rconn)) {
        int version = rconn_get_version(ofconn->rconn);
        if (version > 0) {
            ofconn_set_protocol(CONST_CAST(struct ofconn *, ofconn),
                                ofputil_protocol_from_ofp_version(version));
        }
    }

    return ofconn->protocol;
}

/* Sets the protocol for 'ofconn' to 'protocol' (one of OFPUTIL_P_*).
 *
 * (This doesn't actually send anything to accomplish this.  Presumably the
 * caller already did that.) */
void
ofconn_set_protocol(struct ofconn *ofconn, enum ofputil_protocol protocol)
{
    ofconn->protocol = protocol;
    if (!(protocol & OFPUTIL_P_OF14_UP)) {
        uint32_t *master = ofconn->master_async_config;
        uint32_t *slave = ofconn->slave_async_config;

        /* OFPR_ACTION_SET is not supported before OF1.4 */
        master[OAM_PACKET_IN] &= ~(1u << OFPR_ACTION_SET);
        slave [OAM_PACKET_IN] &= ~(1u << OFPR_ACTION_SET);

        /* OFPR_GROUP is not supported before OF1.4 */
        master[OAM_PACKET_IN] &= ~(1u << OFPR_GROUP);
        slave [OAM_PACKET_IN] &= ~(1u << OFPR_GROUP);
    }
}

/* Returns the currently configured packet in format for 'ofconn', one of
 * NXPIF_*.
 *
 * The default, if no other format has been set, is NXPIF_OPENFLOW10. */
enum nx_packet_in_format
ofconn_get_packet_in_format(struct ofconn *ofconn)
{
    return ofconn->packet_in_format;
}

/* Sets the packet in format for 'ofconn' to 'packet_in_format' (one of
 * NXPIF_*). */
void
ofconn_set_packet_in_format(struct ofconn *ofconn,
                            enum nx_packet_in_format packet_in_format)
{
    ofconn->packet_in_format = packet_in_format;
}

/* Sets the controller connection ID for 'ofconn' to 'controller_id'.
 *
 * The connection controller ID is used for OFPP_CONTROLLER and
 * NXAST_CONTROLLER actions.  See "struct nx_action_controller" for details. */
void
ofconn_set_controller_id(struct ofconn *ofconn, uint16_t controller_id)
{
    ofconn->controller_id = controller_id;
}

/* Returns the default miss send length for 'ofconn'. */
int
ofconn_get_miss_send_len(const struct ofconn *ofconn)
{
    return ofconn->miss_send_len;
}

/* Sets the default miss send length for 'ofconn' to 'miss_send_len'. */
void
ofconn_set_miss_send_len(struct ofconn *ofconn, int miss_send_len)
{
    ofconn->miss_send_len = miss_send_len;
}

void
ofconn_set_async_config(struct ofconn *ofconn,
                        const uint32_t master_masks[OAM_N_TYPES],
                        const uint32_t slave_masks[OAM_N_TYPES])
{
    size_t size = sizeof ofconn->master_async_config;
    memcpy(ofconn->master_async_config, master_masks, size);
    memcpy(ofconn->slave_async_config, slave_masks, size);
}

void
ofconn_get_async_config(struct ofconn *ofconn,
                        uint32_t *master_masks, uint32_t *slave_masks)
{
    size_t size = sizeof ofconn->master_async_config;

    /* Make sure we know the protocol version and the async_config
     * masks are properly updated by calling ofconn_get_protocol() */
    if (OFPUTIL_P_NONE == ofconn_get_protocol(ofconn)){
        OVS_NOT_REACHED();
    }

    memcpy(master_masks, ofconn->master_async_config, size);
    memcpy(slave_masks, ofconn->slave_async_config, size);
}

/* Sends 'msg' on 'ofconn', accounting it as a reply.  (If there is a
 * sufficient number of OpenFlow replies in-flight on a single ofconn, then the
 * connmgr will stop accepting new OpenFlow requests on that ofconn until the
 * controller has accepted some of the replies.) */
void
ofconn_send_reply(const struct ofconn *ofconn, struct ofpbuf *msg)
{
    ofconn_send(ofconn, msg, ofconn->reply_counter);
}

/* Sends each of the messages in list 'replies' on 'ofconn' in order,
 * accounting them as replies. */
void
ofconn_send_replies(const struct ofconn *ofconn, struct ovs_list *replies)
{
    struct ofpbuf *reply;

    LIST_FOR_EACH_POP (reply, list_node, replies) {
        ofconn_send_reply(ofconn, reply);
    }
}

/* Sends 'error' on 'ofconn', as a reply to 'request'.  Only at most the
 * first 64 bytes of 'request' are used. */
void
ofconn_send_error(const struct ofconn *ofconn,
                  const struct ofp_header *request, enum ofperr error)
{
    static struct vlog_rate_limit err_rl = VLOG_RATE_LIMIT_INIT(10, 10);
    struct ofpbuf *reply;

    reply = ofperr_encode_reply(error, request);
    if (!VLOG_DROP_INFO(&err_rl)) {
        const char *type_name;
        size_t request_len;
        enum ofpraw raw;

        request_len = ntohs(request->length);
        type_name = (!ofpraw_decode_partial(&raw, request,
                                            MIN(64, request_len))
                     ? ofpraw_get_name(raw)
                     : "invalid");

        VLOG_INFO("%s: sending %s error reply to %s message",
                  rconn_get_name(ofconn->rconn), ofperr_to_string(error),
                  type_name);
    }
    ofconn_send_reply(ofconn, reply);
}

/* Same as pktbuf_retrieve(), using the pktbuf owned by 'ofconn'. */
enum ofperr
ofconn_pktbuf_retrieve(struct ofconn *ofconn, uint32_t id,
                       struct dp_packet **bufferp, ofp_port_t *in_port)
{
    return pktbuf_retrieve(ofconn->pktbuf, id, bufferp, in_port);
}

/* Reports that a flow_mod operation of the type specified by 'command' was
 * successfully executed by 'ofconn', so that the connmgr can log it. */
void
ofconn_report_flow_mod(struct ofconn *ofconn,
                       enum ofp_flow_mod_command command)
{
    long long int now;

    switch (command) {
    case OFPFC_ADD:
        ofconn->n_add++;
        break;

    case OFPFC_MODIFY:
    case OFPFC_MODIFY_STRICT:
        ofconn->n_modify++;
        break;

    case OFPFC_DELETE:
    case OFPFC_DELETE_STRICT:
        ofconn->n_delete++;
        break;
    }

    now = time_msec();
    if (ofconn->next_op_report == LLONG_MAX) {
        ofconn->first_op = now;
        ofconn->next_op_report = MAX(now + 10 * 1000, ofconn->op_backoff);
        ofconn->op_backoff = ofconn->next_op_report + 60 * 1000;
    }
    ofconn->last_op = now;
}

/* OpenFlow 1.4 bundles. */

static inline uint32_t
bundle_hash(uint32_t id)
{
    return hash_int(id, 0);
}

struct ofp_bundle *
ofconn_get_bundle(struct ofconn *ofconn, uint32_t id)
{
    struct ofp_bundle *bundle;

    HMAP_FOR_EACH_IN_BUCKET(bundle, node, bundle_hash(id), &ofconn->bundles) {
        if (bundle->id == id) {
            return bundle;
        }
    }

    return NULL;
}

enum ofperr
ofconn_insert_bundle(struct ofconn *ofconn, struct ofp_bundle *bundle)
{
    /* XXX: Check the limit of open bundles */

    hmap_insert(&ofconn->bundles, &bundle->node, bundle_hash(bundle->id));

    return 0;
}

enum ofperr
ofconn_remove_bundle(struct ofconn *ofconn, struct ofp_bundle *bundle)
{
    hmap_remove(&ofconn->bundles, &bundle->node);

    return 0;
}

static void
bundle_remove_all(struct ofconn *ofconn)
{
    struct ofp_bundle *b, *next;

    HMAP_FOR_EACH_SAFE (b, next, node, &ofconn->bundles) {
        ofp_bundle_remove__(ofconn, b, false);
    }
}

/* Private ofconn functions. */

static const char *
ofconn_get_target(const struct ofconn *ofconn)
{
    return rconn_get_target(ofconn->rconn);
}

static struct ofconn *
ofconn_create(struct connmgr *mgr, struct rconn *rconn, enum ofconn_type type,
              bool enable_async_msgs)
{
    struct ofconn *ofconn;

    ofconn = xzalloc(sizeof *ofconn);
    ofconn->connmgr = mgr;
    list_push_back(&mgr->all_conns, &ofconn->node);
    ofconn->rconn = rconn;
    ofconn->type = type;
    ofconn->enable_async_msgs = enable_async_msgs;

    hmap_init(&ofconn->monitors);
    list_init(&ofconn->updates);

    hmap_init(&ofconn->bundles);

    ofconn_flush(ofconn);

    return ofconn;
}

/* Clears all of the state in 'ofconn' that should not persist from one
 * connection to the next. */
static void
ofconn_flush(struct ofconn *ofconn)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofmonitor *monitor, *next_monitor;
    int i;

    ofconn_log_flow_mods(ofconn);

    ofconn->role = OFPCR12_ROLE_EQUAL;
    ofconn_set_protocol(ofconn, OFPUTIL_P_NONE);
    ofconn->packet_in_format = NXPIF_OPENFLOW10;

    rconn_packet_counter_destroy(ofconn->packet_in_counter);
    ofconn->packet_in_counter = rconn_packet_counter_create();
    for (i = 0; i < N_SCHEDULERS; i++) {
        if (ofconn->schedulers[i]) {
            int rate, burst;

            pinsched_get_limits(ofconn->schedulers[i], &rate, &burst);
            pinsched_destroy(ofconn->schedulers[i]);
            ofconn->schedulers[i] = pinsched_create(rate, burst);
        }
    }
    if (ofconn->pktbuf) {
        pktbuf_destroy(ofconn->pktbuf);
        ofconn->pktbuf = pktbuf_create();
    }
    ofconn->miss_send_len = (ofconn->type == OFCONN_PRIMARY
                             ? OFP_DEFAULT_MISS_SEND_LEN
                             : 0);
    ofconn->controller_id = 0;

    rconn_packet_counter_destroy(ofconn->reply_counter);
    ofconn->reply_counter = rconn_packet_counter_create();

    if (ofconn->enable_async_msgs) {
        uint32_t *master = ofconn->master_async_config;
        uint32_t *slave = ofconn->slave_async_config;

        /* "master" and "other" roles get all asynchronous messages by default,
         * except that the controller needs to enable nonstandard "packet-in"
         * reasons itself. */
        master[OAM_PACKET_IN] = ((1u << OFPR_NO_MATCH)
                                 | (1u << OFPR_ACTION)
                                 | (1u << OFPR_ACTION_SET)
                                 | (1u << OFPR_GROUP));
        master[OAM_PORT_STATUS] = ((1u << OFPPR_ADD)
                                   | (1u << OFPPR_DELETE)
                                   | (1u << OFPPR_MODIFY));
        master[OAM_FLOW_REMOVED] = ((1u << OFPRR_IDLE_TIMEOUT)
                                    | (1u << OFPRR_HARD_TIMEOUT)
                                    | (1u << OFPRR_DELETE));

        /* "slave" role gets port status updates by default. */
        slave[OAM_PACKET_IN] = 0;
        slave[OAM_PORT_STATUS] = ((1u << OFPPR_ADD)
                                  | (1u << OFPPR_DELETE)
                                  | (1u << OFPPR_MODIFY));
        slave[OAM_FLOW_REMOVED] = 0;
    } else {
        memset(ofconn->master_async_config, 0,
               sizeof ofconn->master_async_config);
        memset(ofconn->slave_async_config, 0,
               sizeof ofconn->slave_async_config);
    }

    ofconn->n_add = ofconn->n_delete = ofconn->n_modify = 0;
    ofconn->first_op = ofconn->last_op = LLONG_MIN;
    ofconn->next_op_report = LLONG_MAX;
    ofconn->op_backoff = LLONG_MIN;

    HMAP_FOR_EACH_SAFE (monitor, next_monitor, ofconn_node,
                        &ofconn->monitors) {
        ofmonitor_destroy(monitor);
    }
    rconn_packet_counter_destroy(ofconn->monitor_counter);
    ofconn->monitor_counter = rconn_packet_counter_create();
    ofpbuf_list_delete(&ofconn->updates); /* ...but it should be empty. */
}

static void
ofconn_destroy(struct ofconn *ofconn)
    OVS_REQUIRES(ofproto_mutex)
{
    ofconn_flush(ofconn);

    if (ofconn->type == OFCONN_PRIMARY) {
        hmap_remove(&ofconn->connmgr->controllers, &ofconn->hmap_node);
    }

    bundle_remove_all(ofconn);
    hmap_destroy(&ofconn->bundles);

    hmap_destroy(&ofconn->monitors);
    list_remove(&ofconn->node);
    rconn_destroy(ofconn->rconn);
    rconn_packet_counter_destroy(ofconn->packet_in_counter);
    rconn_packet_counter_destroy(ofconn->reply_counter);
    pktbuf_destroy(ofconn->pktbuf);
    rconn_packet_counter_destroy(ofconn->monitor_counter);
    free(ofconn);
}

/* Reconfigures 'ofconn' to match 'c'.  'ofconn' and 'c' must have the same
 * target. */
static void
ofconn_reconfigure(struct ofconn *ofconn, const struct ofproto_controller *c)
{
    int probe_interval;

    ofconn->band = c->band;
    ofconn->enable_async_msgs = c->enable_async_msgs;

    rconn_set_max_backoff(ofconn->rconn, c->max_backoff);

    probe_interval = c->probe_interval ? MAX(c->probe_interval, 5) : 0;
    rconn_set_probe_interval(ofconn->rconn, probe_interval);

    ofconn_set_rate_limit(ofconn, c->rate_limit, c->burst_limit);

    /* If dscp value changed reconnect. */
    if (c->dscp != rconn_get_dscp(ofconn->rconn)) {
        rconn_set_dscp(ofconn->rconn, c->dscp);
        rconn_reconnect(ofconn->rconn);
    }
}

/* Returns true if it makes sense for 'ofconn' to receive and process OpenFlow
 * messages. */
static bool
ofconn_may_recv(const struct ofconn *ofconn)
{
    int count = rconn_packet_counter_n_packets(ofconn->reply_counter);
    return count < OFCONN_REPLY_MAX;
}

static void
ofconn_run(struct ofconn *ofconn,
           void (*handle_openflow)(struct ofconn *,
                                   const struct ofpbuf *ofp_msg))
{
    struct connmgr *mgr = ofconn->connmgr;
    size_t i;

    for (i = 0; i < N_SCHEDULERS; i++) {
        struct ovs_list txq;

        pinsched_run(ofconn->schedulers[i], &txq);
        do_send_packet_ins(ofconn, &txq);
    }

    rconn_run(ofconn->rconn);

    /* Limit the number of iterations to avoid starving other tasks. */
    for (i = 0; i < 50 && ofconn_may_recv(ofconn); i++) {
        struct ofpbuf *of_msg = rconn_recv(ofconn->rconn);
        if (!of_msg) {
            break;
        }

        if (mgr->fail_open) {
            fail_open_maybe_recover(mgr->fail_open);
        }

        handle_openflow(ofconn, of_msg);
        ofpbuf_delete(of_msg);
    }

    if (time_msec() >= ofconn->next_op_report) {
        ofconn_log_flow_mods(ofconn);
    }

    ovs_mutex_lock(&ofproto_mutex);
    if (!rconn_is_alive(ofconn->rconn)) {
        ofconn_destroy(ofconn);
    } else if (!rconn_is_connected(ofconn->rconn)) {
        ofconn_flush(ofconn);
    }
    ovs_mutex_unlock(&ofproto_mutex);
}

static void
ofconn_wait(struct ofconn *ofconn)
{
    int i;

    for (i = 0; i < N_SCHEDULERS; i++) {
        pinsched_wait(ofconn->schedulers[i]);
    }
    rconn_run_wait(ofconn->rconn);
    if (ofconn_may_recv(ofconn)) {
        rconn_recv_wait(ofconn->rconn);
    }
    if (ofconn->next_op_report != LLONG_MAX) {
        poll_timer_wait_until(ofconn->next_op_report);
    }
}

static void
ofconn_log_flow_mods(struct ofconn *ofconn)
{
    int n_flow_mods = ofconn->n_add + ofconn->n_delete + ofconn->n_modify;
    if (n_flow_mods) {
        long long int ago = (time_msec() - ofconn->first_op) / 1000;
        long long int interval = (ofconn->last_op - ofconn->first_op) / 1000;
        struct ds s;

        ds_init(&s);
        ds_put_format(&s, "%d flow_mods ", n_flow_mods);
        if (interval == ago) {
            ds_put_format(&s, "in the last %lld s", ago);
        } else if (interval) {
            ds_put_format(&s, "in the %lld s starting %lld s ago",
                          interval, ago);
        } else {
            ds_put_format(&s, "%lld s ago", ago);
        }

        ds_put_cstr(&s, " (");
        if (ofconn->n_add) {
            ds_put_format(&s, "%d adds, ", ofconn->n_add);
        }
        if (ofconn->n_delete) {
            ds_put_format(&s, "%d deletes, ", ofconn->n_delete);
        }
        if (ofconn->n_modify) {
            ds_put_format(&s, "%d modifications, ", ofconn->n_modify);
        }
        s.length -= 2;
        ds_put_char(&s, ')');

        VLOG_INFO("%s: %s", rconn_get_name(ofconn->rconn), ds_cstr(&s));
        ds_destroy(&s);

        ofconn->n_add = ofconn->n_delete = ofconn->n_modify = 0;
    }
    ofconn->next_op_report = LLONG_MAX;
}

/* Returns true if 'ofconn' should receive asynchronous messages of the given
 * OAM_* 'type' and 'reason', which should be a OFPR_* value for OAM_PACKET_IN,
 * a OFPPR_* value for OAM_PORT_STATUS, or an OFPRR_* value for
 * OAM_FLOW_REMOVED.  Returns false if the message should not be sent on
 * 'ofconn'. */
static bool
ofconn_receives_async_msg(const struct ofconn *ofconn,
                          enum ofconn_async_msg_type type,
                          unsigned int reason)
{
    const uint32_t *async_config;

    ovs_assert(reason < 32);
    ovs_assert((unsigned int) type < OAM_N_TYPES);

    if (ofconn_get_protocol(ofconn) == OFPUTIL_P_NONE
        || !rconn_is_connected(ofconn->rconn)) {
        return false;
    }

    /* Keep the following code in sync with the documentation in the
     * "Asynchronous Messages" section in DESIGN. */

    if (ofconn->type == OFCONN_SERVICE && !ofconn->miss_send_len) {
        /* Service connections don't get asynchronous messages unless they have
         * explicitly asked for them by setting a nonzero miss send length. */
        return false;
    }

    async_config = (ofconn->role == OFPCR12_ROLE_SLAVE
                    ? ofconn->slave_async_config
                    : ofconn->master_async_config);
    if (!(async_config[type] & (1u << reason))) {
        return false;
    }

    return true;
}

/* The default "table-miss" behaviour for OpenFlow1.3+ is to drop the
 * packet rather than to send the packet to the controller.
 *
 * This function returns false to indicate the packet should be dropped if
 * the controller action was the result of the default table-miss behaviour
 * and the controller is using OpenFlow1.3+.
 *
 * Otherwise true is returned to indicate the packet should be forwarded to
 * the controller */
static bool
ofconn_wants_packet_in_on_miss(struct ofconn *ofconn,
                               const struct ofproto_packet_in *pin)
{
    if (pin->miss_type == OFPROTO_PACKET_IN_MISS_WITHOUT_FLOW) {
        enum ofputil_protocol protocol = ofconn_get_protocol(ofconn);

        if (protocol != OFPUTIL_P_NONE
            && ofputil_protocol_to_ofp_version(protocol) >= OFP13_VERSION
            && (ofproto_table_get_miss_config(ofconn->connmgr->ofproto,
                                              pin->up.table_id)
                == OFPUTIL_TABLE_MISS_DEFAULT)) {
            return false;
        }
    }
    return true;
}

/* The default "table-miss" behaviour for OpenFlow1.3+ is to drop the
 * packet rather than to send the packet to the controller.
 *
 * This function returns true to indicate that a packet_in message
 * for a "table-miss" should be sent to at least one controller.
 * That is there is at least one controller with controller_id 0
 * which connected using an OpenFlow version earlier than OpenFlow1.3.
 *
 * False otherwise.
 *
 * This logic assumes that "table-miss" packet_in messages
 * are always sent to controller_id 0. */
bool
connmgr_wants_packet_in_on_miss(struct connmgr *mgr) OVS_EXCLUDED(ofproto_mutex)
{
    struct ofconn *ofconn;

    ovs_mutex_lock(&ofproto_mutex);
    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        enum ofputil_protocol protocol = ofconn_get_protocol(ofconn);

        if (ofconn->controller_id == 0 &&
            (protocol == OFPUTIL_P_NONE ||
             ofputil_protocol_to_ofp_version(protocol) < OFP13_VERSION)) {
            ovs_mutex_unlock(&ofproto_mutex);
            return true;
        }
    }
    ovs_mutex_unlock(&ofproto_mutex);

    return false;
}

/* Returns a human-readable name for an OpenFlow connection between 'mgr' and
 * 'target', suitable for use in log messages for identifying the connection.
 *
 * The name is dynamically allocated.  The caller should free it (with free())
 * when it is no longer needed. */
static char *
ofconn_make_name(const struct connmgr *mgr, const char *target)
{
    return xasprintf("%s<->%s", mgr->name, target);
}

static void
ofconn_set_rate_limit(struct ofconn *ofconn, int rate, int burst)
{
    int i;

    for (i = 0; i < N_SCHEDULERS; i++) {
        struct pinsched **s = &ofconn->schedulers[i];

        if (rate > 0) {
            if (!*s) {
                *s = pinsched_create(rate, burst);
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
ofconn_send(const struct ofconn *ofconn, struct ofpbuf *msg,
            struct rconn_packet_counter *counter)
{
    ofpmsg_update_length(msg);
    rconn_send(ofconn->rconn, msg, counter);
}

/* Sending asynchronous messages. */

static void schedule_packet_in(struct ofconn *, struct ofproto_packet_in,
                               enum ofp_packet_in_reason wire_reason);

/* Sends an OFPT_PORT_STATUS message with 'opp' and 'reason' to appropriate
 * controllers managed by 'mgr'.  For messages caused by a controller
 * OFPT_PORT_MOD, specify 'source' as the controller connection that sent the
 * request; otherwise, specify 'source' as NULL. */
void
connmgr_send_port_status(struct connmgr *mgr, struct ofconn *source,
                         const struct ofputil_phy_port *pp, uint8_t reason)
{
    /* XXX Should limit the number of queued port status change messages. */
    struct ofputil_port_status ps;
    struct ofconn *ofconn;

    ps.reason = reason;
    ps.desc = *pp;
    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (ofconn_receives_async_msg(ofconn, OAM_PORT_STATUS, reason)) {
            struct ofpbuf *msg;

            /* Before 1.5, OpenFlow specified that OFPT_PORT_MOD should not
             * generate OFPT_PORT_STATUS messages.  That requirement was a
             * relic of how OpenFlow originally supported a single controller,
             * so that one could expect the controller to already know the
             * changes it had made.
             *
             * EXT-338 changes OpenFlow 1.5 OFPT_PORT_MOD to send
             * OFPT_PORT_STATUS messages to every controller.  This is
             * obviously more useful in the multi-controller case.  We could
             * always implement it that way in OVS, but that would risk
             * confusing controllers that are intended for single-controller
             * use only.  (Imagine a controller that generates an OFPT_PORT_MOD
             * in response to any OFPT_PORT_STATUS!)
             *
             * So this compromises: for OpenFlow 1.4 and earlier, it generates
             * OFPT_PORT_STATUS for OFPT_PORT_MOD, but not back to the
             * originating controller.  In a single-controller environment, in
             * particular, this means that it will never generate
             * OFPT_PORT_STATUS for OFPT_PORT_MOD at all. */
            if (ofconn == source
                && rconn_get_version(ofconn->rconn) < OFP15_VERSION) {
                continue;
            }

            msg = ofputil_encode_port_status(&ps, ofconn_get_protocol(ofconn));
            ofconn_send(ofconn, msg, NULL);
        }
    }
}

/* Sends an OFPT_FLOW_REMOVED or NXT_FLOW_REMOVED message based on 'fr' to
 * appropriate controllers managed by 'mgr'. */
void
connmgr_send_flow_removed(struct connmgr *mgr,
                          const struct ofputil_flow_removed *fr)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (ofconn_receives_async_msg(ofconn, OAM_FLOW_REMOVED, fr->reason)) {
            struct ofpbuf *msg;

            /* Account flow expirations as replies to OpenFlow requests.  That
             * works because preventing OpenFlow requests from being processed
             * also prevents new flows from being added (and expiring).  (It
             * also prevents processing OpenFlow requests that would not add
             * new flows, so it is imperfect.) */
            msg = ofputil_encode_flow_removed(fr, ofconn_get_protocol(ofconn));
            ofconn_send_reply(ofconn, msg);
        }
    }
}

/* Normally a send-to-controller action uses reason OFPR_ACTION.  However, in
 * OpenFlow 1.3 and later, packet_ins generated by a send-to-controller action
 * in a "table-miss" flow (one with priority 0 and completely wildcarded) are
 * sent as OFPR_NO_MATCH.  This function returns the reason that should
 * actually be sent on 'ofconn' for 'pin'. */
static enum ofp_packet_in_reason
wire_reason(struct ofconn *ofconn, const struct ofproto_packet_in *pin)
{
    enum ofputil_protocol protocol = ofconn_get_protocol(ofconn);

    if (pin->miss_type == OFPROTO_PACKET_IN_MISS_FLOW
        && pin->up.reason == OFPR_ACTION
        && protocol != OFPUTIL_P_NONE
        && ofputil_protocol_to_ofp_version(protocol) >= OFP13_VERSION) {
        return OFPR_NO_MATCH;
    }

    switch (pin->up.reason) {
    case OFPR_ACTION_SET:
    case OFPR_GROUP:
    case OFPR_PACKET_OUT:
        if (!(protocol & OFPUTIL_P_OF14_UP)) {
            /* Only supported in OF1.4+ */
            return OFPR_ACTION;
        }
        /* Fall through. */
	case OFPR_NO_MATCH:
	case OFPR_ACTION:
	case OFPR_INVALID_TTL:
	case OFPR_N_REASONS:
    default:
        return pin->up.reason;
    }
}

/* Given 'pin', sends an OFPT_PACKET_IN message to each OpenFlow controller as
 * necessary according to their individual configurations.
 *
 * The caller doesn't need to fill in pin->buffer_id or pin->total_len. */
void
connmgr_send_packet_in(struct connmgr *mgr,
                       const struct ofproto_packet_in *pin)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        enum ofp_packet_in_reason reason = wire_reason(ofconn, pin);

        if (ofconn_wants_packet_in_on_miss(ofconn, pin)
            && ofconn_receives_async_msg(ofconn, OAM_PACKET_IN, reason)
            && ofconn->controller_id == pin->controller_id) {
            schedule_packet_in(ofconn, *pin, reason);
        }
    }
}

static void
do_send_packet_ins(struct ofconn *ofconn, struct ovs_list *txq)
{
    struct ofpbuf *pin;

    LIST_FOR_EACH_POP (pin, list_node, txq) {
        if (rconn_send_with_limit(ofconn->rconn, pin,
                                  ofconn->packet_in_counter, 100) == EAGAIN) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

            VLOG_INFO_RL(&rl, "%s: dropping packet-in due to queue overflow",
                         rconn_get_name(ofconn->rconn));
        }
    }
}

/* Takes 'pin', composes an OpenFlow packet-in message from it, and passes it
 * to 'ofconn''s packet scheduler for sending. */
static void
schedule_packet_in(struct ofconn *ofconn, struct ofproto_packet_in pin,
                   enum ofp_packet_in_reason wire_reason)
{
    struct connmgr *mgr = ofconn->connmgr;
    uint16_t controller_max_len;
    struct ovs_list txq;

    pin.up.total_len = pin.up.packet_len;

    pin.up.reason = wire_reason;
    if (pin.up.reason == OFPR_ACTION) {
        controller_max_len = pin.send_len;  /* max_len */
    } else {
        controller_max_len = ofconn->miss_send_len;
    }

    /* Get OpenFlow buffer_id.
     * For OpenFlow 1.2+, OFPCML_NO_BUFFER (== UINT16_MAX) specifies
     * unbuffered.  This behaviour doesn't violate prior versions, too. */
    if (controller_max_len == UINT16_MAX) {
        pin.up.buffer_id = UINT32_MAX;
    } else if (mgr->fail_open && fail_open_is_active(mgr->fail_open)) {
        pin.up.buffer_id = pktbuf_get_null();
    } else if (!ofconn->pktbuf) {
        pin.up.buffer_id = UINT32_MAX;
    } else {
        pin.up.buffer_id = pktbuf_save(ofconn->pktbuf,
                                       pin.up.packet, pin.up.packet_len,
                                       pin.up.flow_metadata.flow.in_port.ofp_port);
    }

    /* Figure out how much of the packet to send.
     * If not buffered, send the entire packet.  Otherwise, depending on
     * the reason of packet-in, send what requested by the controller. */
    if (pin.up.buffer_id != UINT32_MAX
        && controller_max_len < pin.up.packet_len) {
        pin.up.packet_len = controller_max_len;
    }

    /* Make OFPT_PACKET_IN and hand over to packet scheduler. */
    pinsched_send(ofconn->schedulers[pin.up.reason == OFPR_NO_MATCH ? 0 : 1],
                  pin.up.flow_metadata.flow.in_port.ofp_port,
                  ofputil_encode_packet_in(&pin.up,
                                           ofconn_get_protocol(ofconn),
                                           ofconn->packet_in_format),
                  &txq);
    do_send_packet_ins(ofconn, &txq);
}

/* Fail-open settings. */

/* Returns the failure handling mode (OFPROTO_FAIL_SECURE or
 * OFPROTO_FAIL_STANDALONE) for 'mgr'. */
enum ofproto_fail_mode
connmgr_get_fail_mode(const struct connmgr *mgr)
{
    return mgr->fail_mode;
}

/* Sets the failure handling mode for 'mgr' to 'fail_mode' (either
 * OFPROTO_FAIL_SECURE or OFPROTO_FAIL_STANDALONE). */
void
connmgr_set_fail_mode(struct connmgr *mgr, enum ofproto_fail_mode fail_mode)
{
    if (mgr->fail_mode != fail_mode) {
        mgr->fail_mode = fail_mode;
        update_fail_open(mgr);
        if (!connmgr_has_controllers(mgr)) {
            ofproto_flush_flows(mgr->ofproto);
        }
    }
}

/* Fail-open implementation. */

/* Returns the longest probe interval among the primary controllers configured
 * on 'mgr'.  Returns 0 if there are no primary controllers. */
int
connmgr_get_max_probe_interval(const struct connmgr *mgr)
{
    const struct ofconn *ofconn;
    int max_probe_interval;

    max_probe_interval = 0;
    HMAP_FOR_EACH (ofconn, hmap_node, &mgr->controllers) {
        int probe_interval = rconn_get_probe_interval(ofconn->rconn);
        max_probe_interval = MAX(max_probe_interval, probe_interval);
    }
    return max_probe_interval;
}

/* Returns the number of seconds for which all of 'mgr's primary controllers
 * have been disconnected.  Returns 0 if 'mgr' has no primary controllers. */
int
connmgr_failure_duration(const struct connmgr *mgr)
{
    const struct ofconn *ofconn;
    int min_failure_duration;

    if (!connmgr_has_controllers(mgr)) {
        return 0;
    }

    min_failure_duration = INT_MAX;
    HMAP_FOR_EACH (ofconn, hmap_node, &mgr->controllers) {
        int failure_duration = rconn_failure_duration(ofconn->rconn);
        min_failure_duration = MIN(min_failure_duration, failure_duration);
    }
    return min_failure_duration;
}

/* Returns true if at least one primary controller is connected (regardless of
 * whether those controllers are believed to have authenticated and accepted
 * this switch), false if none of them are connected. */
bool
connmgr_is_any_controller_connected(const struct connmgr *mgr)
{
    const struct ofconn *ofconn;

    HMAP_FOR_EACH (ofconn, hmap_node, &mgr->controllers) {
        if (rconn_is_connected(ofconn->rconn)) {
            return true;
        }
    }
    return false;
}

/* Returns true if at least one primary controller is believed to have
 * authenticated and accepted this switch, false otherwise. */
bool
connmgr_is_any_controller_admitted(const struct connmgr *mgr)
{
    const struct ofconn *ofconn;

    HMAP_FOR_EACH (ofconn, hmap_node, &mgr->controllers) {
        if (rconn_is_admitted(ofconn->rconn)) {
            return true;
        }
    }
    return false;
}

/* In-band configuration. */

static bool any_extras_changed(const struct connmgr *,
                               const struct sockaddr_in *extras, size_t n);

/* Sets the 'n' TCP port addresses in 'extras' as ones to which 'mgr''s
 * in-band control should guarantee access, in the same way that in-band
 * control guarantees access to OpenFlow controllers. */
void
connmgr_set_extra_in_band_remotes(struct connmgr *mgr,
                                  const struct sockaddr_in *extras, size_t n)
{
    if (!any_extras_changed(mgr, extras, n)) {
        return;
    }

    free(mgr->extra_in_band_remotes);
    mgr->n_extra_remotes = n;
    mgr->extra_in_band_remotes = xmemdup(extras, n * sizeof *extras);

    update_in_band_remotes(mgr);
}

/* Sets the OpenFlow queue used by flows set up by in-band control on
 * 'mgr' to 'queue_id'.  If 'queue_id' is negative, then in-band control
 * flows will use the default queue. */
void
connmgr_set_in_band_queue(struct connmgr *mgr, int queue_id)
{
    if (queue_id != mgr->in_band_queue) {
        mgr->in_band_queue = queue_id;
        update_in_band_remotes(mgr);
    }
}

static bool
any_extras_changed(const struct connmgr *mgr,
                   const struct sockaddr_in *extras, size_t n)
{
    size_t i;

    if (n != mgr->n_extra_remotes) {
        return true;
    }

    for (i = 0; i < n; i++) {
        const struct sockaddr_in *old = &mgr->extra_in_band_remotes[i];
        const struct sockaddr_in *new = &extras[i];

        if (old->sin_addr.s_addr != new->sin_addr.s_addr ||
            old->sin_port != new->sin_port) {
            return true;
        }
    }

    return false;
}

/* In-band implementation. */

bool
connmgr_has_in_band(struct connmgr *mgr)
{
    return mgr->in_band != NULL;
}

/* Fail-open and in-band implementation. */

/* Called by 'ofproto' after all flows have been flushed, to allow fail-open
 * and standalone mode to re-create their flows.
 *
 * In-band control has more sophisticated code that manages flows itself. */
void
connmgr_flushed(struct connmgr *mgr)
    OVS_EXCLUDED(ofproto_mutex)
{
    if (mgr->fail_open) {
        fail_open_flushed(mgr->fail_open);
    }

    /* If there are no controllers and we're in standalone mode, set up a flow
     * that matches every packet and directs them to OFPP_NORMAL (which goes to
     * us).  Otherwise, the switch is in secure mode and we won't pass any
     * traffic until a controller has been defined and it tells us to do so. */
    if (!connmgr_has_controllers(mgr)
        && mgr->fail_mode == OFPROTO_FAIL_STANDALONE) {
        struct ofpbuf ofpacts;
        struct match match;

        ofpbuf_init(&ofpacts, OFPACT_OUTPUT_SIZE);
        ofpact_put_OUTPUT(&ofpacts)->port = OFPP_NORMAL;
        ofpact_pad(&ofpacts);

        match_init_catchall(&match);
        ofproto_add_flow(mgr->ofproto, &match, 0, ofpacts.data,
                                                  ofpacts.size);

        ofpbuf_uninit(&ofpacts);
    }
}

/* Returns the number of hidden rules created by the in-band and fail-open
 * implementations in table 0.  (Subtracting this count from the number of
 * rules in the table 0 classifier, as returned by classifier_count(), yields
 * the number of flows that OVS should report via OpenFlow for table 0.) */
int
connmgr_count_hidden_rules(const struct connmgr *mgr)
{
    int n_hidden = 0;
    if (mgr->in_band) {
        n_hidden += in_band_count_rules(mgr->in_band);
    }
    if (mgr->fail_open) {
        n_hidden += fail_open_count_rules(mgr->fail_open);
    }
    return n_hidden;
}

/* Creates a new ofservice for 'target' in 'mgr'.  Returns 0 if successful,
 * otherwise a positive errno value.
 *
 * ofservice_reconfigure() must be called to fully configure the new
 * ofservice. */
static int
ofservice_create(struct connmgr *mgr, const char *target,
                 uint32_t allowed_versions, uint8_t dscp)
{
    struct ofservice *ofservice;
    struct pvconn *pvconn;
    int error;

    error = pvconn_open(target, allowed_versions, dscp, &pvconn);
    if (error) {
        return error;
    }

    ofservice = xzalloc(sizeof *ofservice);
    hmap_insert(&mgr->services, &ofservice->node, hash_string(target, 0));
    ofservice->pvconn = pvconn;
    ofservice->allowed_versions = allowed_versions;

    return 0;
}

static void
ofservice_destroy(struct connmgr *mgr, struct ofservice *ofservice)
{
    hmap_remove(&mgr->services, &ofservice->node);
    pvconn_close(ofservice->pvconn);
    free(ofservice);
}

static void
ofservice_reconfigure(struct ofservice *ofservice,
                      const struct ofproto_controller *c)
{
    ofservice->probe_interval = c->probe_interval;
    ofservice->rate_limit = c->rate_limit;
    ofservice->burst_limit = c->burst_limit;
    ofservice->enable_async_msgs = c->enable_async_msgs;
    ofservice->dscp = c->dscp;
}

/* Finds and returns the ofservice within 'mgr' that has the given
 * 'target', or a null pointer if none exists. */
static struct ofservice *
ofservice_lookup(struct connmgr *mgr, const char *target)
{
    struct ofservice *ofservice;

    HMAP_FOR_EACH_WITH_HASH (ofservice, node, hash_string(target, 0),
                             &mgr->services) {
        if (!strcmp(pvconn_get_name(ofservice->pvconn), target)) {
            return ofservice;
        }
    }
    return NULL;
}

/* Flow monitors (NXST_FLOW_MONITOR). */

/* A counter incremented when something significant happens to an OpenFlow
 * rule.
 *
 *     - When a rule is added, its 'add_seqno' and 'modify_seqno' are set to
 *       the current value (which is then incremented).
 *
 *     - When a rule is modified, its 'modify_seqno' is set to the current
 *       value (which is then incremented).
 *
 * Thus, by comparing an old value of monitor_seqno against a rule's
 * 'add_seqno', one can tell whether the rule was added before or after the old
 * value was read, and similarly for 'modify_seqno'.
 *
 * 32 bits should normally be sufficient (and would be nice, to save space in
 * each rule) but then we'd have to have some special cases for wraparound.
 *
 * We initialize monitor_seqno to 1 to allow 0 to be used as an invalid
 * value. */
static uint64_t monitor_seqno = 1;

COVERAGE_DEFINE(ofmonitor_pause);
COVERAGE_DEFINE(ofmonitor_resume);

enum ofperr
ofmonitor_create(const struct ofputil_flow_monitor_request *request,
                 struct ofconn *ofconn, struct ofmonitor **monitorp)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofmonitor *m;

    *monitorp = NULL;

    m = ofmonitor_lookup(ofconn, request->id);
    if (m) {
        return OFPERR_OFPMOFC_MONITOR_EXISTS;
    }

    m = xmalloc(sizeof *m);
    m->ofconn = ofconn;
    hmap_insert(&ofconn->monitors, &m->ofconn_node, hash_int(request->id, 0));
    m->id = request->id;
    m->flags = request->flags;
    m->out_port = request->out_port;
    m->table_id = request->table_id;
    minimatch_init(&m->match, &request->match);

    *monitorp = m;
    return 0;
}

struct ofmonitor *
ofmonitor_lookup(struct ofconn *ofconn, uint32_t id)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofmonitor *m;

    HMAP_FOR_EACH_IN_BUCKET (m, ofconn_node, hash_int(id, 0),
                             &ofconn->monitors) {
        if (m->id == id) {
            return m;
        }
    }
    return NULL;
}

void
ofmonitor_destroy(struct ofmonitor *m)
    OVS_REQUIRES(ofproto_mutex)
{
    if (m) {
        minimatch_destroy(&m->match);
        hmap_remove(&m->ofconn->monitors, &m->ofconn_node);
        free(m);
    }
}

void
ofmonitor_report(struct connmgr *mgr, struct rule *rule,
                 enum nx_flow_update_event event,
                 enum ofp_flow_removed_reason reason,
                 const struct ofconn *abbrev_ofconn, ovs_be32 abbrev_xid,
                 const struct rule_actions *old_actions)
    OVS_REQUIRES(ofproto_mutex)
{
    enum nx_flow_monitor_flags update;
    struct ofconn *ofconn;

    if (rule_is_hidden(rule)) {
        return;
    }

    switch (event) {
    case NXFME_ADDED:
        update = NXFMF_ADD;
        rule->add_seqno = rule->modify_seqno = monitor_seqno++;
        break;

    case NXFME_DELETED:
        update = NXFMF_DELETE;
        break;

    case NXFME_MODIFIED:
        update = NXFMF_MODIFY;
        rule->modify_seqno = monitor_seqno++;
        break;

    default:
    case NXFME_ABBREV:
        OVS_NOT_REACHED();
    }

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        enum nx_flow_monitor_flags flags = 0;
        struct ofmonitor *m;

        if (ofconn->monitor_paused) {
            /* Only send NXFME_DELETED notifications for flows that were added
             * before we paused. */
            if (event != NXFME_DELETED
                || rule->add_seqno > ofconn->monitor_paused) {
                continue;
            }
        }

        HMAP_FOR_EACH (m, ofconn_node, &ofconn->monitors) {
            if (m->flags & update
                && (m->table_id == 0xff || m->table_id == rule->table_id)
                && (ofproto_rule_has_out_port(rule, m->out_port)
                    || (old_actions
                        && ofpacts_output_to_port(old_actions->ofpacts,
                                                  old_actions->ofpacts_len,
                                                  m->out_port)))
                && cls_rule_is_loose_match(&rule->cr, &m->match)) {
                flags |= m->flags;
            }
        }

        if (flags) {
            if (list_is_empty(&ofconn->updates)) {
                ofputil_start_flow_update(&ofconn->updates);
                ofconn->sent_abbrev_update = false;
            }

            if (flags & NXFMF_OWN || ofconn != abbrev_ofconn
                || ofconn->monitor_paused) {
                struct ofputil_flow_update fu;
                struct match match;

                fu.event = event;
                fu.reason = event == NXFME_DELETED ? reason : 0;
                fu.table_id = rule->table_id;
                fu.cookie = rule->flow_cookie;
                minimatch_expand(&rule->cr.match, &match);
                fu.match = &match;
                fu.priority = rule->cr.priority;

                ovs_mutex_lock(&rule->mutex);
                fu.idle_timeout = rule->idle_timeout;
                fu.hard_timeout = rule->hard_timeout;
                ovs_mutex_unlock(&rule->mutex);

                if (flags & NXFMF_ACTIONS) {
                    const struct rule_actions *actions = rule_get_actions(rule);
                    fu.ofpacts = actions->ofpacts;
                    fu.ofpacts_len = actions->ofpacts_len;
                } else {
                    fu.ofpacts = NULL;
                    fu.ofpacts_len = 0;
                }
                ofputil_append_flow_update(&fu, &ofconn->updates);
            } else if (!ofconn->sent_abbrev_update) {
                struct ofputil_flow_update fu;

                fu.event = NXFME_ABBREV;
                fu.xid = abbrev_xid;
                ofputil_append_flow_update(&fu, &ofconn->updates);

                ofconn->sent_abbrev_update = true;
            }
        }
    }
}

void
ofmonitor_flush(struct connmgr *mgr)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        struct ofpbuf *msg;

        LIST_FOR_EACH_POP (msg, list_node, &ofconn->updates) {
            unsigned int n_bytes;

            ofconn_send(ofconn, msg, ofconn->monitor_counter);
            n_bytes = rconn_packet_counter_n_bytes(ofconn->monitor_counter);
            if (!ofconn->monitor_paused && n_bytes > 128 * 1024) {
                struct ofpbuf *pause;

                COVERAGE_INC(ofmonitor_pause);
                ofconn->monitor_paused = monitor_seqno++;
                pause = ofpraw_alloc_xid(OFPRAW_NXT_FLOW_MONITOR_PAUSED,
                                         OFP10_VERSION, htonl(0), 0);
                ofconn_send(ofconn, pause, ofconn->monitor_counter);
            }
        }
    }
}

static void
ofmonitor_resume(struct ofconn *ofconn)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_collection rules;
    struct ofpbuf *resumed;
    struct ofmonitor *m;
    struct ovs_list msgs;

    rule_collection_init(&rules);
    HMAP_FOR_EACH (m, ofconn_node, &ofconn->monitors) {
        ofmonitor_collect_resume_rules(m, ofconn->monitor_paused, &rules);
    }

    list_init(&msgs);
    ofmonitor_compose_refresh_updates(&rules, &msgs);

    resumed = ofpraw_alloc_xid(OFPRAW_NXT_FLOW_MONITOR_RESUMED, OFP10_VERSION,
                               htonl(0), 0);
    list_push_back(&msgs, &resumed->list_node);
    ofconn_send_replies(ofconn, &msgs);

    ofconn->monitor_paused = 0;
}

static bool
ofmonitor_may_resume(const struct ofconn *ofconn)
    OVS_REQUIRES(ofproto_mutex)
{
    return (ofconn->monitor_paused != 0
            && !rconn_packet_counter_n_packets(ofconn->monitor_counter));
}

static void
ofmonitor_run(struct connmgr *mgr)
{
    struct ofconn *ofconn;

    ovs_mutex_lock(&ofproto_mutex);
    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (ofmonitor_may_resume(ofconn)) {
            COVERAGE_INC(ofmonitor_resume);
            ofmonitor_resume(ofconn);
        }
    }
    ovs_mutex_unlock(&ofproto_mutex);
}

static void
ofmonitor_wait(struct connmgr *mgr)
{
    struct ofconn *ofconn;

    ovs_mutex_lock(&ofproto_mutex);
    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (ofmonitor_may_resume(ofconn)) {
            poll_immediate_wake();
        }
    }
    ovs_mutex_unlock(&ofproto_mutex);
}
