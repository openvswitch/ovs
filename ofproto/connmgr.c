/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include "fail-open.h"
#include "in-band.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto-provider.h"
#include "pinsched.h"
#include "poll-loop.h"
#include "pktbuf.h"
#include "rconn.h"
#include "shash.h"
#include "timeval.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(connmgr);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* An OpenFlow connection. */
struct ofconn {
    struct connmgr *connmgr;    /* Connection's manager. */
    struct list node;           /* In struct connmgr's "all_conns" list. */
    struct rconn *rconn;        /* OpenFlow connection. */
    enum ofconn_type type;      /* Type. */
    enum nx_flow_format flow_format; /* Currently selected flow format. */
    bool flow_mod_table_id;     /* NXT_FLOW_MOD_TABLE_ID enabled? */

    /* Asynchronous flow table operation support. */
    struct list opgroups;       /* Contains pending "ofopgroups", if any. */
    struct ofpbuf *blocked;     /* Postponed OpenFlow message, if any. */
    bool retry;                 /* True if 'blocked' is ready to try again. */

    /* OFPT_PACKET_IN related data. */
    struct rconn_packet_counter *packet_in_counter; /* # queued on 'rconn'. */
#define N_SCHEDULERS 2
    struct pinsched *schedulers[N_SCHEDULERS];
    struct pktbuf *pktbuf;         /* OpenFlow packet buffers. */
    int miss_send_len;             /* Bytes to send of buffered packets. */

    /* Number of OpenFlow messages queued on 'rconn' as replies to OpenFlow
     * requests, and the maximum number before we stop reading OpenFlow
     * requests.  */
#define OFCONN_REPLY_MAX 100
    struct rconn_packet_counter *reply_counter;

    /* type == OFCONN_PRIMARY only. */
    enum nx_role role;           /* Role. */
    struct hmap_node hmap_node;  /* In struct connmgr's "controllers" map. */
    enum ofproto_band band;      /* In-band or out-of-band? */
};

static struct ofconn *ofconn_create(struct connmgr *, struct rconn *,
                                    enum ofconn_type);
static void ofconn_destroy(struct ofconn *);

static void ofconn_reconfigure(struct ofconn *,
                               const struct ofproto_controller *);

static void ofconn_run(struct ofconn *,
                       bool (*handle_openflow)(struct ofconn *,
                                               struct ofpbuf *ofp_msg));
static void ofconn_wait(struct ofconn *, bool handling_openflow);

static const char *ofconn_get_target(const struct ofconn *);
static char *ofconn_make_name(const struct connmgr *, const char *target);

static void ofconn_set_rate_limit(struct ofconn *, int rate, int burst);

static bool ofconn_receives_async_msgs(const struct ofconn *);

static void ofconn_send(const struct ofconn *, struct ofpbuf *,
                        struct rconn_packet_counter *);

static void do_send_packet_in(struct ofpbuf *, void *ofconn_);

/* A listener for incoming OpenFlow "service" connections. */
struct ofservice {
    struct hmap_node node;      /* In struct connmgr's "services" hmap. */
    struct pvconn *pvconn;      /* OpenFlow connection listener. */

    /* These are not used by ofservice directly.  They are settings for
     * accepted "struct ofconn"s from the pvconn. */
    int probe_interval;         /* Max idle time before probing, in seconds. */
    int rate_limit;             /* Max packet-in rate in packets per second. */
    int burst_limit;            /* Limit on accumulating packet credits. */
};

static void ofservice_reconfigure(struct ofservice *,
                                  const struct ofproto_controller *);
static int ofservice_create(struct connmgr *, const char *target);
static void ofservice_destroy(struct connmgr *, struct ofservice *);
static struct ofservice *ofservice_lookup(struct connmgr *,
                                          const char *target);

/* Connection manager for an OpenFlow switch. */
struct connmgr {
    struct ofproto *ofproto;
    char *name;
    char *local_port_name;

    /* OpenFlow connections. */
    struct hmap controllers;   /* Controller "struct ofconn"s. */
    struct list all_conns;     /* Contains "struct ofconn"s. */

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

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, node, &mgr->all_conns) {
        ofconn_destroy(ofconn);
    }
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

/* Does all of the periodic maintenance required by 'mgr'.
 *
 * If 'handle_openflow' is nonnull, calls 'handle_openflow' for each message
 * received on an OpenFlow connection, passing along the OpenFlow connection
 * itself and the message that was sent.  If 'handle_openflow' returns true,
 * the message is considered to be fully processed.  If 'handle_openflow'
 * returns false, the message is considered not to have been processed at all;
 * it will be stored and re-presented to 'handle_openflow' following the next
 * call to connmgr_retry().  'handle_openflow' must not modify or free the
 * message.
 *
 * If 'handle_openflow' is NULL, no OpenFlow messages will be processed and
 * other activities that could affect the flow table (in-band processing,
 * fail-open processing) are suppressed too. */
void
connmgr_run(struct connmgr *mgr,
            bool (*handle_openflow)(struct ofconn *, struct ofpbuf *ofp_msg))
{
    struct ofconn *ofconn, *next_ofconn;
    struct ofservice *ofservice;
    size_t i;

    if (handle_openflow && mgr->in_band) {
        if (!in_band_run(mgr->in_band)) {
            in_band_destroy(mgr->in_band);
            mgr->in_band = NULL;
        }
    }

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, node, &mgr->all_conns) {
        ofconn_run(ofconn, handle_openflow);
    }

    /* Fail-open maintenance.  Do this after processing the ofconns since
     * fail-open checks the status of the controller rconn. */
    if (handle_openflow && mgr->fail_open) {
        fail_open_run(mgr->fail_open);
    }

    HMAP_FOR_EACH (ofservice, node, &mgr->services) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(ofservice->pvconn, OFP_VERSION, &vconn);
        if (!retval) {
            struct rconn *rconn;
            char *name;

            rconn = rconn_create(ofservice->probe_interval, 0);
            name = ofconn_make_name(mgr, vconn_get_name(vconn));
            rconn_connect_unreliably(rconn, vconn, name);
            free(name);

            ofconn = ofconn_create(mgr, rconn, OFCONN_SERVICE);
            ofconn_set_rate_limit(ofconn, ofservice->rate_limit,
                                  ofservice->burst_limit);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", strerror(retval));
        }
    }

    for (i = 0; i < mgr->n_snoops; i++) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(mgr->snoops[i], OFP_VERSION, &vconn);
        if (!retval) {
            add_snooper(mgr, vconn);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", strerror(retval));
        }
    }
}

/* Causes the poll loop to wake up when connmgr_run() needs to run.
 *
 * If 'handling_openflow' is true, arriving OpenFlow messages and other
 * activities that affect the flow table will wake up the poll loop.  If
 * 'handling_openflow' is false, they will not. */
void
connmgr_wait(struct connmgr *mgr, bool handling_openflow)
{
    struct ofservice *ofservice;
    struct ofconn *ofconn;
    size_t i;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        ofconn_wait(ofconn, handling_openflow);
    }
    if (handling_openflow && mgr->in_band) {
        in_band_wait(mgr->in_band);
    }
    if (handling_openflow && mgr->fail_open) {
        fail_open_wait(mgr->fail_open);
    }
    HMAP_FOR_EACH (ofservice, node, &mgr->services) {
        pvconn_wait(ofservice->pvconn);
    }
    for (i = 0; i < mgr->n_snoops; i++) {
        pvconn_wait(mgr->snoops[i]);
    }
}

/* Returns the ofproto that owns 'ofconn''s connmgr. */
struct ofproto *
ofconn_get_ofproto(const struct ofconn *ofconn)
{
    return ofconn->connmgr->ofproto;
}

/* If processing of OpenFlow messages was blocked on any 'mgr' ofconns by
 * returning false to the 'handle_openflow' callback to connmgr_run(), this
 * re-enables them. */
void
connmgr_retry(struct connmgr *mgr)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        ofconn->retry = true;
    }
}

/* OpenFlow configuration. */

static void add_controller(struct connmgr *, const char *target);
static struct ofconn *find_controller_by_target(struct connmgr *,
                                                const char *target);
static void update_fail_open(struct connmgr *);
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

            shash_add(info, target, cinfo);

            cinfo->is_connected = rconn_is_connected(rconn);
            cinfo->role = ofconn->role;

            cinfo->pairs.n = 0;

            if (last_error) {
                cinfo->pairs.keys[cinfo->pairs.n] = "last_error";
                cinfo->pairs.values[cinfo->pairs.n++]
                    = xstrdup(ovs_retval_to_string(last_error));
            }

            cinfo->pairs.keys[cinfo->pairs.n] = "state";
            cinfo->pairs.values[cinfo->pairs.n++]
                = xstrdup(rconn_get_state(rconn));

            if (last_connection != TIME_MIN) {
                cinfo->pairs.keys[cinfo->pairs.n] = "sec_since_connect";
                cinfo->pairs.values[cinfo->pairs.n++]
                    = xasprintf("%ld", (long int) (now - last_connection));
            }

            if (last_disconnect != TIME_MIN) {
                cinfo->pairs.keys[cinfo->pairs.n] = "sec_since_disconnect";
                cinfo->pairs.values[cinfo->pairs.n++]
                    = xasprintf("%ld", (long int) (now - last_disconnect));
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
        while (cinfo->pairs.n) {
            free((char *) cinfo->pairs.values[--cinfo->pairs.n]);
        }
        free(cinfo);
    }
    shash_destroy(info);
}

/* Changes 'mgr''s set of controllers to the 'n_controllers' controllers in
 * 'controllers'. */
void
connmgr_set_controllers(struct connmgr *mgr,
                        const struct ofproto_controller *controllers,
                        size_t n_controllers)
{
    bool had_controllers = connmgr_has_controllers(mgr);
    struct shash new_controllers;
    struct ofconn *ofconn, *next_ofconn;
    struct ofservice *ofservice, *next_ofservice;
    size_t i;

    /* Create newly configured controllers and services.
     * Create a name to ofproto_controller mapping in 'new_controllers'. */
    shash_init(&new_controllers);
    for (i = 0; i < n_controllers; i++) {
        const struct ofproto_controller *c = &controllers[i];

        if (!vconn_verify_name(c->target)) {
            if (!find_controller_by_target(mgr, c->target)) {
                add_controller(mgr, c->target);
            }
        } else if (!pvconn_verify_name(c->target)) {
            if (!ofservice_lookup(mgr, c->target)) {
                ofservice_create(mgr, c->target);
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
        struct ofproto_controller *c;

        c = shash_find_data(&new_controllers, ofconn_get_target(ofconn));
        if (!c) {
            ofconn_destroy(ofconn);
        } else {
            ofconn_reconfigure(ofconn, c);
        }
    }

    /* Delete services that are no longer configured.
     * Update configuration of all now-existing services. */
    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, node, &mgr->services) {
        struct ofproto_controller *c;

        c = shash_find_data(&new_controllers,
                            pvconn_get_name(ofservice->pvconn));
        if (!c) {
            ofservice_destroy(mgr, ofservice);
        } else {
            ofservice_reconfigure(ofservice, c);
        }
    }

    shash_destroy(&new_controllers);

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
add_controller(struct connmgr *mgr, const char *target)
{
    char *name = ofconn_make_name(mgr, target);
    struct ofconn *ofconn;

    ofconn = ofconn_create(mgr, rconn_create(5, 8), OFCONN_PRIMARY);
    ofconn->pktbuf = pktbuf_create();
    ofconn->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;
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
        struct sockaddr_in *sin = &addrs[n_addrs];

        if (ofconn->band == OFPROTO_OUT_OF_BAND) {
            continue;
        }

        sin->sin_addr.s_addr = rconn_get_remote_ip(ofconn->rconn);
        if (sin->sin_addr.s_addr) {
            sin->sin_port = rconn_get_remote_port(ofconn->rconn);
            n_addrs++;
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

/* Returns the role configured for 'ofconn'.
 *
 * The default role, if no other role has been set, is NX_ROLE_OTHER. */
enum nx_role
ofconn_get_role(const struct ofconn *ofconn)
{
    return ofconn->role;
}

/* Changes 'ofconn''s role to 'role'.  If 'role' is NX_ROLE_MASTER then any
 * existing master is demoted to a slave. */
void
ofconn_set_role(struct ofconn *ofconn, enum nx_role role)
{
    if (role == NX_ROLE_MASTER) {
        struct ofconn *other;

        HMAP_FOR_EACH (other, hmap_node, &ofconn->connmgr->controllers) {
            if (other->role == NX_ROLE_MASTER) {
                other->role = NX_ROLE_SLAVE;
            }
        }
    }
    ofconn->role = role;
}

/* Returns the currently configured flow format for 'ofconn', one of NXFF_*.
 *
 * The default, if no other format has been set, is NXFF_OPENFLOW10. */
enum nx_flow_format
ofconn_get_flow_format(struct ofconn *ofconn)
{
    return ofconn->flow_format;
}

/* Sets the flow format for 'ofconn' to 'flow_format' (one of NXFF_*). */
void
ofconn_set_flow_format(struct ofconn *ofconn, enum nx_flow_format flow_format)
{
    ofconn->flow_format = flow_format;
}

/* Returns true if the NXT_FLOW_MOD_TABLE_ID extension is enabled, false
 * otherwise.
 *
 * By default the extension is not enabled. */
bool
ofconn_get_flow_mod_table_id(const struct ofconn *ofconn)
{
    return ofconn->flow_mod_table_id;
}

/* Enables or disables (according to 'enable') the NXT_FLOW_MOD_TABLE_ID
 * extension on 'ofconn'. */
void
ofconn_set_flow_mod_table_id(struct ofconn *ofconn, bool enable)
{
    ofconn->flow_mod_table_id = enable;
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
ofconn_send_replies(const struct ofconn *ofconn, struct list *replies)
{
    struct ofpbuf *reply, *next;

    LIST_FOR_EACH_SAFE (reply, next, list_node, replies) {
        list_remove(&reply->list_node);
        ofconn_send_reply(ofconn, reply);
    }
}

/* Sends 'error', which should be an OpenFlow error created with
 * e.g. ofp_mkerr(), on 'ofconn', as a reply to 'request'.  Only at most the
 * first 64 bytes of 'request' are used. */
void
ofconn_send_error(const struct ofconn *ofconn,
                  const struct ofp_header *request, int error)
{
    struct ofpbuf *msg = ofputil_encode_error_msg(error, request);
    if (msg) {
        ofconn_send_reply(ofconn, msg);
    }
}

/* Same as pktbuf_retrieve(), using the pktbuf owned by 'ofconn'. */
int
ofconn_pktbuf_retrieve(struct ofconn *ofconn, uint32_t id,
                       struct ofpbuf **bufferp, uint16_t *in_port)
{
    return pktbuf_retrieve(ofconn->pktbuf, id, bufferp, in_port);
}

/* Returns true if 'ofconn' has any pending opgroups. */
bool
ofconn_has_pending_opgroups(const struct ofconn *ofconn)
{
    return !list_is_empty(&ofconn->opgroups);
}

/* Returns the number of pending opgroups on 'ofconn'. */
size_t
ofconn_n_pending_opgroups(const struct ofconn *ofconn)
{
    return list_size(&ofconn->opgroups);
}

/* Adds 'ofconn_node' to 'ofconn''s list of pending opgroups.
 *
 * If 'ofconn' is destroyed or its connection drops, then 'ofconn' will remove
 * 'ofconn_node' from the list and re-initialize it with list_init().  The
 * client may, therefore, use list_is_empty(ofconn_node) to determine whether
 * 'ofconn_node' is still associated with an active ofconn.
 *
 * The client may also remove ofconn_node from the list itself, with
 * list_remove(). */
void
ofconn_add_opgroup(struct ofconn *ofconn, struct list *ofconn_node)
{
    list_push_back(&ofconn->opgroups, ofconn_node);
}

/* Private ofconn functions. */

static const char *
ofconn_get_target(const struct ofconn *ofconn)
{
    return rconn_get_target(ofconn->rconn);
}

static struct ofconn *
ofconn_create(struct connmgr *mgr, struct rconn *rconn, enum ofconn_type type)
{
    struct ofconn *ofconn = xzalloc(sizeof *ofconn);
    ofconn->connmgr = mgr;
    list_push_back(&mgr->all_conns, &ofconn->node);
    ofconn->rconn = rconn;
    ofconn->type = type;
    ofconn->flow_format = NXFF_OPENFLOW10;
    ofconn->flow_mod_table_id = false;
    list_init(&ofconn->opgroups);
    ofconn->role = NX_ROLE_OTHER;
    ofconn->packet_in_counter = rconn_packet_counter_create ();
    ofconn->pktbuf = NULL;
    ofconn->miss_send_len = 0;
    ofconn->reply_counter = rconn_packet_counter_create ();
    return ofconn;
}

/* Disassociates 'ofconn' from all of the ofopgroups that it initiated that
 * have not yet completed.  (Those ofopgroups will still run to completion in
 * the usual way, but any errors that they run into will not be reported on any
 * OpenFlow channel.)
 *
 * Also discards any blocked operation on 'ofconn'. */
static void
ofconn_flush(struct ofconn *ofconn)
{
    while (!list_is_empty(&ofconn->opgroups)) {
        list_init(list_pop_front(&ofconn->opgroups));
    }
    ofpbuf_delete(ofconn->blocked);
    ofconn->blocked = NULL;
}

static void
ofconn_destroy(struct ofconn *ofconn)
{
    ofconn_flush(ofconn);

    if (ofconn->type == OFCONN_PRIMARY) {
        hmap_remove(&ofconn->connmgr->controllers, &ofconn->hmap_node);
    }

    list_remove(&ofconn->node);
    rconn_destroy(ofconn->rconn);
    rconn_packet_counter_destroy(ofconn->packet_in_counter);
    rconn_packet_counter_destroy(ofconn->reply_counter);
    pktbuf_destroy(ofconn->pktbuf);
    free(ofconn);
}

/* Reconfigures 'ofconn' to match 'c'.  'ofconn' and 'c' must have the same
 * target. */
static void
ofconn_reconfigure(struct ofconn *ofconn, const struct ofproto_controller *c)
{
    int probe_interval;

    ofconn->band = c->band;

    rconn_set_max_backoff(ofconn->rconn, c->max_backoff);

    probe_interval = c->probe_interval ? MAX(c->probe_interval, 5) : 0;
    rconn_set_probe_interval(ofconn->rconn, probe_interval);

    ofconn_set_rate_limit(ofconn, c->rate_limit, c->burst_limit);
}

/* Returns true if it makes sense for 'ofconn' to receive and process OpenFlow
 * messages. */
static bool
ofconn_may_recv(const struct ofconn *ofconn)
{
    int count = rconn_packet_counter_read (ofconn->reply_counter);
    return (!ofconn->blocked || ofconn->retry) && count < OFCONN_REPLY_MAX;
}

static void
ofconn_run(struct ofconn *ofconn,
           bool (*handle_openflow)(struct ofconn *, struct ofpbuf *ofp_msg))
{
    struct connmgr *mgr = ofconn->connmgr;
    size_t i;

    for (i = 0; i < N_SCHEDULERS; i++) {
        pinsched_run(ofconn->schedulers[i], do_send_packet_in, ofconn);
    }

    rconn_run(ofconn->rconn);

    if (handle_openflow) {
        /* Limit the number of iterations to avoid starving other tasks. */
        for (i = 0; i < 50 && ofconn_may_recv(ofconn); i++) {
            struct ofpbuf *of_msg;

            of_msg = (ofconn->blocked
                      ? ofconn->blocked
                      : rconn_recv(ofconn->rconn));
            if (!of_msg) {
                break;
            }
            if (mgr->fail_open) {
                fail_open_maybe_recover(mgr->fail_open);
            }

            if (handle_openflow(ofconn, of_msg)) {
                ofpbuf_delete(of_msg);
                ofconn->blocked = NULL;
            } else {
                ofconn->blocked = of_msg;
                ofconn->retry = false;
            }
        }
    }

    if (!rconn_is_alive(ofconn->rconn)) {
        ofconn_destroy(ofconn);
    } else if (!rconn_is_connected(ofconn->rconn)) {
        ofconn_flush(ofconn);
    }
}

static void
ofconn_wait(struct ofconn *ofconn, bool handling_openflow)
{
    int i;

    for (i = 0; i < N_SCHEDULERS; i++) {
        pinsched_wait(ofconn->schedulers[i]);
    }
    rconn_run_wait(ofconn->rconn);
    if (handling_openflow && ofconn_may_recv(ofconn)) {
        rconn_recv_wait(ofconn->rconn);
    }
}

/* Returns true if 'ofconn' should receive asynchronous messages. */
static bool
ofconn_receives_async_msgs(const struct ofconn *ofconn)
{
    if (!rconn_is_connected(ofconn->rconn)) {
        return false;
    } else if (ofconn->type == OFCONN_PRIMARY) {
        /* Primary controllers always get asynchronous messages unless they
         * have configured themselves as "slaves".  */
        return ofconn->role != NX_ROLE_SLAVE;
    } else {
        /* Service connections don't get asynchronous messages unless they have
         * explicitly asked for them by setting a nonzero miss send length. */
        return ofconn->miss_send_len > 0;
    }
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
    update_openflow_length(msg);
    if (rconn_send(ofconn->rconn, msg, counter)) {
        ofpbuf_delete(msg);
    }
}

/* Sending asynchronous messages. */

static void schedule_packet_in(struct ofconn *, struct ofputil_packet_in,
                               const struct flow *, struct ofpbuf *rw_packet);

/* Sends an OFPT_PORT_STATUS message with 'opp' and 'reason' to appropriate
 * controllers managed by 'mgr'. */
void
connmgr_send_port_status(struct connmgr *mgr, const struct ofp_phy_port *opp,
                         uint8_t reason)
{
    /* XXX Should limit the number of queued port status change messages. */
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
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
        ops->desc = *opp;
        ofconn_send(ofconn, b, NULL);
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
        struct ofpbuf *msg;

        if (!ofconn_receives_async_msgs(ofconn)) {
            continue;
        }

        /* Account flow expirations as replies to OpenFlow requests.  That
         * works because preventing OpenFlow requests from being processed also
         * prevents new flows from being added (and expiring).  (It also
         * prevents processing OpenFlow requests that would not add new flows,
         * so it is imperfect.) */
        msg = ofputil_encode_flow_removed(fr, ofconn->flow_format);
        ofconn_send_reply(ofconn, msg);
    }
}

/* Given 'pin', sends an OFPT_PACKET_IN message to each OpenFlow controller as
 * necessary according to their individual configurations.
 *
 * 'rw_packet' may be NULL.  Otherwise, 'rw_packet' must contain the same data
 * as pin->packet.  (rw_packet == pin->packet is also valid.)  Ownership of
 * 'rw_packet' is transferred to this function. */
void
connmgr_send_packet_in(struct connmgr *mgr,
                       const struct ofputil_packet_in *pin,
                       const struct flow *flow, struct ofpbuf *rw_packet)
{
    struct ofconn *ofconn, *prev;

    prev = NULL;
    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (ofconn_receives_async_msgs(ofconn)) {
            if (prev) {
                schedule_packet_in(prev, *pin, flow, NULL);
            }
            prev = ofconn;
        }
    }
    if (prev) {
        schedule_packet_in(prev, *pin, flow, rw_packet);
    } else {
        ofpbuf_delete(rw_packet);
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

/* Takes 'pin', whose packet has the flow specified by 'flow', composes an
 * OpenFlow packet-in message from it, and passes it to 'ofconn''s packet
 * scheduler for sending.
 *
 * 'rw_packet' may be NULL.  Otherwise, 'rw_packet' must contain the same data
 * as pin->packet.  (rw_packet == pin->packet is also valid.)  Ownership of
 * 'rw_packet' is transferred to this function. */
static void
schedule_packet_in(struct ofconn *ofconn, struct ofputil_packet_in pin,
                   const struct flow *flow, struct ofpbuf *rw_packet)
{
    struct connmgr *mgr = ofconn->connmgr;

    /* Get OpenFlow buffer_id. */
    if (pin.reason == OFPR_ACTION) {
        pin.buffer_id = UINT32_MAX;
    } else if (mgr->fail_open && fail_open_is_active(mgr->fail_open)) {
        pin.buffer_id = pktbuf_get_null();
    } else if (!ofconn->pktbuf) {
        pin.buffer_id = UINT32_MAX;
    } else {
        pin.buffer_id = pktbuf_save(ofconn->pktbuf, pin.packet, flow->in_port);
    }

    /* Figure out how much of the packet to send. */
    if (pin.reason == OFPR_NO_MATCH) {
        pin.send_len = pin.packet->size;
    } else {
        /* Caller should have initialized 'send_len' to 'max_len' specified in
         * struct ofp_action_output. */
    }
    if (pin.buffer_id != UINT32_MAX) {
        pin.send_len = MIN(pin.send_len, ofconn->miss_send_len);
    }

    /* Make OFPT_PACKET_IN and hand over to packet scheduler.  It might
     * immediately call into do_send_packet_in() or it might buffer it for a
     * while (until a later call to pinsched_run()). */
    pinsched_send(ofconn->schedulers[pin.reason == OFPR_NO_MATCH ? 0 : 1],
                  flow->in_port, ofputil_encode_packet_in(&pin, rw_packet),
                  do_send_packet_in, ofconn);
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

/* Sends 'packet' to each controller connected to 'mgr'.  Takes ownership of
 * 'packet'. */
void
connmgr_broadcast(struct connmgr *mgr, struct ofpbuf *packet)
{
    struct ofconn *ofconn, *prev;

    prev = NULL;
    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (prev) {
            ofconn_send_reply(ofconn, ofpbuf_clone(packet));
        }
        if (rconn_is_connected(ofconn->rconn)) {
            prev = ofconn;
        }
    }
    if (prev) {
        ofconn_send_reply(prev, packet);
    } else {
        ofpbuf_delete(packet);
    }
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
connmgr_msg_in_hook(struct connmgr *mgr, const struct flow *flow,
                    const struct ofpbuf *packet)
{
    return mgr->in_band && in_band_msg_in_hook(mgr->in_band, flow, packet);
}

bool
connmgr_may_set_up_flow(struct connmgr *mgr, const struct flow *flow,
                        const struct nlattr *odp_actions,
                        size_t actions_len)
{
    return !mgr->in_band || in_band_rule_check(flow, odp_actions, actions_len);
}

/* Fail-open and in-band implementation. */

/* Called by 'ofproto' after all flows have been flushed, to allow fail-open
 * and standalone mode to re-create their flows.
 *
 * In-band control has more sophisticated code that manages flows itself. */
void
connmgr_flushed(struct connmgr *mgr)
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
        union ofp_action action;
        struct cls_rule rule;

        memset(&action, 0, sizeof action);
        action.type = htons(OFPAT_OUTPUT);
        action.output.len = htons(sizeof action);
        action.output.port = htons(OFPP_NORMAL);
        cls_rule_init_catchall(&rule, 0);
        ofproto_add_flow(mgr->ofproto, &rule, &action, 1);
    }
}

/* Creates a new ofservice for 'target' in 'mgr'.  Returns 0 if successful,
 * otherwise a positive errno value.
 *
 * ofservice_reconfigure() must be called to fully configure the new
 * ofservice. */
static int
ofservice_create(struct connmgr *mgr, const char *target)
{
    struct ofservice *ofservice;
    struct pvconn *pvconn;
    int error;

    error = pvconn_open(target, &pvconn);
    if (error) {
        return error;
    }

    ofservice = xzalloc(sizeof *ofservice);
    hmap_insert(&mgr->services, &ofservice->node, hash_string(target, 0));
    ofservice->pvconn = pvconn;

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
