/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2019 Nicira, Inc.
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
#include <errno.h>
#include <stdlib.h>

#include "bundles.h"
#include "connmgr.h"
#include "coverage.h"
#include "fail-open.h"
#include "in-band.h"
#include "odp-util.h"
#include "ofproto-provider.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-monitor.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "pinsched.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "openvswitch/shash.h"
#include "sat-math.h"
#include "simap.h"
#include "stream.h"
#include "timeval.h"
#include "util.h"

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
    struct connmgr *connmgr;    /* Connection's manager. */
    struct ovs_list connmgr_node; /* In connmgr->conns. */

    struct ofservice *ofservice;    /* Connection's service. */
    struct ovs_list ofservice_node; /* In service->conns. */

    struct rconn *rconn;        /* OpenFlow connection. */
    enum ofconn_type type;      /* Type. */
    enum ofproto_band band;     /* In-band or out-of-band? */
    bool want_packet_in_on_miss;

    /* OpenFlow state. */
    enum ofp12_controller_role role;           /* Role. */
    enum ofputil_protocol protocol; /* Current protocol variant. */
    enum ofputil_packet_in_format packet_in_format;

    /* OFPT_PACKET_IN related data. */
    int packet_in_queue_size;
    struct rconn_packet_counter *packet_in_counter; /* # queued on 'rconn'. */
#define N_SCHEDULERS 2
    struct pinsched *schedulers[N_SCHEDULERS];
    int miss_send_len;             /* Bytes to send of buffered packets. */
    uint16_t controller_id;     /* Connection controller ID. */

    /* Number of OpenFlow messages queued on 'rconn' as replies to OpenFlow
     * requests, and the maximum number before we stop reading OpenFlow
     * requests.  */
#define OFCONN_REPLY_MAX 100
    struct rconn_packet_counter *reply_counter;

    /* Asynchronous message configuration in each possible role.
     *
     * A 1-bit enables sending an asynchronous message for one possible reason
     * that the message might be generated, a 0-bit disables it. */
    struct ofputil_async_cfg *async_cfg;

    /* Flow table operation logging. */
    int n_add, n_delete, n_modify; /* Number of unreported ops of each kind. */
    long long int first_op, last_op; /* Range of times for unreported ops. */
    long long int next_op_report;    /* Time to report ops, or LLONG_MAX. */
    long long int op_backoff;        /* Earliest time to report ops again. */

    /* Reassembly of multipart requests. */
    struct hmap assembler;

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
    long long int next_bundle_expiry_check;
};

/* vswitchd/ovs-vswitchd.8.in documents the value of BUNDLE_IDLE_LIFETIME in
 * seconds.  That documentation must be kept in sync with the value below. */
#define BUNDLE_EXPIRY_INTERVAL 1000     /* Check bundle expiry every 1 sec. */
#define BUNDLE_IDLE_TIMEOUT_DEFAULT 10000   /* Expire idle bundles after
                                             * 10 seconds. */

static unsigned int bundle_idle_timeout = BUNDLE_IDLE_TIMEOUT_DEFAULT;

static void ofconn_create(struct ofservice *, struct rconn *,
                          const struct ofproto_controller *settings)
    OVS_EXCLUDED(ofproto_mutex);
static void ofconn_destroy(struct ofconn *) OVS_REQUIRES(ofproto_mutex);

static void ofconn_reconfigure(struct ofconn *,
                               const struct ofproto_controller *);

static void ofconn_run(struct ofconn *,
                       void (*handle_openflow)(struct ofconn *,
                                               const struct ovs_list *msgs));
static void ofconn_wait(struct ofconn *);

static void ofconn_log_flow_mods(struct ofconn *);

static char *ofconn_make_name(const struct connmgr *, const char *target);

static void ofconn_set_rate_limit(struct ofconn *, int rate, int burst);

static void ofconn_send(const struct ofconn *, struct ofpbuf *,
                        struct rconn_packet_counter *);

static void do_send_packet_ins(struct ofconn *, struct ovs_list *txq);

/* A listener for incoming OpenFlow connections or for establishing an
 * outgoing connection. */
struct ofservice {
    struct hmap_node hmap_node; /* In connmgr->services, by target. */
    struct connmgr *connmgr;

    char *target;               /* e.g. "tcp:..." or "pssl:...". */
    struct ovs_list conns;      /* "ofconn"s generated by this service. */
    enum ofconn_type type;      /* OFCONN_PRIMARY or OFCONN_SERVICE. */

    /* Source of connections. */
    struct rconn *rconn;        /* Active connection only. */
    struct pvconn *pvconn;      /* Passive listener only. */

    /* Settings for "struct ofconn"s established by this service. */
    struct ofproto_controller s;
};

static void ofservice_run(struct ofservice *);
static void ofservice_wait(struct ofservice *);
static int ofservice_reconfigure(struct ofservice *,
                                 const struct ofproto_controller *)
    OVS_REQUIRES(ofproto_mutex);
static void ofservice_create(struct connmgr *mgr, const char *target,
                             const struct ofproto_controller *)
    OVS_REQUIRES(ofproto_mutex);
static void ofservice_destroy(struct ofservice *) OVS_REQUIRES(ofproto_mutex);
static struct ofservice *ofservice_lookup(struct connmgr *,
                                          const char *target);

/* Connection manager for an OpenFlow switch. */
struct connmgr {
    struct ofproto *ofproto;
    char *name;
    char *local_port_name;

    /* OpenFlow connections.
     *
     * All modifications to 'conns' protected by ofproto_mutex, so that any
     * traversals from other threads can be made safe by holding the
     * ofproto_mutex.*/
    struct ovs_list conns;       /* All ofconns. */
    uint64_t master_election_id; /* monotonically increasing sequence number
                                  * for master election */
    bool master_election_id_defined;

    /* OpenFlow connection establishment. */
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

    ATOMIC(int) want_packet_in_on_miss;   /* Sum of ofconns' values. */
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
    struct connmgr *mgr = xmalloc(sizeof *mgr);
    mgr->ofproto = ofproto;
    mgr->name = xstrdup(name);
    mgr->local_port_name = xstrdup(local_port_name);

    ovs_list_init(&mgr->conns);
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

    atomic_init(&mgr->want_packet_in_on_miss, 0);

    return mgr;
}

/* The default "table-miss" behaviour for OpenFlow1.3+ is to drop the
 * packet rather than to send the packet to the controller.
 *
 * This function maintains the count of pre-OpenFlow1.3 with controller_id 0,
 * as we assume these are the controllers that should receive "table-miss"
 * notifications. */
static void
update_want_packet_in_on_miss(struct ofconn *ofconn)
{
   /* We want a packet-in on miss when controller_id is zero and OpenFlow is
    * lower than version 1.3. */
   enum ofputil_protocol p = ofconn->protocol;
   int new_want = (ofconn->controller_id == 0 &&
                   (p == OFPUTIL_P_NONE ||
                    ofputil_protocol_to_ofp_version(p) < OFP13_VERSION));

   /* Update the setting and the count if necessary. */
   int old_want = ofconn->want_packet_in_on_miss;
   if (old_want != new_want) {
       atomic_int *dst = &ofconn->connmgr->want_packet_in_on_miss;
       int count;
       atomic_read_relaxed(dst, &count);
       atomic_store_relaxed(dst, count - old_want + new_want);

       ofconn->want_packet_in_on_miss = new_want;
   }
}

/* Frees 'mgr' and all of its resources. */
void
connmgr_destroy(struct connmgr *mgr)
    OVS_REQUIRES(ofproto_mutex)
{
    if (!mgr) {
        return;
    }

    struct ofservice *ofservice, *next_ofservice;
    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, hmap_node, &mgr->services) {
        ofservice_destroy(ofservice);
    }
    hmap_destroy(&mgr->services);
    ovs_assert(ovs_list_is_empty(&mgr->conns));

    for (size_t i = 0; i < mgr->n_snoops; i++) {
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
                                    const struct ovs_list *msgs))
    OVS_EXCLUDED(ofproto_mutex)
{
    if (mgr->in_band) {
        if (!in_band_run(mgr->in_band)) {
            in_band_destroy(mgr->in_band);
            mgr->in_band = NULL;
        }
    }

    struct ofconn *ofconn, *next_ofconn;
    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, connmgr_node, &mgr->conns) {
        ofconn_run(ofconn, handle_openflow);
    }
    ofmonitor_run(mgr);

    /* Fail-open maintenance.  Do this after processing the ofconns since
     * fail-open checks the status of the controller rconn. */
    if (mgr->fail_open) {
        fail_open_run(mgr->fail_open);
    }

    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        ofservice_run(ofservice);
    }

    for (size_t i = 0; i < mgr->n_snoops; i++) {
        struct vconn *vconn;
        int retval = pvconn_accept(mgr->snoops[i], &vconn);
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
    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        ofconn_wait(ofconn);
    }

    ofmonitor_wait(mgr);

    if (mgr->in_band) {
        in_band_wait(mgr->in_band);
    }

    if (mgr->fail_open) {
        fail_open_wait(mgr->fail_open);
    }

    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        ofservice_wait(ofservice);
    }

    for (size_t i = 0; i < mgr->n_snoops; i++) {
        pvconn_wait(mgr->snoops[i]);
    }
}

/* Adds some memory usage statistics for 'mgr' into 'usage', for use with
 * memory_report(). */
void
connmgr_get_memory_usage(const struct connmgr *mgr, struct simap *usage)
{
    unsigned int packets = 0;
    unsigned int ofconns = 0;

    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        ofconns++;

        packets += rconn_count_txqlen(ofconn->rconn);
        for (int i = 0; i < N_SCHEDULERS; i++) {
            struct pinsched_stats stats;

            pinsched_get_stats(ofconn->schedulers[i], &stats);
            packets += stats.n_queued;
        }
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

/* Sets the bundle idle timeout to 'timeout' seconds, interpreting 0 as
 * requesting the default timeout.
 *
 * The OpenFlow spec mandates the timeout to be at least one second; . */
void
connmgr_set_bundle_idle_timeout(unsigned timeout)
{
    bundle_idle_timeout = (timeout
                           ? sat_mul(timeout, 1000)
                           : BUNDLE_IDLE_TIMEOUT_DEFAULT);
}

/* OpenFlow configuration. */

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
    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        if (ofservice->type == OFCONN_PRIMARY) {
            return true;
        }
    }
    return false;
}

static struct ofconn *
ofservice_first_conn(const struct ofservice *ofservice)
{
    return (ovs_list_is_empty(&ofservice->conns)
            ? NULL
            : CONTAINER_OF(ofservice->conns.next,
                           struct ofconn, ofservice_node));
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
    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        const struct rconn *rconn = ofservice->rconn;
        if (!rconn) {
            continue;
        }
        const char *target = rconn_get_target(rconn);

        if (!shash_find(info, target)) {
            struct ofconn *ofconn = ofservice_first_conn(ofservice);
            struct ofproto_controller_info *cinfo = xmalloc(sizeof *cinfo);
            long long int now = time_msec();
            long long int last_connection = rconn_get_last_connection(rconn);
            long long int last_disconnect = rconn_get_last_disconnect(rconn);
            int last_error = rconn_get_last_error(rconn);
            int i;

            shash_add(info, target, cinfo);

            cinfo->is_connected = rconn_is_connected(rconn);
            cinfo->role = ofconn ? ofconn->role : OFPCR12_ROLE_NOCHANGE;

            smap_init(&cinfo->pairs);
            if (last_error) {
                smap_add(&cinfo->pairs, "last_error",
                         ovs_retval_to_string(last_error));
            }

            smap_add(&cinfo->pairs, "state", rconn_get_state(rconn));

            if (last_connection != LLONG_MIN) {
                smap_add_format(&cinfo->pairs, "sec_since_connect",
                                "%lld", (now - last_connection) / 1000);
            }

            if (last_disconnect != LLONG_MIN) {
                smap_add_format(&cinfo->pairs, "sec_since_disconnect",
                                "%lld", (now - last_disconnect) / 1000);
            }

            for (i = 0; i < N_SCHEDULERS; i++) {
                if (ofconn && ofconn->schedulers[i]) {
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
connmgr_set_controllers(struct connmgr *mgr, struct shash *controllers)
    OVS_EXCLUDED(ofproto_mutex)
{
    bool had_controllers = connmgr_has_controllers(mgr);

    /* Required to add and remove ofconns.  This could probably be narrowed to
     * cover a smaller amount of code, if that yielded some benefit. */
    ovs_mutex_lock(&ofproto_mutex);

    /* Create newly configured services. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, controllers) {
        const char *target = node->name;
        const struct ofproto_controller *c = node->data;
        if (!ofservice_lookup(mgr, target)) {
            ofservice_create(mgr, target, c);
        }
    }

    /* Delete services that are no longer configured.
     * Update configuration of all now-existing services. */
    struct ofservice *ofservice, *next_ofservice;
    HMAP_FOR_EACH_SAFE (ofservice, next_ofservice, hmap_node, &mgr->services) {
        const char *target = ofservice->target;
        struct ofproto_controller *c = shash_find_data(controllers, target);
        if (!c) {
            VLOG_INFO("%s: removed %s controller \"%s\"",
                      mgr->name, ofconn_type_to_string(ofservice->type),
                      target);
            ofservice_destroy(ofservice);
        } else {
            if (ofservice_reconfigure(ofservice, c)) {
                char *target_to_restore = xstrdup(target);
                VLOG_INFO("%s: Changes to controller \"%s\" "
                          "expects re-initialization: Re-initializing now.",
                          mgr->name, target);
                ofservice_destroy(ofservice);
                ofservice_create(mgr, target_to_restore, c);
                free(target_to_restore);
            }
        }
    }

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

    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
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
    for (size_t i = 0; i < mgr->n_snoops; i++) {
        sset_add(snoops, pvconn_get_name(mgr->snoops[i]));
    }
}

/* Returns true if 'mgr' has at least one snoop, false if it has none. */
bool
connmgr_has_snoops(const struct connmgr *mgr)
{
    return mgr->n_snoops > 0;
}

static void
update_in_band_remotes(struct connmgr *mgr)
{
    /* Allocate enough memory for as many remotes as we could possibly have. */
    size_t max_addrs = mgr->n_extra_remotes + hmap_count(&mgr->services);
    struct sockaddr_in *addrs = xmalloc(max_addrs * sizeof *addrs);
    size_t n_addrs = 0;

    /* Add all the remotes. */
    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        const char *target = ofservice->target;
        union {
            struct sockaddr_storage ss;
            struct sockaddr_in in;
        } sa;

        if (ofservice->s.band == OFPROTO_IN_BAND
            && stream_parse_target_with_default_port(target, OFP_PORT, &sa.ss)
            && sa.ss.ss_family == AF_INET) {
            addrs[n_addrs++] = sa.in;
        }
    }
    for (size_t i = 0; i < mgr->n_extra_remotes; i++) {
        addrs[n_addrs++] = mgr->extra_in_band_remotes[i];
    }

    /* Create or update or destroy in-band. */
    if (n_addrs) {
        if (!mgr->in_band) {
            in_band_create(mgr->ofproto, mgr->local_port_name, &mgr->in_band);
        }
    } else {
        /* in_band_run() needs a chance to delete any existing in-band flows.
         * We will destroy mgr->in_band after it's done with that. */
    }
    if (mgr->in_band) {
        in_band_set_queue(mgr->in_band, mgr->in_band_queue);
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
        ovs_mutex_lock(&ofproto_mutex);
        fail_open_destroy(mgr->fail_open);
        ovs_mutex_unlock(&ofproto_mutex);
        mgr->fail_open = NULL;
    }
}

static int
set_pvconns(struct pvconn ***pvconnsp, size_t *n_pvconnsp,
            const struct sset *sset)
{
    /* Free the old pvconns. */
    struct pvconn **old_pvconns = *pvconnsp;
    size_t old_n_pvconns = *n_pvconnsp;
    for (size_t i = 0; i < old_n_pvconns; i++) {
        pvconn_close(old_pvconns[i]);
    }
    free(old_pvconns);

    /* Populate the new pvconns. */
    struct pvconn **new_pvconns = xmalloc(sset_count(sset)
                                          * sizeof *new_pvconns);
    size_t new_n_pvconns = 0;

    int retval = 0;
    const char *name;
    SSET_FOR_EACH (name, sset) {
        struct pvconn *pvconn;
        int error = pvconn_open(name, 0, 0, &pvconn);
        if (!error) {
            new_pvconns[new_n_pvconns++] = pvconn;
        } else {
            VLOG_ERR("failed to listen on %s: %s", name, ovs_strerror(error));
            if (!retval) {
                retval = error;
            }
        }
    }

    *pvconnsp = new_pvconns;
    *n_pvconnsp = new_n_pvconns;

    return retval;
}

/* Returns a "preference level" for snooping 'ofconn'.  A higher return value
 * means that 'ofconn' is more interesting for monitoring than a lower return
 * value. */
static int
snoop_preference(const struct ofservice *ofservice)
{
    struct ofconn *ofconn = ofservice_first_conn(ofservice);
    if (!ofconn) {
        return 0;
    }

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
    /* Pick a controller for monitoring. */
    struct ofservice *best = NULL;
    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        if (ofservice->rconn &&
            (!best || snoop_preference(ofservice) > snoop_preference(best))) {
            best = ofservice;
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
    status.reason = reason;
    status.role = role;
    ofconn_get_master_election_id(ofconn, &status.generation_id);

    struct ofpbuf *buf
        = ofputil_encode_role_status(&status, ofconn_get_protocol(ofconn));
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

        LIST_FOR_EACH (other, connmgr_node, &ofconn->connmgr->conns) {
            if (other->role == OFPCR12_ROLE_MASTER) {
                other->role = OFPCR12_ROLE_SLAVE;
                ofconn_send_role_status(other, OFPCR12_ROLE_SLAVE,
                                        OFPCRR_MASTER_REQUEST);
            }
        }
    }
    ofconn->role = role;
}

void
ofconn_set_invalid_ttl_to_controller(struct ofconn *ofconn, bool enable)
{
    struct ofputil_async_cfg ac = ofconn_get_async_config(ofconn);
    uint32_t bit = 1u << OFPR_INVALID_TTL;
    if (enable) {
        ac.master[OAM_PACKET_IN] |= bit;
    } else {
        ac.master[OAM_PACKET_IN] &= ~bit;
    }
    ofconn_set_async_config(ofconn, &ac);
}

bool
ofconn_get_invalid_ttl_to_controller(struct ofconn *ofconn)
{
    struct ofputil_async_cfg ac = ofconn_get_async_config(ofconn);
    uint32_t bit = 1u << OFPR_INVALID_TTL;
    return (ac.master[OAM_PACKET_IN] & bit) != 0;
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
    update_want_packet_in_on_miss(ofconn);
}

/* Returns the currently configured packet in format for 'ofconn', one of
 * NXPIF_*.
 *
 * The default, if no other format has been set, is NXPIF_STANDARD. */
enum ofputil_packet_in_format
ofconn_get_packet_in_format(struct ofconn *ofconn)
{
    return ofconn->packet_in_format;
}

/* Sets the packet in format for 'ofconn' to 'packet_in_format' (one of
 * NXPIF_*). */
void
ofconn_set_packet_in_format(struct ofconn *ofconn,
                            enum ofputil_packet_in_format packet_in_format)
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
    update_want_packet_in_on_miss(ofconn);
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
                        const struct ofputil_async_cfg *ac)
{
    if (!ofconn->async_cfg) {
        ofconn->async_cfg = xmalloc(sizeof *ofconn->async_cfg);
    }
    *ofconn->async_cfg = *ac;

    if (ofputil_protocol_to_ofp_version(ofconn_get_protocol(ofconn))
        < OFP14_VERSION) {
        if (ofconn->async_cfg->master[OAM_PACKET_IN] & (1u << OFPR_ACTION)) {
            ofconn->async_cfg->master[OAM_PACKET_IN] |= OFPR14_ACTION_BITS;
        }
        if (ofconn->async_cfg->slave[OAM_PACKET_IN] & (1u << OFPR_ACTION)) {
            ofconn->async_cfg->slave[OAM_PACKET_IN] |= OFPR14_ACTION_BITS;
        }
    }
}

struct ofputil_async_cfg
ofconn_get_async_config(const struct ofconn *ofconn)
{
    if (ofconn->async_cfg) {
        return *ofconn->async_cfg;
    }

    int version = rconn_get_version(ofconn->rconn);
    return (version < 0 || !ofconn->ofservice->s.enable_async_msgs
            ? OFPUTIL_ASYNC_CFG_INIT
            : ofputil_async_cfg_default(version));
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

/* Sends 'error' on 'ofconn', as a reply to 'request'. */
void
ofconn_send_error(const struct ofconn *ofconn,
                  const struct ofp_header *request, enum ofperr error)
{
    static struct vlog_rate_limit err_rl = VLOG_RATE_LIMIT_INIT(10, 10);
    struct ofpbuf *reply = ofperr_encode_reply(error, request);
    if (!VLOG_DROP_INFO(&err_rl)) {
        size_t request_len = ntohs(request->length);

        enum ofpraw raw;
        const char *type_name = (!ofpraw_decode_partial(&raw, request,
                                                        MIN(64, request_len))
                                 ? ofpraw_get_name(raw)
                                 : "invalid");

        VLOG_INFO("%s: sending %s error reply to %s message",
                  rconn_get_name(ofconn->rconn), ofperr_to_string(error),
                  type_name);
    }
    ofconn_send_reply(ofconn, reply);
}

/* Reports that a flow_mod operation of the type specified by 'command' was
 * successfully executed by 'ofconn', so that the connmgr can log it. */
void
ofconn_report_flow_mod(struct ofconn *ofconn,
                       enum ofp_flow_mod_command command)
{
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

    long long int now = time_msec();
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

void
ofconn_insert_bundle(struct ofconn *ofconn, struct ofp_bundle *bundle)
{
    hmap_insert(&ofconn->bundles, &bundle->node, bundle_hash(bundle->id));
}

void
ofconn_remove_bundle(struct ofconn *ofconn, struct ofp_bundle *bundle)
{
    hmap_remove(&ofconn->bundles, &bundle->node);
}

static void
bundle_remove_all(struct ofconn *ofconn)
{
    struct ofp_bundle *b, *next;

    HMAP_FOR_EACH_SAFE (b, next, node, &ofconn->bundles) {
        ofp_bundle_remove__(ofconn, b);
    }
}

static void
bundle_remove_expired(struct ofconn *ofconn, long long int now)
{
    long long int limit = now - bundle_idle_timeout;

    struct ofp_bundle *b, *next;
    HMAP_FOR_EACH_SAFE (b, next, node, &ofconn->bundles) {
        if (b->used <= limit) {
            ofconn_send_error(ofconn, b->msg, OFPERR_OFPBFC_TIMEOUT);
            ofp_bundle_remove__(ofconn, b);
        }
    }
}

/* Private ofconn functions. */

static void
ofconn_create(struct ofservice *ofservice, struct rconn *rconn,
              const struct ofproto_controller *settings)
    OVS_EXCLUDED(ofproto_mutex)
{
    ovs_mutex_lock(&ofproto_mutex);

    struct ofconn *ofconn = xzalloc(sizeof *ofconn);

    ofconn->connmgr = ofservice->connmgr;
    ovs_list_push_back(&ofservice->connmgr->conns, &ofconn->connmgr_node);

    hmap_init(&ofconn->assembler);

    ofconn->ofservice = ofservice;
    ovs_list_push_back(&ofservice->conns, &ofconn->ofservice_node);

    ofconn->rconn = rconn;
    ofconn->type = settings->type;
    ofconn->band = settings->band;

    ofconn->role = OFPCR12_ROLE_EQUAL;
    ofconn_set_protocol(ofconn, OFPUTIL_P_NONE);
    ofconn->packet_in_format = OFPUTIL_PACKET_IN_STD;

    ofconn->packet_in_queue_size = settings->max_pktq_size;
    ofconn->packet_in_counter = rconn_packet_counter_create();
    ofconn->miss_send_len = (ofconn->type == OFCONN_PRIMARY
                             ? OFP_DEFAULT_MISS_SEND_LEN
                             : 0);
    ofconn->controller_id = 0;

    ofconn->reply_counter = rconn_packet_counter_create();

    ofconn->async_cfg = NULL;

    ofconn->n_add = ofconn->n_delete = ofconn->n_modify = 0;
    ofconn->first_op = ofconn->last_op = LLONG_MIN;
    ofconn->next_op_report = LLONG_MAX;
    ofconn->op_backoff = LLONG_MIN;

    hmap_init(&ofconn->monitors);
    ofconn->monitor_counter = rconn_packet_counter_create();

    ovs_list_init(&ofconn->updates);

    hmap_init(&ofconn->bundles);
    ofconn->next_bundle_expiry_check = time_msec() + BUNDLE_EXPIRY_INTERVAL;

    ofconn_set_rate_limit(ofconn, settings->rate_limit, settings->burst_limit);

    ovs_mutex_unlock(&ofproto_mutex);
}

static void
ofconn_destroy(struct ofconn *ofconn)
    OVS_REQUIRES(ofproto_mutex)
{
    if (!ofconn) {
        return;
    }

    ofconn_log_flow_mods(ofconn);

    ovs_list_remove(&ofconn->connmgr_node);
    ovs_list_remove(&ofconn->ofservice_node);

    if (ofconn->rconn != ofconn->ofservice->rconn) {
        rconn_destroy(ofconn->rconn);
    }

    /* Force clearing of want_packet_in_on_miss to keep the global count
     * accurate. */
    ofconn->controller_id = 1;
    update_want_packet_in_on_miss(ofconn);

    rconn_packet_counter_destroy(ofconn->packet_in_counter);
    for (int i = 0; i < N_SCHEDULERS; i++) {
        if (ofconn->schedulers[i]) {
            pinsched_destroy(ofconn->schedulers[i]);
        }
    }

    rconn_packet_counter_destroy(ofconn->reply_counter);

    free(ofconn->async_cfg);

    struct ofmonitor *monitor, *next_monitor;
    HMAP_FOR_EACH_SAFE (monitor, next_monitor, ofconn_node,
                        &ofconn->monitors) {
        ofmonitor_destroy(monitor);
    }
    hmap_destroy(&ofconn->monitors);
    rconn_packet_counter_destroy(ofconn->monitor_counter);

    ofpbuf_list_delete(&ofconn->updates); /* ...but it should be empty. */

    bundle_remove_all(ofconn);
    hmap_destroy(&ofconn->bundles);

    free(ofconn);
}

/* Reconfigures 'ofconn' to match 'c'. */
static void
ofconn_reconfigure(struct ofconn *ofconn, const struct ofproto_controller *c)
{
    rconn_set_max_backoff(ofconn->rconn, c->max_backoff);

    int probe_interval = c->probe_interval ? MAX(c->probe_interval, 5) : 0;
    rconn_set_probe_interval(ofconn->rconn, probe_interval);

    ofconn->band = c->band;
    ofconn->packet_in_queue_size = c->max_pktq_size;

    ofconn_set_rate_limit(ofconn, c->rate_limit, c->burst_limit);

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
                                   const struct ovs_list *msgs))
{
    struct connmgr *mgr = ofconn->connmgr;

    for (size_t i = 0; i < N_SCHEDULERS; i++) {
        struct ovs_list txq;

        pinsched_run(ofconn->schedulers[i], &txq);
        do_send_packet_ins(ofconn, &txq);
    }

    rconn_run(ofconn->rconn);

    /* Limit the number of iterations to avoid starving other tasks. */
    for (int i = 0; i < 50 && ofconn_may_recv(ofconn); i++) {
        struct ofpbuf *of_msg = rconn_recv(ofconn->rconn);
        if (!of_msg) {
            break;
        }

        if (mgr->fail_open) {
            fail_open_maybe_recover(mgr->fail_open);
        }

        struct ovs_list msgs;
        enum ofperr error = ofpmp_assembler_execute(&ofconn->assembler, of_msg,
                                                    &msgs, time_msec());
        if (error) {
            ofconn_send_error(ofconn, of_msg->data, error);
            ofpbuf_delete(of_msg);
        } else if (!ovs_list_is_empty(&msgs)) {
            handle_openflow(ofconn, &msgs);
            ofpbuf_list_delete(&msgs);
        }
    }

    long long int now = time_msec();

    if (now >= ofconn->next_bundle_expiry_check) {
        ofconn->next_bundle_expiry_check = now + BUNDLE_EXPIRY_INTERVAL;
        bundle_remove_expired(ofconn, now);
    }

    if (now >= ofconn->next_op_report) {
        ofconn_log_flow_mods(ofconn);
    }

    struct ofpbuf *error = ofpmp_assembler_run(&ofconn->assembler,
                                               time_msec());
    if (error) {
        ofconn_send(ofconn, error, NULL);
    }

    ovs_mutex_lock(&ofproto_mutex);
    if (rconn_is_reliable(ofconn->rconn)
        ? !rconn_is_connected(ofconn->rconn)
        : !rconn_is_alive(ofconn->rconn)) {
        ofconn_destroy(ofconn);
    }
    ovs_mutex_unlock(&ofproto_mutex);
}

static void
ofconn_wait(struct ofconn *ofconn)
{
    for (int i = 0; i < N_SCHEDULERS; i++) {
        pinsched_wait(ofconn->schedulers[i]);
    }
    rconn_run_wait(ofconn->rconn);
    if (ofconn_may_recv(ofconn)) {
        rconn_recv_wait(ofconn->rconn);
    }
    if (ofconn->next_op_report != LLONG_MAX) {
        poll_timer_wait_until(ofconn->next_op_report);
    }
    poll_timer_wait_until(ofpmp_assembler_wait(&ofconn->assembler));
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
                          enum ofputil_async_msg_type type,
                          unsigned int reason)
{
    ovs_assert(reason < 32);
    ovs_assert((unsigned int) type < OAM_N_TYPES);

    if (!rconn_is_connected(ofconn->rconn) || !ofconn_get_protocol(ofconn)) {
        return false;
    }

    /* Keep the following code in sync with the documentation in the
     * "Asynchronous Messages" section in 'topics/design' */

    if (ofconn->type == OFCONN_SERVICE && !ofconn->miss_send_len) {
        /* Service connections don't get asynchronous messages unless they have
         * explicitly asked for them by setting a nonzero miss send length. */
        return false;
    }

    struct ofputil_async_cfg ac = ofconn_get_async_config(ofconn);
    uint32_t *masks = (ofconn->role == OFPCR12_ROLE_SLAVE
                       ? ac.slave
                       : ac.master);
    return (masks[type] & (1u << reason)) != 0;
}

/* This function returns true to indicate that a packet_in message
 * for a "table-miss" should be sent to at least one controller.
 *
 * False otherwise. */
bool
connmgr_wants_packet_in_on_miss(struct connmgr *mgr)
{
    int count;

    atomic_read_relaxed(&mgr->want_packet_in_on_miss, &count);
    return count > 0;
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
    for (int i = 0; i < N_SCHEDULERS; i++) {
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

/* Sends an OFPT_PORT_STATUS message with 'new_pp' and 'reason' to appropriate
 * controllers managed by 'mgr'.  For messages caused by a controller
 * OFPT_PORT_MOD, specify 'source' as the controller connection that sent the
 * request; otherwise, specify 'source' as NULL.
 *
 * If 'reason' is OFPPR_MODIFY and 'old_pp' is nonnull, then messages are
 * suppressed in the case where the change would not be visible to a particular
 * controller.  For example, OpenFlow 1.0 does not have the OFPPS_LIVE flag, so
 * this would suppress a change solely to that flag from being sent to an
 * OpenFlow 1.0 controller. */
void
connmgr_send_port_status(struct connmgr *mgr, struct ofconn *source,
                         const struct ofputil_phy_port *old_pp,
                         const struct ofputil_phy_port *new_pp,
                         uint8_t reason)
{
    /* XXX Should limit the number of queued port status change messages. */
    struct ofputil_port_status new_ps = { reason, *new_pp };

    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        if (ofconn_receives_async_msg(ofconn, OAM_PORT_STATUS, reason)) {
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

            enum ofputil_protocol protocol = ofconn_get_protocol(ofconn);
            struct ofpbuf *msg = ofputil_encode_port_status(&new_ps, protocol);
            if (reason == OFPPR_MODIFY && old_pp) {
                struct ofputil_port_status old_ps = { reason, *old_pp };
                struct ofpbuf *old_msg = ofputil_encode_port_status(&old_ps,
                                                                    protocol);
                bool suppress = ofpbuf_equal(msg, old_msg);
                ofpbuf_delete(old_msg);

                if (suppress) {
                    ofpbuf_delete(msg);
                    continue;
                }
            }

            ofconn_send(ofconn, msg, NULL);
        }
    }
}

/* Sends an OFPT_REQUESTFORWARD message with 'request' and 'reason' to
 * appropriate controllers managed by 'mgr'.  For messages caused by a
 * controller OFPT_GROUP_MOD and OFPT_METER_MOD, specify 'source' as the
 * controller connection that sent the request; otherwise, specify 'source'
 * as NULL. */
void
connmgr_send_requestforward(struct connmgr *mgr, const struct ofconn *source,
                            const struct ofputil_requestforward *rf)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        /* METER_MOD only supported in OF13 and up. */
        if (rf->reason == OFPRFR_METER_MOD
            && rconn_get_version(ofconn->rconn) < OFP13_VERSION) {
            continue;
        }

        if (ofconn_receives_async_msg(ofconn, OAM_REQUESTFORWARD, rf->reason)
            && ofconn != source) {
            enum ofputil_protocol protocol = ofconn_get_protocol(ofconn);
            ofconn_send(ofconn, ofputil_encode_requestforward(rf, protocol),
                        NULL);
        }
    }
}

/* Sends an OFPT_FLOW_REMOVED or NXT_FLOW_REMOVED message based on 'fr' to
 * appropriate controllers managed by 'mgr'.
 *
 * This may be called from the RCU thread. */
void
connmgr_send_flow_removed(struct connmgr *mgr,
                          const struct ofputil_flow_removed *fr)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        if (ofconn_receives_async_msg(ofconn, OAM_FLOW_REMOVED, fr->reason)) {
            /* Account flow expirations as replies to OpenFlow requests.  That
             * works because preventing OpenFlow requests from being processed
             * also prevents new flows from being added (and expiring).  (It
             * also prevents processing OpenFlow requests that would not add
             * new flows, so it is imperfect.) */
            struct ofpbuf *msg = ofputil_encode_flow_removed(
                fr, ofconn_get_protocol(ofconn));
            ofconn_send_reply(ofconn, msg);
        }
    }
}

/* Sends an OFPT_TABLE_STATUS message with 'reason' to appropriate controllers
 * managed by 'mgr'. When the table state changes, the controller needs to be
 * informed with the OFPT_TABLE_STATUS message. The reason values
 * OFPTR_VACANCY_DOWN and OFPTR_VACANCY_UP identify a vacancy message. The
 * vacancy events are generated when the remaining space in the flow table
 * changes and crosses one of the vacancy thereshold specified by
 * OFPT_TABLE_MOD. */
void
connmgr_send_table_status(struct connmgr *mgr,
                          const struct ofputil_table_desc *td,
                          uint8_t reason)
{
    struct ofputil_table_status ts = {
        .reason = reason,
        .desc = *td
    };

    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        if (ofconn_receives_async_msg(ofconn, OAM_TABLE_STATUS, reason)) {
            struct ofpbuf *msg;

            msg = ofputil_encode_table_status(&ts,
                                              ofconn_get_protocol(ofconn));
            if (msg) {
                ofconn_send(ofconn, msg, NULL);
            }
        }
    }
}

/* Given 'pin', sends an OFPT_PACKET_IN message to each OpenFlow controller as
 * necessary according to their individual configurations. */
void
connmgr_send_async_msg(struct connmgr *mgr,
                       const struct ofproto_async_msg *am)
{
    struct ofconn *ofconn;

    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        enum ofputil_protocol protocol = ofconn_get_protocol(ofconn);
        if (protocol == OFPUTIL_P_NONE || !rconn_is_connected(ofconn->rconn)
            || ofconn->controller_id != am->controller_id
            || !ofconn_receives_async_msg(ofconn, am->oam,
                                          am->pin.up.base.reason)) {
            continue;
        }

        struct ofpbuf *msg = ofputil_encode_packet_in_private(
            &am->pin.up, protocol, ofconn->packet_in_format);

        struct ovs_list txq;
        bool is_miss = (am->pin.up.base.reason == OFPR_NO_MATCH ||
                        am->pin.up.base.reason == OFPR_EXPLICIT_MISS ||
                        am->pin.up.base.reason == OFPR_IMPLICIT_MISS);
        pinsched_send(ofconn->schedulers[is_miss],
                      am->pin.up.base.flow_metadata.flow.in_port.ofp_port,
                      msg, &txq);
        do_send_packet_ins(ofconn, &txq);
    }
}

static void
do_send_packet_ins(struct ofconn *ofconn, struct ovs_list *txq)
{
    struct ofpbuf *pin;

    LIST_FOR_EACH_POP (pin, list_node, txq) {
        if (rconn_send_with_limit(ofconn->rconn, pin,
                                  ofconn->packet_in_counter,
                                  ofconn->packet_in_queue_size) == EAGAIN) {
            static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(5, 5);

            VLOG_INFO_RL(&rll, "%s: dropping packet-in due to queue overflow",
                         rconn_get_name(ofconn->rconn));
        }
    }
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
    int max_probe_interval = 0;

    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        if (ofservice->type == OFCONN_PRIMARY) {
            int probe_interval = ofservice->s.probe_interval;
            max_probe_interval = MAX(max_probe_interval, probe_interval);
        }
    }
    return max_probe_interval;
}

/* Returns the number of seconds for which all of 'mgr's active, primary
 * controllers have been disconnected.  Returns 0 if 'mgr' has no active,
 * primary controllers. */
int
connmgr_failure_duration(const struct connmgr *mgr)
{
    int min_failure_duration = INT_MAX;

    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        if (ofservice->s.type == OFCONN_PRIMARY && ofservice->rconn) {
            int failure_duration = rconn_failure_duration(ofservice->rconn);
            min_failure_duration = MIN(min_failure_duration, failure_duration);
        }
    }

    return min_failure_duration != INT_MAX ? min_failure_duration : 0;
}

/* Returns true if at least one primary controller is connected (regardless of
 * whether those controllers are believed to have authenticated and accepted
 * this switch), false if none of them are connected. */
bool
connmgr_is_any_controller_connected(const struct connmgr *mgr)
{
    struct ofservice *ofservice;
    HMAP_FOR_EACH (ofservice, hmap_node, &mgr->services) {
        if (ofservice->s.type == OFCONN_PRIMARY
            && !ovs_list_is_empty(&ofservice->conns)) {
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

    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        if (ofconn->type == OFCONN_PRIMARY
            && rconn_is_admitted(ofconn->rconn)) {
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
    if (n != mgr->n_extra_remotes) {
        return true;
    }

    for (size_t i = 0; i < n; i++) {
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

        ofpbuf_init(&ofpacts, sizeof(struct ofpact_output));
        ofpact_put_OUTPUT(&ofpacts)->port = OFPP_NORMAL;

        match_init_catchall(&match);
        ofproto_add_flow(mgr->ofproto, &match, 0, ofpacts.data,
                                                  ofpacts.size);

        ofpbuf_uninit(&ofpacts);
    }
}

/* Returns the number of hidden rules created by the in-band and fail-open
 * implementations in table 0.  (Subtracting this count from the number of
 * rules in the table 0 classifier, as maintained in struct oftable, yields
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
static void
ofservice_create(struct connmgr *mgr, const char *target,
                 const struct ofproto_controller *c)
    OVS_REQUIRES(ofproto_mutex)
{
    struct pvconn *pvconn = NULL;
    struct rconn *rconn = NULL;
    if (!vconn_verify_name(target)) {
        char *name = ofconn_make_name(mgr, target);
        rconn = rconn_create(5, 8, c->dscp, c->allowed_versions);
        rconn_connect(rconn, target, name);
        free(name);
    } else if (!pvconn_verify_name(target)) {
        int error = pvconn_open(target, c->allowed_versions, c->dscp, &pvconn);
        if (error) {
            return;
        }
    } else {
        VLOG_WARN_RL(&rl, "%s: unsupported controller \"%s\"",
                     mgr->name, target);
        return;
    }

    struct ofservice *ofservice = xzalloc(sizeof *ofservice);
    hmap_insert(&mgr->services, &ofservice->hmap_node, hash_string(target, 0));
    ofservice->connmgr = mgr;
    ofservice->target = xstrdup(target);
    ovs_list_init(&ofservice->conns);
    ofservice->type = c->type;
    ofservice->rconn = rconn;
    ofservice->pvconn = pvconn;
    ofservice->s = *c;
    ofservice_reconfigure(ofservice, c);

    VLOG_INFO("%s: added %s controller \"%s\"",
              mgr->name, ofconn_type_to_string(ofservice->type), target);
}

static void
ofservice_close_all(struct ofservice *ofservice)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofconn *ofconn, *next;
    LIST_FOR_EACH_SAFE (ofconn, next, ofservice_node, &ofservice->conns) {
        ofconn_destroy(ofconn);
    }
}

static void
ofservice_destroy(struct ofservice *ofservice)
    OVS_REQUIRES(ofproto_mutex)
{
    if (!ofservice) {
        return;
    }

    ofservice_close_all(ofservice);

    hmap_remove(&ofservice->connmgr->services, &ofservice->hmap_node);
    free(ofservice->target);
    if (ofservice->pvconn) {
        pvconn_close(ofservice->pvconn);
    }
    if (ofservice->rconn) {
        rconn_destroy(ofservice->rconn);
    }
    free(ofservice);
}

static void
ofservice_run(struct ofservice *ofservice)
{
    if (ofservice->pvconn) {
        struct vconn *vconn;
        int retval = pvconn_accept(ofservice->pvconn, &vconn);
        if (!retval) {
            /* Passing default value for creation of the rconn */
            struct rconn *rconn = rconn_create(
                ofservice->s.probe_interval, ofservice->s.max_backoff,
                ofservice->s.dscp, ofservice->s.allowed_versions);
            char *name = ofconn_make_name(ofservice->connmgr,
                                          vconn_get_name(vconn));
            rconn_connect_unreliably(rconn, vconn, name);
            free(name);

            ofconn_create(ofservice, rconn, &ofservice->s);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", ovs_strerror(retval));
        }
    } else {
        rconn_run(ofservice->rconn);

        bool connected = rconn_is_connected(ofservice->rconn);
        bool has_ofconn = !ovs_list_is_empty(&ofservice->conns);
        if (connected && !has_ofconn) {
            ofconn_create(ofservice, ofservice->rconn, &ofservice->s);
        }
    }
}

static void
ofservice_wait(struct ofservice *ofservice)
{
    if (ofservice->pvconn) {
        pvconn_wait(ofservice->pvconn);
    }
}

static int
ofservice_reconfigure(struct ofservice *ofservice,
                      const struct ofproto_controller *settings)
    OVS_REQUIRES(ofproto_mutex)
{
    /* If the allowed OpenFlow versions change, a full cleanup is needed
     * for the ofservice and connections. */
    if (ofservice->s.allowed_versions != settings->allowed_versions) {
        return -EINVAL;
    }

    ofservice->s = *settings;

    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, ofservice_node, &ofservice->conns) {
        ofconn_reconfigure(ofconn, settings);
    }

    return 0;
}

/* Finds and returns the ofservice within 'mgr' that has the given
 * 'target', or a null pointer if none exists. */
static struct ofservice *
ofservice_lookup(struct connmgr *mgr, const char *target)
{
    struct ofservice *ofservice;

    HMAP_FOR_EACH_WITH_HASH (ofservice, hmap_node, hash_string(target, 0),
                             &mgr->services) {
        if (!strcmp(ofservice->target, target)) {
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
    *monitorp = NULL;

    struct ofmonitor *m = ofmonitor_lookup(ofconn, request->id);
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
    if (!mgr || rule_is_hidden(rule)) {
        return;
    }

    enum nx_flow_monitor_flags update;
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

    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        if (ofconn->monitor_paused) {
            /* Only send NXFME_DELETED notifications for flows that were added
             * before we paused. */
            if (event != NXFME_DELETED
                || rule->add_seqno > ofconn->monitor_paused) {
                continue;
            }
        }

        enum nx_flow_monitor_flags flags = 0;
        struct ofmonitor *m;
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
            if (ovs_list_is_empty(&ofconn->updates)) {
                ofputil_start_flow_update(&ofconn->updates);
                ofconn->sent_abbrev_update = false;
            }

            if (flags & NXFMF_OWN || ofconn != abbrev_ofconn
                || ofconn->monitor_paused) {
                struct ofputil_flow_update fu;

                fu.event = event;
                fu.reason = event == NXFME_DELETED ? reason : 0;
                fu.table_id = rule->table_id;
                fu.cookie = rule->flow_cookie;
                minimatch_expand(&rule->cr.match, &fu.match);
                fu.priority = rule->cr.priority;

                ovs_mutex_lock(&rule->mutex);
                fu.idle_timeout = rule->idle_timeout;
                fu.hard_timeout = rule->hard_timeout;
                ovs_mutex_unlock(&rule->mutex);

                if (flags & NXFMF_ACTIONS) {
                    const struct rule_actions *actions
                        = rule_get_actions(rule);
                    fu.ofpacts = actions->ofpacts;
                    fu.ofpacts_len = actions->ofpacts_len;
                } else {
                    fu.ofpacts = NULL;
                    fu.ofpacts_len = 0;
                }
                ofputil_append_flow_update(&fu, &ofconn->updates,
                                           ofproto_get_tun_tab(rule->ofproto));
            } else if (!ofconn->sent_abbrev_update) {
                struct ofputil_flow_update fu;

                fu.event = NXFME_ABBREV;
                fu.xid = abbrev_xid;
                ofputil_append_flow_update(&fu, &ofconn->updates,
                                           ofproto_get_tun_tab(rule->ofproto));

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

    if (!mgr) {
        return;
    }

    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        struct rconn_packet_counter *counter = ofconn->monitor_counter;

        struct ofpbuf *msg;
        LIST_FOR_EACH_POP (msg, list_node, &ofconn->updates) {
            ofconn_send(ofconn, msg, counter);
        }

        if (!ofconn->monitor_paused
            && rconn_packet_counter_n_bytes(counter) > 128 * 1024) {
            COVERAGE_INC(ofmonitor_pause);
            ofconn->monitor_paused = monitor_seqno++;
            struct ofpbuf *pause = ofpraw_alloc_xid(
                OFPRAW_NXT_FLOW_MONITOR_PAUSED, OFP10_VERSION, htonl(0), 0);
            ofconn_send(ofconn, pause, counter);
        }
    }
}

static void
ofmonitor_resume(struct ofconn *ofconn)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_collection rules;
    rule_collection_init(&rules);

    struct ofmonitor *m;
    HMAP_FOR_EACH (m, ofconn_node, &ofconn->monitors) {
        ofmonitor_collect_resume_rules(m, ofconn->monitor_paused, &rules);
    }

    struct ovs_list msgs = OVS_LIST_INITIALIZER(&msgs);
    ofmonitor_compose_refresh_updates(&rules, &msgs);

    struct ofpbuf *resumed = ofpraw_alloc_xid(OFPRAW_NXT_FLOW_MONITOR_RESUMED,
                                              OFP10_VERSION, htonl(0), 0);
    ovs_list_push_back(&msgs, &resumed->list_node);
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
    ovs_mutex_lock(&ofproto_mutex);
    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
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
    ovs_mutex_lock(&ofproto_mutex);
    struct ofconn *ofconn;
    LIST_FOR_EACH (ofconn, connmgr_node, &mgr->conns) {
        if (ofmonitor_may_resume(ofconn)) {
            poll_immediate_wake();
        }
    }
    ovs_mutex_unlock(&ofproto_mutex);
}

void
ofproto_async_msg_free(struct ofproto_async_msg *am)
{
    free(am->pin.up.base.packet);
    free(am->pin.up.base.userdata);
    free(am->pin.up.stack);
    free(am->pin.up.actions);
    free(am->pin.up.action_set);
    free(am);
}
