/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
 * limitations under the License.  */

#include <config.h>
#include "ofproto-dpif-upcall.h"

#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>

#include "connmgr.h"
#include "coverage.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "fail-open.h"
#include "guarded-list.h"
#include "latch.h"
#include "list.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "ofproto-dpif-ipfix.h"
#include "ofproto-dpif-sflow.h"
#include "ofproto-dpif-xlate.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "poll-loop.h"
#include "seq.h"
#include "unixctl.h"
#include "vlog.h"

#define MAX_QUEUE_LENGTH 512
#define UPCALL_MAX_BATCH 64
#define REVALIDATE_MAX_BATCH 50

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_upcall);

COVERAGE_DEFINE(dumped_duplicate_flow);
COVERAGE_DEFINE(dumped_new_flow);
COVERAGE_DEFINE(revalidate_missed_dp_flow);

/* A thread that reads upcalls from dpif, forwards each upcall's packet,
 * and possibly sets up a kernel flow as a cache. */
struct handler {
    struct udpif *udpif;               /* Parent udpif. */
    pthread_t thread;                  /* Thread ID. */
    uint32_t handler_id;               /* Handler id. */
};

/* A thread that processes datapath flows, updates OpenFlow statistics, and
 * updates or removes them if necessary. */
struct revalidator {
    struct udpif *udpif;               /* Parent udpif. */
    pthread_t thread;                  /* Thread ID. */
    unsigned int id;                   /* ovsthread_id_self(). */
    struct hmap *ukeys;                /* Points into udpif->ukeys for this
                                          revalidator. Used for GC phase. */
};

/* An upcall handler for ofproto_dpif.
 *
 * udpif keeps records of two kind of logically separate units:
 *
 * upcall handling
 * ---------------
 *
 *    - An array of 'struct handler's for upcall handling and flow
 *      installation.
 *
 * flow revalidation
 * -----------------
 *
 *    - Revalidation threads which read the datapath flow table and maintains
 *      them.
 */
struct udpif {
    struct list list_node;             /* In all_udpifs list. */

    struct dpif *dpif;                 /* Datapath handle. */
    struct dpif_backer *backer;        /* Opaque dpif_backer pointer. */

    uint32_t secret;                   /* Random seed for upcall hash. */

    struct handler *handlers;          /* Upcall handlers. */
    size_t n_handlers;

    struct revalidator *revalidators;  /* Flow revalidators. */
    size_t n_revalidators;

    struct latch exit_latch;           /* Tells child threads to exit. */

    /* Revalidation. */
    struct seq *reval_seq;             /* Incremented to force revalidation. */
    bool need_revalidate;              /* As indicated by 'reval_seq'. */
    bool reval_exit;                   /* Set by leader on 'exit_latch. */
    struct ovs_barrier reval_barrier;  /* Barrier used by revalidators. */
    struct dpif_flow_dump *dump;       /* DPIF flow dump state. */
    long long int dump_duration;       /* Duration of the last flow dump. */
    struct seq *dump_seq;              /* Increments each dump iteration. */

    /* There are 'n_revalidators' ukey hmaps. Each revalidator retains a
     * reference to one of these for garbage collection.
     *
     * During the flow dump phase, revalidators insert into these with a random
     * distribution. During the garbage collection phase, each revalidator
     * takes care of garbage collecting one of these hmaps. */
    struct {
        struct ovs_mutex mutex;        /* Guards the following. */
        struct hmap hmap OVS_GUARDED;  /* Datapath flow keys. */
    } *ukeys;

    /* Datapath flow statistics. */
    unsigned int max_n_flows;
    unsigned int avg_n_flows;

    /* Following fields are accessed and modified by different threads. */
    atomic_uint flow_limit;            /* Datapath flow hard limit. */

    /* n_flows_mutex prevents multiple threads updating these concurrently. */
    atomic_uint n_flows;               /* Number of flows in the datapath. */
    atomic_llong n_flows_timestamp;    /* Last time n_flows was updated. */
    struct ovs_mutex n_flows_mutex;

    /* Following fields are accessed and modified only from the main thread. */
    struct unixctl_conn **conns;       /* Connections waiting on dump_seq. */
    uint64_t conn_seq;                 /* Corresponds to 'dump_seq' when
                                          conns[n_conns-1] was stored. */
    size_t n_conns;                    /* Number of connections waiting. */
};

enum upcall_type {
    BAD_UPCALL,                 /* Some kind of bug somewhere. */
    MISS_UPCALL,                /* A flow miss.  */
    SFLOW_UPCALL,               /* sFlow sample. */
    FLOW_SAMPLE_UPCALL,         /* Per-flow sampling. */
    IPFIX_UPCALL                /* Per-bridge sampling. */
};

struct upcall {
    struct ofproto_dpif *ofproto;  /* Parent ofproto. */

    /* The flow and packet are only required to be constant when using
     * dpif-netdev.  If a modification is absolutely necessary, a const cast
     * may be used with other datapaths. */
    const struct flow *flow;       /* Parsed representation of the packet. */
    const struct ofpbuf *packet;   /* Packet associated with this upcall. */
    ofp_port_t in_port;            /* OpenFlow in port, or OFPP_NONE. */

    enum dpif_upcall_type type;    /* Datapath type of the upcall. */
    const struct nlattr *userdata; /* Userdata for DPIF_UC_ACTION Upcalls. */

    bool xout_initialized;         /* True if 'xout' must be uninitialized. */
    struct xlate_out xout;         /* Result of xlate_actions(). */
    struct ofpbuf put_actions;     /* Actions 'put' in the fastapath. */

    struct dpif_ipfix *ipfix;      /* IPFIX pointer or NULL. */
    struct dpif_sflow *sflow;      /* SFlow pointer or NULL. */

    bool vsp_adjusted;             /* 'packet' and 'flow' were adjusted for
                                      VLAN splinters if true. */

    /* Not used by the upcall callback interface. */
    const struct nlattr *key;      /* Datapath flow key. */
    size_t key_len;                /* Datapath flow key length. */
    const struct nlattr *out_tun_key;  /* Datapath output tunnel key. */
};

/* 'udpif_key's are responsible for tracking the little bit of state udpif
 * needs to do flow expiration which can't be pulled directly from the
 * datapath.  They may be created or maintained by any revalidator during
 * the dump phase, but are owned by a single revalidator, and are destroyed
 * by that revalidator during the garbage-collection phase.
 *
 * While some elements of a udpif_key are protected by a mutex, the ukey itself
 * is not.  Therefore it is not safe to destroy a udpif_key except when all
 * revalidators are in garbage collection phase, or they aren't running. */
struct udpif_key {
    struct hmap_node hmap_node;     /* In parent revalidator 'ukeys' map. */

    /* These elements are read only once created, and therefore aren't
     * protected by a mutex. */
    const struct nlattr *key;      /* Datapath flow key. */
    size_t key_len;                /* Length of 'key'. */

    struct ovs_mutex mutex;                   /* Guards the following. */
    struct dpif_flow_stats stats OVS_GUARDED; /* Last known stats.*/
    long long int created OVS_GUARDED;        /* Estimate of creation time. */
    uint64_t dump_seq OVS_GUARDED;            /* Tracks udpif->dump_seq. */
    bool flow_exists OVS_GUARDED;             /* Ensures flows are only deleted
                                                 once. */

    struct xlate_cache *xcache OVS_GUARDED;   /* Cache for xlate entries that
                                               * are affected by this ukey.
                                               * Used for stats and learning.*/
    union {
        struct odputil_keybuf key_buf;        /* Memory for 'key'. */
        struct nlattr key_buf_nla;
    };
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct list all_udpifs = LIST_INITIALIZER(&all_udpifs);

static size_t recv_upcalls(struct handler *);
static int process_upcall(struct udpif *, struct upcall *,
                          struct ofpbuf *odp_actions);
static void handle_upcalls(struct udpif *, struct upcall *, size_t n_upcalls);
static void udpif_stop_threads(struct udpif *);
static void udpif_start_threads(struct udpif *, size_t n_handlers,
                                size_t n_revalidators);
static void *udpif_upcall_handler(void *);
static void *udpif_revalidator(void *);
static unsigned long udpif_get_n_flows(struct udpif *);
static void revalidate(struct revalidator *);
static void revalidator_sweep(struct revalidator *);
static void revalidator_purge(struct revalidator *);
static void upcall_unixctl_show(struct unixctl_conn *conn, int argc,
                                const char *argv[], void *aux);
static void upcall_unixctl_disable_megaflows(struct unixctl_conn *, int argc,
                                             const char *argv[], void *aux);
static void upcall_unixctl_enable_megaflows(struct unixctl_conn *, int argc,
                                            const char *argv[], void *aux);
static void upcall_unixctl_set_flow_limit(struct unixctl_conn *conn, int argc,
                                            const char *argv[], void *aux);
static void upcall_unixctl_dump_wait(struct unixctl_conn *conn, int argc,
                                     const char *argv[], void *aux);
static void upcall_unixctl_purge(struct unixctl_conn *conn, int argc,
                                 const char *argv[], void *aux);

static struct udpif_key *ukey_create(const struct nlattr *key, size_t key_len,
                                     long long int used);
static struct udpif_key *ukey_lookup(struct udpif *udpif,
                                     const struct nlattr *key, size_t key_len,
                                     uint32_t hash);
static bool ukey_acquire(struct udpif *udpif, const struct nlattr *key,
                         size_t key_len, long long int used,
                         struct udpif_key **result);
static void ukey_delete(struct revalidator *, struct udpif_key *);
static enum upcall_type classify_upcall(enum dpif_upcall_type type,
                                        const struct nlattr *userdata);

static int upcall_receive(struct upcall *, const struct dpif_backer *,
                          const struct ofpbuf *packet, enum dpif_upcall_type,
                          const struct nlattr *userdata, const struct flow *);
static void upcall_uninit(struct upcall *);

static upcall_callback upcall_cb;

static atomic_bool enable_megaflows = ATOMIC_VAR_INIT(true);

struct udpif *
udpif_create(struct dpif_backer *backer, struct dpif *dpif)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct udpif *udpif = xzalloc(sizeof *udpif);

    if (ovsthread_once_start(&once)) {
        unixctl_command_register("upcall/show", "", 0, 0, upcall_unixctl_show,
                                 NULL);
        unixctl_command_register("upcall/disable-megaflows", "", 0, 0,
                                 upcall_unixctl_disable_megaflows, NULL);
        unixctl_command_register("upcall/enable-megaflows", "", 0, 0,
                                 upcall_unixctl_enable_megaflows, NULL);
        unixctl_command_register("upcall/set-flow-limit", "", 1, 1,
                                 upcall_unixctl_set_flow_limit, NULL);
        unixctl_command_register("revalidator/wait", "", 0, 0,
                                 upcall_unixctl_dump_wait, NULL);
        unixctl_command_register("revalidator/purge", "", 0, 0,
                                 upcall_unixctl_purge, NULL);
        ovsthread_once_done(&once);
    }

    udpif->dpif = dpif;
    udpif->backer = backer;
    atomic_init(&udpif->flow_limit, MIN(ofproto_flow_limit, 10000));
    udpif->secret = random_uint32();
    udpif->reval_seq = seq_create();
    udpif->dump_seq = seq_create();
    latch_init(&udpif->exit_latch);
    list_push_back(&all_udpifs, &udpif->list_node);
    atomic_init(&udpif->n_flows, 0);
    atomic_init(&udpif->n_flows_timestamp, LLONG_MIN);
    ovs_mutex_init(&udpif->n_flows_mutex);

    dpif_register_upcall_cb(dpif, upcall_cb, udpif);

    return udpif;
}

void
udpif_run(struct udpif *udpif)
{
    if (udpif->conns && udpif->conn_seq != seq_read(udpif->dump_seq)) {
        int i;

        for (i = 0; i < udpif->n_conns; i++) {
            unixctl_command_reply(udpif->conns[i], NULL);
        }
        free(udpif->conns);
        udpif->conns = NULL;
        udpif->n_conns = 0;
    }
}

void
udpif_destroy(struct udpif *udpif)
{
    udpif_stop_threads(udpif);

    list_remove(&udpif->list_node);
    latch_destroy(&udpif->exit_latch);
    seq_destroy(udpif->reval_seq);
    seq_destroy(udpif->dump_seq);
    ovs_mutex_destroy(&udpif->n_flows_mutex);
    free(udpif);
}

/* Stops the handler and revalidator threads, must be enclosed in
 * ovsrcu quiescent state unless when destroying udpif. */
static void
udpif_stop_threads(struct udpif *udpif)
{
    if (udpif && (udpif->n_handlers != 0 || udpif->n_revalidators != 0)) {
        size_t i;

        latch_set(&udpif->exit_latch);

        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            xpthread_join(handler->thread, NULL);
        }

        for (i = 0; i < udpif->n_revalidators; i++) {
            xpthread_join(udpif->revalidators[i].thread, NULL);
        }

        dpif_disable_upcall(udpif->dpif);

        for (i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            /* Delete ukeys, and delete all flows from the datapath to prevent
             * double-counting stats. */
            revalidator_purge(revalidator);

            hmap_destroy(&udpif->ukeys[i].hmap);
            ovs_mutex_destroy(&udpif->ukeys[i].mutex);
        }

        latch_poll(&udpif->exit_latch);

        ovs_barrier_destroy(&udpif->reval_barrier);

        free(udpif->revalidators);
        udpif->revalidators = NULL;
        udpif->n_revalidators = 0;

        free(udpif->handlers);
        udpif->handlers = NULL;
        udpif->n_handlers = 0;

        free(udpif->ukeys);
        udpif->ukeys = NULL;
    }
}

/* Starts the handler and revalidator threads, must be enclosed in
 * ovsrcu quiescent state. */
static void
udpif_start_threads(struct udpif *udpif, size_t n_handlers,
                    size_t n_revalidators)
{
    if (udpif && n_handlers && n_revalidators) {
        size_t i;

        udpif->n_handlers = n_handlers;
        udpif->n_revalidators = n_revalidators;

        udpif->handlers = xzalloc(udpif->n_handlers * sizeof *udpif->handlers);
        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            handler->udpif = udpif;
            handler->handler_id = i;
            handler->thread = ovs_thread_create(
                "handler", udpif_upcall_handler, handler);
        }

        dpif_enable_upcall(udpif->dpif);

        ovs_barrier_init(&udpif->reval_barrier, udpif->n_revalidators);
        udpif->reval_exit = false;
        udpif->revalidators = xzalloc(udpif->n_revalidators
                                      * sizeof *udpif->revalidators);
        udpif->ukeys = xmalloc(sizeof *udpif->ukeys * n_revalidators);
        for (i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            revalidator->udpif = udpif;
            hmap_init(&udpif->ukeys[i].hmap);
            ovs_mutex_init(&udpif->ukeys[i].mutex);
            revalidator->ukeys = &udpif->ukeys[i].hmap;
            revalidator->thread = ovs_thread_create(
                "revalidator", udpif_revalidator, revalidator);
        }
    }
}

/* Tells 'udpif' how many threads it should use to handle upcalls.
 * 'n_handlers' and 'n_revalidators' can never be zero.  'udpif''s
 * datapath handle must have packet reception enabled before starting
 * threads. */
void
udpif_set_threads(struct udpif *udpif, size_t n_handlers,
                  size_t n_revalidators)
{
    ovs_assert(udpif);
    ovs_assert(n_handlers && n_revalidators);

    ovsrcu_quiesce_start();
    if (udpif->n_handlers != n_handlers
        || udpif->n_revalidators != n_revalidators) {
        udpif_stop_threads(udpif);
    }

    if (!udpif->handlers && !udpif->revalidators) {
        int error;

        error = dpif_handlers_set(udpif->dpif, n_handlers);
        if (error) {
            VLOG_ERR("failed to configure handlers in dpif %s: %s",
                     dpif_name(udpif->dpif), ovs_strerror(error));
            return;
        }

        udpif_start_threads(udpif, n_handlers, n_revalidators);
    }
    ovsrcu_quiesce_end();
}

/* Waits for all ongoing upcall translations to complete.  This ensures that
 * there are no transient references to any removed ofprotos (or other
 * objects).  In particular, this should be called after an ofproto is removed
 * (e.g. via xlate_remove_ofproto()) but before it is destroyed. */
void
udpif_synchronize(struct udpif *udpif)
{
    /* This is stronger than necessary.  It would be sufficient to ensure
     * (somehow) that each handler and revalidator thread had passed through
     * its main loop once. */
    size_t n_handlers = udpif->n_handlers;
    size_t n_revalidators = udpif->n_revalidators;

    ovsrcu_quiesce_start();
    udpif_stop_threads(udpif);
    udpif_start_threads(udpif, n_handlers, n_revalidators);
    ovsrcu_quiesce_end();
}

/* Notifies 'udpif' that something changed which may render previous
 * xlate_actions() results invalid. */
void
udpif_revalidate(struct udpif *udpif)
{
    seq_change(udpif->reval_seq);
}

/* Returns a seq which increments every time 'udpif' pulls stats from the
 * datapath.  Callers can use this to get a sense of when might be a good time
 * to do periodic work which relies on relatively up to date statistics. */
struct seq *
udpif_dump_seq(struct udpif *udpif)
{
    return udpif->dump_seq;
}

void
udpif_get_memory_usage(struct udpif *udpif, struct simap *usage)
{
    size_t i;

    simap_increase(usage, "handlers", udpif->n_handlers);

    simap_increase(usage, "revalidators", udpif->n_revalidators);
    for (i = 0; i < udpif->n_revalidators; i++) {
        ovs_mutex_lock(&udpif->ukeys[i].mutex);
        simap_increase(usage, "udpif keys", hmap_count(&udpif->ukeys[i].hmap));
        ovs_mutex_unlock(&udpif->ukeys[i].mutex);
    }
}

/* Remove flows from a single datapath. */
void
udpif_flush(struct udpif *udpif)
{
    size_t n_handlers, n_revalidators;

    n_handlers = udpif->n_handlers;
    n_revalidators = udpif->n_revalidators;

    ovsrcu_quiesce_start();

    udpif_stop_threads(udpif);
    dpif_flow_flush(udpif->dpif);
    udpif_start_threads(udpif, n_handlers, n_revalidators);

    ovsrcu_quiesce_end();
}

/* Removes all flows from all datapaths. */
static void
udpif_flush_all_datapaths(void)
{
    struct udpif *udpif;

    LIST_FOR_EACH (udpif, list_node, &all_udpifs) {
        udpif_flush(udpif);
    }
}


static unsigned long
udpif_get_n_flows(struct udpif *udpif)
{
    long long int time, now;
    unsigned long flow_count;

    now = time_msec();
    atomic_read_relaxed(&udpif->n_flows_timestamp, &time);
    if (time < now - 100 && !ovs_mutex_trylock(&udpif->n_flows_mutex)) {
        struct dpif_dp_stats stats;

        atomic_store_relaxed(&udpif->n_flows_timestamp, now);
        dpif_get_dp_stats(udpif->dpif, &stats);
        flow_count = stats.n_flows;
        atomic_store_relaxed(&udpif->n_flows, flow_count);
        ovs_mutex_unlock(&udpif->n_flows_mutex);
    } else {
        atomic_read_relaxed(&udpif->n_flows, &flow_count);
    }
    return flow_count;
}

/* The upcall handler thread tries to read a batch of UPCALL_MAX_BATCH
 * upcalls from dpif, processes the batch and installs corresponding flows
 * in dpif. */
static void *
udpif_upcall_handler(void *arg)
{
    struct handler *handler = arg;
    struct udpif *udpif = handler->udpif;

    while (!latch_is_set(&handler->udpif->exit_latch)) {
        if (!recv_upcalls(handler)) {
            dpif_recv_wait(udpif->dpif, handler->handler_id);
            latch_wait(&udpif->exit_latch);
            poll_block();
        }
        coverage_clear();
    }

    return NULL;
}

static size_t
recv_upcalls(struct handler *handler)
{
    struct udpif *udpif = handler->udpif;
    uint64_t recv_stubs[UPCALL_MAX_BATCH][512 / 8];
    struct ofpbuf recv_bufs[UPCALL_MAX_BATCH];
    struct dpif_upcall dupcalls[UPCALL_MAX_BATCH];
    struct upcall upcalls[UPCALL_MAX_BATCH];
    struct flow flows[UPCALL_MAX_BATCH];
    size_t n_upcalls, i;

    n_upcalls = 0;
    while (n_upcalls < UPCALL_MAX_BATCH) {
        struct ofpbuf *recv_buf = &recv_bufs[n_upcalls];
        struct dpif_upcall *dupcall = &dupcalls[n_upcalls];
        struct upcall *upcall = &upcalls[n_upcalls];
        struct flow *flow = &flows[n_upcalls];
        struct pkt_metadata md;
        int error;

        ofpbuf_use_stub(recv_buf, recv_stubs[n_upcalls],
                        sizeof recv_stubs[n_upcalls]);
        if (dpif_recv(udpif->dpif, handler->handler_id, dupcall, recv_buf)) {
            ofpbuf_uninit(recv_buf);
            break;
        }

        if (odp_flow_key_to_flow(dupcall->key, dupcall->key_len, flow)
            == ODP_FIT_ERROR) {
            goto free_dupcall;
        }

        error = upcall_receive(upcall, udpif->backer, &dupcall->packet,
                               dupcall->type, dupcall->userdata, flow);
        if (error) {
            if (error == ENODEV) {
                /* Received packet on datapath port for which we couldn't
                 * associate an ofproto.  This can happen if a port is removed
                 * while traffic is being received.  Print a rate-limited
                 * message in case it happens frequently. */
                dpif_flow_put(udpif->dpif, DPIF_FP_CREATE, dupcall->key,
                              dupcall->key_len, NULL, 0, NULL, 0, NULL);
                VLOG_INFO_RL(&rl, "received packet on unassociated datapath "
                             "port %"PRIu32, flow->in_port.odp_port);
            }
            goto free_dupcall;
        }

        upcall->key = dupcall->key;
        upcall->key_len = dupcall->key_len;

        upcall->out_tun_key = dupcall->out_tun_key;

        if (vsp_adjust_flow(upcall->ofproto, flow, &dupcall->packet)) {
            upcall->vsp_adjusted = true;
        }

        md = pkt_metadata_from_flow(flow);
        flow_extract(&dupcall->packet, &md, flow);

        error = process_upcall(udpif, upcall, NULL);
        if (error) {
            goto cleanup;
        }

        n_upcalls++;
        continue;

cleanup:
        upcall_uninit(upcall);
free_dupcall:
        ofpbuf_uninit(&dupcall->packet);
        ofpbuf_uninit(recv_buf);
    }

    if (n_upcalls) {
        handle_upcalls(handler->udpif, upcalls, n_upcalls);
        for (i = 0; i < n_upcalls; i++) {
            ofpbuf_uninit(&dupcalls[i].packet);
            ofpbuf_uninit(&recv_bufs[i]);
            upcall_uninit(&upcalls[i]);
        }
    }

    return n_upcalls;
}

static void *
udpif_revalidator(void *arg)
{
    /* Used by all revalidators. */
    struct revalidator *revalidator = arg;
    struct udpif *udpif = revalidator->udpif;
    bool leader = revalidator == &udpif->revalidators[0];

    /* Used only by the leader. */
    long long int start_time = 0;
    uint64_t last_reval_seq = 0;
    size_t n_flows = 0;

    revalidator->id = ovsthread_id_self();
    for (;;) {
        if (leader) {
            uint64_t reval_seq;

            reval_seq = seq_read(udpif->reval_seq);
            udpif->need_revalidate = last_reval_seq != reval_seq;
            last_reval_seq = reval_seq;

            n_flows = udpif_get_n_flows(udpif);
            udpif->max_n_flows = MAX(n_flows, udpif->max_n_flows);
            udpif->avg_n_flows = (udpif->avg_n_flows + n_flows) / 2;

            /* Only the leader checks the exit latch to prevent a race where
             * some threads think it's true and exit and others think it's
             * false and block indefinitely on the reval_barrier */
            udpif->reval_exit = latch_is_set(&udpif->exit_latch);

            start_time = time_msec();
            if (!udpif->reval_exit) {
                udpif->dump = dpif_flow_dump_create(udpif->dpif);
            }
        }

        /* Wait for the leader to start the flow dump. */
        ovs_barrier_block(&udpif->reval_barrier);
        if (udpif->reval_exit) {
            break;
        }
        revalidate(revalidator);

        /* Wait for all flows to have been dumped before we garbage collect. */
        ovs_barrier_block(&udpif->reval_barrier);
        revalidator_sweep(revalidator);

        /* Wait for all revalidators to finish garbage collection. */
        ovs_barrier_block(&udpif->reval_barrier);

        if (leader) {
            unsigned int flow_limit;
            long long int duration;

            atomic_read_relaxed(&udpif->flow_limit, &flow_limit);

            dpif_flow_dump_destroy(udpif->dump);
            seq_change(udpif->dump_seq);

            duration = MAX(time_msec() - start_time, 1);
            udpif->dump_duration = duration;
            if (duration > 2000) {
                flow_limit /= duration / 1000;
            } else if (duration > 1300) {
                flow_limit = flow_limit * 3 / 4;
            } else if (duration < 1000 && n_flows > 2000
                       && flow_limit < n_flows * 1000 / duration) {
                flow_limit += 1000;
            }
            flow_limit = MIN(ofproto_flow_limit, MAX(flow_limit, 1000));
            atomic_store_relaxed(&udpif->flow_limit, flow_limit);

            if (duration > 2000) {
                VLOG_INFO("Spent an unreasonably long %lldms dumping flows",
                          duration);
            }

            poll_timer_wait_until(start_time + MIN(ofproto_max_idle, 500));
            seq_wait(udpif->reval_seq, last_reval_seq);
            latch_wait(&udpif->exit_latch);
            poll_block();
        }
    }

    return NULL;
}

static enum upcall_type
classify_upcall(enum dpif_upcall_type type, const struct nlattr *userdata)
{
    union user_action_cookie cookie;
    size_t userdata_len;

    /* First look at the upcall type. */
    switch (type) {
    case DPIF_UC_ACTION:
        break;

    case DPIF_UC_MISS:
        return MISS_UPCALL;

    case DPIF_N_UC_TYPES:
    default:
        VLOG_WARN_RL(&rl, "upcall has unexpected type %"PRIu32, type);
        return BAD_UPCALL;
    }

    /* "action" upcalls need a closer look. */
    if (!userdata) {
        VLOG_WARN_RL(&rl, "action upcall missing cookie");
        return BAD_UPCALL;
    }
    userdata_len = nl_attr_get_size(userdata);
    if (userdata_len < sizeof cookie.type
        || userdata_len > sizeof cookie) {
        VLOG_WARN_RL(&rl, "action upcall cookie has unexpected size %"PRIuSIZE,
                     userdata_len);
        return BAD_UPCALL;
    }
    memset(&cookie, 0, sizeof cookie);
    memcpy(&cookie, nl_attr_get(userdata), userdata_len);
    if (userdata_len == MAX(8, sizeof cookie.sflow)
        && cookie.type == USER_ACTION_COOKIE_SFLOW) {
        return SFLOW_UPCALL;
    } else if (userdata_len == MAX(8, sizeof cookie.slow_path)
               && cookie.type == USER_ACTION_COOKIE_SLOW_PATH) {
        return MISS_UPCALL;
    } else if (userdata_len == MAX(8, sizeof cookie.flow_sample)
               && cookie.type == USER_ACTION_COOKIE_FLOW_SAMPLE) {
        return FLOW_SAMPLE_UPCALL;
    } else if (userdata_len == MAX(8, sizeof cookie.ipfix)
               && cookie.type == USER_ACTION_COOKIE_IPFIX) {
        return IPFIX_UPCALL;
    } else {
        VLOG_WARN_RL(&rl, "invalid user cookie of type %"PRIu16
                     " and size %"PRIuSIZE, cookie.type, userdata_len);
        return BAD_UPCALL;
    }
}

/* Calculates slow path actions for 'xout'.  'buf' must statically be
 * initialized with at least 128 bytes of space. */
static void
compose_slow_path(struct udpif *udpif, struct xlate_out *xout,
                  const struct flow *flow, odp_port_t odp_in_port,
                  struct ofpbuf *buf)
{
    union user_action_cookie cookie;
    odp_port_t port;
    uint32_t pid;

    cookie.type = USER_ACTION_COOKIE_SLOW_PATH;
    cookie.slow_path.unused = 0;
    cookie.slow_path.reason = xout->slow;

    port = xout->slow & (SLOW_CFM | SLOW_BFD | SLOW_LACP | SLOW_STP)
        ? ODPP_NONE
        : odp_in_port;
    pid = dpif_port_get_pid(udpif->dpif, port, flow_hash_5tuple(flow, 0));
    odp_put_userspace_action(pid, &cookie, sizeof cookie.slow_path, ODPP_NONE,
                             buf);
}

/* If there is no error, the upcall must be destroyed with upcall_uninit()
 * before quiescing, as the referred objects are guaranteed to exist only
 * until the calling thread quiesces.  Otherwise, do not call upcall_uninit()
 * since the 'upcall->put_actions' remains uninitialized. */
static int
upcall_receive(struct upcall *upcall, const struct dpif_backer *backer,
               const struct ofpbuf *packet, enum dpif_upcall_type type,
               const struct nlattr *userdata, const struct flow *flow)
{
    int error;

    error = xlate_lookup(backer, flow, &upcall->ofproto, &upcall->ipfix,
                         &upcall->sflow, NULL, &upcall->in_port);
    if (error) {
        return error;
    }

    upcall->flow = flow;
    upcall->packet = packet;
    upcall->type = type;
    upcall->userdata = userdata;
    ofpbuf_init(&upcall->put_actions, 0);

    upcall->xout_initialized = false;
    upcall->vsp_adjusted = false;

    upcall->key = NULL;
    upcall->key_len = 0;

    upcall->out_tun_key = NULL;

    return 0;
}

static void
upcall_xlate(struct udpif *udpif, struct upcall *upcall,
             struct ofpbuf *odp_actions)
{
    struct dpif_flow_stats stats;
    struct xlate_in xin;

    stats.n_packets = 1;
    stats.n_bytes = ofpbuf_size(upcall->packet);
    stats.used = time_msec();
    stats.tcp_flags = ntohs(upcall->flow->tcp_flags);

    xlate_in_init(&xin, upcall->ofproto, upcall->flow, upcall->in_port, NULL,
                  stats.tcp_flags, upcall->packet);
    xin.odp_actions = odp_actions;

    if (upcall->type == DPIF_UC_MISS) {
        xin.resubmit_stats = &stats;
    } else {
        /* For non-miss upcalls, there's a flow in the datapath which this
         * packet was accounted to.  Presumably the revalidators will deal
         * with pushing its stats eventually. */
    }

    xlate_actions(&xin, &upcall->xout);
    upcall->xout_initialized = true;

    /* Special case for fail-open mode.
     *
     * If we are in fail-open mode, but we are connected to a controller too,
     * then we should send the packet up to the controller in the hope that it
     * will try to set up a flow and thereby allow us to exit fail-open.
     *
     * See the top-level comment in fail-open.c for more information.
     *
     * Copy packets before they are modified by execution. */
    if (upcall->xout.fail_open) {
        const struct ofpbuf *packet = upcall->packet;
        struct ofproto_packet_in *pin;

        pin = xmalloc(sizeof *pin);
        pin->up.packet = xmemdup(ofpbuf_data(packet), ofpbuf_size(packet));
        pin->up.packet_len = ofpbuf_size(packet);
        pin->up.reason = OFPR_NO_MATCH;
        pin->up.table_id = 0;
        pin->up.cookie = OVS_BE64_MAX;
        flow_get_metadata(upcall->flow, &pin->up.fmd);
        pin->send_len = 0; /* Not used for flow table misses. */
        pin->miss_type = OFPROTO_PACKET_IN_NO_MISS;
        ofproto_dpif_send_packet_in(upcall->ofproto, pin);
    }

    if (!upcall->xout.slow) {
        ofpbuf_use_const(&upcall->put_actions,
                         ofpbuf_data(upcall->xout.odp_actions),
                         ofpbuf_size(upcall->xout.odp_actions));
    } else {
        ofpbuf_init(&upcall->put_actions, 0);
        compose_slow_path(udpif, &upcall->xout, upcall->flow,
                          upcall->flow->in_port.odp_port,
                          &upcall->put_actions);
    }
}

static void
upcall_uninit(struct upcall *upcall)
{
    if (upcall) {
        if (upcall->xout_initialized) {
            xlate_out_uninit(&upcall->xout);
        }
        ofpbuf_uninit(&upcall->put_actions);
    }
}

static int
upcall_cb(const struct ofpbuf *packet, const struct flow *flow,
          enum dpif_upcall_type type, const struct nlattr *userdata,
          struct ofpbuf *actions, struct flow_wildcards *wc,
          struct ofpbuf *put_actions, void *aux)
{
    struct udpif *udpif = aux;
    unsigned int flow_limit;
    struct upcall upcall;
    bool megaflow;
    int error;

    atomic_read_relaxed(&enable_megaflows, &megaflow);
    atomic_read_relaxed(&udpif->flow_limit, &flow_limit);

    error = upcall_receive(&upcall, udpif->backer, packet, type, userdata,
                           flow);
    if (error) {
        return error;
    }

    error = process_upcall(udpif, &upcall, actions);
    if (error) {
        goto out;
    }

    if (upcall.xout.slow && put_actions) {
        ofpbuf_put(put_actions, ofpbuf_data(&upcall.put_actions),
                   ofpbuf_size(&upcall.put_actions));
    }

    if (OVS_LIKELY(wc)) {
        if (megaflow) {
            /* XXX: This could be avoided with sufficient API changes. */
            *wc = upcall.xout.wc;
        } else {
            flow_wildcards_init_for_packet(wc, flow);
        }
    }

    if (udpif_get_n_flows(udpif) >= flow_limit) {
        error = ENOSPC;
    }

out:
    upcall_uninit(&upcall);
    return error;
}

static int
process_upcall(struct udpif *udpif, struct upcall *upcall,
               struct ofpbuf *odp_actions)
{
    const struct nlattr *userdata = upcall->userdata;
    const struct ofpbuf *packet = upcall->packet;
    const struct flow *flow = upcall->flow;

    switch (classify_upcall(upcall->type, userdata)) {
    case MISS_UPCALL:
        upcall_xlate(udpif, upcall, odp_actions);
        return 0;

    case SFLOW_UPCALL:
        if (upcall->sflow) {
            union user_action_cookie cookie;

            memset(&cookie, 0, sizeof cookie);
            memcpy(&cookie, nl_attr_get(userdata), sizeof cookie.sflow);
            dpif_sflow_received(upcall->sflow, packet, flow,
                                flow->in_port.odp_port, &cookie);
        }
        break;

    case IPFIX_UPCALL:
        if (upcall->ipfix) {
            union user_action_cookie cookie;
            struct flow_tnl output_tunnel_key;

            memset(&cookie, 0, sizeof cookie);
            memcpy(&cookie, nl_attr_get(userdata), sizeof cookie.ipfix);

            if (upcall->out_tun_key) {
                memset(&output_tunnel_key, 0, sizeof output_tunnel_key);
                odp_tun_key_from_attr(upcall->out_tun_key,
                                      &output_tunnel_key);
            }
            dpif_ipfix_bridge_sample(upcall->ipfix, packet, flow,
                                     flow->in_port.odp_port,
                                     cookie.ipfix.output_odp_port,
                                     upcall->out_tun_key ?
                                         &output_tunnel_key : NULL);
        }
        break;

    case FLOW_SAMPLE_UPCALL:
        if (upcall->ipfix) {
            union user_action_cookie cookie;

            memset(&cookie, 0, sizeof cookie);
            memcpy(&cookie, nl_attr_get(userdata), sizeof cookie.flow_sample);

            /* The flow reflects exactly the contents of the packet.
             * Sample the packet using it. */
            dpif_ipfix_flow_sample(upcall->ipfix, packet, flow,
                                   cookie.flow_sample.collector_set_id,
                                   cookie.flow_sample.probability,
                                   cookie.flow_sample.obs_domain_id,
                                   cookie.flow_sample.obs_point_id);
        }
        break;

    case BAD_UPCALL:
        break;
    }

    return EAGAIN;
}

static void
handle_upcalls(struct udpif *udpif, struct upcall *upcalls,
               size_t n_upcalls)
{
    struct odputil_keybuf mask_bufs[UPCALL_MAX_BATCH];
    struct dpif_op *opsp[UPCALL_MAX_BATCH * 2];
    struct dpif_op ops[UPCALL_MAX_BATCH * 2];
    unsigned int flow_limit;
    size_t n_ops, i;
    bool may_put;
    bool megaflow;

    atomic_read_relaxed(&udpif->flow_limit, &flow_limit);
    atomic_read_relaxed(&enable_megaflows, &megaflow);

    may_put = udpif_get_n_flows(udpif) < flow_limit;

    /* Handle the packets individually in order of arrival.
     *
     *   - For SLOW_CFM, SLOW_LACP, SLOW_STP, and SLOW_BFD, translation is what
     *     processes received packets for these protocols.
     *
     *   - For SLOW_CONTROLLER, translation sends the packet to the OpenFlow
     *     controller.
     *
     * The loop fills 'ops' with an array of operations to execute in the
     * datapath. */
    n_ops = 0;
    for (i = 0; i < n_upcalls; i++) {
        struct upcall *upcall = &upcalls[i];
        const struct ofpbuf *packet = upcall->packet;
        struct dpif_op *op;

        if (upcall->vsp_adjusted) {
            /* This packet was received on a VLAN splinter port.  We added a
             * VLAN to the packet to make the packet resemble the flow, but the
             * actions were composed assuming that the packet contained no
             * VLAN.  So, we must remove the VLAN header from the packet before
             * trying to execute the actions. */
            if (ofpbuf_size(upcall->xout.odp_actions)) {
                eth_pop_vlan(CONST_CAST(struct ofpbuf *, upcall->packet));
            }

            /* Remove the flow vlan tags inserted by vlan splinter logic
             * to ensure megaflow masks generated match the data path flow. */
            CONST_CAST(struct flow *, upcall->flow)->vlan_tci = 0;
        }

        /* Do not install a flow into the datapath if:
         *
         *    - The datapath already has too many flows.
         *
         *    - We received this packet via some flow installed in the kernel
         *      already. */
        if (may_put && upcall->type == DPIF_UC_MISS) {
            struct ofpbuf mask;

            ofpbuf_use_stack(&mask, &mask_bufs[i], sizeof mask_bufs[i]);

            if (megaflow) {
                size_t max_mpls;
                bool recirc;

                recirc = ofproto_dpif_get_enable_recirc(upcall->ofproto);
                max_mpls = ofproto_dpif_get_max_mpls_depth(upcall->ofproto);
                odp_flow_key_from_mask(&mask, &upcall->xout.wc.masks,
                                       upcall->flow, UINT32_MAX, max_mpls,
                                       recirc);
            }

            op = &ops[n_ops++];
            op->type = DPIF_OP_FLOW_PUT;
            op->u.flow_put.flags = DPIF_FP_CREATE;
            op->u.flow_put.key = upcall->key;
            op->u.flow_put.key_len = upcall->key_len;
            op->u.flow_put.mask = ofpbuf_data(&mask);
            op->u.flow_put.mask_len = ofpbuf_size(&mask);
            op->u.flow_put.stats = NULL;
            op->u.flow_put.actions = ofpbuf_data(&upcall->put_actions);
            op->u.flow_put.actions_len = ofpbuf_size(&upcall->put_actions);
        }

        if (ofpbuf_size(upcall->xout.odp_actions)) {
            op = &ops[n_ops++];
            op->type = DPIF_OP_EXECUTE;
            op->u.execute.packet = CONST_CAST(struct ofpbuf *, packet);
            odp_key_to_pkt_metadata(upcall->key, upcall->key_len,
                                    &op->u.execute.md);
            op->u.execute.actions = ofpbuf_data(upcall->xout.odp_actions);
            op->u.execute.actions_len = ofpbuf_size(upcall->xout.odp_actions);
            op->u.execute.needs_help = (upcall->xout.slow & SLOW_ACTION) != 0;
            op->u.execute.probe = false;
        }
    }

    /* Execute batch. */
    for (i = 0; i < n_ops; i++) {
        opsp[i] = &ops[i];
    }
    dpif_operate(udpif->dpif, opsp, n_ops);
}

/* Must be called with udpif->ukeys[hash % udpif->n_revalidators].mutex. */
static struct udpif_key *
ukey_lookup(struct udpif *udpif, const struct nlattr *key, size_t key_len,
            uint32_t hash)
    OVS_REQUIRES(udpif->ukeys->mutex)
{
    struct udpif_key *ukey;
    struct hmap *hmap = &udpif->ukeys[hash % udpif->n_revalidators].hmap;

    HMAP_FOR_EACH_WITH_HASH (ukey, hmap_node, hash, hmap) {
        if (ukey->key_len == key_len && !memcmp(ukey->key, key, key_len)) {
            return ukey;
        }
    }
    return NULL;
}

/* Creates a ukey for 'key' and 'key_len', returning it with ukey->mutex in
 * a locked state. */
static struct udpif_key *
ukey_create(const struct nlattr *key, size_t key_len, long long int used)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct udpif_key *ukey = xmalloc(sizeof *ukey);

    ovs_mutex_init(&ukey->mutex);
    ukey->key = &ukey->key_buf_nla;
    memcpy(&ukey->key_buf, key, key_len);
    ukey->key_len = key_len;

    ovs_mutex_lock(&ukey->mutex);
    ukey->dump_seq = 0;
    ukey->flow_exists = true;
    ukey->created = used ? used : time_msec();
    memset(&ukey->stats, 0, sizeof ukey->stats);
    ukey->xcache = NULL;

    return ukey;
}

/* Searches for a ukey in 'udpif->ukeys' that matches 'key' and 'key_len' and
 * attempts to lock the ukey. If the ukey does not exist, create it.
 *
 * Returns true on success, setting *result to the matching ukey and returning
 * it in a locked state. Otherwise, returns false and clears *result. */
static bool
ukey_acquire(struct udpif *udpif, const struct nlattr *key, size_t key_len,
             long long int used, struct udpif_key **result)
    OVS_TRY_LOCK(true, (*result)->mutex)
{
    struct udpif_key *ukey;
    uint32_t hash, idx;
    bool locked = false;

    hash = hash_bytes(key, key_len, udpif->secret);
    idx = hash % udpif->n_revalidators;

    ovs_mutex_lock(&udpif->ukeys[idx].mutex);
    ukey = ukey_lookup(udpif, key, key_len, hash);
    if (!ukey) {
        ukey = ukey_create(key, key_len, used);
        hmap_insert(&udpif->ukeys[idx].hmap, &ukey->hmap_node, hash);
        locked = true;
    } else if (!ovs_mutex_trylock(&ukey->mutex)) {
        locked = true;
    }
    ovs_mutex_unlock(&udpif->ukeys[idx].mutex);

    if (locked) {
        *result = ukey;
    } else {
        *result = NULL;
    }
    return locked;
}

static void
ukey_delete(struct revalidator *revalidator, struct udpif_key *ukey)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    if (revalidator) {
        hmap_remove(revalidator->ukeys, &ukey->hmap_node);
    }
    xlate_cache_delete(ukey->xcache);
    ovs_mutex_destroy(&ukey->mutex);
    free(ukey);
}

static bool
should_revalidate(const struct udpif *udpif, uint64_t packets,
                  long long int used)
{
    long long int metric, now, duration;

    if (udpif->dump_duration < 200) {
        /* We are likely to handle full revalidation for the flows. */
        return true;
    }

    /* Calculate the mean time between seeing these packets. If this
     * exceeds the threshold, then delete the flow rather than performing
     * costly revalidation for flows that aren't being hit frequently.
     *
     * This is targeted at situations where the dump_duration is high (~1s),
     * and revalidation is triggered by a call to udpif_revalidate(). In
     * these situations, revalidation of all flows causes fluctuations in the
     * flow_limit due to the interaction with the dump_duration and max_idle.
     * This tends to result in deletion of low-throughput flows anyway, so
     * skip the revalidation and just delete those flows. */
    packets = MAX(packets, 1);
    now = MAX(used, time_msec());
    duration = now - used;
    metric = duration / packets;

    if (metric < 200) {
        /* The flow is receiving more than ~5pps, so keep it. */
        return true;
    }
    return false;
}

static bool
revalidate_ukey(struct udpif *udpif, struct udpif_key *ukey,
                const struct dpif_flow *f)
    OVS_REQUIRES(ukey->mutex)
{
    uint64_t slow_path_buf[128 / 8];
    struct xlate_out xout, *xoutp;
    struct netflow *netflow;
    struct ofproto_dpif *ofproto;
    struct dpif_flow_stats push;
    struct ofpbuf xout_actions;
    struct flow flow, dp_mask;
    uint32_t *dp32, *xout32;
    ofp_port_t ofp_in_port;
    struct xlate_in xin;
    long long int last_used;
    int error;
    size_t i;
    bool ok;

    ok = false;
    xoutp = NULL;
    netflow = NULL;

    last_used = ukey->stats.used;
    push.used = f->stats.used;
    push.tcp_flags = f->stats.tcp_flags;
    push.n_packets = (f->stats.n_packets > ukey->stats.n_packets
                      ? f->stats.n_packets - ukey->stats.n_packets
                      : 0);
    push.n_bytes = (f->stats.n_bytes > ukey->stats.n_bytes
                    ? f->stats.n_bytes - ukey->stats.n_bytes
                    : 0);

    if (udpif->need_revalidate && last_used
        && !should_revalidate(udpif, push.n_packets, last_used)) {
        ok = false;
        goto exit;
    }

    /* We will push the stats, so update the ukey stats cache. */
    ukey->stats = f->stats;
    if (!push.n_packets && !udpif->need_revalidate) {
        ok = true;
        goto exit;
    }

    if (ukey->xcache && !udpif->need_revalidate) {
        xlate_push_stats(ukey->xcache, &push);
        ok = true;
        goto exit;
    }

    if (odp_flow_key_to_flow(ukey->key, ukey->key_len, &flow)
        == ODP_FIT_ERROR) {
        goto exit;
    }

    error = xlate_lookup(udpif->backer, &flow, &ofproto, NULL, NULL, &netflow,
                         &ofp_in_port);
    if (error) {
        goto exit;
    }

    if (udpif->need_revalidate) {
        xlate_cache_clear(ukey->xcache);
    }
    if (!ukey->xcache) {
        ukey->xcache = xlate_cache_new();
    }

    xlate_in_init(&xin, ofproto, &flow, ofp_in_port, NULL, push.tcp_flags,
                  NULL);
    if (push.n_packets) {
        xin.resubmit_stats = &push;
        xin.may_learn = true;
    }
    xin.xcache = ukey->xcache;
    xin.skip_wildcards = !udpif->need_revalidate;
    xlate_actions(&xin, &xout);
    xoutp = &xout;

    if (!udpif->need_revalidate) {
        ok = true;
        goto exit;
    }

    if (!xout.slow) {
        ofpbuf_use_const(&xout_actions, ofpbuf_data(xout.odp_actions),
                         ofpbuf_size(xout.odp_actions));
    } else {
        ofpbuf_use_stack(&xout_actions, slow_path_buf, sizeof slow_path_buf);
        compose_slow_path(udpif, &xout, &flow, flow.in_port.odp_port,
                          &xout_actions);
    }

    if (f->actions_len != ofpbuf_size(&xout_actions)
        || memcmp(ofpbuf_data(&xout_actions), f->actions, f->actions_len)) {
        goto exit;
    }

    if (odp_flow_key_to_mask(f->mask, f->mask_len, &dp_mask, &flow)
        == ODP_FIT_ERROR) {
        goto exit;
    }

    /* Since the kernel is free to ignore wildcarded bits in the mask, we can't
     * directly check that the masks are the same.  Instead we check that the
     * mask in the kernel is more specific i.e. less wildcarded, than what
     * we've calculated here.  This guarantees we don't catch any packets we
     * shouldn't with the megaflow. */
    dp32 = (uint32_t *) &dp_mask;
    xout32 = (uint32_t *) &xout.wc.masks;
    for (i = 0; i < FLOW_U32S; i++) {
        if ((dp32[i] | xout32[i]) != dp32[i]) {
            goto exit;
        }
    }
    ok = true;

exit:
    if (netflow && !ok) {
        netflow_flow_clear(netflow, &flow);
    }
    xlate_out_uninit(xoutp);
    return ok;
}

struct dump_op {
    struct udpif_key *ukey;
    struct dpif_flow_stats stats; /* Stats for 'op'. */
    struct dpif_op op;            /* Flow del operation. */
};

static void
dump_op_init(struct dump_op *op, const struct nlattr *key, size_t key_len,
             struct udpif_key *ukey)
{
    op->ukey = ukey;
    op->op.type = DPIF_OP_FLOW_DEL;
    op->op.u.flow_del.key = key;
    op->op.u.flow_del.key_len = key_len;
    op->op.u.flow_del.stats = &op->stats;
}

static void
push_dump_ops__(struct udpif *udpif, struct dump_op *ops, size_t n_ops)
{
    struct dpif_op *opsp[REVALIDATE_MAX_BATCH];
    size_t i;

    ovs_assert(n_ops <= REVALIDATE_MAX_BATCH);
    for (i = 0; i < n_ops; i++) {
        opsp[i] = &ops[i].op;
    }
    dpif_operate(udpif->dpif, opsp, n_ops);

    for (i = 0; i < n_ops; i++) {
        struct dump_op *op = &ops[i];
        struct dpif_flow_stats *push, *stats, push_buf;

        stats = op->op.u.flow_del.stats;
        push = &push_buf;

        ovs_mutex_lock(&op->ukey->mutex);
        push->used = MAX(stats->used, op->ukey->stats.used);
        push->tcp_flags = stats->tcp_flags | op->ukey->stats.tcp_flags;
        push->n_packets = stats->n_packets - op->ukey->stats.n_packets;
        push->n_bytes = stats->n_bytes - op->ukey->stats.n_bytes;
        ovs_mutex_unlock(&op->ukey->mutex);

        if (push->n_packets || netflow_exists()) {
            struct ofproto_dpif *ofproto;
            struct netflow *netflow;
            ofp_port_t ofp_in_port;
            struct flow flow;
            int error;

            ovs_mutex_lock(&op->ukey->mutex);
            if (op->ukey->xcache) {
                xlate_push_stats(op->ukey->xcache, push);
                ovs_mutex_unlock(&op->ukey->mutex);
                continue;
            }
            ovs_mutex_unlock(&op->ukey->mutex);

            if (odp_flow_key_to_flow(op->op.u.flow_del.key,
                                     op->op.u.flow_del.key_len, &flow)
                == ODP_FIT_ERROR) {
                continue;
            }

            error = xlate_lookup(udpif->backer, &flow, &ofproto,
                                 NULL, NULL, &netflow, &ofp_in_port);
            if (!error) {
                struct xlate_in xin;

                xlate_in_init(&xin, ofproto, &flow, ofp_in_port, NULL,
                              push->tcp_flags, NULL);
                xin.resubmit_stats = push->n_packets ? push : NULL;
                xin.may_learn = push->n_packets > 0;
                xin.skip_wildcards = true;
                xlate_actions_for_side_effects(&xin);

                if (netflow) {
                    netflow_flow_clear(netflow, &flow);
                }
            }
        }
    }
}

static void
push_dump_ops(struct revalidator *revalidator,
              struct dump_op *ops, size_t n_ops)
{
    int i;

    push_dump_ops__(revalidator->udpif, ops, n_ops);
    for (i = 0; i < n_ops; i++) {
        ukey_delete(revalidator, ops[i].ukey);
    }
}

static void
revalidate(struct revalidator *revalidator)
{
    struct udpif *udpif = revalidator->udpif;
    struct dpif_flow_dump_thread *dump_thread;
    uint64_t dump_seq;
    unsigned int flow_limit;

    dump_seq = seq_read(udpif->dump_seq);
    atomic_read_relaxed(&udpif->flow_limit, &flow_limit);
    dump_thread = dpif_flow_dump_thread_create(udpif->dump);
    for (;;) {
        struct dump_op ops[REVALIDATE_MAX_BATCH];
        int n_ops = 0;

        struct dpif_flow flows[REVALIDATE_MAX_BATCH];
        const struct dpif_flow *f;
        int n_dumped;

        long long int max_idle;
        long long int now;
        size_t n_dp_flows;
        bool kill_them_all;

        n_dumped = dpif_flow_dump_next(dump_thread, flows, ARRAY_SIZE(flows));
        if (!n_dumped) {
            break;
        }

        now = time_msec();

        /* In normal operation we want to keep flows around until they have
         * been idle for 'ofproto_max_idle' milliseconds.  However:
         *
         *     - If the number of datapath flows climbs above 'flow_limit',
         *       drop that down to 100 ms to try to bring the flows down to
         *       the limit.
         *
         *     - If the number of datapath flows climbs above twice
         *       'flow_limit', delete all the datapath flows as an emergency
         *       measure.  (We reassess this condition for the next batch of
         *       datapath flows, so we will recover before all the flows are
         *       gone.) */
        n_dp_flows = udpif_get_n_flows(udpif);
        kill_them_all = n_dp_flows > flow_limit * 2;
        max_idle = n_dp_flows > flow_limit ? 100 : ofproto_max_idle;

        for (f = flows; f < &flows[n_dumped]; f++) {
            long long int used = f->stats.used;
            struct udpif_key *ukey;
            bool already_dumped, keep;

            if (!ukey_acquire(udpif, f->key, f->key_len, used, &ukey)) {
                /* We couldn't acquire the ukey. This means that
                 * another revalidator is processing this flow
                 * concurrently, so don't bother processing it. */
                COVERAGE_INC(dumped_duplicate_flow);
                continue;
            }

            already_dumped = ukey->dump_seq == dump_seq;
            if (already_dumped) {
                /* The flow has already been handled during this flow dump
                 * operation. Skip it. */
                if (ukey->xcache) {
                    COVERAGE_INC(dumped_duplicate_flow);
                } else {
                    COVERAGE_INC(dumped_new_flow);
                }
                ovs_mutex_unlock(&ukey->mutex);
                continue;
            }

            if (!used) {
                used = ukey->created;
            }
            if (kill_them_all || (used && used < now - max_idle)) {
                keep = false;
            } else {
                keep = revalidate_ukey(udpif, ukey, f);
            }
            ukey->dump_seq = dump_seq;
            ukey->flow_exists = keep;

            if (!keep) {
                dump_op_init(&ops[n_ops++], f->key, f->key_len, ukey);
            }
            ovs_mutex_unlock(&ukey->mutex);
        }

        if (n_ops) {
            push_dump_ops__(udpif, ops, n_ops);
        }
    }
    dpif_flow_dump_thread_destroy(dump_thread);
}

/* Called with exclusive access to 'revalidator' and 'ukey'. */
static bool
handle_missed_revalidation(struct revalidator *revalidator,
                           struct udpif_key *ukey)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct udpif *udpif = revalidator->udpif;
    struct dpif_flow flow;
    struct ofpbuf buf;
    uint64_t stub[DPIF_FLOW_BUFSIZE / 8];
    bool keep = false;

    COVERAGE_INC(revalidate_missed_dp_flow);

    ofpbuf_use_stub(&buf, &stub, sizeof stub);
    if (!dpif_flow_get(udpif->dpif, ukey->key, ukey->key_len, &buf, &flow)) {
        keep = revalidate_ukey(udpif, ukey, &flow);
    }
    ofpbuf_uninit(&buf);

    return keep;
}

static void
revalidator_sweep__(struct revalidator *revalidator, bool purge)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dump_op ops[REVALIDATE_MAX_BATCH];
    struct udpif_key *ukey, *next;
    size_t n_ops;
    uint64_t dump_seq;

    n_ops = 0;
    dump_seq = seq_read(revalidator->udpif->dump_seq);

    /* During garbage collection, this revalidator completely owns its ukeys
     * map, and therefore doesn't need to do any locking. */
    HMAP_FOR_EACH_SAFE (ukey, next, hmap_node, revalidator->ukeys) {
        if (ukey->flow_exists
            && (purge
                || (ukey->dump_seq != dump_seq
                    && revalidator->udpif->need_revalidate
                    && !handle_missed_revalidation(revalidator, ukey)))) {
            struct dump_op *op = &ops[n_ops++];

            dump_op_init(op, ukey->key, ukey->key_len, ukey);
            if (n_ops == REVALIDATE_MAX_BATCH) {
                push_dump_ops(revalidator, ops, n_ops);
                n_ops = 0;
            }
        } else if (!ukey->flow_exists) {
            ukey_delete(revalidator, ukey);
        }
    }

    if (n_ops) {
        push_dump_ops(revalidator, ops, n_ops);
    }
}

static void
revalidator_sweep(struct revalidator *revalidator)
{
    revalidator_sweep__(revalidator, false);
}

static void
revalidator_purge(struct revalidator *revalidator)
{
    revalidator_sweep__(revalidator, true);
}

static void
upcall_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct udpif *udpif;

    LIST_FOR_EACH (udpif, list_node, &all_udpifs) {
        unsigned int flow_limit;
        size_t i;

        atomic_read_relaxed(&udpif->flow_limit, &flow_limit);

        ds_put_format(&ds, "%s:\n", dpif_name(udpif->dpif));
        ds_put_format(&ds, "\tflows         : (current %lu)"
            " (avg %u) (max %u) (limit %u)\n", udpif_get_n_flows(udpif),
            udpif->avg_n_flows, udpif->max_n_flows, flow_limit);
        ds_put_format(&ds, "\tdump duration : %lldms\n", udpif->dump_duration);

        ds_put_char(&ds, '\n');
        for (i = 0; i < n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            ovs_mutex_lock(&udpif->ukeys[i].mutex);
            ds_put_format(&ds, "\t%u: (keys %"PRIuSIZE")\n",
                          revalidator->id, hmap_count(&udpif->ukeys[i].hmap));
            ovs_mutex_unlock(&udpif->ukeys[i].mutex);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/* Disable using the megaflows.
 *
 * This command is only needed for advanced debugging, so it's not
 * documented in the man page. */
static void
upcall_unixctl_disable_megaflows(struct unixctl_conn *conn,
                                 int argc OVS_UNUSED,
                                 const char *argv[] OVS_UNUSED,
                                 void *aux OVS_UNUSED)
{
    atomic_store_relaxed(&enable_megaflows, false);
    udpif_flush_all_datapaths();
    unixctl_command_reply(conn, "megaflows disabled");
}

/* Re-enable using megaflows.
 *
 * This command is only needed for advanced debugging, so it's not
 * documented in the man page. */
static void
upcall_unixctl_enable_megaflows(struct unixctl_conn *conn,
                                int argc OVS_UNUSED,
                                const char *argv[] OVS_UNUSED,
                                void *aux OVS_UNUSED)
{
    atomic_store_relaxed(&enable_megaflows, true);
    udpif_flush_all_datapaths();
    unixctl_command_reply(conn, "megaflows enabled");
}

/* Set the flow limit.
 *
 * This command is only needed for advanced debugging, so it's not
 * documented in the man page. */
static void
upcall_unixctl_set_flow_limit(struct unixctl_conn *conn,
                              int argc OVS_UNUSED,
                              const char *argv[] OVS_UNUSED,
                              void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct udpif *udpif;
    unsigned int flow_limit = atoi(argv[1]);

    LIST_FOR_EACH (udpif, list_node, &all_udpifs) {
        atomic_store_relaxed(&udpif->flow_limit, flow_limit);
    }
    ds_put_format(&ds, "set flow_limit to %u\n", flow_limit);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
upcall_unixctl_dump_wait(struct unixctl_conn *conn,
                         int argc OVS_UNUSED,
                         const char *argv[] OVS_UNUSED,
                         void *aux OVS_UNUSED)
{
    if (list_is_singleton(&all_udpifs)) {
        struct udpif *udpif = NULL;
        size_t len;

        udpif = OBJECT_CONTAINING(list_front(&all_udpifs), udpif, list_node);
        len = (udpif->n_conns + 1) * sizeof *udpif->conns;
        udpif->conn_seq = seq_read(udpif->dump_seq);
        udpif->conns = xrealloc(udpif->conns, len);
        udpif->conns[udpif->n_conns++] = conn;
    } else {
        unixctl_command_reply_error(conn, "can't wait on multiple udpifs.");
    }
}

static void
upcall_unixctl_purge(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct udpif *udpif;

    LIST_FOR_EACH (udpif, list_node, &all_udpifs) {
        int n;

        for (n = 0; n < udpif->n_revalidators; n++) {
            revalidator_purge(&udpif->revalidators[n]);
        }
    }
    unixctl_command_reply(conn, "");
}
