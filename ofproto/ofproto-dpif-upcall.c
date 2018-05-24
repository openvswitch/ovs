/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#include "cmap.h"
#include "dpif.h"
#include "openvswitch/dynamic-string.h"
#include "fail-open.h"
#include "guarded-list.h"
#include "latch.h"
#include "openvswitch/list.h"
#include "netlink.h"
#include "openvswitch/ofpbuf.h"
#include "ofproto-dpif-ipfix.h"
#include "ofproto-dpif-sflow.h"
#include "ofproto-dpif-xlate.h"
#include "ofproto-dpif-xlate-cache.h"
#include "ofproto-dpif-trace.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "tunnel.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"

#define MAX_QUEUE_LENGTH 512
#define UPCALL_MAX_BATCH 64
#define REVALIDATE_MAX_BATCH 50

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_upcall);

COVERAGE_DEFINE(dumped_duplicate_flow);
COVERAGE_DEFINE(dumped_new_flow);
COVERAGE_DEFINE(handler_duplicate_upcall);
COVERAGE_DEFINE(upcall_ukey_contention);
COVERAGE_DEFINE(upcall_ukey_replace);
COVERAGE_DEFINE(revalidate_missed_dp_flow);

/* A thread that reads upcalls from dpif, forwards each upcall's packet,
 * and possibly sets up a kernel flow as a cache. */
struct handler {
    struct udpif *udpif;               /* Parent udpif. */
    pthread_t thread;                  /* Thread ID. */
    uint32_t handler_id;               /* Handler id. */
};

/* In the absence of a multiple-writer multiple-reader datastructure for
 * storing udpif_keys ("ukeys"), we use a large number of cmaps, each with its
 * own lock for writing. */
#define N_UMAPS 512 /* per udpif. */
struct umap {
    struct ovs_mutex mutex;            /* Take for writing to the following. */
    struct cmap cmap;                  /* Datapath flow keys. */
};

/* A thread that processes datapath flows, updates OpenFlow statistics, and
 * updates or removes them if necessary.
 *
 * Revalidator threads operate in two phases: "dump" and "sweep". In between
 * each phase, all revalidators sync up so that all revalidator threads are
 * either in one phase or the other, but not a combination.
 *
 *     During the dump phase, revalidators fetch flows from the datapath and
 *     attribute the statistics to OpenFlow rules. Each datapath flow has a
 *     corresponding ukey which caches the most recently seen statistics. If
 *     a flow needs to be deleted (for example, because it is unused over a
 *     period of time), revalidator threads may delete the flow during the
 *     dump phase. The datapath is not guaranteed to reliably dump all flows
 *     from the datapath, and there is no mapping between datapath flows to
 *     revalidators, so a particular flow may be handled by zero or more
 *     revalidators during a single dump phase. To avoid duplicate attribution
 *     of statistics, ukeys are never deleted during this phase.
 *
 *     During the sweep phase, each revalidator takes ownership of a different
 *     slice of umaps and sweeps through all ukeys in those umaps to figure out
 *     whether they need to be deleted. During this phase, revalidators may
 *     fetch individual flows which were not dumped during the dump phase to
 *     validate them and attribute statistics.
 */
struct revalidator {
    struct udpif *udpif;               /* Parent udpif. */
    pthread_t thread;                  /* Thread ID. */
    unsigned int id;                   /* ovsthread_id_self(). */
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
    struct ovs_list list_node;         /* In all_udpifs list. */

    struct dpif *dpif;                 /* Datapath handle. */
    struct dpif_backer *backer;        /* Opaque dpif_backer pointer. */

    struct handler *handlers;          /* Upcall handlers. */
    size_t n_handlers;

    struct revalidator *revalidators;  /* Flow revalidators. */
    size_t n_revalidators;

    struct latch exit_latch;           /* Tells child threads to exit. */

    /* Revalidation. */
    struct seq *reval_seq;             /* Incremented to force revalidation. */
    bool reval_exit;                   /* Set by leader on 'exit_latch. */
    struct ovs_barrier reval_barrier;  /* Barrier used by revalidators. */
    struct dpif_flow_dump *dump;       /* DPIF flow dump state. */
    long long int dump_duration;       /* Duration of the last flow dump. */
    struct seq *dump_seq;              /* Increments each dump iteration. */
    atomic_bool enable_ufid;           /* If true, skip dumping flow attrs. */

    /* These variables provide a mechanism for the main thread to pause
     * all revalidation without having to completely shut the threads down.
     * 'pause_latch' is shared between the main thread and the lead
     * revalidator thread, so when it is desirable to halt revalidation, the
     * main thread will set the latch. 'pause' and 'pause_barrier' are shared
     * by revalidator threads. The lead revalidator will set 'pause' when it
     * observes the latch has been set, and this will cause all revalidator
     * threads to wait on 'pause_barrier' at the beginning of the next
     * revalidation round. */
    bool pause;                        /* Set by leader on 'pause_latch. */
    struct latch pause_latch;          /* Set to force revalidators pause. */
    struct ovs_barrier pause_barrier;  /* Barrier used to pause all */
                                       /* revalidators by main thread. */

    /* There are 'N_UMAPS' maps containing 'struct udpif_key' elements.
     *
     * During the flow dump phase, revalidators insert into these with a random
     * distribution. During the garbage collection phase, each revalidator
     * takes care of garbage collecting a slice of these maps. */
    struct umap *ukeys;

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
    SLOW_PATH_UPCALL,           /* Slow path upcall.  */
    SFLOW_UPCALL,               /* sFlow sample. */
    FLOW_SAMPLE_UPCALL,         /* Per-flow sampling. */
    IPFIX_UPCALL,               /* Per-bridge sampling. */
    CONTROLLER_UPCALL           /* Destined for the controller. */
};

enum reval_result {
    UKEY_KEEP,
    UKEY_DELETE,
    UKEY_MODIFY
};

struct upcall {
    struct ofproto_dpif *ofproto;  /* Parent ofproto. */
    const struct recirc_id_node *recirc; /* Recirculation context. */
    bool have_recirc_ref;                /* Reference held on recirc ctx? */

    /* The flow and packet are only required to be constant when using
     * dpif-netdev.  If a modification is absolutely necessary, a const cast
     * may be used with other datapaths. */
    const struct flow *flow;       /* Parsed representation of the packet. */
    enum odp_key_fitness fitness;  /* Fitness of 'flow' relative to ODP key. */
    const ovs_u128 *ufid;          /* Unique identifier for 'flow'. */
    unsigned pmd_id;               /* Datapath poll mode driver id. */
    const struct dp_packet *packet;   /* Packet associated with this upcall. */
    ofp_port_t ofp_in_port;        /* OpenFlow in port, or OFPP_NONE. */
    uint16_t mru;                  /* If !0, Maximum receive unit of
                                      fragmented IP packet */

    enum upcall_type type;         /* Type of the upcall. */
    const struct nlattr *actions;  /* Flow actions in DPIF_UC_ACTION Upcalls. */

    bool xout_initialized;         /* True if 'xout' must be uninitialized. */
    struct xlate_out xout;         /* Result of xlate_actions(). */
    struct ofpbuf odp_actions;     /* Datapath actions from xlate_actions(). */
    struct flow_wildcards wc;      /* Dependencies that megaflow must match. */
    struct ofpbuf put_actions;     /* Actions 'put' in the fastpath. */

    struct dpif_ipfix *ipfix;      /* IPFIX pointer or NULL. */
    struct dpif_sflow *sflow;      /* SFlow pointer or NULL. */

    struct udpif_key *ukey;        /* Revalidator flow cache. */
    bool ukey_persists;            /* Set true to keep 'ukey' beyond the
                                      lifetime of this upcall. */

    uint64_t reval_seq;            /* udpif->reval_seq at translation time. */

    /* Not used by the upcall callback interface. */
    const struct nlattr *key;      /* Datapath flow key. */
    size_t key_len;                /* Datapath flow key length. */
    const struct nlattr *out_tun_key;  /* Datapath output tunnel key. */

    struct user_action_cookie cookie;

    uint64_t odp_actions_stub[1024 / 8]; /* Stub for odp_actions. */
};

/* Ukeys must transition through these states using transition_ukey(). */
enum ukey_state {
    UKEY_CREATED = 0,
    UKEY_VISIBLE,       /* Ukey is in umap, datapath flow install is queued. */
    UKEY_OPERATIONAL,   /* Ukey is in umap, datapath flow is installed. */
    UKEY_EVICTING,      /* Ukey is in umap, datapath flow delete is queued. */
    UKEY_EVICTED,       /* Ukey is in umap, datapath flow is deleted. */
    UKEY_DELETED,       /* Ukey removed from umap, ukey free is deferred. */
};
#define N_UKEY_STATES (UKEY_DELETED + 1)

/* 'udpif_key's are responsible for tracking the little bit of state udpif
 * needs to do flow expiration which can't be pulled directly from the
 * datapath.  They may be created by any handler or revalidator thread at any
 * time, and read by any revalidator during the dump phase. They are however
 * each owned by a single revalidator which takes care of destroying them
 * during the garbage-collection phase.
 *
 * The mutex within the ukey protects some members of the ukey. The ukey
 * itself is protected by RCU and is held within a umap in the parent udpif.
 * Adding or removing a ukey from a umap is only safe when holding the
 * corresponding umap lock. */
struct udpif_key {
    struct cmap_node cmap_node;     /* In parent revalidator 'ukeys' map. */

    /* These elements are read only once created, and therefore aren't
     * protected by a mutex. */
    const struct nlattr *key;      /* Datapath flow key. */
    size_t key_len;                /* Length of 'key'. */
    const struct nlattr *mask;     /* Datapath flow mask. */
    size_t mask_len;               /* Length of 'mask'. */
    ovs_u128 ufid;                 /* Unique flow identifier. */
    bool ufid_present;             /* True if 'ufid' is in datapath. */
    uint32_t hash;                 /* Pre-computed hash for 'key'. */
    unsigned pmd_id;               /* Datapath poll mode driver id. */

    struct ovs_mutex mutex;                   /* Guards the following. */
    struct dpif_flow_stats stats OVS_GUARDED; /* Last known stats.*/
    long long int created OVS_GUARDED;        /* Estimate of creation time. */
    uint64_t dump_seq OVS_GUARDED;            /* Tracks udpif->dump_seq. */
    uint64_t reval_seq OVS_GUARDED;           /* Tracks udpif->reval_seq. */
    enum ukey_state state OVS_GUARDED;        /* Tracks ukey lifetime. */

    /* 'state' debug information. */
    unsigned int state_thread OVS_GUARDED;    /* Thread that transitions. */
    const char *state_where OVS_GUARDED;      /* transition_ukey() locator. */

    /* Datapath flow actions as nlattrs.  Protected by RCU.  Read with
     * ukey_get_actions(), and write with ukey_set_actions(). */
    OVSRCU_TYPE(struct ofpbuf *) actions;

    struct xlate_cache *xcache OVS_GUARDED;   /* Cache for xlate entries that
                                               * are affected by this ukey.
                                               * Used for stats and learning.*/
    union {
        struct odputil_keybuf buf;
        struct nlattr nla;
    } keybuf, maskbuf;

    uint32_t key_recirc_id;   /* Non-zero if reference is held by the ukey. */
    struct recirc_refs recircs;  /* Action recirc IDs with references held. */
};

/* Datapath operation with optional ukey attached. */
struct ukey_op {
    struct udpif_key *ukey;
    struct dpif_flow_stats stats; /* Stats for 'op'. */
    struct dpif_op dop;           /* Flow operation. */
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct ovs_list all_udpifs = OVS_LIST_INITIALIZER(&all_udpifs);

static size_t recv_upcalls(struct handler *);
static int process_upcall(struct udpif *, struct upcall *,
                          struct ofpbuf *odp_actions, struct flow_wildcards *);
static void handle_upcalls(struct udpif *, struct upcall *, size_t n_upcalls);
static void udpif_stop_threads(struct udpif *);
static void udpif_start_threads(struct udpif *, size_t n_handlers,
                                size_t n_revalidators);
static void udpif_pause_revalidators(struct udpif *);
static void udpif_resume_revalidators(struct udpif *);
static void *udpif_upcall_handler(void *);
static void *udpif_revalidator(void *);
static unsigned long udpif_get_n_flows(struct udpif *);
static void revalidate(struct revalidator *);
static void revalidator_pause(struct revalidator *);
static void revalidator_sweep(struct revalidator *);
static void revalidator_purge(struct revalidator *);
static void upcall_unixctl_show(struct unixctl_conn *conn, int argc,
                                const char *argv[], void *aux);
static void upcall_unixctl_disable_megaflows(struct unixctl_conn *, int argc,
                                             const char *argv[], void *aux);
static void upcall_unixctl_enable_megaflows(struct unixctl_conn *, int argc,
                                            const char *argv[], void *aux);
static void upcall_unixctl_disable_ufid(struct unixctl_conn *, int argc,
                                              const char *argv[], void *aux);
static void upcall_unixctl_enable_ufid(struct unixctl_conn *, int argc,
                                             const char *argv[], void *aux);
static void upcall_unixctl_set_flow_limit(struct unixctl_conn *conn, int argc,
                                            const char *argv[], void *aux);
static void upcall_unixctl_dump_wait(struct unixctl_conn *conn, int argc,
                                     const char *argv[], void *aux);
static void upcall_unixctl_purge(struct unixctl_conn *conn, int argc,
                                 const char *argv[], void *aux);

static struct udpif_key *ukey_create_from_upcall(struct upcall *,
                                                 struct flow_wildcards *);
static int ukey_create_from_dpif_flow(const struct udpif *,
                                      const struct dpif_flow *,
                                      struct udpif_key **);
static void ukey_get_actions(struct udpif_key *, const struct nlattr **actions,
                             size_t *size);
static bool ukey_install__(struct udpif *, struct udpif_key *ukey)
    OVS_TRY_LOCK(true, ukey->mutex);
static bool ukey_install(struct udpif *udpif, struct udpif_key *ukey);
static void transition_ukey_at(struct udpif_key *ukey, enum ukey_state dst,
                               const char *where)
    OVS_REQUIRES(ukey->mutex);
#define transition_ukey(UKEY, DST) \
    transition_ukey_at(UKEY, DST, OVS_SOURCE_LOCATOR)
static struct udpif_key *ukey_lookup(struct udpif *udpif,
                                     const ovs_u128 *ufid,
                                     const unsigned pmd_id);
static int ukey_acquire(struct udpif *, const struct dpif_flow *,
                        struct udpif_key **result, int *error);
static void ukey_delete__(struct udpif_key *);
static void ukey_delete(struct umap *, struct udpif_key *);
static enum upcall_type classify_upcall(enum dpif_upcall_type type,
                                        const struct nlattr *userdata,
                                        struct user_action_cookie *cookie);

static void put_op_init(struct ukey_op *op, struct udpif_key *ukey,
                        enum dpif_flow_put_flags flags);
static void delete_op_init(struct udpif *udpif, struct ukey_op *op,
                           struct udpif_key *ukey);

static int upcall_receive(struct upcall *, const struct dpif_backer *,
                          const struct dp_packet *packet, enum dpif_upcall_type,
                          const struct nlattr *userdata, const struct flow *,
                          const unsigned int mru,
                          const ovs_u128 *ufid, const unsigned pmd_id);
static void upcall_uninit(struct upcall *);

static upcall_callback upcall_cb;
static dp_purge_callback dp_purge_cb;

static atomic_bool enable_megaflows = ATOMIC_VAR_INIT(true);
static atomic_bool enable_ufid = ATOMIC_VAR_INIT(true);

void
udpif_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    if (ovsthread_once_start(&once)) {
        unixctl_command_register("upcall/show", "", 0, 0, upcall_unixctl_show,
                                 NULL);
        unixctl_command_register("upcall/disable-megaflows", "", 0, 0,
                                 upcall_unixctl_disable_megaflows, NULL);
        unixctl_command_register("upcall/enable-megaflows", "", 0, 0,
                                 upcall_unixctl_enable_megaflows, NULL);
        unixctl_command_register("upcall/disable-ufid", "", 0, 0,
                                 upcall_unixctl_disable_ufid, NULL);
        unixctl_command_register("upcall/enable-ufid", "", 0, 0,
                                 upcall_unixctl_enable_ufid, NULL);
        unixctl_command_register("upcall/set-flow-limit", "flow-limit-number",
                                 1, 1, upcall_unixctl_set_flow_limit, NULL);
        unixctl_command_register("revalidator/wait", "", 0, 0,
                                 upcall_unixctl_dump_wait, NULL);
        unixctl_command_register("revalidator/purge", "", 0, 0,
                                 upcall_unixctl_purge, NULL);
        ovsthread_once_done(&once);
    }
}

struct udpif *
udpif_create(struct dpif_backer *backer, struct dpif *dpif)
{
    struct udpif *udpif = xzalloc(sizeof *udpif);

    udpif->dpif = dpif;
    udpif->backer = backer;
    atomic_init(&udpif->flow_limit, MIN(ofproto_flow_limit, 10000));
    udpif->reval_seq = seq_create();
    udpif->dump_seq = seq_create();
    latch_init(&udpif->exit_latch);
    latch_init(&udpif->pause_latch);
    ovs_list_push_back(&all_udpifs, &udpif->list_node);
    atomic_init(&udpif->enable_ufid, false);
    atomic_init(&udpif->n_flows, 0);
    atomic_init(&udpif->n_flows_timestamp, LLONG_MIN);
    ovs_mutex_init(&udpif->n_flows_mutex);
    udpif->ukeys = xmalloc(N_UMAPS * sizeof *udpif->ukeys);
    for (int i = 0; i < N_UMAPS; i++) {
        cmap_init(&udpif->ukeys[i].cmap);
        ovs_mutex_init(&udpif->ukeys[i].mutex);
    }

    dpif_register_upcall_cb(dpif, upcall_cb, udpif);
    dpif_register_dp_purge_cb(dpif, dp_purge_cb, udpif);

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

    dpif_register_dp_purge_cb(udpif->dpif, NULL, udpif);
    dpif_register_upcall_cb(udpif->dpif, NULL, udpif);

    for (int i = 0; i < N_UMAPS; i++) {
        cmap_destroy(&udpif->ukeys[i].cmap);
        ovs_mutex_destroy(&udpif->ukeys[i].mutex);
    }
    free(udpif->ukeys);
    udpif->ukeys = NULL;

    ovs_list_remove(&udpif->list_node);
    latch_destroy(&udpif->exit_latch);
    latch_destroy(&udpif->pause_latch);
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
        }

        latch_poll(&udpif->exit_latch);

        ovs_barrier_destroy(&udpif->reval_barrier);
        ovs_barrier_destroy(&udpif->pause_barrier);

        free(udpif->revalidators);
        udpif->revalidators = NULL;
        udpif->n_revalidators = 0;

        free(udpif->handlers);
        udpif->handlers = NULL;
        udpif->n_handlers = 0;
    }
}

/* Starts the handler and revalidator threads, must be enclosed in
 * ovsrcu quiescent state. */
static void
udpif_start_threads(struct udpif *udpif, size_t n_handlers_,
                    size_t n_revalidators_)
{
    if (udpif && n_handlers_ && n_revalidators_) {
        udpif->n_handlers = n_handlers_;
        udpif->n_revalidators = n_revalidators_;

        udpif->handlers = xzalloc(udpif->n_handlers * sizeof *udpif->handlers);
        for (size_t i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            handler->udpif = udpif;
            handler->handler_id = i;
            handler->thread = ovs_thread_create(
                "handler", udpif_upcall_handler, handler);
        }

        atomic_init(&udpif->enable_ufid, udpif->backer->rt_support.ufid);
        dpif_enable_upcall(udpif->dpif);

        ovs_barrier_init(&udpif->reval_barrier, udpif->n_revalidators);
        ovs_barrier_init(&udpif->pause_barrier, udpif->n_revalidators + 1);
        udpif->reval_exit = false;
        udpif->pause = false;
        udpif->revalidators = xzalloc(udpif->n_revalidators
                                      * sizeof *udpif->revalidators);
        for (size_t i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            revalidator->udpif = udpif;
            revalidator->thread = ovs_thread_create(
                "revalidator", udpif_revalidator, revalidator);
        }
    }
}

/* Pauses all revalidators.  Should only be called by the main thread.
 * When function returns, all revalidators are paused and will proceed
 * only after udpif_resume_revalidators() is called. */
static void
udpif_pause_revalidators(struct udpif *udpif)
{
    if (udpif->backer->recv_set_enable) {
        latch_set(&udpif->pause_latch);
        ovs_barrier_block(&udpif->pause_barrier);
    }
}

/* Resumes the pausing of revalidators.  Should only be called by the
 * main thread. */
static void
udpif_resume_revalidators(struct udpif *udpif)
{
    if (udpif->backer->recv_set_enable) {
        latch_poll(&udpif->pause_latch);
        ovs_barrier_block(&udpif->pause_barrier);
    }
}

/* Tells 'udpif' how many threads it should use to handle upcalls.
 * 'n_handlers_' and 'n_revalidators_' can never be zero.  'udpif''s
 * datapath handle must have packet reception enabled before starting
 * threads. */
void
udpif_set_threads(struct udpif *udpif, size_t n_handlers_,
                  size_t n_revalidators_)
{
    ovs_assert(udpif);
    ovs_assert(n_handlers_ && n_revalidators_);

    ovsrcu_quiesce_start();
    if (udpif->n_handlers != n_handlers_
        || udpif->n_revalidators != n_revalidators_) {
        udpif_stop_threads(udpif);
    }

    if (!udpif->handlers && !udpif->revalidators) {
        int error;

        error = dpif_handlers_set(udpif->dpif, n_handlers_);
        if (error) {
            VLOG_ERR("failed to configure handlers in dpif %s: %s",
                     dpif_name(udpif->dpif), ovs_strerror(error));
            return;
        }

        udpif_start_threads(udpif, n_handlers_, n_revalidators_);
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
    size_t n_handlers_ = udpif->n_handlers;
    size_t n_revalidators_ = udpif->n_revalidators;

    ovsrcu_quiesce_start();
    udpif_stop_threads(udpif);
    udpif_start_threads(udpif, n_handlers_, n_revalidators_);
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
    for (i = 0; i < N_UMAPS; i++) {
        simap_increase(usage, "udpif keys", cmap_count(&udpif->ukeys[i].cmap));
    }
}

/* Remove flows from a single datapath. */
void
udpif_flush(struct udpif *udpif)
{
    size_t n_handlers_ = udpif->n_handlers;
    size_t n_revalidators_ = udpif->n_revalidators;

    ovsrcu_quiesce_start();

    udpif_stop_threads(udpif);
    dpif_flow_flush(udpif->dpif);
    udpif_start_threads(udpif, n_handlers_, n_revalidators_);

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

static bool
udpif_use_ufid(struct udpif *udpif)
{
    bool enable;

    atomic_read_relaxed(&enable_ufid, &enable);
    return enable && udpif->backer->rt_support.ufid;
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
        if (recv_upcalls(handler)) {
            poll_immediate_wake();
        } else {
            dpif_recv_wait(udpif->dpif, handler->handler_id);
            latch_wait(&udpif->exit_latch);
        }
        poll_block();
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
        unsigned int mru;
        int error;

        ofpbuf_use_stub(recv_buf, recv_stubs[n_upcalls],
                        sizeof recv_stubs[n_upcalls]);
        if (dpif_recv(udpif->dpif, handler->handler_id, dupcall, recv_buf)) {
            ofpbuf_uninit(recv_buf);
            break;
        }

        upcall->fitness = odp_flow_key_to_flow(dupcall->key, dupcall->key_len,
                                               flow);
        if (upcall->fitness == ODP_FIT_ERROR) {
            goto free_dupcall;
        }

        if (dupcall->mru) {
            mru = nl_attr_get_u16(dupcall->mru);
        } else {
            mru = 0;
        }

        error = upcall_receive(upcall, udpif->backer, &dupcall->packet,
                               dupcall->type, dupcall->userdata, flow, mru,
                               &dupcall->ufid, PMD_ID_NULL);
        if (error) {
            if (error == ENODEV) {
                /* Received packet on datapath port for which we couldn't
                 * associate an ofproto.  This can happen if a port is removed
                 * while traffic is being received.  Print a rate-limited
                 * message in case it happens frequently. */
                dpif_flow_put(udpif->dpif, DPIF_FP_CREATE, dupcall->key,
                              dupcall->key_len, NULL, 0, NULL, 0,
                              &dupcall->ufid, PMD_ID_NULL, NULL);
                VLOG_INFO_RL(&rl, "received packet on unassociated datapath "
                             "port %"PRIu32, flow->in_port.odp_port);
            }
            goto free_dupcall;
        }

        upcall->key = dupcall->key;
        upcall->key_len = dupcall->key_len;
        upcall->ufid = &dupcall->ufid;

        upcall->out_tun_key = dupcall->out_tun_key;
        upcall->actions = dupcall->actions;

        pkt_metadata_from_flow(&dupcall->packet.md, flow);
        flow_extract(&dupcall->packet, flow);

        error = process_upcall(udpif, upcall,
                               &upcall->odp_actions, &upcall->wc);
        if (error) {
            goto cleanup;
        }

        n_upcalls++;
        continue;

cleanup:
        upcall_uninit(upcall);
free_dupcall:
        dp_packet_uninit(&dupcall->packet);
        ofpbuf_uninit(recv_buf);
    }

    if (n_upcalls) {
        handle_upcalls(handler->udpif, upcalls, n_upcalls);
        for (i = 0; i < n_upcalls; i++) {
            dp_packet_uninit(&dupcalls[i].packet);
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

            recirc_run(); /* Recirculation cleanup. */

            reval_seq = seq_read(udpif->reval_seq);
            last_reval_seq = reval_seq;

            n_flows = udpif_get_n_flows(udpif);
            udpif->max_n_flows = MAX(n_flows, udpif->max_n_flows);
            udpif->avg_n_flows = (udpif->avg_n_flows + n_flows) / 2;

            /* Only the leader checks the pause latch to prevent a race where
             * some threads think it's false and proceed to block on
             * reval_barrier and others think it's true and block indefinitely
             * on the pause_barrier */
            udpif->pause = latch_is_set(&udpif->pause_latch);

            /* Only the leader checks the exit latch to prevent a race where
             * some threads think it's true and exit and others think it's
             * false and block indefinitely on the reval_barrier */
            udpif->reval_exit = latch_is_set(&udpif->exit_latch);

            start_time = time_msec();
            if (!udpif->reval_exit) {
                bool terse_dump;

                terse_dump = udpif_use_ufid(udpif);
                udpif->dump = dpif_flow_dump_create(udpif->dpif, terse_dump,
                                                    NULL);
            }
        }

        /* Wait for the leader to start the flow dump. */
        ovs_barrier_block(&udpif->reval_barrier);
        if (udpif->pause) {
            revalidator_pause(revalidator);
        }

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
            latch_wait(&udpif->pause_latch);
            poll_block();

            if (!latch_is_set(&udpif->pause_latch) &&
                !latch_is_set(&udpif->exit_latch)) {
                long long int now = time_msec();
                /* Block again if we are woken up within 5ms of the last start
                 * time. */
                start_time += 5;

                if (now < start_time) {
                    poll_timer_wait_until(start_time);
                    latch_wait(&udpif->exit_latch);
                    latch_wait(&udpif->pause_latch);
                    poll_block();
                }
            }
        }
    }

    return NULL;
}

static enum upcall_type
classify_upcall(enum dpif_upcall_type type, const struct nlattr *userdata,
                struct user_action_cookie *cookie)
{
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

    size_t userdata_len = nl_attr_get_size(userdata);
    if (userdata_len != sizeof *cookie) {
        VLOG_WARN_RL(&rl, "action upcall cookie has unexpected size %"PRIuSIZE,
                     userdata_len);
        return BAD_UPCALL;
    }
    memcpy(cookie, nl_attr_get(userdata), sizeof *cookie);
    if (cookie->type == USER_ACTION_COOKIE_SFLOW) {
        return SFLOW_UPCALL;
    } else if (cookie->type == USER_ACTION_COOKIE_SLOW_PATH) {
        return SLOW_PATH_UPCALL;
    } else if (cookie->type == USER_ACTION_COOKIE_FLOW_SAMPLE) {
        return FLOW_SAMPLE_UPCALL;
    } else if (cookie->type == USER_ACTION_COOKIE_IPFIX) {
        return IPFIX_UPCALL;
    } else if (cookie->type == USER_ACTION_COOKIE_CONTROLLER) {
        return CONTROLLER_UPCALL;
    } else {
        VLOG_WARN_RL(&rl, "invalid user cookie of type %"PRIu16
                     " and size %"PRIuSIZE, cookie->type, userdata_len);
        return BAD_UPCALL;
    }
}

/* Calculates slow path actions for 'xout'.  'buf' must statically be
 * initialized with at least 128 bytes of space. */
static void
compose_slow_path(struct udpif *udpif, struct xlate_out *xout,
                  const struct flow *flow,
                  odp_port_t odp_in_port, ofp_port_t ofp_in_port,
                  struct ofpbuf *buf, uint32_t meter_id,
                  struct uuid *ofproto_uuid)
{
    struct user_action_cookie cookie;
    odp_port_t port;
    uint32_t pid;

    cookie.type = USER_ACTION_COOKIE_SLOW_PATH;
    cookie.ofp_in_port = ofp_in_port;
    cookie.ofproto_uuid = *ofproto_uuid;
    cookie.slow_path.reason = xout->slow;

    port = xout->slow & (SLOW_CFM | SLOW_BFD | SLOW_LACP | SLOW_STP)
        ? ODPP_NONE
        : odp_in_port;
    pid = dpif_port_get_pid(udpif->dpif, port, flow_hash_5tuple(flow, 0));

    size_t offset;
    size_t ac_offset;
    if (meter_id != UINT32_MAX) {
        /* If slowpath meter is configured, generate clone(meter, userspace)
         * action. */
        offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_SAMPLE);
        nl_msg_put_u32(buf, OVS_SAMPLE_ATTR_PROBABILITY, UINT32_MAX);
        ac_offset = nl_msg_start_nested(buf, OVS_SAMPLE_ATTR_ACTIONS);
        nl_msg_put_u32(buf, OVS_ACTION_ATTR_METER, meter_id);
    }

    odp_put_userspace_action(pid, &cookie, sizeof cookie,
                             ODPP_NONE, false, buf);

    if (meter_id != UINT32_MAX) {
        nl_msg_end_nested(buf, ac_offset);
        nl_msg_end_nested(buf, offset);
    }
}

/* If there is no error, the upcall must be destroyed with upcall_uninit()
 * before quiescing, as the referred objects are guaranteed to exist only
 * until the calling thread quiesces.  Otherwise, do not call upcall_uninit()
 * since the 'upcall->put_actions' remains uninitialized. */
static int
upcall_receive(struct upcall *upcall, const struct dpif_backer *backer,
               const struct dp_packet *packet, enum dpif_upcall_type type,
               const struct nlattr *userdata, const struct flow *flow,
               const unsigned int mru,
               const ovs_u128 *ufid, const unsigned pmd_id)
{
    int error;

    upcall->type = classify_upcall(type, userdata, &upcall->cookie);
    if (upcall->type == BAD_UPCALL) {
        return EAGAIN;
    } else if (upcall->type == MISS_UPCALL) {
        error = xlate_lookup(backer, flow, &upcall->ofproto, &upcall->ipfix,
                             &upcall->sflow, NULL, &upcall->ofp_in_port);
        if (error) {
            return error;
        }
    } else {
        struct ofproto_dpif *ofproto
            = ofproto_dpif_lookup_by_uuid(&upcall->cookie.ofproto_uuid);
        if (!ofproto) {
            VLOG_INFO_RL(&rl, "upcall could not find ofproto");
            return ENODEV;
        }
        upcall->ofproto = ofproto;
        upcall->ipfix = ofproto->ipfix;
        upcall->sflow = ofproto->sflow;
        upcall->ofp_in_port = upcall->cookie.ofp_in_port;
    }

    upcall->recirc = NULL;
    upcall->have_recirc_ref = false;
    upcall->flow = flow;
    upcall->packet = packet;
    upcall->ufid = ufid;
    upcall->pmd_id = pmd_id;
    ofpbuf_use_stub(&upcall->odp_actions, upcall->odp_actions_stub,
                    sizeof upcall->odp_actions_stub);
    ofpbuf_init(&upcall->put_actions, 0);

    upcall->xout_initialized = false;
    upcall->ukey_persists = false;

    upcall->ukey = NULL;
    upcall->key = NULL;
    upcall->key_len = 0;
    upcall->mru = mru;

    upcall->out_tun_key = NULL;
    upcall->actions = NULL;

    return 0;
}

static void
upcall_xlate(struct udpif *udpif, struct upcall *upcall,
             struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    struct dpif_flow_stats stats;
    enum xlate_error xerr;
    struct xlate_in xin;
    struct ds output;

    stats.n_packets = 1;
    stats.n_bytes = dp_packet_size(upcall->packet);
    stats.used = time_msec();
    stats.tcp_flags = ntohs(upcall->flow->tcp_flags);

    xlate_in_init(&xin, upcall->ofproto,
                  ofproto_dpif_get_tables_version(upcall->ofproto),
                  upcall->flow, upcall->ofp_in_port, NULL,
                  stats.tcp_flags, upcall->packet, wc, odp_actions);

    if (upcall->type == MISS_UPCALL) {
        xin.resubmit_stats = &stats;

        if (xin.frozen_state) {
            /* We may install a datapath flow only if we get a reference to the
             * recirculation context (otherwise we could have recirculation
             * upcalls using recirculation ID for which no context can be
             * found).  We may still execute the flow's actions even if we
             * don't install the flow. */
            upcall->recirc = recirc_id_node_from_state(xin.frozen_state);
            upcall->have_recirc_ref = recirc_id_node_try_ref_rcu(upcall->recirc);
        }
    } else {
        /* For non-miss upcalls, we are either executing actions (one of which
         * is an userspace action) for an upcall, in which case the stats have
         * already been taken care of, or there's a flow in the datapath which
         * this packet was accounted to.  Presumably the revalidators will deal
         * with pushing its stats eventually. */
    }

    upcall->reval_seq = seq_read(udpif->reval_seq);

    xerr = xlate_actions(&xin, &upcall->xout);

    /* Translate again and log the ofproto trace for
     * these two error types. */
    if (xerr == XLATE_RECURSION_TOO_DEEP ||
        xerr == XLATE_TOO_MANY_RESUBMITS) {
        static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 1);

        /* This is a huge log, so be conservative. */
        if (!VLOG_DROP_WARN(&rll)) {
            ds_init(&output);
            ofproto_trace(upcall->ofproto, upcall->flow,
                          upcall->packet, NULL, 0, NULL, &output);
            VLOG_WARN("%s", ds_cstr(&output));
            ds_destroy(&output);
        }
    }

    if (wc) {
        /* Convert the input port wildcard from OFP to ODP format. There's no
         * real way to do this for arbitrary bitmasks since the numbering spaces
         * aren't the same. However, flow translation always exact matches the
         * whole thing, so we can do the same here. */
        WC_MASK_FIELD(wc, in_port.odp_port);
    }

    upcall->xout_initialized = true;

    if (upcall->fitness == ODP_FIT_TOO_LITTLE) {
        upcall->xout.slow |= SLOW_MATCH;
    }
    if (!upcall->xout.slow) {
        ofpbuf_use_const(&upcall->put_actions,
                         odp_actions->data, odp_actions->size);
    } else {
        /* upcall->put_actions already initialized by upcall_receive(). */
        compose_slow_path(udpif, &upcall->xout, upcall->flow,
                          upcall->flow->in_port.odp_port, upcall->ofp_in_port,
                          &upcall->put_actions,
                          upcall->ofproto->up.slowpath_meter_id,
                          &upcall->ofproto->uuid);
    }

    /* This function is also called for slow-pathed flows.  As we are only
     * going to create new datapath flows for actual datapath misses, there is
     * no point in creating a ukey otherwise. */
    if (upcall->type == MISS_UPCALL) {
        upcall->ukey = ukey_create_from_upcall(upcall, wc);
    }
}

static void
upcall_uninit(struct upcall *upcall)
{
    if (upcall) {
        if (upcall->xout_initialized) {
            xlate_out_uninit(&upcall->xout);
        }
        ofpbuf_uninit(&upcall->odp_actions);
        ofpbuf_uninit(&upcall->put_actions);
        if (upcall->ukey) {
            if (!upcall->ukey_persists) {
                ukey_delete__(upcall->ukey);
            }
        } else if (upcall->have_recirc_ref) {
            /* The reference was transferred to the ukey if one was created. */
            recirc_id_node_unref(upcall->recirc);
        }
    }
}

/* If there are less flows than the limit, and this is a miss upcall which
 *
 *      - Has no recirc_id, OR
 *      - Has a recirc_id and we can get a reference on the recirc ctx,
 *
 * Then we should install the flow (true). Otherwise, return false. */
static bool
should_install_flow(struct udpif *udpif, struct upcall *upcall)
{
    unsigned int flow_limit;

    if (upcall->type != MISS_UPCALL) {
        return false;
    } else if (upcall->recirc && !upcall->have_recirc_ref) {
        VLOG_DBG_RL(&rl, "upcall: no reference for recirc flow");
        return false;
    }

    atomic_read_relaxed(&udpif->flow_limit, &flow_limit);
    if (udpif_get_n_flows(udpif) >= flow_limit) {
        VLOG_WARN_RL(&rl, "upcall: datapath flow limit reached");
        return false;
    }

    return true;
}

static int
upcall_cb(const struct dp_packet *packet, const struct flow *flow, ovs_u128 *ufid,
          unsigned pmd_id, enum dpif_upcall_type type,
          const struct nlattr *userdata, struct ofpbuf *actions,
          struct flow_wildcards *wc, struct ofpbuf *put_actions, void *aux)
{
    struct udpif *udpif = aux;
    struct upcall upcall;
    bool megaflow;
    int error;

    atomic_read_relaxed(&enable_megaflows, &megaflow);

    error = upcall_receive(&upcall, udpif->backer, packet, type, userdata,
                           flow, 0, ufid, pmd_id);
    if (error) {
        return error;
    }

    upcall.fitness = ODP_FIT_PERFECT;
    error = process_upcall(udpif, &upcall, actions, wc);
    if (error) {
        goto out;
    }

    if (upcall.xout.slow && put_actions) {
        ofpbuf_put(put_actions, upcall.put_actions.data,
                   upcall.put_actions.size);
    }

    if (OVS_UNLIKELY(!megaflow && wc)) {
        flow_wildcards_init_for_packet(wc, flow);
    }

    if (!should_install_flow(udpif, &upcall)) {
        error = ENOSPC;
        goto out;
    }

    if (upcall.ukey && !ukey_install(udpif, upcall.ukey)) {
        static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rll, "upcall_cb failure: ukey installation fails");
        error = ENOSPC;
    }
out:
    if (!error) {
        upcall.ukey_persists = true;
    }
    upcall_uninit(&upcall);
    return error;
}

static size_t
dpif_get_actions(struct udpif *udpif, struct upcall *upcall,
                 const struct nlattr **actions)
{
    size_t actions_len = 0;

    if (upcall->actions) {
        /* Actions were passed up from datapath. */
        *actions = nl_attr_get(upcall->actions);
        actions_len = nl_attr_get_size(upcall->actions);
    }

    if (actions_len == 0) {
        /* Lookup actions in userspace cache. */
        struct udpif_key *ukey = ukey_lookup(udpif, upcall->ufid,
                                             upcall->pmd_id);
        if (ukey) {
            ukey_get_actions(ukey, actions, &actions_len);
        }
    }

    return actions_len;
}

static size_t
dpif_read_actions(struct udpif *udpif, struct upcall *upcall,
                  const struct flow *flow, enum upcall_type type,
                  void *upcall_data)
{
    const struct nlattr *actions = NULL;
    size_t actions_len = dpif_get_actions(udpif, upcall, &actions);

    if (!actions || !actions_len) {
        return 0;
    }

    switch (type) {
    case SFLOW_UPCALL:
        dpif_sflow_read_actions(flow, actions, actions_len, upcall_data, true);
        break;
    case FLOW_SAMPLE_UPCALL:
    case IPFIX_UPCALL:
        dpif_ipfix_read_actions(flow, actions, actions_len, upcall_data);
        break;
    case BAD_UPCALL:
    case MISS_UPCALL:
    case SLOW_PATH_UPCALL:
    case CONTROLLER_UPCALL:
    default:
        break;
    }

    return actions_len;
}

static int
process_upcall(struct udpif *udpif, struct upcall *upcall,
               struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    const struct dp_packet *packet = upcall->packet;
    const struct flow *flow = upcall->flow;
    size_t actions_len = 0;

    switch (upcall->type) {
    case MISS_UPCALL:
    case SLOW_PATH_UPCALL:
        upcall_xlate(udpif, upcall, odp_actions, wc);
        return 0;

    case SFLOW_UPCALL:
        if (upcall->sflow) {
            struct dpif_sflow_actions sflow_actions;

            memset(&sflow_actions, 0, sizeof sflow_actions);

            actions_len = dpif_read_actions(udpif, upcall, flow,
                                            upcall->type, &sflow_actions);
            dpif_sflow_received(upcall->sflow, packet, flow,
                                flow->in_port.odp_port, &upcall->cookie,
                                actions_len > 0 ? &sflow_actions : NULL);
        }
        break;

    case IPFIX_UPCALL:
    case FLOW_SAMPLE_UPCALL:
        if (upcall->ipfix) {
            struct flow_tnl output_tunnel_key;
            struct dpif_ipfix_actions ipfix_actions;

            memset(&ipfix_actions, 0, sizeof ipfix_actions);

            if (upcall->out_tun_key) {
                odp_tun_key_from_attr(upcall->out_tun_key, &output_tunnel_key);
            }

            actions_len = dpif_read_actions(udpif, upcall, flow,
                                            upcall->type, &ipfix_actions);
            if (upcall->type == IPFIX_UPCALL) {
                dpif_ipfix_bridge_sample(upcall->ipfix, packet, flow,
                                         flow->in_port.odp_port,
                                         upcall->cookie.ipfix.output_odp_port,
                                         upcall->out_tun_key ?
                                             &output_tunnel_key : NULL,
                                         actions_len > 0 ?
                                             &ipfix_actions: NULL);
            } else {
                /* The flow reflects exactly the contents of the packet.
                 * Sample the packet using it. */
                dpif_ipfix_flow_sample(upcall->ipfix, packet, flow,
                                       &upcall->cookie, flow->in_port.odp_port,
                                       upcall->out_tun_key ?
                                           &output_tunnel_key : NULL,
                                       actions_len > 0 ? &ipfix_actions: NULL);
            }
        }
        break;

    case CONTROLLER_UPCALL:
        {
            struct user_action_cookie *cookie = &upcall->cookie;

            if (cookie->controller.dont_send) {
                return 0;
            }

            uint32_t recirc_id = cookie->controller.recirc_id;
            if (!recirc_id) {
                break;
            }

            const struct recirc_id_node *recirc_node
                                = recirc_id_node_find(recirc_id);
            if (!recirc_node) {
                break;
            }

            const struct frozen_state *state = &recirc_node->state;

            struct ofproto_async_msg *am = xmalloc(sizeof *am);
            *am = (struct ofproto_async_msg) {
                .controller_id = cookie->controller.controller_id,
                .oam = OAM_PACKET_IN,
                .pin = {
                    .up = {
                        .base = {
                            .packet = xmemdup(dp_packet_data(packet),
                                              dp_packet_size(packet)),
                            .packet_len = dp_packet_size(packet),
                            .reason = cookie->controller.reason,
                            .table_id = state->table_id,
                            .cookie = get_32aligned_be64(
                                         &cookie->controller.rule_cookie),
                            .userdata = (recirc_node->state.userdata_len
                                     ? xmemdup(recirc_node->state.userdata,
                                               recirc_node->state.userdata_len)
                                      : NULL),
                            .userdata_len = recirc_node->state.userdata_len,
                        },
                    },
                    .max_len = cookie->controller.max_len,
                },
            };

            if (cookie->controller.continuation) {
                am->pin.up.stack = (state->stack_size
                          ? xmemdup(state->stack, state->stack_size)
                          : NULL),
                am->pin.up.stack_size = state->stack_size,
                am->pin.up.mirrors = state->mirrors,
                am->pin.up.conntracked = state->conntracked,
                am->pin.up.actions = (state->ofpacts_len
                            ? xmemdup(state->ofpacts,
                                      state->ofpacts_len) : NULL),
                am->pin.up.actions_len = state->ofpacts_len,
                am->pin.up.action_set = (state->action_set_len
                               ? xmemdup(state->action_set,
                                         state->action_set_len)
                               : NULL),
                am->pin.up.action_set_len = state->action_set_len,
                am->pin.up.bridge = upcall->ofproto->uuid;
            }

            /* We don't want to use the upcall 'flow', since it may be
             * more specific than the point at which the "controller"
             * action was specified. */
            struct flow frozen_flow;

            frozen_flow = *flow;
            if (!state->conntracked) {
                flow_clear_conntrack(&frozen_flow);
            }

            frozen_metadata_to_flow(&state->metadata, &frozen_flow);
            flow_get_metadata(&frozen_flow, &am->pin.up.base.flow_metadata);

            ofproto_dpif_send_async_msg(upcall->ofproto, am);
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
    struct dpif_op *opsp[UPCALL_MAX_BATCH * 2];
    struct ukey_op ops[UPCALL_MAX_BATCH * 2];
    size_t n_ops, n_opsp, i;

    /* Handle the packets individually in order of arrival.
     *
     *   - For SLOW_CFM, SLOW_LACP, SLOW_STP, SLOW_BFD, and SLOW_LLDP,
     *     translation is what processes received packets for these
     *     protocols.
     *
     *   - For SLOW_ACTION, translation executes the actions directly.
     *
     * The loop fills 'ops' with an array of operations to execute in the
     * datapath. */
    n_ops = 0;
    for (i = 0; i < n_upcalls; i++) {
        struct upcall *upcall = &upcalls[i];
        const struct dp_packet *packet = upcall->packet;
        struct ukey_op *op;

        if (should_install_flow(udpif, upcall)) {
            struct udpif_key *ukey = upcall->ukey;

            if (ukey_install(udpif, ukey)) {
                upcall->ukey_persists = true;
                put_op_init(&ops[n_ops++], ukey, DPIF_FP_CREATE);
            }
        }

        if (upcall->odp_actions.size) {
            op = &ops[n_ops++];
            op->ukey = NULL;
            op->dop.type = DPIF_OP_EXECUTE;
            op->dop.execute.packet = CONST_CAST(struct dp_packet *, packet);
            op->dop.execute.flow = upcall->flow;
            odp_key_to_dp_packet(upcall->key, upcall->key_len,
                                 op->dop.execute.packet);
            op->dop.execute.actions = upcall->odp_actions.data;
            op->dop.execute.actions_len = upcall->odp_actions.size;
            op->dop.execute.needs_help = (upcall->xout.slow & SLOW_ACTION) != 0;
            op->dop.execute.probe = false;
            op->dop.execute.mtu = upcall->mru;
        }
    }

    /* Execute batch. */
    n_opsp = 0;
    for (i = 0; i < n_ops; i++) {
        opsp[n_opsp++] = &ops[i].dop;
    }
    dpif_operate(udpif->dpif, opsp, n_opsp);
    for (i = 0; i < n_ops; i++) {
        struct udpif_key *ukey = ops[i].ukey;

        if (ukey) {
            ovs_mutex_lock(&ukey->mutex);
            if (ops[i].dop.error) {
                transition_ukey(ukey, UKEY_EVICTED);
            } else if (ukey->state < UKEY_OPERATIONAL) {
                transition_ukey(ukey, UKEY_OPERATIONAL);
            }
            ovs_mutex_unlock(&ukey->mutex);
        }
    }
}

static uint32_t
get_ukey_hash(const ovs_u128 *ufid, const unsigned pmd_id)
{
    return hash_2words(ufid->u32[0], pmd_id);
}

static struct udpif_key *
ukey_lookup(struct udpif *udpif, const ovs_u128 *ufid, const unsigned pmd_id)
{
    struct udpif_key *ukey;
    int idx = get_ukey_hash(ufid, pmd_id) % N_UMAPS;
    struct cmap *cmap = &udpif->ukeys[idx].cmap;

    CMAP_FOR_EACH_WITH_HASH (ukey, cmap_node,
                             get_ukey_hash(ufid, pmd_id), cmap) {
        if (ovs_u128_equals(ukey->ufid, *ufid)) {
            return ukey;
        }
    }
    return NULL;
}

/* Provides safe lockless access of RCU protected 'ukey->actions'.  Callers may
 * alternatively access the field directly if they take 'ukey->mutex'. */
static void
ukey_get_actions(struct udpif_key *ukey, const struct nlattr **actions, size_t *size)
{
    const struct ofpbuf *buf = ovsrcu_get(struct ofpbuf *, &ukey->actions);
    *actions = buf->data;
    *size = buf->size;
}

static void
ukey_set_actions(struct udpif_key *ukey, const struct ofpbuf *actions)
{
    struct ofpbuf *old_actions = ovsrcu_get_protected(struct ofpbuf *,
                                                      &ukey->actions);

    if (old_actions) {
        ovsrcu_postpone(ofpbuf_delete, old_actions);
    }

    ovsrcu_set(&ukey->actions, ofpbuf_clone(actions));
}

static struct udpif_key *
ukey_create__(const struct nlattr *key, size_t key_len,
              const struct nlattr *mask, size_t mask_len,
              bool ufid_present, const ovs_u128 *ufid,
              const unsigned pmd_id, const struct ofpbuf *actions,
              uint64_t reval_seq, long long int used,
              uint32_t key_recirc_id, struct xlate_out *xout)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct udpif_key *ukey = xmalloc(sizeof *ukey);

    memcpy(&ukey->keybuf, key, key_len);
    ukey->key = &ukey->keybuf.nla;
    ukey->key_len = key_len;
    memcpy(&ukey->maskbuf, mask, mask_len);
    ukey->mask = &ukey->maskbuf.nla;
    ukey->mask_len = mask_len;
    ukey->ufid_present = ufid_present;
    ukey->ufid = *ufid;
    ukey->pmd_id = pmd_id;
    ukey->hash = get_ukey_hash(&ukey->ufid, pmd_id);

    ovsrcu_init(&ukey->actions, NULL);
    ukey_set_actions(ukey, actions);

    ovs_mutex_init(&ukey->mutex);
    ukey->dump_seq = 0;     /* Not yet dumped */
    ukey->reval_seq = reval_seq;
    ukey->state = UKEY_CREATED;
    ukey->state_thread = ovsthread_id_self();
    ukey->state_where = OVS_SOURCE_LOCATOR;
    ukey->created = time_msec();
    memset(&ukey->stats, 0, sizeof ukey->stats);
    ukey->stats.used = used;
    ukey->xcache = NULL;

    ukey->key_recirc_id = key_recirc_id;
    recirc_refs_init(&ukey->recircs);
    if (xout) {
        /* Take ownership of the action recirc id references. */
        recirc_refs_swap(&ukey->recircs, &xout->recircs);
    }

    return ukey;
}

static struct udpif_key *
ukey_create_from_upcall(struct upcall *upcall, struct flow_wildcards *wc)
{
    struct odputil_keybuf keystub, maskstub;
    struct ofpbuf keybuf, maskbuf;
    bool megaflow;
    struct odp_flow_key_parms odp_parms = {
        .flow = upcall->flow,
        .mask = wc ? &wc->masks : NULL,
    };

    odp_parms.support = upcall->ofproto->backer->rt_support.odp;
    if (upcall->key_len) {
        ofpbuf_use_const(&keybuf, upcall->key, upcall->key_len);
    } else {
        /* dpif-netdev doesn't provide a netlink-formatted flow key in the
         * upcall, so convert the upcall's flow here. */
        ofpbuf_use_stack(&keybuf, &keystub, sizeof keystub);
        odp_flow_key_from_flow(&odp_parms, &keybuf);
    }

    atomic_read_relaxed(&enable_megaflows, &megaflow);
    ofpbuf_use_stack(&maskbuf, &maskstub, sizeof maskstub);
    if (megaflow && wc) {
        odp_parms.key_buf = &keybuf;
        odp_flow_key_from_mask(&odp_parms, &maskbuf);
    }

    return ukey_create__(keybuf.data, keybuf.size, maskbuf.data, maskbuf.size,
                         true, upcall->ufid, upcall->pmd_id,
                         &upcall->put_actions, upcall->reval_seq, 0,
                         upcall->have_recirc_ref ? upcall->recirc->id : 0,
                         &upcall->xout);
}

static int
ukey_create_from_dpif_flow(const struct udpif *udpif,
                           const struct dpif_flow *flow,
                           struct udpif_key **ukey)
{
    struct dpif_flow full_flow;
    struct ofpbuf actions;
    uint64_t reval_seq;
    uint64_t stub[DPIF_FLOW_BUFSIZE / 8];
    const struct nlattr *a;
    unsigned int left;

    if (!flow->key_len || !flow->actions_len) {
        struct ofpbuf buf;
        int err;

        /* If the key or actions were not provided by the datapath, fetch the
         * full flow. */
        ofpbuf_use_stack(&buf, &stub, sizeof stub);
        err = dpif_flow_get(udpif->dpif, flow->key, flow->key_len,
                            flow->ufid_present ? &flow->ufid : NULL,
                            flow->pmd_id, &buf, &full_flow);
        if (err) {
            return err;
        }
        flow = &full_flow;
    }

    /* Check the flow actions for recirculation action.  As recirculation
     * relies on OVS userspace internal state, we need to delete all old
     * datapath flows with either a non-zero recirc_id in the key, or any
     * recirculation actions upon OVS restart. */
    NL_ATTR_FOR_EACH (a, left, flow->key, flow->key_len) {
        if (nl_attr_type(a) == OVS_KEY_ATTR_RECIRC_ID
            && nl_attr_get_u32(a) != 0) {
            return EINVAL;
        }
    }
    NL_ATTR_FOR_EACH (a, left, flow->actions, flow->actions_len) {
        if (nl_attr_type(a) == OVS_ACTION_ATTR_RECIRC) {
            return EINVAL;
        }
    }

    reval_seq = seq_read(udpif->reval_seq) - 1; /* Ensure revalidation. */
    ofpbuf_use_const(&actions, &flow->actions, flow->actions_len);
    *ukey = ukey_create__(flow->key, flow->key_len,
                          flow->mask, flow->mask_len, flow->ufid_present,
                          &flow->ufid, flow->pmd_id, &actions,
                          reval_seq, flow->stats.used, 0, NULL);

    return 0;
}

static bool
try_ukey_replace(struct umap *umap, struct udpif_key *old_ukey,
                 struct udpif_key *new_ukey)
    OVS_REQUIRES(umap->mutex)
    OVS_TRY_LOCK(true, new_ukey->mutex)
{
    bool replaced = false;

    if (!ovs_mutex_trylock(&old_ukey->mutex)) {
        if (old_ukey->state == UKEY_EVICTED) {
            /* The flow was deleted during the current revalidator dump,
             * but its ukey won't be fully cleaned up until the sweep phase.
             * In the mean time, we are receiving upcalls for this traffic.
             * Expedite the (new) flow install by replacing the ukey. */
            ovs_mutex_lock(&new_ukey->mutex);
            cmap_replace(&umap->cmap, &old_ukey->cmap_node,
                         &new_ukey->cmap_node, new_ukey->hash);
            ovsrcu_postpone(ukey_delete__, old_ukey);
            transition_ukey(old_ukey, UKEY_DELETED);
            transition_ukey(new_ukey, UKEY_VISIBLE);
            replaced = true;
        }
        ovs_mutex_unlock(&old_ukey->mutex);
    }

    if (replaced) {
        COVERAGE_INC(upcall_ukey_replace);
    } else {
        COVERAGE_INC(handler_duplicate_upcall);
    }
    return replaced;
}

/* Attempts to insert a ukey into the shared ukey maps.
 *
 * On success, returns true, installs the ukey and returns it in a locked
 * state. Otherwise, returns false. */
static bool
ukey_install__(struct udpif *udpif, struct udpif_key *new_ukey)
    OVS_TRY_LOCK(true, new_ukey->mutex)
{
    struct umap *umap;
    struct udpif_key *old_ukey;
    uint32_t idx;
    bool locked = false;

    idx = new_ukey->hash % N_UMAPS;
    umap = &udpif->ukeys[idx];
    ovs_mutex_lock(&umap->mutex);
    old_ukey = ukey_lookup(udpif, &new_ukey->ufid, new_ukey->pmd_id);
    if (old_ukey) {
        /* Uncommon case: A ukey is already installed with the same UFID. */
        if (old_ukey->key_len == new_ukey->key_len
            && !memcmp(old_ukey->key, new_ukey->key, new_ukey->key_len)) {
            locked = try_ukey_replace(umap, old_ukey, new_ukey);
        } else {
            struct ds ds = DS_EMPTY_INITIALIZER;

            odp_format_ufid(&old_ukey->ufid, &ds);
            ds_put_cstr(&ds, " ");
            odp_flow_key_format(old_ukey->key, old_ukey->key_len, &ds);
            ds_put_cstr(&ds, "\n");
            odp_format_ufid(&new_ukey->ufid, &ds);
            ds_put_cstr(&ds, " ");
            odp_flow_key_format(new_ukey->key, new_ukey->key_len, &ds);

            VLOG_WARN_RL(&rl, "Conflicting ukey for flows:\n%s", ds_cstr(&ds));
            ds_destroy(&ds);
        }
    } else {
        ovs_mutex_lock(&new_ukey->mutex);
        cmap_insert(&umap->cmap, &new_ukey->cmap_node, new_ukey->hash);
        transition_ukey(new_ukey, UKEY_VISIBLE);
        locked = true;
    }
    ovs_mutex_unlock(&umap->mutex);

    return locked;
}

static void
transition_ukey_at(struct udpif_key *ukey, enum ukey_state dst,
                   const char *where)
    OVS_REQUIRES(ukey->mutex)
{
    if (dst < ukey->state) {
        VLOG_ABORT("Invalid ukey transition %d->%d (last transitioned from "
                   "thread %u at %s)", ukey->state, dst, ukey->state_thread,
                   ukey->state_where);
    }
    if (ukey->state == dst && dst == UKEY_OPERATIONAL) {
        return;
    }

    /* Valid state transitions:
     * UKEY_CREATED -> UKEY_VISIBLE
     *  Ukey is now visible in the umap.
     * UKEY_VISIBLE -> UKEY_OPERATIONAL
     *  A handler has installed the flow, and the flow is in the datapath.
     * UKEY_VISIBLE -> UKEY_EVICTING
     *  A handler installs the flow, then revalidator sweeps the ukey before
     *  the flow is dumped. Most likely the flow was installed; start trying
     *  to delete it.
     * UKEY_VISIBLE -> UKEY_EVICTED
     *  A handler attempts to install the flow, but the datapath rejects it.
     *  Consider that the datapath has already destroyed it.
     * UKEY_OPERATIONAL -> UKEY_EVICTING
     *  A revalidator decides to evict the datapath flow.
     * UKEY_EVICTING    -> UKEY_EVICTED
     *  A revalidator has evicted the datapath flow.
     * UKEY_EVICTED     -> UKEY_DELETED
     *  A revalidator has removed the ukey from the umap and is deleting it.
     */
    if (ukey->state == dst - 1 || (ukey->state == UKEY_VISIBLE &&
                                   dst < UKEY_DELETED)) {
        ukey->state = dst;
    } else {
        struct ds ds = DS_EMPTY_INITIALIZER;

        odp_format_ufid(&ukey->ufid, &ds);
        VLOG_WARN_RL(&rl, "Invalid state transition for ukey %s: %d -> %d",
                     ds_cstr(&ds), ukey->state, dst);
        ds_destroy(&ds);
    }
    ukey->state_thread = ovsthread_id_self();
    ukey->state_where = where;
}

static bool
ukey_install(struct udpif *udpif, struct udpif_key *ukey)
{
    bool installed;

    installed = ukey_install__(udpif, ukey);
    if (installed) {
        ovs_mutex_unlock(&ukey->mutex);
    }

    return installed;
}

/* Searches for a ukey in 'udpif->ukeys' that matches 'flow' and attempts to
 * lock the ukey. If the ukey does not exist, create it.
 *
 * Returns 0 on success, setting *result to the matching ukey and returning it
 * in a locked state. Otherwise, returns an errno and clears *result. EBUSY
 * indicates that another thread is handling this flow. Other errors indicate
 * an unexpected condition creating a new ukey.
 *
 * *error is an output parameter provided to appease the threadsafety analyser,
 * and its value matches the return value. */
static int
ukey_acquire(struct udpif *udpif, const struct dpif_flow *flow,
             struct udpif_key **result, int *error)
    OVS_TRY_LOCK(0, (*result)->mutex)
{
    struct udpif_key *ukey;
    int retval;

    ukey = ukey_lookup(udpif, &flow->ufid, flow->pmd_id);
    if (ukey) {
        retval = ovs_mutex_trylock(&ukey->mutex);
    } else {
        /* Usually we try to avoid installing flows from revalidator threads,
         * because locking on a umap may cause handler threads to block.
         * However there are certain cases, like when ovs-vswitchd is
         * restarted, where it is desirable to handle flows that exist in the
         * datapath gracefully (ie, don't just clear the datapath). */
        bool install;

        retval = ukey_create_from_dpif_flow(udpif, flow, &ukey);
        if (retval) {
            goto done;
        }
        install = ukey_install__(udpif, ukey);
        if (install) {
            retval = 0;
        } else {
            ukey_delete__(ukey);
            retval = EBUSY;
        }
    }

done:
    *error = retval;
    if (retval) {
        *result = NULL;
    } else {
        *result = ukey;
    }
    return retval;
}

static void
ukey_delete__(struct udpif_key *ukey)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    if (ukey) {
        if (ukey->key_recirc_id) {
            recirc_free_id(ukey->key_recirc_id);
        }
        recirc_refs_unref(&ukey->recircs);
        xlate_cache_delete(ukey->xcache);
        ofpbuf_delete(ovsrcu_get(struct ofpbuf *, &ukey->actions));
        ovs_mutex_destroy(&ukey->mutex);
        free(ukey);
    }
}

static void
ukey_delete(struct umap *umap, struct udpif_key *ukey)
    OVS_REQUIRES(umap->mutex)
{
    ovs_mutex_lock(&ukey->mutex);
    if (ukey->state < UKEY_DELETED) {
        cmap_remove(&umap->cmap, &ukey->cmap_node, ukey->hash);
        ovsrcu_postpone(ukey_delete__, ukey);
        transition_ukey(ukey, UKEY_DELETED);
    }
    ovs_mutex_unlock(&ukey->mutex);
}

static bool
should_revalidate(const struct udpif *udpif, uint64_t packets,
                  long long int used)
{
    long long int metric, now, duration;

    if (!used) {
        /* Always revalidate the first time a flow is dumped. */
        return true;
    }

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

struct reval_context {
    /* Optional output parameters */
    struct flow_wildcards *wc;
    struct ofpbuf *odp_actions;
    struct netflow **netflow;
    struct xlate_cache *xcache;

    /* Required output parameters */
    struct xlate_out xout;
    struct flow flow;
};

/* Translates 'key' into a flow, populating 'ctx' as it goes along.
 *
 * Returns 0 on success, otherwise a positive errno value.
 *
 * The caller is responsible for uninitializing ctx->xout on success.
 */
static int
xlate_key(struct udpif *udpif, const struct nlattr *key, unsigned int len,
          const struct dpif_flow_stats *push, struct reval_context *ctx)
{
    struct ofproto_dpif *ofproto;
    ofp_port_t ofp_in_port;
    enum odp_key_fitness fitness;
    struct xlate_in xin;
    int error;

    fitness = odp_flow_key_to_flow(key, len, &ctx->flow);
    if (fitness == ODP_FIT_ERROR) {
        return EINVAL;
    }

    error = xlate_lookup(udpif->backer, &ctx->flow, &ofproto, NULL, NULL,
                         ctx->netflow, &ofp_in_port);
    if (error) {
        return error;
    }

    xlate_in_init(&xin, ofproto, ofproto_dpif_get_tables_version(ofproto),
                  &ctx->flow, ofp_in_port, NULL, push->tcp_flags,
                  NULL, ctx->wc, ctx->odp_actions);
    if (push->n_packets) {
        xin.resubmit_stats = push;
        xin.allow_side_effects = true;
    }
    xin.xcache = ctx->xcache;
    xlate_actions(&xin, &ctx->xout);
    if (fitness == ODP_FIT_TOO_LITTLE) {
        ctx->xout.slow |= SLOW_MATCH;
    }

    return 0;
}

static int
xlate_ukey(struct udpif *udpif, const struct udpif_key *ukey,
           uint16_t tcp_flags, struct reval_context *ctx)
{
    struct dpif_flow_stats push = {
        .tcp_flags = tcp_flags,
    };
    return xlate_key(udpif, ukey->key, ukey->key_len, &push, ctx);
}

static int
populate_xcache(struct udpif *udpif, struct udpif_key *ukey,
                uint16_t tcp_flags)
    OVS_REQUIRES(ukey->mutex)
{
    struct reval_context ctx = {
        .odp_actions = NULL,
        .netflow = NULL,
        .wc = NULL,
    };
    int error;

    ovs_assert(!ukey->xcache);
    ukey->xcache = ctx.xcache = xlate_cache_new();
    error = xlate_ukey(udpif, ukey, tcp_flags, &ctx);
    if (error) {
        return error;
    }
    xlate_out_uninit(&ctx.xout);

    return 0;
}

static enum reval_result
revalidate_ukey__(struct udpif *udpif, const struct udpif_key *ukey,
                  uint16_t tcp_flags, struct ofpbuf *odp_actions,
                  struct recirc_refs *recircs, struct xlate_cache *xcache)
{
    struct xlate_out *xoutp;
    struct netflow *netflow;
    struct flow_wildcards dp_mask, wc;
    enum reval_result result;
    struct reval_context ctx = {
        .odp_actions = odp_actions,
        .netflow = &netflow,
        .xcache = xcache,
        .wc = &wc,
    };

    result = UKEY_DELETE;
    xoutp = NULL;
    netflow = NULL;

    if (xlate_ukey(udpif, ukey, tcp_flags, &ctx)) {
        goto exit;
    }
    xoutp = &ctx.xout;

    if (xoutp->avoid_caching) {
        goto exit;
    }

    if (xoutp->slow) {
        struct ofproto_dpif *ofproto;
        ofp_port_t ofp_in_port;

        ofproto = xlate_lookup_ofproto(udpif->backer, &ctx.flow, &ofp_in_port);

        ofpbuf_clear(odp_actions);

        if (!ofproto) {
            goto exit;
        }

        compose_slow_path(udpif, xoutp, &ctx.flow, ctx.flow.in_port.odp_port,
                          ofp_in_port, odp_actions,
                          ofproto->up.slowpath_meter_id, &ofproto->uuid);
    }

    if (odp_flow_key_to_mask(ukey->mask, ukey->mask_len, &dp_mask, &ctx.flow)
        == ODP_FIT_ERROR) {
        goto exit;
    }

    /* Do not modify if any bit is wildcarded by the installed datapath flow,
     * but not the newly revalidated wildcard mask (wc), i.e., if revalidation
     * tells that the datapath flow is now too generic and must be narrowed
     * down.  Note that we do not know if the datapath has ignored any of the
     * wildcarded bits, so we may be overly conservative here. */
    if (flow_wildcards_has_extra(&dp_mask, ctx.wc)) {
        goto exit;
    }

    if (!ofpbuf_equal(odp_actions,
                      ovsrcu_get(struct ofpbuf *, &ukey->actions))) {
        /* The datapath mask was OK, but the actions seem to have changed.
         * Let's modify it in place. */
        result = UKEY_MODIFY;
        /* Transfer recirc action ID references to the caller. */
        recirc_refs_swap(recircs, &xoutp->recircs);
        goto exit;
    }

    result = UKEY_KEEP;

exit:
    if (netflow && result == UKEY_DELETE) {
        netflow_flow_clear(netflow, &ctx.flow);
    }
    xlate_out_uninit(xoutp);
    return result;
}

/* Verifies that the datapath actions of 'ukey' are still correct, and pushes
 * 'stats' for it.
 *
 * Returns a recommended action for 'ukey', options include:
 *      UKEY_DELETE The ukey should be deleted.
 *      UKEY_KEEP   The ukey is fine as is.
 *      UKEY_MODIFY The ukey's actions should be changed but is otherwise
 *                  fine.  Callers should change the actions to those found
 *                  in the caller supplied 'odp_actions' buffer.  The
 *                  recirculation references can be found in 'recircs' and
 *                  must be handled by the caller.
 *
 * If the result is UKEY_MODIFY, then references to all recirc_ids used by the
 * new flow will be held within 'recircs' (which may be none).
 *
 * The caller is responsible for both initializing 'recircs' prior this call,
 * and ensuring any references are eventually freed.
 */
static enum reval_result
revalidate_ukey(struct udpif *udpif, struct udpif_key *ukey,
                const struct dpif_flow_stats *stats,
                struct ofpbuf *odp_actions, uint64_t reval_seq,
                struct recirc_refs *recircs)
    OVS_REQUIRES(ukey->mutex)
{
    bool need_revalidate = ukey->reval_seq != reval_seq;
    enum reval_result result = UKEY_DELETE;
    struct dpif_flow_stats push;

    ofpbuf_clear(odp_actions);

    push.used = stats->used;
    push.tcp_flags = stats->tcp_flags;
    push.n_packets = (stats->n_packets > ukey->stats.n_packets
                      ? stats->n_packets - ukey->stats.n_packets
                      : 0);
    push.n_bytes = (stats->n_bytes > ukey->stats.n_bytes
                    ? stats->n_bytes - ukey->stats.n_bytes
                    : 0);

    if (need_revalidate) {
        if (should_revalidate(udpif, push.n_packets, ukey->stats.used)) {
            if (!ukey->xcache) {
                ukey->xcache = xlate_cache_new();
            } else {
                xlate_cache_clear(ukey->xcache);
            }
            result = revalidate_ukey__(udpif, ukey, push.tcp_flags,
                                       odp_actions, recircs, ukey->xcache);
        } /* else delete; too expensive to revalidate */
    } else if (!push.n_packets || ukey->xcache
               || !populate_xcache(udpif, ukey, push.tcp_flags)) {
        result = UKEY_KEEP;
    }

    /* Stats for deleted flows will be attributed upon flow deletion. Skip. */
    if (result != UKEY_DELETE) {
        xlate_push_stats(ukey->xcache, &push);
        ukey->stats = *stats;
        ukey->reval_seq = reval_seq;
    }

    return result;
}

static void
delete_op_init__(struct udpif *udpif, struct ukey_op *op,
                 const struct dpif_flow *flow)
{
    op->ukey = NULL;
    op->dop.type = DPIF_OP_FLOW_DEL;
    op->dop.flow_del.key = flow->key;
    op->dop.flow_del.key_len = flow->key_len;
    op->dop.flow_del.ufid = flow->ufid_present ? &flow->ufid : NULL;
    op->dop.flow_del.pmd_id = flow->pmd_id;
    op->dop.flow_del.stats = &op->stats;
    op->dop.flow_del.terse = udpif_use_ufid(udpif);
}

static void
delete_op_init(struct udpif *udpif, struct ukey_op *op, struct udpif_key *ukey)
{
    op->ukey = ukey;
    op->dop.type = DPIF_OP_FLOW_DEL;
    op->dop.flow_del.key = ukey->key;
    op->dop.flow_del.key_len = ukey->key_len;
    op->dop.flow_del.ufid = ukey->ufid_present ? &ukey->ufid : NULL;
    op->dop.flow_del.pmd_id = ukey->pmd_id;
    op->dop.flow_del.stats = &op->stats;
    op->dop.flow_del.terse = udpif_use_ufid(udpif);
}

static void
put_op_init(struct ukey_op *op, struct udpif_key *ukey,
            enum dpif_flow_put_flags flags)
{
    op->ukey = ukey;
    op->dop.type = DPIF_OP_FLOW_PUT;
    op->dop.flow_put.flags = flags;
    op->dop.flow_put.key = ukey->key;
    op->dop.flow_put.key_len = ukey->key_len;
    op->dop.flow_put.mask = ukey->mask;
    op->dop.flow_put.mask_len = ukey->mask_len;
    op->dop.flow_put.ufid = ukey->ufid_present ? &ukey->ufid : NULL;
    op->dop.flow_put.pmd_id = ukey->pmd_id;
    op->dop.flow_put.stats = NULL;
    ukey_get_actions(ukey, &op->dop.flow_put.actions,
                     &op->dop.flow_put.actions_len);
}

/* Executes datapath operations 'ops' and attributes stats retrieved from the
 * datapath as part of those operations. */
static void
push_dp_ops(struct udpif *udpif, struct ukey_op *ops, size_t n_ops)
{
    struct dpif_op *opsp[REVALIDATE_MAX_BATCH];
    size_t i;

    ovs_assert(n_ops <= REVALIDATE_MAX_BATCH);
    for (i = 0; i < n_ops; i++) {
        opsp[i] = &ops[i].dop;
    }
    dpif_operate(udpif->dpif, opsp, n_ops);

    for (i = 0; i < n_ops; i++) {
        struct ukey_op *op = &ops[i];
        struct dpif_flow_stats *push, *stats, push_buf;

        stats = op->dop.flow_del.stats;
        push = &push_buf;

        if (op->dop.type != DPIF_OP_FLOW_DEL) {
            /* Only deleted flows need their stats pushed. */
            continue;
        }

        if (op->dop.error) {
            /* flow_del error, 'stats' is unusable. */
            if (op->ukey) {
                ovs_mutex_lock(&op->ukey->mutex);
                transition_ukey(op->ukey, UKEY_EVICTED);
                ovs_mutex_unlock(&op->ukey->mutex);
            }
            continue;
        }

        if (op->ukey) {
            ovs_mutex_lock(&op->ukey->mutex);
            transition_ukey(op->ukey, UKEY_EVICTED);
            push->used = MAX(stats->used, op->ukey->stats.used);
            push->tcp_flags = stats->tcp_flags | op->ukey->stats.tcp_flags;
            push->n_packets = stats->n_packets - op->ukey->stats.n_packets;
            push->n_bytes = stats->n_bytes - op->ukey->stats.n_bytes;
            ovs_mutex_unlock(&op->ukey->mutex);
        } else {
            push = stats;
        }

        if (push->n_packets || netflow_exists()) {
            const struct nlattr *key = op->dop.flow_del.key;
            size_t key_len = op->dop.flow_del.key_len;
            struct netflow *netflow;
            struct reval_context ctx = {
                .netflow = &netflow,
            };
            int error;

            if (op->ukey) {
                ovs_mutex_lock(&op->ukey->mutex);
                if (op->ukey->xcache) {
                    xlate_push_stats(op->ukey->xcache, push);
                    ovs_mutex_unlock(&op->ukey->mutex);
                    continue;
                }
                ovs_mutex_unlock(&op->ukey->mutex);
                key = op->ukey->key;
                key_len = op->ukey->key_len;
            }

            error = xlate_key(udpif, key, key_len, push, &ctx);
            if (error) {
                static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rll, "xlate_key failed (%s)!",
                             ovs_strerror(error));
            } else {
                xlate_out_uninit(&ctx.xout);
                if (netflow) {
                    netflow_flow_clear(netflow, &ctx.flow);
                }
            }
        }
    }
}

/* Executes datapath operations 'ops', attributes stats retrieved from the
 * datapath, and deletes ukeys corresponding to deleted flows. */
static void
push_ukey_ops(struct udpif *udpif, struct umap *umap,
              struct ukey_op *ops, size_t n_ops)
{
    int i;

    push_dp_ops(udpif, ops, n_ops);
    ovs_mutex_lock(&umap->mutex);
    for (i = 0; i < n_ops; i++) {
        if (ops[i].dop.type == DPIF_OP_FLOW_DEL) {
            ukey_delete(umap, ops[i].ukey);
        }
    }
    ovs_mutex_unlock(&umap->mutex);
}

static void
log_unexpected_flow(const struct dpif_flow *flow, int error)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "Failed to acquire udpif_key corresponding to "
                  "unexpected flow (%s): ", ovs_strerror(error));
    odp_format_ufid(&flow->ufid, &ds);

    static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(10, 60);
    VLOG_WARN_RL(&rll, "%s", ds_cstr(&ds));

    ds_destroy(&ds);
}

static void
reval_op_init(struct ukey_op *op, enum reval_result result,
              struct udpif *udpif, struct udpif_key *ukey,
              struct recirc_refs *recircs, struct ofpbuf *odp_actions)
    OVS_REQUIRES(ukey->mutex)
{
    if (result == UKEY_DELETE) {
        delete_op_init(udpif, op, ukey);
        transition_ukey(ukey, UKEY_EVICTING);
    } else if (result == UKEY_MODIFY) {
        /* Store the new recircs. */
        recirc_refs_swap(&ukey->recircs, recircs);
        /* Release old recircs. */
        recirc_refs_unref(recircs);
        /* ukey->key_recirc_id remains, as the key is the same as before. */

        ukey_set_actions(ukey, odp_actions);
        put_op_init(op, ukey, DPIF_FP_MODIFY);
    }
}

static void
revalidate(struct revalidator *revalidator)
{
    uint64_t odp_actions_stub[1024 / 8];
    struct ofpbuf odp_actions = OFPBUF_STUB_INITIALIZER(odp_actions_stub);

    struct udpif *udpif = revalidator->udpif;
    struct dpif_flow_dump_thread *dump_thread;
    uint64_t dump_seq, reval_seq;
    unsigned int flow_limit;

    dump_seq = seq_read(udpif->dump_seq);
    reval_seq = seq_read(udpif->reval_seq);
    atomic_read_relaxed(&udpif->flow_limit, &flow_limit);
    dump_thread = dpif_flow_dump_thread_create(udpif->dump);
    for (;;) {
        struct ukey_op ops[REVALIDATE_MAX_BATCH];
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
            struct recirc_refs recircs = RECIRC_REFS_EMPTY_INITIALIZER;
            enum reval_result result;
            struct udpif_key *ukey;
            bool already_dumped;
            int error;

            if (ukey_acquire(udpif, f, &ukey, &error)) {
                if (error == EBUSY) {
                    /* Another thread is processing this flow, so don't bother
                     * processing it.*/
                    COVERAGE_INC(upcall_ukey_contention);
                } else {
                    log_unexpected_flow(f, error);
                    if (error != ENOENT) {
                        delete_op_init__(udpif, &ops[n_ops++], f);
                    }
                }
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

            if (ukey->state <= UKEY_OPERATIONAL) {
                /* The flow is now confirmed to be in the datapath. */
                transition_ukey(ukey, UKEY_OPERATIONAL);
            } else {
                VLOG_INFO("Unexpected ukey transition from state %d "
                          "(last transitioned from thread %u at %s)",
                          ukey->state, ukey->state_thread, ukey->state_where);
                ovs_mutex_unlock(&ukey->mutex);
                continue;
            }

            if (!used) {
                used = ukey->created;
            }
            if (kill_them_all || (used && used < now - max_idle)) {
                result = UKEY_DELETE;
            } else {
                result = revalidate_ukey(udpif, ukey, &f->stats, &odp_actions,
                                         reval_seq, &recircs);
            }
            ukey->dump_seq = dump_seq;

            if (result != UKEY_KEEP) {
                /* Takes ownership of 'recircs'. */
                reval_op_init(&ops[n_ops++], result, udpif, ukey, &recircs,
                              &odp_actions);
            }
            ovs_mutex_unlock(&ukey->mutex);
        }

        if (n_ops) {
            /* Push datapath ops but defer ukey deletion to 'sweep' phase. */
            push_dp_ops(udpif, ops, n_ops);
        }
        ovsrcu_quiesce();
    }
    dpif_flow_dump_thread_destroy(dump_thread);
    ofpbuf_uninit(&odp_actions);
}

/* Pauses the 'revalidator', can only proceed after main thread
 * calls udpif_resume_revalidators(). */
static void
revalidator_pause(struct revalidator *revalidator)
{
    /* The first block is for sync'ing the pause with main thread. */
    ovs_barrier_block(&revalidator->udpif->pause_barrier);
    /* The second block is for pausing until main thread resumes. */
    ovs_barrier_block(&revalidator->udpif->pause_barrier);
}

static void
revalidator_sweep__(struct revalidator *revalidator, bool purge)
{
    struct udpif *udpif;
    uint64_t dump_seq, reval_seq;
    int slice;

    udpif = revalidator->udpif;
    dump_seq = seq_read(udpif->dump_seq);
    reval_seq = seq_read(udpif->reval_seq);
    slice = revalidator - udpif->revalidators;
    ovs_assert(slice < udpif->n_revalidators);

    for (int i = slice; i < N_UMAPS; i += udpif->n_revalidators) {
        uint64_t odp_actions_stub[1024 / 8];
        struct ofpbuf odp_actions = OFPBUF_STUB_INITIALIZER(odp_actions_stub);

        struct ukey_op ops[REVALIDATE_MAX_BATCH];
        struct udpif_key *ukey;
        struct umap *umap = &udpif->ukeys[i];
        size_t n_ops = 0;

        CMAP_FOR_EACH(ukey, cmap_node, &umap->cmap) {
            enum ukey_state ukey_state;

            /* Handler threads could be holding a ukey lock while it installs a
             * new flow, so don't hang around waiting for access to it. */
            if (ovs_mutex_trylock(&ukey->mutex)) {
                continue;
            }
            ukey_state = ukey->state;
            if (ukey_state == UKEY_OPERATIONAL
                || (ukey_state == UKEY_VISIBLE && purge)) {
                struct recirc_refs recircs = RECIRC_REFS_EMPTY_INITIALIZER;
                bool seq_mismatch = (ukey->dump_seq != dump_seq
                                     && ukey->reval_seq != reval_seq);
                enum reval_result result;

                if (purge) {
                    result = UKEY_DELETE;
                } else if (!seq_mismatch) {
                    result = UKEY_KEEP;
                } else {
                    struct dpif_flow_stats stats;
                    COVERAGE_INC(revalidate_missed_dp_flow);
                    memset(&stats, 0, sizeof stats);
                    result = revalidate_ukey(udpif, ukey, &stats, &odp_actions,
                                             reval_seq, &recircs);
                }
                if (result != UKEY_KEEP) {
                    /* Clears 'recircs' if filled by revalidate_ukey(). */
                    reval_op_init(&ops[n_ops++], result, udpif, ukey, &recircs,
                                  &odp_actions);
                }
            }
            ovs_mutex_unlock(&ukey->mutex);

            if (ukey_state == UKEY_EVICTED) {
                /* The common flow deletion case involves deletion of the flow
                 * during the dump phase and ukey deletion here. */
                ovs_mutex_lock(&umap->mutex);
                ukey_delete(umap, ukey);
                ovs_mutex_unlock(&umap->mutex);
            }

            if (n_ops == REVALIDATE_MAX_BATCH) {
                /* Update/delete missed flows and clean up corresponding ukeys
                 * if necessary. */
                push_ukey_ops(udpif, umap, ops, n_ops);
                n_ops = 0;
            }
        }

        if (n_ops) {
            push_ukey_ops(udpif, umap, ops, n_ops);
        }

        ofpbuf_uninit(&odp_actions);
        ovsrcu_quiesce();
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

/* In reaction to dpif purge, purges all 'ukey's with same 'pmd_id'. */
static void
dp_purge_cb(void *aux, unsigned pmd_id)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct udpif *udpif = aux;
    size_t i;

    udpif_pause_revalidators(udpif);
    for (i = 0; i < N_UMAPS; i++) {
        struct ukey_op ops[REVALIDATE_MAX_BATCH];
        struct udpif_key *ukey;
        struct umap *umap = &udpif->ukeys[i];
        size_t n_ops = 0;

        CMAP_FOR_EACH(ukey, cmap_node, &umap->cmap) {
            if (ukey->pmd_id == pmd_id) {
                delete_op_init(udpif, &ops[n_ops++], ukey);
                transition_ukey(ukey, UKEY_EVICTING);

                if (n_ops == REVALIDATE_MAX_BATCH) {
                    push_ukey_ops(udpif, umap, ops, n_ops);
                    n_ops = 0;
                }
            }
        }

        if (n_ops) {
            push_ukey_ops(udpif, umap, ops, n_ops);
        }

        ovsrcu_quiesce();
    }
    udpif_resume_revalidators(udpif);
}

static void
upcall_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct udpif *udpif;

    LIST_FOR_EACH (udpif, list_node, &all_udpifs) {
        unsigned int flow_limit;
        bool ufid_enabled;
        size_t i;

        atomic_read_relaxed(&udpif->flow_limit, &flow_limit);
        ufid_enabled = udpif_use_ufid(udpif);

        ds_put_format(&ds, "%s:\n", dpif_name(udpif->dpif));
        ds_put_format(&ds, "\tflows         : (current %lu)"
            " (avg %u) (max %u) (limit %u)\n", udpif_get_n_flows(udpif),
            udpif->avg_n_flows, udpif->max_n_flows, flow_limit);
        ds_put_format(&ds, "\tdump duration : %lldms\n", udpif->dump_duration);
        ds_put_format(&ds, "\tufid enabled : ");
        if (ufid_enabled) {
            ds_put_format(&ds, "true\n");
        } else {
            ds_put_format(&ds, "false\n");
        }
        ds_put_char(&ds, '\n');

        for (i = 0; i < n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];
            int j, elements = 0;

            for (j = i; j < N_UMAPS; j += n_revalidators) {
                elements += cmap_count(&udpif->ukeys[j].cmap);
            }
            ds_put_format(&ds, "\t%u: (keys %d)\n", revalidator->id, elements);
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

/* Disable skipping flow attributes during flow dump.
 *
 * This command is only needed for advanced debugging, so it's not
 * documented in the man page. */
static void
upcall_unixctl_disable_ufid(struct unixctl_conn *conn, int argc OVS_UNUSED,
                           const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    atomic_store_relaxed(&enable_ufid, false);
    unixctl_command_reply(conn, "Datapath dumping tersely using UFID disabled");
}

/* Re-enable skipping flow attributes during flow dump.
 *
 * This command is only needed for advanced debugging, so it's not documented
 * in the man page. */
static void
upcall_unixctl_enable_ufid(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    atomic_store_relaxed(&enable_ufid, true);
    unixctl_command_reply(conn, "Datapath dumping tersely using UFID enabled "
                                "for supported datapaths");
}

/* Set the flow limit.
 *
 * This command is only needed for advanced debugging, so it's not
 * documented in the man page. */
static void
upcall_unixctl_set_flow_limit(struct unixctl_conn *conn,
                              int argc OVS_UNUSED,
                              const char *argv[],
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
    if (ovs_list_is_singleton(&all_udpifs)) {
        struct udpif *udpif = NULL;
        size_t len;

        udpif = OBJECT_CONTAINING(ovs_list_front(&all_udpifs), udpif, list_node);
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
