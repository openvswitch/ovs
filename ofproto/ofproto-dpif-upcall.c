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
#include "packets.h"
#include "poll-loop.h"
#include "seq.h"
#include "unixctl.h"
#include "vlog.h"

#define MAX_QUEUE_LENGTH 512
#define FLOW_MISS_MAX_BATCH 50
#define REVALIDATE_MAX_BATCH 50
#define MAX_IDLE 1500

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_upcall);

COVERAGE_DEFINE(upcall_queue_overflow);

/* A thread that processes each upcall handed to it by the dispatcher thread,
 * forwards the upcall's packet, and possibly sets up a kernel flow as a
 * cache. */
struct handler {
    struct udpif *udpif;               /* Parent udpif. */
    pthread_t thread;                  /* Thread ID. */
    char *name;                        /* Thread name. */

    struct ovs_mutex mutex;            /* Mutex guarding the following. */

    /* Atomic queue of unprocessed upcalls. */
    struct list upcalls OVS_GUARDED;
    size_t n_upcalls OVS_GUARDED;

    bool need_signal;                  /* Only changed by the dispatcher. */

    pthread_cond_t wake_cond;          /* Wakes 'thread' while holding
                                          'mutex'. */
};

/* A thread that processes each kernel flow handed to it by the flow_dumper
 * thread, updates OpenFlow statistics, and updates or removes the kernel flow
 * as necessary. */
struct revalidator {
    struct udpif *udpif;               /* Parent udpif. */
    char *name;                        /* Thread name. */

    pthread_t thread;                  /* Thread ID. */
    struct hmap ukeys;                 /* Datapath flow keys. */

    uint64_t dump_seq;

    struct ovs_mutex mutex;            /* Mutex guarding the following. */
    pthread_cond_t wake_cond;
    struct list udumps OVS_GUARDED;    /* Unprocessed udumps. */
    size_t n_udumps OVS_GUARDED;       /* Number of unprocessed udumps. */
};

/* An upcall handler for ofproto_dpif.
 *
 * udpif has two logically separate pieces:
 *
 *    - A "dispatcher" thread that reads upcalls from the kernel and dispatches
 *      them to one of several "handler" threads (see struct handler).
 *
 *    - A "flow_dumper" thread that reads the kernel flow table and dispatches
 *      flows to one of several "revalidator" threads (see struct
 *      revalidator). */
struct udpif {
    struct list list_node;             /* In all_udpifs list. */

    struct dpif *dpif;                 /* Datapath handle. */
    struct dpif_backer *backer;        /* Opaque dpif_backer pointer. */

    uint32_t secret;                   /* Random seed for upcall hash. */

    pthread_t dispatcher;              /* Dispatcher thread ID. */
    pthread_t flow_dumper;             /* Flow dumper thread ID. */

    struct handler *handlers;          /* Upcall handlers. */
    size_t n_handlers;

    struct revalidator *revalidators;  /* Flow revalidators. */
    size_t n_revalidators;

    uint64_t last_reval_seq;           /* 'reval_seq' at last revalidation. */
    struct seq *reval_seq;             /* Incremented to force revalidation. */

    struct seq *dump_seq;              /* Increments each dump iteration. */

    struct latch exit_latch;           /* Tells child threads to exit. */

    long long int dump_duration;       /* Duration of the last flow dump. */

    /* Datapath flow statistics. */
    unsigned int max_n_flows;
    unsigned int avg_n_flows;

    atomic_uint flow_limit;            /* Datapath flow hard limit. */

    /* n_flows_mutex prevents multiple threads updating these concurrently. */
    atomic_uint64_t n_flows;           /* Number of flows in the datapath. */
    atomic_llong n_flows_timestamp;    /* Last time n_flows was updated. */
    struct ovs_mutex n_flows_mutex;
};

enum upcall_type {
    BAD_UPCALL,                 /* Some kind of bug somewhere. */
    MISS_UPCALL,                /* A flow miss.  */
    SFLOW_UPCALL,               /* sFlow sample. */
    FLOW_SAMPLE_UPCALL,         /* Per-flow sampling. */
    IPFIX_UPCALL                /* Per-bridge sampling. */
};

struct upcall {
    struct list list_node;          /* For queuing upcalls. */
    struct flow_miss *flow_miss;    /* This upcall's flow_miss. */

    /* Raw upcall plus data for keeping track of the memory backing it. */
    struct dpif_upcall dpif_upcall; /* As returned by dpif_recv() */
    struct ofpbuf upcall_buf;       /* Owns some data in 'dpif_upcall'. */
    uint64_t upcall_stub[512 / 8];  /* Buffer to reduce need for malloc(). */
};

/* 'udpif_key's are responsible for tracking the little bit of state udpif
 * needs to do flow expiration which can't be pulled directly from the
 * datapath.  They are owned, created by, maintained, and destroyed by a single
 * revalidator making them easy to efficiently handle with multiple threads. */
struct udpif_key {
    struct hmap_node hmap_node;     /* In parent revalidator 'ukeys' map. */

    struct nlattr *key;            /* Datapath flow key. */
    size_t key_len;                /* Length of 'key'. */

    struct dpif_flow_stats stats;  /* Stats at most recent flow dump. */
    long long int created;         /* Estimation of creation time. */

    bool mark;                     /* Used by mark and sweep GC algorithm. */

    struct odputil_keybuf key_buf; /* Memory for 'key'. */
};

/* 'udpif_flow_dump's hold the state associated with one iteration in a flow
 * dump operation.  This is created by the flow_dumper thread and handed to the
 * appropriate revalidator thread to be processed. */
struct udpif_flow_dump {
    struct list list_node;

    struct nlattr *key;            /* Datapath flow key. */
    size_t key_len;                /* Length of 'key'. */
    uint32_t key_hash;             /* Hash of 'key'. */

    struct odputil_keybuf mask_buf;
    struct nlattr *mask;           /* Datapath mask for 'key'. */
    size_t mask_len;               /* Length of 'mask'. */

    struct dpif_flow_stats stats;  /* Stats pulled from the datapath. */

    bool need_revalidate;          /* Key needs revalidation? */

    struct odputil_keybuf key_buf;
};

/* Flow miss batching.
 *
 * Some dpifs implement operations faster when you hand them off in a batch.
 * To allow batching, "struct flow_miss" queues the dpif-related work needed
 * for a given flow.  Each "struct flow_miss" corresponds to sending one or
 * more packets, plus possibly installing the flow in the dpif. */
struct flow_miss {
    struct hmap_node hmap_node;
    struct ofproto_dpif *ofproto;

    struct flow flow;
    enum odp_key_fitness key_fitness;
    const struct nlattr *key;
    size_t key_len;
    enum dpif_upcall_type upcall_type;
    struct dpif_flow_stats stats;
    odp_port_t odp_in_port;

    uint64_t slow_path_buf[128 / 8];
    struct odputil_keybuf mask_buf;

    struct xlate_out xout;

    bool put;
};

static void upcall_destroy(struct upcall *);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct list all_udpifs = LIST_INITIALIZER(&all_udpifs);

static void recv_upcalls(struct udpif *);
static void handle_upcalls(struct handler *handler, struct list *upcalls);
static void *udpif_flow_dumper(void *);
static void *udpif_dispatcher(void *);
static void *udpif_upcall_handler(void *);
static void *udpif_revalidator(void *);
static uint64_t udpif_get_n_flows(struct udpif *);
static void revalidate_udumps(struct revalidator *, struct list *udumps);
static void revalidator_sweep(struct revalidator *);
static void revalidator_purge(struct revalidator *);
static void upcall_unixctl_show(struct unixctl_conn *conn, int argc,
                                const char *argv[], void *aux);
static void upcall_unixctl_disable_megaflows(struct unixctl_conn *, int argc,
                                             const char *argv[], void *aux);
static void upcall_unixctl_enable_megaflows(struct unixctl_conn *, int argc,
                                            const char *argv[], void *aux);
static void ukey_delete(struct revalidator *, struct udpif_key *);

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

    return udpif;
}

void
udpif_destroy(struct udpif *udpif)
{
    udpif_set_threads(udpif, 0, 0);
    udpif_flush();

    list_remove(&udpif->list_node);
    latch_destroy(&udpif->exit_latch);
    seq_destroy(udpif->reval_seq);
    seq_destroy(udpif->dump_seq);
    ovs_mutex_destroy(&udpif->n_flows_mutex);
    free(udpif);
}

/* Tells 'udpif' how many threads it should use to handle upcalls.  Disables
 * all threads if 'n_handlers' and 'n_revalidators' is zero.  'udpif''s
 * datapath handle must have packet reception enabled before starting threads.
 */
void
udpif_set_threads(struct udpif *udpif, size_t n_handlers,
                  size_t n_revalidators)
{
    /* Stop the old threads (if any). */
    if (udpif->handlers &&
        (udpif->n_handlers != n_handlers
         || udpif->n_revalidators != n_revalidators)) {
        size_t i;

        latch_set(&udpif->exit_latch);

        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            ovs_mutex_lock(&handler->mutex);
            xpthread_cond_signal(&handler->wake_cond);
            ovs_mutex_unlock(&handler->mutex);
            xpthread_join(handler->thread, NULL);
        }

        for (i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            ovs_mutex_lock(&revalidator->mutex);
            xpthread_cond_signal(&revalidator->wake_cond);
            ovs_mutex_unlock(&revalidator->mutex);
            xpthread_join(revalidator->thread, NULL);
        }

        xpthread_join(udpif->flow_dumper, NULL);
        xpthread_join(udpif->dispatcher, NULL);

        for (i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];
            struct udpif_flow_dump *udump, *next_udump;

            LIST_FOR_EACH_SAFE (udump, next_udump, list_node,
                                &revalidator->udumps) {
                list_remove(&udump->list_node);
                free(udump);
            }

            /* Delete ukeys, and delete all flows from the datapath to prevent
             * double-counting stats. */
            revalidator_purge(revalidator);
            hmap_destroy(&revalidator->ukeys);
            ovs_mutex_destroy(&revalidator->mutex);

            free(revalidator->name);
        }

        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];
            struct upcall *miss, *next;

            LIST_FOR_EACH_SAFE (miss, next, list_node, &handler->upcalls) {
                list_remove(&miss->list_node);
                upcall_destroy(miss);
            }
            ovs_mutex_destroy(&handler->mutex);

            xpthread_cond_destroy(&handler->wake_cond);
            free(handler->name);
        }
        latch_poll(&udpif->exit_latch);

        free(udpif->revalidators);
        udpif->revalidators = NULL;
        udpif->n_revalidators = 0;

        free(udpif->handlers);
        udpif->handlers = NULL;
        udpif->n_handlers = 0;
    }

    /* Start new threads (if necessary). */
    if (!udpif->handlers && n_handlers) {
        size_t i;

        udpif->n_handlers = n_handlers;
        udpif->n_revalidators = n_revalidators;

        udpif->handlers = xzalloc(udpif->n_handlers * sizeof *udpif->handlers);
        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            handler->udpif = udpif;
            list_init(&handler->upcalls);
            handler->need_signal = false;
            xpthread_cond_init(&handler->wake_cond, NULL);
            ovs_mutex_init(&handler->mutex);
            xpthread_create(&handler->thread, NULL, udpif_upcall_handler,
                            handler);
        }

        udpif->revalidators = xzalloc(udpif->n_revalidators
                                      * sizeof *udpif->revalidators);
        for (i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            revalidator->udpif = udpif;
            list_init(&revalidator->udumps);
            hmap_init(&revalidator->ukeys);
            ovs_mutex_init(&revalidator->mutex);
            xpthread_cond_init(&revalidator->wake_cond, NULL);
            xpthread_create(&revalidator->thread, NULL, udpif_revalidator,
                            revalidator);
        }
        xpthread_create(&udpif->dispatcher, NULL, udpif_dispatcher, udpif);
        xpthread_create(&udpif->flow_dumper, NULL, udpif_flow_dumper, udpif);
    }
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
    udpif_set_threads(udpif, 0, 0);
    udpif_set_threads(udpif, n_handlers, n_revalidators);
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

    simap_increase(usage, "dispatchers", 1);
    simap_increase(usage, "flow_dumpers", 1);

    simap_increase(usage, "handlers", udpif->n_handlers);
    for (i = 0; i < udpif->n_handlers; i++) {
        struct handler *handler = &udpif->handlers[i];
        ovs_mutex_lock(&handler->mutex);
        simap_increase(usage, "handler upcalls",  handler->n_upcalls);
        ovs_mutex_unlock(&handler->mutex);
    }

    simap_increase(usage, "revalidators", udpif->n_revalidators);
    for (i = 0; i < udpif->n_revalidators; i++) {
        struct revalidator *revalidator = &udpif->revalidators[i];
        ovs_mutex_lock(&revalidator->mutex);
        simap_increase(usage, "revalidator dumps", revalidator->n_udumps);

        /* XXX: This isn't technically thread safe because the revalidator
         * ukeys maps isn't protected by a mutex since it's per thread. */
        simap_increase(usage, "revalidator keys",
                       hmap_count(&revalidator->ukeys));
        ovs_mutex_unlock(&revalidator->mutex);
    }
}

/* Removes all flows from all datapaths. */
void
udpif_flush(void)
{
    struct udpif *udpif;

    LIST_FOR_EACH (udpif, list_node, &all_udpifs) {
        dpif_flow_flush(udpif->dpif);
    }
}

/* Destroys and deallocates 'upcall'. */
static void
upcall_destroy(struct upcall *upcall)
{
    if (upcall) {
        ofpbuf_uninit(&upcall->dpif_upcall.packet);
        ofpbuf_uninit(&upcall->upcall_buf);
        free(upcall);
    }
}

static uint64_t
udpif_get_n_flows(struct udpif *udpif)
{
    long long int time, now;
    uint64_t flow_count;

    now = time_msec();
    atomic_read(&udpif->n_flows_timestamp, &time);
    if (time < now - 100 && !ovs_mutex_trylock(&udpif->n_flows_mutex)) {
        struct dpif_dp_stats stats;

        atomic_store(&udpif->n_flows_timestamp, now);
        dpif_get_dp_stats(udpif->dpif, &stats);
        flow_count = stats.n_flows;
        atomic_store(&udpif->n_flows, flow_count);
        ovs_mutex_unlock(&udpif->n_flows_mutex);
    } else {
        atomic_read(&udpif->n_flows, &flow_count);
    }
    return flow_count;
}

/* The dispatcher thread is responsible for receiving upcalls from the kernel,
 * assigning them to a upcall_handler thread. */
static void *
udpif_dispatcher(void *arg)
{
    struct udpif *udpif = arg;

    set_subprogram_name("dispatcher");
    while (!latch_is_set(&udpif->exit_latch)) {
        recv_upcalls(udpif);
        dpif_recv_wait(udpif->dpif);
        latch_wait(&udpif->exit_latch);
        poll_block();
    }

    return NULL;
}

static void *
udpif_flow_dumper(void *arg)
{
    struct udpif *udpif = arg;

    set_subprogram_name("flow_dumper");
    while (!latch_is_set(&udpif->exit_latch)) {
        const struct dpif_flow_stats *stats;
        long long int start_time, duration;
        const struct nlattr *key, *mask;
        struct dpif_flow_dump dump;
        size_t key_len, mask_len;
        unsigned int flow_limit;
        bool need_revalidate;
        uint64_t reval_seq;
        size_t n_flows, i;

        reval_seq = seq_read(udpif->reval_seq);
        need_revalidate = udpif->last_reval_seq != reval_seq;
        udpif->last_reval_seq = reval_seq;

        n_flows = udpif_get_n_flows(udpif);
        udpif->max_n_flows = MAX(n_flows, udpif->max_n_flows);
        udpif->avg_n_flows = (udpif->avg_n_flows + n_flows) / 2;

        start_time = time_msec();
        dpif_flow_dump_start(&dump, udpif->dpif);
        while (dpif_flow_dump_next(&dump, &key, &key_len, &mask, &mask_len,
                                   NULL, NULL, &stats)
               && !latch_is_set(&udpif->exit_latch)) {
            struct udpif_flow_dump *udump = xmalloc(sizeof *udump);
            struct revalidator *revalidator;

            udump->key_hash = hash_bytes(key, key_len, udpif->secret);
            memcpy(&udump->key_buf, key, key_len);
            udump->key = (struct nlattr *) &udump->key_buf;
            udump->key_len = key_len;

            memcpy(&udump->mask_buf, mask, mask_len);
            udump->mask = (struct nlattr *) &udump->mask_buf;
            udump->mask_len = mask_len;

            udump->stats = *stats;
            udump->need_revalidate = need_revalidate;

            revalidator = &udpif->revalidators[udump->key_hash
                % udpif->n_revalidators];

            ovs_mutex_lock(&revalidator->mutex);
            while (revalidator->n_udumps >= REVALIDATE_MAX_BATCH * 3
                   && !latch_is_set(&udpif->exit_latch)) {
                ovs_mutex_cond_wait(&revalidator->wake_cond,
                                    &revalidator->mutex);
            }
            list_push_back(&revalidator->udumps, &udump->list_node);
            revalidator->n_udumps++;
            xpthread_cond_signal(&revalidator->wake_cond);
            ovs_mutex_unlock(&revalidator->mutex);
        }
        dpif_flow_dump_done(&dump);

        /* Let all the revalidators finish and garbage collect. */
        seq_change(udpif->dump_seq);
        for (i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];
            ovs_mutex_lock(&revalidator->mutex);
            xpthread_cond_signal(&revalidator->wake_cond);
            ovs_mutex_unlock(&revalidator->mutex);
        }

        for (i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            ovs_mutex_lock(&revalidator->mutex);
            while (revalidator->dump_seq != seq_read(udpif->dump_seq)
                   && !latch_is_set(&udpif->exit_latch)) {
                ovs_mutex_cond_wait(&revalidator->wake_cond,
                                    &revalidator->mutex);
            }
            ovs_mutex_unlock(&revalidator->mutex);
        }

        duration = MAX(time_msec() - start_time, 1);
        udpif->dump_duration = duration;
        atomic_read(&udpif->flow_limit, &flow_limit);
        if (duration > 2000) {
            flow_limit /= duration / 1000;
        } else if (duration > 1300) {
            flow_limit = flow_limit * 3 / 4;
        } else if (duration < 1000 && n_flows > 2000
                   && flow_limit < n_flows * 1000 / duration) {
            flow_limit += 1000;
        }
        flow_limit = MIN(ofproto_flow_limit, MAX(flow_limit, 1000));
        atomic_store(&udpif->flow_limit, flow_limit);

        if (duration > 2000) {
            VLOG_INFO("Spent an unreasonably long %lldms dumping flows",
                      duration);
        }

        poll_timer_wait_until(start_time + MIN(MAX_IDLE, 500));
        seq_wait(udpif->reval_seq, udpif->last_reval_seq);
        latch_wait(&udpif->exit_latch);
        poll_block();
    }

    return NULL;
}

/* The miss handler thread is responsible for processing miss upcalls retrieved
 * by the dispatcher thread.  Once finished it passes the processed miss
 * upcalls to ofproto-dpif where they're installed in the datapath. */
static void *
udpif_upcall_handler(void *arg)
{
    struct handler *handler = arg;

    handler->name = xasprintf("handler_%u", ovsthread_id_self());
    set_subprogram_name("%s", handler->name);

    for (;;) {
        struct list misses = LIST_INITIALIZER(&misses);
        size_t i;

        ovs_mutex_lock(&handler->mutex);

        if (latch_is_set(&handler->udpif->exit_latch)) {
            ovs_mutex_unlock(&handler->mutex);
            return NULL;
        }

        if (!handler->n_upcalls) {
            ovs_mutex_cond_wait(&handler->wake_cond, &handler->mutex);
        }

        for (i = 0; i < FLOW_MISS_MAX_BATCH; i++) {
            if (handler->n_upcalls) {
                handler->n_upcalls--;
                list_push_back(&misses, list_pop_front(&handler->upcalls));
            } else {
                break;
            }
        }
        ovs_mutex_unlock(&handler->mutex);

        handle_upcalls(handler, &misses);

        coverage_clear();
    }
}

static void *
udpif_revalidator(void *arg)
{
    struct revalidator *revalidator = arg;

    revalidator->name = xasprintf("revalidator_%u", ovsthread_id_self());
    set_subprogram_name("%s", revalidator->name);
    for (;;) {
        struct list udumps = LIST_INITIALIZER(&udumps);
        struct udpif *udpif = revalidator->udpif;
        size_t i;

        ovs_mutex_lock(&revalidator->mutex);
        if (latch_is_set(&udpif->exit_latch)) {
            ovs_mutex_unlock(&revalidator->mutex);
            return NULL;
        }

        if (!revalidator->n_udumps) {
            if (revalidator->dump_seq != seq_read(udpif->dump_seq)) {
                revalidator->dump_seq = seq_read(udpif->dump_seq);
                revalidator_sweep(revalidator);
            } else {
                ovs_mutex_cond_wait(&revalidator->wake_cond,
                                    &revalidator->mutex);
            }
        }

        for (i = 0; i < REVALIDATE_MAX_BATCH && revalidator->n_udumps; i++) {
            list_push_back(&udumps, list_pop_front(&revalidator->udumps));
            revalidator->n_udumps--;
        }

        /* Wake up the flow dumper. */
        xpthread_cond_signal(&revalidator->wake_cond);
        ovs_mutex_unlock(&revalidator->mutex);

        if (!list_is_empty(&udumps)) {
            revalidate_udumps(revalidator, &udumps);
        }
    }

    return NULL;
}

static enum upcall_type
classify_upcall(const struct upcall *upcall)
{
    const struct dpif_upcall *dpif_upcall = &upcall->dpif_upcall;
    union user_action_cookie cookie;
    size_t userdata_len;

    /* First look at the upcall type. */
    switch (dpif_upcall->type) {
    case DPIF_UC_ACTION:
        break;

    case DPIF_UC_MISS:
        return MISS_UPCALL;

    case DPIF_N_UC_TYPES:
    default:
        VLOG_WARN_RL(&rl, "upcall has unexpected type %"PRIu32,
                     dpif_upcall->type);
        return BAD_UPCALL;
    }

    /* "action" upcalls need a closer look. */
    if (!dpif_upcall->userdata) {
        VLOG_WARN_RL(&rl, "action upcall missing cookie");
        return BAD_UPCALL;
    }
    userdata_len = nl_attr_get_size(dpif_upcall->userdata);
    if (userdata_len < sizeof cookie.type
        || userdata_len > sizeof cookie) {
        VLOG_WARN_RL(&rl, "action upcall cookie has unexpected size %"PRIuSIZE,
                     userdata_len);
        return BAD_UPCALL;
    }
    memset(&cookie, 0, sizeof cookie);
    memcpy(&cookie, nl_attr_get(dpif_upcall->userdata), userdata_len);
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

static void
recv_upcalls(struct udpif *udpif)
{
    int n;

    for (;;) {
        uint32_t hash = udpif->secret;
        struct handler *handler;
        struct upcall *upcall;
        size_t n_bytes, left;
        struct nlattr *nla;
        int error;

        upcall = xmalloc(sizeof *upcall);
        ofpbuf_use_stub(&upcall->upcall_buf, upcall->upcall_stub,
                        sizeof upcall->upcall_stub);
        error = dpif_recv(udpif->dpif, &upcall->dpif_upcall,
                          &upcall->upcall_buf);
        if (error) {
            /* upcall_destroy() can only be called on successfully received
             * upcalls. */
            ofpbuf_uninit(&upcall->upcall_buf);
            free(upcall);
            break;
        }

        n_bytes = 0;
        NL_ATTR_FOR_EACH (nla, left, upcall->dpif_upcall.key,
                          upcall->dpif_upcall.key_len) {
            enum ovs_key_attr type = nl_attr_type(nla);
            if (type == OVS_KEY_ATTR_IN_PORT
                || type == OVS_KEY_ATTR_TCP
                || type == OVS_KEY_ATTR_UDP) {
                if (nl_attr_get_size(nla) == 4) {
                    hash = mhash_add(hash, nl_attr_get_u32(nla));
                    n_bytes += 4;
                } else {
                    VLOG_WARN_RL(&rl,
                                 "Netlink attribute with incorrect size.");
                }
            }
        }
        hash =  mhash_finish(hash, n_bytes);

        handler = &udpif->handlers[hash % udpif->n_handlers];

        ovs_mutex_lock(&handler->mutex);
        if (handler->n_upcalls < MAX_QUEUE_LENGTH) {
            list_push_back(&handler->upcalls, &upcall->list_node);
            if (handler->n_upcalls == 0) {
                handler->need_signal = true;
            }
            handler->n_upcalls++;
            if (handler->need_signal &&
                handler->n_upcalls >= FLOW_MISS_MAX_BATCH) {
                handler->need_signal = false;
                xpthread_cond_signal(&handler->wake_cond);
            }
            ovs_mutex_unlock(&handler->mutex);
            if (!VLOG_DROP_DBG(&rl)) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                odp_flow_key_format(upcall->dpif_upcall.key,
                                    upcall->dpif_upcall.key_len,
                                    &ds);
                VLOG_DBG("dispatcher: enqueue (%s)", ds_cstr(&ds));
                ds_destroy(&ds);
            }
        } else {
            ovs_mutex_unlock(&handler->mutex);
            COVERAGE_INC(upcall_queue_overflow);
            upcall_destroy(upcall);
        }
    }

    for (n = 0; n < udpif->n_handlers; ++n) {
        struct handler *handler = &udpif->handlers[n];

        if (handler->need_signal) {
            handler->need_signal = false;
            ovs_mutex_lock(&handler->mutex);
            xpthread_cond_signal(&handler->wake_cond);
            ovs_mutex_unlock(&handler->mutex);
        }
    }
}

/* Calculates slow path actions for 'xout'.  'buf' must statically be
 * initialized with at least 128 bytes of space. */
static void
compose_slow_path(struct udpif *udpif, struct xlate_out *xout,
                  odp_port_t odp_in_port, struct ofpbuf *buf)
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
    pid = dpif_port_get_pid(udpif->dpif, port);
    odp_put_userspace_action(pid, &cookie, sizeof cookie.slow_path, buf);
}

static struct flow_miss *
flow_miss_find(struct hmap *todo, const struct ofproto_dpif *ofproto,
               const struct flow *flow, uint32_t hash)
{
    struct flow_miss *miss;

    HMAP_FOR_EACH_WITH_HASH (miss, hmap_node, hash, todo) {
        if (miss->ofproto == ofproto && flow_equal(&miss->flow, flow)) {
            return miss;
        }
    }

    return NULL;
}

static void
handle_upcalls(struct handler *handler, struct list *upcalls)
{
    struct hmap misses = HMAP_INITIALIZER(&misses);
    struct udpif *udpif = handler->udpif;

    struct flow_miss miss_buf[FLOW_MISS_MAX_BATCH];
    struct dpif_op *opsp[FLOW_MISS_MAX_BATCH * 2];
    struct dpif_op ops[FLOW_MISS_MAX_BATCH * 2];
    struct flow_miss *miss, *next_miss;
    struct upcall *upcall, *next;
    size_t n_misses, n_ops, i;
    unsigned int flow_limit;
    bool fail_open, may_put;
    enum upcall_type type;

    atomic_read(&udpif->flow_limit, &flow_limit);
    may_put = udpif_get_n_flows(udpif) < flow_limit;

    /* Extract the flow from each upcall.  Construct in 'misses' a hash table
     * that maps each unique flow to a 'struct flow_miss'.
     *
     * Most commonly there is a single packet per flow_miss, but there are
     * several reasons why there might be more than one, e.g.:
     *
     *   - The dpif packet interface does not support TSO (or UFO, etc.), so a
     *     large packet sent to userspace is split into a sequence of smaller
     *     ones.
     *
     *   - A stream of quickly arriving packets in an established "slow-pathed"
     *     flow.
     *
     *   - Rarely, a stream of quickly arriving packets in a flow not yet
     *     established.  (This is rare because most protocols do not send
     *     multiple back-to-back packets before receiving a reply from the
     *     other end of the connection, which gives OVS a chance to set up a
     *     datapath flow.)
     */
    n_misses = 0;
    LIST_FOR_EACH_SAFE (upcall, next, list_node, upcalls) {
        struct dpif_upcall *dupcall = &upcall->dpif_upcall;
        struct flow_miss *miss = &miss_buf[n_misses];
        struct ofpbuf *packet = &dupcall->packet;
        struct flow_miss *existing_miss;
        struct ofproto_dpif *ofproto;
        struct dpif_sflow *sflow;
        struct dpif_ipfix *ipfix;
        odp_port_t odp_in_port;
        struct flow flow;
        int error;

        error = xlate_receive(udpif->backer, packet, dupcall->key,
                              dupcall->key_len, &flow, &miss->key_fitness,
                              &ofproto, &ipfix, &sflow, NULL, &odp_in_port);
        if (error) {
            if (error == ENODEV) {
                /* Received packet on datapath port for which we couldn't
                 * associate an ofproto.  This can happen if a port is removed
                 * while traffic is being received.  Print a rate-limited
                 * message in case it happens frequently.  Install a drop flow
                 * so that future packets of the flow are inexpensively dropped
                 * in the kernel. */
                VLOG_INFO_RL(&rl, "received packet on unassociated datapath "
                             "port %"PRIu32, odp_in_port);
                dpif_flow_put(udpif->dpif, DPIF_FP_CREATE | DPIF_FP_MODIFY,
                              dupcall->key, dupcall->key_len, NULL, 0, NULL, 0,
                              NULL);
            }
            list_remove(&upcall->list_node);
            upcall_destroy(upcall);
            continue;
        }

        type = classify_upcall(upcall);
        if (type == MISS_UPCALL) {
            uint32_t hash;

            flow_extract(packet, flow.skb_priority, flow.pkt_mark,
                         &flow.tunnel, &flow.in_port, &miss->flow);

            hash = flow_hash(&miss->flow, 0);
            existing_miss = flow_miss_find(&misses, ofproto, &miss->flow,
                                           hash);
            if (!existing_miss) {
                hmap_insert(&misses, &miss->hmap_node, hash);
                miss->ofproto = ofproto;
                miss->key = dupcall->key;
                miss->key_len = dupcall->key_len;
                miss->upcall_type = dupcall->type;
                miss->stats.n_packets = 0;
                miss->stats.n_bytes = 0;
                miss->stats.used = time_msec();
                miss->stats.tcp_flags = 0;
                miss->odp_in_port = odp_in_port;
                miss->put = false;

                n_misses++;
            } else {
                miss = existing_miss;
            }
            miss->stats.tcp_flags |= packet_get_tcp_flags(packet, &miss->flow);
            miss->stats.n_bytes += packet->size;
            miss->stats.n_packets++;

            upcall->flow_miss = miss;
            continue;
        }

        switch (type) {
        case SFLOW_UPCALL:
            if (sflow) {
                union user_action_cookie cookie;

                memset(&cookie, 0, sizeof cookie);
                memcpy(&cookie, nl_attr_get(dupcall->userdata),
                       sizeof cookie.sflow);
                dpif_sflow_received(sflow, packet, &flow, odp_in_port,
                                    &cookie);
            }
            break;
        case IPFIX_UPCALL:
            if (ipfix) {
                dpif_ipfix_bridge_sample(ipfix, packet, &flow);
            }
            break;
        case FLOW_SAMPLE_UPCALL:
            if (ipfix) {
                union user_action_cookie cookie;

                memset(&cookie, 0, sizeof cookie);
                memcpy(&cookie, nl_attr_get(dupcall->userdata),
                       sizeof cookie.flow_sample);

                /* The flow reflects exactly the contents of the packet.
                 * Sample the packet using it. */
                dpif_ipfix_flow_sample(ipfix, packet, &flow,
                                       cookie.flow_sample.collector_set_id,
                                       cookie.flow_sample.probability,
                                       cookie.flow_sample.obs_domain_id,
                                       cookie.flow_sample.obs_point_id);
            }
            break;
        case BAD_UPCALL:
            break;
        case MISS_UPCALL:
            OVS_NOT_REACHED();
        }

        dpif_ipfix_unref(ipfix);
        dpif_sflow_unref(sflow);

        list_remove(&upcall->list_node);
        upcall_destroy(upcall);
    }

    /* Initialize each 'struct flow_miss's ->xout.
     *
     * We do this per-flow_miss rather than per-packet because, most commonly,
     * all the packets in a flow can use the same translation.
     *
     * We can't do this in the previous loop because we need the TCP flags for
     * all the packets in each miss. */
    fail_open = false;
    HMAP_FOR_EACH (miss, hmap_node, &misses) {
        struct xlate_in xin;

        xlate_in_init(&xin, miss->ofproto, &miss->flow, NULL,
                      miss->stats.tcp_flags, NULL);
        xin.may_learn = true;

        if (miss->upcall_type == DPIF_UC_MISS) {
            xin.resubmit_stats = &miss->stats;
        } else {
            /* For non-miss upcalls, there's a flow in the datapath which this
             * packet was accounted to.  Presumably the revalidators will deal
             * with pushing its stats eventually. */
        }

        xlate_actions(&xin, &miss->xout);
        fail_open = fail_open || miss->xout.fail_open;
    }

    /* Now handle the packets individually in order of arrival.  In the common
     * case each packet of a miss can share the same actions, but slow-pathed
     * packets need to be translated individually:
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
    LIST_FOR_EACH (upcall, list_node, upcalls) {
        struct flow_miss *miss = upcall->flow_miss;
        struct ofpbuf *packet = &upcall->dpif_upcall.packet;
        struct dpif_op *op;
        ovs_be16 flow_vlan_tci;

        /* Save a copy of flow.vlan_tci in case it is changed to
         * generate proper mega flow masks for VLAN splinter flows. */
        flow_vlan_tci = miss->flow.vlan_tci;

        if (miss->xout.slow) {
            struct xlate_in xin;

            xlate_in_init(&xin, miss->ofproto, &miss->flow, NULL, 0, packet);
            xlate_actions_for_side_effects(&xin);
        }

        if (miss->flow.in_port.ofp_port
            != vsp_realdev_to_vlandev(miss->ofproto,
                                      miss->flow.in_port.ofp_port,
                                      miss->flow.vlan_tci)) {
            /* This packet was received on a VLAN splinter port.  We
             * added a VLAN to the packet to make the packet resemble
             * the flow, but the actions were composed assuming that
             * the packet contained no VLAN.  So, we must remove the
             * VLAN header from the packet before trying to execute the
             * actions. */
            if (miss->xout.odp_actions.size) {
                eth_pop_vlan(packet);
            }

            /* Remove the flow vlan tags inserted by vlan splinter logic
             * to ensure megaflow masks generated match the data path flow. */
            miss->flow.vlan_tci = 0;
        }

        /* Do not install a flow into the datapath if:
         *
         *    - The datapath already has too many flows.
         *
         *    - An earlier iteration of this loop already put the same flow.
         *
         *    - We received this packet via some flow installed in the kernel
         *      already. */
        if (may_put
            && !miss->put
            && upcall->dpif_upcall.type == DPIF_UC_MISS) {
            struct ofpbuf mask;
            bool megaflow;

            miss->put = true;

            atomic_read(&enable_megaflows, &megaflow);
            ofpbuf_use_stack(&mask, &miss->mask_buf, sizeof miss->mask_buf);
            if (megaflow) {
                odp_flow_key_from_mask(&mask, &miss->xout.wc.masks,
                                       &miss->flow, UINT32_MAX);
            }

            op = &ops[n_ops++];
            op->type = DPIF_OP_FLOW_PUT;
            op->u.flow_put.flags = DPIF_FP_CREATE | DPIF_FP_MODIFY;
            op->u.flow_put.key = miss->key;
            op->u.flow_put.key_len = miss->key_len;
            op->u.flow_put.mask = mask.data;
            op->u.flow_put.mask_len = mask.size;
            op->u.flow_put.stats = NULL;

            if (!miss->xout.slow) {
                op->u.flow_put.actions = miss->xout.odp_actions.data;
                op->u.flow_put.actions_len = miss->xout.odp_actions.size;
            } else {
                struct ofpbuf buf;

                ofpbuf_use_stack(&buf, miss->slow_path_buf,
                                 sizeof miss->slow_path_buf);
                compose_slow_path(udpif, &miss->xout, miss->odp_in_port, &buf);
                op->u.flow_put.actions = buf.data;
                op->u.flow_put.actions_len = buf.size;
            }
        }

        /*
         * The 'miss' may be shared by multiple upcalls. Restore
         * the saved flow vlan_tci field before processing the next
         * upcall. */
        miss->flow.vlan_tci = flow_vlan_tci;

        if (miss->xout.odp_actions.size) {

            op = &ops[n_ops++];
            op->type = DPIF_OP_EXECUTE;
            op->u.execute.key = miss->key;
            op->u.execute.key_len = miss->key_len;
            op->u.execute.packet = packet;
            op->u.execute.actions = miss->xout.odp_actions.data;
            op->u.execute.actions_len = miss->xout.odp_actions.size;
            op->u.execute.needs_help = (miss->xout.slow & SLOW_ACTION) != 0;
        }
    }

    /* Special case for fail-open mode.
     *
     * If we are in fail-open mode, but we are connected to a controller too,
     * then we should send the packet up to the controller in the hope that it
     * will try to set up a flow and thereby allow us to exit fail-open.
     *
     * See the top-level comment in fail-open.c for more information.
     *
     * Copy packets before they are modified by execution. */
    if (fail_open) {
        LIST_FOR_EACH (upcall, list_node, upcalls) {
            struct flow_miss *miss = upcall->flow_miss;
            struct ofpbuf *packet = &upcall->dpif_upcall.packet;
            struct ofproto_packet_in *pin;

            pin = xmalloc(sizeof *pin);
            pin->up.packet = xmemdup(packet->data, packet->size);
            pin->up.packet_len = packet->size;
            pin->up.reason = OFPR_NO_MATCH;
            pin->up.table_id = 0;
            pin->up.cookie = OVS_BE64_MAX;
            flow_get_metadata(&miss->flow, &pin->up.fmd);
            pin->send_len = 0; /* Not used for flow table misses. */
            pin->generated_by_table_miss = false;
            ofproto_dpif_send_packet_in(miss->ofproto, pin);
        }
    }

    /* Execute batch. */
    for (i = 0; i < n_ops; i++) {
        opsp[i] = &ops[i];
    }
    dpif_operate(udpif->dpif, opsp, n_ops);

    HMAP_FOR_EACH_SAFE (miss, next_miss, hmap_node, &misses) {
        hmap_remove(&misses, &miss->hmap_node);
        xlate_out_uninit(&miss->xout);
    }
    hmap_destroy(&misses);

    LIST_FOR_EACH_SAFE (upcall, next, list_node, upcalls) {
        list_remove(&upcall->list_node);
        upcall_destroy(upcall);
    }
}

static struct udpif_key *
ukey_lookup(struct revalidator *revalidator, struct udpif_flow_dump *udump)
{
    struct udpif_key *ukey;

    HMAP_FOR_EACH_WITH_HASH (ukey, hmap_node, udump->key_hash,
                             &revalidator->ukeys) {
        if (ukey->key_len == udump->key_len
            && !memcmp(ukey->key, udump->key, udump->key_len)) {
            return ukey;
        }
    }
    return NULL;
}

static struct udpif_key *
ukey_create(const struct nlattr *key, size_t key_len, long long int used)
{
    struct udpif_key *ukey = xmalloc(sizeof *ukey);

    ukey->key = (struct nlattr *) &ukey->key_buf;
    memcpy(&ukey->key_buf, key, key_len);
    ukey->key_len = key_len;

    ukey->mark = false;
    ukey->created = used ? used : time_msec();
    memset(&ukey->stats, 0, sizeof ukey->stats);

    return ukey;
}

static void
ukey_delete(struct revalidator *revalidator, struct udpif_key *ukey)
{
    hmap_remove(&revalidator->ukeys, &ukey->hmap_node);
    free(ukey);
}

static bool
revalidate_ukey(struct udpif *udpif, struct udpif_flow_dump *udump,
                struct udpif_key *ukey)
{
    struct ofpbuf xout_actions, *actions;
    uint64_t slow_path_buf[128 / 8];
    struct xlate_out xout, *xoutp;
    struct flow flow, udump_mask;
    struct ofproto_dpif *ofproto;
    struct dpif_flow_stats push;
    uint32_t *udump32, *xout32;
    odp_port_t odp_in_port;
    struct xlate_in xin;
    int error;
    size_t i;
    bool ok;

    ok = false;
    xoutp = NULL;
    actions = NULL;

    /* If we don't need to revalidate, we can simply push the stats contained
     * in the udump, otherwise we'll have to get the actions so we can check
     * them. */
    if (udump->need_revalidate) {
        if (dpif_flow_get(udpif->dpif, ukey->key, ukey->key_len, &actions,
                          &udump->stats)) {
            goto exit;
        }
    }

    push.used = udump->stats.used;
    push.tcp_flags = udump->stats.tcp_flags;
    push.n_packets = udump->stats.n_packets > ukey->stats.n_packets
        ? udump->stats.n_packets - ukey->stats.n_packets
        : 0;
    push.n_bytes = udump->stats.n_bytes > ukey->stats.n_bytes
        ? udump->stats.n_bytes - ukey->stats.n_bytes
        : 0;
    ukey->stats = udump->stats;

    if (!push.n_packets && !udump->need_revalidate) {
        ok = true;
        goto exit;
    }

    error = xlate_receive(udpif->backer, NULL, ukey->key, ukey->key_len, &flow,
                          NULL, &ofproto, NULL, NULL, NULL, &odp_in_port);
    if (error) {
        goto exit;
    }

    xlate_in_init(&xin, ofproto, &flow, NULL, push.tcp_flags, NULL);
    xin.resubmit_stats = push.n_packets ? &push : NULL;
    xin.may_learn = push.n_packets > 0;
    xin.skip_wildcards = !udump->need_revalidate;
    xlate_actions(&xin, &xout);
    xoutp = &xout;

    if (!udump->need_revalidate) {
        ok = true;
        goto exit;
    }

    if (!xout.slow) {
        ofpbuf_use_const(&xout_actions, xout.odp_actions.data,
                         xout.odp_actions.size);
    } else {
        ofpbuf_use_stack(&xout_actions, slow_path_buf, sizeof slow_path_buf);
        compose_slow_path(udpif, &xout, odp_in_port, &xout_actions);
    }

    if (!ofpbuf_equal(&xout_actions, actions)) {
        goto exit;
    }

    if (odp_flow_key_to_mask(udump->mask, udump->mask_len, &udump_mask, &flow)
        == ODP_FIT_ERROR) {
        goto exit;
    }

    /* Since the kernel is free to ignore wildcarded bits in the mask, we can't
     * directly check that the masks are the same.  Instead we check that the
     * mask in the kernel is more specific i.e. less wildcarded, than what
     * we've calculated here.  This guarantees we don't catch any packets we
     * shouldn't with the megaflow. */
    udump32 = (uint32_t *) &udump_mask;
    xout32 = (uint32_t *) &xout.wc.masks;
    for (i = 0; i < FLOW_U32S; i++) {
        if ((udump32[i] | xout32[i]) != udump32[i]) {
            goto exit;
        }
    }
    ok = true;

exit:
    ofpbuf_delete(actions);
    xlate_out_uninit(xoutp);
    return ok;
}

struct dump_op {
    struct udpif_key *ukey;
    struct udpif_flow_dump *udump;
    struct dpif_flow_stats stats; /* Stats for 'op'. */
    struct dpif_op op;            /* Flow del operation. */
};

static void
dump_op_init(struct dump_op *op, const struct nlattr *key, size_t key_len,
             struct udpif_key *ukey, struct udpif_flow_dump *udump)
{
    op->ukey = ukey;
    op->udump = udump;
    op->op.type = DPIF_OP_FLOW_DEL;
    op->op.u.flow_del.key = key;
    op->op.u.flow_del.key_len = key_len;
    op->op.u.flow_del.stats = &op->stats;
}

static void
push_dump_ops(struct revalidator *revalidator,
              struct dump_op *ops, size_t n_ops)
{
    struct udpif *udpif = revalidator->udpif;
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
        if (op->ukey) {
            push = &push_buf;
            push->used = MAX(stats->used, op->ukey->stats.used);
            push->tcp_flags = stats->tcp_flags | op->ukey->stats.tcp_flags;
            push->n_packets = stats->n_packets - op->ukey->stats.n_packets;
            push->n_bytes = stats->n_bytes - op->ukey->stats.n_bytes;
        } else {
            push = stats;
        }

        if (push->n_packets || netflow_exists()) {
            struct ofproto_dpif *ofproto;
            struct netflow *netflow;
            struct flow flow;

            if (!xlate_receive(udpif->backer, NULL, op->op.u.flow_del.key,
                               op->op.u.flow_del.key_len, &flow, NULL,
                               &ofproto, NULL, NULL, &netflow, NULL)) {
                struct xlate_in xin;

                xlate_in_init(&xin, ofproto, &flow, NULL, push->tcp_flags,
                              NULL);
                xin.resubmit_stats = push->n_packets ? push : NULL;
                xin.may_learn = push->n_packets > 0;
                xin.skip_wildcards = true;
                xlate_actions_for_side_effects(&xin);

                if (netflow) {
                    netflow_expire(netflow, &flow);
                    netflow_flow_clear(netflow, &flow);
                    netflow_unref(netflow);
                }
            }
        }
    }

    for (i = 0; i < n_ops; i++) {
        struct udpif_key *ukey;

        /* If there's a udump, this ukey came directly from a datapath flow
         * dump.  Sometimes a datapath can send duplicates in flow dumps, in
         * which case we wouldn't want to double-free a ukey, so avoid that by
         * looking up the ukey again.
         *
         * If there's no udump then we know what we're doing. */
        ukey = (ops[i].udump
                ? ukey_lookup(revalidator, ops[i].udump)
                : ops[i].ukey);
        if (ukey) {
            ukey_delete(revalidator, ukey);
        }
    }
}

static void
revalidate_udumps(struct revalidator *revalidator, struct list *udumps)
{
    struct udpif *udpif = revalidator->udpif;

    struct dump_op ops[REVALIDATE_MAX_BATCH];
    struct udpif_flow_dump *udump, *next_udump;
    size_t n_ops, n_flows;
    unsigned int flow_limit;
    long long int max_idle;
    bool must_del;

    atomic_read(&udpif->flow_limit, &flow_limit);

    n_flows = udpif_get_n_flows(udpif);

    must_del = false;
    max_idle = MAX_IDLE;
    if (n_flows > flow_limit) {
        must_del = n_flows > 2 * flow_limit;
        max_idle = 100;
    }

    n_ops = 0;
    LIST_FOR_EACH_SAFE (udump, next_udump, list_node, udumps) {
        long long int used, now;
        struct udpif_key *ukey;

        now = time_msec();
        ukey = ukey_lookup(revalidator, udump);

        used = udump->stats.used;
        if (!used && ukey) {
            used = ukey->created;
        }

        if (must_del || (used && used < now - max_idle)) {
            struct dump_op *dop = &ops[n_ops++];

            dump_op_init(dop, udump->key, udump->key_len, ukey, udump);
            continue;
        }

        if (!ukey) {
            ukey = ukey_create(udump->key, udump->key_len, used);
            hmap_insert(&revalidator->ukeys, &ukey->hmap_node,
                        udump->key_hash);
        }
        ukey->mark = true;

        if (!revalidate_ukey(udpif, udump, ukey)) {
            dpif_flow_del(udpif->dpif, udump->key, udump->key_len, NULL);
            ukey_delete(revalidator, ukey);
        }

        list_remove(&udump->list_node);
        free(udump);
    }

    push_dump_ops(revalidator, ops, n_ops);

    LIST_FOR_EACH_SAFE (udump, next_udump, list_node, udumps) {
        list_remove(&udump->list_node);
        free(udump);
    }
}

static void
revalidator_sweep__(struct revalidator *revalidator, bool purge)
{
    struct dump_op ops[REVALIDATE_MAX_BATCH];
    struct udpif_key *ukey, *next;
    size_t n_ops;

    n_ops = 0;

    HMAP_FOR_EACH_SAFE (ukey, next, hmap_node, &revalidator->ukeys) {
        if (!purge && ukey->mark) {
            ukey->mark = false;
        } else {
            struct dump_op *op = &ops[n_ops++];

            /* If we have previously seen a flow in the datapath, but didn't
             * see it during the most recent dump, delete it. This allows us
             * to clean up the ukey and keep the statistics consistent. */
            dump_op_init(op, ukey->key, ukey->key_len, ukey, NULL);
            if (n_ops == REVALIDATE_MAX_BATCH) {
                push_dump_ops(revalidator, ops, n_ops);
                n_ops = 0;
            }
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

        atomic_read(&udpif->flow_limit, &flow_limit);

        ds_put_format(&ds, "%s:\n", dpif_name(udpif->dpif));
        ds_put_format(&ds, "\tflows         : (current %"PRIu64")"
            " (avg %u) (max %u) (limit %u)\n", udpif_get_n_flows(udpif),
            udpif->avg_n_flows, udpif->max_n_flows, flow_limit);
        ds_put_format(&ds, "\tdump duration : %lldms\n", udpif->dump_duration);

        ds_put_char(&ds, '\n');
        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            ovs_mutex_lock(&handler->mutex);
            ds_put_format(&ds, "\t%s: (upcall queue %"PRIuSIZE")\n",
                          handler->name, handler->n_upcalls);
            ovs_mutex_unlock(&handler->mutex);
        }

        ds_put_char(&ds, '\n');
        for (i = 0; i < n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            /* XXX: The result of hmap_count(&revalidator->ukeys) may not be
             * accurate because it's not protected by the revalidator mutex. */
            ovs_mutex_lock(&revalidator->mutex);
            ds_put_format(&ds, "\t%s: (dump queue %"PRIuSIZE") (keys %"PRIuSIZE
                          ")\n", revalidator->name, revalidator->n_udumps,
                          hmap_count(&revalidator->ukeys));
            ovs_mutex_unlock(&revalidator->mutex);
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
    atomic_store(&enable_megaflows, false);
    udpif_flush();
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
    atomic_store(&enable_megaflows, true);
    udpif_flush();
    unixctl_command_reply(conn, "megaflows enabled");
}
