/*
 * Copyright (c) 2025 Red Hat, Inc.
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

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "dpif-offload-dpdk-private.h"
#include "id-fpool.h"
#include "mov-avg.h"
#include "mpsc-queue.h"
#include "netdev-offload-dpdk.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "util.h"
#include "uuid.h"

#include "openvswitch/json.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_dpdk);

#define DEFAULT_OFFLOAD_THREAD_COUNT 1
#define MAX_OFFLOAD_THREAD_COUNT 10

enum dpdk_offload_type {
    DPDK_OFFLOAD_FLOW,
    DPDK_OFFLOAD_FLUSH,
};

enum {
    DPDK_NETDEV_FLOW_OFFLOAD_OP_PUT,
    DPDK_NETDEV_FLOW_OFFLOAD_OP_DEL,
};

struct dpdk_offload_thread {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct mpsc_queue queue;
        atomic_uint64_t enqueued_item;
        struct mov_avg_cma cma;
        struct mov_avg_ema ema;
        struct dpif_offload_dpdk *offload;
        pthread_t thread;
    );
};

struct dpdk_offload_flow_item {
    int op;
    odp_port_t in_port;
    ovs_u128 ufid;
    unsigned pmd_id;
    struct match match;
    struct nlattr *actions;
    size_t actions_len;
    odp_port_t orig_in_port; /* Originating in_port for tunnel flows. */
    bool requested_stats;
    void *flow_reference;
    struct dpif_offload_flow_cb_data callback;
};

struct dpdk_offload_flush_item {
    struct netdev *netdev;
    struct dpif_offload_dpdk *offload;
    struct ovs_barrier *barrier;
};

union dpdk_offload_thread_data {
    struct dpdk_offload_flow_item flow;
    struct dpdk_offload_flush_item flush;
};

struct dpdk_offload_thread_item {
    struct mpsc_queue_node node;
    enum dpdk_offload_type type;
    long long int timestamp;
    union dpdk_offload_thread_data data[0];
};

/* dpif offload interface for the dpdk rte_flow implementation. */
struct dpif_offload_dpdk {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    atomic_count next_offload_thread_id;
    atomic_bool offload_thread_shutdown;
    struct dpdk_offload_thread *offload_threads;

    struct id_fpool *flow_mark_pool;

    dpif_offload_flow_unreference_cb *unreference_cb;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
    unsigned int offload_thread_count; /* Number of offload threads. */
};

static struct dpif_offload_dpdk *
dpif_offload_dpdk_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_dpdk_class);
    return CONTAINER_OF(offload, struct dpif_offload_dpdk, offload);
}

DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, dpdk_offload_thread_id);
DEFINE_EXTERN_PER_THREAD_DATA(dpdk_offload_thread_id, OVSTHREAD_ID_UNSET);

uint32_t
dpif_offload_dpdk_allocate_flow_mark(struct dpif_offload_dpdk *offload)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int uid = dpdk_offload_thread_id() \
                       % offload->offload_thread_count;
    uint32_t flow_mark;

    if (ovsthread_once_start(&init_once)) {
        /* Haven't initiated yet, do it here. */
        offload->flow_mark_pool = id_fpool_create(
            offload->offload_thread_count, 1, UINT32_MAX - 1);
        ovsthread_once_done(&init_once);
    }

    if (id_fpool_new_id(offload->flow_mark_pool, uid, &flow_mark)) {
        return flow_mark;
    }

    return INVALID_FLOW_MARK;
}

void
dpif_offload_dpdk_free_flow_mark(struct dpif_offload_dpdk *offload,
                                 uint32_t flow_mark)
{
    if (flow_mark != INVALID_FLOW_MARK) {
        unsigned int uid = dpdk_offload_thread_id() \
                           % offload->offload_thread_count;

        id_fpool_free_id(offload->flow_mark_pool, uid, flow_mark);
    }
}

unsigned int
dpdk_offload_thread_id(void)
{
    unsigned int id = *dpdk_offload_thread_id_get();

    if (OVS_UNLIKELY(id == OVSTHREAD_ID_UNSET)) {
        /* Offload threads get their ID set at initialization, here
         * only the RCU thread might need initialization. */
        ovs_assert(!strncmp(get_subprogram_name(), "urcu", strlen("urcu")));

        /* RCU will compete with other threads for shared object access.
         * Reclamation functions using a thread ID must be thread-safe.
         * For that end, and because RCU must consider all potential shared
         * objects anyway, its thread-id can be whichever, so return 0. */
        id = 0;
        *dpdk_offload_thread_id_get() = id;
    }

    return id;
}

static unsigned int
dpif_offload_dpdk_ufid_to_thread_id(struct dpif_offload_dpdk *offload,
                                    const ovs_u128 ufid)
{
    uint32_t ufid_hash;

    if (offload->offload_thread_count == 1) {
        return 0;
    }

    ufid_hash = hash_words64_inline(
            (const uint64_t [2]){ ufid.u64.lo,
                                  ufid.u64.hi }, 2, 1);
    return ufid_hash % offload->offload_thread_count;
}

static bool
dpif_offload_dpdk_is_offloading_netdev(struct dpif_offload_dpdk *offload,
                                       struct netdev *netdev)
{
    const struct dpif_offload *netdev_offload;

    netdev_offload = ovsrcu_get(const struct dpif_offload *,
                                &netdev->dpif_offload);

    return netdev_offload == &offload->offload;
}

static struct dpdk_offload_thread_item *
dpif_offload_dpdk_alloc_flow_offload(int op)
{
    struct dpdk_offload_thread_item *item;
    struct dpdk_offload_flow_item *flow_offload;

    item = xzalloc(sizeof *item + sizeof *flow_offload);
    flow_offload = &item->data->flow;

    item->type = DPDK_OFFLOAD_FLOW;
    flow_offload->op = op;

    return item;
}

static void
dpif_offload_dpdk_free_flow_offload__(struct dpdk_offload_thread_item *offload)
{
    struct dpdk_offload_flow_item *flow_offload = &offload->data->flow;

    free(flow_offload->actions);
    free(offload);
}

static void
dpif_offload_dpdk_free_flow_offload(struct dpdk_offload_thread_item *offload)
{
    ovsrcu_postpone(dpif_offload_dpdk_free_flow_offload__, offload);
}

static void
dpif_offload_dpdk_free_offload(struct dpdk_offload_thread_item *offload)
{
    switch (offload->type) {
    case DPDK_OFFLOAD_FLOW:
        dpif_offload_dpdk_free_flow_offload(offload);
        break;
    case DPDK_OFFLOAD_FLUSH:
        free(offload);
        break;
    default:
        OVS_NOT_REACHED();
    };
}

static void
dpif_offload_dpdk_append_offload(const struct dpif_offload_dpdk *offload,
                                 struct dpdk_offload_thread_item *item,
                                 unsigned int tid)
{
    ovs_assert(offload->offload_threads);

    mpsc_queue_insert(&offload->offload_threads[tid].queue, &item->node);
    atomic_count_inc64(&offload->offload_threads[tid].enqueued_item);
}

static void
dpif_offload_dpdk_offload_flow_enqueue(struct dpif_offload_dpdk *offload,
                                       struct dpdk_offload_thread_item *item)
{
    struct dpdk_offload_flow_item *flow_offload = &item->data->flow;
    unsigned int tid;

    ovs_assert(item->type == DPDK_OFFLOAD_FLOW);

    tid = dpif_offload_dpdk_ufid_to_thread_id(offload, flow_offload->ufid);
    dpif_offload_dpdk_append_offload(offload, item, tid);
}

static int
dpif_offload_dpdk_offload_del(struct dpdk_offload_thread *thread,
                              struct dpdk_offload_thread_item *item)
{
    struct dpdk_offload_flow_item *flow = &item->data->flow;
    struct dpif_flow_stats stats;
    struct netdev *netdev;
    int error;

    netdev = dpif_offload_dpdk_get_netdev(thread->offload, flow->in_port);

    if (!netdev) {
        VLOG_DBG("Failed to find netdev for port_id %d", flow->in_port);
        error = ENODEV;
        goto do_callback;
    }

    /* Note that we are responsible for tracking offloads per PMD.  We pass
     * the delete request directly to the dpdk netdev offload code, which
     * will handle the actual hardware offloaded flow.  It will only remove it
     * when no other PMD needs it. */
    error = netdev_offload_dpdk_flow_del(thread->offload, netdev,
                                         flow->pmd_id, &flow->ufid,
                                         flow->flow_reference,
                                         flow->requested_stats ? &stats
                                                               : NULL);

do_callback:
    dpif_offload_datapath_flow_op_continue(&flow->callback,
                                           flow->requested_stats ? &stats
                                                                 : NULL,
                                           flow->pmd_id, flow->flow_reference,
                                           NULL,
                                           error);
    return error;
}

static int
dpif_offload_dpdk_offload_put(struct dpdk_offload_thread *thread,
                              struct dpdk_offload_thread_item *item)
{
    struct dpdk_offload_flow_item *flow = &item->data->flow;
    void *previous_flow_reference = NULL;
    struct dpif_flow_stats stats;
    struct netdev *netdev;
    int error;

    netdev = dpif_offload_dpdk_get_netdev(thread->offload, flow->in_port);

    if (!netdev) {
        VLOG_DBG("Failed to find netdev for port_id %d", flow->in_port);
        error = ENODEV;
        goto do_callback;
    }

    if (!dpif_offload_dpdk_is_offloading_netdev(thread->offload, netdev)) {
        error = EUNATCH;
        goto do_callback;
    }

    /* Note that we are responsible for tracking offloads per PMD.  We pass
     * the put request directly to the dpdk netdev offload code, which
     * will handle the actual hardware offloaded flow.  It will only add it
     * when no other PMD have it offloaded. */
    error = netdev_offload_dpdk_flow_put(thread->offload, flow->pmd_id,
                                         flow->flow_reference,
                                         netdev, &flow->match,
                                         CONST_CAST(struct nlattr *,
                                                    flow->actions),
                                         flow->actions_len, &flow->ufid,
                                         flow->orig_in_port,
                                         &previous_flow_reference,
                                         flow->requested_stats
                                             ? &stats
                                             : NULL);
do_callback:
    dpif_offload_datapath_flow_op_continue(&flow->callback,
                                           flow->requested_stats ? &stats
                                                                 : NULL,
                                           flow->pmd_id, flow->flow_reference,
                                           previous_flow_reference,
                                           error);
    return error;
}

static void
dpif_offload_dpdk_offload_flow(struct dpdk_offload_thread *thread,
                               struct dpdk_offload_thread_item *item)
{
    struct dpdk_offload_flow_item *flow_offload = &item->data->flow;
    const char *op;
    int ret;

    switch (flow_offload->op) {
    case DPDK_NETDEV_FLOW_OFFLOAD_OP_PUT:
        op = "put";
        ret = dpif_offload_dpdk_offload_put(thread, item);
        break;
    case DPDK_NETDEV_FLOW_OFFLOAD_OP_DEL:
        op = "delete";
        ret = dpif_offload_dpdk_offload_del(thread, item);
        break;
    default:
        OVS_NOT_REACHED();
    }

    VLOG_DBG("%s to %s netdev flow "UUID_FMT,
             ret == 0 ? "succeed" : "failed", op,
             UUID_ARGS((struct uuid *) &flow_offload->ufid));
}

static void
dpif_offload_dpdk_offload_flush(struct dpdk_offload_thread_item *item)
{
    struct dpdk_offload_flush_item *flush = &item->data->flush;

    netdev_offload_dpdk_flow_flush(flush->offload, flush->netdev);
    ovs_barrier_block(flush->barrier);
}

#define DPDK_OFFLOAD_BACKOFF_MIN 1
#define DPDK_OFFLOAD_BACKOFF_MAX 64
#define DPDK_OFFLOAD_QUIESCE_INTERVAL_US (10 * 1000) /* 10 ms */

static void *
dpif_offload_dpdk_offload_thread_main(void *arg)
{
    struct dpdk_offload_thread *ofl_thread = arg;
    struct dpdk_offload_thread_item *offload;
    struct mpsc_queue_node *node;
    struct mpsc_queue *queue;
    long long int latency_us;
    long long int next_rcu;
    uint64_t backoff;
    bool exiting;

    if (*dpdk_offload_thread_id_get() == OVSTHREAD_ID_UNSET) {
        unsigned int id;

        id = atomic_count_inc(&ofl_thread->offload->next_offload_thread_id);

        /* Panic if any offload thread is getting a spurious ID. */
        ovs_assert(id < ofl_thread->offload->offload_thread_count);

        *dpdk_offload_thread_id_get() = id;
    }

    queue = &ofl_thread->queue;
    mpsc_queue_acquire(queue);

    do {
        long long int now;

        backoff = DPDK_OFFLOAD_BACKOFF_MIN;
        while (mpsc_queue_tail(queue) == NULL) {
            xnanosleep(backoff * 1E6);
            if (backoff < DPDK_OFFLOAD_BACKOFF_MAX) {
                backoff <<= 1;
            }

            atomic_read_relaxed(&ofl_thread->offload->offload_thread_shutdown,
                                &exiting);
            if (exiting) {
                goto exit_thread;
            }
        }

        now = time_usec();
        next_rcu = now + DPDK_OFFLOAD_QUIESCE_INTERVAL_US;
        MPSC_QUEUE_FOR_EACH_POP (node, queue) {
            offload = CONTAINER_OF(node, struct dpdk_offload_thread_item,
                                   node);
            atomic_count_dec64(&ofl_thread->enqueued_item);

            switch (offload->type) {
            case DPDK_OFFLOAD_FLOW:
                dpif_offload_dpdk_offload_flow(ofl_thread, offload);
                break;
            case DPDK_OFFLOAD_FLUSH:
                dpif_offload_dpdk_offload_flush(offload);
                break;
            default:
                OVS_NOT_REACHED();
            }

            now = time_usec();
            latency_us = now - offload->timestamp;
            mov_avg_cma_update(&ofl_thread->cma, latency_us);
            mov_avg_ema_update(&ofl_thread->ema, latency_us);

            dpif_offload_dpdk_free_offload(offload);

            /* Do RCU synchronization at fixed interval. */
            if (now > next_rcu) {
                ovsrcu_quiesce();
                next_rcu = time_usec() + DPDK_OFFLOAD_QUIESCE_INTERVAL_US;
            }
        }

        atomic_read_relaxed(&ofl_thread->offload->offload_thread_shutdown,
                            &exiting);
    } while (!exiting);

exit_thread:
    mpsc_queue_release(queue);
    return NULL;
}

static void
dpif_offload_dpdk_offload_threads_init(struct dpif_offload_dpdk *offload)
{
    offload->offload_threads = xcalloc(offload->offload_thread_count,
                                       sizeof(struct dpdk_offload_thread));

    for (unsigned int tid = 0; tid < offload->offload_thread_count; tid++) {
        struct dpdk_offload_thread *thread;

        thread = &offload->offload_threads[tid];
        mpsc_queue_init(&thread->queue);
        atomic_init(&thread->enqueued_item, 0);
        mov_avg_cma_init(&thread->cma);
        mov_avg_ema_init(&thread->ema, 100);
        thread->offload = offload;
        thread->thread = ovs_thread_create(
            "dpdk_offload", dpif_offload_dpdk_offload_thread_main, thread);
    }
}

static long long int
dpif_offload_dpdk_get_timestamp(void)
{
    /* XXX: We should look for a better, more efficient way to obtain a
     *  timestamp in the fast path, if only used for gathering statistics. */
    return time_usec();
}

static void
dpif_offload_dpdk_flush_enqueue(struct dpif_offload_dpdk *offload,
                                struct netdev *netdev,
                                struct ovs_barrier *barrier)
{
    unsigned int tid;
    long long int now_us = dpif_offload_dpdk_get_timestamp();

    if (!dpif_offload_enabled()) {
        return;
    }

    for (tid = 0; tid < offload->offload_thread_count; tid++) {
        struct dpdk_offload_thread_item *item;
        struct dpdk_offload_flush_item *flush;

        item = xmalloc(sizeof *item + sizeof *flush);
        item->type = DPDK_OFFLOAD_FLUSH;
        item->timestamp = now_us;

        flush = &item->data->flush;
        flush->netdev = netdev;
        flush->offload = offload;
        flush->barrier = barrier;

        dpif_offload_dpdk_append_offload(offload, item, tid);
    }
}

/* Blocking call that will wait on the offload thread to
 * complete its work.  As the flush order will only be
 * enqueued after existing offload requests, those previous
 * offload requests must be processed.
 *
 * Flow offload flush is done when a port is being deleted.
 * Right before this call executes, the offload API is disabled
 * for the port.  This call must be made blocking until the
 * offload provider completed its job. */
static void
dpif_offload_dpdk_flush(struct dpif_offload_dpdk *offload,
                        struct netdev *netdev)
{
    /* The flush mutex serves to exclude mutual access to the static
     * barrier, and to prevent multiple flush orders to several threads.
     *
     * The memory barrier needs to go beyond the function scope as
     * the other threads can resume from blocking after this function
     * already finished.
     *
     * Additionally, because the flush operation is blocking, it would
     * deadlock if multiple offload threads were blocking on several
     * different barriers.  Only allow a single flush order in the offload
     * queue at a time. */
    static struct ovs_mutex flush_mutex = OVS_MUTEX_INITIALIZER;
    static struct ovs_barrier barrier OVS_GUARDED_BY(flush_mutex);

    ovs_mutex_lock(&flush_mutex);

    ovs_barrier_init(&barrier, 1 + offload->offload_thread_count);

    dpif_offload_dpdk_flush_enqueue(offload, netdev, &barrier);
    ovs_barrier_block(&barrier);
    ovs_barrier_destroy(&barrier);

    ovs_mutex_unlock(&flush_mutex);
}

void dpif_offload_dpdk_traverse_ports(
    const struct dpif_offload_dpdk *offload,
    bool (*cb)(struct netdev *, odp_port_t, void *), void *aux)
{
    struct dpif_offload_port_mgr_port *port;

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
        if (cb(port->netdev, port->port_no, aux)) {
            break;
        }
    }
}

static int
dpif_offload_dpdk_enable_offload(struct dpif_offload *offload_,
                                 struct dpif_offload_port_mgr_port *port)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct netdev *netdev = port->netdev;

    netdev_offload_dpdk_init(netdev, offload->offload_thread_count);
    dpif_offload_set_netdev_offload(netdev, offload_);
    return 0;
}

static int
dpif_offload_dpdk_cleanup_offload(struct dpif_offload *offload_ OVS_UNUSED,
                                  struct dpif_offload_port_mgr_port *port)
{
    struct netdev *netdev = port->netdev;

    netdev_offload_dpdk_uninit(netdev);
    dpif_offload_set_netdev_offload(port->netdev, NULL);
    return 0;
}

static int
dpif_offload_dpdk_port_add(struct dpif_offload *offload_,
                           struct netdev *netdev, odp_port_t port_no)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port = xmalloc(sizeof *port);

    if (dpif_offload_port_mgr_add(offload->port_mgr, port, netdev,
                                  port_no, false)) {
        if (dpif_offload_enabled()) {
            return dpif_offload_dpdk_enable_offload(offload_, port);
        }
        return 0;
    }

    free(port);
    return EEXIST;
}

static void
dpif_offload_dpdk_free_port(struct dpif_offload_port_mgr_port *port)
{
    netdev_close(port->netdev);
    free(port);
}

static int
dpif_offload_dpdk_port_del(struct dpif_offload *offload_, odp_port_t port_no)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port;
    int ret = 0;

    port = dpif_offload_port_mgr_find_by_odp_port(offload->port_mgr, port_no);

    if (dpif_offload_enabled() && port) {
        /* If hardware offload is enabled, we first need to flush (complete)
         * all pending flow operations, especially the pending delete ones,
         * before we remove the netdev from the port_mgr list. */
        dpif_offload_set_netdev_offload(port->netdev, NULL);
        dpif_offload_dpdk_flush(offload, port->netdev);
    }

    port = dpif_offload_port_mgr_remove(offload->port_mgr, port_no);
    if (port) {
        if (dpif_offload_enabled()) {
            ret = dpif_offload_dpdk_cleanup_offload(offload_, port);
        }
        ovsrcu_postpone(dpif_offload_dpdk_free_port, port);
    }
    return ret;
}

static int
dpif_offload_dpdk_port_dump_start(const struct dpif_offload *offload_,
                                  void **statep)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    return dpif_offload_port_mgr_port_dump_start(offload->port_mgr, statep);
}

static int
dpif_offload_dpdk_port_dump_next(const struct dpif_offload *offload_,
                                 void *state,
                                 struct dpif_offload_port *port)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    return dpif_offload_port_mgr_port_dump_next(offload->port_mgr, state,
                                                port);
}

static int
dpif_offload_dpdk_port_dump_done(const struct dpif_offload *offload_,
                                 void *state)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    return dpif_offload_port_mgr_port_dump_done(offload->port_mgr, state);
}

struct netdev *
dpif_offload_dpdk_get_netdev(const struct dpif_offload_dpdk *offload,
                             odp_port_t port_no)
{
    struct dpif_offload_port_mgr_port *port;

    port = dpif_offload_port_mgr_find_by_odp_port(offload->port_mgr,
                                                  port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

static struct netdev *
dpif_offload_dpdk_get_netdev_(struct dpif_offload *offload_,
                              odp_port_t port_no)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    return dpif_offload_dpdk_get_netdev(offload, port_no);
}

static int
dpif_offload_dpdk_open(const struct dpif_offload_class *offload_class,
                       struct dpif *dpif, struct dpif_offload **offload_)
{
    struct dpif_offload_dpdk *offload;

    offload = xmalloc(sizeof *offload);

    dpif_offload_init(&offload->offload, offload_class, dpif);
    offload->port_mgr = dpif_offload_port_mgr_init();
    offload->once_enable = (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;
    offload->offload_thread_count = DEFAULT_OFFLOAD_THREAD_COUNT;
    offload->offload_threads = NULL;
    atomic_count_init(&offload->next_offload_thread_id, 0);
    atomic_init(&offload->offload_thread_shutdown, false);
    offload->flow_mark_pool = NULL;
    offload->unreference_cb = NULL;

    *offload_ = &offload->offload;
    return 0;
}

static void
dpif_offload_dpdk_close(struct dpif_offload *offload_)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port;

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
        dpif_offload_dpdk_port_del(offload_, port->port_no);
    }

    atomic_store_relaxed(&offload->offload_thread_shutdown, true);
    if (offload->offload_threads) {
        for (int i = 0; i < offload->offload_thread_count; i++) {
            xpthread_join(offload->offload_threads[i].thread, NULL);
            mpsc_queue_destroy(&offload->offload_threads[i].queue);
        }
        free(offload->offload_threads);
    }

    dpif_offload_port_mgr_uninit(offload->port_mgr);

    if (offload->flow_mark_pool) {
        id_fpool_destroy(offload->flow_mark_pool);
    }

    ovsthread_once_destroy(&offload->once_enable);
    free(offload);
}

static void
dpif_offload_dpdk_set_config(struct dpif_offload *offload_,
                             const struct smap *other_cfg)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload->once_enable)) {
            struct dpif_offload_port_mgr_port *port;

            unsigned int offload_thread_count = smap_get_uint(
                other_cfg, "n-offload-threads", DEFAULT_OFFLOAD_THREAD_COUNT);

            if (offload_thread_count == 0 ||
                offload_thread_count > MAX_OFFLOAD_THREAD_COUNT) {
                VLOG_WARN("netdev: Invalid number of threads requested: %u",
                          offload_thread_count);
                offload_thread_count = DEFAULT_OFFLOAD_THREAD_COUNT;
            }

            VLOG_INFO("Flow API using %u thread%s", offload_thread_count,
                      offload_thread_count > 1 ? "s" : "");

            offload->offload_thread_count = offload_thread_count;

            dpif_offload_dpdk_offload_threads_init(offload);
            DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
                dpif_offload_dpdk_enable_offload(offload_, port);
            }

            ovsthread_once_done(&offload->once_enable);
        }
    }
}

static void
dpif_offload_dpdk_get_debug(const struct dpif_offload *offload_, struct ds *ds,
                            struct json *json)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    if (json) {
        struct json *json_ports = json_object_create();
        struct dpif_offload_port_mgr_port *port;

        DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
            struct json *json_port = json_object_create();

            json_object_put(json_port, "port_no",
                            json_integer_create(odp_to_u32(port->port_no)));

            json_object_put(json_ports, netdev_get_name(port->netdev),
                            json_port);
        }

        if (!json_object_is_empty(json_ports)) {
            json_object_put(json, "ports", json_ports);
        } else {
            json_destroy(json_ports);
        }
    } else if (ds) {
        struct dpif_offload_port_mgr_port *port;

        DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
            ds_put_format(ds, "  - %s: port_no: %u\n",
                          netdev_get_name(port->netdev), port->port_no);
        }
    }
}

static bool
dpif_offload_dpdk_can_offload(struct dpif_offload *offload OVS_UNUSED,
                              struct netdev *netdev)
{
    if (netdev_vport_is_vport_class(netdev->netdev_class)
        && strcmp(netdev_get_dpif_type(netdev), "netdev")) {
        VLOG_DBG("%s: vport doesn't belong to the netdev datapath, skipping",
                 netdev_get_name(netdev));
        return false;
    }

    return netdev_dpdk_flow_api_supported(netdev, true);
}

static uint64_t
dpif_offload_dpdk_flow_count(const struct dpif_offload *offload_)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port;
    uint64_t total = 0;

    if (!dpif_offload_enabled()) {
        return 0;
    }

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
        total += netdev_offload_dpdk_flow_count(port->netdev,
                                                offload->offload_thread_count);
    }

    return total;
}

static uint64_t
dpif_offload_dpdk_flow_count_by_thread(struct dpif_offload_dpdk *offload,
                                       unsigned int tid)
{
    struct dpif_offload_port_mgr_port *port;
    uint64_t total = 0;

    if (!dpif_offload_enabled()) {
        return 0;
    }

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
        total += netdev_offload_dpdk_flow_count_by_thread(port->netdev, tid);
    }

    return total;
}

static int
dpif_offload_dpdk_netdev_hw_post_process(
    const struct dpif_offload *offload_, struct netdev *netdev,
    unsigned pmd_id, struct dp_packet *packet, void **flow_reference)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    return netdev_offload_dpdk_hw_miss_packet_recover(offload, netdev, pmd_id,
                                                      packet, flow_reference);
}

static int
dpif_offload_dpdk_netdev_flow_put(const struct dpif_offload *offload_,
                                  struct netdev *netdev OVS_UNUSED,
                                  struct dpif_offload_flow_put *put,
                                  void **previous_flow_reference OVS_UNUSED)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpdk_offload_thread_item *item;
    struct dpdk_offload_flow_item *flow_offload;

    item = dpif_offload_dpdk_alloc_flow_offload(
        DPDK_NETDEV_FLOW_OFFLOAD_OP_PUT);
    item->timestamp = dpif_offload_dpdk_get_timestamp();

    flow_offload = &item->data->flow;
    flow_offload->in_port = put->in_port;
    flow_offload->ufid = *put->ufid;
    flow_offload->pmd_id = put->pmd_id;
    flow_offload->flow_reference = put->flow_reference;
    flow_offload->match = *put->match;
    flow_offload->actions = xmalloc(put->actions_len);
    nullable_memcpy(flow_offload->actions, put->actions, put->actions_len);
    flow_offload->actions_len = put->actions_len;
    flow_offload->orig_in_port = put->orig_in_port;
    flow_offload->requested_stats = !!put->stats;
    flow_offload->callback = put->cb_data;

    dpif_offload_dpdk_offload_flow_enqueue(offload, item);
    return EINPROGRESS;
}

static int
dpif_offload_dpdk_netdev_flow_del(const struct dpif_offload *offload_,
                                  struct netdev *netdev OVS_UNUSED,
                                  struct dpif_offload_flow_del *del)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpdk_offload_thread_item *item;
    struct dpdk_offload_flow_item *flow_offload;

    item = dpif_offload_dpdk_alloc_flow_offload(
        DPDK_NETDEV_FLOW_OFFLOAD_OP_DEL);
    item->timestamp =dpif_offload_dpdk_get_timestamp();

    flow_offload = &item->data->flow;
    flow_offload->in_port = del->in_port;
    flow_offload->requested_stats = !!del->stats;
    flow_offload->ufid = *del->ufid;
    flow_offload->flow_reference = del->flow_reference;
    flow_offload->pmd_id = del->pmd_id;
    flow_offload->callback = del->cb_data;

    dpif_offload_dpdk_offload_flow_enqueue(offload, item);
    return EINPROGRESS;
}

static void
dpif_offload_dpdk_register_flow_unreference_cb(
    const struct dpif_offload *offload_, dpif_offload_flow_unreference_cb *cb)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    offload->unreference_cb = cb;
}

void
dpif_offload_dpdk_flow_unreference(struct dpif_offload_dpdk *offload,
                                   unsigned pmd_id, void *flow_reference)
{
    if (offload->unreference_cb) {
        offload->unreference_cb(pmd_id, flow_reference);
    }
}

static bool
dpif_offload_dpdk_netdev_flow_stats(const struct dpif_offload *ol OVS_UNUSED,
                                    struct netdev *netdev,
                                    const ovs_u128 *ufid,
                                    struct dpif_flow_stats *stats,
                                    struct dpif_flow_attrs *attrs)
{
    uint64_t act_buf[1024 / 8];
    struct nlattr *actions;
    struct match match;
    struct ofpbuf buf;

    ofpbuf_use_stack(&buf, &act_buf, sizeof act_buf);

    return !netdev_offload_dpdk_flow_get(netdev, &match, &actions,
                                         ufid, stats, attrs, &buf);
}

static int
dpif_offload_dpdk_get_global_stats(const struct dpif_offload *offload_,
                                   struct netdev_custom_stats *stats)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    unsigned int nb_thread = offload->offload_thread_count;
    struct dpdk_offload_thread *offload_threads = offload->offload_threads;
    unsigned int tid;
    size_t i;

    enum {
        DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED,
        DP_NETDEV_HW_OFFLOADS_STATS_INSERTED,
        DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN,
        DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV,
        DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN,
        DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV,
    };
    struct {
        const char *name;
        uint64_t total;
    } hwol_stats[] = {
        [DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED] =
            { "                Enqueued offloads", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_INSERTED] =
            { "                Inserted offloads", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN] =
            { "  Cumulative Average latency (us)", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV] =
            { "   Cumulative Latency stddev (us)", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN] =
            { " Exponential Average latency (us)", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV] =
            { "  Exponential Latency stddev (us)", 0 },
    };

    if (!dpif_offload_enabled() || !nb_thread) {
        /* Leave stats structure untouched on error per API guidelines. */
        return EINVAL;
    }

    stats->label = xstrdup(dpif_offload_name(offload_));

    /* nb_thread counters for the overall total as well. */
    stats->size = ARRAY_SIZE(hwol_stats) * (nb_thread + 1);
    stats->counters = xcalloc(stats->size, sizeof *stats->counters);

    for (tid = 0; tid < nb_thread; tid++) {
        uint64_t counts[ARRAY_SIZE(hwol_stats)];
        size_t idx = ((tid + 1) * ARRAY_SIZE(hwol_stats));

        memset(counts, 0, sizeof counts);
        if (offload_threads != NULL) {
            counts[DP_NETDEV_HW_OFFLOADS_STATS_INSERTED] =
                dpif_offload_dpdk_flow_count_by_thread(offload, tid);

            atomic_read_relaxed(&offload_threads[tid].enqueued_item,
                                &counts[DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED]);

            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN] =
                mov_avg_cma(&offload_threads[tid].cma);
            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV] =
                mov_avg_cma_std_dev(&offload_threads[tid].cma);

            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN] =
                mov_avg_ema(&offload_threads[tid].ema);
            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV] =
                mov_avg_ema_std_dev(&offload_threads[tid].ema);
        }

        for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
            snprintf(stats->counters[idx + i].name,
                     sizeof(stats->counters[idx + i].name),
                     "  [%3u] %s", tid, hwol_stats[i].name);
            stats->counters[idx + i].value = counts[i];
            hwol_stats[i].total += counts[i];
        }
    }

    /* Do an average of the average for the aggregate. */
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV].total /= nb_thread;

    /* Get the total offload count. */
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_INSERTED].total =
        dpif_offload_dpdk_flow_count(offload_);

    for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
        snprintf(stats->counters[i].name, sizeof(stats->counters[i].name),
                 "  Total %s", hwol_stats[i].name);
        stats->counters[i].value = hwol_stats[i].total;
    }

    return 0;
}

struct dpif_offload_class dpif_offload_dpdk_class = {
    .type = "dpdk",
    .impl_type = DPIF_OFFLOAD_IMPL_FLOWS_DPIF_SYNCED,
    .supported_dpif_types = (const char *const[]) {"netdev", NULL},
    .open = dpif_offload_dpdk_open,
    .close = dpif_offload_dpdk_close,
    .set_config = dpif_offload_dpdk_set_config,
    .get_debug = dpif_offload_dpdk_get_debug,
    .get_global_stats = dpif_offload_dpdk_get_global_stats,
    .can_offload = dpif_offload_dpdk_can_offload,
    .port_add = dpif_offload_dpdk_port_add,
    .port_del = dpif_offload_dpdk_port_del,
    .port_dump_start = dpif_offload_dpdk_port_dump_start,
    .port_dump_next = dpif_offload_dpdk_port_dump_next,
    .port_dump_done = dpif_offload_dpdk_port_dump_done,
    .flow_count = dpif_offload_dpdk_flow_count,
    .get_netdev = dpif_offload_dpdk_get_netdev_,
    .netdev_hw_post_process = dpif_offload_dpdk_netdev_hw_post_process,
    .netdev_flow_put = dpif_offload_dpdk_netdev_flow_put,
    .netdev_flow_del = dpif_offload_dpdk_netdev_flow_del,
    .netdev_flow_stats = dpif_offload_dpdk_netdev_flow_stats,
    .register_flow_unreference_cb =
        dpif_offload_dpdk_register_flow_unreference_cb,
};
