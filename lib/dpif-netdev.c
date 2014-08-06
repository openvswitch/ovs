/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "dpif.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "classifier.h"
#include "csum.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hmap.h"
#include "latch.h"
#include "list.h"
#include "meta-flow.h"
#include "netdev.h"
#include "netdev-dpdk.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "seq.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

/* By default, choose a priority in the middle. */
#define NETDEV_RULE_PRIORITY 0x8000

#define NR_THREADS 1
/* Use per thread recirc_depth to prevent recirculation loop. */
#define MAX_RECIRC_DEPTH 5
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, recirc_depth, 0)

/* Configuration parameters. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */

/* Queues. */
enum { MAX_QUEUE_LEN = 128 };   /* Maximum number of packets per queue. */
enum { QUEUE_MASK = MAX_QUEUE_LEN - 1 };
BUILD_ASSERT_DECL(IS_POW2(MAX_QUEUE_LEN));

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

struct dp_netdev_upcall {
    struct dpif_upcall upcall;  /* Queued upcall information. */
    struct ofpbuf buf;          /* ofpbuf instance for upcall.packet. */
};

/* A queue passing packets from a struct dp_netdev to its clients (handlers).
 *
 *
 * Thread-safety
 * =============
 *
 * Any access at all requires the owning 'dp_netdev''s queue_rwlock and
 * its own mutex. */
struct dp_netdev_queue {
    struct ovs_mutex mutex;
    struct seq *seq;      /* Incremented whenever a packet is queued. */
    struct dp_netdev_upcall upcalls[MAX_QUEUE_LEN] OVS_GUARDED;
    unsigned int head OVS_GUARDED;
    unsigned int tail OVS_GUARDED;
};

/* Datapath based on the network device interface from netdev.h.
 *
 *
 * Thread-safety
 * =============
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 *
 * Acquisition order is, from outermost to innermost:
 *
 *    dp_netdev_mutex (global)
 *    port_rwlock
 *    flow_mutex
 *    cls.rwlock
 *    queue_rwlock
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Flows.
     *
     * Readers of 'cls' and 'flow_table' must take a 'cls->rwlock' read lock.
     *
     * Writers of 'cls' and 'flow_table' must take the 'flow_mutex' and then
     * the 'cls->rwlock' write lock.  (The outer 'flow_mutex' allows writers to
     * atomically perform multiple operations on 'cls' and 'flow_table'.)
     */
    struct ovs_mutex flow_mutex;
    struct classifier cls;      /* Classifier.  Protected by cls.rwlock. */
    struct hmap flow_table OVS_GUARDED; /* Flow table. */

    /* Queues.
     *
     * 'queue_rwlock' protects the modification of 'handler_queues' and
     * 'n_handlers'.  The queue elements are protected by its
     * 'handler_queues''s mutex. */
    struct fat_rwlock queue_rwlock;
    struct dp_netdev_queue *handler_queues;
    uint32_t n_handlers;

    /* Statistics.
     *
     * ovsthread_stats is internally synchronized. */
    struct ovsthread_stats stats; /* Contains 'struct dp_netdev_stats *'. */

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_rwlock'. */
    struct ovs_rwlock port_rwlock;
    struct hmap ports OVS_GUARDED;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* Forwarding threads. */
    struct latch exit_latch;
    struct pmd_thread *pmd_threads;
    size_t n_pmd_threads;
    int pmd_count;
};

static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t)
    OVS_REQ_RDLOCK(dp->port_rwlock);

enum dp_stat_type {
    DP_STAT_HIT,                /* Packets that matched in the flow table. */
    DP_STAT_MISS,               /* Packets that did not match. */
    DP_STAT_LOST,               /* Packets not passed up to the client. */
    DP_N_STATS
};

/* Contained by struct dp_netdev's 'stats' member.  */
struct dp_netdev_stats {
    struct ovs_mutex mutex;          /* Protects 'n'. */

    /* Indexed by DP_STAT_*, protected by 'mutex'. */
    unsigned long long int n[DP_N_STATS] OVS_GUARDED;
};


/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    odp_port_t port_no;
    struct netdev *netdev;
    struct netdev_saved_flags *sf;
    struct netdev_rxq **rxq;
    struct ovs_refcount ref_cnt;
    char *type;                 /* Port type as requested by user. */
};

/* A flow in dp_netdev's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its dp_netdev's classifier.  The text below calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct dp_netdev_flow" are
 * motivated by two goals:
 *
 *    - Prevent threads that read members of "struct dp_netdev_flow" from
 *      reading bad data due to changes by some thread concurrently modifying
 *      those members.
 *
 *    - Prevent two threads making changes to members of a given "struct
 *      dp_netdev_flow" from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A flow 'flow' may be accessed without a risk of being freed by code that
 * holds a read-lock or write-lock on 'cls->rwlock' or that owns a reference to
 * 'flow->ref_cnt' (or both).  Code that needs to hold onto a flow for a while
 * should take 'cls->rwlock', find the flow it needs, increment 'flow->ref_cnt'
 * with dpif_netdev_flow_ref(), and drop 'cls->rwlock'.
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' (that's 'cls->rwlock') and it doesn't
 * protect members of 'flow' from modification.
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */
struct dp_netdev_flow {
    /* Packet classification. */
    const struct cls_rule cr;   /* In owning dp_netdev's 'cls'. */

    /* Hash table index by unmasked flow. */
    const struct hmap_node node; /* In owning dp_netdev's 'flow_table'. */
    const struct flow flow;      /* The flow that created this entry. */

    /* Statistics.
     *
     * Reading or writing these members requires 'mutex'. */
    struct ovsthread_stats stats; /* Contains "struct dp_netdev_flow_stats". */

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;
};

static void dp_netdev_flow_free(struct dp_netdev_flow *);

/* Contained by struct dp_netdev_flow's 'stats' member.  */
struct dp_netdev_flow_stats {
    struct ovs_mutex mutex;         /* Guards all the other members. */

    long long int used OVS_GUARDED; /* Last used time, in monotonic msecs. */
    long long int packet_count OVS_GUARDED; /* Number of packets matched. */
    long long int byte_count OVS_GUARDED;   /* Number of bytes matched. */
    uint16_t tcp_flags OVS_GUARDED; /* Bitwise-OR of seen tcp_flags values. */
};

/* A set of datapath actions within a "struct dp_netdev_flow".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct dp_netdev_actions 'actions' is protected with RCU. */
struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    struct nlattr *actions;     /* Sequence of OVS_ACTION_ATTR_* attributes. */
    unsigned int size;          /* Size of 'actions', in bytes. */
};

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t);
struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *);
static void dp_netdev_actions_free(struct dp_netdev_actions *);

/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself thread.
 *
 * DPDK used PMD for accessing NIC.
 *
 * A thread that receives packets from PMD ports, looks them up in the flow
 * table, and executes the actions it finds.
 **/
struct pmd_thread {
    struct dp_netdev *dp;
    pthread_t thread;
    int id;
    atomic_uint change_seq;
};

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    uint64_t last_port_seq;
};

static int get_port_by_number(struct dp_netdev *dp, odp_port_t port_no,
                              struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock);
static int get_port_by_name(struct dp_netdev *dp, const char *devname,
                            struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock);
static void dp_netdev_free(struct dp_netdev *)
    OVS_REQUIRES(dp_netdev_mutex);
static void dp_netdev_flow_flush(struct dp_netdev *);
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static int do_del_port(struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static void dp_netdev_destroy_all_queues(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->queue_rwlock);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static int dp_netdev_output_userspace(struct dp_netdev *dp, struct ofpbuf *,
                                      int queue_no, int type,
                                      const struct miniflow *,
                                      const struct nlattr *userdata);
static void dp_netdev_execute_actions(struct dp_netdev *dp,
                                      const struct miniflow *,
                                      struct ofpbuf *, bool may_steal,
                                      struct pkt_metadata *,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_port_input(struct dp_netdev *dp, struct ofpbuf *packet,
                                 struct pkt_metadata *);

static void dp_netdev_set_pmd_threads(struct dp_netdev *, int n);

static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    ovs_assert(dpif->dpif_class->open == dpif_netdev_open);
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
    return dpif_netdev_cast(dpif)->dp;
}

static int
dpif_netdev_enumerate(struct sset *all_dps)
{
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH(node, &dp_netdevs) {
        sset_add(all_dps, node->name);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return 0;
}

static bool
dpif_netdev_class_is_dummy(const struct dpif_class *class)
{
    return class != &dpif_netdev_class;
}

static const char *
dpif_netdev_port_open_type(const struct dpif_class *class, const char *type)
{
    return strcmp(type, "internal") ? type
                  : dpif_netdev_class_is_dummy(class) ? "dummy"
                  : "tap";
}

static struct dpif *
create_dpif_netdev(struct dp_netdev *dp)
{
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_netdev *dpif;

    ovs_refcount_ref(&dp->ref_cnt);

    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);
    dpif->dp = dp;
    dpif->last_port_seq = seq_read(dp->port_seq);

    return &dpif->dpif;
}

/* Choose an unused, non-zero port number and return it on success.
 * Return ODPP_NONE on failure. */
static odp_port_t
choose_port(struct dp_netdev *dp, const char *name)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    uint32_t port_no;

    if (dp->class != &dpif_netdev_class) {
        const char *p;
        int start_no = 0;

        /* If the port name begins with "br", start the number search at
         * 100 to make writing tests easier. */
        if (!strncmp(name, "br", 2)) {
            start_no = 100;
        }

        /* If the port name contains a number, try to assign that port number.
         * This can make writing unit tests easier because port numbers are
         * predictable. */
        for (p = name; *p != '\0'; p++) {
            if (isdigit((unsigned char) *p)) {
                port_no = start_no + strtol(p, NULL, 10);
                if (port_no > 0 && port_no != odp_to_u32(ODPP_NONE)
                    && !dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
                    return u32_to_odp(port_no);
                }
                break;
            }
        }
    }

    for (port_no = 1; port_no <= UINT16_MAX; port_no++) {
        if (!dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

static int
create_dp_netdev(const char *name, const struct dpif_class *class,
                 struct dp_netdev **dpp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev *dp;
    int error;

    dp = xzalloc(sizeof *dp);
    shash_add(&dp_netdevs, name, dp);

    *CONST_CAST(const struct dpif_class **, &dp->class) = class;
    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_clear(&dp->destroyed);

    ovs_mutex_init(&dp->flow_mutex);
    classifier_init(&dp->cls, NULL);
    hmap_init(&dp->flow_table);

    fat_rwlock_init(&dp->queue_rwlock);

    ovsthread_stats_init(&dp->stats);

    ovs_rwlock_init(&dp->port_rwlock);
    hmap_init(&dp->ports);
    dp->port_seq = seq_create();
    latch_init(&dp->exit_latch);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = do_add_port(dp, name, "internal", ODPP_LOCAL);
    ovs_rwlock_unlock(&dp->port_rwlock);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    *dpp = dp;
    return 0;
}

static int
dpif_netdev_open(const struct dpif_class *class, const char *name,
                 bool create, struct dpif **dpifp)
{
    struct dp_netdev *dp;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, name);
    if (!dp) {
        error = create ? create_dp_netdev(name, class, &dp) : ENODEV;
    } else {
        error = (dp->class != class ? EINVAL
                 : create ? EEXIST
                 : 0);
    }
    if (!error) {
        *dpifp = create_dpif_netdev(dp);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static void
dp_netdev_purge_queues(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->queue_rwlock)
{
    int i;

    for (i = 0; i < dp->n_handlers; i++) {
        struct dp_netdev_queue *q = &dp->handler_queues[i];

        ovs_mutex_lock(&q->mutex);
        while (q->tail != q->head) {
            struct dp_netdev_upcall *u = &q->upcalls[q->tail++ & QUEUE_MASK];
            ofpbuf_uninit(&u->upcall.packet);
            ofpbuf_uninit(&u->buf);
        }
        ovs_mutex_unlock(&q->mutex);
    }
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port, *next;
    struct dp_netdev_stats *bucket;
    int i;

    shash_find_and_delete(&dp_netdevs, dp->name);

    dp_netdev_set_pmd_threads(dp, 0);
    free(dp->pmd_threads);

    dp_netdev_flow_flush(dp);
    ovs_rwlock_wrlock(&dp->port_rwlock);
    HMAP_FOR_EACH_SAFE (port, next, node, &dp->ports) {
        do_del_port(dp, port->port_no);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    OVSTHREAD_STATS_FOR_EACH_BUCKET (bucket, i, &dp->stats) {
        ovs_mutex_destroy(&bucket->mutex);
        free_cacheline(bucket);
    }
    ovsthread_stats_destroy(&dp->stats);

    fat_rwlock_wrlock(&dp->queue_rwlock);
    dp_netdev_destroy_all_queues(dp);
    fat_rwlock_unlock(&dp->queue_rwlock);

    fat_rwlock_destroy(&dp->queue_rwlock);

    classifier_destroy(&dp->cls);
    hmap_destroy(&dp->flow_table);
    ovs_mutex_destroy(&dp->flow_mutex);
    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    latch_destroy(&dp->exit_latch);
    free(CONST_CAST(char *, dp->name));
    free(dp);
}

static void
dp_netdev_unref(struct dp_netdev *dp)
{
    if (dp) {
        /* Take dp_netdev_mutex so that, if dp->ref_cnt falls to zero, we can't
         * get a new reference to 'dp' through the 'dp_netdevs' shash. */
        ovs_mutex_lock(&dp_netdev_mutex);
        if (ovs_refcount_unref(&dp->ref_cnt) == 1) {
            dp_netdev_free(dp);
        }
        ovs_mutex_unlock(&dp_netdev_mutex);
    }
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    dp_netdev_unref(dp);
    free(dpif);
}

static int
dpif_netdev_destroy(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (!atomic_flag_test_and_set(&dp->destroyed)) {
        if (ovs_refcount_unref(&dp->ref_cnt) == 1) {
            /* Can't happen: 'dpif' still owns a reference to 'dp'. */
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

static int
dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_stats *bucket;
    size_t i;

    fat_rwlock_rdlock(&dp->cls.rwlock);
    stats->n_flows = hmap_count(&dp->flow_table);
    fat_rwlock_unlock(&dp->cls.rwlock);

    stats->n_hit = stats->n_missed = stats->n_lost = 0;
    OVSTHREAD_STATS_FOR_EACH_BUCKET (bucket, i, &dp->stats) {
        ovs_mutex_lock(&bucket->mutex);
        stats->n_hit += bucket->n[DP_STAT_HIT];
        stats->n_missed += bucket->n[DP_STAT_MISS];
        stats->n_lost += bucket->n[DP_STAT_LOST];
        ovs_mutex_unlock(&bucket->mutex);
    }
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;

    return 0;
}

static void
dp_netdev_reload_pmd_threads(struct dp_netdev *dp)
{
    int i;

    for (i = 0; i < dp->n_pmd_threads; i++) {
        struct pmd_thread *f = &dp->pmd_threads[i];
        int id;

        atomic_add(&f->change_seq, 1, &id);
   }
}

static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct netdev_saved_flags *sf;
    struct dp_netdev_port *port;
    struct netdev *netdev;
    enum netdev_flags flags;
    const char *open_type;
    int error;
    int i;

    /* XXX reject devices already in some dp_netdev. */

    /* Open and validate network device. */
    open_type = dpif_netdev_port_open_type(dp->class, type);
    error = netdev_open(devname, open_type, &netdev);
    if (error) {
        return error;
    }
    /* XXX reject non-Ethernet devices */

    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR("%s: cannot add a loopback device", devname);
        netdev_close(netdev);
        return EINVAL;
    }

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->netdev = netdev;
    port->rxq = xmalloc(sizeof *port->rxq * netdev_n_rxq(netdev));
    port->type = xstrdup(type);
    for (i = 0; i < netdev_n_rxq(netdev); i++) {
        error = netdev_rxq_open(netdev, &port->rxq[i], i);
        if (error
            && !(error == EOPNOTSUPP && dpif_netdev_class_is_dummy(dp->class))) {
            VLOG_ERR("%s: cannot receive packets on this network device (%s)",
                     devname, ovs_strerror(errno));
            netdev_close(netdev);
            return error;
        }
    }

    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) {
        for (i = 0; i < netdev_n_rxq(netdev); i++) {
            netdev_rxq_close(port->rxq[i]);
        }
        netdev_close(netdev);
        free(port->rxq);
        free(port);
        return error;
    }
    port->sf = sf;

    if (netdev_is_pmd(netdev)) {
        dp->pmd_count++;
        dp_netdev_set_pmd_threads(dp, NR_THREADS);
        dp_netdev_reload_pmd_threads(dp);
    }
    ovs_refcount_init(&port->ref_cnt);

    hmap_insert(&dp->ports, &port->node, hash_int(odp_to_u32(port_no), 0));
    seq_change(dp->port_seq);

    return 0;
}

static int
dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev,
                     odp_port_t *port_nop)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
        port_no = *port_nop;
        error = dp_netdev_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp, dpif_port);
        error = port_no == ODPP_NONE ? EFBIG : 0;
    }
    if (!error) {
        *port_nop = port_no;
        error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static int
dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = port_no == ODPP_LOCAL ? EINVAL : do_del_port(dp, port_no);
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    return port_no != ODPP_NONE;
}

static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH_IN_BUCKET (port, node, hash_int(odp_to_u32(port_no), 0),
                             &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_netdev_lookup_port(dp, port_no);
        return *portp ? 0 : ENOENT;
    }
}

static void
port_ref(struct dp_netdev_port *port)
{
    if (port) {
        ovs_refcount_ref(&port->ref_cnt);
    }
}

static void
port_unref(struct dp_netdev_port *port)
{
    if (port && ovs_refcount_unref(&port->ref_cnt) == 1) {
        int n_rxq = netdev_n_rxq(port->netdev);
        int i;

        netdev_close(port->netdev);
        netdev_restore_flags(port->sf);

        for (i = 0; i < n_rxq; i++) {
            netdev_rxq_close(port->rxq[i]);
        }
        free(port->rxq);
        free(port->type);
        free(port);
    }
}

static int
get_port_by_name(struct dp_netdev *dp,
                 const char *devname, struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }
    return ENOENT;
}

static int
do_del_port(struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;
    int error;

    error = get_port_by_number(dp, port_no, &port);
    if (error) {
        return error;
    }

    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);
    if (netdev_is_pmd(port->netdev)) {
        dp_netdev_reload_pmd_threads(dp);
    }

    port_unref(port);
    return 0;
}

static void
answer_port_query(const struct dp_netdev_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static int
dpif_netdev_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                 struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static void
dp_netdev_flow_free(struct dp_netdev_flow *flow)
{
    struct dp_netdev_flow_stats *bucket;
    size_t i;

    OVSTHREAD_STATS_FOR_EACH_BUCKET (bucket, i, &flow->stats) {
        ovs_mutex_destroy(&bucket->mutex);
        free_cacheline(bucket);
    }
    ovsthread_stats_destroy(&flow->stats);

    cls_rule_destroy(CONST_CAST(struct cls_rule *, &flow->cr));
    dp_netdev_actions_free(dp_netdev_flow_get_actions(flow));
    free(flow);
}

static void
dp_netdev_remove_flow(struct dp_netdev *dp, struct dp_netdev_flow *flow)
    OVS_REQ_WRLOCK(dp->cls.rwlock)
    OVS_REQUIRES(dp->flow_mutex)
{
    struct cls_rule *cr = CONST_CAST(struct cls_rule *, &flow->cr);
    struct hmap_node *node = CONST_CAST(struct hmap_node *, &flow->node);

    classifier_remove(&dp->cls, cr);
    hmap_remove(&dp->flow_table, node);
    ovsrcu_postpone(dp_netdev_flow_free, flow);
}

static void
dp_netdev_flow_flush(struct dp_netdev *dp)
{
    struct dp_netdev_flow *netdev_flow, *next;

    ovs_mutex_lock(&dp->flow_mutex);
    fat_rwlock_wrlock(&dp->cls.rwlock);
    HMAP_FOR_EACH_SAFE (netdev_flow, next, node, &dp->flow_table) {
        dp_netdev_remove_flow(dp, netdev_flow);
    }
    fat_rwlock_unlock(&dp->cls.rwlock);
    ovs_mutex_unlock(&dp->flow_mutex);
}

static int
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    dp_netdev_flow_flush(dp);
    return 0;
}

struct dp_netdev_port_state {
    uint32_t bucket;
    uint32_t offset;
    char *name;
};

static int
dpif_netdev_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dp_netdev_port_state));
    return 0;
}

static int
dpif_netdev_port_dump_next(const struct dpif *dpif, void *state_,
                           struct dpif_port *dpif_port)
{
    struct dp_netdev_port_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct hmap_node *node;
    int retval;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    node = hmap_at_position(&dp->ports, &state->bucket, &state->offset);
    if (node) {
        struct dp_netdev_port *port;

        port = CONTAINER_OF(node, struct dp_netdev_port, node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return retval;
}

static int
dpif_netdev_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dp_netdev_port_state *state = state_;
    free(state->name);
    free(state);
    return 0;
}

static int
dpif_netdev_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);
    uint64_t new_port_seq;
    int error;

    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }

    return error;
}

static void
dpif_netdev_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);

    seq_wait(dpif->dp->port_seq, dpif->last_port_seq);
}

static struct dp_netdev_flow *
dp_netdev_flow_cast(const struct cls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct dp_netdev_flow, cr) : NULL;
}

static struct dp_netdev_flow *
dp_netdev_lookup_flow(const struct dp_netdev *dp, const struct miniflow *key)
    OVS_EXCLUDED(dp->cls.rwlock)
{
    struct dp_netdev_flow *netdev_flow;
    struct cls_rule *rule;

    fat_rwlock_rdlock(&dp->cls.rwlock);
    rule = classifier_lookup_miniflow_first(&dp->cls, key);
    netdev_flow = dp_netdev_flow_cast(rule);
    fat_rwlock_unlock(&dp->cls.rwlock);

    return netdev_flow;
}

static struct dp_netdev_flow *
dp_netdev_find_flow(const struct dp_netdev *dp, const struct flow *flow)
    OVS_REQ_RDLOCK(dp->cls.rwlock)
{
    struct dp_netdev_flow *netdev_flow;

    HMAP_FOR_EACH_WITH_HASH (netdev_flow, node, flow_hash(flow, 0),
                             &dp->flow_table) {
        if (flow_equal(&netdev_flow->flow, flow)) {
            return netdev_flow;
        }
    }

    return NULL;
}

static void
get_dpif_flow_stats(struct dp_netdev_flow *netdev_flow,
                    struct dpif_flow_stats *stats)
{
    struct dp_netdev_flow_stats *bucket;
    size_t i;

    memset(stats, 0, sizeof *stats);
    OVSTHREAD_STATS_FOR_EACH_BUCKET (bucket, i, &netdev_flow->stats) {
        ovs_mutex_lock(&bucket->mutex);
        stats->n_packets += bucket->packet_count;
        stats->n_bytes += bucket->byte_count;
        stats->used = MAX(stats->used, bucket->used);
        stats->tcp_flags |= bucket->tcp_flags;
        ovs_mutex_unlock(&bucket->mutex);
    }
}

static int
dpif_netdev_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow *mask)
{
    if (mask_key_len) {
        enum odp_key_fitness fitness;

        fitness = odp_flow_key_to_mask(mask_key, mask_key_len, mask, flow);
        if (fitness) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_mask() and odp_flow_key_to_mask()
             * disagree on the acceptable form of a mask.  Log the problem
             * as an error, with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, mask_key, mask_key_len, NULL, &s,
                                true);
                VLOG_ERR("internal error parsing flow mask %s (%s)",
                         ds_cstr(&s), odp_key_fitness_to_string(fitness));
                ds_destroy(&s);
            }

            return EINVAL;
        }
    } else {
        enum mf_field_id id;
        /* No mask key, unwildcard everything except fields whose
         * prerequisities are not met. */
        memset(mask, 0x0, sizeof *mask);

        for (id = 0; id < MFF_N_IDS; ++id) {
            /* Skip registers and metadata. */
            if (!(id >= MFF_REG0 && id < MFF_REG0 + FLOW_N_REGS)
                && id != MFF_METADATA) {
                const struct mf_field *mf = mf_from_id(id);
                if (mf_are_prereqs_ok(mf, flow)) {
                    mf_mask_field(mf, mask);
                }
            }
        }
    }

    /* Force unwildcard the in_port.
     *
     * We need to do this even in the case where we unwildcard "everything"
     * above because "everything" only includes the 16-bit OpenFlow port number
     * mask->in_port.ofp_port, which only covers half of the 32-bit datapath
     * port number mask->in_port.odp_port. */
    mask->in_port.odp_port = u32_to_odp(UINT32_MAX);

    return 0;
}

static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct flow *flow)
{
    odp_port_t in_port;

    if (odp_flow_key_to_flow(key, key_len, flow)) {
        /* This should not happen: it indicates that odp_flow_key_from_flow()
         * and odp_flow_key_to_flow() disagree on the acceptable form of a
         * flow.  Log the problem as an error, with enough details to enable
         * debugging. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        if (!VLOG_DROP_ERR(&rl)) {
            struct ds s;

            ds_init(&s);
            odp_flow_format(key, key_len, NULL, 0, NULL, &s, true);
            VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
            ds_destroy(&s);
        }

        return EINVAL;
    }

    in_port = flow->in_port.odp_port;
    if (!is_valid_port_number(in_port) && in_port != ODPP_NONE) {
        return EINVAL;
    }

    return 0;
}

static int
dpif_netdev_flow_get(const struct dpif *dpif,
                     const struct nlattr *nl_key, size_t nl_key_len,
                     struct ofpbuf **bufp,
                     struct nlattr **maskp, size_t *mask_len,
                     struct nlattr **actionsp, size_t *actions_len,
                     struct dpif_flow_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(nl_key, nl_key_len, &key);
    if (error) {
        return error;
    }

    fat_rwlock_rdlock(&dp->cls.rwlock);
    netdev_flow = dp_netdev_find_flow(dp, &key);
    fat_rwlock_unlock(&dp->cls.rwlock);

    if (netdev_flow) {
        if (stats) {
            get_dpif_flow_stats(netdev_flow, stats);
        }

        if (maskp || actionsp) {
            struct dp_netdev_actions *actions;
            size_t len = 0;

            actions = dp_netdev_flow_get_actions(netdev_flow);
            len += maskp ? sizeof(struct odputil_keybuf) : 0;
            len += actionsp ? actions->size : 0;

            *bufp = ofpbuf_new(len);
            if (maskp) {
                struct flow_wildcards wc;

                minimask_expand(&netdev_flow->cr.match.mask, &wc);
                odp_flow_key_from_mask(*bufp, &wc.masks, &netdev_flow->flow,
                                       odp_to_u32(wc.masks.in_port.odp_port),
                                       SIZE_MAX);
                *maskp = ofpbuf_data(*bufp);
                *mask_len = ofpbuf_size(*bufp);
            }
            if (actionsp) {
                struct dp_netdev_actions *actions;

                actions = dp_netdev_flow_get_actions(netdev_flow);
                *actionsp = ofpbuf_put(*bufp, actions->actions, actions->size);
                *actions_len = actions->size;
            }
        }
     } else {
        error = ENOENT;
    }

    return error;
}

static int
dp_netdev_flow_add(struct dp_netdev *dp, const struct flow *flow,
                   const struct flow_wildcards *wc,
                   const struct nlattr *actions,
                   size_t actions_len)
    OVS_REQUIRES(dp->flow_mutex)
{
    struct dp_netdev_flow *netdev_flow;
    struct match match;

    netdev_flow = xzalloc(sizeof *netdev_flow);
    *CONST_CAST(struct flow *, &netdev_flow->flow) = *flow;

    ovsthread_stats_init(&netdev_flow->stats);

    ovsrcu_set(&netdev_flow->actions,
               dp_netdev_actions_create(actions, actions_len));

    match_init(&match, flow, wc);
    cls_rule_init(CONST_CAST(struct cls_rule *, &netdev_flow->cr),
                  &match, NETDEV_RULE_PRIORITY);
    fat_rwlock_wrlock(&dp->cls.rwlock);
    classifier_insert(&dp->cls,
                      CONST_CAST(struct cls_rule *, &netdev_flow->cr));
    hmap_insert(&dp->flow_table,
                CONST_CAST(struct hmap_node *, &netdev_flow->node),
                flow_hash(flow, 0));
    fat_rwlock_unlock(&dp->cls.rwlock);

    return 0;
}

static void
clear_stats(struct dp_netdev_flow *netdev_flow)
{
    struct dp_netdev_flow_stats *bucket;
    size_t i;

    OVSTHREAD_STATS_FOR_EACH_BUCKET (bucket, i, &netdev_flow->stats) {
        ovs_mutex_lock(&bucket->mutex);
        bucket->used = 0;
        bucket->packet_count = 0;
        bucket->byte_count = 0;
        bucket->tcp_flags = 0;
        ovs_mutex_unlock(&bucket->mutex);
    }
}

static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct flow flow;
    struct miniflow miniflow;
    struct flow_wildcards wc;
    int error;

    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &flow);
    if (error) {
        return error;
    }
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len,
                                          put->mask, put->mask_len,
                                          &flow, &wc.masks);
    if (error) {
        return error;
    }
    miniflow_init(&miniflow, &flow);

    ovs_mutex_lock(&dp->flow_mutex);
    netdev_flow = dp_netdev_lookup_flow(dp, &miniflow);
    if (!netdev_flow) {
        if (put->flags & DPIF_FP_CREATE) {
            if (hmap_count(&dp->flow_table) < MAX_FLOWS) {
                if (put->stats) {
                    memset(put->stats, 0, sizeof *put->stats);
                }
                error = dp_netdev_flow_add(dp, &flow, &wc, put->actions,
                                           put->actions_len);
            } else {
                error = EFBIG;
            }
        } else {
            error = ENOENT;
        }
    } else {
        if (put->flags & DPIF_FP_MODIFY
            && flow_equal(&flow, &netdev_flow->flow)) {
            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions,
                                                   put->actions_len);

            old_actions = dp_netdev_flow_get_actions(netdev_flow);
            ovsrcu_set(&netdev_flow->actions, new_actions);

            if (put->stats) {
                get_dpif_flow_stats(netdev_flow, put->stats);
            }
            if (put->flags & DPIF_FP_ZERO_STATS) {
                clear_stats(netdev_flow);
            }

            ovsrcu_postpone(dp_netdev_actions_free, old_actions);
        } else if (put->flags & DPIF_FP_CREATE) {
            error = EEXIST;
        } else {
            /* Overlapping flow. */
            error = EINVAL;
        }
    }
    ovs_mutex_unlock(&dp->flow_mutex);
    miniflow_destroy(&miniflow);

    return error;
}

static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(del->key, del->key_len, &key);
    if (error) {
        return error;
    }

    ovs_mutex_lock(&dp->flow_mutex);
    fat_rwlock_wrlock(&dp->cls.rwlock);
    netdev_flow = dp_netdev_find_flow(dp, &key);
    if (netdev_flow) {
        if (del->stats) {
            get_dpif_flow_stats(netdev_flow, del->stats);
        }
        dp_netdev_remove_flow(dp, netdev_flow);
    } else {
        error = ENOENT;
    }
    fat_rwlock_unlock(&dp->cls.rwlock);
    ovs_mutex_unlock(&dp->flow_mutex);

    return error;
}

struct dp_netdev_flow_state {
    struct odputil_keybuf keybuf;
    struct odputil_keybuf maskbuf;
    struct dpif_flow_stats stats;
};

struct dp_netdev_flow_iter {
    uint32_t bucket;
    uint32_t offset;
    int status;
    struct ovs_mutex mutex;
};

static void
dpif_netdev_flow_dump_state_init(void **statep)
{
    struct dp_netdev_flow_state *state;

    *statep = state = xmalloc(sizeof *state);
}

static void
dpif_netdev_flow_dump_state_uninit(void *state_)
{
    struct dp_netdev_flow_state *state = state_;

    free(state);
}

static int
dpif_netdev_flow_dump_start(const struct dpif *dpif OVS_UNUSED, void **iterp)
{
    struct dp_netdev_flow_iter *iter;

    *iterp = iter = xmalloc(sizeof *iter);
    iter->bucket = 0;
    iter->offset = 0;
    iter->status = 0;
    ovs_mutex_init(&iter->mutex);
    return 0;
}

/* XXX the caller must use 'actions' without quiescing */
static int
dpif_netdev_flow_dump_next(const struct dpif *dpif, void *iter_, void *state_,
                           const struct nlattr **key, size_t *key_len,
                           const struct nlattr **mask, size_t *mask_len,
                           const struct nlattr **actions, size_t *actions_len,
                           const struct dpif_flow_stats **stats)
{
    struct dp_netdev_flow_iter *iter = iter_;
    struct dp_netdev_flow_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct flow_wildcards wc;
    int error;

    ovs_mutex_lock(&iter->mutex);
    error = iter->status;
    if (!error) {
        struct hmap_node *node;

        fat_rwlock_rdlock(&dp->cls.rwlock);
        node = hmap_at_position(&dp->flow_table, &iter->bucket, &iter->offset);
        if (node) {
            netdev_flow = CONTAINER_OF(node, struct dp_netdev_flow, node);
        }
        fat_rwlock_unlock(&dp->cls.rwlock);
        if (!node) {
            iter->status = error = EOF;
        }
    }
    ovs_mutex_unlock(&iter->mutex);
    if (error) {
        return error;
    }

    minimask_expand(&netdev_flow->cr.match.mask, &wc);

    if (key) {
        struct ofpbuf buf;

        ofpbuf_use_stack(&buf, &state->keybuf, sizeof state->keybuf);
        odp_flow_key_from_flow(&buf, &netdev_flow->flow, &wc.masks,
                               netdev_flow->flow.in_port.odp_port);

        *key = ofpbuf_data(&buf);
        *key_len = ofpbuf_size(&buf);
    }

    if (key && mask) {
        struct ofpbuf buf;

        ofpbuf_use_stack(&buf, &state->maskbuf, sizeof state->maskbuf);
        odp_flow_key_from_mask(&buf, &wc.masks, &netdev_flow->flow,
                               odp_to_u32(wc.masks.in_port.odp_port),
                               SIZE_MAX);

        *mask = ofpbuf_data(&buf);
        *mask_len = ofpbuf_size(&buf);
    }

    if (actions || stats) {
        if (actions) {
            struct dp_netdev_actions *dp_actions =
                dp_netdev_flow_get_actions(netdev_flow);

            *actions = dp_actions->actions;
            *actions_len = dp_actions->size;
        }

        if (stats) {
            get_dpif_flow_stats(netdev_flow, &state->stats);
            *stats = &state->stats;
        }
    }

    return 0;
}

static int
dpif_netdev_flow_dump_done(const struct dpif *dpif OVS_UNUSED, void *iter_)
{
    struct dp_netdev_flow_iter *iter = iter_;

    ovs_mutex_destroy(&iter->mutex);
    free(iter);
    return 0;
}

static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct pkt_metadata *md = &execute->md;
    struct {
        struct miniflow flow;
        uint32_t buf[FLOW_U32S];
    } key;

    if (ofpbuf_size(execute->packet) < ETH_HEADER_LEN ||
        ofpbuf_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    /* Extract flow key. */
    miniflow_initialize(&key.flow, key.buf);
    miniflow_extract(execute->packet, md, &key.flow);

    ovs_rwlock_rdlock(&dp->port_rwlock);
    dp_netdev_execute_actions(dp, &key.flow, execute->packet, false, md,
                              execute->actions, execute->actions_len);
    ovs_rwlock_unlock(&dp->port_rwlock);

    return 0;
}

static void
dp_netdev_destroy_all_queues(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->queue_rwlock)
{
    size_t i;

    dp_netdev_purge_queues(dp);

    for (i = 0; i < dp->n_handlers; i++) {
        struct dp_netdev_queue *q = &dp->handler_queues[i];

        ovs_mutex_destroy(&q->mutex);
        seq_destroy(q->seq);
    }
    free(dp->handler_queues);
    dp->handler_queues = NULL;
    dp->n_handlers = 0;
}

static void
dp_netdev_refresh_queues(struct dp_netdev *dp, uint32_t n_handlers)
    OVS_REQ_WRLOCK(dp->queue_rwlock)
{
    if (dp->n_handlers != n_handlers) {
        size_t i;

        dp_netdev_destroy_all_queues(dp);

        dp->n_handlers = n_handlers;
        dp->handler_queues = xzalloc(n_handlers * sizeof *dp->handler_queues);

        for (i = 0; i < n_handlers; i++) {
            struct dp_netdev_queue *q = &dp->handler_queues[i];

            ovs_mutex_init(&q->mutex);
            q->seq = seq_create();
        }
    }
}

static int
dpif_netdev_recv_set(struct dpif *dpif, bool enable)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if ((dp->handler_queues != NULL) == enable) {
        return 0;
    }

    fat_rwlock_wrlock(&dp->queue_rwlock);
    if (!enable) {
        dp_netdev_destroy_all_queues(dp);
    } else {
        dp_netdev_refresh_queues(dp, 1);
    }
    fat_rwlock_unlock(&dp->queue_rwlock);

    return 0;
}

static int
dpif_netdev_handlers_set(struct dpif *dpif, uint32_t n_handlers)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    fat_rwlock_wrlock(&dp->queue_rwlock);
    if (dp->handler_queues) {
        dp_netdev_refresh_queues(dp, n_handlers);
    }
    fat_rwlock_unlock(&dp->queue_rwlock);

    return 0;
}

static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
}

static bool
dp_netdev_recv_check(const struct dp_netdev *dp, const uint32_t handler_id)
    OVS_REQ_RDLOCK(dp->queue_rwlock)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (!dp->handler_queues) {
        VLOG_WARN_RL(&rl, "receiving upcall disabled");
        return false;
    }

    if (handler_id >= dp->n_handlers) {
        VLOG_WARN_RL(&rl, "handler index out of bound");
        return false;
    }

    return true;
}

static int
dpif_netdev_recv(struct dpif *dpif, uint32_t handler_id,
                 struct dpif_upcall *upcall, struct ofpbuf *buf)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_queue *q;
    int error = 0;

    fat_rwlock_rdlock(&dp->queue_rwlock);

    if (!dp_netdev_recv_check(dp, handler_id)) {
        error = EAGAIN;
        goto out;
    }

    q = &dp->handler_queues[handler_id];
    ovs_mutex_lock(&q->mutex);
    if (q->head != q->tail) {
        struct dp_netdev_upcall *u = &q->upcalls[q->tail++ & QUEUE_MASK];

        *upcall = u->upcall;

        ofpbuf_uninit(buf);
        *buf = u->buf;
    } else {
        error = EAGAIN;
    }
    ovs_mutex_unlock(&q->mutex);

out:
    fat_rwlock_unlock(&dp->queue_rwlock);

    return error;
}

static void
dpif_netdev_recv_wait(struct dpif *dpif, uint32_t handler_id)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_queue *q;
    uint64_t seq;

    fat_rwlock_rdlock(&dp->queue_rwlock);

    if (!dp_netdev_recv_check(dp, handler_id)) {
        goto out;
    }

    q = &dp->handler_queues[handler_id];
    ovs_mutex_lock(&q->mutex);
    seq = seq_read(q->seq);
    if (q->head != q->tail) {
        poll_immediate_wake();
    } else {
        seq_wait(q->seq, seq);
    }

    ovs_mutex_unlock(&q->mutex);

out:
    fat_rwlock_unlock(&dp->queue_rwlock);
}

static void
dpif_netdev_recv_purge(struct dpif *dpif)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);

    fat_rwlock_wrlock(&dpif_netdev->dp->queue_rwlock);
    dp_netdev_purge_queues(dpif_netdev->dp);
    fat_rwlock_unlock(&dpif_netdev->dp->queue_rwlock);
}

/* Creates and returns a new 'struct dp_netdev_actions', with a reference count
 * of 1, whose actions are a copy of from the 'ofpacts_len' bytes of
 * 'ofpacts'. */
struct dp_netdev_actions *
dp_netdev_actions_create(const struct nlattr *actions, size_t size)
{
    struct dp_netdev_actions *netdev_actions;

    netdev_actions = xmalloc(sizeof *netdev_actions);
    netdev_actions->actions = xmemdup(actions, size);
    netdev_actions->size = size;

    return netdev_actions;
}

struct dp_netdev_actions *
dp_netdev_flow_get_actions(const struct dp_netdev_flow *flow)
{
    return ovsrcu_get(struct dp_netdev_actions *, &flow->actions);
}

static void
dp_netdev_actions_free(struct dp_netdev_actions *actions)
{
    free(actions->actions);
    free(actions);
}


static void
dp_netdev_process_rxq_port(struct dp_netdev *dp,
                          struct dp_netdev_port *port,
                          struct netdev_rxq *rxq)
{
    struct ofpbuf *packet[NETDEV_MAX_RX_BATCH];
    int error, c;

    error = netdev_rxq_recv(rxq, packet, &c);
    if (!error) {
        struct pkt_metadata md = PKT_METADATA_INITIALIZER(port->port_no);
        int i;

        for (i = 0; i < c; i++) {
            dp_netdev_port_input(dp, packet[i], &md);
        }
    } else if (error != EAGAIN && error != EOPNOTSUPP) {
        static struct vlog_rate_limit rl
            = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                    netdev_get_name(port->netdev),
                    ovs_strerror(error));
    }
}

static void
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_rwlock_rdlock(&dp->port_rwlock);

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                dp_netdev_process_rxq_port(dp, port, port->rxq[i]);
            }
        }
    }

    ovs_rwlock_unlock(&dp->port_rwlock);
}

static void
dpif_netdev_wait(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_rwlock_rdlock(&dp->port_rwlock);

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                netdev_rxq_wait(port->rxq[i]);
            }
        }
    }
    ovs_rwlock_unlock(&dp->port_rwlock);
}

struct rxq_poll {
    struct dp_netdev_port *port;
    struct netdev_rxq *rx;
};

static int
pmd_load_queues(struct pmd_thread *f,
                struct rxq_poll **ppoll_list, int poll_cnt)
{
    struct dp_netdev *dp = f->dp;
    struct rxq_poll *poll_list = *ppoll_list;
    struct dp_netdev_port *port;
    int id = f->id;
    int index;
    int i;

    /* Simple scheduler for netdev rx polling. */
    ovs_rwlock_rdlock(&dp->port_rwlock);
    for (i = 0; i < poll_cnt; i++) {
         port_unref(poll_list[i].port);
    }

    poll_cnt = 0;
    index = 0;

    HMAP_FOR_EACH (port, node, &f->dp->ports) {
        if (netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                if ((index % dp->n_pmd_threads) == id) {
                    poll_list = xrealloc(poll_list, sizeof *poll_list * (poll_cnt + 1));

                    port_ref(port);
                    poll_list[poll_cnt].port = port;
                    poll_list[poll_cnt].rx = port->rxq[i];
                    poll_cnt++;
                }
                index++;
            }
        }
    }

    ovs_rwlock_unlock(&dp->port_rwlock);
    *ppoll_list = poll_list;
    return poll_cnt;
}

static void *
pmd_thread_main(void *f_)
{
    struct pmd_thread *f = f_;
    struct dp_netdev *dp = f->dp;
    unsigned int lc = 0;
    struct rxq_poll *poll_list;
    unsigned int port_seq;
    int poll_cnt;
    int i;

    poll_cnt = 0;
    poll_list = NULL;

    pmd_thread_setaffinity_cpu(f->id);
reload:
    poll_cnt = pmd_load_queues(f, &poll_list, poll_cnt);
    atomic_read(&f->change_seq, &port_seq);

    for (;;) {
        unsigned int c_port_seq;
        int i;

        for (i = 0; i < poll_cnt; i++) {
            dp_netdev_process_rxq_port(dp,  poll_list[i].port, poll_list[i].rx);
        }

        if (lc++ > 1024) {
            ovsrcu_quiesce();

            /* TODO: need completely userspace based signaling method.
             * to keep this thread entirely in userspace.
             * For now using atomic counter. */
            lc = 0;
            atomic_read_explicit(&f->change_seq, &c_port_seq, memory_order_consume);
            if (c_port_seq != port_seq) {
                break;
            }
        }
    }

    if (!latch_is_set(&f->dp->exit_latch)){
        goto reload;
    }

    for (i = 0; i < poll_cnt; i++) {
         port_unref(poll_list[i].port);
    }

    free(poll_list);
    return NULL;
}

static void
dp_netdev_set_pmd_threads(struct dp_netdev *dp, int n)
{
    int i;

    if (n == dp->n_pmd_threads) {
        return;
    }

    /* Stop existing threads. */
    latch_set(&dp->exit_latch);
    dp_netdev_reload_pmd_threads(dp);
    for (i = 0; i < dp->n_pmd_threads; i++) {
        struct pmd_thread *f = &dp->pmd_threads[i];

        xpthread_join(f->thread, NULL);
    }
    latch_poll(&dp->exit_latch);
    free(dp->pmd_threads);

    /* Start new threads. */
    dp->pmd_threads = xmalloc(n * sizeof *dp->pmd_threads);
    dp->n_pmd_threads = n;

    for (i = 0; i < n; i++) {
        struct pmd_thread *f = &dp->pmd_threads[i];

        f->dp = dp;
        f->id = i;
        atomic_store(&f->change_seq, 1);

        /* Each thread will distribute all devices rx-queues among
         * themselves. */
        f->thread = ovs_thread_create("pmd", pmd_thread_main, f);
    }
}


static void *
dp_netdev_flow_stats_new_cb(void)
{
    struct dp_netdev_flow_stats *bucket = xzalloc_cacheline(sizeof *bucket);
    ovs_mutex_init(&bucket->mutex);
    return bucket;
}

static void
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow,
                    const struct ofpbuf *packet,
                    const struct miniflow *key)
{
    uint16_t tcp_flags = miniflow_get_tcp_flags(key);
    long long int now = time_msec();
    struct dp_netdev_flow_stats *bucket;

    bucket = ovsthread_stats_bucket_get(&netdev_flow->stats,
                                        dp_netdev_flow_stats_new_cb);

    ovs_mutex_lock(&bucket->mutex);
    bucket->used = MAX(now, bucket->used);
    bucket->packet_count++;
    bucket->byte_count += ofpbuf_size(packet);
    bucket->tcp_flags |= tcp_flags;
    ovs_mutex_unlock(&bucket->mutex);
}

static void *
dp_netdev_stats_new_cb(void)
{
    struct dp_netdev_stats *bucket = xzalloc_cacheline(sizeof *bucket);
    ovs_mutex_init(&bucket->mutex);
    return bucket;
}

static void
dp_netdev_count_packet(struct dp_netdev *dp, enum dp_stat_type type)
{
    struct dp_netdev_stats *bucket;

    bucket = ovsthread_stats_bucket_get(&dp->stats, dp_netdev_stats_new_cb);
    ovs_mutex_lock(&bucket->mutex);
    bucket->n[type]++;
    ovs_mutex_unlock(&bucket->mutex);
}

static void
dp_netdev_input(struct dp_netdev *dp, struct ofpbuf *packet,
                struct pkt_metadata *md)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_flow *netdev_flow;
    struct {
        struct miniflow flow;
        uint32_t buf[FLOW_U32S];
    } key;

    if (ofpbuf_size(packet) < ETH_HEADER_LEN) {
        ofpbuf_delete(packet);
        return;
    }
    miniflow_initialize(&key.flow, key.buf);
    miniflow_extract(packet, md, &key.flow);

    netdev_flow = dp_netdev_lookup_flow(dp, &key.flow);
    if (netdev_flow) {
        struct dp_netdev_actions *actions;

        dp_netdev_flow_used(netdev_flow, packet, &key.flow);

        actions = dp_netdev_flow_get_actions(netdev_flow);
        dp_netdev_execute_actions(dp, &key.flow, packet, true, md,
                                  actions->actions, actions->size);
        dp_netdev_count_packet(dp, DP_STAT_HIT);
    } else if (dp->handler_queues) {
        dp_netdev_count_packet(dp, DP_STAT_MISS);
        dp_netdev_output_userspace(dp, packet,
                                   miniflow_hash_5tuple(&key.flow, 0)
                                   % dp->n_handlers,
                                   DPIF_UC_MISS, &key.flow, NULL);
        ofpbuf_delete(packet);
    }
}

static void
dp_netdev_port_input(struct dp_netdev *dp, struct ofpbuf *packet,
                     struct pkt_metadata *md)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    uint32_t *recirc_depth = recirc_depth_get();

    *recirc_depth = 0;
    dp_netdev_input(dp, packet, md);
}

static int
dp_netdev_output_userspace(struct dp_netdev *dp, struct ofpbuf *packet,
                           int queue_no, int type, const struct miniflow *key,
                           const struct nlattr *userdata)
{
    struct dp_netdev_queue *q;
    int error;

    fat_rwlock_rdlock(&dp->queue_rwlock);
    q = &dp->handler_queues[queue_no];
    ovs_mutex_lock(&q->mutex);
    if (q->head - q->tail < MAX_QUEUE_LEN) {
        struct dp_netdev_upcall *u = &q->upcalls[q->head++ & QUEUE_MASK];
        struct dpif_upcall *upcall = &u->upcall;
        struct ofpbuf *buf = &u->buf;
        size_t buf_size;
        struct flow flow;
        void *data;

        upcall->type = type;

        /* Allocate buffer big enough for everything. */
        buf_size = ODPUTIL_FLOW_KEY_BYTES;
        if (userdata) {
            buf_size += NLA_ALIGN(userdata->nla_len);
        }
        buf_size += ofpbuf_size(packet);
        ofpbuf_init(buf, buf_size);

        /* Put ODP flow. */
        miniflow_expand(key, &flow);
        odp_flow_key_from_flow(buf, &flow, NULL, flow.in_port.odp_port);
        upcall->key = ofpbuf_data(buf);
        upcall->key_len = ofpbuf_size(buf);

        /* Put userdata. */
        if (userdata) {
            upcall->userdata = ofpbuf_put(buf, userdata,
                                          NLA_ALIGN(userdata->nla_len));
        }

        data = ofpbuf_put(buf, ofpbuf_data(packet), ofpbuf_size(packet));
        ofpbuf_use_stub(&upcall->packet, data, ofpbuf_size(packet));
        ofpbuf_set_size(&upcall->packet, ofpbuf_size(packet));

        seq_change(q->seq);

        error = 0;
    } else {
        dp_netdev_count_packet(dp, DP_STAT_LOST);
        error = ENOBUFS;
    }
    ovs_mutex_unlock(&q->mutex);
    fat_rwlock_unlock(&dp->queue_rwlock);

    return error;
}

struct dp_netdev_execute_aux {
    struct dp_netdev *dp;
    const struct miniflow *key;
};

static void
dp_execute_cb(void *aux_, struct ofpbuf *packet,
              struct pkt_metadata *md,
              const struct nlattr *a, bool may_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev_execute_aux *aux = aux_;
    int type = nl_attr_type(a);
    struct dp_netdev_port *p;
    uint32_t *depth = recirc_depth_get();

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        p = dp_netdev_lookup_port(aux->dp, u32_to_odp(nl_attr_get_u32(a)));
        if (p) {
            netdev_send(p->netdev, packet, may_steal);
        } else if (may_steal) {
            ofpbuf_delete(packet);
        }

        break;

    case OVS_ACTION_ATTR_USERSPACE: {
        const struct nlattr *userdata;

        userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);

        if (aux->dp->n_handlers > 0) {
            dp_netdev_output_userspace(aux->dp, packet,
                                       miniflow_hash_5tuple(aux->key, 0)
                                       % aux->dp->n_handlers,
                                       DPIF_UC_ACTION, aux->key,
                                       userdata);
        }

        if (may_steal) {
            ofpbuf_delete(packet);
        }
        break;
    }

    case OVS_ACTION_ATTR_HASH: {
        const struct ovs_action_hash *hash_act;
        uint32_t hash;

        hash_act = nl_attr_get(a);
        if (hash_act->hash_alg == OVS_HASH_ALG_L4) {
            /* Hash need not be symmetric, nor does it need to include
             * L2 fields. */
            hash = miniflow_hash_5tuple(aux->key, hash_act->hash_basis);
            if (!hash) {
                hash = 1; /* 0 is not valid */
            }

        } else {
            VLOG_WARN("Unknown hash algorithm specified for the hash action.");
            hash = 2;
        }

        md->dp_hash = hash;
        break;
    }

    case OVS_ACTION_ATTR_RECIRC:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct pkt_metadata recirc_md = *md;
            struct ofpbuf *recirc_packet;

            recirc_packet = may_steal ? packet : ofpbuf_clone(packet);
            recirc_md.recirc_id = nl_attr_get_u32(a);

            (*depth)++;
            dp_netdev_input(aux->dp, recirc_packet, &recirc_md);
            (*depth)--;

            break;
        } else {
            if (may_steal) {
                ofpbuf_delete(packet);
            }
            VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
        }
        break;

    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }
}

static void
dp_netdev_execute_actions(struct dp_netdev *dp, const struct miniflow *key,
                          struct ofpbuf *packet, bool may_steal,
                          struct pkt_metadata *md,
                          const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = {dp, key};

    odp_execute_actions(&aux, packet, may_steal, md,
                        actions, actions_len, dp_execute_cb);
}

const struct dpif_class dpif_netdev_class = {
    "netdev",
    dpif_netdev_enumerate,
    dpif_netdev_port_open_type,
    dpif_netdev_open,
    dpif_netdev_close,
    dpif_netdev_destroy,
    dpif_netdev_run,
    dpif_netdev_wait,
    dpif_netdev_get_stats,
    dpif_netdev_port_add,
    dpif_netdev_port_del,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_netdev_port_dump_start,
    dpif_netdev_port_dump_next,
    dpif_netdev_port_dump_done,
    dpif_netdev_port_poll,
    dpif_netdev_port_poll_wait,
    dpif_netdev_flow_get,
    dpif_netdev_flow_put,
    dpif_netdev_flow_del,
    dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_state_init,
    dpif_netdev_flow_dump_start,
    dpif_netdev_flow_dump_next,
    NULL,
    dpif_netdev_flow_dump_done,
    dpif_netdev_flow_dump_state_uninit,
    dpif_netdev_execute,
    NULL,                       /* operate */
    dpif_netdev_recv_set,
    dpif_netdev_handlers_set,
    dpif_netdev_queue_to_priority,
    dpif_netdev_recv,
    dpif_netdev_recv_wait,
    dpif_netdev_recv_purge,
};

static void
dpif_dummy_change_port_number(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;
    odp_port_t port_no;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }
    ovs_refcount_ref(&dp->ref_cnt);
    ovs_mutex_unlock(&dp_netdev_mutex);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
        goto exit;
    }

    port_no = u32_to_odp(atoi(argv[3]));
    if (!port_no || port_no == ODPP_NONE) {
        unixctl_command_reply_error(conn, "bad port number");
        goto exit;
    }
    if (dp_netdev_lookup_port(dp, port_no)) {
        unixctl_command_reply_error(conn, "port number already in use");
        goto exit;
    }
    hmap_remove(&dp->ports, &port->node);
    port->port_no = port_no;
    hmap_insert(&dp->ports, &port->node, hash_int(odp_to_u32(port_no), 0));
    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);

exit:
    ovs_rwlock_unlock(&dp->port_rwlock);
    dp_netdev_unref(dp);
}

static void
dpif_dummy_register__(const char *type)
{
    struct dpif_class *class;

    class = xmalloc(sizeof *class);
    *class = dpif_netdev_class;
    class->type = xstrdup(type);
    dp_register_provider(class);
}

void
dpif_dummy_register(bool override)
{
    if (override) {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            if (!dp_unregister_provider(type)) {
                dpif_dummy_register__(type);
            }
        }
        sset_destroy(&types);
    }

    dpif_dummy_register__("dummy");

    unixctl_command_register("dpif-dummy/change-port-number",
                             "DP PORT NEW-NUMBER",
                             3, 3, dpif_dummy_change_port_number, NULL);
}
