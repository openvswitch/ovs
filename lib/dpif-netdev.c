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
#include "dpif-netdev.h"

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
#include "cmap.h"
#include "csum.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "dynamic-string.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "cmap.h"
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
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "packet-dpif.h"
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

#define FLOW_DUMP_MAX_BATCH 50
/* Use per thread recirc_depth to prevent recirculation loop. */
#define MAX_RECIRC_DEPTH 5
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, recirc_depth, 0)

/* Configuration parameters. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

static struct vlog_rate_limit upcall_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Stores a miniflow */

/* There are fields in the flow structure that we never use. Therefore we can
 * save a few words of memory */
#define NETDEV_KEY_BUF_SIZE_U32 (FLOW_U32S                 \
                                 - MINI_N_INLINE           \
                                 - FLOW_U32_SIZE(regs)     \
                                 - FLOW_U32_SIZE(metadata) \
                                )
struct netdev_flow_key {
    struct miniflow flow;
    uint32_t buf[NETDEV_KEY_BUF_SIZE_U32];
};

/* Exact match cache for frequently used flows
 *
 * The cache uses a 32-bit hash of the packet (which can be the RSS hash) to
 * search its entries for a miniflow that matches exactly the miniflow of the
 * packet. It stores the 'cls_rule'(rule) that matches the miniflow.
 *
 * A cache entry holds a reference to its 'dp_netdev_flow'.
 *
 * A miniflow with a given hash can be in one of EM_FLOW_HASH_SEGS different
 * entries. The 32-bit hash is split into EM_FLOW_HASH_SEGS values (each of
 * them is EM_FLOW_HASH_SHIFT bits wide and the remainder is thrown away). Each
 * value is the index of a cache entry where the miniflow could be.
 *
 *
 * Thread-safety
 * =============
 *
 * Each pmd_thread has its own private exact match cache.
 * If dp_netdev_input is not called from a pmd thread, a mutex is used.
 */

#define EM_FLOW_HASH_SHIFT 10
#define EM_FLOW_HASH_ENTRIES (1u << EM_FLOW_HASH_SHIFT)
#define EM_FLOW_HASH_MASK (EM_FLOW_HASH_ENTRIES - 1)
#define EM_FLOW_HASH_SEGS 2

struct emc_entry {
    uint32_t hash;
    struct netdev_flow_key mf;
    struct dp_netdev_flow *flow;
};

struct emc_cache {
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES];
};

/* Iterate in the exact match cache through every entry that might contain a
 * miniflow with hash 'HASH'. */
#define EMC_FOR_EACH_POS_WITH_HASH(EMC, CURRENT_ENTRY, HASH)                 \
    for (uint32_t i__ = 0, srch_hash__ = (HASH);                             \
         (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK], \
         i__ < EM_FLOW_HASH_SEGS;                                            \
         i__++, srch_hash__ >>= EM_FLOW_HASH_SHIFT)

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
 *    port_mutex
 *    emc_mutex
 *    flow_mutex
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct dpif *dpif;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Flows.
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'cls' must be made while still holding the 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    struct classifier cls;
    struct cmap flow_table OVS_GUARDED; /* Flow table. */

    /* Statistics.
     *
     * ovsthread_stats is internally synchronized. */
    struct ovsthread_stats stats; /* Contains 'struct dp_netdev_stats *'. */

    /* Ports.
     *
     * Protected by RCU.  Take the mutex to add or remove ports. */
    struct ovs_mutex port_mutex;
    struct cmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */
    void *upcall_aux;

    /* Forwarding threads. */
    struct latch exit_latch;
    struct pmd_thread *pmd_threads;
    size_t n_pmd_threads;
    int pmd_count;

    /* Exact match cache for non-pmd devices.
     * Pmd devices use instead each thread's flow_cache for this purpose.
     * Protected by emc_mutex */
    struct emc_cache flow_cache OVS_GUARDED;
    struct ovs_mutex emc_mutex;
};

static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t);

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
    struct cmap_node node;      /* Node in dp_netdev's 'ports'. */
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
 * A flow 'flow' may be accessed without a risk of being freed during an RCU
 * grace period.  Code that needs to hold onto a flow for a while
 * should try incrementing 'flow->ref_cnt' with dp_netdev_flow_ref().
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' and it doesn't protect members of 'flow'
 * from modification.
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */
struct dp_netdev_flow {
    bool dead;
    /* Packet classification. */
    const struct cls_rule cr;   /* In owning dp_netdev's 'cls'. */

    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev's 'flow_table'. */
    const struct flow flow;      /* The flow that created this entry. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;

    /* Statistics.
     *
     * Reading or writing these members requires 'mutex'. */
    struct ovsthread_stats stats; /* Contains "struct dp_netdev_flow_stats". */

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;
};

static void dp_netdev_flow_unref(struct dp_netdev_flow *);
static bool dp_netdev_flow_ref(struct dp_netdev_flow *);

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
    struct emc_cache flow_cache;
    pthread_t thread;
    int id;
    atomic_uint change_seq;
};

#define PMD_INITIAL_SEQ 1

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    uint64_t last_port_seq;
};

static int get_port_by_number(struct dp_netdev *dp, odp_port_t port_no,
                              struct dp_netdev_port **portp);
static int get_port_by_name(struct dp_netdev *dp, const char *devname,
                            struct dp_netdev_port **portp);
static void dp_netdev_free(struct dp_netdev *)
    OVS_REQUIRES(dp_netdev_mutex);
static void dp_netdev_flow_flush(struct dp_netdev *);
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex);
static void do_del_port(struct dp_netdev *dp, struct dp_netdev_port *)
    OVS_REQUIRES(dp->port_mutex);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static void dp_netdev_execute_actions(struct dp_netdev *dp,
                                      struct dpif_packet **, int c,
                                      bool may_steal, struct pkt_metadata *,
                                      struct emc_cache *flow_cache,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_input(struct dp_netdev *, struct emc_cache *,
                            struct dpif_packet **, int cnt,
                            struct pkt_metadata *);

static void dp_netdev_set_pmd_threads(struct dp_netdev *, int n);
static void dp_netdev_disable_upcall(struct dp_netdev *);

static void emc_clear_entry(struct emc_entry *ce);

static void
emc_cache_init(struct emc_cache *flow_cache)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        flow_cache->entries[i].flow = NULL;
        flow_cache->entries[i].hash = 0;
        miniflow_initialize(&flow_cache->entries[i].mf.flow,
                            flow_cache->entries[i].mf.buf);
    }
}

static void
emc_cache_uninit(struct emc_cache *flow_cache)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        emc_clear_entry(&flow_cache->entries[i]);
    }
}

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
dpif_netdev_enumerate(struct sset *all_dps,
                      const struct dpif_class *dpif_class)
{
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH(node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        if (dpif_class != dp->class) {
            /* 'dp_netdevs' contains both "netdev" and "dummy" dpifs.
             * If the class doesn't match, skip this dpif. */
             continue;
        }
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
    OVS_REQUIRES(dp->port_mutex)
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
    cmap_init(&dp->flow_table);

    ovsthread_stats_init(&dp->stats);

    ovs_mutex_init(&dp->port_mutex);
    cmap_init(&dp->ports);
    dp->port_seq = seq_create();
    latch_init(&dp->exit_latch);
    fat_rwlock_init(&dp->upcall_rwlock);

    /* Disable upcalls by default. */
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

    ovs_mutex_lock(&dp->port_mutex);
    error = do_add_port(dp, name, "internal", ODPP_LOCAL);
    ovs_mutex_unlock(&dp->port_mutex);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    ovs_mutex_init_recursive(&dp->emc_mutex);
    emc_cache_init(&dp->flow_cache);

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
        dp->dpif = *dpifp;
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port;
    struct dp_netdev_stats *bucket;
    int i;

    shash_find_and_delete(&dp_netdevs, dp->name);

    dp_netdev_set_pmd_threads(dp, 0);
    free(dp->pmd_threads);

    dp_netdev_flow_flush(dp);
    ovs_mutex_lock(&dp->port_mutex);
    CMAP_FOR_EACH (port, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    OVSTHREAD_STATS_FOR_EACH_BUCKET (bucket, i, &dp->stats) {
        ovs_mutex_destroy(&bucket->mutex);
        free_cacheline(bucket);
    }
    ovsthread_stats_destroy(&dp->stats);

    classifier_destroy(&dp->cls);
    cmap_destroy(&dp->flow_table);
    ovs_mutex_destroy(&dp->flow_mutex);
    seq_destroy(dp->port_seq);
    cmap_destroy(&dp->ports);
    fat_rwlock_destroy(&dp->upcall_rwlock);
    latch_destroy(&dp->exit_latch);

    emc_cache_uninit(&dp->flow_cache);
    ovs_mutex_destroy(&dp->emc_mutex);

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
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
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
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
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

    stats->n_flows = cmap_count(&dp->flow_table);

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
        int old_seq;

        atomic_add_relaxed(&f->change_seq, 1, &old_seq);
    }
}

static uint32_t
hash_port_no(odp_port_t port_no)
{
    return hash_int(odp_to_u32(port_no), 0);
}

static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
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

    if (netdev_is_pmd(netdev)) {
        int n_cores = ovs_numa_get_n_cores();

        if (n_cores == OVS_CORE_UNSPEC) {
            VLOG_ERR("%s, cannot get cpu core info", devname);
            return ENOENT;
        }
        /* There can only be ovs_numa_get_n_cores() pmd threads,
         * so creates a tx_q for each. */
        error = netdev_set_multiq(netdev, n_cores, NR_QUEUE);
        if (error) {
            VLOG_ERR("%s, cannot set multiq", devname);
            return errno;
        }
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
            free(port->type);
            free(port->rxq);
            free(port);
            return error;
        }
    }

    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) {
        for (i = 0; i < netdev_n_rxq(netdev); i++) {
            netdev_rxq_close(port->rxq[i]);
        }
        netdev_close(netdev);
        free(port->type);
        free(port->rxq);
        free(port);
        return error;
    }
    port->sf = sf;

    if (netdev_is_pmd(netdev)) {
        dp->pmd_count++;
        dp_netdev_set_pmd_threads(dp, NR_PMD_THREADS);
        dp_netdev_reload_pmd_threads(dp);
    }
    ovs_refcount_init(&port->ref_cnt);

    cmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
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

    ovs_mutex_lock(&dp->port_mutex);
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
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static int
dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    if (port_no == ODPP_LOCAL) {
        error = EINVAL;
    } else {
        struct dp_netdev_port *port;

        error = get_port_by_number(dp, port_no, &port);
        if (!error) {
            do_del_port(dp, port);
        }
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    return port_no != ODPP_NONE;
}

static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)
{
    struct dp_netdev_port *port;

    CMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
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

static bool
port_try_ref(struct dp_netdev_port *port)
{
    if (port) {
        return ovs_refcount_try_ref_rcu(&port->ref_cnt);
    }

    return false;
}

static void
port_destroy__(struct dp_netdev_port *port)
{
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

static void
port_unref(struct dp_netdev_port *port)
{
    if (port && ovs_refcount_unref_relaxed(&port->ref_cnt) == 1) {
        ovsrcu_postpone(port_destroy__, port);
    }
}

static int
get_port_by_name(struct dp_netdev *dp,
                 const char *devname, struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    CMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }
    return ENOENT;
}

static void
do_del_port(struct dp_netdev *dp, struct dp_netdev_port *port)
    OVS_REQUIRES(dp->port_mutex)
{
    cmap_remove(&dp->ports, &port->node, hash_odp_port(port->port_no));
    seq_change(dp->port_seq);
    if (netdev_is_pmd(port->netdev)) {
        dp_netdev_reload_pmd_threads(dp);
    }

    port_unref(port);
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

    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }

    return error;
}

static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

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

static void dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
    if (ovs_refcount_unref_relaxed(&flow->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_flow_free, flow);
    }
}

static void
dp_netdev_remove_flow(struct dp_netdev *dp, struct dp_netdev_flow *flow)
    OVS_REQUIRES(dp->flow_mutex)
{
    struct cls_rule *cr = CONST_CAST(struct cls_rule *, &flow->cr);
    struct cmap_node *node = CONST_CAST(struct cmap_node *, &flow->node);

    classifier_remove(&dp->cls, cr);
    cmap_remove(&dp->flow_table, node, flow_hash(&flow->flow, 0));
    flow->dead = true;

    dp_netdev_flow_unref(flow);
}

static void
dp_netdev_flow_flush(struct dp_netdev *dp)
{
    struct dp_netdev_flow *netdev_flow;

    ovs_mutex_lock(&dp->flow_mutex);
    CMAP_FOR_EACH (netdev_flow, node, &dp->flow_table) {
        dp_netdev_remove_flow(dp, netdev_flow);
    }
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
    struct cmap_position position;
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
    struct cmap_node *node;
    int retval;

    node = cmap_next_position(&dp->ports, &state->position);
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

static bool dp_netdev_flow_ref(struct dp_netdev_flow *flow)
{
    return ovs_refcount_try_ref_rcu(&flow->ref_cnt);
}

static inline bool
emc_entry_alive(struct emc_entry *ce)
{
    return ce->flow && !ce->flow->dead;
}

static void
emc_clear_entry(struct emc_entry *ce)
{
    if (ce->flow) {
        dp_netdev_flow_unref(ce->flow);
        ce->flow = NULL;
    }
}

static inline void
emc_change_entry(struct emc_entry *ce, struct dp_netdev_flow *flow,
                 const struct miniflow *mf, uint32_t hash)
{
    if (ce->flow != flow) {
        if (ce->flow) {
            dp_netdev_flow_unref(ce->flow);
        }

        if (dp_netdev_flow_ref(flow)) {
            ce->flow = flow;
        } else {
            ce->flow = NULL;
        }
    }
    if (mf) {
        miniflow_clone_inline(&ce->mf.flow, mf, count_1bits(mf->map));
        ce->hash = hash;
    }
}

static inline void
emc_insert(struct emc_cache *cache, const struct miniflow *mf, uint32_t hash,
           struct dp_netdev_flow *flow)
{
    struct emc_entry *to_be_replaced = NULL;
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, hash) {
        if (current_entry->hash == hash
            && miniflow_equal(&current_entry->mf.flow, mf)) {

            /* We found the entry with the 'mf' miniflow */
            emc_change_entry(current_entry, flow, NULL, 0);
            return;
        }

        /* Replacement policy: put the flow in an empty (not alive) entry, or
         * in the first entry where it can be */
        if (!to_be_replaced
            || (emc_entry_alive(to_be_replaced)
                && !emc_entry_alive(current_entry))
            || current_entry->hash < to_be_replaced->hash) {
            to_be_replaced = current_entry;
        }
    }
    /* We didn't find the miniflow in the cache.
     * The 'to_be_replaced' entry is where the new flow will be stored */

    emc_change_entry(to_be_replaced, flow, mf, hash);
}

static inline struct dp_netdev_flow *
emc_lookup(struct emc_cache *cache, const struct miniflow *mf, uint32_t hash)
{
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, hash) {
        if (current_entry->hash == hash && emc_entry_alive(current_entry)
            && miniflow_equal(&current_entry->mf.flow, mf)) {

            /* We found the entry with the 'mf' miniflow */
            return current_entry->flow;
        }
    }

    return NULL;
}

static struct dp_netdev_flow *
dp_netdev_lookup_flow(const struct dp_netdev *dp, const struct miniflow *key)
{
    struct dp_netdev_flow *netdev_flow;
    struct cls_rule *rule;

    classifier_lookup_miniflow_batch(&dp->cls, &key, &rule, 1);
    netdev_flow = dp_netdev_flow_cast(rule);

    return netdev_flow;
}

static struct dp_netdev_flow *
dp_netdev_find_flow(const struct dp_netdev *dp, const struct flow *flow)
{
    struct dp_netdev_flow *netdev_flow;

    CMAP_FOR_EACH_WITH_HASH (netdev_flow, node, flow_hash(flow, 0),
                             &dp->flow_table) {
        if (flow_equal(&netdev_flow->flow, flow)) {
            return netdev_flow;
        }
    }

    return NULL;
}

static void
get_dpif_flow_stats(const struct dp_netdev_flow *netdev_flow,
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

static void
dp_netdev_flow_to_dpif_flow(const struct dp_netdev_flow *netdev_flow,
                            struct ofpbuf *buffer, struct dpif_flow *flow)
{
    struct flow_wildcards wc;
    struct dp_netdev_actions *actions;

    minimask_expand(&netdev_flow->cr.match.mask, &wc);
    odp_flow_key_from_mask(buffer, &wc.masks, &netdev_flow->flow,
                           odp_to_u32(wc.masks.in_port.odp_port),
                           SIZE_MAX, true);
    flow->mask = ofpbuf_data(buffer);
    flow->mask_len = ofpbuf_size(buffer);

    actions = dp_netdev_flow_get_actions(netdev_flow);
    flow->actions = actions->actions;
    flow->actions_len = actions->size;

    get_dpif_flow_stats(netdev_flow, &flow->stats);
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
dpif_netdev_flow_get(const struct dpif *dpif, const struct dpif_flow_get *get)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(get->key, get->key_len, &key);
    if (error) {
        return error;
    }

    netdev_flow = dp_netdev_find_flow(dp, &key);

    if (netdev_flow) {
        dp_netdev_flow_to_dpif_flow(netdev_flow, get->buffer, get->flow);
     } else {
        error = ENOENT;
    }

    return error;
}

static int
dp_netdev_flow_add(struct dp_netdev *dp, struct match *match,
                   const struct nlattr *actions, size_t actions_len)
    OVS_REQUIRES(dp->flow_mutex)
{
    struct dp_netdev_flow *netdev_flow;

    netdev_flow = xzalloc(sizeof *netdev_flow);
    *CONST_CAST(struct flow *, &netdev_flow->flow) = match->flow;

    ovs_refcount_init(&netdev_flow->ref_cnt);

    ovsthread_stats_init(&netdev_flow->stats);

    ovsrcu_set(&netdev_flow->actions,
               dp_netdev_actions_create(actions, actions_len));

    cls_rule_init(CONST_CAST(struct cls_rule *, &netdev_flow->cr),
                  match, NETDEV_RULE_PRIORITY);
    cmap_insert(&dp->flow_table,
                CONST_CAST(struct cmap_node *, &netdev_flow->node),
                flow_hash(&match->flow, 0));
    classifier_insert(&dp->cls,
                      CONST_CAST(struct cls_rule *, &netdev_flow->cr));

    if (OVS_UNLIKELY(VLOG_IS_DBG_ENABLED())) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_cstr(&ds, "flow_add: ");
        match_format(match, &ds, OFP_DEFAULT_PRIORITY);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len);

        VLOG_DBG_RL(&upcall_rl, "%s", ds_cstr(&ds));

        ds_destroy(&ds);
    }

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
    struct miniflow miniflow;
    struct match match;
    int error;

    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &match.flow);
    if (error) {
        return error;
    }
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len,
                                          put->mask, put->mask_len,
                                          &match.flow, &match.wc.masks);
    if (error) {
        return error;
    }
    miniflow_init(&miniflow, &match.flow);

    ovs_mutex_lock(&dp->flow_mutex);
    netdev_flow = dp_netdev_lookup_flow(dp, &miniflow);
    if (!netdev_flow) {
        if (put->flags & DPIF_FP_CREATE) {
            if (cmap_count(&dp->flow_table) < MAX_FLOWS) {
                if (put->stats) {
                    memset(put->stats, 0, sizeof *put->stats);
                }
                error = dp_netdev_flow_add(dp, &match, put->actions,
                                           put->actions_len);
            } else {
                error = EFBIG;
            }
        } else {
            error = ENOENT;
        }
    } else {
        if (put->flags & DPIF_FP_MODIFY
            && flow_equal(&match.flow, &netdev_flow->flow)) {
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
    netdev_flow = dp_netdev_find_flow(dp, &key);
    if (netdev_flow) {
        if (del->stats) {
            get_dpif_flow_stats(netdev_flow, del->stats);
        }
        dp_netdev_remove_flow(dp, netdev_flow);
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&dp->flow_mutex);

    return error;
}

struct dpif_netdev_flow_dump {
    struct dpif_flow_dump up;
    struct cmap_position pos;
    int status;
    struct ovs_mutex mutex;
};

static struct dpif_netdev_flow_dump *
dpif_netdev_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netdev_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_netdev_flow_dump_create(const struct dpif *dpif_)
{
    struct dpif_netdev_flow_dump *dump;

    dump = xmalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);
    memset(&dump->pos, 0, sizeof dump->pos);
    dump->status = 0;
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_netdev_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);

    ovs_mutex_destroy(&dump->mutex);
    free(dump);
    return 0;
}

struct dpif_netdev_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_netdev_flow_dump *dump;
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
};

static struct dpif_netdev_flow_dump_thread *
dpif_netdev_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_netdev_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_netdev_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);
    struct dpif_netdev_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    return &thread->up;
}

static void
dpif_netdev_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);

    free(thread);
}

static int
dpif_netdev_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                           struct dpif_flow *flows, int max_flows)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);
    struct dpif_netdev_flow_dump *dump = thread->dump;
    struct dpif_netdev *dpif = dpif_netdev_cast(thread->up.dpif);
    struct dp_netdev_flow *netdev_flows[FLOW_DUMP_MAX_BATCH];
    struct dp_netdev *dp = get_dp_netdev(&dpif->dpif);
    int n_flows = 0;
    int i;

    ovs_mutex_lock(&dump->mutex);
    if (!dump->status) {
        for (n_flows = 0; n_flows < MIN(max_flows, FLOW_DUMP_MAX_BATCH);
             n_flows++) {
            struct cmap_node *node;

            node = cmap_next_position(&dp->flow_table, &dump->pos);
            if (!node) {
                dump->status = EOF;
                break;
            }
            netdev_flows[n_flows] = CONTAINER_OF(node, struct dp_netdev_flow,
                                                 node);
        }
    }
    ovs_mutex_unlock(&dump->mutex);

    for (i = 0; i < n_flows; i++) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];
        struct odputil_keybuf *keybuf = &thread->keybuf[i];
        struct dp_netdev_flow *netdev_flow = netdev_flows[i];
        struct dpif_flow *f = &flows[i];
        struct dp_netdev_actions *dp_actions;
        struct flow_wildcards wc;
        struct ofpbuf buf;

        minimask_expand(&netdev_flow->cr.match.mask, &wc);

        /* Key. */
        ofpbuf_use_stack(&buf, keybuf, sizeof *keybuf);
        odp_flow_key_from_flow(&buf, &netdev_flow->flow, &wc.masks,
                               netdev_flow->flow.in_port.odp_port, true);
        f->key = ofpbuf_data(&buf);
        f->key_len = ofpbuf_size(&buf);

        /* Mask. */
        ofpbuf_use_stack(&buf, maskbuf, sizeof *maskbuf);
        odp_flow_key_from_mask(&buf, &wc.masks, &netdev_flow->flow,
                               odp_to_u32(wc.masks.in_port.odp_port),
                               SIZE_MAX, true);
        f->mask = ofpbuf_data(&buf);
        f->mask_len = ofpbuf_size(&buf);

        /* Actions. */
        dp_actions = dp_netdev_flow_get_actions(netdev_flow);
        f->actions = dp_actions->actions;
        f->actions_len = dp_actions->size;

        /* Stats. */
        get_dpif_flow_stats(netdev_flow, &f->stats);
    }

    return n_flows;
}

static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dpif_packet packet, *pp;
    struct pkt_metadata *md = &execute->md;

    if (ofpbuf_size(execute->packet) < ETH_HEADER_LEN ||
        ofpbuf_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    packet.ofpbuf = *execute->packet;
    pp = &packet;

    ovs_mutex_lock(&dp->emc_mutex);
    dp_netdev_execute_actions(dp, &pp, 1, false, md,
                              &dp->flow_cache, execute->actions,
                              execute->actions_len);
    ovs_mutex_unlock(&dp->emc_mutex);

    /* Even though may_steal is set to false, some actions could modify or
     * reallocate the ofpbuf memory. We need to pass those changes to the
     * caller */
    *execute->packet = packet.ofpbuf;

    return 0;
}

static void
dpif_netdev_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    size_t i;

    for (i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            op->error = dpif_netdev_flow_put(dpif, &op->u.flow_put);
            break;

        case DPIF_OP_FLOW_DEL:
            op->error = dpif_netdev_flow_del(dpif, &op->u.flow_del);
            break;

        case DPIF_OP_EXECUTE:
            op->error = dpif_netdev_execute(dpif, &op->u.execute);
            break;

        case DPIF_OP_FLOW_GET:
            op->error = dpif_netdev_flow_get(dpif, &op->u.flow_get);
            break;
        }
    }
}

static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
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
                           struct emc_cache *flow_cache,
                           struct dp_netdev_port *port,
                           struct netdev_rxq *rxq)
{
    struct dpif_packet *packets[NETDEV_MAX_RX_BATCH];
    int error, cnt;

    error = netdev_rxq_recv(rxq, packets, &cnt);
    if (!error) {
        struct pkt_metadata md = PKT_METADATA_INITIALIZER(port->port_no);

        *recirc_depth_get() = 0;
        dp_netdev_input(dp, flow_cache, packets, cnt, &md);
    } else if (error != EAGAIN && error != EOPNOTSUPP) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                    netdev_get_name(port->netdev), ovs_strerror(error));
    }
}

static void
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp->emc_mutex);
    CMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                dp_netdev_process_rxq_port(dp, &dp->flow_cache, port,
                                           port->rxq[i]);
            }
        }
    }
    ovs_mutex_unlock(&dp->emc_mutex);
}

static void
dpif_netdev_wait(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);
    CMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                netdev_rxq_wait(port->rxq[i]);
            }
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
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
    for (i = 0; i < poll_cnt; i++) {
         port_unref(poll_list[i].port);
    }

    poll_cnt = 0;
    index = 0;

    CMAP_FOR_EACH (port, node, &f->dp->ports) {
        /* Calls port_try_ref() to prevent the main thread
         * from deleting the port. */
        if (port_try_ref(port)) {
            if (netdev_is_pmd(port->netdev)) {
                int i;

                for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                    if ((index % dp->n_pmd_threads) == id) {
                        poll_list = xrealloc(poll_list,
                                        sizeof *poll_list * (poll_cnt + 1));

                        port_ref(port);
                        poll_list[poll_cnt].port = port;
                        poll_list[poll_cnt].rx = port->rxq[i];
                        poll_cnt++;
                    }
                    index++;
                }
            }
            /* Unrefs the port_try_ref(). */
            port_unref(port);
        }
    }

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
    unsigned int port_seq = PMD_INITIAL_SEQ;
    int poll_cnt;
    int i;

    poll_cnt = 0;
    poll_list = NULL;

    pmd_thread_setaffinity_cpu(f->id);
reload:
    emc_cache_init(&f->flow_cache);
    poll_cnt = pmd_load_queues(f, &poll_list, poll_cnt);

    for (;;) {
        int i;

        for (i = 0; i < poll_cnt; i++) {
            dp_netdev_process_rxq_port(dp, &f->flow_cache, poll_list[i].port,
                                       poll_list[i].rx);
        }

        if (lc++ > 1024) {
            unsigned int seq;

            lc = 0;

            ovsrcu_quiesce();

            atomic_read_relaxed(&f->change_seq, &seq);
            if (seq != port_seq) {
                port_seq = seq;
                break;
            }
        }
    }

    emc_cache_uninit(&f->flow_cache);

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
dp_netdev_disable_upcall(struct dp_netdev *dp)
    OVS_ACQUIRES(dp->upcall_rwlock)
{
    fat_rwlock_wrlock(&dp->upcall_rwlock);
}

static void
dpif_netdev_disable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_disable_upcall(dp);
}

static void
dp_netdev_enable_upcall(struct dp_netdev *dp)
    OVS_RELEASES(dp->upcall_rwlock)
{
    fat_rwlock_unlock(&dp->upcall_rwlock);
}

static void
dpif_netdev_enable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_enable_upcall(dp);
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
        atomic_init(&f->change_seq, PMD_INITIAL_SEQ);

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
                    int cnt, int size,
                    uint16_t tcp_flags)
{
    long long int now = time_msec();
    struct dp_netdev_flow_stats *bucket;

    bucket = ovsthread_stats_bucket_get(&netdev_flow->stats,
                                        dp_netdev_flow_stats_new_cb);

    ovs_mutex_lock(&bucket->mutex);
    bucket->used = MAX(now, bucket->used);
    bucket->packet_count += cnt;
    bucket->byte_count += size;
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
dp_netdev_count_packet(struct dp_netdev *dp, enum dp_stat_type type, int cnt)
{
    struct dp_netdev_stats *bucket;

    bucket = ovsthread_stats_bucket_get(&dp->stats, dp_netdev_stats_new_cb);
    ovs_mutex_lock(&bucket->mutex);
    bucket->n[type] += cnt;
    ovs_mutex_unlock(&bucket->mutex);
}

static int
dp_netdev_upcall(struct dp_netdev *dp, struct dpif_packet *packet_,
                 struct flow *flow, struct flow_wildcards *wc,
                 enum dpif_upcall_type type, const struct nlattr *userdata,
                 struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct ofpbuf *packet = &packet_->ofpbuf;

    if (type == DPIF_UC_MISS) {
        dp_netdev_count_packet(dp, DP_STAT_MISS, 1);
    }

    if (OVS_UNLIKELY(!dp->upcall_cb)) {
        return ENODEV;
    }

    if (OVS_UNLIKELY(!VLOG_DROP_DBG(&upcall_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        struct ofpbuf key;
        char *packet_str;

        ofpbuf_init(&key, 0);
        odp_flow_key_from_flow(&key, flow, &wc->masks, flow->in_port.odp_port,
                               true);

        packet_str = ofp_packet_to_string(ofpbuf_data(packet),
                                          ofpbuf_size(packet));

        odp_flow_key_format(ofpbuf_data(&key), ofpbuf_size(&key), &ds);

        VLOG_DBG("%s: %s upcall:\n%s\n%s", dp->name,
                 dpif_upcall_type_to_string(type), ds_cstr(&ds), packet_str);

        ofpbuf_uninit(&key);
        free(packet_str);
        ds_destroy(&ds);
    }

    return dp->upcall_cb(packet, flow, type, userdata, actions, wc,
                         put_actions, dp->upcall_aux);
}

static inline uint32_t
dpif_netdev_packet_get_dp_hash(struct dpif_packet *packet,
                               const struct miniflow *mf)
{
    uint32_t hash;

    hash = dpif_packet_get_dp_hash(packet);
    if (OVS_UNLIKELY(!hash)) {
        hash = miniflow_hash_5tuple(mf, 0);
        dpif_packet_set_dp_hash(packet, hash);
    }
    return hash;
}

struct packet_batch {
    unsigned int packet_count;
    unsigned int byte_count;
    uint16_t tcp_flags;

    struct dp_netdev_flow *flow;

    struct dpif_packet *packets[NETDEV_MAX_RX_BATCH];
    struct pkt_metadata md;
};

static inline void
packet_batch_update(struct packet_batch *batch, struct dpif_packet *packet,
                    const struct miniflow *mf)
{
    batch->tcp_flags |= miniflow_get_tcp_flags(mf);
    batch->packets[batch->packet_count++] = packet;
    batch->byte_count += ofpbuf_size(&packet->ofpbuf);
}

static inline void
packet_batch_init(struct packet_batch *batch, struct dp_netdev_flow *flow,
                  struct pkt_metadata *md)
{
    batch->flow = flow;
    batch->md = *md;

    batch->packet_count = 0;
    batch->byte_count = 0;
    batch->tcp_flags = 0;
}

static inline void
packet_batch_execute(struct packet_batch *batch, struct dp_netdev *dp,
                     struct emc_cache *flow_cache)
{
    struct dp_netdev_actions *actions;
    struct dp_netdev_flow *flow = batch->flow;

    dp_netdev_flow_used(batch->flow, batch->packet_count, batch->byte_count,
                        batch->tcp_flags);

    actions = dp_netdev_flow_get_actions(flow);

    dp_netdev_execute_actions(dp, batch->packets, batch->packet_count, true,
                              &batch->md, flow_cache,
                              actions->actions, actions->size);

    dp_netdev_count_packet(dp, DP_STAT_HIT, batch->packet_count);
}

static inline bool
dp_netdev_queue_batches(struct dpif_packet *pkt, struct pkt_metadata *md,
                        struct dp_netdev_flow *flow, const struct miniflow *mf,
                        struct packet_batch *batches, size_t *n_batches,
                        size_t max_batches)
{
    struct packet_batch *batch = NULL;
    int j;

    if (OVS_UNLIKELY(!flow)) {
        return false;
    }
    /* XXX: This O(n^2) algortihm makes sense if we're operating under the
     * assumption that the number of distinct flows (and therefore the
     * number of distinct batches) is quite small.  If this turns out not
     * to be the case, it may make sense to pre sort based on the
     * netdev_flow pointer.  That done we can get the appropriate batching
     * in O(n * log(n)) instead. */
    for (j = *n_batches - 1; j >= 0; j--) {
        if (batches[j].flow == flow) {
            batch = &batches[j];
            packet_batch_update(batch, pkt, mf);
            return true;
        }
    }
    if (OVS_UNLIKELY(*n_batches >= max_batches)) {
        return false;
    }

    batch = &batches[(*n_batches)++];
    packet_batch_init(batch, flow, md);
    packet_batch_update(batch, pkt, mf);
    return true;
}

static inline void
dpif_packet_swap(struct dpif_packet **a, struct dpif_packet **b)
{
    struct dpif_packet *tmp = *a;
    *a = *b;
    *b = tmp;
}

/* Try to process all ('cnt') the 'packets' using only the exact match cache
 * 'flow_cache'. If a flow is not found for a packet 'packets[i]', or if there
 * is no matching batch for a packet's flow, the miniflow is copied into 'keys'
 * and the packet pointer is moved at the beginning of the 'packets' array.
 *
 * The function returns the number of packets that needs to be processed in the
 * 'packets' array (they have been moved to the beginning of the vector).
 */
static inline size_t
emc_processing(struct dp_netdev *dp, struct emc_cache *flow_cache,
               struct dpif_packet **packets, size_t cnt,
               struct pkt_metadata *md, struct netdev_flow_key *keys)
{
    struct netdev_flow_key key;
    struct packet_batch batches[4];
    size_t n_batches, i;
    size_t notfound_cnt = 0;

    n_batches = 0;
    miniflow_initialize(&key.flow, key.buf);
    for (i = 0; i < cnt; i++) {
        struct dp_netdev_flow *flow;
        uint32_t hash;

        if (OVS_UNLIKELY(ofpbuf_size(&packets[i]->ofpbuf) < ETH_HEADER_LEN)) {
            dpif_packet_delete(packets[i]);
            continue;
        }

        miniflow_extract(&packets[i]->ofpbuf, md, &key.flow);

        hash = dpif_netdev_packet_get_dp_hash(packets[i], &key.flow);

        flow = emc_lookup(flow_cache, &key.flow, hash);
        if (OVS_UNLIKELY(!dp_netdev_queue_batches(packets[i], md,
                                                  flow,  &key.flow,
                                                  batches, &n_batches,
                                                  ARRAY_SIZE(batches)))) {
            if (i != notfound_cnt) {
                dpif_packet_swap(&packets[i], &packets[notfound_cnt]);
            }

            keys[notfound_cnt++] = key;
        }
    }

    for (i = 0; i < n_batches; i++) {
        packet_batch_execute(&batches[i], dp, flow_cache);
    }

    return notfound_cnt;
}

static inline void
fast_path_processing(struct dp_netdev *dp, struct emc_cache *flow_cache,
                     struct dpif_packet **packets, size_t cnt,
                     struct pkt_metadata *md, struct netdev_flow_key *keys)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_RX_BATCH };
#endif
    struct packet_batch batches[PKT_ARRAY_SIZE];
    const struct miniflow *mfs[PKT_ARRAY_SIZE]; /* NULL at bad packets. */
    struct cls_rule *rules[PKT_ARRAY_SIZE];
    size_t n_batches, i;
    bool any_miss;

    for (i = 0; i < cnt; i++) {
        mfs[i] = &keys[i].flow;
    }
    any_miss = !classifier_lookup_miniflow_batch(&dp->cls, mfs, rules, cnt);
    if (OVS_UNLIKELY(any_miss) && !fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
        uint64_t actions_stub[512 / 8], slow_stub[512 / 8];
        struct ofpbuf actions, put_actions;
        struct match match;

        ofpbuf_use_stub(&actions, actions_stub, sizeof actions_stub);
        ofpbuf_use_stub(&put_actions, slow_stub, sizeof slow_stub);

        for (i = 0; i < cnt; i++) {
            const struct dp_netdev_flow *netdev_flow;
            struct ofpbuf *add_actions;
            int error;

            if (OVS_LIKELY(rules[i] || !mfs[i])) {
                continue;
            }

            /* It's possible that an earlier slow path execution installed
             * the rule this flow needs.  In this case, it's a lot cheaper
             * to catch it here than execute a miss. */
            netdev_flow = dp_netdev_lookup_flow(dp, mfs[i]);
            if (netdev_flow) {
                rules[i] = CONST_CAST(struct cls_rule *, &netdev_flow->cr);
                continue;
            }

            miniflow_expand(mfs[i], &match.flow);

            ofpbuf_clear(&actions);
            ofpbuf_clear(&put_actions);

            error = dp_netdev_upcall(dp, packets[i], &match.flow, &match.wc,
                                      DPIF_UC_MISS, NULL, &actions,
                                      &put_actions);
            if (OVS_UNLIKELY(error && error != ENOSPC)) {
                continue;
            }

            /* We can't allow the packet batching in the next loop to execute
             * the actions.  Otherwise, if there are any slow path actions,
             * we'll send the packet up twice. */
            dp_netdev_execute_actions(dp, &packets[i], 1, false, md,
                                      flow_cache, ofpbuf_data(&actions),
                                      ofpbuf_size(&actions));

            add_actions = ofpbuf_size(&put_actions)
                ? &put_actions
                : &actions;

            ovs_mutex_lock(&dp->flow_mutex);
            /* XXX: There's a brief race where this flow could have already
             * been installed since we last did the flow lookup.  This could be
             * solved by moving the mutex lock outside the loop, but that's an
             * awful long time to be locking everyone out of making flow
             * installs.  If we move to a per-core classifier, it would be
             * reasonable. */
            if (OVS_LIKELY(error != ENOSPC)
                && !dp_netdev_lookup_flow(dp, mfs[i])) {
                dp_netdev_flow_add(dp, &match, ofpbuf_data(add_actions),
                                   ofpbuf_size(add_actions));
            }
            ovs_mutex_unlock(&dp->flow_mutex);
        }

        ofpbuf_uninit(&actions);
        ofpbuf_uninit(&put_actions);
        fat_rwlock_unlock(&dp->upcall_rwlock);
    }

    n_batches = 0;
    for (i = 0; i < cnt; i++) {
        struct dpif_packet *packet = packets[i];
        struct dp_netdev_flow *flow;

        if (OVS_UNLIKELY(!rules[i] || !mfs[i])) {
            continue;
        }

        flow = dp_netdev_flow_cast(rules[i]);
        emc_insert(flow_cache, mfs[i], dpif_packet_get_dp_hash(packet), flow);
        dp_netdev_queue_batches(packet, md, flow, mfs[i], batches, &n_batches,
                                ARRAY_SIZE(batches));
    }

    for (i = 0; i < n_batches; i++) {
        packet_batch_execute(&batches[i], dp, flow_cache);
    }
}

static void
dp_netdev_input(struct dp_netdev *dp, struct emc_cache *flow_cache,
                struct dpif_packet **packets, int cnt, struct pkt_metadata *md)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_RX_BATCH };
#endif
    struct netdev_flow_key keys[PKT_ARRAY_SIZE];
    size_t newcnt;

    newcnt = emc_processing(dp, flow_cache, packets, cnt, md, keys);
    if (OVS_UNLIKELY(newcnt)) {
        fast_path_processing(dp, flow_cache, packets, newcnt, md, keys);
    }
}

struct dp_netdev_execute_aux {
    struct dp_netdev *dp;
    struct emc_cache *flow_cache;
};

static void
dpif_netdev_register_upcall_cb(struct dpif *dpif, upcall_callback *cb,
                               void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->upcall_aux = aux;
    dp->upcall_cb = cb;
}

static void
dp_execute_cb(void *aux_, struct dpif_packet **packets, int cnt,
              struct pkt_metadata *md,
              const struct nlattr *a, bool may_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev_execute_aux *aux = aux_;
    uint32_t *depth = recirc_depth_get();
    struct dp_netdev *dp = aux->dp;
    int type = nl_attr_type(a);
    struct dp_netdev_port *p;
    int i;

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        p = dp_netdev_lookup_port(dp, u32_to_odp(nl_attr_get_u32(a)));
        if (OVS_LIKELY(p)) {
            netdev_send(p->netdev, NETDEV_QID_NONE, packets, cnt, may_steal);
        } else if (may_steal) {
            for (i = 0; i < cnt; i++) {
                dpif_packet_delete(packets[i]);
            }
        }
        break;

    case OVS_ACTION_ATTR_USERSPACE:
        if (!fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
            const struct nlattr *userdata;
            struct ofpbuf actions;
            struct flow flow;

            userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);
            ofpbuf_init(&actions, 0);

            for (i = 0; i < cnt; i++) {
                int error;

                ofpbuf_clear(&actions);

                flow_extract(&packets[i]->ofpbuf, md, &flow);
                error = dp_netdev_upcall(dp, packets[i], &flow, NULL,
                                         DPIF_UC_ACTION, userdata, &actions,
                                         NULL);
                if (!error || error == ENOSPC) {
                    dp_netdev_execute_actions(dp, &packets[i], 1, false, md,
                                              aux->flow_cache,
                                              ofpbuf_data(&actions),
                                              ofpbuf_size(&actions));
                }

                if (may_steal) {
                    dpif_packet_delete(packets[i]);
                }
            }
            ofpbuf_uninit(&actions);
            fat_rwlock_unlock(&dp->upcall_rwlock);
        }

        break;

    case OVS_ACTION_ATTR_HASH: {
        const struct ovs_action_hash *hash_act;
        uint32_t hash;

        hash_act = nl_attr_get(a);

        for (i = 0; i < cnt; i++) {

            if (hash_act->hash_alg == OVS_HASH_ALG_L4) {
                /* Hash need not be symmetric, nor does it need to include
                 * L2 fields. */
                hash = hash_2words(dpif_packet_get_dp_hash(packets[i]),
                                   hash_act->hash_basis);
            } else {
                VLOG_WARN("Unknown hash algorithm specified "
                          "for the hash action.");
                hash = 2;
            }

            if (!hash) {
                hash = 1; /* 0 is not valid */
            }

            if (i == 0) {
                md->dp_hash = hash;
            }
            dpif_packet_set_dp_hash(packets[i], hash);
        }
        break;
    }

    case OVS_ACTION_ATTR_RECIRC:
        if (*depth < MAX_RECIRC_DEPTH) {

            (*depth)++;
            for (i = 0; i < cnt; i++) {
                struct dpif_packet *recirc_pkt;
                struct pkt_metadata recirc_md = *md;

                recirc_pkt = (may_steal) ? packets[i]
                                    : dpif_packet_clone(packets[i]);

                recirc_md.recirc_id = nl_attr_get_u32(a);

                /* Hash is private to each packet */
                recirc_md.dp_hash = dpif_packet_get_dp_hash(packets[i]);

                dp_netdev_input(dp, aux->flow_cache, &recirc_pkt, 1,
                                &recirc_md);
            }
            (*depth)--;

            break;
        } else {
            VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
            if (may_steal) {
                for (i = 0; i < cnt; i++) {
                    dpif_packet_delete(packets[i]);
                }
            }
        }
        break;

    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }
}

static void
dp_netdev_execute_actions(struct dp_netdev *dp,
                          struct dpif_packet **packets, int cnt,
                          bool may_steal, struct pkt_metadata *md,
                          struct emc_cache *flow_cache,
                          const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = {dp, flow_cache};

    odp_execute_actions(&aux, packets, cnt, may_steal, md, actions,
                        actions_len, dp_execute_cb);
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
    dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_create,
    dpif_netdev_flow_dump_destroy,
    dpif_netdev_flow_dump_thread_create,
    dpif_netdev_flow_dump_thread_destroy,
    dpif_netdev_flow_dump_next,
    dpif_netdev_operate,
    NULL,                       /* recv_set */
    NULL,                       /* handlers_set */
    dpif_netdev_queue_to_priority,
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */
    dpif_netdev_register_upcall_cb,
    dpif_netdev_enable_upcall,
    dpif_netdev_disable_upcall,
};

static void
dpif_dummy_change_port_number(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct dp_netdev_port *old_port;
    struct dp_netdev_port *new_port;
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

    ovs_mutex_lock(&dp->port_mutex);
    if (get_port_by_name(dp, argv[2], &old_port)) {
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

    /* Remove old port. */
    cmap_remove(&dp->ports, &old_port->node, hash_port_no(old_port->port_no));
    ovsrcu_postpone(free, old_port);

    /* Insert new port (cmap semantics mean we cannot re-insert 'old_port'). */
    new_port = xmemdup(old_port, sizeof *old_port);
    new_port->port_no = port_no;
    cmap_insert(&dp->ports, &new_port->node, hash_port_no(port_no));

    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);

exit:
    ovs_mutex_unlock(&dp->port_mutex);
    dp_netdev_unref(dp);
}

static void
dpif_dummy_delete_port(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[], void *aux OVS_UNUSED)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }
    ovs_refcount_ref(&dp->ref_cnt);
    ovs_mutex_unlock(&dp_netdev_mutex);

    ovs_mutex_lock(&dp->port_mutex);
    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
    } else if (port->port_no == ODPP_LOCAL) {
        unixctl_command_reply_error(conn, "can't delete local port");
    } else {
        do_del_port(dp, port);
        unixctl_command_reply(conn, NULL);
    }
    ovs_mutex_unlock(&dp->port_mutex);

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
                             "dp port new-number",
                             3, 3, dpif_dummy_change_port_number, NULL);
    unixctl_command_register("dpif-dummy/delete-port", "dp port",
                             2, 2, dpif_dummy_delete_port, NULL);
}
