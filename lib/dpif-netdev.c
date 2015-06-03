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

#include "cmap.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "dynamic-string.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "cmap.h"
#include "latch.h"
#include "list.h"
#include "match.h"
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
#include "packets.h"
#include "poll-loop.h"
#include "pvector.h"
#include "random.h"
#include "seq.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-arp-cache.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

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

/* Stores a miniflow with inline values */

struct netdev_flow_key {
    uint32_t hash;       /* Hash function differs for different users. */
    uint32_t len;        /* Length of the following miniflow (incl. map). */
    struct miniflow mf;
    uint64_t buf[FLOW_MAX_PACKET_U64S - MINI_N_INLINE];
};

/* Exact match cache for frequently used flows
 *
 * The cache uses a 32-bit hash of the packet (which can be the RSS hash) to
 * search its entries for a miniflow that matches exactly the miniflow of the
 * packet. It stores the 'dpcls_rule' (rule) that matches the miniflow.
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

#define EM_FLOW_HASH_SHIFT 13
#define EM_FLOW_HASH_ENTRIES (1u << EM_FLOW_HASH_SHIFT)
#define EM_FLOW_HASH_MASK (EM_FLOW_HASH_ENTRIES - 1)
#define EM_FLOW_HASH_SEGS 2

struct emc_entry {
    struct dp_netdev_flow *flow;
    struct netdev_flow_key key;   /* key.hash used for emc hash value. */
};

struct emc_cache {
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES];
    int sweep_idx;                /* For emc_cache_slow_sweep(). */
};

/* Iterate in the exact match cache through every entry that might contain a
 * miniflow with hash 'HASH'. */
#define EMC_FOR_EACH_POS_WITH_HASH(EMC, CURRENT_ENTRY, HASH)                 \
    for (uint32_t i__ = 0, srch_hash__ = (HASH);                             \
         (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK], \
         i__ < EM_FLOW_HASH_SEGS;                                            \
         i__++, srch_hash__ >>= EM_FLOW_HASH_SHIFT)

/* Simple non-wildcarding single-priority classifier. */

struct dpcls {
    struct cmap subtables_map;
    struct pvector subtables;
};

/* A rule to be inserted to the classifier. */
struct dpcls_rule {
    struct cmap_node cmap_node;   /* Within struct dpcls_subtable 'rules'. */
    struct netdev_flow_key *mask; /* Subtable's mask. */
    struct netdev_flow_key flow;  /* Matching key. */
    /* 'flow' must be the last field, additional space is allocated here. */
};

static void dpcls_init(struct dpcls *);
static void dpcls_destroy(struct dpcls *);
static void dpcls_insert(struct dpcls *, struct dpcls_rule *,
                         const struct netdev_flow_key *mask);
static void dpcls_remove(struct dpcls *, struct dpcls_rule *);
static bool dpcls_lookup(const struct dpcls *cls,
                         const struct netdev_flow_key keys[],
                         struct dpcls_rule **rules, size_t cnt);

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
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct dpif *dpif;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

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

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;

    /* Number of rx queues for each dpdk interface and the cpu mask
     * for pin of pmd threads. */
    size_t n_dpdk_rxqs;
    char *pmd_cmask;
    uint64_t last_tnl_conf_seq;
};

static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t);

enum dp_stat_type {
    DP_STAT_EXACT_HIT,          /* Packets that had an exact match (emc). */
    DP_STAT_MASKED_HIT,         /* Packets that matched in the flow table. */
    DP_STAT_MISS,               /* Packets that did not match. */
    DP_STAT_LOST,               /* Packets not passed up to the client. */
    DP_N_STATS
};

enum pmd_cycles_counter_type {
    PMD_CYCLES_POLLING,         /* Cycles spent polling NICs. */
    PMD_CYCLES_PROCESSING,      /* Cycles spent processing packets */
    PMD_N_CYCLES
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    struct pkt_metadata md;
    struct netdev *netdev;
    struct cmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct netdev_rxq **rxq;
    struct ovs_refcount ref_cnt;
    char *type;                 /* Port type as requested by user. */
};

/* Contained by struct dp_netdev_flow's 'stats' member.  */
struct dp_netdev_flow_stats {
    atomic_llong used;             /* Last used time, in monotonic msecs. */
    atomic_ullong packet_count;    /* Number of packets matched. */
    atomic_ullong byte_count;      /* Number of bytes matched. */
    atomic_uint16_t tcp_flags;     /* Bitwise-OR of seen tcp_flags values. */
};

/* A flow in 'dp_netdev_pmd_thread's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its pmd thread's classifier.  The text below calls this classifier 'cls'.
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
    const struct flow flow;      /* Unmasked flow that created this entry. */
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */
                                 /* 'flow_table'. */
    const ovs_u128 ufid;         /* Unique flow identifier. */
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */
                                 /* flow. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;

    bool dead;

    /* Statistics. */
    struct dp_netdev_flow_stats stats;

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_init() and packet_batch_execute()). */
    struct packet_batch *batch;

    /* Packet classification. */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */
    /* 'cr' must be the last member. */
};

static void dp_netdev_flow_unref(struct dp_netdev_flow *);
static bool dp_netdev_flow_ref(struct dp_netdev_flow *);
static int dpif_netdev_flow_from_nlattrs(const struct nlattr *, uint32_t,
                                         struct flow *);

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
    unsigned int size;          /* Size of 'actions', in bytes. */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */
};

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t);
struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *);
static void dp_netdev_actions_free(struct dp_netdev_actions *);

/* Contained by struct dp_netdev_pmd_thread's 'stats' member.  */
struct dp_netdev_pmd_stats {
    /* Indexed by DP_STAT_*. */
    atomic_ullong n[DP_N_STATS];
};

/* Contained by struct dp_netdev_pmd_thread's 'cycle' member.  */
struct dp_netdev_pmd_cycles {
    /* Indexed by PMD_CYCLES_*. */
    atomic_ullong n[PMD_N_CYCLES];
};

/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself.
 *
 * DPDK used PMD for accessing NIC.
 *
 * Note, instance with cpu core id NON_PMD_CORE_ID will be reserved for
 * I/O of all non-pmd threads.  There will be no actual thread created
 * for the instance.
 *
 * Each struct has its own flow table and classifier.  Packets received
 * from managed ports are looked up in the corresponding pmd thread's
 * flow table, and are executed with the found actions.
 * */
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */
    struct cmap_node node;          /* In 'dp->poll_threads'. */

    pthread_cond_t cond;            /* For synchronizing pmd thread reload. */
    struct ovs_mutex cond_mutex;    /* Mutex for condition variable. */

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected (e.g. by 'dp_netdev_mutex').  All other
     * instances will only be accessed by its own pmd thread. */
    struct emc_cache flow_cache;

    /* Classifier and Flow-Table.
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'cls' must be made while still holding the 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    struct dpcls cls;
    struct cmap flow_table OVS_GUARDED; /* Flow table. */

    /* Statistics. */
    struct dp_netdev_pmd_stats stats;

    /* Cycles counters */
    struct dp_netdev_pmd_cycles cycles;

    /* Used to count cicles. See 'cycles_counter_end()' */
    unsigned long long last_cycles;

    struct latch exit_latch;        /* For terminating the pmd thread. */
    atomic_uint change_seq;         /* For reloading pmd ports. */
    pthread_t thread;
    int index;                      /* Idx of this pmd thread among pmd*/
                                    /* threads on same numa node. */
    unsigned core_id;               /* CPU core id of this pmd thread. */
    int numa_id;                    /* numa node id of this pmd thread. */
    int tx_qid;                     /* Queue id used by this pmd thread to
                                     * send packets on all netdevs */

    /* Only a pmd thread can write on its own 'cycles' and 'stats'.
     * The main thread keeps 'stats_zero' and 'cycles_zero' as base
     * values and subtracts them from 'stats' and 'cycles' before
     * reporting to the user */
    unsigned long long stats_zero[DP_N_STATS];
    uint64_t cycles_zero[PMD_N_CYCLES];
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
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex);
static void do_del_port(struct dp_netdev *dp, struct dp_netdev_port *)
    OVS_REQUIRES(dp->port_mutex);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static void dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                                      struct dp_packet **, int c,
                                      bool may_steal,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_input(struct dp_netdev_pmd_thread *,
                            struct dp_packet **, int cnt);

static void dp_netdev_disable_upcall(struct dp_netdev *);
void dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd,
                                    struct dp_netdev *dp, int index,
                                    unsigned core_id, int numa_id);
static void dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_set_nonpmd(struct dp_netdev *dp);
static struct dp_netdev_pmd_thread *dp_netdev_get_pmd(struct dp_netdev *dp,
                                                      unsigned core_id);
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos);
static void dp_netdev_destroy_all_pmds(struct dp_netdev *dp);
static void dp_netdev_del_pmds_on_numa(struct dp_netdev *dp, int numa_id);
static void dp_netdev_set_pmds_on_numa(struct dp_netdev *dp, int numa_id);
static void dp_netdev_reset_pmd_threads(struct dp_netdev *dp);
static bool dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd);

static inline bool emc_entry_alive(struct emc_entry *ce);
static void emc_clear_entry(struct emc_entry *ce);

static void
emc_cache_init(struct emc_cache *flow_cache)
{
    int i;

    BUILD_ASSERT(offsetof(struct miniflow, inline_values) == sizeof(uint64_t));

    flow_cache->sweep_idx = 0;
    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        flow_cache->entries[i].flow = NULL;
        flow_cache->entries[i].key.hash = 0;
        flow_cache->entries[i].key.len
            = offsetof(struct miniflow, inline_values);
        miniflow_initialize(&flow_cache->entries[i].key.mf,
                            flow_cache->entries[i].key.buf);
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

/* Check and clear dead flow references slowly (one entry at each
 * invocation).  */
static void
emc_cache_slow_sweep(struct emc_cache *flow_cache)
{
    struct emc_entry *entry = &flow_cache->entries[flow_cache->sweep_idx];

    if (!emc_entry_alive(entry)) {
        emc_clear_entry(entry);
    }
    flow_cache->sweep_idx = (flow_cache->sweep_idx + 1) & EM_FLOW_HASH_MASK;
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

enum pmd_info_type {
    PMD_INFO_SHOW_STATS,  /* show how cpu cycles are spent */
    PMD_INFO_CLEAR_STATS  /* set the cycles count to 0 */
};

static void
pmd_info_show_stats(struct ds *reply,
                    struct dp_netdev_pmd_thread *pmd,
                    unsigned long long stats[DP_N_STATS],
                    uint64_t cycles[PMD_N_CYCLES])
{
    unsigned long long total_packets = 0;
    uint64_t total_cycles = 0;
    int i;

    /* These loops subtracts reference values ('*_zero') from the counters.
     * Since loads and stores are relaxed, it might be possible for a '*_zero'
     * value to be more recent than the current value we're reading from the
     * counter.  This is not a big problem, since these numbers are not
     * supposed to be too accurate, but we should at least make sure that
     * the result is not negative. */
    for (i = 0; i < DP_N_STATS; i++) {
        if (stats[i] > pmd->stats_zero[i]) {
            stats[i] -= pmd->stats_zero[i];
        } else {
            stats[i] = 0;
        }

        if (i != DP_STAT_LOST) {
            /* Lost packets are already included in DP_STAT_MISS */
            total_packets += stats[i];
        }
    }

    for (i = 0; i < PMD_N_CYCLES; i++) {
        if (cycles[i] > pmd->cycles_zero[i]) {
           cycles[i] -= pmd->cycles_zero[i];
        } else {
            cycles[i] = 0;
        }

        total_cycles += cycles[i];
    }

    ds_put_cstr(reply, (pmd->core_id == NON_PMD_CORE_ID)
                        ? "main thread" : "pmd thread");

    if (pmd->numa_id != OVS_NUMA_UNSPEC) {
        ds_put_format(reply, " numa_id %d", pmd->numa_id);
    }
    if (pmd->core_id != OVS_CORE_UNSPEC && pmd->core_id != NON_PMD_CORE_ID) {
        ds_put_format(reply, " core_id %u", pmd->core_id);
    }
    ds_put_cstr(reply, ":\n");

    ds_put_format(reply,
                  "\temc hits:%llu\n\tmegaflow hits:%llu\n"
                  "\tmiss:%llu\n\tlost:%llu\n",
                  stats[DP_STAT_EXACT_HIT], stats[DP_STAT_MASKED_HIT],
                  stats[DP_STAT_MISS], stats[DP_STAT_LOST]);

    if (total_cycles == 0) {
        return;
    }

    ds_put_format(reply,
                  "\tpolling cycles:%"PRIu64" (%.02f%%)\n"
                  "\tprocessing cycles:%"PRIu64" (%.02f%%)\n",
                  cycles[PMD_CYCLES_POLLING],
                  cycles[PMD_CYCLES_POLLING] / (double)total_cycles * 100,
                  cycles[PMD_CYCLES_PROCESSING],
                  cycles[PMD_CYCLES_PROCESSING] / (double)total_cycles * 100);

    if (total_packets == 0) {
        return;
    }

    ds_put_format(reply,
                  "\tavg cycles per packet: %.02f (%"PRIu64"/%llu)\n",
                  total_cycles / (double)total_packets,
                  total_cycles, total_packets);

    ds_put_format(reply,
                  "\tavg processing cycles per packet: "
                  "%.02f (%"PRIu64"/%llu)\n",
                  cycles[PMD_CYCLES_PROCESSING] / (double)total_packets,
                  cycles[PMD_CYCLES_PROCESSING], total_packets);
}

static void
pmd_info_clear_stats(struct ds *reply OVS_UNUSED,
                    struct dp_netdev_pmd_thread *pmd,
                    unsigned long long stats[DP_N_STATS],
                    uint64_t cycles[PMD_N_CYCLES])
{
    int i;

    /* We cannot write 'stats' and 'cycles' (because they're written by other
     * threads) and we shouldn't change 'stats' (because they're used to count
     * datapath stats, which must not be cleared here).  Instead, we save the
     * current values and subtract them from the values to be displayed in the
     * future */
    for (i = 0; i < DP_N_STATS; i++) {
        pmd->stats_zero[i] = stats[i];
    }
    for (i = 0; i < PMD_N_CYCLES; i++) {
        pmd->cycles_zero[i] = cycles[i];
    }
}

static void
dpif_netdev_pmd_info(struct unixctl_conn *conn, int argc, const char *argv[],
                     void *aux)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev *dp = NULL;
    enum pmd_info_type type = *(enum pmd_info_type *) aux;

    ovs_mutex_lock(&dp_netdev_mutex);

    if (argc == 2) {
        dp = shash_find_data(&dp_netdevs, argv[1]);
    } else if (shash_count(&dp_netdevs) == 1) {
        /* There's only one datapath */
        dp = shash_first(&dp_netdevs)->data;
    }

    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn,
                                    "please specify an existing datapath");
        return;
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        unsigned long long stats[DP_N_STATS];
        uint64_t cycles[PMD_N_CYCLES];
        int i;

        /* Read current stats and cycle counters */
        for (i = 0; i < ARRAY_SIZE(stats); i++) {
            atomic_read_relaxed(&pmd->stats.n[i], &stats[i]);
        }
        for (i = 0; i < ARRAY_SIZE(cycles); i++) {
            atomic_read_relaxed(&pmd->cycles.n[i], &cycles[i]);
        }

        if (type == PMD_INFO_CLEAR_STATS) {
            pmd_info_clear_stats(&reply, pmd, stats, cycles);
        } else if (type == PMD_INFO_SHOW_STATS) {
            pmd_info_show_stats(&reply, pmd, stats, cycles);
        }
    }

    ovs_mutex_unlock(&dp_netdev_mutex);

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static int
dpif_netdev_init(void)
{
    static enum pmd_info_type show_aux = PMD_INFO_SHOW_STATS,
                              clear_aux = PMD_INFO_CLEAR_STATS;

    unixctl_command_register("dpif-netdev/pmd-stats-show", "[dp]",
                             0, 1, dpif_netdev_pmd_info,
                             (void *)&show_aux);
    unixctl_command_register("dpif-netdev/pmd-stats-clear", "[dp]",
                             0, 1, dpif_netdev_pmd_info,
                             (void *)&clear_aux);
    return 0;
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

    ovs_mutex_init(&dp->port_mutex);
    cmap_init(&dp->ports);
    dp->port_seq = seq_create();
    fat_rwlock_init(&dp->upcall_rwlock);

    /* Disable upcalls by default. */
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

    cmap_init(&dp->poll_threads);
    ovs_mutex_init_recursive(&dp->non_pmd_mutex);
    ovsthread_key_create(&dp->per_pmd_key, NULL);

    dp_netdev_set_nonpmd(dp);
    dp->n_dpdk_rxqs = NR_QUEUE;

    ovs_mutex_lock(&dp->port_mutex);
    error = do_add_port(dp, name, "internal", ODPP_LOCAL);
    ovs_mutex_unlock(&dp->port_mutex);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    dp->last_tnl_conf_seq = seq_read(tnl_conf_seq);
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

static void
dp_netdev_destroy_upcall_lock(struct dp_netdev *dp)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    /* Check that upcalls are disabled, i.e. that the rwlock is taken */
    ovs_assert(fat_rwlock_tryrdlock(&dp->upcall_rwlock));

    /* Before freeing a lock we should release it */
    fat_rwlock_unlock(&dp->upcall_rwlock);
    fat_rwlock_destroy(&dp->upcall_rwlock);
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port;

    shash_find_and_delete(&dp_netdevs, dp->name);

    dp_netdev_destroy_all_pmds(dp);
    cmap_destroy(&dp->poll_threads);
    ovs_mutex_destroy(&dp->non_pmd_mutex);
    ovsthread_key_delete(dp->per_pmd_key);

    ovs_mutex_lock(&dp->port_mutex);
    CMAP_FOR_EACH (port, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    seq_destroy(dp->port_seq);
    cmap_destroy(&dp->ports);

    /* Upcalls must be disabled at this point */
    dp_netdev_destroy_upcall_lock(dp);

    free(dp->pmd_cmask);
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

/* Add 'n' to the atomic variable 'var' non-atomically and using relaxed
 * load/store semantics.  While the increment is not atomic, the load and
 * store operations are, making it impossible to read inconsistent values.
 *
 * This is used to update thread local stats counters. */
static void
non_atomic_ullong_add(atomic_ullong *var, unsigned long long n)
{
    unsigned long long tmp;

    atomic_read_relaxed(var, &tmp);
    tmp += n;
    atomic_store_relaxed(var, tmp);
}

static int
dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    stats->n_flows = stats->n_hit = stats->n_missed = stats->n_lost = 0;
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        unsigned long long n;
        stats->n_flows += cmap_count(&pmd->flow_table);

        atomic_read_relaxed(&pmd->stats.n[DP_STAT_MASKED_HIT], &n);
        stats->n_hit += n;
        atomic_read_relaxed(&pmd->stats.n[DP_STAT_EXACT_HIT], &n);
        stats->n_hit += n;
        atomic_read_relaxed(&pmd->stats.n[DP_STAT_MISS], &n);
        stats->n_missed += n;
        atomic_read_relaxed(&pmd->stats.n[DP_STAT_LOST], &n);
        stats->n_lost += n;
    }
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;

    return 0;
}

static void
dp_netdev_reload_pmd__(struct dp_netdev_pmd_thread *pmd)
{
    int old_seq;

    if (pmd->core_id == NON_PMD_CORE_ID) {
        return;
    }

    ovs_mutex_lock(&pmd->cond_mutex);
    atomic_add_relaxed(&pmd->change_seq, 1, &old_seq);
    ovs_mutex_cond_wait(&pmd->cond, &pmd->cond_mutex);
    ovs_mutex_unlock(&pmd->cond_mutex);
}

/* Causes all pmd threads to reload its tx/rx devices.
 * Must be called after adding/removing ports. */
static void
dp_netdev_reload_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_reload_pmd__(pmd);
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

    /* Reject devices already in 'dp'. */
    if (!get_port_by_name(dp, devname, &port)) {
        return EEXIST;
    }

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
         * so creates a txq for each, and one extra for the non
         * pmd threads. */
        error = netdev_set_multiq(netdev, n_cores + 1, dp->n_dpdk_rxqs);
        if (error && (error != EOPNOTSUPP)) {
            VLOG_ERR("%s, cannot set multiq", devname);
            return errno;
        }
    }
    port = xzalloc(sizeof *port);
    port->md = PKT_METADATA_INITIALIZER(port_no);
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

    ovs_refcount_init(&port->ref_cnt);
    cmap_insert(&dp->ports, &port->node, hash_port_no(port_no));

    if (netdev_is_pmd(netdev)) {
        dp_netdev_set_pmds_on_numa(dp, netdev_get_numa_id(netdev));
        dp_netdev_reload_pmds(dp);
    }
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
        if (port->md.in_port.odp_port == port_no) {
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
port_unref(struct dp_netdev_port *port)
{
    if (port && ovs_refcount_unref_relaxed(&port->ref_cnt) == 1) {
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

static int
get_n_pmd_threads_on_numa(struct dp_netdev *dp, int numa_id)
{
    struct dp_netdev_pmd_thread *pmd;
    int n_pmds = 0;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->numa_id == numa_id) {
            n_pmds++;
        }
    }

    return n_pmds;
}

/* Returns 'true' if there is a port with pmd netdev and the netdev
 * is on numa node 'numa_id'. */
static bool
has_pmd_port_for_numa(struct dp_netdev *dp, int numa_id)
{
    struct dp_netdev_port *port;

    CMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_pmd(port->netdev)
            && netdev_get_numa_id(port->netdev) == numa_id) {
            return true;
        }
    }

    return false;
}


static void
do_del_port(struct dp_netdev *dp, struct dp_netdev_port *port)
    OVS_REQUIRES(dp->port_mutex)
{
    cmap_remove(&dp->ports, &port->node,
                hash_odp_port(port->md.in_port.odp_port));
    seq_change(dp->port_seq);
    if (netdev_is_pmd(port->netdev)) {
        int numa_id = netdev_get_numa_id(port->netdev);

        /* If there is no netdev on the numa node, deletes the pmd threads
         * for that numa.  Else, just reloads the queues.  */
        if (!has_pmd_port_for_numa(dp, numa_id)) {
            dp_netdev_del_pmds_on_numa(dp, numa_id);
        }
        dp_netdev_reload_pmds(dp);
    }

    port_unref(port);
}

static void
answer_port_query(const struct dp_netdev_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->md.in_port.odp_port;
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
    dp_netdev_actions_free(dp_netdev_flow_get_actions(flow));
    free(flow);
}

static void dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
    if (ovs_refcount_unref_relaxed(&flow->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_flow_free, flow);
    }
}

static uint32_t
dp_netdev_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

static void
dp_netdev_pmd_remove_flow(struct dp_netdev_pmd_thread *pmd,
                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct cmap_node *node = CONST_CAST(struct cmap_node *, &flow->node);

    dpcls_remove(&pmd->cls, &flow->cr);
    cmap_remove(&pmd->flow_table, node, dp_netdev_flow_hash(&flow->ufid));
    flow->dead = true;

    dp_netdev_flow_unref(flow);
}

static void
dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *netdev_flow;

    ovs_mutex_lock(&pmd->flow_mutex);
    CMAP_FOR_EACH (netdev_flow, node, &pmd->flow_table) {
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
}

static int
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_pmd_flow_flush(pmd);
    }

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
        dpif_port->port_no = port->md.in_port.odp_port;

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
dp_netdev_flow_cast(const struct dpcls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct dp_netdev_flow, cr) : NULL;
}

static bool dp_netdev_flow_ref(struct dp_netdev_flow *flow)
{
    return ovs_refcount_try_ref_rcu(&flow->ref_cnt);
}

/* netdev_flow_key utilities.
 *
 * netdev_flow_key is basically a miniflow.  We use these functions
 * (netdev_flow_key_clone, netdev_flow_key_equal, ...) instead of the miniflow
 * functions (miniflow_clone_inline, miniflow_equal, ...), because:
 *
 * - Since we are dealing exclusively with miniflows created by
 *   miniflow_extract(), if the map is different the miniflow is different.
 *   Therefore we can be faster by comparing the map and the miniflow in a
 *   single memcmp().
 * _ netdev_flow_key's miniflow has always inline values.
 * - These functions can be inlined by the compiler.
 *
 * The following assertions make sure that what we're doing with miniflow is
 * safe
 */
BUILD_ASSERT_DECL(offsetof(struct miniflow, inline_values)
                  == sizeof(uint64_t));

/* Given the number of bits set in the miniflow map, returns the size of the
 * 'netdev_flow_key.mf' */
static inline uint32_t
netdev_flow_key_size(uint32_t flow_u32s)
{
    return offsetof(struct miniflow, inline_values) +
        MINIFLOW_VALUES_SIZE(flow_u32s);
}

static inline bool
netdev_flow_key_equal(const struct netdev_flow_key *a,
                      const struct netdev_flow_key *b)
{
    /* 'b->len' may be not set yet. */
    return a->hash == b->hash && !memcmp(&a->mf, &b->mf, a->len);
}

/* Used to compare 'netdev_flow_key' in the exact match cache to a miniflow.
 * The maps are compared bitwise, so both 'key->mf' 'mf' must have been
 * generated by miniflow_extract. */
static inline bool
netdev_flow_key_equal_mf(const struct netdev_flow_key *key,
                         const struct miniflow *mf)
{
    return !memcmp(&key->mf, mf, key->len);
}

static inline void
netdev_flow_key_clone(struct netdev_flow_key *dst,
                      const struct netdev_flow_key *src)
{
    memcpy(dst, src,
           offsetof(struct netdev_flow_key, mf) + src->len);
}

/* Slow. */
static void
netdev_flow_key_from_flow(struct netdev_flow_key *dst,
                          const struct flow *src)
{
    struct dp_packet packet;
    uint64_t buf_stub[512 / 8];

    miniflow_initialize(&dst->mf, dst->buf);

    dp_packet_use_stub(&packet, buf_stub, sizeof buf_stub);
    pkt_metadata_from_flow(&packet.md, src);
    flow_compose(&packet, src);
    miniflow_extract(&packet, &dst->mf);
    dp_packet_uninit(&packet);

    dst->len = netdev_flow_key_size(count_1bits(dst->mf.map));
    dst->hash = 0; /* Not computed yet. */
}

/* Initialize a netdev_flow_key 'mask' from 'match'. */
static inline void
netdev_flow_mask_init(struct netdev_flow_key *mask,
                      const struct match *match)
{
    const uint64_t *mask_u64 = (const uint64_t *) &match->wc.masks;
    uint64_t *dst = mask->mf.inline_values;
    uint64_t map, mask_map = 0;
    uint32_t hash = 0;
    int n;

    /* Only check masks that make sense for the flow. */
    map = flow_wc_map(&match->flow);

    while (map) {
        uint64_t rm1bit = rightmost_1bit(map);
        int i = raw_ctz(map);

        if (mask_u64[i]) {
            mask_map |= rm1bit;
            *dst++ = mask_u64[i];
            hash = hash_add64(hash, mask_u64[i]);
        }
        map -= rm1bit;
    }

    mask->mf.values_inline = true;
    mask->mf.map = mask_map;

    hash = hash_add64(hash, mask_map);

    n = dst - mask->mf.inline_values;

    mask->hash = hash_finish(hash, n * 8);
    mask->len = netdev_flow_key_size(n);
}

/* Initializes 'dst' as a copy of 'src' masked with 'mask'. */
static inline void
netdev_flow_key_init_masked(struct netdev_flow_key *dst,
                            const struct flow *flow,
                            const struct netdev_flow_key *mask)
{
    uint64_t *dst_u64 = dst->mf.inline_values;
    const uint64_t *mask_u64 = mask->mf.inline_values;
    uint32_t hash = 0;
    uint64_t value;

    dst->len = mask->len;
    dst->mf.values_inline = true;
    dst->mf.map = mask->mf.map;

    FLOW_FOR_EACH_IN_MAP(value, flow, mask->mf.map) {
        *dst_u64 = value & *mask_u64++;
        hash = hash_add64(hash, *dst_u64++);
    }
    dst->hash = hash_finish(hash, (dst_u64 - dst->mf.inline_values) * 8);
}

/* Iterate through all netdev_flow_key u64 values specified by 'MAP' */
#define NETDEV_FLOW_KEY_FOR_EACH_IN_MAP(VALUE, KEY, MAP)           \
    for (struct mf_for_each_in_map_aux aux__                       \
             = { (KEY)->mf.inline_values, (KEY)->mf.map, MAP };    \
         mf_get_next_in_map(&aux__, &(VALUE));                     \
        )

/* Returns a hash value for the bits of 'key' where there are 1-bits in
 * 'mask'. */
static inline uint32_t
netdev_flow_key_hash_in_mask(const struct netdev_flow_key *key,
                             const struct netdev_flow_key *mask)
{
    const uint64_t *p = mask->mf.inline_values;
    uint32_t hash = 0;
    uint64_t key_u64;

    NETDEV_FLOW_KEY_FOR_EACH_IN_MAP(key_u64, key, mask->mf.map) {
        hash = hash_add64(hash, key_u64 & *p++);
    }

    return hash_finish(hash, (p - mask->mf.inline_values) * 8);
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
                 const struct netdev_flow_key *key)
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
    if (key) {
        netdev_flow_key_clone(&ce->key, key);
    }
}

static inline void
emc_insert(struct emc_cache *cache, const struct netdev_flow_key *key,
           struct dp_netdev_flow *flow)
{
    struct emc_entry *to_be_replaced = NULL;
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) {
        if (netdev_flow_key_equal(&current_entry->key, key)) {
            /* We found the entry with the 'mf' miniflow */
            emc_change_entry(current_entry, flow, NULL);
            return;
        }

        /* Replacement policy: put the flow in an empty (not alive) entry, or
         * in the first entry where it can be */
        if (!to_be_replaced
            || (emc_entry_alive(to_be_replaced)
                && !emc_entry_alive(current_entry))
            || current_entry->key.hash < to_be_replaced->key.hash) {
            to_be_replaced = current_entry;
        }
    }
    /* We didn't find the miniflow in the cache.
     * The 'to_be_replaced' entry is where the new flow will be stored */

    emc_change_entry(to_be_replaced, flow, key);
}

static inline struct dp_netdev_flow *
emc_lookup(struct emc_cache *cache, const struct netdev_flow_key *key)
{
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) {
        if (current_entry->key.hash == key->hash
            && emc_entry_alive(current_entry)
            && netdev_flow_key_equal_mf(&current_entry->key, &key->mf)) {

            /* We found the entry with the 'key->mf' miniflow */
            return current_entry->flow;
        }
    }

    return NULL;
}

static struct dp_netdev_flow *
dp_netdev_pmd_lookup_flow(const struct dp_netdev_pmd_thread *pmd,
                          const struct netdev_flow_key *key)
{
    struct dp_netdev_flow *netdev_flow;
    struct dpcls_rule *rule;

    dpcls_lookup(&pmd->cls, key, &rule, 1);
    netdev_flow = dp_netdev_flow_cast(rule);

    return netdev_flow;
}

static struct dp_netdev_flow *
dp_netdev_pmd_find_flow(const struct dp_netdev_pmd_thread *pmd,
                        const ovs_u128 *ufidp, const struct nlattr *key,
                        size_t key_len)
{
    struct dp_netdev_flow *netdev_flow;
    struct flow flow;
    ovs_u128 ufid;

    /* If a UFID is not provided, determine one based on the key. */
    if (!ufidp && key && key_len
        && !dpif_netdev_flow_from_nlattrs(key, key_len, &flow)) {
        dpif_flow_hash(pmd->dp->dpif, &flow, sizeof flow, &ufid);
        ufidp = &ufid;
    }

    if (ufidp) {
        CMAP_FOR_EACH_WITH_HASH (netdev_flow, node, dp_netdev_flow_hash(ufidp),
                                 &pmd->flow_table) {
            if (ovs_u128_equal(&netdev_flow->ufid, ufidp)) {
                return netdev_flow;
            }
        }
    }

    return NULL;
}

static void
get_dpif_flow_stats(const struct dp_netdev_flow *netdev_flow_,
                    struct dpif_flow_stats *stats)
{
    struct dp_netdev_flow *netdev_flow;
    unsigned long long n;
    long long used;
    uint16_t flags;

    netdev_flow = CONST_CAST(struct dp_netdev_flow *, netdev_flow_);

    atomic_read_relaxed(&netdev_flow->stats.packet_count, &n);
    stats->n_packets = n;
    atomic_read_relaxed(&netdev_flow->stats.byte_count, &n);
    stats->n_bytes = n;
    atomic_read_relaxed(&netdev_flow->stats.used, &used);
    stats->used = used;
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    stats->tcp_flags = flags;
}

/* Converts to the dpif_flow format, using 'key_buf' and 'mask_buf' for
 * storing the netlink-formatted key/mask. 'key_buf' may be the same as
 * 'mask_buf'. Actions will be returned without copying, by relying on RCU to
 * protect them. */
static void
dp_netdev_flow_to_dpif_flow(const struct dp_netdev_flow *netdev_flow,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf,
                            struct dpif_flow *flow, bool terse)
{
    if (terse) {
        memset(flow, 0, sizeof *flow);
    } else {
        struct flow_wildcards wc;
        struct dp_netdev_actions *actions;
        size_t offset;

        miniflow_expand(&netdev_flow->cr.mask->mf, &wc.masks);

        /* Key */
        offset = key_buf->size;
        flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(key_buf, &netdev_flow->flow, &wc.masks,
                               netdev_flow->flow.in_port.odp_port, true);
        flow->key_len = key_buf->size - offset;

        /* Mask */
        offset = mask_buf->size;
        flow->mask = ofpbuf_tail(mask_buf);
        odp_flow_key_from_mask(mask_buf, &wc.masks, &netdev_flow->flow,
                               odp_to_u32(wc.masks.in_port.odp_port),
                               SIZE_MAX, true);
        flow->mask_len = mask_buf->size - offset;

        /* Actions */
        actions = dp_netdev_flow_get_actions(netdev_flow);
        flow->actions = actions->actions;
        flow->actions_len = actions->size;
    }

    flow->ufid = netdev_flow->ufid;
    flow->ufid_present = true;
    flow->pmd_id = netdev_flow->pmd_id;
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
    struct dp_netdev_pmd_thread *pmd;
    unsigned pmd_id = get->pmd_id == PMD_ID_NULL
                      ? NON_PMD_CORE_ID : get->pmd_id;
    int error = 0;

    pmd = dp_netdev_get_pmd(dp, pmd_id);
    if (!pmd) {
        return EINVAL;
    }

    netdev_flow = dp_netdev_pmd_find_flow(pmd, get->ufid, get->key,
                                          get->key_len);
    if (netdev_flow) {
        dp_netdev_flow_to_dpif_flow(netdev_flow, get->buffer, get->buffer,
                                    get->flow, false);
    } else {
        error = ENOENT;
    }
    dp_netdev_pmd_unref(pmd);


    return error;
}

static struct dp_netdev_flow *
dp_netdev_flow_add(struct dp_netdev_pmd_thread *pmd,
                   struct match *match, const ovs_u128 *ufid,
                   const struct nlattr *actions, size_t actions_len)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct dp_netdev_flow *flow;
    struct netdev_flow_key mask;

    netdev_flow_mask_init(&mask, match);
    /* Make sure wc does not have metadata. */
    ovs_assert(!(mask.mf.map & (MINIFLOW_MAP(metadata) | MINIFLOW_MAP(regs))));

    /* Do not allocate extra space. */
    flow = xmalloc(sizeof *flow - sizeof flow->cr.flow.mf + mask.len);
    memset(&flow->stats, 0, sizeof flow->stats);
    flow->dead = false;
    flow->batch = NULL;
    *CONST_CAST(unsigned *, &flow->pmd_id) = pmd->core_id;
    *CONST_CAST(struct flow *, &flow->flow) = match->flow;
    *CONST_CAST(ovs_u128 *, &flow->ufid) = *ufid;
    ovs_refcount_init(&flow->ref_cnt);
    ovsrcu_set(&flow->actions, dp_netdev_actions_create(actions, actions_len));

    netdev_flow_key_init_masked(&flow->cr.flow, &match->flow, &mask);
    dpcls_insert(&pmd->cls, &flow->cr, &mask);

    cmap_insert(&pmd->flow_table, CONST_CAST(struct cmap_node *, &flow->node),
                dp_netdev_flow_hash(&flow->ufid));

    if (OVS_UNLIKELY(VLOG_IS_DBG_ENABLED())) {
        struct match match;
        struct ds ds = DS_EMPTY_INITIALIZER;

        match.flow = flow->flow;
        miniflow_expand(&flow->cr.mask->mf, &match.wc.masks);

        ds_put_cstr(&ds, "flow_add: ");
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " ");
        match_format(&match, &ds, OFP_DEFAULT_PRIORITY);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len);

        VLOG_DBG_RL(&upcall_rl, "%s", ds_cstr(&ds));

        ds_destroy(&ds);
    }

    return flow;
}

static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct netdev_flow_key key;
    struct dp_netdev_pmd_thread *pmd;
    struct match match;
    ovs_u128 ufid;
    unsigned pmd_id = put->pmd_id == PMD_ID_NULL
                      ? NON_PMD_CORE_ID : put->pmd_id;
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

    pmd = dp_netdev_get_pmd(dp, pmd_id);
    if (!pmd) {
        return EINVAL;
    }

    /* Must produce a netdev_flow_key for lookup.
     * This interface is no longer performance critical, since it is not used
     * for upcall processing any more. */
    netdev_flow_key_from_flow(&key, &match.flow);

    if (put->ufid) {
        ufid = *put->ufid;
    } else {
        dpif_flow_hash(dpif, &match.flow, sizeof match.flow, &ufid);
    }

    ovs_mutex_lock(&pmd->flow_mutex);
    netdev_flow = dp_netdev_pmd_lookup_flow(pmd, &key);
    if (!netdev_flow) {
        if (put->flags & DPIF_FP_CREATE) {
            if (cmap_count(&pmd->flow_table) < MAX_FLOWS) {
                if (put->stats) {
                    memset(put->stats, 0, sizeof *put->stats);
                }
                dp_netdev_flow_add(pmd, &match, &ufid, put->actions,
                                   put->actions_len);
                error = 0;
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
                /* XXX: The userspace datapath uses thread local statistics
                 * (for flows), which should be updated only by the owning
                 * thread.  Since we cannot write on stats memory here,
                 * we choose not to support this flag.  Please note:
                 * - This feature is currently used only by dpctl commands with
                 *   option --clear.
                 * - Should the need arise, this operation can be implemented
                 *   by keeping a base value (to be update here) for each
                 *   counter, and subtracting it before outputting the stats */
                error = EOPNOTSUPP;
            }

            ovsrcu_postpone(dp_netdev_actions_free, old_actions);
        } else if (put->flags & DPIF_FP_CREATE) {
            error = EEXIST;
        } else {
            /* Overlapping flow. */
            error = EINVAL;
        }
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
    dp_netdev_pmd_unref(pmd);

    return error;
}

static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct dp_netdev_pmd_thread *pmd;
    unsigned pmd_id = del->pmd_id == PMD_ID_NULL
                      ? NON_PMD_CORE_ID : del->pmd_id;
    int error = 0;

    pmd = dp_netdev_get_pmd(dp, pmd_id);
    if (!pmd) {
        return EINVAL;
    }

    ovs_mutex_lock(&pmd->flow_mutex);
    netdev_flow = dp_netdev_pmd_find_flow(pmd, del->ufid, del->key,
                                          del->key_len);
    if (netdev_flow) {
        if (del->stats) {
            get_dpif_flow_stats(netdev_flow, del->stats);
        }
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
    dp_netdev_pmd_unref(pmd);

    return error;
}

struct dpif_netdev_flow_dump {
    struct dpif_flow_dump up;
    struct cmap_position poll_thread_pos;
    struct cmap_position flow_pos;
    struct dp_netdev_pmd_thread *cur_pmd;
    int status;
    struct ovs_mutex mutex;
};

static struct dpif_netdev_flow_dump *
dpif_netdev_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netdev_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_netdev_flow_dump_create(const struct dpif *dpif_, bool terse)
{
    struct dpif_netdev_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);
    dump->up.terse = terse;
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
    struct dp_netdev_flow *netdev_flows[FLOW_DUMP_MAX_BATCH];
    int n_flows = 0;
    int i;

    ovs_mutex_lock(&dump->mutex);
    if (!dump->status) {
        struct dpif_netdev *dpif = dpif_netdev_cast(thread->up.dpif);
        struct dp_netdev *dp = get_dp_netdev(&dpif->dpif);
        struct dp_netdev_pmd_thread *pmd = dump->cur_pmd;
        int flow_limit = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

        /* First call to dump_next(), extracts the first pmd thread.
         * If there is no pmd thread, returns immediately. */
        if (!pmd) {
            pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
            if (!pmd) {
                ovs_mutex_unlock(&dump->mutex);
                return n_flows;

            }
        }

        do {
            for (n_flows = 0; n_flows < flow_limit; n_flows++) {
                struct cmap_node *node;

                node = cmap_next_position(&pmd->flow_table, &dump->flow_pos);
                if (!node) {
                    break;
                }
                netdev_flows[n_flows] = CONTAINER_OF(node,
                                                     struct dp_netdev_flow,
                                                     node);
            }
            /* When finishing dumping the current pmd thread, moves to
             * the next. */
            if (n_flows < flow_limit) {
                memset(&dump->flow_pos, 0, sizeof dump->flow_pos);
                dp_netdev_pmd_unref(pmd);
                pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
                if (!pmd) {
                    dump->status = EOF;
                    break;
                }
            }
            /* Keeps the reference to next caller. */
            dump->cur_pmd = pmd;

            /* If the current dump is empty, do not exit the loop, since the
             * remaining pmds could have flows to be dumped.  Just dumps again
             * on the new 'pmd'. */
        } while (!n_flows);
    }
    ovs_mutex_unlock(&dump->mutex);

    for (i = 0; i < n_flows; i++) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];
        struct odputil_keybuf *keybuf = &thread->keybuf[i];
        struct dp_netdev_flow *netdev_flow = netdev_flows[i];
        struct dpif_flow *f = &flows[i];
        struct ofpbuf key, mask;

        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);
        dp_netdev_flow_to_dpif_flow(netdev_flow, &key, &mask, f,
                                    dump->up.terse);
    }

    return n_flows;
}

static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    struct dp_packet *pp;

    if (dp_packet_size(execute->packet) < ETH_HEADER_LEN ||
        dp_packet_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    /* Tries finding the 'pmd'.  If NULL is returned, that means
     * the current thread is a non-pmd thread and should use
     * dp_netdev_get_pmd(dp, NON_PMD_CORE_ID). */
    pmd = ovsthread_getspecific(dp->per_pmd_key);
    if (!pmd) {
        pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
    }

    /* If the current thread is non-pmd thread, acquires
     * the 'non_pmd_mutex'. */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
        ovs_mutex_lock(&dp->port_mutex);
    }

    pp = execute->packet;
    dp_netdev_execute_actions(pmd, &pp, 1, false, execute->actions,
                              execute->actions_len);
    if (pmd->core_id == NON_PMD_CORE_ID) {
        dp_netdev_pmd_unref(pmd);
        ovs_mutex_unlock(&dp->port_mutex);
        ovs_mutex_unlock(&dp->non_pmd_mutex);
    }

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

/* Returns true if the configuration for rx queues or cpu mask
 * is changed. */
static bool
pmd_config_changed(const struct dp_netdev *dp, size_t rxqs, const char *cmask)
{
    if (dp->n_dpdk_rxqs != rxqs) {
        return true;
    } else {
        if (dp->pmd_cmask != NULL && cmask != NULL) {
            return strcmp(dp->pmd_cmask, cmask);
        } else {
            return (dp->pmd_cmask != NULL || cmask != NULL);
        }
    }
}

/* Resets pmd threads if the configuration for 'rxq's or cpu mask changes. */
static int
dpif_netdev_pmd_set(struct dpif *dpif, unsigned int n_rxqs, const char *cmask)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (pmd_config_changed(dp, n_rxqs, cmask)) {
        struct dp_netdev_port *port;

        dp_netdev_destroy_all_pmds(dp);

        CMAP_FOR_EACH (port, node, &dp->ports) {
            if (netdev_is_pmd(port->netdev)) {
                int i, err;

                /* Closes the existing 'rxq's. */
                for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                    netdev_rxq_close(port->rxq[i]);
                    port->rxq[i] = NULL;
                }

                /* Sets the new rx queue config.  */
                err = netdev_set_multiq(port->netdev,
                                        ovs_numa_get_n_cores() + 1,
                                        n_rxqs);
                if (err && (err != EOPNOTSUPP)) {
                    VLOG_ERR("Failed to set dpdk interface %s rx_queue to:"
                             " %u", netdev_get_name(port->netdev),
                             n_rxqs);
                    return err;
                }

                /* If the set_multiq() above succeeds, reopens the 'rxq's. */
                port->rxq = xrealloc(port->rxq, sizeof *port->rxq
                                     * netdev_n_rxq(port->netdev));
                for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                    netdev_rxq_open(port->netdev, &port->rxq[i], i);
                }
            }
        }
        dp->n_dpdk_rxqs = n_rxqs;

        /* Reconfigures the cpu mask. */
        ovs_numa_set_cpu_mask(cmask);
        free(dp->pmd_cmask);
        dp->pmd_cmask = cmask ? xstrdup(cmask) : NULL;

        /* Restores the non-pmd. */
        dp_netdev_set_nonpmd(dp);
        /* Restores all pmd threads. */
        dp_netdev_reset_pmd_threads(dp);
    }

    return 0;
}

static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
}


/* Creates and returns a new 'struct dp_netdev_actions', whose actions are
 * a copy of the 'ofpacts_len' bytes of 'ofpacts'. */
struct dp_netdev_actions *
dp_netdev_actions_create(const struct nlattr *actions, size_t size)
{
    struct dp_netdev_actions *netdev_actions;

    netdev_actions = xmalloc(sizeof *netdev_actions + size);
    memcpy(netdev_actions->actions, actions, size);
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
    free(actions);
}

static inline unsigned long long
cycles_counter(void)
{
#ifdef DPDK_NETDEV
    return rte_get_tsc_cycles();
#else
    return 0;
#endif
}

/* Fake mutex to make sure that the calls to cycles_count_* are balanced */
extern struct ovs_mutex cycles_counter_fake_mutex;

/* Start counting cycles.  Must be followed by 'cycles_count_end()' */
static inline void
cycles_count_start(struct dp_netdev_pmd_thread *pmd)
    OVS_ACQUIRES(&cycles_counter_fake_mutex)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    pmd->last_cycles = cycles_counter();
}

/* Stop counting cycles and add them to the counter 'type' */
static inline void
cycles_count_end(struct dp_netdev_pmd_thread *pmd,
                 enum pmd_cycles_counter_type type)
    OVS_RELEASES(&cycles_counter_fake_mutex)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    unsigned long long interval = cycles_counter() - pmd->last_cycles;

    non_atomic_ullong_add(&pmd->cycles.n[type], interval);
}

static void
dp_netdev_process_rxq_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_port *port,
                           struct netdev_rxq *rxq)
{
    struct dp_packet *packets[NETDEV_MAX_BURST];
    int error, cnt;

    cycles_count_start(pmd);
    error = netdev_rxq_recv(rxq, packets, &cnt);
    cycles_count_end(pmd, PMD_CYCLES_POLLING);
    if (!error) {
        int i;

        *recirc_depth_get() = 0;

        /* XXX: initialize md in netdev implementation. */
        for (i = 0; i < cnt; i++) {
            packets[i]->md = port->md;
        }
        cycles_count_start(pmd);
        dp_netdev_input(pmd, packets, cnt);
        cycles_count_end(pmd, PMD_CYCLES_PROCESSING);
    } else if (error != EAGAIN && error != EOPNOTSUPP) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                    netdev_get_name(port->netdev), ovs_strerror(error));
    }
}

/* Return true if needs to revalidate datapath flows. */
static bool
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *non_pmd = dp_netdev_get_pmd(dp,
                                                             NON_PMD_CORE_ID);
    uint64_t new_tnl_seq;

    ovs_mutex_lock(&dp->non_pmd_mutex);
    CMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                dp_netdev_process_rxq_port(non_pmd, port, port->rxq[i]);
            }
        }
    }
    ovs_mutex_unlock(&dp->non_pmd_mutex);
    dp_netdev_pmd_unref(non_pmd);

    tnl_arp_cache_run();
    new_tnl_seq = seq_read(tnl_conf_seq);

    if (dp->last_tnl_conf_seq != new_tnl_seq) {
        dp->last_tnl_conf_seq = new_tnl_seq;
        return true;
    }
    return false;
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
    seq_wait(tnl_conf_seq, dp->last_tnl_conf_seq);
}

struct rxq_poll {
    struct dp_netdev_port *port;
    struct netdev_rxq *rx;
};

static int
pmd_load_queues(struct dp_netdev_pmd_thread *pmd,
                struct rxq_poll **ppoll_list, int poll_cnt)
{
    struct rxq_poll *poll_list = *ppoll_list;
    struct dp_netdev_port *port;
    int n_pmds_on_numa, index, i;

    /* Simple scheduler for netdev rx polling. */
    for (i = 0; i < poll_cnt; i++) {
        port_unref(poll_list[i].port);
    }

    poll_cnt = 0;
    n_pmds_on_numa = get_n_pmd_threads_on_numa(pmd->dp, pmd->numa_id);
    index = 0;

    CMAP_FOR_EACH (port, node, &pmd->dp->ports) {
        /* Calls port_try_ref() to prevent the main thread
         * from deleting the port. */
        if (port_try_ref(port)) {
            if (netdev_is_pmd(port->netdev)
                && netdev_get_numa_id(port->netdev) == pmd->numa_id) {
                int i;

                for (i = 0; i < netdev_n_rxq(port->netdev); i++) {
                    if ((index % n_pmds_on_numa) == pmd->index) {
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
    struct dp_netdev_pmd_thread *pmd = f_;
    unsigned int lc = 0;
    struct rxq_poll *poll_list;
    unsigned int port_seq = PMD_INITIAL_SEQ;
    int poll_cnt;
    int i;

    poll_cnt = 0;
    poll_list = NULL;

    /* Stores the pmd thread's 'pmd' to 'per_pmd_key'. */
    ovsthread_setspecific(pmd->dp->per_pmd_key, pmd);
    pmd_thread_setaffinity_cpu(pmd->core_id);
reload:
    emc_cache_init(&pmd->flow_cache);
    poll_cnt = pmd_load_queues(pmd, &poll_list, poll_cnt);

    /* Signal here to make sure the pmd finishes
     * reloading the updated configuration. */
    dp_netdev_pmd_reload_done(pmd);

    for (;;) {
        int i;

        for (i = 0; i < poll_cnt; i++) {
            dp_netdev_process_rxq_port(pmd, poll_list[i].port, poll_list[i].rx);
        }

        if (lc++ > 1024) {
            unsigned int seq;

            lc = 0;

            emc_cache_slow_sweep(&pmd->flow_cache);
            ovsrcu_quiesce();

            atomic_read_relaxed(&pmd->change_seq, &seq);
            if (seq != port_seq) {
                port_seq = seq;
                break;
            }
        }
    }

    emc_cache_uninit(&pmd->flow_cache);

    if (!latch_is_set(&pmd->exit_latch)){
        goto reload;
    }

    for (i = 0; i < poll_cnt; i++) {
         port_unref(poll_list[i].port);
    }

    dp_netdev_pmd_reload_done(pmd);

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

void
dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->cond_mutex);
    xpthread_cond_signal(&pmd->cond);
    ovs_mutex_unlock(&pmd->cond_mutex);
}

/* Finds and refs the dp_netdev_pmd_thread on core 'core_id'.  Returns
 * the pointer if succeeds, otherwise, NULL.
 *
 * Caller must unrefs the returned reference.  */
static struct dp_netdev_pmd_thread *
dp_netdev_get_pmd(struct dp_netdev *dp, unsigned core_id)
{
    struct dp_netdev_pmd_thread *pmd;
    const struct cmap_node *pnode;

    pnode = cmap_find(&dp->poll_threads, hash_int(core_id, 0));
    if (!pnode) {
        return NULL;
    }
    pmd = CONTAINER_OF(pnode, struct dp_netdev_pmd_thread, node);

    return dp_netdev_pmd_try_ref(pmd) ? pmd : NULL;
}

/* Sets the 'struct dp_netdev_pmd_thread' for non-pmd threads. */
static void
dp_netdev_set_nonpmd(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *non_pmd;

    non_pmd = xzalloc(sizeof *non_pmd);
    dp_netdev_configure_pmd(non_pmd, dp, 0, NON_PMD_CORE_ID,
                            OVS_NUMA_UNSPEC);
}

/* Caller must have valid pointer to 'pmd'. */
static bool
dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd)
{
    return ovs_refcount_try_ref_rcu(&pmd->ref_cnt);
}

static void
dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd)
{
    if (pmd && ovs_refcount_unref(&pmd->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_destroy_pmd, pmd);
    }
}

/* Given cmap position 'pos', tries to ref the next node.  If try_ref()
 * fails, keeps checking for next node until reaching the end of cmap.
 *
 * Caller must unrefs the returned reference. */
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos)
{
    struct dp_netdev_pmd_thread *next;

    do {
        struct cmap_node *node;

        node = cmap_next_position(&dp->poll_threads, pos);
        next = node ? CONTAINER_OF(node, struct dp_netdev_pmd_thread, node)
            : NULL;
    } while (next && !dp_netdev_pmd_try_ref(next));

    return next;
}

static int
core_id_to_qid(unsigned core_id)
{
    if (core_id != NON_PMD_CORE_ID) {
        return core_id;
    } else {
        return ovs_numa_get_n_cores();
    }
}

/* Configures the 'pmd' based on the input argument. */
static void
dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev *dp,
                        int index, unsigned core_id, int numa_id)
{
    pmd->dp = dp;
    pmd->index = index;
    pmd->core_id = core_id;
    pmd->tx_qid = core_id_to_qid(core_id);
    pmd->numa_id = numa_id;

    ovs_refcount_init(&pmd->ref_cnt);
    latch_init(&pmd->exit_latch);
    atomic_init(&pmd->change_seq, PMD_INITIAL_SEQ);
    xpthread_cond_init(&pmd->cond, NULL);
    ovs_mutex_init(&pmd->cond_mutex);
    ovs_mutex_init(&pmd->flow_mutex);
    dpcls_init(&pmd->cls);
    cmap_init(&pmd->flow_table);
    /* init the 'flow_cache' since there is no
     * actual thread created for NON_PMD_CORE_ID. */
    if (core_id == NON_PMD_CORE_ID) {
        emc_cache_init(&pmd->flow_cache);
    }
    cmap_insert(&dp->poll_threads, CONST_CAST(struct cmap_node *, &pmd->node),
                hash_int(core_id, 0));
}

static void
dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd)
{
    dp_netdev_pmd_flow_flush(pmd);
    dpcls_destroy(&pmd->cls);
    cmap_destroy(&pmd->flow_table);
    ovs_mutex_destroy(&pmd->flow_mutex);
    latch_destroy(&pmd->exit_latch);
    xpthread_cond_destroy(&pmd->cond);
    ovs_mutex_destroy(&pmd->cond_mutex);
    free(pmd);
}

/* Stops the pmd thread, removes it from the 'dp->poll_threads',
 * and unrefs the struct. */
static void
dp_netdev_del_pmd(struct dp_netdev_pmd_thread *pmd)
{
    /* Uninit the 'flow_cache' since there is
     * no actual thread uninit it for NON_PMD_CORE_ID. */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        emc_cache_uninit(&pmd->flow_cache);
    } else {
        latch_set(&pmd->exit_latch);
        dp_netdev_reload_pmd__(pmd);
        ovs_numa_unpin_core(pmd->core_id);
        xpthread_join(pmd->thread, NULL);
    }
    cmap_remove(&pmd->dp->poll_threads, &pmd->node, hash_int(pmd->core_id, 0));
    dp_netdev_pmd_unref(pmd);
}

/* Destroys all pmd threads. */
static void
dp_netdev_destroy_all_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_del_pmd(pmd);
    }
}

/* Deletes all pmd threads on numa node 'numa_id'. */
static void
dp_netdev_del_pmds_on_numa(struct dp_netdev *dp, int numa_id)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->numa_id == numa_id) {
            dp_netdev_del_pmd(pmd);
        }
    }
}

/* Checks the numa node id of 'netdev' and starts pmd threads for
 * the numa node. */
static void
dp_netdev_set_pmds_on_numa(struct dp_netdev *dp, int numa_id)
{
    int n_pmds;

    if (!ovs_numa_numa_id_is_valid(numa_id)) {
        VLOG_ERR("Cannot create pmd threads due to numa id (%d)"
                 "invalid", numa_id);
        return ;
    }

    n_pmds = get_n_pmd_threads_on_numa(dp, numa_id);

    /* If there are already pmd threads created for the numa node
     * in which 'netdev' is on, do nothing.  Else, creates the
     * pmd threads for the numa node. */
    if (!n_pmds) {
        int can_have, n_unpinned, i;

        n_unpinned = ovs_numa_get_n_unpinned_cores_on_numa(numa_id);
        if (!n_unpinned) {
            VLOG_ERR("Cannot create pmd threads due to out of unpinned "
                     "cores on numa node");
            return;
        }

        /* If cpu mask is specified, uses all unpinned cores, otherwise
         * tries creating NR_PMD_THREADS pmd threads. */
        can_have = dp->pmd_cmask ? n_unpinned : MIN(n_unpinned, NR_PMD_THREADS);
        for (i = 0; i < can_have; i++) {
            struct dp_netdev_pmd_thread *pmd = xzalloc(sizeof *pmd);
            unsigned core_id = ovs_numa_get_unpinned_core_on_numa(numa_id);

            dp_netdev_configure_pmd(pmd, dp, i, core_id, numa_id);
            /* Each thread will distribute all devices rx-queues among
             * themselves. */
            pmd->thread = ovs_thread_create("pmd", pmd_thread_main, pmd);
        }
        VLOG_INFO("Created %d pmd threads on numa node %d", can_have, numa_id);
    }
}


/* Called after pmd threads config change.  Restarts pmd threads with
 * new configuration. */
static void
dp_netdev_reset_pmd_threads(struct dp_netdev *dp)
{
    struct dp_netdev_port *port;

    CMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_pmd(port->netdev)) {
            int numa_id = netdev_get_numa_id(port->netdev);

            dp_netdev_set_pmds_on_numa(dp, numa_id);
        }
    }
}

static char *
dpif_netdev_get_datapath_version(void)
{
     return xstrdup("<built-in>");
}

static void
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow, int cnt, int size,
                    uint16_t tcp_flags, long long now)
{
    uint16_t flags;

    atomic_store_relaxed(&netdev_flow->stats.used, now);
    non_atomic_ullong_add(&netdev_flow->stats.packet_count, cnt);
    non_atomic_ullong_add(&netdev_flow->stats.byte_count, size);
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    flags |= tcp_flags;
    atomic_store_relaxed(&netdev_flow->stats.tcp_flags, flags);
}

static void
dp_netdev_count_packet(struct dp_netdev_pmd_thread *pmd,
                       enum dp_stat_type type, int cnt)
{
    non_atomic_ullong_add(&pmd->stats.n[type], cnt);
}

static int
dp_netdev_upcall(struct dp_netdev_pmd_thread *pmd, struct dp_packet *packet_,
                 struct flow *flow, struct flow_wildcards *wc, ovs_u128 *ufid,
                 enum dpif_upcall_type type, const struct nlattr *userdata,
                 struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct dp_netdev *dp = pmd->dp;

    if (OVS_UNLIKELY(!dp->upcall_cb)) {
        return ENODEV;
    }

    if (OVS_UNLIKELY(!VLOG_DROP_DBG(&upcall_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet_str;
        struct ofpbuf key;

        ofpbuf_init(&key, 0);
        odp_flow_key_from_flow(&key, flow, &wc->masks, flow->in_port.odp_port,
                               true);
        packet_str = ofp_packet_to_string(dp_packet_data(packet_),
                                          dp_packet_size(packet_));

        odp_flow_key_format(key.data, key.size, &ds);

        VLOG_DBG("%s: %s upcall:\n%s\n%s", dp->name,
                 dpif_upcall_type_to_string(type), ds_cstr(&ds), packet_str);

        ofpbuf_uninit(&key);
        free(packet_str);

        ds_destroy(&ds);
    }

    return dp->upcall_cb(packet_, flow, ufid, pmd->core_id, type, userdata,
                         actions, wc, put_actions, dp->upcall_aux);
}

static inline uint32_t
dpif_netdev_packet_get_rss_hash(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash, recirc_depth;

    hash = dp_packet_get_rss_hash(packet);
    if (OVS_UNLIKELY(!hash)) {
        hash = miniflow_hash_5tuple(mf, 0);
        dp_packet_set_rss_hash(packet, hash);
    }

    /* The RSS hash must account for the recirculation depth to avoid
     * collisions in the exact match cache */
    recirc_depth = *recirc_depth_get_unsafe();
    if (OVS_UNLIKELY(recirc_depth)) {
        hash = hash_finish(hash, recirc_depth);
        dp_packet_set_rss_hash(packet, hash);
    }
    return hash;
}

struct packet_batch {
    unsigned int packet_count;
    unsigned int byte_count;
    uint16_t tcp_flags;

    struct dp_netdev_flow *flow;

    struct dp_packet *packets[NETDEV_MAX_BURST];
};

static inline void
packet_batch_update(struct packet_batch *batch, struct dp_packet *packet,
                    const struct miniflow *mf)
{
    batch->tcp_flags |= miniflow_get_tcp_flags(mf);
    batch->packets[batch->packet_count++] = packet;
    batch->byte_count += dp_packet_size(packet);
}

static inline void
packet_batch_init(struct packet_batch *batch, struct dp_netdev_flow *flow)
{
    flow->batch = batch;

    batch->flow = flow;
    batch->packet_count = 0;
    batch->byte_count = 0;
    batch->tcp_flags = 0;
}

static inline void
packet_batch_execute(struct packet_batch *batch,
                     struct dp_netdev_pmd_thread *pmd,
                     long long now)
{
    struct dp_netdev_actions *actions;
    struct dp_netdev_flow *flow = batch->flow;

    dp_netdev_flow_used(flow, batch->packet_count, batch->byte_count,
                        batch->tcp_flags, now);

    actions = dp_netdev_flow_get_actions(flow);

    dp_netdev_execute_actions(pmd, batch->packets, batch->packet_count, true,
                              actions->actions, actions->size);
}

static inline void
dp_netdev_queue_batches(struct dp_packet *pkt,
                        struct dp_netdev_flow *flow, const struct miniflow *mf,
                        struct packet_batch *batches, size_t *n_batches)
{
    struct packet_batch *batch = flow->batch;

    if (OVS_LIKELY(batch)) {
        packet_batch_update(batch, pkt, mf);
        return;
    }

    batch = &batches[(*n_batches)++];
    packet_batch_init(batch, flow);
    packet_batch_update(batch, pkt, mf);
}

static inline void
dp_packet_swap(struct dp_packet **a, struct dp_packet **b)
{
    struct dp_packet *tmp = *a;
    *a = *b;
    *b = tmp;
}

/* Try to process all ('cnt') the 'packets' using only the exact match cache
 * 'flow_cache'. If a flow is not found for a packet 'packets[i]', the
 * miniflow is copied into 'keys' and the packet pointer is moved at the
 * beginning of the 'packets' array.
 *
 * The function returns the number of packets that needs to be processed in the
 * 'packets' array (they have been moved to the beginning of the vector).
 */
static inline size_t
emc_processing(struct dp_netdev_pmd_thread *pmd, struct dp_packet **packets,
               size_t cnt, struct netdev_flow_key *keys,
               struct packet_batch batches[], size_t *n_batches)
{
    struct emc_cache *flow_cache = &pmd->flow_cache;
    struct netdev_flow_key key;
    size_t i, notfound_cnt = 0;

    miniflow_initialize(&key.mf, key.buf);
    for (i = 0; i < cnt; i++) {
        struct dp_netdev_flow *flow;

        if (OVS_UNLIKELY(dp_packet_size(packets[i]) < ETH_HEADER_LEN)) {
            dp_packet_delete(packets[i]);
            continue;
        }

        miniflow_extract(packets[i], &key.mf);
        key.len = 0; /* Not computed yet. */
        key.hash = dpif_netdev_packet_get_rss_hash(packets[i], &key.mf);

        flow = emc_lookup(flow_cache, &key);
        if (OVS_LIKELY(flow)) {
            dp_netdev_queue_batches(packets[i], flow, &key.mf, batches,
                                    n_batches);
        } else {
            if (i != notfound_cnt) {
                dp_packet_swap(&packets[i], &packets[notfound_cnt]);
            }

            keys[notfound_cnt++] = key;
        }
    }

    dp_netdev_count_packet(pmd, DP_STAT_EXACT_HIT, cnt - notfound_cnt);

    return notfound_cnt;
}

static inline void
fast_path_processing(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet **packets, size_t cnt,
                     struct netdev_flow_key *keys,
                     struct packet_batch batches[], size_t *n_batches)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct dpcls_rule *rules[PKT_ARRAY_SIZE];
    struct dp_netdev *dp = pmd->dp;
    struct emc_cache *flow_cache = &pmd->flow_cache;
    int miss_cnt = 0, lost_cnt = 0;
    bool any_miss;
    size_t i;

    for (i = 0; i < cnt; i++) {
        /* Key length is needed in all the cases, hash computed on demand. */
        keys[i].len = netdev_flow_key_size(count_1bits(keys[i].mf.map));
    }
    any_miss = !dpcls_lookup(&pmd->cls, keys, rules, cnt);
    if (OVS_UNLIKELY(any_miss) && !fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
        uint64_t actions_stub[512 / 8], slow_stub[512 / 8];
        struct ofpbuf actions, put_actions;
        ovs_u128 ufid;

        ofpbuf_use_stub(&actions, actions_stub, sizeof actions_stub);
        ofpbuf_use_stub(&put_actions, slow_stub, sizeof slow_stub);

        for (i = 0; i < cnt; i++) {
            struct dp_netdev_flow *netdev_flow;
            struct ofpbuf *add_actions;
            struct match match;
            int error;

            if (OVS_LIKELY(rules[i])) {
                continue;
            }

            /* It's possible that an earlier slow path execution installed
             * a rule covering this flow.  In this case, it's a lot cheaper
             * to catch it here than execute a miss. */
            netdev_flow = dp_netdev_pmd_lookup_flow(pmd, &keys[i]);
            if (netdev_flow) {
                rules[i] = &netdev_flow->cr;
                continue;
            }

            miss_cnt++;

            miniflow_expand(&keys[i].mf, &match.flow);

            ofpbuf_clear(&actions);
            ofpbuf_clear(&put_actions);

            dpif_flow_hash(dp->dpif, &match.flow, sizeof match.flow, &ufid);
            error = dp_netdev_upcall(pmd, packets[i], &match.flow, &match.wc,
                                     &ufid, DPIF_UC_MISS, NULL, &actions,
                                     &put_actions);
            if (OVS_UNLIKELY(error && error != ENOSPC)) {
                dp_packet_delete(packets[i]);
                lost_cnt++;
                continue;
            }

            /* We can't allow the packet batching in the next loop to execute
             * the actions.  Otherwise, if there are any slow path actions,
             * we'll send the packet up twice. */
            dp_netdev_execute_actions(pmd, &packets[i], 1, true,
                                      actions.data, actions.size);

            add_actions = put_actions.size ? &put_actions : &actions;
            if (OVS_LIKELY(error != ENOSPC)) {
                /* XXX: There's a race window where a flow covering this packet
                 * could have already been installed since we last did the flow
                 * lookup before upcall.  This could be solved by moving the
                 * mutex lock outside the loop, but that's an awful long time
                 * to be locking everyone out of making flow installs.  If we
                 * move to a per-core classifier, it would be reasonable. */
                ovs_mutex_lock(&pmd->flow_mutex);
                netdev_flow = dp_netdev_pmd_lookup_flow(pmd, &keys[i]);
                if (OVS_LIKELY(!netdev_flow)) {
                    netdev_flow = dp_netdev_flow_add(pmd, &match, &ufid,
                                                     add_actions->data,
                                                     add_actions->size);
                }
                ovs_mutex_unlock(&pmd->flow_mutex);

                emc_insert(flow_cache, &keys[i], netdev_flow);
            }
        }

        ofpbuf_uninit(&actions);
        ofpbuf_uninit(&put_actions);
        fat_rwlock_unlock(&dp->upcall_rwlock);
        dp_netdev_count_packet(pmd, DP_STAT_LOST, lost_cnt);
    } else if (OVS_UNLIKELY(any_miss)) {
        for (i = 0; i < cnt; i++) {
            if (OVS_UNLIKELY(!rules[i])) {
                dp_packet_delete(packets[i]);
                lost_cnt++;
                miss_cnt++;
            }
        }
    }

    for (i = 0; i < cnt; i++) {
        struct dp_packet *packet = packets[i];
        struct dp_netdev_flow *flow;

        if (OVS_UNLIKELY(!rules[i])) {
            continue;
        }

        flow = dp_netdev_flow_cast(rules[i]);

        emc_insert(flow_cache, &keys[i], flow);
        dp_netdev_queue_batches(packet, flow, &keys[i].mf, batches, n_batches);
    }

    dp_netdev_count_packet(pmd, DP_STAT_MASKED_HIT, cnt - miss_cnt);
    dp_netdev_count_packet(pmd, DP_STAT_MISS, miss_cnt);
    dp_netdev_count_packet(pmd, DP_STAT_LOST, lost_cnt);
}

static void
dp_netdev_input(struct dp_netdev_pmd_thread *pmd,
                struct dp_packet **packets, int cnt)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct netdev_flow_key keys[PKT_ARRAY_SIZE];
    struct packet_batch batches[PKT_ARRAY_SIZE];
    long long now = time_msec();
    size_t newcnt, n_batches, i;

    n_batches = 0;
    newcnt = emc_processing(pmd, packets, cnt, keys, batches, &n_batches);
    if (OVS_UNLIKELY(newcnt)) {
        fast_path_processing(pmd, packets, newcnt, keys, batches, &n_batches);
    }

    for (i = 0; i < n_batches; i++) {
        batches[i].flow->batch = NULL;
    }

    for (i = 0; i < n_batches; i++) {
        packet_batch_execute(&batches[i], pmd, now);
    }
}

struct dp_netdev_execute_aux {
    struct dp_netdev_pmd_thread *pmd;
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
dp_netdev_drop_packets(struct dp_packet **packets, int cnt, bool may_steal)
{
    if (may_steal) {
        int i;

        for (i = 0; i < cnt; i++) {
            dp_packet_delete(packets[i]);
        }
    }
}

static int
push_tnl_action(const struct dp_netdev *dp,
                   const struct nlattr *attr,
                   struct dp_packet **packets, int cnt)
{
    struct dp_netdev_port *tun_port;
    const struct ovs_action_push_tnl *data;

    data = nl_attr_get(attr);

    tun_port = dp_netdev_lookup_port(dp, u32_to_odp(data->tnl_port));
    if (!tun_port) {
        return -EINVAL;
    }
    netdev_push_header(tun_port->netdev, packets, cnt, data);

    return 0;
}

static void
dp_netdev_clone_pkt_batch(struct dp_packet **dst_pkts,
                          struct dp_packet **src_pkts, int cnt)
{
    int i;

    for (i = 0; i < cnt; i++) {
        dst_pkts[i] = dp_packet_clone(src_pkts[i]);
    }
}

static void
dp_execute_cb(void *aux_, struct dp_packet **packets, int cnt,
              const struct nlattr *a, bool may_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev_execute_aux *aux = aux_;
    uint32_t *depth = recirc_depth_get();
    struct dp_netdev_pmd_thread *pmd = aux->pmd;
    struct dp_netdev *dp = pmd->dp;
    int type = nl_attr_type(a);
    struct dp_netdev_port *p;
    int i;

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        p = dp_netdev_lookup_port(dp, u32_to_odp(nl_attr_get_u32(a)));
        if (OVS_LIKELY(p)) {
            netdev_send(p->netdev, pmd->tx_qid, packets, cnt, may_steal);
            return;
        }
        break;

    case OVS_ACTION_ATTR_TUNNEL_PUSH:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet *tnl_pkt[NETDEV_MAX_BURST];
            int err;

            if (!may_steal) {
                dp_netdev_clone_pkt_batch(tnl_pkt, packets, cnt);
                packets = tnl_pkt;
            }

            err = push_tnl_action(dp, a, packets, cnt);
            if (!err) {
                (*depth)++;
                dp_netdev_input(pmd, packets, cnt);
                (*depth)--;
            } else {
                dp_netdev_drop_packets(tnl_pkt, cnt, !may_steal);
            }
            return;
        }
        break;

    case OVS_ACTION_ATTR_TUNNEL_POP:
        if (*depth < MAX_RECIRC_DEPTH) {
            odp_port_t portno = u32_to_odp(nl_attr_get_u32(a));

            p = dp_netdev_lookup_port(dp, portno);
            if (p) {
                struct dp_packet *tnl_pkt[NETDEV_MAX_BURST];
                int err;

                if (!may_steal) {
                   dp_netdev_clone_pkt_batch(tnl_pkt, packets, cnt);
                   packets = tnl_pkt;
                }

                err = netdev_pop_header(p->netdev, packets, cnt);
                if (!err) {

                    for (i = 0; i < cnt; i++) {
                        packets[i]->md.in_port.odp_port = portno;
                    }

                    (*depth)++;
                    dp_netdev_input(pmd, packets, cnt);
                    (*depth)--;
                } else {
                    dp_netdev_drop_packets(tnl_pkt, cnt, !may_steal);
                }
                return;
            }
        }
        break;

    case OVS_ACTION_ATTR_USERSPACE:
        if (!fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
            const struct nlattr *userdata;
            struct ofpbuf actions;
            struct flow flow;
            ovs_u128 ufid;

            userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);
            ofpbuf_init(&actions, 0);

            for (i = 0; i < cnt; i++) {
                int error;

                ofpbuf_clear(&actions);

                flow_extract(packets[i], &flow);
                dpif_flow_hash(dp->dpif, &flow, sizeof flow, &ufid);
                error = dp_netdev_upcall(pmd, packets[i], &flow, NULL, &ufid,
                                         DPIF_UC_ACTION, userdata,&actions,
                                         NULL);
                if (!error || error == ENOSPC) {
                    dp_netdev_execute_actions(pmd, &packets[i], 1, may_steal,
                                              actions.data, actions.size);
                } else if (may_steal) {
                    dp_packet_delete(packets[i]);
                }
            }
            ofpbuf_uninit(&actions);
            fat_rwlock_unlock(&dp->upcall_rwlock);

            return;
        }
        break;

    case OVS_ACTION_ATTR_RECIRC:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet *recirc_pkts[NETDEV_MAX_BURST];

            if (!may_steal) {
               dp_netdev_clone_pkt_batch(recirc_pkts, packets, cnt);
               packets = recirc_pkts;
            }

            for (i = 0; i < cnt; i++) {
                packets[i]->md.recirc_id = nl_attr_get_u32(a);
            }

            (*depth)++;
            dp_netdev_input(pmd, packets, cnt);
            (*depth)--;

            return;
        }

        VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
        break;

    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    dp_netdev_drop_packets(packets, cnt, may_steal);
}

static void
dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                          struct dp_packet **packets, int cnt,
                          bool may_steal,
                          const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = { pmd };

    odp_execute_actions(&aux, packets, cnt, may_steal, actions,
                        actions_len, dp_execute_cb);
}

const struct dpif_class dpif_netdev_class = {
    "netdev",
    dpif_netdev_init,
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
    dpif_netdev_pmd_set,
    dpif_netdev_queue_to_priority,
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */
    dpif_netdev_register_upcall_cb,
    dpif_netdev_enable_upcall,
    dpif_netdev_disable_upcall,
    dpif_netdev_get_datapath_version,
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
    cmap_remove(&dp->ports, &old_port->node, hash_port_no(old_port->md.in_port.odp_port));
    ovsrcu_postpone(free, old_port);

    /* Insert new port (cmap semantics mean we cannot re-insert 'old_port'). */
    new_port = xmemdup(old_port, sizeof *old_port);
    new_port->md.in_port.odp_port = port_no;
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
    } else if (port->md.in_port.odp_port == ODPP_LOCAL) {
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

/* Datapath Classifier. */

/* A set of rules that all have the same fields wildcarded. */
struct dpcls_subtable {
    /* The fields are only used by writers. */
    struct cmap_node cmap_node OVS_GUARDED; /* Within dpcls 'subtables_map'. */

    /* These fields are accessed by readers. */
    struct cmap rules;           /* Contains "struct dpcls_rule"s. */
    struct netdev_flow_key mask; /* Wildcards for fields (const). */
    /* 'mask' must be the last field, additional space is allocated here. */
};

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
static void
dpcls_init(struct dpcls *cls)
{
    cmap_init(&cls->subtables_map);
    pvector_init(&cls->subtables);
}

static void
dpcls_destroy_subtable(struct dpcls *cls, struct dpcls_subtable *subtable)
{
    pvector_remove(&cls->subtables, subtable);
    cmap_remove(&cls->subtables_map, &subtable->cmap_node,
                subtable->mask.hash);
    cmap_destroy(&subtable->rules);
    ovsrcu_postpone(free, subtable);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility.
 * May only be called after all the readers have been terminated. */
static void
dpcls_destroy(struct dpcls *cls)
{
    if (cls) {
        struct dpcls_subtable *subtable;

        CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
            dpcls_destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);
        pvector_destroy(&cls->subtables);
    }
}

static struct dpcls_subtable *
dpcls_create_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    /* Need to add one. */
    subtable = xmalloc(sizeof *subtable
                       - sizeof subtable->mask.mf + mask->len);
    cmap_init(&subtable->rules);
    netdev_flow_key_clone(&subtable->mask, mask);
    cmap_insert(&cls->subtables_map, &subtable->cmap_node, mask->hash);
    pvector_insert(&cls->subtables, subtable, 0);
    pvector_publish(&cls->subtables);

    return subtable;
}

static inline struct dpcls_subtable *
dpcls_find_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    CMAP_FOR_EACH_WITH_HASH (subtable, cmap_node, mask->hash,
                             &cls->subtables_map) {
        if (netdev_flow_key_equal(&subtable->mask, mask)) {
            return subtable;
        }
    }
    return dpcls_create_subtable(cls, mask);
}

/* Insert 'rule' into 'cls'. */
static void
dpcls_insert(struct dpcls *cls, struct dpcls_rule *rule,
             const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable = dpcls_find_subtable(cls, mask);

    rule->mask = &subtable->mask;
    cmap_insert(&subtable->rules, &rule->cmap_node, rule->flow.hash);
}

/* Removes 'rule' from 'cls', also destructing the 'rule'. */
static void
dpcls_remove(struct dpcls *cls, struct dpcls_rule *rule)
{
    struct dpcls_subtable *subtable;

    ovs_assert(rule->mask);

    INIT_CONTAINER(subtable, rule->mask, mask);

    if (cmap_remove(&subtable->rules, &rule->cmap_node, rule->flow.hash)
        == 0) {
        dpcls_destroy_subtable(cls, subtable);
        pvector_publish(&cls->subtables);
    }
}

/* Returns true if 'target' satisifies 'key' in 'mask', that is, if each 1-bit
 * in 'mask' the values in 'key' and 'target' are the same.
 *
 * Note: 'key' and 'mask' have the same mask, and 'key' is already masked. */
static inline bool
dpcls_rule_matches_key(const struct dpcls_rule *rule,
                       const struct netdev_flow_key *target)
{
    const uint64_t *keyp = rule->flow.mf.inline_values;
    const uint64_t *maskp = rule->mask->mf.inline_values;
    uint64_t target_u64;

    NETDEV_FLOW_KEY_FOR_EACH_IN_MAP(target_u64, target, rule->flow.mf.map) {
        if (OVS_UNLIKELY((target_u64 & *maskp++) != *keyp++)) {
            return false;
        }
    }
    return true;
}

/* For each miniflow in 'flows' performs a classifier lookup writing the result
 * into the corresponding slot in 'rules'.  If a particular entry in 'flows' is
 * NULL it is skipped.
 *
 * This function is optimized for use in the userspace datapath and therefore
 * does not implement a lot of features available in the standard
 * classifier_lookup() function.  Specifically, it does not implement
 * priorities, instead returning any rule which matches the flow.
 *
 * Returns true if all flows found a corresponding rule. */
static bool
dpcls_lookup(const struct dpcls *cls, const struct netdev_flow_key keys[],
             struct dpcls_rule **rules, const size_t cnt)
{
    /* The batch size 16 was experimentally found faster than 8 or 32. */
    typedef uint16_t map_type;
#define MAP_BITS (sizeof(map_type) * CHAR_BIT)

#if !defined(__CHECKER__) && !defined(_WIN32)
    const int N_MAPS = DIV_ROUND_UP(cnt, MAP_BITS);
#else
    enum { N_MAPS = DIV_ROUND_UP(NETDEV_MAX_BURST, MAP_BITS) };
#endif
    map_type maps[N_MAPS];
    struct dpcls_subtable *subtable;

    memset(maps, 0xff, sizeof maps);
    if (cnt % MAP_BITS) {
        maps[N_MAPS - 1] >>= MAP_BITS - cnt % MAP_BITS; /* Clear extra bits. */
    }
    memset(rules, 0, cnt * sizeof *rules);

    PVECTOR_FOR_EACH (subtable, &cls->subtables) {
        const struct netdev_flow_key *mkeys = keys;
        struct dpcls_rule **mrules = rules;
        map_type remains = 0;
        int m;

        BUILD_ASSERT_DECL(sizeof remains == sizeof *maps);

        for (m = 0; m < N_MAPS; m++, mkeys += MAP_BITS, mrules += MAP_BITS) {
            uint32_t hashes[MAP_BITS];
            const struct cmap_node *nodes[MAP_BITS];
            unsigned long map = maps[m];
            int i;

            if (!map) {
                continue; /* Skip empty maps. */
            }

            /* Compute hashes for the remaining keys. */
            ULONG_FOR_EACH_1(i, map) {
                hashes[i] = netdev_flow_key_hash_in_mask(&mkeys[i],
                                                         &subtable->mask);
            }
            /* Lookup. */
            map = cmap_find_batch(&subtable->rules, map, hashes, nodes);
            /* Check results. */
            ULONG_FOR_EACH_1(i, map) {
                struct dpcls_rule *rule;

                CMAP_NODE_FOR_EACH (rule, cmap_node, nodes[i]) {
                    if (OVS_LIKELY(dpcls_rule_matches_key(rule, &mkeys[i]))) {
                        mrules[i] = rule;
                        goto next;
                    }
                }
                ULONG_SET0(map, i);   /* Did not match. */
            next:
                ;                     /* Keep Sparse happy. */
            }
            maps[m] &= ~map;          /* Clear the found rules. */
            remains |= maps[m];
        }
        if (!remains) {
            return true;              /* All found. */
        }
    }
    return false;                     /* Some misses. */
}
