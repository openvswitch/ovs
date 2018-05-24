/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
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
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "cmap.h"
#include "conntrack.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "hmapx.h"
#include "id-pool.h"
#include "latch.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "pvector.h"
#include "random.h"
#include "seq.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

#define FLOW_DUMP_MAX_BATCH 50
/* Use per thread recirc_depth to prevent recirculation loop. */
#define MAX_RECIRC_DEPTH 6
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, recirc_depth, 0)

/* Use instant packet send by default. */
#define DEFAULT_TX_FLUSH_INTERVAL 0

/* Configuration parameters. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */
enum { MAX_METERS = 65536 };    /* Maximum number of meters. */
enum { MAX_BANDS = 8 };         /* Maximum number of bands / meter. */
enum { N_METER_LOCKS = 64 };    /* Maximum number of meters. */

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

static struct vlog_rate_limit upcall_rl = VLOG_RATE_LIMIT_INIT(600, 600);

#define DP_NETDEV_CS_SUPPORTED_MASK (CS_NEW | CS_ESTABLISHED | CS_RELATED \
                                     | CS_INVALID | CS_REPLY_DIR | CS_TRACKED \
                                     | CS_SRC_NAT | CS_DST_NAT)
#define DP_NETDEV_CS_UNSUPPORTED_MASK (~(uint32_t)DP_NETDEV_CS_SUPPORTED_MASK)

static struct odp_support dp_netdev_support = {
    .max_vlan_headers = SIZE_MAX,
    .max_mpls_depth = SIZE_MAX,
    .recirc = true,
    .ct_state = true,
    .ct_zone = true,
    .ct_mark = true,
    .ct_label = true,
    .ct_state_nat = true,
    .ct_orig_tuple = true,
    .ct_orig_tuple6 = true,
};

/* Stores a miniflow with inline values */

struct netdev_flow_key {
    uint32_t hash;       /* Hash function differs for different users. */
    uint32_t len;        /* Length of the following miniflow (incl. map). */
    struct miniflow mf;
    uint64_t buf[FLOW_MAX_PACKET_U64S];
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

/* Default EMC insert probability is 1 / DEFAULT_EM_FLOW_INSERT_INV_PROB */
#define DEFAULT_EM_FLOW_INSERT_INV_PROB 100
#define DEFAULT_EM_FLOW_INSERT_MIN (UINT32_MAX /                     \
                                    DEFAULT_EM_FLOW_INSERT_INV_PROB)

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

/* Time in microseconds between successive optimizations of the dpcls
 * subtable vector */
#define DPCLS_OPTIMIZATION_INTERVAL 1000000LL

/* Time in microseconds of the interval in which rxq processing cycles used
 * in rxq to pmd assignments is measured and stored. */
#define PMD_RXQ_INTERVAL_LEN 10000000LL

/* Number of intervals for which cycles are stored
 * and used during rxq to pmd assignment. */
#define PMD_RXQ_INTERVAL_MAX 6

struct dpcls {
    struct cmap_node node;      /* Within dp_netdev_pmd_thread.classifiers */
    odp_port_t in_port;
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
static void dpcls_sort_subtable_vector(struct dpcls *);
static void dpcls_insert(struct dpcls *, struct dpcls_rule *,
                         const struct netdev_flow_key *mask);
static void dpcls_remove(struct dpcls *, struct dpcls_rule *);
static bool dpcls_lookup(struct dpcls *cls,
                         const struct netdev_flow_key keys[],
                         struct dpcls_rule **rules, size_t cnt,
                         int *num_lookups_p);

/* Set of supported meter flags */
#define DP_SUPPORTED_METER_FLAGS_MASK \
    (OFPMF13_STATS | OFPMF13_PKTPS | OFPMF13_KBPS | OFPMF13_BURST)

/* Set of supported meter band types */
#define DP_SUPPORTED_METER_BAND_TYPES           \
    ( 1 << OFPMBT13_DROP )

struct dp_meter_band {
    struct ofputil_meter_band up; /* type, prec_level, pad, rate, burst_size */
    uint32_t bucket; /* In 1/1000 packets (for PKTPS), or in bits (for KBPS) */
    uint64_t packet_count;
    uint64_t byte_count;
};

struct dp_meter {
    uint16_t flags;
    uint16_t n_bands;
    uint32_t max_delta_t;
    uint64_t used;
    uint64_t packet_count;
    uint64_t byte_count;
    struct dp_meter_band bands[];
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
 *    port_mutex
 *    non_pmd_mutex
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct dpif *dpif;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* The time that a packet can wait in output batch for sending. */
    atomic_uint32_t tx_flush_interval;

    /* Meters. */
    struct ovs_mutex meter_locks[N_METER_LOCKS];
    struct dp_meter *meters[MAX_METERS]; /* Meter bands. */

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) atomic_uint32_t emc_insert_min;
    /* Enable collection of PMD performance metrics. */
    atomic_bool pmd_perf_metrics;

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */
    void *upcall_aux;

    /* Callback function for notifying the purging of dp flows (during
     * reseting pmd deletion). */
    dp_purge_callback *dp_purge_cb;
    void *dp_purge_aux;

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;
    /* id pool for per thread static_tx_qid. */
    struct id_pool *tx_qid_pool;
    struct ovs_mutex tx_qid_pool_mutex;

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;

    struct seq *reconfigure_seq;
    uint64_t last_reconfigure_seq;

    /* Cpu mask for pin of pmd threads. */
    char *pmd_cmask;

    uint64_t last_tnl_conf_seq;

    struct conntrack conntrack;
};

static void meter_lock(const struct dp_netdev *dp, uint32_t meter_id)
    OVS_ACQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    ovs_mutex_lock(&dp->meter_locks[meter_id % N_METER_LOCKS]);
}

static void meter_unlock(const struct dp_netdev *dp, uint32_t meter_id)
    OVS_RELEASES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    ovs_mutex_unlock(&dp->meter_locks[meter_id % N_METER_LOCKS]);
}


static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t)
    OVS_REQUIRES(dp->port_mutex);

enum rxq_cycles_counter_type {
    RXQ_CYCLES_PROC_CURR,       /* Cycles spent successfully polling and
                                   processing packets during the current
                                   interval. */
    RXQ_CYCLES_PROC_HIST,       /* Total cycles of all intervals that are used
                                   during rxq to pmd assignment. */
    RXQ_N_CYCLES
};

#define XPS_TIMEOUT 500000LL    /* In microseconds. */

/* Contained by struct dp_netdev_port's 'rxqs' member.  */
struct dp_netdev_rxq {
    struct dp_netdev_port *port;
    struct netdev_rxq *rx;
    unsigned core_id;                  /* Core to which this queue should be
                                          pinned. OVS_CORE_UNSPEC if the
                                          queue doesn't need to be pinned to a
                                          particular core. */
    unsigned intrvl_idx;               /* Write index for 'cycles_intrvl'. */
    struct dp_netdev_pmd_thread *pmd;  /* pmd thread that polls this queue. */
    bool is_vhost;                     /* Is rxq of a vhost port. */

    /* Counters of cycles spent successfully polling and processing pkts. */
    atomic_ullong cycles[RXQ_N_CYCLES];
    /* We store PMD_RXQ_INTERVAL_MAX intervals of data for an rxq and then
       sum them to yield the cycles used for an rxq. */
    atomic_ullong cycles_intrvl[PMD_RXQ_INTERVAL_MAX];
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    odp_port_t port_no;
    bool dynamic_txqs;          /* If true XPS will be used. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct dp_netdev_rxq *rxqs;
    unsigned n_rxq;             /* Number of elements in 'rxqs' */
    unsigned *txq_used;         /* Number of threads that use each tx queue. */
    struct ovs_mutex txq_used_mutex;
    char *type;                 /* Port type as requested by user. */
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
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
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch;

    /* Packet classification. */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */
    /* 'cr' must be the last member. */
};

static void dp_netdev_flow_unref(struct dp_netdev_flow *);
static bool dp_netdev_flow_ref(struct dp_netdev_flow *);
static int dpif_netdev_flow_from_nlattrs(const struct nlattr *, uint32_t,
                                         struct flow *, bool);

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

struct polled_queue {
    struct dp_netdev_rxq *rxq;
    odp_port_t port_no;
};

/* Contained by struct dp_netdev_pmd_thread's 'poll_list' member. */
struct rxq_poll {
    struct dp_netdev_rxq *rxq;
    struct hmap_node node;
};

/* Contained by struct dp_netdev_pmd_thread's 'send_port_cache',
 * 'tnl_port_cache' or 'tx_ports'. */
struct tx_port {
    struct dp_netdev_port *port;
    int qid;
    long long last_used;
    struct hmap_node node;
    long long flush_time;
    struct dp_packet_batch output_pkts;
    struct dp_netdev_rxq *output_pkts_rxqs[NETDEV_MAX_BURST];
};

/* A set of properties for the current processing loop that is not directly
 * associated with the pmd thread itself, but with the packets being
 * processed or the short-term system configuration (for example, time).
 * Contained by struct dp_netdev_pmd_thread's 'ctx' member. */
struct dp_netdev_pmd_thread_ctx {
    /* Latest measured time. See 'pmd_thread_ctx_time_update()'. */
    long long now;
    /* RX queue from which last packet was received. */
    struct dp_netdev_rxq *last_rxq;
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
 * Each struct has its own flow cache and classifier per managed ingress port.
 * For packets received on ingress port, a look up is done on corresponding PMD
 * thread's flow cache and in case of a miss, lookup is performed in the
 * corresponding classifier of port.  Packets are executed with the found
 * actions in either case.
 * */
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */
    struct cmap_node node;          /* In 'dp->poll_threads'. */

    pthread_cond_t cond;            /* For synchronizing pmd thread reload. */
    struct ovs_mutex cond_mutex;    /* Mutex for condition variable. */

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected by 'non_pmd_mutex'.  Every other instance
     * will only be accessed by its own pmd thread. */
    struct emc_cache flow_cache;

    /* Flow-Table and classifiers
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'classifiers' must be made while still holding the
     * 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    struct cmap flow_table OVS_GUARDED; /* Flow table. */

    /* One classifier per in_port polled by the pmd */
    struct cmap classifiers;
    /* Periodically sort subtable vectors according to hit frequencies */
    long long int next_optimization;
    /* End of the next time interval for which processing cycles
       are stored for each polled rxq. */
    long long int rxq_next_cycle_store;

    /* Last interval timestamp. */
    uint64_t intrvl_tsc_prev;
    /* Last interval cycles. */
    atomic_ullong intrvl_cycles;

    /* Current context of the PMD thread. */
    struct dp_netdev_pmd_thread_ctx ctx;

    struct latch exit_latch;        /* For terminating the pmd thread. */
    struct seq *reload_seq;
    uint64_t last_reload_seq;
    atomic_bool reload;             /* Do we need to reload ports? */
    pthread_t thread;
    unsigned core_id;               /* CPU core id of this pmd thread. */
    int numa_id;                    /* numa node id of this pmd thread. */
    bool isolated;

    /* Queue id used by this pmd thread to send packets on all netdevs if
     * XPS disabled for this netdev. All static_tx_qid's are unique and less
     * than 'cmap_count(dp->poll_threads)'. */
    uint32_t static_tx_qid;

    /* Number of filled output batches. */
    int n_output_batches;

    struct ovs_mutex port_mutex;    /* Mutex for 'poll_list' and 'tx_ports'. */
    /* List of rx queues to poll. */
    struct hmap poll_list OVS_GUARDED;
    /* Map of 'tx_port's used for transmission.  Written by the main thread,
     * read by the pmd thread. */
    struct hmap tx_ports OVS_GUARDED;

    /* These are thread-local copies of 'tx_ports'.  One contains only tunnel
     * ports (that support push_tunnel/pop_tunnel), the other contains ports
     * with at least one txq (that support send).  A port can be in both.
     *
     * There are two separate maps to make sure that we don't try to execute
     * OUTPUT on a device which has 0 txqs or PUSH/POP on a non-tunnel device.
     *
     * The instances for cpu core NON_PMD_CORE_ID can be accessed by multiple
     * threads, and thusly need to be protected by 'non_pmd_mutex'.  Every
     * other instance will only be accessed by its own pmd thread. */
    struct hmap tnl_port_cache;
    struct hmap send_port_cache;

    /* Keep track of detailed PMD performance statistics. */
    struct pmd_perf_stats perf_stats;

    /* Set to true if the pmd thread needs to be reloaded. */
    bool need_reload;
};

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    uint64_t last_port_seq;
};

static int get_port_by_number(struct dp_netdev *dp, odp_port_t port_no,
                              struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex);
static int get_port_by_name(struct dp_netdev *dp, const char *devname,
                            struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex);
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
                                      struct dp_packet_batch *,
                                      bool should_steal,
                                      const struct flow *flow,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_input(struct dp_netdev_pmd_thread *,
                            struct dp_packet_batch *, odp_port_t port_no);
static void dp_netdev_recirculate(struct dp_netdev_pmd_thread *,
                                  struct dp_packet_batch *);

static void dp_netdev_disable_upcall(struct dp_netdev *);
static void dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd,
                                    struct dp_netdev *dp, unsigned core_id,
                                    int numa_id);
static void dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex);

static void *pmd_thread_main(void *);
static struct dp_netdev_pmd_thread *dp_netdev_get_pmd(struct dp_netdev *dp,
                                                      unsigned core_id);
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos);
static void dp_netdev_del_pmd(struct dp_netdev *dp,
                              struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd);
static void dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                         struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                           struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                     struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                       struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex);
static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force);

static void reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex);
static bool dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd);
static void pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex);
static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt);
static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type);
static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                           unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx);
static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge);
static int dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                                      struct tx_port *tx);

static inline bool emc_entry_alive(struct emc_entry *ce);
static void emc_clear_entry(struct emc_entry *ce);

static void dp_netdev_request_reconfigure(struct dp_netdev *dp);
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd);

static void
emc_cache_init(struct emc_cache *flow_cache)
{
    int i;

    flow_cache->sweep_idx = 0;
    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        flow_cache->entries[i].flow = NULL;
        flow_cache->entries[i].key.hash = 0;
        flow_cache->entries[i].key.len = sizeof(struct miniflow);
        flowmap_init(&flow_cache->entries[i].key.mf.map);
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

/* Updates the time in PMD threads context and should be called in three cases:
 *
 *     1. PMD structure initialization:
 *         - dp_netdev_configure_pmd()
 *
 *     2. Before processing of the new packet batch:
 *         - dpif_netdev_execute()
 *         - dp_netdev_process_rxq_port()
 *
 *     3. At least once per polling iteration in main polling threads if no
 *        packets received on current iteration:
 *         - dpif_netdev_run()
 *         - pmd_thread_main()
 *
 * 'pmd->ctx.now' should be used without update in all other cases if possible.
 */
static inline void
pmd_thread_ctx_time_update(struct dp_netdev_pmd_thread *pmd)
{
    pmd->ctx.now = time_usec();
}

/* Returns true if 'dpif' is a netdev or dummy dpif, false otherwise. */
bool
dpif_is_netdev(const struct dpif *dpif)
{
    return dpif->dpif_class->open == dpif_netdev_open;
}

static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    ovs_assert(dpif_is_netdev(dpif));
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
    return dpif_netdev_cast(dpif)->dp;
}

enum pmd_info_type {
    PMD_INFO_SHOW_STATS,  /* Show how cpu cycles are spent. */
    PMD_INFO_CLEAR_STATS, /* Set the cycles count to 0. */
    PMD_INFO_SHOW_RXQ,    /* Show poll lists of pmd threads. */
    PMD_INFO_PERF_SHOW,   /* Show pmd performance details. */
};

static void
format_pmd_thread(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    ds_put_cstr(reply, (pmd->core_id == NON_PMD_CORE_ID)
                        ? "main thread" : "pmd thread");
    if (pmd->numa_id != OVS_NUMA_UNSPEC) {
        ds_put_format(reply, " numa_id %d", pmd->numa_id);
    }
    if (pmd->core_id != OVS_CORE_UNSPEC && pmd->core_id != NON_PMD_CORE_ID) {
        ds_put_format(reply, " core_id %u", pmd->core_id);
    }
    ds_put_cstr(reply, ":\n");
}

static void
pmd_info_show_stats(struct ds *reply,
                    struct dp_netdev_pmd_thread *pmd)
{
    uint64_t stats[PMD_N_STATS];
    uint64_t total_cycles, total_packets;
    double passes_per_pkt = 0;
    double lookups_per_hit = 0;
    double packets_per_batch = 0;

    pmd_perf_read_counters(&pmd->perf_stats, stats);
    total_cycles = stats[PMD_CYCLES_ITER_IDLE]
                         + stats[PMD_CYCLES_ITER_BUSY];
    total_packets = stats[PMD_STAT_RECV];

    format_pmd_thread(reply, pmd);

    if (total_packets > 0) {
        passes_per_pkt = (total_packets + stats[PMD_STAT_RECIRC])
                            / (double) total_packets;
    }
    if (stats[PMD_STAT_MASKED_HIT] > 0) {
        lookups_per_hit = stats[PMD_STAT_MASKED_LOOKUP]
                            / (double) stats[PMD_STAT_MASKED_HIT];
    }
    if (stats[PMD_STAT_SENT_BATCHES] > 0) {
        packets_per_batch = stats[PMD_STAT_SENT_PKTS]
                            / (double) stats[PMD_STAT_SENT_BATCHES];
    }

    ds_put_format(reply,
                  "\tpackets received: %"PRIu64"\n"
                  "\tpacket recirculations: %"PRIu64"\n"
                  "\tavg. datapath passes per packet: %.02f\n"
                  "\temc hits: %"PRIu64"\n"
                  "\tmegaflow hits: %"PRIu64"\n"
                  "\tavg. subtable lookups per megaflow hit: %.02f\n"
                  "\tmiss with success upcall: %"PRIu64"\n"
                  "\tmiss with failed upcall: %"PRIu64"\n"
                  "\tavg. packets per output batch: %.02f\n",
                  total_packets, stats[PMD_STAT_RECIRC],
                  passes_per_pkt, stats[PMD_STAT_EXACT_HIT],
                  stats[PMD_STAT_MASKED_HIT], lookups_per_hit,
                  stats[PMD_STAT_MISS], stats[PMD_STAT_LOST],
                  packets_per_batch);

    if (total_cycles == 0) {
        return;
    }

    ds_put_format(reply,
                  "\tidle cycles: %"PRIu64" (%.02f%%)\n"
                  "\tprocessing cycles: %"PRIu64" (%.02f%%)\n",
                  stats[PMD_CYCLES_ITER_IDLE],
                  stats[PMD_CYCLES_ITER_IDLE] / (double) total_cycles * 100,
                  stats[PMD_CYCLES_ITER_BUSY],
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_cycles * 100);

    if (total_packets == 0) {
        return;
    }

    ds_put_format(reply,
                  "\tavg cycles per packet: %.02f (%"PRIu64"/%"PRIu64")\n",
                  total_cycles / (double) total_packets,
                  total_cycles, total_packets);

    ds_put_format(reply,
                  "\tavg processing cycles per packet: "
                  "%.02f (%"PRIu64"/%"PRIu64")\n",
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_packets,
                  stats[PMD_CYCLES_ITER_BUSY], total_packets);
}

static void
pmd_info_show_perf(struct ds *reply,
                   struct dp_netdev_pmd_thread *pmd,
                   struct pmd_perf_params *par)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        char *time_str =
                xastrftime_msec("%H:%M:%S.###", time_wall_msec(), true);
        long long now = time_msec();
        double duration = (now - pmd->perf_stats.start_ms) / 1000.0;

        ds_put_cstr(reply, "\n");
        ds_put_format(reply, "Time: %s\n", time_str);
        ds_put_format(reply, "Measurement duration: %.3f s\n", duration);
        ds_put_cstr(reply, "\n");
        format_pmd_thread(reply, pmd);
        ds_put_cstr(reply, "\n");
        pmd_perf_format_overall_stats(reply, &pmd->perf_stats, duration);
        if (pmd_perf_metrics_enabled(pmd)) {
            /* Prevent parallel clearing of perf metrics. */
            ovs_mutex_lock(&pmd->perf_stats.clear_mutex);
            if (par->histograms) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_histograms(reply, &pmd->perf_stats);
            }
            if (par->iter_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_iteration_history(reply, &pmd->perf_stats,
                        par->iter_hist_len);
            }
            if (par->ms_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_ms_history(reply, &pmd->perf_stats,
                        par->ms_hist_len);
            }
            ovs_mutex_unlock(&pmd->perf_stats.clear_mutex);
        }
        free(time_str);
    }
}

static int
compare_poll_list(const void *a_, const void *b_)
{
    const struct rxq_poll *a = a_;
    const struct rxq_poll *b = b_;

    const char *namea = netdev_rxq_get_name(a->rxq->rx);
    const char *nameb = netdev_rxq_get_name(b->rxq->rx);

    int cmp = strcmp(namea, nameb);
    if (!cmp) {
        return netdev_rxq_get_queue_id(a->rxq->rx)
               - netdev_rxq_get_queue_id(b->rxq->rx);
    } else {
        return cmp;
    }
}

static void
sorted_poll_list(struct dp_netdev_pmd_thread *pmd, struct rxq_poll **list,
                 size_t *n)
{
    struct rxq_poll *ret, *poll;
    size_t i;

    *n = hmap_count(&pmd->poll_list);
    if (!*n) {
        ret = NULL;
    } else {
        ret = xcalloc(*n, sizeof *ret);
        i = 0;
        HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
            ret[i] = *poll;
            i++;
        }
        ovs_assert(i == *n);
        qsort(ret, *n, sizeof *ret, compare_poll_list);
    }

    *list = ret;
}

static void
pmd_info_show_rxq(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        struct rxq_poll *list;
        size_t n_rxq;
        uint64_t total_cycles = 0;

        ds_put_format(reply,
                      "pmd thread numa_id %d core_id %u:\n\tisolated : %s\n",
                      pmd->numa_id, pmd->core_id, (pmd->isolated)
                                                  ? "true" : "false");

        ovs_mutex_lock(&pmd->port_mutex);
        sorted_poll_list(pmd, &list, &n_rxq);

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_cycles);
        /* Estimate the cycles to cover all intervals. */
        total_cycles *= PMD_RXQ_INTERVAL_MAX;

        for (int i = 0; i < n_rxq; i++) {
            struct dp_netdev_rxq *rxq = list[i].rxq;
            const char *name = netdev_rxq_get_name(rxq->rx);
            uint64_t proc_cycles = 0;

            for (int j = 0; j < PMD_RXQ_INTERVAL_MAX; j++) {
                proc_cycles += dp_netdev_rxq_get_intrvl_cycles(rxq, j);
            }
            ds_put_format(reply, "\tport: %-16s\tqueue-id: %2d", name,
                          netdev_rxq_get_queue_id(list[i].rxq->rx));
            ds_put_format(reply, "\tpmd usage: ");
            if (total_cycles) {
                ds_put_format(reply, "%2"PRIu64"",
                              proc_cycles * 100 / total_cycles);
                ds_put_cstr(reply, " %");
            } else {
                ds_put_format(reply, "%s", "NOT AVAIL");
            }
            ds_put_cstr(reply, "\n");
        }
        ovs_mutex_unlock(&pmd->port_mutex);
        free(list);
    }
}

static int
compare_poll_thread_list(const void *a_, const void *b_)
{
    const struct dp_netdev_pmd_thread *a, *b;

    a = *(struct dp_netdev_pmd_thread **)a_;
    b = *(struct dp_netdev_pmd_thread **)b_;

    if (a->core_id < b->core_id) {
        return -1;
    }
    if (a->core_id > b->core_id) {
        return 1;
    }
    return 0;
}

/* Create a sorted list of pmd's from the dp->poll_threads cmap. We can use
 * this list, as long as we do not go to quiescent state. */
static void
sorted_poll_thread_list(struct dp_netdev *dp,
                        struct dp_netdev_pmd_thread ***list,
                        size_t *n)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (k >= n_pmds) {
            break;
        }
        pmd_list[k++] = pmd;
    }

    qsort(pmd_list, k, sizeof *pmd_list, compare_poll_thread_list);

    *list = pmd_list;
    *n = k;
}

static void
dpif_netdev_pmd_rebalance(struct unixctl_conn *conn, int argc,
                          const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev *dp = NULL;

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

    dp_netdev_request_reconfigure(dp);
    ovs_mutex_unlock(&dp_netdev_mutex);
    ds_put_cstr(&reply, "pmd rxq rebalance requested.\n");
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_netdev_pmd_info(struct unixctl_conn *conn, int argc, const char *argv[],
                     void *aux)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev_pmd_thread **pmd_list;
    struct dp_netdev *dp = NULL;
    enum pmd_info_type type = *(enum pmd_info_type *) aux;
    unsigned int core_id;
    bool filter_on_pmd = false;
    size_t n;

    ovs_mutex_lock(&dp_netdev_mutex);

    while (argc > 1) {
        if (!strcmp(argv[1], "-pmd") && argc > 2) {
            if (str_to_uint(argv[2], 10, &core_id)) {
                filter_on_pmd = true;
            }
            argc -= 2;
            argv += 2;
        } else {
            dp = shash_find_data(&dp_netdevs, argv[1]);
            argc -= 1;
            argv += 1;
        }
    }

    if (!dp) {
        if (shash_count(&dp_netdevs) == 1) {
            /* There's only one datapath */
            dp = shash_first(&dp_netdevs)->data;
        } else {
            ovs_mutex_unlock(&dp_netdev_mutex);
            unixctl_command_reply_error(conn,
                                        "please specify an existing datapath");
            return;
        }
    }

    sorted_poll_thread_list(dp, &pmd_list, &n);
    for (size_t i = 0; i < n; i++) {
        struct dp_netdev_pmd_thread *pmd = pmd_list[i];
        if (!pmd) {
            break;
        }
        if (filter_on_pmd && pmd->core_id != core_id) {
            continue;
        }
        if (type == PMD_INFO_SHOW_RXQ) {
            pmd_info_show_rxq(&reply, pmd);
        } else if (type == PMD_INFO_CLEAR_STATS) {
            pmd_perf_stats_clear(&pmd->perf_stats);
        } else if (type == PMD_INFO_SHOW_STATS) {
            pmd_info_show_stats(&reply, pmd);
        } else if (type == PMD_INFO_PERF_SHOW) {
            pmd_info_show_perf(&reply, pmd, (struct pmd_perf_params *)aux);
        }
    }
    free(pmd_list);

    ovs_mutex_unlock(&dp_netdev_mutex);

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
pmd_perf_show_cmd(struct unixctl_conn *conn, int argc,
                          const char *argv[],
                          void *aux OVS_UNUSED)
{
    struct pmd_perf_params par;
    long int it_hist = 0, ms_hist = 0;
    par.histograms = true;

    while (argc > 1) {
        if (!strcmp(argv[1], "-nh")) {
            par.histograms = false;
            argc -= 1;
            argv += 1;
        } else if (!strcmp(argv[1], "-it") && argc > 2) {
            it_hist = strtol(argv[2], NULL, 10);
            if (it_hist < 0) {
                it_hist = 0;
            } else if (it_hist > HISTORY_LEN) {
                it_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else if (!strcmp(argv[1], "-ms") && argc > 2) {
            ms_hist = strtol(argv[2], NULL, 10);
            if (ms_hist < 0) {
                ms_hist = 0;
            } else if (ms_hist > HISTORY_LEN) {
                ms_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else {
            break;
        }
    }
    par.iter_hist_len = it_hist;
    par.ms_hist_len = ms_hist;
    par.command_type = PMD_INFO_PERF_SHOW;
    dpif_netdev_pmd_info(conn, argc, argv, &par);
}

static int
dpif_netdev_init(void)
{
    static enum pmd_info_type show_aux = PMD_INFO_SHOW_STATS,
                              clear_aux = PMD_INFO_CLEAR_STATS,
                              poll_aux = PMD_INFO_SHOW_RXQ;

    unixctl_command_register("dpif-netdev/pmd-stats-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&show_aux);
    unixctl_command_register("dpif-netdev/pmd-stats-clear", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&clear_aux);
    unixctl_command_register("dpif-netdev/pmd-rxq-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&poll_aux);
    unixctl_command_register("dpif-netdev/pmd-perf-show",
                             "[-nh] [-it iter-history-len]"
                             " [-ms ms-history-len]"
                             " [-pmd core] [dp]",
                             0, 8, pmd_perf_show_cmd,
                             NULL);
    unixctl_command_register("dpif-netdev/pmd-rxq-rebalance", "[dp]",
                             0, 1, dpif_netdev_pmd_rebalance,
                             NULL);
    unixctl_command_register("dpif-netdev/pmd-perf-log-set",
                             "on|off [-b before] [-a after] [-e|-ne] "
                             "[-us usec] [-q qlen]",
                             0, 10, pmd_perf_log_set_cmd,
                             NULL);
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
                  : dpif_netdev_class_is_dummy(class) ? "dummy-internal"
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
    hmap_init(&dp->ports);
    dp->port_seq = seq_create();
    fat_rwlock_init(&dp->upcall_rwlock);

    dp->reconfigure_seq = seq_create();
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    for (int i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_init_adaptive(&dp->meter_locks[i]);
    }

    /* Disable upcalls by default. */
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

    conntrack_init(&dp->conntrack);

    atomic_init(&dp->emc_insert_min, DEFAULT_EM_FLOW_INSERT_MIN);
    atomic_init(&dp->tx_flush_interval, DEFAULT_TX_FLUSH_INTERVAL);

    cmap_init(&dp->poll_threads);

    ovs_mutex_init(&dp->tx_qid_pool_mutex);
    /* We need 1 Tx queue for each possible core + 1 for non-PMD threads. */
    dp->tx_qid_pool = id_pool_create(0, ovs_numa_get_n_cores() + 1);

    ovs_mutex_init_recursive(&dp->non_pmd_mutex);
    ovsthread_key_create(&dp->per_pmd_key, NULL);

    ovs_mutex_lock(&dp->port_mutex);
    /* non-PMD will be created before all other threads and will
     * allocate static_tx_qid = 0. */
    dp_netdev_set_nonpmd(dp);

    error = do_add_port(dp, name, dpif_netdev_port_open_type(dp->class,
                                                             "internal"),
                        ODPP_LOCAL);
    ovs_mutex_unlock(&dp->port_mutex);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    dp->last_tnl_conf_seq = seq_read(tnl_conf_seq);
    *dpp = dp;
    return 0;
}

static void
dp_netdev_request_reconfigure(struct dp_netdev *dp)
{
    seq_change(dp->reconfigure_seq);
}

static bool
dp_netdev_is_reconf_required(struct dp_netdev *dp)
{
    return seq_read(dp->reconfigure_seq) != dp->last_reconfigure_seq;
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

static void
dp_delete_meter(struct dp_netdev *dp, uint32_t meter_id)
    OVS_REQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    if (dp->meters[meter_id]) {
        free(dp->meters[meter_id]);
        dp->meters[meter_id] = NULL;
    }
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port, *next;

    shash_find_and_delete(&dp_netdevs, dp->name);

    ovs_mutex_lock(&dp->port_mutex);
    HMAP_FOR_EACH_SAFE (port, next, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    dp_netdev_destroy_all_pmds(dp, true);
    cmap_destroy(&dp->poll_threads);

    ovs_mutex_destroy(&dp->tx_qid_pool_mutex);
    id_pool_destroy(dp->tx_qid_pool);

    ovs_mutex_destroy(&dp->non_pmd_mutex);
    ovsthread_key_delete(dp->per_pmd_key);

    conntrack_destroy(&dp->conntrack);


    seq_destroy(dp->reconfigure_seq);

    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    ovs_mutex_destroy(&dp->port_mutex);

    /* Upcalls must be disabled at this point */
    dp_netdev_destroy_upcall_lock(dp);

    int i;

    for (i = 0; i < MAX_METERS; ++i) {
        meter_lock(dp, i);
        dp_delete_meter(dp, i);
        meter_unlock(dp, i);
    }
    for (i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_destroy(&dp->meter_locks[i]);
    }

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
    uint64_t pmd_stats[PMD_N_STATS];

    stats->n_flows = stats->n_hit = stats->n_missed = stats->n_lost = 0;
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        stats->n_flows += cmap_count(&pmd->flow_table);
        pmd_perf_read_counters(&pmd->perf_stats, pmd_stats);
        stats->n_hit += pmd_stats[PMD_STAT_EXACT_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_MASKED_HIT];
        stats->n_missed += pmd_stats[PMD_STAT_MISS];
        stats->n_lost += pmd_stats[PMD_STAT_LOST];
    }
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;

    return 0;
}

static void
dp_netdev_reload_pmd__(struct dp_netdev_pmd_thread *pmd)
{
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&pmd->dp->non_pmd_mutex);
        ovs_mutex_lock(&pmd->port_mutex);
        pmd_load_cached_ports(pmd);
        ovs_mutex_unlock(&pmd->port_mutex);
        ovs_mutex_unlock(&pmd->dp->non_pmd_mutex);
        return;
    }

    ovs_mutex_lock(&pmd->cond_mutex);
    seq_change(pmd->reload_seq);
    atomic_store_relaxed(&pmd->reload, true);
    ovs_mutex_cond_wait(&pmd->cond, &pmd->cond_mutex);
    ovs_mutex_unlock(&pmd->cond_mutex);
}

static uint32_t
hash_port_no(odp_port_t port_no)
{
    return hash_int(odp_to_u32(port_no), 0);
}

static int
port_create(const char *devname, const char *type,
            odp_port_t port_no, struct dp_netdev_port **portp)
{
    struct netdev_saved_flags *sf;
    struct dp_netdev_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    *portp = NULL;

    /* Open and validate network device. */
    error = netdev_open(devname, type, &netdev);
    if (error) {
        return error;
    }
    /* XXX reject non-Ethernet devices */

    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR("%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) {
        VLOG_ERR("%s: cannot set promisc flag", devname);
        goto out;
    }

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->netdev = netdev;
    port->type = xstrdup(type);
    port->sf = sf;
    port->need_reconfigure = true;
    ovs_mutex_init(&port->txq_used_mutex);

    *portp = port;

    return 0;

out:
    netdev_close(netdev);
    return error;
}

static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;
    int error;

    /* Reject devices already in 'dp'. */
    if (!get_port_by_name(dp, devname, &port)) {
        return EEXIST;
    }

    error = port_create(devname, type, port_no, &port);
    if (error) {
        return error;
    }

    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);

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
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_netdev_lookup_port(dp, port_no);
        return *portp ? 0 : ENODEV;
    }
}

static void
port_destroy(struct dp_netdev_port *port)
{
    if (!port) {
        return;
    }

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);

    for (unsigned i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
    }
    ovs_mutex_destroy(&port->txq_used_mutex);
    free(port->rxq_affinity_list);
    free(port->txq_used);
    free(port->rxqs);
    free(port->type);
    free(port);
}

static int
get_port_by_name(struct dp_netdev *dp,
                 const char *devname, struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }

    /* Callers of dpif_netdev_port_query_by_name() expect ENODEV for a non
     * existing port. */
    return ENODEV;
}

/* Returns 'true' if there is a port with pmd netdev. */
static bool
has_pmd_port(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_pmd(port->netdev)) {
            return true;
        }
    }

    return false;
}

static void
do_del_port(struct dp_netdev *dp, struct dp_netdev_port *port)
    OVS_REQUIRES(dp->port_mutex)
{
    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);

    port_destroy(port);
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

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

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

static inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd,
                           odp_port_t in_port)
{
    struct dpcls *cls;
    uint32_t hash = hash_port_no(in_port);
    CMAP_FOR_EACH_WITH_HASH (cls, node, hash, &pmd->classifiers) {
        if (cls->in_port == in_port) {
            /* Port classifier exists already */
            return cls;
        }
    }
    return NULL;
}

static inline struct dpcls *
dp_netdev_pmd_find_dpcls(struct dp_netdev_pmd_thread *pmd,
                         odp_port_t in_port)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    uint32_t hash = hash_port_no(in_port);

    if (!cls) {
        /* Create new classifier for in_port */
        cls = xmalloc(sizeof(*cls));
        dpcls_init(cls);
        cls->in_port = in_port;
        cmap_insert(&pmd->classifiers, &cls->node, hash);
        VLOG_DBG("Creating dpcls %p for in_port %d", cls, in_port);
    }
    return cls;
}

static void
dp_netdev_pmd_remove_flow(struct dp_netdev_pmd_thread *pmd,
                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct cmap_node *node = CONST_CAST(struct cmap_node *, &flow->node);
    struct dpcls *cls;
    odp_port_t in_port = flow->flow.in_port.odp_port;

    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    ovs_assert(cls != NULL);
    dpcls_remove(cls, &flow->cr);
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
    struct hmap_position position;
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

    ovs_mutex_lock(&dp->port_mutex);
    node = hmap_at_position(&dp->ports, &state->position);
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
    ovs_mutex_unlock(&dp->port_mutex);

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
 * - These functions can be inlined by the compiler. */

/* Given the number of bits set in miniflow's maps, returns the size of the
 * 'netdev_flow_key.mf' */
static inline size_t
netdev_flow_key_size(size_t flow_u64s)
{
    return sizeof(struct miniflow) + MINIFLOW_VALUES_SIZE(flow_u64s);
}

static inline bool
netdev_flow_key_equal(const struct netdev_flow_key *a,
                      const struct netdev_flow_key *b)
{
    /* 'b->len' may be not set yet. */
    return a->hash == b->hash && !memcmp(&a->mf, &b->mf, a->len);
}

/* Used to compare 'netdev_flow_key' in the exact match cache to a miniflow.
 * The maps are compared bitwise, so both 'key->mf' and 'mf' must have been
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

/* Initialize a netdev_flow_key 'mask' from 'match'. */
static inline void
netdev_flow_mask_init(struct netdev_flow_key *mask,
                      const struct match *match)
{
    uint64_t *dst = miniflow_values(&mask->mf);
    struct flowmap fmap;
    uint32_t hash = 0;
    size_t idx;

    /* Only check masks that make sense for the flow. */
    flow_wc_map(&match->flow, &fmap);
    flowmap_init(&mask->mf.map);

    FLOWMAP_FOR_EACH_INDEX(idx, fmap) {
        uint64_t mask_u64 = flow_u64_value(&match->wc.masks, idx);

        if (mask_u64) {
            flowmap_set(&mask->mf.map, idx, 1);
            *dst++ = mask_u64;
            hash = hash_add64(hash, mask_u64);
        }
    }

    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, mask->mf.map) {
        hash = hash_add64(hash, map);
    }

    size_t n = dst - miniflow_get_values(&mask->mf);

    mask->hash = hash_finish(hash, n * 8);
    mask->len = netdev_flow_key_size(n);
}

/* Initializes 'dst' as a copy of 'flow' masked with 'mask'. */
static inline void
netdev_flow_key_init_masked(struct netdev_flow_key *dst,
                            const struct flow *flow,
                            const struct netdev_flow_key *mask)
{
    uint64_t *dst_u64 = miniflow_values(&dst->mf);
    const uint64_t *mask_u64 = miniflow_get_values(&mask->mf);
    uint32_t hash = 0;
    uint64_t value;

    dst->len = mask->len;
    dst->mf = mask->mf;   /* Copy maps. */

    FLOW_FOR_EACH_IN_MAPS(value, flow, mask->mf.map) {
        *dst_u64 = value & *mask_u64++;
        hash = hash_add64(hash, *dst_u64++);
    }
    dst->hash = hash_finish(hash,
                            (dst_u64 - miniflow_get_values(&dst->mf)) * 8);
}

/* Iterate through netdev_flow_key TNL u64 values specified by 'FLOWMAP'. */
#define NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(VALUE, KEY, FLOWMAP)   \
    MINIFLOW_FOR_EACH_IN_FLOWMAP(VALUE, &(KEY)->mf, FLOWMAP)

/* Returns a hash value for the bits of 'key' where there are 1-bits in
 * 'mask'. */
static inline uint32_t
netdev_flow_key_hash_in_mask(const struct netdev_flow_key *key,
                             const struct netdev_flow_key *mask)
{
    const uint64_t *p = miniflow_get_values(&mask->mf);
    uint32_t hash = 0;
    uint64_t value;

    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(value, key, mask->mf.map) {
        hash = hash_add64(hash, value & *p++);
    }

    return hash_finish(hash, (p - miniflow_get_values(&mask->mf)) * 8);
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

static inline void
emc_probabilistic_insert(struct dp_netdev_pmd_thread *pmd,
                         const struct netdev_flow_key *key,
                         struct dp_netdev_flow *flow)
{
    /* Insert an entry into the EMC based on probability value 'min'. By
     * default the value is UINT32_MAX / 100 which yields an insertion
     * probability of 1/100 ie. 1% */

    uint32_t min;
    atomic_read_relaxed(&pmd->dp->emc_insert_min, &min);

    if (min && random_uint32() <= min) {
        emc_insert(&pmd->flow_cache, key, flow);
    }
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
dp_netdev_pmd_lookup_flow(struct dp_netdev_pmd_thread *pmd,
                          const struct netdev_flow_key *key,
                          int *lookup_num_p)
{
    struct dpcls *cls;
    struct dpcls_rule *rule;
    odp_port_t in_port = u32_to_odp(MINIFLOW_GET_U32(&key->mf,
                                                     in_port.odp_port));
    struct dp_netdev_flow *netdev_flow = NULL;

    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        dpcls_lookup(cls, key, &rule, 1, lookup_num_p);
        netdev_flow = dp_netdev_flow_cast(rule);
    }
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
        && !dpif_netdev_flow_from_nlattrs(key, key_len, &flow, false)) {
        dpif_flow_hash(pmd->dp->dpif, &flow, sizeof flow, &ufid);
        ufidp = &ufid;
    }

    if (ufidp) {
        CMAP_FOR_EACH_WITH_HASH (netdev_flow, node, dp_netdev_flow_hash(ufidp),
                                 &pmd->flow_table) {
            if (ovs_u128_equals(netdev_flow->ufid, *ufidp)) {
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
        struct odp_flow_key_parms odp_parms = {
            .flow = &netdev_flow->flow,
            .mask = &wc.masks,
            .support = dp_netdev_support,
        };

        miniflow_expand(&netdev_flow->cr.mask->mf, &wc.masks);
        /* in_port is exact matched, but we have left it out from the mask for
         * optimnization reasons. Add in_port back to the mask. */
        wc.masks.in_port.odp_port = ODPP_NONE;

        /* Key */
        offset = key_buf->size;
        flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(&odp_parms, key_buf);
        flow->key_len = key_buf->size - offset;

        /* Mask */
        offset = mask_buf->size;
        flow->mask = ofpbuf_tail(mask_buf);
        odp_parms.key_buf = key_buf;
        odp_flow_key_from_mask(&odp_parms, mask_buf);
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
                              struct flow_wildcards *wc, bool probe)
{
    enum odp_key_fitness fitness;

    fitness = odp_flow_key_to_mask(mask_key, mask_key_len, wc, flow);
    if (fitness) {
        if (!probe) {
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
        }

        return EINVAL;
    }

    return 0;
}

static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct flow *flow, bool probe)
{
    if (odp_flow_key_to_flow(key, key_len, flow)) {
        if (!probe) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_flow() and odp_flow_key_to_flow() disagree on
             * the acceptable form of a flow.  Log the problem as an error,
             * with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, NULL, 0, NULL, &s, true);
                VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
                ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    if (flow->ct_state & DP_NETDEV_CS_UNSUPPORTED_MASK) {
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
    struct hmapx to_find = HMAPX_INITIALIZER(&to_find);
    struct hmapx_node *node;
    int error = EINVAL;

    if (get->pmd_id == PMD_ID_NULL) {
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (dp_netdev_pmd_try_ref(pmd) && !hmapx_add(&to_find, pmd)) {
                dp_netdev_pmd_unref(pmd);
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, get->pmd_id);
        if (!pmd) {
            goto out;
        }
        hmapx_add(&to_find, pmd);
    }

    if (!hmapx_count(&to_find)) {
        goto out;
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        netdev_flow = dp_netdev_pmd_find_flow(pmd, get->ufid, get->key,
                                              get->key_len);
        if (netdev_flow) {
            dp_netdev_flow_to_dpif_flow(netdev_flow, get->buffer, get->buffer,
                                        get->flow, false);
            error = 0;
            break;
        } else {
            error = ENOENT;
        }
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        dp_netdev_pmd_unref(pmd);
    }
out:
    hmapx_destroy(&to_find);
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
    struct dpcls *cls;

    /* Make sure in_port is exact matched before we read it. */
    ovs_assert(match->wc.masks.in_port.odp_port == ODPP_NONE);
    odp_port_t in_port = match->flow.in_port.odp_port;

    /* As we select the dpcls based on the port number, each netdev flow
     * belonging to the same dpcls will have the same odp_port value.
     * For performance reasons we wildcard odp_port here in the mask.  In the
     * typical case dp_hash is also wildcarded, and the resulting 8-byte
     * chunk {dp_hash, in_port} will be ignored by netdev_flow_mask_init() and
     * will not be part of the subtable mask.
     * This will speed up the hash computation during dpcls_lookup() because
     * there is one less call to hash_add64() in this case. */
    match->wc.masks.in_port.odp_port = 0;
    netdev_flow_mask_init(&mask, match);
    match->wc.masks.in_port.odp_port = ODPP_NONE;

    /* Make sure wc does not have metadata. */
    ovs_assert(!FLOWMAP_HAS_FIELD(&mask.mf.map, metadata)
               && !FLOWMAP_HAS_FIELD(&mask.mf.map, regs));

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

    /* Select dpcls for in_port. Relies on in_port to be exact match. */
    cls = dp_netdev_pmd_find_dpcls(pmd, in_port);
    dpcls_insert(cls, &flow->cr, &mask);

    cmap_insert(&pmd->flow_table, CONST_CAST(struct cmap_node *, &flow->node),
                dp_netdev_flow_hash(&flow->ufid));

    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&upcall_rl)))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        struct ofpbuf key_buf, mask_buf;
        struct odp_flow_key_parms odp_parms = {
            .flow = &match->flow,
            .mask = &match->wc.masks,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key_buf, 0);
        ofpbuf_init(&mask_buf, 0);

        odp_flow_key_from_flow(&odp_parms, &key_buf);
        odp_parms.key_buf = &key_buf;
        odp_flow_key_from_mask(&odp_parms, &mask_buf);

        ds_put_cstr(&ds, "flow_add: ");
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " ");
        odp_flow_format(key_buf.data, key_buf.size,
                        mask_buf.data, mask_buf.size,
                        NULL, &ds, false);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len, NULL);

        VLOG_DBG("%s", ds_cstr(&ds));

        ofpbuf_uninit(&key_buf);
        ofpbuf_uninit(&mask_buf);

        /* Add a printout of the actual match installed. */
        struct match m;
        ds_clear(&ds);
        ds_put_cstr(&ds, "flow match: ");
        miniflow_expand(&flow->cr.flow.mf, &m.flow);
        miniflow_expand(&flow->cr.mask->mf, &m.wc.masks);
        memset(&m.tun_md, 0, sizeof m.tun_md);
        match_format(&m, NULL, &ds, OFP_DEFAULT_PRIORITY);

        VLOG_DBG("%s", ds_cstr(&ds));

        ds_destroy(&ds);
    }

    return flow;
}

static int
flow_put_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct netdev_flow_key *key,
                struct match *match,
                ovs_u128 *ufid,
                const struct dpif_flow_put *put,
                struct dpif_flow_stats *stats)
{
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }

    ovs_mutex_lock(&pmd->flow_mutex);
    netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
    if (!netdev_flow) {
        if (put->flags & DPIF_FP_CREATE) {
            if (cmap_count(&pmd->flow_table) < MAX_FLOWS) {
                dp_netdev_flow_add(pmd, match, ufid, put->actions,
                                   put->actions_len);
                error = 0;
            } else {
                error = EFBIG;
            }
        } else {
            error = ENOENT;
        }
    } else {
        if (put->flags & DPIF_FP_MODIFY) {
            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions,
                                                   put->actions_len);

            old_actions = dp_netdev_flow_get_actions(netdev_flow);
            ovsrcu_set(&netdev_flow->actions, new_actions);

            if (stats) {
                get_dpif_flow_stats(netdev_flow, stats);
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
    return error;
}

static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct netdev_flow_key key, mask;
    struct dp_netdev_pmd_thread *pmd;
    struct match match;
    ovs_u128 ufid;
    int error;
    bool probe = put->flags & DPIF_FP_PROBE;

    if (put->stats) {
        memset(put->stats, 0, sizeof *put->stats);
    }
    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &match.flow,
                                          probe);
    if (error) {
        return error;
    }
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len,
                                          put->mask, put->mask_len,
                                          &match.flow, &match.wc, probe);
    if (error) {
        return error;
    }

    if (put->ufid) {
        ufid = *put->ufid;
    } else {
        dpif_flow_hash(dpif, &match.flow, sizeof match.flow, &ufid);
    }

    /* Must produce a netdev_flow_key for lookup.
     * Use the same method as employed to create the key when adding
     * the flow to the dplcs to make sure they match. */
    netdev_flow_mask_init(&mask, &match);
    netdev_flow_key_init_masked(&key, &match.flow, &mask);

    if (put->pmd_id == PMD_ID_NULL) {
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

            pmd_error = flow_put_on_pmd(pmd, &key, &match, &ufid, put,
                                        &pmd_stats);
            if (pmd_error) {
                error = pmd_error;
            } else if (put->stats) {
                put->stats->n_packets += pmd_stats.n_packets;
                put->stats->n_bytes += pmd_stats.n_bytes;
                put->stats->used = MAX(put->stats->used, pmd_stats.used);
                put->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, put->pmd_id);
        if (!pmd) {
            return EINVAL;
        }
        error = flow_put_on_pmd(pmd, &key, &match, &ufid, put, put->stats);
        dp_netdev_pmd_unref(pmd);
    }

    return error;
}

static int
flow_del_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del)
{
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

    ovs_mutex_lock(&pmd->flow_mutex);
    netdev_flow = dp_netdev_pmd_find_flow(pmd, del->ufid, del->key,
                                          del->key_len);
    if (netdev_flow) {
        if (stats) {
            get_dpif_flow_stats(netdev_flow, stats);
        }
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&pmd->flow_mutex);

    return error;
}

static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    int error = 0;

    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

    if (del->pmd_id == PMD_ID_NULL) {
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

            pmd_error = flow_del_on_pmd(pmd, &pmd_stats, del);
            if (pmd_error) {
                error = pmd_error;
            } else if (del->stats) {
                del->stats->n_packets += pmd_stats.n_packets;
                del->stats->n_bytes += pmd_stats.n_bytes;
                del->stats->used = MAX(del->stats->used, pmd_stats.used);
                del->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, del->pmd_id);
        if (!pmd) {
            return EINVAL;
        }
        error = flow_del_on_pmd(pmd, del->stats, del);
        dp_netdev_pmd_unref(pmd);
    }


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
dpif_netdev_flow_dump_create(const struct dpif *dpif_, bool terse,
                             char *type OVS_UNUSED)
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
    struct dp_packet_batch pp;

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
        if (!pmd) {
            return EBUSY;
        }
    }

    if (execute->probe) {
        /* If this is part of a probe, Drop the packet, since executing
         * the action may actually cause spurious packets be sent into
         * the network. */
        if (pmd->core_id == NON_PMD_CORE_ID) {
            dp_netdev_pmd_unref(pmd);
        }
        return 0;
    }

    /* If the current thread is non-pmd thread, acquires
     * the 'non_pmd_mutex'. */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
    }

    /* Update current time in PMD context. */
    pmd_thread_ctx_time_update(pmd);

    /* The action processing expects the RSS hash to be valid, because
     * it's always initialized at the beginning of datapath processing.
     * In this case, though, 'execute->packet' may not have gone through
     * the datapath at all, it may have been generated by the upper layer
     * (OpenFlow packet-out, BFD frame, ...). */
    if (!dp_packet_rss_valid(execute->packet)) {
        dp_packet_set_rss_hash(execute->packet,
                               flow_hash_5tuple(execute->flow, 0));
    }

    dp_packet_batch_init_packet(&pp, execute->packet);
    dp_netdev_execute_actions(pmd, &pp, false, execute->flow,
                              execute->actions, execute->actions_len);
    dp_netdev_pmd_flush_output_packets(pmd, true);

    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_unlock(&dp->non_pmd_mutex);
        dp_netdev_pmd_unref(pmd);
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
            op->error = dpif_netdev_flow_put(dpif, &op->flow_put);
            break;

        case DPIF_OP_FLOW_DEL:
            op->error = dpif_netdev_flow_del(dpif, &op->flow_del);
            break;

        case DPIF_OP_EXECUTE:
            op->error = dpif_netdev_execute(dpif, &op->execute);
            break;

        case DPIF_OP_FLOW_GET:
            op->error = dpif_netdev_flow_get(dpif, &op->flow_get);
            break;
        }
    }
}

/* Applies datapath configuration from the database. Some of the changes are
 * actually applied in dpif_netdev_run(). */
static int
dpif_netdev_set_config(struct dpif *dpif, const struct smap *other_config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    const char *cmask = smap_get(other_config, "pmd-cpu-mask");
    unsigned long long insert_prob =
        smap_get_ullong(other_config, "emc-insert-inv-prob",
                        DEFAULT_EM_FLOW_INSERT_INV_PROB);
    uint32_t insert_min, cur_min;
    uint32_t tx_flush_interval, cur_tx_flush_interval;

    tx_flush_interval = smap_get_int(other_config, "tx-flush-interval",
                                     DEFAULT_TX_FLUSH_INTERVAL);
    atomic_read_relaxed(&dp->tx_flush_interval, &cur_tx_flush_interval);
    if (tx_flush_interval != cur_tx_flush_interval) {
        atomic_store_relaxed(&dp->tx_flush_interval, tx_flush_interval);
        VLOG_INFO("Flushing interval for tx queues set to %"PRIu32" us",
                  tx_flush_interval);
    }

    if (!nullable_string_is_equal(dp->pmd_cmask, cmask)) {
        free(dp->pmd_cmask);
        dp->pmd_cmask = nullable_xstrdup(cmask);
        dp_netdev_request_reconfigure(dp);
    }

    atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
    if (insert_prob <= UINT32_MAX) {
        insert_min = insert_prob == 0 ? 0 : UINT32_MAX / insert_prob;
    } else {
        insert_min = DEFAULT_EM_FLOW_INSERT_MIN;
        insert_prob = DEFAULT_EM_FLOW_INSERT_INV_PROB;
    }

    if (insert_min != cur_min) {
        atomic_store_relaxed(&dp->emc_insert_min, insert_min);
        if (insert_min == 0) {
            VLOG_INFO("EMC has been disabled");
        } else {
            VLOG_INFO("EMC insertion probability changed to 1/%llu (~%.2f%%)",
                      insert_prob, (100 / (float)insert_prob));
        }
    }

    bool perf_enabled = smap_get_bool(other_config, "pmd-perf-metrics", false);
    bool cur_perf_enabled;
    atomic_read_relaxed(&dp->pmd_perf_metrics, &cur_perf_enabled);
    if (perf_enabled != cur_perf_enabled) {
        atomic_store_relaxed(&dp->pmd_perf_metrics, perf_enabled);
        if (perf_enabled) {
            VLOG_INFO("PMD performance metrics collection enabled");
        } else {
            VLOG_INFO("PMD performance metrics collection disabled");
        }
    }

    return 0;
}

/* Parses affinity list and returns result in 'core_ids'. */
static int
parse_affinity_list(const char *affinity_list, unsigned *core_ids, int n_rxq)
{
    unsigned i;
    char *list, *copy, *key, *value;
    int error = 0;

    for (i = 0; i < n_rxq; i++) {
        core_ids[i] = OVS_CORE_UNSPEC;
    }

    if (!affinity_list) {
        return 0;
    }

    list = copy = xstrdup(affinity_list);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        int rxq_id, core_id;

        if (!str_to_int(key, 0, &rxq_id) || rxq_id < 0
            || !str_to_int(value, 0, &core_id) || core_id < 0) {
            error = EINVAL;
            break;
        }

        if (rxq_id < n_rxq) {
            core_ids[rxq_id] = core_id;
        }
    }

    free(copy);
    return error;
}

/* Parses 'affinity_list' and applies configuration if it is valid. */
static int
dpif_netdev_port_set_rxq_affinity(struct dp_netdev_port *port,
                                  const char *affinity_list)
{
    unsigned *core_ids, i;
    int error = 0;

    core_ids = xmalloc(port->n_rxq * sizeof *core_ids);
    if (parse_affinity_list(affinity_list, core_ids, port->n_rxq)) {
        error = EINVAL;
        goto exit;
    }

    for (i = 0; i < port->n_rxq; i++) {
        port->rxqs[i].core_id = core_ids[i];
    }

exit:
    free(core_ids);
    return error;
}

/* Changes the affinity of port's rx queues.  The changes are actually applied
 * in dpif_netdev_run(). */
static int
dpif_netdev_port_set_config(struct dpif *dpif, odp_port_t port_no,
                            const struct smap *cfg)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error = 0;
    const char *affinity_list = smap_get(cfg, "pmd-rxq-affinity");

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (error || !netdev_is_pmd(port->netdev)
        || nullable_string_is_equal(affinity_list, port->rxq_affinity_list)) {
        goto unlock;
    }

    error = dpif_netdev_port_set_rxq_affinity(port, affinity_list);
    if (error) {
        goto unlock;
    }
    free(port->rxq_affinity_list);
    port->rxq_affinity_list = nullable_xstrdup(affinity_list);

    dp_netdev_request_reconfigure(dp);
unlock:
    ovs_mutex_unlock(&dp->port_mutex);
    return error;
}

static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
}


/* Creates and returns a new 'struct dp_netdev_actions', whose actions are
 * a copy of the 'size' bytes of 'actions' input parameters. */
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

static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles)
{
   atomic_store_relaxed(&rx->cycles[type], cycles);
}

static void
dp_netdev_rxq_add_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles)
{
    non_atomic_ullong_add(&rx->cycles[type], cycles);
}

static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles[type], &processing_cycles);
    return processing_cycles;
}

static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                                unsigned long long cycles)
{
    unsigned int idx = rx->intrvl_idx++ % PMD_RXQ_INTERVAL_MAX;
    atomic_store_relaxed(&rx->cycles_intrvl[idx], cycles);
}

static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles_intrvl[idx], &processing_cycles);
    return processing_cycles;
}

#if ATOMIC_ALWAYS_LOCK_FREE_8B
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd)
{
    bool pmd_perf_enabled;
    atomic_read_relaxed(&pmd->dp->pmd_perf_metrics, &pmd_perf_enabled);
    return pmd_perf_enabled;
}
#else
/* If stores and reads of 64-bit integers are not atomic, the full PMD
 * performance metrics are not available as locked access to 64 bit
 * integers would be prohibitively expensive. */
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd OVS_UNUSED)
{
    return false;
}
#endif

static int
dp_netdev_pmd_flush_output_on_port(struct dp_netdev_pmd_thread *pmd,
                                   struct tx_port *p)
{
    int i;
    int tx_qid;
    int output_cnt;
    bool dynamic_txqs;
    struct cycle_timer timer;
    uint64_t cycles;
    uint32_t tx_flush_interval;

    cycle_timer_start(&pmd->perf_stats, &timer);

    dynamic_txqs = p->port->dynamic_txqs;
    if (dynamic_txqs) {
        tx_qid = dpif_netdev_xps_get_tx_qid(pmd, p);
    } else {
        tx_qid = pmd->static_tx_qid;
    }

    output_cnt = dp_packet_batch_size(&p->output_pkts);
    ovs_assert(output_cnt > 0);

    netdev_send(p->port->netdev, tx_qid, &p->output_pkts, dynamic_txqs);
    dp_packet_batch_init(&p->output_pkts);

    /* Update time of the next flush. */
    atomic_read_relaxed(&pmd->dp->tx_flush_interval, &tx_flush_interval);
    p->flush_time = pmd->ctx.now + tx_flush_interval;

    ovs_assert(pmd->n_output_batches > 0);
    pmd->n_output_batches--;

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_PKTS, output_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_BATCHES, 1);

    /* Distribute send cycles evenly among transmitted packets and assign to
     * their respective rx queues. */
    cycles = cycle_timer_stop(&pmd->perf_stats, &timer) / output_cnt;
    for (i = 0; i < output_cnt; i++) {
        if (p->output_pkts_rxqs[i]) {
            dp_netdev_rxq_add_cycles(p->output_pkts_rxqs[i],
                                     RXQ_CYCLES_PROC_CURR, cycles);
        }
    }

    return output_cnt;
}

static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force)
{
    struct tx_port *p;
    int output_cnt = 0;

    if (!pmd->n_output_batches) {
        return 0;
    }

    HMAP_FOR_EACH (p, node, &pmd->send_port_cache) {
        if (!dp_packet_batch_is_empty(&p->output_pkts)
            && (force || pmd->ctx.now >= p->flush_time)) {
            output_cnt += dp_netdev_pmd_flush_output_on_port(pmd, p);
        }
    }
    return output_cnt;
}

static int
dp_netdev_process_rxq_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_rxq *rxq,
                           odp_port_t port_no)
{
    struct pmd_perf_stats *s = &pmd->perf_stats;
    struct dp_packet_batch batch;
    struct cycle_timer timer;
    int error;
    int batch_cnt = 0;
    int rem_qlen = 0, *qlen_p = NULL;
    uint64_t cycles;

    /* Measure duration for polling and processing rx burst. */
    cycle_timer_start(&pmd->perf_stats, &timer);

    pmd->ctx.last_rxq = rxq;
    dp_packet_batch_init(&batch);

    /* Fetch the rx queue length only for vhostuser ports. */
    if (pmd_perf_metrics_enabled(pmd) && rxq->is_vhost) {
        qlen_p = &rem_qlen;
    }

    error = netdev_rxq_recv(rxq->rx, &batch, qlen_p);
    if (!error) {
        /* At least one packet received. */
        *recirc_depth_get() = 0;
        pmd_thread_ctx_time_update(pmd);
        batch_cnt = batch.count;
        if (pmd_perf_metrics_enabled(pmd)) {
            /* Update batch histogram. */
            s->current.batches++;
            histogram_add_sample(&s->pkts_per_batch, batch_cnt);
            /* Update the maximum vhost rx queue fill level. */
            if (rxq->is_vhost && rem_qlen >= 0) {
                uint32_t qfill = batch_cnt + rem_qlen;
                if (qfill > s->current.max_vhost_qfill) {
                    s->current.max_vhost_qfill = qfill;
                }
            }
        }
        /* Process packet batch. */
        dp_netdev_input(pmd, &batch, port_no);

        /* Assign processing cycles to rx queue. */
        cycles = cycle_timer_stop(&pmd->perf_stats, &timer);
        dp_netdev_rxq_add_cycles(rxq, RXQ_CYCLES_PROC_CURR, cycles);

        dp_netdev_pmd_flush_output_packets(pmd, false);
    } else {
        /* Discard cycles. */
        cycle_timer_stop(&pmd->perf_stats, &timer);
        if (error != EAGAIN && error != EOPNOTSUPP) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                    netdev_rxq_get_name(rxq->rx), ovs_strerror(error));
        }
    }

    pmd->ctx.last_rxq = NULL;

    return batch_cnt;
}

static struct tx_port *
tx_port_lookup(const struct hmap *hmap, odp_port_t port_no)
{
    struct tx_port *tx;

    HMAP_FOR_EACH_IN_BUCKET (tx, node, hash_port_no(port_no), hmap) {
        if (tx->port->port_no == port_no) {
            return tx;
        }
    }

    return NULL;
}

static int
port_reconfigure(struct dp_netdev_port *port)
{
    struct netdev *netdev = port->netdev;
    int i, err;

    /* Closes the existing 'rxq's. */
    for (i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
        port->rxqs[i].rx = NULL;
    }
    unsigned last_nrxq = port->n_rxq;
    port->n_rxq = 0;

    /* Allows 'netdev' to apply the pending configuration changes. */
    if (netdev_is_reconf_required(netdev) || port->need_reconfigure) {
        err = netdev_reconfigure(netdev);
        if (err && (err != EOPNOTSUPP)) {
            VLOG_ERR("Failed to set interface %s new configuration",
                     netdev_get_name(netdev));
            return err;
        }
    }
    /* If the netdev_reconfigure() above succeeds, reopens the 'rxq's. */
    port->rxqs = xrealloc(port->rxqs,
                          sizeof *port->rxqs * netdev_n_rxq(netdev));
    /* Realloc 'used' counters for tx queues. */
    free(port->txq_used);
    port->txq_used = xcalloc(netdev_n_txq(netdev), sizeof *port->txq_used);

    for (i = 0; i < netdev_n_rxq(netdev); i++) {
        bool new_queue = i >= last_nrxq;
        if (new_queue) {
            memset(&port->rxqs[i], 0, sizeof port->rxqs[i]);
        }

        port->rxqs[i].port = port;
        port->rxqs[i].is_vhost = !strncmp(port->type, "dpdkvhost", 9);

        err = netdev_rxq_open(netdev, &port->rxqs[i].rx, i);
        if (err) {
            return err;
        }
        port->n_rxq++;
    }

    /* Parse affinity list to apply configuration for new queues. */
    dpif_netdev_port_set_rxq_affinity(port, port->rxq_affinity_list);

    /* If reconfiguration was successful mark it as such, so we can use it */
    port->need_reconfigure = false;

    return 0;
}

struct rr_numa_list {
    struct hmap numas;  /* Contains 'struct rr_numa' */
};

struct rr_numa {
    struct hmap_node node;

    int numa_id;

    /* Non isolated pmds on numa node 'numa_id' */
    struct dp_netdev_pmd_thread **pmds;
    int n_pmds;

    int cur_index;
    bool idx_inc;
};

static struct rr_numa *
rr_numa_list_lookup(struct rr_numa_list *rr, int numa_id)
{
    struct rr_numa *numa;

    HMAP_FOR_EACH_WITH_HASH (numa, node, hash_int(numa_id, 0), &rr->numas) {
        if (numa->numa_id == numa_id) {
            return numa;
        }
    }

    return NULL;
}

/* Returns the next node in numa list following 'numa' in round-robin fashion.
 * Returns first node if 'numa' is a null pointer or the last node in 'rr'.
 * Returns NULL if 'rr' numa list is empty. */
static struct rr_numa *
rr_numa_list_next(struct rr_numa_list *rr, const struct rr_numa *numa)
{
    struct hmap_node *node = NULL;

    if (numa) {
        node = hmap_next(&rr->numas, &numa->node);
    }
    if (!node) {
        node = hmap_first(&rr->numas);
    }

    return (node) ? CONTAINER_OF(node, struct rr_numa, node) : NULL;
}

static void
rr_numa_list_populate(struct dp_netdev *dp, struct rr_numa_list *rr)
{
    struct dp_netdev_pmd_thread *pmd;
    struct rr_numa *numa;

    hmap_init(&rr->numas);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

        numa = rr_numa_list_lookup(rr, pmd->numa_id);
        if (!numa) {
            numa = xzalloc(sizeof *numa);
            numa->numa_id = pmd->numa_id;
            hmap_insert(&rr->numas, &numa->node, hash_int(pmd->numa_id, 0));
        }
        numa->n_pmds++;
        numa->pmds = xrealloc(numa->pmds, numa->n_pmds * sizeof *numa->pmds);
        numa->pmds[numa->n_pmds - 1] = pmd;
        /* At least one pmd so initialise curr_idx and idx_inc. */
        numa->cur_index = 0;
        numa->idx_inc = true;
    }
}

/* Returns the next pmd from the numa node in
 * incrementing or decrementing order. */
static struct dp_netdev_pmd_thread *
rr_numa_get_pmd(struct rr_numa *numa)
{
    int numa_idx = numa->cur_index;

    if (numa->idx_inc == true) {
        /* Incrementing through list of pmds. */
        if (numa->cur_index == numa->n_pmds-1) {
            /* Reached the last pmd. */
            numa->idx_inc = false;
        } else {
            numa->cur_index++;
        }
    } else {
        /* Decrementing through list of pmds. */
        if (numa->cur_index == 0) {
            /* Reached the first pmd. */
            numa->idx_inc = true;
        } else {
            numa->cur_index--;
        }
    }
    return numa->pmds[numa_idx];
}

static void
rr_numa_list_destroy(struct rr_numa_list *rr)
{
    struct rr_numa *numa;

    HMAP_FOR_EACH_POP (numa, node, &rr->numas) {
        free(numa->pmds);
        free(numa);
    }
    hmap_destroy(&rr->numas);
}

/* Sort Rx Queues by the processing cycles they are consuming. */
static int
compare_rxq_cycles(const void *a, const void *b)
{
    struct dp_netdev_rxq *qa;
    struct dp_netdev_rxq *qb;
    uint64_t cycles_qa, cycles_qb;

    qa = *(struct dp_netdev_rxq **) a;
    qb = *(struct dp_netdev_rxq **) b;

    cycles_qa = dp_netdev_rxq_get_cycles(qa, RXQ_CYCLES_PROC_HIST);
    cycles_qb = dp_netdev_rxq_get_cycles(qb, RXQ_CYCLES_PROC_HIST);

    if (cycles_qa != cycles_qb) {
        return (cycles_qa < cycles_qb) ? 1 : -1;
    } else {
        /* Cycles are the same so tiebreak on port/queue id.
         * Tiebreaking (as opposed to return 0) ensures consistent
         * sort results across multiple OS's. */
        uint32_t port_qa = odp_to_u32(qa->port->port_no);
        uint32_t port_qb = odp_to_u32(qb->port->port_no);
        if (port_qa != port_qb) {
            return port_qa > port_qb ? 1 : -1;
        } else {
            return netdev_rxq_get_queue_id(qa->rx)
                    - netdev_rxq_get_queue_id(qb->rx);
        }
    }
}

/* Assign pmds to queues.  If 'pinned' is true, assign pmds to pinned
 * queues and marks the pmds as isolated.  Otherwise, assign non isolated
 * pmds to unpinned queues.
 *
 * If 'pinned' is false queues will be sorted by processing cycles they are
 * consuming and then assigned to pmds in round robin order.
 *
 * The function doesn't touch the pmd threads, it just stores the assignment
 * in the 'pmd' member of each rxq. */
static void
rxq_scheduling(struct dp_netdev *dp, bool pinned) OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;
    struct rr_numa_list rr;
    struct rr_numa *non_local_numa = NULL;
    struct dp_netdev_rxq ** rxqs = NULL;
    int n_rxqs = 0;
    struct rr_numa *numa = NULL;
    int numa_id;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (pinned && q->core_id != OVS_CORE_UNSPEC) {
                struct dp_netdev_pmd_thread *pmd;

                pmd = dp_netdev_get_pmd(dp, q->core_id);
                if (!pmd) {
                    VLOG_WARN("There is no PMD thread on core %d. Queue "
                              "%d on port \'%s\' will not be polled.",
                              q->core_id, qid, netdev_get_name(port->netdev));
                } else {
                    q->pmd = pmd;
                    pmd->isolated = true;
                    dp_netdev_pmd_unref(pmd);
                }
            } else if (!pinned && q->core_id == OVS_CORE_UNSPEC) {
                uint64_t cycle_hist = 0;

                if (n_rxqs == 0) {
                    rxqs = xmalloc(sizeof *rxqs);
                } else {
                    rxqs = xrealloc(rxqs, sizeof *rxqs * (n_rxqs + 1));
                }
                /* Sum the queue intervals and store the cycle history. */
                for (unsigned i = 0; i < PMD_RXQ_INTERVAL_MAX; i++) {
                    cycle_hist += dp_netdev_rxq_get_intrvl_cycles(q, i);
                }
                dp_netdev_rxq_set_cycles(q, RXQ_CYCLES_PROC_HIST, cycle_hist);

                /* Store the queue. */
                rxqs[n_rxqs++] = q;
            }
        }
    }

    if (n_rxqs > 1) {
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }

    rr_numa_list_populate(dp, &rr);
    /* Assign the sorted queues to pmds in round robin. */
    for (int i = 0; i < n_rxqs; i++) {
        numa_id = netdev_get_numa_id(rxqs[i]->port->netdev);
        numa = rr_numa_list_lookup(&rr, numa_id);
        if (!numa) {
            /* There are no pmds on the queue's local NUMA node.
               Round robin on the NUMA nodes that do have pmds. */
            non_local_numa = rr_numa_list_next(&rr, non_local_numa);
            if (!non_local_numa) {
                VLOG_ERR("There is no available (non-isolated) pmd "
                         "thread for port \'%s\' queue %d. This queue "
                         "will not be polled. Is pmd-cpu-mask set to "
                         "zero? Or are all PMDs isolated to other "
                         "queues?", netdev_rxq_get_name(rxqs[i]->rx),
                         netdev_rxq_get_queue_id(rxqs[i]->rx));
                continue;
            }
            rxqs[i]->pmd = rr_numa_get_pmd(non_local_numa);
            VLOG_WARN("There's no available (non-isolated) pmd thread "
                      "on numa node %d. Queue %d on port \'%s\' will "
                      "be assigned to the pmd on core %d "
                      "(numa node %d). Expect reduced performance.",
                      numa_id, netdev_rxq_get_queue_id(rxqs[i]->rx),
                      netdev_rxq_get_name(rxqs[i]->rx),
                      rxqs[i]->pmd->core_id, rxqs[i]->pmd->numa_id);
        } else {
        rxqs[i]->pmd = rr_numa_get_pmd(numa);
        VLOG_INFO("Core %d on numa node %d assigned port \'%s\' "
                  "rx queue %d (measured processing cycles %"PRIu64").",
                  rxqs[i]->pmd->core_id, numa_id,
                  netdev_rxq_get_name(rxqs[i]->rx),
                  netdev_rxq_get_queue_id(rxqs[i]->rx),
                  dp_netdev_rxq_get_cycles(rxqs[i], RXQ_CYCLES_PROC_HIST));
        }
    }

    rr_numa_list_destroy(&rr);
    free(rxqs);
}

static void
reload_affected_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            dp_netdev_reload_pmd__(pmd);
            pmd->need_reload = false;
        }
    }
}

static void
reconfigure_pmd_threads(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *pmd;
    struct ovs_numa_dump *pmd_cores;
    struct ovs_numa_info_core *core;
    struct hmapx to_delete = HMAPX_INITIALIZER(&to_delete);
    struct hmapx_node *node;
    bool changed = false;
    bool need_to_adjust_static_tx_qids = false;

    /* The pmd threads should be started only if there's a pmd port in the
     * datapath.  If the user didn't provide any "pmd-cpu-mask", we start
     * NR_PMD_THREADS per numa node. */
    if (!has_pmd_port(dp)) {
        pmd_cores = ovs_numa_dump_n_cores_per_numa(0);
    } else if (dp->pmd_cmask && dp->pmd_cmask[0]) {
        pmd_cores = ovs_numa_dump_cores_with_cmask(dp->pmd_cmask);
    } else {
        pmd_cores = ovs_numa_dump_n_cores_per_numa(NR_PMD_THREADS);
    }

    /* We need to adjust 'static_tx_qid's only if we're reducing number of
     * PMD threads. Otherwise, new threads will allocate all the freed ids. */
    if (ovs_numa_dump_count(pmd_cores) < cmap_count(&dp->poll_threads) - 1) {
        /* Adjustment is required to keep 'static_tx_qid's sequential and
         * avoid possible issues, for example, imbalanced tx queue usage
         * and unnecessary locking caused by remapping on netdev level. */
        need_to_adjust_static_tx_qids = true;
    }

    /* Check for unwanted pmd threads */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        if (!ovs_numa_dump_contains_core(pmd_cores, pmd->numa_id,
                                                    pmd->core_id)) {
            hmapx_add(&to_delete, pmd);
        } else if (need_to_adjust_static_tx_qids) {
            pmd->need_reload = true;
        }
    }

    HMAPX_FOR_EACH (node, &to_delete) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        VLOG_INFO("PMD thread on numa_id: %d, core id: %2d destroyed.",
                  pmd->numa_id, pmd->core_id);
        dp_netdev_del_pmd(dp, pmd);
    }
    changed = !hmapx_is_empty(&to_delete);
    hmapx_destroy(&to_delete);

    if (need_to_adjust_static_tx_qids) {
        /* 'static_tx_qid's are not sequential now.
         * Reload remaining threads to fix this. */
        reload_affected_pmds(dp);
    }

    /* Check for required new pmd threads */
    FOR_EACH_CORE_ON_DUMP(core, pmd_cores) {
        pmd = dp_netdev_get_pmd(dp, core->core_id);
        if (!pmd) {
            pmd = xzalloc(sizeof *pmd);
            dp_netdev_configure_pmd(pmd, dp, core->core_id, core->numa_id);
            pmd->thread = ovs_thread_create("pmd", pmd_thread_main, pmd);
            VLOG_INFO("PMD thread on numa_id: %d, core id: %2d created.",
                      pmd->numa_id, pmd->core_id);
            changed = true;
        } else {
            dp_netdev_pmd_unref(pmd);
        }
    }

    if (changed) {
        struct ovs_numa_info_numa *numa;

        /* Log the number of pmd threads per numa node. */
        FOR_EACH_NUMA_ON_DUMP (numa, pmd_cores) {
            VLOG_INFO("There are %"PRIuSIZE" pmd threads on numa node %d",
                      numa->n_cores, numa->numa_id);
        }
    }

    ovs_numa_dump_destroy(pmd_cores);
}

static void
pmd_remove_stale_ports(struct dp_netdev *dp,
                       struct dp_netdev_pmd_thread *pmd)
    OVS_EXCLUDED(pmd->port_mutex)
    OVS_REQUIRES(dp->port_mutex)
{
    struct rxq_poll *poll, *poll_next;
    struct tx_port *tx, *tx_next;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) {
        struct dp_netdev_port *port = poll->rxq->port;

        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_rxq_from_pmd(pmd, poll);
        }
    }
    HMAP_FOR_EACH_SAFE (tx, tx_next, node, &pmd->tx_ports) {
        struct dp_netdev_port *port = tx->port;

        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_port_tx_from_pmd(pmd, tx);
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
}

/* Must be called each time a port is added/removed or the cmask changes.
 * This creates and destroys pmd threads, reconfigures ports, opens their
 * rxqs and assigns all rxqs/txqs to pmd threads. */
static void
reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_port *port;
    int wanted_txqs;

    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    /* Step 1: Adjust the pmd threads based on the datapath ports, the cores
     * on the system and the user configuration. */
    reconfigure_pmd_threads(dp);

    wanted_txqs = cmap_count(&dp->poll_threads);

    /* The number of pmd threads might have changed, or a port can be new:
     * adjust the txqs. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_set_tx_multiq(port->netdev, wanted_txqs);
    }

    /* Step 2: Remove from the pmd threads ports that have been removed or
     * need reconfiguration. */

    /* Check for all the ports that need reconfiguration.  We cache this in
     * 'port->need_reconfigure', because netdev_is_reconf_required() can
     * change at any time. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)) {
            port->need_reconfigure = true;
        }
    }

    /* Remove from the pmd threads all the ports that have been deleted or
     * need reconfiguration. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        pmd_remove_stale_ports(dp, pmd);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads before
     * reconfiguring the ports, because a port cannot be reconfigured while
     * it's being used. */
    reload_affected_pmds(dp);

    /* Step 3: Reconfigure ports. */

    /* We only reconfigure the ports that we determined above, because they're
     * not being used by any pmd thread at the moment.  If a port fails to
     * reconfigure we remove it from the datapath. */
    struct dp_netdev_port *next_port;
    HMAP_FOR_EACH_SAFE (port, next_port, node, &dp->ports) {
        int err;

        if (!port->need_reconfigure) {
            continue;
        }

        err = port_reconfigure(port);
        if (err) {
            hmap_remove(&dp->ports, &port->node);
            seq_change(dp->port_seq);
            port_destroy(port);
        } else {
            port->dynamic_txqs = netdev_n_txq(port->netdev) < wanted_txqs;
        }
    }

    /* Step 4: Compute new rxq scheduling.  We don't touch the pmd threads
     * for now, we just update the 'pmd' pointer in each rxq to point to the
     * wanted thread according to the scheduling policy. */

    /* Reset all the pmd threads to non isolated. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        pmd->isolated = false;
    }

    /* Reset all the queues to unassigned */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        for (int i = 0; i < port->n_rxq; i++) {
            port->rxqs[i].pmd = NULL;
        }
    }

    /* Add pinned queues and mark pmd threads isolated. */
    rxq_scheduling(dp, true);

    /* Add non-pinned queues. */
    rxq_scheduling(dp, false);

    /* Step 5: Remove queues not compliant with new scheduling. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct rxq_poll *poll, *poll_next;

        ovs_mutex_lock(&pmd->port_mutex);
        HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) {
            if (poll->rxq->pmd != pmd) {
                dp_netdev_del_rxq_from_pmd(pmd, poll);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads to remove
     * the old queues before readding them, otherwise a queue can be polled by
     * two threads at the same time. */
    reload_affected_pmds(dp);

    /* Step 6: Add queues from scheduling, if they're not there already. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (q->pmd) {
                ovs_mutex_lock(&q->pmd->port_mutex);
                dp_netdev_add_rxq_to_pmd(q->pmd, q);
                ovs_mutex_unlock(&q->pmd->port_mutex);
            }
        }
    }

    /* Add every port to the tx cache of every pmd thread, if it's not
     * there already and if this pmd has at least one rxq to poll. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        ovs_mutex_lock(&pmd->port_mutex);
        if (hmap_count(&pmd->poll_list) || pmd->core_id == NON_PMD_CORE_ID) {
            HMAP_FOR_EACH (port, node, &dp->ports) {
                dp_netdev_add_port_tx_to_pmd(pmd, port);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads. */
    reload_affected_pmds(dp);
}

/* Returns true if one of the netdevs in 'dp' requires a reconfiguration */
static bool
ports_require_restart(const struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)) {
            return true;
        }
    }

    return false;
}

/* Return true if needs to revalidate datapath flows. */
static bool
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *non_pmd;
    uint64_t new_tnl_seq;
    bool need_to_flush = true;

    ovs_mutex_lock(&dp->port_mutex);
    non_pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
    if (non_pmd) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
        HMAP_FOR_EACH (port, node, &dp->ports) {
            if (!netdev_is_pmd(port->netdev)) {
                int i;

                for (i = 0; i < port->n_rxq; i++) {
                    if (dp_netdev_process_rxq_port(non_pmd,
                                                   &port->rxqs[i],
                                                   port->port_no)) {
                        need_to_flush = false;
                    }
                }
            }
        }
        if (need_to_flush) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(non_pmd);
            dp_netdev_pmd_flush_output_packets(non_pmd, false);
        }

        dpif_netdev_xps_revalidate_pmd(non_pmd, false);
        ovs_mutex_unlock(&dp->non_pmd_mutex);

        dp_netdev_pmd_unref(non_pmd);
    }

    if (dp_netdev_is_reconf_required(dp) || ports_require_restart(dp)) {
        reconfigure_datapath(dp);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    tnl_neigh_cache_run();
    tnl_port_map_run();
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
    ovs_mutex_lock(&dp->port_mutex);
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_wait_reconf_required(port->netdev);
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < port->n_rxq; i++) {
                netdev_rxq_wait(port->rxqs[i].rx);
            }
        }
    }
    ovs_mutex_unlock(&dp->port_mutex);
    ovs_mutex_unlock(&dp_netdev_mutex);
    seq_wait(tnl_conf_seq, dp->last_tnl_conf_seq);
}

static void
pmd_free_cached_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct tx_port *tx_port_cached;

    /* Flush all the queued packets. */
    dp_netdev_pmd_flush_output_packets(pmd, true);
    /* Free all used tx queue ids. */
    dpif_netdev_xps_revalidate_pmd(pmd, true);

    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->tnl_port_cache) {
        free(tx_port_cached);
    }
    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->send_port_cache) {
        free(tx_port_cached);
    }
}

/* Copies ports from 'pmd->tx_ports' (shared with the main thread) to
 * thread-local copies. Copy to 'pmd->tnl_port_cache' if it is a tunnel
 * device, otherwise to 'pmd->send_port_cache' if the port has at least
 * one txq. */
static void
pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx_port, *tx_port_cached;

    pmd_free_cached_ports(pmd);
    hmap_shrink(&pmd->send_port_cache);
    hmap_shrink(&pmd->tnl_port_cache);

    HMAP_FOR_EACH (tx_port, node, &pmd->tx_ports) {
        if (netdev_has_tunnel_push_pop(tx_port->port->netdev)) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            hmap_insert(&pmd->tnl_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }

        if (netdev_n_txq(tx_port->port->netdev)) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            hmap_insert(&pmd->send_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }
    }
}

static void
pmd_alloc_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);
    if (!id_pool_alloc_id(pmd->dp->tx_qid_pool, &pmd->static_tx_qid)) {
        VLOG_ABORT("static_tx_qid allocation failed for PMD on core %2d"
                   ", numa_id %d.", pmd->core_id, pmd->numa_id);
    }
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);

    VLOG_DBG("static_tx_qid = %d allocated for PMD thread on core %2d"
             ", numa_id %d.", pmd->static_tx_qid, pmd->core_id, pmd->numa_id);
}

static void
pmd_free_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);
    id_pool_free_id(pmd->dp->tx_qid_pool, pmd->static_tx_qid);
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);
}

static int
pmd_load_queues_and_ports(struct dp_netdev_pmd_thread *pmd,
                          struct polled_queue **ppoll_list)
{
    struct polled_queue *poll_list = *ppoll_list;
    struct rxq_poll *poll;
    int i;

    ovs_mutex_lock(&pmd->port_mutex);
    poll_list = xrealloc(poll_list, hmap_count(&pmd->poll_list)
                                    * sizeof *poll_list);

    i = 0;
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
        poll_list[i].rxq = poll->rxq;
        poll_list[i].port_no = poll->rxq->port->port_no;
        i++;
    }

    pmd_load_cached_ports(pmd);

    ovs_mutex_unlock(&pmd->port_mutex);

    *ppoll_list = poll_list;
    return i;
}

static void *
pmd_thread_main(void *f_)
{
    struct dp_netdev_pmd_thread *pmd = f_;
    struct pmd_perf_stats *s = &pmd->perf_stats;
    unsigned int lc = 0;
    struct polled_queue *poll_list;
    bool exiting;
    int poll_cnt;
    int i;
    int process_packets = 0;

    poll_list = NULL;

    /* Stores the pmd thread's 'pmd' to 'per_pmd_key'. */
    ovsthread_setspecific(pmd->dp->per_pmd_key, pmd);
    ovs_numa_thread_setaffinity_core(pmd->core_id);
    dpdk_set_lcore_id(pmd->core_id);
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    emc_cache_init(&pmd->flow_cache);
reload:
    pmd_alloc_static_tx_qid(pmd);

    /* List port/core affinity */
    for (i = 0; i < poll_cnt; i++) {
       VLOG_DBG("Core %d processing port \'%s\' with queue-id %d\n",
                pmd->core_id, netdev_rxq_get_name(poll_list[i].rxq->rx),
                netdev_rxq_get_queue_id(poll_list[i].rxq->rx));
       /* Reset the rxq current cycles counter. */
       dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR, 0);
    }

    if (!poll_cnt) {
        while (seq_read(pmd->reload_seq) == pmd->last_reload_seq) {
            seq_wait(pmd->reload_seq, pmd->last_reload_seq);
            poll_block();
        }
        lc = UINT_MAX;
    }

    pmd->intrvl_tsc_prev = 0;
    atomic_store_relaxed(&pmd->intrvl_cycles, 0);
    cycles_counter_update(s);
    /* Protect pmd stats from external clearing while polling. */
    ovs_mutex_lock(&pmd->perf_stats.stats_mutex);
    for (;;) {
        uint64_t rx_packets = 0, tx_packets = 0;

        pmd_perf_start_iteration(s);

        for (i = 0; i < poll_cnt; i++) {
            process_packets =
                dp_netdev_process_rxq_port(pmd, poll_list[i].rxq,
                                           poll_list[i].port_no);
            rx_packets += process_packets;
        }

        if (!rx_packets) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(pmd);
            tx_packets = dp_netdev_pmd_flush_output_packets(pmd, false);
        }

        if (lc++ > 1024) {
            bool reload;

            lc = 0;

            coverage_try_clear();
            dp_netdev_pmd_try_optimize(pmd, poll_list, poll_cnt);
            if (!ovsrcu_try_quiesce()) {
                emc_cache_slow_sweep(&pmd->flow_cache);
            }

            atomic_read_relaxed(&pmd->reload, &reload);
            if (reload) {
                break;
            }
        }
        pmd_perf_end_iteration(s, rx_packets, tx_packets,
                               pmd_perf_metrics_enabled(pmd));
    }
    ovs_mutex_unlock(&pmd->perf_stats.stats_mutex);

    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    exiting = latch_is_set(&pmd->exit_latch);
    /* Signal here to make sure the pmd finishes
     * reloading the updated configuration. */
    dp_netdev_pmd_reload_done(pmd);

    pmd_free_static_tx_qid(pmd);

    if (!exiting) {
        goto reload;
    }

    emc_cache_uninit(&pmd->flow_cache);
    free(poll_list);
    pmd_free_cached_ports(pmd);
    return NULL;
}

static void
dp_netdev_disable_upcall(struct dp_netdev *dp)
    OVS_ACQUIRES(dp->upcall_rwlock)
{
    fat_rwlock_wrlock(&dp->upcall_rwlock);
}


/* Meters */
static void
dpif_netdev_meter_get_features(const struct dpif * dpif OVS_UNUSED,
                               struct ofputil_meter_features *features)
{
    features->max_meters = MAX_METERS;
    features->band_types = DP_SUPPORTED_METER_BAND_TYPES;
    features->capabilities = DP_SUPPORTED_METER_FLAGS_MASK;
    features->max_bands = MAX_BANDS;
    features->max_color = 0;
}

/* Returns false when packet needs to be dropped. */
static void
dp_netdev_run_meter(struct dp_netdev *dp, struct dp_packet_batch *packets_,
                    uint32_t meter_id, long long int now)
{
    struct dp_meter *meter;
    struct dp_meter_band *band;
    struct dp_packet *packet;
    long long int long_delta_t; /* msec */
    uint32_t delta_t; /* msec */
    const size_t cnt = dp_packet_batch_size(packets_);
    uint32_t bytes, volume;
    int exceeded_band[NETDEV_MAX_BURST];
    uint32_t exceeded_rate[NETDEV_MAX_BURST];
    int exceeded_pkt = cnt; /* First packet that exceeded a band rate. */

    if (meter_id >= MAX_METERS) {
        return;
    }

    meter_lock(dp, meter_id);
    meter = dp->meters[meter_id];
    if (!meter) {
        goto out;
    }

    /* Initialize as negative values. */
    memset(exceeded_band, 0xff, cnt * sizeof *exceeded_band);
    /* Initialize as zeroes. */
    memset(exceeded_rate, 0, cnt * sizeof *exceeded_rate);

    /* All packets will hit the meter at the same time. */
    long_delta_t = (now - meter->used) / 1000; /* msec */

    /* Make sure delta_t will not be too large, so that bucket will not
     * wrap around below. */
    delta_t = (long_delta_t > (long long int)meter->max_delta_t)
        ? meter->max_delta_t : (uint32_t)long_delta_t;

    /* Update meter stats. */
    meter->used = now;
    meter->packet_count += cnt;
    bytes = 0;
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        bytes += dp_packet_size(packet);
    }
    meter->byte_count += bytes;

    /* Meters can operate in terms of packets per second or kilobits per
     * second. */
    if (meter->flags & OFPMF13_PKTPS) {
        /* Rate in packets/second, bucket 1/1000 packets. */
        /* msec * packets/sec = 1/1000 packets. */
        volume = cnt * 1000; /* Take 'cnt' packets from the bucket. */
    } else {
        /* Rate in kbps, bucket in bits. */
        /* msec * kbps = bits */
        volume = bytes * 8;
    }

    /* Update all bands and find the one hit with the highest rate for each
     * packet (if any). */
    for (int m = 0; m < meter->n_bands; ++m) {
        band = &meter->bands[m];

        /* Update band's bucket. */
        band->bucket += delta_t * band->up.rate;
        if (band->bucket > band->up.burst_size) {
            band->bucket = band->up.burst_size;
        }

        /* Drain the bucket for all the packets, if possible. */
        if (band->bucket >= volume) {
            band->bucket -= volume;
        } else {
            int band_exceeded_pkt;

            /* Band limit hit, must process packet-by-packet. */
            if (meter->flags & OFPMF13_PKTPS) {
                band_exceeded_pkt = band->bucket / 1000;
                band->bucket %= 1000; /* Remainder stays in bucket. */

                /* Update the exceeding band for each exceeding packet.
                 * (Only one band will be fired by a packet, and that
                 * can be different for each packet.) */
                for (int i = band_exceeded_pkt; i < cnt; i++) {
                    if (band->up.rate > exceeded_rate[i]) {
                        exceeded_rate[i] = band->up.rate;
                        exceeded_band[i] = m;
                    }
                }
            } else {
                /* Packet sizes differ, must process one-by-one. */
                band_exceeded_pkt = cnt;
                DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                    uint32_t bits = dp_packet_size(packet) * 8;

                    if (band->bucket >= bits) {
                        band->bucket -= bits;
                    } else {
                        if (i < band_exceeded_pkt) {
                            band_exceeded_pkt = i;
                        }
                        /* Update the exceeding band for the exceeding packet.
                         * (Only one band will be fired by a packet, and that
                         * can be different for each packet.) */
                        if (band->up.rate > exceeded_rate[i]) {
                            exceeded_rate[i] = band->up.rate;
                            exceeded_band[i] = m;
                        }
                    }
                }
            }
            /* Remember the first exceeding packet. */
            if (exceeded_pkt > band_exceeded_pkt) {
                exceeded_pkt = band_exceeded_pkt;
            }
        }
    }

    /* Fire the highest rate band exceeded by each packet.
     * Drop packets if needed, by swapping packet to the end that will be
     * ignored. */
    size_t j;
    DP_PACKET_BATCH_REFILL_FOR_EACH (j, cnt, packet, packets_) {
        if (exceeded_band[j] >= 0) {
            /* Meter drop packet. */
            band = &meter->bands[exceeded_band[j]];
            band->packet_count += 1;
            band->byte_count += dp_packet_size(packet);

            dp_packet_delete(packet);
        } else {
            /* Meter accepts packet. */
            dp_packet_batch_refill(packets_, packet, j);
        }
    }
 out:
    meter_unlock(dp, meter_id);
}

/* Meter set/get/del processing is still single-threaded. */
static int
dpif_netdev_meter_set(struct dpif *dpif, ofproto_meter_id *meter_id,
                      struct ofputil_meter_config *config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t mid = meter_id->uint32;
    struct dp_meter *meter;
    int i;

    if (mid >= MAX_METERS) {
        return EFBIG; /* Meter_id out of range. */
    }

    if (config->flags & ~DP_SUPPORTED_METER_FLAGS_MASK ||
        !(config->flags & (OFPMF13_KBPS | OFPMF13_PKTPS))) {
        return EBADF; /* Unsupported flags set */
    }

    /* Validate bands */
    if (config->n_bands == 0 || config->n_bands > MAX_BANDS) {
        return EINVAL; /* Too many bands */
    }

    /* Validate rates */
    for (i = 0; i < config->n_bands; i++) {
        if (config->bands[i].rate == 0) {
            return EDOM; /* rate must be non-zero */
        }
    }

    for (i = 0; i < config->n_bands; ++i) {
        switch (config->bands[i].type) {
        case OFPMBT13_DROP:
            break;
        default:
            return ENODEV; /* Unsupported band type */
        }
    }

    /* Allocate meter */
    meter = xzalloc(sizeof *meter
                    + config->n_bands * sizeof(struct dp_meter_band));
    if (meter) {
        meter->flags = config->flags;
        meter->n_bands = config->n_bands;
        meter->max_delta_t = 0;
        meter->used = time_usec();

        /* set up bands */
        for (i = 0; i < config->n_bands; ++i) {
            uint32_t band_max_delta_t;

            /* Set burst size to a workable value if none specified. */
            if (config->bands[i].burst_size == 0) {
                config->bands[i].burst_size = config->bands[i].rate;
            }

            meter->bands[i].up = config->bands[i];
            /* Convert burst size to the bucket units: */
            /* pkts => 1/1000 packets, kilobits => bits. */
            meter->bands[i].up.burst_size *= 1000;
            /* Initialize bucket to empty. */
            meter->bands[i].bucket = 0;

            /* Figure out max delta_t that is enough to fill any bucket. */
            band_max_delta_t
                = meter->bands[i].up.burst_size / meter->bands[i].up.rate;
            if (band_max_delta_t > meter->max_delta_t) {
                meter->max_delta_t = band_max_delta_t;
            }
        }

        meter_lock(dp, mid);
        dp_delete_meter(dp, mid); /* Free existing meter, if any */
        dp->meters[mid] = meter;
        meter_unlock(dp, mid);

        return 0;
    }
    return ENOMEM;
}

static int
dpif_netdev_meter_get(const struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    const struct dp_netdev *dp = get_dp_netdev(dpif);
    const struct dp_meter *meter;
    uint32_t meter_id = meter_id_.uint32;

    if (meter_id >= MAX_METERS) {
        return EFBIG;
    }
    meter = dp->meters[meter_id];
    if (!meter) {
        return ENOENT;
    }
    if (stats) {
        int i = 0;

        meter_lock(dp, meter_id);
        stats->packet_in_count = meter->packet_count;
        stats->byte_in_count = meter->byte_count;

        for (i = 0; i < n_bands && i < meter->n_bands; ++i) {
            stats->bands[i].packet_count = meter->bands[i].packet_count;
            stats->bands[i].byte_count = meter->bands[i].byte_count;
        }
        meter_unlock(dp, meter_id);

        stats->n_bands = i;
    }
    return 0;
}

static int
dpif_netdev_meter_del(struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    error = dpif_netdev_meter_get(dpif, meter_id_, stats, n_bands);
    if (!error) {
        uint32_t meter_id = meter_id_.uint32;

        meter_lock(dp, meter_id);
        dp_delete_meter(dp, meter_id);
        meter_unlock(dp, meter_id);
    }
    return error;
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
dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->cond_mutex);
    atomic_store_relaxed(&pmd->reload, false);
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    xpthread_cond_signal(&pmd->cond);
    ovs_mutex_unlock(&pmd->cond_mutex);
}

/* Finds and refs the dp_netdev_pmd_thread on core 'core_id'.  Returns
 * the pointer if succeeds, otherwise, NULL (it can return NULL even if
 * 'core_id' is NON_PMD_CORE_ID).
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
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *non_pmd;

    non_pmd = xzalloc(sizeof *non_pmd);
    dp_netdev_configure_pmd(non_pmd, dp, NON_PMD_CORE_ID, OVS_NUMA_UNSPEC);
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

/* Configures the 'pmd' based on the input argument. */
static void
dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev *dp,
                        unsigned core_id, int numa_id)
{
    pmd->dp = dp;
    pmd->core_id = core_id;
    pmd->numa_id = numa_id;
    pmd->need_reload = false;
    pmd->n_output_batches = 0;

    ovs_refcount_init(&pmd->ref_cnt);
    latch_init(&pmd->exit_latch);
    pmd->reload_seq = seq_create();
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_init(&pmd->reload, false);
    xpthread_cond_init(&pmd->cond, NULL);
    ovs_mutex_init(&pmd->cond_mutex);
    ovs_mutex_init(&pmd->flow_mutex);
    ovs_mutex_init(&pmd->port_mutex);
    cmap_init(&pmd->flow_table);
    cmap_init(&pmd->classifiers);
    pmd->ctx.last_rxq = NULL;
    pmd_thread_ctx_time_update(pmd);
    pmd->next_optimization = pmd->ctx.now + DPCLS_OPTIMIZATION_INTERVAL;
    pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;
    hmap_init(&pmd->poll_list);
    hmap_init(&pmd->tx_ports);
    hmap_init(&pmd->tnl_port_cache);
    hmap_init(&pmd->send_port_cache);
    /* init the 'flow_cache' since there is no
     * actual thread created for NON_PMD_CORE_ID. */
    if (core_id == NON_PMD_CORE_ID) {
        emc_cache_init(&pmd->flow_cache);
        pmd_alloc_static_tx_qid(pmd);
    }
    pmd_perf_stats_init(&pmd->perf_stats);
    cmap_insert(&dp->poll_threads, CONST_CAST(struct cmap_node *, &pmd->node),
                hash_int(core_id, 0));
}

static void
dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd)
{
    struct dpcls *cls;

    dp_netdev_pmd_flow_flush(pmd);
    hmap_destroy(&pmd->send_port_cache);
    hmap_destroy(&pmd->tnl_port_cache);
    hmap_destroy(&pmd->tx_ports);
    hmap_destroy(&pmd->poll_list);
    /* All flows (including their dpcls_rules) have been deleted already */
    CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
        dpcls_destroy(cls);
        ovsrcu_postpone(free, cls);
    }
    cmap_destroy(&pmd->classifiers);
    cmap_destroy(&pmd->flow_table);
    ovs_mutex_destroy(&pmd->flow_mutex);
    latch_destroy(&pmd->exit_latch);
    seq_destroy(pmd->reload_seq);
    xpthread_cond_destroy(&pmd->cond);
    ovs_mutex_destroy(&pmd->cond_mutex);
    ovs_mutex_destroy(&pmd->port_mutex);
    free(pmd);
}

/* Stops the pmd thread, removes it from the 'dp->poll_threads',
 * and unrefs the struct. */
static void
dp_netdev_del_pmd(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
{
    /* NON_PMD_CORE_ID doesn't have a thread, so we don't have to synchronize,
     * but extra cleanup is necessary */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
        emc_cache_uninit(&pmd->flow_cache);
        pmd_free_cached_ports(pmd);
        pmd_free_static_tx_qid(pmd);
        ovs_mutex_unlock(&dp->non_pmd_mutex);
    } else {
        latch_set(&pmd->exit_latch);
        dp_netdev_reload_pmd__(pmd);
        xpthread_join(pmd->thread, NULL);
    }

    dp_netdev_pmd_clear_ports(pmd);

    /* Purges the 'pmd''s flows after stopping the thread, but before
     * destroying the flows, so that the flow stats can be collected. */
    if (dp->dp_purge_cb) {
        dp->dp_purge_cb(dp->dp_purge_aux, pmd->core_id);
    }
    cmap_remove(&pmd->dp->poll_threads, &pmd->node, hash_int(pmd->core_id, 0));
    dp_netdev_pmd_unref(pmd);
}

/* Destroys all pmd threads. If 'non_pmd' is true it also destroys the non pmd
 * thread. */
static void
dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (!non_pmd && pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        /* We cannot call dp_netdev_del_pmd(), since it alters
         * 'dp->poll_threads' (while we're iterating it) and it
         * might quiesce. */
        ovs_assert(k < n_pmds);
        pmd_list[k++] = pmd;
    }

    for (size_t i = 0; i < k; i++) {
        dp_netdev_del_pmd(dp, pmd_list[i]);
    }
    free(pmd_list);
}

/* Deletes all rx queues from pmd->poll_list and all the ports from
 * pmd->tx_ports. */
static void
dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct rxq_poll *poll;
    struct tx_port *port;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_POP (poll, node, &pmd->poll_list) {
        free(poll);
    }
    HMAP_FOR_EACH_POP (port, node, &pmd->tx_ports) {
        free(port);
    }
    ovs_mutex_unlock(&pmd->port_mutex);
}

/* Adds rx queue to poll_list of PMD thread, if it's not there already. */
static void
dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                         struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex)
{
    int qid = netdev_rxq_get_queue_id(rxq->rx);
    uint32_t hash = hash_2words(odp_to_u32(rxq->port->port_no), qid);
    struct rxq_poll *poll;

    HMAP_FOR_EACH_WITH_HASH (poll, node, hash, &pmd->poll_list) {
        if (poll->rxq == rxq) {
            /* 'rxq' is already polled by this thread. Do nothing. */
            return;
        }
    }

    poll = xmalloc(sizeof *poll);
    poll->rxq = rxq;
    hmap_insert(&pmd->poll_list, &poll->node, hash);

    pmd->need_reload = true;
}

/* Delete 'poll' from poll_list of PMD thread. */
static void
dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                           struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex)
{
    hmap_remove(&pmd->poll_list, &poll->node);
    free(poll);

    pmd->need_reload = true;
}

/* Add 'port' to the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                             struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx;

    tx = tx_port_lookup(&pmd->tx_ports, port->port_no);
    if (tx) {
        /* 'port' is already on this thread tx cache. Do nothing. */
        return;
    }

    tx = xzalloc(sizeof *tx);

    tx->port = port;
    tx->qid = -1;
    tx->flush_time = 0LL;
    dp_packet_batch_init(&tx->output_pkts);

    hmap_insert(&pmd->tx_ports, &tx->node, hash_port_no(tx->port->port_no));
    pmd->need_reload = true;
}

/* Del 'tx' from the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                               struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex)
{
    hmap_remove(&pmd->tx_ports, &tx->node);
    free(tx);
    pmd->need_reload = true;
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
        struct odp_flow_key_parms odp_parms = {
            .flow = flow,
            .mask = wc ? &wc->masks : NULL,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key, 0);
        odp_flow_key_from_flow(&odp_parms, &key);
        packet_str = ofp_dp_packet_to_string(packet_);

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
dpif_netdev_packet_get_rss_hash_orig_pkt(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
        hash = dp_packet_get_rss_hash(packet);
    } else {
        hash = miniflow_hash_5tuple(mf, 0);
        dp_packet_set_rss_hash(packet, hash);
    }

    return hash;
}

static inline uint32_t
dpif_netdev_packet_get_rss_hash(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash, recirc_depth;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
        hash = dp_packet_get_rss_hash(packet);
    } else {
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

struct packet_batch_per_flow {
    unsigned int byte_count;
    uint16_t tcp_flags;
    struct dp_netdev_flow *flow;

    struct dp_packet_batch array;
};

static inline void
packet_batch_per_flow_update(struct packet_batch_per_flow *batch,
                             struct dp_packet *packet,
                             const struct miniflow *mf)
{
    batch->byte_count += dp_packet_size(packet);
    batch->tcp_flags |= miniflow_get_tcp_flags(mf);
    batch->array.packets[batch->array.count++] = packet;
}

static inline void
packet_batch_per_flow_init(struct packet_batch_per_flow *batch,
                           struct dp_netdev_flow *flow)
{
    flow->batch = batch;

    batch->flow = flow;
    dp_packet_batch_init(&batch->array);
    batch->byte_count = 0;
    batch->tcp_flags = 0;
}

static inline void
packet_batch_per_flow_execute(struct packet_batch_per_flow *batch,
                              struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_actions *actions;
    struct dp_netdev_flow *flow = batch->flow;

    dp_netdev_flow_used(flow, batch->array.count, batch->byte_count,
                        batch->tcp_flags, pmd->ctx.now / 1000);

    actions = dp_netdev_flow_get_actions(flow);

    dp_netdev_execute_actions(pmd, &batch->array, true, &flow->flow,
                              actions->actions, actions->size);
}

static inline void
dp_netdev_queue_batches(struct dp_packet *pkt,
                        struct dp_netdev_flow *flow, const struct miniflow *mf,
                        struct packet_batch_per_flow *batches,
                        size_t *n_batches)
{
    struct packet_batch_per_flow *batch = flow->batch;

    if (OVS_UNLIKELY(!batch)) {
        batch = &batches[(*n_batches)++];
        packet_batch_per_flow_init(batch, flow);
    }

    packet_batch_per_flow_update(batch, pkt, mf);
}

/* Try to process all ('cnt') the 'packets' using only the exact match cache
 * 'pmd->flow_cache'. If a flow is not found for a packet 'packets[i]', the
 * miniflow is copied into 'keys' and the packet pointer is moved at the
 * beginning of the 'packets' array.
 *
 * The function returns the number of packets that needs to be processed in the
 * 'packets' array (they have been moved to the beginning of the vector).
 *
 * For performance reasons a caller may choose not to initialize the metadata
 * in 'packets_'.  If 'md_is_valid' is false, the metadata in 'packets'
 * is not valid and must be initialized by this function using 'port_no'.
 * If 'md_is_valid' is true, the metadata is already valid and 'port_no'
 * will be ignored.
 */
static inline size_t
emc_processing(struct dp_netdev_pmd_thread *pmd,
               struct dp_packet_batch *packets_,
               struct netdev_flow_key *keys,
               struct packet_batch_per_flow batches[], size_t *n_batches,
               bool md_is_valid, odp_port_t port_no)
{
    struct emc_cache *flow_cache = &pmd->flow_cache;
    struct netdev_flow_key *key = &keys[0];
    size_t n_missed = 0, n_dropped = 0;
    struct dp_packet *packet;
    const size_t cnt = dp_packet_batch_size(packets_);
    uint32_t cur_min;
    int i;

    atomic_read_relaxed(&pmd->dp->emc_insert_min, &cur_min);
    pmd_perf_update_counter(&pmd->perf_stats,
                            md_is_valid ? PMD_STAT_RECIRC : PMD_STAT_RECV,
                            cnt);

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) {
        struct dp_netdev_flow *flow;

        if (OVS_UNLIKELY(dp_packet_size(packet) < ETH_HEADER_LEN)) {
            dp_packet_delete(packet);
            n_dropped++;
            continue;
        }

        if (i != cnt - 1) {
            struct dp_packet **packets = packets_->packets;
            /* Prefetch next packet data and metadata. */
            OVS_PREFETCH(dp_packet_data(packets[i+1]));
            pkt_metadata_prefetch_init(&packets[i+1]->md);
        }

        if (!md_is_valid) {
            pkt_metadata_init(&packet->md, port_no);
        }
        miniflow_extract(packet, &key->mf);
        key->len = 0; /* Not computed yet. */
        /* If EMC is disabled skip hash computation and emc_lookup */
        if (cur_min) {
            if (!md_is_valid) {
                key->hash = dpif_netdev_packet_get_rss_hash_orig_pkt(packet,
                        &key->mf);
            } else {
                key->hash = dpif_netdev_packet_get_rss_hash(packet, &key->mf);
            }
            flow = emc_lookup(flow_cache, key);
        } else {
            flow = NULL;
        }
        if (OVS_LIKELY(flow)) {
            dp_netdev_queue_batches(packet, flow, &key->mf, batches,
                                    n_batches);
        } else {
            /* Exact match cache missed. Group missed packets together at
             * the beginning of the 'packets' array. */
            dp_packet_batch_refill(packets_, packet, i);
            /* 'key[n_missed]' contains the key of the current packet and it
             * must be returned to the caller. The next key should be extracted
             * to 'keys[n_missed + 1]'. */
            key = &keys[++n_missed];
        }
    }

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT,
                            cnt - n_dropped - n_missed);

    return dp_packet_batch_size(packets_);
}

static inline int
handle_packet_upcall(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet *packet,
                     const struct netdev_flow_key *key,
                     struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct ofpbuf *add_actions;
    struct dp_packet_batch b;
    struct match match;
    ovs_u128 ufid;
    int error;
    uint64_t cycles = cycles_counter_update(&pmd->perf_stats);

    match.tun_md.valid = false;
    miniflow_expand(&key->mf, &match.flow);

    ofpbuf_clear(actions);
    ofpbuf_clear(put_actions);

    dpif_flow_hash(pmd->dp->dpif, &match.flow, sizeof match.flow, &ufid);
    error = dp_netdev_upcall(pmd, packet, &match.flow, &match.wc,
                             &ufid, DPIF_UC_MISS, NULL, actions,
                             put_actions);
    if (OVS_UNLIKELY(error && error != ENOSPC)) {
        dp_packet_delete(packet);
        return error;
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here. */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    /* We can't allow the packet batching in the next loop to execute
     * the actions.  Otherwise, if there are any slow path actions,
     * we'll send the packet up twice. */
    dp_packet_batch_init_packet(&b, packet);
    dp_netdev_execute_actions(pmd, &b, true, &match.flow,
                              actions->data, actions->size);

    add_actions = put_actions->size ? put_actions : actions;
    if (OVS_LIKELY(error != ENOSPC)) {
        struct dp_netdev_flow *netdev_flow;

        /* XXX: There's a race window where a flow covering this packet
         * could have already been installed since we last did the flow
         * lookup before upcall.  This could be solved by moving the
         * mutex lock outside the loop, but that's an awful long time
         * to be locking everyone out of making flow installs.  If we
         * move to a per-core classifier, it would be reasonable. */
        ovs_mutex_lock(&pmd->flow_mutex);
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
        if (OVS_LIKELY(!netdev_flow)) {
            netdev_flow = dp_netdev_flow_add(pmd, &match, &ufid,
                                             add_actions->data,
                                             add_actions->size);
        }
        ovs_mutex_unlock(&pmd->flow_mutex);
        emc_probabilistic_insert(pmd, key, netdev_flow);
    }
    if (pmd_perf_metrics_enabled(pmd)) {
        /* Update upcall stats. */
        cycles = cycles_counter_update(&pmd->perf_stats) - cycles;
        struct pmd_perf_stats *s = &pmd->perf_stats;
        s->current.upcalls++;
        s->current.upcall_cycles += cycles;
        histogram_add_sample(&s->cycles_per_upcall, cycles);
    }
    return error;
}

static inline void
fast_path_processing(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet_batch *packets_,
                     struct netdev_flow_key *keys,
                     struct packet_batch_per_flow batches[],
                     size_t *n_batches,
                     odp_port_t in_port)
{
    const size_t cnt = dp_packet_batch_size(packets_);
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct dp_packet *packet;
    struct dpcls *cls;
    struct dpcls_rule *rules[PKT_ARRAY_SIZE];
    struct dp_netdev *dp = pmd->dp;
    int upcall_ok_cnt = 0, upcall_fail_cnt = 0;
    int lookup_cnt = 0, add_lookup_cnt;
    bool any_miss;

    for (size_t i = 0; i < cnt; i++) {
        /* Key length is needed in all the cases, hash computed on demand. */
        keys[i].len = netdev_flow_key_size(miniflow_n_values(&keys[i].mf));
    }
    /* Get the classifier for the in_port */
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        any_miss = !dpcls_lookup(cls, keys, rules, cnt, &lookup_cnt);
    } else {
        any_miss = true;
        memset(rules, 0, sizeof(rules));
    }
    if (OVS_UNLIKELY(any_miss) && !fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
        uint64_t actions_stub[512 / 8], slow_stub[512 / 8];
        struct ofpbuf actions, put_actions;

        ofpbuf_use_stub(&actions, actions_stub, sizeof actions_stub);
        ofpbuf_use_stub(&put_actions, slow_stub, sizeof slow_stub);

        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            struct dp_netdev_flow *netdev_flow;

            if (OVS_LIKELY(rules[i])) {
                continue;
            }

            /* It's possible that an earlier slow path execution installed
             * a rule covering this flow.  In this case, it's a lot cheaper
             * to catch it here than execute a miss. */
            netdev_flow = dp_netdev_pmd_lookup_flow(pmd, &keys[i],
                                                    &add_lookup_cnt);
            if (netdev_flow) {
                lookup_cnt += add_lookup_cnt;
                rules[i] = &netdev_flow->cr;
                continue;
            }

            int error = handle_packet_upcall(pmd, packet, &keys[i],
                                             &actions, &put_actions);

            if (OVS_UNLIKELY(error)) {
                upcall_fail_cnt++;
            } else {
                upcall_ok_cnt++;
            }
        }

        ofpbuf_uninit(&actions);
        ofpbuf_uninit(&put_actions);
        fat_rwlock_unlock(&dp->upcall_rwlock);
    } else if (OVS_UNLIKELY(any_miss)) {
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            if (OVS_UNLIKELY(!rules[i])) {
                dp_packet_delete(packet);
                upcall_fail_cnt++;
            }
        }
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        struct dp_netdev_flow *flow;

        if (OVS_UNLIKELY(!rules[i])) {
            continue;
        }

        flow = dp_netdev_flow_cast(rules[i]);

        emc_probabilistic_insert(pmd, &keys[i], flow);
        dp_netdev_queue_batches(packet, flow, &keys[i].mf, batches, n_batches);
    }

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_HIT,
                            cnt - upcall_ok_cnt - upcall_fail_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_LOOKUP,
                            lookup_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MISS,
                            upcall_ok_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_LOST,
                            upcall_fail_cnt);
}

/* Packets enter the datapath from a port (or from recirculation) here.
 *
 * When 'md_is_valid' is true the metadata in 'packets' are already valid.
 * When false the metadata in 'packets' need to be initialized. */
static void
dp_netdev_input__(struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet_batch *packets,
                  bool md_is_valid, odp_port_t port_no)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = dp_packet_batch_size(packets);
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)
        struct netdev_flow_key keys[PKT_ARRAY_SIZE];
    struct packet_batch_per_flow batches[PKT_ARRAY_SIZE];
    size_t n_batches;
    odp_port_t in_port;

    n_batches = 0;
    emc_processing(pmd, packets, keys, batches, &n_batches,
                            md_is_valid, port_no);
    if (!dp_packet_batch_is_empty(packets)) {
        /* Get ingress port from first packet's metadata. */
        in_port = packets->packets[0]->md.in_port.odp_port;
        fast_path_processing(pmd, packets, keys,
                             batches, &n_batches, in_port);
    }

    /* All the flow batches need to be reset before any call to
     * packet_batch_per_flow_execute() as it could potentially trigger
     * recirculation. When a packet matching flow ‘j’ happens to be
     * recirculated, the nested call to dp_netdev_input__() could potentially
     * classify the packet as matching another flow - say 'k'. It could happen
     * that in the previous call to dp_netdev_input__() that same flow 'k' had
     * already its own batches[k] still waiting to be served.  So if its
     * ‘batch’ member is not reset, the recirculated packet would be wrongly
     * appended to batches[k] of the 1st call to dp_netdev_input__(). */
    size_t i;
    for (i = 0; i < n_batches; i++) {
        batches[i].flow->batch = NULL;
    }

    for (i = 0; i < n_batches; i++) {
        packet_batch_per_flow_execute(&batches[i], pmd);
    }
}

static void
dp_netdev_input(struct dp_netdev_pmd_thread *pmd,
                struct dp_packet_batch *packets,
                odp_port_t port_no)
{
    dp_netdev_input__(pmd, packets, false, port_no);
}

static void
dp_netdev_recirculate(struct dp_netdev_pmd_thread *pmd,
                      struct dp_packet_batch *packets)
{
    dp_netdev_input__(pmd, packets, true, 0);
}

struct dp_netdev_execute_aux {
    struct dp_netdev_pmd_thread *pmd;
    const struct flow *flow;
};

static void
dpif_netdev_register_dp_purge_cb(struct dpif *dpif, dp_purge_callback *cb,
                                 void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->dp_purge_aux = aux;
    dp->dp_purge_cb = cb;
}

static void
dpif_netdev_register_upcall_cb(struct dpif *dpif, upcall_callback *cb,
                               void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->upcall_aux = aux;
    dp->upcall_cb = cb;
}

static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge)
{
    struct tx_port *tx;
    struct dp_netdev_port *port;
    long long interval;

    HMAP_FOR_EACH (tx, node, &pmd->send_port_cache) {
        if (!tx->port->dynamic_txqs) {
            continue;
        }
        interval = pmd->ctx.now - tx->last_used;
        if (tx->qid >= 0 && (purge || interval >= XPS_TIMEOUT)) {
            port = tx->port;
            ovs_mutex_lock(&port->txq_used_mutex);
            port->txq_used[tx->qid]--;
            ovs_mutex_unlock(&port->txq_used_mutex);
            tx->qid = -1;
        }
    }
}

static int
dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                           struct tx_port *tx)
{
    struct dp_netdev_port *port;
    long long interval;
    int i, min_cnt, min_qid;

    interval = pmd->ctx.now - tx->last_used;
    tx->last_used = pmd->ctx.now;

    if (OVS_LIKELY(tx->qid >= 0 && interval < XPS_TIMEOUT)) {
        return tx->qid;
    }

    port = tx->port;

    ovs_mutex_lock(&port->txq_used_mutex);
    if (tx->qid >= 0) {
        port->txq_used[tx->qid]--;
        tx->qid = -1;
    }

    min_cnt = -1;
    min_qid = 0;
    for (i = 0; i < netdev_n_txq(port->netdev); i++) {
        if (port->txq_used[i] < min_cnt || min_cnt == -1) {
            min_cnt = port->txq_used[i];
            min_qid = i;
        }
    }

    port->txq_used[min_qid]++;
    tx->qid = min_qid;

    ovs_mutex_unlock(&port->txq_used_mutex);

    dpif_netdev_xps_revalidate_pmd(pmd, false);

    VLOG_DBG("Core %d: New TX queue ID %d for port \'%s\'.",
             pmd->core_id, tx->qid, netdev_get_name(tx->port->netdev));
    return min_qid;
}

static struct tx_port *
pmd_tnl_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                          odp_port_t port_no)
{
    return tx_port_lookup(&pmd->tnl_port_cache, port_no);
}

static struct tx_port *
pmd_send_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                           odp_port_t port_no)
{
    return tx_port_lookup(&pmd->send_port_cache, port_no);
}

static int
push_tnl_action(const struct dp_netdev_pmd_thread *pmd,
                const struct nlattr *attr,
                struct dp_packet_batch *batch)
{
    struct tx_port *tun_port;
    const struct ovs_action_push_tnl *data;
    int err;

    data = nl_attr_get(attr);

    tun_port = pmd_tnl_port_cache_lookup(pmd, data->tnl_port);
    if (!tun_port) {
        err = -EINVAL;
        goto error;
    }
    err = netdev_push_header(tun_port->port->netdev, batch, data);
    if (!err) {
        return 0;
    }
error:
    dp_packet_delete_batch(batch, true);
    return err;
}

static void
dp_execute_userspace_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet *packet, bool should_steal,
                            struct flow *flow, ovs_u128 *ufid,
                            struct ofpbuf *actions,
                            const struct nlattr *userdata)
{
    struct dp_packet_batch b;
    int error;

    ofpbuf_clear(actions);

    error = dp_netdev_upcall(pmd, packet, flow, NULL, ufid,
                             DPIF_UC_ACTION, userdata, actions,
                             NULL);
    if (!error || error == ENOSPC) {
        dp_packet_batch_init_packet(&b, packet);
        dp_netdev_execute_actions(pmd, &b, should_steal, flow,
                                  actions->data, actions->size);
    } else if (should_steal) {
        dp_packet_delete(packet);
    }
}

static void
dp_execute_cb(void *aux_, struct dp_packet_batch *packets_,
              const struct nlattr *a, bool should_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev_execute_aux *aux = aux_;
    uint32_t *depth = recirc_depth_get();
    struct dp_netdev_pmd_thread *pmd = aux->pmd;
    struct dp_netdev *dp = pmd->dp;
    int type = nl_attr_type(a);
    struct tx_port *p;

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        p = pmd_send_port_cache_lookup(pmd, nl_attr_get_odp_port(a));
        if (OVS_LIKELY(p)) {
            struct dp_packet *packet;
            struct dp_packet_batch out;

            if (!should_steal) {
                dp_packet_batch_clone(&out, packets_);
                dp_packet_batch_reset_cutlen(packets_);
                packets_ = &out;
            }
            dp_packet_batch_apply_cutlen(packets_);

#ifdef DPDK_NETDEV
            if (OVS_UNLIKELY(!dp_packet_batch_is_empty(&p->output_pkts)
                             && packets_->packets[0]->source
                                != p->output_pkts.packets[0]->source)) {
                /* XXX: netdev-dpdk assumes that all packets in a single
                 *      output batch has the same source. Flush here to
                 *      avoid memory access issues. */
                dp_netdev_pmd_flush_output_on_port(pmd, p);
            }
#endif
            if (dp_packet_batch_size(&p->output_pkts)
                + dp_packet_batch_size(packets_) > NETDEV_MAX_BURST) {
                /* Flush here to avoid overflow. */
                dp_netdev_pmd_flush_output_on_port(pmd, p);
            }

            if (dp_packet_batch_is_empty(&p->output_pkts)) {
                pmd->n_output_batches++;
            }

            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                p->output_pkts_rxqs[dp_packet_batch_size(&p->output_pkts)] =
                                                             pmd->ctx.last_rxq;
                dp_packet_batch_add(&p->output_pkts, packet);
            }
            return;
        }
        break;

    case OVS_ACTION_ATTR_TUNNEL_PUSH:
        if (should_steal) {
            /* We're requested to push tunnel header, but also we need to take
             * the ownership of these packets. Thus, we can avoid performing
             * the action, because the caller will not use the result anyway.
             * Just break to free the batch. */
            break;
        }
        dp_packet_batch_apply_cutlen(packets_);
        push_tnl_action(pmd, a, packets_);
        return;

    case OVS_ACTION_ATTR_TUNNEL_POP:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet_batch *orig_packets_ = packets_;
            odp_port_t portno = nl_attr_get_odp_port(a);

            p = pmd_tnl_port_cache_lookup(pmd, portno);
            if (p) {
                struct dp_packet_batch tnl_pkt;

                if (!should_steal) {
                    dp_packet_batch_clone(&tnl_pkt, packets_);
                    packets_ = &tnl_pkt;
                    dp_packet_batch_reset_cutlen(orig_packets_);
                }

                dp_packet_batch_apply_cutlen(packets_);

                netdev_pop_header(p->port->netdev, packets_);
                if (dp_packet_batch_is_empty(packets_)) {
                    return;
                }

                struct dp_packet *packet;
                DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                    packet->md.in_port.odp_port = portno;
                }

                (*depth)++;
                dp_netdev_recirculate(pmd, packets_);
                (*depth)--;
                return;
            }
        }
        break;

    case OVS_ACTION_ATTR_USERSPACE:
        if (!fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
            struct dp_packet_batch *orig_packets_ = packets_;
            const struct nlattr *userdata;
            struct dp_packet_batch usr_pkt;
            struct ofpbuf actions;
            struct flow flow;
            ovs_u128 ufid;
            bool clone = false;

            userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);
            ofpbuf_init(&actions, 0);

            if (packets_->trunc) {
                if (!should_steal) {
                    dp_packet_batch_clone(&usr_pkt, packets_);
                    packets_ = &usr_pkt;
                    clone = true;
                    dp_packet_batch_reset_cutlen(orig_packets_);
                }

                dp_packet_batch_apply_cutlen(packets_);
            }

            struct dp_packet *packet;
            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                flow_extract(packet, &flow);
                dpif_flow_hash(dp->dpif, &flow, sizeof flow, &ufid);
                dp_execute_userspace_action(pmd, packet, should_steal, &flow,
                                            &ufid, &actions, userdata);
            }

            if (clone) {
                dp_packet_delete_batch(packets_, true);
            }

            ofpbuf_uninit(&actions);
            fat_rwlock_unlock(&dp->upcall_rwlock);

            return;
        }
        break;

    case OVS_ACTION_ATTR_RECIRC:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet_batch recirc_pkts;

            if (!should_steal) {
               dp_packet_batch_clone(&recirc_pkts, packets_);
               packets_ = &recirc_pkts;
            }

            struct dp_packet *packet;
            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                packet->md.recirc_id = nl_attr_get_u32(a);
            }

            (*depth)++;
            dp_netdev_recirculate(pmd, packets_);
            (*depth)--;

            return;
        }

        VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
        break;

    case OVS_ACTION_ATTR_CT: {
        const struct nlattr *b;
        bool force = false;
        bool commit = false;
        unsigned int left;
        uint16_t zone = 0;
        const char *helper = NULL;
        const uint32_t *setmark = NULL;
        const struct ovs_key_ct_labels *setlabel = NULL;
        struct nat_action_info_t nat_action_info;
        struct nat_action_info_t *nat_action_info_ref = NULL;
        bool nat_config = false;

        NL_ATTR_FOR_EACH_UNSAFE (b, left, nl_attr_get(a),
                                 nl_attr_get_size(a)) {
            enum ovs_ct_attr sub_type = nl_attr_type(b);

            switch(sub_type) {
            case OVS_CT_ATTR_FORCE_COMMIT:
                force = true;
                /* fall through. */
            case OVS_CT_ATTR_COMMIT:
                commit = true;
                break;
            case OVS_CT_ATTR_ZONE:
                zone = nl_attr_get_u16(b);
                break;
            case OVS_CT_ATTR_HELPER:
                helper = nl_attr_get_string(b);
                break;
            case OVS_CT_ATTR_MARK:
                setmark = nl_attr_get(b);
                break;
            case OVS_CT_ATTR_LABELS:
                setlabel = nl_attr_get(b);
                break;
            case OVS_CT_ATTR_EVENTMASK:
                /* Silently ignored, as userspace datapath does not generate
                 * netlink events. */
                break;
            case OVS_CT_ATTR_NAT: {
                const struct nlattr *b_nest;
                unsigned int left_nest;
                bool ip_min_specified = false;
                bool proto_num_min_specified = false;
                bool ip_max_specified = false;
                bool proto_num_max_specified = false;
                memset(&nat_action_info, 0, sizeof nat_action_info);
                nat_action_info_ref = &nat_action_info;

                NL_NESTED_FOR_EACH_UNSAFE (b_nest, left_nest, b) {
                    enum ovs_nat_attr sub_type_nest = nl_attr_type(b_nest);

                    switch (sub_type_nest) {
                    case OVS_NAT_ATTR_SRC:
                    case OVS_NAT_ATTR_DST:
                        nat_config = true;
                        nat_action_info.nat_action |=
                            ((sub_type_nest == OVS_NAT_ATTR_SRC)
                                ? NAT_ACTION_SRC : NAT_ACTION_DST);
                        break;
                    case OVS_NAT_ATTR_IP_MIN:
                        memcpy(&nat_action_info.min_addr,
                               nl_attr_get(b_nest),
                               nl_attr_get_size(b_nest));
                        ip_min_specified = true;
                        break;
                    case OVS_NAT_ATTR_IP_MAX:
                        memcpy(&nat_action_info.max_addr,
                               nl_attr_get(b_nest),
                               nl_attr_get_size(b_nest));
                        ip_max_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_MIN:
                        nat_action_info.min_port =
                            nl_attr_get_u16(b_nest);
                        proto_num_min_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_MAX:
                        nat_action_info.max_port =
                            nl_attr_get_u16(b_nest);
                        proto_num_max_specified = true;
                        break;
                    case OVS_NAT_ATTR_PERSISTENT:
                    case OVS_NAT_ATTR_PROTO_HASH:
                    case OVS_NAT_ATTR_PROTO_RANDOM:
                        break;
                    case OVS_NAT_ATTR_UNSPEC:
                    case __OVS_NAT_ATTR_MAX:
                        OVS_NOT_REACHED();
                    }
                }

                if (ip_min_specified && !ip_max_specified) {
                    nat_action_info.max_addr = nat_action_info.min_addr;
                }
                if (proto_num_min_specified && !proto_num_max_specified) {
                    nat_action_info.max_port = nat_action_info.min_port;
                }
                if (proto_num_min_specified || proto_num_max_specified) {
                    if (nat_action_info.nat_action & NAT_ACTION_SRC) {
                        nat_action_info.nat_action |= NAT_ACTION_SRC_PORT;
                    } else if (nat_action_info.nat_action & NAT_ACTION_DST) {
                        nat_action_info.nat_action |= NAT_ACTION_DST_PORT;
                    }
                }
                break;
            }
            case OVS_CT_ATTR_UNSPEC:
            case __OVS_CT_ATTR_MAX:
                OVS_NOT_REACHED();
            }
        }

        /* We won't be able to function properly in this case, hence
         * complain loudly. */
        if (nat_config && !commit) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_WARN_RL(&rl, "NAT specified without commit.");
        }

        conntrack_execute(&dp->conntrack, packets_, aux->flow->dl_type, force,
                          commit, zone, setmark, setlabel, aux->flow->tp_src,
                          aux->flow->tp_dst, helper, nat_action_info_ref,
                          pmd->ctx.now / 1000);
        break;
    }

    case OVS_ACTION_ATTR_METER:
        dp_netdev_run_meter(pmd->dp, packets_, nl_attr_get_u32(a),
                            pmd->ctx.now);
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
    case OVS_ACTION_ATTR_TRUNC:
    case OVS_ACTION_ATTR_PUSH_ETH:
    case OVS_ACTION_ATTR_POP_ETH:
    case OVS_ACTION_ATTR_CLONE:
    case OVS_ACTION_ATTR_PUSH_NSH:
    case OVS_ACTION_ATTR_POP_NSH:
    case OVS_ACTION_ATTR_CT_CLEAR:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    dp_packet_delete_batch(packets_, should_steal);
}

static void
dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                          struct dp_packet_batch *packets,
                          bool should_steal, const struct flow *flow,
                          const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = { pmd, flow };

    odp_execute_actions(&aux, packets, should_steal, actions,
                        actions_len, dp_execute_cb);
}

struct dp_netdev_ct_dump {
    struct ct_dpif_dump_state up;
    struct conntrack_dump dump;
    struct conntrack *ct;
    struct dp_netdev *dp;
};

static int
dpif_netdev_ct_dump_start(struct dpif *dpif, struct ct_dpif_dump_state **dump_,
                          const uint16_t *pzone, int *ptot_bkts)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_ct_dump *dump;

    dump = xzalloc(sizeof *dump);
    dump->dp = dp;
    dump->ct = &dp->conntrack;

    conntrack_dump_start(&dp->conntrack, &dump->dump, pzone, ptot_bkts);

    *dump_ = &dump->up;

    return 0;
}

static int
dpif_netdev_ct_dump_next(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_,
                         struct ct_dpif_entry *entry)
{
    struct dp_netdev_ct_dump *dump;

    INIT_CONTAINER(dump, dump_, up);

    return conntrack_dump_next(&dump->dump, entry);
}

static int
dpif_netdev_ct_dump_done(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_)
{
    struct dp_netdev_ct_dump *dump;
    int err;

    INIT_CONTAINER(dump, dump_, up);

    err = conntrack_dump_done(&dump->dump);

    free(dump);

    return err;
}

static int
dpif_netdev_ct_flush(struct dpif *dpif, const uint16_t *zone,
                     const struct ct_dpif_tuple *tuple)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (tuple) {
        return conntrack_flush_tuple(&dp->conntrack, tuple, zone ? *zone : 0);
    }
    return conntrack_flush(&dp->conntrack, zone);
}

static int
dpif_netdev_ct_set_maxconns(struct dpif *dpif, uint32_t maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_maxconns(&dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_maxconns(struct dpif *dpif, uint32_t *maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_maxconns(&dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_nconns(struct dpif *dpif, uint32_t *nconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_nconns(&dp->conntrack, nconns);
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
    dpif_netdev_port_set_config,
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
    dpif_netdev_set_config,
    dpif_netdev_queue_to_priority,
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */
    dpif_netdev_register_dp_purge_cb,
    dpif_netdev_register_upcall_cb,
    dpif_netdev_enable_upcall,
    dpif_netdev_disable_upcall,
    dpif_netdev_get_datapath_version,
    dpif_netdev_ct_dump_start,
    dpif_netdev_ct_dump_next,
    dpif_netdev_ct_dump_done,
    dpif_netdev_ct_flush,
    dpif_netdev_ct_set_maxconns,
    dpif_netdev_ct_get_maxconns,
    dpif_netdev_ct_get_nconns,
    dpif_netdev_meter_get_features,
    dpif_netdev_meter_set,
    dpif_netdev_meter_get,
    dpif_netdev_meter_del,
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

    ovs_mutex_lock(&dp->port_mutex);
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

    /* Remove port. */
    hmap_remove(&dp->ports, &port->node);
    reconfigure_datapath(dp);

    /* Reinsert with new port number. */
    port->port_no = port_no;
    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    reconfigure_datapath(dp);

    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);

exit:
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

static void
dpif_dummy_override(const char *type)
{
    int error;

    /*
     * Ignore EAFNOSUPPORT to allow --enable-dummy=system with
     * a userland-only build.  It's useful for testsuite.
     */
    error = dp_unregister_provider(type);
    if (error == 0 || error == EAFNOSUPPORT) {
        dpif_dummy_register__(type);
    }
}

void
dpif_dummy_register(enum dummy_level level)
{
    if (level == DUMMY_OVERRIDE_ALL) {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            dpif_dummy_override(type);
        }
        sset_destroy(&types);
    } else if (level == DUMMY_OVERRIDE_SYSTEM) {
        dpif_dummy_override("system");
    }

    dpif_dummy_register__("dummy");

    unixctl_command_register("dpif-dummy/change-port-number",
                             "dp port new-number",
                             3, 3, dpif_dummy_change_port_number, NULL);
}

/* Datapath Classifier. */

/* A set of rules that all have the same fields wildcarded. */
struct dpcls_subtable {
    /* The fields are only used by writers. */
    struct cmap_node cmap_node OVS_GUARDED; /* Within dpcls 'subtables_map'. */

    /* These fields are accessed by readers. */
    struct cmap rules;           /* Contains "struct dpcls_rule"s. */
    uint32_t hit_cnt;            /* Number of match hits in subtable in current
                                    optimization interval. */
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
    VLOG_DBG("Destroying subtable %p for in_port %d", subtable, cls->in_port);
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
            ovs_assert(cmap_count(&subtable->rules) == 0);
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
    subtable->hit_cnt = 0;
    netdev_flow_key_clone(&subtable->mask, mask);
    cmap_insert(&cls->subtables_map, &subtable->cmap_node, mask->hash);
    /* Add the new subtable at the end of the pvector (with no hits yet) */
    pvector_insert(&cls->subtables, subtable, 0);
    VLOG_DBG("Creating %"PRIuSIZE". subtable %p for in_port %d",
             cmap_count(&cls->subtables_map), subtable, cls->in_port);
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


/* Periodically sort the dpcls subtable vectors according to hit counts */
static void
dpcls_sort_subtable_vector(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    struct dpcls_subtable *subtable;

    PVECTOR_FOR_EACH (subtable, pvec) {
        pvector_change_priority(pvec, subtable, subtable->hit_cnt);
        subtable->hit_cnt = 0;
    }
    pvector_publish(pvec);
}

static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt)
{
    struct dpcls *cls;

    if (pmd->ctx.now > pmd->rxq_next_cycle_store) {
        uint64_t curr_tsc;
        /* Get the cycles that were used to process each queue and store. */
        for (unsigned i = 0; i < poll_cnt; i++) {
            uint64_t rxq_cyc_curr = dp_netdev_rxq_get_cycles(poll_list[i].rxq,
                                                        RXQ_CYCLES_PROC_CURR);
            dp_netdev_rxq_set_intrvl_cycles(poll_list[i].rxq, rxq_cyc_curr);
            dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR,
                                     0);
        }
        curr_tsc = cycles_counter_update(&pmd->perf_stats);
        if (pmd->intrvl_tsc_prev) {
            /* There is a prev timestamp, store a new intrvl cycle count. */
            atomic_store_relaxed(&pmd->intrvl_cycles,
                                 curr_tsc - pmd->intrvl_tsc_prev);
        }
        pmd->intrvl_tsc_prev = curr_tsc;
        /* Start new measuring interval */
        pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;
    }

    if (pmd->ctx.now > pmd->next_optimization) {
        /* Try to obtain the flow lock to block out revalidator threads.
         * If not possible, just try next time. */
        if (!ovs_mutex_trylock(&pmd->flow_mutex)) {
            /* Optimize each classifier */
            CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
                dpcls_sort_subtable_vector(cls);
            }
            ovs_mutex_unlock(&pmd->flow_mutex);
            /* Start new measuring interval */
            pmd->next_optimization = pmd->ctx.now
                                     + DPCLS_OPTIMIZATION_INTERVAL;
        }
    }
}

/* Insert 'rule' into 'cls'. */
static void
dpcls_insert(struct dpcls *cls, struct dpcls_rule *rule,
             const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable = dpcls_find_subtable(cls, mask);

    /* Refer to subtable's mask, also for later removal. */
    rule->mask = &subtable->mask;
    cmap_insert(&subtable->rules, &rule->cmap_node, rule->flow.hash);
}

/* Removes 'rule' from 'cls', also destructing the 'rule'. */
static void
dpcls_remove(struct dpcls *cls, struct dpcls_rule *rule)
{
    struct dpcls_subtable *subtable;

    ovs_assert(rule->mask);

    /* Get subtable from reference in rule->mask. */
    INIT_CONTAINER(subtable, rule->mask, mask);
    if (cmap_remove(&subtable->rules, &rule->cmap_node, rule->flow.hash)
        == 0) {
        /* Delete empty subtable. */
        dpcls_destroy_subtable(cls, subtable);
        pvector_publish(&cls->subtables);
    }
}

/* Returns true if 'target' satisfies 'key' in 'mask', that is, if each 1-bit
 * in 'mask' the values in 'key' and 'target' are the same. */
static inline bool
dpcls_rule_matches_key(const struct dpcls_rule *rule,
                       const struct netdev_flow_key *target)
{
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);
    const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);
    uint64_t value;

    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(value, target, rule->flow.mf.map) {
        if (OVS_UNLIKELY((value & *maskp++) != *keyp++)) {
            return false;
        }
    }
    return true;
}

/* For each miniflow in 'keys' performs a classifier lookup writing the result
 * into the corresponding slot in 'rules'.  If a particular entry in 'keys' is
 * NULL it is skipped.
 *
 * This function is optimized for use in the userspace datapath and therefore
 * does not implement a lot of features available in the standard
 * classifier_lookup() function.  Specifically, it does not implement
 * priorities, instead returning any rule which matches the flow.
 *
 * Returns true if all miniflows found a corresponding rule. */
static bool
dpcls_lookup(struct dpcls *cls, const struct netdev_flow_key keys[],
             struct dpcls_rule **rules, const size_t cnt,
             int *num_lookups_p)
{
    /* The received 'cnt' miniflows are the search-keys that will be processed
     * to find a matching entry into the available subtables.
     * The number of bits in map_type is equal to NETDEV_MAX_BURST. */
    typedef uint32_t map_type;
#define MAP_BITS (sizeof(map_type) * CHAR_BIT)
    BUILD_ASSERT_DECL(MAP_BITS >= NETDEV_MAX_BURST);

    struct dpcls_subtable *subtable;

    map_type keys_map = TYPE_MAXIMUM(map_type); /* Set all bits. */
    map_type found_map;
    uint32_t hashes[MAP_BITS];
    const struct cmap_node *nodes[MAP_BITS];

    if (cnt != MAP_BITS) {
        keys_map >>= MAP_BITS - cnt; /* Clear extra bits. */
    }
    memset(rules, 0, cnt * sizeof *rules);

    int lookups_match = 0, subtable_pos = 1;

    /* The Datapath classifier - aka dpcls - is composed of subtables.
     * Subtables are dynamically created as needed when new rules are inserted.
     * Each subtable collects rules with matches on a specific subset of packet
     * fields as defined by the subtable's mask.  We proceed to process every
     * search-key against each subtable, but when a match is found for a
     * search-key, the search for that key can stop because the rules are
     * non-overlapping. */
    PVECTOR_FOR_EACH (subtable, &cls->subtables) {
        int i;

        /* Compute hashes for the remaining keys.  Each search-key is
         * masked with the subtable's mask to avoid hashing the wildcarded
         * bits. */
        ULLONG_FOR_EACH_1(i, keys_map) {
            hashes[i] = netdev_flow_key_hash_in_mask(&keys[i],
                                                     &subtable->mask);
        }
        /* Lookup. */
        found_map = cmap_find_batch(&subtable->rules, keys_map, hashes, nodes);
        /* Check results.  When the i-th bit of found_map is set, it means
         * that a set of nodes with a matching hash value was found for the
         * i-th search-key.  Due to possible hash collisions we need to check
         * which of the found rules, if any, really matches our masked
         * search-key. */
        ULLONG_FOR_EACH_1(i, found_map) {
            struct dpcls_rule *rule;

            CMAP_NODE_FOR_EACH (rule, cmap_node, nodes[i]) {
                if (OVS_LIKELY(dpcls_rule_matches_key(rule, &keys[i]))) {
                    rules[i] = rule;
                    /* Even at 20 Mpps the 32-bit hit_cnt cannot wrap
                     * within one second optimization interval. */
                    subtable->hit_cnt++;
                    lookups_match += subtable_pos;
                    goto next;
                }
            }
            /* None of the found rules was a match.  Reset the i-th bit to
             * keep searching this key in the next subtable. */
            ULLONG_SET0(found_map, i);  /* Did not match. */
        next:
            ;                     /* Keep Sparse happy. */
        }
        keys_map &= ~found_map;             /* Clear the found rules. */
        if (!keys_map) {
            if (num_lookups_p) {
                *num_lookups_p = lookups_match;
            }
            return true;              /* All found. */
        }
        subtable_pos++;
    }
    if (num_lookups_p) {
        *num_lookups_p = lookups_match;
    }
    return false;                     /* Some misses. */
}
