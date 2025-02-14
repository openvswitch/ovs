/*
 * Copyright (c) 2009-2014, 2016-2018 Nicira, Inc.
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
#include "dpif-netdev-private.h"
#include "dpif-netdev-private-dfc.h"

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
#include "ccmap.h"
#include "cmap.h"
#include "conntrack.h"
#include "conntrack-tp.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-lookup.h"
#include "dpif-netdev-perf.h"
#include "dpif-netdev-private-extract.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "hmapx.h"
#include "id-fpool.h"
#include "id-pool.h"
#include "ipf.h"
#include "mov-avg.h"
#include "mpsc-queue.h"
#include "netdev.h"
#include "netdev-offload.h"
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
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

/* Auto Load Balancing Defaults */
#define ALB_IMPROVEMENT_THRESHOLD    25
#define ALB_LOAD_THRESHOLD           95
#define ALB_REBALANCE_INTERVAL       1     /* 1 Min */
#define MAX_ALB_REBALANCE_INTERVAL   20000 /* 20000 Min */
#define MIN_TO_MSEC                  60000

#define FLOW_DUMP_MAX_BATCH 50
/* Use per thread recirc_depth to prevent recirculation loop. */
#define MAX_RECIRC_DEPTH 8
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, recirc_depth, 0)

/* Use instant packet send by default. */
#define DEFAULT_TX_FLUSH_INTERVAL 0

/* Configuration parameters. */
enum { MAX_METERS = 1 << 18 };  /* Maximum number of meters. */
enum { MAX_BANDS = 8 };         /* Maximum number of bands / meter. */

COVERAGE_DEFINE(datapath_drop_meter);
COVERAGE_DEFINE(datapath_drop_upcall_error);
COVERAGE_DEFINE(datapath_drop_lock_error);
COVERAGE_DEFINE(datapath_drop_userspace_action_error);
COVERAGE_DEFINE(datapath_drop_tunnel_push_error);
COVERAGE_DEFINE(datapath_drop_tunnel_pop_error);
COVERAGE_DEFINE(datapath_drop_recirc_error);
COVERAGE_DEFINE(datapath_drop_invalid_port);
COVERAGE_DEFINE(datapath_drop_invalid_bond);
COVERAGE_DEFINE(datapath_drop_invalid_tnl_port);
COVERAGE_DEFINE(datapath_drop_rx_invalid_packet);
#ifdef ALLOW_EXPERIMENTAL_API /* Packet restoration API required. */
COVERAGE_DEFINE(datapath_drop_hw_miss_recover);
#endif

/* Protects against changes to 'dp_netdevs'. */
struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

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


/* Simple non-wildcarding single-priority classifier. */

/* Time in microseconds between successive optimizations of the dpcls
 * subtable vector */
#define DPCLS_OPTIMIZATION_INTERVAL 1000000LL

/* Time in microseconds of the interval in which rxq processing cycles used
 * in rxq to pmd assignments is measured and stored. */
#define PMD_INTERVAL_LEN 5000000LL
/* For converting PMD_INTERVAL_LEN to secs. */
#define INTERVAL_USEC_TO_SEC 1000000LL

/* Number of intervals for which cycles are stored
 * and used during rxq to pmd assignment. */
#define PMD_INTERVAL_MAX 12

/* Time in microseconds to try RCU quiescing. */
#define PMD_RCU_QUIESCE_INTERVAL 10000LL

/* Timer resolution for PMD threads in nanoseconds. */
#define PMD_TIMER_RES_NS 1000

/* Number of pkts Rx on an interface that will stop pmd thread sleeping. */
#define PMD_SLEEP_THRESH (NETDEV_MAX_BURST / 2)
/* Time in uS to increment a pmd thread sleep time. */
#define PMD_SLEEP_INC_US 1

struct pmd_sleep {
    unsigned core_id;
    uint64_t max_sleep;
};

struct dpcls {
    struct cmap_node node;      /* Within dp_netdev_pmd_thread.classifiers */
    odp_port_t in_port;
    struct cmap subtables_map;
    struct pvector subtables;
};

/* Data structure to keep packet order till fastpath processing. */
struct dp_packet_flow_map {
    struct dp_packet *packet;
    struct dp_netdev_flow *flow;
    uint16_t tcp_flags;
};

static void dpcls_init(struct dpcls *);
static void dpcls_destroy(struct dpcls *);
static void dpcls_sort_subtable_vector(struct dpcls *);
static uint32_t dpcls_subtable_lookup_reprobe(struct dpcls *cls);
static void dpcls_insert(struct dpcls *, struct dpcls_rule *,
                         const struct netdev_flow_key *mask);
static void dpcls_remove(struct dpcls *, struct dpcls_rule *);

/* Set of supported meter flags */
#define DP_SUPPORTED_METER_FLAGS_MASK \
    (OFPMF13_STATS | OFPMF13_PKTPS | OFPMF13_KBPS | OFPMF13_BURST)

/* Set of supported meter band types */
#define DP_SUPPORTED_METER_BAND_TYPES           \
    ( 1 << OFPMBT13_DROP )

struct dp_meter_band {
    uint32_t rate;
    uint32_t burst_size;
    atomic_uint64_t bucket;          /* In 1/1000 packets for PKTPS,
                                      * or in bits for KBPS. */
    atomic_uint64_t packet_count;
    atomic_uint64_t byte_count;
};

struct dp_meter {
    struct cmap_node node;
    uint32_t id;
    uint16_t flags;
    uint16_t n_bands;
    uint32_t max_delta_t;
    atomic_uint64_t used;  /* Time of a last use in milliseconds. */
    atomic_uint64_t packet_count;
    atomic_uint64_t byte_count;
    struct dp_meter_band bands[];
};

struct pmd_auto_lb {
    bool do_dry_run;
    bool recheck_config;
    bool is_enabled;            /* Current status of Auto load balancing. */
    uint64_t rebalance_intvl;
    uint64_t rebalance_poll_timer;
    uint8_t rebalance_improve_thresh;
    atomic_uint8_t rebalance_load_thresh;
};

enum sched_assignment_type {
    SCHED_ROUNDROBIN,
    SCHED_CYCLES, /* Default.*/
    SCHED_GROUP
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
 *    bond_mutex
 *    non_pmd_mutex
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_rwlock'. */
    struct ovs_rwlock port_rwlock;
    struct hmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* The time that a packet can wait in output batch for sending. */
    atomic_uint32_t tx_flush_interval;

    /* Meters. */
    struct ovs_mutex meters_lock;
    struct cmap meters OVS_GUARDED;

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    atomic_uint32_t emc_insert_min;
    /* Enable collection of PMD performance metrics. */
    atomic_bool pmd_perf_metrics;
    /* Default max load based sleep request. */
    uint64_t pmd_max_sleep_default;
    /* Enable the SMC cache from ovsdb config */
    atomic_bool smc_enable_db;

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
    /* Rxq to pmd assignment type. */
    enum sched_assignment_type pmd_rxq_assign_type;
    bool pmd_iso;

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

    /* PMD max load based sleep request user string. */
    char *max_sleep_list;

    uint64_t last_tnl_conf_seq;

    struct conntrack *conntrack;
    struct pmd_auto_lb pmd_alb;

    /* Bonds. */
    struct ovs_mutex bond_mutex; /* Protects updates of 'tx_bonds'. */
    struct cmap tx_bonds; /* Contains 'struct tx_bond'. */
};

static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t)
    OVS_REQ_RDLOCK(dp->port_rwlock);

enum rxq_cycles_counter_type {
    RXQ_CYCLES_PROC_CURR,       /* Cycles spent successfully polling and
                                   processing packets during the current
                                   interval. */
    RXQ_CYCLES_PROC_HIST,       /* Total cycles of all intervals that are used
                                   during rxq to pmd assignment. */
    RXQ_N_CYCLES
};

enum dp_offload_type {
    DP_OFFLOAD_FLOW,
    DP_OFFLOAD_FLUSH,
};

enum {
    DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
    DP_NETDEV_FLOW_OFFLOAD_OP_MOD,
    DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
};

struct dp_offload_flow_item {
    struct dp_netdev_flow *flow;
    int op;
    struct match match;
    struct nlattr *actions;
    size_t actions_len;
    odp_port_t orig_in_port; /* Originating in_port for tnl flows. */
};

struct dp_offload_flush_item {
    struct netdev *netdev;
    struct ovs_barrier *barrier;
};

union dp_offload_thread_data {
    struct dp_offload_flow_item flow;
    struct dp_offload_flush_item flush;
};

struct dp_offload_thread_item {
    struct mpsc_queue_node node;
    enum dp_offload_type type;
    long long int timestamp;
    struct dp_netdev *dp;
    union dp_offload_thread_data data[0];
};

struct dp_offload_thread {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct mpsc_queue queue;
        atomic_uint64_t enqueued_item;
        struct cmap megaflow_to_mark;
        struct cmap mark_to_flow;
        struct mov_avg_cma cma;
        struct mov_avg_ema ema;
    );
};
static struct dp_offload_thread *dp_offload_threads;
static void *dp_netdev_flow_offload_main(void *arg);

static void
dp_netdev_offload_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int nb_offload_thread = netdev_offload_thread_nb();
    unsigned int tid;

    if (!ovsthread_once_start(&once)) {
        return;
    }

    dp_offload_threads = xcalloc(nb_offload_thread,
                                 sizeof *dp_offload_threads);

    for (tid = 0; tid < nb_offload_thread; tid++) {
        struct dp_offload_thread *thread;

        thread = &dp_offload_threads[tid];
        mpsc_queue_init(&thread->queue);
        cmap_init(&thread->megaflow_to_mark);
        cmap_init(&thread->mark_to_flow);
        atomic_init(&thread->enqueued_item, 0);
        mov_avg_cma_init(&thread->cma);
        mov_avg_ema_init(&thread->ema, 100);
        ovs_thread_create("hw_offload", dp_netdev_flow_offload_main, thread);
    }

    ovsthread_once_done(&once);
}

#define XPS_TIMEOUT 500000LL    /* In microseconds. */

/* Contained by struct dp_netdev_port's 'rxqs' member.  */
struct dp_netdev_rxq {
    struct dp_netdev_port *port;
    struct netdev_rxq *rx;
    unsigned core_id;                  /* Core to which this queue should be
                                          pinned. OVS_CORE_UNSPEC if the
                                          queue doesn't need to be pinned to a
                                          particular core. */
    atomic_count intrvl_idx;           /* Write index for 'cycles_intrvl'. */
    struct dp_netdev_pmd_thread *pmd;  /* pmd thread that polls this queue. */
    bool is_vhost;                     /* Is rxq of a vhost port. */

    /* Counters of cycles spent successfully polling and processing pkts. */
    atomic_ullong cycles[RXQ_N_CYCLES];
    /* We store PMD_INTERVAL_MAX intervals of data for an rxq and then
       sum them to yield the cycles used for an rxq. */
    atomic_ullong cycles_intrvl[PMD_INTERVAL_MAX];
};

enum txq_req_mode {
    TXQ_REQ_MODE_THREAD,
    TXQ_REQ_MODE_HASH,
};

enum txq_mode {
    TXQ_MODE_STATIC,
    TXQ_MODE_XPS,
    TXQ_MODE_XPS_HASH,
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    odp_port_t port_no;
    enum txq_mode txq_mode;     /* static, XPS, XPS_HASH. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct dp_netdev_rxq *rxqs;
    unsigned n_rxq;             /* Number of elements in 'rxqs' */
    unsigned *txq_used;         /* Number of threads that use each tx queue. */
    struct ovs_mutex txq_used_mutex;
    bool emc_enabled;           /* If true EMC will be used. */
    char *type;                 /* Port type as requested by user. */
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
    enum txq_req_mode txq_requested_mode;
};

static bool dp_netdev_flow_ref(struct dp_netdev_flow *);
static int dpif_netdev_flow_from_nlattrs(const struct nlattr *, uint32_t,
                                         struct flow *, bool);

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t);
struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *);
static void dp_netdev_actions_free(struct dp_netdev_actions *);

struct polled_queue {
    struct dp_netdev_rxq *rxq;
    odp_port_t port_no;
    bool emc_enabled;
    bool rxq_enabled;
    uint64_t change_seq;
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
    struct dp_packet_batch *txq_pkts; /* Only for hash mode. */
    struct dp_netdev_rxq *output_pkts_rxqs[NETDEV_MAX_BURST];
};

/* Contained by struct tx_bond 'member_buckets'. */
struct member_entry {
    odp_port_t member_id;
    atomic_ullong n_packets;
    atomic_ullong n_bytes;
};

/* Contained by struct dp_netdev_pmd_thread's 'tx_bonds'. */
struct tx_bond {
    struct cmap_node node;
    uint32_t bond_id;
    struct member_entry member_buckets[BOND_BUCKETS];
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
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static void do_del_port(struct dp_netdev *dp, struct dp_netdev_port *)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static void dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                                      struct dp_packet_batch *,
                                      bool should_steal,
                                      const struct flow *flow,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_recirculate(struct dp_netdev_pmd_thread *,
                                  struct dp_packet_batch *);

static void dp_netdev_disable_upcall(struct dp_netdev *);
static void dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd,
                                    struct dp_netdev *dp, unsigned core_id,
                                    int numa_id);
static void dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock);

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
static void dp_netdev_add_bond_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                         struct tx_bond *bond, bool update)
    OVS_EXCLUDED(pmd->bond_mutex);
static void dp_netdev_del_bond_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                           uint32_t bond_id)
    OVS_EXCLUDED(pmd->bond_mutex);

static void dp_netdev_offload_flush(struct dp_netdev *dp,
                                    struct dp_netdev_port *port);

static void reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock);
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
static uint64_t
get_interval_values(atomic_ullong *source, atomic_count *cur_idx,
                    int num_to_read);
static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge);
static int dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                                      struct tx_port *tx);
inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd,
                           odp_port_t in_port);

static void dp_netdev_request_reconfigure(struct dp_netdev *dp);
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd);
static void queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd,
                                  struct dp_netdev_flow *flow);

static void dp_netdev_simple_match_insert(struct dp_netdev_pmd_thread *pmd,
                                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex);
static void dp_netdev_simple_match_remove(struct dp_netdev_pmd_thread *pmd,
                                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex);

static bool dp_netdev_flow_is_simple_match(const struct match *);

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
    PMD_INFO_SLEEP_SHOW,  /* Show max sleep configuration details. */
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
                  "  packets received: %"PRIu64"\n"
                  "  packet recirculations: %"PRIu64"\n"
                  "  avg. datapath passes per packet: %.02f\n"
                  "  phwol hits: %"PRIu64"\n"
                  "  mfex opt hits: %"PRIu64"\n"
                  "  simple match hits: %"PRIu64"\n"
                  "  emc hits: %"PRIu64"\n"
                  "  smc hits: %"PRIu64"\n"
                  "  megaflow hits: %"PRIu64"\n"
                  "  avg. subtable lookups per megaflow hit: %.02f\n"
                  "  miss with success upcall: %"PRIu64"\n"
                  "  miss with failed upcall: %"PRIu64"\n"
                  "  avg. packets per output batch: %.02f\n",
                  total_packets, stats[PMD_STAT_RECIRC],
                  passes_per_pkt, stats[PMD_STAT_PHWOL_HIT],
                  stats[PMD_STAT_MFEX_OPT_HIT],
                  stats[PMD_STAT_SIMPLE_HIT],
                  stats[PMD_STAT_EXACT_HIT],
                  stats[PMD_STAT_SMC_HIT],
                  stats[PMD_STAT_MASKED_HIT],
                  lookups_per_hit, stats[PMD_STAT_MISS], stats[PMD_STAT_LOST],
                  packets_per_batch);

    if (total_cycles == 0) {
        return;
    }

    ds_put_format(reply,
                  "  idle cycles: %"PRIu64" (%.02f%%)\n"
                  "  processing cycles: %"PRIu64" (%.02f%%)\n",
                  stats[PMD_CYCLES_ITER_IDLE],
                  stats[PMD_CYCLES_ITER_IDLE] / (double) total_cycles * 100,
                  stats[PMD_CYCLES_ITER_BUSY],
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_cycles * 100);

    if (total_packets == 0) {
        return;
    }

    ds_put_format(reply,
                  "  avg cycles per packet: %.02f (%"PRIu64"/%"PRIu64")\n",
                  total_cycles / (double) total_packets,
                  total_cycles, total_packets);

    ds_put_format(reply,
                  "  avg processing cycles per packet: "
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
    OVS_REQUIRES(pmd->port_mutex)
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
pmd_info_show_rxq(struct ds *reply, struct dp_netdev_pmd_thread *pmd,
                  int secs)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        struct rxq_poll *list;
        size_t n_rxq;
        uint64_t total_pmd_cycles = 0;
        uint64_t busy_pmd_cycles = 0;
        uint64_t total_rxq_proc_cycles = 0;
        unsigned int intervals;

        ds_put_format(reply,
                      "pmd thread numa_id %d core_id %u:\n  isolated : %s\n",
                      pmd->numa_id, pmd->core_id, (pmd->isolated)
                                                  ? "true" : "false");

        ovs_mutex_lock(&pmd->port_mutex);
        sorted_poll_list(pmd, &list, &n_rxq);

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_pmd_cycles);
        /* Calculate how many intervals are to be used. */
        intervals = DIV_ROUND_UP(secs,
                                 PMD_INTERVAL_LEN / INTERVAL_USEC_TO_SEC);
        /* Estimate the cycles to cover all intervals. */
        total_pmd_cycles *= intervals;
        busy_pmd_cycles = get_interval_values(pmd->busy_cycles_intrvl,
                                              &pmd->intrvl_idx,
                                              intervals);
        if (busy_pmd_cycles > total_pmd_cycles) {
            busy_pmd_cycles = total_pmd_cycles;
        }

        for (int i = 0; i < n_rxq; i++) {
            struct dp_netdev_rxq *rxq = list[i].rxq;
            const char *name = netdev_rxq_get_name(rxq->rx);
            uint64_t rxq_proc_cycles = 0;

            rxq_proc_cycles = get_interval_values(rxq->cycles_intrvl,
                                                  &rxq->intrvl_idx,
                                                  intervals);
            total_rxq_proc_cycles += rxq_proc_cycles;
            ds_put_format(reply, "  port: %-16s  queue-id: %2d", name,
                          netdev_rxq_get_queue_id(list[i].rxq->rx));
            ds_put_format(reply, " %s", netdev_rxq_enabled(list[i].rxq->rx)
                                        ? "(enabled) " : "(disabled)");
            ds_put_format(reply, "  pmd usage: ");
            if (total_pmd_cycles) {
                ds_put_format(reply, "%2.0f %%",
                              (double) (rxq_proc_cycles * 100) /
                              total_pmd_cycles);
            } else {
                ds_put_format(reply, "%s", "NOT AVAIL");
            }
            ds_put_cstr(reply, "\n");
        }

        if (n_rxq > 0) {
            ds_put_cstr(reply, "  overhead: ");
            if (total_pmd_cycles) {
                uint64_t overhead_cycles = 0;

                if (total_rxq_proc_cycles < busy_pmd_cycles) {
                    overhead_cycles = busy_pmd_cycles - total_rxq_proc_cycles;
                }

                ds_put_format(reply, "%2.0f %%",
                              (double) (overhead_cycles * 100) /
                              total_pmd_cycles);
            } else {
                ds_put_cstr(reply, "NOT AVAIL");
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
dpif_netdev_subtable_lookup_get(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[] OVS_UNUSED,
                                void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;

    dpcls_impl_print_stats(&reply);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_netdev_subtable_lookup_set(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[], void *aux OVS_UNUSED)
{
    /* This function requires 2 parameters (argv[1] and argv[2]) to execute.
     *   argv[1] is subtable name
     *   argv[2] is priority
     */
    const char *func_name = argv[1];

    errno = 0;
    char *err_char;
    uint32_t new_prio = strtoul(argv[2], &err_char, 10);
    uint32_t lookup_dpcls_changed = 0;
    uint32_t lookup_subtable_changed = 0;
    struct shash_node *node;
    if (errno != 0 || new_prio > UINT8_MAX) {
        unixctl_command_reply_error(conn,
            "error converting priority, use integer in range 0-255\n");
        return;
    }

    int32_t err = dpcls_subtable_set_prio(func_name, new_prio);
    if (err) {
        unixctl_command_reply_error(conn,
            "error, subtable lookup function not found\n");
        return;
    }

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;

        /* Get PMD threads list, required to get DPCLS instances. */
        size_t n;
        struct dp_netdev_pmd_thread **pmd_list;
        sorted_poll_thread_list(dp, &pmd_list, &n);

        /* take port mutex as HMAP iters over them. */
        ovs_rwlock_rdlock(&dp->port_rwlock);

        for (size_t i = 0; i < n; i++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[i];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            struct dp_netdev_port *port = NULL;
            HMAP_FOR_EACH (port, node, &dp->ports) {
                odp_port_t in_port = port->port_no;
                struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
                if (!cls) {
                    continue;
                }
                ovs_mutex_lock(&pmd->flow_mutex);
                uint32_t subtbl_changes = dpcls_subtable_lookup_reprobe(cls);
                ovs_mutex_unlock(&pmd->flow_mutex);
                if (subtbl_changes) {
                    lookup_dpcls_changed++;
                    lookup_subtable_changed += subtbl_changes;
                }
            }
        }

        /* release port mutex before netdev mutex. */
        ovs_rwlock_unlock(&dp->port_rwlock);
        free(pmd_list);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    struct ds reply = DS_EMPTY_INITIALIZER;
    ds_put_format(&reply,
        "Lookup priority change affected %d dpcls ports and %d subtables.\n",
        lookup_dpcls_changed, lookup_subtable_changed);
    const char *reply_str = ds_cstr(&reply);
    unixctl_command_reply(conn, reply_str);
    VLOG_INFO("%s", reply_str);
    ds_destroy(&reply);
}

static void
dpif_netdev_impl_get(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev_pmd_thread **pmd_list;
        struct dp_netdev *dp = node->data;
        size_t n;

        /* Get PMD threads list, required to get the DPIF impl used by each PMD
         * thread. */
        sorted_poll_thread_list(dp, &pmd_list, &n);
        dp_netdev_impl_get(&reply, pmd_list, n);
        free(pmd_list);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_netdev_impl_set(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[], void *aux OVS_UNUSED)
{
    /* This function requires just one parameter, the DPIF name. */
    const char *dpif_name = argv[1];
    struct shash_node *node;

    static const char *error_description[2] = {
        "Unknown DPIF implementation",
        "CPU doesn't support the required instruction for",
    };

    ovs_mutex_lock(&dp_netdev_mutex);
    int32_t err = dp_netdev_impl_set_default_by_name(dpif_name);

    if (err) {
        struct ds reply = DS_EMPTY_INITIALIZER;
        ds_put_format(&reply, "DPIF implementation not available: %s %s.\n",
                      error_description[ (err == -ENOTSUP) ], dpif_name);
        const char *reply_str = ds_cstr(&reply);
        unixctl_command_reply_error(conn, reply_str);
        VLOG_ERR("%s", reply_str);
        ds_destroy(&reply);
        ovs_mutex_unlock(&dp_netdev_mutex);
        return;
    }

    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;

        /* Get PMD threads list, required to get DPCLS instances. */
        size_t n;
        struct dp_netdev_pmd_thread **pmd_list;
        sorted_poll_thread_list(dp, &pmd_list, &n);

        for (size_t i = 0; i < n; i++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[i];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            /* Initialize DPIF function pointer to the newly configured
             * default. */
            atomic_store_relaxed(&pmd->netdev_input_func,
                                 dp_netdev_impl_get_default());
        };

        free(pmd_list);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    /* Reply with success to command. */
    struct ds reply = DS_EMPTY_INITIALIZER;
    ds_put_format(&reply, "DPIF implementation set to %s.\n", dpif_name);
    const char *reply_str = ds_cstr(&reply);
    unixctl_command_reply(conn, reply_str);
    VLOG_INFO("%s", reply_str);
    ds_destroy(&reply);
}

static void
dpif_miniflow_extract_impl_get(struct unixctl_conn *conn, int argc OVS_UNUSED,
                               const char *argv[] OVS_UNUSED,
                               void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev_pmd_thread **pmd_list;
        struct dp_netdev *dp = node->data;
        size_t n;

        /* Get PMD threads list, required to get the DPIF impl used by each PMD
         * thread. */
        sorted_poll_thread_list(dp, &pmd_list, &n);
        dp_mfex_impl_get(&reply, pmd_list, n);
        free(pmd_list);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_miniflow_extract_impl_set(struct unixctl_conn *conn, int argc,
                               const char *argv[], void *aux OVS_UNUSED)
{
    /* This command takes some optional and mandatory arguments. The function
     * here first parses all of the options, saving results in local variables.
     * Then the parsed values are acted on.
     */
    unsigned int pmd_thread_to_change = NON_PMD_CORE_ID;
    unsigned int study_count = MFEX_MAX_PKT_COUNT;
    struct ds reply = DS_EMPTY_INITIALIZER;
    bool pmd_thread_update_done = false;
    bool mfex_name_is_study = false;
    const char *mfex_name = NULL;
    const char *reply_str = NULL;
    struct shash_node *node;
    int err;

    while (argc > 1) {
        /* Optional argument "-pmd" limits the commands actions to just this
         * PMD thread.
         */
        if ((!strcmp(argv[1], "-pmd") && !mfex_name)) {
            if (argc < 3) {
                ds_put_format(&reply,
                              "Error: -pmd option requires a thread id"
                              " argument.\n");
                goto error;
            }

            /* Ensure argument can be parsed to an integer. */
            if (!str_to_uint(argv[2], 10, &pmd_thread_to_change) ||
                (pmd_thread_to_change == NON_PMD_CORE_ID)) {
                ds_put_format(&reply,
                              "Error: miniflow extract parser not changed,"
                              " PMD thread passed is not valid: '%s'."
                              " Pass a valid pmd thread ID.\n",
                              argv[2]);
                goto error;
            }

            argc -= 2;
            argv += 2;

        } else if (!mfex_name) {
            /* Name of MFEX impl requested by user. */
            mfex_name = argv[1];
            mfex_name_is_study = strcmp("study", mfex_name) == 0;
            argc -= 1;
            argv += 1;

        /* If name is study and more args exist, parse study_count value. */
        } else if (mfex_name && mfex_name_is_study) {
            if (!str_to_uint(argv[1], 10, &study_count) ||
                (study_count == 0)) {
                ds_put_format(&reply,
                              "Error: invalid study_pkt_cnt value: %s.\n",
                              argv[1]);
                goto error;
            }

            argc -= 1;
            argv += 1;
        } else {
            ds_put_format(&reply, "Error: unknown argument %s.\n", argv[1]);
            goto error;
        }
    }

    /* Ensure user passed an MFEX name. */
    if (!mfex_name) {
        ds_put_format(&reply, "Error: no miniflow extract name provided."
                      " Output of miniflow-parser-get shows implementation"
                      " list.\n");
        goto error;
    }

    /* If the MFEX name is "study", set the study packet count. */
    if (mfex_name_is_study) {
        err = mfex_set_study_pkt_cnt(study_count, mfex_name);
        if (err) {
            ds_put_format(&reply, "Error: failed to set study count %d for"
                          " miniflow extract implementation %s.\n",
                          study_count, mfex_name);
            goto error;
        }
    }

    /* Set the default MFEX impl only if the command was applied to all PMD
     * threads. If a PMD thread was selected, do NOT update the default.
     */
    if (pmd_thread_to_change == NON_PMD_CORE_ID) {
        err = dp_mfex_impl_set_default_by_name(mfex_name);
        if (err == -ENODEV) {
            ds_put_format(&reply,
                          "Error: miniflow extract not available due to CPU"
                          " ISA requirements: %s",
                          mfex_name);
            goto error;
        } else if (err) {
            ds_put_format(&reply,
                          "Error: unknown miniflow extract implementation %s.",
                          mfex_name);
            goto error;
        }
    }

    /* Get the desired MFEX function pointer and error check its usage. */
    miniflow_extract_func mfex_func = NULL;
    err = dp_mfex_impl_get_by_name(mfex_name, &mfex_func);
    if (err) {
        if (err == -ENODEV) {
            ds_put_format(&reply,
                          "Error: miniflow extract not available due to CPU"
                          " ISA requirements: %s", mfex_name);
        } else {
            ds_put_format(&reply,
                          "Error: unknown miniflow extract implementation %s.",
                          mfex_name);
        }
        goto error;
    }

    /* Apply the MFEX pointer to each pmd thread in each netdev, filtering
     * by the users "-pmd" argument if required.
     */
    ovs_mutex_lock(&dp_netdev_mutex);

    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev_pmd_thread **pmd_list;
        struct dp_netdev *dp = node->data;
        size_t n;

        sorted_poll_thread_list(dp, &pmd_list, &n);

        for (size_t i = 0; i < n; i++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[i];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            /* If -pmd specified, skip all other pmd threads. */
            if ((pmd_thread_to_change != NON_PMD_CORE_ID) &&
                (pmd->core_id != pmd_thread_to_change)) {
                continue;
            }

            pmd_thread_update_done = true;
            atomic_store_relaxed(&pmd->miniflow_extract_opt, mfex_func);
        };

        free(pmd_list);
    }

    ovs_mutex_unlock(&dp_netdev_mutex);

    /* If PMD thread was specified, but it wasn't found, return error. */
    if (pmd_thread_to_change != NON_PMD_CORE_ID && !pmd_thread_update_done) {
        ds_put_format(&reply,
                      "Error: miniflow extract parser not changed, "
                      "PMD thread %d not in use, pass a valid pmd"
                      " thread ID.\n", pmd_thread_to_change);
        goto error;
    }

    /* Reply with success to command. */
    ds_put_format(&reply, "Miniflow extract implementation set to %s",
                  mfex_name);
    if (pmd_thread_to_change != NON_PMD_CORE_ID) {
        ds_put_format(&reply, ", on pmd thread %d", pmd_thread_to_change);
    }
    if (mfex_name_is_study) {
        ds_put_format(&reply, ", studying %d packets", study_count);
    }
    ds_put_format(&reply, ".\n");

    reply_str = ds_cstr(&reply);
    VLOG_INFO("%s", reply_str);
    unixctl_command_reply(conn, reply_str);
    ds_destroy(&reply);
    return;

error:
    reply_str = ds_cstr(&reply);
    VLOG_ERR("%s", reply_str);
    unixctl_command_reply_error(conn, reply_str);
    ds_destroy(&reply);
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
pmd_info_show_sleep(struct ds *reply, unsigned core_id, int numa_id,
                    uint64_t pmd_max_sleep)
{
    if (core_id == NON_PMD_CORE_ID) {
        return;
    }
    ds_put_format(reply,
                  "pmd thread numa_id %d core_id %d:\n"
                  "  max sleep: %4"PRIu64" us\n",
                  numa_id, core_id, pmd_max_sleep);
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
    unsigned int secs = 0;
    unsigned long long max_secs = (PMD_INTERVAL_LEN * PMD_INTERVAL_MAX)
                                      / INTERVAL_USEC_TO_SEC;
    bool show_header = true;
    uint64_t max_sleep;

    ovs_mutex_lock(&dp_netdev_mutex);

    while (argc > 1) {
        if (!strcmp(argv[1], "-pmd") && argc > 2) {
            if (str_to_uint(argv[2], 10, &core_id)) {
                filter_on_pmd = true;
            }
            argc -= 2;
            argv += 2;
        } else if (type == PMD_INFO_SHOW_RXQ &&
                       !strcmp(argv[1], "-secs") &&
                       argc > 2) {
            if (!str_to_uint(argv[2], 10, &secs)) {
                secs = max_secs;
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
            if (show_header) {
                if (!secs || secs > max_secs) {
                    secs = max_secs;
                } else {
                    secs = ROUND_UP(secs,
                                    PMD_INTERVAL_LEN / INTERVAL_USEC_TO_SEC);
                }
                ds_put_format(&reply, "Displaying last %u seconds "
                              "pmd usage %%\n", secs);
                show_header = false;
            }
            pmd_info_show_rxq(&reply, pmd, secs);
        } else if (type == PMD_INFO_CLEAR_STATS) {
            pmd_perf_stats_clear(&pmd->perf_stats);
        } else if (type == PMD_INFO_SHOW_STATS) {
            pmd_info_show_stats(&reply, pmd);
        } else if (type == PMD_INFO_PERF_SHOW) {
            pmd_info_show_perf(&reply, pmd, (struct pmd_perf_params *)aux);
        } else if (type == PMD_INFO_SLEEP_SHOW) {
            if (show_header) {
                ds_put_format(&reply, "Default max sleep: %4"PRIu64" us\n",
                              dp->pmd_max_sleep_default);
                show_header = false;
            }
            atomic_read_relaxed(&pmd->max_sleep, &max_sleep);
            pmd_info_show_sleep(&reply, pmd->core_id, pmd->numa_id,
                                max_sleep);
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

static void
dpif_netdev_bond_show(struct unixctl_conn *conn, int argc,
                      const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev *dp = NULL;

    ovs_mutex_lock(&dp_netdev_mutex);
    if (argc == 2) {
        dp = shash_find_data(&dp_netdevs, argv[1]);
    } else if (shash_count(&dp_netdevs) == 1) {
        /* There's only one datapath. */
        dp = shash_first(&dp_netdevs)->data;
    }
    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn,
                                    "please specify an existing datapath");
        return;
    }

    if (cmap_count(&dp->tx_bonds) > 0) {
        struct tx_bond *dp_bond_entry;

        ds_put_cstr(&reply, "Bonds:\n");
        CMAP_FOR_EACH (dp_bond_entry, node, &dp->tx_bonds) {
            ds_put_format(&reply, "  bond-id %"PRIu32":\n",
                          dp_bond_entry->bond_id);
            for (int bucket = 0; bucket < BOND_BUCKETS; bucket++) {
                uint32_t member_id = odp_to_u32(
                    dp_bond_entry->member_buckets[bucket].member_id);
                ds_put_format(&reply,
                              "    bucket %d - member %"PRIu32"\n",
                              bucket, member_id);
            }
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
                              clear_aux = PMD_INFO_CLEAR_STATS,
                              poll_aux = PMD_INFO_SHOW_RXQ,
                              sleep_aux = PMD_INFO_SLEEP_SHOW;

    unixctl_command_register("dpif-netdev/pmd-stats-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&show_aux);
    unixctl_command_register("dpif-netdev/pmd-stats-clear", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&clear_aux);
    unixctl_command_register("dpif-netdev/pmd-rxq-show", "[-pmd core] "
                             "[-secs secs] [dp]",
                             0, 5, dpif_netdev_pmd_info,
                             (void *)&poll_aux);
    unixctl_command_register("dpif-netdev/pmd-sleep-show", "[dp]",
                             0, 1, dpif_netdev_pmd_info,
                             (void *)&sleep_aux);
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
    unixctl_command_register("dpif-netdev/bond-show", "[dp]",
                             0, 1, dpif_netdev_bond_show,
                             NULL);
    unixctl_command_register("dpif-netdev/subtable-lookup-prio-set",
                             "[lookup_func] [prio]",
                             2, 2, dpif_netdev_subtable_lookup_set,
                             NULL);
    unixctl_command_register("dpif-netdev/subtable-lookup-info-get", "",
                             0, 0, dpif_netdev_subtable_lookup_get,
                             NULL);
    unixctl_command_register("dpif-netdev/subtable-lookup-prio-get", NULL,
                             0, 0, dpif_netdev_subtable_lookup_get,
                             NULL);
    unixctl_command_register("dpif-netdev/dpif-impl-set",
                             "dpif_implementation_name",
                             1, 1, dpif_netdev_impl_set,
                             NULL);
    unixctl_command_register("dpif-netdev/dpif-impl-get", "",
                             0, 0, dpif_netdev_impl_get,
                             NULL);
    unixctl_command_register("dpif-netdev/miniflow-parser-set",
                             "[-pmd core] miniflow_implementation_name"
                             " [study_pkt_cnt]",
                             1, 5, dpif_miniflow_extract_impl_set,
                             NULL);
    unixctl_command_register("dpif-netdev/miniflow-parser-get", "",
                             0, 0, dpif_miniflow_extract_impl_get,
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

static uint32_t
dp_meter_hash(uint32_t meter_id)
{
    /* In the ofproto-dpif layer, we use the id-pool to alloc meter id
     * orderly (e.g. 1, 2, ... N.), which provides a better hash
     * distribution.  Use them directly instead of hash_xxx function for
     * achieving high-performance. */
    return meter_id;
}

static void
dp_netdev_meter_destroy(struct dp_netdev *dp)
{
    struct dp_meter *m;

    ovs_mutex_lock(&dp->meters_lock);
    CMAP_FOR_EACH (m, node, &dp->meters) {
        cmap_remove(&dp->meters, &m->node, dp_meter_hash(m->id));
        ovsrcu_postpone(free, m);
    }

    cmap_destroy(&dp->meters);
    ovs_mutex_unlock(&dp->meters_lock);
    ovs_mutex_destroy(&dp->meters_lock);
}

static struct dp_meter *
dp_meter_lookup(struct cmap *meters, uint32_t meter_id)
{
    uint32_t hash = dp_meter_hash(meter_id);
    struct dp_meter *m;

    CMAP_FOR_EACH_WITH_HASH (m, node, hash, meters) {
        if (m->id == meter_id) {
            return m;
        }
    }

    return NULL;
}

static void
dp_meter_detach_free(struct cmap *meters, uint32_t meter_id)
{
    struct dp_meter *m = dp_meter_lookup(meters, meter_id);

    if (m) {
        cmap_remove(meters, &m->node, dp_meter_hash(meter_id));
        ovsrcu_postpone(free, m);
    }
}

static void
dp_meter_attach(struct cmap *meters, struct dp_meter *meter)
{
    cmap_insert(meters, &meter->node, dp_meter_hash(meter->id));
}

static int
create_dp_netdev(const char *name, const struct dpif_class *class,
                 struct dp_netdev **dpp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    static struct ovsthread_once tsc_freq_check = OVSTHREAD_ONCE_INITIALIZER;
    struct dp_netdev *dp;
    int error;

    /* Avoid estimating TSC frequency for dummy datapath to not slow down
     * unit tests. */
    if (!dpif_netdev_class_is_dummy(class)
        && ovsthread_once_start(&tsc_freq_check)) {
        pmd_perf_estimate_tsc_frequency();
        ovsthread_once_done(&tsc_freq_check);
    }

    dp = xzalloc(sizeof *dp);
    shash_add(&dp_netdevs, name, dp);

    *CONST_CAST(const struct dpif_class **, &dp->class) = class;
    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_clear(&dp->destroyed);

    ovs_rwlock_init(&dp->port_rwlock);
    hmap_init(&dp->ports);
    dp->port_seq = seq_create();
    ovs_mutex_init(&dp->bond_mutex);
    cmap_init(&dp->tx_bonds);

    fat_rwlock_init(&dp->upcall_rwlock);

    dp->reconfigure_seq = seq_create();
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    /* Init meter resources. */
    cmap_init(&dp->meters);
    ovs_mutex_init(&dp->meters_lock);

    /* Disable upcalls by default. */
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

    dp->conntrack = conntrack_init();

    dpif_miniflow_extract_init();

    atomic_init(&dp->emc_insert_min, DEFAULT_EM_FLOW_INSERT_MIN);
    atomic_init(&dp->tx_flush_interval, DEFAULT_TX_FLUSH_INTERVAL);

    cmap_init(&dp->poll_threads);
    dp->pmd_rxq_assign_type = SCHED_CYCLES;

    ovs_mutex_init(&dp->tx_qid_pool_mutex);
    /* We need 1 Tx queue for each possible core + 1 for non-PMD threads. */
    dp->tx_qid_pool = id_pool_create(0, ovs_numa_get_n_cores() + 1);

    ovs_mutex_init_recursive(&dp->non_pmd_mutex);
    ovsthread_key_create(&dp->per_pmd_key, NULL);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    /* non-PMD will be created before all other threads and will
     * allocate static_tx_qid = 0. */
    dp_netdev_set_nonpmd(dp);

    error = do_add_port(dp, name, dpif_netdev_port_open_type(dp->class,
                                                             "internal"),
                        ODPP_LOCAL);
    ovs_rwlock_unlock(&dp->port_rwlock);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    dp->max_sleep_list = NULL;

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

static uint32_t
hash_bond_id(uint32_t bond_id)
{
    return hash_int(bond_id, 0);
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port;
    struct tx_bond *bond;

    shash_find_and_delete(&dp_netdevs, dp->name);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    HMAP_FOR_EACH_SAFE (port, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    ovs_mutex_lock(&dp->bond_mutex);
    CMAP_FOR_EACH (bond, node, &dp->tx_bonds) {
        cmap_remove(&dp->tx_bonds, &bond->node, hash_bond_id(bond->bond_id));
        ovsrcu_postpone(free, bond);
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    dp_netdev_destroy_all_pmds(dp, true);
    cmap_destroy(&dp->poll_threads);

    ovs_mutex_destroy(&dp->tx_qid_pool_mutex);
    id_pool_destroy(dp->tx_qid_pool);

    ovs_mutex_destroy(&dp->non_pmd_mutex);
    ovsthread_key_delete(dp->per_pmd_key);

    conntrack_destroy(dp->conntrack);


    seq_destroy(dp->reconfigure_seq);

    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    ovs_rwlock_destroy(&dp->port_rwlock);

    cmap_destroy(&dp->tx_bonds);
    ovs_mutex_destroy(&dp->bond_mutex);

    /* Upcalls must be disabled at this point */
    dp_netdev_destroy_upcall_lock(dp);

    dp_netdev_meter_destroy(dp);

    free(dp->max_sleep_list);
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
        stats->n_hit += pmd_stats[PMD_STAT_PHWOL_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_SIMPLE_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_EXACT_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_SMC_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_MASKED_HIT];
        stats->n_missed += pmd_stats[PMD_STAT_MISS];
        stats->n_lost += pmd_stats[PMD_STAT_LOST];
    }
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;
    stats->n_cache_hit = UINT64_MAX;

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

    seq_change(pmd->reload_seq);
    atomic_store_explicit(&pmd->reload, true, memory_order_release);
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

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->netdev = netdev;
    port->type = xstrdup(type);
    port->sf = NULL;
    port->emc_enabled = true;
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
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct netdev_saved_flags *sf;
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

    /* Check that port was successfully configured. */
    if (!dp_netdev_lookup_port(dp, port_no)) {
        return EINVAL;
    }

    /* Updating device flags triggers an if_notifier, which triggers a bridge
     * reconfiguration and another attempt to add this port, leading to an
     * infinite loop if the device is configured incorrectly and cannot be
     * added.  Setting the promisc mode after a successful reconfiguration,
     * since we already know that the device is somehow properly configured. */
    error = netdev_turn_flags_on(port->netdev, NETDEV_PROMISC, &sf);
    if (error) {
        VLOG_ERR("%s: cannot set promisc flag", devname);
        do_del_port(dp, port);
        return error;
    }
    port->sf = sf;

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
    if (port_no == ODPP_LOCAL) {
        error = EINVAL;
    } else {
        struct dp_netdev_port *port;

        error = get_port_by_number(dp, port_no, &port);
        if (!error) {
            do_del_port(dp, port);
        }
    }
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
    OVS_REQ_RDLOCK(dp->port_rwlock)
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
    OVS_REQ_RDLOCK(dp->port_rwlock)
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
    OVS_REQ_RDLOCK(dp->port_rwlock)
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
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);

    /* Flush and disable offloads only after 'port' has been made
     * inaccessible through datapath reconfiguration.
     * This prevents having PMDs enqueuing offload requests after
     * the flush.
     * When only this port is deleted instead of the whole datapath,
     * revalidator threads are still active and can still enqueue
     * offload modification or deletion. Managing those stray requests
     * is done in the offload threads. */
    dp_netdev_offload_flush(dp, port);
    netdev_uninit_flow_api(port->netdev);

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

    ovs_rwlock_wrlock(&dp->port_rwlock);
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
    dp_netdev_actions_free(dp_netdev_flow_get_actions(flow));
    free(flow->dp_extra_info);
    free(flow);
}

void dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
    if (ovs_refcount_unref_relaxed(&flow->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_flow_free, flow);
    }
}

inline struct dpcls *
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

    if (!cls) {
        uint32_t hash = hash_port_no(in_port);

        /* Create new classifier for in_port */
        cls = xmalloc(sizeof(*cls));
        dpcls_init(cls);
        cls->in_port = in_port;
        cmap_insert(&pmd->classifiers, &cls->node, hash);
        VLOG_DBG("Creating dpcls %p for in_port %d", cls, in_port);
    }
    return cls;
}

#define MAX_FLOW_MARK       (UINT32_MAX - 1)
#define INVALID_FLOW_MARK   0
/* Zero flow mark is used to indicate the HW to remove the mark. A packet
 * marked with zero mark is received in SW without a mark at all, so it
 * cannot be used as a valid mark.
 */

struct megaflow_to_mark_data {
    const struct cmap_node node;
    ovs_u128 mega_ufid;
    uint32_t mark;
};

static struct id_fpool *flow_mark_pool;

static uint32_t
flow_mark_alloc(void)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t mark;

    if (ovsthread_once_start(&init_once)) {
        /* Haven't initiated yet, do it here */
        flow_mark_pool = id_fpool_create(netdev_offload_thread_nb(),
                                         1, MAX_FLOW_MARK);
        ovsthread_once_done(&init_once);
    }

    if (id_fpool_new_id(flow_mark_pool, tid, &mark)) {
        return mark;
    }

    return INVALID_FLOW_MARK;
}

static void
flow_mark_free(uint32_t mark)
{
    unsigned int tid = netdev_offload_thread_id();

    id_fpool_free_id(flow_mark_pool, tid, mark);
}

/* associate megaflow with a mark, which is a 1:1 mapping */
static void
megaflow_to_mark_associate(const ovs_u128 *mega_ufid, uint32_t mark)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data = xzalloc(sizeof(*data));
    unsigned int tid = netdev_offload_thread_id();

    data->mega_ufid = *mega_ufid;
    data->mark = mark;

    cmap_insert(&dp_offload_threads[tid].megaflow_to_mark,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

/* disassociate meagaflow with a mark */
static void
megaflow_to_mark_disassociate(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;
    unsigned int tid = netdev_offload_thread_id();

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &dp_offload_threads[tid].megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            cmap_remove(&dp_offload_threads[tid].megaflow_to_mark,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return;
        }
    }

    VLOG_WARN("Masked ufid "UUID_FMT" is not associated with a mark?\n",
              UUID_ARGS((struct uuid *)mega_ufid));
}

static inline uint32_t
megaflow_to_mark_find(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;
    unsigned int tid = netdev_offload_thread_id();

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &dp_offload_threads[tid].megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            return data->mark;
        }
    }

    VLOG_DBG("Mark id for ufid "UUID_FMT" was not found\n",
             UUID_ARGS((struct uuid *)mega_ufid));
    return INVALID_FLOW_MARK;
}

/* associate mark with a flow, which is 1:N mapping */
static void
mark_to_flow_associate(const uint32_t mark, struct dp_netdev_flow *flow)
{
    unsigned int tid = netdev_offload_thread_id();
    dp_netdev_flow_ref(flow);

    cmap_insert(&dp_offload_threads[tid].mark_to_flow,
                CONST_CAST(struct cmap_node *, &flow->mark_node),
                hash_int(mark, 0));
    flow->mark = mark;

    VLOG_DBG("Associated dp_netdev flow %p with mark %u mega_ufid "UUID_FMT,
             flow, mark, UUID_ARGS((struct uuid *) &flow->mega_ufid));
}

static bool
flow_mark_has_no_ref(uint32_t mark)
{
    unsigned int tid = netdev_offload_thread_id();
    struct dp_netdev_flow *flow;

    CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash_int(mark, 0),
                             &dp_offload_threads[tid].mark_to_flow) {
        if (flow->mark == mark) {
            return false;
        }
    }

    return true;
}

static int
mark_to_flow_disassociate(struct dp_netdev *dp,
                          struct dp_netdev_flow *flow)
{
    const char *dpif_type_str = dpif_normalize_type(dp->class->type);
    struct cmap_node *mark_node = CONST_CAST(struct cmap_node *,
                                             &flow->mark_node);
    unsigned int tid = netdev_offload_thread_id();
    uint32_t mark = flow->mark;
    int ret = 0;

    /* INVALID_FLOW_MARK may mean that the flow has been disassociated or
     * never associated. */
    if (OVS_UNLIKELY(mark == INVALID_FLOW_MARK)) {
        return EINVAL;
    }

    cmap_remove(&dp_offload_threads[tid].mark_to_flow,
                mark_node, hash_int(mark, 0));
    flow->mark = INVALID_FLOW_MARK;

    /*
     * no flow is referencing the mark any more? If so, let's
     * remove the flow from hardware and free the mark.
     */
    if (flow_mark_has_no_ref(mark)) {
        struct netdev *port;
        odp_port_t in_port = flow->flow.in_port.odp_port;

        port = netdev_ports_get(in_port, dpif_type_str);
        if (port) {
            /* Taking a global 'port_rwlock' to fulfill thread safety
             * restrictions regarding netdev port mapping. */
            ovs_rwlock_rdlock(&dp->port_rwlock);
            ret = netdev_flow_del(port, &flow->mega_ufid, NULL);
            ovs_rwlock_unlock(&dp->port_rwlock);
            netdev_close(port);
        }

        flow_mark_free(mark);
        VLOG_DBG("Freed flow mark %u mega_ufid "UUID_FMT, mark,
                 UUID_ARGS((struct uuid *) &flow->mega_ufid));

        megaflow_to_mark_disassociate(&flow->mega_ufid);
    }
    dp_netdev_flow_unref(flow);

    return ret;
}

static struct dp_netdev_flow *
mark_to_flow_find(const struct dp_netdev_pmd_thread *pmd,
                  const uint32_t mark)
{
    struct dp_netdev_flow *flow;
    unsigned int tid;
    size_t hash;

    if (dp_offload_threads == NULL) {
        return NULL;
    }

    hash = hash_int(mark, 0);
    for (tid = 0; tid < netdev_offload_thread_nb(); tid++) {
        CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash,
                                 &dp_offload_threads[tid].mark_to_flow) {
            if (flow->mark == mark && flow->pmd_id == pmd->core_id &&
                flow->dead == false) {
                return flow;
            }
        }
    }

    return NULL;
}

static struct dp_offload_thread_item *
dp_netdev_alloc_flow_offload(struct dp_netdev *dp,
                             struct dp_netdev_flow *flow,
                             int op)
{
    struct dp_offload_thread_item *item;
    struct dp_offload_flow_item *flow_offload;

    item = xzalloc(sizeof *item + sizeof *flow_offload);
    flow_offload = &item->data->flow;

    item->type = DP_OFFLOAD_FLOW;
    item->dp = dp;

    flow_offload->flow = flow;
    flow_offload->op = op;

    dp_netdev_flow_ref(flow);

    return item;
}

static void
dp_netdev_free_flow_offload__(struct dp_offload_thread_item *offload)
{
    struct dp_offload_flow_item *flow_offload = &offload->data->flow;

    free(flow_offload->actions);
    free(offload);
}

static void
dp_netdev_free_flow_offload(struct dp_offload_thread_item *offload)
{
    struct dp_offload_flow_item *flow_offload = &offload->data->flow;

    dp_netdev_flow_unref(flow_offload->flow);
    ovsrcu_postpone(dp_netdev_free_flow_offload__, offload);
}

static void
dp_netdev_free_offload(struct dp_offload_thread_item *offload)
{
    switch (offload->type) {
    case DP_OFFLOAD_FLOW:
        dp_netdev_free_flow_offload(offload);
        break;
    case DP_OFFLOAD_FLUSH:
        free(offload);
        break;
    default:
        OVS_NOT_REACHED();
    };
}

static void
dp_netdev_append_offload(struct dp_offload_thread_item *offload,
                         unsigned int tid)
{
    dp_netdev_offload_init();

    mpsc_queue_insert(&dp_offload_threads[tid].queue, &offload->node);
    atomic_count_inc64(&dp_offload_threads[tid].enqueued_item);
}

static void
dp_netdev_offload_flow_enqueue(struct dp_offload_thread_item *item)
{
    struct dp_offload_flow_item *flow_offload = &item->data->flow;
    unsigned int tid;

    ovs_assert(item->type == DP_OFFLOAD_FLOW);

    tid = netdev_offload_ufid_to_thread_id(flow_offload->flow->mega_ufid);
    dp_netdev_append_offload(item, tid);
}

static int
dp_netdev_flow_offload_del(struct dp_offload_thread_item *item)
{
    return mark_to_flow_disassociate(item->dp, item->data->flow.flow);
}

/*
 * There are two flow offload operations here: addition and modification.
 *
 * For flow addition, this function does:
 * - allocate a new flow mark id
 * - perform hardware flow offload
 * - associate the flow mark with flow and mega flow
 *
 * For flow modification, both flow mark and the associations are still
 * valid, thus only item 2 needed.
 */
static int
dp_netdev_flow_offload_put(struct dp_offload_thread_item *item)
{
    struct dp_offload_flow_item *offload = &item->data->flow;
    struct dp_netdev *dp = item->dp;
    struct dp_netdev_flow *flow = offload->flow;
    odp_port_t in_port = flow->flow.in_port.odp_port;
    const char *dpif_type_str = dpif_normalize_type(dp->class->type);
    bool modification = offload->op == DP_NETDEV_FLOW_OFFLOAD_OP_MOD
                        && flow->mark != INVALID_FLOW_MARK;
    struct offload_info info;
    struct netdev *port;
    uint32_t mark;
    int ret;

    if (flow->dead) {
        return -1;
    }

    if (modification) {
        mark = flow->mark;
    } else {
        /*
         * If a mega flow has already been offloaded (from other PMD
         * instances), do not offload it again.
         */
        mark = megaflow_to_mark_find(&flow->mega_ufid);
        if (mark != INVALID_FLOW_MARK) {
            VLOG_DBG("Flow has already been offloaded with mark %u\n", mark);
            if (flow->mark != INVALID_FLOW_MARK) {
                ovs_assert(flow->mark == mark);
            } else {
                mark_to_flow_associate(mark, flow);
            }
            return 0;
        }

        mark = flow_mark_alloc();
        if (mark == INVALID_FLOW_MARK) {
            VLOG_ERR("Failed to allocate flow mark!\n");
            return -1;
        }
    }
    info.flow_mark = mark;
    info.orig_in_port = offload->orig_in_port;

    port = netdev_ports_get(in_port, dpif_type_str);
    if (!port) {
        goto err_free;
    }

    /* Taking a global 'port_rwlock' to fulfill thread safety
     * restrictions regarding the netdev port mapping. */
    ovs_rwlock_rdlock(&dp->port_rwlock);
    ret = netdev_flow_put(port, &offload->match,
                          CONST_CAST(struct nlattr *, offload->actions),
                          offload->actions_len, &flow->mega_ufid, &info,
                          NULL);
    ovs_rwlock_unlock(&dp->port_rwlock);
    netdev_close(port);

    if (ret) {
        goto err_free;
    }

    if (!modification) {
        megaflow_to_mark_associate(&flow->mega_ufid, mark);
        mark_to_flow_associate(mark, flow);
    }
    return 0;

err_free:
    if (!modification) {
        flow_mark_free(mark);
    } else {
        mark_to_flow_disassociate(item->dp, flow);
    }
    return -1;
}

static void
dp_offload_flow(struct dp_offload_thread_item *item)
{
    struct dp_offload_flow_item *flow_offload = &item->data->flow;
    const char *op;
    int ret;

    switch (flow_offload->op) {
    case DP_NETDEV_FLOW_OFFLOAD_OP_ADD:
        op = "add";
        ret = dp_netdev_flow_offload_put(item);
        break;
    case DP_NETDEV_FLOW_OFFLOAD_OP_MOD:
        op = "modify";
        ret = dp_netdev_flow_offload_put(item);
        break;
    case DP_NETDEV_FLOW_OFFLOAD_OP_DEL:
        op = "delete";
        ret = dp_netdev_flow_offload_del(item);
        break;
    default:
        OVS_NOT_REACHED();
    }

    VLOG_DBG("%s to %s netdev flow "UUID_FMT,
             ret == 0 ? "succeed" : "failed", op,
             UUID_ARGS((struct uuid *) &flow_offload->flow->mega_ufid));
}

static void
dp_offload_flush(struct dp_offload_thread_item *item)
{
    struct dp_offload_flush_item *flush = &item->data->flush;

    ovs_rwlock_rdlock(&item->dp->port_rwlock);
    netdev_flow_flush(flush->netdev);
    ovs_rwlock_unlock(&item->dp->port_rwlock);

    ovs_barrier_block(flush->barrier);

    /* Allow the initiator thread to take again the port lock,
     * before continuing offload operations in this thread.
     */
    ovs_barrier_block(flush->barrier);
}

#define DP_NETDEV_OFFLOAD_BACKOFF_MIN 1
#define DP_NETDEV_OFFLOAD_BACKOFF_MAX 64
#define DP_NETDEV_OFFLOAD_QUIESCE_INTERVAL_US (10 * 1000) /* 10 ms */

static void *
dp_netdev_flow_offload_main(void *arg)
{
    struct dp_offload_thread *ofl_thread = arg;
    struct dp_offload_thread_item *offload;
    struct mpsc_queue_node *node;
    struct mpsc_queue *queue;
    long long int latency_us;
    long long int next_rcu;
    long long int now;
    uint64_t backoff;

    queue = &ofl_thread->queue;
    mpsc_queue_acquire(queue);

    while (true) {
        backoff = DP_NETDEV_OFFLOAD_BACKOFF_MIN;
        while (mpsc_queue_tail(queue) == NULL) {
            xnanosleep(backoff * 1E6);
            if (backoff < DP_NETDEV_OFFLOAD_BACKOFF_MAX) {
                backoff <<= 1;
            }
        }

        next_rcu = time_usec() + DP_NETDEV_OFFLOAD_QUIESCE_INTERVAL_US;
        MPSC_QUEUE_FOR_EACH_POP (node, queue) {
            offload = CONTAINER_OF(node, struct dp_offload_thread_item, node);
            atomic_count_dec64(&ofl_thread->enqueued_item);

            switch (offload->type) {
            case DP_OFFLOAD_FLOW:
                dp_offload_flow(offload);
                break;
            case DP_OFFLOAD_FLUSH:
                dp_offload_flush(offload);
                break;
            default:
                OVS_NOT_REACHED();
            }

            now = time_usec();

            latency_us = now - offload->timestamp;
            mov_avg_cma_update(&ofl_thread->cma, latency_us);
            mov_avg_ema_update(&ofl_thread->ema, latency_us);

            dp_netdev_free_offload(offload);

            /* Do RCU synchronization at fixed interval. */
            if (now > next_rcu) {
                ovsrcu_quiesce();
                next_rcu = time_usec() + DP_NETDEV_OFFLOAD_QUIESCE_INTERVAL_US;
            }
        }
    }

    OVS_NOT_REACHED();
    mpsc_queue_release(queue);

    return NULL;
}

static void
queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd,
                      struct dp_netdev_flow *flow)
{
    struct dp_offload_thread_item *offload;

    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    offload = dp_netdev_alloc_flow_offload(pmd->dp, flow,
                                           DP_NETDEV_FLOW_OFFLOAD_OP_DEL);
    offload->timestamp = pmd->ctx.now;
    dp_netdev_offload_flow_enqueue(offload);
}

static void
log_netdev_flow_change(const struct dp_netdev_flow *flow,
                       const struct match *match,
                       const struct dp_netdev_actions *old_actions,
                       const struct nlattr *actions,
                       size_t actions_len)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct ofpbuf key_buf, mask_buf;
    struct odp_flow_key_parms odp_parms = {
        .flow = &match->flow,
        .mask = &match->wc.masks,
        .support = dp_netdev_support,
    };

    if (OVS_LIKELY(VLOG_DROP_DBG((&upcall_rl)))) {
        return;
    }

    ofpbuf_init(&key_buf, 0);
    ofpbuf_init(&mask_buf, 0);

    odp_flow_key_from_flow(&odp_parms, &key_buf);
    odp_parms.key_buf = &key_buf;
    odp_flow_key_from_mask(&odp_parms, &mask_buf);

    if (old_actions) {
        ds_put_cstr(&ds, "flow_mod: ");
    } else {
        ds_put_cstr(&ds, "flow_add: ");
    }
    odp_format_ufid(&flow->ufid, &ds);
    ds_put_cstr(&ds, " mega_");
    odp_format_ufid(&flow->mega_ufid, &ds);
    ds_put_cstr(&ds, " ");
    odp_flow_format(key_buf.data, key_buf.size,
                    mask_buf.data, mask_buf.size,
                    NULL, &ds, false, true);
    if (old_actions) {
        ds_put_cstr(&ds, ", old_actions:");
        format_odp_actions(&ds, old_actions->actions, old_actions->size,
                           NULL);
    }
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

static void
queue_netdev_flow_put(struct dp_netdev_pmd_thread *pmd,
                      struct dp_netdev_flow *flow, struct match *match,
                      const struct nlattr *actions, size_t actions_len,
                      int op)
{
    struct dp_offload_thread_item *item;
    struct dp_offload_flow_item *flow_offload;

    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    item = dp_netdev_alloc_flow_offload(pmd->dp, flow, op);
    flow_offload = &item->data->flow;
    flow_offload->match = *match;
    flow_offload->actions = xmalloc(actions_len);
    memcpy(flow_offload->actions, actions, actions_len);
    flow_offload->actions_len = actions_len;
    flow_offload->orig_in_port = flow->orig_in_port;

    item->timestamp = pmd->ctx.now;
    dp_netdev_offload_flow_enqueue(item);
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
    dp_netdev_simple_match_remove(pmd, flow);
    cmap_remove(&pmd->flow_table, node, dp_netdev_flow_hash(&flow->ufid));
    ccmap_dec(&pmd->n_flows, odp_to_u32(in_port));
    queue_netdev_flow_del(pmd, flow);
    flow->dead = true;

    dp_netdev_flow_unref(flow);
}

static void
dp_netdev_offload_flush_enqueue(struct dp_netdev *dp,
                                struct netdev *netdev,
                                struct ovs_barrier *barrier)
{
    unsigned int tid;
    long long int now_us = time_usec();

    for (tid = 0; tid < netdev_offload_thread_nb(); tid++) {
        struct dp_offload_thread_item *item;
        struct dp_offload_flush_item *flush;

        item = xmalloc(sizeof *item + sizeof *flush);
        item->type = DP_OFFLOAD_FLUSH;
        item->dp = dp;
        item->timestamp = now_us;

        flush = &item->data->flush;
        flush->netdev = netdev;
        flush->barrier = barrier;

        dp_netdev_append_offload(item, tid);
    }
}

/* Blocking call that will wait on the offload thread to
 * complete its work.  As the flush order will only be
 * enqueued after existing offload requests, those previous
 * offload requests must be processed, which requires being
 * able to lock the 'port_rwlock' from the offload thread.
 *
 * Flow offload flush is done when a port is being deleted.
 * Right after this call executes, the offload API is disabled
 * for the port. This call must be made blocking until the
 * offload provider completed its job.
 */
static void
dp_netdev_offload_flush(struct dp_netdev *dp,
                        struct dp_netdev_port *port)
    OVS_REQ_WRLOCK(dp->port_rwlock)
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
     * different barriers. Only allow a single flush order in the offload
     * queue at a time.
     */
    static struct ovs_mutex flush_mutex = OVS_MUTEX_INITIALIZER;
    static struct ovs_barrier barrier OVS_GUARDED_BY(flush_mutex);
    struct netdev *netdev;

    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    ovs_rwlock_unlock(&dp->port_rwlock);
    ovs_mutex_lock(&flush_mutex);

    /* This thread and the offload threads. */
    ovs_barrier_init(&barrier, 1 + netdev_offload_thread_nb());

    netdev = netdev_ref(port->netdev);
    dp_netdev_offload_flush_enqueue(dp, netdev, &barrier);
    ovs_barrier_block(&barrier);
    netdev_close(netdev);

    /* Take back the datapath port lock before allowing the offload
     * threads to proceed further. The port deletion must complete first,
     * to ensure no further offloads are inserted after the flush.
     *
     * Some offload provider (e.g. DPDK) keeps a netdev reference with
     * the offload data. If this reference is not closed, the netdev is
     * kept indefinitely. */
    ovs_rwlock_wrlock(&dp->port_rwlock);

    ovs_barrier_block(&barrier);
    ovs_barrier_destroy(&barrier);

    ovs_mutex_unlock(&flush_mutex);
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

    ovs_rwlock_rdlock(&dp->port_rwlock);
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

static inline bool
netdev_flow_key_equal(const struct netdev_flow_key *a,
                      const struct netdev_flow_key *b)
{
    /* 'b->len' may be not set yet. */
    return a->hash == b->hash && !memcmp(&a->mf, &b->mf, a->len);
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

/* Initializes 'key' as a copy of 'flow'. */
static inline void
netdev_flow_key_init(struct netdev_flow_key *key,
                     const struct flow *flow)
{
    uint32_t hash = 0;
    uint64_t value;

    miniflow_map_init(&key->mf, flow);
    miniflow_init(&key->mf, flow);

    size_t n = miniflow_n_values(&key->mf);

    FLOW_FOR_EACH_IN_MAPS (value, flow, key->mf.map) {
        hash = hash_add64(hash, value);
    }

    key->hash = hash_finish(hash, n * 8);
    key->len = netdev_flow_key_size(n);
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

    uint32_t min = pmd->ctx.emc_insert_min;

    if (min && random_uint32() <= min) {
        emc_insert(&(pmd->flow_cache).emc_cache, key, flow);
    }
}

static inline const struct cmap_node *
smc_entry_get(struct dp_netdev_pmd_thread *pmd, const uint32_t hash)
{
    struct smc_cache *cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &cache->buckets[hash & SMC_MASK];
    uint16_t sig = hash >> 16;
    uint16_t index = UINT16_MAX;

    for (int i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->sig[i] == sig) {
            index = bucket->flow_idx[i];
            break;
        }
    }
    if (index != UINT16_MAX) {
        return cmap_find_by_index(&pmd->flow_table, index);
    }
    return NULL;
}

/* Insert the flow_table index into SMC. Insertion may fail when 1) SMC is
 * turned off, 2) the flow_table index is larger than uint16_t can handle.
 * If there is already an SMC entry having same signature, the index will be
 * updated. If there is no existing entry, but an empty entry is available,
 * the empty entry will be taken. If no empty entry or existing same signature,
 * a random entry from the hashed bucket will be picked. */
static inline void
smc_insert(struct dp_netdev_pmd_thread *pmd,
           const struct netdev_flow_key *key,
           uint32_t hash)
{
    struct smc_cache *smc_cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &smc_cache->buckets[key->hash & SMC_MASK];
    uint16_t index;
    uint32_t cmap_index;
    int i;

    if (!pmd->ctx.smc_enable_db) {
        return;
    }

    cmap_index = cmap_find_index(&pmd->flow_table, hash);
    index = (cmap_index >= UINT16_MAX) ? UINT16_MAX : (uint16_t)cmap_index;

    /* If the index is larger than SMC can handle (uint16_t), we don't
     * insert */
    if (index == UINT16_MAX) {
        return;
    }

    /* If an entry with same signature already exists, update the index */
    uint16_t sig = key->hash >> 16;
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->sig[i] == sig) {
            bucket->flow_idx[i] = index;
            return;
        }
    }
    /* If there is an empty entry, occupy it. */
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->flow_idx[i] == UINT16_MAX) {
            bucket->sig[i] = sig;
            bucket->flow_idx[i] = index;
            return;
        }
    }
    /* Otherwise, pick a random entry. */
    i = random_uint32() % SMC_ENTRY_PER_BUCKET;
    bucket->sig[i] = sig;
    bucket->flow_idx[i] = index;
}

inline void
emc_probabilistic_insert_batch(struct dp_netdev_pmd_thread *pmd,
                               const struct netdev_flow_key *keys,
                               struct dpcls_rule **rules,
                               uint32_t emc_insert_mask)
{
    while (emc_insert_mask) {
        uint32_t i = raw_ctz(emc_insert_mask);
        emc_insert_mask &= emc_insert_mask - 1;
        /* Get the require parameters for EMC/SMC from the rule */
        struct dp_netdev_flow *flow = dp_netdev_flow_cast(rules[i]);
        /* Insert the key into EMC/SMC. */
        emc_probabilistic_insert(pmd, &keys[i], flow);
    }
}

inline void
smc_insert_batch(struct dp_netdev_pmd_thread *pmd,
                 const struct netdev_flow_key *keys,
                 struct dpcls_rule **rules,
                 uint32_t smc_insert_mask)
{
    while (smc_insert_mask) {
        uint32_t i = raw_ctz(smc_insert_mask);
        smc_insert_mask &= smc_insert_mask - 1;
        /* Get the require parameters for EMC/SMC from the rule */
        struct dp_netdev_flow *flow = dp_netdev_flow_cast(rules[i]);
        uint32_t hash = dp_netdev_flow_hash(&flow->ufid);
        /* Insert the key into EMC/SMC. */
        smc_insert(pmd, &keys[i], hash);
    }
}

static struct dp_netdev_flow *
dp_netdev_pmd_lookup_flow(struct dp_netdev_pmd_thread *pmd,
                          const struct netdev_flow_key *key,
                          int *lookup_num_p)
{
    struct dpcls *cls;
    struct dpcls_rule *rule = NULL;
    odp_port_t in_port = u32_to_odp(MINIFLOW_GET_U32(&key->mf,
                                                     in_port.odp_port));
    struct dp_netdev_flow *netdev_flow = NULL;

    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        dpcls_lookup(cls, &key, &rule, 1, lookup_num_p);
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
        odp_flow_key_hash(&flow, sizeof flow, &ufid);
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
dp_netdev_flow_set_last_stats_attrs(struct dp_netdev_flow *netdev_flow,
                                    const struct dpif_flow_stats *stats,
                                    const struct dpif_flow_attrs *attrs,
                                    int result)
{
    struct dp_netdev_flow_stats *last_stats = &netdev_flow->last_stats;
    struct dp_netdev_flow_attrs *last_attrs = &netdev_flow->last_attrs;

    atomic_store_relaxed(&netdev_flow->netdev_flow_get_result, result);
    if (result) {
        return;
    }

    atomic_store_relaxed(&last_stats->used,         stats->used);
    atomic_store_relaxed(&last_stats->packet_count, stats->n_packets);
    atomic_store_relaxed(&last_stats->byte_count,   stats->n_bytes);
    atomic_store_relaxed(&last_stats->tcp_flags,    stats->tcp_flags);

    atomic_store_relaxed(&last_attrs->offloaded,    attrs->offloaded);
    atomic_store_relaxed(&last_attrs->dp_layer,     attrs->dp_layer);

}

static void
dp_netdev_flow_get_last_stats_attrs(struct dp_netdev_flow *netdev_flow,
                                    struct dpif_flow_stats *stats,
                                    struct dpif_flow_attrs *attrs,
                                    int *result)
{
    struct dp_netdev_flow_stats *last_stats = &netdev_flow->last_stats;
    struct dp_netdev_flow_attrs *last_attrs = &netdev_flow->last_attrs;

    atomic_read_relaxed(&netdev_flow->netdev_flow_get_result, result);
    if (*result) {
        return;
    }

    atomic_read_relaxed(&last_stats->used,         &stats->used);
    atomic_read_relaxed(&last_stats->packet_count, &stats->n_packets);
    atomic_read_relaxed(&last_stats->byte_count,   &stats->n_bytes);
    atomic_read_relaxed(&last_stats->tcp_flags,    &stats->tcp_flags);

    atomic_read_relaxed(&last_attrs->offloaded,    &attrs->offloaded);
    atomic_read_relaxed(&last_attrs->dp_layer,     &attrs->dp_layer);
}

static bool
dpif_netdev_get_flow_offload_status(const struct dp_netdev *dp,
                                    struct dp_netdev_flow *netdev_flow,
                                    struct dpif_flow_stats *stats,
                                    struct dpif_flow_attrs *attrs)
{
    uint64_t act_buf[1024 / 8];
    struct nlattr *actions;
    struct netdev *netdev;
    struct match match;
    struct ofpbuf buf;

    int ret = 0;

    if (!netdev_is_flow_api_enabled()) {
        return false;
    }

    netdev = netdev_ports_get(netdev_flow->flow.in_port.odp_port,
                              dpif_normalize_type(dp->class->type));
    if (!netdev) {
        return false;
    }
    ofpbuf_use_stack(&buf, &act_buf, sizeof act_buf);
    /* Taking a global 'port_rwlock' to fulfill thread safety
     * restrictions regarding netdev port mapping.
     *
     * XXX: Main thread will try to pause/stop all revalidators during datapath
     *      reconfiguration via datapath purge callback (dp_purge_cb) while
     *      rw-holding 'dp->port_rwlock'.  So we're not waiting for lock here.
     *      Otherwise, deadlock is possible, because revalidators might sleep
     *      waiting for the main thread to release the lock and main thread
     *      will wait for them to stop processing.
     *      This workaround might make statistics less accurate. Especially
     *      for flow deletion case, since there will be no other attempt.  */
    if (!ovs_rwlock_tryrdlock(&dp->port_rwlock)) {
        ret = netdev_flow_get(netdev, &match, &actions,
                              &netdev_flow->mega_ufid, stats, attrs, &buf);
        /* Storing statistics and attributes from the last request for
         * later use on mutex contention. */
        dp_netdev_flow_set_last_stats_attrs(netdev_flow, stats, attrs, ret);
        ovs_rwlock_unlock(&dp->port_rwlock);
    } else {
        dp_netdev_flow_get_last_stats_attrs(netdev_flow, stats, attrs, &ret);
        if (!ret && !attrs->dp_layer) {
            /* Flow was never reported as 'offloaded' so it's harmless
             * to continue to think so. */
            ret = EAGAIN;
        }
    }
    netdev_close(netdev);
    if (ret) {
        return false;
    }

    return true;
}

static void
get_dpif_flow_status(const struct dp_netdev *dp,
                     const struct dp_netdev_flow *netdev_flow_,
                     struct dpif_flow_stats *stats,
                     struct dpif_flow_attrs *attrs)
{
    struct dpif_flow_stats offload_stats;
    struct dpif_flow_attrs offload_attrs;
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

    if (dpif_netdev_get_flow_offload_status(dp, netdev_flow,
                                            &offload_stats, &offload_attrs)) {
        stats->n_packets += offload_stats.n_packets;
        stats->n_bytes += offload_stats.n_bytes;
        stats->used = MAX(stats->used, offload_stats.used);
        stats->tcp_flags |= offload_stats.tcp_flags;
        if (attrs) {
            attrs->offloaded = offload_attrs.offloaded;
            attrs->dp_layer = offload_attrs.dp_layer;
        }
    } else if (attrs) {
        attrs->offloaded = false;
        attrs->dp_layer = "ovs";
    }
}

/* Converts to the dpif_flow format, using 'key_buf' and 'mask_buf' for
 * storing the netlink-formatted key/mask. 'key_buf' may be the same as
 * 'mask_buf'. Actions will be returned without copying, by relying on RCU to
 * protect them. */
static void
dp_netdev_flow_to_dpif_flow(const struct dp_netdev *dp,
                            const struct dp_netdev_flow *netdev_flow,
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

    get_dpif_flow_status(dp, netdev_flow, &flow->stats, &flow->attrs);
    flow->attrs.dp_extra_info = netdev_flow->dp_extra_info;
}

static int
dpif_netdev_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow_wildcards *wc, bool probe)
{
    enum odp_key_fitness fitness;

    fitness = odp_flow_key_to_mask(mask_key, mask_key_len, wc, flow, NULL);
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
                                true, true);
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
    if (odp_flow_key_to_flow(key, key_len, flow, NULL)) {
        if (!probe) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_flow() and odp_flow_key_to_flow() disagree on
             * the acceptable form of a flow.  Log the problem as an error,
             * with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, NULL, 0, NULL, &s, true, false);
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
            dp_netdev_flow_to_dpif_flow(dp, netdev_flow, get->buffer,
                                        get->buffer, get->flow, false);
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

static void
dp_netdev_get_mega_ufid(const struct match *match, ovs_u128 *mega_ufid)
{
    struct flow masked_flow;
    size_t i;

    for (i = 0; i < sizeof(struct flow); i++) {
        ((uint8_t *)&masked_flow)[i] = ((uint8_t *)&match->flow)[i] &
                                       ((uint8_t *)&match->wc)[i];
    }
    odp_flow_key_hash(&masked_flow, sizeof masked_flow, mega_ufid);
}

uint64_t
dp_netdev_simple_match_mark(odp_port_t in_port, ovs_be16 dl_type,
                            uint8_t nw_frag, ovs_be16 vlan_tci)
{
    /* Simple Match Mark:
     *
     * BE:
     * +-----------------+-------------++---------+---+-----------+
     * |     in_port     |   dl_type   || nw_frag |CFI|  VID(12)  |
     * +-----------------+-------------++---------+---+-----------+
     * 0                 32          47 49         51  52     63
     *
     * LE:
     * +-----------------+-------------+------++-------+---+------+
     * |     in_port     |   dl_type   |VID(8)||nw_frag|CFI|VID(4)|
     * +-----------------+-------------+------++-------+---+------+
     * 0                 32          47 48  55  57   59 60  61   63
     *
     *         Big Endian              Little Endian
     * in_port : 32 bits [ 0..31]  in_port : 32 bits [ 0..31]
     * dl_type : 16 bits [32..47]  dl_type : 16 bits [32..47]
     * <empty> :  1 bit  [48..48]  vlan VID:  8 bits [48..55]
     * nw_frag :  2 bits [49..50]  <empty> :  1 bit  [56..56]
     * vlan CFI:  1 bit  [51..51]  nw_frag :  2 bits [57..59]
     * vlan VID: 12 bits [52..63]  vlan CFI:  1 bit  [60..60]
     *                             vlan VID:  4 bits [61..63]
     *
     * Layout is different for LE and BE in order to save a couple of
     * network to host translations.
     * */
    return ((uint64_t) odp_to_u32(in_port) << 32)
           | ((OVS_FORCE uint32_t) dl_type << 16)
#if WORDS_BIGENDIAN
           | (((uint16_t) nw_frag & FLOW_NW_FRAG_MASK) << VLAN_PCP_SHIFT)
#else
           | ((nw_frag & FLOW_NW_FRAG_MASK) << (VLAN_PCP_SHIFT - 8))
#endif
           | (OVS_FORCE uint16_t) (vlan_tci & htons(VLAN_VID_MASK | VLAN_CFI));
}

struct dp_netdev_flow *
dp_netdev_simple_match_lookup(const struct dp_netdev_pmd_thread *pmd,
                              odp_port_t in_port, ovs_be16 dl_type,
                              uint8_t nw_frag, ovs_be16 vlan_tci)
{
    uint64_t mark = dp_netdev_simple_match_mark(in_port, dl_type,
                                                nw_frag, vlan_tci);
    uint32_t hash = hash_uint64(mark);
    struct dp_netdev_flow *flow;
    bool found = false;

    CMAP_FOR_EACH_WITH_HASH (flow, simple_match_node,
                             hash, &pmd->simple_match_table) {
        if (flow->simple_match_mark == mark) {
            found = true;
            break;
        }
    }
    return found ? flow : NULL;
}

bool
dp_netdev_simple_match_enabled(const struct dp_netdev_pmd_thread *pmd,
                               odp_port_t in_port)
{
    return ccmap_find(&pmd->n_flows, odp_to_u32(in_port))
           == ccmap_find(&pmd->n_simple_flows, odp_to_u32(in_port));
}

static void
dp_netdev_simple_match_insert(struct dp_netdev_pmd_thread *pmd,
                              struct dp_netdev_flow *dp_flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    odp_port_t in_port = dp_flow->flow.in_port.odp_port;
    ovs_be16 vlan_tci = dp_flow->flow.vlans[0].tci;
    ovs_be16 dl_type = dp_flow->flow.dl_type;
    uint8_t nw_frag = dp_flow->flow.nw_frag;

    if (!dp_netdev_flow_ref(dp_flow)) {
        return;
    }

    /* Avoid double insertion.  Should not happen in practice. */
    dp_netdev_simple_match_remove(pmd, dp_flow);

    uint64_t mark = dp_netdev_simple_match_mark(in_port, dl_type,
                                                nw_frag, vlan_tci);
    uint32_t hash = hash_uint64(mark);

    dp_flow->simple_match_mark = mark;
    cmap_insert(&pmd->simple_match_table,
                CONST_CAST(struct cmap_node *, &dp_flow->simple_match_node),
                hash);
    ccmap_inc(&pmd->n_simple_flows, odp_to_u32(in_port));

    VLOG_DBG("Simple match insert: "
             "core_id(%d),in_port(%"PRIu32"),mark(0x%016"PRIx64").",
             pmd->core_id, in_port, mark);
}

static void
dp_netdev_simple_match_remove(struct dp_netdev_pmd_thread *pmd,
                               struct dp_netdev_flow *dp_flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    odp_port_t in_port = dp_flow->flow.in_port.odp_port;
    ovs_be16 vlan_tci = dp_flow->flow.vlans[0].tci;
    ovs_be16 dl_type = dp_flow->flow.dl_type;
    uint8_t nw_frag = dp_flow->flow.nw_frag;
    struct dp_netdev_flow *flow;
    uint64_t mark = dp_netdev_simple_match_mark(in_port, dl_type,
                                                nw_frag, vlan_tci);
    uint32_t hash = hash_uint64(mark);

    flow = dp_netdev_simple_match_lookup(pmd, in_port, dl_type,
                                         nw_frag, vlan_tci);
    if (flow == dp_flow) {
        VLOG_DBG("Simple match remove: "
                 "core_id(%d),in_port(%"PRIu32"),mark(0x%016"PRIx64").",
                 pmd->core_id, in_port, mark);
        cmap_remove(&pmd->simple_match_table,
                    CONST_CAST(struct cmap_node *, &flow->simple_match_node),
                    hash);
        ccmap_dec(&pmd->n_simple_flows, odp_to_u32(in_port));
        dp_netdev_flow_unref(flow);
    }
}

static bool
dp_netdev_flow_is_simple_match(const struct match *match)
{
    const struct flow *flow = &match->flow;
    const struct flow_wildcards *wc = &match->wc;

    if (flow->recirc_id || flow->packet_type != htonl(PT_ETH)) {
        return false;
    }

    /* Check that flow matches only minimal set of fields that always set.
     * Also checking that VLAN VID+CFI is an exact match, because these
     * are not mandatory and could be masked. */
    struct flow_wildcards *minimal = xmalloc(sizeof *minimal);
    ovs_be16 vlan_tci_mask = htons(VLAN_VID_MASK | VLAN_CFI);

    flow_wildcards_init_catchall(minimal);
    /* 'dpif-netdev' always has following in exact match:
     *   - recirc_id                   <-- recirc_id == 0 checked on input.
     *   - in_port                     <-- Will be checked on input.
     *   - packet_type                 <-- Assuming all packets are PT_ETH.
     *   - dl_type                     <-- Need to match with.
     *   - vlan_tci                    <-- Need to match with.
     *   - and nw_frag for ip packets. <-- Need to match with.
     */
    WC_MASK_FIELD(minimal, recirc_id);
    WC_MASK_FIELD(minimal, in_port);
    WC_MASK_FIELD(minimal, packet_type);
    WC_MASK_FIELD(minimal, dl_type);
    WC_MASK_FIELD_MASK(minimal, vlans[0].tci, vlan_tci_mask);
    WC_MASK_FIELD_MASK(minimal, nw_frag, FLOW_NW_FRAG_MASK);

    if (flow_wildcards_has_extra(minimal, wc)
        || wc->masks.vlans[0].tci != vlan_tci_mask) {
        free(minimal);
        return false;
    }
    free(minimal);

    return true;
}

static struct dp_netdev_flow *
dp_netdev_flow_add(struct dp_netdev_pmd_thread *pmd,
                   struct match *match, const ovs_u128 *ufid,
                   const struct nlattr *actions, size_t actions_len,
                   odp_port_t orig_in_port)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct ds extra_info = DS_EMPTY_INITIALIZER;
    struct dp_netdev_flow *flow;
    struct netdev_flow_key mask;
    struct dpcls *cls;
    size_t unit;

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
    atomic_init(&flow->netdev_flow_get_result, 0);
    memset(&flow->last_stats, 0, sizeof flow->last_stats);
    memset(&flow->last_attrs, 0, sizeof flow->last_attrs);
    flow->dead = false;
    flow->batch = NULL;
    flow->mark = INVALID_FLOW_MARK;
    flow->orig_in_port = orig_in_port;
    *CONST_CAST(unsigned *, &flow->pmd_id) = pmd->core_id;
    *CONST_CAST(struct flow *, &flow->flow) = match->flow;
    *CONST_CAST(ovs_u128 *, &flow->ufid) = *ufid;
    ovs_refcount_init(&flow->ref_cnt);
    ovsrcu_set(&flow->actions, dp_netdev_actions_create(actions, actions_len));

    dp_netdev_get_mega_ufid(match, CONST_CAST(ovs_u128 *, &flow->mega_ufid));
    netdev_flow_key_init_masked(&flow->cr.flow, &match->flow, &mask);

    /* Select dpcls for in_port. Relies on in_port to be exact match. */
    cls = dp_netdev_pmd_find_dpcls(pmd, in_port);
    dpcls_insert(cls, &flow->cr, &mask);

    ds_put_cstr(&extra_info, "miniflow_bits(");
    FLOWMAP_FOR_EACH_UNIT (unit) {
        if (unit) {
            ds_put_char(&extra_info, ',');
        }
        ds_put_format(&extra_info, "%d",
                      count_1bits(flow->cr.mask->mf.map.bits[unit]));
    }
    ds_put_char(&extra_info, ')');
    flow->dp_extra_info = ds_steal_cstr(&extra_info);
    ds_destroy(&extra_info);

    cmap_insert(&pmd->flow_table, CONST_CAST(struct cmap_node *, &flow->node),
                dp_netdev_flow_hash(&flow->ufid));
    ccmap_inc(&pmd->n_flows, odp_to_u32(in_port));

    if (dp_netdev_flow_is_simple_match(match)) {
        dp_netdev_simple_match_insert(pmd, flow);
    }

    queue_netdev_flow_put(pmd, flow, match, actions, actions_len,
                          DP_NETDEV_FLOW_OFFLOAD_OP_ADD);
    log_netdev_flow_change(flow, match, NULL, actions, actions_len);

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
    struct dp_netdev_flow *netdev_flow = NULL;
    int error = 0;

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }

    ovs_mutex_lock(&pmd->flow_mutex);
    if (put->ufid) {
        netdev_flow = dp_netdev_pmd_find_flow(pmd, put->ufid,
                                              put->key, put->key_len);
    } else {
        /* Use key instead of the locally generated ufid
         * to search netdev_flow. */
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
    }

    if (put->flags & DPIF_FP_CREATE) {
        if (!netdev_flow) {
            dp_netdev_flow_add(pmd, match, ufid,
                               put->actions, put->actions_len, ODPP_NONE);
        } else {
            error = EEXIST;
        }
        goto exit;
    }

    if (put->flags & DPIF_FP_MODIFY) {
        if (!netdev_flow) {
            error = ENOENT;
        } else {
            if (!put->ufid && !flow_equal(&match->flow, &netdev_flow->flow)) {
                /* Overlapping flow. */
                error = EINVAL;
                goto exit;
            }

            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions,
                                                   put->actions_len);

            old_actions = dp_netdev_flow_get_actions(netdev_flow);
            ovsrcu_set(&netdev_flow->actions, new_actions);

            queue_netdev_flow_put(pmd, netdev_flow, match,
                                  put->actions, put->actions_len,
                                  DP_NETDEV_FLOW_OFFLOAD_OP_MOD);
            log_netdev_flow_change(netdev_flow, match, old_actions,
                                   put->actions, put->actions_len);

            if (stats) {
                get_dpif_flow_status(pmd->dp, netdev_flow, stats, NULL);
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
        }
    }

exit:
    ovs_mutex_unlock(&pmd->flow_mutex);
    return error;
}

static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct netdev_flow_key key;
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

    if (match.wc.masks.in_port.odp_port != ODPP_NONE) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_ERR_RL(&rl, "failed to put%s flow: in_port is not an exact match",
                    (put->flags & DPIF_FP_CREATE) ? "[create]"
                    : (put->flags & DPIF_FP_MODIFY) ? "[modify]" : "[zero]");
        return EINVAL;
    }

    if (put->ufid) {
        ufid = *put->ufid;
    } else {
        odp_flow_key_hash(&match.flow, sizeof match.flow, &ufid);
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in handle_packet_upcall(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(VLAN_VID_MASK | VLAN_CFI);
    }

    /* Must produce a netdev_flow_key for lookup.
     * Use the same method as employed to create the key when adding
     * the flow to the dplcs to make sure they match.
     * We need to put in the unmasked key as flow_put_on_pmd() will first try
     * to see if an entry exists doing a packet type lookup. As masked-out
     * fields are interpreted as zeros, they could falsely match a wider IP
     * address mask. Installation of the flow will use the match variable. */
    netdev_flow_key_init(&key, &match.flow);

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
            get_dpif_flow_status(pmd->dp, netdev_flow, stats, NULL);
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
                             struct dpif_flow_dump_types *types OVS_UNUSED)
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
    struct dpif_netdev *dpif = dpif_netdev_cast(thread->up.dpif);
    struct dp_netdev *dp = get_dp_netdev(&dpif->dpif);
    int n_flows = 0;
    int i;

    ovs_mutex_lock(&dump->mutex);
    if (!dump->status) {
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
        dp_netdev_flow_to_dpif_flow(dp, netdev_flow, &key, &mask, f,
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

    /* Update current time in PMD context. We don't care about EMC insertion
     * probability, because we are on a slow path. */
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

    /* Making a copy because the packet might be stolen during the execution
     * and caller might still need it.  */
    struct dp_packet *packet_clone = dp_packet_clone(execute->packet);
    dp_packet_batch_init_packet(&pp, packet_clone);
    dp_netdev_execute_actions(pmd, &pp, false, execute->flow,
                              execute->actions, execute->actions_len);
    dp_netdev_pmd_flush_output_packets(pmd, true);

    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_unlock(&dp->non_pmd_mutex);
        dp_netdev_pmd_unref(pmd);
    }

    if (dp_packet_batch_size(&pp) == 1) {
        /* Packet wasn't dropped during the execution.  Swapping content with
         * the original packet, because the caller might expect actions to
         * modify it.  Uisng the packet from a batch instead of 'packet_clone'
         * because it maybe stolen and replaced by other packet, e.g. by
         * the fragmentation engine. */
        dp_packet_swap(execute->packet, pp.packets[0]);
        dp_packet_delete_batch(&pp, true);
    } else if (dp_packet_batch_size(&pp)) {
        /* FIXME: We have more packets than expected.  Likely, we got IP
         * fragments of the reassembled packet.  Dropping them here as we have
         * no way to get them to the caller.  It might be that all the required
         * actions with them are already executed, but it also might not be a
         * case, e.g. if dpif_netdev_execute() called to execute a single
         * tunnel push. */
        dp_packet_delete_batch(&pp, true);
    }

    return 0;
}

static void
dpif_netdev_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                    enum dpif_offload_type offload_type OVS_UNUSED)
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

static int
dpif_netdev_offload_stats_get(struct dpif *dpif,
                              struct netdev_custom_stats *stats)
{
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
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    unsigned int nb_thread;
    uint64_t *port_nb_offloads;
    uint64_t *nb_offloads;
    unsigned int tid;
    size_t i;

    if (!netdev_is_flow_api_enabled()) {
        return EINVAL;
    }

    nb_thread = netdev_offload_thread_nb();
    if (!nb_thread) {
        return EINVAL;
    }

    /* nb_thread counters for the overall total as well. */
    stats->size = ARRAY_SIZE(hwol_stats) * (nb_thread + 1);
    stats->counters = xcalloc(stats->size, sizeof *stats->counters);

    nb_offloads = xcalloc(nb_thread, sizeof *nb_offloads);
    port_nb_offloads = xcalloc(nb_thread, sizeof *port_nb_offloads);

    ovs_rwlock_rdlock(&dp->port_rwlock);
    HMAP_FOR_EACH (port, node, &dp->ports) {
        memset(port_nb_offloads, 0, nb_thread * sizeof *port_nb_offloads);
        /* Do not abort on read error from a port, just report 0. */
        if (!netdev_flow_get_n_flows(port->netdev, port_nb_offloads)) {
            for (i = 0; i < nb_thread; i++) {
                nb_offloads[i] += port_nb_offloads[i];
            }
        }
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    free(port_nb_offloads);

    for (tid = 0; tid < nb_thread; tid++) {
        uint64_t counts[ARRAY_SIZE(hwol_stats)];
        size_t idx = ((tid + 1) * ARRAY_SIZE(hwol_stats));

        memset(counts, 0, sizeof counts);
        counts[DP_NETDEV_HW_OFFLOADS_STATS_INSERTED] = nb_offloads[tid];
        if (dp_offload_threads != NULL) {
            atomic_read_relaxed(&dp_offload_threads[tid].enqueued_item,
                                &counts[DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED]);

            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN] =
                mov_avg_cma(&dp_offload_threads[tid].cma);
            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV] =
                mov_avg_cma_std_dev(&dp_offload_threads[tid].cma);

            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN] =
                mov_avg_ema(&dp_offload_threads[tid].ema);
            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV] =
                mov_avg_ema_std_dev(&dp_offload_threads[tid].ema);
        }

        for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
            snprintf(stats->counters[idx + i].name,
                     sizeof(stats->counters[idx + i].name),
                     "  [%3u] %s", tid, hwol_stats[i].name);
            stats->counters[idx + i].value = counts[i];
            hwol_stats[i].total += counts[i];
        }
    }

    free(nb_offloads);

    /* Do an average of the average for the aggregate. */
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV].total /= nb_thread;

    for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
        snprintf(stats->counters[i].name, sizeof(stats->counters[i].name),
                 "  Total %s", hwol_stats[i].name);
        stats->counters[i].value = hwol_stats[i].total;
    }

    return 0;
}

/* Enable or Disable PMD auto load balancing. */
static void
set_pmd_auto_lb(struct dp_netdev *dp, bool state, bool always_log)
{
    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;

    if (pmd_alb->is_enabled != state || always_log) {
        pmd_alb->is_enabled = state;
        if (pmd_alb->is_enabled) {
            uint8_t rebalance_load_thresh;

            atomic_read_relaxed(&pmd_alb->rebalance_load_thresh,
                                &rebalance_load_thresh);
            VLOG_INFO("PMD auto load balance is enabled, "
                      "interval %"PRIu64" mins, "
                      "pmd load threshold %"PRIu8"%%, "
                      "improvement threshold %"PRIu8"%%.",
                       pmd_alb->rebalance_intvl / MIN_TO_MSEC,
                       rebalance_load_thresh,
                       pmd_alb->rebalance_improve_thresh);
        } else {
            pmd_alb->rebalance_poll_timer = 0;
            VLOG_INFO("PMD auto load balance is disabled.");
        }
    }
}

static int
parse_pmd_sleep_list(const char *max_sleep_list,
                     struct pmd_sleep **pmd_sleeps)
{
    char *list, *copy, *key, *value;
    int num_vals = 0;

    if (!max_sleep_list) {
        return num_vals;
    }

    list = copy = xstrdup(max_sleep_list);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        uint64_t temp, pmd_max_sleep;
        char *error = NULL;
        unsigned core;
        int i;

        error = str_to_u64(key, &temp);
        if (error) {
            free(error);
            continue;
        }

        if (value[0] == '\0') {
            /* No value specified. key is dp default. */
            core = UINT_MAX;
            pmd_max_sleep = temp;
        } else {
            error = str_to_u64(value, &pmd_max_sleep);
            if (!error && temp < UINT_MAX) {
                /* Key is pmd core id. */
                core = (unsigned) temp;
            } else {
                free(error);
                continue;
            }
        }

        /* Detect duplicate max sleep values. */
        for (i = 0; i < num_vals; i++) {
            if ((*pmd_sleeps)[i].core_id == core) {
                break;
            }
        }
        if (i == num_vals) {
            /* Not duplicate, add a new entry. */
            *pmd_sleeps = xrealloc(*pmd_sleeps,
                                   (num_vals + 1) * sizeof **pmd_sleeps);
            num_vals++;
        }

        pmd_max_sleep = MIN(PMD_RCU_QUIESCE_INTERVAL, pmd_max_sleep);

        (*pmd_sleeps)[i].core_id = core;
        (*pmd_sleeps)[i].max_sleep = pmd_max_sleep;
    }

    free(copy);
    return num_vals;
}

static void
log_pmd_sleep(unsigned core_id, int numa_id, uint64_t pmd_max_sleep)
{
    if (core_id == NON_PMD_CORE_ID) {
        return;
    }
    VLOG_INFO("PMD thread on numa_id: %d, core id: %2d, "
              "max sleep: %4"PRIu64" us.", numa_id, core_id, pmd_max_sleep);
}

static void
pmd_init_max_sleep(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
{
    uint64_t max_sleep = dp->pmd_max_sleep_default;
    struct pmd_sleep *pmd_sleeps = NULL;
    int num_vals;

    num_vals = parse_pmd_sleep_list(dp->max_sleep_list, &pmd_sleeps);

    /* Check if the user has set a specific value for this pmd. */
    for (int i = 0; i < num_vals; i++) {
        if (pmd_sleeps[i].core_id == pmd->core_id) {
            max_sleep = pmd_sleeps[i].max_sleep;
            break;
        }
    }
    atomic_init(&pmd->max_sleep, max_sleep);
    log_pmd_sleep(pmd->core_id, pmd->numa_id, max_sleep);
    free(pmd_sleeps);
}

static bool
assign_sleep_values_to_pmds(struct dp_netdev *dp, int num_vals,
                            struct pmd_sleep *pmd_sleeps)
{
    struct dp_netdev_pmd_thread *pmd;
    bool value_changed = false;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        uint64_t new_max_sleep, cur_pmd_max_sleep;

        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }

        /* Default to global value. */
        new_max_sleep = dp->pmd_max_sleep_default;

        /* Check for pmd specific value. */
        for (int i = 0;  i < num_vals; i++) {
            if (pmd->core_id == pmd_sleeps[i].core_id) {
                new_max_sleep = pmd_sleeps[i].max_sleep;
                break;
            }
        }
        atomic_read_relaxed(&pmd->max_sleep, &cur_pmd_max_sleep);
        if (new_max_sleep != cur_pmd_max_sleep) {
            atomic_store_relaxed(&pmd->max_sleep, new_max_sleep);
            value_changed = true;
        }
    }
    return value_changed;
}

static void
log_all_pmd_sleeps(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread **pmd_list = NULL;
    struct dp_netdev_pmd_thread *pmd;
    size_t n;

    VLOG_INFO("Default PMD thread max sleep: %4"PRIu64" us.",
              dp->pmd_max_sleep_default);

    sorted_poll_thread_list(dp, &pmd_list, &n);

    for (size_t i = 0; i < n; i++) {
        uint64_t cur_pmd_max_sleep;

        pmd = pmd_list[i];
        atomic_read_relaxed(&pmd->max_sleep, &cur_pmd_max_sleep);
        log_pmd_sleep(pmd->core_id, pmd->numa_id, cur_pmd_max_sleep);
    }
    free(pmd_list);
}

static bool
set_all_pmd_max_sleeps(struct dp_netdev *dp, const struct smap *config)
{
    const char *max_sleep_list = smap_get(config, "pmd-sleep-max");
    struct pmd_sleep *pmd_sleeps = NULL;
    uint64_t default_max_sleep = 0;
    bool default_changed = false;
    bool pmd_changed = false;
    uint64_t pmd_maxsleep;
    int num_vals = 0;

    /* Check for deprecated 'pmd-maxsleep' value. */
    pmd_maxsleep = smap_get_ullong(config, "pmd-maxsleep", UINT64_MAX);
    if (pmd_maxsleep != UINT64_MAX && !max_sleep_list) {
        VLOG_WARN_ONCE("pmd-maxsleep is deprecated. "
                       "Please use pmd-sleep-max instead.");
        default_max_sleep = pmd_maxsleep;
    }

    /* Check if there is no change in string or value. */
    if (!!dp->max_sleep_list == !!max_sleep_list) {
        if (max_sleep_list
            ? nullable_string_is_equal(max_sleep_list, dp->max_sleep_list)
            : default_max_sleep == dp->pmd_max_sleep_default) {
            return false;
        }
    }

    /* Free existing string and copy new one (if any). */
    free(dp->max_sleep_list);
    dp->max_sleep_list = nullable_xstrdup(max_sleep_list);

    if (max_sleep_list) {
        num_vals = parse_pmd_sleep_list(max_sleep_list, &pmd_sleeps);

        /* Check if the user has set a global value. */
        for (int i = 0; i < num_vals; i++) {
            if (pmd_sleeps[i].core_id == UINT_MAX) {
                default_max_sleep = pmd_sleeps[i].max_sleep;
                break;
            }
        }
    }

    if (dp->pmd_max_sleep_default != default_max_sleep) {
        dp->pmd_max_sleep_default = default_max_sleep;
        default_changed = true;
    }
    pmd_changed = assign_sleep_values_to_pmds(dp, num_vals, pmd_sleeps);

    free(pmd_sleeps);
    return default_changed || pmd_changed;
}

/* Applies datapath configuration from the database. Some of the changes are
 * actually applied in dpif_netdev_run(). */
static int
dpif_netdev_set_config(struct dpif *dpif, const struct smap *other_config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    const char *cmask = smap_get(other_config, "pmd-cpu-mask");
    const char *pmd_rxq_assign = smap_get_def(other_config, "pmd-rxq-assign",
                                             "cycles");
    unsigned long long insert_prob =
        smap_get_ullong(other_config, "emc-insert-inv-prob",
                        DEFAULT_EM_FLOW_INSERT_INV_PROB);
    uint32_t insert_min, cur_min;
    uint32_t tx_flush_interval, cur_tx_flush_interval;
    uint64_t rebalance_intvl;
    uint8_t cur_rebalance_load;
    uint32_t rebalance_load, rebalance_improve;
    bool log_autolb = false;
    enum sched_assignment_type pmd_rxq_assign_type;
    static bool first_set_config = true;

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
            VLOG_INFO("EMC insertion probability changed to zero");
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

    bool smc_enable = smap_get_bool(other_config, "smc-enable", false);
    bool cur_smc;
    atomic_read_relaxed(&dp->smc_enable_db, &cur_smc);
    if (smc_enable != cur_smc) {
        atomic_store_relaxed(&dp->smc_enable_db, smc_enable);
        if (smc_enable) {
            VLOG_INFO("SMC cache is enabled");
        } else {
            VLOG_INFO("SMC cache is disabled");
        }
    }

    if (!strcmp(pmd_rxq_assign, "roundrobin")) {
        pmd_rxq_assign_type = SCHED_ROUNDROBIN;
    } else if (!strcmp(pmd_rxq_assign, "cycles")) {
        pmd_rxq_assign_type = SCHED_CYCLES;
    } else if (!strcmp(pmd_rxq_assign, "group")) {
        pmd_rxq_assign_type = SCHED_GROUP;
    } else {
        /* Default. */
        VLOG_WARN("Unsupported rx queue to PMD assignment mode in "
                  "pmd-rxq-assign. Defaulting to 'cycles'.");
        pmd_rxq_assign_type = SCHED_CYCLES;
        pmd_rxq_assign = "cycles";
    }
    if (dp->pmd_rxq_assign_type != pmd_rxq_assign_type) {
        dp->pmd_rxq_assign_type = pmd_rxq_assign_type;
        VLOG_INFO("Rxq to PMD assignment mode changed to: \'%s\'.",
                  pmd_rxq_assign);
        dp_netdev_request_reconfigure(dp);
    }

    bool pmd_iso = smap_get_bool(other_config, "pmd-rxq-isolate", true);

    if (pmd_rxq_assign_type != SCHED_GROUP && pmd_iso == false) {
        /* Invalid combination. */
        VLOG_WARN("pmd-rxq-isolate can only be set false "
                  "when using pmd-rxq-assign=group");
        pmd_iso = true;
    }
    if (dp->pmd_iso != pmd_iso) {
        dp->pmd_iso = pmd_iso;
        if (pmd_iso) {
            VLOG_INFO("pmd-rxq-affinity isolates PMD core");
        } else {
            VLOG_INFO("pmd-rxq-affinity does not isolate PMD core");
        }
        dp_netdev_request_reconfigure(dp);
    }

    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;

    rebalance_intvl = smap_get_ullong(other_config,
                                      "pmd-auto-lb-rebal-interval",
                                      ALB_REBALANCE_INTERVAL);
    if (rebalance_intvl > MAX_ALB_REBALANCE_INTERVAL) {
        rebalance_intvl = ALB_REBALANCE_INTERVAL;
    }

    /* Input is in min, convert it to msec. */
    rebalance_intvl =
        rebalance_intvl ? rebalance_intvl * MIN_TO_MSEC : MIN_TO_MSEC;

    if (pmd_alb->rebalance_intvl != rebalance_intvl) {
        pmd_alb->rebalance_intvl = rebalance_intvl;
        VLOG_INFO("PMD auto load balance interval set to "
                  "%"PRIu64" mins\n", rebalance_intvl / MIN_TO_MSEC);
        log_autolb = true;
    }

    rebalance_improve = smap_get_uint(other_config,
                                      "pmd-auto-lb-improvement-threshold",
                                      ALB_IMPROVEMENT_THRESHOLD);
    if (rebalance_improve > 100) {
        rebalance_improve = ALB_IMPROVEMENT_THRESHOLD;
    }
    if (rebalance_improve != pmd_alb->rebalance_improve_thresh) {
        pmd_alb->rebalance_improve_thresh = rebalance_improve;
        VLOG_INFO("PMD auto load balance improvement threshold set to "
                  "%"PRIu32"%%", rebalance_improve);
        log_autolb = true;
    }

    rebalance_load = smap_get_uint(other_config, "pmd-auto-lb-load-threshold",
                                   ALB_LOAD_THRESHOLD);
    if (rebalance_load > 100) {
        rebalance_load = ALB_LOAD_THRESHOLD;
    }
    atomic_read_relaxed(&pmd_alb->rebalance_load_thresh, &cur_rebalance_load);
    if (rebalance_load != cur_rebalance_load) {
        atomic_store_relaxed(&pmd_alb->rebalance_load_thresh,
                             rebalance_load);
        VLOG_INFO("PMD auto load balance load threshold set to %"PRIu32"%%",
                  rebalance_load);
        log_autolb = true;
    }

    bool autolb_state = smap_get_bool(other_config, "pmd-auto-lb", false);

    set_pmd_auto_lb(dp, autolb_state, log_autolb);

    bool sleep_changed = set_all_pmd_max_sleeps(dp, other_config);
    if (first_set_config || sleep_changed) {
        log_all_pmd_sleeps(dp);
    }

    first_set_config = false;
    return 0;
}

static bool
dpif_netdev_number_handlers_required(struct dpif *dpif_ OVS_UNUSED,
                                     uint32_t *n_handlers)
{
    *n_handlers = 0;
    return true;
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

/* Returns 'true' if one of the 'port's RX queues exists in 'poll_list'
 * of given PMD thread. */
static bool
dpif_netdev_pmd_polls_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_port *port)
    OVS_EXCLUDED(pmd->port_mutex)
{
    struct rxq_poll *poll;
    bool found = false;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
        if (port == poll->rxq->port) {
            found = true;
            break;
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
    return found;
}

/* Updates port configuration from the database.  The changes are actually
 * applied in dpif_netdev_run(). */
static int
dpif_netdev_port_set_config(struct dpif *dpif, odp_port_t port_no,
                            const struct smap *cfg)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error = 0;
    const char *affinity_list = smap_get(cfg, "pmd-rxq-affinity");
    bool emc_enabled = smap_get_bool(cfg, "emc-enable", true);
    const char *tx_steering_mode = smap_get(cfg, "tx-steering");
    enum txq_req_mode txq_mode;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = get_port_by_number(dp, port_no, &port);
    if (error) {
        goto unlock;
    }

    if (emc_enabled != port->emc_enabled) {
        struct dp_netdev_pmd_thread *pmd;
        struct ds ds = DS_EMPTY_INITIALIZER;
        uint32_t cur_min, insert_prob;

        port->emc_enabled = emc_enabled;
        /* Mark for reload all the threads that polls this port and request
         * for reconfiguration for the actual reloading of threads. */
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (dpif_netdev_pmd_polls_port(pmd, port)) {
                pmd->need_reload = true;
            }
        }
        dp_netdev_request_reconfigure(dp);

        ds_put_format(&ds, "%s: EMC has been %s.",
                      netdev_get_name(port->netdev),
                      (emc_enabled) ? "enabled" : "disabled");
        if (emc_enabled) {
            ds_put_cstr(&ds, " Current insertion probability is ");
            atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
            if (!cur_min) {
                ds_put_cstr(&ds, "zero.");
            } else {
                insert_prob = UINT32_MAX / cur_min;
                ds_put_format(&ds, "1/%"PRIu32" (~%.2f%%).",
                              insert_prob, 100 / (float) insert_prob);
            }
        }
        VLOG_INFO("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    /* Checking for RXq affinity changes. */
    if (netdev_is_pmd(port->netdev)
        && !nullable_string_is_equal(affinity_list, port->rxq_affinity_list)) {

        error = dpif_netdev_port_set_rxq_affinity(port, affinity_list);
        if (error) {
            goto unlock;
        }
        free(port->rxq_affinity_list);
        port->rxq_affinity_list = nullable_xstrdup(affinity_list);

        dp_netdev_request_reconfigure(dp);
    }

    if (nullable_string_is_equal(tx_steering_mode, "hash")) {
        txq_mode = TXQ_REQ_MODE_HASH;
    } else {
        txq_mode = TXQ_REQ_MODE_THREAD;
    }

    if (txq_mode != port->txq_requested_mode) {
        port->txq_requested_mode = txq_mode;
        VLOG_INFO("%s: Tx packet steering mode has been set to '%s'.",
                  netdev_get_name(port->netdev),
                  (txq_mode == TXQ_REQ_MODE_THREAD) ? "thread" : "hash");
        dp_netdev_request_reconfigure(dp);
    }

unlock:
    ovs_rwlock_unlock(&dp->port_rwlock);
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
    netdev_actions->size = size;
    if (size) {
        memcpy(netdev_actions->actions, actions, size);
    }

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
    unsigned int idx = atomic_count_inc(&rx->intrvl_idx) % PMD_INTERVAL_MAX;
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
    bool concurrent_txqs;
    struct cycle_timer timer;
    uint64_t cycles;
    uint32_t tx_flush_interval;

    cycle_timer_start(&pmd->perf_stats, &timer);

    output_cnt = dp_packet_batch_size(&p->output_pkts);
    ovs_assert(output_cnt > 0);

    if (p->port->txq_mode == TXQ_MODE_XPS_HASH) {
        int n_txq = netdev_n_txq(p->port->netdev);

        /* Re-batch per txq based on packet hash. */
        struct dp_packet *packet;
        DP_PACKET_BATCH_FOR_EACH (j, packet, &p->output_pkts) {
            uint32_t hash;

            if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
                hash = dp_packet_get_rss_hash(packet);
            } else {
                struct flow flow;

                flow_extract(packet, &flow);
                hash = flow_hash_5tuple(&flow, 0);
            }
            dp_packet_batch_add(&p->txq_pkts[hash % n_txq], packet);
        }

        /* Flush batches of each Tx queues. */
        for (i = 0; i < n_txq; i++) {
            if (dp_packet_batch_is_empty(&p->txq_pkts[i])) {
                continue;
            }
            netdev_send(p->port->netdev, i, &p->txq_pkts[i], true);
            dp_packet_batch_init(&p->txq_pkts[i]);
        }
    } else {
        if (p->port->txq_mode == TXQ_MODE_XPS) {
            tx_qid = dpif_netdev_xps_get_tx_qid(pmd, p);
            concurrent_txqs = true;
        } else {
            tx_qid = pmd->static_tx_qid;
            concurrent_txqs = false;
        }
        netdev_send(p->port->netdev, tx_qid, &p->output_pkts, concurrent_txqs);
    }
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
        batch_cnt = dp_packet_batch_size(&batch);
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
        int ret = pmd->netdev_input_func(pmd, &batch, port_no);
        if (ret) {
            dp_netdev_input(pmd, &batch, port_no);
        }

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

static struct tx_bond *
tx_bond_lookup(const struct cmap *tx_bonds, uint32_t bond_id)
{
    uint32_t hash = hash_bond_id(bond_id);
    struct tx_bond *tx;

    CMAP_FOR_EACH_WITH_HASH (tx, node, hash, tx_bonds) {
        if (tx->bond_id == bond_id) {
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

struct sched_numa_list {
    struct hmap numas;  /* Contains 'struct sched_numa'. */
};

/* Meta data for out-of-place pmd rxq assignments. */
struct sched_pmd {
    struct sched_numa *numa;
    /* Associated PMD thread. */
    struct dp_netdev_pmd_thread *pmd;
    uint64_t pmd_proc_cycles;
    struct dp_netdev_rxq **rxqs;
    unsigned n_rxq;
    bool isolated;
};

struct sched_numa {
    struct hmap_node node;
    int numa_id;
    /* PMDs on numa node. */
    struct sched_pmd *pmds;
    /* Num of PMDs on numa node. */
    unsigned n_pmds;
    /* Num of isolated PMDs on numa node. */
    unsigned n_isolated;
    int rr_cur_index;
    bool rr_idx_inc;
};

static size_t
sched_numa_list_count(struct sched_numa_list *numa_list)
{
    return hmap_count(&numa_list->numas);
}

static struct sched_numa *
sched_numa_list_next(struct sched_numa_list *numa_list,
                     const struct sched_numa *numa)
{
    struct hmap_node *node = NULL;

    if (numa) {
        node = hmap_next(&numa_list->numas, &numa->node);
    }
    if (!node) {
        node = hmap_first(&numa_list->numas);
    }

    return (node) ? CONTAINER_OF(node, struct sched_numa, node) : NULL;
}

static struct sched_numa *
sched_numa_list_lookup(struct sched_numa_list *numa_list, int numa_id)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH_WITH_HASH (numa, node, hash_int(numa_id, 0),
                             &numa_list->numas) {
        if (numa->numa_id == numa_id) {
            return numa;
        }
    }
    return NULL;
}

static int
compare_sched_pmd_list(const void *a_, const void *b_)
{
    struct sched_pmd *a, *b;

    a = (struct sched_pmd *) a_;
    b = (struct sched_pmd *) b_;

    return compare_poll_thread_list(&a->pmd, &b->pmd);
}

static void
sort_numa_list_pmds(struct sched_numa_list *numa_list)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH (numa, node, &numa_list->numas) {
        if (numa->n_pmds > 1) {
            qsort(numa->pmds, numa->n_pmds, sizeof *numa->pmds,
                  compare_sched_pmd_list);
        }
    }
}

/* Populate numas and pmds on those numas. */
static void
sched_numa_list_populate(struct sched_numa_list *numa_list,
                         struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    hmap_init(&numa_list->numas);

    /* For each pmd on this datapath. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct sched_numa *numa;
        struct sched_pmd *sched_pmd;
        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }

        /* Get the numa of the PMD. */
        numa = sched_numa_list_lookup(numa_list, pmd->numa_id);
        /* Create a new numa node for it if not already created. */
        if (!numa) {
            numa = xzalloc(sizeof *numa);
            numa->numa_id = pmd->numa_id;
            hmap_insert(&numa_list->numas, &numa->node,
                        hash_int(pmd->numa_id, 0));
        }

        /* Create a sched_pmd on this numa for the pmd. */
        numa->n_pmds++;
        numa->pmds = xrealloc(numa->pmds, numa->n_pmds * sizeof *numa->pmds);
        sched_pmd = &numa->pmds[numa->n_pmds - 1];
        memset(sched_pmd, 0, sizeof *sched_pmd);
        sched_pmd->numa = numa;
        sched_pmd->pmd = pmd;
        /* At least one pmd is present so initialize curr_idx and idx_inc. */
        numa->rr_cur_index = 0;
        numa->rr_idx_inc = true;
    }
    sort_numa_list_pmds(numa_list);
}

static void
sched_numa_list_free_entries(struct sched_numa_list *numa_list)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH_POP (numa, node, &numa_list->numas) {
        for (unsigned i = 0; i < numa->n_pmds; i++) {
            struct sched_pmd *sched_pmd;

            sched_pmd = &numa->pmds[i];
            sched_pmd->n_rxq = 0;
            free(sched_pmd->rxqs);
        }
        numa->n_pmds = 0;
        free(numa->pmds);
        free(numa);
    }
    hmap_destroy(&numa_list->numas);
}

static struct sched_pmd *
sched_pmd_find_by_pmd(struct sched_numa_list *numa_list,
                      struct dp_netdev_pmd_thread *pmd)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH (numa, node, &numa_list->numas) {
        for (unsigned i = 0; i < numa->n_pmds; i++) {
            struct sched_pmd *sched_pmd;

            sched_pmd = &numa->pmds[i];
            if (pmd == sched_pmd->pmd) {
                return sched_pmd;
            }
        }
    }
    return NULL;
}

static void
sched_pmd_add_rxq(struct sched_pmd *sched_pmd, struct dp_netdev_rxq *rxq,
                  uint64_t cycles)
{
    /* As sched_pmd is allocated outside this fn. better to not assume
     * rxqs is initialized to NULL. */
    if (sched_pmd->n_rxq == 0) {
        sched_pmd->rxqs = xmalloc(sizeof *sched_pmd->rxqs);
    } else {
        sched_pmd->rxqs = xrealloc(sched_pmd->rxqs, (sched_pmd->n_rxq + 1) *
                                                    sizeof *sched_pmd->rxqs);
    }

    sched_pmd->rxqs[sched_pmd->n_rxq++] = rxq;
    sched_pmd->pmd_proc_cycles += cycles;
}

static void
sched_numa_list_assignments(struct sched_numa_list *numa_list,
                            struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    /* For each port. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }
        /* For each rxq on the port. */
        for (unsigned qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *rxq = &port->rxqs[qid];
            struct sched_pmd *sched_pmd;
            uint64_t proc_cycles = 0;

            for (int i = 0; i < PMD_INTERVAL_MAX; i++) {
                proc_cycles  += dp_netdev_rxq_get_intrvl_cycles(rxq, i);
            }

            sched_pmd = sched_pmd_find_by_pmd(numa_list, rxq->pmd);
            if (sched_pmd) {
                if (rxq->core_id != OVS_CORE_UNSPEC && dp->pmd_iso) {
                    sched_pmd->isolated = true;
                }
                sched_pmd_add_rxq(sched_pmd, rxq, proc_cycles);
            }
        }
    }
}

static void
sched_numa_list_put_in_place(struct sched_numa_list *numa_list)
{
    struct sched_numa *numa;

    /* For each numa. */
    HMAP_FOR_EACH (numa, node, &numa_list->numas) {
        /* For each pmd. */
        for (int i = 0; i < numa->n_pmds; i++) {
            struct sched_pmd *sched_pmd;

            sched_pmd = &numa->pmds[i];
            sched_pmd->pmd->isolated = sched_pmd->isolated;
            /* For each rxq. */
            for (unsigned k = 0; k < sched_pmd->n_rxq; k++) {
                /* Store the new pmd from the out of place sched_numa_list
                 * struct to the dp_netdev_rxq struct */
                sched_pmd->rxqs[k]->pmd = sched_pmd->pmd;
            }
        }
    }
}

/* Returns 'true' if OVS rxq scheduling algorithm assigned any unpinned rxq to
 * a PMD thread core on a non-local numa node. */
static bool
sched_numa_list_cross_numa_polling(struct sched_numa_list *numa_list)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH (numa, node, &numa_list->numas) {
        for (int i = 0; i < numa->n_pmds; i++) {
            struct sched_pmd *sched_pmd;

            sched_pmd = &numa->pmds[i];
            if (sched_pmd->isolated) {
                /* All rxqs on this PMD thread core are pinned. */
                continue;
            }
            for (unsigned k = 0; k < sched_pmd->n_rxq; k++) {
                struct dp_netdev_rxq *rxq = sched_pmd->rxqs[k];
                /* Check if the rxq is not pinned to a specific PMD thread core
                 * by the user AND the PMD thread core that OVS assigned is
                 * non-local to the rxq port. */
                if (rxq->core_id == OVS_CORE_UNSPEC &&
                    rxq->pmd->numa_id !=
                        netdev_get_numa_id(rxq->port->netdev)) {
                    return true;
                }
            }
        }
    }
    return false;
}

static unsigned
sched_numa_noniso_pmd_count(struct sched_numa *numa)
{
    if (numa->n_pmds > numa->n_isolated) {
        return numa->n_pmds - numa->n_isolated;
    }
    return 0;
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

static bool
sched_pmd_new_lowest(struct sched_pmd *current_lowest, struct sched_pmd *pmd,
                     bool has_proc)
{
    uint64_t current_num, pmd_num;

    if (current_lowest == NULL) {
        return true;
    }

    if (has_proc) {
        current_num = current_lowest->pmd_proc_cycles;
        pmd_num = pmd->pmd_proc_cycles;
    } else {
        current_num = current_lowest->n_rxq;
        pmd_num = pmd->n_rxq;
    }

    if (pmd_num < current_num) {
        return true;
    }
    return false;
}

static struct sched_pmd *
sched_pmd_get_lowest(struct sched_numa *numa, bool has_cyc)
{
    struct sched_pmd *lowest_sched_pmd = NULL;

    for (unsigned i = 0; i < numa->n_pmds; i++) {
        struct sched_pmd *sched_pmd;

        sched_pmd = &numa->pmds[i];
        if (sched_pmd->isolated) {
            continue;
        }
        if (sched_pmd_new_lowest(lowest_sched_pmd, sched_pmd, has_cyc)) {
            lowest_sched_pmd = sched_pmd;
        }
    }
    return lowest_sched_pmd;
}

/*
 * Returns the next pmd from the numa node.
 *
 * If 'updown' is 'true' it will alternate between selecting the next pmd in
 * either an up or down walk, switching between up/down when the first or last
 * core is reached. e.g. 1,2,3,3,2,1,1,2...
 *
 * If 'updown' is 'false' it will select the next pmd wrapping around when
 * last core reached. e.g. 1,2,3,1,2,3,1,2...
 */
static struct sched_pmd *
sched_pmd_next_rr(struct sched_numa *numa, bool updown)
{
    int numa_idx = numa->rr_cur_index;

    if (numa->rr_idx_inc == true) {
        /* Incrementing through list of pmds. */
        if (numa->rr_cur_index == numa->n_pmds - 1) {
            /* Reached the last pmd. */
            if (updown) {
                numa->rr_idx_inc = false;
            } else {
                numa->rr_cur_index = 0;
            }
        } else {
            numa->rr_cur_index++;
        }
    } else {
        /* Decrementing through list of pmds. */
        if (numa->rr_cur_index == 0) {
            /* Reached the first pmd. */
            numa->rr_idx_inc = true;
        } else {
            numa->rr_cur_index--;
        }
    }
    return &numa->pmds[numa_idx];
}

static struct sched_pmd *
sched_pmd_next_noniso_rr(struct sched_numa *numa, bool updown)
{
    struct sched_pmd *sched_pmd = NULL;

    /* sched_pmd_next_rr() may return duplicate PMDs before all PMDs have been
     * returned depending on updown. Call it more than n_pmds to ensure all
     * PMDs can be searched for the next non-isolated PMD. */
    for (unsigned i = 0; i < numa->n_pmds * 2; i++) {
        sched_pmd = sched_pmd_next_rr(numa, updown);
        if (!sched_pmd->isolated) {
            break;
        }
        sched_pmd = NULL;
    }
    return sched_pmd;
}

static struct sched_pmd *
sched_pmd_next(struct sched_numa *numa, enum sched_assignment_type algo,
               bool has_proc)
{
    if (algo == SCHED_GROUP) {
        return sched_pmd_get_lowest(numa, has_proc);
    }

    /* By default RR the PMDs. */
    return sched_pmd_next_noniso_rr(numa, algo == SCHED_CYCLES ? true : false);
}

static const char *
get_assignment_type_string(enum sched_assignment_type algo)
{
    switch (algo) {
    case SCHED_ROUNDROBIN: return "roundrobin";
    case SCHED_CYCLES: return "cycles";
    case SCHED_GROUP: return "group";
    default: return "Unknown";
    }
}

#define MAX_RXQ_CYC_TEXT 40
#define MAX_RXQ_CYC_STRLEN (INT_STRLEN(uint64_t) + MAX_RXQ_CYC_TEXT)

static char *
get_rxq_cyc_log(char *a, enum sched_assignment_type algo, uint64_t cycles)
{
    int ret = 0;

    if (algo != SCHED_ROUNDROBIN) {
        ret = snprintf(a, MAX_RXQ_CYC_STRLEN,
                       " (measured processing cycles %"PRIu64")", cycles);
    }

    if (algo == SCHED_ROUNDROBIN || ret <= 0) {
        a[0] = '\0';
    }
    return a;
}

static void
sched_numa_list_schedule(struct sched_numa_list *numa_list,
                         struct dp_netdev *dp,
                         enum sched_assignment_type algo,
                         enum vlog_level level)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;
    struct dp_netdev_rxq **rxqs = NULL;
    struct sched_numa *last_cross_numa;
    unsigned n_rxqs = 0;
    bool start_logged = false;
    size_t n_numa;

    /* For each port. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        /* For each rxq on the port. */
        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *rxq = &port->rxqs[qid];

            if (algo != SCHED_ROUNDROBIN) {
                uint64_t cycle_hist = 0;

                /* Sum the queue intervals and store the cycle history. */
                for (unsigned i = 0; i < PMD_INTERVAL_MAX; i++) {
                    cycle_hist += dp_netdev_rxq_get_intrvl_cycles(rxq, i);
                }
                dp_netdev_rxq_set_cycles(rxq, RXQ_CYCLES_PROC_HIST,
                                         cycle_hist);
            }

            /* Check if this rxq is pinned. */
            if (rxq->core_id != OVS_CORE_UNSPEC) {
                struct sched_pmd *sched_pmd;
                struct dp_netdev_pmd_thread *pmd;
                struct sched_numa *numa;
                bool iso = dp->pmd_iso;
                uint64_t proc_cycles;
                char rxq_cyc_log[MAX_RXQ_CYC_STRLEN];

                /* This rxq should be pinned, pin it now. */
                pmd = dp_netdev_get_pmd(dp, rxq->core_id);
                sched_pmd = sched_pmd_find_by_pmd(numa_list, pmd);
                dp_netdev_pmd_unref(pmd);
                if (!sched_pmd) {
                    /* Cannot find the PMD.  Cannot pin this rxq. */
                    VLOG(level == VLL_DBG ? VLL_DBG : VLL_WARN,
                            "Core %2u cannot be pinned with "
                            "port \'%s\' rx queue %d. Use pmd-cpu-mask to "
                            "enable a pmd on core %u. An alternative core "
                            "will be assigned.",
                            rxq->core_id,
                            netdev_rxq_get_name(rxq->rx),
                            netdev_rxq_get_queue_id(rxq->rx),
                            rxq->core_id);
                    rxqs = xrealloc(rxqs, (n_rxqs + 1) * sizeof *rxqs);
                    rxqs[n_rxqs++] = rxq;
                    continue;
                }
                if (iso) {
                    /* Mark PMD as isolated if not done already. */
                    if (sched_pmd->isolated == false) {
                        sched_pmd->isolated = true;
                        numa = sched_pmd->numa;
                        numa->n_isolated++;
                    }
                }
                proc_cycles = dp_netdev_rxq_get_cycles(rxq,
                                                       RXQ_CYCLES_PROC_HIST);
                VLOG(level, "Core %2u on numa node %d is pinned with "
                            "port \'%s\' rx queue %d%s",
                            sched_pmd->pmd->core_id, sched_pmd->pmd->numa_id,
                            netdev_rxq_get_name(rxq->rx),
                            netdev_rxq_get_queue_id(rxq->rx),
                            get_rxq_cyc_log(rxq_cyc_log, algo, proc_cycles));
                sched_pmd_add_rxq(sched_pmd, rxq, proc_cycles);
            } else {
                rxqs = xrealloc(rxqs, (n_rxqs + 1) * sizeof *rxqs);
                rxqs[n_rxqs++] = rxq;
            }
        }
    }

    if (n_rxqs > 1 && algo != SCHED_ROUNDROBIN) {
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }

    last_cross_numa = NULL;
    n_numa = sched_numa_list_count(numa_list);
    for (unsigned i = 0; i < n_rxqs; i++) {
        struct dp_netdev_rxq *rxq = rxqs[i];
        struct sched_pmd *sched_pmd = NULL;
        struct sched_numa *numa;
        int port_numa_id;
        uint64_t proc_cycles;
        char rxq_cyc_log[MAX_RXQ_CYC_STRLEN];

        if (start_logged == false && level != VLL_DBG) {
            VLOG(level, "Performing pmd to rx queue assignment using %s "
                        "algorithm.", get_assignment_type_string(algo));
            start_logged = true;
        }

        /* Store the cycles for this rxq as we will log these later. */
        proc_cycles = dp_netdev_rxq_get_cycles(rxq, RXQ_CYCLES_PROC_HIST);

        port_numa_id = netdev_get_numa_id(rxq->port->netdev);

        /* Select numa. */
        numa = sched_numa_list_lookup(numa_list, port_numa_id);

        /* Check if numa has no PMDs or no non-isolated PMDs. */
        if (!numa || !sched_numa_noniso_pmd_count(numa)) {
            /* Unable to use this numa to find a PMD. */
            numa = NULL;
            /* Find any numa with available PMDs. */
            for (int j = 0; j < n_numa; j++) {
                numa = sched_numa_list_next(numa_list, last_cross_numa);
                last_cross_numa = numa;
                if (sched_numa_noniso_pmd_count(numa)) {
                    break;
                }
                numa = NULL;
            }
        }

        if (numa) {
            /* Select the PMD that should be used for this rxq. */
            sched_pmd = sched_pmd_next(numa, algo,
                                       proc_cycles ? true : false);
        }

        /* Check that a pmd has been selected. */
        if (sched_pmd) {
            int pmd_numa_id;

            pmd_numa_id = sched_pmd->numa->numa_id;
            /* Check if selected pmd numa matches port numa. */
            if (pmd_numa_id != port_numa_id) {
                VLOG(level, "There's no available (non-isolated) pmd thread "
                            "on numa node %d. Port \'%s\' rx queue %d will "
                            "be assigned to a pmd on numa node %d. "
                            "This may lead to reduced performance.",
                            port_numa_id, netdev_rxq_get_name(rxq->rx),
                            netdev_rxq_get_queue_id(rxq->rx), pmd_numa_id);
            }
            VLOG(level, "Core %2u on numa node %d assigned port \'%s\' "
                        "rx queue %d%s.",
                        sched_pmd->pmd->core_id, sched_pmd->pmd->numa_id,
                        netdev_rxq_get_name(rxq->rx),
                        netdev_rxq_get_queue_id(rxq->rx),
                        get_rxq_cyc_log(rxq_cyc_log, algo, proc_cycles));
            sched_pmd_add_rxq(sched_pmd, rxq, proc_cycles);
        } else  {
            VLOG(level == VLL_DBG ? level : VLL_WARN,
                 "No non-isolated pmd on any numa available for "
                 "port \'%s\' rx queue %d%s. "
                 "This rx queue will not be polled.",
                 netdev_rxq_get_name(rxq->rx),
                 netdev_rxq_get_queue_id(rxq->rx),
                 get_rxq_cyc_log(rxq_cyc_log, algo, proc_cycles));
        }
    }
    free(rxqs);
}

static void
rxq_scheduling(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct sched_numa_list numa_list;
    enum sched_assignment_type algo = dp->pmd_rxq_assign_type;

    sched_numa_list_populate(&numa_list, dp);
    sched_numa_list_schedule(&numa_list, dp, algo, VLL_INFO);
    sched_numa_list_put_in_place(&numa_list);

    sched_numa_list_free_entries(&numa_list);
}

static uint64_t variance(uint64_t a[], int n);

static uint64_t
sched_numa_variance(struct sched_numa *numa)
{
    uint64_t *percent_busy = NULL;
    int n_proc = 0;
    uint64_t var;

    percent_busy = xmalloc(numa->n_pmds * sizeof *percent_busy);

    for (unsigned i = 0; i < numa->n_pmds; i++) {
        struct sched_pmd *sched_pmd;
        uint64_t total_cycles = 0;

        sched_pmd = &numa->pmds[i];
        /* Exclude isolated PMDs from variance calculations. */
        if (sched_pmd->isolated == true) {
            continue;
        }
        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&sched_pmd->pmd->intrvl_cycles, &total_cycles);

        if (total_cycles) {
            /* Estimate the cycles to cover all intervals. */
            total_cycles *= PMD_INTERVAL_MAX;
            percent_busy[n_proc++] = (sched_pmd->pmd_proc_cycles * 100)
                                            / total_cycles;
        } else {
            percent_busy[n_proc++] = 0;
        }
    }
    var = variance(percent_busy, n_proc);
    free(percent_busy);
    return var;
}

/*
 * This function checks that some basic conditions needed for a rebalance to be
 * effective are met. Such as Rxq scheduling assignment type, more than one
 * PMD, more than 2 Rxqs on a PMD. If there was no reconfiguration change
 * since the last check, it reuses the last result.
 *
 * It is not intended to be an inclusive check of every condition that may make
 * a rebalance ineffective. It is done as a quick check so a full
 * pmd_rebalance_dry_run() can be avoided when it is not needed.
 */
static bool
pmd_rebalance_dry_run_needed(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_pmd_thread *pmd;
    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    unsigned int cnt = 0;
    bool multi_rxq = false;

    /* Check if there was no reconfiguration since last check. */
    if (!pmd_alb->recheck_config) {
        if (!pmd_alb->do_dry_run) {
            VLOG_DBG("PMD auto load balance nothing to do, "
                     "no configuration changes since last check.");
            return false;
        }
        return true;
    }
    pmd_alb->recheck_config = false;

    /* Check for incompatible assignment type. */
    if (dp->pmd_rxq_assign_type == SCHED_ROUNDROBIN) {
        VLOG_DBG("PMD auto load balance nothing to do, "
                 "pmd-rxq-assign=roundrobin assignment type configured.");
        return pmd_alb->do_dry_run = false;
    }

    /* Check that there is at least 2 non-isolated PMDs and
     * one of them is polling more than one rxq. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

        if (hmap_count(&pmd->poll_list) > 1) {
            multi_rxq = true;
        }
        if (cnt && multi_rxq) {
            return pmd_alb->do_dry_run = true;
        }
        cnt++;
    }

    VLOG_DBG("PMD auto load balance nothing to do, "
             "not enough non-isolated PMDs or RxQs.");
    return pmd_alb->do_dry_run = false;
}

static bool
pmd_rebalance_dry_run(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct sched_numa_list numa_list_cur;
    struct sched_numa_list numa_list_est;
    bool thresh_met = false;

    VLOG_DBG("PMD auto load balance performing dry run.");

    /* Populate current assignments. */
    sched_numa_list_populate(&numa_list_cur, dp);
    sched_numa_list_assignments(&numa_list_cur, dp);

    /* Populate estimated assignments. */
    sched_numa_list_populate(&numa_list_est, dp);
    sched_numa_list_schedule(&numa_list_est, dp,
                             dp->pmd_rxq_assign_type, VLL_DBG);

    /* Check if cross-numa polling, there is only one numa with PMDs. */
    if (!sched_numa_list_cross_numa_polling(&numa_list_est) ||
            sched_numa_list_count(&numa_list_est) == 1) {
        struct sched_numa *numa_cur;

        /* Calculate variances. */
        HMAP_FOR_EACH (numa_cur, node, &numa_list_cur.numas) {
            uint64_t current_var, estimate_var;
            struct sched_numa *numa_est;
            uint64_t improvement = 0;

            numa_est = sched_numa_list_lookup(&numa_list_est,
                                              numa_cur->numa_id);
            if (!numa_est) {
                continue;
            }
            current_var = sched_numa_variance(numa_cur);
            estimate_var = sched_numa_variance(numa_est);
            if (estimate_var < current_var) {
                improvement = ((current_var - estimate_var) * 100)
                              / current_var;
            }
            VLOG_DBG("Numa node %d. Current variance %"PRIu64" Estimated "
                     "variance %"PRIu64". Variance improvement %"PRIu64"%%.",
                     numa_cur->numa_id, current_var,
                     estimate_var, improvement);
            if (improvement >= dp->pmd_alb.rebalance_improve_thresh) {
                thresh_met = true;
            }
        }
        VLOG_DBG("PMD load variance improvement threshold %u%% is %s.",
                 dp->pmd_alb.rebalance_improve_thresh,
                 thresh_met ? "met" : "not met");
    } else {
        VLOG_DBG("PMD auto load balance detected cross-numa polling with "
                 "multiple numa nodes. Unable to accurately estimate.");
    }

    sched_numa_list_free_entries(&numa_list_cur);
    sched_numa_list_free_entries(&numa_list_est);

    return thresh_met;
}

static void
reload_affected_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            dp_netdev_reload_pmd__(pmd);
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            if (pmd->core_id != NON_PMD_CORE_ID) {
                bool reload;

                do {
                    atomic_read_explicit(&pmd->reload, &reload,
                                         memory_order_acquire);
                } while (reload);
            }
            pmd->need_reload = false;
        }
    }
}

static void
reconfigure_pmd_threads(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
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
            atomic_store_relaxed(&pmd->reload_tx_qid, true);
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
            struct ds name = DS_EMPTY_INITIALIZER;

            pmd = xzalloc(sizeof *pmd);
            dp_netdev_configure_pmd(pmd, dp, core->core_id, core->numa_id);

            ds_put_format(&name, "pmd-c%02d/id:", core->core_id);
            pmd->thread = ovs_thread_create(ds_cstr(&name),
                                            pmd_thread_main, pmd);
            ds_destroy(&name);

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
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct rxq_poll *poll;
    struct tx_port *tx;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_SAFE (poll, node, &pmd->poll_list) {
        struct dp_netdev_port *port = poll->rxq->port;

        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_rxq_from_pmd(pmd, poll);
        }
    }
    HMAP_FOR_EACH_SAFE (tx, node, &pmd->tx_ports) {
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
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct hmapx busy_threads = HMAPX_INITIALIZER(&busy_threads);
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
     * change at any time.
     * Also mark for reconfiguration all ports which will likely change their
     * 'txq_mode' parameter.  It's required to stop using them before
     * changing this setting and it's simpler to mark ports here and allow
     * 'pmd_remove_stale_ports' to remove them from threads.  There will be
     * no actual reconfiguration in 'port_reconfigure' because it's
     * unnecessary.  */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)
            || ((port->txq_mode == TXQ_MODE_XPS)
                != (netdev_n_txq(port->netdev) < wanted_txqs))
            || ((port->txq_mode == TXQ_MODE_XPS_HASH)
                != (port->txq_requested_mode == TXQ_REQ_MODE_HASH
                    && netdev_n_txq(port->netdev) > 1))) {
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
    HMAP_FOR_EACH_SAFE (port, node, &dp->ports) {
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
            /* With a single queue, there is no point in using hash mode. */
            if (port->txq_requested_mode == TXQ_REQ_MODE_HASH &&
                netdev_n_txq(port->netdev) > 1) {
                port->txq_mode = TXQ_MODE_XPS_HASH;
            } else if (netdev_n_txq(port->netdev) < wanted_txqs) {
                port->txq_mode = TXQ_MODE_XPS;
            } else {
                port->txq_mode = TXQ_MODE_STATIC;
            }
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
    rxq_scheduling(dp);

    /* Step 5: Remove queues not compliant with new scheduling. */

    /* Count all the threads that will have at least one queue to poll. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (q->pmd) {
                hmapx_add(&busy_threads, q->pmd);
            }
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct rxq_poll *poll;

        ovs_mutex_lock(&pmd->port_mutex);
        HMAP_FOR_EACH_SAFE (poll, node, &pmd->poll_list) {
            if (poll->rxq->pmd != pmd) {
                dp_netdev_del_rxq_from_pmd(pmd, poll);

                /* This pmd might sleep after this step if it has no rxq
                 * remaining. Tell it to busy wait for new assignment if it
                 * has at least one scheduled queue. */
                if (hmap_count(&pmd->poll_list) == 0 &&
                    hmapx_contains(&busy_threads, pmd)) {
                    atomic_store_relaxed(&pmd->wait_for_reload, true);
                }
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    hmapx_destroy(&busy_threads);

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

    /* Add every port and bond to the tx port and bond caches of
     * every pmd thread, if it's not there already and if this pmd
     * has at least one rxq to poll.
     */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        ovs_mutex_lock(&pmd->port_mutex);
        if (hmap_count(&pmd->poll_list) || pmd->core_id == NON_PMD_CORE_ID) {
            struct tx_bond *bond;

            HMAP_FOR_EACH (port, node, &dp->ports) {
                dp_netdev_add_port_tx_to_pmd(pmd, port);
            }

            CMAP_FOR_EACH (bond, node, &dp->tx_bonds) {
                dp_netdev_add_bond_tx_to_pmd(pmd, bond, false);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads. */
    reload_affected_pmds(dp);

    /* PMD ALB will need to recheck if dry run needed. */
    dp->pmd_alb.recheck_config = true;
}

/* Returns true if one of the netdevs in 'dp' requires a reconfiguration */
static bool
ports_require_restart(const struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)) {
            return true;
        }
    }

    return false;
}

/* Calculates variance in the values stored in array 'a'. 'n' is the number
 * of elements in array to be considered for calculating vairance.
 * Usage example: data array 'a' contains the processing load of each pmd and
 * 'n' is the number of PMDs. It returns the variance in processing load of
 * PMDs*/
static uint64_t
variance(uint64_t a[], int n)
{
    /* Compute mean (average of elements). */
    uint64_t sum = 0;
    uint64_t mean = 0;
    uint64_t sqDiff = 0;

    if (!n) {
        return 0;
    }

    for (int i = 0; i < n; i++) {
        sum += a[i];
    }

    if (sum) {
        mean = sum / n;

        /* Compute sum squared differences with mean. */
        for (int i = 0; i < n; i++) {
            sqDiff += (a[i] - mean)*(a[i] - mean);
        }
    }
    return (sqDiff ? (sqDiff / n) : 0);
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
    bool pmd_rebalance = false;
    long long int now = time_msec();
    struct dp_netdev_pmd_thread *pmd;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    non_pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
    if (non_pmd) {
        ovs_mutex_lock(&dp->non_pmd_mutex);

        atomic_read_relaxed(&dp->smc_enable_db, &non_pmd->ctx.smc_enable_db);

        HMAP_FOR_EACH (port, node, &dp->ports) {
            if (!netdev_is_pmd(port->netdev)) {
                int i;

                if (port->emc_enabled) {
                    atomic_read_relaxed(&dp->emc_insert_min,
                                        &non_pmd->ctx.emc_insert_min);
                } else {
                    non_pmd->ctx.emc_insert_min = 0;
                }

                for (i = 0; i < port->n_rxq; i++) {

                    if (!netdev_rxq_enabled(port->rxqs[i].rx)) {
                        continue;
                    }

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

    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    if (pmd_alb->is_enabled) {
        if (!pmd_alb->rebalance_poll_timer) {
            pmd_alb->rebalance_poll_timer = now;
        } else if ((pmd_alb->rebalance_poll_timer +
                   pmd_alb->rebalance_intvl) < now) {
            pmd_alb->rebalance_poll_timer = now;
            CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
                if (atomic_count_get(&pmd->pmd_overloaded) >=
                                    PMD_INTERVAL_MAX) {
                    pmd_rebalance = true;
                    break;
                }
            }

            if (pmd_rebalance &&
                !dp_netdev_is_reconf_required(dp) &&
                !ports_require_restart(dp) &&
                pmd_rebalance_dry_run_needed(dp) &&
                pmd_rebalance_dry_run(dp)) {
                VLOG_INFO("PMD auto load balance dry run. "
                          "Requesting datapath reconfigure.");
                dp_netdev_request_reconfigure(dp);
            }
        }
    }

    if (dp_netdev_is_reconf_required(dp) || ports_require_restart(dp)) {
        reconfigure_datapath(dp);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

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
    ovs_rwlock_rdlock(&dp->port_rwlock);
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_wait_reconf_required(port->netdev);
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < port->n_rxq; i++) {
                netdev_rxq_wait(port->rxqs[i].rx);
            }
        }
    }
    ovs_rwlock_unlock(&dp->port_rwlock);
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
        free(tx_port_cached->txq_pkts);
        free(tx_port_cached);
    }
    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->send_port_cache) {
        free(tx_port_cached->txq_pkts);
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
        int n_txq = netdev_n_txq(tx_port->port->netdev);
        struct dp_packet_batch *txq_pkts_cached;

        if (netdev_has_tunnel_push_pop(tx_port->port->netdev)) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            if (tx_port->txq_pkts) {
                txq_pkts_cached = xmemdup(tx_port->txq_pkts,
                                          n_txq * sizeof *tx_port->txq_pkts);
                tx_port_cached->txq_pkts = txq_pkts_cached;
            }
            hmap_insert(&pmd->tnl_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }

        if (n_txq) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            if (tx_port->txq_pkts) {
                txq_pkts_cached = xmemdup(tx_port->txq_pkts,
                                          n_txq * sizeof *tx_port->txq_pkts);
                tx_port_cached->txq_pkts = txq_pkts_cached;
            }
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
        poll_list[i].emc_enabled = poll->rxq->port->emc_enabled;
        poll_list[i].rxq_enabled = netdev_rxq_enabled(poll->rxq->rx);
        poll_list[i].change_seq =
                     netdev_get_change_seq(poll->rxq->port->netdev);
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
    bool wait_for_reload = false;
    bool dpdk_attached;
    bool reload_tx_qid;
    bool exiting;
    bool reload;
    int poll_cnt;
    int i;
    int process_packets = 0;
    uint64_t sleep_time = 0;

    poll_list = NULL;

    /* Stores the pmd thread's 'pmd' to 'per_pmd_key'. */
    ovsthread_setspecific(pmd->dp->per_pmd_key, pmd);
    ovs_numa_thread_setaffinity_core(pmd->core_id);
    dpdk_attached = dpdk_attach_thread(pmd->core_id);
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    dfc_cache_init(&pmd->flow_cache);
    pmd_alloc_static_tx_qid(pmd);
    set_timer_resolution(PMD_TIMER_RES_NS);

reload:
    atomic_count_init(&pmd->pmd_overloaded, 0);

    pmd->intrvl_tsc_prev = 0;
    atomic_store_relaxed(&pmd->intrvl_cycles, 0);

    if (!dpdk_attached) {
        dpdk_attached = dpdk_attach_thread(pmd->core_id);
    }

    /* List port/core affinity */
    for (i = 0; i < poll_cnt; i++) {
       VLOG_DBG("Core %d processing port \'%s\' with queue-id %d\n",
                pmd->core_id, netdev_rxq_get_name(poll_list[i].rxq->rx),
                netdev_rxq_get_queue_id(poll_list[i].rxq->rx));
       /* Reset the rxq current cycles counter. */
       dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR, 0);
       for (int j = 0; j < PMD_INTERVAL_MAX; j++) {
           dp_netdev_rxq_set_intrvl_cycles(poll_list[i].rxq, 0);
       }
    }

    if (!poll_cnt) {
        if (wait_for_reload) {
            /* Don't sleep, control thread will ask for a reload shortly. */
            do {
                atomic_read_explicit(&pmd->reload, &reload,
                                     memory_order_acquire);
            } while (!reload);
        } else {
            while (seq_read(pmd->reload_seq) == pmd->last_reload_seq) {
                seq_wait(pmd->reload_seq, pmd->last_reload_seq);
                poll_block();
            }
        }
    }

    for (i = 0; i < PMD_INTERVAL_MAX; i++) {
        atomic_store_relaxed(&pmd->busy_cycles_intrvl[i], 0);
    }
    atomic_count_set(&pmd->intrvl_idx, 0);
    cycles_counter_update(s);

    pmd->next_rcu_quiesce = pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;

    /* Protect pmd stats from external clearing while polling. */
    ovs_mutex_lock(&pmd->perf_stats.stats_mutex);
    for (;;) {
        uint64_t rx_packets = 0, tx_packets = 0;
        uint64_t time_slept = 0;
        uint64_t max_sleep;

        pmd_perf_start_iteration(s);

        atomic_read_relaxed(&pmd->dp->smc_enable_db, &pmd->ctx.smc_enable_db);
        atomic_read_relaxed(&pmd->max_sleep, &max_sleep);

        for (i = 0; i < poll_cnt; i++) {

            if (!poll_list[i].rxq_enabled) {
                continue;
            }

            if (poll_list[i].emc_enabled) {
                atomic_read_relaxed(&pmd->dp->emc_insert_min,
                                    &pmd->ctx.emc_insert_min);
            } else {
                pmd->ctx.emc_insert_min = 0;
            }

            process_packets =
                dp_netdev_process_rxq_port(pmd, poll_list[i].rxq,
                                           poll_list[i].port_no);
            rx_packets += process_packets;
            if (process_packets >= PMD_SLEEP_THRESH) {
                sleep_time = 0;
            }
        }

        if (!rx_packets) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(pmd);
            tx_packets = dp_netdev_pmd_flush_output_packets(pmd,
                                                   max_sleep && sleep_time
                                                   ? true : false);
        }

        if (max_sleep) {
            /* Check if a sleep should happen on this iteration. */
            if (sleep_time) {
                struct cycle_timer sleep_timer;

                cycle_timer_start(&pmd->perf_stats, &sleep_timer);
                xnanosleep_no_quiesce(sleep_time * 1000);
                time_slept = cycle_timer_stop(&pmd->perf_stats, &sleep_timer);
                pmd_thread_ctx_time_update(pmd);
            }
            if (sleep_time < max_sleep) {
                /* Increase sleep time for next iteration. */
                sleep_time += PMD_SLEEP_INC_US;
            } else {
                sleep_time = max_sleep;
            }
        } else {
            /* Reset sleep time as max sleep policy may have been changed. */
            sleep_time = 0;
        }

        /* Do RCU synchronization at fixed interval.  This ensures that
         * synchronization would not be delayed long even at high load of
         * packet processing. */
        if (pmd->ctx.now > pmd->next_rcu_quiesce) {
            if (!ovsrcu_try_quiesce()) {
                pmd->next_rcu_quiesce =
                    pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
            }
        }

        if (lc++ > 1024) {
            lc = 0;

            coverage_try_clear();
            dp_netdev_pmd_try_optimize(pmd, poll_list, poll_cnt);
            if (!ovsrcu_try_quiesce()) {
                emc_cache_slow_sweep(&((pmd->flow_cache).emc_cache));
                pmd->next_rcu_quiesce =
                    pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
            }

            for (i = 0; i < poll_cnt; i++) {
                uint64_t current_seq =
                         netdev_get_change_seq(poll_list[i].rxq->port->netdev);
                if (poll_list[i].change_seq != current_seq) {
                    poll_list[i].change_seq = current_seq;
                    poll_list[i].rxq_enabled =
                                 netdev_rxq_enabled(poll_list[i].rxq->rx);
                }
            }
        }

        atomic_read_explicit(&pmd->reload, &reload, memory_order_acquire);
        if (OVS_UNLIKELY(reload)) {
            break;
        }

        pmd_perf_end_iteration(s, rx_packets, tx_packets, time_slept,
                               pmd_perf_metrics_enabled(pmd));
    }
    ovs_mutex_unlock(&pmd->perf_stats.stats_mutex);

    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    atomic_read_relaxed(&pmd->wait_for_reload, &wait_for_reload);
    atomic_read_relaxed(&pmd->reload_tx_qid, &reload_tx_qid);
    atomic_read_relaxed(&pmd->exit, &exiting);
    /* Signal here to make sure the pmd finishes
     * reloading the updated configuration. */
    dp_netdev_pmd_reload_done(pmd);

    if (reload_tx_qid) {
        pmd_free_static_tx_qid(pmd);
        pmd_alloc_static_tx_qid(pmd);
    }

    if (!exiting) {
        goto reload;
    }

    pmd_free_static_tx_qid(pmd);
    dfc_cache_uninit(&pmd->flow_cache);
    free(poll_list);
    pmd_free_cached_ports(pmd);
    if (dpdk_attached) {
        dpdk_detach_thread();
    }
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

/* Tries to atomically add 'n' to 'value' in terms of saturation arithmetic,
 * i.e., if the result will be larger than 'max_value', will store 'max_value'
 * instead. */
static void
atomic_sat_add(atomic_uint64_t *value, uint64_t n, uint64_t max_value)
{
    uint64_t current, new_value;

    atomic_read_relaxed(value, &current);
    do {
        new_value = current + n;
        new_value = MIN(new_value, max_value);
    } while (!atomic_compare_exchange_weak_relaxed(value, &current,
                                                   new_value));
}

/* Tries to atomically subtract 'n' from 'value'.  Does not perform the
 * operation and returns 'false' if the result will be less than 'min_value'.
 * Otherwise, stores the result and returns 'true'. */
static bool
atomic_bound_sub(atomic_uint64_t *value, uint64_t n, uint64_t min_value)
{
    uint64_t current;

    atomic_read_relaxed(value, &current);
    do {
        if (current < min_value + n) {
            return false;
        }
    } while (!atomic_compare_exchange_weak_relaxed(value, &current,
                                                   current - n));
    return true;
}

/* Applies the meter identified by 'meter_id' to 'packets_'.  Packets
 * that exceed a band are dropped in-place. */
static void
dp_netdev_run_meter(struct dp_netdev *dp, struct dp_packet_batch *packets_,
                    uint32_t meter_id, long long int now_ms)
{
    const size_t cnt = dp_packet_batch_size(packets_);
    uint32_t exceeded_rate[NETDEV_MAX_BURST];
    uint32_t exceeded_band[NETDEV_MAX_BURST];
    uint64_t bytes, volume, meter_used, old;
    uint64_t band_packets[MAX_BANDS];
    uint64_t band_bytes[MAX_BANDS];
    struct dp_meter_band *band;
    struct dp_packet *packet;
    struct dp_meter *meter;
    bool exceeded = false;

    if (meter_id >= MAX_METERS) {
        return;
    }

    meter = dp_meter_lookup(&dp->meters, meter_id);
    if (!meter) {
        return;
    }

    /* Initialize as negative values. */
    memset(exceeded_band, 0xff, cnt * sizeof *exceeded_band);
    /* Initialize as zeroes. */
    memset(exceeded_rate, 0, cnt * sizeof *exceeded_rate);

    atomic_read_relaxed(&meter->used, &meter_used);
    do {
        if (meter_used >= now_ms) {
            /* The '>' condition means that we have several threads hitting the
             * same meter, and the other one already advanced the time. */
            meter_used = now_ms;
            break;
        }
    } while (!atomic_compare_exchange_weak_relaxed(&meter->used,
                                                   &meter_used, now_ms));

    /* Refill all buckets right away, since other threads may use them. */
    if (meter_used < now_ms) {
        /* All packets will hit the meter at the same time. */
        uint64_t delta_t = now_ms - meter_used;

        /* Make sure delta_t will not be too large, so that bucket will not
         * wrap around below. */
        delta_t = MIN(delta_t, meter->max_delta_t);

        for (int m = 0; m < meter->n_bands; m++) {
            band = &meter->bands[m];
            /* Update band's bucket.  We can't just use atomic add here,
             * because we should never add above the max capacity. */
            atomic_sat_add(&band->bucket, delta_t * band->rate,
                           band->burst_size * 1000ULL);
        }
    }

    /* Update meter stats. */
    atomic_add_relaxed(&meter->packet_count, cnt, &old);
    bytes = 0;
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        bytes += dp_packet_size(packet);
    }
    atomic_add_relaxed(&meter->byte_count, bytes, &old);

    /* Meters can operate in terms of packets per second or kilobits per
     * second. */
    if (meter->flags & OFPMF13_PKTPS) {
        /* Rate in packets/second, bucket 1/1000 packets.
         * msec * packets/sec = 1/1000 packets. */
        volume = cnt * 1000; /* Take 'cnt' packets from the bucket. */
    } else {
        /* Rate in kbps, bucket in bits.
         * msec * kbps = bits */
        volume = bytes * 8;
    }

    /* Find the band hit with the highest rate for each packet (if any). */
    for (int m = 0; m < meter->n_bands; m++) {
        band = &meter->bands[m];

        /* Drain the bucket for all the packets, if possible. */
        if (atomic_bound_sub(&band->bucket, volume, 0)) {
            continue;
        }

        /* Band limit hit, must process packet-by-packet. */
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            uint64_t packet_volume = (meter->flags & OFPMF13_PKTPS)
                                     ? 1000 : (dp_packet_size(packet) * 8);

            if (!atomic_bound_sub(&band->bucket, packet_volume, 0)) {
                /* Update the exceeding band for the exceeding packet.
                 * Only one band will be fired by a packet, and that can
                 * be different for each packet. */
                if (band->rate > exceeded_rate[i]) {
                    exceeded_rate[i] = band->rate;
                    exceeded_band[i] = m;
                    exceeded = true;
                }
            }
        }
    }

    /* No need to iterate over packets if there are no drops. */
    if (!exceeded) {
        return;
    }

    /* Fire the highest rate band exceeded by each packet, and drop
     * packets if needed. */

    memset(band_packets, 0, sizeof band_packets);
    memset(band_bytes,   0, sizeof band_bytes);

    size_t j;
    DP_PACKET_BATCH_REFILL_FOR_EACH (j, cnt, packet, packets_) {
        uint32_t m = exceeded_band[j];

        if (m != UINT32_MAX) {
            /* Meter drop packet. */
            band_packets[m]++;
            band_bytes[m] += dp_packet_size(packet);
            dp_packet_delete(packet);
        } else {
            /* Meter accepts packet. */
            dp_packet_batch_refill(packets_, packet, j);
        }
    }

    for (int m = 0; m < meter->n_bands; m++) {
        if (!band_packets[m]) {
            continue;
        }
        band = &meter->bands[m];
        atomic_add_relaxed(&band->packet_count, band_packets[m], &old);
        atomic_add_relaxed(&band->byte_count,   band_bytes[m],   &old);
        COVERAGE_ADD(datapath_drop_meter, band_packets[m]);
    }
}

/* Meter set/get/del processing is still single-threaded. */
static int
dpif_netdev_meter_set(struct dpif *dpif, ofproto_meter_id meter_id,
                      struct ofputil_meter_config *config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t mid = meter_id.uint32;
    struct dp_meter *meter;
    int i;

    if (mid >= MAX_METERS) {
        return EFBIG; /* Meter_id out of range. */
    }

    if (config->flags & ~DP_SUPPORTED_METER_FLAGS_MASK) {
        return EBADF; /* Unsupported flags set */
    }

    if (config->n_bands > MAX_BANDS) {
        return EINVAL;
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

    meter->flags = config->flags;
    meter->n_bands = config->n_bands;
    meter->max_delta_t = 0;
    meter->id = mid;
    atomic_init(&meter->used, time_msec());

    /* set up bands */
    for (i = 0; i < config->n_bands; ++i) {
        uint32_t band_max_delta_t;
        uint64_t bucket_size;

        /* Set burst size to a workable value if none specified. */
        if (config->bands[i].burst_size == 0) {
            config->bands[i].burst_size = config->bands[i].rate;
        }

        meter->bands[i].rate = config->bands[i].rate;
        meter->bands[i].burst_size = config->bands[i].burst_size;
        /* Start with a full bucket. */
        bucket_size = meter->bands[i].burst_size * 1000ULL;
        atomic_init(&meter->bands[i].bucket, bucket_size);

        /* Figure out max delta_t that is enough to fill any bucket. */
        band_max_delta_t = bucket_size / meter->bands[i].rate;
        if (band_max_delta_t > meter->max_delta_t) {
            meter->max_delta_t = band_max_delta_t;
        }
    }

    ovs_mutex_lock(&dp->meters_lock);

    dp_meter_detach_free(&dp->meters, mid); /* Free existing meter, if any. */
    dp_meter_attach(&dp->meters, meter);

    ovs_mutex_unlock(&dp->meters_lock);

    return 0;
}

static int
dpif_netdev_meter_get(const struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t meter_id = meter_id_.uint32;
    struct dp_meter *meter;

    if (meter_id >= MAX_METERS) {
        return EFBIG;
    }

    meter = dp_meter_lookup(&dp->meters, meter_id);
    if (!meter) {
        return ENOENT;
    }

    if (stats) {
        int i = 0;

        atomic_read_relaxed(&meter->packet_count, &stats->packet_in_count);
        atomic_read_relaxed(&meter->byte_count, &stats->byte_in_count);

        for (i = 0; i < n_bands && i < meter->n_bands; ++i) {
            atomic_read_relaxed(&meter->bands[i].packet_count,
                                &stats->bands[i].packet_count);
            atomic_read_relaxed(&meter->bands[i].byte_count,
                                &stats->bands[i].byte_count);
        }
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

        ovs_mutex_lock(&dp->meters_lock);
        dp_meter_detach_free(&dp->meters, meter_id);
        ovs_mutex_unlock(&dp->meters_lock);
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
    atomic_store_relaxed(&pmd->wait_for_reload, false);
    atomic_store_relaxed(&pmd->reload_tx_qid, false);
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_store_explicit(&pmd->reload, false, memory_order_release);
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

    CMAP_FOR_EACH_WITH_HASH (pmd, node, hash_int(core_id, 0),
                             &dp->poll_threads) {
        if (pmd->core_id == core_id) {
            return dp_netdev_pmd_try_ref(pmd) ? pmd : NULL;
        }
    }

    return NULL;
}

/* Sets the 'struct dp_netdev_pmd_thread' for non-pmd threads. */
static void
dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
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
    atomic_init(&pmd->exit, false);
    pmd->reload_seq = seq_create();
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_init(&pmd->reload, false);
    ovs_mutex_init(&pmd->flow_mutex);
    ovs_mutex_init(&pmd->port_mutex);
    ovs_mutex_init(&pmd->bond_mutex);
    cmap_init(&pmd->flow_table);
    cmap_init(&pmd->classifiers);
    cmap_init(&pmd->simple_match_table);
    ccmap_init(&pmd->n_flows);
    ccmap_init(&pmd->n_simple_flows);
    pmd->ctx.last_rxq = NULL;
    pmd_thread_ctx_time_update(pmd);
    pmd->next_optimization = pmd->ctx.now + DPCLS_OPTIMIZATION_INTERVAL;
    pmd->next_rcu_quiesce = pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
    pmd->next_cycle_store = pmd->ctx.now + PMD_INTERVAL_LEN;
    pmd->busy_cycles_intrvl = xzalloc(PMD_INTERVAL_MAX *
                                      sizeof *pmd->busy_cycles_intrvl);
    hmap_init(&pmd->poll_list);
    hmap_init(&pmd->tx_ports);
    hmap_init(&pmd->tnl_port_cache);
    hmap_init(&pmd->send_port_cache);
    cmap_init(&pmd->tx_bonds);

    pmd_init_max_sleep(dp, pmd);

    /* Initialize DPIF function pointer to the default configured version. */
    atomic_init(&pmd->netdev_input_func, dp_netdev_impl_get_default());

    /* Init default miniflow_extract function */
    atomic_init(&pmd->miniflow_extract_opt, dp_mfex_impl_get_default());

    /* init the 'flow_cache' since there is no
     * actual thread created for NON_PMD_CORE_ID. */
    if (core_id == NON_PMD_CORE_ID) {
        dfc_cache_init(&pmd->flow_cache);
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
    cmap_destroy(&pmd->tx_bonds);
    hmap_destroy(&pmd->poll_list);
    free(pmd->busy_cycles_intrvl);
    /* All flows (including their dpcls_rules) have been deleted already */
    CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
        dpcls_destroy(cls);
        ovsrcu_postpone(free, cls);
    }
    cmap_destroy(&pmd->classifiers);
    cmap_destroy(&pmd->flow_table);
    cmap_destroy(&pmd->simple_match_table);
    ccmap_destroy(&pmd->n_flows);
    ccmap_destroy(&pmd->n_simple_flows);
    ovs_mutex_destroy(&pmd->flow_mutex);
    seq_destroy(pmd->reload_seq);
    ovs_mutex_destroy(&pmd->port_mutex);
    ovs_mutex_destroy(&pmd->bond_mutex);
    free(pmd->netdev_input_func_userdata);
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
        dfc_cache_uninit(&pmd->flow_cache);
        pmd_free_cached_ports(pmd);
        pmd_free_static_tx_qid(pmd);
        ovs_mutex_unlock(&dp->non_pmd_mutex);
    } else {
        atomic_store_relaxed(&pmd->exit, true);
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
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_POP (poll, node, &pmd->poll_list) {
        free(poll);
    }
    HMAP_FOR_EACH_POP (port, node, &pmd->tx_ports) {
        free(port->txq_pkts);
        free(port);
    }
    ovs_mutex_unlock(&pmd->port_mutex);

    ovs_mutex_lock(&pmd->bond_mutex);
    CMAP_FOR_EACH (tx, node, &pmd->tx_bonds) {
        cmap_remove(&pmd->tx_bonds, &tx->node, hash_bond_id(tx->bond_id));
        ovsrcu_postpone(free, tx);
    }
    ovs_mutex_unlock(&pmd->bond_mutex);
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

    if (tx->port->txq_mode == TXQ_MODE_XPS_HASH) {
        int i, n_txq = netdev_n_txq(tx->port->netdev);

        tx->txq_pkts = xzalloc(n_txq * sizeof *tx->txq_pkts);
        for (i = 0; i < n_txq; i++) {
            dp_packet_batch_init(&tx->txq_pkts[i]);
        }
    }

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
    free(tx->txq_pkts);
    free(tx);
    pmd->need_reload = true;
}

/* Add bond to the tx bond cmap of 'pmd'. */
static void
dp_netdev_add_bond_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                             struct tx_bond *bond, bool update)
    OVS_EXCLUDED(pmd->bond_mutex)
{
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->bond_mutex);
    tx = tx_bond_lookup(&pmd->tx_bonds, bond->bond_id);

    if (tx && !update) {
        /* It's not an update and the entry already exists.  Do nothing. */
        goto unlock;
    }

    if (tx) {
        struct tx_bond *new_tx = xmemdup(bond, sizeof *bond);

        /* Copy the stats for each bucket. */
        for (int i = 0; i < BOND_BUCKETS; i++) {
            uint64_t n_packets, n_bytes;

            atomic_read_relaxed(&tx->member_buckets[i].n_packets, &n_packets);
            atomic_read_relaxed(&tx->member_buckets[i].n_bytes, &n_bytes);
            atomic_init(&new_tx->member_buckets[i].n_packets, n_packets);
            atomic_init(&new_tx->member_buckets[i].n_bytes, n_bytes);
        }
        cmap_replace(&pmd->tx_bonds, &tx->node, &new_tx->node,
                     hash_bond_id(bond->bond_id));
        ovsrcu_postpone(free, tx);
    } else {
        tx = xmemdup(bond, sizeof *bond);
        cmap_insert(&pmd->tx_bonds, &tx->node, hash_bond_id(bond->bond_id));
    }
unlock:
    ovs_mutex_unlock(&pmd->bond_mutex);
}

/* Delete bond from the tx bond cmap of 'pmd'. */
static void
dp_netdev_del_bond_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                               uint32_t bond_id)
    OVS_EXCLUDED(pmd->bond_mutex)
{
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->bond_mutex);
    tx = tx_bond_lookup(&pmd->tx_bonds, bond_id);
    if (tx) {
        cmap_remove(&pmd->tx_bonds, &tx->node, hash_bond_id(tx->bond_id));
        ovsrcu_postpone(free, tx);
    }
    ovs_mutex_unlock(&pmd->bond_mutex);
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

    if (type != DPIF_UC_MISS) {
        dp_packet_ol_send_prepare(packet_, 0);
    }

    return dp->upcall_cb(packet_, flow, ufid, pmd->core_id, type, userdata,
                         actions, wc, put_actions, dp->upcall_aux);
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
                             uint16_t tcp_flags)
{
    batch->byte_count += dp_packet_size(packet);
    batch->tcp_flags |= tcp_flags;
    dp_packet_batch_add(&batch->array, packet);
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

    dp_netdev_flow_used(flow, dp_packet_batch_size(&batch->array),
                        batch->byte_count,
                        batch->tcp_flags, pmd->ctx.now / 1000);

    actions = dp_netdev_flow_get_actions(flow);

    dp_netdev_execute_actions(pmd, &batch->array, true, &flow->flow,
                              actions->actions, actions->size);
}

void
dp_netdev_batch_execute(struct dp_netdev_pmd_thread *pmd,
                        struct dp_packet_batch *packets,
                        struct dpcls_rule *rule,
                        uint32_t bytes,
                        uint16_t tcp_flags)
{
    /* Gets action* from the rule. */
    struct dp_netdev_flow *flow = dp_netdev_flow_cast(rule);
    struct dp_netdev_actions *actions = dp_netdev_flow_get_actions(flow);

    dp_netdev_flow_used(flow, dp_packet_batch_size(packets), bytes,
                        tcp_flags, pmd->ctx.now / 1000);
    const uint32_t steal = 1;
    dp_netdev_execute_actions(pmd, packets, steal, &flow->flow,
                              actions->actions, actions->size);
}

static inline void
dp_netdev_queue_batches(struct dp_packet *pkt,
                        struct dp_netdev_flow *flow, uint16_t tcp_flags,
                        struct packet_batch_per_flow *batches,
                        size_t *n_batches)
{
    struct packet_batch_per_flow *batch = flow->batch;

    if (OVS_UNLIKELY(!batch)) {
        batch = &batches[(*n_batches)++];
        packet_batch_per_flow_init(batch, flow);
    }

    packet_batch_per_flow_update(batch, pkt, tcp_flags);
}

static inline void
packet_enqueue_to_flow_map(struct dp_packet *packet,
                           struct dp_netdev_flow *flow,
                           uint16_t tcp_flags,
                           struct dp_packet_flow_map *flow_map,
                           size_t index)
{
    struct dp_packet_flow_map *map = &flow_map[index];
    map->flow = flow;
    map->packet = packet;
    map->tcp_flags = tcp_flags;
}

/* SMC lookup function for a batch of packets.
 * By doing batching SMC lookup, we can use prefetch
 * to hide memory access latency.
 */
static inline void
smc_lookup_batch(struct dp_netdev_pmd_thread *pmd,
            struct netdev_flow_key *keys,
            struct netdev_flow_key **missed_keys,
            struct dp_packet_batch *packets_,
            const int cnt,
            struct dp_packet_flow_map *flow_map,
            uint8_t *index_map)
{
    int i;
    struct dp_packet *packet;
    size_t n_smc_hit = 0, n_missed = 0;
    struct dfc_cache *cache = &pmd->flow_cache;
    struct smc_cache *smc_cache = &cache->smc_cache;
    const struct cmap_node *flow_node;
    int recv_idx;
    uint16_t tcp_flags;

    /* Prefetch buckets for all packets */
    for (i = 0; i < cnt; i++) {
        OVS_PREFETCH(&smc_cache->buckets[keys[i].hash & SMC_MASK]);
    }

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) {
        struct dp_netdev_flow *flow = NULL;
        flow_node = smc_entry_get(pmd, keys[i].hash);
        bool hit = false;
        /* Get the original order of this packet in received batch. */
        recv_idx = index_map[i];

        if (OVS_LIKELY(flow_node != NULL)) {
            CMAP_NODE_FOR_EACH (flow, node, flow_node) {
                /* Since we dont have per-port megaflow to check the port
                 * number, we need to  verify that the input ports match. */
                if (OVS_LIKELY(dpcls_rule_matches_key(&flow->cr, &keys[i]) &&
                flow->flow.in_port.odp_port == packet->md.in_port.odp_port)) {
                    tcp_flags = miniflow_get_tcp_flags(&keys[i].mf);

                    /* SMC hit and emc miss, we insert into EMC */
                    keys[i].len =
                        netdev_flow_key_size(miniflow_n_values(&keys[i].mf));
                    emc_probabilistic_insert(pmd, &keys[i], flow);
                    /* Add these packets into the flow map in the same order
                     * as received.
                     */
                    packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                               flow_map, recv_idx);
                    n_smc_hit++;
                    hit = true;
                    break;
                }
            }
            if (hit) {
                continue;
            }
        }

        /* SMC missed. Group missed packets together at
         * the beginning of the 'packets' array. */
        dp_packet_batch_refill(packets_, packet, i);

        /* Preserve the order of packet for flow batching. */
        index_map[n_missed] = recv_idx;

        /* Put missed keys to the pointer arrays return to the caller */
        missed_keys[n_missed++] = &keys[i];
    }

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SMC_HIT, n_smc_hit);
}

struct dp_netdev_flow *
smc_lookup_single(struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet *packet,
                  struct netdev_flow_key *key)
{
    const struct cmap_node *flow_node = smc_entry_get(pmd, key->hash);

    if (OVS_LIKELY(flow_node != NULL)) {
        struct dp_netdev_flow *flow = NULL;

        CMAP_NODE_FOR_EACH (flow, node, flow_node) {
            /* Since we dont have per-port megaflow to check the port
             * number, we need to verify that the input ports match. */
            if (OVS_LIKELY(dpcls_rule_matches_key(&flow->cr, key) &&
                flow->flow.in_port.odp_port == packet->md.in_port.odp_port)) {

                return (void *) flow;
            }
        }
    }

    return NULL;
}

inline int
dp_netdev_hw_flow(const struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet *packet,
                  struct dp_netdev_flow **flow)
{
    uint32_t mark;

#ifdef ALLOW_EXPERIMENTAL_API /* Packet restoration API required. */
    /* Restore the packet if HW processing was terminated before completion. */
    struct dp_netdev_rxq *rxq = pmd->ctx.last_rxq;
    bool miss_api_supported;

    atomic_read_relaxed(&rxq->port->netdev->hw_info.miss_api_supported,
                        &miss_api_supported);
    if (miss_api_supported) {
        int err = netdev_hw_miss_packet_recover(rxq->port->netdev, packet);
        if (err && err != EOPNOTSUPP) {
            COVERAGE_INC(datapath_drop_hw_miss_recover);
            return -1;
        }
    }
#endif

    /* If no mark, no flow to find. */
    if (!dp_packet_has_flow_mark(packet, &mark)) {
        *flow = NULL;
        return 0;
    }

    *flow = mark_to_flow_find(pmd, mark);
    return 0;
}

/* Enqueues already classified packet into per-flow batches or the flow map,
 * depending on the fact if batching enabled. */
static inline void
dfc_processing_enqueue_classified_packet(struct dp_packet *packet,
                                         struct dp_netdev_flow *flow,
                                         uint16_t tcp_flags,
                                         bool batch_enable,
                                         struct packet_batch_per_flow *batches,
                                         size_t *n_batches,
                                         struct dp_packet_flow_map *flow_map,
                                         size_t *map_cnt)

{
    if (OVS_LIKELY(batch_enable)) {
        dp_netdev_queue_batches(packet, flow, tcp_flags, batches,
                                n_batches);
    } else {
        /* Flow batching should be performed only after fast-path
         * processing is also completed for packets with emc miss
         * or else it will result in reordering of packets with
         * same datapath flows. */
        packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                   flow_map, (*map_cnt)++);
    }

}

/* Try to process all ('cnt') the 'packets' using only the datapath flow cache
 * 'pmd->flow_cache'. If a flow is not found for a packet 'packets[i]', the
 * miniflow is copied into 'keys' and the packet pointer is moved at the
 * beginning of the 'packets' array. The pointers of missed keys are put in the
 * missed_keys pointer array for future processing.
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
dfc_processing(struct dp_netdev_pmd_thread *pmd,
               struct dp_packet_batch *packets_,
               struct netdev_flow_key *keys,
               struct netdev_flow_key **missed_keys,
               struct packet_batch_per_flow batches[], size_t *n_batches,
               struct dp_packet_flow_map *flow_map,
               size_t *n_flows, uint8_t *index_map,
               bool md_is_valid, odp_port_t port_no)
{
    const bool netdev_flow_api = netdev_is_flow_api_enabled();
    const uint32_t recirc_depth = *recirc_depth_get();
    const size_t cnt = dp_packet_batch_size(packets_);
    size_t n_missed = 0, n_emc_hit = 0, n_phwol_hit = 0;
    size_t n_mfex_opt_hit = 0, n_simple_hit = 0;
    struct dfc_cache *cache = &pmd->flow_cache;
    struct netdev_flow_key *key = &keys[0];
    struct dp_packet *packet;
    size_t map_cnt = 0;
    bool batch_enable = true;

    const bool simple_match_enabled =
        !md_is_valid && dp_netdev_simple_match_enabled(pmd, port_no);
    /* 'simple_match_table' is a full flow table.  If the flow is not there,
     * upcall is required, and there is no chance to find a match in caches. */
    const bool smc_enable_db = !simple_match_enabled && pmd->ctx.smc_enable_db;
    const uint32_t cur_min = simple_match_enabled
                             ? 0 : pmd->ctx.emc_insert_min;

    pmd_perf_update_counter(&pmd->perf_stats,
                            md_is_valid ? PMD_STAT_RECIRC : PMD_STAT_RECV,
                            cnt);
    int i;
    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) {
        struct dp_netdev_flow *flow = NULL;
        uint16_t tcp_flags;

        if (OVS_UNLIKELY(dp_packet_size(packet) < ETH_HEADER_LEN)) {
            dp_packet_delete(packet);
            COVERAGE_INC(datapath_drop_rx_invalid_packet);
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

        if (netdev_flow_api && recirc_depth == 0) {
            if (OVS_UNLIKELY(dp_netdev_hw_flow(pmd, packet, &flow))) {
                /* Packet restoration failed and it was dropped, do not
                 * continue processing.
                 */
                continue;
            }
            if (OVS_LIKELY(flow)) {
                tcp_flags = parse_tcp_flags(packet, NULL, NULL, NULL);
                n_phwol_hit++;
                dfc_processing_enqueue_classified_packet(
                        packet, flow, tcp_flags, batch_enable,
                        batches, n_batches, flow_map, &map_cnt);
                continue;
            }
        }

        if (!flow && simple_match_enabled) {
            ovs_be16 dl_type = 0, vlan_tci = 0;
            uint8_t nw_frag = 0;

            tcp_flags = parse_tcp_flags(packet, &dl_type, &nw_frag, &vlan_tci);
            flow = dp_netdev_simple_match_lookup(pmd, port_no, dl_type,
                                                 nw_frag, vlan_tci);
            if (OVS_LIKELY(flow)) {
                n_simple_hit++;
                dfc_processing_enqueue_classified_packet(
                        packet, flow, tcp_flags, batch_enable,
                        batches, n_batches, flow_map, &map_cnt);
                continue;
            }
        }

        miniflow_extract(packet, &key->mf);
        key->len = 0; /* Not computed yet. */
        key->hash =
                (md_is_valid == false)
                ? dpif_netdev_packet_get_rss_hash_orig_pkt(packet, &key->mf)
                : dpif_netdev_packet_get_rss_hash(packet, &key->mf);

        /* If EMC is disabled skip emc_lookup */
        flow = (cur_min != 0) ? emc_lookup(&cache->emc_cache, key) : NULL;
        if (OVS_LIKELY(flow)) {
            tcp_flags = miniflow_get_tcp_flags(&key->mf);
            n_emc_hit++;
            dfc_processing_enqueue_classified_packet(
                    packet, flow, tcp_flags, batch_enable,
                    batches, n_batches, flow_map, &map_cnt);
        } else {
            /* Exact match cache missed. Group missed packets together at
             * the beginning of the 'packets' array. */
            dp_packet_batch_refill(packets_, packet, i);

            /* Preserve the order of packet for flow batching. */
            index_map[n_missed] = map_cnt;
            flow_map[map_cnt++].flow = NULL;

            /* 'key[n_missed]' contains the key of the current packet and it
             * will be passed to SMC lookup. The next key should be extracted
             * to 'keys[n_missed + 1]'.
             * We also maintain a pointer array to keys missed both SMC and EMC
             * which will be returned to the caller for future processing. */
            missed_keys[n_missed] = key;
            key = &keys[++n_missed];

            /* Skip batching for subsequent packets to avoid reordering. */
            batch_enable = false;
        }
    }
    /* Count of packets which are not flow batched. */
    *n_flows = map_cnt;

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_PHWOL_HIT, n_phwol_hit);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MFEX_OPT_HIT,
                            n_mfex_opt_hit);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SIMPLE_HIT,
                            n_simple_hit);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT, n_emc_hit);

    if (!smc_enable_db) {
        return dp_packet_batch_size(packets_);
    }

    /* Packets miss EMC will do a batch lookup in SMC if enabled */
    smc_lookup_batch(pmd, keys, missed_keys, packets_,
                     n_missed, flow_map, index_map);

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
    odp_port_t orig_in_port = packet->md.orig_in_port;

    match.tun_md.valid = false;
    miniflow_expand(&key->mf, &match.flow);
    memset(&match.wc, 0, sizeof match.wc);

    ofpbuf_clear(actions);
    ofpbuf_clear(put_actions);

    odp_flow_key_hash(&match.flow, sizeof match.flow, &ufid);
    error = dp_netdev_upcall(pmd, packet, &match.flow, &match.wc,
                             &ufid, DPIF_UC_MISS, NULL, actions,
                             put_actions);
    if (OVS_UNLIKELY(error && error != ENOSPC)) {
        dp_packet_delete(packet);
        COVERAGE_INC(datapath_drop_upcall_error);
        return error;
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in dpif_netdev_flow_put(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(VLAN_VID_MASK | VLAN_CFI);
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
         * to be locking revalidators out of making flow modifications. */
        ovs_mutex_lock(&pmd->flow_mutex);
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
        if (OVS_LIKELY(!netdev_flow)) {
            netdev_flow = dp_netdev_flow_add(pmd, &match, &ufid,
                                             add_actions->data,
                                             add_actions->size, orig_in_port);
        }
        ovs_mutex_unlock(&pmd->flow_mutex);
        uint32_t hash = dp_netdev_flow_hash(&netdev_flow->ufid);
        smc_insert(pmd, key, hash);
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
                     struct netdev_flow_key **keys,
                     struct dp_packet_flow_map *flow_map,
                     uint8_t *index_map,
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
        keys[i]->len = netdev_flow_key_size(miniflow_n_values(&keys[i]->mf));
    }
    /* Get the classifier for the in_port */
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        any_miss = !dpcls_lookup(cls, (const struct netdev_flow_key **)keys,
                                rules, cnt, &lookup_cnt);
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
            netdev_flow = dp_netdev_pmd_lookup_flow(pmd, keys[i],
                                                    &add_lookup_cnt);
            if (netdev_flow) {
                lookup_cnt += add_lookup_cnt;
                rules[i] = &netdev_flow->cr;
                continue;
            }

            int error = handle_packet_upcall(pmd, packet, keys[i],
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
                COVERAGE_INC(datapath_drop_lock_error);
                upcall_fail_cnt++;
            }
        }
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        struct dp_netdev_flow *flow;
        /* Get the original order of this packet in received batch. */
        int recv_idx = index_map[i];
        uint16_t tcp_flags;

        if (OVS_UNLIKELY(!rules[i])) {
            continue;
        }

        flow = dp_netdev_flow_cast(rules[i]);
        uint32_t hash =  dp_netdev_flow_hash(&flow->ufid);
        smc_insert(pmd, keys[i], hash);

        emc_probabilistic_insert(pmd, keys[i], flow);
        /* Add these packets into the flow map in the same order
         * as received.
         */
        tcp_flags = miniflow_get_tcp_flags(&keys[i]->mf);
        packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                   flow_map, recv_idx);
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
    struct netdev_flow_key *missed_keys[PKT_ARRAY_SIZE];
    struct packet_batch_per_flow batches[PKT_ARRAY_SIZE];
    size_t n_batches;
    struct dp_packet_flow_map flow_map[PKT_ARRAY_SIZE];
    uint8_t index_map[PKT_ARRAY_SIZE];
    size_t n_flows, i;

    odp_port_t in_port;

    n_batches = 0;
    dfc_processing(pmd, packets, keys, missed_keys, batches, &n_batches,
                   flow_map, &n_flows, index_map, md_is_valid, port_no);

    if (!dp_packet_batch_is_empty(packets)) {
        /* Get ingress port from first packet's metadata. */
        in_port = packets->packets[0]->md.in_port.odp_port;
        fast_path_processing(pmd, packets, missed_keys,
                             flow_map, index_map, in_port);
    }

    /* Batch rest of packets which are in flow map. */
    for (i = 0; i < n_flows; i++) {
        struct dp_packet_flow_map *map = &flow_map[i];

        if (OVS_UNLIKELY(!map->flow)) {
            continue;
        }
        dp_netdev_queue_batches(map->packet, map->flow, map->tcp_flags,
                                batches, &n_batches);
     }

    /* All the flow batches need to be reset before any call to
     * packet_batch_per_flow_execute() as it could potentially trigger
     * recirculation. When a packet matching flow 'j' happens to be
     * recirculated, the nested call to dp_netdev_input__() could potentially
     * classify the packet as matching another flow - say 'k'. It could happen
     * that in the previous call to dp_netdev_input__() that same flow 'k' had
     * already its own batches[k] still waiting to be served.  So if its
     * 'batch' member is not reset, the recirculated packet would be wrongly
     * appended to batches[k] of the 1st call to dp_netdev_input__(). */
    for (i = 0; i < n_batches; i++) {
        batches[i].flow->batch = NULL;
    }

    for (i = 0; i < n_batches; i++) {
        packet_batch_per_flow_execute(&batches[i], pmd);
    }
}

int32_t
dp_netdev_input(struct dp_netdev_pmd_thread *pmd,
                struct dp_packet_batch *packets,
                odp_port_t port_no)
{
    dp_netdev_input__(pmd, packets, false, port_no);
    return 0;
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
        if (tx->port->txq_mode != TXQ_MODE_XPS) {
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
        COVERAGE_INC(datapath_drop_userspace_action_error);
    }
}

static bool
dp_execute_output_action(struct dp_netdev_pmd_thread *pmd,
                         struct dp_packet_batch *packets_,
                         bool should_steal, odp_port_t port_no)
{
    struct tx_port *p = pmd_send_port_cache_lookup(pmd, port_no);
    struct dp_packet_batch out;

    if (!OVS_LIKELY(p)) {
        COVERAGE_ADD(datapath_drop_invalid_port,
                     dp_packet_batch_size(packets_));
        dp_packet_delete_batch(packets_, should_steal);
        return false;
    }
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

    struct dp_packet *packet;
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        p->output_pkts_rxqs[dp_packet_batch_size(&p->output_pkts)] =
            pmd->ctx.last_rxq;
        dp_packet_batch_add(&p->output_pkts, packet);
    }
    return true;
}

static void
dp_execute_lb_output_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet_batch *packets_,
                            bool should_steal, uint32_t bond)
{
    struct tx_bond *p_bond = tx_bond_lookup(&pmd->tx_bonds, bond);
    struct dp_packet_batch out;
    struct dp_packet *packet;

    if (!p_bond) {
        COVERAGE_ADD(datapath_drop_invalid_bond,
                     dp_packet_batch_size(packets_));
        dp_packet_delete_batch(packets_, should_steal);
        return;
    }
    if (!should_steal) {
        dp_packet_batch_clone(&out, packets_);
        dp_packet_batch_reset_cutlen(packets_);
        packets_ = &out;
    }
    dp_packet_batch_apply_cutlen(packets_);

    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        /*
         * Lookup the bond-hash table using hash to get the member.
         */
        uint32_t hash = dp_packet_get_rss_hash(packet);
        struct member_entry *s_entry
            = &p_bond->member_buckets[hash & BOND_MASK];
        odp_port_t bond_member = s_entry->member_id;
        uint32_t size = dp_packet_size(packet);
        struct dp_packet_batch output_pkt;

        dp_packet_batch_init_packet(&output_pkt, packet);
        if (OVS_LIKELY(dp_execute_output_action(pmd, &output_pkt, true,
                                                bond_member))) {
            /* Update member stats. */
            non_atomic_ullong_add(&s_entry->n_packets, 1);
            non_atomic_ullong_add(&s_entry->n_bytes, size);
        }
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
    uint32_t packet_count, packets_dropped;

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        dp_execute_output_action(pmd, packets_, should_steal,
                                 nl_attr_get_odp_port(a));
        return;

    case OVS_ACTION_ATTR_LB_OUTPUT:
        dp_execute_lb_output_action(pmd, packets_, should_steal,
                                    nl_attr_get_u32(a));
        return;

    case OVS_ACTION_ATTR_TUNNEL_PUSH:
        if (should_steal) {
            /* We're requested to push tunnel header, but also we need to take
             * the ownership of these packets. Thus, we can avoid performing
             * the action, because the caller will not use the result anyway.
             * Just break to free the batch. */
            break;
        }
        dp_packet_batch_apply_cutlen(packets_);
        packet_count = dp_packet_batch_size(packets_);
        if (push_tnl_action(pmd, a, packets_)) {
            COVERAGE_ADD(datapath_drop_tunnel_push_error,
                         packet_count);
        }
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

                packet_count = dp_packet_batch_size(packets_);
                netdev_pop_header(p->port->netdev, packets_);
                packets_dropped =
                   packet_count - dp_packet_batch_size(packets_);
                if (packets_dropped) {
                    COVERAGE_ADD(datapath_drop_tunnel_pop_error,
                                 packets_dropped);
                }
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
            COVERAGE_ADD(datapath_drop_invalid_tnl_port,
                         dp_packet_batch_size(packets_));
        } else {
            COVERAGE_ADD(datapath_drop_recirc_error,
                         dp_packet_batch_size(packets_));
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
                odp_flow_key_hash(&flow, sizeof flow, &ufid);
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
        COVERAGE_ADD(datapath_drop_lock_error,
                     dp_packet_batch_size(packets_));
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

        COVERAGE_ADD(datapath_drop_recirc_error,
                     dp_packet_batch_size(packets_));
        VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
        break;

    case OVS_ACTION_ATTR_CT: {
        const struct nlattr *b;
        bool force = false;
        bool commit = false;
        unsigned int left;
        uint16_t zone = 0;
        uint32_t tp_id = 0;
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
            case OVS_CT_ATTR_TIMEOUT:
                if (!str_to_uint(nl_attr_get_string(b), 10, &tp_id)) {
                    VLOG_WARN("Invalid Timeout Policy ID: %s.",
                              nl_attr_get_string(b));
                    tp_id = DEFAULT_TP_ID;
                }
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
                    case OVS_NAT_ATTR_PROTO_RANDOM:
                        nat_action_info.nat_flags |= NAT_RANGE_RANDOM;
                        break;
                    case OVS_NAT_ATTR_PERSISTENT:
                        nat_action_info.nat_flags |= NAT_PERSISTENT;
                        break;
                    case OVS_NAT_ATTR_PROTO_HASH:
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

        conntrack_execute(dp->conntrack, packets_, aux->flow->dl_type, force,
                          commit, zone, setmark, setlabel, helper,
                          nat_action_info_ref, pmd->ctx.now / 1000, tp_id);
        break;
    }

    case OVS_ACTION_ATTR_METER:
        dp_netdev_run_meter(pmd->dp, packets_, nl_attr_get_u32(a),
                            pmd->ctx.now / 1000);
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
    case OVS_ACTION_ATTR_CHECK_PKT_LEN:
    case OVS_ACTION_ATTR_DROP:
    case OVS_ACTION_ATTR_ADD_MPLS:
    case OVS_ACTION_ATTR_DEC_TTL:
    case OVS_ACTION_ATTR_PSAMPLE:
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
    dump->ct = dp->conntrack;

    conntrack_dump_start(dp->conntrack, &dump->dump, pzone, ptot_bkts);

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
dpif_netdev_ct_exp_dump_start(struct dpif *dpif,
                              struct ct_dpif_dump_state **dump_,
                              const uint16_t *pzone)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_ct_dump *dump;

    dump = xzalloc(sizeof *dump);
    dump->dp = dp;
    dump->ct = dp->conntrack;

    conntrack_exp_dump_start(dp->conntrack, &dump->dump, pzone);

    *dump_ = &dump->up;

    return 0;
}

static int
dpif_netdev_ct_exp_dump_next(struct dpif *dpif OVS_UNUSED,
                             struct ct_dpif_dump_state *dump_,
                             struct ct_dpif_exp *entry)
{
    struct dp_netdev_ct_dump *dump;

    INIT_CONTAINER(dump, dump_, up);

    return conntrack_exp_dump_next(&dump->dump, entry);
}

static int
dpif_netdev_ct_exp_dump_done(struct dpif *dpif OVS_UNUSED,
                             struct ct_dpif_dump_state *dump_)
{
    struct dp_netdev_ct_dump *dump;
    int err;

    INIT_CONTAINER(dump, dump_, up);

    err = conntrack_exp_dump_done(&dump->dump);

    free(dump);

    return err;
}

static int
dpif_netdev_ct_flush(struct dpif *dpif, const uint16_t *zone,
                     const struct ct_dpif_tuple *tuple)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (tuple) {
        return conntrack_flush_tuple(dp->conntrack, tuple, zone ? *zone : 0);
    }
    return conntrack_flush(dp->conntrack, zone);
}

static int
dpif_netdev_ct_set_maxconns(struct dpif *dpif, uint32_t maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_maxconns(dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_maxconns(struct dpif *dpif, uint32_t *maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_maxconns(dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_nconns(struct dpif *dpif, uint32_t *nconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_nconns(dp->conntrack, nconns);
}

static int
dpif_netdev_ct_set_tcp_seq_chk(struct dpif *dpif, bool enabled)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_tcp_seq_chk(dp->conntrack, enabled);
}

static int
dpif_netdev_ct_get_tcp_seq_chk(struct dpif *dpif, bool *enabled)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    *enabled = conntrack_get_tcp_seq_chk(dp->conntrack);
    return 0;
}

static int
dpif_netdev_ct_set_sweep_interval(struct dpif *dpif, uint32_t ms)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return conntrack_set_sweep_interval(dp->conntrack, ms);
}

static int
dpif_netdev_ct_get_sweep_interval(struct dpif *dpif, uint32_t *ms)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    *ms = conntrack_get_sweep_interval(dp->conntrack);
    return 0;
}

static int
dpif_netdev_ct_set_limits(struct dpif *dpif,
                           const struct ovs_list *zone_limits)
{
    int err = 0;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    struct ct_dpif_zone_limit *zone_limit;
    LIST_FOR_EACH (zone_limit, node, zone_limits) {
        err = zone_limit_update(dp->conntrack, zone_limit->zone,
                                zone_limit->limit);
        if (err != 0) {
            break;
        }
    }
    return err;
}

static int
dpif_netdev_ct_get_limits(struct dpif *dpif,
                           const struct ovs_list *zone_limits_request,
                           struct ovs_list *zone_limits_reply)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct conntrack_zone_info czl;

    if (!ovs_list_is_empty(zone_limits_request)) {
        struct ct_dpif_zone_limit *zone_limit;
        LIST_FOR_EACH (zone_limit, node, zone_limits_request) {
            czl = zone_limit_get(dp->conntrack, zone_limit->zone);
            if (czl.zone == zone_limit->zone || czl.zone == DEFAULT_ZONE) {
                ct_dpif_push_zone_limit(zone_limits_reply, zone_limit->zone,
                                        czl.limit,
                                        czl.count);
            } else {
                return EINVAL;
            }
        }
    } else {
        czl = zone_limit_get(dp->conntrack, DEFAULT_ZONE);
        if (czl.zone == DEFAULT_ZONE) {
            ct_dpif_push_zone_limit(zone_limits_reply, DEFAULT_ZONE,
                                    czl.limit, 0);
        }

        for (int z = MIN_ZONE; z <= MAX_ZONE; z++) {
            czl = zone_limit_get(dp->conntrack, z);
            if (czl.zone == z) {
                ct_dpif_push_zone_limit(zone_limits_reply, z, czl.limit,
                                        czl.count);
            }
        }
    }

    return 0;
}

static int
dpif_netdev_ct_del_limits(struct dpif *dpif,
                           const struct ovs_list *zone_limits)
{
    int err = 0;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct ct_dpif_zone_limit *zone_limit;
    LIST_FOR_EACH (zone_limit, node, zone_limits) {
        err = zone_limit_delete(dp->conntrack, zone_limit->zone);
        if (err != 0) {
            break;
        }
    }

    return err;
}

static int
dpif_netdev_ct_get_features(struct dpif *dpif OVS_UNUSED,
                            enum ct_features *features)
{
    if (features != NULL) {
        *features = CONNTRACK_F_ZERO_SNAT;
    }
    return 0;
}

static int
dpif_netdev_ct_set_timeout_policy(struct dpif *dpif,
                                  const struct ct_dpif_timeout_policy *dpif_tp)
{
    struct timeout_policy tp;
    struct dp_netdev *dp;

    dp = get_dp_netdev(dpif);
    memcpy(&tp.policy, dpif_tp, sizeof tp.policy);
    return timeout_policy_update(dp->conntrack, &tp);
}

static int
dpif_netdev_ct_get_timeout_policy(struct dpif *dpif, uint32_t tp_id,
                                  struct ct_dpif_timeout_policy *dpif_tp)
{
    struct timeout_policy *tp;
    struct dp_netdev *dp;
    int err = 0;

    dp = get_dp_netdev(dpif);
    tp = timeout_policy_get(dp->conntrack, tp_id);
    if (!tp) {
        return ENOENT;
    }
    memcpy(dpif_tp, &tp->policy, sizeof tp->policy);
    return err;
}

static int
dpif_netdev_ct_del_timeout_policy(struct dpif *dpif,
                                  uint32_t tp_id)
{
    struct dp_netdev *dp;
    int err = 0;

    dp = get_dp_netdev(dpif);
    err = timeout_policy_delete(dp->conntrack, tp_id);
    return err;
}

static int
dpif_netdev_ct_get_timeout_policy_name(struct dpif *dpif OVS_UNUSED,
                                       uint32_t tp_id,
                                       uint16_t dl_type OVS_UNUSED,
                                       uint8_t nw_proto OVS_UNUSED,
                                       char **tp_name, bool *is_generic)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "%"PRIu32, tp_id);
    *tp_name = ds_steal_cstr(&ds);
    *is_generic = true;
    return 0;
}

static int
dpif_netdev_ipf_set_enabled(struct dpif *dpif, bool v6, bool enable)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_enabled(conntrack_ipf_ctx(dp->conntrack), v6, enable);
}

static int
dpif_netdev_ipf_set_min_frag(struct dpif *dpif, bool v6, uint32_t min_frag)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_min_frag(conntrack_ipf_ctx(dp->conntrack), v6, min_frag);
}

static int
dpif_netdev_ipf_set_max_nfrags(struct dpif *dpif, uint32_t max_frags)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_max_nfrags(conntrack_ipf_ctx(dp->conntrack), max_frags);
}

/* Adjust this function if 'dpif_ipf_status' and 'ipf_status' were to
 * diverge. */
static int
dpif_netdev_ipf_get_status(struct dpif *dpif,
                           struct dpif_ipf_status *dpif_ipf_status)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    ipf_get_status(conntrack_ipf_ctx(dp->conntrack),
                   (struct ipf_status *) dpif_ipf_status);
    return 0;
}

static int
dpif_netdev_ipf_dump_start(struct dpif *dpif OVS_UNUSED,
                           struct ipf_dump_ctx **ipf_dump_ctx)
{
    return ipf_dump_start(ipf_dump_ctx);
}

static int
dpif_netdev_ipf_dump_next(struct dpif *dpif, void *ipf_dump_ctx, char **dump)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_dump_next(conntrack_ipf_ctx(dp->conntrack), ipf_dump_ctx,
                         dump);
}

static int
dpif_netdev_ipf_dump_done(struct dpif *dpif OVS_UNUSED, void *ipf_dump_ctx)
{
    return ipf_dump_done(ipf_dump_ctx);

}

static int
dpif_netdev_bond_add(struct dpif *dpif, uint32_t bond_id,
                     odp_port_t *member_map)
{
    struct tx_bond *new_tx = xzalloc(sizeof *new_tx);
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    /* Prepare new bond mapping. */
    new_tx->bond_id = bond_id;
    for (int bucket = 0; bucket < BOND_BUCKETS; bucket++) {
        new_tx->member_buckets[bucket].member_id = member_map[bucket];
    }

    ovs_mutex_lock(&dp->bond_mutex);
    /* Check if bond already existed. */
    struct tx_bond *old_tx = tx_bond_lookup(&dp->tx_bonds, bond_id);
    if (old_tx) {
        cmap_replace(&dp->tx_bonds, &old_tx->node, &new_tx->node,
                     hash_bond_id(bond_id));
        ovsrcu_postpone(free, old_tx);
    } else {
        cmap_insert(&dp->tx_bonds, &new_tx->node, hash_bond_id(bond_id));
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    /* Update all PMDs with new bond mapping. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_add_bond_tx_to_pmd(pmd, new_tx, true);
    }
    return 0;
}

static int
dpif_netdev_bond_del(struct dpif *dpif, uint32_t bond_id)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    struct tx_bond *tx;

    ovs_mutex_lock(&dp->bond_mutex);
    /* Check if bond existed. */
    tx = tx_bond_lookup(&dp->tx_bonds, bond_id);
    if (tx) {
        cmap_remove(&dp->tx_bonds, &tx->node, hash_bond_id(bond_id));
        ovsrcu_postpone(free, tx);
    } else {
        /* Bond is not present. */
        ovs_mutex_unlock(&dp->bond_mutex);
        return ENOENT;
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    /* Remove the bond map in all pmds. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_del_bond_tx_from_pmd(pmd, bond_id);
    }
    return 0;
}

static int
dpif_netdev_bond_stats_get(struct dpif *dpif, uint32_t bond_id,
                           uint64_t *n_bytes)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    if (!tx_bond_lookup(&dp->tx_bonds, bond_id)) {
        return ENOENT;
    }

    /* Search the bond in all PMDs. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct tx_bond *pmd_bond_entry
            = tx_bond_lookup(&pmd->tx_bonds, bond_id);

        if (!pmd_bond_entry) {
            continue;
        }

        /* Read bond stats. */
        for (int i = 0; i < BOND_BUCKETS; i++) {
            uint64_t pmd_n_bytes;

            atomic_read_relaxed(&pmd_bond_entry->member_buckets[i].n_bytes,
                                &pmd_n_bytes);
            n_bytes[i] += pmd_n_bytes;
        }
    }
    return 0;
}

const struct dpif_class dpif_netdev_class = {
    "netdev",
    true,                       /* cleanup_required */
    true,                       /* synced_dp_layers */
    dpif_netdev_init,
    dpif_netdev_enumerate,
    dpif_netdev_port_open_type,
    dpif_netdev_open,
    dpif_netdev_close,
    dpif_netdev_destroy,
    dpif_netdev_run,
    dpif_netdev_wait,
    dpif_netdev_get_stats,
    NULL,                      /* set_features */
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
    dpif_netdev_offload_stats_get,
    NULL,                       /* recv_set */
    NULL,                       /* handlers_set */
    dpif_netdev_number_handlers_required,
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
    dpif_netdev_ct_exp_dump_start,
    dpif_netdev_ct_exp_dump_next,
    dpif_netdev_ct_exp_dump_done,
    dpif_netdev_ct_flush,
    dpif_netdev_ct_set_maxconns,
    dpif_netdev_ct_get_maxconns,
    dpif_netdev_ct_get_nconns,
    dpif_netdev_ct_set_tcp_seq_chk,
    dpif_netdev_ct_get_tcp_seq_chk,
    dpif_netdev_ct_set_sweep_interval,
    dpif_netdev_ct_get_sweep_interval,
    dpif_netdev_ct_set_limits,
    dpif_netdev_ct_get_limits,
    dpif_netdev_ct_del_limits,
    dpif_netdev_ct_set_timeout_policy,
    dpif_netdev_ct_get_timeout_policy,
    dpif_netdev_ct_del_timeout_policy,
    NULL,                       /* ct_timeout_policy_dump_start */
    NULL,                       /* ct_timeout_policy_dump_next */
    NULL,                       /* ct_timeout_policy_dump_done */
    dpif_netdev_ct_get_timeout_policy_name,
    dpif_netdev_ct_get_features,
    dpif_netdev_ipf_set_enabled,
    dpif_netdev_ipf_set_min_frag,
    dpif_netdev_ipf_set_max_nfrags,
    dpif_netdev_ipf_get_status,
    dpif_netdev_ipf_dump_start,
    dpif_netdev_ipf_dump_next,
    dpif_netdev_ipf_dump_done,
    dpif_netdev_meter_get_features,
    dpif_netdev_meter_set,
    dpif_netdev_meter_get,
    dpif_netdev_meter_del,
    dpif_netdev_bond_add,
    dpif_netdev_bond_del,
    dpif_netdev_bond_stats_get,
    NULL,                       /* cache_get_supported_levels */
    NULL,                       /* cache_get_name */
    NULL,                       /* cache_get_size */
    NULL,                       /* cache_set_size */
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

static void
dpcls_subtable_destroy_cb(struct dpcls_subtable *subtable)
{
    cmap_destroy(&subtable->rules);
    ovsrcu_postpone(free, subtable->mf_masks);
    ovsrcu_postpone(free, subtable);
}

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
    dpcls_info_dec_usage(subtable->lookup_func_info);
    ovsrcu_postpone(dpcls_subtable_destroy_cb, subtable);
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

    /* The count of bits in the mask defines the space required for masks.
     * Then call gen_masks() to create the appropriate masks, avoiding the cost
     * of doing runtime calculations. */
    uint32_t unit0 = count_1bits(mask->mf.map.bits[0]);
    uint32_t unit1 = count_1bits(mask->mf.map.bits[1]);
    subtable->mf_bits_set_unit0 = unit0;
    subtable->mf_bits_set_unit1 = unit1;
    subtable->mf_masks = xmalloc(sizeof(uint64_t) * (unit0 + unit1));
    dpcls_flow_key_gen_masks(mask, subtable->mf_masks, unit0, unit1);

    /* Get the preferred subtable search function for this (u0,u1) subtable.
     * The function is guaranteed to always return a valid implementation, and
     * possibly an ISA optimized, and/or specialized implementation. Initialize
     * the subtable search function atomically to avoid garbage data being read
     * by the PMD thread.
     */
    atomic_init(&subtable->lookup_func,
                dpcls_subtable_get_best_impl(unit0, unit1,
                                             &subtable->lookup_func_info));
    dpcls_info_inc_usage(subtable->lookup_func_info);

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

/* Checks for the best available implementation for each subtable lookup
 * function, and assigns it as the lookup function pointer for each subtable.
 * Returns the number of subtables that have changed lookup implementation.
 * This function requires holding a flow_mutex when called. This is to make
 * sure modifications done by this function are not overwritten. This could
 * happen if dpcls_sort_subtable_vector() is called at the same time as this
 * function.
 */
static uint32_t
dpcls_subtable_lookup_reprobe(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    uint32_t subtables_changed = 0;
    struct dpcls_subtable *subtable = NULL;

    PVECTOR_FOR_EACH (subtable, pvec) {
        uint32_t u0_bits = subtable->mf_bits_set_unit0;
        uint32_t u1_bits = subtable->mf_bits_set_unit1;
        void *old_func = subtable->lookup_func;
        struct dpcls_subtable_lookup_info_t *old_info;
        old_info = subtable->lookup_func_info;
        /* Set the subtable lookup function atomically to avoid garbage data
         * being read by the PMD thread. */
        atomic_store_relaxed(&subtable->lookup_func,
                dpcls_subtable_get_best_impl(u0_bits, u1_bits,
                                             &subtable->lookup_func_info));
        if (old_func != subtable->lookup_func) {
            subtables_changed += 1;
        }

        if (old_info != subtable->lookup_func_info) {
            /* In theory, functions can be shared between implementations, so
             * do an explicit check on the function info structures. */
            dpcls_info_dec_usage(old_info);
            dpcls_info_inc_usage(subtable->lookup_func_info);
        }
    }

    return subtables_changed;
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
    uint64_t tot_idle = 0, tot_proc = 0, tot_sleep = 0;
    unsigned int pmd_load = 0;

    if (pmd->ctx.now > pmd->next_cycle_store) {
        uint64_t curr_tsc;
        uint8_t rebalance_load_trigger;
        struct pmd_auto_lb *pmd_alb = &pmd->dp->pmd_alb;
        unsigned int idx;

        if (pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE] >=
                pmd->prev_stats[PMD_CYCLES_ITER_IDLE] &&
            pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY] >=
                pmd->prev_stats[PMD_CYCLES_ITER_BUSY]) {
            tot_idle = pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE] -
                       pmd->prev_stats[PMD_CYCLES_ITER_IDLE];
            tot_proc = pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY] -
                       pmd->prev_stats[PMD_CYCLES_ITER_BUSY];
            tot_sleep = pmd->perf_stats.counters.n[PMD_CYCLES_SLEEP] -
                        pmd->prev_stats[PMD_CYCLES_SLEEP];

            if (pmd_alb->is_enabled && !pmd->isolated) {
                if (tot_proc) {
                    pmd_load = ((tot_proc * 100) /
                                    (tot_idle + tot_proc + tot_sleep));
                }

                atomic_read_relaxed(&pmd_alb->rebalance_load_thresh,
                                    &rebalance_load_trigger);
                if (pmd_load >= rebalance_load_trigger) {
                    atomic_count_inc(&pmd->pmd_overloaded);
                } else {
                    atomic_count_set(&pmd->pmd_overloaded, 0);
                }
            }
        }

        pmd->prev_stats[PMD_CYCLES_ITER_IDLE] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE];
        pmd->prev_stats[PMD_CYCLES_ITER_BUSY] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY];
        pmd->prev_stats[PMD_CYCLES_SLEEP] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_SLEEP];

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
        idx = atomic_count_inc(&pmd->intrvl_idx) % PMD_INTERVAL_MAX;
        atomic_store_relaxed(&pmd->busy_cycles_intrvl[idx], tot_proc);
        pmd->intrvl_tsc_prev = curr_tsc;
        /* Start new measuring interval */
        pmd->next_cycle_store = pmd->ctx.now + PMD_INTERVAL_LEN;
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

/* Returns the sum of a specified number of newest to
 * oldest interval values. 'cur_idx' is where the next
 * write will be and wrap around needs to be handled.
 */
static uint64_t
get_interval_values(atomic_ullong *source, atomic_count *cur_idx,
                    int num_to_read) {
    unsigned int i;
    uint64_t total = 0;

    i = atomic_count_get(cur_idx) % PMD_INTERVAL_MAX;
    for (int read = 0; read < num_to_read; read++) {
        uint64_t interval_value;

        i = i ? i - 1 : PMD_INTERVAL_MAX - 1;
        atomic_read_relaxed(&source[i], &interval_value);
        total += interval_value;
    }
    return total;
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

/* Inner loop for mask generation of a unit, see dpcls_flow_key_gen_masks. */
static inline void
dpcls_flow_key_gen_mask_unit(uint64_t iter, const uint64_t count,
                             uint64_t *mf_masks)
{
    int i;
    for (i = 0; i < count; i++) {
        uint64_t lowest_bit = (iter & -iter);
        iter &= ~lowest_bit;
        mf_masks[i] = (lowest_bit - 1);
    }
    /* Checks that count has covered all bits in the iter bitmap. */
    ovs_assert(iter == 0);
}

/* Generate a mask for each block in the miniflow, based on the bits set. This
 * allows easily masking packets with the generated array here, without
 * calculations. This replaces runtime-calculating the masks.
 * @param key The table to generate the mf_masks for
 * @param mf_masks Pointer to a u64 array of at least *mf_bits* in size
 * @param mf_bits_total Number of bits set in the whole miniflow (both units)
 * @param mf_bits_unit0 Number of bits set in unit0 of the miniflow
 */
void
dpcls_flow_key_gen_masks(const struct netdev_flow_key *tbl,
                         uint64_t *mf_masks,
                         const uint32_t mf_bits_u0,
                         const uint32_t mf_bits_u1)
{
    uint64_t iter_u0 = tbl->mf.map.bits[0];
    uint64_t iter_u1 = tbl->mf.map.bits[1];

    dpcls_flow_key_gen_mask_unit(iter_u0, mf_bits_u0, &mf_masks[0]);
    dpcls_flow_key_gen_mask_unit(iter_u1, mf_bits_u1, &mf_masks[mf_bits_u0]);
}

/* Returns true if 'target' satisfies 'key' in 'mask', that is, if each 1-bit
 * in 'mask' the values in 'key' and 'target' are the same. */
inline bool
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
bool
dpcls_lookup(struct dpcls *cls, const struct netdev_flow_key *keys[],
             struct dpcls_rule **rules, const size_t cnt,
             int *num_lookups_p)
{
    /* The received 'cnt' miniflows are the search-keys that will be processed
     * to find a matching entry into the available subtables.
     * The number of bits in map_type is equal to NETDEV_MAX_BURST. */
#define MAP_BITS (sizeof(uint32_t) * CHAR_BIT)
    BUILD_ASSERT_DECL(MAP_BITS >= NETDEV_MAX_BURST);

    struct dpcls_subtable *subtable;
    uint32_t keys_map = TYPE_MAXIMUM(uint32_t); /* Set all bits. */

    if (cnt != MAP_BITS) {
        keys_map >>= MAP_BITS - cnt; /* Clear extra bits. */
    }
    memset(rules, 0, cnt * sizeof *rules);

    int lookups_match = 0, subtable_pos = 1;
    uint32_t found_map;

    /* The Datapath classifier - aka dpcls - is composed of subtables.
     * Subtables are dynamically created as needed when new rules are inserted.
     * Each subtable collects rules with matches on a specific subset of packet
     * fields as defined by the subtable's mask.  We proceed to process every
     * search-key against each subtable, but when a match is found for a
     * search-key, the search for that key can stop because the rules are
     * non-overlapping. */
    PVECTOR_FOR_EACH (subtable, &cls->subtables) {
        /* Call the subtable specific lookup function. */
        found_map = subtable->lookup_func(subtable, keys_map, keys, rules);

        /* Count the number of subtables searched for this packet match. This
         * estimates the "spread" of subtables looked at per matched packet. */
        uint32_t pkts_matched = count_1bits(found_map);
        lookups_match += pkts_matched * subtable_pos;

        /* Clear the found rules, and return early if all packets are found. */
        keys_map &= ~found_map;
        if (!keys_map) {
            if (num_lookups_p) {
                *num_lookups_p = lookups_match;
            }
            return true;
        }
        subtable_pos++;
    }

    if (num_lookups_p) {
        *num_lookups_p = lookups_match;
    }
    return false;
}
