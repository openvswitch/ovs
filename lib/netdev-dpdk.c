/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
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
#include "netdev-dpdk.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/virtio_net.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/if.h>

#include <rte_bus.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_meter.h>
#include <rte_pci.h>
#include <rte_version.h>
#include <rte_vhost.h>

#include "cmap.h"
#include "coverage.h"
#include "dirs.h"
#include "dp-packet.h"
#include "dpdk.h"
#include "dpif-netdev.h"
#include "fatal-signal.h"
#include "if-notifier.h"
#include "mpsc-queue.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "packets.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "userspace-tso.h"
#include "util.h"
#include "uuid.h"

enum {VIRTIO_RXQ, VIRTIO_TXQ, VIRTIO_QNUM};

VLOG_DEFINE_THIS_MODULE(netdev_dpdk);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

COVERAGE_DEFINE(vhost_tx_contention);

static char *vhost_sock_dir = NULL;   /* Location of vhost-user sockets */
static bool vhost_iommu_enabled = false; /* Status of vHost IOMMU support */
static bool vhost_postcopy_enabled = false; /* Status of vHost POSTCOPY
                                             * support. */
static bool per_port_memory = false; /* Status of per port memory support */

#define DPDK_PORT_WATCHDOG_INTERVAL 5

#define OVS_CACHE_LINE_SIZE CACHE_LINE_SIZE
#define OVS_VPORT_DPDK "ovs_dpdk"

/*
 * need to reserve tons of extra space in the mbufs so we can align the
 * DMA addresses to 4KB.
 * The minimum mbuf size is limited to avoid scatter behaviour and drop in
 * performance for standard Ethernet MTU.
 */
#define ETHER_HDR_MAX_LEN           (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN \
                                     + (2 * VLAN_HEADER_LEN))
#define MTU_TO_FRAME_LEN(mtu)       ((mtu) + RTE_ETHER_HDR_LEN + \
                                     RTE_ETHER_CRC_LEN)
#define MTU_TO_MAX_FRAME_LEN(mtu)   ((mtu) + ETHER_HDR_MAX_LEN)
#define FRAME_LEN_TO_MTU(frame_len) ((frame_len)                    \
                                     - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN)
#define NETDEV_DPDK_MBUF_ALIGN      1024
#define NETDEV_DPDK_MAX_PKT_LEN     9728

/* Max and min number of packets in the mempool. OVS tries to allocate a
 * mempool with MAX_NB_MBUF: if this fails (because the system doesn't have
 * enough hugepages) we keep halving the number until the allocation succeeds
 * or we reach MIN_NB_MBUF */

#define MAX_NB_MBUF          (4096 * 64)
#define MIN_NB_MBUF          (4096 * 4)
#define MP_CACHE_SZ          RTE_MEMPOOL_CACHE_MAX_SIZE

/* MAX_NB_MBUF can be divided by 2 many times, until MIN_NB_MBUF */
BUILD_ASSERT_DECL(MAX_NB_MBUF % ROUND_DOWN_POW2(MAX_NB_MBUF / MIN_NB_MBUF)
                  == 0);

/* The smallest possible NB_MBUF that we're going to try should be a multiple
 * of MP_CACHE_SZ. This is advised by DPDK documentation. */
BUILD_ASSERT_DECL((MAX_NB_MBUF / ROUND_DOWN_POW2(MAX_NB_MBUF / MIN_NB_MBUF))
                  % MP_CACHE_SZ == 0);

#define SOCKET0              0

/* Default size of Physical NIC RXQ */
#define NIC_PORT_DEFAULT_RXQ_SIZE 2048
/* Default size of Physical NIC TXQ */
#define NIC_PORT_DEFAULT_TXQ_SIZE 2048

#define OVS_VHOST_MAX_QUEUE_NUM 1024  /* Maximum number of vHost TX queues. */
#define OVS_VHOST_QUEUE_MAP_UNKNOWN (-1) /* Mapping not initialized. */
#define OVS_VHOST_QUEUE_DISABLED    (-2) /* Queue was disabled by guest and not
                                          * yet mapped to another queue. */

#define DPDK_ETH_PORT_ID_INVALID    RTE_MAX_ETHPORTS

/* DPDK library uses uint16_t for port_id. */
typedef uint16_t dpdk_port_t;
#define DPDK_PORT_ID_FMT "%"PRIu16

/* Minimum amount of vhost tx retries, effectively a disable. */
#define VHOST_ENQ_RETRY_MIN 0
/* Maximum amount of vhost tx retries. */
#define VHOST_ENQ_RETRY_MAX 32
/* Legacy default value for vhost tx retries. */
#define VHOST_ENQ_RETRY_DEF 8

/* VDUSE-only, ignore for vhost-user. */
#define VHOST_MAX_QUEUE_PAIRS_MIN 1
#define VHOST_MAX_QUEUE_PAIRS_DEF VHOST_MAX_QUEUE_PAIRS_MIN
#define VHOST_MAX_QUEUE_PAIRS_MAX 128

#define IF_NAME_SZ (PATH_MAX > IFNAMSIZ ? PATH_MAX : IFNAMSIZ)

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .offloads = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

/*
 * These callbacks allow virtio-net devices to be added to vhost ports when
 * configuration has been fully completed.
 */
static int new_device(int vid);
static void destroy_device(int vid);
static int vring_state_changed(int vid, uint16_t queue_id, int enable);
static void destroy_connection(int vid);

static const struct rte_vhost_device_ops virtio_net_device_ops =
{
    .new_device =  new_device,
    .destroy_device = destroy_device,
    .vring_state_changed = vring_state_changed,
    .features_changed = NULL,
    .new_connection = NULL,
    .destroy_connection = destroy_connection,
};

/* Custom software stats for dpdk ports */
struct netdev_dpdk_sw_stats {
    /* No. of retries when unable to transmit. */
    uint64_t tx_retries;
    /* Packet drops when unable to transmit; Probably Tx queue is full. */
    uint64_t tx_failure_drops;
    /* Packet length greater than device MTU. */
    uint64_t tx_mtu_exceeded_drops;
    /* Packet drops in egress policer processing. */
    uint64_t tx_qos_drops;
    /* Packet drops in ingress policer processing. */
    uint64_t rx_qos_drops;
    /* Packet drops in HWOL processing. */
    uint64_t tx_invalid_hwol_drops;
};

enum dpdk_dev_type {
    DPDK_DEV_ETH = 0,
    DPDK_DEV_VHOST = 1,
};

/* Quality of Service */

/* An instance of a QoS configuration.  Always associated with a particular
 * network device.
 *
 * Each QoS implementation subclasses this with whatever additional data it
 * needs.
 */
struct qos_conf {
    const struct dpdk_qos_ops *ops;
    rte_spinlock_t lock;
};

/* QoS queue information used by the netdev queue dump functions. */
struct netdev_dpdk_queue_state {
    uint32_t *queues;
    size_t cur_queue;
    size_t n_queues;
};

/* A particular implementation of dpdk QoS operations.
 *
 * The functions below return 0 if successful or a positive errno value on
 * failure, except where otherwise noted. All of them must be provided, except
 * where otherwise noted.
 */
struct dpdk_qos_ops {

    /* Name of the QoS type */
    const char *qos_name;

    /* Called to construct a qos_conf object. The implementation should make
     * the appropriate calls to configure QoS according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * This function must return 0 if and only if it sets '*conf' to an
     * initialized 'struct qos_conf'.
     *
     * For all QoS implementations it should always be non-null.
     */
    int (*qos_construct)(const struct smap *details, struct qos_conf **conf);

    /* Destroys the data structures allocated by the implementation as part of
     * 'qos_conf'.
     *
     * For all QoS implementations it should always be non-null.
     */
    void (*qos_destruct)(struct qos_conf *conf);

    /* Retrieves details of 'conf' configuration into 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     */
    int (*qos_get)(const struct qos_conf *conf, struct smap *details);

    /* Returns true if 'conf' is already configured according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * For all QoS implementations it should always be non-null.
     */
    bool (*qos_is_equal)(const struct qos_conf *conf,
                         const struct smap *details);

    /* Modify an array of rte_mbufs. The modification is specific to
     * each qos implementation.
     *
     * The function should take and array of mbufs and an int representing
     * the current number of mbufs present in the array.
     *
     * After the function has performed a qos modification to the array of
     * mbufs it returns an int representing the number of mbufs now present in
     * the array. This value is can then be passed to the port send function
     * along with the modified array for transmission.
     *
     * For all QoS implementations it should always be non-null.
     */
    int (*qos_run)(struct qos_conf *qos_conf, struct rte_mbuf **pkts,
                   int pkt_cnt, bool should_steal);

    /* Called to construct a QoS Queue. The implementation should make
     * the appropriate calls to configure QoS Queue according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * This function must return 0 if and only if it constructs
     * QoS queue successfully.
     */
    int (*qos_queue_construct)(const struct smap *details,
                               uint32_t queue_id, struct qos_conf *conf);

    /* Destroys the QoS Queue. */
    void (*qos_queue_destruct)(struct qos_conf *conf, uint32_t queue_id);

    /* Retrieves details of QoS Queue configuration into 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     */
    int (*qos_queue_get)(struct smap *details, uint32_t queue_id,
                         const struct qos_conf *conf);

    /* Retrieves statistics of QoS Queue configuration into 'stats'. */
    int (*qos_queue_get_stats)(const struct qos_conf *conf, uint32_t queue_id,
                               struct netdev_queue_stats *stats);

    /* Setup the 'netdev_dpdk_queue_state' structure used by the dpdk queue
     * dump functions.
     */
    int (*qos_queue_dump_state_init)(const struct qos_conf *conf,
                                     struct netdev_dpdk_queue_state *state);
};

/* dpdk_qos_ops for each type of user space QoS implementation. */
static const struct dpdk_qos_ops egress_policer_ops;
static const struct dpdk_qos_ops trtcm_policer_ops;

/*
 * Array of dpdk_qos_ops, contains pointer to all supported QoS
 * operations.
 */
static const struct dpdk_qos_ops *const qos_confs[] = {
    &egress_policer_ops,
    &trtcm_policer_ops,
    NULL
};

static struct ovs_mutex dpdk_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dpdk_dev's. */
static struct ovs_list dpdk_list OVS_GUARDED_BY(dpdk_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_list);

static struct ovs_mutex dpdk_mp_mutex OVS_ACQ_AFTER(dpdk_mutex)
    = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dpdk_mp's. */
static struct ovs_list dpdk_mp_list OVS_GUARDED_BY(dpdk_mp_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_mp_list);

struct dpdk_mp {
     struct rte_mempool *mp;
     int mtu;
     int socket_id;
     int refcount;
     struct ovs_list list_node OVS_GUARDED_BY(dpdk_mp_mutex);
};

struct user_mempool_config {
    int adj_mtu;
    int socket_id;
};

static struct user_mempool_config *user_mempools = NULL;
static int n_user_mempools;

/* There should be one 'struct dpdk_tx_queue' created for
 * each netdev tx queue. */
struct dpdk_tx_queue {
    /* Padding to make dpdk_tx_queue exactly one cache line long. */
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* Protects the members and the NIC queue from concurrent access.
         * It is used only if the queue is shared among different pmd threads
         * (see 'concurrent_txq'). */
        rte_spinlock_t tx_lock;
        /* Mapping of configured vhost-user queue to enabled by guest. */
        int map;
    );
};

struct ingress_policer {
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm in_policer;
    struct rte_meter_srtcm_profile in_prof;
    rte_spinlock_t policer_lock;
};

enum dpdk_hw_ol_features {
    NETDEV_RX_CHECKSUM_OFFLOAD = 1 << 0,
    NETDEV_RX_HW_CRC_STRIP = 1 << 1,
    NETDEV_RX_HW_SCATTER = 1 << 2,
    NETDEV_TX_IPV4_CKSUM_OFFLOAD = 1 << 3,
    NETDEV_TX_TCP_CKSUM_OFFLOAD = 1 << 4,
    NETDEV_TX_UDP_CKSUM_OFFLOAD = 1 << 5,
    NETDEV_TX_SCTP_CKSUM_OFFLOAD = 1 << 6,
    NETDEV_TX_TSO_OFFLOAD = 1 << 7,
    NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD = 1 << 8,
    NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD = 1 << 9,
    NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD = 1 << 10,
    NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD = 1 << 11,
    NETDEV_TX_GRE_TNL_TSO_OFFLOAD = 1 << 12,
};

enum dpdk_rx_steer_flags {
    DPDK_RX_STEER_LACP = 1 << 0,
};

/* Flags for the netdev_dpdk virtio_features_state field.
 * This is used for the virtio features recovery mechanism linked to TSO
 * support. */
#define OVS_VIRTIO_F_CLEAN (UINT8_C(1) << 0)
#define OVS_VIRTIO_F_WORKAROUND (UINT8_C(1) << 1)
#define OVS_VIRTIO_F_NEGOTIATED (UINT8_C(1) << 2)
#define OVS_VIRTIO_F_RECONF_PENDING (UINT8_C(1) << 3)
#define OVS_VIRTIO_F_CLEAN_NEGOTIATED \
    (OVS_VIRTIO_F_CLEAN | OVS_VIRTIO_F_NEGOTIATED)
#define OVS_VIRTIO_F_WORKAROUND_NEGOTIATED \
    (OVS_VIRTIO_F_WORKAROUND | OVS_VIRTIO_F_NEGOTIATED)

/*
 * In order to avoid confusion in variables names, following naming convention
 * should be used, if possible:
 *
 *     'struct netdev'          : 'netdev'
 *     'struct netdev_dpdk'     : 'dev'
 *     'struct netdev_rxq'      : 'rxq'
 *     'struct netdev_rxq_dpdk' : 'rx'
 *
 * Example:
 *     struct netdev *netdev = netdev_from_name(name);
 *     struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
 *
 *  Also, 'netdev' should be used instead of 'dev->up', where 'netdev' was
 *  already defined.
 */

struct netdev_dpdk {
    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
        dpdk_port_t port_id;

        /* If true, device was attached by rte_eth_dev_attach(). */
        bool attached;
        /* If true, rte_eth_dev_start() was successfully called. */
        bool started;
        /* If true, this is a port representor. */
        bool is_representor;
        struct eth_addr hwaddr;
        /* 1 pad bytes here. */
        int mtu;
        int socket_id;
        int buf_size;
        int max_packet_len;
        enum dpdk_dev_type type;
        enum netdev_flags flags;
        int link_reset_cnt;
        union {
            /* Device arguments for dpdk ports. */
            char *devargs;
            /* Identifier used to distinguish vhost devices from each other. */
            char *vhost_id;
        };
        struct dpdk_tx_queue *tx_q;
        struct rte_eth_link link;
    );

    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline1,
        struct ovs_mutex mutex OVS_ACQ_AFTER(dpdk_mutex);
        struct dpdk_mp *dpdk_mp;

        /* virtio identifier for vhost devices */
        ovsrcu_index vid;

        /* True if vHost device is 'up' and has been reconfigured at least once */
        bool vhost_reconfigured;

        atomic_uint8_t vhost_tx_retries_max;

        /* Flags for virtio features recovery mechanism. */
        uint8_t virtio_features_state;

        /* 1 pad byte here. */
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev up;
        /* In dpdk_list. */
        struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);

        /* QoS configuration and lock for the device */
        OVSRCU_TYPE(struct qos_conf *) qos_conf;

        /* Ingress Policer */
        OVSRCU_TYPE(struct ingress_policer *) ingress_policer;
        uint32_t policer_rate;
        uint32_t policer_burst;

        /* Array of vhost rxq states, see vring_state_changed. */
        bool *vhost_rxq_enabled;

        /* Ensures that Rx metadata delivery is configured only once. */
        bool rx_metadata_delivery_configured;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev_stats stats;
        struct netdev_dpdk_sw_stats *sw_stats;
        /* Protects stats */
        rte_spinlock_t stats_lock;
        /* 36 pad bytes here. */
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* The following properties cannot be changed when a device is running,
         * so we remember the request and update them next time
         * netdev_dpdk*_reconfigure() is called */
        int requested_mtu;
        int requested_n_txq;
        /* User input for n_rxq (see dpdk_set_rxq_config). */
        int user_n_rxq;
        /* user_n_rxq + an optional rx steering queue (see
         * netdev_dpdk_reconfigure). This field is different from the other
         * requested_* fields as it may contain a different value than the user
         * input. */
        int requested_n_rxq;
        int requested_rxq_size;
        int requested_txq_size;

        /* Number of rx/tx descriptors for physical devices */
        int rxq_size;
        int txq_size;

        /* Socket ID detected when vHost device is brought up */
        int requested_socket_id;

        /* Ignored by DPDK for vhost-user backends, only for VDUSE. */
        uint8_t vhost_max_queue_pairs;

        /* Denotes whether vHost port is client/server mode */
        uint64_t vhost_driver_flags;

        /* DPDK-ETH Flow control */
        struct rte_eth_fc_conf fc_conf;

        /* DPDK-ETH hardware offload features,
         * from the enum set 'dpdk_hw_ol_features' */
        uint32_t hw_ol_features;

        /* Properties for link state change detection mode.
         * If lsc_interrupt_mode is set to false, poll mode is used,
         * otherwise interrupt mode is used. */
        bool requested_lsc_interrupt_mode;
        bool lsc_interrupt_mode;

        /* VF configuration. */
        struct eth_addr requested_hwaddr;

        /* Requested rx queue steering flags,
         * from the enum set 'dpdk_rx_steer_flags'. */
        uint64_t requested_rx_steer_flags;
        uint64_t rx_steer_flags;
        size_t rx_steer_flows_num;
        struct rte_flow **rx_steer_flows;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* Names of all XSTATS counters */
        struct rte_eth_xstat_name *rte_xstats_names;
        int rte_xstats_names_size;
        int rte_xstats_ids_size;
        uint64_t *rte_xstats_ids;
    );
};

struct netdev_rxq_dpdk {
    struct netdev_rxq up;
    dpdk_port_t port_id;
};

static void netdev_dpdk_destruct(struct netdev *netdev);
static void netdev_dpdk_vhost_destruct(struct netdev *netdev);

static int netdev_dpdk_get_sw_custom_stats(const struct netdev *,
                                           struct netdev_custom_stats *);
static void netdev_dpdk_configure_xstats(struct netdev_dpdk *dev);
static void netdev_dpdk_clear_xstats(struct netdev_dpdk *dev);

int netdev_dpdk_get_vid(const struct netdev_dpdk *dev);

struct ingress_policer *
netdev_dpdk_get_ingress_policer(const struct netdev_dpdk *dev);

static void netdev_dpdk_mbuf_dump(const char *prefix, const char *message,
                                  const struct rte_mbuf *);

static bool
is_dpdk_class(const struct netdev_class *class)
{
    return class->destruct == netdev_dpdk_destruct
           || class->destruct == netdev_dpdk_vhost_destruct;
}

/* DPDK NIC drivers allocate RX buffers at a particular granularity, typically
 * aligned at 1k or less. If a declared mbuf size is not a multiple of this
 * value, insufficient buffers are allocated to accomodate the packet in its
 * entirety. Furthermore, certain drivers need to ensure that there is also
 * sufficient space in the Rx buffer to accommodate two VLAN tags (for QinQ
 * frames). If the RX buffer is too small, then the driver enables scatter RX
 * behaviour, which reduces performance. To prevent this, use a buffer size
 * that is closest to 'mtu', but which satisfies the aforementioned criteria.
 */
static uint32_t
dpdk_buf_size(int mtu)
{
    return ROUND_UP(MTU_TO_MAX_FRAME_LEN(mtu), NETDEV_DPDK_MBUF_ALIGN)
            + RTE_PKTMBUF_HEADROOM;
}

static int
dpdk_get_user_adjusted_mtu(int port_adj_mtu, int port_mtu, int port_socket_id)
{
    int best_adj_user_mtu = INT_MAX;

    for (unsigned i = 0; i < n_user_mempools; i++) {
        int user_adj_mtu, user_socket_id;

        user_adj_mtu = user_mempools[i].adj_mtu;
        user_socket_id = user_mempools[i].socket_id;
        if (port_adj_mtu > user_adj_mtu
            || (user_socket_id != INT_MAX
                && user_socket_id != port_socket_id)) {
            continue;
        }
        if (user_adj_mtu < best_adj_user_mtu) {
            /* This is the is the lowest valid user MTU. */
            best_adj_user_mtu = user_adj_mtu;
            if (best_adj_user_mtu == port_adj_mtu) {
                /* Found an exact fit, no need to keep searching. */
                break;
            }
        }
    }
    if (best_adj_user_mtu == INT_MAX) {
        VLOG_DBG("No user configured shared mempool mbuf sizes found "
                 "suitable for port with MTU %d, NUMA %d.", port_mtu,
                 port_socket_id);
        best_adj_user_mtu = port_adj_mtu;
    } else {
        VLOG_DBG("Found user configured shared mempool with mbufs "
                 "of size %d, suitable for port with MTU %d, NUMA %d.",
                 MTU_TO_FRAME_LEN(best_adj_user_mtu), port_mtu,
                 port_socket_id);
    }
    return best_adj_user_mtu;
}

/* Allocates an area of 'sz' bytes from DPDK.  The memory is zero'ed.
 *
 * Unlike xmalloc(), this function can return NULL on failure. */
static void *
dpdk_rte_mzalloc(size_t sz)
{
    return rte_zmalloc(OVS_VPORT_DPDK, sz, OVS_CACHE_LINE_SIZE);
}

void
free_dpdk_buf(struct dp_packet *p)
{
    struct rte_mbuf *pkt = (struct rte_mbuf *) p;

    rte_pktmbuf_free(pkt);
}

static void
ovs_rte_pktmbuf_init(struct rte_mempool *mp OVS_UNUSED,
                     void *opaque_arg OVS_UNUSED,
                     void *_p,
                     unsigned i OVS_UNUSED)
{
    struct rte_mbuf *pkt = _p;

    dp_packet_init_dpdk((struct dp_packet *) pkt);
}

static int
dpdk_mp_full(const struct rte_mempool *mp) OVS_REQUIRES(dpdk_mp_mutex)
{
    /* At this point we want to know if all the mbufs are back
     * in the mempool. rte_mempool_full() is not atomic but it's
     * the best available and as we are no longer requesting mbufs
     * from the mempool, it means mbufs will not move from
     * 'mempool ring' --> 'mempool cache'. In rte_mempool_full()
     * the ring is counted before caches, so we won't get false
     * positives in this use case and we handle false negatives.
     *
     * If future implementations of rte_mempool_full() were to change
     * it could be possible for a false positive. Even that would
     * likely be ok, as there are additional checks during mempool
     * freeing but it would make things racey.
     */
    return rte_mempool_full(mp);
}

/* Free unused mempools. */
static void
dpdk_mp_sweep(void) OVS_REQUIRES(dpdk_mp_mutex)
{
    struct dpdk_mp *dmp;

    LIST_FOR_EACH_SAFE (dmp, list_node, &dpdk_mp_list) {
        if (!dmp->refcount && dpdk_mp_full(dmp->mp)) {
            VLOG_DBG("Freeing mempool \"%s\"", dmp->mp->name);
            ovs_list_remove(&dmp->list_node);
            rte_mempool_free(dmp->mp);
            rte_free(dmp);
        }
    }
}

/* Calculating the required number of mbufs differs depending on the
 * mempool model being used. Check if per port memory is in use before
 * calculating.
 */
static uint32_t
dpdk_calculate_mbufs(struct netdev_dpdk *dev, int mtu)
{
    uint32_t n_mbufs;

    if (!per_port_memory) {
        /* Shared memory are being used.
         * XXX: this is a really rough method of provisioning memory.
         * It's impossible to determine what the exact memory requirements are
         * when the number of ports and rxqs that utilize a particular mempool
         * can change dynamically at runtime. For now, use this rough
         * heurisitic.
         */
        if (mtu >= RTE_ETHER_MTU) {
            n_mbufs = MAX_NB_MBUF;
        } else {
            n_mbufs = MIN_NB_MBUF;
        }
    } else {
        /* Per port memory is being used.
         * XXX: rough estimation of number of mbufs required for this port:
         * <packets required to fill the device rxqs>
         * + <packets that could be stuck on other ports txqs>
         * + <packets in the pmd threads>
         * + <additional memory for corner cases>
         */
        n_mbufs = dev->requested_n_rxq * dev->requested_rxq_size
                  + dev->requested_n_txq * dev->requested_txq_size
                  + MIN(RTE_MAX_LCORE, dev->requested_n_rxq) * NETDEV_MAX_BURST
                  + MIN_NB_MBUF;
    }

    return n_mbufs;
}

static struct dpdk_mp *
dpdk_mp_create(struct netdev_dpdk *dev, int mtu)
{
    char mp_name[RTE_MEMPOOL_NAMESIZE];
    const char *netdev_name = netdev_get_name(&dev->up);
    int socket_id = dev->requested_socket_id;
    uint32_t n_mbufs = 0;
    uint32_t mbuf_size = 0;
    uint32_t aligned_mbuf_size = 0;
    uint32_t mbuf_priv_data_len = 0;
    uint32_t pkt_size = 0;
    uint32_t hash = hash_string(netdev_name, 0);
    struct dpdk_mp *dmp = NULL;
    int ret;

    dmp = dpdk_rte_mzalloc(sizeof *dmp);
    if (!dmp) {
        return NULL;
    }
    dmp->socket_id = socket_id;
    dmp->mtu = mtu;
    dmp->refcount = 1;

    /* Get the size of each mbuf, based on the MTU */
    mbuf_size = MTU_TO_FRAME_LEN(mtu);

    n_mbufs = dpdk_calculate_mbufs(dev, mtu);

    do {
        /* Full DPDK memory pool name must be unique and cannot be
         * longer than RTE_MEMPOOL_NAMESIZE. Note that for the shared
         * mempool case this can result in one device using a mempool
         * which references a different device in it's name. However as
         * mempool names are hashed, the device name will not be readable
         * so this is not an issue for tasks such as debugging.
         */
        ret = snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
                       "ovs%08x%02d%05d%07u",
                        hash, socket_id, mtu, n_mbufs);
        if (ret < 0 || ret >= RTE_MEMPOOL_NAMESIZE) {
            VLOG_DBG("snprintf returned %d. "
                     "Failed to generate a mempool name for \"%s\". "
                     "Hash:0x%x, socket_id: %d, mtu:%d, mbufs:%u.",
                     ret, netdev_name, hash, socket_id, mtu, n_mbufs);
            break;
        }

        VLOG_DBG("Port %s: Requesting a mempool of %u mbufs of size %u "
                  "on socket %d for %d Rx and %d Tx queues, "
                  "cache line size of %u",
                  netdev_name, n_mbufs, mbuf_size, socket_id,
                  dev->requested_n_rxq, dev->requested_n_txq,
                  RTE_CACHE_LINE_SIZE);

        /* The size of the mbuf's private area (i.e. area that holds OvS'
         * dp_packet data)*/
        mbuf_priv_data_len = sizeof(struct dp_packet) -
                                 sizeof(struct rte_mbuf);
        /* The size of the entire dp_packet. */
        pkt_size = sizeof(struct dp_packet) + mbuf_size;
        /* mbuf size, rounded up to cacheline size. */
        aligned_mbuf_size = ROUND_UP(pkt_size, RTE_CACHE_LINE_SIZE);
        /* If there is a size discrepancy, add padding to mbuf_priv_data_len.
         * This maintains mbuf size cache alignment, while also honoring RX
         * buffer alignment in the data portion of the mbuf. If this adjustment
         * is not made, there is a possiblity later on that for an element of
         * the mempool, buf, buf->data_len < (buf->buf_len - buf->data_off).
         * This is problematic in the case of multi-segment mbufs, particularly
         * when an mbuf segment needs to be resized (when [push|popp]ing a VLAN
         * header, for example.
         */
        mbuf_priv_data_len += (aligned_mbuf_size - pkt_size);

        dmp->mp = rte_pktmbuf_pool_create(mp_name, n_mbufs, MP_CACHE_SZ,
                                          mbuf_priv_data_len,
                                          mbuf_size,
                                          socket_id);

        if (dmp->mp) {
            VLOG_DBG("Allocated \"%s\" mempool with %u mbufs",
                     mp_name, n_mbufs);
            /* rte_pktmbuf_pool_create has done some initialization of the
             * rte_mbuf part of each dp_packet, while ovs_rte_pktmbuf_init
             * initializes some OVS specific fields of dp_packet.
             */
            rte_mempool_obj_iter(dmp->mp, ovs_rte_pktmbuf_init, NULL);
            return dmp;
        } else if (rte_errno == EEXIST) {
            /* A mempool with the same name already exists.  We just
             * retrieve its pointer to be returned to the caller. */
            dmp->mp = rte_mempool_lookup(mp_name);
            /* As the mempool create returned EEXIST we can expect the
             * lookup has returned a valid pointer.  If for some reason
             * that's not the case we keep track of it. */
            VLOG_DBG("A mempool with name \"%s\" already exists at %p.",
                     mp_name, dmp->mp);
            return dmp;
        } else {
            VLOG_DBG("Failed to create mempool \"%s\" with a request of "
                     "%u mbufs, retrying with %u mbufs",
                     mp_name, n_mbufs, n_mbufs / 2);
        }
    } while (!dmp->mp && rte_errno == ENOMEM && (n_mbufs /= 2) >= MIN_NB_MBUF);

    VLOG_ERR("Failed to create mempool \"%s\" with a request of %u mbufs",
             mp_name, n_mbufs);

    rte_free(dmp);
    return NULL;
}

static struct dpdk_mp *
dpdk_mp_get(struct netdev_dpdk *dev, int mtu)
{
    struct dpdk_mp *dmp = NULL, *next;
    bool reuse = false;

    ovs_mutex_lock(&dpdk_mp_mutex);
    /* Check if shared memory is being used, if so check existing mempools
     * to see if reuse is possible. */
    if (!per_port_memory) {
        /* If user has provided defined mempools, check if one is suitable
         * and get new buffer size.*/
        mtu = dpdk_get_user_adjusted_mtu(mtu, dev->requested_mtu,
                                         dev->requested_socket_id);
        LIST_FOR_EACH (dmp, list_node, &dpdk_mp_list) {
            if (dmp->socket_id == dev->requested_socket_id
                && dmp->mtu == mtu) {
                VLOG_DBG("Reusing mempool \"%s\"", dmp->mp->name);
                dmp->refcount++;
                reuse = true;
                break;
            }
        }
    }
    /* Sweep mempools after reuse or before create. */
    dpdk_mp_sweep();

    if (!reuse) {
        dmp = dpdk_mp_create(dev, mtu);
        if (dmp) {
            /* Shared memory will hit the reuse case above so will not
             * request a mempool that already exists but we need to check
             * for the EEXIST case for per port memory case. Compare the
             * mempool returned by dmp to each entry in dpdk_mp_list. If a
             * match is found, free dmp as a new entry is not required, set
             * dmp to point to the existing entry and increment the refcount
             * to avoid being freed at a later stage.
             */
            if (per_port_memory && rte_errno == EEXIST) {
                LIST_FOR_EACH (next, list_node, &dpdk_mp_list) {
                    if (dmp->mp == next->mp) {
                        rte_free(dmp);
                        dmp = next;
                        dmp->refcount++;
                    }
                }
            } else {
                ovs_list_push_back(&dpdk_mp_list, &dmp->list_node);
            }
        }
    }

    ovs_mutex_unlock(&dpdk_mp_mutex);

    return dmp;
}

/* Decrement reference to a mempool. */
static void
dpdk_mp_put(struct dpdk_mp *dmp)
{
    if (!dmp) {
        return;
    }

    ovs_mutex_lock(&dpdk_mp_mutex);
    ovs_assert(dmp->refcount);
    dmp->refcount--;
    ovs_mutex_unlock(&dpdk_mp_mutex);
}

/* Depending on the memory model being used this function tries to
 * identify and reuse an existing mempool or tries to allocate a new
 * mempool on requested_socket_id with mbuf size corresponding to the
 * requested_mtu. On success, a new configuration will be applied.
 * On error, device will be left unchanged. */
static int
netdev_dpdk_mempool_configure(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    uint32_t buf_size = dpdk_buf_size(dev->requested_mtu);
    struct dpdk_mp *dmp;
    int ret = 0;

    /* With shared memory we do not need to configure a mempool if the MTU
     * and socket ID have not changed, the previous configuration is still
     * valid so return 0 */
    if (!per_port_memory && dev->mtu == dev->requested_mtu
        && dev->socket_id == dev->requested_socket_id) {
        return ret;
    }

    dmp = dpdk_mp_get(dev, FRAME_LEN_TO_MTU(buf_size));
    if (!dmp) {
        VLOG_ERR("Failed to create memory pool for netdev "
                 "%s, with MTU %d on socket %d: %s\n",
                 dev->up.name, dev->requested_mtu, dev->requested_socket_id,
                 rte_strerror(rte_errno));
        ret = rte_errno;
    } else {
        /* Check for any pre-existing dpdk_mp for the device before accessing
         * the associated mempool.
         */
        if (dev->dpdk_mp != NULL) {
            /* A new MTU was requested, decrement the reference count for the
             * devices current dpdk_mp. This is required even if a pointer to
             * same dpdk_mp is returned by dpdk_mp_get. The refcount for dmp
             * has already been incremented by dpdk_mp_get at this stage so it
             * must be decremented to keep an accurate refcount for the
             * dpdk_mp.
             */
            dpdk_mp_put(dev->dpdk_mp);
        }
        dev->dpdk_mp = dmp;
        dev->mtu = dev->requested_mtu;
        dev->socket_id = dev->requested_socket_id;
        dev->max_packet_len = MTU_TO_FRAME_LEN(dev->mtu);
    }

    return ret;
}

static void
check_link_status(struct netdev_dpdk *dev)
{
    struct rte_eth_link link;

    if (rte_eth_link_get_nowait(dev->port_id, &link) < 0) {
        VLOG_DBG_RL(&rl,
                    "Failed to retrieve link status for port "DPDK_PORT_ID_FMT,
                    dev->port_id);
        return;
    }

    if (dev->link.link_status != link.link_status) {
        netdev_change_seq_changed(&dev->up);

        dev->link_reset_cnt++;
        dev->link = link;
        if (dev->link.link_status) {
            VLOG_DBG_RL(&rl,
                        "Port "DPDK_PORT_ID_FMT" Link Up - speed %u Mbps - %s",
                        dev->port_id, (unsigned) dev->link.link_speed,
                        (dev->link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX)
                        ? "full-duplex" : "half-duplex");
        } else {
            VLOG_DBG_RL(&rl, "Port "DPDK_PORT_ID_FMT" Link Down",
                        dev->port_id);
        }
    }
}

static void *
dpdk_watchdog(void *dummy OVS_UNUSED)
{
    struct netdev_dpdk *dev;

    pthread_detach(pthread_self());

    for (;;) {
        ovs_mutex_lock(&dpdk_mutex);
        LIST_FOR_EACH (dev, list_node, &dpdk_list) {
            ovs_mutex_lock(&dev->mutex);
            if (dev->type == DPDK_DEV_ETH) {
                check_link_status(dev);
            }
            ovs_mutex_unlock(&dev->mutex);
        }
        ovs_mutex_unlock(&dpdk_mutex);
        xsleep(DPDK_PORT_WATCHDOG_INTERVAL);
    }

    return NULL;
}

static void
netdev_dpdk_update_netdev_flag(struct netdev_dpdk *dev,
                               enum dpdk_hw_ol_features hw_ol_features,
                               enum netdev_ol_flags flag)
    OVS_REQUIRES(dev->mutex)
{
    struct netdev *netdev = &dev->up;

    if (dev->hw_ol_features & hw_ol_features) {
        netdev->ol_flags |= flag;
    } else {
        netdev->ol_flags &= ~flag;
    }
}

static void
netdev_dpdk_update_netdev_flags(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_IPV4_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_IPV4_CKSUM);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_TCP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_TCP_CKSUM);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_UDP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_UDP_CKSUM);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_SCTP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_SCTP_CKSUM);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_TSO_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_TCP_TSO);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_VXLAN_TNL_TSO);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_GRE_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_GRE_TNL_TSO);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_GENEVE_TNL_TSO);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_OUTER_IP_CKSUM);
    netdev_dpdk_update_netdev_flag(dev, NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_OUTER_UDP_CKSUM);
}

static int
dpdk_eth_dev_port_config(struct netdev_dpdk *dev,
                         const struct rte_eth_dev_info *info,
                         int n_rxq, int n_txq)
{
    struct rte_eth_conf conf = port_conf;
    uint16_t conf_mtu;
    int diag = 0;
    int i;

    /* As of DPDK 17.11.1 a few PMDs require to explicitly enable
     * scatter to support jumbo RX.
     * Setting scatter for the device is done after checking for
     * scatter support in the device capabilites. */
    if (dev->mtu > RTE_ETHER_MTU) {
        if (dev->hw_ol_features & NETDEV_RX_HW_SCATTER) {
            conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
        }
    }

    conf.intr_conf.lsc = dev->lsc_interrupt_mode;

    if (dev->hw_ol_features & NETDEV_RX_CHECKSUM_OFFLOAD) {
        conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;
    }

    if (!(dev->hw_ol_features & NETDEV_RX_HW_CRC_STRIP)
        && info->rx_offload_capa & RTE_ETH_RX_OFFLOAD_KEEP_CRC) {
        conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_KEEP_CRC;
    }

    if (dev->hw_ol_features & NETDEV_TX_IPV4_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_TCP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_UDP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_SCTP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_SCTP_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_TSO_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_TSO;
    }

    if (dev->hw_ol_features & NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO;
    }

    if (dev->hw_ol_features & NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO;
    }

    if (dev->hw_ol_features & NETDEV_TX_GRE_TNL_TSO_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO;
    }

    if (dev->hw_ol_features & NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;
    }

    /* Limit configured rss hash functions to only those supported
     * by the eth device. */
    conf.rx_adv_conf.rss_conf.rss_hf &= info->flow_type_rss_offloads;
    if (conf.rx_adv_conf.rss_conf.rss_hf == 0) {
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    } else {
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    }

    /* A device may report more queues than it makes available (this has
     * been observed for Intel xl710, which reserves some of them for
     * SRIOV):  rte_eth_*_queue_setup will fail if a queue is not
     * available.  When this happens we can retry the configuration
     * and request less queues */
    while (n_rxq && n_txq) {
        if (diag) {
            VLOG_INFO("Retrying setup with (rxq:%d txq:%d)", n_rxq, n_txq);
        }

        diag = rte_eth_dev_configure(dev->port_id, n_rxq, n_txq, &conf);
        if (diag) {
            VLOG_WARN("Interface %s eth_dev setup error %s\n",
                      dev->up.name, rte_strerror(-diag));
            break;
        }

        diag = rte_eth_dev_set_mtu(dev->port_id, dev->mtu);
        if (diag) {
            /* A device may not support rte_eth_dev_set_mtu, in this case
             * flag a warning to the user and include the devices configured
             * MTU value that will be used instead. */
            if (-ENOTSUP == diag) {
                rte_eth_dev_get_mtu(dev->port_id, &conf_mtu);
                VLOG_WARN("Interface %s does not support MTU configuration, "
                          "max packet size supported is %"PRIu16".",
                          dev->up.name, conf_mtu);
            } else {
                VLOG_ERR("Interface %s MTU (%d) setup error: %s",
                         dev->up.name, dev->mtu, rte_strerror(-diag));
                break;
            }
        }

        for (i = 0; i < n_txq; i++) {
            diag = rte_eth_tx_queue_setup(dev->port_id, i, dev->txq_size,
                                          dev->socket_id, NULL);
            if (diag) {
                VLOG_INFO("Interface %s unable to setup txq(%d): %s",
                          dev->up.name, i, rte_strerror(-diag));
                break;
            }
        }

        if (i != n_txq) {
            /* Retry with less tx queues */
            n_txq = i;
            continue;
        }

        for (i = 0; i < n_rxq; i++) {
            diag = rte_eth_rx_queue_setup(dev->port_id, i, dev->rxq_size,
                                          dev->socket_id, NULL,
                                          dev->dpdk_mp->mp);
            if (diag) {
                VLOG_INFO("Interface %s unable to setup rxq(%d): %s",
                          dev->up.name, i, rte_strerror(-diag));
                break;
            }
        }

        if (i != n_rxq) {
            /* Retry with less rx queues */
            n_rxq = i;
            continue;
        }

        dev->up.n_rxq = n_rxq;
        dev->up.n_txq = n_txq;

        return 0;
    }

    return diag;
}

static void
dpdk_eth_flow_ctrl_setup(struct netdev_dpdk *dev) OVS_REQUIRES(dev->mutex)
{
    if (rte_eth_dev_flow_ctrl_set(dev->port_id, &dev->fc_conf)) {
        VLOG_WARN("Failed to enable flow control on device "DPDK_PORT_ID_FMT,
                  dev->port_id);
    }
}

static void
dpdk_eth_dev_init_rx_metadata(struct netdev_dpdk *dev)
{
    uint64_t rx_metadata = 0;
    int ret;

    if (dev->rx_metadata_delivery_configured) {
        return;
    }

    /* For the fallback offload (non-"transfer" rules). */
    rx_metadata |= RTE_ETH_RX_METADATA_USER_MARK;

#ifdef ALLOW_EXPERIMENTAL_API
    /* For the tunnel offload.  */
    rx_metadata |= RTE_ETH_RX_METADATA_TUNNEL_ID;
#endif /* ALLOW_EXPERIMENTAL_API */

    ret = rte_eth_rx_metadata_negotiate(dev->port_id, &rx_metadata);
    if (ret == 0) {
        if (!(rx_metadata & RTE_ETH_RX_METADATA_USER_MARK)) {
            VLOG_DBG("%s: The NIC will not provide per-packet USER_MARK",
                     netdev_get_name(&dev->up));
        }
#ifdef ALLOW_EXPERIMENTAL_API
        if (!(rx_metadata & RTE_ETH_RX_METADATA_TUNNEL_ID)) {
            VLOG_DBG("%s: The NIC will not provide per-packet TUNNEL_ID",
                     netdev_get_name(&dev->up));
        }
#endif /* ALLOW_EXPERIMENTAL_API */
    } else {
        VLOG(ret == -ENOTSUP ? VLL_DBG : VLL_WARN,
             "%s: Cannot negotiate Rx metadata: %s",
             netdev_get_name(&dev->up), rte_strerror(-ret));
    }

    dev->rx_metadata_delivery_configured = true;
}

static int
dpdk_eth_dev_init(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    struct rte_pktmbuf_pool_private *mbp_priv;
    struct rte_eth_dev_info info;
    struct rte_ether_addr eth_addr;
    int diag;
    int n_rxq, n_txq;
    uint32_t rx_chksm_offload_capa = RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
                                     RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
                                     RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;

    if (netdev_is_flow_api_enabled()) {
        /*
         * Full tunnel offload requires that tunnel ID metadata be
         * delivered with "miss" packets from the hardware to the
         * PMD. The same goes for megaflow mark metadata which is
         * used in MARK + RSS offload scenario.
         *
         * Request delivery of such metadata.
         */
        dpdk_eth_dev_init_rx_metadata(dev);
    }

    diag = rte_eth_dev_info_get(dev->port_id, &info);
    if (diag < 0) {
        VLOG_ERR("Interface %s rte_eth_dev_info_get error: %s",
                 dev->up.name, rte_strerror(-diag));
        return -diag;
    }

    dev->is_representor = !!(*info.dev_flags & RTE_ETH_DEV_REPRESENTOR);

    if (strstr(info.driver_name, "vf") != NULL) {
        VLOG_INFO("Virtual function detected, HW_CRC_STRIP will be enabled");
        dev->hw_ol_features |= NETDEV_RX_HW_CRC_STRIP;
    } else {
        dev->hw_ol_features &= ~NETDEV_RX_HW_CRC_STRIP;
    }

    if ((info.rx_offload_capa & rx_chksm_offload_capa) !=
            rx_chksm_offload_capa) {
        VLOG_WARN("Rx checksum offload is not supported on port "
                  DPDK_PORT_ID_FMT, dev->port_id);
        dev->hw_ol_features &= ~NETDEV_RX_CHECKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features |= NETDEV_RX_CHECKSUM_OFFLOAD;
    }

    if (info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) {
        dev->hw_ol_features |= NETDEV_RX_HW_SCATTER;
    } else {
        /* Do not warn on lack of scatter support */
        dev->hw_ol_features &= ~NETDEV_RX_HW_SCATTER;
    }

    if (!strcmp(info.driver_name, "net_tap")) {
        /* FIXME: L4 checksum offloading is broken in DPDK net/tap driver.
         * This workaround can be removed once the fix makes it to a DPDK
         * LTS release used by OVS. */
        VLOG_INFO("%s: disabled Tx L4 checksum offloads for a net/tap port.",
                  netdev_get_name(&dev->up));
        info.tx_offload_capa &= ~RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
        info.tx_offload_capa &= ~RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    }

    if (!strcmp(info.driver_name, "net_txgbe")) {
        /* FIXME: Driver advertises the capability but doesn't seem
         * to actually support it correctly.  Can remove this once
         * the driver is fixed on DPDK side. */
        VLOG_INFO("%s: disabled Tx outer udp checksum offloads for a "
                  "net/txgbe port.",
                  netdev_get_name(&dev->up));
        info.tx_offload_capa &= ~RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_IPV4_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_IPV4_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_TCP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_TCP_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_UDP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_UDP_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SCTP_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_SCTP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_SCTP_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD;
    }

    dev->hw_ol_features &= ~NETDEV_TX_TSO_OFFLOAD;
    if (userspace_tso_enabled()) {
        if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) {
            dev->hw_ol_features |= NETDEV_TX_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx TSO offload is not supported.",
                      netdev_get_name(&dev->up));
        }

        if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO) {
            dev->hw_ol_features |= NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx Vxlan tunnel TSO offload is not supported.",
                      netdev_get_name(&dev->up));
        }

        if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO) {
            dev->hw_ol_features |= NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx Geneve tunnel TSO offload is not supported.",
                      netdev_get_name(&dev->up));
        }

        if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO) {
            dev->hw_ol_features |= NETDEV_TX_GRE_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx GRE tunnel TSO offload is not supported.",
                      netdev_get_name(&dev->up));
        }
    }

    n_rxq = MIN(info.max_rx_queues, dev->up.n_rxq);
    n_txq = MIN(info.max_tx_queues, dev->up.n_txq);

    diag = dpdk_eth_dev_port_config(dev, &info, n_rxq, n_txq);
    if (diag) {
        VLOG_ERR("Interface %s(rxq:%d txq:%d lsc interrupt mode:%s) "
                 "configure error: %s",
                 dev->up.name, n_rxq, n_txq,
                 dev->lsc_interrupt_mode ? "true" : "false",
                 rte_strerror(-diag));
        return -diag;
    }

    diag = rte_eth_dev_start(dev->port_id);
    if (diag) {
        VLOG_ERR("Interface %s start error: %s", dev->up.name,
                 rte_strerror(-diag));
        return -diag;
    }
    dev->started = true;

    netdev_dpdk_configure_xstats(dev);

    rte_eth_promiscuous_enable(dev->port_id);
    rte_eth_allmulticast_enable(dev->port_id);

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(dev->port_id, &eth_addr);
    VLOG_INFO_RL(&rl, "Port "DPDK_PORT_ID_FMT": "ETH_ADDR_FMT,
                 dev->port_id, ETH_ADDR_BYTES_ARGS(eth_addr.addr_bytes));

    memcpy(dev->hwaddr.ea, eth_addr.addr_bytes, ETH_ADDR_LEN);
    if (rte_eth_link_get_nowait(dev->port_id, &dev->link) < 0) {
        memset(&dev->link, 0, sizeof dev->link);
    }

    mbp_priv = rte_mempool_get_priv(dev->dpdk_mp->mp);
    dev->buf_size = mbp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM;
    return 0;
}

static struct netdev_dpdk *
netdev_dpdk_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_dpdk, up);
}

static struct netdev *
netdev_dpdk_alloc(void)
{
    struct netdev_dpdk *dev;

    dev = dpdk_rte_mzalloc(sizeof *dev);
    if (dev) {
        return &dev->up;
    }

    return NULL;
}

static struct dpdk_tx_queue *
netdev_dpdk_alloc_txq(unsigned int n_txqs)
{
    struct dpdk_tx_queue *txqs;
    unsigned i;

    txqs = dpdk_rte_mzalloc(n_txqs * sizeof *txqs);
    if (txqs) {
        for (i = 0; i < n_txqs; i++) {
            /* Initialize map for vhost devices. */
            txqs[i].map = OVS_VHOST_QUEUE_MAP_UNKNOWN;
            rte_spinlock_init(&txqs[i].tx_lock);
        }
    }

    return txqs;
}

static int
common_construct(struct netdev *netdev, dpdk_port_t port_no,
                 enum dpdk_dev_type type, int socket_id)
    OVS_REQUIRES(dpdk_mutex)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_init(&dev->mutex);

    rte_spinlock_init(&dev->stats_lock);

    /* If the 'sid' is negative, it means that the kernel fails
     * to obtain the pci numa info.  In that situation, always
     * use 'SOCKET0'. */
    dev->socket_id = socket_id < 0 ? SOCKET0 : socket_id;
    dev->requested_socket_id = dev->socket_id;
    dev->port_id = port_no;
    dev->type = type;
    dev->flags = 0;
    dev->requested_mtu = RTE_ETHER_MTU;
    dev->max_packet_len = MTU_TO_FRAME_LEN(dev->mtu);
    dev->requested_lsc_interrupt_mode = 0;
    ovsrcu_index_init(&dev->vid, -1);
    dev->vhost_reconfigured = false;
    dev->virtio_features_state = OVS_VIRTIO_F_CLEAN;
    dev->attached = false;
    dev->started = false;

    ovsrcu_init(&dev->qos_conf, NULL);

    ovsrcu_init(&dev->ingress_policer, NULL);
    dev->policer_rate = 0;
    dev->policer_burst = 0;

    netdev->n_rxq = 0;
    netdev->n_txq = 0;
    dev->user_n_rxq = NR_QUEUE;
    dev->requested_n_rxq = NR_QUEUE;
    dev->requested_n_txq = NR_QUEUE;
    dev->requested_rxq_size = NIC_PORT_DEFAULT_RXQ_SIZE;
    dev->requested_txq_size = NIC_PORT_DEFAULT_TXQ_SIZE;
    dev->requested_rx_steer_flags = 0;
    dev->rx_steer_flags = 0;
    dev->rx_steer_flows_num = 0;
    dev->rx_steer_flows = NULL;

    /* Initialize the flow control to NULL */
    memset(&dev->fc_conf, 0, sizeof dev->fc_conf);

    /* Initilize the hardware offload flags to 0 */
    dev->hw_ol_features = 0;

    dev->rx_metadata_delivery_configured = false;

    dev->flags = NETDEV_UP | NETDEV_PROMISC;

    ovs_list_push_back(&dpdk_list, &dev->list_node);

    netdev_request_reconfigure(netdev);

    dev->rte_xstats_names = NULL;
    dev->rte_xstats_names_size = 0;

    dev->rte_xstats_ids = NULL;
    dev->rte_xstats_ids_size = 0;

    dev->sw_stats = xzalloc(sizeof *dev->sw_stats);
    dev->sw_stats->tx_retries = (dev->type == DPDK_DEV_VHOST) ? 0 : UINT64_MAX;

    return 0;
}

static int
vhost_common_construct(struct netdev *netdev)
    OVS_REQUIRES(dpdk_mutex)
{
    int socket_id = rte_lcore_to_socket_id(rte_get_main_lcore());
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    dev->vhost_rxq_enabled = dpdk_rte_mzalloc(OVS_VHOST_MAX_QUEUE_NUM *
                                              sizeof *dev->vhost_rxq_enabled);
    if (!dev->vhost_rxq_enabled) {
        return ENOMEM;
    }
    dev->tx_q = netdev_dpdk_alloc_txq(OVS_VHOST_MAX_QUEUE_NUM);
    if (!dev->tx_q) {
        rte_free(dev->vhost_rxq_enabled);
        return ENOMEM;
    }

    atomic_init(&dev->vhost_tx_retries_max, VHOST_ENQ_RETRY_DEF);

    dev->vhost_max_queue_pairs = VHOST_MAX_QUEUE_PAIRS_DEF;

    return common_construct(netdev, DPDK_ETH_PORT_ID_INVALID,
                            DPDK_DEV_VHOST, socket_id);
}

static int
netdev_dpdk_vhost_construct(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    const char *name = netdev->name;
    int err;

    /* 'name' is appended to 'vhost_sock_dir' and used to create a socket in
     * the file system. '/' or '\' would traverse directories, so they're not
     * acceptable in 'name'. */
    if (strchr(name, '/') || strchr(name, '\\')) {
        VLOG_ERR("\"%s\" is not a valid name for a vhost-user port. "
                 "A valid name must not include '/' or '\\'",
                 name);
        return EINVAL;
    }

    ovs_mutex_lock(&dpdk_mutex);
    /* Take the name of the vhost-user port and append it to the location where
     * the socket is to be created, then register the socket.
     */
    dev->vhost_id = xasprintf("%s/%s", vhost_sock_dir, name);

    dev->vhost_driver_flags &= ~RTE_VHOST_USER_CLIENT;

    /* There is no support for multi-segments buffers. */
    dev->vhost_driver_flags |= RTE_VHOST_USER_LINEARBUF_SUPPORT;
    err = rte_vhost_driver_register(dev->vhost_id, dev->vhost_driver_flags);
    if (err) {
        VLOG_ERR("vhost-user socket device setup failure for socket %s\n",
                 dev->vhost_id);
        goto out;
    } else {
        fatal_signal_add_file_to_unlink(dev->vhost_id);
        VLOG_INFO("Socket %s created for vhost-user port %s\n",
                  dev->vhost_id, name);
    }

    err = rte_vhost_driver_callback_register(dev->vhost_id,
                                                &virtio_net_device_ops);
    if (err) {
        VLOG_ERR("rte_vhost_driver_callback_register failed for vhost user "
                 "port: %s\n", name);
        goto out;
    }

    if (!userspace_tso_enabled()) {
        err = rte_vhost_driver_disable_features(dev->vhost_id,
                                    1ULL << VIRTIO_NET_F_HOST_TSO4
                                    | 1ULL << VIRTIO_NET_F_HOST_TSO6
                                    | 1ULL << VIRTIO_NET_F_CSUM);
        if (err) {
            VLOG_ERR("rte_vhost_driver_disable_features failed for vhost user "
                     "port: %s\n", name);
            goto out;
        }
    }

    err = rte_vhost_driver_start(dev->vhost_id);
    if (err) {
        VLOG_ERR("rte_vhost_driver_start failed for vhost user "
                 "port: %s\n", name);
        goto out;
    }

    err = vhost_common_construct(netdev);
    if (err) {
        VLOG_ERR("vhost_common_construct failed for vhost user "
                 "port: %s\n", name);
    }

out:
    if (err) {
        free(dev->vhost_id);
        dev->vhost_id = NULL;
    }

    ovs_mutex_unlock(&dpdk_mutex);
    VLOG_WARN_ONCE("dpdkvhostuser ports are considered deprecated;  "
                   "please migrate to dpdkvhostuserclient ports.");
    return err;
}

static int
netdev_dpdk_vhost_client_construct(struct netdev *netdev)
{
    int err;

    ovs_mutex_lock(&dpdk_mutex);
    err = vhost_common_construct(netdev);
    if (err) {
        VLOG_ERR("vhost_common_construct failed for vhost user client"
                 "port: %s\n", netdev->name);
    }
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

static int
netdev_dpdk_construct(struct netdev *netdev)
{
    int err;

    ovs_mutex_lock(&dpdk_mutex);
    err = common_construct(netdev, DPDK_ETH_PORT_ID_INVALID,
                           DPDK_DEV_ETH, SOCKET0);
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

static void
common_destruct(struct netdev_dpdk *dev)
    OVS_REQUIRES(dpdk_mutex)
    OVS_EXCLUDED(dev->mutex)
{
    rte_free(dev->tx_q);
    dpdk_mp_put(dev->dpdk_mp);

    ovs_list_remove(&dev->list_node);
    free(ovsrcu_get_protected(struct ingress_policer *,
                              &dev->ingress_policer));
    free(dev->sw_stats);
    ovs_mutex_destroy(&dev->mutex);
}

static void dpdk_rx_steer_unconfigure(struct netdev_dpdk *);

static void
netdev_dpdk_destruct(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dpdk_mutex);

    /* Destroy any rx-steering flows to allow RXQs to be removed. */
    dpdk_rx_steer_unconfigure(dev);

    rte_eth_dev_stop(dev->port_id);
    dev->started = false;

    if (dev->attached) {
        bool dpdk_resources_still_used = false;
        struct rte_eth_dev_info dev_info;
        dpdk_port_t sibling_port_id;
        int diag;

        /* Check if this netdev has siblings (i.e. shares DPDK resources) among
         * other OVS netdevs. */
        RTE_ETH_FOREACH_DEV_SIBLING (sibling_port_id, dev->port_id) {
            struct netdev_dpdk *sibling;

            /* RTE_ETH_FOREACH_DEV_SIBLING lists dev->port_id as part of the
             * loop. */
            if (sibling_port_id == dev->port_id) {
                continue;
            }
            LIST_FOR_EACH (sibling, list_node, &dpdk_list) {
                if (sibling->port_id != sibling_port_id) {
                    continue;
                }
                dpdk_resources_still_used = true;
                break;
            }
            if (dpdk_resources_still_used) {
                break;
            }
        }

        /* Retrieve eth device data before closing it. */
        diag = rte_eth_dev_info_get(dev->port_id, &dev_info);

        /* Remove the eth device. */
        rte_eth_dev_close(dev->port_id);

        /* Remove the rte device if no associated eth device is used by OVS.
         * Note: any remaining eth devices associated to this rte device are
         * closed by DPDK ethdev layer. */
        if (!dpdk_resources_still_used) {
            if (!diag) {
                diag = rte_dev_remove(dev_info.device);
            }

            if (diag < 0) {
                VLOG_ERR("Device '%s' can not be detached: %s.",
                         dev->devargs, rte_strerror(-diag));
            } else {
                /* Device was closed and detached. */
                VLOG_INFO("Device '%s' has been removed and detached",
                    dev->devargs);
            }
        } else {
            /* Device was only closed. rte_dev_remove() was not called. */
            VLOG_INFO("Device '%s' has been removed", dev->devargs);
        }
    }

    netdev_dpdk_clear_xstats(dev);
    free(dev->devargs);
    common_destruct(dev);

    ovs_mutex_unlock(&dpdk_mutex);
}

/* rte_vhost_driver_unregister() can call back destroy_device(), which will
 * try to acquire 'dpdk_mutex' and possibly 'dev->mutex'.  To avoid a
 * deadlock, none of the mutexes must be held while calling this function. */
static int
dpdk_vhost_driver_unregister(struct netdev_dpdk *dev OVS_UNUSED,
                             char *vhost_id)
    OVS_EXCLUDED(dpdk_mutex)
    OVS_EXCLUDED(dev->mutex)
{
    return rte_vhost_driver_unregister(vhost_id);
}

static void
netdev_dpdk_vhost_destruct(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    char *vhost_id;

    ovs_mutex_lock(&dpdk_mutex);

    /* Guest becomes an orphan if still attached. */
    if (netdev_dpdk_get_vid(dev) >= 0
        && !(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)) {
        VLOG_ERR("Removing port '%s' while vhost device still attached.",
                 netdev->name);
        VLOG_ERR("To restore connectivity after re-adding of port, VM on "
                 "socket '%s' must be restarted.", dev->vhost_id);
    }

    vhost_id = dev->vhost_id;
    dev->vhost_id = NULL;
    rte_free(dev->vhost_rxq_enabled);

    common_destruct(dev);

    ovs_mutex_unlock(&dpdk_mutex);

    if (!vhost_id) {
        goto out;
    }

    if (dpdk_vhost_driver_unregister(dev, vhost_id)) {
        VLOG_ERR("%s: Unable to unregister vhost driver for socket '%s'.\n",
                 netdev->name, vhost_id);
    } else if (!(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)) {
        /* OVS server mode - remove this socket from list for deletion */
        fatal_signal_remove_file_to_unlink(vhost_id);
    }
out:
    free(vhost_id);
}

static void
netdev_dpdk_dealloc(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    rte_free(dev);
}

static void
netdev_dpdk_clear_xstats(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    free(dev->rte_xstats_names);
    dev->rte_xstats_names = NULL;
    dev->rte_xstats_names_size = 0;
    free(dev->rte_xstats_ids);
    dev->rte_xstats_ids = NULL;
    dev->rte_xstats_ids_size = 0;
}

static const char *
netdev_dpdk_get_xstat_name(struct netdev_dpdk *dev, uint64_t id)
    OVS_REQUIRES(dev->mutex)
{
    if (id >= dev->rte_xstats_names_size) {
        return "UNKNOWN";
    }
    return dev->rte_xstats_names[id].name;
}

static bool
is_queue_stat(const char *s)
{
    uint16_t tmp;

    return (s[0] == 'r' || s[0] == 't') &&
            (ovs_scan(s + 1, "x_q%"SCNu16"_packets", &tmp) ||
             ovs_scan(s + 1, "x_q%"SCNu16"_bytes", &tmp));
}

static void
netdev_dpdk_configure_xstats(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    struct rte_eth_xstat_name *rte_xstats_names = NULL;
    struct rte_eth_xstat *rte_xstats = NULL;
    int rte_xstats_names_size;
    int rte_xstats_len;
    const char *name;
    uint64_t id;

    netdev_dpdk_clear_xstats(dev);

    rte_xstats_names_size = rte_eth_xstats_get_names(dev->port_id, NULL, 0);
    if (rte_xstats_names_size < 0) {
        VLOG_WARN("Cannot get XSTATS names for port: "DPDK_PORT_ID_FMT,
                  dev->port_id);
        goto out;
    }

    rte_xstats_names = xcalloc(rte_xstats_names_size,
                               sizeof *rte_xstats_names);
    rte_xstats_len = rte_eth_xstats_get_names(dev->port_id,
                                              rte_xstats_names,
                                              rte_xstats_names_size);
    if (rte_xstats_len < 0 || rte_xstats_len != rte_xstats_names_size) {
        VLOG_WARN("Cannot get XSTATS names for port: "DPDK_PORT_ID_FMT,
                  dev->port_id);
        goto out;
    }

    rte_xstats = xcalloc(rte_xstats_names_size, sizeof *rte_xstats);
    rte_xstats_len = rte_eth_xstats_get(dev->port_id, rte_xstats,
                                        rte_xstats_names_size);
    if (rte_xstats_len < 0 || rte_xstats_len != rte_xstats_names_size) {
        VLOG_WARN("Cannot get XSTATS for port: "DPDK_PORT_ID_FMT,
                  dev->port_id);
        goto out;
    }

    dev->rte_xstats_names = rte_xstats_names;
    rte_xstats_names = NULL;
    dev->rte_xstats_names_size = rte_xstats_names_size;

    dev->rte_xstats_ids = xcalloc(rte_xstats_names_size,
                                  sizeof *dev->rte_xstats_ids);
    for (unsigned int i = 0; i < rte_xstats_names_size; i++) {
        id = rte_xstats[i].id;
        name = netdev_dpdk_get_xstat_name(dev, id);

        /* For custom stats, we filter out everything except per rxq/txq basic
         * stats, and dropped, error and management counters. */
        if (is_queue_stat(name) ||
            string_ends_with(name, "_errors") ||
            strstr(name, "_management_") ||
            string_ends_with(name, "_dropped")) {

            dev->rte_xstats_ids[dev->rte_xstats_ids_size] = id;
            dev->rte_xstats_ids_size++;
        }
    }

out:
    free(rte_xstats);
    free(rte_xstats_names);
}

static int
netdev_dpdk_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    if (dev->devargs && dev->devargs[0]) {
        smap_add_format(args, "dpdk-devargs", "%s", dev->devargs);
    }

    smap_add_format(args, "n_rxq", "%d", dev->user_n_rxq);

    if (dev->fc_conf.mode == RTE_ETH_FC_TX_PAUSE ||
        dev->fc_conf.mode == RTE_ETH_FC_FULL) {
        smap_add(args, "rx-flow-ctrl", "true");
    }

    if (dev->fc_conf.mode == RTE_ETH_FC_RX_PAUSE ||
        dev->fc_conf.mode == RTE_ETH_FC_FULL) {
        smap_add(args, "tx-flow-ctrl", "true");
    }

    if (dev->fc_conf.autoneg) {
        smap_add(args, "flow-ctrl-autoneg", "true");
    }

    smap_add_format(args, "n_rxq_desc", "%d", dev->rxq_size);
    smap_add_format(args, "n_txq_desc", "%d", dev->txq_size);

    if (dev->rx_steer_flags == DPDK_RX_STEER_LACP) {
        smap_add(args, "rx-steering", "rss+lacp");
    }

    smap_add(args, "dpdk-lsc-interrupt",
             dev->lsc_interrupt_mode ? "true" : "false");

    if (dev->is_representor) {
        smap_add_format(args, "dpdk-vf-mac", ETH_ADDR_FMT,
                        ETH_ADDR_ARGS(dev->requested_hwaddr));
    }

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static struct netdev_dpdk *
netdev_dpdk_lookup_by_port_id(dpdk_port_t port_id)
    OVS_REQUIRES(dpdk_mutex)
{
    struct netdev_dpdk *dev;

    LIST_FOR_EACH (dev, list_node, &dpdk_list) {
        if (dev->port_id == port_id) {
            return dev;
        }
    }

    return NULL;
}

static dpdk_port_t
netdev_dpdk_get_port_by_mac(const char *mac_str)
{
    dpdk_port_t port_id;
    struct eth_addr mac, port_mac;

    if (!eth_addr_from_string(mac_str, &mac)) {
        VLOG_ERR("invalid mac: %s", mac_str);
        return DPDK_ETH_PORT_ID_INVALID;
    }

    RTE_ETH_FOREACH_DEV (port_id) {
        struct rte_ether_addr ea;

        rte_eth_macaddr_get(port_id, &ea);
        memcpy(port_mac.ea, ea.addr_bytes, ETH_ADDR_LEN);
        if (eth_addr_equals(mac, port_mac)) {
            return port_id;
        }
    }

    return DPDK_ETH_PORT_ID_INVALID;
}

/* Return the first DPDK port id matching the devargs pattern. */
static dpdk_port_t netdev_dpdk_get_port_by_devargs(const char *devargs)
    OVS_REQUIRES(dpdk_mutex)
{
    dpdk_port_t port_id;
    struct rte_dev_iterator iterator;

    RTE_ETH_FOREACH_MATCHING_DEV (port_id, devargs, &iterator) {
        /* If a break is done - must call rte_eth_iterator_cleanup. */
        rte_eth_iterator_cleanup(&iterator);
        break;
    }

    return port_id;
}

/*
 * Normally, a PCI id (optionally followed by a representor identifier)
 * is enough for identifying a specific DPDK port.
 * However, for some NICs having multiple ports sharing the same PCI
 * id, using PCI id won't work then.
 *
 * To fix that, here one more method is introduced: "class=eth,mac=$MAC".
 *
 * Note that the compatibility is fully kept: user can still use the
 * PCI id for adding ports (when it's enough for them).
 */
static dpdk_port_t
netdev_dpdk_process_devargs(struct netdev_dpdk *dev,
                            const char *devargs, char **errp)
    OVS_REQUIRES(dpdk_mutex)
{
    dpdk_port_t new_port_id;

    if (strncmp(devargs, "class=eth,mac=", 14) == 0) {
        new_port_id = netdev_dpdk_get_port_by_mac(&devargs[14]);
    } else {
        new_port_id = netdev_dpdk_get_port_by_devargs(devargs);
        if (!rte_eth_dev_is_valid_port(new_port_id)) {
            /* Device not found in DPDK, attempt to attach it */
            if (rte_dev_probe(devargs)) {
                new_port_id = DPDK_ETH_PORT_ID_INVALID;
            } else {
                new_port_id = netdev_dpdk_get_port_by_devargs(devargs);
                if (rte_eth_dev_is_valid_port(new_port_id)) {
                    /* Attach successful */
                    dev->attached = true;
                    VLOG_INFO("Device '%s' attached to DPDK", devargs);
                } else {
                    /* Attach unsuccessful */
                    new_port_id = DPDK_ETH_PORT_ID_INVALID;
                }
            }
        }
    }

    if (new_port_id == DPDK_ETH_PORT_ID_INVALID) {
        VLOG_WARN_BUF(errp, "Error attaching device '%s' to DPDK", devargs);
    }

    return new_port_id;
}

static struct seq *netdev_dpdk_reset_seq;
static uint64_t netdev_dpdk_last_reset_seq;
static atomic_bool netdev_dpdk_pending_reset[RTE_MAX_ETHPORTS];

static void
netdev_dpdk_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{
    uint64_t last_reset_seq = seq_read(netdev_dpdk_reset_seq);

    if (netdev_dpdk_last_reset_seq == last_reset_seq) {
        seq_wait(netdev_dpdk_reset_seq, netdev_dpdk_last_reset_seq);
    } else {
        poll_immediate_wake();
    }
}

static void
netdev_dpdk_run(const struct netdev_class *netdev_class OVS_UNUSED)
{
    uint64_t reset_seq = seq_read(netdev_dpdk_reset_seq);

    if (reset_seq != netdev_dpdk_last_reset_seq) {
        dpdk_port_t port_id;

        netdev_dpdk_last_reset_seq = reset_seq;

        for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
            struct netdev_dpdk *dev;
            bool pending_reset;

            atomic_read_relaxed(&netdev_dpdk_pending_reset[port_id],
                                &pending_reset);
            if (!pending_reset) {
                continue;
            }

            ovs_mutex_lock(&dpdk_mutex);
            dev = netdev_dpdk_lookup_by_port_id(port_id);
            if (dev) {
                ovs_mutex_lock(&dev->mutex);
                netdev_request_reconfigure(&dev->up);
                VLOG_DBG_RL(&rl, "%s: Device reset requested.",
                            netdev_get_name(&dev->up));
                ovs_mutex_unlock(&dev->mutex);
            }
            ovs_mutex_unlock(&dpdk_mutex);
        }
    }
}

static int
dpdk_eth_event_callback(dpdk_port_t port_id, enum rte_eth_event_type type,
                        void *param OVS_UNUSED, void *ret_param OVS_UNUSED)
{
    switch ((int) type) {
    case RTE_ETH_EVENT_INTR_RESET:
        atomic_store_relaxed(&netdev_dpdk_pending_reset[port_id], true);
        seq_change(netdev_dpdk_reset_seq);
        break;

    default:
        /* Ignore all other types. */
        break;
    }
    return 0;
}

static void
dpdk_set_rxq_config(struct netdev_dpdk *dev, const struct smap *args)
    OVS_REQUIRES(dev->mutex)
{
    int new_n_rxq;

    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq != dev->user_n_rxq) {
        dev->user_n_rxq = new_n_rxq;
        netdev_request_reconfigure(&dev->up);
    }
}

static void
dpdk_process_queue_size(struct netdev *netdev, const struct smap *args,
                        struct rte_eth_dev_info *info, bool is_rx)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_eth_desc_lim *lim;
    int default_size, queue_size, cur_size, new_requested_size;
    int *cur_requested_size;
    bool reconfig = false;

    if (is_rx) {
        default_size = NIC_PORT_DEFAULT_RXQ_SIZE;
        new_requested_size = smap_get_int(args, "n_rxq_desc", default_size);
        cur_size = dev->rxq_size;
        cur_requested_size = &dev->requested_rxq_size;
        lim = info ? &info->rx_desc_lim : NULL;
    } else {
        default_size = NIC_PORT_DEFAULT_TXQ_SIZE;
        new_requested_size = smap_get_int(args, "n_txq_desc", default_size);
        cur_size = dev->txq_size;
        cur_requested_size = &dev->requested_txq_size;
        lim = info ? &info->tx_desc_lim : NULL;
    }

    queue_size = new_requested_size;

    if (queue_size <= 0 || !is_pow2(queue_size)) {
        queue_size = default_size;
    }

    if (lim) {
        /* Check for device limits. */
        if (lim->nb_align) {
            queue_size = ROUND_UP(queue_size, lim->nb_align);
        }
        queue_size = MIN(queue_size, lim->nb_max);
        queue_size = MAX(queue_size, lim->nb_min);
    }

    *cur_requested_size = queue_size;

    if (cur_size != queue_size) {
        netdev_request_reconfigure(netdev);
        reconfig = true;
    }
    if (new_requested_size != queue_size) {
        VLOG(reconfig ? VLL_INFO : VLL_DBG,
             "%s: Unable to set the number of %s descriptors to %d. "
             "Adjusted to %d.", netdev_get_name(netdev),
             is_rx ? "rx": "tx", new_requested_size, queue_size);
    }
}

static void
dpdk_set_rx_steer_config(struct netdev *netdev, struct netdev_dpdk *dev,
                         const struct smap *args, char **errp)
{
    const char *arg = smap_get_def(args, "rx-steering", "rss");
    uint64_t flags = 0;

    if (!strcmp(arg, "rss+lacp")) {
        flags = DPDK_RX_STEER_LACP;
    } else if (strcmp(arg, "rss")) {
        VLOG_WARN_BUF(errp, "%s: options:rx-steering "
                      "unsupported parameter value '%s'",
                      netdev_get_name(netdev), arg);
    }

    if (flags && dev->type != DPDK_DEV_ETH) {
        VLOG_WARN_BUF(errp, "%s: options:rx-steering "
                      "is only supported on ethernet ports",
                      netdev_get_name(netdev));
        flags = 0;
    }

    if (flags && netdev_is_flow_api_enabled()) {
        VLOG_WARN_BUF(errp, "%s: options:rx-steering "
                      "is incompatible with hw-offload",
                      netdev_get_name(netdev));
        flags = 0;
    }

    if (flags != dev->requested_rx_steer_flags) {
        dev->requested_rx_steer_flags = flags;
        netdev_request_reconfigure(netdev);
    }
}

static int
netdev_dpdk_set_config(struct netdev *netdev, const struct smap *args,
                       char **errp)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    bool rx_fc_en, tx_fc_en, autoneg, lsc_interrupt_mode;
    bool flow_control_requested = true;
    enum rte_eth_fc_mode fc_mode;
    static const enum rte_eth_fc_mode fc_mode_set[2][2] = {
        {RTE_ETH_FC_NONE,     RTE_ETH_FC_TX_PAUSE},
        {RTE_ETH_FC_RX_PAUSE, RTE_ETH_FC_FULL    }
    };
    struct rte_eth_dev_info info;
    const char *new_devargs;
    const char *vf_mac;
    int err = 0;

    ovs_mutex_lock(&dpdk_mutex);
    ovs_mutex_lock(&dev->mutex);

    dpdk_set_rx_steer_config(netdev, dev, args, errp);

    dpdk_set_rxq_config(dev, args);

    new_devargs = smap_get(args, "dpdk-devargs");

    if (dev->devargs && new_devargs && strcmp(new_devargs, dev->devargs)) {
        /* The user requested a new device.  If we return error, the caller
         * will delete this netdev and try to recreate it. */
        err = EAGAIN;
        goto out;
    }

    /* dpdk-devargs is required for device configuration */
    if (new_devargs && new_devargs[0]) {
        /* Don't process dpdk-devargs if value is unchanged and port id
         * is valid */
        if (!(dev->devargs && !strcmp(dev->devargs, new_devargs)
               && rte_eth_dev_is_valid_port(dev->port_id))) {
            dpdk_port_t new_port_id = netdev_dpdk_process_devargs(dev,
                                                                  new_devargs,
                                                                  errp);
            if (!rte_eth_dev_is_valid_port(new_port_id)) {
                err = EINVAL;
            } else if (new_port_id == dev->port_id) {
                /* Already configured, do not reconfigure again */
                err = 0;
            } else {
                struct netdev_dpdk *dup_dev;

                dup_dev = netdev_dpdk_lookup_by_port_id(new_port_id);
                if (dup_dev) {
                    VLOG_WARN_BUF(errp, "'%s' is trying to use device '%s' "
                                  "which is already in use by '%s'",
                                  netdev_get_name(netdev), new_devargs,
                                  netdev_get_name(&dup_dev->up));
                    err = EADDRINUSE;
                } else {
                    int sid = rte_eth_dev_socket_id(new_port_id);

                    dev->requested_socket_id = sid < 0 ? SOCKET0 : sid;
                    dev->devargs = xstrdup(new_devargs);
                    dev->port_id = new_port_id;
                    netdev_request_reconfigure(&dev->up);
                    err = 0;
                }
            }
        }
    } else {
        VLOG_WARN_BUF(errp, "'%s' is missing 'options:dpdk-devargs'. "
                            "The old 'dpdk<port_id>' names are not supported",
                      netdev_get_name(netdev));
        err = EINVAL;
    }

    if (err) {
        goto out;
    }

    err = -rte_eth_dev_info_get(dev->port_id, &info);
    if (err) {
        VLOG_WARN_BUF(errp, "%s: Failed to get device info: %s" ,
                      netdev_get_name(netdev), rte_strerror(err));
        goto out;
    }

    dpdk_process_queue_size(netdev, args, &info, true);
    dpdk_process_queue_size(netdev, args, &info, false);

    vf_mac = smap_get(args, "dpdk-vf-mac");
    if (vf_mac) {
        struct eth_addr mac;

        if (!dev->is_representor) {
            VLOG_WARN("'%s' is trying to set the VF MAC '%s' "
                      "but 'options:dpdk-vf-mac' is only supported for "
                      "VF representors.",
                      netdev_get_name(netdev), vf_mac);
        } else if (!eth_addr_from_string(vf_mac, &mac)) {
            VLOG_WARN("interface '%s': cannot parse VF MAC '%s'.",
                      netdev_get_name(netdev), vf_mac);
        } else if (eth_addr_is_multicast(mac)) {
            VLOG_WARN("interface '%s': cannot set VF MAC to multicast "
                      "address '%s'.", netdev_get_name(netdev), vf_mac);
        } else if (!eth_addr_equals(dev->requested_hwaddr, mac)) {
            dev->requested_hwaddr = mac;
            netdev_request_reconfigure(netdev);
        }
    }

    lsc_interrupt_mode = smap_get_bool(args, "dpdk-lsc-interrupt", true);
    if (lsc_interrupt_mode && !(*info.dev_flags & RTE_ETH_DEV_INTR_LSC)) {
        if (smap_get(args, "dpdk-lsc-interrupt")) {
            VLOG_WARN_BUF(errp, "'%s': link status interrupt is not "
                          "supported.", netdev_get_name(netdev));
            err = EINVAL;
            goto out;
        }
        VLOG_DBG("'%s': not enabling link status interrupt.",
                 netdev_get_name(netdev));
        lsc_interrupt_mode = false;
    }
    if (dev->requested_lsc_interrupt_mode != lsc_interrupt_mode) {
        dev->requested_lsc_interrupt_mode = lsc_interrupt_mode;
        netdev_request_reconfigure(netdev);
    }

    rx_fc_en = smap_get_bool(args, "rx-flow-ctrl", false);
    tx_fc_en = smap_get_bool(args, "tx-flow-ctrl", false);
    autoneg = smap_get_bool(args, "flow-ctrl-autoneg", false);

    fc_mode = fc_mode_set[tx_fc_en][rx_fc_en];

    if (!smap_get(args, "rx-flow-ctrl") && !smap_get(args, "tx-flow-ctrl")
        && !smap_get(args, "flow-ctrl-autoneg")) {
        /* FIXME: User didn't ask for flow control configuration.
         *        For now we'll not print a warning if flow control is not
         *        supported by the DPDK port. */
        flow_control_requested = false;
    }

    /* Get the Flow control configuration. */
    err = -rte_eth_dev_flow_ctrl_get(dev->port_id, &dev->fc_conf);
    if (err) {
        if (err == ENOTSUP) {
            if (flow_control_requested) {
                VLOG_WARN("%s: Flow control is not supported.",
                          netdev_get_name(netdev));
            }
            err = 0; /* Not fatal. */
        } else {
            VLOG_WARN_BUF(errp, "%s: Cannot get flow control parameters: %s",
                          netdev_get_name(netdev), rte_strerror(err));
        }
        goto out;
    }

    if (dev->fc_conf.mode != fc_mode || autoneg != dev->fc_conf.autoneg) {
        dev->fc_conf.mode = fc_mode;
        dev->fc_conf.autoneg = autoneg;
        dpdk_eth_flow_ctrl_setup(dev);
    }

out:
    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&dpdk_mutex);

    return err;
}

static int
netdev_dpdk_vhost_client_get_config(const struct netdev *netdev,
                                    struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int tx_retries_max;

    ovs_mutex_lock(&dev->mutex);

    if (dev->vhost_id) {
        smap_add(args, "vhost-server-path", dev->vhost_id);
    }

    atomic_read_relaxed(&dev->vhost_tx_retries_max, &tx_retries_max);
    if (tx_retries_max != VHOST_ENQ_RETRY_DEF) {
        smap_add_format(args, "tx-retries-max", "%d", tx_retries_max);
    }

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_vhost_client_set_config(struct netdev *netdev,
                                    const struct smap *args,
                                    char **errp OVS_UNUSED)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    const char *path;
    int max_tx_retries, cur_max_tx_retries;
    uint32_t max_queue_pairs;

    ovs_mutex_lock(&dev->mutex);
    if (!(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)) {
        path = smap_get(args, "vhost-server-path");
        if (!nullable_string_is_equal(path, dev->vhost_id)) {
            free(dev->vhost_id);
            dev->vhost_id = nullable_xstrdup(path);

            max_queue_pairs = smap_get_int(args, "vhost-max-queue-pairs",
                                           VHOST_MAX_QUEUE_PAIRS_DEF);
            if (max_queue_pairs < VHOST_MAX_QUEUE_PAIRS_MIN
                || max_queue_pairs > VHOST_MAX_QUEUE_PAIRS_MAX) {
                max_queue_pairs = VHOST_MAX_QUEUE_PAIRS_DEF;
            }
            dev->vhost_max_queue_pairs = max_queue_pairs;

            netdev_request_reconfigure(netdev);
        }
    }

    max_tx_retries = smap_get_int(args, "tx-retries-max",
                                  VHOST_ENQ_RETRY_DEF);
    if (max_tx_retries < VHOST_ENQ_RETRY_MIN
        || max_tx_retries > VHOST_ENQ_RETRY_MAX) {
        max_tx_retries = VHOST_ENQ_RETRY_DEF;
    }
    atomic_read_relaxed(&dev->vhost_tx_retries_max, &cur_max_tx_retries);
    if (max_tx_retries != cur_max_tx_retries) {
        atomic_store_relaxed(&dev->vhost_tx_retries_max, max_tx_retries);
        VLOG_INFO("Max Tx retries for vhost device '%s' set to %d",
                  netdev_get_name(netdev), max_tx_retries);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_get_numa_id(const struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    return dev->socket_id;
}

/* Sets the number of tx queues for the dpdk interface. */
static int
netdev_dpdk_set_tx_multiq(struct netdev *netdev, unsigned int n_txq)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    if (dev->requested_n_txq == n_txq) {
        goto out;
    }

    dev->requested_n_txq = n_txq;
    netdev_request_reconfigure(netdev);

out:
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

static struct netdev_rxq *
netdev_dpdk_rxq_alloc(void)
{
    struct netdev_rxq_dpdk *rx = dpdk_rte_mzalloc(sizeof *rx);

    if (rx) {
        return &rx->up;
    }

    return NULL;
}

static struct netdev_rxq_dpdk *
netdev_rxq_dpdk_cast(const struct netdev_rxq *rxq)
{
    return CONTAINER_OF(rxq, struct netdev_rxq_dpdk, up);
}

static int
netdev_dpdk_rxq_construct(struct netdev_rxq *rxq)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq);
    struct netdev_dpdk *dev = netdev_dpdk_cast(rxq->netdev);

    ovs_mutex_lock(&dev->mutex);
    rx->port_id = dev->port_id;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static void
netdev_dpdk_rxq_destruct(struct netdev_rxq *rxq OVS_UNUSED)
{
}

static void
netdev_dpdk_rxq_dealloc(struct netdev_rxq *rxq)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq);

    rte_free(rx);
}

static inline void
netdev_dpdk_batch_init_packet_fields(struct dp_packet_batch *batch)
{
    struct dp_packet *packet;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        dp_packet_reset_cutlen(packet);
        packet->packet_type = htonl(PT_ETH);
        packet->has_hash = !!(packet->mbuf.ol_flags & RTE_MBUF_F_RX_RSS_HASH);
        packet->has_mark = !!(packet->mbuf.ol_flags & RTE_MBUF_F_RX_FDIR_ID);
        packet->offloads =
            packet->mbuf.ol_flags & (RTE_MBUF_F_RX_IP_CKSUM_BAD
                                     | RTE_MBUF_F_RX_IP_CKSUM_GOOD
                                     | RTE_MBUF_F_RX_L4_CKSUM_BAD
                                     | RTE_MBUF_F_RX_L4_CKSUM_GOOD);
    }
}

/* Prepare the packet for HWOL.
 * Return True if the packet is OK to continue. */
static bool
netdev_dpdk_prep_hwol_packet(struct netdev_dpdk *dev, struct rte_mbuf *mbuf)
{
    struct dp_packet *pkt = CONTAINER_OF(mbuf, struct dp_packet, mbuf);
    uint64_t unexpected = mbuf->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK;
    const struct ip_header *ip;
    bool is_sctp;
    bool l3_csum;
    bool l4_csum;
    bool is_tcp;
    bool is_udp;
    void *l2;
    void *l3;
    void *l4;

    if (OVS_UNLIKELY(unexpected)) {
        VLOG_WARN_RL(&rl, "%s: Unexpected Tx offload flags: %#"PRIx64,
                     netdev_get_name(&dev->up), unexpected);
        netdev_dpdk_mbuf_dump(netdev_get_name(&dev->up),
                              "Packet with unexpected ol_flags", mbuf);
        return false;
    }

    if (!dp_packet_ip_checksum_partial(pkt)
        && !dp_packet_inner_ip_checksum_partial(pkt)
        && !dp_packet_l4_checksum_partial(pkt)
        && !dp_packet_inner_l4_checksum_partial(pkt)
        && !mbuf->tso_segsz) {

        return true;
    }

    if (dp_packet_tunnel(pkt)
        && (dp_packet_inner_ip_checksum_partial(pkt)
            || dp_packet_inner_l4_checksum_partial(pkt)
            || mbuf->tso_segsz)) {
        if (dp_packet_ip_checksum_partial(pkt)
            || dp_packet_l4_checksum_partial(pkt)) {
            mbuf->outer_l2_len = (char *) dp_packet_l3(pkt) -
                                 (char *) dp_packet_eth(pkt);
            mbuf->outer_l3_len = (char *) dp_packet_l4(pkt) -
                                 (char *) dp_packet_l3(pkt);

            if (dp_packet_tunnel_geneve(pkt)) {
                mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_GENEVE;
            } else if (dp_packet_tunnel_vxlan(pkt)) {
                mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_VXLAN;
            } else {
                ovs_assert(dp_packet_tunnel_gre(pkt));
                mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_GRE;
            }

            if (dp_packet_ip_checksum_partial(pkt)) {
                mbuf->ol_flags |= RTE_MBUF_F_TX_OUTER_IP_CKSUM;
            }

            if (dp_packet_l4_checksum_partial(pkt)) {
                ovs_assert(dp_packet_l4_proto_udp(pkt));
                mbuf->ol_flags |= RTE_MBUF_F_TX_OUTER_UDP_CKSUM;
            }

            ip = dp_packet_l3(pkt);
            mbuf->ol_flags |= IP_VER(ip->ip_ihl_ver) == 4
                              ? RTE_MBUF_F_TX_OUTER_IPV4
                              : RTE_MBUF_F_TX_OUTER_IPV6;

            /* Inner L2 length must account for the tunnel header length. */
            l2 = dp_packet_l4(pkt);
            l3 = dp_packet_inner_l3(pkt);
            l3_csum = dp_packet_inner_ip_checksum_partial(pkt);
            l4 = dp_packet_inner_l4(pkt);
            l4_csum = dp_packet_inner_l4_checksum_partial(pkt);
            is_tcp = dp_packet_inner_l4_proto_tcp(pkt);
            is_udp = dp_packet_inner_l4_proto_udp(pkt);
            is_sctp = dp_packet_inner_l4_proto_sctp(pkt);
        } else {
            mbuf->outer_l2_len = 0;
            mbuf->outer_l3_len = 0;

            /* Skip outer headers. */
            l2 = dp_packet_eth(pkt);
            l3 = dp_packet_inner_l3(pkt);
            l3_csum = dp_packet_inner_ip_checksum_partial(pkt);
            l4 = dp_packet_inner_l4(pkt);
            l4_csum = dp_packet_inner_l4_checksum_partial(pkt);
            is_tcp = dp_packet_inner_l4_proto_tcp(pkt);
            is_udp = dp_packet_inner_l4_proto_udp(pkt);
            is_sctp = dp_packet_inner_l4_proto_sctp(pkt);
        }
    } else {
        mbuf->outer_l2_len = 0;
        mbuf->outer_l3_len = 0;

        l2 = dp_packet_eth(pkt);
        l3 = dp_packet_l3(pkt);
        l3_csum = dp_packet_ip_checksum_partial(pkt);
        l4 = dp_packet_l4(pkt);
        l4_csum = dp_packet_l4_checksum_partial(pkt);
        is_tcp = dp_packet_l4_proto_tcp(pkt);
        is_udp = dp_packet_l4_proto_udp(pkt);
        is_sctp = dp_packet_l4_proto_sctp(pkt);
    }

    ovs_assert(l4);

    ip = l3;
    mbuf->ol_flags |= IP_VER(ip->ip_ihl_ver) == 4
                      ? RTE_MBUF_F_TX_IPV4 : RTE_MBUF_F_TX_IPV6;

    if (l3_csum) {
        mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
    }

    if (l4_csum) {
        if (is_tcp) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
        } else if (is_udp) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        } else {
            ovs_assert(is_sctp);
            mbuf->ol_flags |= RTE_MBUF_F_TX_SCTP_CKSUM;
        }
    }

    mbuf->l2_len = (char *) l3 - (char *) l2;
    mbuf->l3_len = (char *) l4 - (char *) l3;

    if (mbuf->tso_segsz) {
        struct tcp_header *th = l4;
        uint16_t link_tso_segsz;
        int hdr_len;

        mbuf->l4_len = TCP_OFFSET(th->tcp_ctl) * 4;
        if (dp_packet_tunnel(pkt)) {
            link_tso_segsz = dev->mtu - mbuf->l2_len - mbuf->l3_len -
                             mbuf->l4_len - mbuf->outer_l3_len;
        } else {
            link_tso_segsz = dev->mtu - mbuf->l3_len - mbuf->l4_len;
        }

        if (mbuf->tso_segsz > link_tso_segsz) {
            mbuf->tso_segsz = link_tso_segsz;
        }

        hdr_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;
        if (OVS_UNLIKELY((hdr_len + mbuf->tso_segsz) > dev->max_packet_len)) {
            VLOG_WARN_RL(&rl, "%s: Oversized TSO packet. hdr: %"PRIu32", "
                         "gso: %"PRIu32", max len: %"PRIu32"",
                         dev->up.name, hdr_len, mbuf->tso_segsz,
                         dev->max_packet_len);
            return false;
        }
        mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;

        /* DPDK API mandates IPv4 checksum when requesting TSO. */
        if (IP_VER(ip->ip_ihl_ver) == 4) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
        }
    }

    return true;
}

/* Prepare a batch for HWOL.
 * Return the number of good packets in the batch. */
static int
netdev_dpdk_prep_hwol_batch(struct netdev_dpdk *dev, struct rte_mbuf **pkts,
                            int pkt_cnt)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt;

    /* Prepare and filter bad HWOL packets. */
    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (!netdev_dpdk_prep_hwol_packet(dev, pkt)) {
            rte_pktmbuf_free(pkt);
            continue;
        }

        if (OVS_UNLIKELY(i != cnt)) {
            pkts[cnt] = pkt;
        }
        cnt++;
    }

    return cnt;
}

static void
netdev_dpdk_mbuf_dump(const char *prefix, const char *message,
                      const struct rte_mbuf *mbuf)
{
    static struct vlog_rate_limit dump_rl = VLOG_RATE_LIMIT_INIT(5, 5);
    char *response = NULL;
    FILE *stream;
    size_t size;

    if (VLOG_DROP_DBG(&dump_rl)) {
        return;
    }

    stream = open_memstream(&response, &size);
    if (!stream) {
        VLOG_ERR("Unable to open memstream for mbuf dump: %s.",
                 ovs_strerror(errno));
        return;
    }

    rte_pktmbuf_dump(stream, mbuf, rte_pktmbuf_pkt_len(mbuf));

    fclose(stream);

    VLOG_DBG(prefix ? "%s: %s:\n%s" : "%s%s:\n%s",
             prefix ? prefix : "", message, response);
    free(response);
}

/* Tries to transmit 'pkts' to txq 'qid' of device 'dev'.  Takes ownership of
 * 'pkts', even in case of failure.
 *
 * Returns the number of packets that weren't transmitted. */
static inline int
netdev_dpdk_eth_tx_burst(struct netdev_dpdk *dev, int qid,
                         struct rte_mbuf **pkts, int cnt)
{
    uint32_t nb_tx = 0;
    uint16_t nb_tx_prep = cnt;

    nb_tx_prep = rte_eth_tx_prepare(dev->port_id, qid, pkts, cnt);
    if (nb_tx_prep != cnt) {
        VLOG_WARN_RL(&rl, "%s: Output batch contains invalid packets. "
                     "Only %u/%u are valid: %s", netdev_get_name(&dev->up),
                     nb_tx_prep, cnt, rte_strerror(rte_errno));
        netdev_dpdk_mbuf_dump(netdev_get_name(&dev->up),
                              "First invalid packet", pkts[nb_tx_prep]);
    }

    while (nb_tx != nb_tx_prep) {
        uint32_t ret;

        ret = rte_eth_tx_burst(dev->port_id, qid, pkts + nb_tx,
                               nb_tx_prep - nb_tx);
        if (!ret) {
            break;
        }

        nb_tx += ret;
    }

    if (OVS_UNLIKELY(nb_tx != cnt)) {
        /* Free buffers, which we couldn't transmit. */
        rte_pktmbuf_free_bulk(&pkts[nb_tx], cnt - nb_tx);
    }

    return cnt - nb_tx;
}

static inline bool
netdev_dpdk_srtcm_policer_pkt_handle(struct rte_meter_srtcm *meter,
                                     struct rte_meter_srtcm_profile *profile,
                                     struct rte_mbuf *pkt, uint64_t time)
{
    uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct rte_ether_hdr);

    return rte_meter_srtcm_color_blind_check(meter, profile, time, pkt_len) ==
                                             RTE_COLOR_GREEN;
}

static int
srtcm_policer_run_single_packet(struct rte_meter_srtcm *meter,
                                struct rte_meter_srtcm_profile *profile,
                                struct rte_mbuf **pkts, int pkt_cnt,
                                bool should_steal)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt = NULL;
    uint64_t current_time = rte_rdtsc();

    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        /* Handle current packet */
        if (netdev_dpdk_srtcm_policer_pkt_handle(meter, profile,
                                                 pkt, current_time)) {
            if (cnt != i) {
                pkts[cnt] = pkt;
            }
            cnt++;
        } else {
            if (should_steal) {
                rte_pktmbuf_free(pkt);
            }
        }
    }

    return cnt;
}

static int
ingress_policer_run(struct ingress_policer *policer, struct rte_mbuf **pkts,
                    int pkt_cnt, bool should_steal)
{
    int cnt = 0;

    rte_spinlock_lock(&policer->policer_lock);
    cnt = srtcm_policer_run_single_packet(&policer->in_policer,
                                          &policer->in_prof,
                                          pkts, pkt_cnt, should_steal);
    rte_spinlock_unlock(&policer->policer_lock);

    return cnt;
}

static bool
is_vhost_running(struct netdev_dpdk *dev)
{
    return (netdev_dpdk_get_vid(dev) >= 0 && dev->vhost_reconfigured);
}

/*
 * The receive path for the vhost port is the TX path out from guest.
 */
static int
netdev_dpdk_vhost_rxq_recv(struct netdev_rxq *rxq,
                           struct dp_packet_batch *batch, int *qfill)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(rxq->netdev);
    struct ingress_policer *policer = netdev_dpdk_get_ingress_policer(dev);
    uint16_t nb_rx = 0;
    uint16_t qos_drops = 0;
    int qid = rxq->queue_id * VIRTIO_QNUM + VIRTIO_TXQ;
    int vid = netdev_dpdk_get_vid(dev);

    if (OVS_UNLIKELY(vid < 0 || !dev->vhost_reconfigured
                     || !(dev->flags & NETDEV_UP))) {
        return EAGAIN;
    }

    nb_rx = rte_vhost_dequeue_burst(vid, qid, dev->dpdk_mp->mp,
                                    (struct rte_mbuf **) batch->packets,
                                    NETDEV_MAX_BURST);
    if (!nb_rx) {
        return EAGAIN;
    }

    if (qfill) {
        if (nb_rx == NETDEV_MAX_BURST) {
            /* The DPDK API returns a uint32_t which often has invalid bits in
             * the upper 16-bits. Need to restrict the value to uint16_t. */
            *qfill = rte_vhost_rx_queue_count(vid, qid) & UINT16_MAX;
        } else {
            *qfill = 0;
        }
    }

    if (policer) {
        qos_drops = nb_rx;
        nb_rx = ingress_policer_run(policer,
                                    (struct rte_mbuf **) batch->packets,
                                    nb_rx, true);
        qos_drops -= nb_rx;
    }

    if (OVS_UNLIKELY(qos_drops)) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.rx_dropped += qos_drops;
        dev->sw_stats->rx_qos_drops += qos_drops;
        rte_spinlock_unlock(&dev->stats_lock);
    }

    batch->count = nb_rx;
    netdev_dpdk_batch_init_packet_fields(batch);

    return 0;
}

static bool
netdev_dpdk_vhost_rxq_enabled(struct netdev_rxq *rxq)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(rxq->netdev);

    return dev->vhost_rxq_enabled[rxq->queue_id];
}

static int
netdev_dpdk_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch,
                     int *qfill)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq);
    struct netdev_dpdk *dev = netdev_dpdk_cast(rxq->netdev);
    struct ingress_policer *policer = netdev_dpdk_get_ingress_policer(dev);
    int nb_rx;
    int dropped = 0;

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        return EAGAIN;
    }

    nb_rx = rte_eth_rx_burst(rx->port_id, rxq->queue_id,
                             (struct rte_mbuf **) batch->packets,
                             NETDEV_MAX_BURST);
    if (!nb_rx) {
        return EAGAIN;
    }

    if (policer) {
        dropped = nb_rx;
        nb_rx = ingress_policer_run(policer,
                                    (struct rte_mbuf **) batch->packets,
                                    nb_rx, true);
        dropped -= nb_rx;
    }

    /* Update stats to reflect dropped packets */
    if (OVS_UNLIKELY(dropped)) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.rx_dropped += dropped;
        dev->sw_stats->rx_qos_drops += dropped;
        rte_spinlock_unlock(&dev->stats_lock);
    }

    batch->count = nb_rx;
    netdev_dpdk_batch_init_packet_fields(batch);

    if (qfill) {
        if (nb_rx == NETDEV_MAX_BURST) {
            *qfill = rte_eth_rx_queue_count(rx->port_id, rxq->queue_id);
        } else {
            *qfill = 0;
        }
    }

    return 0;
}

static inline int
netdev_dpdk_qos_run(struct netdev_dpdk *dev, struct rte_mbuf **pkts,
                    int cnt, bool should_steal)
{
    struct qos_conf *qos_conf = ovsrcu_get(struct qos_conf *, &dev->qos_conf);

    if (qos_conf) {
        rte_spinlock_lock(&qos_conf->lock);
        cnt = qos_conf->ops->qos_run(qos_conf, pkts, cnt, should_steal);
        rte_spinlock_unlock(&qos_conf->lock);
    }

    return cnt;
}

static int
netdev_dpdk_filter_packet_len(struct netdev_dpdk *dev, struct rte_mbuf **pkts,
                              int pkt_cnt)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt;

    /* Filter oversized packets. The TSO packets are filtered out
     * during the offloading preparation for performance reasons. */
    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (OVS_UNLIKELY((pkt->pkt_len > dev->max_packet_len)
            && !pkt->tso_segsz)) {
            VLOG_WARN_RL(&rl, "%s: Too big size %" PRIu32 " "
                         "max_packet_len %d", dev->up.name, pkt->pkt_len,
                         dev->max_packet_len);
            rte_pktmbuf_free(pkt);
            continue;
        }

        if (OVS_UNLIKELY(i != cnt)) {
            pkts[cnt] = pkt;
        }
        cnt++;
    }

    return cnt;
}

static void
netdev_dpdk_extbuf_free(void *addr OVS_UNUSED, void *opaque)
{
    rte_free(opaque);
}

static struct rte_mbuf *
dpdk_pktmbuf_attach_extbuf(struct rte_mbuf *pkt, uint32_t data_len)
{
    uint32_t total_len = RTE_PKTMBUF_HEADROOM + data_len;
    struct rte_mbuf_ext_shared_info *shinfo = NULL;
    uint16_t buf_len;
    void *buf;

    total_len += sizeof *shinfo + sizeof(uintptr_t);
    total_len = RTE_ALIGN_CEIL(total_len, sizeof(uintptr_t));

    if (OVS_UNLIKELY(total_len > UINT16_MAX)) {
        VLOG_ERR("Can't copy packet: too big %u", total_len);
        return NULL;
    }

    buf_len = total_len;
    buf = rte_malloc(NULL, buf_len, RTE_CACHE_LINE_SIZE);
    if (OVS_UNLIKELY(buf == NULL)) {
        VLOG_ERR("Failed to allocate memory using rte_malloc: %u", buf_len);
        return NULL;
    }

    /* Initialize shinfo. */
    shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf, &buf_len,
                                                netdev_dpdk_extbuf_free,
                                                buf);
    if (OVS_UNLIKELY(shinfo == NULL)) {
        rte_free(buf);
        VLOG_ERR("Failed to initialize shared info for mbuf while "
                 "attempting to attach an external buffer.");
        return NULL;
    }

    rte_pktmbuf_attach_extbuf(pkt, buf, rte_malloc_virt2iova(buf), buf_len,
                              shinfo);
    rte_pktmbuf_reset_headroom(pkt);

    return pkt;
}

static struct rte_mbuf *
dpdk_pktmbuf_alloc(struct rte_mempool *mp, uint32_t data_len)
{
    struct rte_mbuf *pkt = rte_pktmbuf_alloc(mp);

    if (OVS_UNLIKELY(!pkt)) {
        return NULL;
    }

    if (rte_pktmbuf_tailroom(pkt) >= data_len) {
        return pkt;
    }

    if (dpdk_pktmbuf_attach_extbuf(pkt, data_len)) {
        return pkt;
    }

    rte_pktmbuf_free(pkt);

    return NULL;
}

static struct dp_packet *
dpdk_copy_dp_packet_to_mbuf(struct rte_mempool *mp, struct dp_packet *pkt_orig)
{
    struct rte_mbuf *mbuf_dest;
    struct dp_packet *pkt_dest;
    uint32_t pkt_len;

    pkt_len = dp_packet_size(pkt_orig);
    mbuf_dest = dpdk_pktmbuf_alloc(mp, pkt_len);
    if (OVS_UNLIKELY(mbuf_dest == NULL)) {
            return NULL;
    }

    pkt_dest = CONTAINER_OF(mbuf_dest, struct dp_packet, mbuf);
    memcpy(dp_packet_data(pkt_dest), dp_packet_data(pkt_orig), pkt_len);
    dp_packet_set_size(pkt_dest, pkt_len);

    mbuf_dest->tx_offload = pkt_orig->mbuf.tx_offload;
    mbuf_dest->packet_type = pkt_orig->mbuf.packet_type;
    mbuf_dest->ol_flags |= (pkt_orig->mbuf.ol_flags &
                            ~(RTE_MBUF_F_EXTERNAL | RTE_MBUF_F_INDIRECT));
    mbuf_dest->tso_segsz = pkt_orig->mbuf.tso_segsz;

    memcpy(&pkt_dest->l2_pad_size, &pkt_orig->l2_pad_size,
           sizeof(struct dp_packet) - offsetof(struct dp_packet, l2_pad_size));

    if (dp_packet_l3(pkt_dest)) {
        if (dp_packet_eth(pkt_dest)) {
            mbuf_dest->l2_len = (char *) dp_packet_l3(pkt_dest)
                                - (char *) dp_packet_eth(pkt_dest);
        } else {
            mbuf_dest->l2_len = 0;
        }
        if (dp_packet_l4(pkt_dest)) {
            mbuf_dest->l3_len = (char *) dp_packet_l4(pkt_dest)
                                - (char *) dp_packet_l3(pkt_dest);
        } else {
            mbuf_dest->l3_len = 0;
        }
    }

    return pkt_dest;
}

/* Replace packets in a 'batch' with their corresponding copies using
 * DPDK memory.
 *
 * Returns the number of good packets in the batch. */
static size_t
dpdk_copy_batch_to_mbuf(struct netdev *netdev, struct dp_packet_batch *batch)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    size_t i, size = dp_packet_batch_size(batch);
    struct dp_packet *packet;

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, size, packet, batch) {
        if (OVS_UNLIKELY(packet->source == DPBUF_DPDK)) {
            dp_packet_batch_refill(batch, packet, i);
        } else {
            struct dp_packet *pktcopy;

            pktcopy = dpdk_copy_dp_packet_to_mbuf(dev->dpdk_mp->mp, packet);
            if (pktcopy) {
                dp_packet_batch_refill(batch, pktcopy, i);
            }

            dp_packet_delete(packet);
        }
    }

    return dp_packet_batch_size(batch);
}

static size_t
netdev_dpdk_common_send(struct netdev *netdev, struct dp_packet_batch *batch,
                        struct netdev_dpdk_sw_stats *stats)
{
    struct rte_mbuf **pkts = (struct rte_mbuf **) batch->packets;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    size_t cnt, pkt_cnt = dp_packet_batch_size(batch);
    struct dp_packet *packet;
    bool need_copy = false;

    memset(stats, 0, sizeof *stats);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        if (packet->source != DPBUF_DPDK) {
            need_copy = true;
            break;
        }
    }

    /* Copy dp-packets to mbufs. */
    if (OVS_UNLIKELY(need_copy)) {
        cnt = dpdk_copy_batch_to_mbuf(netdev, batch);
        stats->tx_failure_drops += pkt_cnt - cnt;
        pkt_cnt = cnt;
    }

    /* Drop oversized packets. */
    cnt = netdev_dpdk_filter_packet_len(dev, pkts, pkt_cnt);
    stats->tx_mtu_exceeded_drops += pkt_cnt - cnt;
    pkt_cnt = cnt;

    if (netdev->ol_flags) {
        /* Prepare each mbuf for hardware offloading. */
        cnt = netdev_dpdk_prep_hwol_batch(dev, pkts, pkt_cnt);
        stats->tx_invalid_hwol_drops += pkt_cnt - cnt;
        pkt_cnt = cnt;
    }

    /* Apply Quality of Service policy. */
    cnt = netdev_dpdk_qos_run(dev, pkts, pkt_cnt, true);
    stats->tx_qos_drops += pkt_cnt - cnt;

    return cnt;
}

static int
netdev_dpdk_vhost_send(struct netdev *netdev, int qid,
                       struct dp_packet_batch *batch,
                       bool concurrent_txq OVS_UNUSED)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int max_retries = VHOST_ENQ_RETRY_MIN;
    int cnt, batch_cnt, vhost_batch_cnt;
    int vid = netdev_dpdk_get_vid(dev);
    struct netdev_dpdk_sw_stats stats;
    struct rte_mbuf **pkts;
    int dropped;
    int retries;

    batch_cnt = cnt = dp_packet_batch_size(batch);
    qid = dev->tx_q[qid % netdev->n_txq].map;
    if (OVS_UNLIKELY(vid < 0 || !dev->vhost_reconfigured || qid < 0
                     || !(dev->flags & NETDEV_UP))) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += cnt;
        rte_spinlock_unlock(&dev->stats_lock);
        dp_packet_delete_batch(batch, true);
        return 0;
    }

    if (OVS_UNLIKELY(!rte_spinlock_trylock(&dev->tx_q[qid].tx_lock))) {
        COVERAGE_INC(vhost_tx_contention);
        rte_spinlock_lock(&dev->tx_q[qid].tx_lock);
    }

    cnt = netdev_dpdk_common_send(netdev, batch, &stats);
    dropped = batch_cnt - cnt;

    pkts = (struct rte_mbuf **) batch->packets;
    vhost_batch_cnt = cnt;
    retries = 0;
    do {
        int vhost_qid = qid * VIRTIO_QNUM + VIRTIO_RXQ;
        int tx_pkts;

        tx_pkts = rte_vhost_enqueue_burst(vid, vhost_qid, pkts, cnt);
        if (OVS_LIKELY(tx_pkts)) {
            /* Packets have been sent.*/
            cnt -= tx_pkts;
            /* Prepare for possible retry.*/
            pkts = &pkts[tx_pkts];
            if (OVS_UNLIKELY(cnt && !retries)) {
                /*
                 * Read max retries as there are packets not sent
                 * and no retries have already occurred.
                 */
                atomic_read_relaxed(&dev->vhost_tx_retries_max, &max_retries);
            }
        } else {
            /* No packets sent - do not retry.*/
            break;
        }
    } while (cnt && (retries++ < max_retries));

    rte_spinlock_unlock(&dev->tx_q[qid].tx_lock);

    stats.tx_failure_drops += cnt;
    dropped += cnt;
    stats.tx_retries = MIN(retries, max_retries);

    if (OVS_UNLIKELY(dropped || stats.tx_retries)) {
        struct netdev_dpdk_sw_stats *sw_stats = dev->sw_stats;

        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += dropped;
        sw_stats->tx_retries += stats.tx_retries;
        sw_stats->tx_failure_drops += stats.tx_failure_drops;
        sw_stats->tx_mtu_exceeded_drops += stats.tx_mtu_exceeded_drops;
        sw_stats->tx_qos_drops += stats.tx_qos_drops;
        sw_stats->tx_invalid_hwol_drops += stats.tx_invalid_hwol_drops;
        rte_spinlock_unlock(&dev->stats_lock);
    }

    pkts = (struct rte_mbuf **) batch->packets;
    rte_pktmbuf_free_bulk(pkts, vhost_batch_cnt);

    return 0;
}

static int
netdev_dpdk_eth_send(struct netdev *netdev, int qid,
                     struct dp_packet_batch *batch, bool concurrent_txq)
{
    struct rte_mbuf **pkts = (struct rte_mbuf **) batch->packets;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int batch_cnt = dp_packet_batch_size(batch);
    struct netdev_dpdk_sw_stats stats;
    int cnt, dropped;

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += dp_packet_batch_size(batch);
        rte_spinlock_unlock(&dev->stats_lock);
        dp_packet_delete_batch(batch, true);
        return 0;
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        qid = qid % dev->up.n_txq;
        rte_spinlock_lock(&dev->tx_q[qid].tx_lock);
    }

    cnt = netdev_dpdk_common_send(netdev, batch, &stats);

    dropped = netdev_dpdk_eth_tx_burst(dev, qid, pkts, cnt);
    stats.tx_failure_drops += dropped;
    dropped += batch_cnt - cnt;
    if (OVS_UNLIKELY(dropped)) {
        struct netdev_dpdk_sw_stats *sw_stats = dev->sw_stats;

        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += dropped;
        sw_stats->tx_failure_drops += stats.tx_failure_drops;
        sw_stats->tx_mtu_exceeded_drops += stats.tx_mtu_exceeded_drops;
        sw_stats->tx_qos_drops += stats.tx_qos_drops;
        sw_stats->tx_invalid_hwol_drops += stats.tx_invalid_hwol_drops;
        rte_spinlock_unlock(&dev->stats_lock);
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        rte_spinlock_unlock(&dev->tx_q[qid].tx_lock);
    }

    return 0;
}

static int
netdev_dpdk_set_etheraddr__(struct netdev_dpdk *dev, const struct eth_addr mac)
    OVS_REQUIRES(dev->mutex)
{
    int err = 0;

    if (dev->type == DPDK_DEV_ETH) {
        struct rte_ether_addr ea;

        memcpy(ea.addr_bytes, mac.ea, ETH_ADDR_LEN);
        err = -rte_eth_dev_default_mac_addr_set(dev->port_id, &ea);
    }
    if (!err) {
        dev->hwaddr = mac;
    } else {
        VLOG_WARN("%s: Failed to set requested mac("ETH_ADDR_FMT"): %s",
                  netdev_get_name(&dev->up), ETH_ADDR_ARGS(mac),
                  rte_strerror(err));
    }

    return err;
}

static int
netdev_dpdk_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        err = netdev_dpdk_set_etheraddr__(dev, mac);
        if (!err) {
            netdev_change_seq_changed(netdev);
        }
    }
    ovs_mutex_unlock(&dev->mutex);

    return err;
}

static int
netdev_dpdk_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mac = dev->hwaddr;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_get_mtu(const struct netdev *netdev, int *mtup)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mtup = dev->mtu;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_set_mtu(struct netdev *netdev, int mtu)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    /* XXX: Ensure that the overall frame length of the requested MTU does not
     * surpass the NETDEV_DPDK_MAX_PKT_LEN. DPDK device drivers differ in how
     * the L2 frame length is calculated for a given MTU when
     * rte_eth_dev_set_mtu(mtu) is called e.g. i40e driver includes 2 x vlan
     * headers, the em driver includes 1 x vlan header, the ixgbe driver does
     * not include vlan headers. As such we should use
     * MTU_TO_MAX_FRAME_LEN(mtu) which includes an additional 2 x vlan headers
     * (8 bytes) for comparison. This avoids a failure later with
     * rte_eth_dev_set_mtu(). This approach should be used until DPDK provides
     * a method to retrieve the upper bound MTU for a given device.
     */
    if (MTU_TO_MAX_FRAME_LEN(mtu) > NETDEV_DPDK_MAX_PKT_LEN
        || mtu < RTE_ETHER_MIN_MTU) {
        VLOG_WARN("%s: unsupported MTU %d\n", dev->up.name, mtu);
        return EINVAL;
    }

    ovs_mutex_lock(&dev->mutex);
    if (dev->requested_mtu != mtu) {
        dev->requested_mtu = mtu;
        netdev_request_reconfigure(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_vhost_get_stats(const struct netdev *netdev,
                            struct netdev_stats *stats)
{
    struct rte_vhost_stat_name *vhost_stats_names = NULL;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_vhost_stat *vhost_stats = NULL;
    int vhost_stats_count;
    int err;
    int qid;
    int vid;

    ovs_mutex_lock(&dev->mutex);

    if (!is_vhost_running(dev)) {
        err = EPROTO;
        goto out;
    }

    vid = netdev_dpdk_get_vid(dev);

    /* We expect all rxqs have the same number of stats, only query rxq0. */
    qid = 0 * VIRTIO_QNUM + VIRTIO_TXQ;
    err = rte_vhost_vring_stats_get_names(vid, qid, NULL, 0);
    if (err < 0) {
        err = EPROTO;
        goto out;
    }

    vhost_stats_count = err;
    vhost_stats_names = xcalloc(vhost_stats_count, sizeof *vhost_stats_names);
    vhost_stats = xcalloc(vhost_stats_count, sizeof *vhost_stats);

    err = rte_vhost_vring_stats_get_names(vid, qid, vhost_stats_names,
                                          vhost_stats_count);
    if (err != vhost_stats_count) {
        err = EPROTO;
        goto out;
    }

#define VHOST_RXQ_STATS                                               \
    VHOST_RXQ_STAT(rx_packets,              "good_packets")           \
    VHOST_RXQ_STAT(rx_bytes,                "good_bytes")             \
    VHOST_RXQ_STAT(rx_broadcast_packets,    "broadcast_packets")      \
    VHOST_RXQ_STAT(multicast,               "multicast_packets")      \
    VHOST_RXQ_STAT(rx_undersized_errors,    "undersize_packets")      \
    VHOST_RXQ_STAT(rx_1_to_64_packets,      "size_64_packets")        \
    VHOST_RXQ_STAT(rx_65_to_127_packets,    "size_65_127_packets")    \
    VHOST_RXQ_STAT(rx_128_to_255_packets,   "size_128_255_packets")   \
    VHOST_RXQ_STAT(rx_256_to_511_packets,   "size_256_511_packets")   \
    VHOST_RXQ_STAT(rx_512_to_1023_packets,  "size_512_1023_packets")  \
    VHOST_RXQ_STAT(rx_1024_to_1522_packets, "size_1024_1518_packets") \
    VHOST_RXQ_STAT(rx_1523_to_max_packets,  "size_1519_max_packets")

#define VHOST_RXQ_STAT(MEMBER, NAME) dev->stats.MEMBER = 0;
    VHOST_RXQ_STATS;
#undef VHOST_RXQ_STAT

    for (int q = 0; q < dev->up.n_rxq; q++) {
        qid = q * VIRTIO_QNUM + VIRTIO_TXQ;

        err = rte_vhost_vring_stats_get(vid, qid, vhost_stats,
                                        vhost_stats_count);
        if (err != vhost_stats_count) {
            err = EPROTO;
            goto out;
        }

        for (int i = 0; i < vhost_stats_count; i++) {
#define VHOST_RXQ_STAT(MEMBER, NAME)                                 \
            if (string_ends_with(vhost_stats_names[i].name, NAME)) { \
                dev->stats.MEMBER += vhost_stats[i].value;           \
                continue;                                            \
            }
            VHOST_RXQ_STATS;
#undef VHOST_RXQ_STAT
        }
    }

    /* OVS reports 64 bytes and smaller packets into "rx_1_to_64_packets".
     * Since vhost only reports good packets and has no error counter,
     * rx_undersized_errors is highjacked (see above) to retrieve
     * "undersize_packets". */
    dev->stats.rx_1_to_64_packets += dev->stats.rx_undersized_errors;
    memset(&dev->stats.rx_undersized_errors, 0xff,
           sizeof dev->stats.rx_undersized_errors);

#define VHOST_RXQ_STAT(MEMBER, NAME) stats->MEMBER = dev->stats.MEMBER;
    VHOST_RXQ_STATS;
#undef VHOST_RXQ_STAT

    free(vhost_stats_names);
    vhost_stats_names = NULL;
    free(vhost_stats);
    vhost_stats = NULL;

    /* We expect all txqs have the same number of stats, only query txq0. */
    qid = 0 * VIRTIO_QNUM;
    err = rte_vhost_vring_stats_get_names(vid, qid, NULL, 0);
    if (err < 0) {
        err = EPROTO;
        goto out;
    }

    vhost_stats_count = err;
    vhost_stats_names = xcalloc(vhost_stats_count, sizeof *vhost_stats_names);
    vhost_stats = xcalloc(vhost_stats_count, sizeof *vhost_stats);

    err = rte_vhost_vring_stats_get_names(vid, qid, vhost_stats_names,
                                          vhost_stats_count);
    if (err != vhost_stats_count) {
        err = EPROTO;
        goto out;
    }

#define VHOST_TXQ_STATS                                               \
    VHOST_TXQ_STAT(tx_packets,              "good_packets")           \
    VHOST_TXQ_STAT(tx_bytes,                "good_bytes")             \
    VHOST_TXQ_STAT(tx_broadcast_packets,    "broadcast_packets")      \
    VHOST_TXQ_STAT(tx_multicast_packets,    "multicast_packets")      \
    VHOST_TXQ_STAT(rx_undersized_errors,    "undersize_packets")      \
    VHOST_TXQ_STAT(tx_1_to_64_packets,      "size_64_packets")        \
    VHOST_TXQ_STAT(tx_65_to_127_packets,    "size_65_127_packets")    \
    VHOST_TXQ_STAT(tx_128_to_255_packets,   "size_128_255_packets")   \
    VHOST_TXQ_STAT(tx_256_to_511_packets,   "size_256_511_packets")   \
    VHOST_TXQ_STAT(tx_512_to_1023_packets,  "size_512_1023_packets")  \
    VHOST_TXQ_STAT(tx_1024_to_1522_packets, "size_1024_1518_packets") \
    VHOST_TXQ_STAT(tx_1523_to_max_packets,  "size_1519_max_packets")

#define VHOST_TXQ_STAT(MEMBER, NAME) dev->stats.MEMBER = 0;
    VHOST_TXQ_STATS;
#undef VHOST_TXQ_STAT

    for (int q = 0; q < dev->up.n_txq; q++) {
        qid = q * VIRTIO_QNUM;

        err = rte_vhost_vring_stats_get(vid, qid, vhost_stats,
                                        vhost_stats_count);
        if (err != vhost_stats_count) {
            err = EPROTO;
            goto out;
        }

        for (int i = 0; i < vhost_stats_count; i++) {
#define VHOST_TXQ_STAT(MEMBER, NAME)                                 \
            if (string_ends_with(vhost_stats_names[i].name, NAME)) { \
                dev->stats.MEMBER += vhost_stats[i].value;           \
                continue;                                            \
            }
            VHOST_TXQ_STATS;
#undef VHOST_TXQ_STAT
        }
    }

    /* OVS reports 64 bytes and smaller packets into "tx_1_to_64_packets".
     * Same as for rx, rx_undersized_errors is highjacked. */
    dev->stats.tx_1_to_64_packets += dev->stats.rx_undersized_errors;
    memset(&dev->stats.rx_undersized_errors, 0xff,
           sizeof dev->stats.rx_undersized_errors);

#define VHOST_TXQ_STAT(MEMBER, NAME) stats->MEMBER = dev->stats.MEMBER;
    VHOST_TXQ_STATS;
#undef VHOST_TXQ_STAT

    rte_spinlock_lock(&dev->stats_lock);
    stats->rx_dropped = dev->stats.rx_dropped;
    stats->tx_dropped = dev->stats.tx_dropped;
    rte_spinlock_unlock(&dev->stats_lock);

    err = 0;
out:

    ovs_mutex_unlock(&dev->mutex);

    free(vhost_stats);
    free(vhost_stats_names);

    return err;
}

static int
netdev_dpdk_vhost_get_custom_stats(const struct netdev *netdev,
                                   struct netdev_custom_stats *custom_stats)
{
    struct rte_vhost_stat_name *vhost_stats_names = NULL;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_vhost_stat *vhost_stats = NULL;
    int vhost_rxq_stats_count;
    int vhost_txq_stats_count;
    int stat_offset;
    int err;
    int qid;
    int vid;

    netdev_dpdk_get_sw_custom_stats(netdev, custom_stats);
    stat_offset = custom_stats->size;

    ovs_mutex_lock(&dev->mutex);

    if (!is_vhost_running(dev)) {
        goto out;
    }

    vid = netdev_dpdk_get_vid(dev);

    qid = 0 * VIRTIO_QNUM + VIRTIO_TXQ;
    err = rte_vhost_vring_stats_get_names(vid, qid, NULL, 0);
    if (err < 0) {
        goto out;
    }
    vhost_rxq_stats_count = err;

    qid = 0 * VIRTIO_QNUM;
    err = rte_vhost_vring_stats_get_names(vid, qid, NULL, 0);
    if (err < 0) {
        goto out;
    }
    vhost_txq_stats_count = err;

    stat_offset += dev->up.n_rxq * vhost_rxq_stats_count;
    stat_offset += dev->up.n_txq * vhost_txq_stats_count;
    custom_stats->counters = xrealloc(custom_stats->counters,
                                      stat_offset *
                                      sizeof *custom_stats->counters);
    stat_offset = custom_stats->size;

    vhost_stats_names = xcalloc(vhost_rxq_stats_count,
                                sizeof *vhost_stats_names);
    vhost_stats = xcalloc(vhost_rxq_stats_count, sizeof *vhost_stats);

    for (int q = 0; q < dev->up.n_rxq; q++) {
        qid = q * VIRTIO_QNUM + VIRTIO_TXQ;

        err = rte_vhost_vring_stats_get_names(vid, qid, vhost_stats_names,
                                              vhost_rxq_stats_count);
        if (err != vhost_rxq_stats_count) {
            goto out;
        }

        err = rte_vhost_vring_stats_get(vid, qid, vhost_stats,
                                        vhost_rxq_stats_count);
        if (err != vhost_rxq_stats_count) {
            goto out;
        }

        for (int i = 0; i < vhost_rxq_stats_count; i++) {
            ovs_strlcpy(custom_stats->counters[stat_offset + i].name,
                        vhost_stats_names[i].name,
                        NETDEV_CUSTOM_STATS_NAME_SIZE);
            custom_stats->counters[stat_offset + i].value =
                 vhost_stats[i].value;
        }
        stat_offset += vhost_rxq_stats_count;
    }

    free(vhost_stats_names);
    vhost_stats_names = NULL;
    free(vhost_stats);
    vhost_stats = NULL;

    vhost_stats_names = xcalloc(vhost_txq_stats_count,
                                sizeof *vhost_stats_names);
    vhost_stats = xcalloc(vhost_txq_stats_count, sizeof *vhost_stats);

    for (int q = 0; q < dev->up.n_txq; q++) {
        qid = q * VIRTIO_QNUM;

        err = rte_vhost_vring_stats_get_names(vid, qid, vhost_stats_names,
                                              vhost_txq_stats_count);
        if (err != vhost_txq_stats_count) {
            goto out;
        }

        err = rte_vhost_vring_stats_get(vid, qid, vhost_stats,
                                        vhost_txq_stats_count);
        if (err != vhost_txq_stats_count) {
            goto out;
        }

        for (int i = 0; i < vhost_txq_stats_count; i++) {
            ovs_strlcpy(custom_stats->counters[stat_offset + i].name,
                        vhost_stats_names[i].name,
                        NETDEV_CUSTOM_STATS_NAME_SIZE);
            custom_stats->counters[stat_offset + i].value =
                 vhost_stats[i].value;
        }
        stat_offset += vhost_txq_stats_count;
    }

out:
    ovs_mutex_unlock(&dev->mutex);

    custom_stats->size = stat_offset;
    free(vhost_stats_names);
    free(vhost_stats);

    return 0;
}

static void
netdev_dpdk_convert_xstats(struct netdev_stats *stats,
                           const struct rte_eth_xstat *xstats,
                           const struct rte_eth_xstat_name *names,
                           const unsigned int size)
{
/* DPDK XSTATS Counter names definition. */
#define DPDK_XSTATS \
    DPDK_XSTAT(multicast,               "rx_multicast_packets"            ) \
    DPDK_XSTAT(tx_multicast_packets,    "tx_multicast_packets"            ) \
    DPDK_XSTAT(rx_broadcast_packets,    "rx_broadcast_packets"            ) \
    DPDK_XSTAT(tx_broadcast_packets,    "tx_broadcast_packets"            ) \
    DPDK_XSTAT(rx_undersized_errors,    "rx_undersized_errors"            ) \
    DPDK_XSTAT(rx_oversize_errors,      "rx_oversize_errors"              ) \
    DPDK_XSTAT(rx_fragmented_errors,    "rx_fragmented_errors"            ) \
    DPDK_XSTAT(rx_jabber_errors,        "rx_jabber_errors"                ) \
    DPDK_XSTAT(rx_1_to_64_packets,      "rx_size_64_packets"              ) \
    DPDK_XSTAT(rx_65_to_127_packets,    "rx_size_65_to_127_packets"       ) \
    DPDK_XSTAT(rx_128_to_255_packets,   "rx_size_128_to_255_packets"      ) \
    DPDK_XSTAT(rx_256_to_511_packets,   "rx_size_256_to_511_packets"      ) \
    DPDK_XSTAT(rx_512_to_1023_packets,  "rx_size_512_to_1023_packets"     ) \
    DPDK_XSTAT(rx_1024_to_1522_packets, "rx_size_1024_to_1522_packets"    ) \
    DPDK_XSTAT(rx_1523_to_max_packets,  "rx_size_1523_to_max_packets"     ) \
    DPDK_XSTAT(tx_1_to_64_packets,      "tx_size_64_packets"              ) \
    DPDK_XSTAT(tx_65_to_127_packets,    "tx_size_65_to_127_packets"       ) \
    DPDK_XSTAT(tx_128_to_255_packets,   "tx_size_128_to_255_packets"      ) \
    DPDK_XSTAT(tx_256_to_511_packets,   "tx_size_256_to_511_packets"      ) \
    DPDK_XSTAT(tx_512_to_1023_packets,  "tx_size_512_to_1023_packets"     ) \
    DPDK_XSTAT(tx_1024_to_1522_packets, "tx_size_1024_to_1522_packets"    ) \
    DPDK_XSTAT(tx_1523_to_max_packets,  "tx_size_1523_to_max_packets"     )

    for (unsigned int i = 0; i < size; i++) {
#define DPDK_XSTAT(MEMBER, NAME) \
        if (strcmp(NAME, names[i].name) == 0) {   \
            stats->MEMBER = xstats[i].value;      \
            continue;                             \
        }
        DPDK_XSTATS;
#undef DPDK_XSTAT
    }
#undef DPDK_XSTATS
}

static int
netdev_dpdk_get_carrier(const struct netdev *netdev, bool *carrier);

static int
netdev_dpdk_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_eth_stats rte_stats;
    bool gg;

    netdev_dpdk_get_carrier(netdev, &gg);
    ovs_mutex_lock(&dev->mutex);

    struct rte_eth_xstat *rte_xstats = NULL;
    struct rte_eth_xstat_name *rte_xstats_names = NULL;
    int rte_xstats_len, rte_xstats_new_len, rte_xstats_ret;

    if (rte_eth_stats_get(dev->port_id, &rte_stats)) {
        VLOG_ERR("Can't get ETH statistics for port: "DPDK_PORT_ID_FMT,
                 dev->port_id);
        ovs_mutex_unlock(&dev->mutex);
        return EPROTO;
    }

    /* Get length of statistics */
    rte_xstats_len = rte_eth_xstats_get_names(dev->port_id, NULL, 0);
    if (rte_xstats_len < 0) {
        VLOG_WARN("Cannot get XSTATS values for port: "DPDK_PORT_ID_FMT,
                  dev->port_id);
        goto out;
    }
    /* Reserve memory for xstats names and values */
    rte_xstats_names = xcalloc(rte_xstats_len, sizeof *rte_xstats_names);
    rte_xstats = xcalloc(rte_xstats_len, sizeof *rte_xstats);

    /* Retreive xstats names */
    rte_xstats_new_len = rte_eth_xstats_get_names(dev->port_id,
                                                  rte_xstats_names,
                                                  rte_xstats_len);
    if (rte_xstats_new_len != rte_xstats_len) {
        VLOG_WARN("Cannot get XSTATS names for port: "DPDK_PORT_ID_FMT,
                  dev->port_id);
        goto out;
    }
    /* Retreive xstats values */
    memset(rte_xstats, 0xff, sizeof *rte_xstats * rte_xstats_len);
    rte_xstats_ret = rte_eth_xstats_get(dev->port_id, rte_xstats,
                                        rte_xstats_len);
    if (rte_xstats_ret > 0 && rte_xstats_ret <= rte_xstats_len) {
        netdev_dpdk_convert_xstats(stats, rte_xstats, rte_xstats_names,
                                   rte_xstats_len);
    } else {
        VLOG_WARN("Cannot get XSTATS values for port: "DPDK_PORT_ID_FMT,
                  dev->port_id);
    }

out:
    free(rte_xstats);
    free(rte_xstats_names);

    stats->rx_packets = rte_stats.ipackets;
    stats->tx_packets = rte_stats.opackets;
    stats->rx_bytes = rte_stats.ibytes;
    stats->tx_bytes = rte_stats.obytes;
    stats->rx_errors = rte_stats.ierrors;
    stats->tx_errors = rte_stats.oerrors;

    rte_spinlock_lock(&dev->stats_lock);
    stats->tx_dropped = dev->stats.tx_dropped;
    stats->rx_dropped = dev->stats.rx_dropped;
    rte_spinlock_unlock(&dev->stats_lock);

    /* These are the available DPDK counters for packets not received due to
     * local resource constraints in DPDK and NIC respectively. */
    stats->rx_dropped += rte_stats.rx_nombuf + rte_stats.imissed;
    stats->rx_missed_errors = rte_stats.imissed;

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_get_custom_stats(const struct netdev *netdev,
                             struct netdev_custom_stats *custom_stats)
{

    uint32_t i;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int rte_xstats_ret, sw_stats_size;

    netdev_dpdk_get_sw_custom_stats(netdev, custom_stats);

    ovs_mutex_lock(&dev->mutex);

    if (dev->rte_xstats_ids_size > 0) {
        uint64_t *values = xcalloc(dev->rte_xstats_ids_size,
                                   sizeof(uint64_t));

        rte_xstats_ret =
                rte_eth_xstats_get_by_id(dev->port_id, dev->rte_xstats_ids,
                                         values, dev->rte_xstats_ids_size);

        if (rte_xstats_ret > 0 &&
            rte_xstats_ret <= dev->rte_xstats_ids_size) {

            sw_stats_size = custom_stats->size;
            custom_stats->size += rte_xstats_ret;
            custom_stats->counters = xrealloc(custom_stats->counters,
                                              custom_stats->size *
                                              sizeof *custom_stats->counters);

            for (i = 0; i < rte_xstats_ret; i++) {
                ovs_strlcpy(custom_stats->counters[sw_stats_size + i].name,
                            netdev_dpdk_get_xstat_name(dev,
                                                       dev->rte_xstats_ids[i]),
                            NETDEV_CUSTOM_STATS_NAME_SIZE);
                custom_stats->counters[sw_stats_size + i].value = values[i];
            }
        } else {
            VLOG_WARN("Cannot get XSTATS values for port: "DPDK_PORT_ID_FMT,
                      dev->port_id);
        }

        free(values);
    }

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_get_sw_custom_stats(const struct netdev *netdev,
                                struct netdev_custom_stats *custom_stats)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int i, n;

#define SW_CSTATS                    \
    SW_CSTAT(tx_retries)             \
    SW_CSTAT(tx_failure_drops)       \
    SW_CSTAT(tx_mtu_exceeded_drops)  \
    SW_CSTAT(tx_qos_drops)           \
    SW_CSTAT(rx_qos_drops)           \
    SW_CSTAT(tx_invalid_hwol_drops)

#define SW_CSTAT(NAME) + 1
    custom_stats->size = SW_CSTATS;
#undef SW_CSTAT
    custom_stats->counters = xcalloc(custom_stats->size,
                                     sizeof *custom_stats->counters);

    ovs_mutex_lock(&dev->mutex);

    rte_spinlock_lock(&dev->stats_lock);
    i = 0;
#define SW_CSTAT(NAME) \
    custom_stats->counters[i++].value = dev->sw_stats->NAME;
    SW_CSTATS;
#undef SW_CSTAT
    rte_spinlock_unlock(&dev->stats_lock);

    ovs_mutex_unlock(&dev->mutex);

    i = 0;
    n = 0;
#define SW_CSTAT(NAME) \
    if (custom_stats->counters[i].value != UINT64_MAX) {                   \
        ovs_strlcpy(custom_stats->counters[n].name,                        \
                    "ovs_"#NAME, NETDEV_CUSTOM_STATS_NAME_SIZE);           \
        custom_stats->counters[n].value = custom_stats->counters[i].value; \
        n++;                                                               \
    }                                                                      \
    i++;
    SW_CSTATS;
#undef SW_CSTAT

    custom_stats->size = n;
    return 0;
}

static int
netdev_dpdk_get_features(const struct netdev *netdev,
                         enum netdev_features *current,
                         enum netdev_features *advertised,
                         enum netdev_features *supported,
                         enum netdev_features *peer)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_eth_link link;
    uint32_t feature = 0;

    ovs_mutex_lock(&dev->mutex);
    link = dev->link;
    ovs_mutex_unlock(&dev->mutex);

    /* Match against OpenFlow defined link speed values. */
    if (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) {
        switch (link.link_speed) {
        case RTE_ETH_SPEED_NUM_10M:
            feature |= NETDEV_F_10MB_FD;
            break;
        case RTE_ETH_SPEED_NUM_100M:
            feature |= NETDEV_F_100MB_FD;
            break;
        case RTE_ETH_SPEED_NUM_1G:
            feature |= NETDEV_F_1GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_10G:
            feature |= NETDEV_F_10GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_40G:
            feature |= NETDEV_F_40GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_100G:
            feature |= NETDEV_F_100GB_FD;
            break;
        default:
            feature |= NETDEV_F_OTHER;
        }
    } else if (link.link_duplex == RTE_ETH_LINK_HALF_DUPLEX) {
        switch (link.link_speed) {
        case RTE_ETH_SPEED_NUM_10M:
            feature |= NETDEV_F_10MB_HD;
            break;
        case RTE_ETH_SPEED_NUM_100M:
            feature |= NETDEV_F_100MB_HD;
            break;
        case RTE_ETH_SPEED_NUM_1G:
            feature |= NETDEV_F_1GB_HD;
            break;
        default:
            feature |= NETDEV_F_OTHER;
        }
    }

    if (link.link_autoneg) {
        feature |= NETDEV_F_AUTONEG;
    }

    *current = feature;
    *advertised = *supported = *peer = 0;

    return 0;
}

static int
netdev_dpdk_get_speed(const struct netdev *netdev, uint32_t *current,
                      uint32_t *max)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_eth_dev_info dev_info;
    struct rte_eth_link link;
    int diag;

    ovs_mutex_lock(&dev->mutex);
    link = dev->link;
    diag = rte_eth_dev_info_get(dev->port_id, &dev_info);
    ovs_mutex_unlock(&dev->mutex);

    *current = link.link_speed != RTE_ETH_SPEED_NUM_UNKNOWN
               ? link.link_speed : 0;

    if (diag < 0) {
        *max = 0;
        goto out;
    }

    if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_200G) {
        *max = RTE_ETH_SPEED_NUM_200G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_100G) {
        *max = RTE_ETH_SPEED_NUM_100G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_56G) {
        *max = RTE_ETH_SPEED_NUM_56G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_50G) {
        *max = RTE_ETH_SPEED_NUM_50G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_40G) {
        *max = RTE_ETH_SPEED_NUM_40G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_25G) {
        *max = RTE_ETH_SPEED_NUM_25G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_20G) {
        *max = RTE_ETH_SPEED_NUM_20G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_10G) {
        *max = RTE_ETH_SPEED_NUM_10G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_5G) {
        *max = RTE_ETH_SPEED_NUM_5G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_2_5G) {
        *max = RTE_ETH_SPEED_NUM_2_5G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_1G) {
        *max = RTE_ETH_SPEED_NUM_1G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_100M ||
        dev_info.speed_capa & RTE_ETH_LINK_SPEED_100M_HD) {
        *max = RTE_ETH_SPEED_NUM_100M;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_10M ||
        dev_info.speed_capa & RTE_ETH_LINK_SPEED_10M_HD) {
        *max = RTE_ETH_SPEED_NUM_10M;
    } else {
        *max = 0;
    }

out:
    return 0;
}

static int
netdev_dpdk_get_duplex(const struct netdev *netdev, bool *full_duplex)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&dev->mutex);
    if (dev->link.link_speed != RTE_ETH_SPEED_NUM_UNKNOWN) {
        *full_duplex = dev->link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX;
    } else {
        err = EOPNOTSUPP;
    }
    ovs_mutex_unlock(&dev->mutex);

    return err;
}

static struct ingress_policer *
netdev_dpdk_policer_construct(uint32_t rate, uint32_t burst)
{
    struct ingress_policer *policer = NULL;
    uint64_t rate_bytes;
    uint64_t burst_bytes;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    rte_spinlock_init(&policer->policer_lock);

    /* rte_meter requires bytes so convert kbits rate and burst to bytes. */
    rate_bytes = rate * 1000ULL / 8;
    burst_bytes = burst * 1000ULL / 8;

    policer->app_srtcm_params.cir = rate_bytes;
    policer->app_srtcm_params.cbs = burst_bytes;
    policer->app_srtcm_params.ebs = 0;
    err = rte_meter_srtcm_profile_config(&policer->in_prof,
                                         &policer->app_srtcm_params);
    if (!err) {
        err = rte_meter_srtcm_config(&policer->in_policer,
                                     &policer->in_prof);
    }
    if (err) {
        VLOG_ERR("Could not create rte meter for ingress policer");
        free(policer);
        return NULL;
    }

    return policer;
}

static int
netdev_dpdk_set_policing(struct netdev* netdev, uint32_t policer_rate,
                         uint32_t policer_burst,
                         uint32_t policer_kpkts_rate OVS_UNUSED,
                         uint32_t policer_kpkts_burst OVS_UNUSED)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct ingress_policer *policer;

    /* Force to 0 if no rate specified,
     * default to 8000 kbits if burst is 0,
     * else stick with user-specified value.
     */
    policer_burst = (!policer_rate ? 0
                     : !policer_burst ? 8000
                     : policer_burst);

    ovs_mutex_lock(&dev->mutex);

    policer = ovsrcu_get_protected(struct ingress_policer *,
                                    &dev->ingress_policer);

    if (dev->policer_rate == policer_rate &&
        dev->policer_burst == policer_burst) {
        /* Assume that settings haven't changed since we last set them. */
        ovs_mutex_unlock(&dev->mutex);
        return 0;
    }

    /* Destroy any existing ingress policer for the device if one exists */
    if (policer) {
        ovsrcu_postpone(free, policer);
    }

    if (policer_rate != 0) {
        policer = netdev_dpdk_policer_construct(policer_rate, policer_burst);
    } else {
        policer = NULL;
    }
    ovsrcu_set(&dev->ingress_policer, policer);
    dev->policer_rate = policer_rate;
    dev->policer_burst = policer_burst;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_get_ifindex(const struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    /* Calculate hash from the netdev name. Ensure that ifindex is a 24-bit
     * postive integer to meet RFC 2863 recommendations.
     */
    int ifindex = hash_string(netdev->name, 0) % 0xfffffe + 1;
    ovs_mutex_unlock(&dev->mutex);

    return ifindex;
}

static int
netdev_dpdk_get_carrier(const struct netdev *netdev, bool *carrier)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    check_link_status(dev);
    *carrier = dev->link.link_status;

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_vhost_get_carrier(const struct netdev *netdev, bool *carrier)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    if (is_vhost_running(dev)) {
        *carrier = 1;
    } else {
        *carrier = 0;
    }

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static long long int
netdev_dpdk_get_carrier_resets(const struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    long long int carrier_resets;

    ovs_mutex_lock(&dev->mutex);
    carrier_resets = dev->link_reset_cnt;
    ovs_mutex_unlock(&dev->mutex);

    return carrier_resets;
}

static int
netdev_dpdk_set_miimon(struct netdev *netdev OVS_UNUSED,
                       long long int interval OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdk_update_flags__(struct netdev_dpdk *dev,
                           enum netdev_flags off, enum netdev_flags on,
                           enum netdev_flags *old_flagsp)
    OVS_REQUIRES(dev->mutex)
{
    if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }

    *old_flagsp = dev->flags;
    dev->flags |= on;
    dev->flags &= ~off;

    if (dev->flags == *old_flagsp) {
        return 0;
    }

    if (dev->type == DPDK_DEV_ETH) {

        if ((dev->flags ^ *old_flagsp) & NETDEV_UP) {
            int err;

            if (dev->flags & NETDEV_UP) {
                err = rte_eth_dev_set_link_up(dev->port_id);
            } else {
                err = rte_eth_dev_set_link_down(dev->port_id);
            }
            if (err == -ENOTSUP) {
                VLOG_INFO("Interface %s does not support link state "
                          "configuration", netdev_get_name(&dev->up));
            } else if (err < 0) {
                VLOG_ERR("Interface %s link change error: %s",
                         netdev_get_name(&dev->up), rte_strerror(-err));
                dev->flags = *old_flagsp;
                return -err;
            }
        }

        if (dev->flags & NETDEV_PROMISC) {
            rte_eth_promiscuous_enable(dev->port_id);
        }

        netdev_change_seq_changed(&dev->up);
    } else {
        /* If DPDK_DEV_VHOST device's NETDEV_UP flag was changed and vhost is
         * running then change netdev's change_seq to trigger link state
         * update. */

        if ((NETDEV_UP & ((*old_flagsp ^ on) | (*old_flagsp ^ off)))
            && is_vhost_running(dev)) {
            netdev_change_seq_changed(&dev->up);

            /* Clear statistics if device is getting up. */
            if (NETDEV_UP & on) {
                rte_spinlock_lock(&dev->stats_lock);
                memset(&dev->stats, 0, sizeof dev->stats);
                memset(dev->sw_stats, 0, sizeof *dev->sw_stats);
                rte_spinlock_unlock(&dev->stats_lock);
            }
        }
    }

    return 0;
}

static int
netdev_dpdk_update_flags(struct netdev *netdev,
                         enum netdev_flags off, enum netdev_flags on,
                         enum netdev_flags *old_flagsp)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int error;

    ovs_mutex_lock(&dev->mutex);
    error = netdev_dpdk_update_flags__(dev, off, on, old_flagsp);
    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_vhost_user_get_status(const struct netdev *netdev,
                                  struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    bool client_mode = dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT;
    smap_add_format(args, "mode", "%s", client_mode ? "client" : "server");

    int vid = netdev_dpdk_get_vid(dev);
    if (vid < 0) {
        smap_add_format(args, "status", "disconnected");
        ovs_mutex_unlock(&dev->mutex);
        return 0;
    } else {
        smap_add_format(args, "status", "connected");
    }

    char socket_name[PATH_MAX];
    if (!rte_vhost_get_ifname(vid, socket_name, PATH_MAX)) {
        smap_add_format(args, "socket", "%s", socket_name);
    }

    uint64_t features;
    if (!rte_vhost_get_negotiated_features(vid, &features)) {
        smap_add_format(args, "features", "0x%016"PRIx64, features);
    }

    uint16_t mtu;
    if (!rte_vhost_get_mtu(vid, &mtu)) {
        smap_add_format(args, "mtu", "%d", mtu);
    }

    int numa = rte_vhost_get_numa_node(vid);
    if (numa >= 0) {
        smap_add_format(args, "numa", "%d", numa);
    }

    uint16_t vring_num = rte_vhost_get_vring_num(vid);
    if (vring_num) {
        smap_add_format(args, "num_of_vrings", "%d", vring_num);
    }

    for (int i = 0; i < vring_num; i++) {
        struct rte_vhost_vring vring;

        rte_vhost_get_vhost_vring(vid, i, &vring);
        smap_add_nocopy(args, xasprintf("vring_%d_size", i),
                        xasprintf("%d", vring.size));
    }

    if (userspace_tso_enabled()
        && dev->virtio_features_state & OVS_VIRTIO_F_WORKAROUND) {

        smap_add_format(args, "userspace-tso", "disabled");
    }

    smap_add_format(args, "n_rxq", "%d", netdev->n_rxq);
    smap_add_format(args, "n_txq", "%d", netdev->n_txq);

    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

/*
 * Convert a given uint32_t link speed defined in DPDK to a string
 * equivalent.
 */
static const char *
netdev_dpdk_link_speed_to_str__(uint32_t link_speed)
{
    switch (link_speed) {
    case RTE_ETH_SPEED_NUM_10M:    return "10Mbps";
    case RTE_ETH_SPEED_NUM_100M:   return "100Mbps";
    case RTE_ETH_SPEED_NUM_1G:     return "1Gbps";
    case RTE_ETH_SPEED_NUM_2_5G:   return "2.5Gbps";
    case RTE_ETH_SPEED_NUM_5G:     return "5Gbps";
    case RTE_ETH_SPEED_NUM_10G:    return "10Gbps";
    case RTE_ETH_SPEED_NUM_20G:    return "20Gbps";
    case RTE_ETH_SPEED_NUM_25G:    return "25Gbps";
    case RTE_ETH_SPEED_NUM_40G:    return "40Gbps";
    case RTE_ETH_SPEED_NUM_50G:    return "50Gbps";
    case RTE_ETH_SPEED_NUM_56G:    return "56Gbps";
    case RTE_ETH_SPEED_NUM_100G:   return "100Gbps";
    default:                       return "Not Defined";
    }
}

static int
netdev_dpdk_get_status(const struct netdev *netdev, struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_eth_dev_info dev_info;
    size_t rx_steer_flows_num;
    uint64_t rx_steer_flags;
    uint32_t link_speed;
    int n_rxq;
    int diag;

    if (!rte_eth_dev_is_valid_port(dev->port_id)) {
        return ENODEV;
    }

    ovs_mutex_lock(&dpdk_mutex);
    ovs_mutex_lock(&dev->mutex);
    diag = rte_eth_dev_info_get(dev->port_id, &dev_info);
    link_speed = dev->link.link_speed;
    rx_steer_flags = dev->rx_steer_flags;
    rx_steer_flows_num = dev->rx_steer_flows_num;
    n_rxq = netdev->n_rxq;
    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&dpdk_mutex);

    smap_add_format(args, "port_no", DPDK_PORT_ID_FMT, dev->port_id);
    smap_add_format(args, "numa_id", "%d",
                           rte_eth_dev_socket_id(dev->port_id));
    if (!diag) {
        smap_add_format(args, "driver_name", "%s", dev_info.driver_name);
        smap_add_format(args, "min_rx_bufsize", "%u", dev_info.min_rx_bufsize);
    }
    smap_add_format(args, "max_rx_pktlen", "%u", dev->max_packet_len);
    if (!diag) {
        smap_add_format(args, "max_rx_queues", "%u", dev_info.max_rx_queues);
        smap_add_format(args, "max_tx_queues", "%u", dev_info.max_tx_queues);
        smap_add_format(args, "max_mac_addrs", "%u", dev_info.max_mac_addrs);
        smap_add_format(args, "max_hash_mac_addrs", "%u",
                        dev_info.max_hash_mac_addrs);
        smap_add_format(args, "max_vfs", "%u", dev_info.max_vfs);
        smap_add_format(args, "max_vmdq_pools", "%u", dev_info.max_vmdq_pools);
    }

    smap_add_format(args, "n_rxq", "%d", netdev->n_rxq);
    smap_add_format(args, "n_txq", "%d", netdev->n_txq);

    smap_add(args, "rx_csum_offload",
             dev->hw_ol_features & NETDEV_RX_CHECKSUM_OFFLOAD
             ? "true" : "false");

    /* Querying the DPDK library for iftype may be done in future, pending
     * support; cf. RFC 3635 Section 3.2.4. */
    enum { IF_TYPE_ETHERNETCSMACD = 6 };

    smap_add_format(args, "if_type", "%"PRIu32, IF_TYPE_ETHERNETCSMACD);
    smap_add_format(args, "if_descr", "%s %s", rte_version(),
                    diag < 0 ? "<unknown>" : dev_info.driver_name);
    if (!diag) {
        const char *bus_info = rte_dev_bus_info(dev_info.device);
        smap_add_format(args, "bus_info", "bus_name=%s%s%s",
                        rte_bus_name(rte_dev_bus(dev_info.device)),
                        bus_info != NULL ? ", " : "",
                        bus_info != NULL ? bus_info : "");
    }

    /* Not all link speeds are defined in the OpenFlow specs e.g. 25 Gbps.
     * In that case the speed will not be reported as part of the usual
     * call to get_features(). Get the link speed of the device and add it
     * to the device status in an easy to read string format.
     */
    smap_add(args, "link_speed",
             netdev_dpdk_link_speed_to_str__(link_speed));

    if (dev->is_representor) {
        smap_add_format(args, "dpdk-vf-mac", ETH_ADDR_FMT,
                        ETH_ADDR_ARGS(dev->hwaddr));
    }

    if (rx_steer_flags && !rx_steer_flows_num) {
        smap_add(args, "rx-steering", "unsupported");
    } else if (rx_steer_flags == DPDK_RX_STEER_LACP) {
        smap_add(args, "rx-steering", "rss+lacp");
    } else {
        ovs_assert(!rx_steer_flags);
        smap_add(args, "rx-steering", "rss");
    }

    if (rx_steer_flags && rx_steer_flows_num) {
        smap_add_format(args, "rx_steering_queue", "%d", n_rxq - 1);
        if (n_rxq > 2) {
            smap_add_format(args, "rss_queues", "0-%d", n_rxq - 2);
        } else {
            smap_add(args, "rss_queues", "0");
        }
    }

    return 0;
}

static void
netdev_dpdk_set_admin_state__(struct netdev_dpdk *dev, bool admin_state)
    OVS_REQUIRES(dev->mutex)
{
    enum netdev_flags old_flags;

    if (admin_state) {
        netdev_dpdk_update_flags__(dev, 0, NETDEV_UP, &old_flags);
    } else {
        netdev_dpdk_update_flags__(dev, NETDEV_UP, 0, &old_flags);
    }
}

static void
netdev_dpdk_set_admin_state(struct unixctl_conn *conn, int argc,
                            const char *argv[], void *aux OVS_UNUSED)
{
    bool up;

    if (!strcasecmp(argv[argc - 1], "up")) {
        up = true;
    } else if ( !strcasecmp(argv[argc - 1], "down")) {
        up = false;
    } else {
        unixctl_command_reply_error(conn, "Invalid Admin State");
        return;
    }

    if (argc > 2) {
        struct netdev *netdev = netdev_from_name(argv[1]);

        if (netdev && is_dpdk_class(netdev->netdev_class)) {
            struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

            ovs_mutex_lock(&dev->mutex);
            netdev_dpdk_set_admin_state__(dev, up);
            ovs_mutex_unlock(&dev->mutex);

            netdev_close(netdev);
        } else {
            unixctl_command_reply_error(conn, "Not a DPDK Interface");
            netdev_close(netdev);
            return;
        }
    } else {
        struct netdev_dpdk *dev;

        ovs_mutex_lock(&dpdk_mutex);
        LIST_FOR_EACH (dev, list_node, &dpdk_list) {
            ovs_mutex_lock(&dev->mutex);
            netdev_dpdk_set_admin_state__(dev, up);
            ovs_mutex_unlock(&dev->mutex);
        }
        ovs_mutex_unlock(&dpdk_mutex);
    }
    unixctl_command_reply(conn, "OK");
}

static void
netdev_dpdk_detach(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds used_interfaces = DS_EMPTY_INITIALIZER;
    struct rte_eth_dev_info dev_info;
    dpdk_port_t sibling_port_id;
    dpdk_port_t port_id;
    bool used = false;
    char *response;
    int diag;

    ovs_mutex_lock(&dpdk_mutex);

    port_id = netdev_dpdk_get_port_by_devargs(argv[1]);
    if (!rte_eth_dev_is_valid_port(port_id)) {
        response = xasprintf("Device '%s' not found in DPDK", argv[1]);
        goto error;
    }

    ds_put_format(&used_interfaces,
                  "Device '%s' is being used by the following interfaces:",
                  argv[1]);

    RTE_ETH_FOREACH_DEV_SIBLING (sibling_port_id, port_id) {
        struct netdev_dpdk *dev;

        LIST_FOR_EACH (dev, list_node, &dpdk_list) {
            if (dev->port_id != sibling_port_id) {
                continue;
            }
            used = true;
            ds_put_format(&used_interfaces, " %s",
                          netdev_get_name(&dev->up));
            break;
        }
    }

    if (used) {
        ds_put_cstr(&used_interfaces, ". Remove them before detaching.");
        response = ds_steal_cstr(&used_interfaces);
        ds_destroy(&used_interfaces);
        goto error;
    }
    ds_destroy(&used_interfaces);

    diag = rte_eth_dev_info_get(port_id, &dev_info);
    rte_eth_dev_close(port_id);
    if (diag < 0 || rte_dev_remove(dev_info.device) < 0) {
        response = xasprintf("Device '%s' can not be detached", argv[1]);
        goto error;
    }

    response = xasprintf("All devices shared with device '%s' "
                         "have been detached", argv[1]);

    ovs_mutex_unlock(&dpdk_mutex);
    unixctl_command_reply(conn, response);
    free(response);
    return;

error:
    ovs_mutex_unlock(&dpdk_mutex);
    unixctl_command_reply_error(conn, response);
    free(response);
}

static void
netdev_dpdk_get_mempool_info(struct unixctl_conn *conn,
                             int argc, const char *argv[],
                             void *aux OVS_UNUSED)
{
    struct netdev *netdev = NULL;
    const char *error = NULL;
    char *response = NULL;
    FILE *stream;
    size_t size;

    if (argc == 2) {
        netdev = netdev_from_name(argv[1]);
        if (!netdev || !is_dpdk_class(netdev->netdev_class)) {
            unixctl_command_reply_error(conn, "Not a DPDK Interface");
            goto out;
        }
    }

    stream = open_memstream(&response, &size);
    if (!stream) {
        response = xasprintf("Unable to open memstream: %s.",
                             ovs_strerror(errno));
        unixctl_command_reply_error(conn, response);
        goto out;
    }

    if (netdev) {
        struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

        ovs_mutex_lock(&dev->mutex);
        ovs_mutex_lock(&dpdk_mp_mutex);

        if (dev->dpdk_mp) {
            rte_mempool_dump(stream, dev->dpdk_mp->mp);
            fprintf(stream, "    count: avail (%u), in use (%u)\n",
                    rte_mempool_avail_count(dev->dpdk_mp->mp),
                    rte_mempool_in_use_count(dev->dpdk_mp->mp));
        } else {
            error = "Not allocated";
        }

        ovs_mutex_unlock(&dpdk_mp_mutex);
        ovs_mutex_unlock(&dev->mutex);
    } else {
        ovs_mutex_lock(&dpdk_mp_mutex);
        rte_mempool_list_dump(stream);
        ovs_mutex_unlock(&dpdk_mp_mutex);
    }

    fclose(stream);

    if (error) {
        unixctl_command_reply_error(conn, error);
    } else {
        unixctl_command_reply(conn, response);
    }
out:
    free(response);
    netdev_close(netdev);
}

/*
 * Set virtqueue flags so that we do not receive interrupts.
 */
static void
set_irq_status(int vid)
{
    uint32_t i;

    for (i = 0; i < rte_vhost_get_vring_num(vid); i++) {
        rte_vhost_enable_guest_notification(vid, i, 0);
    }
}

/*
 * Fixes mapping for vhost-user tx queues. Must be called after each
 * enabling/disabling of queues and n_txq modifications.
 */
static void
netdev_dpdk_remap_txqs(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    int *enabled_queues, n_enabled = 0;
    int i, k, total_txqs = dev->up.n_txq;

    enabled_queues = xcalloc(total_txqs, sizeof *enabled_queues);

    for (i = 0; i < total_txqs; i++) {
        /* Enabled queues always mapped to themselves. */
        if (dev->tx_q[i].map == i) {
            enabled_queues[n_enabled++] = i;
        }
    }

    if (n_enabled == 0 && total_txqs != 0) {
        enabled_queues[0] = OVS_VHOST_QUEUE_DISABLED;
        n_enabled = 1;
    }

    k = 0;
    for (i = 0; i < total_txqs; i++) {
        if (dev->tx_q[i].map != i) {
            dev->tx_q[i].map = enabled_queues[k];
            k = (k + 1) % n_enabled;
        }
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds mapping = DS_EMPTY_INITIALIZER;

        ds_put_format(&mapping, "TX queue mapping for port '%s':\n",
                      netdev_get_name(&dev->up));
        for (i = 0; i < total_txqs; i++) {
            ds_put_format(&mapping, "%2d --> %2d\n", i, dev->tx_q[i].map);
        }

        VLOG_DBG("%s", ds_cstr(&mapping));
        ds_destroy(&mapping);
    }

    free(enabled_queues);
}

/*
 * A new virtio-net device is added to a vhost port.
 */
static int
new_device(int vid)
{
    struct netdev_dpdk *dev;
    bool exists = false;
    int newnode = 0;
    char ifname[IF_NAME_SZ];

    rte_vhost_get_ifname(vid, ifname, sizeof ifname);

    ovs_mutex_lock(&dpdk_mutex);
    /* Add device to the vhost port with the same name as that passed down. */
    LIST_FOR_EACH(dev, list_node, &dpdk_list) {
        ovs_mutex_lock(&dev->mutex);
        if (nullable_string_is_equal(ifname, dev->vhost_id)) {
            uint32_t qp_num = rte_vhost_get_vring_num(vid) / VIRTIO_QNUM;
            uint64_t features;

            /* Get NUMA information */
            newnode = rte_vhost_get_numa_node(vid);
            if (newnode == -1) {
#ifdef VHOST_NUMA
                VLOG_INFO("Error getting NUMA info for vHost Device '%s'",
                          ifname);
#endif
                newnode = dev->socket_id;
            }

            dev->virtio_features_state |= OVS_VIRTIO_F_NEGOTIATED;

            if (dev->requested_n_txq < qp_num
                || dev->requested_n_rxq < qp_num
                || dev->requested_socket_id != newnode
                || dev->dpdk_mp == NULL) {
                dev->requested_socket_id = newnode;
                dev->requested_n_rxq = qp_num;
                dev->requested_n_txq = qp_num;
                netdev_request_reconfigure(&dev->up);
            } else {
                /* Reconfiguration not required. */
                dev->vhost_reconfigured = true;
            }

            if (rte_vhost_get_negotiated_features(vid, &features)) {
                VLOG_INFO("Error checking guest features for "
                          "vHost Device '%s'", dev->vhost_id);
            } else {
                if (features & (1ULL << VIRTIO_NET_F_GUEST_CSUM)) {
                    dev->hw_ol_features |= NETDEV_TX_TCP_CKSUM_OFFLOAD;
                    dev->hw_ol_features |= NETDEV_TX_UDP_CKSUM_OFFLOAD;
                    dev->hw_ol_features |= NETDEV_TX_SCTP_CKSUM_OFFLOAD;

                    /* There is no support in virtio net to offload IPv4 csum,
                     * but the vhost library handles IPv4 csum offloading. */
                    dev->hw_ol_features |= NETDEV_TX_IPV4_CKSUM_OFFLOAD;
                }

                if (userspace_tso_enabled()
                    && dev->virtio_features_state & OVS_VIRTIO_F_CLEAN) {

                    if (features & (1ULL << VIRTIO_NET_F_GUEST_TSO4)
                        && features & (1ULL << VIRTIO_NET_F_GUEST_TSO6)) {

                        dev->hw_ol_features |= NETDEV_TX_TSO_OFFLOAD;
                        VLOG_DBG("%s: TSO enabled on vhost port",
                                 netdev_get_name(&dev->up));
                    } else {
                        VLOG_WARN("%s: Tx TSO offload is not supported.",
                                  netdev_get_name(&dev->up));
                    }
                }
            }

            netdev_dpdk_update_netdev_flags(dev);

            ovsrcu_index_set(&dev->vid, vid);
            exists = true;

            /* Disable notifications. */
            set_irq_status(vid);
            netdev_change_seq_changed(&dev->up);
            ovs_mutex_unlock(&dev->mutex);
            break;
        }
        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dpdk_mutex);

    if (!exists) {
        VLOG_INFO("vHost Device '%s' can't be added - name not found", ifname);

        return -1;
    }

    VLOG_INFO("vHost Device '%s' has been added on numa node %i",
              ifname, newnode);

    return 0;
}

/* Clears mapping for all available queues of vhost interface. */
static void
netdev_dpdk_txq_map_clear(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    int i;

    for (i = 0; i < dev->up.n_txq; i++) {
        dev->tx_q[i].map = OVS_VHOST_QUEUE_MAP_UNKNOWN;
    }
}

/*
 * Remove a virtio-net device from the specific vhost port.  Use dev->remove
 * flag to stop any more packets from being sent or received to/from a VM and
 * ensure all currently queued packets have been sent/received before removing
 *  the device.
 */
static void
destroy_device(int vid)
{
    struct netdev_dpdk *dev;
    bool exists = false;
    char ifname[IF_NAME_SZ];

    rte_vhost_get_ifname(vid, ifname, sizeof ifname);

    ovs_mutex_lock(&dpdk_mutex);
    LIST_FOR_EACH (dev, list_node, &dpdk_list) {
        if (netdev_dpdk_get_vid(dev) == vid) {

            ovs_mutex_lock(&dev->mutex);
            dev->vhost_reconfigured = false;
            ovsrcu_index_set(&dev->vid, -1);
            memset(dev->vhost_rxq_enabled, 0,
                   dev->up.n_rxq * sizeof *dev->vhost_rxq_enabled);
            netdev_dpdk_txq_map_clear(dev);

            /* Clear offload capabilities before next new_device. */
            dev->hw_ol_features = 0;
            netdev_dpdk_update_netdev_flags(dev);

            netdev_change_seq_changed(&dev->up);
            ovs_mutex_unlock(&dev->mutex);
            exists = true;
            break;
        }
    }

    ovs_mutex_unlock(&dpdk_mutex);

    if (exists) {
        /*
         * Wait for other threads to quiesce after setting the 'virtio_dev'
         * to NULL, before returning.
         */
        ovsrcu_synchronize();
        /*
         * As call to ovsrcu_synchronize() will end the quiescent state,
         * put thread back into quiescent state before returning.
         */
        ovsrcu_quiesce_start();
        VLOG_INFO("vHost Device '%s' has been removed", ifname);
    } else {
        VLOG_INFO("vHost Device '%s' not found", ifname);
    }
}

static struct mpsc_queue vhost_state_change_queue
    = MPSC_QUEUE_INITIALIZER(&vhost_state_change_queue);
static atomic_uint64_t vhost_state_change_queue_size;

struct vhost_state_change {
    struct mpsc_queue_node node;
    char ifname[IF_NAME_SZ];
    uint16_t queue_id;
    int enable;
};

static void
vring_state_changed__(struct vhost_state_change *sc)
{
    struct netdev_dpdk *dev;
    bool exists = false;
    int qid = sc->queue_id / VIRTIO_QNUM;
    bool is_rx = (sc->queue_id % VIRTIO_QNUM) == VIRTIO_TXQ;

    ovs_mutex_lock(&dpdk_mutex);
    LIST_FOR_EACH (dev, list_node, &dpdk_list) {
        ovs_mutex_lock(&dev->mutex);
        if (nullable_string_is_equal(sc->ifname, dev->vhost_id)) {
            if (is_rx) {
                bool old_state = dev->vhost_rxq_enabled[qid];

                dev->vhost_rxq_enabled[qid] = sc->enable != 0;
                if (old_state != dev->vhost_rxq_enabled[qid]) {
                    netdev_change_seq_changed(&dev->up);
                }
            } else {
                if (sc->enable) {
                    dev->tx_q[qid].map = qid;
                } else {
                    dev->tx_q[qid].map = OVS_VHOST_QUEUE_DISABLED;
                }
                netdev_dpdk_remap_txqs(dev);
            }
            exists = true;
            ovs_mutex_unlock(&dev->mutex);
            break;
        }
        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dpdk_mutex);

    if (exists) {
        VLOG_INFO("State of queue %d ( %s_qid %d ) of vhost device '%s' "
                  "changed to \'%s\'", sc->queue_id, is_rx ? "rx" : "tx",
                  qid, sc->ifname, sc->enable == 1 ? "enabled" : "disabled");
    } else {
        VLOG_INFO("vHost Device '%s' not found", sc->ifname);
    }
}

#define NETDEV_DPDK_VHOST_EVENTS_BACKOFF_MIN 1
#define NETDEV_DPDK_VHOST_EVENTS_BACKOFF_MAX 64
static void *
netdev_dpdk_vhost_events_main(void *arg OVS_UNUSED)
{
    mpsc_queue_acquire(&vhost_state_change_queue);

    for (;;) {
        struct mpsc_queue_node *node;
        uint64_t backoff;

        backoff = NETDEV_DPDK_VHOST_EVENTS_BACKOFF_MIN;
        while (mpsc_queue_tail(&vhost_state_change_queue) == NULL) {
            xnanosleep(backoff * 1E6);
            if (backoff < NETDEV_DPDK_VHOST_EVENTS_BACKOFF_MAX) {
                backoff <<= 1;
            }
        }

        MPSC_QUEUE_FOR_EACH_POP (node, &vhost_state_change_queue) {
            struct vhost_state_change *sc;

            sc = CONTAINER_OF(node, struct vhost_state_change, node);
            vring_state_changed__(sc);
            free(sc);
            atomic_count_dec64(&vhost_state_change_queue_size);
        }
    }

    OVS_NOT_REACHED();
    mpsc_queue_release(&vhost_state_change_queue);

    return NULL;
}

static int
vring_state_changed(int vid, uint16_t queue_id, int enable)
{
    static struct vlog_rate_limit vhost_rl = VLOG_RATE_LIMIT_INIT(5, 5);
    struct vhost_state_change *sc;

    sc = xmalloc(sizeof *sc);
    if (!rte_vhost_get_ifname(vid, sc->ifname, sizeof sc->ifname)) {
        uint64_t queue_size;

        sc->queue_id = queue_id;
        sc->enable = enable;
        mpsc_queue_insert(&vhost_state_change_queue, &sc->node);
        queue_size = atomic_count_inc64(&vhost_state_change_queue_size);
        if (queue_size >= 1000) {
            VLOG_WARN_RL(&vhost_rl, "vring state change queue has %"PRIu64" "
                         "entries. Last update was for socket %s.", queue_size,
                         sc->ifname);
        }
    } else {
        free(sc);
    }

    return 0;
}

static void
destroy_connection(int vid)
{
    struct netdev_dpdk *dev;
    char ifname[IF_NAME_SZ];
    bool exists = false;

    rte_vhost_get_ifname(vid, ifname, sizeof ifname);

    ovs_mutex_lock(&dpdk_mutex);
    LIST_FOR_EACH (dev, list_node, &dpdk_list) {
        ovs_mutex_lock(&dev->mutex);
        if (nullable_string_is_equal(ifname, dev->vhost_id)) {
            uint32_t qp_num = NR_QUEUE;

            if (netdev_dpdk_get_vid(dev) >= 0) {
                VLOG_ERR("Connection on socket '%s' destroyed while vhost "
                         "device still attached.", dev->vhost_id);
            }

            /* Restore the number of queue pairs to default. */
            if (dev->requested_n_txq != qp_num
                || dev->requested_n_rxq != qp_num) {
                dev->requested_n_rxq = qp_num;
                dev->requested_n_txq = qp_num;
                netdev_request_reconfigure(&dev->up);
            }

            if (!(dev->virtio_features_state & OVS_VIRTIO_F_NEGOTIATED)) {
                /* The socket disconnected before reaching new_device. It
                 * likely means that the guest did not agree with the virtio
                 * features. */
                VLOG_WARN_RL(&rl, "Connection on socket '%s' closed during "
                             "initialization.", dev->vhost_id);
            }
            if (!(dev->virtio_features_state & OVS_VIRTIO_F_RECONF_PENDING)) {
                switch (dev->virtio_features_state) {
                case OVS_VIRTIO_F_CLEAN:
                    dev->virtio_features_state = OVS_VIRTIO_F_WORKAROUND;
                    break;

                case OVS_VIRTIO_F_WORKAROUND:
                    dev->virtio_features_state = OVS_VIRTIO_F_CLEAN;
                    break;

                case OVS_VIRTIO_F_CLEAN_NEGOTIATED:
                    /* The virtio features were clean and got accepted by the
                     * guest. We expect it will be the case in the future and
                     * change nothing. */
                    break;

                case OVS_VIRTIO_F_WORKAROUND_NEGOTIATED:
                    /* Let's try to go with clean virtio features on a next
                     * connection. */
                    dev->virtio_features_state = OVS_VIRTIO_F_CLEAN;
                    break;

                default:
                    OVS_NOT_REACHED();
                }
                if (!(dev->virtio_features_state & OVS_VIRTIO_F_NEGOTIATED)) {
                    dev->virtio_features_state |= OVS_VIRTIO_F_RECONF_PENDING;
                    netdev_request_reconfigure(&dev->up);
                }
            }

            ovs_mutex_unlock(&dev->mutex);
            exists = true;
            break;
        }
        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dpdk_mutex);

    if (exists) {
        VLOG_INFO("vHost Device '%s' connection has been destroyed", ifname);
    } else {
        VLOG_INFO("vHost Device '%s' not found", ifname);
    }
}

/*
 * Retrieve the DPDK virtio device ID (vid) associated with a vhostuser
 * or vhostuserclient netdev.
 *
 * Returns a value greater or equal to zero for a valid vid or '-1' if
 * there is no valid vid associated. A vid of '-1' must not be used in
 * rte_vhost_ APi calls.
 *
 * Once obtained and validated, a vid can be used by a PMD for multiple
 * subsequent rte_vhost API calls until the PMD quiesces. A PMD should
 * not fetch the vid again for each of a series of API calls.
 */

int
netdev_dpdk_get_vid(const struct netdev_dpdk *dev)
{
    return ovsrcu_index_get(&dev->vid);
}

static int
netdev_dpdk_class_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    /* This function can be called for different classes.  The initialization
     * needs to be done only once */
    if (ovsthread_once_start(&once)) {
        int ret;

        ovs_thread_create("dpdk_watchdog", dpdk_watchdog, NULL);
        unixctl_command_register("netdev-dpdk/set-admin-state",
                                 "[netdev] up|down", 1, 2,
                                 netdev_dpdk_set_admin_state, NULL);

        unixctl_command_register("netdev-dpdk/detach",
                                 "pci address of device", 1, 1,
                                 netdev_dpdk_detach, NULL);

        unixctl_command_register("netdev-dpdk/get-mempool-info",
                                 "[netdev]", 0, 1,
                                 netdev_dpdk_get_mempool_info, NULL);

        netdev_dpdk_reset_seq = seq_create();
        netdev_dpdk_last_reset_seq = seq_read(netdev_dpdk_reset_seq);
        ret = rte_eth_dev_callback_register(RTE_ETH_ALL,
                                            RTE_ETH_EVENT_INTR_RESET,
                                            dpdk_eth_event_callback, NULL);
        if (ret != 0) {
            VLOG_ERR("Ethernet device callback register error: %s",
                     rte_strerror(-ret));
        }

        ovsthread_once_done(&once);
    }

    return 0;
}

static int
netdev_dpdk_vhost_class_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        ovs_thread_create("ovs_vhost", netdev_dpdk_vhost_events_main, NULL);
        ovsthread_once_done(&once);
    }

    return 0;
}

/* QoS Functions */

struct ingress_policer *
netdev_dpdk_get_ingress_policer(const struct netdev_dpdk *dev)
{
    return ovsrcu_get(struct ingress_policer *, &dev->ingress_policer);
}

/*
 * Initialize QoS configuration operations.
 */
static void
qos_conf_init(struct qos_conf *conf, const struct dpdk_qos_ops *ops)
{
    conf->ops = ops;
    rte_spinlock_init(&conf->lock);
}

/*
 * Search existing QoS operations in qos_ops and compare each set of
 * operations qos_name to name. Return a dpdk_qos_ops pointer to a match,
 * else return NULL
 */
static const struct dpdk_qos_ops *
qos_lookup_name(const char *name)
{
    const struct dpdk_qos_ops *const *opsp;

    for (opsp = qos_confs; *opsp != NULL; opsp++) {
        const struct dpdk_qos_ops *ops = *opsp;
        if (!strcmp(name, ops->qos_name)) {
            return ops;
        }
    }
    return NULL;
}

static int
netdev_dpdk_get_qos_types(const struct netdev *netdev OVS_UNUSED,
                           struct sset *types)
{
    const struct dpdk_qos_ops *const *opsp;

    for (opsp = qos_confs; *opsp != NULL; opsp++) {
        const struct dpdk_qos_ops *ops = *opsp;
        if (ops->qos_construct && ops->qos_name[0] != '\0') {
            sset_add(types, ops->qos_name);
        }
    }
    return 0;
}

static int
netdev_dpdk_get_qos(const struct netdev *netdev,
                    const char **typep, struct smap *details)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);
    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (qos_conf) {
        *typep = qos_conf->ops->qos_name;
        error = (qos_conf->ops->qos_get
                 ? qos_conf->ops->qos_get(qos_conf, details): 0);
    } else {
        /* No QoS configuration set, return an empty string */
        *typep = "";
    }
    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_set_qos(struct netdev *netdev, const char *type,
                    const struct smap *details)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    const struct dpdk_qos_ops *new_ops = NULL;
    struct qos_conf *qos_conf, *new_qos_conf = NULL;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);

    new_ops = qos_lookup_name(type);

    if (!new_ops || !new_ops->qos_construct) {
        new_qos_conf = NULL;
        if (type && type[0]) {
            error = EOPNOTSUPP;
        }
    } else if (qos_conf && qos_conf->ops == new_ops
               && qos_conf->ops->qos_is_equal(qos_conf, details)) {
        new_qos_conf = qos_conf;
    } else {
        error = new_ops->qos_construct(details, &new_qos_conf);
    }

    if (error) {
        VLOG_ERR("Failed to set QoS type %s on port %s: %s",
                 type, netdev->name, rte_strerror(error));
    }

    if (new_qos_conf != qos_conf) {
        ovsrcu_set(&dev->qos_conf, new_qos_conf);
        if (qos_conf) {
            ovsrcu_postpone(qos_conf->ops->qos_destruct, qos_conf);
        }
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_get_queue(const struct netdev *netdev, uint32_t queue_id,
                      struct smap *details)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (!qos_conf || !qos_conf->ops || !qos_conf->ops->qos_queue_get) {
        error = EOPNOTSUPP;
    } else {
        error = qos_conf->ops->qos_queue_get(details, queue_id, qos_conf);
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_set_queue(struct netdev *netdev, uint32_t queue_id,
                      const struct smap *details)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (!qos_conf || !qos_conf->ops || !qos_conf->ops->qos_queue_construct) {
        error = EOPNOTSUPP;
    } else {
        error = qos_conf->ops->qos_queue_construct(details, queue_id,
                                                   qos_conf);
    }

    if (error && error != EOPNOTSUPP) {
        VLOG_ERR("Failed to set QoS queue %d on port %s: %s",
                 queue_id, netdev_get_name(netdev), rte_strerror(error));
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_delete_queue(struct netdev *netdev, uint32_t queue_id)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (qos_conf && qos_conf->ops && qos_conf->ops->qos_queue_destruct) {
        qos_conf->ops->qos_queue_destruct(qos_conf, queue_id);
    } else {
        error =  EOPNOTSUPP;
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_get_queue_stats(const struct netdev *netdev, uint32_t queue_id,
                            struct netdev_queue_stats *stats)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (qos_conf && qos_conf->ops && qos_conf->ops->qos_queue_get_stats) {
        qos_conf->ops->qos_queue_get_stats(qos_conf, queue_id, stats);
    } else {
        error = EOPNOTSUPP;
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_queue_dump_start(const struct netdev *netdev, void **statep)
{
    int error = 0;
    struct qos_conf *qos_conf;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (qos_conf && qos_conf->ops
        && qos_conf->ops->qos_queue_dump_state_init) {
        struct netdev_dpdk_queue_state *state;

        *statep = state = xmalloc(sizeof *state);
        error = qos_conf->ops->qos_queue_dump_state_init(qos_conf, state);
    } else {
        error = EOPNOTSUPP;
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_queue_dump_next(const struct netdev *netdev, void *state_,
                            uint32_t *queue_idp, struct smap *details)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct netdev_dpdk_queue_state *state = state_;
    struct qos_conf *qos_conf;
    int error = EOF;

    ovs_mutex_lock(&dev->mutex);

    while (state->cur_queue < state->n_queues) {
        uint32_t queue_id = state->queues[state->cur_queue++];

        qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
        if (qos_conf && qos_conf->ops && qos_conf->ops->qos_queue_get) {
            *queue_idp = queue_id;
            error = qos_conf->ops->qos_queue_get(details, queue_id, qos_conf);
            break;
        }
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static int
netdev_dpdk_queue_dump_done(const struct netdev *netdev OVS_UNUSED,
                            void *state_)
{
    struct netdev_dpdk_queue_state *state = state_;

    free(state->queues);
    free(state);
    return 0;
}



/* egress-policer details */

struct egress_policer {
    struct qos_conf qos_conf;
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm egress_meter;
    struct rte_meter_srtcm_profile egress_prof;
};

static void
egress_policer_details_to_param(const struct smap *details,
                                struct rte_meter_srtcm_params *params)
{
    memset(params, 0, sizeof *params);
    params->cir = smap_get_ullong(details, "cir", 0);
    params->cbs = smap_get_ullong(details, "cbs", 0);
    params->ebs = 0;
}

static int
egress_policer_qos_construct(const struct smap *details,
                             struct qos_conf **conf)
{
    struct egress_policer *policer;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    qos_conf_init(&policer->qos_conf, &egress_policer_ops);
    egress_policer_details_to_param(details, &policer->app_srtcm_params);
    err = rte_meter_srtcm_profile_config(&policer->egress_prof,
                                         &policer->app_srtcm_params);
    if (!err) {
        err = rte_meter_srtcm_config(&policer->egress_meter,
                                     &policer->egress_prof);
    }

    if (!err) {
        *conf = &policer->qos_conf;
    } else {
        VLOG_ERR("Could not create rte meter for egress policer");
        free(policer);
        *conf = NULL;
        err = -err;
    }

    return err;
}

static void
egress_policer_qos_destruct(struct qos_conf *conf)
{
    struct egress_policer *policer = CONTAINER_OF(conf, struct egress_policer,
                                                  qos_conf);
    free(policer);
}

static int
egress_policer_qos_get(const struct qos_conf *conf, struct smap *details)
{
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);

    smap_add_format(details, "cir", "%"PRIu64, policer->app_srtcm_params.cir);
    smap_add_format(details, "cbs", "%"PRIu64, policer->app_srtcm_params.cbs);

    return 0;
}

static bool
egress_policer_qos_is_equal(const struct qos_conf *conf,
                            const struct smap *details)
{
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);
    struct rte_meter_srtcm_params params;

    egress_policer_details_to_param(details, &params);

    return !memcmp(&params, &policer->app_srtcm_params, sizeof params);
}

static int
egress_policer_run(struct qos_conf *conf, struct rte_mbuf **pkts, int pkt_cnt,
                   bool should_steal)
{
    int cnt = 0;
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);

    cnt = srtcm_policer_run_single_packet(&policer->egress_meter,
                                          &policer->egress_prof, pkts,
                                          pkt_cnt, should_steal);

    return cnt;
}

static const struct dpdk_qos_ops egress_policer_ops = {
    .qos_name = "egress-policer",    /* qos_name */
    .qos_construct = egress_policer_qos_construct,
    .qos_destruct = egress_policer_qos_destruct,
    .qos_get = egress_policer_qos_get,
    .qos_is_equal = egress_policer_qos_is_equal,
    .qos_run = egress_policer_run
};

/* trtcm-policer details */

struct trtcm_policer {
    struct qos_conf qos_conf;
    struct rte_meter_trtcm_rfc4115_params meter_params;
    struct rte_meter_trtcm_rfc4115_profile meter_profile;
    struct rte_meter_trtcm_rfc4115 meter;
    struct netdev_queue_stats stats;
    struct hmap queues;
};

struct trtcm_policer_queue {
    struct hmap_node hmap_node;
    uint32_t queue_id;
    struct rte_meter_trtcm_rfc4115_params meter_params;
    struct rte_meter_trtcm_rfc4115_profile meter_profile;
    struct rte_meter_trtcm_rfc4115 meter;
    struct netdev_queue_stats stats;
};

static void
trtcm_policer_details_to_param(const struct smap *details,
                               struct rte_meter_trtcm_rfc4115_params *params)
{
    memset(params, 0, sizeof *params);
    params->cir = smap_get_ullong(details, "cir", 0);
    params->eir = smap_get_ullong(details, "eir", 0);
    params->cbs = smap_get_ullong(details, "cbs", 0);
    params->ebs = smap_get_ullong(details, "ebs", 0);
}

static void
trtcm_policer_param_to_detail(
    const struct rte_meter_trtcm_rfc4115_params *params,
    struct smap *details)
{
    smap_add_format(details, "cir", "%"PRIu64, params->cir);
    smap_add_format(details, "eir", "%"PRIu64, params->eir);
    smap_add_format(details, "cbs", "%"PRIu64, params->cbs);
    smap_add_format(details, "ebs", "%"PRIu64, params->ebs);
}


static int
trtcm_policer_qos_construct(const struct smap *details,
                            struct qos_conf **conf)
{
    struct trtcm_policer *policer;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    qos_conf_init(&policer->qos_conf, &trtcm_policer_ops);
    trtcm_policer_details_to_param(details, &policer->meter_params);
    err = rte_meter_trtcm_rfc4115_profile_config(&policer->meter_profile,
                                                 &policer->meter_params);
    if (!err) {
        err = rte_meter_trtcm_rfc4115_config(&policer->meter,
                                             &policer->meter_profile);
    }

    if (!err) {
        *conf = &policer->qos_conf;
        memset(&policer->stats, 0, sizeof policer->stats);
        hmap_init(&policer->queues);
    } else {
        free(policer);
        *conf = NULL;
        err = -err;
    }

    return err;
}

static void
trtcm_policer_qos_destruct(struct qos_conf *conf)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    HMAP_FOR_EACH_SAFE (queue, hmap_node, &policer->queues) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
    }
    hmap_destroy(&policer->queues);
    free(policer);
}

static int
trtcm_policer_qos_get(const struct qos_conf *conf, struct smap *details)
{
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    trtcm_policer_param_to_detail(&policer->meter_params, details);
    return 0;
}

static bool
trtcm_policer_qos_is_equal(const struct qos_conf *conf,
                           const struct smap *details)
{
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);
    struct rte_meter_trtcm_rfc4115_params params;

    trtcm_policer_details_to_param(details, &params);

    return !memcmp(&params, &policer->meter_params, sizeof params);
}

static struct trtcm_policer_queue *
trtcm_policer_qos_find_queue(struct trtcm_policer *policer, uint32_t queue_id)
{
    struct trtcm_policer_queue *queue;
    HMAP_FOR_EACH_WITH_HASH (queue, hmap_node, hash_2words(queue_id, 0),
                             &policer->queues) {
        if (queue->queue_id == queue_id) {
            return queue;
        }
    }
    return NULL;
}

static inline bool
trtcm_policer_run_single_packet(struct trtcm_policer *policer,
                                struct rte_mbuf *pkt, uint64_t time)
{
    enum rte_color pkt_color;
    struct trtcm_policer_queue *queue;
    uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct rte_ether_hdr);
    struct dp_packet *dpkt = CONTAINER_OF(pkt, struct dp_packet, mbuf);

    queue = trtcm_policer_qos_find_queue(policer, dpkt->md.skb_priority);
    if (!queue) {
        /* If no queue is found, use the default queue, which MUST exist. */
        queue = trtcm_policer_qos_find_queue(policer, 0);
        if (!queue) {
            return false;
        }
    }

    pkt_color = rte_meter_trtcm_rfc4115_color_blind_check(&queue->meter,
                                                          &queue->meter_profile,
                                                          time,
                                                          pkt_len);

    if (pkt_color == RTE_COLOR_RED) {
        queue->stats.tx_errors++;
    } else {
        queue->stats.tx_bytes += pkt_len;
        queue->stats.tx_packets++;
    }

    pkt_color = rte_meter_trtcm_rfc4115_color_aware_check(&policer->meter,
                                                     &policer->meter_profile,
                                                     time, pkt_len,
                                                     pkt_color);

    if (pkt_color == RTE_COLOR_RED) {
        policer->stats.tx_errors++;
        return false;
    }

    policer->stats.tx_bytes += pkt_len;
    policer->stats.tx_packets++;
    return true;
}

static int
trtcm_policer_run(struct qos_conf *conf, struct rte_mbuf **pkts, int pkt_cnt,
                  bool should_steal)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt = NULL;
    uint64_t current_time = rte_rdtsc();

    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];

        if (trtcm_policer_run_single_packet(policer, pkt, current_time)) {
            if (cnt != i) {
                pkts[cnt] = pkt;
            }
            cnt++;
        } else {
            if (should_steal) {
                rte_pktmbuf_free(pkt);
            }
        }
    }
    return cnt;
}

static int
trtcm_policer_qos_queue_construct(const struct smap *details,
                                  uint32_t queue_id, struct qos_conf *conf)
{
    int err = 0;
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        queue = xmalloc(sizeof *queue);
        queue->queue_id = queue_id;
        memset(&queue->stats, 0, sizeof queue->stats);
        queue->stats.created = time_msec();
        hmap_insert(&policer->queues, &queue->hmap_node,
                    hash_2words(queue_id, 0));
    }
    if (queue_id == 0 && smap_is_empty(details)) {
        /* No default queue configured, use port values */
        memcpy(&queue->meter_params, &policer->meter_params,
               sizeof queue->meter_params);
    } else {
        trtcm_policer_details_to_param(details, &queue->meter_params);
    }

    err = rte_meter_trtcm_rfc4115_profile_config(&queue->meter_profile,
                                                 &queue->meter_params);

    if (!err) {
        err = rte_meter_trtcm_rfc4115_config(&queue->meter,
                                             &queue->meter_profile);
    }
    if (err) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
        err = -err;
    }
    return err;
}

static void
trtcm_policer_qos_queue_destruct(struct qos_conf *conf, uint32_t queue_id)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (queue) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
    }
}

static int
trtcm_policer_qos_queue_get(struct smap *details, uint32_t queue_id,
                            const struct qos_conf *conf)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        return EINVAL;
    }

    trtcm_policer_param_to_detail(&queue->meter_params, details);
    return 0;
}

static int
trtcm_policer_qos_queue_get_stats(const struct qos_conf *conf,
                                  uint32_t queue_id,
                                  struct netdev_queue_stats *stats)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        return EINVAL;
    }
    memcpy(stats, &queue->stats, sizeof *stats);
    return 0;
}

static int
trtcm_policer_qos_queue_dump_state_init(const struct qos_conf *conf,
                                        struct netdev_dpdk_queue_state *state)
{
    uint32_t i = 0;
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    state->n_queues = hmap_count(&policer->queues);
    state->cur_queue = 0;
    state->queues = xmalloc(state->n_queues * sizeof *state->queues);

    HMAP_FOR_EACH (queue, hmap_node, &policer->queues) {
        state->queues[i++] = queue->queue_id;
    }
    return 0;
}

static const struct dpdk_qos_ops trtcm_policer_ops = {
    .qos_name = "trtcm-policer",
    .qos_construct = trtcm_policer_qos_construct,
    .qos_destruct = trtcm_policer_qos_destruct,
    .qos_get = trtcm_policer_qos_get,
    .qos_is_equal = trtcm_policer_qos_is_equal,
    .qos_run = trtcm_policer_run,
    .qos_queue_construct = trtcm_policer_qos_queue_construct,
    .qos_queue_destruct = trtcm_policer_qos_queue_destruct,
    .qos_queue_get = trtcm_policer_qos_queue_get,
    .qos_queue_get_stats = trtcm_policer_qos_queue_get_stats,
    .qos_queue_dump_state_init = trtcm_policer_qos_queue_dump_state_init
};

static int
dpdk_rx_steer_add_flow(struct netdev_dpdk *dev,
                      const struct rte_flow_item items[],
                      const char *desc)
{
    const struct rte_flow_attr attr = { .ingress = 1 };
    const struct rte_flow_action actions[] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_QUEUE,
            .conf = &(const struct rte_flow_action_queue) {
                .index = dev->up.n_rxq - 1,
            },
        },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_error error;
    struct rte_flow *flow;
    size_t num;
    int err;

    set_error(&error, RTE_FLOW_ERROR_TYPE_NONE);
    err = rte_flow_validate(dev->port_id, &attr, items, actions, &error);
    if (err) {
        VLOG_WARN("%s: rx-steering: device does not support %s flow: %s",
                  netdev_get_name(&dev->up), desc,
                  error.message ? error.message : "");
        goto out;
    }

    set_error(&error, RTE_FLOW_ERROR_TYPE_NONE);
    flow = rte_flow_create(dev->port_id, &attr, items, actions, &error);
    if (flow == NULL) {
        VLOG_WARN("%s: rx-steering: failed to add %s flow: %s",
                  netdev_get_name(&dev->up), desc,
                  error.message ? error.message : "");
        err = rte_errno;
        goto out;
    }

    num = dev->rx_steer_flows_num + 1;
    dev->rx_steer_flows = xrealloc(dev->rx_steer_flows, num * sizeof flow);
    dev->rx_steer_flows[dev->rx_steer_flows_num] = flow;
    dev->rx_steer_flows_num = num;

    VLOG_INFO("%s: rx-steering: redirected %s traffic to rx queue %d",
              netdev_get_name(&dev->up), desc, dev->up.n_rxq - 1);
out:
    return err;
}

#define RETA_CONF_SIZE (RTE_ETH_RSS_RETA_SIZE_512 / RTE_ETH_RETA_GROUP_SIZE)

static int
dpdk_rx_steer_rss_configure(struct netdev_dpdk *dev, int rss_n_rxq)
{
    struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];
    struct rte_eth_dev_info info;
    int err;

    err = rte_eth_dev_info_get(dev->port_id, &info);
    if (err < 0) {
        VLOG_WARN("%s: failed to query RSS info: %s",
                  netdev_get_name(&dev->up), rte_strerror(-err));
        goto error;
    }

    if (info.reta_size % rss_n_rxq != 0 &&
        info.reta_size < RTE_ETH_RSS_RETA_SIZE_128) {
        /*
         * Some drivers set reta_size equal to the total number of rxqs that
         * are configured when it is a power of two. Since we are actually
         * reconfiguring the redirection table to exclude the last rxq, we may
         * end up with an imbalanced redirection table. For example, such
         * configuration:
         *
         *   options:n_rxq=3 options:rx-steering=rss+lacp
         *
         * Will actually configure 4 rxqs on the NIC, and the default reta to:
         *
         *   [0, 1, 2, 3]
         *
         * And dpdk_rx_steer_rss_configure() will reconfigure reta to:
         *
         *   [0, 1, 2, 0]
         *
         * Causing queue 0 to receive twice as much traffic as queues 1 and 2.
         *
         * Work around that corner case by forcing a bigger redirection table
         * size to 128 entries when reta_size is not a multiple of rss_n_rxq
         * and when reta_size is less than 128. This value seems to be
         * supported by most of the drivers that also support rte_flow.
         */
        info.reta_size = RTE_ETH_RSS_RETA_SIZE_128;
    }

    memset(reta_conf, 0, sizeof reta_conf);
    for (uint16_t i = 0; i < info.reta_size; i++) {
        uint16_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
        uint16_t shift = i % RTE_ETH_RETA_GROUP_SIZE;

        reta_conf[idx].mask |= 1ULL << shift;
        reta_conf[idx].reta[shift] = i % rss_n_rxq;
    }

    err = rte_eth_dev_rss_reta_update(dev->port_id, reta_conf, info.reta_size);
    if (err < 0) {
        VLOG_WARN("%s: failed to configure RSS redirection table: err=%d",
                  netdev_get_name(&dev->up), err);
    }

error:
    return err;
}

static int
dpdk_rx_steer_configure(struct netdev_dpdk *dev)
{
    int err = 0;

    if (dev->up.n_rxq < 2) {
        err = ENOTSUP;
        VLOG_WARN("%s: rx-steering: not enough available rx queues",
                  netdev_get_name(&dev->up));
        goto out;
    }

    if (dev->requested_rx_steer_flags & DPDK_RX_STEER_LACP) {
        const struct rte_flow_item items[] = {
            {
                .type = RTE_FLOW_ITEM_TYPE_ETH,
                .spec = &(const struct rte_flow_item_eth){
                    .type = htons(ETH_TYPE_LACP),
                },
                .mask = &(const struct rte_flow_item_eth){
                    .type = htons(0xffff),
                },
            },
            { .type = RTE_FLOW_ITEM_TYPE_END },
        };
        err = dpdk_rx_steer_add_flow(dev, items, "lacp");
        if (err) {
            goto out;
        }
    }

    if (dev->rx_steer_flows_num) {
        /* Reconfigure RSS reta in all but the rx steering queue. */
        err = dpdk_rx_steer_rss_configure(dev, dev->up.n_rxq - 1);
        if (err) {
            goto out;
        }
        if (dev->up.n_rxq == 2) {
            VLOG_INFO("%s: rx-steering: redirected other traffic to "
                      "rx queue 0", netdev_get_name(&dev->up));
        } else {
            VLOG_INFO("%s: rx-steering: applied rss on rx queues 0-%u",
                      netdev_get_name(&dev->up), dev->up.n_rxq - 2);
        }
    }

out:
    return err;
}

static void
dpdk_rx_steer_unconfigure(struct netdev_dpdk *dev)
{
    struct rte_flow_error error;

    if (!dev->rx_steer_flows_num) {
        return;
    }

    VLOG_DBG("%s: rx-steering: reset flows", netdev_get_name(&dev->up));

    for (int i = 0; i < dev->rx_steer_flows_num; i++) {
        set_error(&error, RTE_FLOW_ERROR_TYPE_NONE);
        if (rte_flow_destroy(dev->port_id, dev->rx_steer_flows[i], &error)) {
            VLOG_WARN("%s: rx-steering: failed to destroy flow: %s",
                      netdev_get_name(&dev->up),
                      error.message ? error.message : "");
        }
    }
    free(dev->rx_steer_flows);
    dev->rx_steer_flows_num = 0;
    dev->rx_steer_flows = NULL;
    /*
     * Most DPDK drivers seem to reset their RSS redirection table in
     * rte_eth_dev_configure() or rte_eth_dev_start(), both of which are
     * called in dpdk_eth_dev_init(). No need to explicitly reset it.
     */
}

static int
netdev_dpdk_reconfigure(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    bool pending_reset;
    bool try_rx_steer;
    int err = 0;

    ovs_mutex_lock(&dev->mutex);

    try_rx_steer = dev->requested_rx_steer_flags != 0;
    dev->requested_n_rxq = dev->user_n_rxq;
    if (try_rx_steer) {
        dev->requested_n_rxq += 1;
    }

    atomic_read_relaxed(&netdev_dpdk_pending_reset[dev->port_id],
                        &pending_reset);

    if (netdev->n_txq == dev->requested_n_txq
        && netdev->n_rxq == dev->requested_n_rxq
        && dev->rx_steer_flags == dev->requested_rx_steer_flags
        && dev->mtu == dev->requested_mtu
        && dev->lsc_interrupt_mode == dev->requested_lsc_interrupt_mode
        && dev->rxq_size == dev->requested_rxq_size
        && dev->txq_size == dev->requested_txq_size
        && eth_addr_equals(dev->hwaddr, dev->requested_hwaddr)
        && dev->socket_id == dev->requested_socket_id
        && dev->started && !pending_reset) {
        /* Reconfiguration is unnecessary */

        goto out;
    }

retry:
    dpdk_rx_steer_unconfigure(dev);

    if (pending_reset) {
        /*
         * Set false before reset to avoid missing a new reset interrupt event
         * in a race with event callback.
         */
        atomic_store_relaxed(&netdev_dpdk_pending_reset[dev->port_id], false);
        rte_eth_dev_reset(dev->port_id);
        if_notifier_manual_report();
    } else {
        rte_eth_dev_stop(dev->port_id);
    }

    dev->started = false;

    err = netdev_dpdk_mempool_configure(dev);
    if (err && err != EEXIST) {
        goto out;
    }

    dev->lsc_interrupt_mode = dev->requested_lsc_interrupt_mode;

    netdev->n_txq = dev->requested_n_txq;
    netdev->n_rxq = dev->requested_n_rxq;

    dev->rxq_size = dev->requested_rxq_size;
    dev->txq_size = dev->requested_txq_size;

    rte_free(dev->tx_q);
    dev->tx_q = NULL;

    if (!eth_addr_equals(dev->hwaddr, dev->requested_hwaddr)) {
        err = netdev_dpdk_set_etheraddr__(dev, dev->requested_hwaddr);
        if (err) {
            goto out;
        }
    }

    err = dpdk_eth_dev_init(dev);
    if (err) {
        goto out;
    }
    netdev_dpdk_update_netdev_flags(dev);

    /* If both requested and actual hwaddr were previously
     * unset (initialized to 0), then first device init above
     * will have set actual hwaddr to something new.
     * This would trigger spurious MAC reconfiguration unless
     * the requested MAC is kept in sync.
     *
     * This is harmless in case requested_hwaddr was
     * configured by the user, as netdev_dpdk_set_etheraddr__()
     * will have succeeded to get to this point.
     */
    dev->requested_hwaddr = dev->hwaddr;

    if (try_rx_steer) {
        err = dpdk_rx_steer_configure(dev);
        if (err) {
            /* No hw support, disable & recover gracefully. */
            try_rx_steer = false;
            /*
             * The extra queue must be explicitly removed here to ensure that
             * it is unconfigured immediately.
             */
            dev->requested_n_rxq = dev->user_n_rxq;
            goto retry;
        }
    } else {
        VLOG_INFO("%s: rx-steering: default rss", netdev_get_name(&dev->up));
    }
    dev->rx_steer_flags = dev->requested_rx_steer_flags;

    dev->tx_q = netdev_dpdk_alloc_txq(netdev->n_txq);
    if (!dev->tx_q) {
        err = ENOMEM;
    }

    netdev_change_seq_changed(netdev);

out:
    ovs_mutex_unlock(&dev->mutex);
    return err;
}

static int
dpdk_vhost_reconfigure_helper(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    dev->up.n_txq = dev->requested_n_txq;
    dev->up.n_rxq = dev->requested_n_rxq;

    /* Always keep RX queue 0 enabled for implementations that won't
     * report vring states. */
    dev->vhost_rxq_enabled[0] = true;

    /* Enable TX queue 0 by default if it wasn't disabled. */
    if (dev->tx_q[0].map == OVS_VHOST_QUEUE_MAP_UNKNOWN) {
        dev->tx_q[0].map = 0;
    }

    rte_spinlock_lock(&dev->stats_lock);
    memset(&dev->stats, 0, sizeof dev->stats);
    memset(dev->sw_stats, 0, sizeof *dev->sw_stats);
    rte_spinlock_unlock(&dev->stats_lock);

    netdev_dpdk_remap_txqs(dev);

    if (netdev_dpdk_get_vid(dev) >= 0) {
        int err;

        err = netdev_dpdk_mempool_configure(dev);
        if (!err) {
            /* A new mempool was created or re-used. */
            netdev_change_seq_changed(&dev->up);
        } else if (err != EEXIST) {
            return err;
        }

        if (dev->vhost_reconfigured == false) {
            dev->vhost_reconfigured = true;
            /* Carrier status may need updating. */
            netdev_change_seq_changed(&dev->up);
        }
    }

    netdev_dpdk_update_netdev_flags(dev);

    return 0;
}

static int
netdev_dpdk_vhost_reconfigure(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int err;

    ovs_mutex_lock(&dev->mutex);
    err = dpdk_vhost_reconfigure_helper(dev);
    ovs_mutex_unlock(&dev->mutex);

    return err;
}

static int
netdev_dpdk_vhost_client_reconfigure(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    bool unregister = false;
    char *vhost_id;
    int err;

    ovs_mutex_lock(&dev->mutex);

    if (dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT && dev->vhost_id
        && dev->virtio_features_state & OVS_VIRTIO_F_RECONF_PENDING) {

        /* This vhost-user port was registered to the vhost library already,
         * but a socket disconnection happened and configuration must be
         * re-evaluated wrt dev->virtio_features_state. */
        dev->vhost_driver_flags &= ~RTE_VHOST_USER_CLIENT;
        vhost_id = dev->vhost_id;
        unregister = true;
    }

    ovs_mutex_unlock(&dev->mutex);

    if (unregister) {
        dpdk_vhost_driver_unregister(dev, vhost_id);
    }

    ovs_mutex_lock(&dev->mutex);

    /* Configure vHost client mode if requested and if the following criteria
     * are met:
     *  1. Device hasn't been registered yet.
     *  2. A path has been specified.
     */
    if (!(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT) && dev->vhost_id) {
        uint64_t virtio_unsup_features = 0;
        uint64_t vhost_flags = 0;
        bool enable_tso;

        enable_tso = userspace_tso_enabled()
                     && dev->virtio_features_state & OVS_VIRTIO_F_CLEAN;
        dev->virtio_features_state &= ~OVS_VIRTIO_F_RECONF_PENDING;

        /* Register client-mode device. */
        vhost_flags |= RTE_VHOST_USER_CLIENT;

        /* Extended per vq statistics. */
        vhost_flags |= RTE_VHOST_USER_NET_STATS_ENABLE;

        /* There is no support for multi-segments buffers. */
        vhost_flags |= RTE_VHOST_USER_LINEARBUF_SUPPORT;

        /* Enable IOMMU support, if explicitly requested. */
        if (vhost_iommu_enabled) {
            vhost_flags |= RTE_VHOST_USER_IOMMU_SUPPORT;
        }

        /* Enable POSTCOPY support, if explicitly requested. */
        if (vhost_postcopy_enabled) {
            vhost_flags |= RTE_VHOST_USER_POSTCOPY_SUPPORT;
        }

        /* Use "compliant" ol_flags API so that the vhost library behaves
         * like a DPDK ethdev driver. */
        vhost_flags |= RTE_VHOST_USER_NET_COMPLIANT_OL_FLAGS;

        /* Enable External Buffers if TCP Segmentation Offload is enabled. */
        if (enable_tso) {
            vhost_flags |= RTE_VHOST_USER_EXTBUF_SUPPORT;
        }

        err = rte_vhost_driver_register(dev->vhost_id, vhost_flags);
        if (err) {
            VLOG_ERR("vhost-user device setup failure for device %s\n",
                     dev->vhost_id);
            goto unlock;
        } else {
            /* Configuration successful */
            dev->vhost_driver_flags |= vhost_flags;
            VLOG_INFO("vHost User device '%s' created in 'client' mode, "
                      "using client socket '%s'",
                      dev->up.name, dev->vhost_id);
        }

        err = rte_vhost_driver_callback_register(dev->vhost_id,
                                                 &virtio_net_device_ops);
        if (err) {
            VLOG_ERR("rte_vhost_driver_callback_register failed for "
                     "vhost user client port: %s\n", dev->up.name);
            goto unlock;
        }

        if (enable_tso) {
            virtio_unsup_features = 1ULL << VIRTIO_NET_F_HOST_ECN
                                    | 1ULL << VIRTIO_NET_F_HOST_UFO;
            VLOG_DBG("%s: TSO enabled on vhost port",
                     netdev_get_name(&dev->up));
        } else {
            /* Advertise checksum offloading to the guest, but explicitly
             * disable TSO and friends.
             * NOTE: we can't disable HOST_ECN which may have been wrongly
             * negotiated by a running guest. */
            virtio_unsup_features = 1ULL << VIRTIO_NET_F_HOST_TSO4
                                    | 1ULL << VIRTIO_NET_F_HOST_TSO6
                                    | 1ULL << VIRTIO_NET_F_HOST_UFO;
        }

        err = rte_vhost_driver_disable_features(dev->vhost_id,
                                                virtio_unsup_features);
        if (err) {
            VLOG_ERR("rte_vhost_driver_disable_features failed for "
                     "vhost user client port: %s\n", dev->up.name);
            goto unlock;
        }

        /* Setting max queue pairs is only useful and effective with VDUSE. */
        if (strncmp(dev->vhost_id, "/dev/vduse/", 11) == 0) {
            uint32_t max_qp = dev->vhost_max_queue_pairs;

            err = rte_vhost_driver_set_max_queue_num(dev->vhost_id, max_qp);
            if (err) {
                VLOG_ERR("rte_vhost_driver_set_max_queue_num failed for "
                         "vhost-user client port: %s\n", dev->up.name);
                goto unlock;
            }
        }

        err = rte_vhost_driver_start(dev->vhost_id);
        if (err) {
            VLOG_ERR("rte_vhost_driver_start failed for vhost user "
                     "client port: %s\n", dev->up.name);
            goto unlock;
        }
    }

    err = dpdk_vhost_reconfigure_helper(dev);

unlock:
    ovs_mutex_unlock(&dev->mutex);

    return err;
}

int
netdev_dpdk_get_port_id(struct netdev *netdev)
{
    struct netdev_dpdk *dev;
    int ret = -1;

    if (!is_dpdk_class(netdev->netdev_class)) {
        goto out;
    }

    dev = netdev_dpdk_cast(netdev);
    ovs_mutex_lock(&dev->mutex);
    ret = dev->port_id;
    ovs_mutex_unlock(&dev->mutex);
out:
    return ret;
}

bool
netdev_dpdk_flow_api_supported(struct netdev *netdev)
{
    struct netdev_dpdk *dev;
    bool ret = false;

    if ((!strcmp(netdev_get_type(netdev), "vxlan") ||
         !strcmp(netdev_get_type(netdev), "gre")) &&
        !strcmp(netdev_get_dpif_type(netdev), "netdev")) {
        ret = true;
        goto out;
    }

    if (!is_dpdk_class(netdev->netdev_class)) {
        goto out;
    }

    dev = netdev_dpdk_cast(netdev);
    ovs_mutex_lock(&dev->mutex);
    if (dev->type == DPDK_DEV_ETH) {
        if (dev->requested_rx_steer_flags) {
            VLOG_WARN("%s: rx-steering is mutually exclusive with hw-offload,"
                      " falling back to default rss mode",
                      netdev_get_name(netdev));
            dev->requested_rx_steer_flags = 0;
            netdev_request_reconfigure(netdev);
        }
        /* TODO: Check if we able to offload some minimal flow. */
        ret = true;
    }
    ovs_mutex_unlock(&dev->mutex);
out:
    return ret;
}

int
netdev_dpdk_rte_flow_destroy(struct netdev *netdev,
                             struct rte_flow *rte_flow,
                             struct rte_flow_error *error)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int ret;

    ret = rte_flow_destroy(dev->port_id, rte_flow, error);
    return ret;
}

struct rte_flow *
netdev_dpdk_rte_flow_create(struct netdev *netdev,
                            const struct rte_flow_attr *attr,
                            const struct rte_flow_item *items,
                            const struct rte_flow_action *actions,
                            struct rte_flow_error *error)
{
    struct rte_flow *flow;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    flow = rte_flow_create(dev->port_id, attr, items, actions, error);
    return flow;
}

int
netdev_dpdk_rte_flow_query_count(struct netdev *netdev,
                                 struct rte_flow *rte_flow,
                                 struct rte_flow_query_count *query,
                                 struct rte_flow_error *error)
{
    struct rte_flow_action_count count = { .id = 0, };
    const struct rte_flow_action actions[] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_COUNT,
            .conf = &count,
        },
        {
            .type = RTE_FLOW_ACTION_TYPE_END,
        },
    };
    struct netdev_dpdk *dev;
    int ret;

    if (!is_dpdk_class(netdev->netdev_class)) {
        return -1;
    }

    dev = netdev_dpdk_cast(netdev);
    ret = rte_flow_query(dev->port_id, rte_flow, actions, query, error);
    return ret;
}

#ifdef ALLOW_EXPERIMENTAL_API

int
netdev_dpdk_rte_flow_tunnel_decap_set(struct netdev *netdev,
                                      struct rte_flow_tunnel *tunnel,
                                      struct rte_flow_action **actions,
                                      uint32_t *num_of_actions,
                                      struct rte_flow_error *error)
{
    struct netdev_dpdk *dev;
    int ret;

    if (!is_dpdk_class(netdev->netdev_class)) {
        return -1;
    }

    dev = netdev_dpdk_cast(netdev);
    ovs_mutex_lock(&dev->mutex);
    ret = rte_flow_tunnel_decap_set(dev->port_id, tunnel, actions,
                                    num_of_actions, error);
    ovs_mutex_unlock(&dev->mutex);
    return ret;
}

int
netdev_dpdk_rte_flow_tunnel_match(struct netdev *netdev,
                                  struct rte_flow_tunnel *tunnel,
                                  struct rte_flow_item **items,
                                  uint32_t *num_of_items,
                                  struct rte_flow_error *error)
{
    struct netdev_dpdk *dev;
    int ret;

    if (!is_dpdk_class(netdev->netdev_class)) {
        return -1;
    }

    dev = netdev_dpdk_cast(netdev);
    ovs_mutex_lock(&dev->mutex);
    ret = rte_flow_tunnel_match(dev->port_id, tunnel, items, num_of_items,
                                error);
    ovs_mutex_unlock(&dev->mutex);
    return ret;
}

int
netdev_dpdk_rte_flow_get_restore_info(struct netdev *netdev,
                                      struct dp_packet *p,
                                      struct rte_flow_restore_info *info,
                                      struct rte_flow_error *error)
{
    struct rte_mbuf *m = (struct rte_mbuf *) p;
    struct netdev_dpdk *dev;
    int ret;

    if (!is_dpdk_class(netdev->netdev_class)) {
        return -1;
    }

    dev = netdev_dpdk_cast(netdev);
    ovs_mutex_lock(&dev->mutex);
    ret = rte_flow_get_restore_info(dev->port_id, m, info, error);
    ovs_mutex_unlock(&dev->mutex);
    return ret;
}

int
netdev_dpdk_rte_flow_tunnel_action_decap_release(
    struct netdev *netdev,
    struct rte_flow_action *actions,
    uint32_t num_of_actions,
    struct rte_flow_error *error)
{
    struct netdev_dpdk *dev;
    int ret;

    if (!is_dpdk_class(netdev->netdev_class)) {
        return -1;
    }

    dev = netdev_dpdk_cast(netdev);
    ovs_mutex_lock(&dev->mutex);
    ret = rte_flow_tunnel_action_decap_release(dev->port_id, actions,
                                               num_of_actions, error);
    ovs_mutex_unlock(&dev->mutex);
    return ret;
}

int
netdev_dpdk_rte_flow_tunnel_item_release(struct netdev *netdev,
                                         struct rte_flow_item *items,
                                         uint32_t num_of_items,
                                         struct rte_flow_error *error)
{
    struct netdev_dpdk *dev;
    int ret;

    if (!is_dpdk_class(netdev->netdev_class)) {
        return -1;
    }

    dev = netdev_dpdk_cast(netdev);
    ovs_mutex_lock(&dev->mutex);
    ret = rte_flow_tunnel_item_release(dev->port_id, items, num_of_items,
                                       error);
    ovs_mutex_unlock(&dev->mutex);
    return ret;
}

#endif /* ALLOW_EXPERIMENTAL_API */

static void
parse_mempool_config(const struct smap *ovs_other_config)
{
    per_port_memory = smap_get_bool(ovs_other_config,
                                    "per-port-memory", false);
    VLOG_INFO("Per port memory for DPDK devices %s.",
              per_port_memory ? "enabled" : "disabled");
}

static void
parse_user_mempools_list(const struct smap *ovs_other_config)
{
    const char *mtus = smap_get(ovs_other_config, "shared-mempool-config");
    char *list, *copy, *key, *value;
    int error = 0;

    if (!mtus) {
        return;
    }

    n_user_mempools = 0;
    list = copy = xstrdup(mtus);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        int socket_id, mtu, adj_mtu;

        if (!str_to_int(key, 0, &mtu) || mtu < 0) {
            error = EINVAL;
            VLOG_WARN("Invalid user configured shared mempool MTU.");
            break;
        }

        if (!str_to_int(value, 0, &socket_id)) {
            /* No socket specified. It will apply for all numas. */
            socket_id = INT_MAX;
        } else if (socket_id < 0) {
            error = EINVAL;
            VLOG_WARN("Invalid user configured shared mempool NUMA.");
            break;
        }

        user_mempools = xrealloc(user_mempools, (n_user_mempools + 1) *
                                 sizeof(struct user_mempool_config));
        adj_mtu = FRAME_LEN_TO_MTU(dpdk_buf_size(mtu));
        user_mempools[n_user_mempools].adj_mtu = adj_mtu;
        user_mempools[n_user_mempools].socket_id = socket_id;
        n_user_mempools++;
        VLOG_INFO("User configured shared mempool set for: MTU %d, NUMA %s.",
                  mtu, socket_id == INT_MAX ? "ALL" : value);
    }

    if (error) {
        VLOG_WARN("User configured shared mempools will not be used.");
        n_user_mempools = 0;
        free(user_mempools);
        user_mempools = NULL;
    }
    free(copy);
}

static int
process_vhost_flags(char *flag, const char *default_val, int size,
                    const struct smap *ovs_other_config,
                    char **new_val)
{
    const char *val;
    int changed = 0;

    val = smap_get(ovs_other_config, flag);

    /* Process the vhost-sock-dir flag if it is provided, otherwise resort to
     * default value.
     */
    if (val && (strlen(val) <= size)) {
        changed = 1;
        *new_val = xstrdup(val);
        VLOG_INFO("User-provided %s in use: %s", flag, *new_val);
    } else {
        VLOG_INFO("No %s provided - defaulting to %s", flag, default_val);
        *new_val = xstrdup(default_val);
    }

    return changed;
}

static void
parse_vhost_config(const struct smap *ovs_other_config)
{
    char *sock_dir_subcomponent;

    if (process_vhost_flags("vhost-sock-dir", ovs_rundir(),
                            NAME_MAX, ovs_other_config,
                            &sock_dir_subcomponent)) {
        struct stat s;

        if (!strstr(sock_dir_subcomponent, "..")) {
            vhost_sock_dir = xasprintf("%s/%s", ovs_rundir(),
                                       sock_dir_subcomponent);

            if (stat(vhost_sock_dir, &s)) {
                VLOG_ERR("vhost-user sock directory '%s' does not exist.",
                         vhost_sock_dir);
            }
        } else {
            vhost_sock_dir = xstrdup(ovs_rundir());
            VLOG_ERR("vhost-user sock directory request '%s/%s' has invalid"
                     "characters '..' - using %s instead.",
                     ovs_rundir(), sock_dir_subcomponent, ovs_rundir());
        }
        free(sock_dir_subcomponent);
    } else {
        vhost_sock_dir = sock_dir_subcomponent;
    }

    vhost_iommu_enabled = smap_get_bool(ovs_other_config,
                                        "vhost-iommu-support", false);
    VLOG_INFO("IOMMU support for vhost-user-client %s.",
               vhost_iommu_enabled ? "enabled" : "disabled");

    vhost_postcopy_enabled = smap_get_bool(ovs_other_config,
                                           "vhost-postcopy-support", false);
    if (vhost_postcopy_enabled && memory_all_locked()) {
        VLOG_WARN("vhost-postcopy-support and mlockall are not compatible.");
        vhost_postcopy_enabled = false;
    }
    VLOG_INFO("POSTCOPY support for vhost-user-client %s.",
              vhost_postcopy_enabled ? "enabled" : "disabled");
}

#define NETDEV_DPDK_CLASS_COMMON                            \
    .is_pmd = true,                                         \
    .alloc = netdev_dpdk_alloc,                             \
    .dealloc = netdev_dpdk_dealloc,                         \
    .get_numa_id = netdev_dpdk_get_numa_id,                 \
    .set_etheraddr = netdev_dpdk_set_etheraddr,             \
    .get_etheraddr = netdev_dpdk_get_etheraddr,             \
    .get_mtu = netdev_dpdk_get_mtu,                         \
    .set_mtu = netdev_dpdk_set_mtu,                         \
    .get_ifindex = netdev_dpdk_get_ifindex,                 \
    .get_carrier_resets = netdev_dpdk_get_carrier_resets,   \
    .set_miimon_interval = netdev_dpdk_set_miimon,          \
    .set_policing = netdev_dpdk_set_policing,               \
    .get_qos_types = netdev_dpdk_get_qos_types,             \
    .get_qos = netdev_dpdk_get_qos,                         \
    .set_qos = netdev_dpdk_set_qos,                         \
    .get_queue = netdev_dpdk_get_queue,                     \
    .set_queue = netdev_dpdk_set_queue,                     \
    .delete_queue = netdev_dpdk_delete_queue,               \
    .get_queue_stats = netdev_dpdk_get_queue_stats,         \
    .queue_dump_start = netdev_dpdk_queue_dump_start,       \
    .queue_dump_next = netdev_dpdk_queue_dump_next,         \
    .queue_dump_done = netdev_dpdk_queue_dump_done,         \
    .update_flags = netdev_dpdk_update_flags,               \
    .rxq_alloc = netdev_dpdk_rxq_alloc,                     \
    .rxq_construct = netdev_dpdk_rxq_construct,             \
    .rxq_destruct = netdev_dpdk_rxq_destruct,               \
    .rxq_dealloc = netdev_dpdk_rxq_dealloc

#define NETDEV_DPDK_CLASS_BASE                          \
    NETDEV_DPDK_CLASS_COMMON,                           \
    .init = netdev_dpdk_class_init,                     \
    .run = netdev_dpdk_run,                             \
    .wait = netdev_dpdk_wait,                           \
    .destruct = netdev_dpdk_destruct,                   \
    .set_tx_multiq = netdev_dpdk_set_tx_multiq,         \
    .get_carrier = netdev_dpdk_get_carrier,             \
    .get_stats = netdev_dpdk_get_stats,                 \
    .get_custom_stats = netdev_dpdk_get_custom_stats,   \
    .get_features = netdev_dpdk_get_features,           \
    .get_speed = netdev_dpdk_get_speed,                 \
    .get_duplex = netdev_dpdk_get_duplex,               \
    .get_status = netdev_dpdk_get_status,               \
    .reconfigure = netdev_dpdk_reconfigure,             \
    .rxq_recv = netdev_dpdk_rxq_recv

static const struct netdev_class dpdk_class = {
    .type = "dpdk",
    NETDEV_DPDK_CLASS_BASE,
    .construct = netdev_dpdk_construct,
    .get_config = netdev_dpdk_get_config,
    .set_config = netdev_dpdk_set_config,
    .send = netdev_dpdk_eth_send,
};

static const struct netdev_class dpdk_vhost_class = {
    .type = "dpdkvhostuser",
    NETDEV_DPDK_CLASS_COMMON,
    .init = netdev_dpdk_vhost_class_init,
    .construct = netdev_dpdk_vhost_construct,
    .destruct = netdev_dpdk_vhost_destruct,
    .send = netdev_dpdk_vhost_send,
    .get_carrier = netdev_dpdk_vhost_get_carrier,
    .get_stats = netdev_dpdk_vhost_get_stats,
    .get_custom_stats = netdev_dpdk_vhost_get_custom_stats,
    .get_status = netdev_dpdk_vhost_user_get_status,
    .reconfigure = netdev_dpdk_vhost_reconfigure,
    .rxq_recv = netdev_dpdk_vhost_rxq_recv,
    .rxq_enabled = netdev_dpdk_vhost_rxq_enabled,
};

static const struct netdev_class dpdk_vhost_client_class = {
    .type = "dpdkvhostuserclient",
    NETDEV_DPDK_CLASS_COMMON,
    .init = netdev_dpdk_vhost_class_init,
    .construct = netdev_dpdk_vhost_client_construct,
    .destruct = netdev_dpdk_vhost_destruct,
    .get_config = netdev_dpdk_vhost_client_get_config,
    .set_config = netdev_dpdk_vhost_client_set_config,
    .send = netdev_dpdk_vhost_send,
    .get_carrier = netdev_dpdk_vhost_get_carrier,
    .get_stats = netdev_dpdk_vhost_get_stats,
    .get_custom_stats = netdev_dpdk_vhost_get_custom_stats,
    .get_status = netdev_dpdk_vhost_user_get_status,
    .reconfigure = netdev_dpdk_vhost_client_reconfigure,
    .rxq_recv = netdev_dpdk_vhost_rxq_recv,
    .rxq_enabled = netdev_dpdk_vhost_rxq_enabled,
};

void
netdev_dpdk_register(const struct smap *ovs_other_config)
{
    parse_mempool_config(ovs_other_config);
    parse_user_mempools_list(ovs_other_config);
    parse_vhost_config(ovs_other_config);

    netdev_register_provider(&dpdk_class);
    netdev_register_provider(&dpdk_vhost_class);
    netdev_register_provider(&dpdk_vhost_client_class);
}
