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

#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/virtio_net.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <rte_bus_pci.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_meter.h>
#include <rte_pci.h>
#include <rte_vhost.h>
#include <rte_version.h>

#include "dirs.h"
#include "dp-packet.h"
#include "dpdk.h"
#include "dpif-netdev.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/shash.h"
#include "smap.h"
#include "sset.h"
#include "unaligned.h"
#include "timeval.h"
#include "unixctl.h"

enum {VIRTIO_RXQ, VIRTIO_TXQ, VIRTIO_QNUM};

VLOG_DEFINE_THIS_MODULE(netdev_dpdk);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define DPDK_PORT_WATCHDOG_INTERVAL 5

#define OVS_CACHE_LINE_SIZE CACHE_LINE_SIZE
#define OVS_VPORT_DPDK "ovs_dpdk"

/*
 * need to reserve tons of extra space in the mbufs so we can align the
 * DMA addresses to 4KB.
 * The minimum mbuf size is limited to avoid scatter behaviour and drop in
 * performance for standard Ethernet MTU.
 */
#define ETHER_HDR_MAX_LEN           (ETHER_HDR_LEN + ETHER_CRC_LEN \
                                     + (2 * VLAN_HEADER_LEN))
#define MTU_TO_FRAME_LEN(mtu)       ((mtu) + ETHER_HDR_LEN + ETHER_CRC_LEN)
#define MTU_TO_MAX_FRAME_LEN(mtu)   ((mtu) + ETHER_HDR_MAX_LEN)
#define FRAME_LEN_TO_MTU(frame_len) ((frame_len)                    \
                                     - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define MBUF_SIZE(mtu)              ROUND_UP((MTU_TO_MAX_FRAME_LEN(mtu) \
                                             + sizeof(struct dp_packet) \
                                             + RTE_PKTMBUF_HEADROOM),   \
                                             RTE_CACHE_LINE_SIZE)
#define NETDEV_DPDK_MBUF_ALIGN      1024
#define NETDEV_DPDK_MAX_PKT_LEN     9728

/* Max and min number of packets in the mempool.  OVS tries to allocate a
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

/*
 * DPDK XSTATS Counter names definition
 */
#define XSTAT_RX_64_PACKETS              "rx_size_64_packets"
#define XSTAT_RX_65_TO_127_PACKETS       "rx_size_65_to_127_packets"
#define XSTAT_RX_128_TO_255_PACKETS      "rx_size_128_to_255_packets"
#define XSTAT_RX_256_TO_511_PACKETS      "rx_size_256_to_511_packets"
#define XSTAT_RX_512_TO_1023_PACKETS     "rx_size_512_to_1023_packets"
#define XSTAT_RX_1024_TO_1522_PACKETS    "rx_size_1024_to_1522_packets"
#define XSTAT_RX_1523_TO_MAX_PACKETS     "rx_size_1523_to_max_packets"

#define XSTAT_TX_64_PACKETS              "tx_size_64_packets"
#define XSTAT_TX_65_TO_127_PACKETS       "tx_size_65_to_127_packets"
#define XSTAT_TX_128_TO_255_PACKETS      "tx_size_128_to_255_packets"
#define XSTAT_TX_256_TO_511_PACKETS      "tx_size_256_to_511_packets"
#define XSTAT_TX_512_TO_1023_PACKETS     "tx_size_512_to_1023_packets"
#define XSTAT_TX_1024_TO_1522_PACKETS    "tx_size_1024_to_1522_packets"
#define XSTAT_TX_1523_TO_MAX_PACKETS     "tx_size_1523_to_max_packets"

#define XSTAT_RX_MULTICAST_PACKETS       "rx_multicast_packets"
#define XSTAT_TX_MULTICAST_PACKETS       "tx_multicast_packets"
#define XSTAT_RX_BROADCAST_PACKETS       "rx_broadcast_packets"
#define XSTAT_TX_BROADCAST_PACKETS       "tx_broadcast_packets"
#define XSTAT_RX_UNDERSIZED_ERRORS       "rx_undersized_errors"
#define XSTAT_RX_OVERSIZE_ERRORS         "rx_oversize_errors"
#define XSTAT_RX_FRAGMENTED_ERRORS       "rx_fragmented_errors"
#define XSTAT_RX_JABBER_ERRORS           "rx_jabber_errors"

#define SOCKET0              0

/* Default size of Physical NIC RXQ */
#define NIC_PORT_DEFAULT_RXQ_SIZE 2048
/* Default size of Physical NIC TXQ */
#define NIC_PORT_DEFAULT_TXQ_SIZE 2048
/* Maximum size of Physical NIC Queues */
#define NIC_PORT_MAX_Q_SIZE 4096

#define OVS_VHOST_MAX_QUEUE_NUM 1024  /* Maximum number of vHost TX queues. */
#define OVS_VHOST_QUEUE_MAP_UNKNOWN (-1) /* Mapping not initialized. */
#define OVS_VHOST_QUEUE_DISABLED    (-2) /* Queue was disabled by guest and not
                                          * yet mapped to another queue. */

#define DPDK_ETH_PORT_ID_INVALID    RTE_MAX_ETHPORTS

/* DPDK library uses uint16_t for port_id. */
typedef uint16_t dpdk_port_t;
#define DPDK_PORT_ID_FMT "%"PRIu16

#define VHOST_ENQ_RETRY_NUM 8
#define IF_NAME_SZ (PATH_MAX > IFNAMSIZ ? PATH_MAX : IFNAMSIZ)

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .split_hdr_size = 0,
        .header_split   = 0, /* Header Split disabled */
        .hw_ip_checksum = 0, /* IP checksum offload disabled */
        .hw_vlan_filter = 0, /* VLAN filtering disabled */
        .jumbo_frame    = 0, /* Jumbo Frame Support disabled */
        .hw_strip_crc   = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

/*
 * These callbacks allow virtio-net devices to be added to vhost ports when
 * configuration has been fully completed.
 */
static int new_device(int vid);
static void destroy_device(int vid);
static int vring_state_changed(int vid, uint16_t queue_id, int enable);
static const struct vhost_device_ops virtio_net_device_ops =
{
    .new_device =  new_device,
    .destroy_device = destroy_device,
    .vring_state_changed = vring_state_changed,
    .features_changed = NULL
};

enum { DPDK_RING_SIZE = 256 };
BUILD_ASSERT_DECL(IS_POW2(DPDK_RING_SIZE));
enum { DRAIN_TSC = 200000ULL };

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
                   int pkt_cnt, bool may_steal);
};

/* dpdk_qos_ops for each type of user space QoS implementation */
static const struct dpdk_qos_ops egress_policer_ops;

/*
 * Array of dpdk_qos_ops, contains pointer to all supported QoS
 * operations.
 */
static const struct dpdk_qos_ops *const qos_confs[] = {
    &egress_policer_ops,
    NULL
};

static struct ovs_mutex dpdk_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dpdk_dev's. */
static struct ovs_list dpdk_list OVS_GUARDED_BY(dpdk_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_list);

static struct ovs_mutex dpdk_mp_mutex OVS_ACQ_AFTER(dpdk_mutex)
    = OVS_MUTEX_INITIALIZER;

static struct ovs_list dpdk_mp_list OVS_GUARDED_BY(dpdk_mp_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_mp_list);


struct dpdk_mp {
     struct rte_mempool *mp;
     int mtu;
     int socket_id;
     int refcount;
     struct ovs_list list_node OVS_GUARDED_BY(dpdk_mp_mutex);
 };


/* There should be one 'struct dpdk_tx_queue' created for
 * each cpu core. */
struct dpdk_tx_queue {
    rte_spinlock_t tx_lock;        /* Protects the members and the NIC queue
                                    * from concurrent access.  It is used only
                                    * if the queue is shared among different
                                    * pmd threads (see 'concurrent_txq'). */
    int map;                       /* Mapping of configured vhost-user queues
                                    * to enabled by guest. */
};

/* dpdk has no way to remove dpdk ring ethernet devices
   so we have to keep them around once they've been created
*/

static struct ovs_list dpdk_ring_list OVS_GUARDED_BY(dpdk_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_ring_list);

struct dpdk_ring {
    /* For the client rings */
    struct rte_ring *cring_tx;
    struct rte_ring *cring_rx;
    unsigned int user_port_id; /* User given port no, parsed from port name */
    dpdk_port_t eth_port_id; /* ethernet device port id */
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);
};

struct ingress_policer {
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm in_policer;
    rte_spinlock_t policer_lock;
};

enum dpdk_hw_ol_features {
    NETDEV_RX_CHECKSUM_OFFLOAD = 1 << 0,
};

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
        /* If true, rte_eth_dev_start() was successfully called */
        bool started;
        struct eth_addr hwaddr;
        int mtu;
        int socket_id;
        int buf_size;
        int max_packet_len;
        enum dpdk_dev_type type;
        enum netdev_flags flags;
        int link_reset_cnt;
        char *devargs;  /* Device arguments for dpdk ports */
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
        /* 3 pad bytes here. */
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* Identifier used to distinguish vhost devices from each other. */
        char vhost_id[PATH_MAX];
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
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev_stats stats;
        /* Protects stats */
        rte_spinlock_t stats_lock;
        /* 44 pad bytes here. */
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* The following properties cannot be changed when a device is running,
         * so we remember the request and update them next time
         * netdev_dpdk*_reconfigure() is called */
        int requested_mtu;
        int requested_n_txq;
        int requested_n_rxq;
        int requested_rxq_size;
        int requested_txq_size;

        /* Number of rx/tx descriptors for physical devices */
        int rxq_size;
        int txq_size;

        /* Socket ID detected when vHost device is brought up */
        int requested_socket_id;

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

static void netdev_dpdk_clear_xstats(struct netdev_dpdk *dev);

int netdev_dpdk_get_vid(const struct netdev_dpdk *dev);

struct ingress_policer *
netdev_dpdk_get_ingress_policer(const struct netdev_dpdk *dev);

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
    return ROUND_UP((MTU_TO_MAX_FRAME_LEN(mtu) + RTE_PKTMBUF_HEADROOM),
                     NETDEV_DPDK_MBUF_ALIGN);
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

    dp_packet_init_dpdk((struct dp_packet *) pkt, pkt->buf_len);
}

static struct dpdk_mp *
dpdk_mp_create(int socket_id, int mtu)
{
    struct dpdk_mp *dmp;
    unsigned mp_size;
    char *mp_name;

    dmp = dpdk_rte_mzalloc(sizeof *dmp);
    if (!dmp) {
        return NULL;
    }
    dmp->socket_id = socket_id;
    dmp->mtu = mtu;
    dmp->refcount = 1;
    /* XXX: this is a really rough method of provisioning memory.
     * It's impossible to determine what the exact memory requirements are
     * when the number of ports and rxqs that utilize a particular mempool can
     * change dynamically at runtime. For now, use this rough heurisitic.
     */
    if (mtu >= ETHER_MTU) {
        mp_size = MAX_NB_MBUF;
    } else {
        mp_size = MIN_NB_MBUF;
    }

    do {
        mp_name = xasprintf("ovs_mp_%d_%d_%u", dmp->mtu, dmp->socket_id,
                            mp_size);

        dmp->mp = rte_pktmbuf_pool_create(mp_name, mp_size,
                                          MP_CACHE_SZ,
                                          sizeof (struct dp_packet)
                                          - sizeof (struct rte_mbuf),
                                          MBUF_SIZE(mtu)
                                          - sizeof(struct dp_packet),
                                          socket_id);
        if (dmp->mp) {
            VLOG_DBG("Allocated \"%s\" mempool with %u mbufs",
                     mp_name, mp_size);
        }
        free(mp_name);
        if (dmp->mp) {
            /* rte_pktmbuf_pool_create has done some initialization of the
             * rte_mbuf part of each dp_packet, while ovs_rte_pktmbuf_init
             * initializes some OVS specific fields of dp_packet.
             */
            rte_mempool_obj_iter(dmp->mp, ovs_rte_pktmbuf_init, NULL);
            return dmp;
        }
    } while (rte_errno == ENOMEM && (mp_size /= 2) >= MIN_NB_MBUF);

    rte_free(dmp);
    return NULL;
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
    struct dpdk_mp *dmp, *next;

    LIST_FOR_EACH_SAFE (dmp, next, list_node, &dpdk_mp_list) {
        if (!dmp->refcount && dpdk_mp_full(dmp->mp)) {
            VLOG_DBG("Freeing mempool \"%s\"", dmp->mp->name);
            ovs_list_remove(&dmp->list_node);
            rte_mempool_free(dmp->mp);
            rte_free(dmp);
        }
    }
}

static struct dpdk_mp *
dpdk_mp_get(int socket_id, int mtu)
{
    struct dpdk_mp *dmp;
    bool reuse = false;

    ovs_mutex_lock(&dpdk_mp_mutex);
    LIST_FOR_EACH (dmp, list_node, &dpdk_mp_list) {
        if (dmp->socket_id == socket_id && dmp->mtu == mtu) {
            VLOG_DBG("Reusing mempool \"%s\"", dmp->mp->name);
            dmp->refcount++;
            reuse = true;
            break;
        }
    }
    /* Sweep mempools after reuse or before create. */
    dpdk_mp_sweep();

    if (!reuse) {
        dmp = dpdk_mp_create(socket_id, mtu);
        if (dmp) {
            ovs_list_push_back(&dpdk_mp_list, &dmp->list_node);
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

/* Tries to allocate new mempool on requested_socket_id with
 * mbuf size corresponding to requested_mtu.
 * On success new configuration will be applied.
 * On error, device will be left unchanged. */
static int
netdev_dpdk_mempool_configure(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    uint32_t buf_size = dpdk_buf_size(dev->requested_mtu);
    struct dpdk_mp *mp;

    mp = dpdk_mp_get(dev->requested_socket_id, FRAME_LEN_TO_MTU(buf_size));
    if (!mp) {
        VLOG_ERR("Failed to create memory pool for netdev "
                 "%s, with MTU %d on socket %d: %s\n",
                 dev->up.name, dev->requested_mtu, dev->requested_socket_id,
        rte_strerror(rte_errno));
        return rte_errno;
    } else {
        dpdk_mp_put(dev->dpdk_mp);
        dev->dpdk_mp = mp;
        dev->mtu = dev->requested_mtu;
        dev->socket_id = dev->requested_socket_id;
        dev->max_packet_len = MTU_TO_FRAME_LEN(dev->mtu);
    }

    return 0;
}

static void
check_link_status(struct netdev_dpdk *dev)
{
    struct rte_eth_link link;

    rte_eth_link_get_nowait(dev->port_id, &link);

    if (dev->link.link_status != link.link_status) {
        netdev_change_seq_changed(&dev->up);

        dev->link_reset_cnt++;
        dev->link = link;
        if (dev->link.link_status) {
            VLOG_DBG_RL(&rl,
                        "Port "DPDK_PORT_ID_FMT" Link Up - speed %u Mbps - %s",
                        dev->port_id, (unsigned) dev->link.link_speed,
                        (dev->link.link_duplex == ETH_LINK_FULL_DUPLEX)
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

static int
dpdk_eth_dev_port_config(struct netdev_dpdk *dev, int n_rxq, int n_txq)
{
    int diag = 0;
    int i;
    struct rte_eth_conf conf = port_conf;
    struct rte_eth_dev_info info;

    /* As of DPDK 17.11.1 a few PMDs require to explicitly enable
     * scatter to support jumbo RX. Checking the offload capabilities
     * is not an option as PMDs are not required yet to report
     * them. The only reliable info is the driver name and knowledge
     * (testing or code review). Listing all such PMDs feels harder
     * than highlighting the one known not to need scatter */
    if (dev->mtu > ETHER_MTU) {
        rte_eth_dev_info_get(dev->port_id, &info);
        if (strncmp(info.driver_name, "net_nfp", 7)) {
            conf.rxmode.enable_scatter = 1;
        }
    }

    conf.intr_conf.lsc = dev->lsc_interrupt_mode;
    conf.rxmode.hw_ip_checksum = (dev->hw_ol_features &
                                  NETDEV_RX_CHECKSUM_OFFLOAD) != 0;
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
            VLOG_ERR("Interface %s MTU (%d) setup error: %s",
                    dev->up.name, dev->mtu, rte_strerror(-diag));
            break;
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

static int
dpdk_eth_dev_init(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    struct rte_pktmbuf_pool_private *mbp_priv;
    struct rte_eth_dev_info info;
    struct ether_addr eth_addr;
    int diag;
    int n_rxq, n_txq;
    uint32_t rx_chksm_offload_capa = DEV_RX_OFFLOAD_UDP_CKSUM |
                                     DEV_RX_OFFLOAD_TCP_CKSUM |
                                     DEV_RX_OFFLOAD_IPV4_CKSUM;

    rte_eth_dev_info_get(dev->port_id, &info);

    if ((info.rx_offload_capa & rx_chksm_offload_capa) !=
            rx_chksm_offload_capa) {
        VLOG_WARN("Rx checksum offload is not supported on port "
                  DPDK_PORT_ID_FMT, dev->port_id);
        dev->hw_ol_features &= ~NETDEV_RX_CHECKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features |= NETDEV_RX_CHECKSUM_OFFLOAD;
    }

    n_rxq = MIN(info.max_rx_queues, dev->up.n_rxq);
    n_txq = MIN(info.max_tx_queues, dev->up.n_txq);

    diag = dpdk_eth_dev_port_config(dev, n_rxq, n_txq);
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

    rte_eth_promiscuous_enable(dev->port_id);
    rte_eth_allmulticast_enable(dev->port_id);

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(dev->port_id, &eth_addr);
    VLOG_INFO_RL(&rl, "Port "DPDK_PORT_ID_FMT": "ETH_ADDR_FMT,
                 dev->port_id, ETH_ADDR_BYTES_ARGS(eth_addr.addr_bytes));

    memcpy(dev->hwaddr.ea, eth_addr.addr_bytes, ETH_ADDR_LEN);
    rte_eth_link_get_nowait(dev->port_id, &dev->link);

    mbp_priv = rte_mempool_get_priv(dev->dpdk_mp->mp);
    dev->buf_size = mbp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM;

    /* Get the Flow control configuration for DPDK-ETH */
    diag = rte_eth_dev_flow_ctrl_get(dev->port_id, &dev->fc_conf);
    if (diag) {
        VLOG_DBG("cannot get flow control parameters on port "DPDK_PORT_ID_FMT
                 ", err=%d", dev->port_id, diag);
    }

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
    dev->requested_mtu = ETHER_MTU;
    dev->max_packet_len = MTU_TO_FRAME_LEN(dev->mtu);
    dev->requested_lsc_interrupt_mode = 0;
    ovsrcu_index_init(&dev->vid, -1);
    dev->vhost_reconfigured = false;
    dev->attached = false;

    ovsrcu_init(&dev->qos_conf, NULL);

    ovsrcu_init(&dev->ingress_policer, NULL);
    dev->policer_rate = 0;
    dev->policer_burst = 0;

    netdev->n_rxq = 0;
    netdev->n_txq = 0;
    dev->requested_n_rxq = NR_QUEUE;
    dev->requested_n_txq = NR_QUEUE;
    dev->requested_rxq_size = NIC_PORT_DEFAULT_RXQ_SIZE;
    dev->requested_txq_size = NIC_PORT_DEFAULT_TXQ_SIZE;

    /* Initialize the flow control to NULL */
    memset(&dev->fc_conf, 0, sizeof dev->fc_conf);

    /* Initilize the hardware offload flags to 0 */
    dev->hw_ol_features = 0;

    dev->flags = NETDEV_UP | NETDEV_PROMISC;

    ovs_list_push_back(&dpdk_list, &dev->list_node);

    netdev_request_reconfigure(netdev);

    dev->rte_xstats_names = NULL;
    dev->rte_xstats_names_size = 0;

    dev->rte_xstats_ids = NULL;
    dev->rte_xstats_ids_size = 0;

    return 0;
}

/* dev_name must be the prefix followed by a positive decimal number.
 * (no leading + or - signs are allowed) */
static int
dpdk_dev_parse_name(const char dev_name[], const char prefix[],
                    unsigned int *port_no)
{
    const char *cport;

    if (strncmp(dev_name, prefix, strlen(prefix))) {
        return ENODEV;
    }

    cport = dev_name + strlen(prefix);

    if (str_to_uint(cport, 10, port_no)) {
        return 0;
    } else {
        return ENODEV;
    }
}

static int
vhost_common_construct(struct netdev *netdev)
    OVS_REQUIRES(dpdk_mutex)
{
    int socket_id = rte_lcore_to_socket_id(rte_get_master_lcore());
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    dev->tx_q = netdev_dpdk_alloc_txq(OVS_VHOST_MAX_QUEUE_NUM);
    if (!dev->tx_q) {
        return ENOMEM;
    }

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
    snprintf(dev->vhost_id, sizeof dev->vhost_id, "%s/%s",
             dpdk_get_vhost_sock_dir(), name);

    dev->vhost_driver_flags &= ~RTE_VHOST_USER_CLIENT;
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

    err = rte_vhost_driver_disable_features(dev->vhost_id,
                                1ULL << VIRTIO_NET_F_HOST_TSO4
                                | 1ULL << VIRTIO_NET_F_HOST_TSO6
                                | 1ULL << VIRTIO_NET_F_CSUM);
    if (err) {
        VLOG_ERR("rte_vhost_driver_disable_features failed for vhost user "
                 "port: %s\n", name);
        goto out;
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
    ovs_mutex_destroy(&dev->mutex);
}

static void
netdev_dpdk_destruct(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    char devname[RTE_ETH_NAME_MAX_LEN];

    ovs_mutex_lock(&dpdk_mutex);

    rte_eth_dev_stop(dev->port_id);
    dev->started = false;

    if (dev->attached) {
        rte_eth_dev_close(dev->port_id);
        if (rte_eth_dev_detach(dev->port_id, devname) < 0) {
            VLOG_ERR("Device '%s' can not be detached", dev->devargs);
        } else {
            VLOG_INFO("Device '%s' has been detached", devname);
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

    vhost_id = xstrdup(dev->vhost_id);

    common_destruct(dev);

    ovs_mutex_unlock(&dpdk_mutex);

    if (!vhost_id[0]) {
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
{
    /* If statistics are already allocated, we have to
     * reconfigure, as port_id could have been changed. */
    if (dev->rte_xstats_names) {
        free(dev->rte_xstats_names);
        dev->rte_xstats_names = NULL;
        dev->rte_xstats_names_size = 0;
    }
    if (dev->rte_xstats_ids) {
        free(dev->rte_xstats_ids);
        dev->rte_xstats_ids = NULL;
        dev->rte_xstats_ids_size = 0;
    }
}

static const char*
netdev_dpdk_get_xstat_name(struct netdev_dpdk *dev, uint64_t id)
{
    if (id >= dev->rte_xstats_names_size) {
        return "UNKNOWN";
    }
    return dev->rte_xstats_names[id].name;
}

static bool
netdev_dpdk_configure_xstats(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    int rte_xstats_len;
    bool ret;
    struct rte_eth_xstat *rte_xstats;
    uint64_t id;
    int xstats_no;
    const char *name;

    /* Retrieving all XSTATS names. If something will go wrong
     * or amount of counters will be equal 0, rte_xstats_names
     * buffer will be marked as NULL, and any further xstats
     * query won't be performed (e.g. during netdev_dpdk_get_stats
     * execution). */

    ret = false;
    rte_xstats = NULL;

    if (dev->rte_xstats_names == NULL || dev->rte_xstats_ids == NULL) {
        dev->rte_xstats_names_size =
                rte_eth_xstats_get_names(dev->port_id, NULL, 0);

        if (dev->rte_xstats_names_size < 0) {
            VLOG_WARN("Cannot get XSTATS for port: "DPDK_PORT_ID_FMT,
                      dev->port_id);
            dev->rte_xstats_names_size = 0;
        } else {
            /* Reserve memory for xstats names and values */
            dev->rte_xstats_names = xcalloc(dev->rte_xstats_names_size,
                                            sizeof *dev->rte_xstats_names);

            if (dev->rte_xstats_names) {
                /* Retreive xstats names */
                rte_xstats_len =
                        rte_eth_xstats_get_names(dev->port_id,
                                                 dev->rte_xstats_names,
                                                 dev->rte_xstats_names_size);

                if (rte_xstats_len < 0) {
                    VLOG_WARN("Cannot get XSTATS names for port: "
                              DPDK_PORT_ID_FMT, dev->port_id);
                    goto out;
                } else if (rte_xstats_len != dev->rte_xstats_names_size) {
                    VLOG_WARN("XSTATS size doesn't match for port: "
                              DPDK_PORT_ID_FMT, dev->port_id);
                    goto out;
                }

                dev->rte_xstats_ids = xcalloc(dev->rte_xstats_names_size,
                                              sizeof(uint64_t));

                /* We have to calculate number of counters */
                rte_xstats = xmalloc(rte_xstats_len * sizeof *rte_xstats);
                memset(rte_xstats, 0xff, sizeof *rte_xstats * rte_xstats_len);

                /* Retreive xstats values */
                if (rte_eth_xstats_get(dev->port_id, rte_xstats,
                                       rte_xstats_len) > 0) {
                    dev->rte_xstats_ids_size = 0;
                    xstats_no = 0;
                    for (uint32_t i = 0; i < rte_xstats_len; i++) {
                        id = rte_xstats[i].id;
                        name = netdev_dpdk_get_xstat_name(dev, id);
                        /* We need to filter out everything except
                         * dropped, error and management counters */
                        if (string_ends_with(name, "_errors") ||
                            strstr(name, "_management_") ||
                            string_ends_with(name, "_dropped")) {

                            dev->rte_xstats_ids[xstats_no] = id;
                            xstats_no++;
                        }
                    }
                    dev->rte_xstats_ids_size = xstats_no;
                    ret = true;
                } else {
                    VLOG_WARN("Can't get XSTATS IDs for port: "
                              DPDK_PORT_ID_FMT, dev->port_id);
                }

                free(rte_xstats);
            }
        }
    } else {
        /* Already configured */
        ret = true;
    }

out:
    if (!ret) {
        netdev_dpdk_clear_xstats(dev);
    }
    return ret;
}

static int
netdev_dpdk_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    smap_add_format(args, "requested_rx_queues", "%d", dev->requested_n_rxq);
    smap_add_format(args, "configured_rx_queues", "%d", netdev->n_rxq);
    smap_add_format(args, "requested_tx_queues", "%d", dev->requested_n_txq);
    smap_add_format(args, "configured_tx_queues", "%d", netdev->n_txq);
    smap_add_format(args, "mtu", "%d", dev->mtu);

    if (dev->type == DPDK_DEV_ETH) {
        smap_add_format(args, "requested_rxq_descriptors", "%d",
                        dev->requested_rxq_size);
        smap_add_format(args, "configured_rxq_descriptors", "%d",
                        dev->rxq_size);
        smap_add_format(args, "requested_txq_descriptors", "%d",
                        dev->requested_txq_size);
        smap_add_format(args, "configured_txq_descriptors", "%d",
                        dev->txq_size);
        if (dev->hw_ol_features & NETDEV_RX_CHECKSUM_OFFLOAD) {
            smap_add(args, "rx_csum_offload", "true");
        } else {
            smap_add(args, "rx_csum_offload", "false");
        }
        smap_add(args, "lsc_interrupt_mode",
                 dev->lsc_interrupt_mode ? "true" : "false");
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
        struct ether_addr ea;

        rte_eth_macaddr_get(port_id, &ea);
        memcpy(port_mac.ea, ea.addr_bytes, ETH_ADDR_LEN);
        if (eth_addr_equals(mac, port_mac)) {
            return port_id;
        }
    }

    return DPDK_ETH_PORT_ID_INVALID;
}

/*
 * Normally, a PCI id is enough for identifying a specific DPDK port.
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
{
    char *name;
    dpdk_port_t new_port_id = DPDK_ETH_PORT_ID_INVALID;

    if (strncmp(devargs, "class=eth,mac=", 14) == 0) {
        new_port_id = netdev_dpdk_get_port_by_mac(&devargs[14]);
    } else {
        name = xmemdup0(devargs, strcspn(devargs, ","));
        if (rte_eth_dev_get_port_by_name(name, &new_port_id)
                || !rte_eth_dev_is_valid_port(new_port_id)) {
            /* Device not found in DPDK, attempt to attach it */
            if (!rte_eth_dev_attach(devargs, &new_port_id)) {
                /* Attach successful */
                dev->attached = true;
                VLOG_INFO("Device '%s' attached to DPDK", devargs);
            } else {
                /* Attach unsuccessful */
                new_port_id = DPDK_ETH_PORT_ID_INVALID;
            }
        }
        free(name);
    }

    if (new_port_id == DPDK_ETH_PORT_ID_INVALID) {
        VLOG_WARN_BUF(errp, "Error attaching device '%s' to DPDK", devargs);
    }

    return new_port_id;
}

static void
dpdk_set_rxq_config(struct netdev_dpdk *dev, const struct smap *args)
    OVS_REQUIRES(dev->mutex)
{
    int new_n_rxq;

    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq != dev->requested_n_rxq) {
        dev->requested_n_rxq = new_n_rxq;
        netdev_request_reconfigure(&dev->up);
    }
}

static void
dpdk_process_queue_size(struct netdev *netdev, const struct smap *args,
                        const char *flag, int default_size, int *new_size)
{
    int queue_size = smap_get_int(args, flag, default_size);

    if (queue_size <= 0 || queue_size > NIC_PORT_MAX_Q_SIZE
            || !is_pow2(queue_size)) {
        queue_size = default_size;
    }

    if (queue_size != *new_size) {
        *new_size = queue_size;
        netdev_request_reconfigure(netdev);
    }
}

static int
netdev_dpdk_set_config(struct netdev *netdev, const struct smap *args,
                       char **errp)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    bool rx_fc_en, tx_fc_en, autoneg, lsc_interrupt_mode;
    enum rte_eth_fc_mode fc_mode;
    static const enum rte_eth_fc_mode fc_mode_set[2][2] = {
        {RTE_FC_NONE,     RTE_FC_TX_PAUSE},
        {RTE_FC_RX_PAUSE, RTE_FC_FULL    }
    };
    const char *new_devargs;
    int err = 0;

    ovs_mutex_lock(&dpdk_mutex);
    ovs_mutex_lock(&dev->mutex);

    dpdk_set_rxq_config(dev, args);

    dpdk_process_queue_size(netdev, args, "n_rxq_desc",
                            NIC_PORT_DEFAULT_RXQ_SIZE,
                            &dev->requested_rxq_size);
    dpdk_process_queue_size(netdev, args, "n_txq_desc",
                            NIC_PORT_DEFAULT_TXQ_SIZE,
                            &dev->requested_txq_size);

    new_devargs = smap_get(args, "dpdk-devargs");

    if (dev->devargs && strcmp(new_devargs, dev->devargs)) {
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
                    netdev_dpdk_clear_xstats(dev);
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

    lsc_interrupt_mode = smap_get_bool(args, "dpdk-lsc-interrupt", false);
    if (dev->requested_lsc_interrupt_mode != lsc_interrupt_mode) {
        dev->requested_lsc_interrupt_mode = lsc_interrupt_mode;
        netdev_request_reconfigure(netdev);
    }

    rx_fc_en = smap_get_bool(args, "rx-flow-ctrl", false);
    tx_fc_en = smap_get_bool(args, "tx-flow-ctrl", false);
    autoneg = smap_get_bool(args, "flow-ctrl-autoneg", false);

    fc_mode = fc_mode_set[tx_fc_en][rx_fc_en];
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
netdev_dpdk_ring_set_config(struct netdev *netdev, const struct smap *args,
                            char **errp OVS_UNUSED)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    dpdk_set_rxq_config(dev, args);
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

    ovs_mutex_lock(&dev->mutex);
    if (!(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)) {
        path = smap_get(args, "vhost-server-path");
        if (path && strcmp(path, dev->vhost_id)) {
            strcpy(dev->vhost_id, path);
            /* check zero copy configuration */
            if (smap_get_bool(args, "dq-zero-copy", false)) {
                dev->vhost_driver_flags |= RTE_VHOST_USER_DEQUEUE_ZERO_COPY;
            } else {
                dev->vhost_driver_flags &= ~RTE_VHOST_USER_DEQUEUE_ZERO_COPY;
            }
            netdev_request_reconfigure(netdev);
        }
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

/* Tries to transmit 'pkts' to txq 'qid' of device 'dev'.  Takes ownership of
 * 'pkts', even in case of failure.
 *
 * Returns the number of packets that weren't transmitted. */
static inline int
netdev_dpdk_eth_tx_burst(struct netdev_dpdk *dev, int qid,
                         struct rte_mbuf **pkts, int cnt)
{
    uint32_t nb_tx = 0;

    while (nb_tx != cnt) {
        uint32_t ret;

        ret = rte_eth_tx_burst(dev->port_id, qid, pkts + nb_tx, cnt - nb_tx);
        if (!ret) {
            break;
        }

        nb_tx += ret;
    }

    if (OVS_UNLIKELY(nb_tx != cnt)) {
        /* Free buffers, which we couldn't transmit, one at a time (each
         * packet could come from a different mempool) */
        int i;

        for (i = nb_tx; i < cnt; i++) {
            rte_pktmbuf_free(pkts[i]);
        }
    }

    return cnt - nb_tx;
}

static inline bool
netdev_dpdk_policer_pkt_handle(struct rte_meter_srtcm *meter,
                               struct rte_mbuf *pkt, uint64_t time)
{
    uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct ether_hdr);

    return rte_meter_srtcm_color_blind_check(meter, time, pkt_len) ==
                                                e_RTE_METER_GREEN;
}

static int
netdev_dpdk_policer_run(struct rte_meter_srtcm *meter,
                        struct rte_mbuf **pkts, int pkt_cnt,
                        bool may_steal)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt = NULL;
    uint64_t current_time = rte_rdtsc();

    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        /* Handle current packet */
        if (netdev_dpdk_policer_pkt_handle(meter, pkt, current_time)) {
            if (cnt != i) {
                pkts[cnt] = pkt;
            }
            cnt++;
        } else {
            if (may_steal) {
                rte_pktmbuf_free(pkt);
            }
        }
    }

    return cnt;
}

static int
ingress_policer_run(struct ingress_policer *policer, struct rte_mbuf **pkts,
                    int pkt_cnt, bool may_steal)
{
    int cnt = 0;

    rte_spinlock_lock(&policer->policer_lock);
    cnt = netdev_dpdk_policer_run(&policer->in_policer, pkts,
                                  pkt_cnt, may_steal);
    rte_spinlock_unlock(&policer->policer_lock);

    return cnt;
}

static bool
is_vhost_running(struct netdev_dpdk *dev)
{
    return (netdev_dpdk_get_vid(dev) >= 0 && dev->vhost_reconfigured);
}

static inline void
netdev_dpdk_vhost_update_rx_size_counters(struct netdev_stats *stats,
                                          unsigned int packet_size)
{
    /* Hard-coded search for the size bucket. */
    if (packet_size < 256) {
        if (packet_size >= 128) {
            stats->rx_128_to_255_packets++;
        } else if (packet_size <= 64) {
            stats->rx_1_to_64_packets++;
        } else {
            stats->rx_65_to_127_packets++;
        }
    } else {
        if (packet_size >= 1523) {
            stats->rx_1523_to_max_packets++;
        } else if (packet_size >= 1024) {
            stats->rx_1024_to_1522_packets++;
        } else if (packet_size < 512) {
            stats->rx_256_to_511_packets++;
        } else {
            stats->rx_512_to_1023_packets++;
        }
    }
}

static inline void
netdev_dpdk_vhost_update_rx_counters(struct netdev_stats *stats,
                                     struct dp_packet **packets, int count,
                                     int dropped)
{
    int i;
    unsigned int packet_size;
    struct dp_packet *packet;

    stats->rx_packets += count;
    stats->rx_dropped += dropped;
    for (i = 0; i < count; i++) {
        packet = packets[i];
        packet_size = dp_packet_size(packet);

        if (OVS_UNLIKELY(packet_size < ETH_HEADER_LEN)) {
            /* This only protects the following multicast counting from
             * too short packets, but it does not stop the packet from
             * further processing. */
            stats->rx_errors++;
            stats->rx_length_errors++;
            continue;
        }

        netdev_dpdk_vhost_update_rx_size_counters(stats, packet_size);

        struct eth_header *eh = (struct eth_header *) dp_packet_data(packet);
        if (OVS_UNLIKELY(eth_addr_is_multicast(eh->eth_dst))) {
            stats->multicast++;
        }

        stats->rx_bytes += packet_size;
    }
}

/*
 * The receive path for the vhost port is the TX path out from guest.
 */
static int
netdev_dpdk_vhost_rxq_recv(struct netdev_rxq *rxq,
                           struct dp_packet_batch *batch)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(rxq->netdev);
    struct ingress_policer *policer = netdev_dpdk_get_ingress_policer(dev);
    uint16_t nb_rx = 0;
    uint16_t dropped = 0;
    int qid = rxq->queue_id;
    int vid = netdev_dpdk_get_vid(dev);

    if (OVS_UNLIKELY(vid < 0 || !dev->vhost_reconfigured
                     || !(dev->flags & NETDEV_UP))) {
        return EAGAIN;
    }

    nb_rx = rte_vhost_dequeue_burst(vid, qid * VIRTIO_QNUM + VIRTIO_TXQ,
                                    dev->dpdk_mp->mp,
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

    rte_spinlock_lock(&dev->stats_lock);
    netdev_dpdk_vhost_update_rx_counters(&dev->stats, batch->packets,
                                         nb_rx, dropped);
    rte_spinlock_unlock(&dev->stats_lock);

    batch->count = nb_rx;
    dp_packet_batch_init_packet_fields(batch);

    return 0;
}

static int
netdev_dpdk_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch)
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
        rte_spinlock_unlock(&dev->stats_lock);
    }

    batch->count = nb_rx;
    dp_packet_batch_init_packet_fields(batch);

    return 0;
}

static inline int
netdev_dpdk_qos_run(struct netdev_dpdk *dev, struct rte_mbuf **pkts,
                    int cnt, bool may_steal)
{
    struct qos_conf *qos_conf = ovsrcu_get(struct qos_conf *, &dev->qos_conf);

    if (qos_conf) {
        rte_spinlock_lock(&qos_conf->lock);
        cnt = qos_conf->ops->qos_run(qos_conf, pkts, cnt, may_steal);
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

    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (OVS_UNLIKELY(pkt->pkt_len > dev->max_packet_len)) {
            VLOG_WARN_RL(&rl, "%s: Too big size %" PRIu32 " max_packet_len %d",
                         dev->up.name, pkt->pkt_len, dev->max_packet_len);
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

static inline void
netdev_dpdk_vhost_update_tx_counters(struct netdev_stats *stats,
                                     struct dp_packet **packets,
                                     int attempted,
                                     int dropped)
{
    int i;
    int sent = attempted - dropped;

    stats->tx_packets += sent;
    stats->tx_dropped += dropped;

    for (i = 0; i < sent; i++) {
        stats->tx_bytes += dp_packet_size(packets[i]);
    }
}

static void
__netdev_dpdk_vhost_send(struct netdev *netdev, int qid,
                         struct dp_packet **pkts, int cnt)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_mbuf **cur_pkts = (struct rte_mbuf **) pkts;
    unsigned int total_pkts = cnt;
    unsigned int dropped = 0;
    int i, retries = 0;
    int vid = netdev_dpdk_get_vid(dev);

    qid = dev->tx_q[qid % netdev->n_txq].map;

    if (OVS_UNLIKELY(vid < 0 || !dev->vhost_reconfigured || qid < 0
                     || !(dev->flags & NETDEV_UP))) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped+= cnt;
        rte_spinlock_unlock(&dev->stats_lock);
        goto out;
    }

    rte_spinlock_lock(&dev->tx_q[qid].tx_lock);

    cnt = netdev_dpdk_filter_packet_len(dev, cur_pkts, cnt);
    /* Check has QoS has been configured for the netdev */
    cnt = netdev_dpdk_qos_run(dev, cur_pkts, cnt, true);
    dropped = total_pkts - cnt;

    do {
        int vhost_qid = qid * VIRTIO_QNUM + VIRTIO_RXQ;
        unsigned int tx_pkts;

        tx_pkts = rte_vhost_enqueue_burst(vid, vhost_qid, cur_pkts, cnt);
        if (OVS_LIKELY(tx_pkts)) {
            /* Packets have been sent.*/
            cnt -= tx_pkts;
            /* Prepare for possible retry.*/
            cur_pkts = &cur_pkts[tx_pkts];
        } else {
            /* No packets sent - do not retry.*/
            break;
        }
    } while (cnt && (retries++ <= VHOST_ENQ_RETRY_NUM));

    rte_spinlock_unlock(&dev->tx_q[qid].tx_lock);

    rte_spinlock_lock(&dev->stats_lock);
    netdev_dpdk_vhost_update_tx_counters(&dev->stats, pkts, total_pkts,
                                         cnt + dropped);
    rte_spinlock_unlock(&dev->stats_lock);

out:
    for (i = 0; i < total_pkts - dropped; i++) {
        dp_packet_delete(pkts[i]);
    }
}

/* Tx function. Transmit packets indefinitely */
static void
dpdk_do_tx_copy(struct netdev *netdev, int qid, struct dp_packet_batch *batch)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    const size_t batch_cnt = dp_packet_batch_size(batch);
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = batch_cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_mbuf *pkts[PKT_ARRAY_SIZE];
    uint32_t cnt = batch_cnt;
    uint32_t dropped = 0;

    if (dev->type != DPDK_DEV_VHOST) {
        /* Check if QoS has been configured for this netdev. */
        cnt = netdev_dpdk_qos_run(dev, (struct rte_mbuf **) batch->packets,
                                  batch_cnt, false);
        dropped += batch_cnt - cnt;
    }

    uint32_t txcnt = 0;

    for (uint32_t i = 0; i < cnt; i++) {
        struct dp_packet *packet = batch->packets[i];
        uint32_t size = dp_packet_size(packet);

        if (OVS_UNLIKELY(size > dev->max_packet_len)) {
            VLOG_WARN_RL(&rl, "Too big size %u max_packet_len %d",
                         size, dev->max_packet_len);

            dropped++;
            continue;
        }

        pkts[txcnt] = rte_pktmbuf_alloc(dev->dpdk_mp->mp);
        if (OVS_UNLIKELY(!pkts[txcnt])) {
            dropped += cnt - i;
            break;
        }

        /* We have to do a copy for now */
        memcpy(rte_pktmbuf_mtod(pkts[txcnt], void *),
               dp_packet_data(packet), size);
        dp_packet_set_size((struct dp_packet *)pkts[txcnt], size);

        txcnt++;
    }

    if (OVS_LIKELY(txcnt)) {
        if (dev->type == DPDK_DEV_VHOST) {
            __netdev_dpdk_vhost_send(netdev, qid, (struct dp_packet **) pkts,
                                     txcnt);
        } else {
            dropped += netdev_dpdk_eth_tx_burst(dev, qid, pkts, txcnt);
        }
    }

    if (OVS_UNLIKELY(dropped)) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += dropped;
        rte_spinlock_unlock(&dev->stats_lock);
    }
}

static int
netdev_dpdk_vhost_send(struct netdev *netdev, int qid,
                       struct dp_packet_batch *batch,
                       bool concurrent_txq OVS_UNUSED)
{

    if (OVS_UNLIKELY(batch->packets[0]->source != DPBUF_DPDK)) {
        dpdk_do_tx_copy(netdev, qid, batch);
        dp_packet_delete_batch(batch, true);
    } else {
        __netdev_dpdk_vhost_send(netdev, qid, batch->packets, batch->count);
    }
    return 0;
}

static inline void
netdev_dpdk_send__(struct netdev_dpdk *dev, int qid,
                   struct dp_packet_batch *batch,
                   bool concurrent_txq)
{
    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        dp_packet_delete_batch(batch, true);
        return;
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        qid = qid % dev->up.n_txq;
        rte_spinlock_lock(&dev->tx_q[qid].tx_lock);
    }

    if (OVS_UNLIKELY(batch->packets[0]->source != DPBUF_DPDK)) {
        struct netdev *netdev = &dev->up;

        dpdk_do_tx_copy(netdev, qid, batch);
        dp_packet_delete_batch(batch, true);
    } else {
        int tx_cnt, dropped;
        int batch_cnt = dp_packet_batch_size(batch);
        struct rte_mbuf **pkts = (struct rte_mbuf **) batch->packets;

        tx_cnt = netdev_dpdk_filter_packet_len(dev, pkts, batch_cnt);
        tx_cnt = netdev_dpdk_qos_run(dev, pkts, tx_cnt, true);
        dropped = batch_cnt - tx_cnt;

        dropped += netdev_dpdk_eth_tx_burst(dev, qid, pkts, tx_cnt);

        if (OVS_UNLIKELY(dropped)) {
            rte_spinlock_lock(&dev->stats_lock);
            dev->stats.tx_dropped += dropped;
            rte_spinlock_unlock(&dev->stats_lock);
        }
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        rte_spinlock_unlock(&dev->tx_q[qid].tx_lock);
    }
}

static int
netdev_dpdk_eth_send(struct netdev *netdev, int qid,
                     struct dp_packet_batch *batch, bool concurrent_txq)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    netdev_dpdk_send__(dev, qid, batch, concurrent_txq);
    return 0;
}

static int
netdev_dpdk_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        dev->hwaddr = mac;
        netdev_change_seq_changed(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
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
        || mtu < ETHER_MIN_MTU) {
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
netdev_dpdk_get_carrier(const struct netdev *netdev, bool *carrier);

static int
netdev_dpdk_vhost_get_stats(const struct netdev *netdev,
                            struct netdev_stats *stats)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    rte_spinlock_lock(&dev->stats_lock);
    /* Supported Stats */
    stats->rx_packets = dev->stats.rx_packets;
    stats->tx_packets = dev->stats.tx_packets;
    stats->rx_dropped = dev->stats.rx_dropped;
    stats->tx_dropped = dev->stats.tx_dropped;
    stats->multicast = dev->stats.multicast;
    stats->rx_bytes = dev->stats.rx_bytes;
    stats->tx_bytes = dev->stats.tx_bytes;
    stats->rx_errors = dev->stats.rx_errors;
    stats->rx_length_errors = dev->stats.rx_length_errors;

    stats->rx_1_to_64_packets = dev->stats.rx_1_to_64_packets;
    stats->rx_65_to_127_packets = dev->stats.rx_65_to_127_packets;
    stats->rx_128_to_255_packets = dev->stats.rx_128_to_255_packets;
    stats->rx_256_to_511_packets = dev->stats.rx_256_to_511_packets;
    stats->rx_512_to_1023_packets = dev->stats.rx_512_to_1023_packets;
    stats->rx_1024_to_1522_packets = dev->stats.rx_1024_to_1522_packets;
    stats->rx_1523_to_max_packets = dev->stats.rx_1523_to_max_packets;

    rte_spinlock_unlock(&dev->stats_lock);

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static void
netdev_dpdk_convert_xstats(struct netdev_stats *stats,
                           const struct rte_eth_xstat *xstats,
                           const struct rte_eth_xstat_name *names,
                           const unsigned int size)
{
    for (unsigned int i = 0; i < size; i++) {
        if (strcmp(XSTAT_RX_64_PACKETS, names[i].name) == 0) {
            stats->rx_1_to_64_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_65_TO_127_PACKETS, names[i].name) == 0) {
            stats->rx_65_to_127_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_128_TO_255_PACKETS, names[i].name) == 0) {
            stats->rx_128_to_255_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_256_TO_511_PACKETS, names[i].name) == 0) {
            stats->rx_256_to_511_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_512_TO_1023_PACKETS, names[i].name) == 0) {
            stats->rx_512_to_1023_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_1024_TO_1522_PACKETS, names[i].name) == 0) {
            stats->rx_1024_to_1522_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_1523_TO_MAX_PACKETS, names[i].name) == 0) {
            stats->rx_1523_to_max_packets = xstats[i].value;
        } else if (strcmp(XSTAT_TX_64_PACKETS, names[i].name) == 0) {
            stats->tx_1_to_64_packets = xstats[i].value;
        } else if (strcmp(XSTAT_TX_65_TO_127_PACKETS, names[i].name) == 0) {
            stats->tx_65_to_127_packets = xstats[i].value;
        } else if (strcmp(XSTAT_TX_128_TO_255_PACKETS, names[i].name) == 0) {
            stats->tx_128_to_255_packets = xstats[i].value;
        } else if (strcmp(XSTAT_TX_256_TO_511_PACKETS, names[i].name) == 0) {
            stats->tx_256_to_511_packets = xstats[i].value;
        } else if (strcmp(XSTAT_TX_512_TO_1023_PACKETS, names[i].name) == 0) {
            stats->tx_512_to_1023_packets = xstats[i].value;
        } else if (strcmp(XSTAT_TX_1024_TO_1522_PACKETS, names[i].name) == 0) {
            stats->tx_1024_to_1522_packets = xstats[i].value;
        } else if (strcmp(XSTAT_TX_1523_TO_MAX_PACKETS, names[i].name) == 0) {
            stats->tx_1523_to_max_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_MULTICAST_PACKETS, names[i].name) == 0) {
            stats->multicast = xstats[i].value;
        } else if (strcmp(XSTAT_TX_MULTICAST_PACKETS, names[i].name) == 0) {
            stats->tx_multicast_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_BROADCAST_PACKETS, names[i].name) == 0) {
            stats->rx_broadcast_packets = xstats[i].value;
        } else if (strcmp(XSTAT_TX_BROADCAST_PACKETS, names[i].name) == 0) {
            stats->tx_broadcast_packets = xstats[i].value;
        } else if (strcmp(XSTAT_RX_UNDERSIZED_ERRORS, names[i].name) == 0) {
            stats->rx_undersized_errors = xstats[i].value;
        } else if (strcmp(XSTAT_RX_FRAGMENTED_ERRORS, names[i].name) == 0) {
            stats->rx_fragmented_errors = xstats[i].value;
        } else if (strcmp(XSTAT_RX_JABBER_ERRORS, names[i].name) == 0) {
            stats->rx_jabber_errors = xstats[i].value;
        }
    }
}

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
    int rte_xstats_ret;

    ovs_mutex_lock(&dev->mutex);

    if (netdev_dpdk_configure_xstats(dev)) {
        uint64_t *values = xcalloc(dev->rte_xstats_ids_size,
                                   sizeof(uint64_t));

        rte_xstats_ret =
                rte_eth_xstats_get_by_id(dev->port_id, dev->rte_xstats_ids,
                                         values, dev->rte_xstats_ids_size);

        if (rte_xstats_ret > 0 &&
            rte_xstats_ret <= dev->rte_xstats_ids_size) {

            custom_stats->size = rte_xstats_ret;
            custom_stats->counters =
                    (struct netdev_custom_counter *) xcalloc(rte_xstats_ret,
                            sizeof(struct netdev_custom_counter));

            for (i = 0; i < rte_xstats_ret; i++) {
                ovs_strlcpy(custom_stats->counters[i].name,
                            netdev_dpdk_get_xstat_name(dev,
                                                       dev->rte_xstats_ids[i]),
                            NETDEV_CUSTOM_STATS_NAME_SIZE);
                custom_stats->counters[i].value = values[i];
            }
        } else {
            VLOG_WARN("Cannot get XSTATS values for port: "DPDK_PORT_ID_FMT,
                      dev->port_id);
            custom_stats->counters = NULL;
            custom_stats->size = 0;
            /* Let's clear statistics cache, so it will be
             * reconfigured */
            netdev_dpdk_clear_xstats(dev);
        }

        free(values);
    }

    ovs_mutex_unlock(&dev->mutex);

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

    ovs_mutex_lock(&dev->mutex);
    link = dev->link;
    ovs_mutex_unlock(&dev->mutex);

    if (link.link_duplex == ETH_LINK_HALF_DUPLEX) {
        if (link.link_speed == ETH_SPEED_NUM_10M) {
            *current = NETDEV_F_10MB_HD;
        }
        if (link.link_speed == ETH_SPEED_NUM_100M) {
            *current = NETDEV_F_100MB_HD;
        }
        if (link.link_speed == ETH_SPEED_NUM_1G) {
            *current = NETDEV_F_1GB_HD;
        }
    } else if (link.link_duplex == ETH_LINK_FULL_DUPLEX) {
        if (link.link_speed == ETH_SPEED_NUM_10M) {
            *current = NETDEV_F_10MB_FD;
        }
        if (link.link_speed == ETH_SPEED_NUM_100M) {
            *current = NETDEV_F_100MB_FD;
        }
        if (link.link_speed == ETH_SPEED_NUM_1G) {
            *current = NETDEV_F_1GB_FD;
        }
        if (link.link_speed == ETH_SPEED_NUM_10G) {
            *current = NETDEV_F_10GB_FD;
        }
    }

    if (link.link_autoneg) {
        *current |= NETDEV_F_AUTONEG;
    }

    *advertised = *supported = *peer = 0;

    return 0;
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
    err = rte_meter_srtcm_config(&policer->in_policer,
                                    &policer->app_srtcm_params);
    if (err) {
        VLOG_ERR("Could not create rte meter for ingress policer");
        free(policer);
        return NULL;
    }

    return policer;
}

static int
netdev_dpdk_set_policing(struct netdev* netdev, uint32_t policer_rate,
                         uint32_t policer_burst)
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
        char vhost_vring[16];

        rte_vhost_get_vhost_vring(vid, i, &vring);
        snprintf(vhost_vring, 16, "vring_%d_size", i);
        smap_add_format(args, vhost_vring, "%d", vring.size);
    }

    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

static int
netdev_dpdk_get_status(const struct netdev *netdev, struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(dev->port_id)) {
        return ENODEV;
    }

    ovs_mutex_lock(&dev->mutex);
    rte_eth_dev_info_get(dev->port_id, &dev_info);
    ovs_mutex_unlock(&dev->mutex);

    smap_add_format(args, "port_no", DPDK_PORT_ID_FMT, dev->port_id);
    smap_add_format(args, "numa_id", "%d",
                           rte_eth_dev_socket_id(dev->port_id));
    smap_add_format(args, "driver_name", "%s", dev_info.driver_name);
    smap_add_format(args, "min_rx_bufsize", "%u", dev_info.min_rx_bufsize);
    smap_add_format(args, "max_rx_pktlen", "%u", dev->max_packet_len);
    smap_add_format(args, "max_rx_queues", "%u", dev_info.max_rx_queues);
    smap_add_format(args, "max_tx_queues", "%u", dev_info.max_tx_queues);
    smap_add_format(args, "max_mac_addrs", "%u", dev_info.max_mac_addrs);
    smap_add_format(args, "max_hash_mac_addrs", "%u",
                           dev_info.max_hash_mac_addrs);
    smap_add_format(args, "max_vfs", "%u", dev_info.max_vfs);
    smap_add_format(args, "max_vmdq_pools", "%u", dev_info.max_vmdq_pools);

    /* Querying the DPDK library for iftype may be done in future, pending
     * support; cf. RFC 3635 Section 3.2.4. */
    enum { IF_TYPE_ETHERNETCSMACD = 6 };

    smap_add_format(args, "if_type", "%"PRIu32, IF_TYPE_ETHERNETCSMACD);
    smap_add_format(args, "if_descr", "%s %s", rte_version(),
                                               dev_info.driver_name);

    if (dev_info.pci_dev) {
        smap_add_format(args, "pci-vendor_id", "0x%u",
                        dev_info.pci_dev->id.vendor_id);
        smap_add_format(args, "pci-device_id", "0x%x",
                        dev_info.pci_dev->id.device_id);
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
    int ret;
    char *response;
    dpdk_port_t port_id;
    char devname[RTE_ETH_NAME_MAX_LEN];
    struct netdev_dpdk *dev;

    ovs_mutex_lock(&dpdk_mutex);

    if (rte_eth_dev_get_port_by_name(argv[1], &port_id)) {
        response = xasprintf("Device '%s' not found in DPDK", argv[1]);
        goto error;
    }

    dev = netdev_dpdk_lookup_by_port_id(port_id);
    if (dev) {
        response = xasprintf("Device '%s' is being used by interface '%s'. "
                             "Remove it before detaching",
                             argv[1], netdev_get_name(&dev->up));
        goto error;
    }

    rte_eth_dev_close(port_id);

    ret = rte_eth_dev_detach(port_id, devname);
    if (ret < 0) {
        response = xasprintf("Device '%s' can not be detached", argv[1]);
        goto error;
    }

    response = xasprintf("Device '%s' has been detached", argv[1]);

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
    size_t size;
    FILE *stream;
    char *response = NULL;
    struct netdev *netdev = NULL;

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

        rte_mempool_dump(stream, dev->dpdk_mp->mp);

        ovs_mutex_unlock(&dpdk_mp_mutex);
        ovs_mutex_unlock(&dev->mutex);
    } else {
        ovs_mutex_lock(&dpdk_mp_mutex);
        rte_mempool_list_dump(stream);
        ovs_mutex_unlock(&dpdk_mp_mutex);
    }

    fclose(stream);

    unixctl_command_reply(conn, response);
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

    VLOG_DBG("TX queue mapping for %s\n", dev->vhost_id);
    for (i = 0; i < total_txqs; i++) {
        VLOG_DBG("%2d --> %2d", i, dev->tx_q[i].map);
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
        if (strncmp(ifname, dev->vhost_id, IF_NAME_SZ) == 0) {
            uint32_t qp_num = rte_vhost_get_vring_num(vid)/VIRTIO_QNUM;

            /* Get NUMA information */
            newnode = rte_vhost_get_numa_node(vid);
            if (newnode == -1) {
#ifdef VHOST_NUMA
                VLOG_INFO("Error getting NUMA info for vHost Device '%s'",
                          ifname);
#endif
                newnode = dev->socket_id;
            }

            if (dev->requested_n_txq != qp_num
                || dev->requested_n_rxq != qp_num
                || dev->requested_socket_id != newnode) {
                dev->requested_socket_id = newnode;
                dev->requested_n_rxq = qp_num;
                dev->requested_n_txq = qp_num;
                netdev_request_reconfigure(&dev->up);
            } else {
                /* Reconfiguration not required. */
                dev->vhost_reconfigured = true;
            }

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
            netdev_dpdk_txq_map_clear(dev);

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

static int
vring_state_changed(int vid, uint16_t queue_id, int enable)
{
    struct netdev_dpdk *dev;
    bool exists = false;
    int qid = queue_id / VIRTIO_QNUM;
    char ifname[IF_NAME_SZ];

    rte_vhost_get_ifname(vid, ifname, sizeof ifname);

    if (queue_id % VIRTIO_QNUM == VIRTIO_TXQ) {
        return 0;
    }

    ovs_mutex_lock(&dpdk_mutex);
    LIST_FOR_EACH (dev, list_node, &dpdk_list) {
        ovs_mutex_lock(&dev->mutex);
        if (strncmp(ifname, dev->vhost_id, IF_NAME_SZ) == 0) {
            if (enable) {
                dev->tx_q[qid].map = qid;
            } else {
                dev->tx_q[qid].map = OVS_VHOST_QUEUE_DISABLED;
            }
            netdev_dpdk_remap_txqs(dev);
            exists = true;
            ovs_mutex_unlock(&dev->mutex);
            break;
        }
        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dpdk_mutex);

    if (exists) {
        VLOG_INFO("State of queue %d ( tx_qid %d ) of vhost device '%s'"
                  "changed to \'%s\'", queue_id, qid, ifname,
                  (enable == 1) ? "enabled" : "disabled");
    } else {
        VLOG_INFO("vHost Device '%s' not found", ifname);
        return -1;
    }

    return 0;
}

int
netdev_dpdk_get_vid(const struct netdev_dpdk *dev)
{
    return ovsrcu_index_get(&dev->vid);
}

struct ingress_policer *
netdev_dpdk_get_ingress_policer(const struct netdev_dpdk *dev)
{
    return ovsrcu_get(struct ingress_policer *, &dev->ingress_policer);
}

static int
netdev_dpdk_class_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    /* This function can be called for different classes.  The initialization
     * needs to be done only once */
    if (ovsthread_once_start(&once)) {
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

        ovsthread_once_done(&once);
    }

    return 0;
}


/* Client Rings */

static int
dpdk_ring_create(const char dev_name[], unsigned int port_no,
                 dpdk_port_t *eth_port_id)
{
    struct dpdk_ring *ring_pair;
    char *ring_name;
    int port_id;

    ring_pair = dpdk_rte_mzalloc(sizeof *ring_pair);
    if (!ring_pair) {
        return ENOMEM;
    }

    /* XXX: Add support for multiquque ring. */
    ring_name = xasprintf("%s_tx", dev_name);

    /* Create single producer tx ring, netdev does explicit locking. */
    ring_pair->cring_tx = rte_ring_create(ring_name, DPDK_RING_SIZE, SOCKET0,
                                        RING_F_SP_ENQ);
    free(ring_name);
    if (ring_pair->cring_tx == NULL) {
        rte_free(ring_pair);
        return ENOMEM;
    }

    ring_name = xasprintf("%s_rx", dev_name);

    /* Create single consumer rx ring, netdev does explicit locking. */
    ring_pair->cring_rx = rte_ring_create(ring_name, DPDK_RING_SIZE, SOCKET0,
                                        RING_F_SC_DEQ);
    free(ring_name);
    if (ring_pair->cring_rx == NULL) {
        rte_free(ring_pair);
        return ENOMEM;
    }

    port_id = rte_eth_from_rings(dev_name, &ring_pair->cring_rx, 1,
                                 &ring_pair->cring_tx, 1, SOCKET0);

    if (port_id < 0) {
        rte_free(ring_pair);
        return ENODEV;
    }

    ring_pair->user_port_id = port_no;
    ring_pair->eth_port_id = port_id;
    *eth_port_id = port_id;

    ovs_list_push_back(&dpdk_ring_list, &ring_pair->list_node);

    return 0;
}

static int
dpdk_ring_open(const char dev_name[], dpdk_port_t *eth_port_id)
    OVS_REQUIRES(dpdk_mutex)
{
    struct dpdk_ring *ring_pair;
    unsigned int port_no;
    int err = 0;

    /* Names always start with "dpdkr" */
    err = dpdk_dev_parse_name(dev_name, "dpdkr", &port_no);
    if (err) {
        return err;
    }

    /* Look through our list to find the device */
    LIST_FOR_EACH (ring_pair, list_node, &dpdk_ring_list) {
         if (ring_pair->user_port_id == port_no) {
            VLOG_INFO("Found dpdk ring device %s:", dev_name);
            /* Really all that is needed */
            *eth_port_id = ring_pair->eth_port_id;
            return 0;
         }
    }
    /* Need to create the device rings */
    return dpdk_ring_create(dev_name, port_no, eth_port_id);
}

static int
netdev_dpdk_ring_send(struct netdev *netdev, int qid,
                      struct dp_packet_batch *batch, bool concurrent_txq)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct dp_packet *packet;

    /* When using 'dpdkr' and sending to a DPDK ring, we want to ensure that
     * the rss hash field is clear. This is because the same mbuf may be
     * modified by the consumer of the ring and return into the datapath
     * without recalculating the RSS hash. */
    DP_PACKET_BATCH_FOR_EACH (packet, batch) {
        dp_packet_mbuf_rss_flag_reset(packet);
    }

    netdev_dpdk_send__(dev, qid, batch, concurrent_txq);
    return 0;
}

static int
netdev_dpdk_ring_construct(struct netdev *netdev)
{
    dpdk_port_t port_no = 0;
    int err = 0;

    ovs_mutex_lock(&dpdk_mutex);

    err = dpdk_ring_open(netdev->name, &port_no);
    if (err) {
        goto unlock_dpdk;
    }

    err = common_construct(netdev, port_no, DPDK_DEV_ETH,
                           rte_eth_dev_socket_id(port_no));
unlock_dpdk:
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

/* QoS Functions */

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

/* egress-policer details */

struct egress_policer {
    struct qos_conf qos_conf;
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm egress_meter;
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
    err = rte_meter_srtcm_config(&policer->egress_meter,
                                 &policer->app_srtcm_params);
    if (!err) {
        *conf = &policer->qos_conf;
    } else {
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
                   bool may_steal)
{
    int cnt = 0;
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);

    cnt = netdev_dpdk_policer_run(&policer->egress_meter, pkts,
                                  pkt_cnt, may_steal);

    return cnt;
}

static const struct dpdk_qos_ops egress_policer_ops = {
    "egress-policer",    /* qos_name */
    egress_policer_qos_construct,
    egress_policer_qos_destruct,
    egress_policer_qos_get,
    egress_policer_qos_is_equal,
    egress_policer_run
};

static int
netdev_dpdk_reconfigure(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&dev->mutex);

    if (netdev->n_txq == dev->requested_n_txq
        && netdev->n_rxq == dev->requested_n_rxq
        && dev->mtu == dev->requested_mtu
        && dev->lsc_interrupt_mode == dev->requested_lsc_interrupt_mode
        && dev->rxq_size == dev->requested_rxq_size
        && dev->txq_size == dev->requested_txq_size
        && dev->socket_id == dev->requested_socket_id
        && dev->started) {
        /* Reconfiguration is unnecessary */

        goto out;
    }

    rte_eth_dev_stop(dev->port_id);
    dev->started = false;

    if (dev->mtu != dev->requested_mtu
        || dev->socket_id != dev->requested_socket_id) {
        err = netdev_dpdk_mempool_configure(dev);
        if (err) {
            goto out;
        }
    }

    dev->lsc_interrupt_mode = dev->requested_lsc_interrupt_mode;

    netdev->n_txq = dev->requested_n_txq;
    netdev->n_rxq = dev->requested_n_rxq;

    dev->rxq_size = dev->requested_rxq_size;
    dev->txq_size = dev->requested_txq_size;

    rte_free(dev->tx_q);
    err = dpdk_eth_dev_init(dev);
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
    int err;

    /* Enable TX queue 0 by default if it wasn't disabled. */
    if (dev->tx_q[0].map == OVS_VHOST_QUEUE_MAP_UNKNOWN) {
        dev->tx_q[0].map = 0;
    }

    netdev_dpdk_remap_txqs(dev);

    if (dev->requested_socket_id != dev->socket_id
        || dev->requested_mtu != dev->mtu) {
        err = netdev_dpdk_mempool_configure(dev);
        if (err) {
            return err;
        } else {
            netdev_change_seq_changed(&dev->up);
        }
    }

    if (netdev_dpdk_get_vid(dev) >= 0) {
        if (dev->vhost_reconfigured == false) {
            dev->vhost_reconfigured = true;
            /* Carrier status may need updating. */
            netdev_change_seq_changed(&dev->up);
        }
    }

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
    int err;
    uint64_t vhost_flags = 0;
    bool zc_enabled;

    ovs_mutex_lock(&dev->mutex);

    /* Configure vHost client mode if requested and if the following criteria
     * are met:
     *  1. Device hasn't been registered yet.
     *  2. A path has been specified.
     */
    if (!(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)
            && strlen(dev->vhost_id)) {
        /* Register client-mode device. */
        vhost_flags |= RTE_VHOST_USER_CLIENT;

        /* Enable IOMMU support, if explicitly requested. */
        if (dpdk_vhost_iommu_enabled()) {
            vhost_flags |= RTE_VHOST_USER_IOMMU_SUPPORT;
        }

        zc_enabled = dev->vhost_driver_flags
                     & RTE_VHOST_USER_DEQUEUE_ZERO_COPY;
        /* Enable zero copy flag, if requested */
        if (zc_enabled) {
            vhost_flags |= RTE_VHOST_USER_DEQUEUE_ZERO_COPY;
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
            if (zc_enabled) {
                VLOG_INFO("Zero copy enabled for vHost port %s", dev->up.name);
            }
        }

        err = rte_vhost_driver_callback_register(dev->vhost_id,
                                                 &virtio_net_device_ops);
        if (err) {
            VLOG_ERR("rte_vhost_driver_callback_register failed for "
                     "vhost user client port: %s\n", dev->up.name);
            goto unlock;
        }

        err = rte_vhost_driver_disable_features(dev->vhost_id,
                                    1ULL << VIRTIO_NET_F_HOST_TSO4
                                    | 1ULL << VIRTIO_NET_F_HOST_TSO6
                                    | 1ULL << VIRTIO_NET_F_CSUM);
        if (err) {
            VLOG_ERR("rte_vhost_driver_disable_features failed for vhost user "
                     "client port: %s\n", dev->up.name);
            goto unlock;
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

#define NETDEV_DPDK_CLASS(NAME, INIT, CONSTRUCT, DESTRUCT,    \
                          SET_CONFIG, SET_TX_MULTIQ, SEND,    \
                          GET_CARRIER, GET_STATS,			  \
                          GET_CUSTOM_STATS,					  \
                          GET_FEATURES, GET_STATUS,           \
                          RECONFIGURE, RXQ_RECV)              \
{                                                             \
    NAME,                                                     \
    true,                       /* is_pmd */                  \
    INIT,                       /* init */                    \
    NULL,                       /* netdev_dpdk_run */         \
    NULL,                       /* netdev_dpdk_wait */        \
                                                              \
    netdev_dpdk_alloc,                                        \
    CONSTRUCT,                                                \
    DESTRUCT,                                                 \
    netdev_dpdk_dealloc,                                      \
    netdev_dpdk_get_config,                                   \
    SET_CONFIG,                                               \
    NULL,                       /* get_tunnel_config */       \
    NULL,                       /* build header */            \
    NULL,                       /* push header */             \
    NULL,                       /* pop header */              \
    netdev_dpdk_get_numa_id,    /* get_numa_id */             \
    SET_TX_MULTIQ,                                            \
                                                              \
    SEND,                       /* send */                    \
    NULL,                       /* send_wait */               \
                                                              \
    netdev_dpdk_set_etheraddr,                                \
    netdev_dpdk_get_etheraddr,                                \
    netdev_dpdk_get_mtu,                                      \
    netdev_dpdk_set_mtu,                                      \
    netdev_dpdk_get_ifindex,                                  \
    GET_CARRIER,                                              \
    netdev_dpdk_get_carrier_resets,                           \
    netdev_dpdk_set_miimon,                                   \
    GET_STATS,                                                \
    GET_CUSTOM_STATS,										  \
    GET_FEATURES,                                             \
    NULL,                       /* set_advertisements */      \
    NULL,                       /* get_pt_mode */             \
                                                              \
    netdev_dpdk_set_policing,                                 \
    netdev_dpdk_get_qos_types,                                \
    NULL,                       /* get_qos_capabilities */    \
    netdev_dpdk_get_qos,                                      \
    netdev_dpdk_set_qos,                                      \
    NULL,                       /* get_queue */               \
    NULL,                       /* set_queue */               \
    NULL,                       /* delete_queue */            \
    NULL,                       /* get_queue_stats */         \
    NULL,                       /* queue_dump_start */        \
    NULL,                       /* queue_dump_next */         \
    NULL,                       /* queue_dump_done */         \
    NULL,                       /* dump_queue_stats */        \
                                                              \
    NULL,                       /* set_in4 */                 \
    NULL,                       /* get_addr_list */           \
    NULL,                       /* add_router */              \
    NULL,                       /* get_next_hop */            \
    GET_STATUS,                                               \
    NULL,                       /* arp_lookup */              \
                                                              \
    netdev_dpdk_update_flags,                                 \
    RECONFIGURE,                                              \
                                                              \
    netdev_dpdk_rxq_alloc,                                    \
    netdev_dpdk_rxq_construct,                                \
    netdev_dpdk_rxq_destruct,                                 \
    netdev_dpdk_rxq_dealloc,                                  \
    RXQ_RECV,                                                 \
    NULL,                       /* rx_wait */                 \
    NULL,                       /* rxq_drain */               \
    NO_OFFLOAD_API                                            \
}

static const struct netdev_class dpdk_class =
    NETDEV_DPDK_CLASS(
        "dpdk",
        netdev_dpdk_class_init,
        netdev_dpdk_construct,
        netdev_dpdk_destruct,
        netdev_dpdk_set_config,
        netdev_dpdk_set_tx_multiq,
        netdev_dpdk_eth_send,
        netdev_dpdk_get_carrier,
        netdev_dpdk_get_stats,
        netdev_dpdk_get_custom_stats,
        netdev_dpdk_get_features,
        netdev_dpdk_get_status,
        netdev_dpdk_reconfigure,
        netdev_dpdk_rxq_recv);

static const struct netdev_class dpdk_ring_class =
    NETDEV_DPDK_CLASS(
        "dpdkr",
        netdev_dpdk_class_init,
        netdev_dpdk_ring_construct,
        netdev_dpdk_destruct,
        netdev_dpdk_ring_set_config,
        netdev_dpdk_set_tx_multiq,
        netdev_dpdk_ring_send,
        netdev_dpdk_get_carrier,
        netdev_dpdk_get_stats,
        netdev_dpdk_get_custom_stats,
        netdev_dpdk_get_features,
        netdev_dpdk_get_status,
        netdev_dpdk_reconfigure,
        netdev_dpdk_rxq_recv);

static const struct netdev_class dpdk_vhost_class =
    NETDEV_DPDK_CLASS(
        "dpdkvhostuser",
        NULL,
        netdev_dpdk_vhost_construct,
        netdev_dpdk_vhost_destruct,
        NULL,
        NULL,
        netdev_dpdk_vhost_send,
        netdev_dpdk_vhost_get_carrier,
        netdev_dpdk_vhost_get_stats,
        NULL,
        NULL,
        netdev_dpdk_vhost_user_get_status,
        netdev_dpdk_vhost_reconfigure,
        netdev_dpdk_vhost_rxq_recv);
static const struct netdev_class dpdk_vhost_client_class =
    NETDEV_DPDK_CLASS(
        "dpdkvhostuserclient",
        NULL,
        netdev_dpdk_vhost_client_construct,
        netdev_dpdk_vhost_destruct,
        netdev_dpdk_vhost_client_set_config,
        NULL,
        netdev_dpdk_vhost_send,
        netdev_dpdk_vhost_get_carrier,
        netdev_dpdk_vhost_get_stats,
        NULL,
        NULL,
        netdev_dpdk_vhost_user_get_status,
        netdev_dpdk_vhost_client_reconfigure,
        netdev_dpdk_vhost_rxq_recv);

void
netdev_dpdk_register(void)
{
    netdev_register_provider(&dpdk_class);
    netdev_register_provider(&dpdk_ring_class);
    netdev_register_provider(&dpdk_vhost_class);
    netdev_register_provider(&dpdk_vhost_client_class);
}
