/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_meter.h>
#include <rte_virtio_net.h>

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
#define MBUF_SIZE(mtu)              (MTU_TO_MAX_FRAME_LEN(mtu)      \
                                     + sizeof(struct dp_packet)     \
                                     + RTE_PKTMBUF_HEADROOM)
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
BUILD_ASSERT_DECL(MAX_NB_MBUF % ROUND_DOWN_POW2(MAX_NB_MBUF/MIN_NB_MBUF) == 0);

/* The smallest possible NB_MBUF that we're going to try should be a multiple
 * of MP_CACHE_SZ. This is advised by DPDK documentation. */
BUILD_ASSERT_DECL((MAX_NB_MBUF / ROUND_DOWN_POW2(MAX_NB_MBUF/MIN_NB_MBUF))
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
                   int pkt_cnt);
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
    int eth_port_id; /* ethernet device port id */
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);
};

struct ingress_policer {
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm in_policer;
    rte_spinlock_t policer_lock;
};

struct netdev_dpdk {
    struct netdev up;
    int port_id;
    int max_packet_len;
    enum dpdk_dev_type type;

    struct dpdk_tx_queue *tx_q;

    struct ovs_mutex mutex OVS_ACQ_AFTER(dpdk_mutex);

    struct dpdk_mp *dpdk_mp;
    int mtu;
    int socket_id;
    int buf_size;
    struct netdev_stats stats;
    /* Protects stats */
    rte_spinlock_t stats_lock;

    struct eth_addr hwaddr;
    enum netdev_flags flags;

    struct rte_eth_link link;
    int link_reset_cnt;

    /* virtio identifier for vhost devices */
    ovsrcu_index vid;

    /* True if vHost device is 'up' and has been reconfigured at least once */
    bool vhost_reconfigured;

    /* Identifier used to distinguish vhost devices from each other. */
    char vhost_id[PATH_MAX];

    /* In dpdk_list. */
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);

    /* QoS configuration and lock for the device */
    OVSRCU_TYPE(struct qos_conf *) qos_conf;

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

    /* Ingress Policer */
    OVSRCU_TYPE(struct ingress_policer *) ingress_policer;
    uint32_t policer_rate;
    uint32_t policer_burst;

    /* DPDK-ETH Flow control */
    struct rte_eth_fc_conf fc_conf;
};

struct netdev_rxq_dpdk {
    struct netdev_rxq up;
    int port_id;
};

static int netdev_dpdk_class_init(void);
static int netdev_dpdk_vhost_class_init(void);

int netdev_dpdk_get_vid(const struct netdev_dpdk *dev);

struct ingress_policer *
netdev_dpdk_get_ingress_policer(const struct netdev_dpdk *dev);

static bool
is_dpdk_class(const struct netdev_class *class)
{
    return class->init == netdev_dpdk_class_init
           || class->init == netdev_dpdk_vhost_class_init;
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
ovs_rte_pktmbuf_init(struct rte_mempool *mp,
                     void *opaque_arg OVS_UNUSED,
                     void *_p,
                     unsigned i OVS_UNUSED)
{
    struct rte_mbuf *pkt = _p;

    rte_pktmbuf_init(mp, opaque_arg, _p, i);

    dp_packet_init_dpdk((struct dp_packet *) pkt, pkt->buf_len);
}

static struct dpdk_mp *
dpdk_mp_create(int socket_id, int mtu)
{
    struct rte_pktmbuf_pool_private mbp_priv;
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
    mbp_priv.mbuf_data_room_size = MBUF_SIZE(mtu) - sizeof(struct dp_packet);
    mbp_priv.mbuf_priv_size = sizeof(struct dp_packet)
                              - sizeof(struct rte_mbuf);
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

        dmp->mp = rte_mempool_create(mp_name, mp_size, MBUF_SIZE(mtu),
                                     MP_CACHE_SZ,
                                     sizeof(struct rte_pktmbuf_pool_private),
                                     rte_pktmbuf_pool_init, &mbp_priv,
                                     ovs_rte_pktmbuf_init, NULL,
                                     socket_id, 0);
        if (dmp->mp) {
            VLOG_DBG("Allocated \"%s\" mempool with %u mbufs",
                     mp_name, mp_size);
        }
        free(mp_name);
        if (dmp->mp) {
            return dmp;
        }
    } while (rte_errno == ENOMEM && (mp_size /= 2) >= MIN_NB_MBUF);

    rte_free(dmp);
    return NULL;
}

static struct dpdk_mp *
dpdk_mp_get(int socket_id, int mtu)
{
    struct dpdk_mp *dmp;

    ovs_mutex_lock(&dpdk_mp_mutex);
    LIST_FOR_EACH (dmp, list_node, &dpdk_mp_list) {
        if (dmp->socket_id == socket_id && dmp->mtu == mtu) {
            dmp->refcount++;
            goto out;
        }
    }

    dmp = dpdk_mp_create(socket_id, mtu);
    ovs_list_push_back(&dpdk_mp_list, &dmp->list_node);

out:
    ovs_mutex_unlock(&dpdk_mp_mutex);

    return dmp;
}

static void
dpdk_mp_put(struct dpdk_mp *dmp)
{
    if (!dmp) {
        return;
    }

    ovs_mutex_lock(&dpdk_mp_mutex);
    ovs_assert(dmp->refcount);

    if (!--dmp->refcount) {
        ovs_list_remove(&dmp->list_node);
        rte_mempool_free(dmp->mp);
        rte_free(dmp);
    }
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
        VLOG_ERR("Insufficient memory to create memory pool for netdev "
                 "%s, with MTU %d on socket %d\n",
                 dev->up.name, dev->requested_mtu, dev->requested_socket_id);
        return ENOMEM;
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
            VLOG_DBG_RL(&rl, "Port %d Link Up - speed %u Mbps - %s",
                        dev->port_id, (unsigned) dev->link.link_speed,
                        (dev->link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                         ("full-duplex") : ("half-duplex"));
        } else {
            VLOG_DBG_RL(&rl, "Port %d Link Down", dev->port_id);
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
dpdk_eth_dev_queue_setup(struct netdev_dpdk *dev, int n_rxq, int n_txq)
{
    int diag = 0;
    int i;
    struct rte_eth_conf conf = port_conf;

    if (dev->mtu > ETHER_MTU) {
        conf.rxmode.jumbo_frame = 1;
        conf.rxmode.max_rx_pkt_len = dev->max_packet_len;
    } else {
        conf.rxmode.jumbo_frame = 0;
        conf.rxmode.max_rx_pkt_len = 0;
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

        for (i = 0; i < n_txq; i++) {
            diag = rte_eth_tx_queue_setup(dev->port_id, i, dev->txq_size,
                                          dev->socket_id, NULL);
            if (diag) {
                VLOG_INFO("Interface %s txq(%d) setup error: %s",
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
                VLOG_INFO("Interface %s rxq(%d) setup error: %s",
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
        VLOG_WARN("Failed to enable flow control on device %d", dev->port_id);
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

    if (!rte_eth_dev_is_valid_port(dev->port_id)) {
        return ENODEV;
    }

    rte_eth_dev_info_get(dev->port_id, &info);

    n_rxq = MIN(info.max_rx_queues, dev->up.n_rxq);
    n_txq = MIN(info.max_tx_queues, dev->up.n_txq);

    diag = dpdk_eth_dev_queue_setup(dev, n_rxq, n_txq);
    if (diag) {
        VLOG_ERR("Interface %s(rxq:%d txq:%d) configure error: %s",
                 dev->up.name, n_rxq, n_txq, rte_strerror(-diag));
        return -diag;
    }

    diag = rte_eth_dev_start(dev->port_id);
    if (diag) {
        VLOG_ERR("Interface %s start error: %s", dev->up.name,
                 rte_strerror(-diag));
        return -diag;
    }

    rte_eth_promiscuous_enable(dev->port_id);
    rte_eth_allmulticast_enable(dev->port_id);

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(dev->port_id, &eth_addr);
    VLOG_INFO_RL(&rl, "Port %d: "ETH_ADDR_FMT"",
                    dev->port_id, ETH_ADDR_BYTES_ARGS(eth_addr.addr_bytes));

    memcpy(dev->hwaddr.ea, eth_addr.addr_bytes, ETH_ADDR_LEN);
    rte_eth_link_get_nowait(dev->port_id, &dev->link);

    mbp_priv = rte_mempool_get_priv(dev->dpdk_mp->mp);
    dev->buf_size = mbp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM;

    dev->flags = NETDEV_UP | NETDEV_PROMISC;

    /* Get the Flow control configuration for DPDK-ETH */
    diag = rte_eth_dev_flow_ctrl_get(dev->port_id, &dev->fc_conf);
    if (diag) {
        VLOG_DBG("cannot get flow control parameters on port=%d, err=%d",
                 dev->port_id, diag);
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
netdev_dpdk_init(struct netdev *netdev, unsigned int port_no,
                 enum dpdk_dev_type type)
    OVS_REQUIRES(dpdk_mutex)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int sid;
    int err = 0;

    ovs_mutex_init(&dev->mutex);
    ovs_mutex_lock(&dev->mutex);

    rte_spinlock_init(&dev->stats_lock);

    /* If the 'sid' is negative, it means that the kernel fails
     * to obtain the pci numa info.  In that situation, always
     * use 'SOCKET0'. */
    if (type == DPDK_DEV_ETH) {
        sid = rte_eth_dev_socket_id(port_no);
    } else {
        sid = rte_lcore_to_socket_id(rte_get_master_lcore());
    }

    dev->socket_id = sid < 0 ? SOCKET0 : sid;
    dev->requested_socket_id = dev->socket_id;
    dev->port_id = port_no;
    dev->type = type;
    dev->flags = 0;
    dev->requested_mtu = dev->mtu = ETHER_MTU;
    dev->max_packet_len = MTU_TO_FRAME_LEN(dev->mtu);
    ovsrcu_index_init(&dev->vid, -1);
    dev->vhost_reconfigured = false;

    err = netdev_dpdk_mempool_configure(dev);
    if (err) {
        goto unlock;
    }

    ovsrcu_init(&dev->qos_conf, NULL);

    ovsrcu_init(&dev->ingress_policer, NULL);
    dev->policer_rate = 0;
    dev->policer_burst = 0;

    netdev->n_rxq = NR_QUEUE;
    netdev->n_txq = NR_QUEUE;
    dev->requested_n_rxq = netdev->n_rxq;
    dev->requested_n_txq = netdev->n_txq;
    dev->rxq_size = NIC_PORT_DEFAULT_RXQ_SIZE;
    dev->txq_size = NIC_PORT_DEFAULT_TXQ_SIZE;
    dev->requested_rxq_size = dev->rxq_size;
    dev->requested_txq_size = dev->txq_size;

    /* Initialize the flow control to NULL */
    memset(&dev->fc_conf, 0, sizeof dev->fc_conf);
    if (type == DPDK_DEV_ETH) {
        err = dpdk_eth_dev_init(dev);
        if (err) {
            goto unlock;
        }
        dev->tx_q = netdev_dpdk_alloc_txq(netdev->n_txq);
    } else {
        dev->tx_q = netdev_dpdk_alloc_txq(OVS_VHOST_MAX_QUEUE_NUM);
        /* Enable DPDK_DEV_VHOST device and set promiscuous mode flag. */
        dev->flags = NETDEV_UP | NETDEV_PROMISC;
    }

    if (!dev->tx_q) {
        err = ENOMEM;
        goto unlock;
    }

    ovs_list_push_back(&dpdk_list, &dev->list_node);

unlock:
    ovs_mutex_unlock(&dev->mutex);
    return err;
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
    } else {
        fatal_signal_add_file_to_unlink(dev->vhost_id);
        VLOG_INFO("Socket %s created for vhost-user port %s\n",
                  dev->vhost_id, name);
    }
    err = netdev_dpdk_init(netdev, -1, DPDK_DEV_VHOST);

    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

static int
netdev_dpdk_vhost_client_construct(struct netdev *netdev)
{
    int err;

    ovs_mutex_lock(&dpdk_mutex);
    err = netdev_dpdk_init(netdev, -1, DPDK_DEV_VHOST);
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

static int
netdev_dpdk_construct(struct netdev *netdev)
{
    unsigned int port_no;
    int err;

    /* Names always start with "dpdk" */
    err = dpdk_dev_parse_name(netdev->name, "dpdk", &port_no);
    if (err) {
        return err;
    }

    ovs_mutex_lock(&dpdk_mutex);
    err = netdev_dpdk_init(netdev, port_no, DPDK_DEV_ETH);
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

static void
netdev_dpdk_destruct(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dpdk_mutex);
    ovs_mutex_lock(&dev->mutex);

    rte_eth_dev_stop(dev->port_id);
    free(ovsrcu_get_protected(struct ingress_policer *,
                              &dev->ingress_policer));

    rte_free(dev->tx_q);
    ovs_list_remove(&dev->list_node);
    dpdk_mp_put(dev->dpdk_mp);

    ovs_mutex_unlock(&dev->mutex);
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
    ovs_mutex_lock(&dev->mutex);

    /* Guest becomes an orphan if still attached. */
    if (netdev_dpdk_get_vid(dev) >= 0
        && !(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)) {
        VLOG_ERR("Removing port '%s' while vhost device still attached.",
                 netdev->name);
        VLOG_ERR("To restore connectivity after re-adding of port, VM on "
                 "socket '%s' must be restarted.", dev->vhost_id);
    }

    free(ovsrcu_get_protected(struct ingress_policer *,
                              &dev->ingress_policer));

    rte_free(dev->tx_q);
    ovs_list_remove(&dev->list_node);
    dpdk_mp_put(dev->dpdk_mp);

    vhost_id = xstrdup(dev->vhost_id);

    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&dpdk_mutex);

    if (dpdk_vhost_driver_unregister(dev, vhost_id)) {
        VLOG_ERR("%s: Unable to unregister vhost driver for socket '%s'.\n",
                 netdev->name, vhost_id);
    } else if (!(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)) {
        /* OVS server mode - remove this socket from list for deletion */
        fatal_signal_remove_file_to_unlink(vhost_id);
    }
    free(vhost_id);
}

static void
netdev_dpdk_dealloc(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    rte_free(dev);
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
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static void
dpdk_set_rxq_config(struct netdev_dpdk *dev, const struct smap *args)
    OVS_REQUIRES(dev->mutex)
{
    int new_n_rxq;

    new_n_rxq = MAX(smap_get_int(args, "n_rxq", dev->requested_n_rxq), 1);
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
netdev_dpdk_set_config(struct netdev *netdev, const struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    bool rx_fc_en, tx_fc_en, autoneg;
    enum rte_eth_fc_mode fc_mode;
    static const enum rte_eth_fc_mode fc_mode_set[2][2] = {
        {RTE_FC_NONE,     RTE_FC_TX_PAUSE},
        {RTE_FC_RX_PAUSE, RTE_FC_FULL    }
    };

    ovs_mutex_lock(&dev->mutex);

    dpdk_set_rxq_config(dev, args);

    dpdk_process_queue_size(netdev, args, "n_rxq_desc",
                            NIC_PORT_DEFAULT_RXQ_SIZE,
                            &dev->requested_rxq_size);
    dpdk_process_queue_size(netdev, args, "n_txq_desc",
                            NIC_PORT_DEFAULT_TXQ_SIZE,
                            &dev->requested_txq_size);

    rx_fc_en = smap_get_bool(args, "rx-flow-ctrl", false);
    tx_fc_en = smap_get_bool(args, "tx-flow-ctrl", false);
    autoneg = smap_get_bool(args, "flow-ctrl-autoneg", false);

    fc_mode = fc_mode_set[tx_fc_en][rx_fc_en];
    if (dev->fc_conf.mode != fc_mode || autoneg != dev->fc_conf.autoneg) {
        dev->fc_conf.mode = fc_mode;
        dev->fc_conf.autoneg = autoneg;
        dpdk_eth_flow_ctrl_setup(dev);
    }

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_ring_set_config(struct netdev *netdev, const struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    dpdk_set_rxq_config(dev, args);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_vhost_client_set_config(struct netdev *netdev,
                                    const struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    const char *path;

    ovs_mutex_lock(&dev->mutex);
    if (!(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)) {
        path = smap_get(args, "vhost-server-path");
        if (path && strcmp(path, dev->vhost_id)) {
            strcpy(dev->vhost_id, path);
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
                        struct rte_mbuf **pkts, int pkt_cnt)
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
            rte_pktmbuf_free(pkt);
        }
    }

    return cnt;
}

static int
ingress_policer_run(struct ingress_policer *policer, struct rte_mbuf **pkts,
                    int pkt_cnt)
{
    int cnt = 0;

    rte_spinlock_lock(&policer->policer_lock);
    cnt = netdev_dpdk_policer_run(&policer->in_policer, pkts, pkt_cnt);
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
    int qid = rxq->queue_id;
    struct ingress_policer *policer = netdev_dpdk_get_ingress_policer(dev);
    uint16_t nb_rx = 0;
    uint16_t dropped = 0;

    if (OVS_UNLIKELY(!is_vhost_running(dev)
                     || !(dev->flags & NETDEV_UP))) {
        return EAGAIN;
    }

    nb_rx = rte_vhost_dequeue_burst(netdev_dpdk_get_vid(dev),
                                    qid * VIRTIO_QNUM + VIRTIO_TXQ,
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
                                    nb_rx);
        dropped -= nb_rx;
    }

    rte_spinlock_lock(&dev->stats_lock);
    netdev_dpdk_vhost_update_rx_counters(&dev->stats, batch->packets,
                                         nb_rx, dropped);
    rte_spinlock_unlock(&dev->stats_lock);

    batch->count = (int) nb_rx;
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
                                    nb_rx);
        dropped -= nb_rx;
    }

    /* Update stats to reflect dropped packets */
    if (OVS_UNLIKELY(dropped)) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.rx_dropped += dropped;
        rte_spinlock_unlock(&dev->stats_lock);
    }

    batch->count = nb_rx;

    return 0;
}

static inline int
netdev_dpdk_qos_run(struct netdev_dpdk *dev, struct rte_mbuf **pkts,
                    int cnt)
{
    struct qos_conf *qos_conf = ovsrcu_get(struct qos_conf *, &dev->qos_conf);

    if (qos_conf) {
        rte_spinlock_lock(&qos_conf->lock);
        cnt = qos_conf->ops->qos_run(qos_conf, pkts, cnt);
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

    qid = dev->tx_q[qid % netdev->n_txq].map;

    if (OVS_UNLIKELY(!is_vhost_running(dev) || qid < 0
                     || !(dev->flags & NETDEV_UP))) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped+= cnt;
        rte_spinlock_unlock(&dev->stats_lock);
        goto out;
    }

    rte_spinlock_lock(&dev->tx_q[qid].tx_lock);

    cnt = netdev_dpdk_filter_packet_len(dev, cur_pkts, cnt);
    /* Check has QoS has been configured for the netdev */
    cnt = netdev_dpdk_qos_run(dev, cur_pkts, cnt);
    dropped = total_pkts - cnt;

    do {
        int vhost_qid = qid * VIRTIO_QNUM + VIRTIO_RXQ;
        unsigned int tx_pkts;

        tx_pkts = rte_vhost_enqueue_burst(netdev_dpdk_get_vid(dev),
                                          vhost_qid, cur_pkts, cnt);
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
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = batch->count;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_mbuf *pkts[PKT_ARRAY_SIZE];
    int dropped = 0;
    int newcnt = 0;
    int i;

    dp_packet_batch_apply_cutlen(batch);

    for (i = 0; i < batch->count; i++) {
        int size = dp_packet_size(batch->packets[i]);

        if (OVS_UNLIKELY(size > dev->max_packet_len)) {
            VLOG_WARN_RL(&rl, "Too big size %d max_packet_len %d",
                         (int) size, dev->max_packet_len);

            dropped++;
            continue;
        }

        pkts[newcnt] = rte_pktmbuf_alloc(dev->dpdk_mp->mp);

        if (!pkts[newcnt]) {
            dropped += batch->count - i;
            break;
        }

        /* We have to do a copy for now */
        memcpy(rte_pktmbuf_mtod(pkts[newcnt], void *),
               dp_packet_data(batch->packets[i]), size);

        rte_pktmbuf_data_len(pkts[newcnt]) = size;
        rte_pktmbuf_pkt_len(pkts[newcnt]) = size;

        newcnt++;
    }

    if (dev->type == DPDK_DEV_VHOST) {
        __netdev_dpdk_vhost_send(netdev, qid, (struct dp_packet **) pkts,
                                 newcnt);
    } else {
        unsigned int qos_pkts = newcnt;

        /* Check if QoS has been configured for this netdev. */
        newcnt = netdev_dpdk_qos_run(dev, pkts, newcnt);

        dropped += qos_pkts - newcnt;
        dropped += netdev_dpdk_eth_tx_burst(dev, qid, pkts, newcnt);
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
                       bool may_steal, bool concurrent_txq OVS_UNUSED)
{

    if (OVS_UNLIKELY(!may_steal || batch->packets[0]->source != DPBUF_DPDK)) {
        dpdk_do_tx_copy(netdev, qid, batch);
        dp_packet_delete_batch(batch, may_steal);
    } else {
        dp_packet_batch_apply_cutlen(batch);
        __netdev_dpdk_vhost_send(netdev, qid, batch->packets, batch->count);
    }
    return 0;
}

static inline void
netdev_dpdk_send__(struct netdev_dpdk *dev, int qid,
                   struct dp_packet_batch *batch, bool may_steal,
                   bool concurrent_txq)
{
    if (OVS_UNLIKELY(concurrent_txq)) {
        qid = qid % dev->up.n_txq;
        rte_spinlock_lock(&dev->tx_q[qid].tx_lock);
    }

    if (OVS_UNLIKELY(!may_steal ||
                     batch->packets[0]->source != DPBUF_DPDK)) {
        struct netdev *netdev = &dev->up;

        dpdk_do_tx_copy(netdev, qid, batch);
        dp_packet_delete_batch(batch, may_steal);
    } else {
        int dropped;
        int cnt = batch->count;
        struct rte_mbuf **pkts = (struct rte_mbuf **) batch->packets;

        dp_packet_batch_apply_cutlen(batch);

        cnt = netdev_dpdk_filter_packet_len(dev, pkts, cnt);
        cnt = netdev_dpdk_qos_run(dev, pkts, cnt);
        dropped = batch->count - cnt;

        dropped += netdev_dpdk_eth_tx_burst(dev, qid, pkts, cnt);

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
                     struct dp_packet_batch *batch, bool may_steal,
                     bool concurrent_txq)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    netdev_dpdk_send__(dev, qid, batch, may_steal, concurrent_txq);
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

    if (MTU_TO_FRAME_LEN(mtu) > NETDEV_DPDK_MAX_PKT_LEN
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
    stats->rx_packets += dev->stats.rx_packets;
    stats->tx_packets += dev->stats.tx_packets;
    stats->rx_dropped = dev->stats.rx_dropped;
    stats->tx_dropped += dev->stats.tx_dropped;
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
        VLOG_ERR("Can't get ETH statistics for port: %i.", dev->port_id);
        ovs_mutex_unlock(&dev->mutex);
        return EPROTO;
    }

    /* Get length of statistics */
    rte_xstats_len = rte_eth_xstats_get_names(dev->port_id, NULL, 0);
    if (rte_xstats_len < 0) {
        VLOG_WARN("Cannot get XSTATS values for port: %i", dev->port_id);
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
        VLOG_WARN("Cannot get XSTATS names for port: %i.", dev->port_id);
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
        VLOG_WARN("Cannot get XSTATS values for port: %i.", dev->port_id);
    }

out:
    free(rte_xstats);
    free(rte_xstats_names);

    stats->rx_packets = rte_stats.ipackets;
    stats->tx_packets = rte_stats.opackets;
    stats->rx_bytes = rte_stats.ibytes;
    stats->tx_bytes = rte_stats.obytes;
    /* DPDK counts imissed as errors, but count them here as dropped instead */
    stats->rx_errors = rte_stats.ierrors - rte_stats.imissed;
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
netdev_dpdk_get_features(const struct netdev *netdev,
                         enum netdev_features *current,
                         enum netdev_features *advertised OVS_UNUSED,
                         enum netdev_features *supported OVS_UNUSED,
                         enum netdev_features *peer OVS_UNUSED)
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
    rate_bytes = rate * 1000/8;
    burst_bytes = burst * 1000/8;

    policer->app_srtcm_params.cir = rate_bytes;
    policer->app_srtcm_params.cbs = burst_bytes;
    policer->app_srtcm_params.ebs = 0;
    err = rte_meter_srtcm_config(&policer->in_policer,
                                    &policer->app_srtcm_params);
    if (err) {
        VLOG_ERR("Could not create rte meter for ingress policer");
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
    int ifindex;

    ovs_mutex_lock(&dev->mutex);
    ifindex = dev->port_id;
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
    int err;

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
        if (dev->flags & NETDEV_UP) {
            err = rte_eth_dev_start(dev->port_id);
            if (err)
                return -err;
        }

        if (dev->flags & NETDEV_PROMISC) {
            rte_eth_promiscuous_enable(dev->port_id);
        }

        if (!(dev->flags & NETDEV_UP)) {
            rte_eth_dev_stop(dev->port_id);
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

    smap_add_format(args, "port_no", "%d", dev->port_id);
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
            struct netdev_dpdk *dpdk_dev = netdev_dpdk_cast(netdev);

            ovs_mutex_lock(&dpdk_dev->mutex);
            netdev_dpdk_set_admin_state__(dpdk_dev, up);
            ovs_mutex_unlock(&dpdk_dev->mutex);

            netdev_close(netdev);
        } else {
            unixctl_command_reply_error(conn, "Not a DPDK Interface");
            netdev_close(netdev);
            return;
        }
    } else {
        struct netdev_dpdk *netdev;

        ovs_mutex_lock(&dpdk_mutex);
        LIST_FOR_EACH (netdev, list_node, &dpdk_list) {
            ovs_mutex_lock(&netdev->mutex);
            netdev_dpdk_set_admin_state__(netdev, up);
            ovs_mutex_unlock(&netdev->mutex);
        }
        ovs_mutex_unlock(&dpdk_mutex);
    }
    unixctl_command_reply(conn, "OK");
}

/*
 * Set virtqueue flags so that we do not receive interrupts.
 */
static void
set_irq_status(int vid)
{
    uint32_t i;
    uint64_t idx;

    for (i = 0; i < rte_vhost_get_queue_num(vid); i++) {
        idx = i * VIRTIO_QNUM;
        rte_vhost_enable_guest_notification(vid, idx + VIRTIO_RXQ, 0);
        rte_vhost_enable_guest_notification(vid, idx + VIRTIO_TXQ, 0);
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
            uint32_t qp_num = rte_vhost_get_queue_num(vid);

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

/*
 * These callbacks allow virtio-net devices to be added to vhost ports when
 * configuration has been fully complete.
 */
static const struct virtio_net_device_ops virtio_net_device_ops =
{
    .new_device =  new_device,
    .destroy_device = destroy_device,
    .vring_state_changed = vring_state_changed
};

static void *
start_vhost_loop(void *dummy OVS_UNUSED)
{
     pthread_detach(pthread_self());
     /* Put the vhost thread into quiescent state. */
     ovsrcu_quiesce_start();
     rte_vhost_driver_session_start();
     return NULL;
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

        ovsthread_once_done(&once);
    }

    return 0;
}

static int
netdev_dpdk_vhost_class_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    /* This function can be called for different classes.  The initialization
     * needs to be done only once */
    if (ovsthread_once_start(&once)) {
        rte_vhost_driver_callback_register(&virtio_net_device_ops);
        rte_vhost_feature_disable(1ULL << VIRTIO_NET_F_HOST_TSO4
                                  | 1ULL << VIRTIO_NET_F_HOST_TSO6
                                  | 1ULL << VIRTIO_NET_F_CSUM
                                  | 1ULL << VIRTIO_RING_F_INDIRECT_DESC);
        ovs_thread_create("vhost_thread", start_vhost_loop, NULL);

        ovsthread_once_done(&once);
    }

    return 0;
}

/* Client Rings */

static int
dpdk_ring_create(const char dev_name[], unsigned int port_no,
                 unsigned int *eth_port_id)
{
    struct dpdk_ring *ivshmem;
    char *ring_name;
    int err;

    ivshmem = dpdk_rte_mzalloc(sizeof *ivshmem);
    if (!ivshmem) {
        return ENOMEM;
    }

    /* XXX: Add support for multiquque ring. */
    ring_name = xasprintf("%s_tx", dev_name);

    /* Create single producer tx ring, netdev does explicit locking. */
    ivshmem->cring_tx = rte_ring_create(ring_name, DPDK_RING_SIZE, SOCKET0,
                                        RING_F_SP_ENQ);
    free(ring_name);
    if (ivshmem->cring_tx == NULL) {
        rte_free(ivshmem);
        return ENOMEM;
    }

    ring_name = xasprintf("%s_rx", dev_name);

    /* Create single consumer rx ring, netdev does explicit locking. */
    ivshmem->cring_rx = rte_ring_create(ring_name, DPDK_RING_SIZE, SOCKET0,
                                        RING_F_SC_DEQ);
    free(ring_name);
    if (ivshmem->cring_rx == NULL) {
        rte_free(ivshmem);
        return ENOMEM;
    }

    err = rte_eth_from_rings(dev_name, &ivshmem->cring_rx, 1,
                             &ivshmem->cring_tx, 1, SOCKET0);

    if (err < 0) {
        rte_free(ivshmem);
        return ENODEV;
    }

    ivshmem->user_port_id = port_no;
    ivshmem->eth_port_id = rte_eth_dev_count() - 1;
    ovs_list_push_back(&dpdk_ring_list, &ivshmem->list_node);

    *eth_port_id = ivshmem->eth_port_id;
    return 0;
}

static int
dpdk_ring_open(const char dev_name[], unsigned int *eth_port_id)
    OVS_REQUIRES(dpdk_mutex)
{
    struct dpdk_ring *ivshmem;
    unsigned int port_no;
    int err = 0;

    /* Names always start with "dpdkr" */
    err = dpdk_dev_parse_name(dev_name, "dpdkr", &port_no);
    if (err) {
        return err;
    }

    /* Look through our list to find the device */
    LIST_FOR_EACH (ivshmem, list_node, &dpdk_ring_list) {
         if (ivshmem->user_port_id == port_no) {
            VLOG_INFO("Found dpdk ring device %s:", dev_name);
            /* Really all that is needed */
            *eth_port_id = ivshmem->eth_port_id;
            return 0;
         }
    }
    /* Need to create the device rings */
    return dpdk_ring_create(dev_name, port_no, eth_port_id);
}

static int
netdev_dpdk_ring_send(struct netdev *netdev, int qid,
                      struct dp_packet_batch *batch, bool may_steal,
                      bool concurrent_txq)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    unsigned i;

    /* When using 'dpdkr' and sending to a DPDK ring, we want to ensure that
     * the rss hash field is clear. This is because the same mbuf may be
     * modified by the consumer of the ring and return into the datapath
     * without recalculating the RSS hash. */
    for (i = 0; i < batch->count; i++) {
        dp_packet_rss_invalidate(batch->packets[i]);
    }

    netdev_dpdk_send__(dev, qid, batch, may_steal, concurrent_txq);
    return 0;
}

static int
netdev_dpdk_ring_construct(struct netdev *netdev)
{
    unsigned int port_no = 0;
    int err = 0;

    ovs_mutex_lock(&dpdk_mutex);

    err = dpdk_ring_open(netdev->name, &port_no);
    if (err) {
        goto unlock_dpdk;
    }

    err = netdev_dpdk_init(netdev, port_no, DPDK_DEV_ETH);

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
egress_policer_qos_is_equal(const struct qos_conf *conf, const struct smap *details)
{
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);
    struct rte_meter_srtcm_params params;

    egress_policer_details_to_param(details, &params);

    return !memcmp(&params, &policer->app_srtcm_params, sizeof params);
}

static int
egress_policer_run(struct qos_conf *conf, struct rte_mbuf **pkts, int pkt_cnt)
{
    int cnt = 0;
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);

    cnt = netdev_dpdk_policer_run(&policer->egress_meter, pkts, pkt_cnt);

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
        && dev->rxq_size == dev->requested_rxq_size
        && dev->txq_size == dev->requested_txq_size) {
        /* Reconfiguration is unnecessary */

        goto out;
    }

    rte_eth_dev_stop(dev->port_id);

    if (dev->mtu != dev->requested_mtu) {
        netdev_dpdk_mempool_configure(dev);
    }

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

static void
dpdk_vhost_reconfigure_helper(struct netdev_dpdk *dev)
    OVS_REQUIRES(dev->mutex)
{
    dev->up.n_txq = dev->requested_n_txq;
    dev->up.n_rxq = dev->requested_n_rxq;

    /* Enable TX queue 0 by default if it wasn't disabled. */
    if (dev->tx_q[0].map == OVS_VHOST_QUEUE_MAP_UNKNOWN) {
        dev->tx_q[0].map = 0;
    }

    netdev_dpdk_remap_txqs(dev);

    if (dev->requested_socket_id != dev->socket_id
        || dev->requested_mtu != dev->mtu) {
        if (!netdev_dpdk_mempool_configure(dev)) {
            netdev_change_seq_changed(&dev->up);
        }
    }

    if (netdev_dpdk_get_vid(dev) >= 0) {
        dev->vhost_reconfigured = true;
    }
}

static int
netdev_dpdk_vhost_reconfigure(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    dpdk_vhost_reconfigure_helper(dev);
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

static int
netdev_dpdk_vhost_client_reconfigure(struct netdev *netdev)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&dev->mutex);

    dpdk_vhost_reconfigure_helper(dev);

    /* Configure vHost client mode if requested and if the following criteria
     * are met:
     *  1. Device hasn't been registered yet.
     *  2. A path has been specified.
     */
    if (!(dev->vhost_driver_flags & RTE_VHOST_USER_CLIENT)
            && strlen(dev->vhost_id)) {
        /* Register client-mode device */
        err = rte_vhost_driver_register(dev->vhost_id,
                                        RTE_VHOST_USER_CLIENT);
        if (err) {
            VLOG_ERR("vhost-user device setup failure for device %s\n",
                     dev->vhost_id);
        } else {
            /* Configuration successful */
            dev->vhost_driver_flags |= RTE_VHOST_USER_CLIENT;
            VLOG_INFO("vHost User device '%s' created in 'client' mode, "
                      "using client socket '%s'",
                      dev->up.name, dev->vhost_id);
        }
    }

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

#define NETDEV_DPDK_CLASS(NAME, INIT, CONSTRUCT, DESTRUCT,    \
                          SET_CONFIG, SET_TX_MULTIQ, SEND,    \
                          GET_CARRIER, GET_STATS,             \
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
    GET_FEATURES,                                             \
    NULL,                       /* set_advertisements */      \
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
        netdev_dpdk_get_features,
        netdev_dpdk_get_status,
        netdev_dpdk_reconfigure,
        netdev_dpdk_rxq_recv);

static const struct netdev_class dpdk_vhost_class =
    NETDEV_DPDK_CLASS(
        "dpdkvhostuser",
        netdev_dpdk_vhost_class_init,
        netdev_dpdk_vhost_construct,
        netdev_dpdk_vhost_destruct,
        NULL,
        NULL,
        netdev_dpdk_vhost_send,
        netdev_dpdk_vhost_get_carrier,
        netdev_dpdk_vhost_get_stats,
        NULL,
        NULL,
        netdev_dpdk_vhost_reconfigure,
        netdev_dpdk_vhost_rxq_recv);
static const struct netdev_class dpdk_vhost_client_class =
    NETDEV_DPDK_CLASS(
        "dpdkvhostuserclient",
        netdev_dpdk_vhost_class_init,
        netdev_dpdk_vhost_client_construct,
        netdev_dpdk_vhost_destruct,
        netdev_dpdk_vhost_client_set_config,
        NULL,
        netdev_dpdk_vhost_send,
        netdev_dpdk_vhost_get_carrier,
        netdev_dpdk_vhost_get_stats,
        NULL,
        NULL,
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
