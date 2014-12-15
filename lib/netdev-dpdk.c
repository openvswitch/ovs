/*
 * Copyright (c) 2014 Nicira, Inc.
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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <config.h>
#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "dpif-netdev.h"
#include "list.h"
#include "netdev-dpdk.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "ovs-numa.h"
#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "packet-dpif.h"
#include "packets.h"
#include "shash.h"
#include "sset.h"
#include "unaligned.h"
#include "timeval.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpdk);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define DPDK_PORT_WATCHDOG_INTERVAL 5

#define OVS_CACHE_LINE_SIZE CACHE_LINE_SIZE
#define OVS_VPORT_DPDK "ovs_dpdk"

/*
 * need to reserve tons of extra space in the mbufs so we can align the
 * DMA addresses to 4KB.
 */

#define MTU_TO_MAX_LEN(mtu)  ((mtu) + ETHER_HDR_LEN + ETHER_CRC_LEN)
#define MBUF_SIZE(mtu)       (MTU_TO_MAX_LEN(mtu) + (512) + \
                             sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

/* XXX: mempool size should be based on system resources. */
#define NB_MBUF              (4096 * 64)
#define MP_CACHE_SZ          (256 * 2)
#define SOCKET0              0

#define NIC_PORT_RX_Q_SIZE 2048  /* Size of Physical NIC RX Queue, Max (n+32<=4096)*/
#define NIC_PORT_TX_Q_SIZE 2048  /* Size of Physical NIC TX Queue, Max (n+32<=4096)*/

/* XXX: Needs per NIC value for these constants. */
#define RX_PTHRESH 32 /* Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 32 /* Default values of RX host threshold reg. */
#define RX_WTHRESH 16 /* Default values of RX write-back threshold reg. */

#define TX_PTHRESH 36 /* Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /* Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /* Default values of TX write-back threshold reg. */

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
            .rss_hf = ETH_RSS_IPV4_TCP | ETH_RSS_IPV4 | ETH_RSS_IPV6
                    | ETH_RSS_IPV4_UDP | ETH_RSS_IPV6_TCP | ETH_RSS_IPV6_UDP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = RX_PTHRESH,
        .hthresh = RX_HTHRESH,
        .wthresh = RX_WTHRESH,
    },
};

static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = TX_PTHRESH,
        .hthresh = TX_HTHRESH,
        .wthresh = TX_WTHRESH,
    },
    .tx_free_thresh = 0,
    .tx_rs_thresh = 0,
    .txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS|ETH_TXQ_FLAGS_NOOFFLOADS,
};

enum { MAX_RX_QUEUE_LEN = 192 };
enum { MAX_TX_QUEUE_LEN = 384 };
enum { DPDK_RING_SIZE = 256 };
BUILD_ASSERT_DECL(IS_POW2(DPDK_RING_SIZE));
enum { DRAIN_TSC = 200000ULL };

static int rte_eal_init_ret = ENODEV;

static struct ovs_mutex dpdk_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dpdk_dev's. */
static struct ovs_list dpdk_list OVS_GUARDED_BY(dpdk_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_list);

static struct ovs_list dpdk_mp_list OVS_GUARDED_BY(dpdk_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_mp_list);

/* This mutex must be used by non pmd threads when allocating or freeing
 * mbufs through mempools. Since dpdk_queue_pkts() and dpdk_queue_flush() may
 * use mempools, a non pmd thread should hold this mutex while calling them */
struct ovs_mutex nonpmd_mempool_mutex = OVS_MUTEX_INITIALIZER;

struct dpdk_mp {
    struct rte_mempool *mp;
    int mtu;
    int socket_id;
    int refcount;
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);
};

/* There should be one 'struct dpdk_tx_queue' created for
 * each cpu core. */
struct dpdk_tx_queue {
    bool flush_tx;                 /* Set to true to flush queue everytime */
                                   /* pkts are queued. */
    int count;
    uint64_t tsc;
    struct rte_mbuf *burst_pkts[MAX_TX_QUEUE_LEN];
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
    int user_port_id; /* User given port no, parsed from port name */
    int eth_port_id; /* ethernet device port id */
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);
};

struct netdev_dpdk {
    struct netdev up;
    int port_id;
    int max_packet_len;

    struct dpdk_tx_queue *tx_q;

    struct ovs_mutex mutex OVS_ACQ_AFTER(dpdk_mutex);

    struct dpdk_mp *dpdk_mp;
    int mtu;
    int socket_id;
    int buf_size;
    struct netdev_stats stats;

    uint8_t hwaddr[ETH_ADDR_LEN];
    enum netdev_flags flags;

    struct rte_eth_link link;
    int link_reset_cnt;

    /* In dpdk_list. */
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);
    rte_spinlock_t dpdkr_tx_lock;
};

struct netdev_rxq_dpdk {
    struct netdev_rxq up;
    int port_id;
};

static bool thread_is_pmd(void);

static int netdev_dpdk_construct(struct netdev *);

static bool
is_dpdk_class(const struct netdev_class *class)
{
    return class->construct == netdev_dpdk_construct;
}

/* XXX: use dpdk malloc for entire OVS. infact huge page shld be used
 * for all other sengments data, bss and text. */

static void *
dpdk_rte_mzalloc(size_t sz)
{
    void *ptr;

    ptr = rte_zmalloc(OVS_VPORT_DPDK, sz, OVS_CACHE_LINE_SIZE);
    if (ptr == NULL) {
        out_of_memory();
    }
    return ptr;
}

/* XXX this function should be called only by pmd threads (or by non pmd
 * threads holding the nonpmd_mempool_mutex) */
void
free_dpdk_buf(struct dpif_packet *p)
{
    struct rte_mbuf *pkt = (struct rte_mbuf *) p;

    rte_pktmbuf_free_seg(pkt);
}

static void
__rte_pktmbuf_init(struct rte_mempool *mp,
                   void *opaque_arg OVS_UNUSED,
                   void *_m,
                   unsigned i OVS_UNUSED)
{
    struct rte_mbuf *m = _m;
    uint32_t buf_len = mp->elt_size - sizeof(struct dpif_packet);

    RTE_MBUF_ASSERT(mp->elt_size >= sizeof(struct dpif_packet));

    memset(m, 0, mp->elt_size);

    /* start of buffer is just after mbuf structure */
    m->buf_addr = (char *)m + sizeof(struct dpif_packet);
    m->buf_physaddr = rte_mempool_virt2phy(mp, m) +
                    sizeof(struct dpif_packet);
    m->buf_len = (uint16_t)buf_len;

    /* keep some headroom between start of buffer and data */
    m->pkt.data = (char*) m->buf_addr + RTE_MIN(RTE_PKTMBUF_HEADROOM, m->buf_len);

    /* init some constant fields */
    m->type = RTE_MBUF_PKT;
    m->pool = mp;
    m->pkt.nb_segs = 1;
    m->pkt.in_port = 0xff;
}

static void
ovs_rte_pktmbuf_init(struct rte_mempool *mp,
                     void *opaque_arg OVS_UNUSED,
                     void *_m,
                     unsigned i OVS_UNUSED)
{
    struct rte_mbuf *m = _m;

    __rte_pktmbuf_init(mp, opaque_arg, _m, i);

    ofpbuf_init_dpdk((struct ofpbuf *) m, m->buf_len);
}

static struct dpdk_mp *
dpdk_mp_get(int socket_id, int mtu) OVS_REQUIRES(dpdk_mutex)
{
    struct dpdk_mp *dmp = NULL;
    char mp_name[RTE_MEMPOOL_NAMESIZE];

    LIST_FOR_EACH (dmp, list_node, &dpdk_mp_list) {
        if (dmp->socket_id == socket_id && dmp->mtu == mtu) {
            dmp->refcount++;
            return dmp;
        }
    }

    dmp = dpdk_rte_mzalloc(sizeof *dmp);
    dmp->socket_id = socket_id;
    dmp->mtu = mtu;
    dmp->refcount = 1;

    if (snprintf(mp_name, RTE_MEMPOOL_NAMESIZE, "ovs_mp_%d_%d", dmp->mtu,
                 dmp->socket_id) < 0) {
        return NULL;
    }

    dmp->mp = rte_mempool_create(mp_name, NB_MBUF, MBUF_SIZE(mtu),
                                 MP_CACHE_SZ,
                                 sizeof(struct rte_pktmbuf_pool_private),
                                 rte_pktmbuf_pool_init, NULL,
                                 ovs_rte_pktmbuf_init, NULL,
                                 socket_id, 0);

    if (dmp->mp == NULL) {
        return NULL;
    }

    list_push_back(&dpdk_mp_list, &dmp->list_node);
    return dmp;
}

static void
dpdk_mp_put(struct dpdk_mp *dmp)
{

    if (!dmp) {
        return;
    }

    dmp->refcount--;
    ovs_assert(dmp->refcount >= 0);

#if 0
    /* I could not find any API to destroy mp. */
    if (dmp->refcount == 0) {
        list_delete(dmp->list_node);
        /* destroy mp-pool. */
    }
#endif
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
                        dev->port_id, (unsigned)dev->link.link_speed,
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
            check_link_status(dev);
            ovs_mutex_unlock(&dev->mutex);
        }
        ovs_mutex_unlock(&dpdk_mutex);
        xsleep(DPDK_PORT_WATCHDOG_INTERVAL);
    }

    return NULL;
}

static int
dpdk_eth_dev_init(struct netdev_dpdk *dev) OVS_REQUIRES(dpdk_mutex)
{
    struct rte_pktmbuf_pool_private *mbp_priv;
    struct ether_addr eth_addr;
    int diag;
    int i;

    if (dev->port_id < 0 || dev->port_id >= rte_eth_dev_count()) {
        return ENODEV;
    }

    diag = rte_eth_dev_configure(dev->port_id, dev->up.n_rxq, dev->up.n_txq,
                                 &port_conf);
    if (diag) {
        VLOG_ERR("eth dev config error %d",diag);
        return -diag;
    }

    for (i = 0; i < dev->up.n_txq; i++) {
        diag = rte_eth_tx_queue_setup(dev->port_id, i, NIC_PORT_TX_Q_SIZE,
                                      dev->socket_id, &tx_conf);
        if (diag) {
            VLOG_ERR("eth dev tx queue setup error %d",diag);
            return -diag;
        }
    }

    for (i = 0; i < dev->up.n_rxq; i++) {
        diag = rte_eth_rx_queue_setup(dev->port_id, i, NIC_PORT_RX_Q_SIZE,
                                      dev->socket_id,
                                      &rx_conf, dev->dpdk_mp->mp);
        if (diag) {
            VLOG_ERR("eth dev rx queue setup error %d",diag);
            return -diag;
        }
    }

    diag = rte_eth_dev_start(dev->port_id);
    if (diag) {
        VLOG_ERR("eth dev start error %d",diag);
        return -diag;
    }

    rte_eth_promiscuous_enable(dev->port_id);
    rte_eth_allmulticast_enable(dev->port_id);

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(dev->port_id, &eth_addr);
    VLOG_INFO_RL(&rl, "Port %d: "ETH_ADDR_FMT"",
                    dev->port_id, ETH_ADDR_ARGS(eth_addr.addr_bytes));

    memcpy(dev->hwaddr, eth_addr.addr_bytes, ETH_ADDR_LEN);
    rte_eth_link_get_nowait(dev->port_id, &dev->link);

    mbp_priv = rte_mempool_get_priv(dev->dpdk_mp->mp);
    dev->buf_size = mbp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM;

    dev->flags = NETDEV_UP | NETDEV_PROMISC;
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
    struct netdev_dpdk *netdev = dpdk_rte_mzalloc(sizeof *netdev);
    return &netdev->up;
}

static void
netdev_dpdk_alloc_txq(struct netdev_dpdk *netdev, unsigned int n_txqs)
{
    int i;

    netdev->tx_q = dpdk_rte_mzalloc(n_txqs * sizeof *netdev->tx_q);
    /* Each index is considered as a cpu core id, since there should
     * be one tx queue for each cpu core. */
    for (i = 0; i < n_txqs; i++) {
        int numa_id = ovs_numa_get_numa_id(i);

        /* If the corresponding core is not on the same numa node
         * as 'netdev', flags the 'flush_tx'. */
        netdev->tx_q[i].flush_tx = netdev->socket_id == numa_id;
    }
}

static int
netdev_dpdk_init(struct netdev *netdev_, unsigned int port_no)
    OVS_REQUIRES(dpdk_mutex)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);
    int sid;
    int err = 0;

    ovs_mutex_init(&netdev->mutex);

    ovs_mutex_lock(&netdev->mutex);

    /* If the 'sid' is negative, it means that the kernel fails
     * to obtain the pci numa info.  In that situation, always
     * use 'SOCKET0'. */
    sid = rte_eth_dev_socket_id(port_no);
    netdev->socket_id = sid < 0 ? SOCKET0 : sid;
    netdev_dpdk_alloc_txq(netdev, NR_QUEUE);
    netdev->port_id = port_no;
    netdev->flags = 0;
    netdev->mtu = ETHER_MTU;
    netdev->max_packet_len = MTU_TO_MAX_LEN(netdev->mtu);
    rte_spinlock_init(&netdev->dpdkr_tx_lock);

    netdev->dpdk_mp = dpdk_mp_get(netdev->socket_id, netdev->mtu);
    if (!netdev->dpdk_mp) {
        err = ENOMEM;
        goto unlock;
    }

    netdev_->n_txq = NR_QUEUE;
    netdev_->n_rxq = NR_QUEUE;
    err = dpdk_eth_dev_init(netdev);
    if (err) {
        goto unlock;
    }

    list_push_back(&dpdk_list, &netdev->list_node);

unlock:
    if (err) {
        rte_free(netdev->tx_q);
    }
    ovs_mutex_unlock(&netdev->mutex);
    return err;
}

static int
dpdk_dev_parse_name(const char dev_name[], const char prefix[],
                    unsigned int *port_no)
{
    const char *cport;

    if (strncmp(dev_name, prefix, strlen(prefix))) {
        return ENODEV;
    }

    cport = dev_name + strlen(prefix);
    *port_no = strtol(cport, 0, 0); /* string must be null terminated */
    return 0;
}

static int
netdev_dpdk_construct(struct netdev *netdev)
{
    unsigned int port_no;
    int err;

    if (rte_eal_init_ret) {
        return rte_eal_init_ret;
    }

    /* Names always start with "dpdk" */
    err = dpdk_dev_parse_name(netdev->name, "dpdk", &port_no);
    if (err) {
        return err;
    }

    ovs_mutex_lock(&dpdk_mutex);
    err = netdev_dpdk_init(netdev, port_no);
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

static void
netdev_dpdk_destruct(struct netdev *netdev_)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev_);

    ovs_mutex_lock(&dev->mutex);
    rte_eth_dev_stop(dev->port_id);
    ovs_mutex_unlock(&dev->mutex);

    ovs_mutex_lock(&dpdk_mutex);
    rte_free(dev->tx_q);
    list_remove(&dev->list_node);
    dpdk_mp_put(dev->dpdk_mp);
    ovs_mutex_unlock(&dpdk_mutex);

    ovs_mutex_destroy(&dev->mutex);
}

static void
netdev_dpdk_dealloc(struct netdev *netdev_)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);

    rte_free(netdev);
}

static int
netdev_dpdk_get_config(const struct netdev *netdev_, struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev_);

    ovs_mutex_lock(&dev->mutex);

    smap_add_format(args, "configured_rx_queues", "%d", netdev_->n_rxq);
    smap_add_format(args, "configured_tx_queues", "%d", netdev_->n_txq);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_get_numa_id(const struct netdev *netdev_)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);

    return netdev->socket_id;
}

/* Sets the number of tx queues and rx queues for the dpdk interface.
 * If the configuration fails, do not try restoring its old configuration
 * and just returns the error. */
static int
netdev_dpdk_set_multiq(struct netdev *netdev_, unsigned int n_txq,
                       unsigned int n_rxq)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);
    int err = 0;

    if (netdev->up.n_txq == n_txq && netdev->up.n_rxq == n_rxq) {
        return err;
    }

    ovs_mutex_lock(&dpdk_mutex);
    ovs_mutex_lock(&netdev->mutex);

    rte_eth_dev_stop(netdev->port_id);

    netdev->up.n_txq = n_txq;
    netdev->up.n_rxq = n_rxq;
    rte_free(netdev->tx_q);
    netdev_dpdk_alloc_txq(netdev, n_txq);
    err = dpdk_eth_dev_init(netdev);

    ovs_mutex_unlock(&netdev->mutex);
    ovs_mutex_unlock(&dpdk_mutex);

    return err;
}

static struct netdev_rxq *
netdev_dpdk_rxq_alloc(void)
{
    struct netdev_rxq_dpdk *rx = dpdk_rte_mzalloc(sizeof *rx);

    return &rx->up;
}

static struct netdev_rxq_dpdk *
netdev_rxq_dpdk_cast(const struct netdev_rxq *rx)
{
    return CONTAINER_OF(rx, struct netdev_rxq_dpdk, up);
}

static int
netdev_dpdk_rxq_construct(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq_);
    struct netdev_dpdk *netdev = netdev_dpdk_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    rx->port_id = netdev->port_id;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static void
netdev_dpdk_rxq_destruct(struct netdev_rxq *rxq_ OVS_UNUSED)
{
}

static void
netdev_dpdk_rxq_dealloc(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq_);

    rte_free(rx);
}

static inline void
dpdk_queue_flush__(struct netdev_dpdk *dev, int qid)
{
    struct dpdk_tx_queue *txq = &dev->tx_q[qid];
    uint32_t nb_tx = 0;

    while (nb_tx != txq->count) {
        uint32_t ret;

        ret = rte_eth_tx_burst(dev->port_id, qid, txq->burst_pkts + nb_tx,
                               txq->count - nb_tx);
        if (!ret) {
            break;
        }

        nb_tx += ret;
    }

    if (OVS_UNLIKELY(nb_tx != txq->count)) {
        /* free buffers, which we couldn't transmit, one at a time (each
         * packet could come from a different mempool) */
        int i;

        for (i = nb_tx; i < txq->count; i++) {
            rte_pktmbuf_free_seg(txq->burst_pkts[i]);
        }
        ovs_mutex_lock(&dev->mutex);
        dev->stats.tx_dropped += txq->count-nb_tx;
        ovs_mutex_unlock(&dev->mutex);
    }

    txq->count = 0;
    txq->tsc = rte_get_timer_cycles();
}

static inline void
dpdk_queue_flush(struct netdev_dpdk *dev, int qid)
{
    struct dpdk_tx_queue *txq = &dev->tx_q[qid];

    if (txq->count == 0) {
        return;
    }
    dpdk_queue_flush__(dev, qid);
}

static int
netdev_dpdk_rxq_recv(struct netdev_rxq *rxq_, struct dpif_packet **packets,
                     int *c)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq_);
    struct netdev *netdev = rx->up.netdev;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int nb_rx;

    /* There is only one tx queue for this core.  Do not flush other
     * queueus. */
    if (rxq_->queue_id == rte_lcore_id()) {
        dpdk_queue_flush(dev, rxq_->queue_id);
    }

    nb_rx = rte_eth_rx_burst(rx->port_id, rxq_->queue_id,
                             (struct rte_mbuf **) packets,
                             MIN((int)NETDEV_MAX_RX_BATCH,
                                 (int)MAX_RX_QUEUE_LEN));
    if (!nb_rx) {
        return EAGAIN;
    }

    *c = nb_rx;

    return 0;
}

inline static void
dpdk_queue_pkts(struct netdev_dpdk *dev, int qid,
               struct rte_mbuf **pkts, int cnt)
{
    struct dpdk_tx_queue *txq = &dev->tx_q[qid];
    uint64_t diff_tsc;

    int i = 0;

    while (i < cnt) {
        int freeslots = MAX_TX_QUEUE_LEN - txq->count;
        int tocopy = MIN(freeslots, cnt-i);

        memcpy(&txq->burst_pkts[txq->count], &pkts[i],
               tocopy * sizeof (struct rte_mbuf *));

        txq->count += tocopy;
        i += tocopy;

        if (txq->count == MAX_TX_QUEUE_LEN || txq->flush_tx) {
            dpdk_queue_flush__(dev, qid);
        }
        diff_tsc = rte_get_timer_cycles() - txq->tsc;
        if (diff_tsc >= DRAIN_TSC) {
            dpdk_queue_flush__(dev, qid);
        }
    }
}

/* Tx function. Transmit packets indefinitely */
static void
dpdk_do_tx_copy(struct netdev *netdev, int qid, struct dpif_packet ** pkts,
                int cnt)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_mbuf *mbufs[cnt];
    int dropped = 0;
    int newcnt = 0;
    int i;

    /* If we are on a non pmd thread we have to use the mempool mutex, because
     * every non pmd thread shares the same mempool cache */

    if (!thread_is_pmd()) {
        ovs_mutex_lock(&nonpmd_mempool_mutex);
    }

    for (i = 0; i < cnt; i++) {
        int size = ofpbuf_size(&pkts[i]->ofpbuf);

        if (OVS_UNLIKELY(size > dev->max_packet_len)) {
            VLOG_WARN_RL(&rl, "Too big size %d max_packet_len %d",
                         (int)size , dev->max_packet_len);

            dropped++;
            continue;
        }

        mbufs[newcnt] = rte_pktmbuf_alloc(dev->dpdk_mp->mp);

        if (!mbufs[newcnt]) {
            dropped += cnt - i;
            break;
        }

        /* We have to do a copy for now */
        memcpy(mbufs[newcnt]->pkt.data, ofpbuf_data(&pkts[i]->ofpbuf), size);

        rte_pktmbuf_data_len(mbufs[newcnt]) = size;
        rte_pktmbuf_pkt_len(mbufs[newcnt]) = size;

        newcnt++;
    }

    if (OVS_UNLIKELY(dropped)) {
        ovs_mutex_lock(&dev->mutex);
        dev->stats.tx_dropped += dropped;
        ovs_mutex_unlock(&dev->mutex);
    }

    dpdk_queue_pkts(dev, qid, mbufs, newcnt);
    dpdk_queue_flush(dev, qid);

    if (!thread_is_pmd()) {
        ovs_mutex_unlock(&nonpmd_mempool_mutex);
    }
}

static inline void
netdev_dpdk_send__(struct netdev_dpdk *dev, int qid,
                   struct dpif_packet **pkts, int cnt, bool may_steal)
{
    int i;

    if (OVS_UNLIKELY(!may_steal ||
                     pkts[0]->ofpbuf.source != OFPBUF_DPDK)) {
        struct netdev *netdev = &dev->up;

        dpdk_do_tx_copy(netdev, qid, pkts, cnt);

        if (may_steal) {
            for (i = 0; i < cnt; i++) {
                dpif_packet_delete(pkts[i]);
            }
        }
    } else {
        int next_tx_idx = 0;
        int dropped = 0;

        for (i = 0; i < cnt; i++) {
            int size = ofpbuf_size(&pkts[i]->ofpbuf);
            if (OVS_UNLIKELY(size > dev->max_packet_len)) {
                if (next_tx_idx != i) {
                    dpdk_queue_pkts(dev, qid,
                                    (struct rte_mbuf **)&pkts[next_tx_idx],
                                    i-next_tx_idx);
                }

                VLOG_WARN_RL(&rl, "Too big size %d max_packet_len %d",
                             (int)size , dev->max_packet_len);

                dpif_packet_delete(pkts[i]);
                dropped++;
                next_tx_idx = i + 1;
            }
        }
        if (next_tx_idx != cnt) {
           dpdk_queue_pkts(dev, qid,
                            (struct rte_mbuf **)&pkts[next_tx_idx],
                            cnt-next_tx_idx);
        }

        if (OVS_UNLIKELY(dropped)) {
            ovs_mutex_lock(&dev->mutex);
            dev->stats.tx_dropped += dropped;
            ovs_mutex_unlock(&dev->mutex);
        }
    }
}

static int
netdev_dpdk_eth_send(struct netdev *netdev, int qid,
                     struct dpif_packet **pkts, int cnt, bool may_steal)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    netdev_dpdk_send__(dev, qid, pkts, cnt, may_steal);
    return 0;
}

static int
netdev_dpdk_set_etheraddr(struct netdev *netdev,
                          const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        memcpy(dev->hwaddr, mac, ETH_ADDR_LEN);
        netdev_change_seq_changed(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_get_etheraddr(const struct netdev *netdev,
                          uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    memcpy(mac, dev->hwaddr, ETH_ADDR_LEN);
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
netdev_dpdk_set_mtu(const struct netdev *netdev, int mtu)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int old_mtu, err;
    struct dpdk_mp *old_mp;
    struct dpdk_mp *mp;

    ovs_mutex_lock(&dpdk_mutex);
    ovs_mutex_lock(&dev->mutex);
    if (dev->mtu == mtu) {
        err = 0;
        goto out;
    }

    mp = dpdk_mp_get(dev->socket_id, dev->mtu);
    if (!mp) {
        err = ENOMEM;
        goto out;
    }

    rte_eth_dev_stop(dev->port_id);

    old_mtu = dev->mtu;
    old_mp = dev->dpdk_mp;
    dev->dpdk_mp = mp;
    dev->mtu = mtu;
    dev->max_packet_len = MTU_TO_MAX_LEN(dev->mtu);

    err = dpdk_eth_dev_init(dev);
    if (err) {
        dpdk_mp_put(mp);
        dev->mtu = old_mtu;
        dev->dpdk_mp = old_mp;
        dev->max_packet_len = MTU_TO_MAX_LEN(dev->mtu);
        dpdk_eth_dev_init(dev);
        goto out;
    }

    dpdk_mp_put(old_mp);
    netdev_change_seq_changed(netdev);
out:
    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

static int
netdev_dpdk_get_carrier(const struct netdev *netdev_, bool *carrier);

static int
netdev_dpdk_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_eth_stats rte_stats;
    bool gg;

    netdev_dpdk_get_carrier(netdev, &gg);
    ovs_mutex_lock(&dev->mutex);
    rte_eth_stats_get(dev->port_id, &rte_stats);

    memset(stats, 0, sizeof(*stats));

    stats->rx_packets = rte_stats.ipackets;
    stats->tx_packets = rte_stats.opackets;
    stats->rx_bytes = rte_stats.ibytes;
    stats->tx_bytes = rte_stats.obytes;
    stats->rx_errors = rte_stats.ierrors;
    stats->tx_errors = rte_stats.oerrors;
    stats->multicast = rte_stats.imcasts;

    stats->tx_dropped = dev->stats.tx_dropped;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dpdk_get_features(const struct netdev *netdev_,
                         enum netdev_features *current,
                         enum netdev_features *advertised OVS_UNUSED,
                         enum netdev_features *supported OVS_UNUSED,
                         enum netdev_features *peer OVS_UNUSED)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev_);
    struct rte_eth_link link;

    ovs_mutex_lock(&dev->mutex);
    link = dev->link;
    ovs_mutex_unlock(&dev->mutex);

    if (link.link_duplex == ETH_LINK_AUTONEG_DUPLEX) {
        if (link.link_speed == ETH_LINK_SPEED_AUTONEG) {
            *current = NETDEV_F_AUTONEG;
        }
    } else if (link.link_duplex == ETH_LINK_HALF_DUPLEX) {
        if (link.link_speed == ETH_LINK_SPEED_10) {
            *current = NETDEV_F_10MB_HD;
        }
        if (link.link_speed == ETH_LINK_SPEED_100) {
            *current = NETDEV_F_100MB_HD;
        }
        if (link.link_speed == ETH_LINK_SPEED_1000) {
            *current = NETDEV_F_1GB_HD;
        }
    } else if (link.link_duplex == ETH_LINK_FULL_DUPLEX) {
        if (link.link_speed == ETH_LINK_SPEED_10) {
            *current = NETDEV_F_10MB_FD;
        }
        if (link.link_speed == ETH_LINK_SPEED_100) {
            *current = NETDEV_F_100MB_FD;
        }
        if (link.link_speed == ETH_LINK_SPEED_1000) {
            *current = NETDEV_F_1GB_FD;
        }
        if (link.link_speed == ETH_LINK_SPEED_10000) {
            *current = NETDEV_F_10GB_FD;
        }
    }

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
netdev_dpdk_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev_);

    ovs_mutex_lock(&dev->mutex);
    check_link_status(dev);
    *carrier = dev->link.link_status;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static long long int
netdev_dpdk_get_carrier_resets(const struct netdev *netdev_)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev_);
    long long int carrier_resets;

    ovs_mutex_lock(&dev->mutex);
    carrier_resets = dev->link_reset_cnt;
    ovs_mutex_unlock(&dev->mutex);

    return carrier_resets;
}

static int
netdev_dpdk_set_miimon(struct netdev *netdev_ OVS_UNUSED,
                       long long int interval OVS_UNUSED)
{
    return 0;
}

static int
netdev_dpdk_update_flags__(struct netdev_dpdk *dev,
                           enum netdev_flags off, enum netdev_flags on,
                           enum netdev_flags *old_flagsp) OVS_REQUIRES(dev->mutex)
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

    return 0;
}

static int
netdev_dpdk_update_flags(struct netdev *netdev_,
                         enum netdev_flags off, enum netdev_flags on,
                         enum netdev_flags *old_flagsp)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);
    error = netdev_dpdk_update_flags__(netdev, off, on, old_flagsp);
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

static int
netdev_dpdk_get_status(const struct netdev *netdev_, struct smap *args)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev_);
    struct rte_eth_dev_info dev_info;

    if (dev->port_id < 0)
        return ENODEV;

    ovs_mutex_lock(&dev->mutex);
    rte_eth_dev_info_get(dev->port_id, &dev_info);
    ovs_mutex_unlock(&dev->mutex);

    smap_add_format(args, "driver_name", "%s", dev_info.driver_name);

    smap_add_format(args, "port_no", "%d", dev->port_id);
    smap_add_format(args, "numa_id", "%d", rte_eth_dev_socket_id(dev->port_id));
    smap_add_format(args, "driver_name", "%s", dev_info.driver_name);
    smap_add_format(args, "min_rx_bufsize", "%u", dev_info.min_rx_bufsize);
    smap_add_format(args, "max_rx_pktlen", "%u", dev_info.max_rx_pktlen);
    smap_add_format(args, "max_rx_queues", "%u", dev_info.max_rx_queues);
    smap_add_format(args, "max_tx_queues", "%u", dev_info.max_tx_queues);
    smap_add_format(args, "max_mac_addrs", "%u", dev_info.max_mac_addrs);
    smap_add_format(args, "max_hash_mac_addrs", "%u", dev_info.max_hash_mac_addrs);
    smap_add_format(args, "max_vfs", "%u", dev_info.max_vfs);
    smap_add_format(args, "max_vmdq_pools", "%u", dev_info.max_vmdq_pools);

    smap_add_format(args, "pci-vendor_id", "0x%u", dev_info.pci_dev->id.vendor_id);
    smap_add_format(args, "pci-device_id", "0x%x", dev_info.pci_dev->id.device_id);

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

static void
dpdk_common_init(void)
{
    unixctl_command_register("netdev-dpdk/set-admin-state",
                             "[netdev] up|down", 1, 2,
                             netdev_dpdk_set_admin_state, NULL);

    ovs_thread_create("dpdk_watchdog", dpdk_watchdog, NULL);
}

static int
dpdk_class_init(void)
{
    int result;

    result = rte_eal_pci_probe();
    if (result) {
        VLOG_ERR("Cannot probe PCI");
        return -result;
    }

    VLOG_INFO("Ethernet Device Count: %d", (int)rte_eth_dev_count());

    return 0;
}

/* Client Rings */

static int
dpdk_ring_create(const char dev_name[], unsigned int port_no,
                 unsigned int *eth_port_id)
{
    struct dpdk_ring *ivshmem;
    char ring_name[10];
    int err;

    ivshmem = dpdk_rte_mzalloc(sizeof *ivshmem);
    if (ivshmem == NULL) {
        return ENOMEM;
    }

    /* XXX: Add support for multiquque ring. */
    err = snprintf(ring_name, 10, "%s_tx", dev_name);
    if (err < 0) {
        return -err;
    }

    /* Create single consumer/producer rings, netdev does explicit locking. */
    ivshmem->cring_tx = rte_ring_create(ring_name, DPDK_RING_SIZE, SOCKET0,
                                        RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (ivshmem->cring_tx == NULL) {
        rte_free(ivshmem);
        return ENOMEM;
    }

    err = snprintf(ring_name, 10, "%s_rx", dev_name);
    if (err < 0) {
        return -err;
    }

    /* Create single consumer/producer rings, netdev does explicit locking. */
    ivshmem->cring_rx = rte_ring_create(ring_name, DPDK_RING_SIZE, SOCKET0,
                                        RING_F_SP_ENQ | RING_F_SC_DEQ);
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
    list_push_back(&dpdk_ring_list, &ivshmem->list_node);

    *eth_port_id = ivshmem->eth_port_id;
    return 0;
}

static int
dpdk_ring_open(const char dev_name[], unsigned int *eth_port_id) OVS_REQUIRES(dpdk_mutex)
{
    struct dpdk_ring *ivshmem;
    unsigned int port_no;
    int err = 0;

    /* Names always start with "dpdkr" */
    err = dpdk_dev_parse_name(dev_name, "dpdkr", &port_no);
    if (err) {
        return err;
    }

    /* look through our list to find the device */
    LIST_FOR_EACH (ivshmem, list_node, &dpdk_ring_list) {
         if (ivshmem->user_port_id == port_no) {
            VLOG_INFO("Found dpdk ring device %s:\n", dev_name);
            *eth_port_id = ivshmem->eth_port_id; /* really all that is needed */
            return 0;
         }
    }
    /* Need to create the device rings */
    return dpdk_ring_create(dev_name, port_no, eth_port_id);
}

static int
netdev_dpdk_ring_send(struct netdev *netdev, int qid OVS_UNUSED,
                      struct dpif_packet **pkts, int cnt, bool may_steal)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    /* DPDK Rings have a single TX queue, Therefore needs locking. */
    rte_spinlock_lock(&dev->dpdkr_tx_lock);
    netdev_dpdk_send__(dev, 0, pkts, cnt, may_steal);
    rte_spinlock_unlock(&dev->dpdkr_tx_lock);
    return 0;
}

static int
netdev_dpdk_ring_construct(struct netdev *netdev)
{
    unsigned int port_no = 0;
    int err = 0;

    if (rte_eal_init_ret) {
        return rte_eal_init_ret;
    }

    ovs_mutex_lock(&dpdk_mutex);

    err = dpdk_ring_open(netdev->name, &port_no);
    if (err) {
        goto unlock_dpdk;
    }

    err = netdev_dpdk_init(netdev, port_no);

unlock_dpdk:
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

#define NETDEV_DPDK_CLASS(NAME, INIT, CONSTRUCT, MULTIQ, SEND)      \
{                                                             \
    NAME,                                                     \
    INIT,                       /* init */                    \
    NULL,                       /* netdev_dpdk_run */         \
    NULL,                       /* netdev_dpdk_wait */        \
                                                              \
    netdev_dpdk_alloc,                                        \
    CONSTRUCT,                                                \
    netdev_dpdk_destruct,                                     \
    netdev_dpdk_dealloc,                                      \
    netdev_dpdk_get_config,                                   \
    NULL,                       /* netdev_dpdk_set_config */  \
    NULL,                       /* get_tunnel_config */       \
    NULL, /* build header */                                  \
    NULL, /* push header */                                   \
    NULL, /* pop header */                                    \
    netdev_dpdk_get_numa_id,    /* get_numa_id */             \
    MULTIQ,                     /* set_multiq */              \
                                                              \
    SEND,                       /* send */                    \
    NULL,                       /* send_wait */               \
                                                              \
    netdev_dpdk_set_etheraddr,                                \
    netdev_dpdk_get_etheraddr,                                \
    netdev_dpdk_get_mtu,                                      \
    netdev_dpdk_set_mtu,                                      \
    netdev_dpdk_get_ifindex,                                  \
    netdev_dpdk_get_carrier,                                  \
    netdev_dpdk_get_carrier_resets,                           \
    netdev_dpdk_set_miimon,                                   \
    netdev_dpdk_get_stats,                                    \
    netdev_dpdk_get_features,                                 \
    NULL,                       /* set_advertisements */      \
                                                              \
    NULL,                       /* set_policing */            \
    NULL,                       /* get_qos_types */           \
    NULL,                       /* get_qos_capabilities */    \
    NULL,                       /* get_qos */                 \
    NULL,                       /* set_qos */                 \
    NULL,                       /* get_queue */               \
    NULL,                       /* set_queue */               \
    NULL,                       /* delete_queue */            \
    NULL,                       /* get_queue_stats */         \
    NULL,                       /* queue_dump_start */        \
    NULL,                       /* queue_dump_next */         \
    NULL,                       /* queue_dump_done */         \
    NULL,                       /* dump_queue_stats */        \
                                                              \
    NULL,                       /* get_in4 */                 \
    NULL,                       /* set_in4 */                 \
    NULL,                       /* get_in6 */                 \
    NULL,                       /* add_router */              \
    NULL,                       /* get_next_hop */            \
    netdev_dpdk_get_status,                                   \
    NULL,                       /* arp_lookup */              \
                                                              \
    netdev_dpdk_update_flags,                                 \
                                                              \
    netdev_dpdk_rxq_alloc,                                    \
    netdev_dpdk_rxq_construct,                                \
    netdev_dpdk_rxq_destruct,                                 \
    netdev_dpdk_rxq_dealloc,                                  \
    netdev_dpdk_rxq_recv,                                     \
    NULL,                       /* rx_wait */                 \
    NULL,                       /* rxq_drain */               \
}

int
dpdk_init(int argc, char **argv)
{
    int result;

    if (argc < 2 || strcmp(argv[1], "--dpdk"))
        return 0;

    /* Make sure program name passed to rte_eal_init() is vswitchd. */
    argv[1] = argv[0];

    argc--;
    argv++;

    /* Make sure things are initialized ... */
    result = rte_eal_init(argc, argv);
    if (result < 0) {
        ovs_abort(result, "Cannot init EAL\n");
    }

    rte_memzone_dump(stdout);
    rte_eal_init_ret = 0;

    if (argc > result) {
        argv[result] = argv[0];
    }

    /* We are called from the main thread here */
    thread_set_nonpmd();

    return result + 1;
}

const struct netdev_class dpdk_class =
    NETDEV_DPDK_CLASS(
        "dpdk",
        dpdk_class_init,
        netdev_dpdk_construct,
        netdev_dpdk_set_multiq,
        netdev_dpdk_eth_send);

const struct netdev_class dpdk_ring_class =
    NETDEV_DPDK_CLASS(
        "dpdkr",
        NULL,
        netdev_dpdk_ring_construct,
        NULL,
        netdev_dpdk_ring_send);

void
netdev_dpdk_register(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (rte_eal_init_ret) {
        return;
    }

    if (ovsthread_once_start(&once)) {
        dpdk_common_init();
        netdev_register_provider(&dpdk_class);
        netdev_register_provider(&dpdk_ring_class);
        ovsthread_once_done(&once);
    }
}

int
pmd_thread_setaffinity_cpu(int cpu)
{
    cpu_set_t cpuset;
    int err;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (err) {
        VLOG_ERR("Thread affinity error %d",err);
        return err;
    }
    /* lcore_id 0 is reseved for use by non pmd threads. */
    ovs_assert(cpu);
    RTE_PER_LCORE(_lcore_id) = cpu;

    return 0;
}

void
thread_set_nonpmd(void)
{
    /* We have to use 0 to allow non pmd threads to perform certain DPDK
     * operations, like rte_eth_dev_configure(). */
    RTE_PER_LCORE(_lcore_id) = 0;
}

static bool
thread_is_pmd(void)
{
    return rte_lcore_id() != 0;
}
