/*
 * Copyright (c) 2018, 2019 Nicira, Inc.
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

#include "netdev-linux-private.h"
#include "netdev-linux.h"
#include "netdev-afxdp.h"
#include "netdev-afxdp-pool.h"

#include <errno.h>
#include <inttypes.h>
#include <linux/rtnetlink.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "fatal-signal.h"
#include "openvswitch/compiler.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "socket-util.h"
#include "util.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

COVERAGE_DEFINE(afxdp_cq_empty);
COVERAGE_DEFINE(afxdp_fq_full);
COVERAGE_DEFINE(afxdp_tx_full);
COVERAGE_DEFINE(afxdp_cq_skip);

VLOG_DEFINE_THIS_MODULE(netdev_afxdp);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define MAX_XSKQ            16
#define FRAME_HEADROOM      XDP_PACKET_HEADROOM
#define OVS_XDP_HEADROOM    128
#define FRAME_SIZE          XSK_UMEM__DEFAULT_FRAME_SIZE
#define FRAME_SHIFT         XSK_UMEM__DEFAULT_FRAME_SHIFT
#define FRAME_SHIFT_MASK    ((1 << FRAME_SHIFT) - 1)

#define PROD_NUM_DESCS      XSK_RING_PROD__DEFAULT_NUM_DESCS
#define CONS_NUM_DESCS      XSK_RING_CONS__DEFAULT_NUM_DESCS

/* The worst case is all 4 queues TX/CQ/RX/FILL are full + some packets
 * still on processing in threads. Number of packets currently in OVS
 * processing is hard to estimate because it depends on number of ports.
 * Setting NUM_FRAMES twice as large than total of ring sizes should be
 * enough for most corner cases.
 */
#define NUM_FRAMES          (4 * (PROD_NUM_DESCS + CONS_NUM_DESCS))
#define BATCH_SIZE          NETDEV_MAX_BURST

BUILD_ASSERT_DECL(IS_POW2(NUM_FRAMES));
BUILD_ASSERT_DECL(PROD_NUM_DESCS == CONS_NUM_DESCS);

#define UMEM2DESC(elem, base) ((uint64_t)((char *)elem - (char *)base))

static struct xsk_socket_info *xsk_configure(int ifindex, int xdp_queue_id,
                                             int mode);
static void xsk_remove_xdp_program(uint32_t ifindex, int xdpmode);
static void xsk_destroy(struct xsk_socket_info *xsk);
static int xsk_configure_all(struct netdev *netdev);
static void xsk_destroy_all(struct netdev *netdev);

struct unused_pool {
    struct xsk_umem_info *umem_info;
    int lost_in_rings; /* Number of packets left in tx, rx, cq and fq. */
    struct ovs_list list_node;
};

static struct ovs_mutex unused_pools_mutex = OVS_MUTEX_INITIALIZER;
static struct ovs_list unused_pools OVS_GUARDED_BY(unused_pools_mutex) =
    OVS_LIST_INITIALIZER(&unused_pools);

struct xsk_umem_info {
    struct umem_pool mpool;
    struct xpacket_pool xpool;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    uint32_t outstanding_tx; /* Number of descriptors filled in tx and cq. */
    uint32_t available_rx;   /* Number of descriptors filled in rx and fq. */
    atomic_uint64_t tx_dropped;
};

static void
netdev_afxdp_cleanup_unused_pool(struct unused_pool *pool)
{
    /* Free the packet buffer. */
    free_pagealign(pool->umem_info->buffer);

    /* Cleanup umem pool. */
    umem_pool_cleanup(&pool->umem_info->mpool);

    /* Cleanup metadata pool. */
    xpacket_pool_cleanup(&pool->umem_info->xpool);

    free(pool->umem_info);
}

static void
netdev_afxdp_sweep_unused_pools(void *aux OVS_UNUSED)
{
    struct unused_pool *pool, *next;
    unsigned int count;

    ovs_mutex_lock(&unused_pools_mutex);
    LIST_FOR_EACH_SAFE (pool, next, list_node, &unused_pools) {

        count = umem_pool_count(&pool->umem_info->mpool);
        ovs_assert(count + pool->lost_in_rings <= NUM_FRAMES);

        if (count + pool->lost_in_rings == NUM_FRAMES) {
            /* OVS doesn't use this memory pool anymore.  Kernel doesn't
             * use it since closing the xdp socket.  So, it's safe to free
             * the pool now. */
            VLOG_DBG("Freeing umem pool at 0x%"PRIxPTR,
                     (uintptr_t) pool->umem_info);
            ovs_list_remove(&pool->list_node);
            netdev_afxdp_cleanup_unused_pool(pool);
            free(pool);
        }
    }
    ovs_mutex_unlock(&unused_pools_mutex);
}

static struct xsk_umem_info *
xsk_configure_umem(void *buffer, uint64_t size, int xdpmode)
{
    struct xsk_umem_config uconfig;
    struct xsk_umem_info *umem;
    int ret;
    int i;

    umem = xzalloc(sizeof *umem);

    memset(&uconfig, 0, sizeof uconfig);
    uconfig.fill_size = PROD_NUM_DESCS;
    uconfig.comp_size = CONS_NUM_DESCS;
    uconfig.frame_size = FRAME_SIZE;
    uconfig.frame_headroom = OVS_XDP_HEADROOM;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                           &uconfig);
    if (ret) {
        VLOG_ERR("xsk_umem__create failed (%s) mode: %s",
                 ovs_strerror(errno),
                 xdpmode == XDP_COPY ? "SKB": "DRV");
        free(umem);
        return NULL;
    }

    umem->buffer = buffer;

    /* Set-up umem pool. */
    if (umem_pool_init(&umem->mpool, NUM_FRAMES) < 0) {
        VLOG_ERR("umem_pool_init failed");
        if (xsk_umem__delete(umem->umem)) {
            VLOG_ERR("xsk_umem__delete failed");
        }
        free(umem);
        return NULL;
    }

    for (i = NUM_FRAMES - 1; i >= 0; i--) {
        void *elem;

        elem = ALIGNED_CAST(void *, (char *)umem->buffer + i * FRAME_SIZE);
        umem_elem_push(&umem->mpool, elem);
    }

    /* Set-up metadata. */
    if (xpacket_pool_init(&umem->xpool, NUM_FRAMES) < 0) {
        VLOG_ERR("xpacket_pool_init failed");
        umem_pool_cleanup(&umem->mpool);
        if (xsk_umem__delete(umem->umem)) {
            VLOG_ERR("xsk_umem__delete failed");
        }
        free(umem);
        return NULL;
    }

    VLOG_DBG("%s: xpacket pool from %p to %p", __func__,
              umem->xpool.array,
              (char *)umem->xpool.array +
              NUM_FRAMES * sizeof(struct dp_packet_afxdp));

    for (i = NUM_FRAMES - 1; i >= 0; i--) {
        struct dp_packet_afxdp *xpacket;
        struct dp_packet *packet;

        xpacket = &umem->xpool.array[i];
        xpacket->mpool = &umem->mpool;

        packet = &xpacket->packet;
        packet->source = DPBUF_AFXDP;
    }

    return umem;
}

static struct xsk_socket_info *
xsk_configure_socket(struct xsk_umem_info *umem, uint32_t ifindex,
                     uint32_t queue_id, int xdpmode)
{
    struct xsk_socket_config cfg;
    struct xsk_socket_info *xsk;
    char devname[IF_NAMESIZE];
    uint32_t idx = 0, prog_id;
    int ret;
    int i;

    xsk = xzalloc(sizeof *xsk);
    xsk->umem = umem;
    cfg.rx_size = CONS_NUM_DESCS;
    cfg.tx_size = PROD_NUM_DESCS;
    cfg.libbpf_flags = 0;

    if (xdpmode == XDP_ZEROCOPY) {
        cfg.bind_flags = XDP_ZEROCOPY;
        cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    } else {
        cfg.bind_flags = XDP_COPY;
        cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
    }

    if (if_indextoname(ifindex, devname) == NULL) {
        VLOG_ERR("ifindex %d to devname failed (%s)",
                 ifindex, ovs_strerror(errno));
        free(xsk);
        return NULL;
    }

    ret = xsk_socket__create(&xsk->xsk, devname, queue_id, umem->umem,
                             &xsk->rx, &xsk->tx, &cfg);
    if (ret) {
        VLOG_ERR("xsk_socket__create failed (%s) mode: %s qid: %d",
                 ovs_strerror(errno),
                 xdpmode == XDP_COPY ? "SKB": "DRV",
                 queue_id);
        free(xsk);
        return NULL;
    }

    /* Make sure the built-in AF_XDP program is loaded. */
    ret = bpf_get_link_xdp_id(ifindex, &prog_id, cfg.xdp_flags);
    if (ret) {
        VLOG_ERR("Get XDP prog ID failed (%s)", ovs_strerror(errno));
        xsk_socket__delete(xsk->xsk);
        free(xsk);
        return NULL;
    }

    while (!xsk_ring_prod__reserve(&xsk->umem->fq,
                                   PROD_NUM_DESCS, &idx)) {
        VLOG_WARN_RL(&rl, "Retry xsk_ring_prod__reserve to FILL queue");
    }

    for (i = 0;
         i < PROD_NUM_DESCS * FRAME_SIZE;
         i += FRAME_SIZE) {
        void *elem;
        uint64_t addr;

        elem = umem_elem_pop(&xsk->umem->mpool);
        addr = UMEM2DESC(elem, xsk->umem->buffer);

        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = addr;
    }

    xsk_ring_prod__submit(&xsk->umem->fq,
                          PROD_NUM_DESCS);
    return xsk;
}

static struct xsk_socket_info *
xsk_configure(int ifindex, int xdp_queue_id, int xdpmode)
{
    struct xsk_socket_info *xsk;
    struct xsk_umem_info *umem;
    void *bufs;

    netdev_afxdp_sweep_unused_pools(NULL);

    /* Umem memory region. */
    bufs = xmalloc_pagealign(NUM_FRAMES * FRAME_SIZE);
    memset(bufs, 0, NUM_FRAMES * FRAME_SIZE);

    /* Create AF_XDP socket. */
    umem = xsk_configure_umem(bufs,
                              NUM_FRAMES * FRAME_SIZE,
                              xdpmode);
    if (!umem) {
        free_pagealign(bufs);
        return NULL;
    }

    VLOG_DBG("Allocated umem pool at 0x%"PRIxPTR, (uintptr_t) umem);

    xsk = xsk_configure_socket(umem, ifindex, xdp_queue_id, xdpmode);
    if (!xsk) {
        /* Clean up umem and xpacket pool. */
        if (xsk_umem__delete(umem->umem)) {
            VLOG_ERR("xsk_umem__delete failed.");
        }
        free_pagealign(bufs);
        umem_pool_cleanup(&umem->mpool);
        xpacket_pool_cleanup(&umem->xpool);
        free(umem);
    }
    return xsk;
}

static int
xsk_configure_all(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info;
    int i, ifindex, n_rxq, n_txq;

    ifindex = linux_get_ifindex(netdev_get_name(netdev));

    ovs_assert(dev->xsks == NULL);
    ovs_assert(dev->tx_locks == NULL);

    n_rxq = netdev_n_rxq(netdev);
    dev->xsks = xcalloc(n_rxq, sizeof *dev->xsks);

    /* Configure each queue. */
    for (i = 0; i < n_rxq; i++) {
        VLOG_INFO("%s: configure queue %d mode %s", __func__, i,
                  dev->xdpmode == XDP_COPY ? "SKB" : "DRV");
        xsk_info = xsk_configure(ifindex, i, dev->xdpmode);
        if (!xsk_info) {
            VLOG_ERR("Failed to create AF_XDP socket on queue %d.", i);
            dev->xsks[i] = NULL;
            goto err;
        }
        dev->xsks[i] = xsk_info;
        atomic_init(&xsk_info->tx_dropped, 0);
        xsk_info->outstanding_tx = 0;
        xsk_info->available_rx = PROD_NUM_DESCS;
    }

    n_txq = netdev_n_txq(netdev);
    dev->tx_locks = xcalloc(n_txq, sizeof *dev->tx_locks);

    for (i = 0; i < n_txq; i++) {
        ovs_spin_init(&dev->tx_locks[i]);
    }

    return 0;

err:
    xsk_destroy_all(netdev);
    return EINVAL;
}

static void
xsk_destroy(struct xsk_socket_info *xsk_info)
{
    struct xsk_umem *umem;
    struct unused_pool *pool;

    xsk_socket__delete(xsk_info->xsk);
    xsk_info->xsk = NULL;

    umem = xsk_info->umem->umem;
    if (xsk_umem__delete(umem)) {
        VLOG_ERR("xsk_umem__delete failed.");
    }

    pool = xzalloc(sizeof *pool);
    pool->umem_info = xsk_info->umem;
    pool->lost_in_rings = xsk_info->outstanding_tx + xsk_info->available_rx;

    ovs_mutex_lock(&unused_pools_mutex);
    ovs_list_push_back(&unused_pools, &pool->list_node);
    ovs_mutex_unlock(&unused_pools_mutex);

    free(xsk_info);

    netdev_afxdp_sweep_unused_pools(NULL);
}

static void
xsk_destroy_all(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int i, ifindex;

    if (dev->xsks) {
        for (i = 0; i < netdev_n_rxq(netdev); i++) {
            if (dev->xsks[i]) {
                xsk_destroy(dev->xsks[i]);
                dev->xsks[i] = NULL;
                VLOG_INFO("Destroyed xsk[%d].", i);
            }
        }

        free(dev->xsks);
        dev->xsks = NULL;
    }

    VLOG_INFO("%s: Removing xdp program.", netdev_get_name(netdev));
    ifindex = linux_get_ifindex(netdev_get_name(netdev));
    xsk_remove_xdp_program(ifindex, dev->xdpmode);

    if (dev->tx_locks) {
        for (i = 0; i < netdev_n_txq(netdev); i++) {
            ovs_spin_destroy(&dev->tx_locks[i]);
        }
        free(dev->tx_locks);
        dev->tx_locks = NULL;
    }
}

static inline void OVS_UNUSED
log_xsk_stat(struct xsk_socket_info *xsk OVS_UNUSED) {
    struct xdp_statistics stat;
    socklen_t optlen;

    optlen = sizeof stat;
    ovs_assert(getsockopt(xsk_socket__fd(xsk->xsk), SOL_XDP, XDP_STATISTICS,
               &stat, &optlen) == 0);

    VLOG_DBG_RL(&rl, "rx dropped %llu, rx_invalid %llu, tx_invalid %llu",
                stat.rx_dropped,
                stat.rx_invalid_descs,
                stat.tx_invalid_descs);
}

int
netdev_afxdp_set_config(struct netdev *netdev, const struct smap *args,
                        char **errp OVS_UNUSED)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    const char *str_xdpmode;
    int xdpmode, new_n_rxq;

    ovs_mutex_lock(&dev->mutex);
    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq > MAX_XSKQ) {
        ovs_mutex_unlock(&dev->mutex);
        VLOG_ERR("%s: Too big 'n_rxq' (%d > %d).",
                 netdev_get_name(netdev), new_n_rxq, MAX_XSKQ);
        return EINVAL;
    }

    str_xdpmode = smap_get_def(args, "xdpmode", "skb");
    if (!strcasecmp(str_xdpmode, "drv")) {
        xdpmode = XDP_ZEROCOPY;
    } else if (!strcasecmp(str_xdpmode, "skb")) {
        xdpmode = XDP_COPY;
    } else {
        VLOG_ERR("%s: Incorrect xdpmode (%s).",
                 netdev_get_name(netdev), str_xdpmode);
        ovs_mutex_unlock(&dev->mutex);
        return EINVAL;
    }

    if (dev->requested_n_rxq != new_n_rxq
        || dev->requested_xdpmode != xdpmode) {
        dev->requested_n_rxq = new_n_rxq;
        dev->requested_xdpmode = xdpmode;
        netdev_request_reconfigure(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

int
netdev_afxdp_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    smap_add_format(args, "n_rxq", "%d", netdev->n_rxq);
    smap_add_format(args, "xdpmode", "%s",
        dev->xdpmode == XDP_ZEROCOPY ? "drv" : "skb");
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

int
netdev_afxdp_reconfigure(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int err = 0;

    ovs_mutex_lock(&dev->mutex);

    if (netdev->n_rxq == dev->requested_n_rxq
        && dev->xdpmode == dev->requested_xdpmode
        && dev->xsks) {
        goto out;
    }

    xsk_destroy_all(netdev);

    netdev->n_rxq = dev->requested_n_rxq;
    netdev->n_txq = netdev->n_rxq;

    dev->xdpmode = dev->requested_xdpmode;
    VLOG_INFO("%s: Setting XDP mode to %s.", netdev_get_name(netdev),
              dev->xdpmode == XDP_ZEROCOPY ? "DRV" : "SKB");

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        VLOG_ERR("setrlimit(RLIMIT_MEMLOCK) failed: %s", ovs_strerror(errno));
    }

    err = xsk_configure_all(netdev);
    if (err) {
        VLOG_ERR("AF_XDP device %s reconfig failed.", netdev_get_name(netdev));
    }
    netdev_change_seq_changed(netdev);
out:
    ovs_mutex_unlock(&dev->mutex);
    return err;
}

int
netdev_afxdp_get_numa_id(const struct netdev *netdev)
{
    /* FIXME: Get netdev's PCIe device ID, then find
     * its NUMA node id.
     */
    VLOG_INFO("FIXME: Device %s always use numa id 0.",
              netdev_get_name(netdev));
    return 0;
}

static void
xsk_remove_xdp_program(uint32_t ifindex, int xdpmode)
{
    uint32_t flags;

    flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

    if (xdpmode == XDP_COPY) {
        flags |= XDP_FLAGS_SKB_MODE;
    } else if (xdpmode == XDP_ZEROCOPY) {
        flags |= XDP_FLAGS_DRV_MODE;
    }

    bpf_set_link_xdp_fd(ifindex, -1, flags);
}

void
signal_remove_xdp(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int ifindex;

    ifindex = linux_get_ifindex(netdev_get_name(netdev));

    VLOG_WARN("Force removing xdp program.");
    xsk_remove_xdp_program(ifindex, dev->xdpmode);
}

static struct dp_packet_afxdp *
dp_packet_cast_afxdp(const struct dp_packet *d)
{
    ovs_assert(d->source == DPBUF_AFXDP);
    return CONTAINER_OF(d, struct dp_packet_afxdp, packet);
}

static inline void
prepare_fill_queue(struct xsk_socket_info *xsk_info)
{
    struct xsk_umem_info *umem;
    void *elems[BATCH_SIZE];
    unsigned int idx_fq;
    int i, ret;

    umem = xsk_info->umem;

    if (xsk_prod_nb_free(&umem->fq, BATCH_SIZE) < BATCH_SIZE) {
        return;
    }

    ret = umem_elem_pop_n(&umem->mpool, BATCH_SIZE, elems);
    if (OVS_UNLIKELY(ret)) {
        return;
    }

    if (!xsk_ring_prod__reserve(&umem->fq, BATCH_SIZE, &idx_fq)) {
        umem_elem_push_n(&umem->mpool, BATCH_SIZE, elems);
        COVERAGE_INC(afxdp_fq_full);
        return;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        uint64_t index;
        void *elem;

        elem = elems[i];
        index = (uint64_t)((char *)elem - (char *)umem->buffer);
        ovs_assert((index & FRAME_SHIFT_MASK) == 0);
        *xsk_ring_prod__fill_addr(&umem->fq, idx_fq) = index;

        idx_fq++;
    }
    xsk_ring_prod__submit(&umem->fq, BATCH_SIZE);
    xsk_info->available_rx += BATCH_SIZE;
}

int
netdev_afxdp_rxq_recv(struct netdev_rxq *rxq_, struct dp_packet_batch *batch,
                      int *qfill)
{
    struct netdev_rxq_linux *rx = netdev_rxq_linux_cast(rxq_);
    struct netdev *netdev = rx->up.netdev;
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info;
    struct xsk_umem_info *umem;
    uint32_t idx_rx = 0;
    int qid = rxq_->queue_id;
    unsigned int rcvd, i;

    xsk_info = dev->xsks[qid];
    if (!xsk_info || !xsk_info->xsk) {
        return EAGAIN;
    }

    prepare_fill_queue(xsk_info);

    umem = xsk_info->umem;
    rx->fd = xsk_socket__fd(xsk_info->xsk);

    rcvd = xsk_ring_cons__peek(&xsk_info->rx, BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        return EAGAIN;
    }

    /* Setup a dp_packet batch from descriptors in RX queue. */
    for (i = 0; i < rcvd; i++) {
        struct dp_packet_afxdp *xpacket;
        const struct xdp_desc *desc;
        struct dp_packet *packet;
        uint64_t addr, index;
        uint32_t len;
        char *pkt;

        desc = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx);
        addr = desc->addr;
        len = desc->len;

        pkt = xsk_umem__get_data(umem->buffer, addr);
        index = addr >> FRAME_SHIFT;
        xpacket = &umem->xpool.array[index];
        packet = &xpacket->packet;

        /* Initialize the struct dp_packet. */
        dp_packet_use_afxdp(packet, pkt,
                            FRAME_SIZE - FRAME_HEADROOM,
                            OVS_XDP_HEADROOM);
        dp_packet_set_size(packet, len);

        /* Add packet into batch, increase batch->count. */
        dp_packet_batch_add(batch, packet);

        idx_rx++;
    }
    /* Release the RX queue. */
    xsk_ring_cons__release(&xsk_info->rx, rcvd);
    xsk_info->available_rx -= rcvd;

    if (qfill) {
        /* TODO: return the number of remaining packets in the queue. */
        *qfill = 0;
    }

#ifdef AFXDP_DEBUG
    log_xsk_stat(xsk_info);
#endif
    return 0;
}

static inline int
kick_tx(struct xsk_socket_info *xsk_info, int xdpmode)
{
    int ret, retries;
    static const int KERNEL_TX_BATCH_SIZE = 16;

    /* In SKB_MODE packet transmission is synchronous, and the kernel xmits
     * only TX_BATCH_SIZE(16) packets for a single sendmsg syscall.
     * So, we have to kick the kernel (n_packets / 16) times to be sure that
     * all packets are transmitted. */
    retries = (xdpmode == XDP_COPY)
              ? xsk_info->outstanding_tx / KERNEL_TX_BATCH_SIZE
              : 0;
kick_retry:
    /* This causes system call into kernel's xsk_sendmsg, and
     * xsk_generic_xmit (skb mode) or xsk_async_xmit (driver mode).
     */
    ret = sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT,
                                NULL, 0);
    if (ret < 0) {
        if (retries-- && errno == EAGAIN) {
            goto kick_retry;
        }
        if (errno == ENXIO || errno == ENOBUFS || errno == EOPNOTSUPP) {
            return errno;
        }
    }
    /* No error, or EBUSY, or too many retries on EAGAIN. */
    return 0;
}

void
free_afxdp_buf(struct dp_packet *p)
{
    struct dp_packet_afxdp *xpacket;
    uintptr_t addr;

    xpacket = dp_packet_cast_afxdp(p);
    if (xpacket->mpool) {
        void *base = dp_packet_base(p);

        addr = (uintptr_t)base & (~FRAME_SHIFT_MASK);
        umem_elem_push(xpacket->mpool, (void *)addr);
    }
}

static void
free_afxdp_buf_batch(struct dp_packet_batch *batch)
{
    struct dp_packet_afxdp *xpacket = NULL;
    struct dp_packet *packet;
    void *elems[BATCH_SIZE];
    uintptr_t addr;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        void *base;

        xpacket = dp_packet_cast_afxdp(packet);
        base = dp_packet_base(packet);
        addr = (uintptr_t)base & (~FRAME_SHIFT_MASK);
        elems[i] = (void *)addr;
    }
    umem_elem_push_n(xpacket->mpool, batch->count, elems);
    dp_packet_batch_init(batch);
}

static inline bool
check_free_batch(struct dp_packet_batch *batch)
{
    struct umem_pool *first_mpool = NULL;
    struct dp_packet_afxdp *xpacket;
    struct dp_packet *packet;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        if (packet->source != DPBUF_AFXDP) {
            return false;
        }
        xpacket = dp_packet_cast_afxdp(packet);
        if (i == 0) {
            first_mpool = xpacket->mpool;
            continue;
        }
        if (xpacket->mpool != first_mpool) {
            return false;
        }
    }
    /* All packets are DPBUF_AFXDP and from the same mpool. */
    return true;
}

static inline void
afxdp_complete_tx(struct xsk_socket_info *xsk_info)
{
    void *elems_push[BATCH_SIZE];
    struct xsk_umem_info *umem;
    uint32_t idx_cq = 0;
    int tx_to_free = 0;
    int tx_done, j;

    umem = xsk_info->umem;
    tx_done = xsk_ring_cons__peek(&umem->cq, CONS_NUM_DESCS, &idx_cq);

    /* Recycle back to umem pool. */
    for (j = 0; j < tx_done; j++) {
        uint64_t *addr;
        void *elem;

        addr = (uint64_t *)xsk_ring_cons__comp_addr(&umem->cq, idx_cq++);
        if (*addr != UINT64_MAX) {
            elem = ALIGNED_CAST(void *, (char *)umem->buffer + *addr);
            elems_push[tx_to_free] = elem;
            *addr = UINT64_MAX; /* Mark as pushed. */
            tx_to_free++;
        } else {
            /* The elem has been pushed already. */
            COVERAGE_INC(afxdp_cq_skip);
        }

        if (tx_to_free == BATCH_SIZE || j == tx_done - 1) {
            umem_elem_push_n(&umem->mpool, tx_to_free, elems_push);
            xsk_info->outstanding_tx -= tx_to_free;
            tx_to_free = 0;
        }
    }

    if (tx_done > 0) {
        xsk_ring_cons__release(&umem->cq, tx_done);
    } else {
        COVERAGE_INC(afxdp_cq_empty);
    }
}

static inline int
__netdev_afxdp_batch_send(struct netdev *netdev, int qid,
                        struct dp_packet_batch *batch)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info;
    void *elems_pop[BATCH_SIZE];
    struct xsk_umem_info *umem;
    struct dp_packet *packet;
    bool free_batch = false;
    unsigned long orig;
    uint32_t idx = 0;
    int error = 0;
    int ret;

    xsk_info = dev->xsks[qid];
    if (!xsk_info || !xsk_info->xsk) {
        goto out;
    }

    afxdp_complete_tx(xsk_info);

    free_batch = check_free_batch(batch);

    umem = xsk_info->umem;
    ret = umem_elem_pop_n(&umem->mpool, batch->count, elems_pop);
    if (OVS_UNLIKELY(ret)) {
        atomic_add_relaxed(&xsk_info->tx_dropped, batch->count, &orig);
        VLOG_WARN_RL(&rl, "%s: send failed due to exhausted memory pool.",
                     netdev_get_name(netdev));
        error = ENOMEM;
        goto out;
    }

    /* Make sure we have enough TX descs. */
    ret = xsk_ring_prod__reserve(&xsk_info->tx, batch->count, &idx);
    if (OVS_UNLIKELY(ret == 0)) {
        umem_elem_push_n(&umem->mpool, batch->count, elems_pop);
        atomic_add_relaxed(&xsk_info->tx_dropped, batch->count, &orig);
        COVERAGE_INC(afxdp_tx_full);
        afxdp_complete_tx(xsk_info);
        kick_tx(xsk_info, dev->xdpmode);
        error = ENOMEM;
        goto out;
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        uint64_t index;
        void *elem;

        elem = elems_pop[i];
        /* Copy the packet to the umem we just pop from umem pool.
         * TODO: avoid this copy if the packet and the pop umem
         * are located in the same umem.
         */
        memcpy(elem, dp_packet_data(packet), dp_packet_size(packet));

        index = (uint64_t)((char *)elem - (char *)umem->buffer);
        xsk_ring_prod__tx_desc(&xsk_info->tx, idx + i)->addr = index;
        xsk_ring_prod__tx_desc(&xsk_info->tx, idx + i)->len
            = dp_packet_size(packet);
    }
    xsk_ring_prod__submit(&xsk_info->tx, batch->count);
    xsk_info->outstanding_tx += batch->count;

    ret = kick_tx(xsk_info, dev->xdpmode);
    if (OVS_UNLIKELY(ret)) {
        VLOG_WARN_RL(&rl, "%s: error sending AF_XDP packet: %s.",
                     netdev_get_name(netdev), ovs_strerror(ret));
    }

out:
    if (free_batch) {
        free_afxdp_buf_batch(batch);
    } else {
        dp_packet_delete_batch(batch, true);
    }

    return error;
}

int
netdev_afxdp_batch_send(struct netdev *netdev, int qid,
                        struct dp_packet_batch *batch,
                        bool concurrent_txq)
{
    struct netdev_linux *dev;
    int ret;

    if (concurrent_txq) {
        dev = netdev_linux_cast(netdev);
        qid = qid % netdev_n_txq(netdev);

        ovs_spin_lock(&dev->tx_locks[qid]);
        ret = __netdev_afxdp_batch_send(netdev, qid, batch);
        ovs_spin_unlock(&dev->tx_locks[qid]);
    } else {
        ret = __netdev_afxdp_batch_send(netdev, qid, batch);
    }

    return ret;
}

int
netdev_afxdp_rxq_construct(struct netdev_rxq *rxq_ OVS_UNUSED)
{
   /* Done at reconfigure. */
   return 0;
}

void
netdev_afxdp_rxq_destruct(struct netdev_rxq *rxq_ OVS_UNUSED)
{
    /* Nothing. */
}

int
netdev_afxdp_construct(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int ret;

    /* Configure common netdev-linux first. */
    ret = netdev_linux_construct(netdev);
    if (ret) {
        return ret;
    }

    /* Queues should not be used before the first reconfiguration. Clearing. */
    netdev->n_rxq = 0;
    netdev->n_txq = 0;
    dev->xdpmode = 0;

    dev->requested_n_rxq = NR_QUEUE;
    dev->requested_xdpmode = XDP_COPY;

    dev->xsks = NULL;
    dev->tx_locks = NULL;

    netdev_request_reconfigure(netdev);
    return 0;
}

void
netdev_afxdp_destruct(struct netdev *netdev)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct netdev_linux *dev = netdev_linux_cast(netdev);

    if (ovsthread_once_start(&once)) {
        fatal_signal_add_hook(netdev_afxdp_sweep_unused_pools,
                              NULL, NULL, true);
        ovsthread_once_done(&once);
    }

    /* Note: tc is by-passed when using drv-mode, but when using
     * skb-mode, we might need to clean up tc. */

    xsk_destroy_all(netdev);
    ovs_mutex_destroy(&dev->mutex);
}

int
netdev_afxdp_get_stats(const struct netdev *netdev,
                       struct netdev_stats *stats)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info;
    struct netdev_stats dev_stats;
    int error, i;

    ovs_mutex_lock(&dev->mutex);

    error = get_stats_via_netlink(netdev, &dev_stats);
    if (error) {
        VLOG_WARN_RL(&rl, "%s: Error getting AF_XDP statistics.",
                     netdev_get_name(netdev));
    } else {
        /* Use kernel netdev's packet and byte counts. */
        stats->rx_packets = dev_stats.rx_packets;
        stats->rx_bytes = dev_stats.rx_bytes;
        stats->tx_packets = dev_stats.tx_packets;
        stats->tx_bytes = dev_stats.tx_bytes;

        stats->rx_errors           += dev_stats.rx_errors;
        stats->tx_errors           += dev_stats.tx_errors;
        stats->rx_dropped          += dev_stats.rx_dropped;
        stats->tx_dropped          += dev_stats.tx_dropped;
        stats->multicast           += dev_stats.multicast;
        stats->collisions          += dev_stats.collisions;
        stats->rx_length_errors    += dev_stats.rx_length_errors;
        stats->rx_over_errors      += dev_stats.rx_over_errors;
        stats->rx_crc_errors       += dev_stats.rx_crc_errors;
        stats->rx_frame_errors     += dev_stats.rx_frame_errors;
        stats->rx_fifo_errors      += dev_stats.rx_fifo_errors;
        stats->rx_missed_errors    += dev_stats.rx_missed_errors;
        stats->tx_aborted_errors   += dev_stats.tx_aborted_errors;
        stats->tx_carrier_errors   += dev_stats.tx_carrier_errors;
        stats->tx_fifo_errors      += dev_stats.tx_fifo_errors;
        stats->tx_heartbeat_errors += dev_stats.tx_heartbeat_errors;
        stats->tx_window_errors    += dev_stats.tx_window_errors;

        /* Account the dropped in each xsk. */
        for (i = 0; i < netdev_n_rxq(netdev); i++) {
            xsk_info = dev->xsks[i];
            if (xsk_info) {
                uint64_t tx_dropped;

                atomic_read_relaxed(&xsk_info->tx_dropped, &tx_dropped);
                stats->tx_dropped += tx_dropped;
            }
        }
    }
    ovs_mutex_unlock(&dev->mutex);

    return error;
}
