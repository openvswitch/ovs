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
#include <numa.h>
#include <numaif.h>
#include <poll.h>
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
#include "openvswitch/thread.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
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

#ifdef HAVE_XDP_NEED_WAKEUP
#define NEED_WAKEUP_DEFAULT true
#else
#define NEED_WAKEUP_DEFAULT false
#endif

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
                                             enum afxdp_mode mode,
                                             bool use_need_wakeup,
                                             bool report_socket_failures);
static void xsk_remove_xdp_program(uint32_t ifindex, enum afxdp_mode);
static void xsk_destroy(struct xsk_socket_info *xsk);
static int xsk_configure_all(struct netdev *netdev);
static void xsk_destroy_all(struct netdev *netdev);

static struct {
    const char *name;
    uint32_t bind_flags;
    uint32_t xdp_flags;
} xdp_modes[] = {
    [OVS_AF_XDP_MODE_UNSPEC] = {
        .name = "unspecified",
        .bind_flags = 0,
        .xdp_flags = 0,
    },
    [OVS_AF_XDP_MODE_BEST_EFFORT] = {
        .name = "best-effort",
        .bind_flags = 0,
        .xdp_flags = 0,
    },
    [OVS_AF_XDP_MODE_NATIVE_ZC] = {
        .name = "native-with-zerocopy",
        .bind_flags = XDP_ZEROCOPY,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
    },
    [OVS_AF_XDP_MODE_NATIVE] = {
        .name = "native",
        .bind_flags = XDP_COPY,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
    },
    [OVS_AF_XDP_MODE_GENERIC] = {
        .name = "generic",
        .bind_flags = XDP_COPY,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
    },
};

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

struct netdev_afxdp_tx_lock {
    /* Padding to make netdev_afxdp_tx_lock exactly one cache line long. */
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct ovs_spin lock;
    );
};

#ifdef HAVE_XDP_NEED_WAKEUP
static inline void
xsk_rx_wakeup_if_needed(struct xsk_umem_info *umem,
                        struct netdev *netdev, int fd)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct pollfd pfd;
    int ret;

    if (!dev->use_need_wakeup) {
        return;
    }

    if (xsk_ring_prod__needs_wakeup(&umem->fq)) {
        pfd.fd = fd;
        pfd.events = POLLIN;

        ret = poll(&pfd, 1, 0);
        if (OVS_UNLIKELY(ret < 0)) {
            VLOG_WARN_RL(&rl, "%s: error polling rx fd: %s.",
                         netdev_get_name(netdev),
                         ovs_strerror(errno));
        }
    }
}

static inline bool
xsk_tx_need_wakeup(struct xsk_socket_info *xsk_info)
{
    return xsk_ring_prod__needs_wakeup(&xsk_info->tx);
}

#else /* !HAVE_XDP_NEED_WAKEUP */
static inline void
xsk_rx_wakeup_if_needed(struct xsk_umem_info *umem OVS_UNUSED,
                        struct netdev *netdev OVS_UNUSED,
                        int fd OVS_UNUSED)
{
    /* Nothing. */
}

static inline bool
xsk_tx_need_wakeup(struct xsk_socket_info *xsk_info OVS_UNUSED)
{
    return true;
}
#endif /* HAVE_XDP_NEED_WAKEUP */

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
xsk_configure_umem(void *buffer, uint64_t size)
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
        VLOG_ERR("xsk_umem__create failed: %s.", ovs_strerror(errno));
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
                     uint32_t queue_id, enum afxdp_mode mode,
                     bool use_need_wakeup, bool report_socket_failures)
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
    cfg.bind_flags = xdp_modes[mode].bind_flags;
    cfg.xdp_flags = xdp_modes[mode].xdp_flags | XDP_FLAGS_UPDATE_IF_NOEXIST;

#ifdef HAVE_XDP_NEED_WAKEUP
    if (use_need_wakeup) {
        cfg.bind_flags |= XDP_USE_NEED_WAKEUP;
    }
#endif

    if (if_indextoname(ifindex, devname) == NULL) {
        VLOG_ERR("ifindex %d to devname failed (%s)",
                 ifindex, ovs_strerror(errno));
        free(xsk);
        return NULL;
    }

    ret = xsk_socket__create(&xsk->xsk, devname, queue_id, umem->umem,
                             &xsk->rx, &xsk->tx, &cfg);
    if (ret) {
        VLOG(report_socket_failures ? VLL_ERR : VLL_DBG,
             "xsk_socket__create failed (%s) mode: %s, "
             "use-need-wakeup: %s, qid: %d",
             ovs_strerror(errno), xdp_modes[mode].name,
             use_need_wakeup ? "true" : "false", queue_id);
        free(xsk);
        return NULL;
    }

    /* Make sure the built-in AF_XDP program is loaded. */
    ret = bpf_get_link_xdp_id(ifindex, &prog_id, cfg.xdp_flags);
    if (ret || !prog_id) {
        if (ret) {
            VLOG_ERR("Get XDP prog ID failed (%s)", ovs_strerror(errno));
        } else {
            VLOG_ERR("No XDP program is loaded at ifindex %d", ifindex);
        }
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
xsk_configure(int ifindex, int xdp_queue_id, enum afxdp_mode mode,
              bool use_need_wakeup, bool report_socket_failures)
{
    struct xsk_socket_info *xsk;
    struct xsk_umem_info *umem;
    void *bufs;

    netdev_afxdp_sweep_unused_pools(NULL);

    /* Umem memory region. */
    bufs = xmalloc_pagealign(NUM_FRAMES * FRAME_SIZE);
    memset(bufs, 0, NUM_FRAMES * FRAME_SIZE);

    /* Create AF_XDP socket. */
    umem = xsk_configure_umem(bufs, NUM_FRAMES * FRAME_SIZE);
    if (!umem) {
        free_pagealign(bufs);
        return NULL;
    }

    VLOG_DBG("Allocated umem pool at 0x%"PRIxPTR, (uintptr_t) umem);

    xsk = xsk_configure_socket(umem, ifindex, xdp_queue_id, mode,
                               use_need_wakeup, report_socket_failures);
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
xsk_configure_queue(struct netdev_linux *dev, int ifindex, int queue_id,
                    enum afxdp_mode mode, bool report_socket_failures)
{
    struct xsk_socket_info *xsk_info;

    VLOG_DBG("%s: configuring queue: %d, mode: %s, use-need-wakeup: %s.",
             netdev_get_name(&dev->up), queue_id, xdp_modes[mode].name,
             dev->use_need_wakeup ? "true" : "false");
    xsk_info = xsk_configure(ifindex, queue_id, mode, dev->use_need_wakeup,
                             report_socket_failures);
    if (!xsk_info) {
        VLOG(report_socket_failures ? VLL_ERR : VLL_DBG,
             "%s: Failed to create AF_XDP socket on queue %d in %s mode.",
             netdev_get_name(&dev->up), queue_id, xdp_modes[mode].name);
        dev->xsks[queue_id] = NULL;
        return -1;
    }
    dev->xsks[queue_id] = xsk_info;
    atomic_init(&xsk_info->tx_dropped, 0);
    xsk_info->outstanding_tx = 0;
    xsk_info->available_rx = PROD_NUM_DESCS;
    return 0;
}


static int
xsk_configure_all(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int i, ifindex, n_rxq, n_txq;
    int qid = 0;

    ifindex = linux_get_ifindex(netdev_get_name(netdev));

    ovs_assert(dev->xsks == NULL);
    ovs_assert(dev->tx_locks == NULL);

    n_rxq = netdev_n_rxq(netdev);
    dev->xsks = xcalloc(n_rxq, sizeof *dev->xsks);

    if (dev->xdp_mode == OVS_AF_XDP_MODE_BEST_EFFORT) {
        /* Trying to configure first queue with different modes to
         * find the most suitable. */
        for (i = OVS_AF_XDP_MODE_NATIVE_ZC; i < OVS_AF_XDP_MODE_MAX; i++) {
            if (!xsk_configure_queue(dev, ifindex, qid, i,
                                     i == OVS_AF_XDP_MODE_MAX - 1)) {
                dev->xdp_mode_in_use = i;
                VLOG_INFO("%s: %s XDP mode will be in use.",
                          netdev_get_name(netdev), xdp_modes[i].name);
                break;
            }
        }
        if (i == OVS_AF_XDP_MODE_MAX) {
            VLOG_ERR("%s: Failed to detect suitable XDP mode.",
                     netdev_get_name(netdev));
            goto err;
        }
        qid++;
    } else {
        dev->xdp_mode_in_use = dev->xdp_mode;
    }

    /* Configure remaining queues. */
    for (; qid < n_rxq; qid++) {
        if (xsk_configure_queue(dev, ifindex, qid,
                                dev->xdp_mode_in_use, true)) {
            VLOG_ERR("%s: Failed to create AF_XDP socket on queue %d.",
                     netdev_get_name(netdev), qid);
            goto err;
        }
    }

    n_txq = netdev_n_txq(netdev);
    dev->tx_locks = xzalloc_cacheline(n_txq * sizeof *dev->tx_locks);

    for (i = 0; i < n_txq; i++) {
        ovs_spin_init(&dev->tx_locks[i].lock);
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
                VLOG_DBG("%s: Destroyed xsk[%d].", netdev_get_name(netdev), i);
            }
        }

        free(dev->xsks);
        dev->xsks = NULL;
    }

    VLOG_INFO("%s: Removing xdp program.", netdev_get_name(netdev));
    ifindex = linux_get_ifindex(netdev_get_name(netdev));
    xsk_remove_xdp_program(ifindex, dev->xdp_mode_in_use);

    if (dev->tx_locks) {
        for (i = 0; i < netdev_n_txq(netdev); i++) {
            ovs_spin_destroy(&dev->tx_locks[i].lock);
        }
        free_cacheline(dev->tx_locks);
        dev->tx_locks = NULL;
    }
}

int
netdev_afxdp_set_config(struct netdev *netdev, const struct smap *args,
                        char **errp OVS_UNUSED)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    const char *str_xdp_mode;
    enum afxdp_mode xdp_mode;
    bool need_wakeup;
    int new_n_rxq;

    ovs_mutex_lock(&dev->mutex);
    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq > MAX_XSKQ) {
        ovs_mutex_unlock(&dev->mutex);
        VLOG_ERR("%s: Too big 'n_rxq' (%d > %d).",
                 netdev_get_name(netdev), new_n_rxq, MAX_XSKQ);
        return EINVAL;
    }

    str_xdp_mode = smap_get_def(args, "xdp-mode", "best-effort");
    for (xdp_mode = OVS_AF_XDP_MODE_BEST_EFFORT;
         xdp_mode < OVS_AF_XDP_MODE_MAX;
         xdp_mode++) {
        if (!strcasecmp(str_xdp_mode, xdp_modes[xdp_mode].name)) {
            break;
        }
    }
    if (xdp_mode == OVS_AF_XDP_MODE_MAX) {
        VLOG_ERR("%s: Incorrect xdp-mode (%s).",
                 netdev_get_name(netdev), str_xdp_mode);
        ovs_mutex_unlock(&dev->mutex);
        return EINVAL;
    }

    need_wakeup = smap_get_bool(args, "use-need-wakeup", NEED_WAKEUP_DEFAULT);
#ifndef HAVE_XDP_NEED_WAKEUP
    if (need_wakeup) {
        VLOG_WARN("XDP need_wakeup is not supported in libbpf.");
        need_wakeup = false;
    }
#endif

    if (dev->requested_n_rxq != new_n_rxq
        || dev->requested_xdp_mode != xdp_mode
        || dev->requested_need_wakeup != need_wakeup) {
        dev->requested_n_rxq = new_n_rxq;
        dev->requested_xdp_mode = xdp_mode;
        dev->requested_need_wakeup = need_wakeup;
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
    smap_add_format(args, "xdp-mode", "%s", xdp_modes[dev->xdp_mode].name);
    smap_add_format(args, "xdp-mode-in-use", "%s",
                    xdp_modes[dev->xdp_mode_in_use].name);
    smap_add_format(args, "use-need-wakeup", "%s",
                    dev->use_need_wakeup ? "true" : "false");
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

int
netdev_afxdp_reconfigure(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bitmask *old_bm = NULL;
    int old_policy, numa_id;
    int err = 0;

    /* Allocate all the xsk related memory in the netdev's NUMA domain. */
    if (numa_available() != -1 && ovs_numa_get_n_numas() > 1) {
        numa_id = netdev_get_numa_id(netdev);
        if (numa_id != NETDEV_NUMA_UNSPEC) {
            old_bm = numa_allocate_nodemask();
            if (get_mempolicy(&old_policy, old_bm->maskp, old_bm->size + 1,
                              NULL, 0)) {
                VLOG_INFO("Failed to get NUMA memory policy: %s.",
                          ovs_strerror(errno));
                numa_bitmask_free(old_bm);
                old_bm = NULL;
            } else {
                numa_set_preferred(numa_id);
            }
        }
    }

    ovs_mutex_lock(&dev->mutex);

    if (netdev->n_rxq == dev->requested_n_rxq
        && dev->xdp_mode == dev->requested_xdp_mode
        && dev->use_need_wakeup == dev->requested_need_wakeup
        && dev->xsks) {
        goto out;
    }

    xsk_destroy_all(netdev);

    netdev->n_rxq = dev->requested_n_rxq;
    netdev->n_txq = netdev->n_rxq;

    dev->xdp_mode = dev->requested_xdp_mode;
    VLOG_INFO("%s: Setting XDP mode to %s.", netdev_get_name(netdev),
              xdp_modes[dev->xdp_mode].name);

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        VLOG_ERR("setrlimit(RLIMIT_MEMLOCK) failed: %s", ovs_strerror(errno));
    }
    dev->use_need_wakeup = dev->requested_need_wakeup;

    err = xsk_configure_all(netdev);
    if (err) {
        VLOG_ERR("%s: AF_XDP device reconfiguration failed.",
                 netdev_get_name(netdev));
    }
    netdev_change_seq_changed(netdev);
out:
    ovs_mutex_unlock(&dev->mutex);
    if (old_bm) {
        if (set_mempolicy(old_policy, old_bm->maskp, old_bm->size + 1)) {
            VLOG_WARN("Failed to restore NUMA memory policy: %s.",
                      ovs_strerror(errno));
            /* Can't restore correctly.  Try to use localalloc as the most
             * likely default memory policy. */
            numa_set_localalloc();
        }
        numa_bitmask_free(old_bm);
    }
    return err;
}

static void
xsk_remove_xdp_program(uint32_t ifindex, enum afxdp_mode mode)
{
    uint32_t flags = xdp_modes[mode].xdp_flags | XDP_FLAGS_UPDATE_IF_NOEXIST;
    uint32_t ret, prog_id = 0;

    /* Check whether XDP program is loaded. */
    ret = bpf_get_link_xdp_id(ifindex, &prog_id, flags);
    if (ret) {
        VLOG_ERR("Failed to get XDP prog id (%s)", ovs_strerror(errno));
        return;
    }

    if (!prog_id) {
        VLOG_INFO("No XDP program is loaded at ifindex %d", ifindex);
        return;
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
    xsk_remove_xdp_program(ifindex, dev->xdp_mode_in_use);
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
        xsk_rx_wakeup_if_needed(umem, netdev, rx->fd);
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
    return 0;
}

static inline int
kick_tx(struct xsk_socket_info *xsk_info, enum afxdp_mode mode,
        bool use_need_wakeup)
{
    int ret, retries;
    static const int KERNEL_TX_BATCH_SIZE = 16;

    if (use_need_wakeup && !xsk_tx_need_wakeup(xsk_info)) {
        return 0;
    }

    /* In all modes except native-with-zerocopy packet transmission is
     * synchronous, and the kernel xmits only TX_BATCH_SIZE(16) packets for a
     * single sendmsg syscall.
     * So, we have to kick the kernel (n_packets / 16) times to be sure that
     * all packets are transmitted. */
    retries = (mode != OVS_AF_XDP_MODE_NATIVE_ZC)
              ? xsk_info->outstanding_tx / KERNEL_TX_BATCH_SIZE
              : 0;
kick_retry:
    /* This causes system call into kernel's xsk_sendmsg, and xsk_generic_xmit
     * (generic and native modes) or xsk_zc_xmit (native-with-zerocopy mode).
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
    umem_elem_push_n(xpacket->mpool, dp_packet_batch_size(batch), elems);
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
    ret = umem_elem_pop_n(&umem->mpool, dp_packet_batch_size(batch),
                          elems_pop);
    if (OVS_UNLIKELY(ret)) {
        atomic_add_relaxed(&xsk_info->tx_dropped, dp_packet_batch_size(batch),
                           &orig);
        VLOG_WARN_RL(&rl, "%s: send failed due to exhausted memory pool.",
                     netdev_get_name(netdev));
        error = ENOMEM;
        goto out;
    }

    /* Make sure we have enough TX descs. */
    ret = xsk_ring_prod__reserve(&xsk_info->tx, dp_packet_batch_size(batch),
                                 &idx);
    if (OVS_UNLIKELY(ret == 0)) {
        umem_elem_push_n(&umem->mpool, dp_packet_batch_size(batch), elems_pop);
        atomic_add_relaxed(&xsk_info->tx_dropped, dp_packet_batch_size(batch),
                           &orig);
        COVERAGE_INC(afxdp_tx_full);
        afxdp_complete_tx(xsk_info);
        kick_tx(xsk_info, dev->xdp_mode_in_use, dev->use_need_wakeup);
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
    xsk_ring_prod__submit(&xsk_info->tx, dp_packet_batch_size(batch));
    xsk_info->outstanding_tx += dp_packet_batch_size(batch);

    ret = kick_tx(xsk_info, dev->xdp_mode_in_use, dev->use_need_wakeup);
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

        ovs_spin_lock(&dev->tx_locks[qid].lock);
        ret = __netdev_afxdp_batch_send(netdev, qid, batch);
        ovs_spin_unlock(&dev->tx_locks[qid].lock);
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

static int
libbpf_print(enum libbpf_print_level level,
             const char *format, va_list args)
{
    if (level == LIBBPF_WARN) {
        vlog_valist(&this_module, VLL_WARN, format, args);
    } else if (level == LIBBPF_INFO) {
        vlog_valist(&this_module, VLL_INFO, format, args);
    } else {
        vlog_valist(&this_module, VLL_DBG, format, args);
    }
    return 0;
}

int netdev_afxdp_init(void)
{
    libbpf_set_print(libbpf_print);
    return 0;
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
    dev->xdp_mode = OVS_AF_XDP_MODE_UNSPEC;
    dev->xdp_mode_in_use = OVS_AF_XDP_MODE_UNSPEC;

    dev->requested_n_rxq = NR_QUEUE;
    dev->requested_xdp_mode = OVS_AF_XDP_MODE_BEST_EFFORT;
    dev->requested_need_wakeup = NEED_WAKEUP_DEFAULT;

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
netdev_afxdp_verify_mtu_size(const struct netdev *netdev OVS_UNUSED, int mtu)
{
    /*
     * If a device is used in xdpmode skb, no driver-specific MTU size is
     * checked and any value is allowed resulting in packet drops.
     * This check will verify the maximum supported value based on the
     * buffer size allocated and the additional headroom required.
     */
    if (mtu > (FRAME_SIZE - OVS_XDP_HEADROOM -
               XDP_PACKET_HEADROOM - VLAN_ETH_HEADER_LEN)) {
        return EINVAL;
    }

    return 0;
}

int
netdev_afxdp_get_custom_stats(const struct netdev *netdev,
                              struct netdev_custom_stats *custom_stats)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info;
    struct xdp_statistics stat;
    uint32_t i, c = 0;
    socklen_t optlen;

    ovs_mutex_lock(&dev->mutex);

#define XDP_CSTATS                                                           \
    XDP_CSTAT(rx_dropped)                                                    \
    XDP_CSTAT(rx_invalid_descs)                                              \
    XDP_CSTAT(tx_invalid_descs)

#define XDP_CSTAT(NAME) + 1
    enum { N_XDP_CSTATS = XDP_CSTATS };
#undef XDP_CSTAT

    custom_stats->counters = xcalloc(netdev_n_rxq(netdev) * N_XDP_CSTATS,
                                     sizeof *custom_stats->counters);

    /* Account the stats for each xsk. */
    for (i = 0; i < netdev_n_rxq(netdev); i++) {
        xsk_info = dev->xsks[i];
        optlen  = sizeof stat;

        if (xsk_info && !getsockopt(xsk_socket__fd(xsk_info->xsk), SOL_XDP,
                                    XDP_STATISTICS, &stat, &optlen)) {
#define XDP_CSTAT(NAME)                                                      \
            snprintf(custom_stats->counters[c].name,                         \
                     NETDEV_CUSTOM_STATS_NAME_SIZE,                          \
                     "xsk_queue_%d_" #NAME, i);                              \
            custom_stats->counters[c++].value = stat.NAME;
            XDP_CSTATS;
#undef XDP_CSTAT
        }
    }
    custom_stats->size = c;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
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
