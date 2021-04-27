/*
 * Copyright (c) 2019 Nicira, Inc.
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

#ifndef NETDEV_LINUX_PRIVATE_H
#define NETDEV_LINUX_PRIVATE_H 1

#include <linux/filter.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <stdint.h>
#include <stdbool.h>

#include "dp-packet.h"
#include "netdev-afxdp.h"
#include "netdev-afxdp-pool.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "openvswitch/thread.h"
#include "ovs-atomic.h"
#include "timer.h"

struct netdev;

/* The maximum packet length is 16 bits */
#define LINUX_RXQ_TSO_MAX_LEN 65535

struct netdev_rxq_linux {
    struct netdev_rxq up;
    bool is_tap;
    int fd;
    struct dp_packet *aux_bufs[NETDEV_MAX_BURST]; /* Preallocated TSO
                                                     packets. */
};

int netdev_linux_construct(struct netdev *);
void netdev_linux_run(const struct netdev_class *);

int get_stats_via_netlink(const struct netdev *netdev_,
                          struct netdev_stats *stats);

struct netdev_linux {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    unsigned int cache_valid;

    bool miimon;                    /* Link status of last poll. */
    long long int miimon_interval;  /* Miimon Poll rate. Disabled if <= 0. */
    struct timer miimon_timer;

    int netnsid;                    /* Network namespace ID. */
    /* The following are figured out "on demand" only.  They are only valid
     * when the corresponding VALID_* bit in 'cache_valid' is set. */
    int ifindex;
    struct eth_addr etheraddr;
    int mtu;
    unsigned int ifi_flags;
    long long int carrier_resets;
    uint32_t kbits_rate;        /* Policing data. */
    uint32_t kbits_burst;
    int vport_stats_error;      /* Cached error code from vport_get_stats().
                                   0 or an errno value. */
    int netdev_mtu_error;       /* Cached error code from SIOCGIFMTU
                                 * or SIOCSIFMTU.
                                 */
    int ether_addr_error;       /* Cached error code from set/get etheraddr. */
    int netdev_policing_error;  /* Cached error code from set policing. */
    int get_features_error;     /* Cached error code from ETHTOOL_GSET. */
    int get_ifindex_error;      /* Cached error code from SIOCGIFINDEX. */

    enum netdev_features current;    /* Cached from ETHTOOL_GSET. */
    enum netdev_features advertised; /* Cached from ETHTOOL_GSET. */
    enum netdev_features supported;  /* Cached from ETHTOOL_GSET. */

    struct ethtool_drvinfo drvinfo;  /* Cached from ETHTOOL_GDRVINFO. */
    struct tc *tc;

    /* For devices of class netdev_tap_class only. */
    int tap_fd;
    bool present;               /* If the device is present in the namespace */
    uint64_t tx_dropped;        /* tap device can drop if the iface is down */
    uint64_t rx_dropped;        /* Packets dropped while recv from kernel. */

    /* LAG information. */
    bool is_lag_master;         /* True if the netdev is a LAG master. */

    int numa_id;                /* NUMA node id. */

#ifdef HAVE_AF_XDP
    /* AF_XDP information. */
    struct xsk_socket_info **xsks;
    int requested_n_rxq;

    enum afxdp_mode xdp_mode;               /* Configured AF_XDP mode. */
    enum afxdp_mode requested_xdp_mode;     /* Requested  AF_XDP mode. */
    enum afxdp_mode xdp_mode_in_use;        /* Effective  AF_XDP mode. */

    bool use_need_wakeup;
    bool requested_need_wakeup;

    struct netdev_afxdp_tx_lock *tx_locks;  /* Array of locks for TX queues. */
#endif
};

static bool
is_netdev_linux_class(const struct netdev_class *netdev_class)
{
    return netdev_class->run == netdev_linux_run;
}

static struct netdev_linux *
netdev_linux_cast(const struct netdev *netdev)
{
    ovs_assert(is_netdev_linux_class(netdev_get_class(netdev)));

    return CONTAINER_OF(netdev, struct netdev_linux, up);
}

static struct netdev_rxq_linux *
netdev_rxq_linux_cast(const struct netdev_rxq *rx)
{
    ovs_assert(is_netdev_linux_class(netdev_get_class(rx->netdev)));

    return CONTAINER_OF(rx, struct netdev_rxq_linux, up);
}

#endif /* netdev-linux-private.h */
