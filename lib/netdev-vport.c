/*
 * Copyright (c) 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or apatched to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "list.h"
#include "netdev-vport.h"
#include "openvswitch/datapath-protocol.h"
#include "shash.h"
#include "socket-util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_vport)

struct netdev_vport_notifier {
    struct netdev_notifier notifier;
    struct list list_node;
    struct shash_node *shash_node;
};

static struct shash netdev_vport_notifiers =
                                    SHASH_INITIALIZER(&netdev_vport_notifiers);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

int
netdev_vport_do_ioctl(int cmd, void *arg)
{
    static int ioctl_fd = -1;

    if (ioctl_fd < 0) {
        ioctl_fd = open("/dev/net/dp0", O_RDONLY | O_NONBLOCK);
        if (ioctl_fd < 0) {
            VLOG_ERR_RL(&rl, "failed to open ioctl fd: %s", strerror(errno));
            return errno;
        }
    }

    return ioctl(ioctl_fd, cmd, arg) ? errno : 0;
}

int
netdev_vport_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct odp_vport_ether vport_ether;
    int err;

    ovs_strlcpy(vport_ether.devname, netdev_get_name(netdev),
                sizeof vport_ether.devname);

    memcpy(vport_ether.ether_addr, mac, ETH_ADDR_LEN);

    err = netdev_vport_do_ioctl(ODP_VPORT_ETHER_SET, &vport_ether);
    if (err) {
        return err;
    }

    netdev_vport_poll_notify(netdev);
    return 0;
}

int
netdev_vport_get_etheraddr(const struct netdev *netdev,
                           uint8_t mac[ETH_ADDR_LEN])
{
    struct odp_vport_ether vport_ether;
    int err;

    ovs_strlcpy(vport_ether.devname, netdev_get_name(netdev),
                sizeof vport_ether.devname);

    err = netdev_vport_do_ioctl(ODP_VPORT_ETHER_GET, &vport_ether);
    if (err) {
        return err;
    }

    memcpy(mac, vport_ether.ether_addr, ETH_ADDR_LEN);
    return 0;
}

int
netdev_vport_get_mtu(const struct netdev *netdev, int *mtup)
{
    struct odp_vport_mtu vport_mtu;
    int err;

    ovs_strlcpy(vport_mtu.devname, netdev_get_name(netdev),
                sizeof vport_mtu.devname);

    err = netdev_vport_do_ioctl(ODP_VPORT_MTU_GET, &vport_mtu);
    if (err) {
        return err;
    }

    *mtup = vport_mtu.mtu;
    return 0;
}

int
netdev_vport_get_carrier(const struct netdev *netdev OVS_UNUSED, bool *carrier)
{
    *carrier = true;
    return 0;
}

int
netdev_vport_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    const char *name = netdev_get_name(netdev);
    struct odp_vport_stats_req ovsr;
    int err;

    ovs_strlcpy(ovsr.devname, name, sizeof ovsr.devname);
    err = netdev_vport_do_ioctl(ODP_VPORT_STATS_GET, &ovsr);
    if (err) {
        return err;
    }

    stats->rx_packets = ovsr.stats.rx_packets;
    stats->tx_packets = ovsr.stats.tx_packets;
    stats->rx_bytes = ovsr.stats.rx_bytes;
    stats->tx_bytes = ovsr.stats.tx_bytes;
    stats->rx_errors = ovsr.stats.rx_errors;
    stats->tx_errors = ovsr.stats.tx_errors;
    stats->rx_dropped = ovsr.stats.rx_dropped;
    stats->tx_dropped = ovsr.stats.tx_dropped;
    stats->multicast = UINT64_MAX;
    stats->collisions = ovsr.stats.collisions;
    stats->rx_length_errors = UINT64_MAX;
    stats->rx_over_errors = ovsr.stats.rx_over_err;
    stats->rx_crc_errors = ovsr.stats.rx_crc_err;
    stats->rx_frame_errors = ovsr.stats.rx_frame_err;
    stats->rx_fifo_errors = UINT64_MAX;
    stats->rx_missed_errors = UINT64_MAX;
    stats->tx_aborted_errors = UINT64_MAX;
    stats->tx_carrier_errors = UINT64_MAX;
    stats->tx_fifo_errors = UINT64_MAX;
    stats->tx_heartbeat_errors = UINT64_MAX;
    stats->tx_window_errors = UINT64_MAX;

    return 0;
}

int
netdev_vport_set_stats(struct netdev *netdev, const struct netdev_stats *stats)
{
    struct odp_vport_stats_req ovsr;
    int err;

    ovs_strlcpy(ovsr.devname, netdev_get_name(netdev), sizeof ovsr.devname);

    ovsr.stats.rx_packets = stats->rx_packets;
    ovsr.stats.tx_packets = stats->tx_packets;
    ovsr.stats.rx_bytes = stats->rx_bytes;
    ovsr.stats.tx_bytes = stats->tx_bytes;
    ovsr.stats.rx_errors = stats->rx_errors;
    ovsr.stats.tx_errors = stats->tx_errors;
    ovsr.stats.rx_dropped = stats->rx_dropped;
    ovsr.stats.tx_dropped = stats->tx_dropped;
    ovsr.stats.collisions = stats->collisions;
    ovsr.stats.rx_over_err = stats->rx_over_errors;
    ovsr.stats.rx_crc_err = stats->rx_crc_errors;
    ovsr.stats.rx_frame_err = stats->rx_frame_errors;

    err = netdev_vport_do_ioctl(ODP_VPORT_STATS_SET, &ovsr);

    /* If the vport layer doesn't know about the device, that doesn't mean it
     * doesn't exist (after all were able to open it when netdev_open() was
     * called), it just means that it isn't attached and we'll be getting
     * stats a different way. */
    if (err == ENODEV) {
        err = EOPNOTSUPP;
    }

    return err;
}

int
netdev_vport_update_flags(struct netdev *netdev OVS_UNUSED,
                        enum netdev_flags off, enum netdev_flags on OVS_UNUSED,
                        enum netdev_flags *old_flagsp)
{
    if (off & (NETDEV_UP | NETDEV_PROMISC)) {
        return EOPNOTSUPP;
    }

    *old_flagsp = NETDEV_UP | NETDEV_PROMISC;
    return 0;
}

static char *
make_poll_name(const struct netdev *netdev)
{
    return xasprintf("%s:%s", netdev_get_type(netdev), netdev_get_name(netdev));
}

int
netdev_vport_poll_add(struct netdev *netdev,
                      void (*cb)(struct netdev_notifier *), void *aux,
                      struct netdev_notifier **notifierp)
{
    char *poll_name = make_poll_name(netdev);
    struct netdev_vport_notifier *notifier;
    struct list *list;
    struct shash_node *shash_node;

    shash_node = shash_find_data(&netdev_vport_notifiers, poll_name);
    if (!shash_node) {
        list = xmalloc(sizeof *list);
        list_init(list);
        shash_node = shash_add(&netdev_vport_notifiers,
			       netdev_get_name(netdev), list);
    } else {
        list = shash_node->data;
    }

    notifier = xmalloc(sizeof *notifier);
    netdev_notifier_init(&notifier->notifier, netdev, cb, aux);
    list_push_back(list, &notifier->list_node);
    notifier->shash_node = shash_node;

    *notifierp = &notifier->notifier;
    free(poll_name);

    return 0;
}

void
netdev_vport_poll_remove(struct netdev_notifier *notifier_)
{
    struct netdev_vport_notifier *notifier =
                CONTAINER_OF(notifier_, struct netdev_vport_notifier, notifier);

    struct list *list;

    list = list_remove(&notifier->list_node);
    if (list_is_empty(list)) {
        shash_delete(&netdev_vport_notifiers, notifier->shash_node);
        free(list);
    }

    free(notifier);
}

void
netdev_vport_poll_notify(const struct netdev *netdev)
{
    char *poll_name = make_poll_name(netdev);
    struct list *list = shash_find_data(&netdev_vport_notifiers,
                                        poll_name);

    if (list) {
        struct netdev_vport_notifier *notifier;

        LIST_FOR_EACH (notifier, struct netdev_vport_notifier,
                       list_node, list) {
            struct netdev_notifier *n = &notifier->notifier;
            n->cb(n);
        }
    }

    free(poll_name);
}
