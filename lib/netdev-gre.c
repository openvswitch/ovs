/*
 * Copyright (c) 2010 Nicira Networks.
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
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "list.h"
#include "netdev-provider.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "openvswitch/gre.h"
#include "packets.h"
#include "shash.h"
#include "socket-util.h"

#define THIS_MODULE VLM_netdev_gre
#include "vlog.h"

struct netdev_dev_gre {
    struct netdev_dev netdev_dev;
};

struct netdev_gre {
    struct netdev netdev;
};

struct netdev_gre_notifier {
    struct netdev_notifier notifier;
    struct list node;
};

static int ioctl_fd = -1;
static struct shash netdev_gre_notifiers =
                                    SHASH_INITIALIZER(&netdev_gre_notifiers);

static void poll_notify(const struct netdev_gre *netdev);

static struct netdev_dev_gre *
netdev_dev_gre_cast(const struct netdev_dev *netdev_dev)
{
    netdev_dev_assert_class(netdev_dev, &netdev_grenew_class);
    return CONTAINER_OF(netdev_dev, struct netdev_dev_gre, netdev_dev);
}

static struct netdev_gre *
netdev_gre_cast(const struct netdev *netdev)
{
    netdev_assert_class(netdev, &netdev_grenew_class);
    return CONTAINER_OF(netdev, struct netdev_gre, netdev);
}

static int
netdev_gre_init(void)
{
    static int status = -1;
    if (status < 0) {
        ioctl_fd = open("/dev/net/dp0", O_RDONLY | O_NONBLOCK);
        status = ioctl_fd >= 0 ? 0 : errno;
        if (status) {
            VLOG_ERR("failed to open ioctl fd: %s", strerror(status));
        }
    }
    return status;
}

static int
do_ioctl(int cmd, void *arg)
{
    return ioctl(ioctl_fd, cmd, arg) ? errno : 0;
}

static int
parse_config(const char *name, const struct shash *args,
             struct gre_port_config *config)
{
    struct shash_node *node;

    memset(config, 0, sizeof *config);

    config->flags |= GRE_F_IN_CSUM;
    config->flags |= GRE_F_OUT_CSUM;
    config->flags |= GRE_F_PMTUD;

    SHASH_FOR_EACH (node, args) {
        if (!strcmp(node->name, "remote_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->data, &in_addr)) {
                VLOG_WARN("%s: bad gre 'remote_ip'", name);
            } else {
                config->daddr = in_addr.s_addr;
            }
        } else if (!strcmp(node->name, "local_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->data, &in_addr)) {
                VLOG_WARN("%s: bad gre 'local_ip'", name);
            } else {
                config->saddr = in_addr.s_addr;
            }
        } else if (!strcmp(node->name, "key")) {
            if (!strcmp(node->data, "flow")) {
                config->flags |= GRE_F_IN_KEY_MATCH;
                config->flags |= GRE_F_OUT_KEY_ACTION;
            } else {
                config->out_key = config->in_key = htonl(atoi(node->data));
            }
        } else if (!strcmp(node->name, "in_key")) {
            if (!strcmp(node->data, "flow")) {
                config->flags |= GRE_F_IN_KEY_MATCH;
            } else {
                config->in_key = htonl(atoi(node->data));
            }
        } else if (!strcmp(node->name, "out_key")) {
            if (!strcmp(node->data, "flow")) {
                config->flags |= GRE_F_OUT_KEY_ACTION;
            } else {
                config->out_key = htonl(atoi(node->data));
            }
        } else if (!strcmp(node->name, "tos")) {
            if (!strcmp(node->data, "inherit")) {
                config->flags |= GRE_F_TOS_INHERIT;
            } else {
                config->tos = atoi(node->data);
            }
        } else if (!strcmp(node->name, "ttl")) {
            if (!strcmp(node->data, "inherit")) {
                config->flags |= GRE_F_TTL_INHERIT;
            } else {
                config->ttl = atoi(node->data);
            }
        } else if (!strcmp(node->name, "csum")) {
            if (!strcmp(node->data, "false")) {
                config->flags &= ~GRE_F_IN_CSUM;
                config->flags &= ~GRE_F_OUT_CSUM;
            }
        } else if (!strcmp(node->name, "pmtud")) {
            if (!strcmp(node->data, "false")) {
                config->flags &= ~GRE_F_PMTUD;
            }
        } else {
            VLOG_WARN("%s: unknown gre argument '%s'", name, node->name);
        }
    }

    if (!config->daddr) {
        VLOG_WARN("%s: gre type requires valid 'remote_ip' argument", name);
        return EINVAL;
    }

    return 0;
}

static int
netdev_gre_create(const char *name, const char *type OVS_UNUSED,
                  const struct shash *args, struct netdev_dev **netdev_devp)
{
    int err;
    struct odp_vport_add ova;
    struct gre_port_config port_config;
    struct netdev_dev_gre *netdev_dev;

    ovs_strlcpy(ova.port_type, "gre", sizeof ova.port_type);
    ovs_strlcpy(ova.devname, name, sizeof ova.devname);
    ova.config = &port_config;

    err = parse_config(name, args, &port_config);
    if (err) {
        return err;
    }

    err = do_ioctl(ODP_VPORT_ADD, &ova);
    if (err == EEXIST) {
        VLOG_WARN("%s: destroying existing device", name);

        err = do_ioctl(ODP_VPORT_DEL, ova.devname);
        if (err) {
            return err;
        }

        err = do_ioctl(ODP_VPORT_ADD, &ova);
    }

    if (err) {
        return err;
    }

    netdev_dev = xmalloc(sizeof *netdev_dev);
    netdev_dev_init(&netdev_dev->netdev_dev, name, &netdev_grenew_class);

    *netdev_devp = &netdev_dev->netdev_dev;
    return 0;
}

static int
netdev_gre_reconfigure(struct netdev_dev *netdev_dev_, const struct shash *args)
{
    const char *name = netdev_dev_get_name(netdev_dev_);
    struct odp_vport_mod ovm;
    struct gre_port_config port_config;
    int err;

    ovs_strlcpy(ovm.devname, name, sizeof ovm.devname);
    ovm.config = &port_config;

    err = parse_config(name, args, &port_config);
    if (err) {
        return err;
    }

    return do_ioctl(ODP_VPORT_MOD, &ovm);
}

static void
netdev_gre_destroy(struct netdev_dev *netdev_dev_)
{
    struct netdev_dev_gre *netdev_dev = netdev_dev_gre_cast(netdev_dev_);

    do_ioctl(ODP_VPORT_DEL, (char *)netdev_dev_get_name(netdev_dev_));
    free(netdev_dev);
}

static int
netdev_gre_open(struct netdev_dev *netdev_dev_, int ethertype OVS_UNUSED,
                struct netdev **netdevp)
{
    struct netdev_gre *netdev;

    netdev = xmalloc(sizeof *netdev);
    netdev_init(&netdev->netdev, netdev_dev_);

    *netdevp = &netdev->netdev;
    return 0;
}

static void
netdev_gre_close(struct netdev *netdev_)
{
    struct netdev_gre *netdev = netdev_gre_cast(netdev_);
    free(netdev);
}

static int
netdev_gre_set_etheraddr(struct netdev *netdev_,
                         const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_gre *netdev = netdev_gre_cast(netdev_);
    struct odp_vport_ether vport_ether;
    int err;

    ovs_strlcpy(vport_ether.devname, netdev_get_name(netdev_),
                sizeof vport_ether.devname);

    memcpy(vport_ether.ether_addr, mac, ETH_ADDR_LEN);

    err = ioctl(ioctl_fd, ODP_VPORT_ETHER_SET, &vport_ether);
    if (err) {
        return err;
    }

    poll_notify(netdev);
    return 0;
}

static int
netdev_gre_get_etheraddr(const struct netdev *netdev_,
                         uint8_t mac[ETH_ADDR_LEN])
{
    struct odp_vport_ether vport_ether;
    int err;

    ovs_strlcpy(vport_ether.devname, netdev_get_name(netdev_),
                sizeof vport_ether.devname);

    err = ioctl(ioctl_fd, ODP_VPORT_ETHER_GET, &vport_ether);
    if (err) {
        return err;
    }

    memcpy(mac, vport_ether.ether_addr, ETH_ADDR_LEN);
    return 0;
}

static int
netdev_gre_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct odp_vport_mtu vport_mtu;
    int err;

    ovs_strlcpy(vport_mtu.devname, netdev_get_name(netdev_),
                sizeof vport_mtu.devname);

    err = ioctl(ioctl_fd, ODP_VPORT_MTU_GET, &vport_mtu);
    if (err) {
        return err;
    }

    *mtup = vport_mtu.mtu;
    return 0;
}

static int
netdev_gre_get_carrier(const struct netdev *netdev OVS_UNUSED, bool *carrier)
{
    *carrier = true;
    return 0;
}

static int
netdev_gre_get_stats(const struct netdev *netdev_, struct netdev_stats *stats)
{
    const char *name = netdev_get_name(netdev_);
    struct odp_vport_stats_req ovsr;
    int err;

    ovs_strlcpy(ovsr.devname, name, sizeof ovsr.devname);
    err = do_ioctl(ODP_VPORT_STATS_GET, &ovsr);
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

static int
netdev_gre_update_flags(struct netdev *netdev OVS_UNUSED,
                        enum netdev_flags off, enum netdev_flags on OVS_UNUSED,
                        enum netdev_flags *old_flagsp)
{
    if (off & (NETDEV_UP | NETDEV_PROMISC)) {
        return EOPNOTSUPP;
    }

    *old_flagsp = NETDEV_UP | NETDEV_PROMISC;
    return 0;
}

static int
netdev_gre_poll_add(struct netdev *netdev, void (*cb)(struct netdev_notifier *),
                    void *aux, struct netdev_notifier **notifierp)
{
    const char *netdev_name = netdev_get_name(netdev);
    struct netdev_gre_notifier *notifier;
    struct list *list;

    list = shash_find_data(&netdev_gre_notifiers, netdev_name);
    if (!list) {
        list = xmalloc(sizeof *list);
        list_init(list);
        shash_add(&netdev_gre_notifiers, netdev_name, list);
    }

    notifier = xmalloc(sizeof *notifier);
    netdev_notifier_init(&notifier->notifier, netdev, cb, aux);
    list_push_back(list, &notifier->node);

    *notifierp = &notifier->notifier;
    return 0;
}

static void
netdev_gre_poll_remove(struct netdev_notifier *notifier_)
{
    struct netdev_gre_notifier *notifier =
                CONTAINER_OF(notifier_, struct netdev_gre_notifier, notifier);
    struct list *list;

    list = list_remove(&notifier->node);
    if (list_is_empty(list)) {
        const char *netdev_name = netdev_get_name(notifier_->netdev);
        shash_delete(&netdev_gre_notifiers,
                     shash_find(&netdev_gre_notifiers, netdev_name));
        free(list);
    }
    free(notifier);
}

static void
poll_notify(const struct netdev_gre *netdev)
{
    struct list *list = shash_find_data(&netdev_gre_notifiers,
                                        netdev_get_name(&netdev->netdev));

    if (list) {
        struct netdev_gre_notifier *notifier;

        LIST_FOR_EACH (notifier, struct netdev_gre_notifier, node, list) {
            struct netdev_notifier *n = &notifier->notifier;
            n->cb(n);
        }
    }
}

const struct netdev_class netdev_grenew_class = {
    "grenew",

    netdev_gre_init,
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_gre_create,
    netdev_gre_destroy,
    netdev_gre_reconfigure,

    netdev_gre_open,
    netdev_gre_close,

    NULL,                       /* enumerate */

    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* drain */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_gre_set_etheraddr,
    netdev_gre_get_etheraddr,
    netdev_gre_get_mtu,
    NULL,                       /* get_ifindex */
    netdev_gre_get_carrier,
    netdev_gre_get_stats,

    NULL,                       /* get_features */
    NULL,                       /* set_advertisements */
    NULL,                       /* get_vlan_vid */
    NULL,                       /* set_policing */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* arp_lookup */

    netdev_gre_update_flags,

    netdev_gre_poll_add,
    netdev_gre_poll_remove,
};
