/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

#include "netdev-vport.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "byte-order.h"
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "netdev-provider.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "ofpbuf.h"
#include "openvswitch/datapath-protocol.h"
#include "openvswitch/tunnel.h"
#include "packets.h"
#include "rtnetlink.h"
#include "route-table.h"
#include "rtnetlink-link.h"
#include "shash.h"
#include "socket-util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_vport);

static struct hmap name_map;
static struct rtnetlink_notifier netdev_vport_link_notifier;

struct name_node {
    struct hmap_node node; /* Node in name_map. */
    uint32_t ifi_index;    /* Kernel interface index. */

    char ifname[IFNAMSIZ]; /* Interface name. */
};

struct netdev_vport_notifier {
    struct netdev_notifier notifier;
    struct list list_node;
    struct shash_node *shash_node;
};

struct netdev_dev_vport {
    struct netdev_dev netdev_dev;
    uint64_t config[VPORT_CONFIG_SIZE / 8];
};

struct netdev_vport {
    struct netdev netdev;
};

struct vport_class {
    struct netdev_class netdev_class;
    int (*parse_config)(const char *name, const char *type,
                        const struct shash *args, void *config);
    int (*unparse_config)(const char *name, const char *type,
                          const void *config, struct shash *args);
};

static struct shash netdev_vport_notifiers =
                                    SHASH_INITIALIZER(&netdev_vport_notifiers);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static int netdev_vport_do_ioctl(int cmd, void *arg);
static int netdev_vport_create(const struct netdev_class *, const char *,
                               const struct shash *, struct netdev_dev **);
static void netdev_vport_poll_notify(const struct netdev *);

static void netdev_vport_tnl_iface_init(void);
static void netdev_vport_link_change(const struct rtnetlink_link_change *,
                                     void *);
static const char *netdev_vport_get_tnl_iface(const struct netdev *netdev);

static bool
is_vport_class(const struct netdev_class *class)
{
    return class->create == netdev_vport_create;
}

static const struct vport_class *
vport_class_cast(const struct netdev_class *class)
{
    assert(is_vport_class(class));
    return CONTAINER_OF(class, struct vport_class, netdev_class);
}

static struct netdev_dev_vport *
netdev_dev_vport_cast(const struct netdev_dev *netdev_dev)
{
    assert(is_vport_class(netdev_dev_get_class(netdev_dev)));
    return CONTAINER_OF(netdev_dev, struct netdev_dev_vport, netdev_dev);
}

static struct netdev_vport *
netdev_vport_cast(const struct netdev *netdev)
{
    struct netdev_dev *netdev_dev = netdev_get_dev(netdev);
    assert(is_vport_class(netdev_dev_get_class(netdev_dev)));
    return CONTAINER_OF(netdev, struct netdev_vport, netdev);
}

/* If 'netdev' is a vport netdev, copies its kernel configuration into
 * 'config'.  Otherwise leaves 'config' untouched. */
void
netdev_vport_get_config(const struct netdev *netdev, void *config)
{
    const struct netdev_dev *dev = netdev_get_dev(netdev);

    if (is_vport_class(netdev_dev_get_class(dev))) {
        const struct netdev_dev_vport *vport = netdev_dev_vport_cast(dev);
        memcpy(config, vport->config, VPORT_CONFIG_SIZE);
    }
}

static int
netdev_vport_init(void)
{
    netdev_vport_tnl_iface_init();
    route_table_register();
    return 0;
}

static int
netdev_vport_create(const struct netdev_class *netdev_class, const char *name,
                    const struct shash *args,
                    struct netdev_dev **netdev_devp)
{
    const struct vport_class *vport_class = vport_class_cast(netdev_class);
    uint64_t config[VPORT_CONFIG_SIZE / 8];
    struct shash fetched_args;
    int error;

    memset(config, 0, sizeof config);
    shash_init(&fetched_args);

    if (!shash_is_empty(args)) {
        /* Parse the provided configuration. */
        error = vport_class->parse_config(name, netdev_class->type,
                                          args, config);
    } else {
        /* Fetch an existing configuration from the kernel.
         *
         * This case could be ambiguous with initializing a new vport with an
         * empty configuration, but none of the existing vport classes accept
         * an empty configuration. */
        struct odp_port odp_port;

        memset(&odp_port, 0, sizeof odp_port);
        strncpy(odp_port.devname, name, sizeof odp_port.devname);
        error = netdev_vport_do_ioctl(ODP_VPORT_QUERY, &odp_port);
        if (!error) {
            /* XXX verify correct type */
            memcpy(config, odp_port.config, sizeof config);
            error = vport_class->unparse_config(name, netdev_class->type,
                                                odp_port.config,
                                                &fetched_args);
            if (error) {
                VLOG_ERR_RL(&rl, "%s: failed to parse kernel config (%s)",
                            name, strerror(error));
            }
        } else {
            VLOG_ERR_RL(&rl, "%s: vport query failed (%s)",
                        name, strerror(error));
        }
    }

    if (!error) {
        struct netdev_dev_vport *dev;

        dev = xmalloc(sizeof *dev);
        netdev_dev_init(&dev->netdev_dev, name,
                        shash_is_empty(&fetched_args) ? args : &fetched_args,
                        netdev_class);
        memcpy(dev->config, config, sizeof dev->config);

        *netdev_devp = &dev->netdev_dev;
    }

    shash_destroy(&fetched_args);

    return error;
}

static void
netdev_vport_destroy(struct netdev_dev *netdev_dev_)
{
    struct netdev_dev_vport *netdev_dev = netdev_dev_vport_cast(netdev_dev_);

    route_table_unregister();
    free(netdev_dev);
}

static int
netdev_vport_open(struct netdev_dev *netdev_dev_, int ethertype OVS_UNUSED,
                struct netdev **netdevp)
{
    struct netdev_vport *netdev;

    netdev = xmalloc(sizeof *netdev);
    netdev_init(&netdev->netdev, netdev_dev_);

    *netdevp = &netdev->netdev;
    return 0;
}

static void
netdev_vport_close(struct netdev *netdev_)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);
    free(netdev);
}

static int
netdev_vport_set_config(struct netdev_dev *dev_, const struct shash *args)
{
    const struct netdev_class *netdev_class = netdev_dev_get_class(dev_);
    const struct vport_class *vport_class = vport_class_cast(netdev_class);
    struct netdev_dev_vport *dev = netdev_dev_vport_cast(dev_);
    struct odp_port port;
    int error;

    memset(&port, 0, sizeof port);
    strncpy(port.devname, netdev_dev_get_name(dev_), sizeof port.devname);
    strncpy(port.type, netdev_dev_get_type(dev_), sizeof port.type);
    error = vport_class->parse_config(netdev_dev_get_name(dev_),
                                      netdev_dev_get_type(dev_),
                                      args, port.config);
    if (!error && memcmp(port.config, dev->config, sizeof dev->config)) {
        error = netdev_vport_do_ioctl(ODP_VPORT_MOD, &port);
        if (!error || error == ENODEV) {
            /* Either reconfiguration succeeded or this vport is not installed
             * in the kernel (e.g. it hasn't been added to a dpif yet with
             * dpif_port_add()). */
            memcpy(dev->config, port.config, sizeof dev->config);
        }
    }
    return error;
}

static int
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

static int
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

static int
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
    stats->multicast = ovsr.stats.multicast;
    stats->collisions = ovsr.stats.collisions;
    stats->rx_length_errors = ovsr.stats.rx_length_errors;
    stats->rx_over_errors = ovsr.stats.rx_over_errors;
    stats->rx_crc_errors = ovsr.stats.rx_crc_errors;
    stats->rx_frame_errors = ovsr.stats.rx_frame_errors;
    stats->rx_fifo_errors = ovsr.stats.rx_fifo_errors;
    stats->rx_missed_errors = ovsr.stats.rx_missed_errors;
    stats->tx_aborted_errors = ovsr.stats.tx_aborted_errors;
    stats->tx_carrier_errors = ovsr.stats.tx_carrier_errors;
    stats->tx_fifo_errors = ovsr.stats.tx_fifo_errors;
    stats->tx_heartbeat_errors = ovsr.stats.tx_heartbeat_errors;
    stats->tx_window_errors = ovsr.stats.tx_window_errors;

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
    ovsr.stats.multicast = stats->multicast;
    ovsr.stats.collisions = stats->collisions;
    ovsr.stats.rx_length_errors = stats->rx_length_errors;
    ovsr.stats.rx_over_errors = stats->rx_over_errors;
    ovsr.stats.rx_crc_errors = stats->rx_crc_errors;
    ovsr.stats.rx_frame_errors = stats->rx_frame_errors;
    ovsr.stats.rx_fifo_errors = stats->rx_fifo_errors;
    ovsr.stats.rx_missed_errors = stats->rx_missed_errors;
    ovsr.stats.tx_aborted_errors = stats->tx_aborted_errors;
    ovsr.stats.tx_carrier_errors = stats->tx_carrier_errors;
    ovsr.stats.tx_fifo_errors = stats->tx_fifo_errors;
    ovsr.stats.tx_heartbeat_errors = stats->tx_heartbeat_errors;
    ovsr.stats.tx_window_errors = stats->tx_window_errors;

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

static int
netdev_vport_get_status(const struct netdev *netdev, struct shash *sh)
{
    const char *iface = netdev_vport_get_tnl_iface(netdev);

    if (iface) {
        struct netdev *egress_netdev;

        shash_add(sh, "tunnel_egress_iface", xstrdup(iface));

        if (!netdev_open_default(iface, &egress_netdev)) {
            shash_add(sh, "tunnel_egress_iface_carrier",
                      xstrdup(netdev_get_carrier(egress_netdev)
                              ? "up" : "down"));
            netdev_close(egress_netdev);
        }
    }

    return 0;
}

static int
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

static int
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
        shash_node = shash_add(&netdev_vport_notifiers, poll_name, list);
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

static void
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

static void
netdev_vport_run(void)
{
    rtnetlink_link_notifier_run();
    route_table_run();
}

static void
netdev_vport_wait(void)
{
    rtnetlink_link_notifier_wait();
    route_table_wait();
}

/* get_tnl_iface() implementation. */

static struct name_node *
name_node_lookup(int ifi_index)
{
    struct name_node *nn;

    HMAP_FOR_EACH_WITH_HASH(nn, node, hash_int(ifi_index, 0), &name_map) {
        if (nn->ifi_index == ifi_index) {
            return nn;
        }
    }

    return NULL;
}

/* Queries the kernel for fresh data to populate the name map with. */
static int
netdev_vport_reset_names(void)
{
    int error;
    struct nl_dump dump;
    struct rtgenmsg *rtmsg;
    struct ofpbuf request, reply;
    static struct nl_sock *rtnl_sock;
    struct name_node *nn, *nn_next;

    HMAP_FOR_EACH_SAFE(nn, nn_next, node, &name_map) {
        hmap_remove(&name_map, &nn->node);
        free(nn);
    }

    error = nl_sock_create(NETLINK_ROUTE, &rtnl_sock);
    if (error) {
        VLOG_WARN_RL(&rl, "Failed to create NETLINK_ROUTE socket");
        return error;
    }

    ofpbuf_init(&request, 0);

    nl_msg_put_nlmsghdr(&request, sizeof *rtmsg, RTM_GETLINK, NLM_F_REQUEST);

    rtmsg = ofpbuf_put_zeros(&request, sizeof *rtmsg);
    rtmsg->rtgen_family = AF_INET;

    nl_dump_start(&dump, rtnl_sock, &request);

    while (nl_dump_next(&dump, &reply)) {
        struct rtnetlink_link_change change;

        if (rtnetlink_link_parse(&reply, &change)) {
            netdev_vport_link_change(&change, NULL);
        }
    }
    nl_sock_destroy(rtnl_sock);

    return nl_dump_done(&dump);
}

static void
netdev_vport_link_change(const struct rtnetlink_link_change *change,
                         void *aux OVS_UNUSED)
{

    if (!change) {
        netdev_vport_reset_names();
    } else if (change->nlmsg_type == RTM_NEWLINK) {
        struct name_node *nn;

        if (name_node_lookup(change->ifi_index)) {
            return;
        }

        nn            = xzalloc(sizeof *nn);
        nn->ifi_index = change->ifi_index;

        strncpy(nn->ifname, change->ifname, IFNAMSIZ);
        nn->ifname[IFNAMSIZ - 1] = '\0';

        hmap_insert(&name_map, &nn->node, hash_int(nn->ifi_index, 0));
    } else if (change->nlmsg_type == RTM_DELLINK) {
        struct name_node *nn;

        nn = name_node_lookup(change->ifi_index);

        if (nn) {
            hmap_remove(&name_map, &nn->node);
            free(nn);
        }

    } else {
        VLOG_WARN_RL(&rl, "Received unexpected rtnetlink message type %d",
                     change->nlmsg_type);
    }
}

static void
netdev_vport_tnl_iface_init(void)
{
    static bool tnl_iface_is_init = false;

    if (!tnl_iface_is_init) {
        hmap_init(&name_map);

        rtnetlink_link_notifier_register(&netdev_vport_link_notifier,
                                         netdev_vport_link_change, NULL);

        netdev_vport_reset_names();
        tnl_iface_is_init = true;
    }
}

static const char *
netdev_vport_get_tnl_iface(const struct netdev *netdev)
{
    int ifindex;
    uint32_t route;
    struct netdev_dev_vport *ndv;
    struct tnl_port_config *config;

    ndv = netdev_dev_vport_cast(netdev_get_dev(netdev));
    config = (struct tnl_port_config *) ndv->config;
    route = config->daddr;

    if (route_table_get_ifindex(route, &ifindex)) {
        struct name_node *nn;
        HMAP_FOR_EACH_WITH_HASH(nn, node, hash_int(ifindex, 0), &name_map) {
            if (nn->ifi_index == ifindex) {
                return nn->ifname;
            }
        }
    }

    return NULL;
}

/* Helper functions. */

static int
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

static void
netdev_vport_poll_notify(const struct netdev *netdev)
{
    char *poll_name = make_poll_name(netdev);
    struct list *list = shash_find_data(&netdev_vport_notifiers,
                                        poll_name);

    if (list) {
        struct netdev_vport_notifier *notifier;

        LIST_FOR_EACH (notifier, list_node, list) {
            struct netdev_notifier *n = &notifier->notifier;
            n->cb(n);
        }
    }

    free(poll_name);
}

/* Code specific to individual vport types. */

static int
parse_tunnel_config(const char *name, const char *type,
                    const struct shash *args, void *configp)
{
    bool is_gre = false;
    bool is_ipsec = false;
    struct tnl_port_config config;
    struct shash_node *node;
    bool ipsec_mech_set = false;

    memset(&config, 0, sizeof config);
    config.flags |= TNL_F_PMTUD;
    config.flags |= TNL_F_HDR_CACHE;

    if (!strcmp(type, "gre")) {
        is_gre = true;
    } else if (!strcmp(type, "ipsec_gre")) {
        is_gre = true;
        is_ipsec = true;

        config.flags |= TNL_F_IPSEC;

        /* IPsec doesn't work when header caching is enabled. */
        config.flags &= ~TNL_F_HDR_CACHE;
    }

    SHASH_FOR_EACH (node, args) {
        if (!strcmp(node->name, "remote_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->data, &in_addr)) {
                VLOG_WARN("%s: bad %s 'remote_ip'", name, type);
            } else {
                config.daddr = in_addr.s_addr;
            }
        } else if (!strcmp(node->name, "local_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->data, &in_addr)) {
                VLOG_WARN("%s: bad %s 'local_ip'", name, type);
            } else {
                config.saddr = in_addr.s_addr;
            }
        } else if (!strcmp(node->name, "key") && is_gre) {
            if (!strcmp(node->data, "flow")) {
                config.flags |= TNL_F_IN_KEY_MATCH;
                config.flags |= TNL_F_OUT_KEY_ACTION;
            } else {
                uint64_t key = strtoull(node->data, NULL, 0);
                config.out_key = config.in_key = htonll(key);
            }
        } else if (!strcmp(node->name, "in_key") && is_gre) {
            if (!strcmp(node->data, "flow")) {
                config.flags |= TNL_F_IN_KEY_MATCH;
            } else {
                config.in_key = htonll(strtoull(node->data, NULL, 0));
            }
        } else if (!strcmp(node->name, "out_key") && is_gre) {
            if (!strcmp(node->data, "flow")) {
                config.flags |= TNL_F_OUT_KEY_ACTION;
            } else {
                config.out_key = htonll(strtoull(node->data, NULL, 0));
            }
        } else if (!strcmp(node->name, "tos")) {
            if (!strcmp(node->data, "inherit")) {
                config.flags |= TNL_F_TOS_INHERIT;
            } else {
                config.tos = atoi(node->data);
            }
        } else if (!strcmp(node->name, "ttl")) {
            if (!strcmp(node->data, "inherit")) {
                config.flags |= TNL_F_TTL_INHERIT;
            } else {
                config.ttl = atoi(node->data);
            }
        } else if (!strcmp(node->name, "csum") && is_gre) {
            if (!strcmp(node->data, "true")) {
                config.flags |= TNL_F_CSUM;
            }
        } else if (!strcmp(node->name, "pmtud")) {
            if (!strcmp(node->data, "false")) {
                config.flags &= ~TNL_F_PMTUD;
            }
        } else if (!strcmp(node->name, "header_cache")) {
            if (!strcmp(node->data, "false")) {
                config.flags &= ~TNL_F_HDR_CACHE;
            }
        } else if (!strcmp(node->name, "peer_cert") && is_ipsec) {
            if (shash_find(args, "certificate")) {
                ipsec_mech_set = true;
            } else {
                const char *use_ssl_cert;

                /* If the "use_ssl_cert" is true, then "certificate" and
                 * "private_key" will be pulled from the SSL table.  The
                 * use of this option is strongly discouraged, since it
                 * will like be removed when multiple SSL configurations
                 * are supported by OVS.
                 */
                use_ssl_cert = shash_find_data(args, "use_ssl_cert");
                if (!use_ssl_cert || strcmp(use_ssl_cert, "true")) {
                    VLOG_WARN("%s: 'peer_cert' requires 'certificate' argument",
                              name);
                    return EINVAL;
                }
                ipsec_mech_set = true;
            }
        } else if (!strcmp(node->name, "psk") && is_ipsec) {
            ipsec_mech_set = true;
        } else if (is_ipsec
                && (!strcmp(node->name, "certificate")
                    || !strcmp(node->name, "private_key")
                    || !strcmp(node->name, "use_ssl_cert"))) {
            /* Ignore options not used by the netdev. */
        } else {
            VLOG_WARN("%s: unknown %s argument '%s'",
                      name, type, node->name);
        }
    }

    if (is_ipsec) {
        if (shash_find(args, "peer_cert") && shash_find(args, "psk")) {
            VLOG_WARN("%s: cannot define both 'peer_cert' and 'psk'", name);
            return EINVAL;
        }

        if (!ipsec_mech_set) {
            VLOG_WARN("%s: IPsec requires an 'peer_cert' or psk' argument",
                      name);
            return EINVAL;
        }
    }

    if (!config.daddr) {
        VLOG_WARN("%s: %s type requires valid 'remote_ip' argument",
                  name, type);
        return EINVAL;
    }

    BUILD_ASSERT(sizeof config <= VPORT_CONFIG_SIZE);
    memcpy(configp, &config, sizeof config);
    return 0;
}

static int
unparse_tunnel_config(const char *name OVS_UNUSED, const char *type OVS_UNUSED,
                      const void *config_, struct shash *args)
{
    const struct tnl_port_config *config = config_;

    if (!(config->flags & TNL_F_HDR_CACHE) == !(config->flags & TNL_F_IPSEC)) {
        smap_add(args, "header_cache",
                 config->flags & TNL_F_HDR_CACHE ? "true" : "false");
    }
    shash_add(args, "remote_ip", xasprintf(IP_FMT, IP_ARGS(&config->daddr)));
    if (config->saddr) {
        shash_add(args, "local_ip",
                  xasprintf(IP_FMT, IP_ARGS(&config->saddr)));
    }

    if ((config->flags & (TNL_F_IN_KEY_MATCH | TNL_F_OUT_KEY_ACTION))
                      == (TNL_F_IN_KEY_MATCH | TNL_F_OUT_KEY_ACTION)) {
        smap_add(args, "key", "flow");
    } else if (config->in_key && config->in_key == config->out_key) {
        shash_add(args, "key",
                  xasprintf("%"PRIu64, ntohll(config->in_key)));
    } else {
        if (config->flags & TNL_F_IN_KEY_MATCH) {
            smap_add(args, "in_key", "flow");
        } else if (config->in_key) {
            shash_add(args, "in_key",
                      xasprintf("%"PRIu64, ntohll(config->in_key)));
        }

        if (config->flags & TNL_F_OUT_KEY_ACTION) {
            smap_add(args, "out_key", "flow");
        } else if (config->out_key) {
            shash_add(args, "out_key",
                      xasprintf("%"PRIu64, ntohll(config->out_key)));
        }
    }

    if (config->flags & TNL_F_TTL_INHERIT) {
        smap_add(args, "tos", "inherit");
    } else if (config->ttl) {
        shash_add(args, "tos", xasprintf("%"PRIu8, config->ttl));
    }

    if (config->flags & TNL_F_CSUM) {
        smap_add(args, "csum", "true");
    }
    if (!(config->flags & TNL_F_PMTUD)) {
        smap_add(args, "pmtud", "false");
    }

    return 0;
}

static int
parse_patch_config(const char *name, const char *type OVS_UNUSED,
                   const struct shash *args, void *configp)
{
    const char *peer;

    peer = shash_find_data(args, "peer");
    if (!peer) {
        VLOG_WARN("%s: patch type requires valid 'peer' argument", name);
        return EINVAL;
    }

    if (shash_count(args) > 1) {
        VLOG_WARN("%s: patch type takes only a 'peer' argument", name);
        return EINVAL;
    }

    if (strlen(peer) >= MIN(IFNAMSIZ, VPORT_CONFIG_SIZE)) {
        VLOG_WARN("%s: patch 'peer' arg too long", name);
        return EINVAL;
    }

    if (!strcmp(name, peer)) {
        VLOG_WARN("%s: patch peer must not be self", name);
        return EINVAL;
    }

    strncpy(configp, peer, VPORT_CONFIG_SIZE);

    return 0;
}

static int
unparse_patch_config(const char *name OVS_UNUSED, const char *type OVS_UNUSED,
                     const void *config_, struct shash *args)
{
    char peer[IFNAMSIZ];

    ovs_strlcpy(peer, config_, MIN(sizeof peer, VPORT_CONFIG_SIZE));
    if (peer[0]) {
        smap_add(args, "peer", peer);
    }

    return 0;
}

#define VPORT_FUNCTIONS(GET_STATUS)                         \
    netdev_vport_init,                                      \
    netdev_vport_run,                                       \
    netdev_vport_wait,                                      \
                                                            \
    netdev_vport_create,                                    \
    netdev_vport_destroy,                                   \
    netdev_vport_set_config,                                \
                                                            \
    netdev_vport_open,                                      \
    netdev_vport_close,                                     \
                                                            \
    NULL,                       /* enumerate */             \
                                                            \
    NULL,                       /* recv */                  \
    NULL,                       /* recv_wait */             \
    NULL,                       /* drain */                 \
                                                            \
    NULL,                       /* send */                  \
    NULL,                       /* send_wait */             \
                                                            \
    netdev_vport_set_etheraddr,                             \
    netdev_vport_get_etheraddr,                             \
    netdev_vport_get_mtu,                                   \
    NULL,                       /* get_ifindex */           \
    NULL,                       /* get_carrier */           \
    NULL,                       /* get_miimon */            \
    netdev_vport_get_stats,                                 \
    netdev_vport_set_stats,                                 \
                                                            \
    NULL,                       /* get_features */          \
    NULL,                       /* set_advertisements */    \
    NULL,                       /* get_vlan_vid */          \
                                                            \
    NULL,                       /* set_policing */          \
    NULL,                       /* get_qos_types */         \
    NULL,                       /* get_qos_capabilities */  \
    NULL,                       /* get_qos */               \
    NULL,                       /* set_qos */               \
    NULL,                       /* get_queue */             \
    NULL,                       /* set_queue */             \
    NULL,                       /* delete_queue */          \
    NULL,                       /* get_queue_stats */       \
    NULL,                       /* dump_queues */           \
    NULL,                       /* dump_queue_stats */      \
                                                            \
    NULL,                       /* get_in4 */               \
    NULL,                       /* set_in4 */               \
    NULL,                       /* get_in6 */               \
    NULL,                       /* add_router */            \
    NULL,                       /* get_next_hop */          \
    GET_STATUS,                                             \
    NULL,                       /* arp_lookup */            \
                                                            \
    netdev_vport_update_flags,                              \
                                                            \
    netdev_vport_poll_add,                                  \
    netdev_vport_poll_remove,

void
netdev_vport_register(void)
{
    static const struct vport_class vport_classes[] = {
        { { "gre", VPORT_FUNCTIONS(netdev_vport_get_status) },
          parse_tunnel_config, unparse_tunnel_config },
        { { "ipsec_gre", VPORT_FUNCTIONS(netdev_vport_get_status) },
          parse_tunnel_config, unparse_tunnel_config },
        { { "capwap", VPORT_FUNCTIONS(netdev_vport_get_status) },
          parse_tunnel_config, unparse_tunnel_config },
        { { "patch", VPORT_FUNCTIONS(NULL) },
          parse_patch_config, unparse_patch_config }
    };

    int i;

    for (i = 0; i < ARRAY_SIZE(vport_classes); i++) {
        netdev_register_provider(&vport_classes[i].netdev_class);
    }
}
