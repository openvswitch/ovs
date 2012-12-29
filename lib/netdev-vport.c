/*
 * Copyright (c) 2010, 2011, 2012 Nicira, Inc.
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
#include <linux/openvswitch.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "byte-order.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif-linux.h"
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "netdev-linux.h"
#include "netdev-provider.h"
#include "netlink.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "ofpbuf.h"
#include "openvswitch/tunnel.h"
#include "packets.h"
#include "route-table.h"
#include "shash.h"
#include "socket-util.h"
#include "unaligned.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_vport);

struct netdev_dev_vport {
    struct netdev_dev netdev_dev;
    struct ofpbuf *options;
    int dp_ifindex;             /* -1 if unknown. */
    uint32_t port_no;           /* UINT32_MAX if unknown. */
    unsigned int change_seq;
};

struct netdev_vport {
    struct netdev netdev;
};

struct vport_class {
    enum ovs_vport_type type;
    struct netdev_class netdev_class;
    int (*parse_config)(const char *name, const char *type,
                        const struct smap *args, struct ofpbuf *options);
    int (*unparse_config)(const char *name, const char *type,
                          const struct nlattr *options, size_t options_len,
                          struct smap *args);
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static int netdev_vport_create(const struct netdev_class *, const char *,
                               struct netdev_dev **);
static void netdev_vport_poll_notify(const struct netdev *);
static int tnl_port_config_from_nlattr(const struct nlattr *options,
                                       size_t options_len,
                                       struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1]);

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

/* If 'netdev' is a vport netdev, returns an ofpbuf that contains Netlink
 * options to include in OVS_VPORT_ATTR_OPTIONS for configuring that vport.
 * Otherwise returns NULL. */
const struct ofpbuf *
netdev_vport_get_options(const struct netdev *netdev)
{
    const struct netdev_dev *dev = netdev_get_dev(netdev);

    return (is_vport_class(netdev_dev_get_class(dev))
            ? netdev_dev_vport_cast(dev)->options
            : NULL);
}

enum ovs_vport_type
netdev_vport_get_vport_type(const struct netdev *netdev)
{
    const struct netdev_dev *dev = netdev_get_dev(netdev);
    const struct netdev_class *class = netdev_dev_get_class(dev);

    return (is_vport_class(class) ? vport_class_cast(class)->type
            : class == &netdev_internal_class ? OVS_VPORT_TYPE_INTERNAL
            : (class == &netdev_linux_class ||
               class == &netdev_tap_class) ? OVS_VPORT_TYPE_NETDEV
            : OVS_VPORT_TYPE_UNSPEC);
}

static uint32_t
get_u32_or_zero(const struct nlattr *a)
{
    return a ? nl_attr_get_u32(a) : 0;
}

const char *
netdev_vport_get_netdev_type(const struct dpif_linux_vport *vport)
{
    struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1];

    switch (vport->type) {
    case OVS_VPORT_TYPE_UNSPEC:
        break;

    case OVS_VPORT_TYPE_NETDEV:
        return "system";

    case OVS_VPORT_TYPE_INTERNAL:
        return "internal";

    case OVS_VPORT_TYPE_PATCH:
        return "patch";

    case OVS_VPORT_TYPE_GRE:
        if (tnl_port_config_from_nlattr(vport->options, vport->options_len,
                                        a)) {
            break;
        }
        return (get_u32_or_zero(a[OVS_TUNNEL_ATTR_FLAGS]) & TNL_F_IPSEC
                ? "ipsec_gre" : "gre");

    case OVS_VPORT_TYPE_GRE64:
        if (tnl_port_config_from_nlattr(vport->options, vport->options_len,
                                        a)) {
            break;
        }
        return (get_u32_or_zero(a[OVS_TUNNEL_ATTR_FLAGS]) & TNL_F_IPSEC
                ? "ipsec_gre64" : "gre64");

    case OVS_VPORT_TYPE_CAPWAP:
        return "capwap";

    case OVS_VPORT_TYPE_FT_GRE:
    case __OVS_VPORT_TYPE_MAX:
        break;
    }

    VLOG_WARN_RL(&rl, "dp%d: port `%s' has unsupported type %u",
                 vport->dp_ifindex, vport->name, (unsigned int) vport->type);
    return "unknown";
}

static int
netdev_vport_create(const struct netdev_class *netdev_class, const char *name,
                    struct netdev_dev **netdev_devp)
{
    struct netdev_dev_vport *dev;

    dev = xmalloc(sizeof *dev);
    netdev_dev_init(&dev->netdev_dev, name, netdev_class);
    dev->options = NULL;
    dev->dp_ifindex = -1;
    dev->port_no = UINT32_MAX;
    dev->change_seq = 1;

    *netdev_devp = &dev->netdev_dev;
    route_table_register();

    return 0;
}

static void
netdev_vport_destroy(struct netdev_dev *netdev_dev_)
{
    struct netdev_dev_vport *netdev_dev = netdev_dev_vport_cast(netdev_dev_);

    ofpbuf_delete(netdev_dev->options);
    route_table_unregister();
    free(netdev_dev);
}

static int
netdev_vport_open(struct netdev_dev *netdev_dev_, struct netdev **netdevp)
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
netdev_vport_get_config(struct netdev_dev *dev_, struct smap *args)
{
    const struct netdev_class *netdev_class = netdev_dev_get_class(dev_);
    const struct vport_class *vport_class = vport_class_cast(netdev_class);
    struct netdev_dev_vport *dev = netdev_dev_vport_cast(dev_);
    const char *name = netdev_dev_get_name(dev_);
    int error;

    if (!dev->options) {
        struct dpif_linux_vport reply;
        struct ofpbuf *buf;

        error = dpif_linux_vport_get(name, &reply, &buf);
        if (error) {
            VLOG_ERR_RL(&rl, "%s: vport query failed (%s)",
                        name, strerror(error));
            return error;
        }

        dev->options = ofpbuf_clone_data(reply.options, reply.options_len);
        dev->dp_ifindex = reply.dp_ifindex;
        dev->port_no = reply.port_no;
        ofpbuf_delete(buf);
    }

    error = vport_class->unparse_config(name, netdev_class->type,
                                        dev->options->data,
                                        dev->options->size,
                                        args);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to parse kernel config (%s)",
                    name, strerror(error));
    }
    return error;
}

static int
netdev_vport_set_config(struct netdev_dev *dev_, const struct smap *args)
{
    const struct netdev_class *netdev_class = netdev_dev_get_class(dev_);
    const struct vport_class *vport_class = vport_class_cast(netdev_class);
    struct netdev_dev_vport *dev = netdev_dev_vport_cast(dev_);
    const char *name = netdev_dev_get_name(dev_);
    struct ofpbuf *options;
    int error;

    options = ofpbuf_new(64);
    error = vport_class->parse_config(name, netdev_dev_get_type(dev_),
                                      args, options);
    if (!error
        && (!dev->options
            || options->size != dev->options->size
            || memcmp(options->data, dev->options->data, options->size))) {
        struct dpif_linux_vport vport;

        dpif_linux_vport_init(&vport);
        vport.cmd = OVS_VPORT_CMD_SET;
        vport.name = name;
        vport.options = options->data;
        vport.options_len = options->size;
        error = dpif_linux_vport_transact(&vport, NULL, NULL);
        if (!error || error == ENODEV) {
            /* Either reconfiguration succeeded or this vport is not installed
             * in the kernel (e.g. it hasn't been added to a dpif yet with
             * dpif_port_add()). */
            ofpbuf_delete(dev->options);
            dev->options = options;
            options = NULL;
            error = 0;
        }
    }
    ofpbuf_delete(options);

    return error;
}

static int
netdev_vport_send(struct netdev *netdev, const void *data, size_t size)
{
    struct netdev_dev *dev_ = netdev_get_dev(netdev);
    struct netdev_dev_vport *dev = netdev_dev_vport_cast(dev_);

    if (dev->dp_ifindex == -1) {
        const char *name = netdev_get_name(netdev);
        struct dpif_linux_vport reply;
        struct ofpbuf *buf;
        int error;

        error = dpif_linux_vport_get(name, &reply, &buf);
        if (error) {
            VLOG_ERR_RL(&rl, "%s: failed to query vport for send (%s)",
                        name, strerror(error));
            return error;
        }
        dev->dp_ifindex = reply.dp_ifindex;
        dev->port_no = reply.port_no;
        ofpbuf_delete(buf);
    }

    return dpif_linux_vport_send(dev->dp_ifindex, dev->port_no, data, size);
}

static int
netdev_vport_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct dpif_linux_vport vport;
    int error;

    dpif_linux_vport_init(&vport);
    vport.cmd = OVS_VPORT_CMD_SET;
    vport.name = netdev_get_name(netdev);
    vport.address = mac;

    error = dpif_linux_vport_transact(&vport, NULL, NULL);
    if (!error) {
        netdev_vport_poll_notify(netdev);
    }
    return error;
}

static int
netdev_vport_get_etheraddr(const struct netdev *netdev,
                           uint8_t mac[ETH_ADDR_LEN])
{
    struct dpif_linux_vport reply;
    struct ofpbuf *buf;
    int error;

    error = dpif_linux_vport_get(netdev_get_name(netdev), &reply, &buf);
    if (!error) {
        if (reply.address) {
            memcpy(mac, reply.address, ETH_ADDR_LEN);
        } else {
            error = EOPNOTSUPP;
        }
        ofpbuf_delete(buf);
    }
    return error;
}

/* Copies 'src' into 'dst', performing format conversion in the process.
 *
 * 'src' is allowed to be misaligned. */
static void
netdev_stats_from_ovs_vport_stats(struct netdev_stats *dst,
                                  const struct ovs_vport_stats *src)
{
    dst->rx_packets = get_unaligned_u64(&src->rx_packets);
    dst->tx_packets = get_unaligned_u64(&src->tx_packets);
    dst->rx_bytes = get_unaligned_u64(&src->rx_bytes);
    dst->tx_bytes = get_unaligned_u64(&src->tx_bytes);
    dst->rx_errors = get_unaligned_u64(&src->rx_errors);
    dst->tx_errors = get_unaligned_u64(&src->tx_errors);
    dst->rx_dropped = get_unaligned_u64(&src->rx_dropped);
    dst->tx_dropped = get_unaligned_u64(&src->tx_dropped);
    dst->multicast = 0;
    dst->collisions = 0;
    dst->rx_length_errors = 0;
    dst->rx_over_errors = 0;
    dst->rx_crc_errors = 0;
    dst->rx_frame_errors = 0;
    dst->rx_fifo_errors = 0;
    dst->rx_missed_errors = 0;
    dst->tx_aborted_errors = 0;
    dst->tx_carrier_errors = 0;
    dst->tx_fifo_errors = 0;
    dst->tx_heartbeat_errors = 0;
    dst->tx_window_errors = 0;
}

/* Copies 'src' into 'dst', performing format conversion in the process. */
static void
netdev_stats_to_ovs_vport_stats(struct ovs_vport_stats *dst,
                                const struct netdev_stats *src)
{
    dst->rx_packets = src->rx_packets;
    dst->tx_packets = src->tx_packets;
    dst->rx_bytes = src->rx_bytes;
    dst->tx_bytes = src->tx_bytes;
    dst->rx_errors = src->rx_errors;
    dst->tx_errors = src->tx_errors;
    dst->rx_dropped = src->rx_dropped;
    dst->tx_dropped = src->tx_dropped;
}

int
netdev_vport_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct dpif_linux_vport reply;
    struct ofpbuf *buf;
    int error;

    error = dpif_linux_vport_get(netdev_get_name(netdev), &reply, &buf);
    if (error) {
        return error;
    } else if (!reply.stats) {
        ofpbuf_delete(buf);
        return EOPNOTSUPP;
    }

    netdev_stats_from_ovs_vport_stats(stats, reply.stats);

    ofpbuf_delete(buf);

    return 0;
}

int
netdev_vport_set_stats(struct netdev *netdev, const struct netdev_stats *stats)
{
    struct ovs_vport_stats rtnl_stats;
    struct dpif_linux_vport vport;
    int err;

    netdev_stats_to_ovs_vport_stats(&rtnl_stats, stats);

    dpif_linux_vport_init(&vport);
    vport.cmd = OVS_VPORT_CMD_SET;
    vport.name = netdev_get_name(netdev);
    vport.stats = &rtnl_stats;

    err = dpif_linux_vport_transact(&vport, NULL, NULL);

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
netdev_vport_get_drv_info(const struct netdev *netdev, struct smap *smap)
{
    const char *iface = netdev_vport_get_tnl_iface(netdev);

    if (iface) {
        struct netdev *egress_netdev;

        smap_add(smap, "tunnel_egress_iface", iface);

        if (!netdev_open(iface, "system", &egress_netdev)) {
            smap_add(smap, "tunnel_egress_iface_carrier",
                     netdev_get_carrier(egress_netdev) ? "up" : "down");
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

static unsigned int
netdev_vport_change_seq(const struct netdev *netdev)
{
    return netdev_dev_vport_cast(netdev_get_dev(netdev))->change_seq;
}

static void
netdev_vport_run(void)
{
    route_table_run();
}

static void
netdev_vport_wait(void)
{
    route_table_wait();
}

/* get_tnl_iface() implementation. */
static const char *
netdev_vport_get_tnl_iface(const struct netdev *netdev)
{
    struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1];
    struct netdev_dev_vport *ndv;
    static char name[IFNAMSIZ];

    ndv = netdev_dev_vport_cast(netdev_get_dev(netdev));
    if (tnl_port_config_from_nlattr(ndv->options->data, ndv->options->size,
                                    a)) {
        return NULL;
    }
    if (a[OVS_TUNNEL_ATTR_DST_IPV4]) {
        ovs_be32 route = nl_attr_get_be32(a[OVS_TUNNEL_ATTR_DST_IPV4]);

        if (route_table_get_name(route, name)) {
            return name;
        }
    }
    return NULL;
}

/* Helper functions. */

static void
netdev_vport_poll_notify(const struct netdev *netdev)
{
    struct netdev_dev_vport *ndv;

    ndv = netdev_dev_vport_cast(netdev_get_dev(netdev));

    ndv->change_seq++;
    if (!ndv->change_seq) {
        ndv->change_seq++;
    }
}

/* Code specific to individual vport types. */

static void
set_key(const struct smap *args, const char *name, uint16_t type,
        struct ofpbuf *options)
{
    const char *s;

    s = smap_get(args, name);
    if (!s) {
        s = smap_get(args, "key");
        if (!s) {
            s = "0";
        }
    }

    if (!strcmp(s, "flow")) {
        /* This is the default if no attribute is present. */
    } else {
        nl_msg_put_be64(options, type, htonll(strtoull(s, NULL, 0)));
    }
}

static int
parse_tunnel_config(const char *name, const char *type,
                    const struct smap *args, struct ofpbuf *options)
{
    bool is_gre = false;
    bool is_ipsec = false;
    struct smap_node *node;
    bool ipsec_mech_set = false;
    ovs_be32 daddr = htonl(0);
    ovs_be32 saddr = htonl(0);
    uint32_t flags;

    if (!strcmp(type, "capwap")) {
        VLOG_WARN_ONCE("CAPWAP tunnel support is deprecated.");
    }

    flags = TNL_F_DF_DEFAULT;
    if (!strcmp(type, "gre") || !strcmp(type, "gre64")) {
        is_gre = true;
    } else if (!strcmp(type, "ipsec_gre") || !strcmp(type, "ipsec_gre64")) {
        is_gre = true;
        is_ipsec = true;
        flags |= TNL_F_IPSEC;
    }

    SMAP_FOR_EACH (node, args) {
        if (!strcmp(node->key, "remote_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->value, &in_addr)) {
                VLOG_WARN("%s: bad %s 'remote_ip'", name, type);
            } else {
                daddr = in_addr.s_addr;
            }
        } else if (!strcmp(node->key, "local_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->value, &in_addr)) {
                VLOG_WARN("%s: bad %s 'local_ip'", name, type);
            } else {
                saddr = in_addr.s_addr;
            }
        } else if (!strcmp(node->key, "tos")) {
            if (!strcmp(node->value, "inherit")) {
                flags |= TNL_F_TOS_INHERIT;
            } else {
                char *endptr;
                int tos;
                tos = strtol(node->value, &endptr, 0);
                if (*endptr == '\0' && tos == (tos & IP_DSCP_MASK)) {
                    nl_msg_put_u8(options, OVS_TUNNEL_ATTR_TOS, tos);
                } else {
                    VLOG_WARN("%s: invalid TOS %s", name, node->value);
                }
            }
        } else if (!strcmp(node->key, "ttl")) {
            if (!strcmp(node->value, "inherit")) {
                flags |= TNL_F_TTL_INHERIT;
            } else {
                nl_msg_put_u8(options, OVS_TUNNEL_ATTR_TTL, atoi(node->value));
            }
        } else if (!strcmp(node->key, "csum") && is_gre) {
            if (!strcmp(node->value, "true")) {
                flags |= TNL_F_CSUM;
            }
        } else if (!strcmp(node->key, "df_inherit")) {
            if (!strcmp(node->value, "true")) {
                flags |= TNL_F_DF_INHERIT;
            }
        } else if (!strcmp(node->key, "df_default")) {
            if (!strcmp(node->value, "false")) {
                flags &= ~TNL_F_DF_DEFAULT;
            }
        } else if (!strcmp(node->key, "pmtud")) {
            if (!strcmp(node->value, "true")) {
                VLOG_WARN_ONCE("%s: The tunnel Path MTU discovery is "
                               "deprecated and may be removed in February "
                               "2013. Please email dev@openvswitch.org with "
                               "concerns.", name);
                flags |= TNL_F_PMTUD;
            }
        } else if (!strcmp(node->key, "peer_cert") && is_ipsec) {
            if (smap_get(args, "certificate")) {
                ipsec_mech_set = true;
            } else {
                const char *use_ssl_cert;

                /* If the "use_ssl_cert" is true, then "certificate" and
                 * "private_key" will be pulled from the SSL table.  The
                 * use of this option is strongly discouraged, since it
                 * will like be removed when multiple SSL configurations
                 * are supported by OVS.
                 */
                use_ssl_cert = smap_get(args, "use_ssl_cert");
                if (!use_ssl_cert || strcmp(use_ssl_cert, "true")) {
                    VLOG_ERR("%s: 'peer_cert' requires 'certificate' argument",
                             name);
                    return EINVAL;
                }
                ipsec_mech_set = true;
            }
        } else if (!strcmp(node->key, "psk") && is_ipsec) {
            ipsec_mech_set = true;
        } else if (is_ipsec
                && (!strcmp(node->key, "certificate")
                    || !strcmp(node->key, "private_key")
                    || !strcmp(node->key, "use_ssl_cert"))) {
            /* Ignore options not used by the netdev. */
        } else if (!strcmp(node->key, "key") ||
                   !strcmp(node->key, "in_key") ||
                   !strcmp(node->key, "out_key")) {
            /* Handled separately below. */
        } else {
            VLOG_WARN("%s: unknown %s argument '%s'", name, type, node->key);
        }
    }

    if (is_ipsec) {
        static pid_t pid = 0;
        if (pid <= 0) {
            char *file_name = xasprintf("%s/%s", ovs_rundir(),
                                        "ovs-monitor-ipsec.pid");
            pid = read_pidfile(file_name);
            free(file_name);
        }

        if (pid < 0) {
            VLOG_ERR("%s: IPsec requires the ovs-monitor-ipsec daemon",
                     name);
            return EINVAL;
        }

        if (smap_get(args, "peer_cert") && smap_get(args, "psk")) {
            VLOG_ERR("%s: cannot define both 'peer_cert' and 'psk'", name);
            return EINVAL;
        }

        if (!ipsec_mech_set) {
            VLOG_ERR("%s: IPsec requires an 'peer_cert' or psk' argument",
                     name);
            return EINVAL;
        }
    }

    set_key(args, "in_key", OVS_TUNNEL_ATTR_IN_KEY, options);
    set_key(args, "out_key", OVS_TUNNEL_ATTR_OUT_KEY, options);

    if (!daddr) {
        VLOG_ERR("%s: %s type requires valid 'remote_ip' argument",
                 name, type);
        return EINVAL;
    }
    nl_msg_put_be32(options, OVS_TUNNEL_ATTR_DST_IPV4, daddr);

    if (saddr) {
        if (ip_is_multicast(daddr)) {
            VLOG_WARN("%s: remote_ip is multicast, ignoring local_ip", name);
        } else {
            nl_msg_put_be32(options, OVS_TUNNEL_ATTR_SRC_IPV4, saddr);
        }
    }

    nl_msg_put_u32(options, OVS_TUNNEL_ATTR_FLAGS, flags);

    return 0;
}

static int
tnl_port_config_from_nlattr(const struct nlattr *options, size_t options_len,
                            struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1])
{
    static const struct nl_policy ovs_tunnel_policy[] = {
        [OVS_TUNNEL_ATTR_FLAGS] = { .type = NL_A_U32, .optional = true },
        [OVS_TUNNEL_ATTR_DST_IPV4] = { .type = NL_A_BE32, .optional = true },
        [OVS_TUNNEL_ATTR_SRC_IPV4] = { .type = NL_A_BE32, .optional = true },
        [OVS_TUNNEL_ATTR_IN_KEY] = { .type = NL_A_BE64, .optional = true },
        [OVS_TUNNEL_ATTR_OUT_KEY] = { .type = NL_A_BE64, .optional = true },
        [OVS_TUNNEL_ATTR_TOS] = { .type = NL_A_U8, .optional = true },
        [OVS_TUNNEL_ATTR_TTL] = { .type = NL_A_U8, .optional = true },
    };
    struct ofpbuf buf;

    ofpbuf_use_const(&buf, options, options_len);
    if (!nl_policy_parse(&buf, 0, ovs_tunnel_policy,
                         a, ARRAY_SIZE(ovs_tunnel_policy))) {
        return EINVAL;
    }
    return 0;
}

static uint64_t
get_be64_or_zero(const struct nlattr *a)
{
    return a ? ntohll(nl_attr_get_be64(a)) : 0;
}

static int
unparse_tunnel_config(const char *name OVS_UNUSED, const char *type OVS_UNUSED,
                      const struct nlattr *options, size_t options_len,
                      struct smap *args)
{
    struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1];
    uint32_t flags;
    int error;

    error = tnl_port_config_from_nlattr(options, options_len, a);
    if (error) {
        return error;
    }

    if (a[OVS_TUNNEL_ATTR_DST_IPV4]) {
        ovs_be32 daddr = nl_attr_get_be32(a[OVS_TUNNEL_ATTR_DST_IPV4]);
        smap_add_format(args, "remote_ip", IP_FMT, IP_ARGS(&daddr));
    }

    if (a[OVS_TUNNEL_ATTR_SRC_IPV4]) {
        ovs_be32 saddr = nl_attr_get_be32(a[OVS_TUNNEL_ATTR_SRC_IPV4]);
        smap_add_format(args, "local_ip", IP_FMT, IP_ARGS(&saddr));
    }

    if (!a[OVS_TUNNEL_ATTR_IN_KEY] && !a[OVS_TUNNEL_ATTR_OUT_KEY]) {
        smap_add(args, "key", "flow");
    } else {
        uint64_t in_key = get_be64_or_zero(a[OVS_TUNNEL_ATTR_IN_KEY]);
        uint64_t out_key = get_be64_or_zero(a[OVS_TUNNEL_ATTR_OUT_KEY]);

        if (in_key && in_key == out_key) {
            smap_add_format(args, "key", "%"PRIu64, in_key);
        } else {
            if (!a[OVS_TUNNEL_ATTR_IN_KEY]) {
                smap_add(args, "in_key", "flow");
            } else if (in_key) {
                smap_add_format(args, "in_key", "%"PRIu64, in_key);
            }

            if (!a[OVS_TUNNEL_ATTR_OUT_KEY]) {
                smap_add(args, "out_key", "flow");
            } else if (out_key) {
                smap_add_format(args, "out_key", "%"PRIu64, out_key);
            }
        }
    }

    flags = get_u32_or_zero(a[OVS_TUNNEL_ATTR_FLAGS]);

    if (flags & TNL_F_TTL_INHERIT) {
        smap_add(args, "ttl", "inherit");
    } else if (a[OVS_TUNNEL_ATTR_TTL]) {
        int ttl = nl_attr_get_u8(a[OVS_TUNNEL_ATTR_TTL]);
        smap_add_format(args, "ttl", "%d", ttl);
    }

    if (flags & TNL_F_TOS_INHERIT) {
        smap_add(args, "tos", "inherit");
    } else if (a[OVS_TUNNEL_ATTR_TOS]) {
        int tos = nl_attr_get_u8(a[OVS_TUNNEL_ATTR_TOS]);
        smap_add_format(args, "tos", "0x%x", tos);
    }

    if (flags & TNL_F_CSUM) {
        smap_add(args, "csum", "true");
    }
    if (flags & TNL_F_DF_INHERIT) {
        smap_add(args, "df_inherit", "true");
    }
    if (!(flags & TNL_F_DF_DEFAULT)) {
        smap_add(args, "df_default", "false");
    }
    if (flags & TNL_F_PMTUD) {
        smap_add(args, "pmtud", "true");
    }

    return 0;
}

static int
parse_patch_config(const char *name, const char *type OVS_UNUSED,
                   const struct smap *args, struct ofpbuf *options)
{
    const char *peer;

    peer = smap_get(args, "peer");
    if (!peer) {
        VLOG_ERR("%s: patch type requires valid 'peer' argument", name);
        return EINVAL;
    }

    if (smap_count(args) > 1) {
        VLOG_ERR("%s: patch type takes only a 'peer' argument", name);
        return EINVAL;
    }

    if (strlen(peer) >= IFNAMSIZ) {
        VLOG_ERR("%s: patch 'peer' arg too long", name);
        return EINVAL;
    }

    if (!strcmp(name, peer)) {
        VLOG_ERR("%s: patch peer must not be self", name);
        return EINVAL;
    }

    nl_msg_put_string(options, OVS_PATCH_ATTR_PEER, peer);

    return 0;
}

static int
unparse_patch_config(const char *name OVS_UNUSED, const char *type OVS_UNUSED,
                     const struct nlattr *options, size_t options_len,
                     struct smap *args)
{
    static const struct nl_policy ovs_patch_policy[] = {
        [OVS_PATCH_ATTR_PEER] = { .type = NL_A_STRING,
                               .max_len = IFNAMSIZ,
                               .optional = false }
    };

    struct nlattr *a[ARRAY_SIZE(ovs_patch_policy)];
    struct ofpbuf buf;

    ofpbuf_use_const(&buf, options, options_len);
    if (!nl_policy_parse(&buf, 0, ovs_patch_policy,
                         a, ARRAY_SIZE(ovs_patch_policy))) {
        return EINVAL;
    }

    smap_add(args, "peer", nl_attr_get_string(a[OVS_PATCH_ATTR_PEER]));
    return 0;
}

#define VPORT_FUNCTIONS(GET_STATUS)                         \
    NULL,                                                   \
    netdev_vport_run,                                       \
    netdev_vport_wait,                                      \
                                                            \
    netdev_vport_create,                                    \
    netdev_vport_destroy,                                   \
    netdev_vport_get_config,                                \
    netdev_vport_set_config,                                \
                                                            \
    netdev_vport_open,                                      \
    netdev_vport_close,                                     \
                                                            \
    NULL,                       /* listen */                \
    NULL,                       /* recv */                  \
    NULL,                       /* recv_wait */             \
    NULL,                       /* drain */                 \
                                                            \
    netdev_vport_send,          /* send */                  \
    NULL,                       /* send_wait */             \
                                                            \
    netdev_vport_set_etheraddr,                             \
    netdev_vport_get_etheraddr,                             \
    NULL,                       /* get_mtu */               \
    NULL,                       /* set_mtu */               \
    NULL,                       /* get_ifindex */           \
    NULL,                       /* get_carrier */           \
    NULL,                       /* get_carrier_resets */    \
    NULL,                       /* get_miimon */            \
    netdev_vport_get_stats,                                 \
    netdev_vport_set_stats,                                 \
                                                            \
    NULL,                       /* get_features */          \
    NULL,                       /* set_advertisements */    \
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
    netdev_vport_change_seq

void
netdev_vport_register(void)
{
    static const struct vport_class vport_classes[] = {
        { OVS_VPORT_TYPE_GRE,
          { "gre", VPORT_FUNCTIONS(netdev_vport_get_drv_info) },
          parse_tunnel_config, unparse_tunnel_config },

        { OVS_VPORT_TYPE_GRE,
          { "ipsec_gre", VPORT_FUNCTIONS(netdev_vport_get_drv_info) },
          parse_tunnel_config, unparse_tunnel_config },

        { OVS_VPORT_TYPE_GRE64,
          { "gre64", VPORT_FUNCTIONS(netdev_vport_get_drv_info) },
          parse_tunnel_config, unparse_tunnel_config },

        { OVS_VPORT_TYPE_GRE64,
          { "ipsec_gre64", VPORT_FUNCTIONS(netdev_vport_get_drv_info) },
          parse_tunnel_config, unparse_tunnel_config },

        { OVS_VPORT_TYPE_CAPWAP,
          { "capwap", VPORT_FUNCTIONS(netdev_vport_get_drv_info) },
          parse_tunnel_config, unparse_tunnel_config },

        { OVS_VPORT_TYPE_PATCH,
          { "patch", VPORT_FUNCTIONS(NULL) },
          parse_patch_config, unparse_patch_config }
    };

    int i;

    for (i = 0; i < ARRAY_SIZE(vport_classes); i++) {
        netdev_register_provider(&vport_classes[i].netdev_class);
    }
}
