/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "dpif.h"
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

/* Default to the OTV port, per the VXLAN IETF draft. */
#define VXLAN_DST_PORT 8472

#define DEFAULT_TTL 64

struct netdev_dev_vport {
    struct netdev_dev netdev_dev;
    unsigned int change_seq;
    uint8_t etheraddr[ETH_ADDR_LEN];

    /* Tunnels. */
    struct ofpbuf *options;
    struct netdev_tunnel_config tnl_cfg;

    /* Patch Ports. */
    struct netdev_stats stats;
    char *peer;
};

struct vport_class {
    enum ovs_vport_type type;
    struct netdev_class netdev_class;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static int netdev_vport_create(const struct netdev_class *, const char *,
                               struct netdev_dev **);
static void netdev_vport_poll_notify(const struct netdev *);
static int tnl_port_config_from_nlattr(const struct nlattr *options,
                                       size_t options_len,
                                       struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1]);

static bool
is_vport_class(const struct netdev_class *class)
{
    return class->create == netdev_vport_create;
}

static const struct vport_class *
vport_class_cast(const struct netdev_class *class)
{
    ovs_assert(is_vport_class(class));
    return CONTAINER_OF(class, struct vport_class, netdev_class);
}

static struct netdev_dev_vport *
netdev_dev_vport_cast(const struct netdev_dev *netdev_dev)
{
    ovs_assert(is_vport_class(netdev_dev_get_class(netdev_dev)));
    return CONTAINER_OF(netdev_dev, struct netdev_dev_vport, netdev_dev);
}

static struct netdev_dev_vport *
netdev_vport_get_dev(const struct netdev *netdev)
{
    return netdev_dev_vport_cast(netdev_get_dev(netdev));
}

static const struct netdev_tunnel_config *
get_netdev_tunnel_config(const struct netdev_dev *netdev_dev)
{
    return &netdev_dev_vport_cast(netdev_dev)->tnl_cfg;
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

bool
netdev_vport_is_patch(const struct netdev *netdev)
{
    return netdev_vport_get_vport_type(netdev) == OVS_VPORT_TYPE_PATCH;
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

    case OVS_VPORT_TYPE_VXLAN:
        return "vxlan";

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

    dev = xzalloc(sizeof *dev);
    netdev_dev_init(&dev->netdev_dev, name, netdev_class);
    dev->change_seq = 1;
    eth_addr_random(dev->etheraddr);

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
    free(netdev_dev->peer);
    free(netdev_dev);
}

static int
netdev_vport_open(struct netdev_dev *netdev_dev, struct netdev **netdevp)
{
    *netdevp = xmalloc(sizeof **netdevp);
    netdev_init(*netdevp, netdev_dev);
    return 0;
}

static void
netdev_vport_close(struct netdev *netdev)
{
    free(netdev);
}

static int
netdev_vport_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    memcpy(netdev_vport_get_dev(netdev)->etheraddr, mac, ETH_ADDR_LEN);
    netdev_vport_poll_notify(netdev);
    return 0;
}

static int
netdev_vport_get_etheraddr(const struct netdev *netdev,
                           uint8_t mac[ETH_ADDR_LEN])
{
    memcpy(mac, netdev_vport_get_dev(netdev)->etheraddr, ETH_ADDR_LEN);
    return 0;
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

static int
tunnel_get_status(const struct netdev *netdev, struct smap *smap)
{
    static char iface[IFNAMSIZ];
    ovs_be32 route;

    route = netdev_vport_get_dev(netdev)->tnl_cfg.ip_dst;
    if (route_table_get_name(route, iface)) {
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
    return netdev_vport_get_dev(netdev)->change_seq;
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

/* Helper functions. */

static void
netdev_vport_poll_notify(const struct netdev *netdev)
{
    struct netdev_dev_vport *ndv = netdev_vport_get_dev(netdev);

    ndv->change_seq++;
    if (!ndv->change_seq) {
        ndv->change_seq++;
    }
}

/* Code specific to tunnel types. */

static ovs_be64
parse_key(const struct smap *args, const char *name,
          bool *present, bool *flow)
{
    const char *s;

    *present = false;
    *flow = false;

    s = smap_get(args, name);
    if (!s) {
        s = smap_get(args, "key");
        if (!s) {
            return 0;
        }
    }

    *present = true;

    if (!strcmp(s, "flow")) {
        *flow = true;
        return 0;
    } else {
        return htonll(strtoull(s, NULL, 0));
    }
}

static int
set_tunnel_config(struct netdev_dev *dev_, const struct smap *args)
{
    struct netdev_dev_vport *dev = netdev_dev_vport_cast(dev_);
    const char *name = netdev_dev_get_name(dev_);
    const char *type = netdev_dev_get_type(dev_);
    bool ipsec_mech_set, needs_dst_port, has_csum;
    struct netdev_tunnel_config tnl_cfg;
    struct smap_node *node;
    struct ofpbuf *options;
    int error = EINVAL;
    uint8_t flags;

    flags = TNL_F_DF_DEFAULT;
    has_csum = strstr(type, "gre");
    ipsec_mech_set = false;
    memset(&tnl_cfg, 0, sizeof tnl_cfg);

    options = ofpbuf_new(64);

    if (!strcmp(type, "capwap")) {
        VLOG_WARN_ONCE("CAPWAP tunnel support is deprecated.");
    }

    needs_dst_port = !strcmp(type, "vxlan");
    tnl_cfg.ipsec = strstr(type, "ipsec");
    if (tnl_cfg.ipsec) {
        flags |= TNL_F_IPSEC;
    }
    tnl_cfg.dont_fragment = true;

    SMAP_FOR_EACH (node, args) {
        if (!strcmp(node->key, "remote_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->value, &in_addr)) {
                VLOG_WARN("%s: bad %s 'remote_ip'", name, type);
            } else {
                tnl_cfg.ip_dst = in_addr.s_addr;
            }
        } else if (!strcmp(node->key, "local_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->value, &in_addr)) {
                VLOG_WARN("%s: bad %s 'local_ip'", name, type);
            } else {
                tnl_cfg.ip_src = in_addr.s_addr;
            }
        } else if (!strcmp(node->key, "tos")) {
            if (!strcmp(node->value, "inherit")) {
                flags |= TNL_F_TOS_INHERIT;
                tnl_cfg.tos_inherit = true;
            } else {
                char *endptr;
                int tos;
                tos = strtol(node->value, &endptr, 0);
                if (*endptr == '\0' && tos == (tos & IP_DSCP_MASK)) {
                    nl_msg_put_u8(options, OVS_TUNNEL_ATTR_TOS, tos);
                    tnl_cfg.tos = tos;
                } else {
                    VLOG_WARN("%s: invalid TOS %s", name, node->value);
                }
            }
        } else if (!strcmp(node->key, "ttl")) {
            if (!strcmp(node->value, "inherit")) {
                flags |= TNL_F_TTL_INHERIT;
                tnl_cfg.ttl_inherit = true;
            } else {
                nl_msg_put_u8(options, OVS_TUNNEL_ATTR_TTL, atoi(node->value));
                tnl_cfg.ttl = atoi(node->value);
            }
        } else if (!strcmp(node->key, "dst_port") && needs_dst_port) {
            tnl_cfg.dst_port = htons(atoi(node->value));
            nl_msg_put_u16(options, OVS_TUNNEL_ATTR_DST_PORT,
                           atoi(node->value));
        } else if (!strcmp(node->key, "csum") && has_csum) {
            if (!strcmp(node->value, "true")) {
                flags |= TNL_F_CSUM;
                tnl_cfg.csum = true;
            }
        } else if (!strcmp(node->key, "df_default")) {
            if (!strcmp(node->value, "false")) {
                flags &= ~TNL_F_DF_DEFAULT;
                tnl_cfg.dont_fragment = false;
            }
        } else if (!strcmp(node->key, "peer_cert") && tnl_cfg.ipsec) {
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
                    goto exit;
                }
                ipsec_mech_set = true;
            }
        } else if (!strcmp(node->key, "psk") && tnl_cfg.ipsec) {
            ipsec_mech_set = true;
        } else if (tnl_cfg.ipsec
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

    /* Add a default destination port for VXLAN if none specified. */
    if (needs_dst_port && !tnl_cfg.dst_port) {
        nl_msg_put_u16(options, OVS_TUNNEL_ATTR_DST_PORT, VXLAN_DST_PORT);
        tnl_cfg.dst_port = htons(VXLAN_DST_PORT);
    }

    if (tnl_cfg.ipsec) {
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
            goto exit;
        }

        if (smap_get(args, "peer_cert") && smap_get(args, "psk")) {
            VLOG_ERR("%s: cannot define both 'peer_cert' and 'psk'", name);
            goto exit;
        }

        if (!ipsec_mech_set) {
            VLOG_ERR("%s: IPsec requires an 'peer_cert' or psk' argument",
                     name);
            goto exit;
        }
    }

    if (!tnl_cfg.ip_dst) {
        VLOG_ERR("%s: %s type requires valid 'remote_ip' argument",
                 name, type);
        goto exit;
    }
    nl_msg_put_be32(options, OVS_TUNNEL_ATTR_DST_IPV4, tnl_cfg.ip_dst);

    if (tnl_cfg.ip_src) {
        if (ip_is_multicast(tnl_cfg.ip_dst)) {
            VLOG_WARN("%s: remote_ip is multicast, ignoring local_ip", name);
            tnl_cfg.ip_src = 0;
        } else {
            nl_msg_put_be32(options, OVS_TUNNEL_ATTR_SRC_IPV4, tnl_cfg.ip_src);
        }
    }

    if (!tnl_cfg.ttl) {
        tnl_cfg.ttl = DEFAULT_TTL;
    }

    tnl_cfg.in_key = parse_key(args, "in_key",
                               &tnl_cfg.in_key_present,
                               &tnl_cfg.in_key_flow);
    if (tnl_cfg.in_key_present && !tnl_cfg.in_key_flow) {
        nl_msg_put_be64(options, OVS_TUNNEL_ATTR_IN_KEY, tnl_cfg.in_key);
    }

    tnl_cfg.out_key = parse_key(args, "out_key",
                               &tnl_cfg.out_key_present,
                               &tnl_cfg.out_key_flow);
    if (tnl_cfg.out_key_present && !tnl_cfg.out_key_flow) {
        nl_msg_put_be64(options, OVS_TUNNEL_ATTR_OUT_KEY, tnl_cfg.out_key);
    }
    nl_msg_put_u32(options, OVS_TUNNEL_ATTR_FLAGS, flags);

    dev->tnl_cfg = tnl_cfg;

    error = 0;
    if (!dev->options
        || options->size != dev->options->size
        || memcmp(options->data, dev->options->data, options->size)) {
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

exit:
    ofpbuf_delete(options);
    return error;
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
        [OVS_TUNNEL_ATTR_DST_PORT] = { .type = NL_A_U16, .optional = true },
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
get_tunnel_config(struct netdev_dev *dev_, struct smap *args)
{
    struct netdev_dev_vport *dev = netdev_dev_vport_cast(dev_);
    const char *name = netdev_dev_get_name(dev_);
    struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1];
    uint32_t flags;
    int error;

    if (!dev->options) {
        struct dpif_linux_vport reply;
        struct ofpbuf *buf;

        error = dpif_linux_vport_get(name, &reply, &buf);
        if (error) {
            VLOG_ERR_RL(&rl, "%s: vport query failed (%s)", name,
                        strerror(error));
            return error;
        }

        dev->options = ofpbuf_clone_data(reply.options, reply.options_len);
        ofpbuf_delete(buf);
    }

    error = tnl_port_config_from_nlattr(dev->options->data, dev->options->size,
                                        a);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to parse kernel config (%s)",
                    name, strerror(error));
        return error;
    }

    if (a[OVS_TUNNEL_ATTR_DST_IPV4]) {
        ovs_be32 daddr = nl_attr_get_be32(a[OVS_TUNNEL_ATTR_DST_IPV4]);
        smap_add_format(args, "remote_ip", IP_FMT, IP_ARGS(daddr));
    }

    if (a[OVS_TUNNEL_ATTR_SRC_IPV4]) {
        ovs_be32 saddr = nl_attr_get_be32(a[OVS_TUNNEL_ATTR_SRC_IPV4]);
        smap_add_format(args, "local_ip", IP_FMT, IP_ARGS(saddr));
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

    if (a[OVS_TUNNEL_ATTR_DST_PORT]) {
        uint16_t dst_port = nl_attr_get_u16(a[OVS_TUNNEL_ATTR_DST_PORT]);
        if (dst_port != VXLAN_DST_PORT) {
            smap_add_format(args, "dst_port", "%d", dst_port);
        }
    }

    if (flags & TNL_F_CSUM) {
        smap_add(args, "csum", "true");
    }
    if (flags & TNL_F_DF_INHERIT) {
        /* Shouldn't happen as "df_inherit" is no longer supported.  However,
         * for completeness we report it if it's there. */
        smap_add(args, "df_inherit", "true");
    }
    if (!(flags & TNL_F_DF_DEFAULT)) {
        smap_add(args, "df_default", "false");
    }

    return 0;
}

/* Code specific to patch ports. */

const char *
netdev_vport_patch_peer(const struct netdev *netdev)
{
    return netdev_vport_is_patch(netdev)
        ? netdev_vport_get_dev(netdev)->peer
        : NULL;
}

void
netdev_vport_patch_inc_rx(const struct netdev *netdev,
                          const struct dpif_flow_stats *stats)
{
    if (netdev_vport_is_patch(netdev)) {
        struct netdev_dev_vport *dev = netdev_vport_get_dev(netdev);
        dev->stats.rx_packets += stats->n_packets;
        dev->stats.rx_bytes += stats->n_bytes;
    }
}

void
netdev_vport_patch_inc_tx(const struct netdev *netdev,
                          const struct dpif_flow_stats *stats)
{
    if (netdev_vport_is_patch(netdev)) {
        struct netdev_dev_vport *dev = netdev_vport_get_dev(netdev);
        dev->stats.tx_packets += stats->n_packets;
        dev->stats.tx_bytes += stats->n_bytes;
    }
}

static int
get_patch_config(struct netdev_dev *dev_, struct smap *args)
{
    struct netdev_dev_vport *dev = netdev_dev_vport_cast(dev_);

    if (dev->peer) {
        smap_add(args, "peer", dev->peer);
    }
    return 0;
}

static int
set_patch_config(struct netdev_dev *dev_, const struct smap *args)
{
    struct netdev_dev_vport *dev = netdev_dev_vport_cast(dev_);
    const char *name = netdev_dev_get_name(dev_);
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

    if (!strcmp(name, peer)) {
        VLOG_ERR("%s: patch peer must not be self", name);
        return EINVAL;
    }

    free(dev->peer);
    dev->peer = xstrdup(peer);

    return 0;
}

static int
patch_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_dev_vport *dev = netdev_vport_get_dev(netdev);
    memcpy(stats, &dev->stats, sizeof *stats);
    return 0;
}

#define VPORT_FUNCTIONS(GET_CONFIG, SET_CONFIG,             \
                        GET_TUNNEL_CONFIG, GET_STATS,       \
                        GET_STATUS)                         \
    NULL,                                                   \
    netdev_vport_run,                                       \
    netdev_vport_wait,                                      \
                                                            \
    netdev_vport_create,                                    \
    netdev_vport_destroy,                                   \
    GET_CONFIG,                                             \
    SET_CONFIG,                                             \
    GET_TUNNEL_CONFIG,                                      \
                                                            \
    netdev_vport_open,                                      \
    netdev_vport_close,                                     \
                                                            \
    NULL,                       /* listen */                \
    NULL,                       /* recv */                  \
    NULL,                       /* recv_wait */             \
    NULL,                       /* drain */                 \
                                                            \
    NULL,                       /* send */                  \
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
    GET_STATS,                                              \
    NULL,                       /* set_stats */             \
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

#define TUNNEL_CLASS(NAME, VPORT_TYPE)                      \
    { VPORT_TYPE,                                           \
        { NAME, VPORT_FUNCTIONS(get_tunnel_config,          \
                                set_tunnel_config,          \
                                get_netdev_tunnel_config,   \
                                netdev_vport_get_stats,     \
                                tunnel_get_status) }}

void
netdev_vport_register(void)
{
    static const struct vport_class vport_classes[] = {
        TUNNEL_CLASS("gre", OVS_VPORT_TYPE_GRE),
        TUNNEL_CLASS("ipsec_gre", OVS_VPORT_TYPE_GRE),
        TUNNEL_CLASS("gre64", OVS_VPORT_TYPE_GRE64),
        TUNNEL_CLASS("ipsec_gre64", OVS_VPORT_TYPE_GRE64),
        TUNNEL_CLASS("capwap", OVS_VPORT_TYPE_CAPWAP),
        TUNNEL_CLASS("vxlan", OVS_VPORT_TYPE_VXLAN),

        { OVS_VPORT_TYPE_PATCH,
          { "patch", VPORT_FUNCTIONS(get_patch_config,
                                     set_patch_config,
                                     NULL,
                                     patch_get_stats,
                                     NULL) }},
    };

    int i;

    for (i = 0; i < ARRAY_SIZE(vport_classes); i++) {
        netdev_register_provider(&vport_classes[i].netdev_class);
    }
}
