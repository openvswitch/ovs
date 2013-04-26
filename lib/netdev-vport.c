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
#include <net/if.h>
#include <sys/ioctl.h>

#include "byte-order.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif.h"
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "netdev-provider.h"
#include "ofpbuf.h"
#include "packets.h"
#include "route-table.h"
#include "shash.h"
#include "socket-util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_vport);

#define VXLAN_DST_PORT 4789

#define DEFAULT_TTL 64

struct netdev_dev_vport {
    struct netdev_dev netdev_dev;
    unsigned int change_seq;
    uint8_t etheraddr[ETH_ADDR_LEN];
    struct netdev_stats stats;

    /* Tunnels. */
    struct netdev_tunnel_config tnl_cfg;

    /* Patch Ports. */
    char *peer;
};

struct vport_class {
    const char *dpif_port;
    struct netdev_class netdev_class;
};

static int netdev_vport_create(const struct netdev_class *, const char *,
                               struct netdev_dev **);
static int get_patch_config(struct netdev_dev *, struct smap *args);
static int get_tunnel_config(struct netdev_dev *, struct smap *args);
static void netdev_vport_poll_notify(struct netdev_dev_vport *);

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

bool
netdev_vport_is_patch(const struct netdev *netdev)
{
    const struct netdev_dev *dev = netdev_get_dev(netdev);
    const struct netdev_class *class = netdev_dev_get_class(dev);

    return class->get_config == get_patch_config;
}

static bool
netdev_vport_is_vxlan(const struct netdev *netdev)
{
    const struct netdev_dev *dev = netdev_get_dev(netdev);
    const struct netdev_class *class = netdev_dev_get_class(dev);
    const char *type = netdev_dev_get_type(dev);

    return (class->get_config == get_tunnel_config
            && !strcmp("vxlan", type));
}

const char *
netdev_vport_get_dpif_port(const struct netdev *netdev)
{
    const struct netdev_dev *dev = netdev_get_dev(netdev);
    const struct netdev_class *class = netdev_dev_get_class(dev);
    const char *dpif_port;

    if (netdev_vport_is_vxlan(netdev)) {
        const struct netdev_dev_vport *vport = netdev_vport_get_dev(netdev);
        const char *type = netdev_dev_get_type(dev);
        static char dpif_port_vxlan[IFNAMSIZ];

        /*
         * Note: IFNAMSIZ is 16 bytes long. The maximum length of a VXLAN
         * port name below is 15 bytes. Still, assert here on the size of
         * strlen(type) in case that changes in the future.
         */
        ovs_assert(strlen(type) + 10 < IFNAMSIZ);
        snprintf(dpif_port_vxlan, IFNAMSIZ, "%s_sys_%d", type,
                 ntohs(vport->tnl_cfg.dst_port));
        return dpif_port_vxlan;
    } else {
        dpif_port = (is_vport_class(class)
                     ? vport_class_cast(class)->dpif_port
                     : NULL);
    }

    return dpif_port ? dpif_port : netdev_get_name(netdev);
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
    struct netdev_dev_vport *dev = netdev_vport_get_dev(netdev);
    memcpy(dev->etheraddr, mac, ETH_ADDR_LEN);
    netdev_vport_poll_notify(dev);
    return 0;
}

static int
netdev_vport_get_etheraddr(const struct netdev *netdev,
                           uint8_t mac[ETH_ADDR_LEN])
{
    memcpy(mac, netdev_vport_get_dev(netdev)->etheraddr, ETH_ADDR_LEN);
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
netdev_vport_poll_notify(struct netdev_dev_vport *ndv)
{
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

    has_csum = strstr(type, "gre");
    ipsec_mech_set = false;
    memset(&tnl_cfg, 0, sizeof tnl_cfg);

    needs_dst_port = !strcmp(type, "vxlan");
    tnl_cfg.ipsec = strstr(type, "ipsec");
    tnl_cfg.dont_fragment = true;

    SMAP_FOR_EACH (node, args) {
        if (!strcmp(node->key, "remote_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->value, &in_addr)) {
                VLOG_WARN("%s: bad %s 'remote_ip'", name, type);
            } else if (ip_is_multicast(in_addr.s_addr)) {
                VLOG_WARN("%s: multicast remote_ip="IP_FMT" not allowed",
                          name, IP_ARGS(in_addr.s_addr));
                return EINVAL;
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
                tnl_cfg.tos_inherit = true;
            } else {
                char *endptr;
                int tos;
                tos = strtol(node->value, &endptr, 0);
                if (*endptr == '\0' && tos == (tos & IP_DSCP_MASK)) {
                    tnl_cfg.tos = tos;
                } else {
                    VLOG_WARN("%s: invalid TOS %s", name, node->value);
                }
            }
        } else if (!strcmp(node->key, "ttl")) {
            if (!strcmp(node->value, "inherit")) {
                tnl_cfg.ttl_inherit = true;
            } else {
                tnl_cfg.ttl = atoi(node->value);
            }
        } else if (!strcmp(node->key, "dst_port") && needs_dst_port) {
            tnl_cfg.dst_port = htons(atoi(node->value));
        } else if (!strcmp(node->key, "csum") && has_csum) {
            if (!strcmp(node->value, "true")) {
                tnl_cfg.csum = true;
            }
        } else if (!strcmp(node->key, "df_default")) {
            if (!strcmp(node->value, "false")) {
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
                    return EINVAL;
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

    if (!tnl_cfg.ip_dst) {
        VLOG_ERR("%s: %s type requires valid 'remote_ip' argument",
                 name, type);
        return EINVAL;
    }
    if (!tnl_cfg.ttl) {
        tnl_cfg.ttl = DEFAULT_TTL;
    }

    tnl_cfg.in_key = parse_key(args, "in_key",
                               &tnl_cfg.in_key_present,
                               &tnl_cfg.in_key_flow);

    tnl_cfg.out_key = parse_key(args, "out_key",
                               &tnl_cfg.out_key_present,
                               &tnl_cfg.out_key_flow);

    dev->tnl_cfg = tnl_cfg;
    netdev_vport_poll_notify(dev);

    return 0;
}

static int
get_tunnel_config(struct netdev_dev *dev, struct smap *args)
{
    const struct netdev_tunnel_config *tnl_cfg =
        &netdev_dev_vport_cast(dev)->tnl_cfg;

    if (tnl_cfg->ip_dst) {
        smap_add_format(args, "remote_ip", IP_FMT, IP_ARGS(tnl_cfg->ip_dst));
    }

    if (tnl_cfg->ip_src) {
        smap_add_format(args, "local_ip", IP_FMT, IP_ARGS(tnl_cfg->ip_src));
    }

    if (tnl_cfg->in_key_flow && tnl_cfg->out_key_flow) {
        smap_add(args, "key", "flow");
    } else if (tnl_cfg->in_key_present && tnl_cfg->out_key_present
               && tnl_cfg->in_key == tnl_cfg->out_key) {
        smap_add_format(args, "key", "%"PRIu64, ntohll(tnl_cfg->in_key));
    } else {
        if (tnl_cfg->in_key_flow) {
            smap_add(args, "in_key", "flow");
        } else if (tnl_cfg->in_key_present) {
            smap_add_format(args, "in_key", "%"PRIu64,
                            ntohll(tnl_cfg->in_key));
        }

        if (tnl_cfg->out_key_flow) {
            smap_add(args, "out_key", "flow");
        } else if (tnl_cfg->out_key_present) {
            smap_add_format(args, "out_key", "%"PRIu64,
                            ntohll(tnl_cfg->out_key));
        }
    }

    if (tnl_cfg->ttl_inherit) {
        smap_add(args, "ttl", "inherit");
    } else if (tnl_cfg->ttl != DEFAULT_TTL) {
        smap_add_format(args, "ttl", "%"PRIu8, tnl_cfg->ttl);
    }

    if (tnl_cfg->tos_inherit) {
        smap_add(args, "tos", "inherit");
    } else if (tnl_cfg->tos) {
        smap_add_format(args, "tos", "0x%x", tnl_cfg->tos);
    }

    if (tnl_cfg->dst_port) {
        uint16_t dst_port = ntohs(tnl_cfg->dst_port);
        if (dst_port != VXLAN_DST_PORT) {
            smap_add_format(args, "dst_port", "%d", dst_port);
        }
    }

    if (tnl_cfg->csum) {
        smap_add(args, "csum", "true");
    }

    if (!tnl_cfg->dont_fragment) {
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
netdev_vport_inc_rx(const struct netdev *netdev,
                          const struct dpif_flow_stats *stats)
{
    if (is_vport_class(netdev_dev_get_class(netdev_get_dev(netdev)))) {
        struct netdev_dev_vport *dev = netdev_vport_get_dev(netdev);
        dev->stats.rx_packets += stats->n_packets;
        dev->stats.rx_bytes += stats->n_bytes;
    }
}

void
netdev_vport_inc_tx(const struct netdev *netdev,
                    const struct dpif_flow_stats *stats)
{
    if (is_vport_class(netdev_dev_get_class(netdev_get_dev(netdev)))) {
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
get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_dev_vport *dev = netdev_vport_get_dev(netdev);
    memcpy(stats, &dev->stats, sizeof *stats);
    return 0;
}

#define VPORT_FUNCTIONS(GET_CONFIG, SET_CONFIG,             \
                        GET_TUNNEL_CONFIG, GET_STATUS)      \
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
    get_stats,                                              \
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

#define TUNNEL_CLASS(NAME, DPIF_PORT)                       \
    { DPIF_PORT,                                            \
        { NAME, VPORT_FUNCTIONS(get_tunnel_config,          \
                                set_tunnel_config,          \
                                get_netdev_tunnel_config,   \
                                tunnel_get_status) }}

void
netdev_vport_tunnel_register(void)
{
    static const struct vport_class vport_classes[] = {
        TUNNEL_CLASS("gre", "gre_system"),
        TUNNEL_CLASS("ipsec_gre", "gre_system"),
        TUNNEL_CLASS("gre64", "gre64_system"),
        TUNNEL_CLASS("ipsec_gre64", "gre64_system"),
        TUNNEL_CLASS("vxlan", "vxlan_system")
    };

    int i;

    for (i = 0; i < ARRAY_SIZE(vport_classes); i++) {
        netdev_register_provider(&vport_classes[i].netdev_class);
    }
}

void
netdev_vport_patch_register(void)
{
    static const struct vport_class patch_class =
        { NULL,
            { "patch", VPORT_FUNCTIONS(get_patch_config,
                                       set_patch_config,
                                       NULL,
                                       NULL) }};
    netdev_register_provider(&patch_class.netdev_class);
}
