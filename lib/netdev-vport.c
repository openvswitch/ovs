/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "csum.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif.h"
#include "dp-packet.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "netdev-provider.h"
#include "odp-netlink.h"
#include "dp-packet.h"
#include "ovs-router.h"
#include "packets.h"
#include "poll-loop.h"
#include "route-table.h"
#include "shash.h"
#include "socket-util.h"
#include "openvswitch/vlog.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netdev_vport);
static struct vlog_rate_limit err_rl = VLOG_RATE_LIMIT_INIT(60, 5);

#define GENEVE_DST_PORT 6081
#define VXLAN_DST_PORT 4789
#define LISP_DST_PORT 4341
#define STT_DST_PORT 7471

#define VXLAN_HLEN   (sizeof(struct eth_header) +         \
                      sizeof(struct ip_header)  +         \
                      sizeof(struct udp_header) +         \
                      sizeof(struct vxlanhdr))

#define GENEVE_BASE_HLEN   (sizeof(struct eth_header) +         \
                            sizeof(struct ip_header)  +         \
                            sizeof(struct udp_header) +         \
                            sizeof(struct genevehdr))

#define DEFAULT_TTL 64

struct netdev_vport {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    uint8_t etheraddr[ETH_ADDR_LEN];
    struct netdev_stats stats;

    /* Tunnels. */
    struct netdev_tunnel_config tnl_cfg;
    char egress_iface[IFNAMSIZ];
    bool carrier_status;

    /* Patch Ports. */
    char *peer;
};

struct vport_class {
    const char *dpif_port;
    struct netdev_class netdev_class;
};

/* Last read of the route-table's change number. */
static uint64_t rt_change_seqno;

static int netdev_vport_construct(struct netdev *);
static int get_patch_config(const struct netdev *netdev, struct smap *args);
static int get_tunnel_config(const struct netdev *, struct smap *args);
static bool tunnel_check_status_change__(struct netdev_vport *);

static uint16_t tnl_udp_port_min = 32768;
static uint16_t tnl_udp_port_max = 61000;

static bool
is_vport_class(const struct netdev_class *class)
{
    return class->construct == netdev_vport_construct;
}

bool
netdev_vport_is_vport_class(const struct netdev_class *class)
{
    return is_vport_class(class);
}

static const struct vport_class *
vport_class_cast(const struct netdev_class *class)
{
    ovs_assert(is_vport_class(class));
    return CONTAINER_OF(class, struct vport_class, netdev_class);
}

static struct netdev_vport *
netdev_vport_cast(const struct netdev *netdev)
{
    ovs_assert(is_vport_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_vport, up);
}

static const struct netdev_tunnel_config *
get_netdev_tunnel_config(const struct netdev *netdev)
{
    return &netdev_vport_cast(netdev)->tnl_cfg;
}

bool
netdev_vport_is_patch(const struct netdev *netdev)
{
    const struct netdev_class *class = netdev_get_class(netdev);

    return class->get_config == get_patch_config;
}

bool
netdev_vport_is_layer3(const struct netdev *dev)
{
    const char *type = netdev_get_type(dev);

    return (!strcmp("lisp", type));
}

static bool
netdev_vport_needs_dst_port(const struct netdev *dev)
{
    const struct netdev_class *class = netdev_get_class(dev);
    const char *type = netdev_get_type(dev);

    return (class->get_config == get_tunnel_config &&
            (!strcmp("geneve", type) || !strcmp("vxlan", type) ||
             !strcmp("lisp", type) || !strcmp("stt", type)) );
}

const char *
netdev_vport_class_get_dpif_port(const struct netdev_class *class)
{
    return is_vport_class(class) ? vport_class_cast(class)->dpif_port : NULL;
}

const char *
netdev_vport_get_dpif_port(const struct netdev *netdev,
                           char namebuf[], size_t bufsize)
{
    const struct netdev_class *class = netdev_get_class(netdev);
    const char *dpif_port = netdev_vport_class_get_dpif_port(class);

    if (!dpif_port) {
        return netdev_get_name(netdev);
    }

    if (netdev_vport_needs_dst_port(netdev)) {
        const struct netdev_vport *vport = netdev_vport_cast(netdev);

        /*
         * Note: IFNAMSIZ is 16 bytes long. Implementations should choose
         * a dpif port name that is short enough to fit including any
         * port numbers but assert just in case.
         */
        BUILD_ASSERT(NETDEV_VPORT_NAME_BUFSIZE >= IFNAMSIZ);
        ovs_assert(strlen(dpif_port) + 6 < IFNAMSIZ);
        snprintf(namebuf, bufsize, "%s_%d", dpif_port,
                 ntohs(vport->tnl_cfg.dst_port));
        return namebuf;
    } else {
        return dpif_port;
    }
}

char *
netdev_vport_get_dpif_port_strdup(const struct netdev *netdev)
{
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];

    return xstrdup(netdev_vport_get_dpif_port(netdev, namebuf,
                                              sizeof namebuf));
}

/* Whenever the route-table change number is incremented,
 * netdev_vport_route_changed() should be called to update
 * the corresponding tunnel interface status. */
static void
netdev_vport_route_changed(void)
{
    struct netdev **vports;
    size_t i, n_vports;

    vports = netdev_get_vports(&n_vports);
    for (i = 0; i < n_vports; i++) {
        struct netdev *netdev_ = vports[i];
        struct netdev_vport *netdev = netdev_vport_cast(netdev_);

        ovs_mutex_lock(&netdev->mutex);
        /* Finds all tunnel vports. */
        if (netdev->tnl_cfg.ip_dst) {
            if (tunnel_check_status_change__(netdev)) {
                netdev_change_seq_changed(netdev_);
            }
        }
        ovs_mutex_unlock(&netdev->mutex);

        netdev_close(netdev_);
    }

    free(vports);
}

static struct netdev *
netdev_vport_alloc(void)
{
    struct netdev_vport *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static int
netdev_vport_construct(struct netdev *netdev_)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev_);
    const char *type = netdev_get_type(netdev_);

    ovs_mutex_init(&dev->mutex);
    eth_addr_random(dev->etheraddr);

    /* Add a default destination port for tunnel ports if none specified. */
    if (!strcmp(type, "geneve")) {
        dev->tnl_cfg.dst_port = htons(GENEVE_DST_PORT);
    } else if (!strcmp(type, "vxlan")) {
        dev->tnl_cfg.dst_port = htons(VXLAN_DST_PORT);
    } else if (!strcmp(type, "lisp")) {
        dev->tnl_cfg.dst_port = htons(LISP_DST_PORT);
    } else if (!strcmp(type, "stt")) {
        dev->tnl_cfg.dst_port = htons(STT_DST_PORT);
    }

    dev->tnl_cfg.dont_fragment = true;
    dev->tnl_cfg.ttl = DEFAULT_TTL;
    return 0;
}

static void
netdev_vport_destruct(struct netdev *netdev_)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);

    free(netdev->peer);
    ovs_mutex_destroy(&netdev->mutex);
}

static void
netdev_vport_dealloc(struct netdev *netdev_)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);
    free(netdev);
}

static int
netdev_vport_set_etheraddr(struct netdev *netdev_,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    memcpy(netdev->etheraddr, mac, ETH_ADDR_LEN);
    ovs_mutex_unlock(&netdev->mutex);
    netdev_change_seq_changed(netdev_);

    return 0;
}

static int
netdev_vport_get_etheraddr(const struct netdev *netdev_,
                           uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    memcpy(mac, netdev->etheraddr, ETH_ADDR_LEN);
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

/* Checks if the tunnel status has changed and returns a boolean.
 * Updates the tunnel status if it has changed. */
static bool
tunnel_check_status_change__(struct netdev_vport *netdev)
    OVS_REQUIRES(netdev->mutex)
{
    char iface[IFNAMSIZ];
    bool status = false;
    ovs_be32 route;
    ovs_be32 gw;

    iface[0] = '\0';
    route = netdev->tnl_cfg.ip_dst;
    if (ovs_router_lookup(route, iface, &gw)) {
        struct netdev *egress_netdev;

        if (!netdev_open(iface, "system", &egress_netdev)) {
            status = netdev_get_carrier(egress_netdev);
            netdev_close(egress_netdev);
        }
    }

    if (strcmp(netdev->egress_iface, iface)
        || netdev->carrier_status != status) {
        ovs_strlcpy(netdev->egress_iface, iface, IFNAMSIZ);
        netdev->carrier_status = status;

        return true;
    }

    return false;
}

static int
tunnel_get_status(const struct netdev *netdev_, struct smap *smap)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);

    if (netdev->egress_iface[0]) {
        smap_add(smap, "tunnel_egress_iface", netdev->egress_iface);

        smap_add(smap, "tunnel_egress_iface_carrier",
                 netdev->carrier_status ? "up" : "down");
    }

    return 0;
}

static int
netdev_vport_update_flags(struct netdev *netdev OVS_UNUSED,
                          enum netdev_flags off,
                          enum netdev_flags on OVS_UNUSED,
                          enum netdev_flags *old_flagsp)
{
    if (off & (NETDEV_UP | NETDEV_PROMISC)) {
        return EOPNOTSUPP;
    }

    *old_flagsp = NETDEV_UP | NETDEV_PROMISC;
    return 0;
}

static void
netdev_vport_run(void)
{
    uint64_t seq;

    route_table_run();
    seq = route_table_get_change_seq();
    if (rt_change_seqno != seq) {
        rt_change_seqno = seq;
        netdev_vport_route_changed();
    }
}

static void
netdev_vport_wait(void)
{
    uint64_t seq;

    route_table_wait();
    seq = route_table_get_change_seq();
    if (rt_change_seqno != seq) {
        poll_immediate_wake();
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
set_tunnel_config(struct netdev *dev_, const struct smap *args)
{
    struct netdev_vport *dev = netdev_vport_cast(dev_);
    const char *name = netdev_get_name(dev_);
    const char *type = netdev_get_type(dev_);
    bool ipsec_mech_set, needs_dst_port, has_csum;
    struct netdev_tunnel_config tnl_cfg;
    struct smap_node *node;

    has_csum = strstr(type, "gre") || strstr(type, "geneve") ||
               strstr(type, "stt") || strstr(type, "vxlan");
    ipsec_mech_set = false;
    memset(&tnl_cfg, 0, sizeof tnl_cfg);

    /* Add a default destination port for tunnel ports if none specified. */
    if (!strcmp(type, "geneve")) {
        tnl_cfg.dst_port = htons(GENEVE_DST_PORT);
    }

    if (!strcmp(type, "vxlan")) {
        tnl_cfg.dst_port = htons(VXLAN_DST_PORT);
    }

    if (!strcmp(type, "lisp")) {
        tnl_cfg.dst_port = htons(LISP_DST_PORT);
    }

    if (!strcmp(type, "stt")) {
        tnl_cfg.dst_port = htons(STT_DST_PORT);
    }

    needs_dst_port = netdev_vport_needs_dst_port(dev_);
    tnl_cfg.ipsec = strstr(type, "ipsec");
    tnl_cfg.dont_fragment = true;

    SMAP_FOR_EACH (node, args) {
        if (!strcmp(node->key, "remote_ip")) {
            struct in_addr in_addr;
            if (!strcmp(node->value, "flow")) {
                tnl_cfg.ip_dst_flow = true;
                tnl_cfg.ip_dst = htonl(0);
            } else if (lookup_ip(node->value, &in_addr)) {
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
            if (!strcmp(node->value, "flow")) {
                tnl_cfg.ip_src_flow = true;
                tnl_cfg.ip_src = htonl(0);
            } else if (lookup_ip(node->value, &in_addr)) {
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
        } else if (!strcmp(node->key, "exts")) {
            char *str = xstrdup(node->value);
            char *ext, *save_ptr = NULL;

            tnl_cfg.exts = 0;

            ext = strtok_r(str, ",", &save_ptr);
            while (ext) {
                if (!strcmp(type, "vxlan") && !strcmp(ext, "gbp")) {
                    tnl_cfg.exts |= (1 << OVS_VXLAN_EXT_GBP);
                } else {
                    VLOG_WARN("%s: unknown extension '%s'", name, ext);
                }

                ext = strtok_r(NULL, ",", &save_ptr);
            }

            free(str);
        } else {
            VLOG_WARN("%s: unknown %s argument '%s'", name, type, node->key);
        }
    }

    if (tnl_cfg.ipsec) {
        static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
        static pid_t pid = 0;

#ifndef _WIN32
        ovs_mutex_lock(&mutex);
        if (pid <= 0) {
            char *file_name = xasprintf("%s/%s", ovs_rundir(),
                                        "ovs-monitor-ipsec.pid");
            pid = read_pidfile(file_name);
            free(file_name);
        }
        ovs_mutex_unlock(&mutex);
#endif

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

    if (!tnl_cfg.ip_dst && !tnl_cfg.ip_dst_flow) {
        VLOG_ERR("%s: %s type requires valid 'remote_ip' argument",
                 name, type);
        return EINVAL;
    }
    if (tnl_cfg.ip_src_flow && !tnl_cfg.ip_dst_flow) {
        VLOG_ERR("%s: %s type requires 'remote_ip=flow' with 'local_ip=flow'",
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

    ovs_mutex_lock(&dev->mutex);
    if (memcmp(&dev->tnl_cfg, &tnl_cfg, sizeof tnl_cfg)) {
        dev->tnl_cfg = tnl_cfg;
        tunnel_check_status_change__(dev);
        netdev_change_seq_changed(dev_);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
get_tunnel_config(const struct netdev *dev, struct smap *args)
{
    struct netdev_vport *netdev = netdev_vport_cast(dev);
    struct netdev_tunnel_config tnl_cfg;

    ovs_mutex_lock(&netdev->mutex);
    tnl_cfg = netdev->tnl_cfg;
    ovs_mutex_unlock(&netdev->mutex);

    if (tnl_cfg.ip_dst) {
        smap_add_format(args, "remote_ip", IP_FMT, IP_ARGS(tnl_cfg.ip_dst));
    } else if (tnl_cfg.ip_dst_flow) {
        smap_add(args, "remote_ip", "flow");
    }

    if (tnl_cfg.ip_src) {
        smap_add_format(args, "local_ip", IP_FMT, IP_ARGS(tnl_cfg.ip_src));
    } else if (tnl_cfg.ip_src_flow) {
        smap_add(args, "local_ip", "flow");
    }

    if (tnl_cfg.in_key_flow && tnl_cfg.out_key_flow) {
        smap_add(args, "key", "flow");
    } else if (tnl_cfg.in_key_present && tnl_cfg.out_key_present
               && tnl_cfg.in_key == tnl_cfg.out_key) {
        smap_add_format(args, "key", "%"PRIu64, ntohll(tnl_cfg.in_key));
    } else {
        if (tnl_cfg.in_key_flow) {
            smap_add(args, "in_key", "flow");
        } else if (tnl_cfg.in_key_present) {
            smap_add_format(args, "in_key", "%"PRIu64,
                            ntohll(tnl_cfg.in_key));
        }

        if (tnl_cfg.out_key_flow) {
            smap_add(args, "out_key", "flow");
        } else if (tnl_cfg.out_key_present) {
            smap_add_format(args, "out_key", "%"PRIu64,
                            ntohll(tnl_cfg.out_key));
        }
    }

    if (tnl_cfg.ttl_inherit) {
        smap_add(args, "ttl", "inherit");
    } else if (tnl_cfg.ttl != DEFAULT_TTL) {
        smap_add_format(args, "ttl", "%"PRIu8, tnl_cfg.ttl);
    }

    if (tnl_cfg.tos_inherit) {
        smap_add(args, "tos", "inherit");
    } else if (tnl_cfg.tos) {
        smap_add_format(args, "tos", "0x%x", tnl_cfg.tos);
    }

    if (tnl_cfg.dst_port) {
        uint16_t dst_port = ntohs(tnl_cfg.dst_port);
        const char *type = netdev_get_type(dev);

        if ((!strcmp("geneve", type) && dst_port != GENEVE_DST_PORT) ||
            (!strcmp("vxlan", type) && dst_port != VXLAN_DST_PORT) ||
            (!strcmp("lisp", type) && dst_port != LISP_DST_PORT) ||
            (!strcmp("stt", type) && dst_port != STT_DST_PORT)) {
            smap_add_format(args, "dst_port", "%d", dst_port);
        }
    }

    if (tnl_cfg.csum) {
        smap_add(args, "csum", "true");
    }

    if (!tnl_cfg.dont_fragment) {
        smap_add(args, "df_default", "false");
    }

    return 0;
}

/* Code specific to patch ports. */

/* If 'netdev' is a patch port, returns the name of its peer as a malloc()'d
 * string that the caller must free.
 *
 * If 'netdev' is not a patch port, returns NULL. */
char *
netdev_vport_patch_peer(const struct netdev *netdev_)
{
    char *peer = NULL;

    if (netdev_vport_is_patch(netdev_)) {
        struct netdev_vport *netdev = netdev_vport_cast(netdev_);

        ovs_mutex_lock(&netdev->mutex);
        if (netdev->peer) {
            peer = xstrdup(netdev->peer);
        }
        ovs_mutex_unlock(&netdev->mutex);
    }

    return peer;
}

void
netdev_vport_inc_rx(const struct netdev *netdev,
                    const struct dpif_flow_stats *stats)
{
    if (is_vport_class(netdev_get_class(netdev))) {
        struct netdev_vport *dev = netdev_vport_cast(netdev);

        ovs_mutex_lock(&dev->mutex);
        dev->stats.rx_packets += stats->n_packets;
        dev->stats.rx_bytes += stats->n_bytes;
        ovs_mutex_unlock(&dev->mutex);
    }
}

void
netdev_vport_inc_tx(const struct netdev *netdev,
                    const struct dpif_flow_stats *stats)
{
    if (is_vport_class(netdev_get_class(netdev))) {
        struct netdev_vport *dev = netdev_vport_cast(netdev);

        ovs_mutex_lock(&dev->mutex);
        dev->stats.tx_packets += stats->n_packets;
        dev->stats.tx_bytes += stats->n_bytes;
        ovs_mutex_unlock(&dev->mutex);
    }
}

static int
get_patch_config(const struct netdev *dev_, struct smap *args)
{
    struct netdev_vport *dev = netdev_vport_cast(dev_);

    ovs_mutex_lock(&dev->mutex);
    if (dev->peer) {
        smap_add(args, "peer", dev->peer);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
set_patch_config(struct netdev *dev_, const struct smap *args)
{
    struct netdev_vport *dev = netdev_vport_cast(dev_);
    const char *name = netdev_get_name(dev_);
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

    ovs_mutex_lock(&dev->mutex);
    if (!dev->peer || strcmp(dev->peer, peer)) {
        free(dev->peer);
        dev->peer = xstrdup(peer);
        netdev_change_seq_changed(dev_);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *stats = dev->stats;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}


/* Tunnel push pop ops. */

static struct ip_header *
ip_hdr(void *eth)
{
    return (void *)((char *)eth + sizeof (struct eth_header));
}

static struct gre_base_hdr *
gre_hdr(struct ip_header *ip)
{
     return (void *)((char *)ip + sizeof (struct ip_header));
}

static void *
ip_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl)
{
    struct ip_header *nh;
    void *l4;

    nh = dp_packet_l3(packet);
    l4 = dp_packet_l4(packet);

    if (!nh || !l4) {
        return NULL;
    }

    tnl->ip_src = get_16aligned_be32(&nh->ip_src);
    tnl->ip_dst = get_16aligned_be32(&nh->ip_dst);
    tnl->ip_tos = nh->ip_tos;
    tnl->ip_ttl = nh->ip_ttl;

    return l4;
}

/* Pushes the 'size' bytes of 'header' into the headroom of 'packet',
 * reallocating the packet if necessary.  'header' should contain an Ethernet
 * header, followed by an IPv4 header (without options), and an L4 header.
 *
 * This function sets the IP header's ip_tot_len field (which should be zeroed
 * as part of 'header') and puts its value into '*ip_tot_size' as well.  Also
 * updates IP header checksum.
 *
 * Return pointer to the L4 header added to 'packet'. */
static void *
push_ip_header(struct dp_packet *packet,
               const void *header, int size, int *ip_tot_size)
{
    struct eth_header *eth;
    struct ip_header *ip;

    eth = dp_packet_push_uninit(packet, size);
    *ip_tot_size = dp_packet_size(packet) - sizeof (struct eth_header);

    memcpy(eth, header, size);
    ip = ip_hdr(eth);
    ip->ip_tot_len = htons(*ip_tot_size);


    ip->ip_csum = recalc_csum16(ip->ip_csum, 0, ip->ip_tot_len);

    return ip + 1;
}

static void *
udp_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl)
{
    struct udp_header *udp;

    udp = ip_extract_tnl_md(packet, tnl);
    if (!udp) {
        return NULL;
    }

    if (udp->udp_csum) {
        uint32_t csum = packet_csum_pseudoheader(dp_packet_l3(packet));

        csum = csum_continue(csum, udp, dp_packet_size(packet) -
                             ((const unsigned char *)udp -
                              (const unsigned char *)dp_packet_l2(packet)));
        if (csum_finish(csum)) {
            return NULL;
        }
        tnl->flags |= FLOW_TNL_F_CSUM;
    }

    tnl->tp_src = udp->udp_src;
    tnl->tp_dst = udp->udp_dst;

    return udp + 1;
}

static ovs_be16
get_src_port(struct dp_packet *packet)
{
    uint32_t hash;

    hash = dp_packet_get_rss_hash(packet);

    return htons((((uint64_t) hash * (tnl_udp_port_max - tnl_udp_port_min)) >> 32) +
                 tnl_udp_port_min);
}

static void
push_udp_header(struct dp_packet *packet,
                const struct ovs_action_push_tnl *data)
{
    struct udp_header *udp;
    int ip_tot_size;

    udp = push_ip_header(packet, data->header, data->header_len, &ip_tot_size);

    /* set udp src port */
    udp->udp_src = get_src_port(packet);
    udp->udp_len = htons(ip_tot_size - sizeof (struct ip_header));

    if (udp->udp_csum) {
        uint32_t csum = packet_csum_pseudoheader(ip_hdr(dp_packet_data(packet)));

        csum = csum_continue(csum, udp,
                             ip_tot_size - sizeof (struct ip_header));
        udp->udp_csum = csum_finish(csum);

        if (!udp->udp_csum) {
            udp->udp_csum = htons(0xffff);
        }
    }
}

static void *
udp_build_header(struct netdev_tunnel_config *tnl_cfg,
                 const struct flow *tnl_flow,
                 struct ovs_action_push_tnl *data)
{
    struct ip_header *ip;
    struct udp_header *udp;

    ip = ip_hdr(data->header);
    ip->ip_proto = IPPROTO_UDP;

    udp = (struct udp_header *) (ip + 1);
    udp->udp_dst = tnl_cfg->dst_port;

    if (tnl_flow->tunnel.flags & FLOW_TNL_F_CSUM) {
        /* Write a value in now to mark that we should compute the checksum
         * later. 0xffff is handy because it is transparent to the
         * calculation. */
        udp->udp_csum = htons(0xffff);
    }

    return udp + 1;
}

static int
gre_header_len(ovs_be16 flags)
{
    int hlen = sizeof(struct eth_header) +
               sizeof(struct ip_header) + 4;

    if (flags & htons(GRE_CSUM)) {
        hlen += 4;
    }
    if (flags & htons(GRE_KEY)) {
        hlen += 4;
    }
    if (flags & htons(GRE_SEQ)) {
        hlen += 4;
    }
    return hlen;
}

static int
parse_gre_header(struct dp_packet *packet,
                 struct flow_tnl *tnl)
{
    const struct gre_base_hdr *greh;
    ovs_16aligned_be32 *options;
    int hlen;

    greh = ip_extract_tnl_md(packet, tnl);
    if (!greh) {
        return -EINVAL;
    }

    if (greh->flags & ~(htons(GRE_CSUM | GRE_KEY | GRE_SEQ))) {
        return -EINVAL;
    }

    if (greh->protocol != htons(ETH_TYPE_TEB)) {
        return -EINVAL;
    }

    hlen = gre_header_len(greh->flags);
    if (hlen > dp_packet_size(packet)) {
        return -EINVAL;
    }

    options = (ovs_16aligned_be32 *)(greh + 1);
    if (greh->flags & htons(GRE_CSUM)) {
        ovs_be16 pkt_csum;

        pkt_csum = csum(greh, dp_packet_size(packet) -
                              ((const unsigned char *)greh -
                               (const unsigned char *)dp_packet_l2(packet)));
        if (pkt_csum) {
            return -EINVAL;
        }
        tnl->flags = FLOW_TNL_F_CSUM;
        options++;
    }

    if (greh->flags & htons(GRE_KEY)) {
        tnl->tun_id = (OVS_FORCE ovs_be64) ((OVS_FORCE uint64_t)(get_16aligned_be32(options)) << 32);
        tnl->flags |= FLOW_TNL_F_KEY;
        options++;
    }

    if (greh->flags & htons(GRE_SEQ)) {
        options++;
    }

    return hlen;
}

static int
netdev_gre_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    int hlen = sizeof(struct eth_header) +
               sizeof(struct ip_header) + 4;

    memset(md, 0, sizeof *md);
    if (hlen > dp_packet_size(packet)) {
        return EINVAL;
    }

    hlen = parse_gre_header(packet, tnl);
    if (hlen < 0) {
        return -hlen;
    }

    dp_packet_reset_packet(packet, hlen);

    return 0;
}

static void
netdev_gre_push_header(struct dp_packet *packet,
                       const struct ovs_action_push_tnl *data)
{
    struct gre_base_hdr *greh;
    int ip_tot_size;

    greh = push_ip_header(packet, data->header, data->header_len, &ip_tot_size);

    if (greh->flags & htons(GRE_CSUM)) {
        ovs_be16 *csum_opt = (ovs_be16 *) (greh + 1);
        *csum_opt = csum(greh, ip_tot_size - sizeof (struct ip_header));
    }
}

static int
netdev_gre_build_header(const struct netdev *netdev,
                        struct ovs_action_push_tnl *data,
                        const struct flow *tnl_flow)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct ip_header *ip;
    struct gre_base_hdr *greh;
    ovs_16aligned_be32 *options;
    int hlen;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    ip = ip_hdr(data->header);
    ip->ip_proto = IPPROTO_GRE;

    greh = gre_hdr(ip);
    greh->protocol = htons(ETH_TYPE_TEB);
    greh->flags = 0;

    options = (ovs_16aligned_be32 *) (greh + 1);
    if (tnl_flow->tunnel.flags & FLOW_TNL_F_CSUM) {
        greh->flags |= htons(GRE_CSUM);
        put_16aligned_be32(options, 0);
        options++;
    }

    if (tnl_cfg->out_key_present) {
        greh->flags |= htons(GRE_KEY);
        put_16aligned_be32(options, (OVS_FORCE ovs_be32)
                                    ((OVS_FORCE uint64_t) tnl_flow->tunnel.tun_id >> 32));
        options++;
    }

    ovs_mutex_unlock(&dev->mutex);

    hlen = (uint8_t *) options - (uint8_t *) greh;

    data->header_len = sizeof(struct eth_header) +
                       sizeof(struct ip_header)  + hlen;
    data->tnl_type = OVS_VPORT_TYPE_GRE;
    return 0;
}

static int
netdev_vxlan_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct vxlanhdr *vxh;

    memset(md, 0, sizeof *md);
    if (VXLAN_HLEN > dp_packet_size(packet)) {
        return EINVAL;
    }

    vxh = udp_extract_tnl_md(packet, tnl);
    if (!vxh) {
        return EINVAL;
    }

    if (get_16aligned_be32(&vxh->vx_flags) != htonl(VXLAN_FLAGS) ||
       (get_16aligned_be32(&vxh->vx_vni) & htonl(0xff))) {
        VLOG_WARN_RL(&err_rl, "invalid vxlan flags=%#x vni=%#x\n",
                     ntohl(get_16aligned_be32(&vxh->vx_flags)),
                     ntohl(get_16aligned_be32(&vxh->vx_vni)));
        return EINVAL;
    }
    tnl->tun_id = htonll(ntohl(get_16aligned_be32(&vxh->vx_vni)) >> 8);
    tnl->flags |= FLOW_TNL_F_KEY;

    dp_packet_reset_packet(packet, VXLAN_HLEN);

    return 0;
}

static int
netdev_vxlan_build_header(const struct netdev *netdev,
                          struct ovs_action_push_tnl *data,
                          const struct flow *tnl_flow)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct vxlanhdr *vxh;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    vxh = udp_build_header(tnl_cfg, tnl_flow, data);

    put_16aligned_be32(&vxh->vx_flags, htonl(VXLAN_FLAGS));
    put_16aligned_be32(&vxh->vx_vni, htonl(ntohll(tnl_flow->tunnel.tun_id) << 8));

    ovs_mutex_unlock(&dev->mutex);
    data->header_len = VXLAN_HLEN;
    data->tnl_type = OVS_VPORT_TYPE_VXLAN;
    return 0;
}

static int
netdev_geneve_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct genevehdr *gnh;
    unsigned int hlen;

    memset(md, 0, sizeof *md);
    if (GENEVE_BASE_HLEN > dp_packet_size(packet)) {
        VLOG_WARN_RL(&err_rl, "geneve packet too small: min header=%u packet size=%u\n",
                     (unsigned int)GENEVE_BASE_HLEN, dp_packet_size(packet));
        return EINVAL;
    }

    gnh = udp_extract_tnl_md(packet, tnl);
    if (!gnh) {
        return EINVAL;
    }

    hlen = GENEVE_BASE_HLEN + gnh->opt_len * 4;
    if (hlen > dp_packet_size(packet)) {
        VLOG_WARN_RL(&err_rl, "geneve packet too small: header len=%u packet size=%u\n",
                     hlen, dp_packet_size(packet));
        return EINVAL;
    }

    if (gnh->ver != 0) {
        VLOG_WARN_RL(&err_rl, "unknown geneve version: %"PRIu8"\n", gnh->ver);
        return EINVAL;
    }

    if (gnh->opt_len && gnh->critical) {
        VLOG_WARN_RL(&err_rl, "unknown geneve critical options: %"PRIu8" bytes\n",
                     gnh->opt_len * 4);
        return EINVAL;
    }

    if (gnh->proto_type != htons(ETH_TYPE_TEB)) {
        VLOG_WARN_RL(&err_rl, "unknown geneve encapsulated protocol: %#x\n",
                     ntohs(gnh->proto_type));
        return EINVAL;
    }

    tnl->flags |= gnh->oam ? FLOW_TNL_F_OAM : 0;
    tnl->tun_id = htonll(ntohl(get_16aligned_be32(&gnh->vni)) >> 8);
    tnl->flags |= FLOW_TNL_F_KEY;

    dp_packet_reset_packet(packet, hlen);

    return 0;
}

static int
netdev_geneve_build_header(const struct netdev *netdev,
                           struct ovs_action_push_tnl *data,
                           const struct flow *tnl_flow)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct genevehdr *gnh;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    gnh = udp_build_header(tnl_cfg, tnl_flow, data);

    gnh->oam = !!(tnl_flow->tunnel.flags & FLOW_TNL_F_OAM);
    gnh->proto_type = htons(ETH_TYPE_TEB);
    put_16aligned_be32(&gnh->vni, htonl(ntohll(tnl_flow->tunnel.tun_id) << 8));

    ovs_mutex_unlock(&dev->mutex);
    data->header_len = GENEVE_BASE_HLEN;
    data->tnl_type = OVS_VPORT_TYPE_GENEVE;
    return 0;
}

static void
netdev_vport_range(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    int val1, val2;

    if (argc < 3) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "Tunnel UDP source port range: %"PRIu16"-%"PRIu16"\n",
                            tnl_udp_port_min, tnl_udp_port_max);

        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
        return;
    }

    if (argc != 3) {
        return;
    }

    val1 = atoi(argv[1]);
    if (val1 <= 0 || val1 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid min.");
        return;
    }
    val2 = atoi(argv[2]);
    if (val2 <= 0 || val2 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid max.");
        return;
    }

    if (val1 > val2) {
        tnl_udp_port_min = val2;
        tnl_udp_port_max = val1;
    } else {
        tnl_udp_port_min = val1;
        tnl_udp_port_max = val2;
    }
    seq_change(tnl_conf_seq);

    unixctl_command_reply(conn, "OK");
}


#define VPORT_FUNCTIONS(GET_CONFIG, SET_CONFIG,             \
                        GET_TUNNEL_CONFIG, GET_STATUS,      \
                        BUILD_HEADER,                       \
                        PUSH_HEADER, POP_HEADER)            \
    NULL,                                                   \
    netdev_vport_run,                                       \
    netdev_vport_wait,                                      \
                                                            \
    netdev_vport_alloc,                                     \
    netdev_vport_construct,                                 \
    netdev_vport_destruct,                                  \
    netdev_vport_dealloc,                                   \
    GET_CONFIG,                                             \
    SET_CONFIG,                                             \
    GET_TUNNEL_CONFIG,                                      \
    BUILD_HEADER,                                           \
    PUSH_HEADER,                                            \
    POP_HEADER,                                             \
    NULL,                       /* get_numa_id */           \
    NULL,                       /* set_multiq */            \
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
    NULL,                       /* queue_dump_start */      \
    NULL,                       /* queue_dump_next */       \
    NULL,                       /* queue_dump_done */       \
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
    NULL,                   /* rx_alloc */                  \
    NULL,                   /* rx_construct */              \
    NULL,                   /* rx_destruct */               \
    NULL,                   /* rx_dealloc */                \
    NULL,                   /* rx_recv */                   \
    NULL,                   /* rx_wait */                   \
    NULL,                   /* rx_drain */


#define TUNNEL_CLASS(NAME, DPIF_PORT, BUILD_HEADER, PUSH_HEADER, POP_HEADER)   \
    { DPIF_PORT,                                                               \
        { NAME, VPORT_FUNCTIONS(get_tunnel_config,                             \
                                set_tunnel_config,                             \
                                get_netdev_tunnel_config,                      \
                                tunnel_get_status,                             \
                                BUILD_HEADER, PUSH_HEADER, POP_HEADER) }}

void
netdev_vport_tunnel_register(void)
{
    /* The name of the dpif_port should be short enough to accomodate adding
     * a port number to the end if one is necessary. */
    static const struct vport_class vport_classes[] = {
        TUNNEL_CLASS("geneve", "genev_sys", netdev_geneve_build_header,
                                            push_udp_header,
                                            netdev_geneve_pop_header),
        TUNNEL_CLASS("gre", "gre_sys", netdev_gre_build_header,
                                       netdev_gre_push_header,
                                       netdev_gre_pop_header),
        TUNNEL_CLASS("ipsec_gre", "gre_sys", NULL, NULL, NULL),
        TUNNEL_CLASS("gre64", "gre64_sys", NULL,  NULL, NULL),
        TUNNEL_CLASS("ipsec_gre64", "gre64_sys", NULL, NULL, NULL),
        TUNNEL_CLASS("vxlan", "vxlan_sys", netdev_vxlan_build_header,
                                           push_udp_header,
                                           netdev_vxlan_pop_header),
        TUNNEL_CLASS("lisp", "lisp_sys", NULL, NULL, NULL),
        TUNNEL_CLASS("stt", "stt_sys", NULL, NULL, NULL),
    };
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        int i;

        for (i = 0; i < ARRAY_SIZE(vport_classes); i++) {
            netdev_register_provider(&vport_classes[i].netdev_class);
        }

        unixctl_command_register("tnl/egress_port_range", "min max", 0, 2,
                                 netdev_vport_range, NULL);

        ovsthread_once_done(&once);
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
                                       NULL, NULL, NULL, NULL) }};
    netdev_register_provider(&patch_class.netdev_class);
}
