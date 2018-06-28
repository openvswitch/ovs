/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2017 Nicira, Inc.
 * Copyright (c) 2016 Red Hat, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>

#include "byte-order.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif.h"
#include "netdev.h"
#include "netdev-native-tnl.h"
#include "netdev-provider.h"
#include "netdev-vport-private.h"
#include "openvswitch/dynamic-string.h"
#include "ovs-router.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "route-table.h"
#include "smap.h"
#include "socket-util.h"
#include "unaligned.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "netdev-tc-offloads.h"
#ifdef __linux__
#include "netdev-linux.h"
#endif

VLOG_DEFINE_THIS_MODULE(netdev_vport);

#define GENEVE_DST_PORT 6081
#define VXLAN_DST_PORT 4789
#define LISP_DST_PORT 4341
#define STT_DST_PORT 7471

#define DEFAULT_TTL 64

/* Last read of the route-table's change number. */
static uint64_t rt_change_seqno;

static int get_patch_config(const struct netdev *netdev, struct smap *args);
static int get_tunnel_config(const struct netdev *, struct smap *args);
static bool tunnel_check_status_change__(struct netdev_vport *);

struct vport_class {
    const char *dpif_port;
    struct netdev_class netdev_class;
};

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
        if (ipv6_addr_is_set(&netdev->tnl_cfg.ipv6_dst)) {
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

int
netdev_vport_construct(struct netdev *netdev_)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev_);
    const char *type = netdev_get_type(netdev_);

    ovs_mutex_init(&dev->mutex);
    eth_addr_random(&dev->etheraddr);

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
netdev_vport_set_etheraddr(struct netdev *netdev_, const struct eth_addr mac)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    netdev->etheraddr = mac;
    ovs_mutex_unlock(&netdev->mutex);
    netdev_change_seq_changed(netdev_);

    return 0;
}

static int
netdev_vport_get_etheraddr(const struct netdev *netdev_, struct eth_addr *mac)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *mac = netdev->etheraddr;
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
    struct in6_addr *route;
    struct in6_addr gw;
    uint32_t mark;

    iface[0] = '\0';
    route = &netdev->tnl_cfg.ipv6_dst;
    mark = netdev->tnl_cfg.egress_pkt_mark;
    if (ovs_router_lookup(mark, route, iface, NULL, &gw)) {
        struct netdev *egress_netdev;

        if (!netdev_open(iface, NULL, &egress_netdev)) {
            status = netdev_get_carrier(egress_netdev);
            netdev_close(egress_netdev);
        }
    }

    if (strcmp(netdev->egress_iface, iface)
        || netdev->carrier_status != status) {
        ovs_strlcpy_arrays(netdev->egress_iface, iface);
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
netdev_vport_run(const struct netdev_class *netdev_class OVS_UNUSED)
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
netdev_vport_wait(const struct netdev_class *netdev_class OVS_UNUSED)
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
parse_tunnel_ip(const char *value, bool accept_mcast, bool *flow,
                struct in6_addr *ipv6, uint16_t *protocol)
{
    if (!strcmp(value, "flow")) {
        *flow = true;
        *protocol = 0;
        return 0;
    }
    if (addr_is_ipv6(value)) {
        if (lookup_ipv6(value, ipv6)) {
            return ENOENT;
        }
        if (!accept_mcast && ipv6_addr_is_multicast(ipv6)) {
            return EINVAL;
        }
        *protocol = ETH_TYPE_IPV6;
    } else {
        struct in_addr ip;
        if (lookup_ip(value, &ip)) {
            return ENOENT;
        }
        if (!accept_mcast && ip_is_multicast(ip.s_addr)) {
            return EINVAL;
        }
        in6_addr_set_mapped_ipv4(ipv6, ip.s_addr);
        *protocol = ETH_TYPE_IP;
    }
    return 0;
}

enum tunnel_layers {
    TNL_L2 = 1 << 0,       /* 1 if a tunnel type can carry Ethernet traffic. */
    TNL_L3 = 1 << 1        /* 1 if a tunnel type can carry L3 traffic. */
};
static enum tunnel_layers
tunnel_supported_layers(const char *type,
                        const struct netdev_tunnel_config *tnl_cfg)
{
    if (!strcmp(type, "lisp")) {
        return TNL_L3;
    } else if (!strcmp(type, "gre")) {
        return TNL_L2 | TNL_L3;
    } else if (!strcmp(type, "vxlan")
               && tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GPE)) {
        return TNL_L2 | TNL_L3;
    } else {
        return TNL_L2;
    }
}
static enum netdev_pt_mode
default_pt_mode(enum tunnel_layers layers)
{
    return layers == TNL_L3 ? NETDEV_PT_LEGACY_L3 : NETDEV_PT_LEGACY_L2;
}

static int
set_tunnel_config(struct netdev *dev_, const struct smap *args, char **errp)
{
    struct netdev_vport *dev = netdev_vport_cast(dev_);
    const char *name = netdev_get_name(dev_);
    const char *type = netdev_get_type(dev_);
    struct ds errors = DS_EMPTY_INITIALIZER;
    bool needs_dst_port, has_csum, has_seq;
    uint16_t dst_proto = 0, src_proto = 0;
    struct netdev_tunnel_config tnl_cfg;
    struct smap_node *node;
    int err;

    has_csum = strstr(type, "gre") || strstr(type, "geneve") ||
               strstr(type, "stt") || strstr(type, "vxlan");
    has_seq = strstr(type, "gre");
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
    tnl_cfg.dont_fragment = true;

    SMAP_FOR_EACH (node, args) {
        if (!strcmp(node->key, "remote_ip")) {
            err = parse_tunnel_ip(node->value, false, &tnl_cfg.ip_dst_flow,
                                  &tnl_cfg.ipv6_dst, &dst_proto);
            switch (err) {
            case ENOENT:
                ds_put_format(&errors, "%s: bad %s 'remote_ip'\n", name, type);
                break;
            case EINVAL:
                ds_put_format(&errors,
                              "%s: multicast remote_ip=%s not allowed\n",
                              name, node->value);
                goto out;
            }
        } else if (!strcmp(node->key, "local_ip")) {
            err = parse_tunnel_ip(node->value, true, &tnl_cfg.ip_src_flow,
                                  &tnl_cfg.ipv6_src, &src_proto);
            switch (err) {
            case ENOENT:
                ds_put_format(&errors, "%s: bad %s 'local_ip'\n", name, type);
                break;
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
                    ds_put_format(&errors, "%s: invalid TOS %s\n", name,
                                  node->value);
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
        } else if (!strcmp(node->key, "seq") && has_seq) {
            if (!strcmp(node->value, "true")) {
                tnl_cfg.set_seq = true;
            }
        } else if (!strcmp(node->key, "df_default")) {
            if (!strcmp(node->value, "false")) {
                tnl_cfg.dont_fragment = false;
            }
        } else if (!strcmp(node->key, "key") ||
                   !strcmp(node->key, "in_key") ||
                   !strcmp(node->key, "out_key") ||
                   !strcmp(node->key, "packet_type")) {
            /* Handled separately below. */
        } else if (!strcmp(node->key, "exts") && !strcmp(type, "vxlan")) {
            char *str = xstrdup(node->value);
            char *ext, *save_ptr = NULL;

            tnl_cfg.exts = 0;

            ext = strtok_r(str, ",", &save_ptr);
            while (ext) {
                if (!strcmp(type, "vxlan") && !strcmp(ext, "gbp")) {
                    tnl_cfg.exts |= (1 << OVS_VXLAN_EXT_GBP);
                } else if (!strcmp(type, "vxlan") && !strcmp(ext, "gpe")) {
                    tnl_cfg.exts |= (1 << OVS_VXLAN_EXT_GPE);
                } else {
                    ds_put_format(&errors, "%s: unknown extension '%s'\n",
                                  name, ext);
                }

                ext = strtok_r(NULL, ",", &save_ptr);
            }

            free(str);
        } else if (!strcmp(node->key, "egress_pkt_mark")) {
            tnl_cfg.egress_pkt_mark = strtoul(node->value, NULL, 10);
            tnl_cfg.set_egress_pkt_mark = true;
        } else if (!strcmp(node->key, "erspan_idx")) {
            if (!strcmp(node->value, "flow")) {
                tnl_cfg.erspan_idx_flow = true;
            } else {
                tnl_cfg.erspan_idx_flow = false;
                tnl_cfg.erspan_idx = strtol(node->value, NULL, 16);

                if (tnl_cfg.erspan_idx & ~ERSPAN_IDX_MASK) {
                    ds_put_format(&errors, "%s: invalid erspan index: %s\n",
                                  name, node->value);
                    err = EINVAL;
                    goto out;
                }
            }
        } else if (!strcmp(node->key, "erspan_ver")) {
            if (!strcmp(node->value, "flow")) {
                tnl_cfg.erspan_ver_flow = true;
                tnl_cfg.erspan_idx_flow = true;
                tnl_cfg.erspan_dir_flow = true;
                tnl_cfg.erspan_hwid_flow = true;
            } else {
                tnl_cfg.erspan_ver_flow = false;
                tnl_cfg.erspan_ver = atoi(node->value);

                if (tnl_cfg.erspan_ver != 1 && tnl_cfg.erspan_ver != 2) {
                    ds_put_format(&errors, "%s: invalid erspan version: %s\n",
                                  name, node->value);
                    err = EINVAL;
                    goto out;
                }
            }
        } else if (!strcmp(node->key, "erspan_dir")) {
            if (!strcmp(node->value, "flow")) {
                tnl_cfg.erspan_dir_flow = true;
            } else {
                tnl_cfg.erspan_dir_flow = false;
                tnl_cfg.erspan_dir = atoi(node->value);

                if (tnl_cfg.erspan_dir != 0 && tnl_cfg.erspan_dir != 1) {
                    ds_put_format(&errors, "%s: invalid erspan direction: %s\n",
                                  name, node->value);
                    err = EINVAL;
                    goto out;
                }
            }
        } else if (!strcmp(node->key, "erspan_hwid")) {
            if (!strcmp(node->value, "flow")) {
                tnl_cfg.erspan_hwid_flow = true;
            } else {
                tnl_cfg.erspan_hwid_flow = false;
                tnl_cfg.erspan_hwid = strtol(node->value, NULL, 16);

                if (tnl_cfg.erspan_hwid & ~(ERSPAN_HWID_MASK >> 4)) {
                    ds_put_format(&errors, "%s: invalid erspan hardware ID: %s\n",
                                  name, node->value);
                    err = EINVAL;
                    goto out;
                }
            }
        } else {
            ds_put_format(&errors, "%s: unknown %s argument '%s'\n", name,
                          type, node->key);
        }
    }

    enum tunnel_layers layers = tunnel_supported_layers(type, &tnl_cfg);
    const char *full_type = (strcmp(type, "vxlan") ? type
                             : (tnl_cfg.exts & (1 << OVS_VXLAN_EXT_GPE)
                                ? "VXLAN-GPE" : "VXLAN (without GPE"));
    const char *packet_type = smap_get(args, "packet_type");
    if (!packet_type) {
        tnl_cfg.pt_mode = default_pt_mode(layers);
    } else if (!strcmp(packet_type, "legacy_l2")) {
        tnl_cfg.pt_mode = NETDEV_PT_LEGACY_L2;
        if (!(layers & TNL_L2)) {
            ds_put_format(&errors, "%s: legacy_l2 configured on %s tunnel "
                          "that cannot carry L2 traffic\n",
                          name, full_type);
            err = EINVAL;
            goto out;
        }
    } else if (!strcmp(packet_type, "legacy_l3")) {
        tnl_cfg.pt_mode = NETDEV_PT_LEGACY_L3;
        if (!(layers & TNL_L3)) {
            ds_put_format(&errors, "%s: legacy_l3 configured on %s tunnel "
                          "that cannot carry L3 traffic\n",
                          name, full_type);
            err = EINVAL;
            goto out;
        }
    } else if (!strcmp(packet_type, "ptap")) {
        tnl_cfg.pt_mode = NETDEV_PT_AWARE;
    } else {
        ds_put_format(&errors, "%s: unknown packet_type '%s'\n",
                      name, packet_type);
        err = EINVAL;
        goto out;
    }

    if (!ipv6_addr_is_set(&tnl_cfg.ipv6_dst) && !tnl_cfg.ip_dst_flow) {
        ds_put_format(&errors,
                      "%s: %s type requires valid 'remote_ip' argument\n",
                      name, type);
        err = EINVAL;
        goto out;
    }
    if (tnl_cfg.ip_src_flow && !tnl_cfg.ip_dst_flow) {
        ds_put_format(&errors,
                      "%s: %s type requires 'remote_ip=flow' "
                      "with 'local_ip=flow'\n",
                      name, type);
        err = EINVAL;
        goto out;
    }
    if (src_proto && dst_proto && src_proto != dst_proto) {
        ds_put_format(&errors,
                      "%s: 'remote_ip' and 'local_ip' "
                      "has to be of the same address family\n",
                      name);
        err = EINVAL;
        goto out;
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

    err = 0;

out:
    if (errors.length) {
        ds_chomp(&errors, '\n');
        VLOG_WARN("%s", ds_cstr(&errors));
        if (err) {
            *errp = ds_steal_cstr(&errors);
        }
    }

    ds_destroy(&errors);

    return err;
}

static int
get_tunnel_config(const struct netdev *dev, struct smap *args)
{
    struct netdev_vport *netdev = netdev_vport_cast(dev);
    const char *type = netdev_get_type(dev);
    struct netdev_tunnel_config tnl_cfg;

    ovs_mutex_lock(&netdev->mutex);
    tnl_cfg = netdev->tnl_cfg;
    ovs_mutex_unlock(&netdev->mutex);

    if (ipv6_addr_is_set(&tnl_cfg.ipv6_dst)) {
        smap_add_ipv6(args, "remote_ip", &tnl_cfg.ipv6_dst);
    } else if (tnl_cfg.ip_dst_flow) {
        smap_add(args, "remote_ip", "flow");
    }

    if (ipv6_addr_is_set(&tnl_cfg.ipv6_src)) {
        smap_add_ipv6(args, "local_ip", &tnl_cfg.ipv6_src);
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

    if (tnl_cfg.set_seq) {
        smap_add(args, "seq", "true");
    }

    enum tunnel_layers layers = tunnel_supported_layers(type, &tnl_cfg);
    if (tnl_cfg.pt_mode != default_pt_mode(layers)) {
        smap_add(args, "packet_type",
                 tnl_cfg.pt_mode == NETDEV_PT_LEGACY_L2 ? "legacy_l2"
                 : tnl_cfg.pt_mode == NETDEV_PT_LEGACY_L3 ? "legacy_l3"
                 : "ptap");
    }

    if (!tnl_cfg.dont_fragment) {
        smap_add(args, "df_default", "false");
    }

    if (tnl_cfg.set_egress_pkt_mark) {
        smap_add_format(args, "egress_pkt_mark",
                        "%"PRIu32, tnl_cfg.egress_pkt_mark);
    }

    if (!strcmp("erspan", type) || !strcmp("ip6erspan", type)) {
        if (tnl_cfg.erspan_ver_flow) {
            /* since version number is not determined,
             * assume print all other as flow
             */
            smap_add(args, "erspan_ver", "flow");
            smap_add(args, "erspan_idx", "flow");
            smap_add(args, "erspan_dir", "flow");
            smap_add(args, "erspan_hwid", "flow");
        } else {
            smap_add_format(args, "erspan_ver", "%d", tnl_cfg.erspan_ver);

            if (tnl_cfg.erspan_ver == 1) {
                if (tnl_cfg.erspan_idx_flow) {
                    smap_add(args, "erspan_idx", "flow");
                } else {
                    smap_add_format(args, "erspan_idx", "0x%x",
                                    tnl_cfg.erspan_idx);
                }
            } else if (tnl_cfg.erspan_ver == 2) {
                if (tnl_cfg.erspan_dir_flow) {
                    smap_add(args, "erspan_dir", "flow");
                } else {
                    smap_add_format(args, "erspan_dir", "%d",
                                    tnl_cfg.erspan_dir);
                }
                if (tnl_cfg.erspan_hwid_flow) {
                    smap_add(args, "erspan_hwid", "flow");
                } else {
                    smap_add_format(args, "erspan_hwid", "0x%x",
                                    tnl_cfg.erspan_hwid);
                }
            }
        }
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
set_patch_config(struct netdev *dev_, const struct smap *args, char **errp)
{
    struct netdev_vport *dev = netdev_vport_cast(dev_);
    const char *name = netdev_get_name(dev_);
    const char *peer;

    peer = smap_get(args, "peer");
    if (!peer) {
        VLOG_ERR_BUF(errp, "%s: patch type requires valid 'peer' argument",
                     name);
        return EINVAL;
    }

    if (smap_count(args) > 1) {
        VLOG_ERR_BUF(errp, "%s: patch type takes only a 'peer' argument",
                     name);
        return EINVAL;
    }

    if (!strcmp(name, peer)) {
        VLOG_ERR_BUF(errp, "%s: patch peer must not be self", name);
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
    /* Passing only collected counters */
    stats->tx_packets = dev->stats.tx_packets;
    stats->tx_bytes = dev->stats.tx_bytes;
    stats->rx_packets = dev->stats.rx_packets;
    stats->rx_bytes = dev->stats.rx_bytes;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static enum netdev_pt_mode
get_pt_mode(const struct netdev *netdev)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);

    return dev->tnl_cfg.pt_mode;
}



#ifdef __linux__
static int
netdev_vport_get_ifindex(const struct netdev *netdev_)
{
    char buf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *name = netdev_vport_get_dpif_port(netdev_, buf, sizeof(buf));

    return linux_get_ifindex(name);
}

#define NETDEV_VPORT_GET_IFINDEX netdev_vport_get_ifindex
#define NETDEV_FLOW_OFFLOAD_API LINUX_FLOW_OFFLOAD_API
#else /* !__linux__ */
#define NETDEV_VPORT_GET_IFINDEX NULL
#define NETDEV_FLOW_OFFLOAD_API NO_OFFLOAD_API
#endif /* __linux__ */

#define VPORT_FUNCTIONS(GET_CONFIG, SET_CONFIG,             \
                        GET_TUNNEL_CONFIG, GET_STATUS,      \
                        BUILD_HEADER,                       \
                        PUSH_HEADER, POP_HEADER,            \
                        GET_IFINDEX)                        \
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
    NULL,                       /* set_tx_multiq */         \
                                                            \
    NULL,                       /* send */                  \
    NULL,                       /* send_wait */             \
                                                            \
    netdev_vport_set_etheraddr,                             \
    netdev_vport_get_etheraddr,                             \
    NULL,                       /* get_mtu */               \
    NULL,                       /* set_mtu */               \
    GET_IFINDEX,                                            \
    NULL,                       /* get_carrier */           \
    NULL,                       /* get_carrier_resets */    \
    NULL,                       /* get_miimon */            \
    get_stats,                                              \
    NULL,                       /* get_custom_stats */      \
                                                            \
    NULL,                       /* get_features */          \
    NULL,                       /* set_advertisements */    \
    get_pt_mode,                                            \
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
    NULL,                       /* set_in4 */               \
    NULL,                       /* get_addr_list */         \
    NULL,                       /* add_router */            \
    NULL,                       /* get_next_hop */          \
    GET_STATUS,                                             \
    NULL,                       /* arp_lookup */            \
                                                            \
    netdev_vport_update_flags,                              \
    NULL,                       /* reconfigure */           \
                                                            \
    NULL,                   /* rx_alloc */                  \
    NULL,                   /* rx_construct */              \
    NULL,                   /* rx_destruct */               \
    NULL,                   /* rx_dealloc */                \
    NULL,                   /* rx_recv */                   \
    NULL,                   /* rx_wait */                   \
    NULL,                   /* rx_drain */                  \
                                                            \
    NETDEV_FLOW_OFFLOAD_API,                                 \
    NULL                    /* get_block_id */


#define TUNNEL_CLASS(NAME, DPIF_PORT, BUILD_HEADER, PUSH_HEADER, POP_HEADER,   \
                     GET_IFINDEX)                                              \
    { DPIF_PORT,                                                               \
        { NAME, false,                                                         \
          VPORT_FUNCTIONS(get_tunnel_config,                                   \
                          set_tunnel_config,                                   \
                          get_netdev_tunnel_config,                            \
                          tunnel_get_status,                                   \
                          BUILD_HEADER, PUSH_HEADER, POP_HEADER,               \
                          GET_IFINDEX) }}

void
netdev_vport_tunnel_register(void)
{
    /* The name of the dpif_port should be short enough to accomodate adding
     * a port number to the end if one is necessary. */
    static const struct vport_class vport_classes[] = {
        TUNNEL_CLASS("geneve", "genev_sys", netdev_geneve_build_header,
                                            netdev_tnl_push_udp_header,
                                            netdev_geneve_pop_header,
                                            NETDEV_VPORT_GET_IFINDEX),
        TUNNEL_CLASS("gre", "gre_sys", netdev_gre_build_header,
                                       netdev_gre_push_header,
                                       netdev_gre_pop_header,
                                       NULL),
        TUNNEL_CLASS("vxlan", "vxlan_sys", netdev_vxlan_build_header,
                                           netdev_tnl_push_udp_header,
                                           netdev_vxlan_pop_header,
                                           NETDEV_VPORT_GET_IFINDEX),
        TUNNEL_CLASS("lisp", "lisp_sys", NULL, NULL, NULL, NULL),
        TUNNEL_CLASS("stt", "stt_sys", NULL, NULL, NULL, NULL),
        TUNNEL_CLASS("erspan", "erspan_sys", netdev_erspan_build_header,
                                             netdev_erspan_push_header,
                                             netdev_erspan_pop_header,
                                             NULL),
        TUNNEL_CLASS("ip6erspan", "ip6erspan_sys", netdev_erspan_build_header,
                                                   netdev_erspan_push_header,
                                                   netdev_erspan_pop_header,
                                                   NULL),
        TUNNEL_CLASS("ip6gre", "ip6gre_sys", netdev_gre_build_header,
                                             netdev_gre_push_header,
                                             netdev_gre_pop_header,
                                             NULL),
    };
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        int i;

        for (i = 0; i < ARRAY_SIZE(vport_classes); i++) {
            netdev_register_provider(&vport_classes[i].netdev_class);
        }

        unixctl_command_register("tnl/egress_port_range", "min max", 0, 2,
                                 netdev_tnl_egress_port_range, NULL);

        ovsthread_once_done(&once);
    }
}

void
netdev_vport_patch_register(void)
{
    static const struct vport_class patch_class =
        { NULL,
            { "patch", false,
              VPORT_FUNCTIONS(get_patch_config,
                              set_patch_config,
                              NULL,
                              NULL, NULL, NULL, NULL, NULL) }};
    netdev_register_provider(&patch_class.netdev_class);
}
