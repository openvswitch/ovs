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

#include "netdev-provider.h"
#include "netdev-vport.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "openvswitch/tunnel.h"
#include "packets.h"
#include "socket-util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_tunnel)

struct netdev_dev_tunnel {
    struct netdev_dev netdev_dev;
};

struct netdev_tunnel {
    struct netdev netdev;
};

static int netdev_tunnel_create(const char *name, const char *type,
                                const struct shash *args, struct netdev_dev **);

static struct netdev_dev_tunnel *
netdev_dev_tunnel_cast(const struct netdev_dev *netdev_dev)
{
    assert(netdev_dev_get_class(netdev_dev)->create == netdev_tunnel_create);
    return CONTAINER_OF(netdev_dev, struct netdev_dev_tunnel, netdev_dev);
}

static struct netdev_tunnel *
netdev_tunnel_cast(const struct netdev *netdev)
{
    struct netdev_dev *netdev_dev = netdev_get_dev(netdev);
    assert(netdev_dev_get_class(netdev_dev)->create == netdev_tunnel_create);
    return CONTAINER_OF(netdev, struct netdev_tunnel, netdev);
}

static int
parse_config(const char *name, const char *type, const struct shash *args,
             struct tnl_port_config *config)
{
    struct shash_node *node;

    memset(config, 0, sizeof *config);

    config->flags |= TNL_F_PMTUD;

    SHASH_FOR_EACH (node, args) {
        if (!strcmp(node->name, "remote_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->data, &in_addr)) {
                VLOG_WARN("%s: bad %s 'remote_ip'", name, type);
            } else {
                config->daddr = in_addr.s_addr;
            }
        } else if (!strcmp(node->name, "local_ip")) {
            struct in_addr in_addr;
            if (lookup_ip(node->data, &in_addr)) {
                VLOG_WARN("%s: bad %s 'local_ip'", name, type);
            } else {
                config->saddr = in_addr.s_addr;
            }
        } else if (!strcmp(node->name, "key") && !strcmp(type, "gre")) {
            if (!strcmp(node->data, "flow")) {
                config->flags |= TNL_F_IN_KEY_MATCH;
                config->flags |= TNL_F_OUT_KEY_ACTION;
            } else {
                config->out_key = config->in_key = htonl(atoi(node->data));
            }
        } else if (!strcmp(node->name, "in_key") && !strcmp(type, "gre")) {
            if (!strcmp(node->data, "flow")) {
                config->flags |= TNL_F_IN_KEY_MATCH;
            } else {
                config->in_key = htonl(atoi(node->data));
            }
        } else if (!strcmp(node->name, "out_key") && !strcmp(type, "gre")) {
            if (!strcmp(node->data, "flow")) {
                config->flags |= TNL_F_OUT_KEY_ACTION;
            } else {
                config->out_key = htonl(atoi(node->data));
            }
        } else if (!strcmp(node->name, "tos")) {
            if (!strcmp(node->data, "inherit")) {
                config->flags |= TNL_F_TOS_INHERIT;
            } else {
                config->tos = atoi(node->data);
            }
        } else if (!strcmp(node->name, "ttl")) {
            if (!strcmp(node->data, "inherit")) {
                config->flags |= TNL_F_TTL_INHERIT;
            } else {
                config->ttl = atoi(node->data);
            }
        } else if (!strcmp(node->name, "csum") && !strcmp(type, "gre")) {
            if (!strcmp(node->data, "true")) {
                config->flags |= TNL_F_CSUM;
            }
        } else if (!strcmp(node->name, "pmtud")) {
            if (!strcmp(node->data, "false")) {
                config->flags &= ~TNL_F_PMTUD;
            }
        } else {
            VLOG_WARN("%s: unknown %s argument '%s'", name, type, node->name);
        }
    }

    if (!config->daddr) {
        VLOG_WARN("%s: %s type requires valid 'remote_ip' argument", name, type);
        return EINVAL;
    }

    return 0;
}

static int
netdev_tunnel_create(const char *name, const char *type,
                     const struct shash *args, struct netdev_dev **netdev_devp)
{
    int err;
    struct odp_vport_add ova;
    struct tnl_port_config port_config;
    struct netdev_dev_tunnel *netdev_dev;

    ovs_strlcpy(ova.port_type, type, sizeof ova.port_type);
    ovs_strlcpy(ova.devname, name, sizeof ova.devname);
    ova.config = &port_config;

    err = parse_config(name, type, args, &port_config);
    if (err) {
        return err;
    }

    err = netdev_vport_do_ioctl(ODP_VPORT_ADD, &ova);
    if (err == EBUSY) {
        VLOG_WARN("%s: destroying existing device", name);

        err = netdev_vport_do_ioctl(ODP_VPORT_DEL, ova.devname);
        if (err) {
            return err;
        }

        err = netdev_vport_do_ioctl(ODP_VPORT_ADD, &ova);
    }

    if (err) {
        return err;
    }

    netdev_dev = xmalloc(sizeof *netdev_dev);

    if (!strcmp(type, "gre")) {
        netdev_dev_init(&netdev_dev->netdev_dev, name, &netdev_gre_class);
    } else {
        netdev_dev_init(&netdev_dev->netdev_dev, name, &netdev_capwap_class);
    }

    *netdev_devp = &netdev_dev->netdev_dev;
    return 0;
}

static int
netdev_tunnel_reconfigure(struct netdev_dev *netdev_dev_, const struct shash *args)
{
    const char *name = netdev_dev_get_name(netdev_dev_);
    struct odp_vport_mod ovm;
    struct tnl_port_config port_config;
    int err;

    ovs_strlcpy(ovm.devname, name, sizeof ovm.devname);
    ovm.config = &port_config;

    err = parse_config(name, netdev_dev_get_class(netdev_dev_)->type, args,
                       &port_config);
    if (err) {
        return err;
    }

    return netdev_vport_do_ioctl(ODP_VPORT_MOD, &ovm);
}

static void
netdev_tunnel_destroy(struct netdev_dev *netdev_dev_)
{
    struct netdev_dev_tunnel *netdev_dev = netdev_dev_tunnel_cast(netdev_dev_);

    netdev_vport_do_ioctl(ODP_VPORT_DEL, (char *)netdev_dev_get_name(netdev_dev_));
    free(netdev_dev);
}

static int
netdev_tunnel_open(struct netdev_dev *netdev_dev_, int ethertype OVS_UNUSED,
                struct netdev **netdevp)
{
    struct netdev_tunnel *netdev;

    netdev = xmalloc(sizeof *netdev);
    netdev_init(&netdev->netdev, netdev_dev_);

    *netdevp = &netdev->netdev;
    return 0;
}

static void
netdev_tunnel_close(struct netdev *netdev_)
{
    struct netdev_tunnel *netdev = netdev_tunnel_cast(netdev_);
    free(netdev);
}

const struct netdev_class netdev_gre_class = {
    "gre",

    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_tunnel_create,
    netdev_tunnel_destroy,
    netdev_tunnel_reconfigure,

    netdev_tunnel_open,
    netdev_tunnel_close,

    NULL,                       /* enumerate */

    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* drain */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_vport_set_etheraddr,
    netdev_vport_get_etheraddr,
    netdev_vport_get_mtu,
    NULL,                       /* get_ifindex */
    netdev_vport_get_carrier,
    netdev_vport_get_stats,
    netdev_vport_set_stats,

    NULL,                       /* get_features */
    NULL,                       /* set_advertisements */
    NULL,                       /* get_vlan_vid */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* dump_queues */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* arp_lookup */

    netdev_vport_update_flags,

    netdev_vport_poll_add,
    netdev_vport_poll_remove,
};

const struct netdev_class netdev_capwap_class = {
    "capwap",

    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_tunnel_create,
    netdev_tunnel_destroy,
    netdev_tunnel_reconfigure,

    netdev_tunnel_open,
    netdev_tunnel_close,

    NULL,                       /* enumerate */

    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* drain */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_vport_set_etheraddr,
    netdev_vport_get_etheraddr,
    netdev_vport_get_mtu,
    NULL,                       /* get_ifindex */
    netdev_vport_get_carrier,
    netdev_vport_get_stats,
    netdev_vport_set_stats,

    NULL,                       /* get_features */
    NULL,                       /* set_advertisements */
    NULL,                       /* get_vlan_vid */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* dump_queues */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* arp_lookup */

    netdev_vport_update_flags,

    netdev_vport_poll_add,
    netdev_vport_poll_remove,
};
