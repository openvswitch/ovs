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
#include "openvswitch/gre.h"
#include "openvswitch/xflow.h"
#include "packets.h"
#include "socket-util.h"

#define THIS_MODULE VLM_netdev_gre
#include "vlog.h"

struct netdev_dev_gre {
    struct netdev_dev netdev_dev;
};

struct netdev_gre {
    struct netdev netdev;
};

static struct netdev_dev_gre *
netdev_dev_gre_cast(const struct netdev_dev *netdev_dev)
{
    netdev_dev_assert_class(netdev_dev, &netdev_gre_class);
    return CONTAINER_OF(netdev_dev, struct netdev_dev_gre, netdev_dev);
}

static struct netdev_gre *
netdev_gre_cast(const struct netdev *netdev)
{
    netdev_assert_class(netdev, &netdev_gre_class);
    return CONTAINER_OF(netdev, struct netdev_gre, netdev);
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
    struct xflow_vport_add ova;
    struct gre_port_config port_config;
    struct netdev_dev_gre *netdev_dev;

    ovs_strlcpy(ova.port_type, "gre", sizeof ova.port_type);
    ovs_strlcpy(ova.devname, name, sizeof ova.devname);
    ova.config = &port_config;

    err = parse_config(name, args, &port_config);
    if (err) {
        return err;
    }

    err = netdev_vport_do_ioctl(XFLOW_VPORT_ADD, &ova);
    if (err == EEXIST) {
        VLOG_WARN("%s: destroying existing device", name);

        err = netdev_vport_do_ioctl(XFLOW_VPORT_DEL, ova.devname);
        if (err) {
            return err;
        }

        err = netdev_vport_do_ioctl(XFLOW_VPORT_ADD, &ova);
    }

    if (err) {
        return err;
    }

    netdev_dev = xmalloc(sizeof *netdev_dev);
    netdev_dev_init(&netdev_dev->netdev_dev, name, &netdev_gre_class);

    *netdev_devp = &netdev_dev->netdev_dev;
    return 0;
}

static int
netdev_gre_reconfigure(struct netdev_dev *netdev_dev_, const struct shash *args)
{
    const char *name = netdev_dev_get_name(netdev_dev_);
    struct xflow_vport_mod ovm;
    struct gre_port_config port_config;
    int err;

    ovs_strlcpy(ovm.devname, name, sizeof ovm.devname);
    ovm.config = &port_config;

    err = parse_config(name, args, &port_config);
    if (err) {
        return err;
    }

    return netdev_vport_do_ioctl(XFLOW_VPORT_MOD, &ovm);
}

static void
netdev_gre_destroy(struct netdev_dev *netdev_dev_)
{
    struct netdev_dev_gre *netdev_dev = netdev_dev_gre_cast(netdev_dev_);

    netdev_vport_do_ioctl(XFLOW_VPORT_DEL, (char *)netdev_dev_get_name(netdev_dev_));
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

const struct netdev_class netdev_gre_class = {
    "gre",

    NULL,                       /* init */
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

    netdev_vport_set_etheraddr,
    netdev_vport_get_etheraddr,
    netdev_vport_get_mtu,
    NULL,                       /* get_ifindex */
    netdev_vport_get_carrier,
    netdev_vport_get_stats,
    NULL,                       /* set_stats */

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

    netdev_vport_update_flags,

    netdev_vport_poll_add,
    netdev_vport_poll_remove,
};
