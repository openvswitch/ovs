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
#include <net/if.h>
#include <sys/ioctl.h>

#include "netdev-provider.h"
#include "netdev-vport.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "packets.h"
#include "socket-util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_patch)

struct netdev_dev_patch {
    struct netdev_dev netdev_dev;
};

struct netdev_patch {
    struct netdev netdev;
};

static struct netdev_dev_patch *
netdev_dev_patch_cast(const struct netdev_dev *netdev_dev)
{
    netdev_dev_assert_class(netdev_dev, &netdev_patch_class);
    return CONTAINER_OF(netdev_dev, struct netdev_dev_patch, netdev_dev);
}

static struct netdev_patch *
netdev_patch_cast(const struct netdev *netdev)
{
    netdev_assert_class(netdev, &netdev_patch_class);
    return CONTAINER_OF(netdev, struct netdev_patch, netdev);
}

static int
parse_config(const char *name, const struct shash *args,
             const char **peerp)
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

    if (strlen(peer) >= IFNAMSIZ) {
        VLOG_WARN("%s: patch 'peer' arg too long", name);
        return EINVAL;
    }

    if (!strcmp(name, peer)) {
        VLOG_WARN("%s: patch peer must not be self", name);
        return EINVAL;
    }

    *peerp = peer;

    return 0;
}

static int
netdev_patch_create(const char *name, const char *type OVS_UNUSED,
                  const struct shash *args, struct netdev_dev **netdev_devp)
{
    int err;
    struct odp_vport_add ova;
    const char *peer;
    struct netdev_dev_patch *netdev_dev;

    err = parse_config(name, args, &peer);
    if (err) {
        return err;
    }

    ovs_strlcpy(ova.port_type, "patch", sizeof ova.port_type);
    ovs_strlcpy(ova.devname, name, sizeof ova.devname);
    ova.config = (char *)peer;

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
    netdev_dev_init(&netdev_dev->netdev_dev, name, &netdev_patch_class);

    *netdev_devp = &netdev_dev->netdev_dev;
    return 0;
}

static int
netdev_patch_reconfigure(struct netdev_dev *netdev_dev_, const struct shash *args)
{
    const char *name = netdev_dev_get_name(netdev_dev_);
    struct odp_vport_mod ovm;
    const char *peer;
    int err;

    err = parse_config(name, args, &peer);
    if (err) {
        return err;
    }

    ovs_strlcpy(ovm.devname, name, sizeof ovm.devname);
    ovm.config = (char *)peer;

    return netdev_vport_do_ioctl(ODP_VPORT_MOD, &ovm);
}

static void
netdev_patch_destroy(struct netdev_dev *netdev_dev_)
{
    struct netdev_dev_patch *netdev_dev = netdev_dev_patch_cast(netdev_dev_);

    netdev_vport_do_ioctl(ODP_VPORT_DEL, (char *)netdev_dev_get_name(netdev_dev_));
    free(netdev_dev);
}

static int
netdev_patch_open(struct netdev_dev *netdev_dev_, int ethertype OVS_UNUSED,
                struct netdev **netdevp)
{
    struct netdev_patch *netdev;

    netdev = xmalloc(sizeof *netdev);
    netdev_init(&netdev->netdev, netdev_dev_);

    *netdevp = &netdev->netdev;
    return 0;
}

static void
netdev_patch_close(struct netdev *netdev_)
{
    struct netdev_patch *netdev = netdev_patch_cast(netdev_);
    free(netdev);
}

const struct netdev_class netdev_patch_class = {
    "patch",

    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_patch_create,
    netdev_patch_destroy,
    netdev_patch_reconfigure,

    netdev_patch_open,
    netdev_patch_close,

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
