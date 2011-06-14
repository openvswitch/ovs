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

#include "dummy.h"

#include <errno.h>

#include "list.h"
#include "netdev-provider.h"
#include "packets.h"
#include "shash.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_dummy);

struct netdev_dev_dummy {
    struct netdev_dev netdev_dev;
    uint8_t hwaddr[ETH_ADDR_LEN];
    int mtu;
    struct netdev_stats stats;
    enum netdev_flags flags;
    unsigned int change_seq;
};

struct netdev_dummy {
    struct netdev netdev;
};

static int netdev_dummy_create(const struct netdev_class *, const char *,
                               const struct shash *, struct netdev_dev **);
static void netdev_dummy_poll_notify(const struct netdev *);

static bool
is_dummy_class(const struct netdev_class *class)
{
    return class->create == netdev_dummy_create;
}

static struct netdev_dev_dummy *
netdev_dev_dummy_cast(const struct netdev_dev *netdev_dev)
{
    assert(is_dummy_class(netdev_dev_get_class(netdev_dev)));
    return CONTAINER_OF(netdev_dev, struct netdev_dev_dummy, netdev_dev);
}

static struct netdev_dummy *
netdev_dummy_cast(const struct netdev *netdev)
{
    struct netdev_dev *netdev_dev = netdev_get_dev(netdev);
    assert(is_dummy_class(netdev_dev_get_class(netdev_dev)));
    return CONTAINER_OF(netdev, struct netdev_dummy, netdev);
}

static int
netdev_dummy_create(const struct netdev_class *class, const char *name,
                    const struct shash *args,
                    struct netdev_dev **netdev_devp)
{
    static unsigned int n = 0xaa550000;
    struct netdev_dev_dummy *netdev_dev;

    netdev_dev = xzalloc(sizeof *netdev_dev);
    netdev_dev_init(&netdev_dev->netdev_dev, name, args, class);
    netdev_dev->hwaddr[0] = 0xaa;
    netdev_dev->hwaddr[1] = 0x55;
    netdev_dev->hwaddr[2] = n >> 24;
    netdev_dev->hwaddr[3] = n >> 16;
    netdev_dev->hwaddr[4] = n >> 8;
    netdev_dev->hwaddr[5] = n;
    netdev_dev->mtu = 1500;
    netdev_dev->flags = 0;
    netdev_dev->change_seq = 1;

    n++;

    *netdev_devp = &netdev_dev->netdev_dev;

    return 0;
}

static void
netdev_dummy_destroy(struct netdev_dev *netdev_dev_)
{
    struct netdev_dev_dummy *netdev_dev = netdev_dev_dummy_cast(netdev_dev_);

    free(netdev_dev);
}

static int
netdev_dummy_open(struct netdev_dev *netdev_dev_, int ethertype OVS_UNUSED,
                  struct netdev **netdevp)
{
    struct netdev_dummy *netdev;

    netdev = xmalloc(sizeof *netdev);
    netdev_init(&netdev->netdev, netdev_dev_);

    *netdevp = &netdev->netdev;
    return 0;
}

static void
netdev_dummy_close(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    free(netdev);
}

static int
netdev_dummy_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    if (!eth_addr_equals(dev->hwaddr, mac)) {
        memcpy(dev->hwaddr, mac, ETH_ADDR_LEN);
        netdev_dummy_poll_notify(netdev);
    }

    return 0;
}

static int
netdev_dummy_get_etheraddr(const struct netdev *netdev,
                           uint8_t mac[ETH_ADDR_LEN])
{
    const struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    memcpy(mac, dev->hwaddr, ETH_ADDR_LEN);
    return 0;
}

static int
netdev_dummy_get_mtu(const struct netdev *netdev, int *mtup)
{
    const struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    *mtup = dev->mtu;
    return 0;
}

static int
netdev_dummy_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    const struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    *stats = dev->stats;
    return 0;
}

static int
netdev_dummy_set_stats(struct netdev *netdev, const struct netdev_stats *stats)
{
    struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    dev->stats = *stats;
    return 0;
}

static int
netdev_dummy_update_flags(struct netdev *netdev,
                          enum netdev_flags off, enum netdev_flags on,
                          enum netdev_flags *old_flagsp)
{
    struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }

    *old_flagsp = dev->flags;
    dev->flags |= on;
    dev->flags &= ~off;
    if (*old_flagsp != dev->flags) {
        netdev_dummy_poll_notify(netdev);
    }
    return 0;
}

static unsigned int
netdev_dummy_change_seq(const struct netdev *netdev)
{
    return netdev_dev_dummy_cast(netdev_get_dev(netdev))->change_seq;
}

/* Helper functions. */

static void
netdev_dummy_poll_notify(const struct netdev *netdev)
{
    struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    dev->change_seq++;
    if (!dev->change_seq) {
        dev->change_seq++;
    }
}

static const struct netdev_class dummy_class = {
    "dummy",
    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_dummy_create,
    netdev_dummy_destroy,
    NULL,                       /* set_config */
    NULL,                       /* config_equal */

    netdev_dummy_open,
    netdev_dummy_close,

    NULL,                       /* enumerate */

    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* drain */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_dummy_set_etheraddr,
    netdev_dummy_get_etheraddr,
    netdev_dummy_get_mtu,
    NULL,                       /* get_ifindex */
    NULL,                       /* get_carrier */
    NULL,                       /* get_miimon */
    netdev_dummy_get_stats,
    netdev_dummy_set_stats,

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
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_dummy_update_flags,

    netdev_dummy_change_seq
};

void
netdev_dummy_register(void)
{
    netdev_register_provider(&dummy_class);
}
