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

#include "dummy.h"

#include <errno.h>

#include "flow.h"
#include "list.h"
#include "netdev-provider.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "sset.h"
#include "unixctl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_dummy);

struct netdev_dev_dummy {
    struct netdev_dev netdev_dev;
    uint8_t hwaddr[ETH_ADDR_LEN];
    int mtu;
    struct netdev_stats stats;
    enum netdev_flags flags;
    unsigned int change_seq;

    struct list devs;           /* List of child "netdev_dummy"s. */
};

struct netdev_dummy {
    struct netdev netdev;
    struct list node;           /* In netdev_dev_dummy's "devs" list. */
    struct list recv_queue;
    bool listening;
};

static struct shash dummy_netdev_devs = SHASH_INITIALIZER(&dummy_netdev_devs);

static unixctl_cb_func netdev_dummy_set_admin_state;
static int netdev_dummy_create(const struct netdev_class *, const char *,
                               struct netdev_dev **);
static void netdev_dev_dummy_poll_notify(struct netdev_dev_dummy *);
static int netdev_dev_dummy_update_flags(struct netdev_dev_dummy *,
                                         enum netdev_flags off,
                                         enum netdev_flags on,
                                         enum netdev_flags *old_flagsp);

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
                    struct netdev_dev **netdev_devp)
{
    static unsigned int n = 0xaa550000;
    struct netdev_dev_dummy *netdev_dev;

    netdev_dev = xzalloc(sizeof *netdev_dev);
    netdev_dev_init(&netdev_dev->netdev_dev, name, class);
    netdev_dev->hwaddr[0] = 0xaa;
    netdev_dev->hwaddr[1] = 0x55;
    netdev_dev->hwaddr[2] = n >> 24;
    netdev_dev->hwaddr[3] = n >> 16;
    netdev_dev->hwaddr[4] = n >> 8;
    netdev_dev->hwaddr[5] = n;
    netdev_dev->mtu = 1500;
    netdev_dev->flags = 0;
    netdev_dev->change_seq = 1;
    list_init(&netdev_dev->devs);

    shash_add(&dummy_netdev_devs, name, netdev_dev);

    n++;

    *netdev_devp = &netdev_dev->netdev_dev;

    return 0;
}

static void
netdev_dummy_destroy(struct netdev_dev *netdev_dev_)
{
    struct netdev_dev_dummy *netdev_dev = netdev_dev_dummy_cast(netdev_dev_);

    shash_find_and_delete(&dummy_netdev_devs,
                          netdev_dev_get_name(netdev_dev_));
    free(netdev_dev);
}

static int
netdev_dummy_open(struct netdev_dev *netdev_dev_, struct netdev **netdevp)
{
    struct netdev_dev_dummy *netdev_dev = netdev_dev_dummy_cast(netdev_dev_);
    struct netdev_dummy *netdev;

    netdev = xmalloc(sizeof *netdev);
    netdev_init(&netdev->netdev, netdev_dev_);
    list_init(&netdev->recv_queue);
    netdev->listening = false;

    *netdevp = &netdev->netdev;
    list_push_back(&netdev_dev->devs, &netdev->node);
    return 0;
}

static void
netdev_dummy_close(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    list_remove(&netdev->node);
    ofpbuf_list_delete(&netdev->recv_queue);
    free(netdev);
}

static int
netdev_dummy_listen(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    netdev->listening = true;
    return 0;
}

static int
netdev_dummy_recv(struct netdev *netdev_, void *buffer, size_t size)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    struct ofpbuf *packet;
    size_t packet_size;

    if (list_is_empty(&netdev->recv_queue)) {
        return -EAGAIN;
    }

    packet = ofpbuf_from_list(list_pop_front(&netdev->recv_queue));
    if (packet->size > size) {
        return -EMSGSIZE;
    }
    packet_size = packet->size;

    memcpy(buffer, packet->data, packet->size);
    ofpbuf_delete(packet);

    return packet_size;
}

static void
netdev_dummy_recv_wait(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    if (!list_is_empty(&netdev->recv_queue)) {
        poll_immediate_wake();
    }
}

static int
netdev_dummy_drain(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    ofpbuf_list_delete(&netdev->recv_queue);
    return 0;
}

static int
netdev_dummy_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    if (!eth_addr_equals(dev->hwaddr, mac)) {
        memcpy(dev->hwaddr, mac, ETH_ADDR_LEN);
        netdev_dev_dummy_poll_notify(dev);
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
netdev_dummy_set_mtu(const struct netdev *netdev, int mtu)
{
    struct netdev_dev_dummy *dev =
        netdev_dev_dummy_cast(netdev_get_dev(netdev));

    dev->mtu = mtu;
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

    return netdev_dev_dummy_update_flags(dev, off, on, old_flagsp);
}

static int
netdev_dev_dummy_update_flags(struct netdev_dev_dummy *dev,
                              enum netdev_flags off, enum netdev_flags on,
                              enum netdev_flags *old_flagsp)
{
    if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }

    *old_flagsp = dev->flags;
    dev->flags |= on;
    dev->flags &= ~off;
    if (*old_flagsp != dev->flags) {
        netdev_dev_dummy_poll_notify(dev);
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
netdev_dev_dummy_poll_notify(struct netdev_dev_dummy *dev)
{
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
    NULL,                       /* get_config */
    NULL,                       /* set_config */

    netdev_dummy_open,
    netdev_dummy_close,

    netdev_dummy_listen,
    netdev_dummy_recv,
    netdev_dummy_recv_wait,
    netdev_dummy_drain,

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_dummy_set_etheraddr,
    netdev_dummy_get_etheraddr,
    netdev_dummy_get_mtu,
    netdev_dummy_set_mtu,
    NULL,                       /* get_ifindex */
    NULL,                       /* get_carrier */
    NULL,                       /* get_carrier_resets */
    NULL,                       /* get_miimon */
    netdev_dummy_get_stats,
    netdev_dummy_set_stats,

    NULL,                       /* get_features */
    NULL,                       /* set_advertisements */

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
    NULL,                       /* get_drv_info */
    NULL,                       /* arp_lookup */

    netdev_dummy_update_flags,

    netdev_dummy_change_seq
};

static struct ofpbuf *
eth_from_packet_or_flow(const char *s)
{
    enum odp_key_fitness fitness;
    struct ofpbuf *packet;
    struct ofpbuf odp_key;
    struct flow flow;
    int error;

    if (!eth_from_hex(s, &packet)) {
        return packet;
    }

    /* Convert string to datapath key.
     *
     * It would actually be nicer to parse an OpenFlow-like flow key here, but
     * the code for that currently calls exit() on parse error.  We have to
     * settle for parsing a datapath key for now.
     */
    ofpbuf_init(&odp_key, 0);
    error = odp_flow_key_from_string(s, NULL, &odp_key);
    if (error) {
        ofpbuf_uninit(&odp_key);
        return NULL;
    }

    /* Convert odp_key to flow. */
    fitness = odp_flow_key_to_flow(odp_key.data, odp_key.size, &flow);
    if (fitness == ODP_FIT_ERROR) {
        ofpbuf_uninit(&odp_key);
        return NULL;
    }

    packet = ofpbuf_new(0);
    flow_compose(packet, &flow);

    ofpbuf_uninit(&odp_key);
    return packet;
}

static void
netdev_dummy_receive(struct unixctl_conn *conn,
                     int argc, const char *argv[], void *aux OVS_UNUSED)
{
    struct netdev_dev_dummy *dummy_dev;
    int n_listeners;
    int i;

    dummy_dev = shash_find_data(&dummy_netdev_devs, argv[1]);
    if (!dummy_dev) {
        unixctl_command_reply_error(conn, "no such dummy netdev");
        return;
    }

    n_listeners = 0;
    for (i = 2; i < argc; i++) {
        struct netdev_dummy *dev;
        struct ofpbuf *packet;

        packet = eth_from_packet_or_flow(argv[i]);
        if (!packet) {
            unixctl_command_reply_error(conn, "bad packet syntax");
            return;
        }

        n_listeners = 0;
        LIST_FOR_EACH (dev, node, &dummy_dev->devs) {
            if (dev->listening) {
                struct ofpbuf *copy = ofpbuf_clone(packet);
                list_push_back(&dev->recv_queue, &copy->list_node);
                n_listeners++;
            }
        }
        ofpbuf_delete(packet);
    }

    if (!n_listeners) {
        unixctl_command_reply(conn, "packets queued but nobody listened");
    } else {
        unixctl_command_reply(conn, "success");
    }
}

static void
netdev_dev_dummy_set_admin_state(struct netdev_dev_dummy *dev,
                                 bool admin_state)
{
    enum netdev_flags old_flags;

    if (admin_state) {
        netdev_dev_dummy_update_flags(dev, 0, NETDEV_UP, &old_flags);
    } else {
        netdev_dev_dummy_update_flags(dev, NETDEV_UP, 0, &old_flags);
    }
}

static void
netdev_dummy_set_admin_state(struct unixctl_conn *conn, int argc,
                             const char *argv[], void *aux OVS_UNUSED)
{
    bool up;

    if (!strcasecmp(argv[argc - 1], "up")) {
        up = true;
    } else if ( !strcasecmp(argv[argc - 1], "down")) {
        up = false;
    } else {
        unixctl_command_reply_error(conn, "Invalid Admin State");
        return;
    }

    if (argc > 2) {
        struct netdev_dev_dummy *dummy_dev;

        dummy_dev  = shash_find_data(&dummy_netdev_devs, argv[1]);
        if (dummy_dev) {
            netdev_dev_dummy_set_admin_state(dummy_dev, up);
        } else {
            unixctl_command_reply_error(conn, "Unknown Dummy Interface");
            return;
        }
    } else {
        struct shash_node *node;

        SHASH_FOR_EACH (node, &dummy_netdev_devs) {
            netdev_dev_dummy_set_admin_state(node->data, up);
        }
    }
    unixctl_command_reply(conn, "OK");
}

void
netdev_dummy_register(bool override)
{
    unixctl_command_register("netdev-dummy/receive", "NAME PACKET|FLOW...",
                             2, INT_MAX, netdev_dummy_receive, NULL);
    unixctl_command_register("netdev-dummy/set-admin-state",
                             "[netdev] up|down", 1, 2,
                             netdev_dummy_set_admin_state, NULL);

    if (override) {
        struct sset types;
        const char *type;

        sset_init(&types);
        netdev_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            if (!netdev_unregister_provider(type)) {
                struct netdev_class *class;

                class = xmalloc(sizeof *class);
                *class = dummy_class;
                class->type = xstrdup(type);
                netdev_register_provider(class);
            }
        }
        sset_destroy(&types);
    }
    netdev_register_provider(&dummy_class);
}
