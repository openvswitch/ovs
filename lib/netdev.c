/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "netdev.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "list.h"
#include "netdev-provider.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "svec.h"

#define THIS_MODULE VLM_netdev
#include "vlog.h"

static const struct netdev_class *netdev_classes[] = {
    &netdev_linux_class,
    &netdev_tap_class,
};
enum { N_NETDEV_CLASSES = ARRAY_SIZE(netdev_classes) };

/* All open network devices. */
static struct list netdev_list = LIST_INITIALIZER(&netdev_list);

/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static void restore_all_flags(void *aux);
static int restore_flags(struct netdev *netdev);

/* Attempts to initialize the netdev module.  Returns 0 if successful,
 * otherwise a positive errno value.
 *
 * Calling this function is optional.  If not called explicitly, it will
 * automatically be called upon the first attempt to open a network device. */
int
netdev_initialize(void)
{
    static int status = -1;
    if (status < 0) {
        int i;

        fatal_signal_add_hook(restore_all_flags, NULL, true);

        status = 0;
        for (i = 0; i < N_NETDEV_CLASSES; i++) {
            const struct netdev_class *class = netdev_classes[i];
            if (class->init) {
                int retval = class->init();
                if (retval) {
                    VLOG_ERR("failed to initialize %s network device "
                             "class: %s", class->name, strerror(retval));
                    if (!status) {
                        status = retval;
                    }
                }
            }
        }
    }
    return status;
}

/* Performs periodic work needed by all the various kinds of netdevs.
 *
 * If your program opens any netdevs, it must call this function within its
 * main poll loop. */
void
netdev_run(void)
{
    int i;
    for (i = 0; i < N_NETDEV_CLASSES; i++) {
        const struct netdev_class *class = netdev_classes[i];
        if (class->run) {
            class->run();
        }
    }
}

/* Arranges for poll_block() to wake up when netdev_run() needs to be called.
 *
 * If your program opens any netdevs, it must call this function within its
 * main poll loop. */
void
netdev_wait(void)
{
    int i;
    for (i = 0; i < N_NETDEV_CLASSES; i++) {
        const struct netdev_class *class = netdev_classes[i];
        if (class->wait) {
            class->wait();
        }
    }
}

/* Opens the network device named 'name' (e.g. "eth0") and returns zero if
 * successful, otherwise a positive errno value.  On success, sets '*netdevp'
 * to the new network device, otherwise to null.
 *
 * 'ethertype' may be a 16-bit Ethernet protocol value in host byte order to
 * capture frames of that type received on the device.  It may also be one of
 * the 'enum netdev_pseudo_ethertype' values to receive frames in one of those
 * categories. */
int
netdev_open(const char *name_, int ethertype, struct netdev **netdevp)
{
    char *name = xstrdup(name_);
    char *prefix, *suffix, *colon;
    struct netdev *netdev = NULL;
    int error;
    int i;

    error = netdev_initialize();
    if (error) {
        return error;
    }

    colon = strchr(name, ':');
    if (colon) {
        *colon = '\0';
        prefix = name;
        suffix = colon + 1;
    } else {
        prefix = "";
        suffix = name;
    }

    for (i = 0; i < N_NETDEV_CLASSES; i++) {
        const struct netdev_class *class = netdev_classes[i];
        if (!strcmp(prefix, class->prefix)) {
            error = class->open(name_, suffix, ethertype, &netdev);
            goto exit;
        }
    }
    error = EAFNOSUPPORT;

exit:
    *netdevp = error ? NULL : netdev;
    return error;
}

/* Closes and destroys 'netdev'. */
void
netdev_close(struct netdev *netdev)
{
    if (netdev) {
        char *name;
        int error;

        /* Restore flags that we changed, if any. */
        fatal_signal_block();
        error = restore_flags(netdev);
        list_remove(&netdev->node);
        fatal_signal_unblock();
        if (error) {
            VLOG_WARN("failed to restore network device flags on %s: %s",
                      netdev->name, strerror(error));
        }

        /* Free. */
        name = netdev->name;
        netdev->class->close(netdev);
        free(name);
    }
}

/* Returns true if a network device named 'name' exists and may be opened,
 * otherwise false. */
bool
netdev_exists(const char *name)
{
    struct netdev *netdev;
    int error;

    error = netdev_open(name, NETDEV_ETH_TYPE_NONE, &netdev);
    if (!error) {
        netdev_close(netdev);
        return true;
    } else {
        if (error != ENODEV) {
            VLOG_WARN("failed to open network device %s: %s",
                      name, strerror(error));
        }
        return false;
    }
}

/* Initializes 'svec' with a list of the names of all known network devices. */
int
netdev_enumerate(struct svec *svec)
{
    int error;
    int i;

    svec_init(svec);

    error = netdev_initialize();
    if (error) {
        return error;
    }

    error = 0;
    for (i = 0; i < N_NETDEV_CLASSES; i++) {
        const struct netdev_class *class = netdev_classes[i];
        if (class->enumerate) {
            int retval = class->enumerate(svec);
            if (retval) {
                VLOG_WARN("failed to enumerate %s network devices: %s",
                          class->name, strerror(retval));
                if (!error) {
                    error = retval;
                }
            }
        }
    }
    return error;
}

/* Attempts to receive a packet from 'netdev' into 'buffer', which the caller
 * must have initialized with sufficient room for the packet.  The space
 * required to receive any packet is ETH_HEADER_LEN bytes, plus VLAN_HEADER_LEN
 * bytes, plus the device's MTU (which may be retrieved via netdev_get_mtu()).
 * (Some devices do not allow for a VLAN header, in which case VLAN_HEADER_LEN
 * need not be included.)
 *
 * If a packet is successfully retrieved, returns 0.  In this case 'buffer' is
 * guaranteed to contain at least ETH_TOTAL_MIN bytes.  Otherwise, returns a
 * positive errno value.  Returns EAGAIN immediately if no packet is ready to
 * be returned.
 */
int
netdev_recv(struct netdev *netdev, struct ofpbuf *buffer)
{
    int retval;

    assert(buffer->size == 0);
    assert(ofpbuf_tailroom(buffer) >= ETH_TOTAL_MIN);

    retval = netdev->class->recv(netdev,
                                 buffer->data, ofpbuf_tailroom(buffer));
    if (retval >= 0) {
        COVERAGE_INC(netdev_received);
        buffer->size += retval;
        if (buffer->size < ETH_TOTAL_MIN) {
            ofpbuf_put_zeros(buffer, ETH_TOTAL_MIN - buffer->size);
        }
        return 0;
    } else {
        return -retval;
    }
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when a packet is ready to be received with netdev_recv() on 'netdev'. */
void
netdev_recv_wait(struct netdev *netdev)
{
    netdev->class->recv_wait(netdev);
}

/* Discards all packets waiting to be received from 'netdev'. */
int
netdev_drain(struct netdev *netdev)
{
    return netdev->class->drain(netdev);
}

/* Sends 'buffer' on 'netdev'.  Returns 0 if successful, otherwise a positive
 * errno value.  Returns EAGAIN without blocking if the packet cannot be queued
 * immediately.  Returns EMSGSIZE if a partial packet was transmitted or if
 * the packet is too big or too small to transmit on the device.
 *
 * The caller retains ownership of 'buffer' in all cases.
 *
 * The kernel maintains a packet transmission queue, so the caller is not
 * expected to do additional queuing of packets. */
int
netdev_send(struct netdev *netdev, const struct ofpbuf *buffer)
{
    int error = netdev->class->send(netdev, buffer->data, buffer->size);
    if (!error) {
        COVERAGE_INC(netdev_sent);
    }
    return error;
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send().
 *
 * The kernel maintains a packet transmission queue, so the client is not
 * expected to do additional queuing of packets.  Thus, this function is
 * unlikely to ever be used.  It is included for completeness. */
void
netdev_send_wait(struct netdev *netdev)
{
    return netdev->class->send_wait(netdev);
}

/* Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
netdev_set_etheraddr(struct netdev *netdev, const uint8_t mac[ETH_ADDR_LEN])
{
    return netdev->class->set_etheraddr(netdev, mac);
}

/* Retrieves 'netdev''s MAC address.  If successful, returns 0 and copies the
 * the MAC address into 'mac'.  On failure, returns a positive errno value and
 * clears 'mac' to all-zeros. */
int
netdev_get_etheraddr(const struct netdev *netdev, uint8_t mac[ETH_ADDR_LEN])
{
    return netdev->class->get_etheraddr(netdev, mac);
}

/* Returns the name of the network device that 'netdev' represents,
 * e.g. "eth0".  The caller must not modify or free the returned string. */
const char *
netdev_get_name(const struct netdev *netdev)
{
    return netdev->name;
}

/* Retrieves the MTU of 'netdev'.  The MTU is the maximum size of transmitted
 * (and received) packets, in bytes, not including the hardware header; thus,
 * this is typically 1500 bytes for Ethernet devices.
 *
 * If successful, returns 0 and stores the MTU size in '*mtup'.  On failure,
 * returns a positive errno value and stores ETH_PAYLOAD_MAX (1500) in
 * '*mtup'. */
int
netdev_get_mtu(const struct netdev *netdev, int *mtup)
{
    int error = netdev->class->get_mtu(netdev, mtup);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to retrieve MTU for network device %s: %s",
                     netdev_get_name(netdev), strerror(error));
        *mtup = ETH_PAYLOAD_MAX;
    }
    return error;
}

/* Stores the features supported by 'netdev' into each of '*current',
 * '*advertised', '*supported', and '*peer' that are non-null.  Each value is a
 * bitmap of "enum ofp_port_features" bits, in host byte order.  Returns 0 if
 * successful, otherwise a positive errno value.  On failure, all of the
 * passed-in values are set to 0. */
int
netdev_get_features(struct netdev *netdev,
                    uint32_t *current, uint32_t *advertised,
                    uint32_t *supported, uint32_t *peer)
{
    uint32_t dummy[4];
    return netdev->class->get_features(netdev,
                                       current ? current : &dummy[0],
                                       advertised ? advertised : &dummy[1],
                                       supported ? supported : &dummy[2],
                                       peer ? peer : &dummy[3]);
}

/* Set the features advertised by 'netdev' to 'advertise'.  Returns 0 if
 * successful, otherwise a positive errno value. */
int
netdev_set_advertisements(struct netdev *netdev, uint32_t advertise)
{
    return (netdev->class->set_advertisements
            ? netdev->class->set_advertisements(netdev, advertise)
            : EOPNOTSUPP);
}

/* If 'netdev' has an assigned IPv4 address, sets '*in4' to that address and
 * returns 0.  Otherwise, returns a positive errno value and sets '*in4' to 0
 * (INADDR_ANY).
 *
 * The following error values have well-defined meanings:
 *
 *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv4 address.
 *
 *   - EOPNOTSUPP: No IPv4 network stack attached to 'netdev'.
 *
 * 'in4' may be null, in which case the address itself is not reported. */
int
netdev_get_in4(const struct netdev *netdev, struct in_addr *in4)
{
    struct in_addr dummy;
    int error;

    error = (netdev->class->get_in4
             ? netdev->class->get_in4(netdev, in4 ? in4 : &dummy)
             : EOPNOTSUPP);
    if (error && in4) {
        in4->s_addr = 0;
    }
    return error;
}

/* Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
 * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.  Returns a
 * positive errno value. */
int
netdev_set_in4(struct netdev *netdev, struct in_addr addr, struct in_addr mask)
{
    return (netdev->class->set_in4
            ? netdev->class->set_in4(netdev, addr, mask)
            : EOPNOTSUPP);
}

/* Adds 'router' as a default IP gateway for the TCP/IP stack that corresponds
 * to 'netdev'. */
int
netdev_add_router(struct netdev *netdev, struct in_addr router)
{
    COVERAGE_INC(netdev_add_router);
    return (netdev->class->add_router
            ? netdev->class->add_router(netdev, router)
            : EOPNOTSUPP);
}

/* If 'netdev' has an assigned IPv6 address, sets '*in6' to that address and
 * returns 0.  Otherwise, returns a positive errno value and sets '*in6' to
 * all-zero-bits (in6addr_any).
 *
 * The following error values have well-defined meanings:
 *
 *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv6 address.
 *
 *   - EOPNOTSUPP: No IPv6 network stack attached to 'netdev'.
 *
 * 'in6' may be null, in which case the address itself is not reported. */
int
netdev_get_in6(const struct netdev *netdev, struct in6_addr *in6)
{
    struct in6_addr dummy;
    int error;

    error = (netdev->class->get_in6
             ? netdev->class->get_in6(netdev, in6 ? in6 : &dummy)
             : EOPNOTSUPP);
    if (error && in6) {
        memset(in6, 0, sizeof *in6);
    }
    return error;
}

/* On 'netdev', turns off the flags in 'off' and then turns on the flags in
 * 'on'.  If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.  Returns 0 if
 * successful, otherwise a positive errno value. */
static int
do_update_flags(struct netdev *netdev, enum netdev_flags off,
                enum netdev_flags on, enum netdev_flags *old_flagsp,
                bool permanent)
{
    enum netdev_flags old_flags;
    int error;

    error = netdev->class->update_flags(netdev, off & ~on, on, &old_flags);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to %s flags for network device %s: %s",
                     off || on ? "set" : "get", netdev_get_name(netdev),
                     strerror(error));
        old_flags = 0;
    } else if ((off || on) && !permanent) {
        enum netdev_flags new_flags = (old_flags & ~off) | on;
        enum netdev_flags changed_flags = old_flags ^ new_flags;
        if (changed_flags) {
            if (!netdev->changed_flags) {
                netdev->save_flags = old_flags;
            }
            netdev->changed_flags |= changed_flags;
        }
    }
    if (old_flagsp) {
        *old_flagsp = old_flags;
    }
    return error;
}

/* Obtains the current flags for 'netdev' and stores them into '*flagsp'.
 * Returns 0 if successful, otherwise a positive errno value.  On failure,
 * stores 0 into '*flagsp'. */
int
netdev_get_flags(const struct netdev *netdev_, enum netdev_flags *flagsp)
{
    struct netdev *netdev = (struct netdev *) netdev_;
    return do_update_flags(netdev, 0, 0, flagsp, false);
}

/* Sets the flags for 'netdev' to 'flags'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_set_flags(struct netdev *netdev, enum netdev_flags flags,
                 bool permanent)
{
    return do_update_flags(netdev, -1, flags, NULL, permanent);
}

/* Turns on the specified 'flags' on 'netdev'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_turn_flags_on(struct netdev *netdev, enum netdev_flags flags,
                     bool permanent)
{
    return do_update_flags(netdev, 0, flags, NULL, permanent);
}

/* Turns off the specified 'flags' on 'netdev'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_turn_flags_off(struct netdev *netdev, enum netdev_flags flags,
                      bool permanent)
{
    return do_update_flags(netdev, flags, 0, NULL, permanent);
}

/* Looks up the ARP table entry for 'ip' on 'netdev'.  If one exists and can be
 * successfully retrieved, it stores the corresponding MAC address in 'mac' and
 * returns 0.  Otherwise, it returns a positive errno value; in particular,
 * ENXIO indicates that there is no ARP table entry for 'ip' on 'netdev'. */
int
netdev_arp_lookup(const struct netdev *netdev,
                  uint32_t ip, uint8_t mac[ETH_ADDR_LEN])
{
    int error = (netdev->class->arp_lookup
                 ? netdev->class->arp_lookup(netdev, ip, mac)
                 : EOPNOTSUPP);
    if (error) {
        memset(mac, 0, ETH_ADDR_LEN);
    }
    return error;
}

/* Sets 'carrier' to true if carrier is active (link light is on) on
 * 'netdev'. */
int
netdev_get_carrier(const struct netdev *netdev, bool *carrier)
{
    int error = (netdev->class->get_carrier
                 ? netdev->class->get_carrier(netdev, carrier)
                 : EOPNOTSUPP);
    if (error) {
        *carrier = false;
    }
    return error;
}

/* Retrieves current device stats for 'netdev'. */
int
netdev_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    int error;

    COVERAGE_INC(netdev_get_stats);
    error = (netdev->class->get_stats
             ? netdev->class->get_stats(netdev, stats)
             : EOPNOTSUPP);
    if (error) {
        memset(stats, 0xff, sizeof *stats);
    }
    return error;
}

/* Attempts to set input rate limiting (policing) policy, such that up to
 * 'kbits_rate' kbps of traffic is accepted, with a maximum accumulative burst
 * size of 'kbits' kb. */
int
netdev_set_policing(struct netdev *netdev, uint32_t kbits_rate,
                    uint32_t kbits_burst)
{
    return (netdev->class->set_policing
            ? netdev->class->set_policing(netdev, kbits_rate, kbits_burst)
            : EOPNOTSUPP);
}

/* If 'netdev' is a VLAN network device (e.g. one created with vconfig(8)),
 * sets '*vlan_vid' to the VLAN VID associated with that device and returns 0.
 * Otherwise returns a errno value (specifically ENOENT if 'netdev_name' is the
 * name of a network device that is not a VLAN device) and sets '*vlan_vid' to
 * -1. */
int
netdev_get_vlan_vid(const struct netdev *netdev, int *vlan_vid)
{
    int error = (netdev->class->get_vlan_vid
                 ? netdev->class->get_vlan_vid(netdev, vlan_vid)
                 : ENOENT);
    if (error) {
        *vlan_vid = 0;
    }
    return error;
}

/* Returns a network device that has 'in4' as its IP address, if one exists,
 * otherwise a null pointer. */
struct netdev *
netdev_find_dev_by_in4(const struct in_addr *in4)
{
    struct netdev *netdev;
    struct svec dev_list;
    size_t i;

    netdev_enumerate(&dev_list);
    for (i = 0; i < dev_list.n; i++) {
        const char *name = dev_list.names[i];
        struct in_addr dev_in4;

        if (!netdev_open(name, NETDEV_ETH_TYPE_NONE, &netdev)
            && !netdev_get_in4(netdev, &dev_in4)
            && dev_in4.s_addr == in4->s_addr) {
            goto exit;
        }
        netdev_close(netdev);
    }
    netdev = NULL;

exit:
    svec_destroy(&dev_list);
    return netdev;
}

/* Initializes 'netdev' as a netdev named 'name' of the specified 'class'.
 *
 * This function adds 'netdev' to a netdev-owned linked list, so it is very
 * important that 'netdev' only be freed after calling netdev_close(). */
void
netdev_init(struct netdev *netdev, const char *name,
            const struct netdev_class *class)
{
    netdev->class = class;
    netdev->name = xstrdup(name);
    netdev->save_flags = 0;
    netdev->changed_flags = 0;
    list_push_back(&netdev_list, &netdev->node);
}

/* Initializes 'notifier' as a netdev notifier for 'netdev', for which
 * notification will consist of calling 'cb', with auxiliary data 'aux'. */
void
netdev_notifier_init(struct netdev_notifier *notifier, struct netdev *netdev,
                     void (*cb)(struct netdev_notifier *), void *aux)
{
    notifier->netdev = netdev;
    notifier->cb = cb;
    notifier->aux = aux;
}

/* Tracks changes in the status of a set of network devices. */
struct netdev_monitor {
    struct shash polled_netdevs;
    struct shash changed_netdevs;
};

/* Creates and returns a new structure for monitor changes in the status of
 * network devices. */
struct netdev_monitor *
netdev_monitor_create(void)
{
    struct netdev_monitor *monitor = xmalloc(sizeof *monitor);
    shash_init(&monitor->polled_netdevs);
    shash_init(&monitor->changed_netdevs);
    return monitor;
}

/* Destroys 'monitor'. */
void
netdev_monitor_destroy(struct netdev_monitor *monitor)
{
    if (monitor) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, &monitor->polled_netdevs) {
            struct netdev_notifier *notifier = node->data;
            notifier->netdev->class->poll_remove(notifier);
        }

        shash_destroy(&monitor->polled_netdevs);
        shash_destroy(&monitor->changed_netdevs);
        free(monitor);
    }
}

static void
netdev_monitor_cb(struct netdev_notifier *notifier)
{
    struct netdev_monitor *monitor = notifier->aux;
    const char *name = netdev_get_name(notifier->netdev);
    if (!shash_find(&monitor->changed_netdevs, name)) {
        shash_add(&monitor->changed_netdevs, name, NULL);
    }
}

/* Attempts to add 'netdev' as a netdev monitored by 'monitor'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Adding a given 'netdev' to a monitor multiple times is equivalent to adding
 * it once. */
int
netdev_monitor_add(struct netdev_monitor *monitor, struct netdev *netdev)
{
    const char *netdev_name = netdev_get_name(netdev);
    int error = 0;
    if (!shash_find(&monitor->polled_netdevs, netdev_name)
        && netdev->class->poll_add)
    {
        struct netdev_notifier *notifier;
        error = netdev->class->poll_add(netdev, netdev_monitor_cb, monitor,
                                        &notifier);
        if (!error) {
            assert(notifier->netdev == netdev);
            shash_add(&monitor->polled_netdevs, netdev_name, notifier);
        }
    }
    return error;
}

/* Removes 'netdev' from the set of netdevs monitored by 'monitor'.  (This has
 * no effect if 'netdev' is not in the set of devices monitored by
 * 'monitor'.) */
void
netdev_monitor_remove(struct netdev_monitor *monitor, struct netdev *netdev)
{
    const char *netdev_name = netdev_get_name(netdev);
    struct shash_node *node;

    node = shash_find(&monitor->polled_netdevs, netdev_name);
    if (node) {
        /* Cancel future notifications. */
        struct netdev_notifier *notifier = node->data;
        netdev->class->poll_remove(notifier);
        shash_delete(&monitor->polled_netdevs, node);

        /* Drop any pending notification. */
        node = shash_find(&monitor->changed_netdevs, netdev_name);
        if (node) {
            shash_delete(&monitor->changed_netdevs, node);
        }
    }
}

/* Checks for changes to netdevs in the set monitored by 'monitor'.  If any of
 * the attributes (Ethernet address, carrier status, speed or peer-advertised
 * speed, flags, etc.) of a network device monitored by 'monitor' has changed,
 * sets '*devnamep' to the name of a device that has changed and returns 0.
 * The caller is responsible for freeing '*devnamep' (with free()).
 *
 * If no devices have changed, sets '*devnamep' to NULL and returns EAGAIN.
 */
int
netdev_monitor_poll(struct netdev_monitor *monitor, char **devnamep)
{
    struct shash_node *node = shash_first(&monitor->changed_netdevs);
    if (!node) {
        *devnamep = NULL;
        return EAGAIN;
    } else {
        *devnamep = xstrdup(node->name);
        shash_delete(&monitor->changed_netdevs, node);
        return 0;
    }
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when netdev_monitor_poll(monitor) would indicate that a device has
 * changed. */
void
netdev_monitor_poll_wait(const struct netdev_monitor *monitor)
{
    if (!shash_is_empty(&monitor->changed_netdevs)) {
        poll_immediate_wake();
    } else {
        /* XXX Nothing needed here for netdev_linux, but maybe other netdev
         * classes need help. */
    }
}

/* Restore the network device flags on 'netdev' to those that were active
 * before we changed them.  Returns 0 if successful, otherwise a positive
 * errno value.
 *
 * To avoid reentry, the caller must ensure that fatal signals are blocked. */
static int
restore_flags(struct netdev *netdev)
{
    if (netdev->changed_flags) {
        enum netdev_flags restore = netdev->save_flags & netdev->changed_flags;
        enum netdev_flags old_flags;
        return netdev->class->update_flags(netdev,
                                           netdev->changed_flags & ~restore,
                                           restore, &old_flags);
    }
    return 0;
}

/* Retores all the flags on all network devices that we modified.  Called from
 * a signal handler, so it does not attempt to report error conditions. */
static void
restore_all_flags(void *aux UNUSED)
{
    struct netdev *netdev;
    LIST_FOR_EACH (netdev, struct netdev, node, &netdev_list) {
        restore_flags(netdev);
    }
}
