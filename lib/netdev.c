/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "hash.h"
#include "list.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "smap.h"
#include "sset.h"
#include "svec.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev);

COVERAGE_DEFINE(netdev_received);
COVERAGE_DEFINE(netdev_sent);
COVERAGE_DEFINE(netdev_add_router);
COVERAGE_DEFINE(netdev_get_stats);

static struct shash netdev_classes = SHASH_INITIALIZER(&netdev_classes);

/* All created network devices. */
static struct shash netdev_dev_shash = SHASH_INITIALIZER(&netdev_dev_shash);

/* All open network devices. */
static struct list netdev_list = LIST_INITIALIZER(&netdev_list);

/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static void close_all_netdevs(void *aux OVS_UNUSED);
static int restore_flags(struct netdev *netdev);
void update_device_args(struct netdev_dev *, const struct shash *args);

static void
netdev_initialize(void)
{
    static bool inited;

    if (!inited) {
        inited = true;

        fatal_signal_add_hook(close_all_netdevs, NULL, NULL, true);

#ifdef LINUX_DATAPATH
        netdev_register_provider(&netdev_linux_class);
        netdev_register_provider(&netdev_internal_class);
        netdev_register_provider(&netdev_tap_class);
        netdev_vport_register();
#endif
#ifdef __FreeBSD__
        netdev_register_provider(&netdev_tap_class);
        netdev_register_provider(&netdev_bsd_class);
#endif
    }
}

/* Performs periodic work needed by all the various kinds of netdevs.
 *
 * If your program opens any netdevs, it must call this function within its
 * main poll loop. */
void
netdev_run(void)
{
    struct shash_node *node;
    SHASH_FOR_EACH(node, &netdev_classes) {
        const struct netdev_class *netdev_class = node->data;
        if (netdev_class->run) {
            netdev_class->run();
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
    struct shash_node *node;
    SHASH_FOR_EACH(node, &netdev_classes) {
        const struct netdev_class *netdev_class = node->data;
        if (netdev_class->wait) {
            netdev_class->wait();
        }
    }
}

/* Initializes and registers a new netdev provider.  After successful
 * registration, new netdevs of that type can be opened using netdev_open(). */
int
netdev_register_provider(const struct netdev_class *new_class)
{
    if (shash_find(&netdev_classes, new_class->type)) {
        VLOG_WARN("attempted to register duplicate netdev provider: %s",
                   new_class->type);
        return EEXIST;
    }

    if (new_class->init) {
        int error = new_class->init();
        if (error) {
            VLOG_ERR("failed to initialize %s network device class: %s",
                     new_class->type, strerror(error));
            return error;
        }
    }

    shash_add(&netdev_classes, new_class->type, new_class);

    return 0;
}

/* Unregisters a netdev provider.  'type' must have been previously
 * registered and not currently be in use by any netdevs.  After unregistration
 * new netdevs of that type cannot be opened using netdev_open(). */
int
netdev_unregister_provider(const char *type)
{
    struct shash_node *del_node, *netdev_dev_node;

    del_node = shash_find(&netdev_classes, type);
    if (!del_node) {
        VLOG_WARN("attempted to unregister a netdev provider that is not "
                  "registered: %s", type);
        return EAFNOSUPPORT;
    }

    SHASH_FOR_EACH(netdev_dev_node, &netdev_dev_shash) {
        struct netdev_dev *netdev_dev = netdev_dev_node->data;
        if (!strcmp(netdev_dev->netdev_class->type, type)) {
            VLOG_WARN("attempted to unregister in use netdev provider: %s",
                      type);
            return EBUSY;
        }
    }

    shash_delete(&netdev_classes, del_node);

    return 0;
}

const struct netdev_class *
netdev_lookup_provider(const char *type)
{
    netdev_initialize();
    return shash_find_data(&netdev_classes, type && type[0] ? type : "system");
}

/* Clears 'types' and enumerates the types of all currently registered netdev
 * providers into it.  The caller must first initialize the sset. */
void
netdev_enumerate_types(struct sset *types)
{
    struct shash_node *node;

    netdev_initialize();
    sset_clear(types);

    SHASH_FOR_EACH(node, &netdev_classes) {
        const struct netdev_class *netdev_class = node->data;
        sset_add(types, netdev_class->type);
    }
}

/* Opens the network device named 'name' (e.g. "eth0") of the specified 'type'
 * (e.g. "system") and returns zero if successful, otherwise a positive errno
 * value.  On success, sets '*netdevp' to the new network device, otherwise to
 * null.
 *
 * Some network devices may need to be configured (with netdev_set_config())
 * before they can be used. */
int
netdev_open(const char *name, const char *type, struct netdev **netdevp)
{
    struct netdev_dev *netdev_dev;
    int error;

    *netdevp = NULL;
    netdev_initialize();

    netdev_dev = shash_find_data(&netdev_dev_shash, name);

    if (!netdev_dev) {
        const struct netdev_class *class;

        class = netdev_lookup_provider(type);
        if (!class) {
            VLOG_WARN("could not create netdev %s of unknown type %s",
                      name, type);
            return EAFNOSUPPORT;
        }
        error = class->create(class, name, &netdev_dev);
        if (error) {
            return error;
        }
        assert(netdev_dev->netdev_class == class);

    }

    error = netdev_dev->netdev_class->open(netdev_dev, netdevp);

    if (!error) {
        netdev_dev->ref_cnt++;
    } else {
        if (!netdev_dev->ref_cnt) {
            netdev_dev_uninit(netdev_dev, true);
        }
    }

    return error;
}

/* Reconfigures the device 'netdev' with 'args'.  'args' may be empty
 * or NULL if none are needed. */
int
netdev_set_config(struct netdev *netdev, const struct smap *args)
{
    struct netdev_dev *netdev_dev = netdev_get_dev(netdev);

    if (netdev_dev->netdev_class->set_config) {
        struct smap no_args = SMAP_INITIALIZER(&no_args);
        return netdev_dev->netdev_class->set_config(netdev_dev,
                                                    args ? args : &no_args);
    } else if (args && !smap_is_empty(args)) {
        VLOG_WARN("%s: arguments provided to device that is not configurable",
                  netdev_get_name(netdev));
    }

    return 0;
}

/* Returns the current configuration for 'netdev' in 'args'.  The caller must
 * have already initialized 'args' with smap_init().  Returns 0 on success, in
 * which case 'args' will be filled with 'netdev''s configuration.  On failure
 * returns a positive errno value, in which case 'args' will be empty.
 *
 * The caller owns 'args' and its contents and must eventually free them with
 * smap_destroy(). */
int
netdev_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_dev *netdev_dev = netdev_get_dev(netdev);
    int error;

    smap_clear(args);
    if (netdev_dev->netdev_class->get_config) {
        error = netdev_dev->netdev_class->get_config(netdev_dev, args);
        if (error) {
            smap_clear(args);
        }
    } else {
        error = 0;
    }

    return error;
}

/* Closes and destroys 'netdev'. */
void
netdev_close(struct netdev *netdev)
{
    if (netdev) {
        struct netdev_dev *netdev_dev = netdev_get_dev(netdev);

        assert(netdev_dev->ref_cnt);
        netdev_dev->ref_cnt--;
        netdev_uninit(netdev, true);

        /* If the reference count for the netdev device is zero, destroy it. */
        if (!netdev_dev->ref_cnt) {
            netdev_dev_uninit(netdev_dev, true);
        }
    }
}

/* Returns true if a network device named 'name' exists and may be opened,
 * otherwise false. */
bool
netdev_exists(const char *name)
{
    struct netdev *netdev;
    int error;

    error = netdev_open(name, "system", &netdev);
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

/* Returns true if a network device named 'name' is currently opened,
 * otherwise false. */
bool
netdev_is_open(const char *name)
{
    return !!shash_find_data(&netdev_dev_shash, name);
}

/* Parses 'netdev_name_', which is of the form [type@]name into its component
 * pieces.  'name' and 'type' must be freed by the caller. */
void
netdev_parse_name(const char *netdev_name_, char **name, char **type)
{
    char *netdev_name = xstrdup(netdev_name_);
    char *separator;

    separator = strchr(netdev_name, '@');
    if (separator) {
        *separator = '\0';
        *type = netdev_name;
        *name = xstrdup(separator + 1);
    } else {
        *name = netdev_name;
        *type = xstrdup("system");
    }
}

/* Attempts to set up 'netdev' for receiving packets with netdev_recv().
 * Returns 0 if successful, otherwise a positive errno value.  EOPNOTSUPP
 * indicates that the network device does not implement packet reception
 * through this interface. */
int
netdev_listen(struct netdev *netdev)
{
    int (*listen)(struct netdev *);

    listen = netdev_get_dev(netdev)->netdev_class->listen;
    return listen ? (listen)(netdev) : EOPNOTSUPP;
}

/* Attempts to receive a packet from 'netdev' into 'buffer', which the caller
 * must have initialized with sufficient room for the packet.  The space
 * required to receive any packet is ETH_HEADER_LEN bytes, plus VLAN_HEADER_LEN
 * bytes, plus the device's MTU (which may be retrieved via netdev_get_mtu()).
 * (Some devices do not allow for a VLAN header, in which case VLAN_HEADER_LEN
 * need not be included.)
 *
 * This function can only be expected to return a packet if ->listen() has
 * been called successfully.
 *
 * If a packet is successfully retrieved, returns 0.  In this case 'buffer' is
 * guaranteed to contain at least ETH_TOTAL_MIN bytes.  Otherwise, returns a
 * positive errno value.  Returns EAGAIN immediately if no packet is ready to
 * be returned.
 *
 * Some network devices may not implement support for this function.  In such
 * cases this function will always return EOPNOTSUPP. */
int
netdev_recv(struct netdev *netdev, struct ofpbuf *buffer)
{
    int (*recv)(struct netdev *, void *, size_t);
    int retval;

    assert(buffer->size == 0);
    assert(ofpbuf_tailroom(buffer) >= ETH_TOTAL_MIN);

    recv = netdev_get_dev(netdev)->netdev_class->recv;
    retval = (recv
              ? (recv)(netdev, buffer->data, ofpbuf_tailroom(buffer))
              : -EOPNOTSUPP);
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
    void (*recv_wait)(struct netdev *);

    recv_wait = netdev_get_dev(netdev)->netdev_class->recv_wait;
    if (recv_wait) {
        recv_wait(netdev);
    }
}

/* Discards all packets waiting to be received from 'netdev'. */
int
netdev_drain(struct netdev *netdev)
{
    int (*drain)(struct netdev *);

    drain = netdev_get_dev(netdev)->netdev_class->drain;
    return drain ? drain(netdev) : 0;
}

/* Sends 'buffer' on 'netdev'.  Returns 0 if successful, otherwise a positive
 * errno value.  Returns EAGAIN without blocking if the packet cannot be queued
 * immediately.  Returns EMSGSIZE if a partial packet was transmitted or if
 * the packet is too big or too small to transmit on the device.
 *
 * The caller retains ownership of 'buffer' in all cases.
 *
 * The kernel maintains a packet transmission queue, so the caller is not
 * expected to do additional queuing of packets.
 *
 * Some network devices may not implement support for this function.  In such
 * cases this function will always return EOPNOTSUPP. */
int
netdev_send(struct netdev *netdev, const struct ofpbuf *buffer)
{
    int (*send)(struct netdev *, const void *, size_t);
    int error;

    send = netdev_get_dev(netdev)->netdev_class->send;
    error = send ? (send)(netdev, buffer->data, buffer->size) : EOPNOTSUPP;
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
    void (*send_wait)(struct netdev *);

    send_wait = netdev_get_dev(netdev)->netdev_class->send_wait;
    if (send_wait) {
        send_wait(netdev);
    }
}

/* Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
netdev_set_etheraddr(struct netdev *netdev, const uint8_t mac[ETH_ADDR_LEN])
{
    return netdev_get_dev(netdev)->netdev_class->set_etheraddr(netdev, mac);
}

/* Retrieves 'netdev''s MAC address.  If successful, returns 0 and copies the
 * the MAC address into 'mac'.  On failure, returns a positive errno value and
 * clears 'mac' to all-zeros. */
int
netdev_get_etheraddr(const struct netdev *netdev, uint8_t mac[ETH_ADDR_LEN])
{
    return netdev_get_dev(netdev)->netdev_class->get_etheraddr(netdev, mac);
}

/* Returns the name of the network device that 'netdev' represents,
 * e.g. "eth0".  The caller must not modify or free the returned string. */
const char *
netdev_get_name(const struct netdev *netdev)
{
    return netdev_get_dev(netdev)->name;
}

/* Retrieves the MTU of 'netdev'.  The MTU is the maximum size of transmitted
 * (and received) packets, in bytes, not including the hardware header; thus,
 * this is typically 1500 bytes for Ethernet devices.
 *
 * If successful, returns 0 and stores the MTU size in '*mtup'.  Returns
 * EOPNOTSUPP if 'netdev' does not have an MTU (as e.g. some tunnels do not).
 * On other failure, returns a positive errno value.  On failure, sets '*mtup'
 * to 0. */
int
netdev_get_mtu(const struct netdev *netdev, int *mtup)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    int error;

    error = class->get_mtu ? class->get_mtu(netdev, mtup) : EOPNOTSUPP;
    if (error) {
        *mtup = 0;
        if (error != EOPNOTSUPP) {
            VLOG_DBG_RL(&rl, "failed to retrieve MTU for network device %s: "
                         "%s", netdev_get_name(netdev), strerror(error));
        }
    }
    return error;
}

/* Sets the MTU of 'netdev'.  The MTU is the maximum size of transmitted
 * (and received) packets, in bytes.
 *
 * If successful, returns 0.  Returns EOPNOTSUPP if 'netdev' does not have an
 * MTU (as e.g. some tunnels do not).  On other failure, returns a positive
 * errno value. */
int
netdev_set_mtu(const struct netdev *netdev, int mtu)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    int error;

    error = class->set_mtu ? class->set_mtu(netdev, mtu) : EOPNOTSUPP;
    if (error && error != EOPNOTSUPP) {
        VLOG_DBG_RL(&rl, "failed to set MTU for network device %s: %s",
                     netdev_get_name(netdev), strerror(error));
    }

    return error;
}

/* Returns the ifindex of 'netdev', if successful, as a positive number.  On
 * failure, returns a negative errno value.
 *
 * The desired semantics of the ifindex value are a combination of those
 * specified by POSIX for if_nametoindex() and by SNMP for ifIndex.  An ifindex
 * value should be unique within a host and remain stable at least until
 * reboot.  SNMP says an ifindex "ranges between 1 and the value of ifNumber"
 * but many systems do not follow this rule anyhow.
 *
 * Some network devices may not implement support for this function.  In such
 * cases this function will always return -EOPNOTSUPP.
 */
int
netdev_get_ifindex(const struct netdev *netdev)
{
    int (*get_ifindex)(const struct netdev *);

    get_ifindex = netdev_get_dev(netdev)->netdev_class->get_ifindex;

    return get_ifindex ? get_ifindex(netdev) : -EOPNOTSUPP;
}

/* Stores the features supported by 'netdev' into each of '*current',
 * '*advertised', '*supported', and '*peer' that are non-null.  Each value is a
 * bitmap of "enum ofp_port_features" bits, in host byte order.  Returns 0 if
 * successful, otherwise a positive errno value.  On failure, all of the
 * passed-in values are set to 0.
 *
 * Some network devices may not implement support for this function.  In such
 * cases this function will always return EOPNOTSUPP. */
int
netdev_get_features(const struct netdev *netdev,
                    enum netdev_features *current,
                    enum netdev_features *advertised,
                    enum netdev_features *supported,
                    enum netdev_features *peer)
{
    int (*get_features)(const struct netdev *netdev,
                        enum netdev_features *current,
                        enum netdev_features *advertised,
                        enum netdev_features *supported,
                        enum netdev_features *peer);
    enum netdev_features dummy[4];
    int error;

    if (!current) {
        current = &dummy[0];
    }
    if (!advertised) {
        advertised = &dummy[1];
    }
    if (!supported) {
        supported = &dummy[2];
    }
    if (!peer) {
        peer = &dummy[3];
    }

    get_features = netdev_get_dev(netdev)->netdev_class->get_features;
    error = get_features
                    ? get_features(netdev, current, advertised, supported,
                                   peer)
                    : EOPNOTSUPP;
    if (error) {
        *current = *advertised = *supported = *peer = 0;
    }
    return error;
}

/* Returns the maximum speed of a network connection that has the NETDEV_F_*
 * bits in 'features', in bits per second.  If no bits that indicate a speed
 * are set in 'features', assumes 100Mbps. */
uint64_t
netdev_features_to_bps(enum netdev_features features)
{
    enum {
        F_1000000MB = NETDEV_F_1TB_FD,
        F_100000MB = NETDEV_F_100GB_FD,
        F_40000MB = NETDEV_F_40GB_FD,
        F_10000MB = NETDEV_F_10GB_FD,
        F_1000MB = NETDEV_F_1GB_HD | NETDEV_F_1GB_FD,
        F_100MB = NETDEV_F_100MB_HD | NETDEV_F_100MB_FD,
        F_10MB = NETDEV_F_10MB_HD | NETDEV_F_10MB_FD
    };

    return (  features & F_1000000MB ? UINT64_C(1000000000000)
            : features & F_100000MB  ? UINT64_C(100000000000)
            : features & F_40000MB   ? UINT64_C(40000000000)
            : features & F_10000MB   ? UINT64_C(10000000000)
            : features & F_1000MB    ? UINT64_C(1000000000)
            : features & F_100MB     ? UINT64_C(100000000)
            : features & F_10MB      ? UINT64_C(10000000)
                                     : UINT64_C(100000000));
}

/* Returns true if any of the NETDEV_F_* bits that indicate a full-duplex link
 * are set in 'features', otherwise false. */
bool
netdev_features_is_full_duplex(enum netdev_features features)
{
    return (features & (NETDEV_F_10MB_FD | NETDEV_F_100MB_FD | NETDEV_F_1GB_FD
                        | NETDEV_F_10GB_FD | NETDEV_F_40GB_FD
                        | NETDEV_F_100GB_FD | NETDEV_F_1TB_FD)) != 0;
}

/* Set the features advertised by 'netdev' to 'advertise'.  Returns 0 if
 * successful, otherwise a positive errno value. */
int
netdev_set_advertisements(struct netdev *netdev,
                          enum netdev_features advertise)
{
    return (netdev_get_dev(netdev)->netdev_class->set_advertisements
            ? netdev_get_dev(netdev)->netdev_class->set_advertisements(
                    netdev, advertise)
            : EOPNOTSUPP);
}

/* If 'netdev' has an assigned IPv4 address, sets '*address' to that address
 * and '*netmask' to its netmask and returns 0.  Otherwise, returns a positive
 * errno value and sets '*address' to 0 (INADDR_ANY).
 *
 * The following error values have well-defined meanings:
 *
 *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv4 address.
 *
 *   - EOPNOTSUPP: No IPv4 network stack attached to 'netdev'.
 *
 * 'address' or 'netmask' or both may be null, in which case the address or
 * netmask is not reported. */
int
netdev_get_in4(const struct netdev *netdev,
               struct in_addr *address_, struct in_addr *netmask_)
{
    struct in_addr address;
    struct in_addr netmask;
    int error;

    error = (netdev_get_dev(netdev)->netdev_class->get_in4
             ? netdev_get_dev(netdev)->netdev_class->get_in4(netdev,
                    &address, &netmask)
             : EOPNOTSUPP);
    if (address_) {
        address_->s_addr = error ? 0 : address.s_addr;
    }
    if (netmask_) {
        netmask_->s_addr = error ? 0 : netmask.s_addr;
    }
    return error;
}

/* Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
 * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.  Returns a
 * positive errno value. */
int
netdev_set_in4(struct netdev *netdev, struct in_addr addr, struct in_addr mask)
{
    return (netdev_get_dev(netdev)->netdev_class->set_in4
            ? netdev_get_dev(netdev)->netdev_class->set_in4(netdev, addr, mask)
            : EOPNOTSUPP);
}

/* Obtains ad IPv4 address from device name and save the address in
 * in4.  Returns 0 if successful, otherwise a positive errno value.
 */
int
netdev_get_in4_by_name(const char *device_name, struct in_addr *in4)
{
    struct netdev *netdev;
    int error;

    error = netdev_open(device_name, "system", &netdev);
    if (error) {
        in4->s_addr = htonl(0);
        return error;
    }

    error = netdev_get_in4(netdev, in4, NULL);
    netdev_close(netdev);
    return error;
}

/* Adds 'router' as a default IP gateway for the TCP/IP stack that corresponds
 * to 'netdev'. */
int
netdev_add_router(struct netdev *netdev, struct in_addr router)
{
    COVERAGE_INC(netdev_add_router);
    return (netdev_get_dev(netdev)->netdev_class->add_router
            ? netdev_get_dev(netdev)->netdev_class->add_router(netdev, router)
            : EOPNOTSUPP);
}

/* Looks up the next hop for 'host' for the TCP/IP stack that corresponds to
 * 'netdev'.  If a route cannot not be determined, sets '*next_hop' to 0,
 * '*netdev_name' to null, and returns a positive errno value.  Otherwise, if a
 * next hop is found, stores the next hop gateway's address (0 if 'host' is on
 * a directly connected network) in '*next_hop' and a copy of the name of the
 * device to reach 'host' in '*netdev_name', and returns 0.  The caller is
 * responsible for freeing '*netdev_name' (by calling free()). */
int
netdev_get_next_hop(const struct netdev *netdev,
                    const struct in_addr *host, struct in_addr *next_hop,
                    char **netdev_name)
{
    int error = (netdev_get_dev(netdev)->netdev_class->get_next_hop
                 ? netdev_get_dev(netdev)->netdev_class->get_next_hop(
                        host, next_hop, netdev_name)
                 : EOPNOTSUPP);
    if (error) {
        next_hop->s_addr = 0;
        *netdev_name = NULL;
    }
    return error;
}

/* Populates 'smap' with status information.
 *
 * Populates 'smap' with 'netdev' specific status information.  This
 * information may be used to populate the status column of the Interface table
 * as defined in ovs-vswitchd.conf.db(5). */
int
netdev_get_drv_info(const struct netdev *netdev, struct smap *smap)
{
    struct netdev_dev *dev = netdev_get_dev(netdev);

    return (dev->netdev_class->get_drv_info
            ? dev->netdev_class->get_drv_info(netdev, smap)
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

    error = (netdev_get_dev(netdev)->netdev_class->get_in6
             ? netdev_get_dev(netdev)->netdev_class->get_in6(netdev,
                    in6 ? in6 : &dummy)
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

    error = netdev_get_dev(netdev)->netdev_class->update_flags(netdev,
                off & ~on, on, &old_flags);
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
    struct netdev *netdev = CONST_CAST(struct netdev *, netdev_);
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
                  ovs_be32 ip, uint8_t mac[ETH_ADDR_LEN])
{
    int error = (netdev_get_dev(netdev)->netdev_class->arp_lookup
                 ? netdev_get_dev(netdev)->netdev_class->arp_lookup(netdev,
                        ip, mac)
                 : EOPNOTSUPP);
    if (error) {
        memset(mac, 0, ETH_ADDR_LEN);
    }
    return error;
}

/* Returns true if carrier is active (link light is on) on 'netdev'. */
bool
netdev_get_carrier(const struct netdev *netdev)
{
    int error;
    enum netdev_flags flags;
    bool carrier;

    netdev_get_flags(netdev, &flags);
    if (!(flags & NETDEV_UP)) {
        return false;
    }

    if (!netdev_get_dev(netdev)->netdev_class->get_carrier) {
        return true;
    }

    error = netdev_get_dev(netdev)->netdev_class->get_carrier(netdev,
                                                              &carrier);
    if (error) {
        VLOG_DBG("%s: failed to get network device carrier status, assuming "
                 "down: %s", netdev_get_name(netdev), strerror(error));
        carrier = false;
    }

    return carrier;
}

/* Returns the number of times 'netdev''s carrier has changed. */
long long int
netdev_get_carrier_resets(const struct netdev *netdev)
{
    return (netdev_get_dev(netdev)->netdev_class->get_carrier_resets
            ? netdev_get_dev(netdev)->netdev_class->get_carrier_resets(netdev)
            : 0);
}

/* Attempts to force netdev_get_carrier() to poll 'netdev''s MII registers for
 * link status instead of checking 'netdev''s carrier.  'netdev''s MII
 * registers will be polled once ever 'interval' milliseconds.  If 'netdev'
 * does not support MII, another method may be used as a fallback.  If
 * 'interval' is less than or equal to zero, reverts netdev_get_carrier() to
 * its normal behavior.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_set_miimon_interval(struct netdev *netdev, long long int interval)
{
    struct netdev_dev *netdev_dev = netdev_get_dev(netdev);
    return (netdev_dev->netdev_class->set_miimon_interval
            ? netdev_dev->netdev_class->set_miimon_interval(netdev, interval)
            : EOPNOTSUPP);
}

/* Retrieves current device stats for 'netdev'. */
int
netdev_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    int error;

    COVERAGE_INC(netdev_get_stats);
    error = (netdev_get_dev(netdev)->netdev_class->get_stats
             ? netdev_get_dev(netdev)->netdev_class->get_stats(netdev, stats)
             : EOPNOTSUPP);
    if (error) {
        memset(stats, 0xff, sizeof *stats);
    }
    return error;
}

/* Attempts to change the stats for 'netdev' to those provided in 'stats'.
 * Returns 0 if successful, otherwise a positive errno value.
 *
 * This will probably fail for most network devices.  Some devices might only
 * allow setting their stats to 0. */
int
netdev_set_stats(struct netdev *netdev, const struct netdev_stats *stats)
{
    return (netdev_get_dev(netdev)->netdev_class->set_stats
             ? netdev_get_dev(netdev)->netdev_class->set_stats(netdev, stats)
             : EOPNOTSUPP);
}

/* Attempts to set input rate limiting (policing) policy, such that up to
 * 'kbits_rate' kbps of traffic is accepted, with a maximum accumulative burst
 * size of 'kbits' kb. */
int
netdev_set_policing(struct netdev *netdev, uint32_t kbits_rate,
                    uint32_t kbits_burst)
{
    return (netdev_get_dev(netdev)->netdev_class->set_policing
            ? netdev_get_dev(netdev)->netdev_class->set_policing(netdev,
                    kbits_rate, kbits_burst)
            : EOPNOTSUPP);
}

/* Adds to 'types' all of the forms of QoS supported by 'netdev', or leaves it
 * empty if 'netdev' does not support QoS.  Any names added to 'types' should
 * be documented as valid for the "type" column in the "QoS" table in
 * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
 *
 * Every network device supports disabling QoS with a type of "", but this type
 * will not be added to 'types'.
 *
 * The caller must initialize 'types' (e.g. with sset_init()) before calling
 * this function.  The caller is responsible for destroying 'types' (e.g. with
 * sset_destroy()) when it is no longer needed.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_get_qos_types(const struct netdev *netdev, struct sset *types)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    return (class->get_qos_types
            ? class->get_qos_types(netdev, types)
            : 0);
}

/* Queries 'netdev' for its capabilities regarding the specified 'type' of QoS,
 * which should be "" or one of the types returned by netdev_get_qos_types()
 * for 'netdev'.  Returns 0 if successful, otherwise a positive errno value.
 * On success, initializes 'caps' with the QoS capabilities; on failure, clears
 * 'caps' to all zeros. */
int
netdev_get_qos_capabilities(const struct netdev *netdev, const char *type,
                            struct netdev_qos_capabilities *caps)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;

    if (*type) {
        int retval = (class->get_qos_capabilities
                      ? class->get_qos_capabilities(netdev, type, caps)
                      : EOPNOTSUPP);
        if (retval) {
            memset(caps, 0, sizeof *caps);
        }
        return retval;
    } else {
        /* Every netdev supports turning off QoS. */
        memset(caps, 0, sizeof *caps);
        return 0;
    }
}

/* Obtains the number of queues supported by 'netdev' for the specified 'type'
 * of QoS.  Returns 0 if successful, otherwise a positive errno value.  Stores
 * the number of queues (zero on failure) in '*n_queuesp'.
 *
 * This is just a simple wrapper around netdev_get_qos_capabilities(). */
int
netdev_get_n_queues(const struct netdev *netdev,
                    const char *type, unsigned int *n_queuesp)
{
    struct netdev_qos_capabilities caps;
    int retval;

    retval = netdev_get_qos_capabilities(netdev, type, &caps);
    *n_queuesp = caps.n_queues;
    return retval;
}

/* Queries 'netdev' about its currently configured form of QoS.  If successful,
 * stores the name of the current form of QoS into '*typep', stores any details
 * of configuration as string key-value pairs in 'details', and returns 0.  On
 * failure, sets '*typep' to NULL and returns a positive errno value.
 *
 * A '*typep' of "" indicates that QoS is currently disabled on 'netdev'.
 *
 * The caller must initialize 'details' as an empty smap (e.g. with
 * smap_init()) before calling this function.  The caller must free 'details'
 * when it is no longer needed (e.g. with smap_destroy()).
 *
 * The caller must not modify or free '*typep'.
 *
 * '*typep' will be one of the types returned by netdev_get_qos_types() for
 * 'netdev'.  The contents of 'details' should be documented as valid for
 * '*typep' in the "other_config" column in the "QoS" table in
 * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)). */
int
netdev_get_qos(const struct netdev *netdev,
               const char **typep, struct smap *details)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    int retval;

    if (class->get_qos) {
        retval = class->get_qos(netdev, typep, details);
        if (retval) {
            *typep = NULL;
            smap_clear(details);
        }
        return retval;
    } else {
        /* 'netdev' doesn't support QoS, so report that QoS is disabled. */
        *typep = "";
        return 0;
    }
}

/* Attempts to reconfigure QoS on 'netdev', changing the form of QoS to 'type'
 * with details of configuration from 'details'.  Returns 0 if successful,
 * otherwise a positive errno value.  On error, the previous QoS configuration
 * is retained.
 *
 * When this function changes the type of QoS (not just 'details'), this also
 * resets all queue configuration for 'netdev' to their defaults (which depend
 * on the specific type of QoS).  Otherwise, the queue configuration for
 * 'netdev' is unchanged.
 *
 * 'type' should be "" (to disable QoS) or one of the types returned by
 * netdev_get_qos_types() for 'netdev'.  The contents of 'details' should be
 * documented as valid for the given 'type' in the "other_config" column in the
 * "QoS" table in vswitchd/vswitch.xml (which is built as
 * ovs-vswitchd.conf.db(8)).
 *
 * NULL may be specified for 'details' if there are no configuration
 * details. */
int
netdev_set_qos(struct netdev *netdev,
               const char *type, const struct smap *details)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;

    if (!type) {
        type = "";
    }

    if (class->set_qos) {
        if (!details) {
            static struct smap empty = SMAP_INITIALIZER(&empty);
            details = &empty;
        }
        return class->set_qos(netdev, type, details);
    } else {
        return *type ? EOPNOTSUPP : 0;
    }
}

/* Queries 'netdev' for information about the queue numbered 'queue_id'.  If
 * successful, adds that information as string key-value pairs to 'details'.
 * Returns 0 if successful, otherwise a positive errno value.
 *
 * 'queue_id' must be less than the number of queues supported by 'netdev' for
 * the current form of QoS (e.g. as returned by netdev_get_n_queues(netdev)).
 *
 * The returned contents of 'details' should be documented as valid for the
 * given 'type' in the "other_config" column in the "Queue" table in
 * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
 *
 * The caller must initialize 'details' (e.g. with smap_init()) before calling
 * this function.  The caller must free 'details' when it is no longer needed
 * (e.g. with smap_destroy()). */
int
netdev_get_queue(const struct netdev *netdev,
                 unsigned int queue_id, struct smap *details)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    int retval;

    retval = (class->get_queue
              ? class->get_queue(netdev, queue_id, details)
              : EOPNOTSUPP);
    if (retval) {
        smap_clear(details);
    }
    return retval;
}

/* Configures the queue numbered 'queue_id' on 'netdev' with the key-value
 * string pairs in 'details'.  The contents of 'details' should be documented
 * as valid for the given 'type' in the "other_config" column in the "Queue"
 * table in vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
 * Returns 0 if successful, otherwise a positive errno value.  On failure, the
 * given queue's configuration should be unmodified.
 *
 * 'queue_id' must be less than the number of queues supported by 'netdev' for
 * the current form of QoS (e.g. as returned by netdev_get_n_queues(netdev)).
 *
 * This function does not modify 'details', and the caller retains ownership of
 * it. */
int
netdev_set_queue(struct netdev *netdev,
                 unsigned int queue_id, const struct smap *details)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    return (class->set_queue
            ? class->set_queue(netdev, queue_id, details)
            : EOPNOTSUPP);
}

/* Attempts to delete the queue numbered 'queue_id' from 'netdev'.  Some kinds
 * of QoS may have a fixed set of queues, in which case attempts to delete them
 * will fail with EOPNOTSUPP.
 *
 * Returns 0 if successful, otherwise a positive errno value.  On failure, the
 * given queue will be unmodified.
 *
 * 'queue_id' must be less than the number of queues supported by 'netdev' for
 * the current form of QoS (e.g. as returned by
 * netdev_get_n_queues(netdev)). */
int
netdev_delete_queue(struct netdev *netdev, unsigned int queue_id)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    return (class->delete_queue
            ? class->delete_queue(netdev, queue_id)
            : EOPNOTSUPP);
}

/* Obtains statistics about 'queue_id' on 'netdev'.  On success, returns 0 and
 * fills 'stats' with the queue's statistics; individual members of 'stats' may
 * be set to all-1-bits if the statistic is unavailable.  On failure, returns a
 * positive errno value and fills 'stats' with all-1-bits. */
int
netdev_get_queue_stats(const struct netdev *netdev, unsigned int queue_id,
                       struct netdev_queue_stats *stats)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    int retval;

    retval = (class->get_queue_stats
              ? class->get_queue_stats(netdev, queue_id, stats)
              : EOPNOTSUPP);
    if (retval) {
        memset(stats, 0xff, sizeof *stats);
    }
    return retval;
}

/* Iterates over all of 'netdev''s queues, calling 'cb' with the queue's ID,
 * its configuration, and the 'aux' specified by the caller.  The order of
 * iteration is unspecified, but (when successful) each queue is visited
 * exactly once.
 *
 * Calling this function may be more efficient than calling netdev_get_queue()
 * for every queue.
 *
 * 'cb' must not modify or free the 'details' argument passed in.  It may
 * delete or modify the queue passed in as its 'queue_id' argument.  It may
 * modify but must not delete any other queue within 'netdev'.  'cb' should not
 * add new queues because this may cause some queues to be visited twice or not
 * at all.
 *
 * Returns 0 if successful, otherwise a positive errno value.  On error, some
 * configured queues may not have been included in the iteration. */
int
netdev_dump_queues(const struct netdev *netdev,
                   netdev_dump_queues_cb *cb, void *aux)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    return (class->dump_queues
            ? class->dump_queues(netdev, cb, aux)
            : EOPNOTSUPP);
}

/* Iterates over all of 'netdev''s queues, calling 'cb' with the queue's ID,
 * its statistics, and the 'aux' specified by the caller.  The order of
 * iteration is unspecified, but (when successful) each queue is visited
 * exactly once.
 *
 * Calling this function may be more efficient than calling
 * netdev_get_queue_stats() for every queue.
 *
 * 'cb' must not modify or free the statistics passed in.
 *
 * Returns 0 if successful, otherwise a positive errno value.  On error, some
 * configured queues may not have been included in the iteration. */
int
netdev_dump_queue_stats(const struct netdev *netdev,
                        netdev_dump_queue_stats_cb *cb, void *aux)
{
    const struct netdev_class *class = netdev_get_dev(netdev)->netdev_class;
    return (class->dump_queue_stats
            ? class->dump_queue_stats(netdev, cb, aux)
            : EOPNOTSUPP);
}

/* Returns a sequence number which indicates changes in one of 'netdev''s
 * properties.  The returned sequence will be nonzero so that callers have a
 * value which they may use as a reset when tracking 'netdev'.
 *
 * The returned sequence number will change whenever 'netdev''s flags,
 * features, ethernet address, or carrier changes.  It may change for other
 * reasons as well, or no reason at all. */
unsigned int
netdev_change_seq(const struct netdev *netdev)
{
    return netdev_get_dev(netdev)->netdev_class->change_seq(netdev);
}

/* Initializes 'netdev_dev' as a netdev device named 'name' of the specified
 * 'netdev_class'.  This function is ordinarily called from a netdev provider's
 * 'create' function.
 *
 * This function adds 'netdev_dev' to a netdev-owned shash, so it is
 * very important that 'netdev_dev' only be freed after calling
 * the refcount drops to zero.  */
void
netdev_dev_init(struct netdev_dev *netdev_dev, const char *name,
                const struct netdev_class *netdev_class)
{
    assert(!shash_find(&netdev_dev_shash, name));

    memset(netdev_dev, 0, sizeof *netdev_dev);
    netdev_dev->netdev_class = netdev_class;
    netdev_dev->name = xstrdup(name);
    netdev_dev->node = shash_add(&netdev_dev_shash, name, netdev_dev);
}

/* Undoes the results of initialization.
 *
 * Normally this function does not need to be called as netdev_close has
 * the same effect when the refcount drops to zero.
 * However, it may be called by providers due to an error on creation
 * that occurs after initialization.  It this case netdev_close() would
 * never be called. */
void
netdev_dev_uninit(struct netdev_dev *netdev_dev, bool destroy)
{
    char *name = netdev_dev->name;

    assert(!netdev_dev->ref_cnt);

    shash_delete(&netdev_dev_shash, netdev_dev->node);

    if (destroy) {
        netdev_dev->netdev_class->destroy(netdev_dev);
    }
    free(name);
}

/* Returns the class type of 'netdev_dev'.
 *
 * The caller must not free the returned value. */
const char *
netdev_dev_get_type(const struct netdev_dev *netdev_dev)
{
    return netdev_dev->netdev_class->type;
}

/* Returns the class associated with 'netdev_dev'. */
const struct netdev_class *
netdev_dev_get_class(const struct netdev_dev *netdev_dev)
{
    return netdev_dev->netdev_class;
}

/* Returns the name of 'netdev_dev'.
 *
 * The caller must not free the returned value. */
const char *
netdev_dev_get_name(const struct netdev_dev *netdev_dev)
{
    return netdev_dev->name;
}

/* Returns the netdev_dev with 'name' or NULL if there is none.
 *
 * The caller must not free the returned value. */
struct netdev_dev *
netdev_dev_from_name(const char *name)
{
    return shash_find_data(&netdev_dev_shash, name);
}

/* Fills 'device_list' with devices that match 'netdev_class'.
 *
 * The caller is responsible for initializing and destroying 'device_list'
 * but the contained netdev_devs must not be freed. */
void
netdev_dev_get_devices(const struct netdev_class *netdev_class,
                       struct shash *device_list)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, &netdev_dev_shash) {
        struct netdev_dev *dev = node->data;

        if (dev->netdev_class == netdev_class) {
            shash_add(device_list, node->name, node->data);
        }
    }
}

/* Initializes 'netdev' as a instance of the netdev_dev.
 *
 * This function adds 'netdev' to a netdev-owned linked list, so it is very
 * important that 'netdev' only be freed after calling netdev_close(). */
void
netdev_init(struct netdev *netdev, struct netdev_dev *netdev_dev)
{
    memset(netdev, 0, sizeof *netdev);
    netdev->netdev_dev = netdev_dev;
    list_push_back(&netdev_list, &netdev->node);
}

/* Undoes the results of initialization.
 *
 * Normally this function only needs to be called from netdev_close().
 * However, it may be called by providers due to an error on opening
 * that occurs after initialization.  It this case netdev_close() would
 * never be called. */
void
netdev_uninit(struct netdev *netdev, bool close)
{
    /* Restore flags that we changed, if any. */
    int error = restore_flags(netdev);
    list_remove(&netdev->node);
    if (error) {
        VLOG_WARN("failed to restore network device flags on %s: %s",
                  netdev_get_name(netdev), strerror(error));
    }

    if (close) {
        netdev_get_dev(netdev)->netdev_class->close(netdev);
    }
}


/* Returns the class type of 'netdev'.
 *
 * The caller must not free the returned value. */
const char *
netdev_get_type(const struct netdev *netdev)
{
    return netdev_get_dev(netdev)->netdev_class->type;
}

struct netdev_dev *
netdev_get_dev(const struct netdev *netdev)
{
    return netdev->netdev_dev;
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
        return netdev_get_dev(netdev)->netdev_class->update_flags(netdev,
                                           netdev->changed_flags & ~restore,
                                           restore, &old_flags);
    }
    return 0;
}

/* Close all netdevs on shutdown so they can do any needed cleanup such as
 * destroying devices, restoring flags, etc. */
static void
close_all_netdevs(void *aux OVS_UNUSED)
{
    struct netdev *netdev, *next;
    LIST_FOR_EACH_SAFE(netdev, next, node, &netdev_list) {
        netdev_close(netdev);
    }
}
