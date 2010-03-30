/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "svec.h"

#define THIS_MODULE VLM_netdev
#include "vlog.h"

static const struct netdev_class *base_netdev_classes[] = {
    &netdev_linux_class,
    &netdev_tap_class,
    &netdev_gre_class,
    &netdev_patch_class,
};

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
    static int status = -1;

    if (status < 0) {
        int i;

        fatal_signal_add_hook(close_all_netdevs, NULL, NULL, true);

        status = 0;
        for (i = 0; i < ARRAY_SIZE(base_netdev_classes); i++) {
            netdev_register_provider(base_netdev_classes[i]);
        }
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
    struct netdev_class *new_provider;

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

    new_provider = xmalloc(sizeof *new_provider);
    memcpy(new_provider, new_class, sizeof *new_provider);

    shash_add(&netdev_classes, new_class->type, new_provider);

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
    free(del_node->data);

    return 0;
}

/* Clears 'types' and enumerates the types of all currently registered netdev
 * providers into it.  The caller must first initialize the svec. */
void
netdev_enumerate_types(struct svec *types)
{
    struct shash_node *node;

    netdev_initialize();
    svec_clear(types);

    SHASH_FOR_EACH(node, &netdev_classes) {
        const struct netdev_class *netdev_class = node->data;
        svec_add(types, netdev_class->type);
    }
}

/* Compares 'args' to those used to those used by 'dev'.  Returns true
 * if the arguments are the same, false otherwise.  Does not update the
 * values stored in 'dev'. */
static bool
compare_device_args(const struct netdev_dev *dev, const struct shash *args)
{
    const struct shash_node **new_args;
    bool result = true;
    int i;

    if (shash_count(args) != dev->n_args) {
        return false;
    }

    new_args = shash_sort(args);
    for (i = 0; i < dev->n_args; i++) {
        if (strcmp(dev->args[i].key, new_args[i]->name) || 
            strcmp(dev->args[i].value, new_args[i]->data)) {
            result = false;
            goto finish;
        }
    }

finish:
    free(new_args);
    return result;
}

static int
compare_args(const void *a_, const void *b_)
{
    const struct arg *a = a_;
    const struct arg *b = b_;
    return strcmp(a->key, b->key);
}

void
update_device_args(struct netdev_dev *dev, const struct shash *args)
{
    struct shash_node *node;
    int i;

    if (dev->n_args) {
        for (i = 0; i < dev->n_args; i++) {
            free(dev->args[i].key);
            free(dev->args[i].value);
        }

        free(dev->args);
        dev->n_args = 0;
    }

    if (!args || shash_is_empty(args)) {
        return;
    }

    dev->n_args = shash_count(args);
    dev->args = xmalloc(dev->n_args * sizeof *dev->args);

    i = 0;
    SHASH_FOR_EACH(node, args) {
        dev->args[i].key = xstrdup(node->name);
        dev->args[i].value = xstrdup(node->data);
        i++;
    }

    qsort(dev->args, dev->n_args, sizeof *dev->args, compare_args);
}

static int
create_device(struct netdev_options *options, struct netdev_dev **netdev_devp)
{
    struct netdev_class *netdev_class;

    if (!options->may_create) {
        VLOG_WARN("attempted to create a device that may not be created: %s",
                  options->name);
        return ENODEV;
    }

    if (!options->type || strlen(options->type) == 0) {
        /* Default to system. */
        options->type = "system";
    }

    netdev_class = shash_find_data(&netdev_classes, options->type);
    if (!netdev_class) {
        VLOG_WARN("could not create netdev %s of unknown type %s",
                  options->name, options->type);
        return EAFNOSUPPORT;
    }

    return netdev_class->create(options->name, options->type, options->args,
                                netdev_devp);
}

/* Opens the network device named 'name' (e.g. "eth0") and returns zero if
 * successful, otherwise a positive errno value.  On success, sets '*netdevp'
 * to the new network device, otherwise to null.
 *
 * If this is the first time the device has been opened, then create is called
 * before opening.  The device is  created using the given type and arguments.
 *
 * 'ethertype' may be a 16-bit Ethernet protocol value in host byte order to
 * capture frames of that type received on the device.  It may also be one of
 * the 'enum netdev_pseudo_ethertype' values to receive frames in one of those
 * categories.
 *
 * If the 'may_create' flag is set then this is allowed to be the first time
 * the device is opened (i.e. the refcount will be 1 after this call).  It
 * may be set to false if the device should have already been created.
 *
 * If the 'may_open' flag is set then the call will succeed even if another
 * caller has already opened it.  It may be to false if the device should not
 * currently be open. */

int
netdev_open(struct netdev_options *options, struct netdev **netdevp)
{
    struct shash empty_args = SHASH_INITIALIZER(&empty_args);
    struct netdev_dev *netdev_dev;
    int error;

    *netdevp = NULL;
    netdev_initialize();

    if (!options->args) {
        options->args = &empty_args;
    }

    netdev_dev = shash_find_data(&netdev_dev_shash, options->name);

    if (!netdev_dev) {
        error = create_device(options, &netdev_dev);
        if (error) {
            return error;
        }
        update_device_args(netdev_dev, options->args);

    } else if (options->may_open) {
        if (!shash_is_empty(options->args) &&
            !compare_device_args(netdev_dev, options->args)) {

            VLOG_WARN("%s: attempted to open already created netdev with "
                      "different arguments", options->name);
            return EINVAL;
        }
    } else {
        VLOG_WARN("%s: attempted to create a netdev device with bound name",
                  options->name);
        return EEXIST;
    }

    error = netdev_dev->netdev_class->open(netdev_dev, options->ethertype, 
                netdevp);

    if (!error) {
        netdev_dev->ref_cnt++;
    } else {
        if (!netdev_dev->ref_cnt) {
            netdev_dev_uninit(netdev_dev, true);
        }
    }

    return error;
}

int
netdev_open_default(const char *name, struct netdev **netdevp)
{
    struct netdev_options options;

    memset(&options, 0, sizeof options);

    options.name = name;
    options.ethertype = NETDEV_ETH_TYPE_NONE;
    options.may_create = true;
    options.may_open = true;

    return netdev_open(&options, netdevp);
}

/* Reconfigures the device 'netdev' with 'args'.  'args' may be empty
 * or NULL if none are needed. */
int
netdev_reconfigure(struct netdev *netdev, const struct shash *args)
{
    struct shash empty_args = SHASH_INITIALIZER(&empty_args);
    struct netdev_dev *netdev_dev = netdev_get_dev(netdev);

    if (!args) {
        args = &empty_args;
    }

    if (netdev_dev->netdev_class->reconfigure) {
        if (!compare_device_args(netdev_dev, args)) {
            update_device_args(netdev_dev, args);
            return netdev_dev->netdev_class->reconfigure(netdev_dev, args);
        }
    } else if (!shash_is_empty(args)) {
        VLOG_WARN("%s: arguments provided to device that does not have a "
                  "reconfigure function", netdev_get_name(netdev));
    }

    return 0;
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

    error = netdev_open_default(name, &netdev);
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

/*  Clears 'svec' and enumerates the names of all known network devices. */
int
netdev_enumerate(struct svec *svec)
{
    struct shash_node *node;
    int error = 0;

    netdev_initialize();
    svec_clear(svec);

    SHASH_FOR_EACH(node, &netdev_classes) {
        const struct netdev_class *netdev_class = node->data;
        if (netdev_class->enumerate) {
            int retval = netdev_class->enumerate(svec);
            if (retval) {
                VLOG_WARN("failed to enumerate %s network devices: %s",
                          netdev_class->type, strerror(retval));
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
 *
 * Some network devices may not implement support for this function.  In such
 * cases this function will always return EOPNOTSUPP.
 */
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
 * If successful, returns 0 and stores the MTU size in '*mtup'.  On failure,
 * returns a positive errno value and stores ETH_PAYLOAD_MAX (1500) in
 * '*mtup'. */
int
netdev_get_mtu(const struct netdev *netdev, int *mtup)
{
    int error = netdev_get_dev(netdev)->netdev_class->get_mtu(netdev, mtup);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to retrieve MTU for network device %s: %s",
                     netdev_get_name(netdev), strerror(error));
        *mtup = ETH_PAYLOAD_MAX;
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
 */
int
netdev_get_ifindex(const struct netdev *netdev)
{
    return netdev_get_dev(netdev)->netdev_class->get_ifindex(netdev);
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

    error = netdev_get_dev(netdev)->netdev_class->get_features(netdev, current,
            advertised, supported, peer);
    if (error) {
        *current = *advertised = *supported = *peer = 0;
    }
    return error;
}

/* Returns the maximum speed of a network connection that has the "enum
 * ofp_port_features" bits in 'features', in bits per second.  If no bits that
 * indicate a speed are set in 'features', assumes 100Mbps. */
uint64_t
netdev_features_to_bps(uint32_t features)
{
    enum {
        F_10000MB = OFPPF_10GB_FD,
        F_1000MB = OFPPF_1GB_HD | OFPPF_1GB_FD,
        F_100MB = OFPPF_100MB_HD | OFPPF_100MB_FD,
        F_10MB = OFPPF_10MB_HD | OFPPF_10MB_FD
    };

    return (  features & F_10000MB  ? UINT64_C(10000000000)
            : features & F_1000MB   ? UINT64_C(1000000000)
            : features & F_100MB    ? UINT64_C(100000000)
            : features & F_10MB     ? UINT64_C(10000000)
                                    : UINT64_C(100000000));
}

/* Returns true if any of the "enum ofp_port_features" bits that indicate a
 * full-duplex link are set in 'features', otherwise false. */
bool
netdev_features_is_full_duplex(uint32_t features)
{
    return (features & (OFPPF_10MB_FD | OFPPF_100MB_FD | OFPPF_1GB_FD
                        | OFPPF_10GB_FD)) != 0;
}

/* Set the features advertised by 'netdev' to 'advertise'.  Returns 0 if
 * successful, otherwise a positive errno value. */
int
netdev_set_advertisements(struct netdev *netdev, uint32_t advertise)
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
 * 'address' or 'netmask' or both may be null, in which case the address or netmask
 * is not reported. */
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
    int error = (netdev_get_dev(netdev)->netdev_class->arp_lookup
                 ? netdev_get_dev(netdev)->netdev_class->arp_lookup(netdev, 
                        ip, mac)
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
    int error = (netdev_get_dev(netdev)->netdev_class->get_carrier
                 ? netdev_get_dev(netdev)->netdev_class->get_carrier(netdev, 
                        carrier)
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
    error = (netdev_get_dev(netdev)->netdev_class->get_stats
             ? netdev_get_dev(netdev)->netdev_class->get_stats(netdev, stats)
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
    return (netdev_get_dev(netdev)->netdev_class->set_policing
            ? netdev_get_dev(netdev)->netdev_class->set_policing(netdev, 
                    kbits_rate, kbits_burst)
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
    int error = (netdev_get_dev(netdev)->netdev_class->get_vlan_vid
                 ? netdev_get_dev(netdev)->netdev_class->get_vlan_vid(netdev, 
                        vlan_vid)
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
    struct svec dev_list = SVEC_EMPTY_INITIALIZER;
    size_t i;

    netdev_enumerate(&dev_list);
    for (i = 0; i < dev_list.n; i++) {
        const char *name = dev_list.names[i];
        struct in_addr dev_in4;

        if (!netdev_open_default(name, &netdev)
            && !netdev_get_in4(netdev, &dev_in4, NULL)
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

/* Initializes 'netdev_dev' as a netdev device named 'name' of the
 * specified 'netdev_class'.
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
    update_device_args(netdev_dev, NULL);

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
            netdev_get_dev(notifier->netdev)->netdev_class->poll_remove(
                    notifier);
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
            && netdev_get_dev(netdev)->netdev_class->poll_add)
    {
        struct netdev_notifier *notifier;
        error = netdev_get_dev(netdev)->netdev_class->poll_add(netdev,
                    netdev_monitor_cb, monitor, &notifier);
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
        netdev_get_dev(netdev)->netdev_class->poll_remove(notifier);
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
    LIST_FOR_EACH_SAFE(netdev, next, struct netdev, node, &netdev_list) {
        netdev_close(netdev);
    }
}
