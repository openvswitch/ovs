/*
 * Copyright (c) 2009 Nicira Networks.
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

#ifndef NETDEV_PROVIDER_H
#define NETDEV_PROVIDER_H 1

/* Generic interface to network devices. */

#include <assert.h>
#include "netdev.h"
#include "list.h"
#include "shash.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* A network device object that was created through the netdev_create()
 * call.
 *
 * This structure should be treated as opaque by network device
 * implementations. */
struct netdev_obj {
    const struct netdev_class *netdev_class;
    int ref_cnt;
    bool created;                    /* Was netdev_create() called? */
};

void netdev_obj_init(struct netdev_obj *, const char *name,
                     const struct netdev_class *, bool created);
static inline void netdev_obj_assert_class(const struct netdev_obj *netdev_obj,
                                           const struct netdev_class *class_)
{
    assert(netdev_obj->netdev_class == class_);
}

/* A network device (e.g. an Ethernet device).
 *
 * This structure should be treated as opaque by network device
 * implementations. */
struct netdev {
    const struct netdev_class *netdev_class;
    char *name;                      /* e.g. "eth0" */

    enum netdev_flags save_flags;    /* Initial device flags. */
    enum netdev_flags changed_flags; /* Flags that we changed. */
    struct list node;                /* Element in global list. */
};

void netdev_init(struct netdev *, const char *name,
                 const struct netdev_class *);
static inline void netdev_assert_class(const struct netdev *netdev,
                                       const struct netdev_class *netdev_class)
{
    assert(netdev->netdev_class == netdev_class);
}
const char *netdev_get_type(const struct netdev *netdev);

/* A network device notifier.
 *
 * Network device implementations should use netdev_notifier_init() to
 * initialize this structure, but they may freely read its members after
 * initialization. */
struct netdev_notifier {
    struct netdev *netdev;
    void (*cb)(struct netdev_notifier *);
    void *aux;
};
void netdev_notifier_init(struct netdev_notifier *, struct netdev *,
                          void (*cb)(struct netdev_notifier *), void *aux);

/* Network device class structure, to be defined by each implementation of a
 * network device.
 *
 * These functions return 0 if successful or a positive errno value on failure,
 * except where otherwise noted. */
struct netdev_class {
    /* Type of netdevs in this class, e.g. "system", "tap", "gre", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed when a device name was not bound through the 
     * netdev_create() call.  The "system" type corresponds to an 
     * existing network device on the system. */
    const char *type;

    /* Called only once, at program startup.  Returning an error from this
     * function will prevent any network device in this class from being
     * opened.
     *
     * This function may be set to null if a network device class needs no
     * initialization at program startup. */
    int (*init)(void);

    /* Performs periodic work needed by netdevs of this class.  May be null if
     * no periodic work is necessary. */
    void (*run)(void);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called.  May be null if nothing is needed here. */
    void (*wait)(void);

    /* Attempts to create a network device object of 'type' with 'name'.  
     * 'type' corresponds to the 'type' field used in the netdev_class
     * structure.  
     *
     * The 'created' flag indicates that the user called netdev_create()
     * and thus will eventually call netdev_destroy().  If the flag is 
     * false, then the object was dynamically created based on a call to 
     * netdev_open() without first calling netdev_create() and will be
     * automatically destroyed when no more netdevs have 'name' open.  A 
     * provider implementation should pass this flag to netdev_obj_init(). */
    int (*create)(const char *name, const char *type, 
                  const struct shash *args, bool created);

    /* Destroys 'netdev_obj'.  
     *
     * Netdev objects maintain a reference count that is incremented on 
     * netdev_open() and decremented on netdev_close().  If 'netdev_obj' 
     * has a non-zero reference count, then this function will not be 
     * called. */
    void (*destroy)(struct netdev_obj *netdev_obj);

    /* Reconfigures the device object 'netdev_obj' with 'args'. 
     *
     * If this netdev class does not support reconfiguring a netdev
     * object, this may be a null pointer.
     */
    int (*reconfigure)(struct netdev_obj *netdev_obj, 
                       const struct shash *args);

    /* Attempts to open a network device.  On success, sets '*netdevp' to the
     * new network device.  'name' is the network device name provided by
     * the user.  This name is useful for error messages but must not be
     * modified.
     *
     * 'ethertype' may be a 16-bit Ethernet protocol value in host byte order
     * to capture frames of that type received on the device.  It may also be
     * one of the 'enum netdev_pseudo_ethertype' values to receive frames in
     * one of those categories. */
    int (*open)(const char *name, int ethertype, struct netdev **netdevp);

    /* Closes 'netdev'. */
    void (*close)(struct netdev *netdev);

    /* Enumerates the names of all network devices of this class.
     *
     * The caller has already initialized 'all_names' and might already have
     * added some names to it.  This function should not disturb any existing
     * names in 'all_names'.
     *
     * If this netdev class does not support enumeration, this may be a null
     * pointer. */
    int (*enumerate)(struct svec *all_names);

    /* Attempts to receive a packet from 'netdev' into the 'size' bytes in
     * 'buffer'.  If successful, returns the number of bytes in the received
     * packet, otherwise a negative errno value.  Returns -EAGAIN immediately
     * if no packet is ready to be received. */
    int (*recv)(struct netdev *netdev, void *buffer, size_t size);

    /* Registers with the poll loop to wake up from the next call to
     * poll_block() when a packet is ready to be received with netdev_recv() on
     * 'netdev'. */
    void (*recv_wait)(struct netdev *netdev);

    /* Discards all packets waiting to be received from 'netdev'. */
    int (*drain)(struct netdev *netdev);

    /* Sends the 'size'-byte packet in 'buffer' on 'netdev'.  Returns 0 if
     * successful, otherwise a positive errno value.  Returns EAGAIN without
     * blocking if the packet cannot be queued immediately.  Returns EMSGSIZE
     * if a partial packet was transmitted or if the packet is too big or too
     * small to transmit on the device.
     *
     * The caller retains ownership of 'buffer' in all cases.
     *
     * The network device is expected to maintain a packet transmission queue,
     * so that the caller does not ordinarily have to do additional queuing of
     * packets. */
    int (*send)(struct netdev *netdev, const void *buffer, size_t size);

    /* Registers with the poll loop to wake up from the next call to
     * poll_block() when the packet transmission queue for 'netdev' has
     * sufficient room to transmit a packet with netdev_send().
     *
     * The network device is expected to maintain a packet transmission queue,
     * so that the caller does not ordinarily have to do additional queuing of
     * packets.  Thus, this function is unlikely to ever be useful. */
    void (*send_wait)(struct netdev *netdev);

    /* Sets 'netdev''s Ethernet address to 'mac' */
    int (*set_etheraddr)(struct netdev *netdev, const uint8_t mac[6]);

    /* Retrieves 'netdev''s Ethernet address into 'mac'. */
    int (*get_etheraddr)(const struct netdev *netdev, uint8_t mac[6]);

    /* Retrieves 'netdev''s MTU into '*mtup'.
     *
     * The MTU is the maximum size of transmitted (and received) packets, in
     * bytes, not including the hardware header; thus, this is typically 1500
     * bytes for Ethernet devices.*/
    int (*get_mtu)(const struct netdev *, int *mtup);

    /* Returns the ifindex of 'netdev', if successful, as a positive number.
     * On failure, returns a negative errno value.
     *
     * The desired semantics of the ifindex value are a combination of those
     * specified by POSIX for if_nametoindex() and by SNMP for ifIndex.  An
     * ifindex value should be unique within a host and remain stable at least
     * until reboot.  SNMP says an ifindex "ranges between 1 and the value of
     * ifNumber" but many systems do not follow this rule anyhow. */
    int (*get_ifindex)(const struct netdev *);

    /* Sets 'carrier' to true if carrier is active (link light is on) on
     * 'netdev'. */
    int (*get_carrier)(const struct netdev *netdev, bool *carrier);

    /* Retrieves current device stats for 'netdev' into 'stats'.
     *
     * A network device that supports some statistics but not others, it should
     * set the values of the unsupported statistics to all-1-bits
     * (UINT64_MAX). */
    int (*get_stats)(const struct netdev *netdev, struct netdev_stats *stats);

    /* Stores the features supported by 'netdev' into each of '*current',
     * '*advertised', '*supported', and '*peer'.  Each value is a bitmap of
     * "enum ofp_port_features" bits, in host byte order. */
    int (*get_features)(struct netdev *netdev,
                        uint32_t *current, uint32_t *advertised,
                        uint32_t *supported, uint32_t *peer);

    /* Set the features advertised by 'netdev' to 'advertise', which is a
     * bitmap of "enum ofp_port_features" bits, in host byte order.
     *
     * This function may be set to null for a network device that does not
     * support configuring advertisements. */
    int (*set_advertisements)(struct netdev *, uint32_t advertise);

    /* If 'netdev' is a VLAN network device (e.g. one created with vconfig(8)),
     * sets '*vlan_vid' to the VLAN VID associated with that device and returns
     * 0.
     *
     * Returns ENOENT if 'netdev_name' is the name of a network device that is
     * not a VLAN device.
     *
     * This function should be set to null if it doesn't make any sense for
     * your network device (it probably doesn't). */
    int (*get_vlan_vid)(const struct netdev *netdev, int *vlan_vid);

    /* Attempts to set input rate limiting (policing) policy, such that up to
     * 'kbits_rate' kbps of traffic is accepted, with a maximum accumulative
     * burst size of 'kbits' kb.
     *
     * This function may be set to null if policing is not supported. */
    int (*set_policing)(struct netdev *netdev, unsigned int kbits_rate,
                        unsigned int kbits_burst);

    /* If 'netdev' has an assigned IPv4 address, sets '*address' to that
     * address and '*netmask' to the associated netmask.
     *
     * The following error values have well-defined meanings:
     *
     *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv4 address.
     *
     *   - EOPNOTSUPP: No IPv4 network stack attached to 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*get_in4)(const struct netdev *netdev, struct in_addr *address,
                   struct in_addr *netmask);

    /* Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
     * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*set_in4)(struct netdev *, struct in_addr addr, struct in_addr mask);

    /* If 'netdev' has an assigned IPv6 address, sets '*in6' to that address.
     *
     * The following error values have well-defined meanings:
     *
     *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv6 address.
     *
     *   - EOPNOTSUPP: No IPv6 network stack attached to 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*get_in6)(const struct netdev *netdev, struct in6_addr *in6);

    /* Adds 'router' as a default IP gateway for the TCP/IP stack that
     * corresponds to 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*add_router)(struct netdev *netdev, struct in_addr router);

    /* Looks up the next hop for 'host'.  If succesful, stores the next hop
     * gateway's address (0 if 'host' is on a directly connected network) in
     * '*next_hop' and a copy of the name of the device to reach 'host' in
     * '*netdev_name', and returns 0.  The caller is responsible for freeing
     * '*netdev_name' (by calling free()).
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*get_next_hop)(const struct in_addr *host, struct in_addr *next_hop,
                        char **netdev_name);

    /* Looks up the ARP table entry for 'ip' on 'netdev' and stores the
     * corresponding MAC address in 'mac'.  A return value of ENXIO, in
     * particular, indicates that there is no ARP table entry for 'ip' on
     * 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*arp_lookup)(const struct netdev *, uint32_t ip, uint8_t mac[6]);

    /* Retrieves the current set of flags on 'netdev' into '*old_flags'.  Then,
     * turns off the flags that are set to 1 in 'off' and turns on the flags
     * that are set to 1 in 'on'.  (No bit will be set to 1 in both 'off' and
     * 'on'; that is, off & on == 0.)
     *
     * This function may be invoked from a signal handler.  Therefore, it
     * should not do anything that is not signal-safe (such as logging). */
    int (*update_flags)(struct netdev *netdev, enum netdev_flags off,
                        enum netdev_flags on, enum netdev_flags *old_flags);

    /* Arranges for 'cb' to be called whenever one of the attributes of
     * 'netdev' changes and sets '*notifierp' to a newly created
     * netdev_notifier that represents this arrangement.  The created notifier
     * will have its 'netdev', 'cb', and 'aux' members set to the values of the
     * corresponding parameters. */
    int (*poll_add)(struct netdev *netdev,
                    void (*cb)(struct netdev_notifier *), void *aux,
                    struct netdev_notifier **notifierp);

    /* Cancels poll notification for 'notifier'. */
    void (*poll_remove)(struct netdev_notifier *notifier);
};

extern const struct netdev_class netdev_linux_class;
extern const struct netdev_class netdev_tap_class;

#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */
