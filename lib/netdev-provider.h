/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

/* A network device (e.g. an Ethernet device).
 *
 * This structure should be treated as opaque by network device
 * implementations. */
struct netdev_dev {
    char *name;                         /* Name of network device. */
    const struct netdev_class *netdev_class; /* Functions to control
                                                this device. */
    int ref_cnt;                        /* Times this devices was opened. */
    struct shash_node *node;            /* Pointer to element in global map. */
    struct shash args;                  /* Argument list from last config. */
};

void netdev_dev_init(struct netdev_dev *, const char *name,
                     const struct shash *args,
                     const struct netdev_class *);
void netdev_dev_uninit(struct netdev_dev *, bool destroy);
const char *netdev_dev_get_type(const struct netdev_dev *);
const struct netdev_class *netdev_dev_get_class(const struct netdev_dev *);
const char *netdev_dev_get_name(const struct netdev_dev *);
struct netdev_dev *netdev_dev_from_name(const char *name);
void netdev_dev_get_devices(const struct netdev_class *,
                            struct shash *device_list);
bool netdev_dev_args_equal(const struct netdev_dev *netdev_dev,
                           const struct shash *args);

static inline void netdev_dev_assert_class(const struct netdev_dev *netdev_dev,
                                           const struct netdev_class *class_)
{
    assert(netdev_dev->netdev_class == class_);
}

/* A instance of an open network device.
 *
 * This structure should be treated as opaque by network device
 * implementations. */
struct netdev {
    struct netdev_dev *netdev_dev;   /* Parent netdev_dev. */
    struct list node;                /* Element in global list. */

    enum netdev_flags save_flags;    /* Initial device flags. */
    enum netdev_flags changed_flags; /* Flags that we changed. */
};

void netdev_init(struct netdev *, struct netdev_dev *);
void netdev_uninit(struct netdev *, bool close);
struct netdev_dev *netdev_get_dev(const struct netdev *);

static inline void netdev_assert_class(const struct netdev *netdev,
                                       const struct netdev_class *netdev_class)
{
    netdev_dev_assert_class(netdev_get_dev(netdev), netdev_class);
}

/* Network device class structure, to be defined by each implementation of a
 * network device.
 *
 * These functions return 0 if successful or a positive errno value on failure,
 * except where otherwise noted. */
struct netdev_class {
    /* Type of netdevs in this class, e.g. "system", "tap", "gre", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed if no type is specified when opening a netdev.
     * The "system" type corresponds to an existing network device on
     * the system. */
    const char *type;

    /* Called when the netdev provider is registered, typically at program
     * startup.  Returning an error from this function will prevent any network
     * device in this class from being opened.
     *
     * This function may be set to null if a network device class needs no
     * initialization at registration time. */
    int (*init)(void);

    /* Performs periodic work needed by netdevs of this class.  May be null if
     * no periodic work is necessary. */
    void (*run)(void);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called.  Implementations are additionally required to wake
     * whenever something changes in any of its netdevs which would cause their
     * ->change_seq() function to change its result.  May be null if nothing is
     * needed here. */
    void (*wait)(void);

    /* Attempts to create a network device named 'name' with initial 'args' in
     * 'netdev_class'.  On success sets 'netdev_devp' to the newly created
     * device. */
    int (*create)(const struct netdev_class *netdev_class, const char *name,
                  const struct shash *args, struct netdev_dev **netdev_devp);

    /* Destroys 'netdev_dev'.
     *
     * Netdev devices maintain a reference count that is incremented on
     * netdev_open() and decremented on netdev_close().  If 'netdev_dev'
     * has a non-zero reference count, then this function will not be
     * called. */
    void (*destroy)(struct netdev_dev *netdev_dev);

    /* Changes the device 'netdev_dev''s configuration to 'args'.
     *
     * If this netdev class does not support reconfiguring a netdev
     * device, this may be a null pointer.
     */
    int (*set_config)(struct netdev_dev *netdev_dev, const struct shash *args);

    /* Returns true if 'args' is equivalent to the "args" field in
     * 'netdev_dev', otherwise false.
     *
     * If no special processing needs to be done beyond a simple
     * shash comparison, this may be a null pointer.
     */
    bool (*config_equal)(const struct netdev_dev *netdev_dev,
                         const struct shash *args);

    /* Attempts to open a network device.  On success, sets 'netdevp'
     * to the new network device.
     *
     * 'ethertype' may be a 16-bit Ethernet protocol value in host byte order
     * to capture frames of that type received on the device.  It may also be
     * one of the 'enum netdev_pseudo_ethertype' values to receive frames in
     * one of those categories. */
    int (*open)(struct netdev_dev *netdev_dev, int ethertype,
                struct netdev **netdevp);

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
    int (*enumerate)(struct sset *all_names);

    /* Attempts to receive a packet from 'netdev' into the 'size' bytes in
     * 'buffer'.  If successful, returns the number of bytes in the received
     * packet, otherwise a negative errno value.  Returns -EAGAIN immediately
     * if no packet is ready to be received.
     *
     * May return -EOPNOTSUPP if a network device does not implement packet
     * reception through this interface.  This function may be set to null if
     * it would always return -EOPNOTSUPP anyhow.  (This will prevent the
     * network device from being usefully used by the netdev-based "userspace
     * datapath".) */
    int (*recv)(struct netdev *netdev, void *buffer, size_t size);

    /* Registers with the poll loop to wake up from the next call to
     * poll_block() when a packet is ready to be received with netdev_recv() on
     * 'netdev'.
     *
     * May be null if not needed, such as for a network device that does not
     * implement packet reception through the 'recv' member function. */
    void (*recv_wait)(struct netdev *netdev);

    /* Discards all packets waiting to be received from 'netdev'.
     *
     * May be null if not needed, such as for a network device that does not
     * implement packet reception through the 'recv' member function. */
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
     * packets.
     *
     * May return EOPNOTSUPP if a network device does not implement packet
     * transmission through this interface.  This function may be set to null
     * if it would always return EOPNOTSUPP anyhow.  (This will prevent the
     * network device from being usefully used by the netdev-based "userspace
     * datapath".  It will also prevent the OVS implementation of bonding from
     * working properly over 'netdev'.) */
    int (*send)(struct netdev *netdev, const void *buffer, size_t size);

    /* Registers with the poll loop to wake up from the next call to
     * poll_block() when the packet transmission queue for 'netdev' has
     * sufficient room to transmit a packet with netdev_send().
     *
     * The network device is expected to maintain a packet transmission queue,
     * so that the caller does not ordinarily have to do additional queuing of
     * packets.  Thus, this function is unlikely to ever be useful.
     *
     * May be null if not needed, such as for a network device that does not
     * implement packet transmission through the 'send' member function. */
    void (*send_wait)(struct netdev *netdev);

    /* Sets 'netdev''s Ethernet address to 'mac' */
    int (*set_etheraddr)(struct netdev *netdev, const uint8_t mac[6]);

    /* Retrieves 'netdev''s Ethernet address into 'mac'. */
    int (*get_etheraddr)(const struct netdev *netdev, uint8_t mac[6]);

    /* Retrieves 'netdev''s MTU into '*mtup'.
     *
     * The MTU is the maximum size of transmitted (and received) packets, in
     * bytes, not including the hardware header; thus, this is typically 1500
     * bytes for Ethernet devices.
     *
     * If 'netdev' does not have an MTU (e.g. as some tunnels do not), then
     * this function should set '*mtup' to INT_MAX. */
    int (*get_mtu)(const struct netdev *netdev, int *mtup);

    /* Returns the ifindex of 'netdev', if successful, as a positive number.
     * On failure, returns a negative errno value.
     *
     * The desired semantics of the ifindex value are a combination of those
     * specified by POSIX for if_nametoindex() and by SNMP for ifIndex.  An
     * ifindex value should be unique within a host and remain stable at least
     * until reboot.  SNMP says an ifindex "ranges between 1 and the value of
     * ifNumber" but many systems do not follow this rule anyhow.
     *
     * This function may be set to null if it would always return -EOPNOTSUPP.
     */
    int (*get_ifindex)(const struct netdev *netdev);

    /* Sets 'carrier' to true if carrier is active (link light is on) on
     * 'netdev'.
     *
     * May be null if device does not provide carrier status (will be always
     * up as long as device is up).
     */
    int (*get_carrier)(const struct netdev *netdev, bool *carrier);

    /* Forces ->get_carrier() to poll 'netdev''s MII registers for link status
     * instead of checking 'netdev''s carrier.  'netdev''s MII registers will
     * be polled once ever 'interval' milliseconds.  If 'netdev' does not
     * support MII, another method may be used as a fallback.  If 'interval' is
     * less than or equal to zero, reverts ->get_carrier() to its normal
     * behavior.
     *
     * Most network devices won't support this feature and will set this
     * function pointer to NULL, which is equivalent to returning EOPNOTSUPP.
     */
    int (*set_miimon_interval)(struct netdev *netdev, long long int interval);

    /* Retrieves current device stats for 'netdev' into 'stats'.
     *
     * A network device that supports some statistics but not others, it should
     * set the values of the unsupported statistics to all-1-bits
     * (UINT64_MAX). */
    int (*get_stats)(const struct netdev *netdev, struct netdev_stats *);

    /* Sets the device stats for 'netdev' to 'stats'.
     *
     * Most network devices won't support this feature and will set this
     * function pointer to NULL, which is equivalent to returning EOPNOTSUPP.
     *
     * Some network devices might only allow setting their stats to 0. */
    int (*set_stats)(struct netdev *netdev, const struct netdev_stats *);

    /* Stores the features supported by 'netdev' into each of '*current',
     * '*advertised', '*supported', and '*peer'.  Each value is a bitmap of
     * "enum ofp_port_features" bits, in host byte order.
     *
     * This function may be set to null if it would always return EOPNOTSUPP.
     */
    int (*get_features)(const struct netdev *netdev,
                        uint32_t *current, uint32_t *advertised,
                        uint32_t *supported, uint32_t *peer);

    /* Set the features advertised by 'netdev' to 'advertise', which is a
     * bitmap of "enum ofp_port_features" bits, in host byte order.
     *
     * This function may be set to null for a network device that does not
     * support configuring advertisements. */
    int (*set_advertisements)(struct netdev *netdev, uint32_t advertise);

    /* If 'netdev' is a VLAN network device (e.g. one created with vconfig(8)),
     * sets '*vlan_vid' to the VLAN VID associated with that device and returns
     * 0.
     *
     * Returns ENOENT if 'netdev' is a network device that is not a
     * VLAN device.
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

    /* Adds to 'types' all of the forms of QoS supported by 'netdev', or leaves
     * it empty if 'netdev' does not support QoS.  Any names added to 'types'
     * should be documented as valid for the "type" column in the "QoS" table
     * in vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
     *
     * Every network device must support disabling QoS with a type of "", but
     * this function must not add "" to 'types'.
     *
     * The caller is responsible for initializing 'types' (e.g. with
     * sset_init()) before calling this function.  The caller retains ownership
     * of 'types'.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int (*get_qos_types)(const struct netdev *netdev, struct sset *types);

    /* Queries 'netdev' for its capabilities regarding the specified 'type' of
     * QoS.  On success, initializes 'caps' with the QoS capabilities.
     *
     * Should return EOPNOTSUPP if 'netdev' does not support 'type'.  May be
     * NULL if 'netdev' does not support QoS at all. */
    int (*get_qos_capabilities)(const struct netdev *netdev,
                                const char *type,
                                struct netdev_qos_capabilities *caps);

    /* Queries 'netdev' about its currently configured form of QoS.  If
     * successful, stores the name of the current form of QoS into '*typep'
     * and any details of configuration as string key-value pairs in
     * 'details'.
     *
     * A '*typep' of "" indicates that QoS is currently disabled on 'netdev'.
     *
     * The caller initializes 'details' before calling this function.  The
     * caller takes ownership of the string key-values pairs added to
     * 'details'.
     *
     * The netdev retains ownership of '*typep'.
     *
     * '*typep' will be one of the types returned by netdev_get_qos_types() for
     * 'netdev'.  The contents of 'details' should be documented as valid for
     * '*typep' in the "other_config" column in the "QoS" table in
     * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int (*get_qos)(const struct netdev *netdev,
                   const char **typep, struct shash *details);

    /* Attempts to reconfigure QoS on 'netdev', changing the form of QoS to
     * 'type' with details of configuration from 'details'.
     *
     * On error, the previous QoS configuration is retained.
     *
     * When this function changes the type of QoS (not just 'details'), this
     * also resets all queue configuration for 'netdev' to their defaults
     * (which depend on the specific type of QoS).  Otherwise, the queue
     * configuration for 'netdev' is unchanged.
     *
     * 'type' should be "" (to disable QoS) or one of the types returned by
     * netdev_get_qos_types() for 'netdev'.  The contents of 'details' should
     * be documented as valid for the given 'type' in the "other_config" column
     * in the "QoS" table in vswitchd/vswitch.xml (which is built as
     * ovs-vswitchd.conf.db(8)).
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int (*set_qos)(struct netdev *netdev,
                   const char *type, const struct shash *details);

    /* Queries 'netdev' for information about the queue numbered 'queue_id'.
     * If successful, adds that information as string key-value pairs to
     * 'details'.  Returns 0 if successful, otherwise a positive errno value.
     *
     * Should return EINVAL if 'queue_id' is greater than or equal to the
     * number of supported queues (as reported in the 'n_queues' member of
     * struct netdev_qos_capabilities by 'get_qos_capabilities').
     *
     * The caller initializes 'details' before calling this function.  The
     * caller takes ownership of the string key-values pairs added to
     * 'details'.
     *
     * The returned contents of 'details' should be documented as valid for the
     * given 'type' in the "other_config" column in the "Queue" table in
     * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
     */
    int (*get_queue)(const struct netdev *netdev,
                     unsigned int queue_id, struct shash *details);

    /* Configures the queue numbered 'queue_id' on 'netdev' with the key-value
     * string pairs in 'details'.  The contents of 'details' should be
     * documented as valid for the given 'type' in the "other_config" column in
     * the "Queue" table in vswitchd/vswitch.xml (which is built as
     * ovs-vswitchd.conf.db(8)).  Returns 0 if successful, otherwise a positive
     * errno value.  On failure, the given queue's configuration should be
     * unmodified.
     *
     * Should return EINVAL if 'queue_id' is greater than or equal to the
     * number of supported queues (as reported in the 'n_queues' member of
     * struct netdev_qos_capabilities by 'get_qos_capabilities'), or if
     * 'details' is invalid for the type of queue.
     *
     * This function does not modify 'details', and the caller retains
     * ownership of it.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int (*set_queue)(struct netdev *netdev,
                     unsigned int queue_id, const struct shash *details);

    /* Attempts to delete the queue numbered 'queue_id' from 'netdev'.
     *
     * Should return EINVAL if 'queue_id' is greater than or equal to the
     * number of supported queues (as reported in the 'n_queues' member of
     * struct netdev_qos_capabilities by 'get_qos_capabilities').  Should
     * return EOPNOTSUPP if 'queue_id' is valid but may not be deleted (e.g. if
     * 'netdev' has a fixed set of queues with the current QoS mode).
     *
     * May be NULL if 'netdev' does not support QoS at all, or if all of its
     * QoS modes have fixed sets of queues. */
    int (*delete_queue)(struct netdev *netdev, unsigned int queue_id);

    /* Obtains statistics about 'queue_id' on 'netdev'.  Fills 'stats' with the
     * queue's statistics.  May set individual members of 'stats' to all-1-bits
     * if the statistic is unavailable.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int (*get_queue_stats)(const struct netdev *netdev, unsigned int queue_id,
                           struct netdev_queue_stats *stats);

    /* Iterates over all of 'netdev''s queues, calling 'cb' with the queue's
     * ID, its configuration, and the 'aux' specified by the caller.  The order
     * of iteration is unspecified, but (when successful) each queue is visited
     * exactly once.
     *
     * 'cb' will not modify or free the 'details' argument passed in. */
    int (*dump_queues)(const struct netdev *netdev,
                       void (*cb)(unsigned int queue_id,
                                  const struct shash *details,
                                  void *aux),
                       void *aux);

    /* Iterates over all of 'netdev''s queues, calling 'cb' with the queue's
     * ID, its statistics, and the 'aux' specified by the caller.  The order of
     * iteration is unspecified, but (when successful) each queue must be
     * visited exactly once.
     *
     * 'cb' will not modify or free the statistics passed in. */
    int (*dump_queue_stats)(const struct netdev *netdev,
                            void (*cb)(unsigned int queue_id,
                                       struct netdev_queue_stats *,
                                       void *aux),
                            void *aux);

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
    int (*set_in4)(struct netdev *netdev, struct in_addr addr,
                   struct in_addr mask);

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

    /* Retrieves the status of the device.
     *
     * Populates 'sh' with key-value pairs representing the status of the
     * device.  A device's status is a set of key-value string pairs
     * representing netdev type specific information.  For more information see
     * ovs-vswitchd.conf.db(5).
     *
     * The data of 'sh' are heap allocated strings which the caller is
     * responsible for deallocating.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*get_status)(const struct netdev *netdev, struct shash *sh);

    /* Looks up the ARP table entry for 'ip' on 'netdev' and stores the
     * corresponding MAC address in 'mac'.  A return value of ENXIO, in
     * particular, indicates that there is no ARP table entry for 'ip' on
     * 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*arp_lookup)(const struct netdev *netdev, ovs_be32 ip,
                      uint8_t mac[6]);

    /* Retrieves the current set of flags on 'netdev' into '*old_flags'.
     * Then, turns off the flags that are set to 1 in 'off' and turns on the
     * flags that are set to 1 in 'on'.  (No bit will be set to 1 in both 'off'
     * and 'on'; that is, off & on == 0.)
     *
     * This function may be invoked from a signal handler.  Therefore, it
     * should not do anything that is not signal-safe (such as logging). */
    int (*update_flags)(struct netdev *netdev, enum netdev_flags off,
                        enum netdev_flags on, enum netdev_flags *old_flags);

    /* Returns a sequence number which indicates changes in one of 'netdev''s
     * properties.  The returned sequence number must be nonzero so that
     * callers have a value which they may use as a reset when tracking
     * 'netdev'.
     *
     * Minimally, the returned sequence number is required to change whenever
     * 'netdev''s flags, features, ethernet address, or carrier changes.  The
     * returned sequence number is allowed to change even when 'netdev' doesn't
     * change, although implementations should try to avoid this. */
    unsigned int (*change_seq)(const struct netdev *netdev);
};

int netdev_register_provider(const struct netdev_class *);
int netdev_unregister_provider(const char *type);
const struct netdev_class *netdev_lookup_provider(const char *type);

extern const struct netdev_class netdev_linux_class;
extern const struct netdev_class netdev_internal_class;
extern const struct netdev_class netdev_tap_class;

#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */
