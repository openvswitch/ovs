/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
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

#include "connectivity.h"
#include "netdev.h"
#include "openvswitch/list.h"
#include "ovs-numa.h"
#include "packets.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "smap.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct netdev_tnl_build_header_params;
#define NETDEV_NUMA_UNSPEC OVS_NUMA_UNSPEC

/* A network device (e.g. an Ethernet device).
 *
 * Network device implementations may read these members but should not modify
 * them. */
struct netdev {
    /* The following do not change during the lifetime of a struct netdev. */
    char *name;                         /* Name of network device. */
    const struct netdev_class *netdev_class; /* Functions to control
                                                this device. */

    /* If this is 'true' the user did not specify a netdev_class when
     * opening this device, and therefore got assigned to the "system" class */
    bool auto_classified;

    /* If this is 'true', the user explicitly specified an MTU for this
     * netdev.  Otherwise, Open vSwitch is allowed to override it. */
    bool mtu_user_config;

    int ref_cnt;                        /* Times this devices was opened. */

    /* A sequence number which indicates changes in one of 'netdev''s
     * properties.   It must be nonzero so that users have a value which
     * they may use as a reset when tracking 'netdev'.
     *
     * Minimally, the sequence number is required to change whenever
     * 'netdev''s flags, features, ethernet address, or carrier changes. */
    uint64_t change_seq;

    /* A netdev provider might be unable to change some of the device's
     * parameter (n_rxq, mtu) when the device is in use.  In this case
     * the provider can notify the upper layer by calling
     * netdev_request_reconfigure().  The upper layer will react by stopping
     * the operations on the device and calling netdev_reconfigure() to allow
     * the configuration changes.  'last_reconfigure_seq' remembers the value
     * of 'reconfigure_seq' when the last reconfiguration happened. */
    struct seq *reconfigure_seq;
    uint64_t last_reconfigure_seq;

    /* The core netdev code initializes these at netdev construction and only
     * provide read-only access to its client.  Netdev implementations may
     * modify them. */
    int n_txq;
    int n_rxq;
    struct shash_node *node;            /* Pointer to element in global map. */
    struct ovs_list saved_flags_list; /* Contains "struct netdev_saved_flags". */
};

static inline void
netdev_change_seq_changed(const struct netdev *netdev_)
{
    struct netdev *netdev = CONST_CAST(struct netdev *, netdev_);
    seq_change(connectivity_seq_get());
    netdev->change_seq++;
    if (!netdev->change_seq) {
        netdev->change_seq++;
    }
}

static inline void
netdev_request_reconfigure(struct netdev *netdev)
{
    seq_change(netdev->reconfigure_seq);
}

const char *netdev_get_type(const struct netdev *);
const struct netdev_class *netdev_get_class(const struct netdev *);
const char *netdev_get_name(const struct netdev *);
struct netdev *netdev_from_name(const char *name);
void netdev_get_devices(const struct netdev_class *,
                        struct shash *device_list);
struct netdev **netdev_get_vports(size_t *size);

/* A data structure for capturing packets received by a network device.
 *
 * Network device implementations may read these members but should not modify
 * them.
 *
 * None of these members change during the lifetime of a struct netdev_rxq. */
struct netdev_rxq {
    struct netdev *netdev;      /* Owns a reference to the netdev. */
    int queue_id;
};

struct netdev *netdev_rxq_get_netdev(const struct netdev_rxq *);


struct netdev_flow_dump {
    struct netdev *netdev;
    odp_port_t port;
    bool terse;
    struct nl_dump *nl_dump;
};

/* Network device class structure, to be defined by each implementation of a
 * network device.
 *
 * These functions return 0 if successful or a positive errno value on failure,
 * except where otherwise noted.
 *
 *
 * Data Structures
 * ===============
 *
 * These functions work primarily with two different kinds of data structures:
 *
 *   - "struct netdev", which represents a network device.
 *
 *   - "struct netdev_rxq", which represents a handle for capturing packets
 *     received on a network device
 *
 * Each of these data structures contains all of the implementation-independent
 * generic state for the respective concept, called the "base" state.  None of
 * them contains any extra space for implementations to use.  Instead, each
 * implementation is expected to declare its own data structure that contains
 * an instance of the generic data structure plus additional
 * implementation-specific members, called the "derived" state.  The
 * implementation can use casts or (preferably) the CONTAINER_OF macro to
 * obtain access to derived state given only a pointer to the embedded generic
 * data structure.
 *
 *
 * Life Cycle
 * ==========
 *
 * Four stylized functions accompany each of these data structures:
 *
 *            "alloc"          "construct"        "destruct"       "dealloc"
 *            ------------   ----------------  ---------------  --------------
 * netdev      ->alloc        ->construct        ->destruct        ->dealloc
 * netdev_rxq  ->rxq_alloc    ->rxq_construct    ->rxq_destruct    ->rxq_dealloc
 *
 * Any instance of a given data structure goes through the following life
 * cycle:
 *
 *   1. The client calls the "alloc" function to obtain raw memory.  If "alloc"
 *      fails, skip all the other steps.
 *
 *   2. The client initializes all of the data structure's base state.  If this
 *      fails, skip to step 7.
 *
 *   3. The client calls the "construct" function.  The implementation
 *      initializes derived state.  It may refer to the already-initialized
 *      base state.  If "construct" fails, skip to step 6.
 *
 *   4. The data structure is now initialized and in use.
 *
 *   5. When the data structure is no longer needed, the client calls the
 *      "destruct" function.  The implementation uninitializes derived state.
 *      The base state has not been uninitialized yet, so the implementation
 *      may still refer to it.
 *
 *   6. The client uninitializes all of the data structure's base state.
 *
 *   7. The client calls the "dealloc" to free the raw memory.  The
 *      implementation must not refer to base or derived state in the data
 *      structure, because it has already been uninitialized.
 *
 * If netdev support multi-queue IO then netdev->construct should set initialize
 * netdev->n_rxq to number of queues.
 *
 * Each "alloc" function allocates and returns a new instance of the respective
 * data structure.  The "alloc" function is not given any information about the
 * use of the new data structure, so it cannot perform much initialization.
 * Its purpose is just to ensure that the new data structure has enough room
 * for base and derived state.  It may return a null pointer if memory is not
 * available, in which case none of the other functions is called.
 *
 * Each "construct" function initializes derived state in its respective data
 * structure.  When "construct" is called, all of the base state has already
 * been initialized, so the "construct" function may refer to it.  The
 * "construct" function is allowed to fail, in which case the client calls the
 * "dealloc" function (but not the "destruct" function).
 *
 * Each "destruct" function uninitializes and frees derived state in its
 * respective data structure.  When "destruct" is called, the base state has
 * not yet been uninitialized, so the "destruct" function may refer to it.  The
 * "destruct" function is not allowed to fail.
 *
 * Each "dealloc" function frees raw memory that was allocated by the
 * "alloc" function.  The memory's base and derived members might not have ever
 * been initialized (but if "construct" returned successfully, then it has been
 * "destruct"ed already).  The "dealloc" function is not allowed to fail.
 *
 *
 * Device Change Notification
 * ==========================
 *
 * Minimally, implementations are required to report changes to netdev flags,
 * features, ethernet address or carrier through connectivity_seq. Changes to
 * other properties are allowed to cause notification through this interface,
 * although implementations should try to avoid this. connectivity_seq_get()
 * can be used to acquire a reference to the struct seq. The interface is
 * described in detail in seq.h. */
struct netdev_class {
    /* Type of netdevs in this class, e.g. "system", "tap", "gre", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed if no type is specified when opening a netdev.
     * The "system" type corresponds to an existing network device on
     * the system. */
    const char *type;

    /* If 'true' then this netdev should be polled by PMD threads. */
    bool is_pmd;

/* ## ------------------- ## */
/* ## Top-Level Functions ## */
/* ## ------------------- ## */

    /* Called when the netdev provider is registered, typically at program
     * startup.  Returning an error from this function will prevent any network
     * device in this class from being opened.
     *
     * This function may be set to null if a network device class needs no
     * initialization at registration time. */
    int (*init)(void);

    /* Performs periodic work needed by netdevs of this class.  May be null if
     * no periodic work is necessary.
     *
     * 'netdev_class' points to the class.  It is useful in case the same
     * function is used to implement different classes. */
    void (*run)(const struct netdev_class *netdev_class);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called.  Implementations are additionally required to wake
     * whenever something changes in any of its netdevs which would cause their
     * ->change_seq() function to change its result.  May be null if nothing is
     * needed here.
     *
     * 'netdev_class' points to the class.  It is useful in case the same
     * function is used to implement different classes. */
    void (*wait)(const struct netdev_class *netdev_class);

/* ## ---------------- ## */
/* ## netdev Functions ## */
/* ## ---------------- ## */

    /* Life-cycle functions for a netdev.  See the large comment above on
     * struct netdev_class. */
    struct netdev *(*alloc)(void);
    int (*construct)(struct netdev *);
    void (*destruct)(struct netdev *);
    void (*dealloc)(struct netdev *);

    /* Fetches the device 'netdev''s configuration, storing it in 'args'.
     * The caller owns 'args' and pre-initializes it to an empty smap.
     *
     * If this netdev class does not have any configuration options, this may
     * be a null pointer. */
    int (*get_config)(const struct netdev *netdev, struct smap *args);

    /* Changes the device 'netdev''s configuration to 'args'.
     *
     * If this netdev class does not support configuration, this may be a null
     * pointer.
     *
     * If the return value is not zero (meaning that an error occurred),
     * the provider can allocate a string with an error message in '*errp'.
     * The caller has to call free on it. */
    int (*set_config)(struct netdev *netdev, const struct smap *args,
                      char **errp);

    /* Returns the tunnel configuration of 'netdev'.  If 'netdev' is
     * not a tunnel, returns null.
     *
     * If this function would always return null, it may be null instead. */
    const struct netdev_tunnel_config *
        (*get_tunnel_config)(const struct netdev *netdev);

    /* Build Tunnel header.  Ethernet and ip header parameters are passed to
     * tunnel implementation to build entire outer header for given flow. */
    int (*build_header)(const struct netdev *, struct ovs_action_push_tnl *data,
                        const struct netdev_tnl_build_header_params *params);

    /* build_header() can not build entire header for all packets for given
     * flow.  Push header is called for packet to build header specific to
     * a packet on actual transmit.  It uses partial header build by
     * build_header() which is passed as data. */
    void (*push_header)(const struct netdev *,
                        struct dp_packet *packet,
                        const struct ovs_action_push_tnl *data);

    /* Pop tunnel header from packet, build tunnel metadata and resize packet
     * for further processing.
     * Returns NULL in case of error or tunnel implementation queued packet for further
     * processing. */
    struct dp_packet * (*pop_header)(struct dp_packet *packet);

    /* Returns the id of the numa node the 'netdev' is on.  If there is no
     * such info, returns NETDEV_NUMA_UNSPEC. */
    int (*get_numa_id)(const struct netdev *netdev);

    /* Configures the number of tx queues of 'netdev'. Returns 0 if successful,
     * otherwise a positive errno value.
     *
     * 'n_txq' specifies the exact number of transmission queues to create.
     *
     * The caller will call netdev_reconfigure() (if necessary) before using
     * netdev_send() on any of the newly configured queues, giving the provider
     * a chance to adjust its settings.
     *
     * On error, the tx queue configuration is unchanged. */
    int (*set_tx_multiq)(struct netdev *netdev, unsigned int n_txq);

    /* Sends buffers on 'netdev'.
     * Returns 0 if successful (for every buffer), otherwise a positive errno
     * value.  Returns EAGAIN without blocking if one or more packets cannot be
     * queued immediately. Returns EMSGSIZE if a partial packet was transmitted
     * or if a packet is too big or too small to transmit on the device.
     *
     * If the function returns a non-zero value, some of the packets might have
     * been sent anyway.
     *
     * The caller transfers ownership of all the packets to the network
     * device, regardless of success.
     *
     * If 'concurrent_txq' is true, the caller may perform concurrent calls
     * to netdev_send() with the same 'qid'. The netdev provider is responsible
     * for making sure that these concurrent calls do not create a race
     * condition by using locking or other synchronization if required.
     *
     * The network device is expected to maintain one or more packet
     * transmission queues, so that the caller does not ordinarily have to
     * do additional queuing of packets.  'qid' specifies the queue to use
     * and can be ignored if the implementation does not support multiple
     * queues.
     *
     * May return EOPNOTSUPP if a network device does not implement packet
     * transmission through this interface.  This function may be set to null
     * if it would always return EOPNOTSUPP anyhow.  (This will prevent the
     * network device from being usefully used by the netdev-based "userspace
     * datapath".  It will also prevent the OVS implementation of bonding from
     * working properly over 'netdev'.) */
    int (*send)(struct netdev *netdev, int qid, struct dp_packet_batch *batch,
                bool concurrent_txq);

    /* Registers with the poll loop to wake up from the next call to
     * poll_block() when the packet transmission queue for 'netdev' has
     * sufficient room to transmit a packet with netdev_send().
     *
     * The network device is expected to maintain one or more packet
     * transmission queues, so that the caller does not ordinarily have to
     * do additional queuing of packets.  'qid' specifies the queue to use
     * and can be ignored if the implementation does not support multiple
     * queues.
     *
     * May be null if not needed, such as for a network device that does not
     * implement packet transmission through the 'send' member function. */
    void (*send_wait)(struct netdev *netdev, int qid);

    /* Sets 'netdev''s Ethernet address to 'mac' */
    int (*set_etheraddr)(struct netdev *netdev, const struct eth_addr mac);

    /* Retrieves 'netdev''s Ethernet address into 'mac'.
     *
     * This address will be advertised as 'netdev''s MAC address through the
     * OpenFlow protocol, among other uses. */
    int (*get_etheraddr)(const struct netdev *netdev, struct eth_addr *mac);

    /* Retrieves 'netdev''s MTU into '*mtup'.
     *
     * The MTU is the maximum size of transmitted (and received) packets, in
     * bytes, not including the hardware header; thus, this is typically 1500
     * bytes for Ethernet devices.
     *
     * If 'netdev' does not have an MTU (e.g. as some tunnels do not), then
     * this function should return EOPNOTSUPP.  This function may be set to
     * null if it would always return EOPNOTSUPP. */
    int (*get_mtu)(const struct netdev *netdev, int *mtup);

    /* Sets 'netdev''s MTU to 'mtu'.
     *
     * If 'netdev' does not have an MTU (e.g. as some tunnels do not), then
     * this function should return EOPNOTSUPP.  This function may be set to
     * null if it would always return EOPNOTSUPP. */
    int (*set_mtu)(struct netdev *netdev, int mtu);

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

    /* Returns the number of times 'netdev''s carrier has changed since being
     * initialized.
     *
     * If null, callers will assume the number of carrier resets is zero. */
    long long int (*get_carrier_resets)(const struct netdev *netdev);

    /* Forces ->get_carrier() to poll 'netdev''s MII registers for link status
     * instead of checking 'netdev''s carrier.  'netdev''s MII registers will
     * be polled once every 'interval' milliseconds.  If 'netdev' does not
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

    /* Retrieves current device custom stats for 'netdev' into 'custom_stats'.
     *
     * A network device should return only available statistics (if any).
     * If there are not statistics available, empty array should be
     * returned.
     *
     * The caller initializes 'custom_stats' before calling this function.
     * The caller takes ownership over allocated array of counters inside
     * structure netdev_custom_stats.
     * */
    int (*get_custom_stats)(const struct netdev *netdev,
                            struct netdev_custom_stats *custom_stats);

    /* Stores the features supported by 'netdev' into each of '*current',
     * '*advertised', '*supported', and '*peer'.  Each value is a bitmap of
     * NETDEV_F_* bits.
     *
     * This function may be set to null if it would always return EOPNOTSUPP.
     */
    int (*get_features)(const struct netdev *netdev,
                        enum netdev_features *current,
                        enum netdev_features *advertised,
                        enum netdev_features *supported,
                        enum netdev_features *peer);

    /* Set the features advertised by 'netdev' to 'advertise', which is a
     * set of NETDEV_F_* bits.
     *
     * This function may be set to null for a network device that does not
     * support configuring advertisements. */
    int (*set_advertisements)(struct netdev *netdev,
                              enum netdev_features advertise);

    /* Returns 'netdev''s configured packet_type mode.
     *
     * This function may be set to null if it would always return
     * NETDEV_PT_LEGACY_L2. */
    enum netdev_pt_mode (*get_pt_mode)(const struct netdev *netdev);

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
                   const char **typep, struct smap *details);

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
                   const char *type, const struct smap *details);

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
                     unsigned int queue_id, struct smap *details);

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
                     unsigned int queue_id, const struct smap *details);

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

    /* Attempts to begin dumping the queues in 'netdev'.  On success, returns 0
     * and initializes '*statep' with any data needed for iteration.  On
     * failure, returns a positive errno value.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int (*queue_dump_start)(const struct netdev *netdev, void **statep);

    /* Attempts to retrieve another queue from 'netdev' for 'state', which was
     * initialized by a successful call to the 'queue_dump_start' function for
     * 'netdev'.  On success, stores a queue ID into '*queue_id' and fills
     * 'details' with the configuration of the queue with that ID.  Returns EOF
     * if the last queue has been dumped, or a positive errno value on error.
     * This function will not be called again once it returns nonzero once for
     * a given iteration (but the 'queue_dump_done' function will be called
     * afterward).
     *
     * The caller initializes and clears 'details' before calling this
     * function.  The caller takes ownership of the string key-values pairs
     * added to 'details'.
     *
     * The returned contents of 'details' should be documented as valid for the
     * given 'type' in the "other_config" column in the "Queue" table in
     * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int (*queue_dump_next)(const struct netdev *netdev, void *state,
                           unsigned int *queue_id, struct smap *details);

    /* Releases resources from 'netdev' for 'state', which was initialized by a
     * successful call to the 'queue_dump_start' function for 'netdev'.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int (*queue_dump_done)(const struct netdev *netdev, void *state);

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

    /* Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
     * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*set_in4)(struct netdev *netdev, struct in_addr addr,
                   struct in_addr mask);

    /* Returns all assigned IP address to  'netdev' and returns 0.
     * API allocates array of address and masks and set it to
     * '*addr' and '*mask'.
     * Otherwise, returns a positive errno value and sets '*addr', '*mask
     * and '*n_addr' to NULL.
     *
     * The following error values have well-defined meanings:
     *
     *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv6 address.
     *
     *   - EOPNOTSUPP: No IPv6 network stack attached to 'netdev'.
     *
     * 'addr' may be null, in which case the address itself is not reported. */
    int (*get_addr_list)(const struct netdev *netdev, struct in6_addr **in,
                         struct in6_addr **mask, int *n_in6);

    /* Adds 'router' as a default IP gateway for the TCP/IP stack that
     * corresponds to 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*add_router)(struct netdev *netdev, struct in_addr router);

    /* Looks up the next hop for 'host' in the host's routing table.  If
     * successful, stores the next hop gateway's address (0 if 'host' is on a
     * directly connected network) in '*next_hop' and a copy of the name of the
     * device to reach 'host' in '*netdev_name', and returns 0.  The caller is
     * responsible for freeing '*netdev_name' (by calling free()).
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*get_next_hop)(const struct in_addr *host, struct in_addr *next_hop,
                        char **netdev_name);

    /* Retrieves driver information of the device.
     *
     * Populates 'smap' with key-value pairs representing the status of the
     * device.  'smap' is a set of key-value string pairs representing netdev
     * type specific information.  For more information see
     * ovs-vswitchd.conf.db(5).
     *
     * The caller is responsible for destroying 'smap' and its data.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*get_status)(const struct netdev *netdev, struct smap *smap);

    /* Looks up the ARP table entry for 'ip' on 'netdev' and stores the
     * corresponding MAC address in 'mac'.  A return value of ENXIO, in
     * particular, indicates that there is no ARP table entry for 'ip' on
     * 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int (*arp_lookup)(const struct netdev *netdev, ovs_be32 ip,
                      struct eth_addr *mac);

    /* Retrieves the current set of flags on 'netdev' into '*old_flags'.  Then,
     * turns off the flags that are set to 1 in 'off' and turns on the flags
     * that are set to 1 in 'on'.  (No bit will be set to 1 in both 'off' and
     * 'on'; that is, off & on == 0.)
     *
     * This function may be invoked from a signal handler.  Therefore, it
     * should not do anything that is not signal-safe (such as logging). */
    int (*update_flags)(struct netdev *netdev, enum netdev_flags off,
                        enum netdev_flags on, enum netdev_flags *old_flags);

    /* If the provider called netdev_request_reconfigure(), the upper layer
     * will eventually call this.  The provider can update the device
     * configuration knowing that the upper layer will not call rxq_recv() or
     * send() until this function returns.
     *
     * On error, the configuration is indeterminant and the device cannot be
     * used to send and receive packets until a successful configuration is
     * applied. */
    int (*reconfigure)(struct netdev *netdev);
/* ## -------------------- ## */
/* ## netdev_rxq Functions ## */
/* ## -------------------- ## */

/* If a particular netdev class does not support receiving packets, all these
 * function pointers must be NULL. */

    /* Life-cycle functions for a netdev_rxq.  See the large comment above on
     * struct netdev_class. */
    struct netdev_rxq *(*rxq_alloc)(void);
    int (*rxq_construct)(struct netdev_rxq *);
    void (*rxq_destruct)(struct netdev_rxq *);
    void (*rxq_dealloc)(struct netdev_rxq *);

    /* Attempts to receive a batch of packets from 'rx'.  In 'batch', the
     * caller supplies 'packets' as the pointer to the beginning of an array
     * of NETDEV_MAX_BURST pointers to dp_packet.  If successful, the
     * implementation stores pointers to up to NETDEV_MAX_BURST dp_packets into
     * the array, transferring ownership of the packets to the caller, stores
     * the number of received packets into 'count', and returns 0.
     *
     * The implementation does not necessarily initialize any non-data members
     * of 'packets' in 'batch'.  That is, the caller must initialize layer
     * pointers and metadata itself, if desired, e.g. with pkt_metadata_init()
     * and miniflow_extract().
     *
     * Implementations should allocate buffers with DP_NETDEV_HEADROOM bytes of
     * headroom.
     *
     * If the caller provides a non-NULL qfill pointer, the implementation
     * should return the number (zero or more) of remaining packets in the
     * queue after the reception the current batch, if it supports that,
     * or -ENOTSUP otherwise.
     *
     * Returns EAGAIN immediately if no packet is ready to be received or
     * another positive errno value if an error was encountered. */
    int (*rxq_recv)(struct netdev_rxq *rx, struct dp_packet_batch *batch,
                    int *qfill);

    /* Registers with the poll loop to wake up from the next call to
     * poll_block() when a packet is ready to be received with
     * netdev_rxq_recv() on 'rx'. */
    void (*rxq_wait)(struct netdev_rxq *rx);

    /* Discards all packets waiting to be received from 'rx'. */
    int (*rxq_drain)(struct netdev_rxq *rx);

    /* ## -------------------------------- ## */
    /* ## netdev flow offloading functions ## */
    /* ## -------------------------------- ## */

    /* If a particular netdev class does not support offloading flows,
     * all these function pointers must be NULL. */

    /* Flush all offloaded flows from a netdev.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*flow_flush)(struct netdev *);

    /* Flow dumping interface.
     *
     * This is the back-end for the flow dumping interface described in
     * dpif.h.  Please read the comments there first, because this code
     * closely follows it.
     *
     * On success returns 0 and allocates data, on failure returns
     * positive errno. */
    int (*flow_dump_create)(struct netdev *, struct netdev_flow_dump **dump);
    int (*flow_dump_destroy)(struct netdev_flow_dump *);

    /* Returns true if there are more flows to dump.
     * 'rbuffer' is used as a temporary buffer and needs to be pre allocated
     * by the caller.  While there are more flows the same 'rbuffer'
     * should be provided. 'wbuffer' is used to store dumped actions and needs
     * to be pre allocated by the caller. */
    bool (*flow_dump_next)(struct netdev_flow_dump *, struct match *,
                           struct nlattr **actions,
                           struct dpif_flow_stats *stats, ovs_u128 *ufid,
                           struct ofpbuf *rbuffer, struct ofpbuf *wbuffer);

    /* Offload the given flow on netdev.
     * To modify a flow, use the same ufid.
     * 'actions' are in netlink format, as with struct dpif_flow_put.
     * 'info' is extra info needed to offload the flow.
     * 'stats' is populated according to the rules set out in the description
     * above 'struct dpif_flow_put'.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*flow_put)(struct netdev *, struct match *, struct nlattr *actions,
                    size_t actions_len, const ovs_u128 *ufid,
                    struct offload_info *info, struct dpif_flow_stats *);

    /* Queries a flow specified by ufid on netdev.
     * Fills output buffer as 'wbuffer' in flow_dump_next, which
     * needs to be be pre allocated.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*flow_get)(struct netdev *, struct match *, struct nlattr **actions,
                    const ovs_u128 *ufid, struct dpif_flow_stats *,
                    struct ofpbuf *wbuffer);

    /* Delete a flow specified by ufid from netdev.
     * 'stats' is populated according to the rules set out in the description
     * above 'struct dpif_flow_del'.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*flow_del)(struct netdev *, const ovs_u128 *ufid,
                    struct dpif_flow_stats *);

    /* Initializies the netdev flow api.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*init_flow_api)(struct netdev *);
};

int netdev_register_provider(const struct netdev_class *);
int netdev_unregister_provider(const char *type);

#if defined(__FreeBSD__) || defined(__NetBSD__)
extern const struct netdev_class netdev_bsd_class;
#elif defined(_WIN32)
extern const struct netdev_class netdev_windows_class;
#else
extern const struct netdev_class netdev_linux_class;
#endif
extern const struct netdev_class netdev_internal_class;
extern const struct netdev_class netdev_tap_class;

#ifdef  __cplusplus
}
#endif

#define NO_OFFLOAD_API NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL

#endif /* netdev.h */
