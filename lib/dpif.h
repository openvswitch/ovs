/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

/*
 * dpif, the DataPath InterFace.
 *
 * In Open vSwitch terminology, a "datapath" is a flow-based software switch.
 * A datapath has no intelligence of its own.  Rather, it relies entirely on
 * its client to set up flows.  The datapath layer is core to the Open vSwitch
 * software switch: one could say, without much exaggeration, that everything
 * in ovs-vswitchd above dpif exists only to make the correct decisions
 * interacting with dpif.
 *
 * Typically, the client of a datapath is the software switch module in
 * "ovs-vswitchd", but other clients can be written.  The "ovs-dpctl" utility
 * is also a (simple) client.
 *
 *
 * Overview
 * ========
 *
 * The terms written in quotes below are defined in later sections.
 *
 * When a datapath "port" receives a packet, it extracts the headers (the
 * "flow").  If the datapath's "flow table" contains a "flow entry" matching
 * the packet, then it executes the "actions" in the flow entry and increments
 * the flow's statistics.  If there is no matching flow entry, the datapath
 * instead appends the packet to an "upcall" queue.
 *
 *
 * Ports
 * =====
 *
 * A datapath has a set of ports that are analogous to the ports on an Ethernet
 * switch.  At the datapath level, each port has the following information
 * associated with it:
 *
 *    - A name, a short string that must be unique within the host.  This is
 *      typically a name that would be familiar to the system administrator,
 *      e.g. "eth0" or "vif1.1", but it is otherwise arbitrary.
 *
 *    - A 32-bit port number that must be unique within the datapath but is
 *      otherwise arbitrary.  The port number is the most important identifier
 *      for a port in the datapath interface.
 *
 *    - A type, a short string that identifies the kind of port.  On a Linux
 *      host, typical types are "system" (for a network device such as eth0),
 *      "internal" (for a simulated port used to connect to the TCP/IP stack),
 *      and "gre" (for a GRE tunnel).
 *
 *    - A Netlink PID for each upcall reading thread (see "Upcall Queuing and
 *      Ordering" below).
 *
 * The dpif interface has functions for adding and deleting ports.  When a
 * datapath implements these (e.g. as the Linux and netdev datapaths do), then
 * Open vSwitch's ovs-vswitchd daemon can directly control what ports are used
 * for switching.  Some datapaths might not implement them, or implement them
 * with restrictions on the types of ports that can be added or removed
 * (e.g. on ESX), on systems where port membership can only be changed by some
 * external entity.
 *
 * Each datapath must have a port, sometimes called the "local port", whose
 * name is the same as the datapath itself, with port number 0.  The local port
 * cannot be deleted.
 *
 * Ports are available as "struct netdev"s.  To obtain a "struct netdev *" for
 * a port named 'name' with type 'port_type', in a datapath of type
 * 'datapath_type', call netdev_open(name, dpif_port_open_type(datapath_type,
 * port_type).  The netdev can be used to get and set important data related to
 * the port, such as:
 *
 *    - MTU (netdev_get_mtu(), netdev_set_mtu()).
 *
 *    - Ethernet address (netdev_get_etheraddr(), netdev_set_etheraddr()).
 *
 *    - Statistics such as the number of packets and bytes transmitted and
 *      received (netdev_get_stats()).
 *
 *    - Carrier status (netdev_get_carrier()).
 *
 *    - Speed (netdev_get_features()).
 *
 *    - QoS queue configuration (netdev_get_queue(), netdev_set_queue() and
 *      related functions.)
 *
 *    - Arbitrary port-specific configuration parameters (netdev_get_config(),
 *      netdev_set_config()).  An example of such a parameter is the IP
 *      endpoint for a GRE tunnel.
 *
 *
 * Flow Table
 * ==========
 *
 * The flow table is a collection of "flow entries".  Each flow entry contains:
 *
 *    - A "flow", that is, a summary of the headers in an Ethernet packet.  The
 *      flow must be unique within the flow table.  Flows are fine-grained
 *      entities that include L2, L3, and L4 headers.  A single TCP connection
 *      consists of two flows, one in each direction.
 *
 *      In Open vSwitch userspace, "struct flow" is the typical way to describe
 *      a flow, but the datapath interface uses a different data format to
 *      allow ABI forward- and backward-compatibility.  datapath/README
 *      describes the rationale and design.  Refer to OVS_KEY_ATTR_* and
 *      "struct ovs_key_*" in include/linux/openvswitch.h for details.
 *      lib/odp-util.h defines several functions for working with these flows.
 *
 *    - A "mask" that, for each bit in the flow, specifies whether the datapath
 *      should consider the corresponding flow bit when deciding whether a
 *      given packet matches the flow entry.  The original datapath design did
 *      not support matching: every flow entry was exact match.  With the
 *      addition of a mask, the interface supports datapaths with a spectrum of
 *      wildcard matching capabilities, from those that only support exact
 *      matches to those that support bitwise wildcarding on the entire flow
 *      key, as well as datapaths with capabilities somewhere in between.
 *
 *      Datapaths do not provide a way to query their wildcarding capabilities,
 *      nor is it expected that the client should attempt to probe for the
 *      details of their support.  Instead, a client installs flows with masks
 *      that wildcard as many bits as acceptable.  The datapath then actually
 *      wildcards as many of those bits as it can and changes the wildcard bits
 *      that it does not support into exact match bits.  A datapath that can
 *      wildcard any bit, for example, would install the supplied mask, an
 *      exact-match only datapath would install an exact-match mask regardless
 *      of what mask the client supplied, and a datapath in the middle of the
 *      spectrum would selectively change some wildcard bits into exact match
 *      bits.
 *
 *      Regardless of the requested or installed mask, the datapath retains the
 *      original flow supplied by the client.  (It does not, for example, "zero
 *      out" the wildcarded bits.)  This allows the client to unambiguously
 *      identify the flow entry in later flow table operations.
 *
 *      The flow table does not have priorities; that is, all flow entries have
 *      equal priority.  Detecting overlapping flow entries is expensive in
 *      general, so the datapath is not required to do it.  It is primarily the
 *      client's responsibility not to install flow entries whose flow and mask
 *      combinations overlap.
 *
 *    - A list of "actions" that tell the datapath what to do with packets
 *      within a flow.  Some examples of actions are OVS_ACTION_ATTR_OUTPUT,
 *      which transmits the packet out a port, and OVS_ACTION_ATTR_SET, which
 *      modifies packet headers.  Refer to OVS_ACTION_ATTR_* and "struct
 *      ovs_action_*" in include/linux/openvswitch.h for details.
 *      lib/odp-util.h defines several functions for working with datapath
 *      actions.
 *
 *      The actions list may be empty.  This indicates that nothing should be
 *      done to matching packets, that is, they should be dropped.
 *
 *      (In case you are familiar with OpenFlow, datapath actions are analogous
 *      to OpenFlow actions.)
 *
 *    - Statistics: the number of packets and bytes that the flow has
 *      processed, the last time that the flow processed a packet, and the
 *      union of all the TCP flags in packets processed by the flow.  (The
 *      latter is 0 if the flow is not a TCP flow.)
 *
 * The datapath's client manages the flow table, primarily in reaction to
 * "upcalls" (see below).
 *
 *
 * Upcalls
 * =======
 *
 * A datapath sometimes needs to notify its client that a packet was received.
 * The datapath mechanism to do this is called an "upcall".
 *
 * Upcalls are used in two situations:
 *
 *    - When a packet is received, but there is no matching flow entry in its
 *      flow table (a flow table "miss"), this causes an upcall of type
 *      DPIF_UC_MISS.  These are called "miss" upcalls.
 *
 *    - A datapath action of type OVS_ACTION_ATTR_USERSPACE causes an upcall of
 *      type DPIF_UC_ACTION.  These are called "action" upcalls.
 *
 * An upcall contains an entire packet.  There is no attempt to, e.g., copy
 * only as much of the packet as normally needed to make a forwarding decision.
 * Such an optimization is doable, but experimental prototypes showed it to be
 * of little benefit because an upcall typically contains the first packet of a
 * flow, which is usually short (e.g. a TCP SYN).  Also, the entire packet can
 * sometimes really be needed.
 *
 * After a client reads a given upcall, the datapath is finished with it, that
 * is, the datapath doesn't maintain any lingering state past that point.
 *
 * The latency from the time that a packet arrives at a port to the time that
 * it is received from dpif_recv() is critical in some benchmarks.  For
 * example, if this latency is 1 ms, then a netperf TCP_CRR test, which opens
 * and closes TCP connections one at a time as quickly as it can, cannot
 * possibly achieve more than 500 transactions per second, since every
 * connection consists of two flows with 1-ms latency to set up each one.
 *
 * To receive upcalls, a client has to enable them with dpif_recv_set().  A
 * datapath should generally support being opened multiple times (e.g. so that
 * one may run "ovs-dpctl show" or "ovs-dpctl dump-flows" while "ovs-vswitchd"
 * is also running) but need not support more than one of these clients
 * enabling upcalls at once.
 *
 *
 * Upcall Queuing and Ordering
 * ---------------------------
 *
 * The datapath's client reads upcalls one at a time by calling dpif_recv().
 * When more than one upcall is pending, the order in which the datapath
 * presents upcalls to its client is important.  The datapath's client does not
 * directly control this order, so the datapath implementer must take care
 * during design.
 *
 * The minimal behavior, suitable for initial testing of a datapath
 * implementation, is that all upcalls are appended to a single queue, which is
 * delivered to the client in order.
 *
 * The datapath should ensure that a high rate of upcalls from one particular
 * port cannot cause upcalls from other sources to be dropped or unreasonably
 * delayed.  Otherwise, one port conducting a port scan or otherwise initiating
 * high-rate traffic spanning many flows could suppress other traffic.
 * Ideally, the datapath should present upcalls from each port in a "round
 * robin" manner, to ensure fairness.
 *
 * The client has no control over "miss" upcalls and no insight into the
 * datapath's implementation, so the datapath is entirely responsible for
 * queuing and delivering them.  On the other hand, the datapath has
 * considerable freedom of implementation.  One good approach is to maintain a
 * separate queue for each port, to prevent any given port's upcalls from
 * interfering with other ports' upcalls.  If this is impractical, then another
 * reasonable choice is to maintain some fixed number of queues and assign each
 * port to one of them.  Ports assigned to the same queue can then interfere
 * with each other, but not with ports assigned to different queues.  Other
 * approaches are also possible.
 *
 * The client has some control over "action" upcalls: it can specify a 32-bit
 * "Netlink PID" as part of the action.  This terminology comes from the Linux
 * datapath implementation, which uses a protocol called Netlink in which a PID
 * designates a particular socket and the upcall data is delivered to the
 * socket's receive queue.  Generically, though, a Netlink PID identifies a
 * queue for upcalls.  The basic requirements on the datapath are:
 *
 *    - The datapath must provide a Netlink PID associated with each port.  The
 *      client can retrieve the PID with dpif_port_get_pid().
 *
 *    - The datapath must provide a "special" Netlink PID not associated with
 *      any port.  dpif_port_get_pid() also provides this PID.  (ovs-vswitchd
 *      uses this PID to queue special packets that must not be lost even if a
 *      port is otherwise busy, such as packets used for tunnel monitoring.)
 *
 * The minimal behavior of dpif_port_get_pid() and the treatment of the Netlink
 * PID in "action" upcalls is that dpif_port_get_pid() returns a constant value
 * and all upcalls are appended to a single queue.
 *
 * The preferred behavior is:
 *
 *    - Each port has a PID that identifies the queue used for "miss" upcalls
 *      on that port.  (Thus, if each port has its own queue for "miss"
 *      upcalls, then each port has a different Netlink PID.)
 *
 *    - "miss" upcalls for a given port and "action" upcalls that specify that
 *      port's Netlink PID add their upcalls to the same queue.  The upcalls
 *      are delivered to the datapath's client in the order that the packets
 *      were received, regardless of whether the upcalls are "miss" or "action"
 *      upcalls.
 *
 *    - Upcalls that specify the "special" Netlink PID are queued separately.
 *
 * Multiple threads may want to read upcalls simultaneously from a single
 * datapath.  To support multiple threads well, one extends the above preferred
 * behavior:
 *
 *    - Each port has multiple PIDs.  The datapath distributes "miss" upcalls
 *      across the PIDs, ensuring that a given flow is mapped in a stable way
 *      to a single PID.
 *
 *    - For "action" upcalls, the thread can specify its own Netlink PID or
 *      other threads' Netlink PID of the same port for offloading purpose
 *      (e.g. in a "round robin" manner).
 *
 *
 * Packet Format
 * =============
 *
 * The datapath interface works with packets in a particular form.  This is the
 * form taken by packets received via upcalls (i.e. by dpif_recv()).  Packets
 * supplied to the datapath for processing (i.e. to dpif_execute()) also take
 * this form.
 *
 * A VLAN tag is represented by an 802.1Q header.  If the layer below the
 * datapath interface uses another representation, then the datapath interface
 * must perform conversion.
 *
 * The datapath interface requires all packets to fit within the MTU.  Some
 * operating systems internally process packets larger than MTU, with features
 * such as TSO and UFO.  When such a packet passes through the datapath
 * interface, it must be broken into multiple MTU or smaller sized packets for
 * presentation as upcalls.  (This does not happen often, because an upcall
 * typically contains the first packet of a flow, which is usually short.)
 *
 * Some operating system TCP/IP stacks maintain packets in an unchecksummed or
 * partially checksummed state until transmission.  The datapath interface
 * requires all host-generated packets to be fully checksummed (e.g. IP and TCP
 * checksums must be correct).  On such an OS, the datapath interface must fill
 * in these checksums.
 *
 * Packets passed through the datapath interface must be at least 14 bytes
 * long, that is, they must have a complete Ethernet header.  They are not
 * required to be padded to the minimum Ethernet length.
 *
 *
 * Typical Usage
 * =============
 *
 * Typically, the client of a datapath begins by configuring the datapath with
 * a set of ports.  Afterward, the client runs in a loop polling for upcalls to
 * arrive.
 *
 * For each upcall received, the client examines the enclosed packet and
 * figures out what should be done with it.  For example, if the client
 * implements a MAC-learning switch, then it searches the forwarding database
 * for the packet's destination MAC and VLAN and determines the set of ports to
 * which it should be sent.  In any case, the client composes a set of datapath
 * actions to properly dispatch the packet and then directs the datapath to
 * execute those actions on the packet (e.g. with dpif_execute()).
 *
 * Most of the time, the actions that the client executed on the packet apply
 * to every packet with the same flow.  For example, the flow includes both
 * destination MAC and VLAN ID (and much more), so this is true for the
 * MAC-learning switch example above.  In such a case, the client can also
 * direct the datapath to treat any further packets in the flow in the same
 * way, using dpif_flow_put() to add a new flow entry.
 *
 * Other tasks the client might need to perform, in addition to reacting to
 * upcalls, include:
 *
 *    - Periodically polling flow statistics, perhaps to supply to its own
 *      clients.
 *
 *    - Deleting flow entries from the datapath that haven't been used
 *      recently, to save memory.
 *
 *    - Updating flow entries whose actions should change.  For example, if a
 *      MAC learning switch learns that a MAC has moved, then it must update
 *      the actions of flow entries that sent packets to the MAC at its old
 *      location.
 *
 *    - Adding and removing ports to achieve a new configuration.
 *
 *
 * Thread-safety
 * =============
 *
 * Most of the dpif functions are fully thread-safe: they may be called from
 * any number of threads on the same or different dpif objects.  The exceptions
 * are:
 *
 *    - dpif_port_poll() and dpif_port_poll_wait() are conditionally
 *      thread-safe: they may be called from different threads only on
 *      different dpif objects.
 *
 *    - dpif_flow_dump_next() is conditionally thread-safe: It may be called
 *      from different threads with the same 'struct dpif_flow_dump', but all
 *      other parameters must be different for each thread.
 *
 *    - dpif_flow_dump_done() is conditionally thread-safe: All threads that
 *      share the same 'struct dpif_flow_dump' must have finished using it.
 *      This function must then be called exactly once for a particular
 *      dpif_flow_dump to finish the corresponding flow dump operation.
 *
 *    - Functions that operate on 'struct dpif_port_dump' are conditionally
 *      thread-safe with respect to those objects.  That is, one may dump ports
 *      from any number of threads at once, but each thread must use its own
 *      struct dpif_port_dump.
 */
#ifndef DPIF_H
#define DPIF_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "netdev.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct dpif;
struct ds;
struct flow;
struct nlattr;
struct sset;
struct dpif_class;

int dp_register_provider(const struct dpif_class *);
int dp_unregister_provider(const char *type);
void dp_blacklist_provider(const char *type);
void dp_enumerate_types(struct sset *types);
const char *dpif_normalize_type(const char *);

int dp_enumerate_names(const char *type, struct sset *names);
void dp_parse_name(const char *datapath_name, char **name, char **type);

int dpif_open(const char *name, const char *type, struct dpif **);
int dpif_create(const char *name, const char *type, struct dpif **);
int dpif_create_and_open(const char *name, const char *type, struct dpif **);
void dpif_close(struct dpif *);

void dpif_run(struct dpif *);
void dpif_wait(struct dpif *);

const char *dpif_name(const struct dpif *);
const char *dpif_base_name(const struct dpif *);
const char *dpif_type(const struct dpif *);

int dpif_delete(struct dpif *);

/* Statistics for a dpif as a whole. */
struct dpif_dp_stats {
    uint64_t n_hit;             /* Number of flow table matches. */
    uint64_t n_missed;          /* Number of flow table misses. */
    uint64_t n_lost;            /* Number of misses not sent to userspace. */
    uint64_t n_flows;           /* Number of flows present. */
    uint64_t n_mask_hit;        /* Number of mega flow masks visited for
                                   flow table matches. */
    uint32_t n_masks;           /* Number of mega flow masks. */
};
int dpif_get_dp_stats(const struct dpif *, struct dpif_dp_stats *);


/* Port operations. */

const char *dpif_port_open_type(const char *datapath_type,
                                const char *port_type);
int dpif_port_add(struct dpif *, struct netdev *, odp_port_t *port_nop);
int dpif_port_del(struct dpif *, odp_port_t port_no);

/* A port within a datapath.
 *
 * 'name' and 'type' are suitable for passing to netdev_open(). */
struct dpif_port {
    char *name;                 /* Network device name, e.g. "eth0". */
    char *type;                 /* Network device type, e.g. "system". */
    odp_port_t port_no;         /* Port number within datapath. */
};
void dpif_port_clone(struct dpif_port *, const struct dpif_port *);
void dpif_port_destroy(struct dpif_port *);
bool dpif_port_exists(const struct dpif *dpif, const char *devname);
int dpif_port_query_by_number(const struct dpif *, odp_port_t port_no,
                              struct dpif_port *);
int dpif_port_query_by_name(const struct dpif *, const char *devname,
                            struct dpif_port *);
int dpif_port_get_name(struct dpif *, odp_port_t port_no,
                       char *name, size_t name_size);
uint32_t dpif_port_get_pid(const struct dpif *, odp_port_t port_no,
                           uint32_t hash);

struct dpif_port_dump {
    const struct dpif *dpif;
    int error;
    void *state;
};
void dpif_port_dump_start(struct dpif_port_dump *, const struct dpif *);
bool dpif_port_dump_next(struct dpif_port_dump *, struct dpif_port *);
int dpif_port_dump_done(struct dpif_port_dump *);

/* Iterates through each DPIF_PORT in DPIF, using DUMP as state.
 *
 * Arguments all have pointer type.
 *
 * If you break out of the loop, then you need to free the dump structure by
 * hand using dpif_port_dump_done(). */
#define DPIF_PORT_FOR_EACH(DPIF_PORT, DUMP, DPIF)   \
    for (dpif_port_dump_start(DUMP, DPIF);          \
         (dpif_port_dump_next(DUMP, DPIF_PORT)      \
          ? true                                    \
          : (dpif_port_dump_done(DUMP), false));    \
        )

int dpif_port_poll(const struct dpif *, char **devnamep);
void dpif_port_poll_wait(const struct dpif *);

/* Flow table operations. */

struct dpif_flow_stats {
    uint64_t n_packets;
    uint64_t n_bytes;
    long long int used;
    uint16_t tcp_flags;
};

void dpif_flow_stats_extract(const struct flow *, const struct ofpbuf *packet,
                             long long int used, struct dpif_flow_stats *);
void dpif_flow_stats_format(const struct dpif_flow_stats *, struct ds *);

enum dpif_flow_put_flags {
    DPIF_FP_CREATE = 1 << 0,    /* Allow creating a new flow. */
    DPIF_FP_MODIFY = 1 << 1,    /* Allow modifying an existing flow. */
    DPIF_FP_ZERO_STATS = 1 << 2 /* Zero the stats of an existing flow. */
};

int dpif_flow_flush(struct dpif *);
int dpif_flow_put(struct dpif *, enum dpif_flow_put_flags,
                  const struct nlattr *key, size_t key_len,
                  const struct nlattr *mask, size_t mask_len,
                  const struct nlattr *actions, size_t actions_len,
                  struct dpif_flow_stats *);
int dpif_flow_del(struct dpif *,
                  const struct nlattr *key, size_t key_len,
                  struct dpif_flow_stats *);
int dpif_flow_get(const struct dpif *,
                  const struct nlattr *key, size_t key_len,
                  struct ofpbuf **bufp,
                  struct nlattr **maskp, size_t *mask_len,
                  struct nlattr **actionsp, size_t *acts_len,
                  struct dpif_flow_stats *stats);

struct dpif_flow_dump {
    const struct dpif *dpif;
    void *iter;
};
void dpif_flow_dump_state_init(const struct dpif *, void **statep);
int dpif_flow_dump_start(struct dpif_flow_dump *, const struct dpif *);
bool dpif_flow_dump_next(struct dpif_flow_dump *, void *state,
                         const struct nlattr **key, size_t *key_len,
                         const struct nlattr **mask, size_t *mask_len,
                         const struct nlattr **actions, size_t *actions_len,
                         const struct dpif_flow_stats **);
bool dpif_flow_dump_next_may_destroy_keys(struct dpif_flow_dump *dump,
                                          void *state);
int dpif_flow_dump_done(struct dpif_flow_dump *);
void dpif_flow_dump_state_uninit(const struct dpif *, void *state);

/* Operation batching interface.
 *
 * Some datapaths are faster at performing N operations together than the same
 * N operations individually, hence an interface for batching.
 */

enum dpif_op_type {
    DPIF_OP_FLOW_PUT = 1,
    DPIF_OP_FLOW_DEL,
    DPIF_OP_EXECUTE,
};

struct dpif_flow_put {
    /* Input. */
    enum dpif_flow_put_flags flags; /* DPIF_FP_*. */
    const struct nlattr *key;       /* Flow to put. */
    size_t key_len;                 /* Length of 'key' in bytes. */
    const struct nlattr *mask;      /* Mask to put. */
    size_t mask_len;                /* Length of 'mask' in bytes. */
    const struct nlattr *actions;   /* Actions to perform on flow. */
    size_t actions_len;             /* Length of 'actions' in bytes. */

    /* Output. */
    struct dpif_flow_stats *stats;  /* Optional flow statistics. */
};

struct dpif_flow_del {
    /* Input. */
    const struct nlattr *key;       /* Flow to delete. */
    size_t key_len;                 /* Length of 'key' in bytes. */

    /* Output. */
    struct dpif_flow_stats *stats;  /* Optional flow statistics. */
};

struct dpif_execute {
    /* Raw support for execute passed along to the provider. */
    const struct nlattr *actions;   /* Actions to execute on packet. */
    size_t actions_len;             /* Length of 'actions' in bytes. */
    struct ofpbuf *packet;          /* Packet to execute. */
    struct pkt_metadata md;         /* Packet metadata. */

    /* Some dpif providers do not implement every action.  The Linux kernel
     * datapath, in particular, does not implement ARP field modification.
     *
     * If this member is set to true, the dpif layer executes in userspace all
     * of the actions that it can, and for OVS_ACTION_ATTR_OUTPUT and
     * OVS_ACTION_ATTR_USERSPACE actions it passes the packet through to the
     * dpif implementation. */
    bool needs_help;
};

int dpif_execute(struct dpif *, struct dpif_execute *);

struct dpif_op {
    enum dpif_op_type type;
    int error;
    union {
        struct dpif_flow_put flow_put;
        struct dpif_flow_del flow_del;
        struct dpif_execute execute;
    } u;
};

void dpif_operate(struct dpif *, struct dpif_op **ops, size_t n_ops);

/* Upcalls. */

enum dpif_upcall_type {
    DPIF_UC_MISS,               /* Miss in flow table. */
    DPIF_UC_ACTION,             /* OVS_ACTION_ATTR_USERSPACE action. */
    DPIF_N_UC_TYPES
};

const char *dpif_upcall_type_to_string(enum dpif_upcall_type);

/* A packet passed up from the datapath to userspace.
 *
 * The 'packet', 'key' and 'userdata' may point into data in a buffer
 * provided by the caller, so the buffer should be released only after the
 * upcall processing has been finished.
 *
 * While being processed, the 'packet' may be reallocated, so the packet must
 * be separately released with ofpbuf_uninit().
 */
struct dpif_upcall {
    /* All types. */
    enum dpif_upcall_type type;
    struct ofpbuf packet;       /* Packet data. */
    struct nlattr *key;         /* Flow key. */
    size_t key_len;             /* Length of 'key' in bytes. */

    /* DPIF_UC_ACTION only. */
    struct nlattr *userdata;    /* Argument to OVS_ACTION_ATTR_USERSPACE. */
};

int dpif_recv_set(struct dpif *, bool enable);
int dpif_handlers_set(struct dpif *, uint32_t n_handlers);
int dpif_recv(struct dpif *, uint32_t handler_id, struct dpif_upcall *,
              struct ofpbuf *);
void dpif_recv_purge(struct dpif *);
void dpif_recv_wait(struct dpif *, uint32_t handler_id);

/* Miscellaneous. */

void dpif_get_netflow_ids(const struct dpif *,
                          uint8_t *engine_type, uint8_t *engine_id);

int dpif_queue_to_priority(const struct dpif *, uint32_t queue_id,
                           uint32_t *priority);

#ifdef  __cplusplus
}
#endif

#endif /* dpif.h */
