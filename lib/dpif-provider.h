/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef DPIF_PROVIDER_H
#define DPIF_PROVIDER_H 1

/* Provider interface to dpifs, which provide an interface to an Open vSwitch
 * datapath.  A datapath is a collection of physical or virtual ports that are
 * exposed over OpenFlow as a single switch.  Datapaths and the collections of
 * ports that they contain may be fixed or dynamic. */

#include "openflow/openflow.h"
#include "dpif.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Open vSwitch datapath interface.
 *
 * This structure should be treated as opaque by dpif implementations. */
struct dpif {
    const struct dpif_class *dpif_class;
    char *base_name;
    char *full_name;
    uint8_t netflow_engine_type;
    uint8_t netflow_engine_id;
};

void dpif_init(struct dpif *, const struct dpif_class *, const char *name,
               uint8_t netflow_engine_type, uint8_t netflow_engine_id);
void dpif_uninit(struct dpif *dpif, bool close);

static inline void dpif_assert_class(const struct dpif *dpif,
                                     const struct dpif_class *dpif_class)
{
    ovs_assert(dpif->dpif_class == dpif_class);
}

struct dpif_flow_dump {
    struct dpif *dpif;
    bool terse;         /* If true, key/mask/actions may be omitted. */
};

static inline void
dpif_flow_dump_init(struct dpif_flow_dump *dump, const struct dpif *dpif)
{
    dump->dpif = CONST_CAST(struct dpif *, dpif);
}

struct dpif_flow_dump_thread {
    struct dpif *dpif;
};

static inline void
dpif_flow_dump_thread_init(struct dpif_flow_dump_thread *thread,
                           struct dpif_flow_dump *dump)
{
    thread->dpif = dump->dpif;
}

/* Datapath interface class structure, to be defined by each implementation of
 * a datapath interface.
 *
 * These functions return 0 if successful or a positive errno value on failure,
 * except where otherwise noted.
 *
 * These functions are expected to execute synchronously, that is, to block as
 * necessary to obtain a result.  Thus, they may not return EAGAIN or
 * EWOULDBLOCK or EINPROGRESS.  We may relax this requirement in the future if
 * and when we encounter performance problems. */
struct dpif_class {
    /* Type of dpif in this class, e.g. "system", "netdev", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed if no type is specified when opening a dpif. */
    const char *type;

    /* Called when the dpif provider is registered, typically at program
     * startup.  Returning an error from this function will prevent any
     * datapath with this class from being created.
     *
     * This function may be set to null if a datapath class needs no
     * initialization at registration time. */
    int (*init)(void);

    /* Enumerates the names of all known created datapaths (of class
     * 'dpif_class'), if possible, into 'all_dps'.  The caller has already
     * initialized 'all_dps' and other dpif classes might already have added
     * names to it.
     *
     * This is used by the vswitch at startup, so that it can delete any
     * datapaths that are not configured.
     *
     * Some kinds of datapaths might not be practically enumerable, in which
     * case this function may be a null pointer. */
    int (*enumerate)(struct sset *all_dps, const struct dpif_class *dpif_class);

    /* Returns the type to pass to netdev_open() when a dpif of class
     * 'dpif_class' has a port of type 'type', for a few special cases
     * when a netdev type differs from a port type.  For example, when
     * using the userspace datapath, a port of type "internal" needs to
     * be opened as "tap".
     *
     * Returns either 'type' itself or a string literal, which must not
     * be freed. */
    const char *(*port_open_type)(const struct dpif_class *dpif_class,
                                  const char *type);

    /* Attempts to open an existing dpif called 'name', if 'create' is false,
     * or to open an existing dpif or create a new one, if 'create' is true.
     *
     * 'dpif_class' is the class of dpif to open.
     *
     * If successful, stores a pointer to the new dpif in '*dpifp', which must
     * have class 'dpif_class'.  On failure there are no requirements on what
     * is stored in '*dpifp'. */
    int (*open)(const struct dpif_class *dpif_class,
                const char *name, bool create, struct dpif **dpifp);

    /* Closes 'dpif' and frees associated memory. */
    void (*close)(struct dpif *dpif);

    /* Attempts to destroy the dpif underlying 'dpif'.
     *
     * If successful, 'dpif' will not be used again except as an argument for
     * the 'close' member function. */
    int (*destroy)(struct dpif *dpif);

    /* Performs periodic work needed by 'dpif', if any is necessary.
     * Returns true if need to revalidate. */
    bool (*run)(struct dpif *dpif);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called for 'dpif'. */
    void (*wait)(struct dpif *dpif);

    /* Retrieves statistics for 'dpif' into 'stats'. */
    int (*get_stats)(const struct dpif *dpif, struct dpif_dp_stats *stats);

    /* Adds 'netdev' as a new port in 'dpif'.  If '*port_no' is not
     * UINT32_MAX, attempts to use that as the port's port number.
     *
     * If port is successfully added, sets '*port_no' to the new port's
     * port number.  Returns EBUSY if caller attempted to choose a port
     * number, and it was in use. */
    int (*port_add)(struct dpif *dpif, struct netdev *netdev,
                    odp_port_t *port_no);

    /* Removes port numbered 'port_no' from 'dpif'. */
    int (*port_del)(struct dpif *dpif, odp_port_t port_no);

    /* Queries 'dpif' for a port with the given 'port_no' or 'devname'.
     * If 'port' is not null, stores information about the port into
     * '*port' if successful.
     *
     * If 'port' is not null, the caller takes ownership of data in
     * 'port' and must free it with dpif_port_destroy() when it is no
     * longer needed. */
    int (*port_query_by_number)(const struct dpif *dpif, odp_port_t port_no,
                                struct dpif_port *port);
    int (*port_query_by_name)(const struct dpif *dpif, const char *devname,
                              struct dpif_port *port);

    /* Returns the Netlink PID value to supply in OVS_ACTION_ATTR_USERSPACE
     * actions as the OVS_USERSPACE_ATTR_PID attribute's value, for use in
     * flows whose packets arrived on port 'port_no'.  In the case where the
     * provider allocates multiple Netlink PIDs to a single port, it may use
     * 'hash' to spread load among them.  The caller need not use a particular
     * hash function; a 5-tuple hash is suitable.
     *
     * (The datapath implementation might use some different hash function for
     * distributing packets received via flow misses among PIDs.  This means
     * that packets received via flow misses might be reordered relative to
     * packets received via userspace actions.  This is not ordinarily a
     * problem.)
     *
     * A 'port_no' of UINT32_MAX should be treated as a special case.  The
     * implementation should return a reserved PID, not allocated to any port,
     * that the client may use for special purposes.
     *
     * The return value only needs to be meaningful when DPIF_UC_ACTION has
     * been enabled in the 'dpif''s listen mask, and it is allowed to change
     * when DPIF_UC_ACTION is disabled and then re-enabled.
     *
     * A dpif provider that doesn't have meaningful Netlink PIDs can use NULL
     * for this function.  This is equivalent to always returning 0. */
    uint32_t (*port_get_pid)(const struct dpif *dpif, odp_port_t port_no,
                             uint32_t hash);

    /* Attempts to begin dumping the ports in a dpif.  On success, returns 0
     * and initializes '*statep' with any data needed for iteration.  On
     * failure, returns a positive errno value. */
    int (*port_dump_start)(const struct dpif *dpif, void **statep);

    /* Attempts to retrieve another port from 'dpif' for 'state', which was
     * initialized by a successful call to the 'port_dump_start' function for
     * 'dpif'.  On success, stores a new dpif_port into 'port' and returns 0.
     * Returns EOF if the end of the port table has been reached, or a positive
     * errno value on error.  This function will not be called again once it
     * returns nonzero once for a given iteration (but the 'port_dump_done'
     * function will be called afterward).
     *
     * The dpif provider retains ownership of the data stored in 'port'.  It
     * must remain valid until at least the next call to 'port_dump_next' or
     * 'port_dump_done' for 'state'. */
    int (*port_dump_next)(const struct dpif *dpif, void *state,
                          struct dpif_port *port);

    /* Releases resources from 'dpif' for 'state', which was initialized by a
     * successful call to the 'port_dump_start' function for 'dpif'.  */
    int (*port_dump_done)(const struct dpif *dpif, void *state);

    /* Polls for changes in the set of ports in 'dpif'.  If the set of ports in
     * 'dpif' has changed, then this function should do one of the
     * following:
     *
     * - Preferably: store the name of the device that was added to or deleted
     *   from 'dpif' in '*devnamep' and return 0.  The caller is responsible
     *   for freeing '*devnamep' (with free()) when it no longer needs it.
     *
     * - Alternatively: return ENOBUFS, without indicating the device that was
     *   added or deleted.
     *
     * Occasional 'false positives', in which the function returns 0 while
     * indicating a device that was not actually added or deleted or returns
     * ENOBUFS without any change, are acceptable.
     *
     * If the set of ports in 'dpif' has not changed, returns EAGAIN.  May also
     * return other positive errno values to indicate that something has gone
     * wrong. */
    int (*port_poll)(const struct dpif *dpif, char **devnamep);

    /* Arranges for the poll loop to wake up when 'port_poll' will return a
     * value other than EAGAIN. */
    void (*port_poll_wait)(const struct dpif *dpif);

    /* Deletes all flows from 'dpif' and clears all of its queues of received
     * packets. */
    int (*flow_flush)(struct dpif *dpif);

    /* Flow dumping interface.
     *
     * This is the back-end for the flow dumping interface described in
     * dpif.h.  Please read the comments there first, because this code
     * closely follows it.
     *
     * 'flow_dump_create' and 'flow_dump_thread_create' must always return an
     * initialized and usable data structure and defer error return until
     * flow_dump_destroy().  This hasn't been a problem for the dpifs that
     * exist so far.
     *
     * 'flow_dump_create' and 'flow_dump_thread_create' must initialize the
     * structures that they return with dpif_flow_dump_init() and
     * dpif_flow_dump_thread_init(), respectively.
     *
     * If 'terse' is true, then only UID and statistics will
     * be returned in the dump. Otherwise, all fields will be returned. */
    struct dpif_flow_dump *(*flow_dump_create)(const struct dpif *dpif,
                                               bool terse);
    int (*flow_dump_destroy)(struct dpif_flow_dump *dump);

    struct dpif_flow_dump_thread *(*flow_dump_thread_create)(
        struct dpif_flow_dump *dump);
    void (*flow_dump_thread_destroy)(struct dpif_flow_dump_thread *thread);

    int (*flow_dump_next)(struct dpif_flow_dump_thread *thread,
                          struct dpif_flow *flows, int max_flows);

    /* Executes each of the 'n_ops' operations in 'ops' on 'dpif', in the order
     * in which they are specified, placing each operation's results in the
     * "output" members documented in comments and the 'error' member of each
     * dpif_op. */
    void (*operate)(struct dpif *dpif, struct dpif_op **ops, size_t n_ops);

    /* Enables or disables receiving packets with dpif_recv() for 'dpif'.
     * Turning packet receive off and then back on is allowed to change Netlink
     * PID assignments (see ->port_get_pid()).  The client is responsible for
     * updating flows as necessary if it does this. */
    int (*recv_set)(struct dpif *dpif, bool enable);

    /* Refreshes the poll loops and Netlink sockets associated to each port,
     * when the number of upcall handlers (upcall receiving thread) is changed
     * to 'n_handlers' and receiving packets for 'dpif' is enabled by
     * recv_set().
     *
     * Since multiple upcall handlers can read upcalls simultaneously from
     * 'dpif', each port can have multiple Netlink sockets, one per upcall
     * handler.  So, handlers_set() is responsible for the following tasks:
     *
     *    When receiving upcall is enabled, extends or creates the
     *    configuration to support:
     *
     *        - 'n_handlers' Netlink sockets for each port.
     *
     *        - 'n_handlers' poll loops, one for each upcall handler.
     *
     *        - registering the Netlink sockets for the same upcall handler to
     *          the corresponding poll loop.
     * */
    int (*handlers_set)(struct dpif *dpif, uint32_t n_handlers);

    /* If 'dpif' creates its own I/O polling threads, refreshes poll threads
     * configuration.  'n_rxqs' configures the number of rx_queues, which
     * are distributed among threads.  'cmask' configures the cpu mask
     * for setting the polling threads' cpu affinity. */
    int (*poll_threads_set)(struct dpif *dpif, unsigned int n_rxqs,
                            const char *cmask);

    /* Translates OpenFlow queue ID 'queue_id' (in host byte order) into a
     * priority value used for setting packet priority. */
    int (*queue_to_priority)(const struct dpif *dpif, uint32_t queue_id,
                             uint32_t *priority);

    /* Polls for an upcall from 'dpif' for an upcall handler.  Since there
     * can be multiple poll loops (see ->handlers_set()), 'handler_id' is
     * needed as index to identify the corresponding poll loop.  If
     * successful, stores the upcall into '*upcall', using 'buf' for
     * storage.  Should only be called if 'recv_set' has been used to enable
     * receiving packets from 'dpif'.
     *
     * The implementation should point 'upcall->key' and 'upcall->userdata'
     * (if any) into data in the caller-provided 'buf'.  The implementation may
     * also use 'buf' for storing the data of 'upcall->packet'.  If necessary
     * to make room, the implementation may reallocate the data in 'buf'.
     *
     * The caller owns the data of 'upcall->packet' and may modify it.  If
     * packet's headroom is exhausted as it is manipulated, 'upcall->packet'
     * will be reallocated.  This requires the data of 'upcall->packet' to be
     * released with ofpbuf_uninit() before 'upcall' is destroyed.  However,
     * when an error is returned, the 'upcall->packet' may be uninitialized
     * and should not be released.
     *
     * This function must not block.  If no upcall is pending when it is
     * called, it should return EAGAIN without blocking. */
    int (*recv)(struct dpif *dpif, uint32_t handler_id,
                struct dpif_upcall *upcall, struct ofpbuf *buf);

    /* Arranges for the poll loop for an upcall handler to wake up when 'dpif'
     * has a message queued to be received with the recv member functions.
     * Since there can be multiple poll loops (see ->handlers_set()),
     * 'handler_id' is needed as index to identify the corresponding poll loop.
     * */
    void (*recv_wait)(struct dpif *dpif, uint32_t handler_id);

    /* Throws away any queued upcalls that 'dpif' currently has ready to
     * return. */
    void (*recv_purge)(struct dpif *dpif);

    /* For datapaths that run in userspace (i.e. dpif-netdev), threads polling
     * for incoming packets can directly call upcall functions instead of
     * offloading packet processing to separate handler threads. Datapaths
     * that directly call upcall functions should use the functions below to
     * to register an upcall function and enable / disable upcalls.
     *
     * Registers an upcall callback function with 'dpif'. This is only used if
     * if 'dpif' directly executes upcall functions. 'aux' is passed to the
     * callback on invocation. */
    void (*register_upcall_cb)(struct dpif *, upcall_callback *, void *aux);

    /* Enables upcalls if 'dpif' directly executes upcall functions. */
    void (*enable_upcall)(struct dpif *);

    /* Disables upcalls if 'dpif' directly executes upcall functions. */
    void (*disable_upcall)(struct dpif *);

    /* Get datapath version. Caller is responsible for freeing the string
     * returned.  */
    char *(*get_datapath_version)(void);
};

extern const struct dpif_class dpif_netlink_class;
extern const struct dpif_class dpif_netdev_class;

#ifdef  __cplusplus
}
#endif

#endif /* dpif-provider.h */
