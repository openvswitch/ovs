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

#ifndef DPIF_PROVIDER_H
#define DPIF_PROVIDER_H 1

/* Provider interface to dpifs, which provide an interface to an Open vSwitch
 * datapath.  A datapath is a collection of physical or virtual ports that are
 * exposed over OpenFlow as a single switch.  Datapaths and the collections of
 * ports that they contain may be fixed or dynamic. */

#include <assert.h>
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
    assert(dpif->dpif_class == dpif_class);
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

    /* Performs periodic work needed by dpifs of this class, if any is
     * necessary. */
    void (*run)(void);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called. */
    void (*wait)(void);

    /* Enumerates the names of all known created datapaths, if possible, into
     * 'all_dps'.  The caller has already initialized 'all_dps' and other dpif
     * classes might already have added names to it.
     *
     * This is used by the vswitch at startup, so that it can delete any
     * datapaths that are not configured.
     *
     * Some kinds of datapaths might not be practically enumerable, in which
     * case this function may be a null pointer. */
    int (*enumerate)(struct svec *all_dps);

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

    /* Enumerates all names that may be used to open 'dpif' into 'all_names'.
     * The Linux datapath, for example, supports opening a datapath both by
     * number, e.g. "dp0", and by the name of the datapath's local port.  For
     * some datapaths, this might be an infinite set (e.g. in a file name,
     * slashes may be duplicated any number of times), in which case only the
     * names most likely to be used should be enumerated.
     *
     * The caller has already initialized 'all_names' and might already have
     * added some names to it.  This function should not disturb any existing
     * names in 'all_names'.
     *
     * If a datapath class does not support multiple names for a datapath, this
     * function may be a null pointer.
     *
     * This is used by the vswitch at startup, */
    int (*get_all_names)(const struct dpif *dpif, struct svec *all_names);

    /* Attempts to destroy the dpif underlying 'dpif'.
     *
     * If successful, 'dpif' will not be used again except as an argument for
     * the 'close' member function. */
    int (*destroy)(struct dpif *dpif);

    /* Retrieves statistics for 'dpif' into 'stats'. */
    int (*get_stats)(const struct dpif *dpif, struct odp_stats *stats);

    /* Retrieves 'dpif''s current treatment of IP fragments into '*drop_frags':
     * true indicates that fragments are dropped, false indicates that
     * fragments are treated in the same way as other IP packets (except that
     * the L4 header cannot be read). */
    int (*get_drop_frags)(const struct dpif *dpif, bool *drop_frags);

    /* Changes 'dpif''s treatment of IP fragments to 'drop_frags', whose
     * meaning is the same as for the get_drop_frags member function. */
    int (*set_drop_frags)(struct dpif *dpif, bool drop_frags);

    /* Adds 'netdev' as a new port in 'dpif'.  If successful, sets '*port_no'
     * to the new port's port number. */
    int (*port_add)(struct dpif *dpif, struct netdev *netdev,
                    uint16_t *port_no);

    /* Removes port numbered 'port_no' from 'dpif'. */
    int (*port_del)(struct dpif *dpif, uint16_t port_no);

    /* Queries 'dpif' for a port with the given 'port_no' or 'devname'.  Stores
     * information about the port into '*port' if successful.
     *
     * The caller takes ownership of data in 'port' and must free it with
     * dpif_port_destroy() when it is no longer needed. */
    int (*port_query_by_number)(const struct dpif *dpif, uint16_t port_no,
                                struct dpif_port *port);
    int (*port_query_by_name)(const struct dpif *dpif, const char *devname,
                              struct dpif_port *port);

    /* Returns one greater than the largest port number accepted in flow
     * actions. */
    int (*get_max_ports)(const struct dpif *dpif);

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

    /* For each flow 'flow' in the 'n' flows in 'flows':
     *
     * - If a flow matching 'flow->key' exists in 'dpif':
     *
     *     Stores 0 into 'flow->stats.error' and stores statistics for the flow
     *     into 'flow->stats'.
     *
     *     If 'flow->n_actions' is zero, then 'flow->actions' is ignored.  If
     *     'flow->n_actions' is nonzero, then 'flow->actions' should point to
     *     an array of the specified number of actions.  At most that many of
     *     the flow's actions will be copied into that array.
     *     'flow->n_actions' will be updated to the number of actions actually
     *     present in the flow, which may be greater than the number stored if
     *     the flow has more actions than space available in the array.
     *
     * - Flow-specific errors are indicated by a positive errno value in
     *   'flow->stats.error'.  In particular, ENOENT indicates that no flow
     *   matching 'flow->key' exists in 'dpif'.  When an error value is stored,
     *   the contents of 'flow->key' are preserved but other members of 'flow'
     *   should be treated as indeterminate.
     *
     * Returns 0 if all 'n' flows in 'flows' were updated (whether they were
     * individually successful or not is indicated by 'flow->stats.error',
     * however).  Returns a positive errno value if an error that prevented
     * this update occurred, in which the caller must not depend on any
     * elements in 'flows' being updated or not updated.
     */
    int (*flow_get)(const struct dpif *dpif, struct odp_flow flows[], int n);

    /* Adds or modifies a flow in 'dpif' as specified in 'put':
     *
     * - If the flow specified in 'put->flow' does not exist in 'dpif', then
     *   behavior depends on whether ODPPF_CREATE is specified in 'put->flags':
     *   if it is, the flow will be added, otherwise the operation will fail
     *   with ENOENT.
     *
     * - Otherwise, the flow specified in 'put->flow' does exist in 'dpif'.
     *   Behavior in this case depends on whether ODPPF_MODIFY is specified in
     *   'put->flags': if it is, the flow's actions will be updated, otherwise
     *   the operation will fail with EEXIST.  If the flow's actions are
     *   updated, then its statistics will be zeroed if ODPPF_ZERO_STATS is set
     *   in 'put->flags', left as-is otherwise.
     */
    int (*flow_put)(struct dpif *dpif, struct odp_flow_put *put);

    /* Deletes a flow matching 'flow->key' from 'dpif' or returns ENOENT if
     * 'dpif' does not contain such a flow.
     *
     * If successful, updates 'flow->stats', 'flow->n_actions', and
     * 'flow->actions' as described in more detail under the flow_get member
     * function below. */
    int (*flow_del)(struct dpif *dpif, struct odp_flow *flow);

    /* Deletes all flows from 'dpif' and clears all of its queues of received
     * packets. */
    int (*flow_flush)(struct dpif *dpif);

    /* Attempts to begin dumping the flows in a dpif.  On success, returns 0
     * and initializes '*statep' with any data needed for iteration.  On
     * failure, returns a positive errno value. */
    int (*flow_dump_start)(const struct dpif *dpif, void **statep);

    /* Attempts to retrieve another flow from 'dpif' for 'state', which was
     * initialized by a successful call to the 'flow_dump_start' function for
     * 'dpif'.  On success, stores a new odp_flow into 'flow' and returns 0.
     * Returns EOF if the end of the flow table has been reached, or a positive
     * errno value on error.  This function will not be called again once it
     * returns nonzero once for a given iteration (but the 'flow_dump_done'
     * function will be called afterward).
     *
     * Dumping flow actions is optional.  If the caller does not want to dump
     * actions it will initialize 'flow->actions' to NULL and
     * 'flow->actions_len' to 0.  Otherwise, 'flow->actions' points to an array
     * of struct nlattr and 'flow->actions_len' contains the number of bytes of
     * Netlink attributes.  The implemention should fill in as many actions as
     * will fit into the provided array and update 'flow->actions_len' with the
     * number of bytes required (regardless of whether they fit in the provided
     * space). */
    int (*flow_dump_next)(const struct dpif *dpif, void *state,
                          struct odp_flow *flow);

    /* Releases resources from 'dpif' for 'state', which was initialized by a
     * successful call to the 'flow_dump_start' function for 'dpif'.  */
    int (*flow_dump_done)(const struct dpif *dpif, void *state);

    /* Performs the 'actions_len' bytes of actions in 'actions' on the Ethernet
     * frame specified in 'packet'. */
    int (*execute)(struct dpif *dpif, const struct nlattr *actions,
                   size_t actions_len, const struct ofpbuf *packet);

    /* Retrieves 'dpif''s "listen mask" into '*listen_mask'.  Each ODPL_* bit
     * set in '*listen_mask' indicates the 'dpif' will receive messages of the
     * corresponding type when it calls the recv member function. */
    int (*recv_get_mask)(const struct dpif *dpif, int *listen_mask);

    /* Sets 'dpif''s "listen mask" to 'listen_mask'.  Each ODPL_* bit set in
     * 'listen_mask' indicates the 'dpif' will receive messages of the
     * corresponding type when it calls the recv member function. */
    int (*recv_set_mask)(struct dpif *dpif, int listen_mask);

    /* Retrieves 'dpif''s sFlow sampling probability into '*probability'.
     * Return value is 0 or a positive errno value.  EOPNOTSUPP indicates that
     * the datapath does not support sFlow, as does a null pointer.
     *
     * '*probability' is expressed as the number of packets out of UINT_MAX to
     * sample, e.g. probability/UINT_MAX is the probability of sampling a given
     * packet. */
    int (*get_sflow_probability)(const struct dpif *dpif,
                                 uint32_t *probability);

    /* Sets 'dpif''s sFlow sampling probability to 'probability'.  Return value
     * is 0 or a positive errno value.  EOPNOTSUPP indicates that the datapath
     * does not support sFlow, as does a null pointer.
     *
     * 'probability' is expressed as the number of packets out of UINT_MAX to
     * sample, e.g. probability/UINT_MAX is the probability of sampling a given
     * packet. */
    int (*set_sflow_probability)(struct dpif *dpif, uint32_t probability);

    /* Translates OpenFlow queue ID 'queue_id' (in host byte order) into a
     * priority value for use in the ODPAT_SET_PRIORITY action in
     * '*priority'. */
    int (*queue_to_priority)(const struct dpif *dpif, uint32_t queue_id,
                             uint32_t *priority);

    /* Polls for an upcall from 'dpif'.  If successful, stores the upcall into
     * '*upcall'.  Only upcalls of the types selected with the set_listen_mask
     * member function should be received.
     *
     * The caller takes ownership of the data that 'upcall' points to.
     * 'upcall->key' and 'upcall->actions' (if nonnull) point into data owned
     * by 'upcall->packet', so their memory cannot be freed separately.  (This
     * is hardly a great way to do things but it works out OK for the dpif
     * providers that exist so far.)
     *
     * For greatest efficiency, 'upcall->packet' should have at least
     * offsetof(struct ofp_packet_in, data) bytes of headroom.
     *
     * This function must not block.  If no upcall is pending when it is
     * called, it should return EAGAIN without blocking. */
    int (*recv)(struct dpif *dpif, struct dpif_upcall *upcall);

    /* Arranges for the poll loop to wake up when 'dpif' has a message queued
     * to be received with the recv member function. */
    void (*recv_wait)(struct dpif *dpif);

    /* Throws away any queued upcalls that 'dpif' currently has ready to
     * return. */
    void (*recv_purge)(struct dpif *dpif);
};

extern const struct dpif_class dpif_linux_class;
extern const struct dpif_class dpif_netdev_class;

#ifdef  __cplusplus
}
#endif

#endif /* dpif-provider.h */
