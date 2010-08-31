/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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

#ifndef XFIF_PROVIDER_H
#define XFIF_PROVIDER_H 1

/* Provider interface to xfifs, which provide an interface to an Open vSwitch
 * datapath.  A datapath is a collection of physical or virtual ports that are
 * exposed over OpenFlow as a single switch.  Datapaths and the collections of
 * ports that they contain may be fixed or dynamic. */

#include <assert.h>
#include "openflow/openflow.h"
#include "xfif.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Open vSwitch datapath interface.
 *
 * This structure should be treated as opaque by xfif implementations. */
struct xfif {
    const struct xfif_class *xfif_class;
    char *base_name;
    char *full_name;
    uint8_t netflow_engine_type;
    uint8_t netflow_engine_id;
};

void xfif_init(struct xfif *, const struct xfif_class *, const char *name,
               uint8_t netflow_engine_type, uint8_t netflow_engine_id);
void xfif_uninit(struct xfif *xfif, bool close);

static inline void xfif_assert_class(const struct xfif *xfif,
                                     const struct xfif_class *xfif_class)
{
    assert(xfif->xfif_class == xfif_class);
}

/* Datapath interface class structure, to be defined by each implementation of
 * a datapath interface.
 *
 * These functions return 0 if successful or a positive errno value on failure,
 * except where otherwise noted.
 *
 * Most of these functions are expected to execute synchronously, that is, to
 * block as necessary to obtain a result.  Thus, these functions may return
 * EAGAIN (or EWOULDBLOCK or EINPROGRESS) only where the function descriptions
 * explicitly say those errors are a possibility.  We may relax this
 * requirement in the future if and when we encounter performance problems. */
struct xfif_class {
    /* Type of xfif in this class, e.g. "system", "netdev", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed if no type is specified when opening a xfif. */
    const char *type;

    /* Performs periodic work needed by xfifs of this class, if any is
     * necessary. */
    void (*run)(void);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called. */
    void (*wait)(void);

    /* Enumerates the names of all known created datapaths, if possible, into
     * 'all_dps'.  The caller has already initialized 'all_dps' and other xfif
     * classes might already have added names to it.
     *
     * This is used by the vswitch at startup, so that it can delete any
     * datapaths that are not configured.
     *
     * Some kinds of datapaths might not be practically enumerable, in which
     * case this function may be a null pointer. */
    int (*enumerate)(struct svec *all_dps);

    /* Attempts to open an existing xfif called 'name', if 'create' is false,
     * or to open an existing xfif or create a new one, if 'create' is true.
     * 'type' corresponds to the 'type' field used in the xfif_class
     * structure.
     *
     * If successful, stores a pointer to the new xfif in '*xfifp'.  On failure
     * there are no requirements on what is stored in '*xfifp'. */
    int (*open)(const char *name, const char *type, bool create,
                struct xfif **xfifp);

    /* Closes 'xfif' and frees associated memory. */
    void (*close)(struct xfif *xfif);

    /* Enumerates all names that may be used to open 'xfif' into 'all_names'.
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
    int (*get_all_names)(const struct xfif *xfif, struct svec *all_names);

    /* Attempts to destroy the xfif underlying 'xfif'.
     *
     * If successful, 'xfif' will not be used again except as an argument for
     * the 'close' member function. */
    int (*destroy)(struct xfif *xfif);

    /* Retrieves statistics for 'xfif' into 'stats'. */
    int (*get_stats)(const struct xfif *xfif, struct xflow_stats *stats);

    /* Retrieves 'xfif''s current treatment of IP fragments into '*drop_frags':
     * true indicates that fragments are dropped, false indicates that
     * fragments are treated in the same way as other IP packets (except that
     * the L4 header cannot be read). */
    int (*get_drop_frags)(const struct xfif *xfif, bool *drop_frags);

    /* Changes 'xfif''s treatment of IP fragments to 'drop_frags', whose
     * meaning is the same as for the get_drop_frags member function. */
    int (*set_drop_frags)(struct xfif *xfif, bool drop_frags);

    /* Creates a new port in 'xfif' connected to network device 'devname'.
     * 'flags' is a set of XFLOW_PORT_* flags.  If successful, sets '*port_no'
     * to the new port's port number. */
    int (*port_add)(struct xfif *xfif, const char *devname, uint16_t flags,
                    uint16_t *port_no);

    /* Removes port numbered 'port_no' from 'xfif'. */
    int (*port_del)(struct xfif *xfif, uint16_t port_no);

    /* Queries 'xfif' for a port with the given 'port_no' or 'devname'.  Stores
     * information about the port into '*port' if successful. */
    int (*port_query_by_number)(const struct xfif *xfif, uint16_t port_no,
                                struct xflow_port *port);
    int (*port_query_by_name)(const struct xfif *xfif, const char *devname,
                              struct xflow_port *port);

    /* Stores in 'ports' information about up to 'n' ports attached to 'xfif',
     * in no particular order.  Returns the number of ports attached to 'xfif'
     * (not the number stored), if successful, otherwise a negative errno
     * value. */
    int (*port_list)(const struct xfif *xfif, struct xflow_port *ports, int n);

    /* Polls for changes in the set of ports in 'xfif'.  If the set of ports in
     * 'xfif' has changed, then this function should do one of the
     * following:
     *
     * - Preferably: store the name of the device that was added to or deleted
     *   from 'xfif' in '*devnamep' and return 0.  The caller is responsible
     *   for freeing '*devnamep' (with free()) when it no longer needs it.
     *
     * - Alternatively: return ENOBUFS, without indicating the device that was
     *   added or deleted.
     *
     * Occasional 'false positives', in which the function returns 0 while
     * indicating a device that was not actually added or deleted or returns
     * ENOBUFS without any change, are acceptable.
     *
     * If the set of ports in 'xfif' has not changed, returns EAGAIN.  May also
     * return other positive errno values to indicate that something has gone
     * wrong. */
    int (*port_poll)(const struct xfif *xfif, char **devnamep);

    /* Arranges for the poll loop to wake up when 'port_poll' will return a
     * value other than EAGAIN. */
    void (*port_poll_wait)(const struct xfif *xfif);

    /* Stores in 'ports' the port numbers of up to 'n' ports that belong to
     * 'group' in 'xfif'.  Returns the number of ports in 'group' (not the
     * number stored), if successful, otherwise a negative errno value. */
    int (*port_group_get)(const struct xfif *xfif, int group,
                          uint16_t ports[], int n);

    /* Changes port group 'group' in 'xfif' to consist of the 'n' ports whose
     * numbers are given in 'ports'.
     *
     * Use the get_stats member function to obtain the number of supported port
     * groups. */
    int (*port_group_set)(struct xfif *xfif, int group,
                          const uint16_t ports[], int n);

    /* For each flow 'flow' in the 'n' flows in 'flows':
     *
     * - If a flow matching 'flow->key' exists in 'xfif':
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
     *   matching 'flow->key' exists in 'xfif'.  When an error value is stored,
     *   the contents of 'flow->key' are preserved but other members of 'flow'
     *   should be treated as indeterminate.
     *
     * Returns 0 if all 'n' flows in 'flows' were updated (whether they were
     * individually successful or not is indicated by 'flow->stats.error',
     * however).  Returns a positive errno value if an error that prevented
     * this update occurred, in which the caller must not depend on any
     * elements in 'flows' being updated or not updated.
     */
    int (*flow_get)(const struct xfif *xfif, struct xflow_flow flows[], int n);

    /* Adds or modifies a flow in 'xfif' as specified in 'put':
     *
     * - If the flow specified in 'put->flow' does not exist in 'xfif', then
     *   behavior depends on whether XFLOWPF_CREATE is specified in 'put->flags':
     *   if it is, the flow will be added, otherwise the operation will fail
     *   with ENOENT.
     *
     * - Otherwise, the flow specified in 'put->flow' does exist in 'xfif'.
     *   Behavior in this case depends on whether XFLOWPF_MODIFY is specified in
     *   'put->flags': if it is, the flow's actions will be updated, otherwise
     *   the operation will fail with EEXIST.  If the flow's actions are
     *   updated, then its statistics will be zeroed if XFLOWPF_ZERO_STATS is set
     *   in 'put->flags', left as-is otherwise.
     */
    int (*flow_put)(struct xfif *xfif, struct xflow_flow_put *put);

    /* Deletes a flow matching 'flow->key' from 'xfif' or returns ENOENT if
     * 'xfif' does not contain such a flow.
     *
     * If successful, updates 'flow->stats', 'flow->n_actions', and
     * 'flow->actions' as described in more detail under the flow_get member
     * function below. */
    int (*flow_del)(struct xfif *xfif, struct xflow_flow *flow);

    /* Deletes all flows from 'xfif' and clears all of its queues of received
     * packets. */
    int (*flow_flush)(struct xfif *xfif);

    /* Stores up to 'n' flows in 'xfif' into 'flows', updating their statistics
     * and actions as described under the flow_get member function.  If
     * successful, returns the number of flows actually present in 'xfif',
     * which might be greater than the number stored (if 'xfif' has more than
     * 'n' flows).  On failure, returns a negative errno value. */
    int (*flow_list)(const struct xfif *xfif,
                     struct xflow_flow flows[], int n);

    /* Performs the 'n_actions' actions in 'actions' on the Ethernet frame
     * specified in 'packet'.
     *
     * Pretends that the frame was originally received on the port numbered
     * 'in_port'.  This affects only XFLOWAT_OUTPUT_GROUP actions, which will
     * not send a packet out their input port.  Specify the number of an unused
     * port (e.g. UINT16_MAX is currently always unused) to avoid this
     * behavior. */
    int (*execute)(struct xfif *xfif, uint16_t in_port,
                   const union xflow_action actions[], int n_actions,
                   const struct ofpbuf *packet);

    /* Retrieves 'xfif''s "listen mask" into '*listen_mask'.  Each XFLOWL_* bit
     * set in '*listen_mask' indicates the 'xfif' will receive messages of the
     * corresponding type when it calls the recv member function. */
    int (*recv_get_mask)(const struct xfif *xfif, int *listen_mask);

    /* Sets 'xfif''s "listen mask" to 'listen_mask'.  Each XFLOWL_* bit set in
     * 'listen_mask' indicates the 'xfif' will receive messages of the
     * corresponding type when it calls the recv member function. */
    int (*recv_set_mask)(struct xfif *xfif, int listen_mask);

    /* Retrieves 'xfif''s sFlow sampling probability into '*probability'.
     * Return value is 0 or a positive errno value.  EOPNOTSUPP indicates that
     * the datapath does not support sFlow, as does a null pointer.
     *
     * '*probability' is expressed as the number of packets out of UINT_MAX to
     * sample, e.g. probability/UINT_MAX is the probability of sampling a given
     * packet. */
    int (*get_sflow_probability)(const struct xfif *xfif,
                                 uint32_t *probability);

    /* Sets 'xfif''s sFlow sampling probability to 'probability'.  Return value
     * is 0 or a positive errno value.  EOPNOTSUPP indicates that the datapath
     * does not support sFlow, as does a null pointer.
     *
     * 'probability' is expressed as the number of packets out of UINT_MAX to
     * sample, e.g. probability/UINT_MAX is the probability of sampling a given
     * packet. */
    int (*set_sflow_probability)(struct xfif *xfif, uint32_t probability);

    /* Translates OpenFlow queue ID 'queue_id' (in host byte order) into a
     * priority value for use in the XFLOWAT_SET_PRIORITY action in
     * '*priority'. */
    int (*queue_to_priority)(const struct xfif *xfif, uint32_t queue_id,
                             uint32_t *priority);

    /* Attempts to receive a message from 'xfif'.  If successful, stores the
     * message into '*packetp'.  The message, if one is received, must begin
     * with 'struct xflow_msg' as a header, and must have at least
     * XFIF_RECV_MSG_PADDING bytes of headroom (allocated using
     * e.g. ofpbuf_reserve()).  Only messages of the types selected with the
     * set_listen_mask member function should be received.
     *
     * This function must not block.  If no message is ready to be received
     * when it is called, it should return EAGAIN without blocking. */
    int (*recv)(struct xfif *xfif, struct ofpbuf **packetp);

    /* Arranges for the poll loop to wake up when 'xfif' has a message queued
     * to be received with the recv member function. */
    void (*recv_wait)(struct xfif *xfif);
};

extern const struct xfif_class xfif_linux_class;
extern const struct xfif_class xfif_netdev_class;

#ifdef  __cplusplus
}
#endif

#endif /* xfif-provider.h */
