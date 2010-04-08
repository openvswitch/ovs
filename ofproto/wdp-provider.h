/*
 * Copyright (c) 2010 Nicira Networks.
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

#ifndef WDP_PROVIDER_H
#define WDP_PROVIDER_H 1

/* Provider interface to wdps, which provide an interface to an Open vSwitch
 * datapath. */

#include <assert.h>
#include "util.h"
#include "wdp.h"

#ifdef  __cplusplus
extern "C" {
#endif

static inline struct wdp_rule *
wdp_rule_cast(const struct cls_rule *cls_rule)
{
    return cls_rule ? CONTAINER_OF(cls_rule, struct wdp_rule, cr) : NULL;
}

/* Open vSwitch datapath interface.
 *
 * This structure should be treated as opaque by wdp implementations. */
struct wdp {
    const struct wdp_class *wdp_class;
    char *base_name;
    char *full_name;
    uint8_t netflow_engine_type;
    uint8_t netflow_engine_id;
};

void wdp_init(struct wdp *, const struct wdp_class *, const char *name,
              uint8_t netflow_engine_type, uint8_t netflow_engine_id);
void wdp_uninit(struct wdp *wdp, bool close);

static inline void wdp_assert_class(const struct wdp *wdp,
                                    const struct wdp_class *wdp_class)
{
    assert(wdp->wdp_class == wdp_class);
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
struct wdp_class {
    /* Type of wdp in this class, e.g. "system", "netdev", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed if no type is specified when opening a wdp. */
    const char *type;

    /* Performs periodic work needed by wdps of this class, if any is
     * necessary. */
    void (*run)(void);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called. */
    void (*wait)(void);

    /* Enumerates the names of all known created datapaths for 'wdp_class',
     * if possible, into 'all_wdps'.  The caller has already initialized
     * 'all_wdps' and other wdp classes might already have added names to it.
     *
     * This is used by the vswitch at startup, so that it can delete any
     * datapaths that are not configured.
     *
     * Some kinds of datapaths might not be practically enumerable, in which
     * case this function may be a null pointer. */
    int (*enumerate)(const struct wdp_class *wdp_class,
                     struct svec *all_wdps);

    /* Attempts to open an existing wdp of class 'wdp_class' called 'name',
     * if 'create' is false, or to open an existing wdp or create a new one,
     * if 'create' is true.
     *
     * If successful, stores a pointer to the new wdp in '*wdpp'.  On
     * failure there are no requirements on what is stored in '*wdpp'. */
    int (*open)(const struct wdp_class *wdp_class, const char *name,
                bool create, struct wdp **wdpp);

    /* Closes 'wdp' and frees associated memory. */
    void (*close)(struct wdp *wdp);

    /* Enumerates all names that may be used to open 'wdp' into 'all_names'.
     * The Linux datapath, for example, supports opening a datapath both by
     * number, e.g. "wdp0", and by the name of the datapath's local port.  For
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
    int (*get_all_names)(const struct wdp *wdp, struct svec *all_names);

    /* Attempts to destroy the wdp underlying 'wdp'.
     *
     * If successful, 'wdp' will not be used again except as an argument for
     * the 'close' member function. */
    int (*destroy)(struct wdp *wdp);

    /* Creates a "struct ofp_switch_features" for 'wdp' and stores it in
     * '*featuresp'.  The caller is responsible for freeing '*featuresp' (with
     * ofpbuf_delete()) when it is no longer needed. */
    int (*get_features)(const struct wdp *wdp, struct ofpbuf **featuresp);

    /* Retrieves statistics for 'wdp' into 'stats'. */
    int (*get_stats)(const struct wdp *wdp, struct wdp_stats *stats);

    /* Retrieves 'wdp''s current treatment of IP fragments into '*drop_frags':
     * true indicates that fragments are dropped, false indicates that
     * fragments are treated in the same way as other IP packets (except that
     * the L4 header cannot be read). */
    int (*get_drop_frags)(const struct wdp *wdp, bool *drop_frags);

    /* Changes 'wdp''s treatment of IP fragments to 'drop_frags', whose meaning
     * is the same as for the get_drop_frags member function.  EOPNOTSUPP
     * indicates that the datapath does not support changing the fragment
     * dropping policy, as does a null pointer. */
    int (*set_drop_frags)(struct wdp *wdp, bool drop_frags);

    /* Creates a new port in 'wdp' connected to network device 'devname'.  If
     * 'internal' is true, creates the port as an internal port.  If
     * successful, sets '*port_nop' to the new port's port number.
     *
     * Possible error return values include:
     *
     *   - ENODEV: No device named 'devname' exists (if 'internal' is false).
     *
     *   - EEXIST: A device named 'devname' already exists (if 'internal' is
     *     true).
     *
     *   - EINVAL: Device 'devname' is not supported as part of a datapath
     *     (e.g. it is not an Ethernet device), or 'devname' is too long for a
     *     network device name (if 'internal' is true)
     *
     *   - EFBIG: The datapath already has as many ports as it can support.
     *
     *   - EOPNOTSUPP: 'wdp' has a fixed set of ports.
     *
     * A null pointer is equivalent to returning EOPNOTSUPP.
     */
    int (*port_add)(struct wdp *wdp, const char *devname,
                    bool internal, uint16_t *port_nop);

    /* Removes port numbered 'port_no' from 'wdp'.
     *
     * Possible error return values include:
     *
     *   - EINVAL: 'port_no' is outside the valid range, or this particular
     *     port is not removable (e.g. it is the local port).
     *
     *   - ENOENT: 'wdp' currently has no port numbered 'port_no'.
     *
     *   - EOPNOTSUPP: 'wdp' has a fixed set of ports.
     *
     * A null pointer is equivalent to returning EOPNOTSUPP.
     */
    int (*port_del)(struct wdp *wdp, uint16_t port_no);

    /* Looks up a port in 'wdp' by name or number.  On success, returns 0 and
     * initializes '*portp'.  On failure, returns a positive errno value.
     *
     * The caller takes ownership of everything in '*portp' and will eventually
     * free it with, e.g., wdp_port_free(). */
    int (*port_query_by_number)(const struct wdp *wdp, uint16_t port_no,
                                struct wdp_port *portp);
    int (*port_query_by_name)(const struct wdp *wdp, const char *devname,
                              struct wdp_port *portp);

    /* Obtains a list of all the ports in 'wdp'.  Sets '*portsp' to point to an
     * array of port structures and '*n_portsp' to the number of ports in the
     * array.
     *
     * The caller takes ownership of '*portsp' and all of the ports in it and
     * is responsible for freeing the ports and the array with, e.g.,
     * wdp_port_array_free(). */
    int (*port_list)(const struct wdp *wdp, struct wdp_port **portsp,
                     size_t *n_portsp);

    int (*port_set_config)(struct wdp *sdpif, uint16_t port_no,
                           uint32_t config);

    /* Polls for changes in the set of ports in 'wdp'.  If the set of ports
     * in 'wdp' has changed, then this function should do one of the
     * following:
     *
     * - Preferably: store the name of the device that was added to or deleted
     *   from 'wdp' in '*devnamep' and return 0.  The caller is responsible
     *   for freeing '*devnamep' (with free()) when it no longer needs it.
     *
     * - Alternatively: return ENOBUFS, without indicating the device that was
     *   added or deleted.
     *
     * Occasional 'false positives', in which the function returns 0 while
     * indicating a device that was not actually added or deleted or returns
     * ENOBUFS without any change, are acceptable.
     *
     * If the set of ports in 'wdp' has not changed, returns EAGAIN.  May
     * also return other positive errno values to indicate that something has
     * gone wrong.
     *
     * If 'wdp' has a fixed set of ports, this function may be null, which is
     * equivalent to always returning EAGAIN.
     */
    int (*port_poll)(const struct wdp *wdp, char **devnamep);

    /* Arranges for the poll loop to wake up when 'port_poll' will return a
     * value other than EAGAIN.
     *
     * If 'wdp' has a fixed set of ports, this function may be null. */
    void (*port_poll_wait)(const struct wdp *wdp);

    /* If 'wdp' contains a flow exactly equal to 'flow', returns that flow.
     * Otherwise returns null. */
    struct wdp_rule *(*flow_get)(const struct wdp *wdp,
                                 const flow_t *flow);

    /* If 'wdp' contains one or more flows that match 'flow', returns the
     * highest-priority matching flow.  If there is more than one
     * highest-priority match, picks one of them in an arbitrary fashion.
     * Otherwise returns null.
     *
     * Ignores 'flow->priority' and 'flow->wildcards'. */
    struct wdp_rule *(*flow_match)(const struct wdp *wdp,
                                   const flow_t *flow);

    /* Iterates through all of the flows in 'wdp''s flow table, passing each
     * flow that matches the specified search criteria to 'callback' along with
     * 'aux'.
     *
     * Flows are filtered out in two ways.  First, based on 'include':
     * Exact-match flows are excluded unless CLS_INC_EXACT is in 'include'.
     * Wildcarded flows are excluded unless CLS_INC_WILD is in 'include'.
     *
     * Flows are also filtered out based on 'target': on a field-by-field
     * basis, a flow is included if 'target' wildcards that field or if the
     * flow and 'target' both have the same exact value for the field.  A flow
     * is excluded if any field does not match based on these criteria.
     *
     * Ignores 'target->priority'.
     *
     * 'callback' is allowed to delete the rule that is passed as its argument.
     * It may modify any flow in 'wdp', e.g. changing their actions.
     * 'callback' must not delete flows from 'wdp' other than its argument
     * flow, nor may it insert new flows into 'wdp'. */
    void (*flow_for_each_match)(const struct wdp *wdp, const flow_t *flow,
                                int include,
                                wdp_flow_cb_func *callback, void *aux);

    /* Retrieves flow statistics for 'rule', which must be in 'wdp''s flow
     * table, and stores them into '*stats'.  Returns 0 if successful,
     * otherwise a positive errno value. */
    int (*flow_get_stats)(const struct wdp *wdp,
                          const struct wdp_rule *rule,
                          struct wdp_flow_stats *stats);

    /* Searches 'wdp''s flow table for a flow that overlaps 'flow'.  Two flow
     * entries overlap if they have the same priority and a single packet may
     * match both.
     *
     * This is intended for implementing OpenFlow's OFPFF_CHECK_OVERLAP
     * feature. */
    bool (*flow_overlaps)(const struct wdp *wdp, const flow_t *flow);

    /* Adds or modifies a flow in 'wdp' as specified in 'put':
     *
     *   - If a rule with the same priority, wildcards, and values for fields
     *     that are not wildcarded specified in 'put->flow' does not already
     *     exist in 'wdp', then behavior depends on whether WDP_PUT_CREATE is
     *     specified in 'put->flags': if it is, the flow will be added,
     *     otherwise the operation will fail with ENOENT.
     *
     *     The new flow's actions and timeouts are set from the values in
     *     'put'.
     *
     *   - Otherwise, the flow specified in 'put->flow' does exist in 'wdp'.
     *     Behavior in this case depends on whether WDP_PUT_MODIFY is specified
     *     in 'put->flags': if it is, the flow will be updated, otherwise the
     *     operation will fail with EEXIST.  The exact updates depend on the
     *     remaining flags in 'put->flags':
     *
     *       . If WDP_PUT_COUNTERS is set, packet counters, byte counters, TCP
     *         flags, and IP TOS values are set to 0.
     *
     *       . If WDP_PUT_ACTIONS is set, the actions are replaced by the
     *         'put->n_actions' actions in 'put->actions'.
     *
     *       . If WDP_PUT_INSERTED is set, the flow's insertion time is updated
     *         to the current time.  (Timeouts are relative to a flow's
     *         insertion time so this affects their interpretation.)
     *
     *       . If WDP_PUT_TIMEOUTS is set, the flow's idle and hard timeouts
     *         are updated from 'put->idle_timeout' and 'put->hard_timeout',
     *         respectively.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful:
     *
     *   - If 'old_stats' is nonnull, then 'old_stats' is filled with the
     *     flow's stats as they existed just before the update, or it is zeroed
     *     if the flow is newly created.
     *
     *   - If 'rulep' is nonnull, then it is set to the newly created rule.
     *
     * Some error return values have specific meanings:
     *
     *   - ENOENT: Flow does not exist and WDP_PUT_CREATE not specified.
     *
     *   - EEXIST: Flow exists and WDP_PUT_MODIFY not specified.
     *
     *   - ENOBUFS: Flow table full.
     *
     *   - EINVAL: Flow table cannot accept flow of this form.
     */
    int (*flow_put)(struct wdp *wdp, const struct wdp_flow_put *put,
                    struct wdp_flow_stats *old_stats,
                    struct wdp_rule **rulep);

    /* Deletes 'rule' from 'wdp'.  Returns 0 if successful, otherwise a
     * positive errno value.
     *
     * If successful and 'final_stats' is non-null, stores the flow's
     * statistics just before it is deleted into '*final_stats'. */
    int (*flow_delete)(struct wdp *wdp, struct wdp_rule *rule,
                       struct wdp_flow_stats *final_stats);

    /* Deletes all flows from 'wdp' and clears all of its queues of received
     * packets. */
    int (*flow_flush)(struct wdp *wdp);

    /* Performs the actions for 'rule' on the Ethernet frame specified in
     * 'packet'.  Pretends that the frame was originally received on the port
     * numbered 'in_port'.  Packets and bytes sent should be credited to
     * 'rule'. */
    int (*flow_inject)(struct wdp *wdp, struct wdp_rule *rule,
                       uint16_t in_port, const struct ofpbuf *packet);

    /* Performs the 'n_actions' actions in 'actions' on the Ethernet frame
     * specified in 'packet'.  Pretends that the frame was originally received
     * on the port numbered 'in_port'. */
    int (*execute)(struct wdp *wdp, uint16_t in_port,
                   const union ofp_action actions[], int n_actions,
                   const struct ofpbuf *packet);

    /* Retrieves 'wdp''s "listen mask" into '*listen_mask'.  Each bit set in
     * '*listen_mask' indicates the 'wdp' will receive messages of the
     * corresponding WDP_CHAN_* when it calls the recv member function. */
    int (*recv_get_mask)(const struct wdp *wdp, int *listen_mask);

    /* Sets 'wdp''s "listen mask" to 'listen_mask'.  Each bit set in
     * 'listen_mask' indicates the 'wdp' will receive messages of the
     * corresponding WDP_CHAN_* type when it calls the recv member function. */
    int (*recv_set_mask)(struct wdp *wdp, int listen_mask);

    /* Retrieves 'wdp''s sFlow sampling probability into '*probability'.
     * Return value is 0 or a positive errno value.  EOPNOTSUPP indicates that
     * the datapath does not support sFlow, as does a null pointer.
     *
     * '*probability' is expressed as the number of packets out of UINT_MAX to
     * sample, e.g. probability/UINT_MAX is the probability of sampling a given
     * packet. */
    int (*get_sflow_probability)(const struct wdp *wdp,
                                 uint32_t *probability);

    /* Sets 'wdp''s sFlow sampling probability to 'probability'.  Return value
     * is 0 or a positive errno value.  EOPNOTSUPP indicates that the datapath
     * does not support sFlow, as does a null pointer.
     *
     * 'probability' is expressed as the number of packets out of UINT_MAX to
     * sample, e.g. probability/UINT_MAX is the probability of sampling a given
     * packet. */
    int (*set_sflow_probability)(struct wdp *wdp, uint32_t probability);

    /* Attempts to receive a message from 'wdp'.  If successful, stores the
     * message into '*packet'.  Only messages of the types selected with the
     * recv_set_mask member function should be received.
     *
     * This function must not block.  If no message is ready to be received
     * when it is called, it should return EAGAIN without blocking. */
    int (*recv)(struct wdp *wdp, struct wdp_packet *packet);

    /* Arranges for the poll loop to wake up when 'wdp' has a message queued
     * to be received with the recv member function. */
    void (*recv_wait)(struct wdp *wdp);
};

extern const struct wdp_class wdp_linux_class;
extern const struct wdp_class wdp_netdev_class;

#ifdef  __cplusplus
}
#endif

#endif /* wdp-provider.h */
