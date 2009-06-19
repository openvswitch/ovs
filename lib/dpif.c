/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "dpif-provider.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "util.h"
#include "valgrind.h"

#include "vlog.h"
#define THIS_MODULE VLM_dpif

static struct dpif_class *dpif_classes[] = {
    &dpif_linux_class,
};
enum { N_DPIF_CLASSES = ARRAY_SIZE(dpif_classes) };

/* Rate limit for individual messages going to or from the datapath, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit dpmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Not really much point in logging many dpif errors. */
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

static void log_operation(const struct dpif *, const char *operation,
                          int error);
static void log_flow_operation(const struct dpif *, const char *operation,
                               int error, struct odp_flow *flow);
static void log_flow_put(struct dpif *, int error,
                         const struct odp_flow_put *);
static bool should_log_flow_message(int error);
static void check_rw_odp_flow(struct odp_flow *);

/* Performs periodic work needed by all the various kinds of dpifs.
 *
 * If your program opens any dpifs, it must call this function within its main
 * poll loop. */
void
dp_run(void)
{
    int i;
    for (i = 0; i < N_DPIF_CLASSES; i++) {
        const struct dpif_class *class = dpif_classes[i];
        if (class->run) {
            class->run();
        }
    }
}

/* Arranges for poll_block() to wake up when dp_run() needs to be called.
 *
 * If your program opens any dpifs, it must call this function within its main
 * poll loop. */
void
dp_wait(void)
{
    int i;
    for (i = 0; i < N_DPIF_CLASSES; i++) {
        const struct dpif_class *class = dpif_classes[i];
        if (class->wait) {
            class->wait();
        }
    }
}

static int
do_open(const char *name_, bool create, struct dpif **dpifp)
{
    char *name = xstrdup(name_);
    char *prefix, *suffix, *colon;
    struct dpif *dpif = NULL;
    int error;
    int i;

    colon = strchr(name, ':');
    if (colon) {
        *colon = '\0';
        prefix = name;
        suffix = colon + 1;
    } else {
        prefix = "";
        suffix = name;
    }

    for (i = 0; i < N_DPIF_CLASSES; i++) {
        const struct dpif_class *class = dpif_classes[i];
        if (!strcmp(prefix, class->prefix)) {
            error = class->open(name_, suffix, create, &dpif);
            goto exit;
        }
    }
    error = EAFNOSUPPORT;

exit:
    *dpifp = error ? NULL : dpif;
    return error;
}

/* Tries to open an existing datapath named 'name'.  Will fail if no datapath
 * named 'name' exists.  Returns 0 if successful, otherwise a positive errno
 * value.  On success stores a pointer to the datapath in '*dpifp', otherwise a
 * null pointer. */
int
dpif_open(const char *name, struct dpif **dpifp)
{
    return do_open(name, false, dpifp);
}

/* Tries to create and open a new datapath with the given 'name'.  Will fail if
 * a datapath named 'name' already exists.  Returns 0 if successful, otherwise
 * a positive errno value.  On success stores a pointer to the datapath in
 * '*dpifp', otherwise a null pointer.*/
int
dpif_create(const char *name, struct dpif **dpifp)
{
    return do_open(name, true, dpifp);
}

/* Closes and frees the connection to 'dpif'.  Does not destroy the datapath
 * itself; call dpif_delete() first, instead, if that is desirable. */
void
dpif_close(struct dpif *dpif)
{
    if (dpif) {
        char *name = dpif->name;
        dpif->class->close(dpif);
        free(name);
    }
}

/* Returns the name of datapath 'dpif' (for use in log messages). */
const char *
dpif_name(const struct dpif *dpif)
{
    return dpif->name;
}

/* Destroys the datapath that 'dpif' is connected to, first removing all of its
 * ports.  After calling this function, it does not make sense to pass 'dpif'
 * to any functions other than dpif_name() or dpif_close(). */
int
dpif_delete(struct dpif *dpif)
{
    int error;

    COVERAGE_INC(dpif_destroy);

    error = dpif->class->delete(dpif);
    log_operation(dpif, "delete", error);
    return error;
}

/* Retrieves statistics for 'dpif' into 'stats'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
dpif_get_dp_stats(const struct dpif *dpif, struct odp_stats *stats)
{
    int error = dpif->class->get_stats(dpif, stats);
    if (error) {
        memset(stats, 0, sizeof *stats);
    }
    log_operation(dpif, "get_stats", error);
    return error;
}

/* Retrieves the current IP fragment handling policy for 'dpif' into
 * '*drop_frags': true indicates that fragments are dropped, false indicates
 * that fragments are treated in the same way as other IP packets (except that
 * the L4 header cannot be read).  Returns 0 if successful, otherwise a
 * positive errno value. */
int
dpif_get_drop_frags(const struct dpif *dpif, bool *drop_frags)
{
    int error = dpif->class->get_drop_frags(dpif, drop_frags);
    if (error) {
        *drop_frags = false;
    }
    log_operation(dpif, "get_drop_frags", error);
    return error;
}

/* Changes 'dpif''s treatment of IP fragments to 'drop_frags', whose meaning is
 * the same as for the get_drop_frags member function.  Returns 0 if
 * successful, otherwise a positive errno value. */
int
dpif_set_drop_frags(struct dpif *dpif, bool drop_frags)
{
    int error = dpif->class->set_drop_frags(dpif, drop_frags);
    log_operation(dpif, "set_drop_frags", error);
    return error;
}

/* Attempts to add 'devname' as a port on 'dpif', given the combination of
 * ODP_PORT_* flags in 'flags'.  If successful, returns 0 and sets '*port_nop'
 * to the new port's port number (if 'port_nop' is non-null).  On failure,
 * returns a positive errno value and sets '*port_nop' to UINT16_MAX (if
 * 'port_nop' is non-null). */
int
dpif_port_add(struct dpif *dpif, const char *devname, uint16_t flags,
              uint16_t *port_nop)
{
    uint16_t port_no;
    int error;

    COVERAGE_INC(dpif_port_add);

    error = dpif->class->port_add(dpif, devname, flags, &port_no);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: added %s as port %"PRIu16,
                    dpif_name(dpif), devname, port_no);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to add %s as port: %s",
                     dpif_name(dpif), devname, strerror(error));
        port_no = UINT16_MAX;
    }
    if (port_nop) {
        *port_nop = port_no;
    }
    return error;
}

/* Attempts to remove 'dpif''s port number 'port_no'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
dpif_port_del(struct dpif *dpif, uint16_t port_no)
{
    int error;

    COVERAGE_INC(dpif_port_del);

    error = dpif->class->port_del(dpif, port_no);
    log_operation(dpif, "port_del", error);
    return error;
}

/* Looks up port number 'port_no' in 'dpif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value. */
int
dpif_port_query_by_number(const struct dpif *dpif, uint16_t port_no,
                          struct odp_port *port)
{
    int error = dpif->class->port_query_by_number(dpif, port_no, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port %"PRIu16" is device %s",
                    dpif_name(dpif), port_no, port->devname);
    } else {
        memset(port, 0, sizeof *port);
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %"PRIu16": %s",
                     dpif_name(dpif), port_no, strerror(error));
    }
    return error;
}

/* Looks up port named 'devname' in 'dpif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value. */
int
dpif_port_query_by_name(const struct dpif *dpif, const char *devname,
                        struct odp_port *port)
{
    int error = dpif->class->port_query_by_name(dpif, devname, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: device %s is on port %"PRIu16,
                    dpif_name(dpif), devname, port->port);
    } else {
        memset(port, 0, sizeof *port);

        /* Log level is DBG here because all the current callers are interested
         * in whether 'dpif' actually has a port 'devname', so that it's not an
         * issue worth logging if it doesn't. */
        VLOG_DBG_RL(&error_rl, "%s: failed to query port %s: %s",
                    dpif_name(dpif), devname, strerror(error));
    }
    return error;
}

/* Looks up port number 'port_no' in 'dpif'.  On success, returns 0 and copies
 * the port's name into the 'name_size' bytes in 'name', ensuring that the
 * result is null-terminated.  On failure, returns a positive errno value and
 * makes 'name' the empty string. */
int
dpif_port_get_name(struct dpif *dpif, uint16_t port_no,
                   char *name, size_t name_size)
{
    struct odp_port port;
    int error;

    assert(name_size > 0);

    error = dpif_port_query_by_number(dpif, port_no, &port);
    if (!error) {
        ovs_strlcpy(name, port.devname, name_size);
    } else {
        *name = '\0';
    }
    return error;
}

/* Obtains a list of all the ports in 'dpif'.
 *
 * If successful, returns 0 and sets '*portsp' to point to an array of
 * appropriately initialized port structures and '*n_portsp' to the number of
 * ports in the array.  The caller is responsible for freeing '*portp' by
 * calling free().
 *
 * On failure, returns a positive errno value and sets '*portsp' to NULL and
 * '*n_portsp' to 0. */
int
dpif_port_list(const struct dpif *dpif,
               struct odp_port **portsp, size_t *n_portsp)
{
    struct odp_port *ports;
    size_t n_ports;
    int error;

    for (;;) {
        struct odp_stats stats;
        int retval;

        error = dpif_get_dp_stats(dpif, &stats);
        if (error) {
            goto exit;
        }

        ports = xcalloc(stats.n_ports, sizeof *ports);
        retval = dpif->class->port_list(dpif, ports, stats.n_ports);
        if (retval < 0) {
            /* Hard error. */
            error = -retval;
            free(ports);
            goto exit;
        } else if (retval <= stats.n_ports) {
            /* Success. */
            error = 0;
            n_ports = retval;
            goto exit;
        } else {
            /* Soft error: port count increased behind our back.  Try again. */
            free(ports);
        }
    }

exit:
    if (error) {
        *portsp = NULL;
        *n_portsp = 0;
    } else {
        *portsp = ports;
        *n_portsp = n_ports;
    }
    log_operation(dpif, "port_list", error);
    return error;
}

/* Retrieves a list of the port numbers in port group 'group' in 'dpif'.
 *
 * On success, returns 0 and points '*ports' to a newly allocated array of
 * integers, each of which is a 'dpif' port number for a port in
 * 'group'.  Stores the number of elements in the array in '*n_ports'.  The
 * caller is responsible for freeing '*ports' by calling free().
 *
 * On failure, returns a positive errno value and sets '*ports' to NULL and
 * '*n_ports' to 0. */
int
dpif_port_group_get(const struct dpif *dpif, uint16_t group,
                    uint16_t **ports, size_t *n_ports)
{
    int error;

    *ports = NULL;
    *n_ports = 0;
    for (;;) {
        int retval = dpif->class->port_group_get(dpif, group,
                                                 *ports, *n_ports);
        if (retval < 0) {
            /* Hard error. */
            error = -retval;
            free(*ports);
            *ports = NULL;
            *n_ports = 0;
            break;
        } else if (retval <= *n_ports) {
            /* Success. */
            error = 0;
            *n_ports = retval;
            break;
        } else {
            /* Soft error: there were more ports than we expected in the
             * group.  Try again. */
            free(*ports);
            *ports = xcalloc(retval, sizeof **ports);
            *n_ports = retval;
        }
    }
    log_operation(dpif, "port_group_get", error);
    return error;
}

/* Updates port group 'group' in 'dpif', making it contain the 'n_ports' ports
 * whose 'dpif' port numbers are given in 'n_ports'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Behavior is undefined if the values in ports[] are not unique. */
int
dpif_port_group_set(struct dpif *dpif, uint16_t group,
                    const uint16_t ports[], size_t n_ports)
{
    int error;

    COVERAGE_INC(dpif_port_group_set);

    error = dpif->class->port_group_set(dpif, group, ports, n_ports);
    log_operation(dpif, "port_group_set", error);
    return error;
}

/* Deletes all flows from 'dpif'.  Returns 0 if successful, otherwise a
 * positive errno value.  */
int
dpif_flow_flush(struct dpif *dpif)
{
    int error;

    COVERAGE_INC(dpif_flow_flush);

    error = dpif->class->flow_flush(dpif);
    log_operation(dpif, "flow_flush", error);
    return error;
}

/* Queries 'dpif' for a flow entry matching 'flow->key'.
 *
 * If a flow matching 'flow->key' exists in 'dpif', stores statistics for the
 * flow into 'flow->stats'.  If 'flow->n_actions' is zero, then 'flow->actions'
 * is ignored.  If 'flow->n_actions' is nonzero, then 'flow->actions' should
 * point to an array of the specified number of actions.  At most that many of
 * the flow's actions will be copied into that array.  'flow->n_actions' will
 * be updated to the number of actions actually present in the flow, which may
 * be greater than the number stored if the flow has more actions than space
 * available in the array.
 *
 * If no flow matching 'flow->key' exists in 'dpif', returns ENOENT.  On other
 * failure, returns a positive errno value. */
int
dpif_flow_get(const struct dpif *dpif, struct odp_flow *flow)
{
    int error;

    COVERAGE_INC(dpif_flow_get);

    check_rw_odp_flow(flow);
    error = dpif->class->flow_get(dpif, flow, 1);
    if (!error) {
        error = flow->stats.error;
    }
    if (should_log_flow_message(error)) {
        log_flow_operation(dpif, "flow_get", error, flow);
    }
    return error;
}

/* For each flow 'flow' in the 'n' flows in 'flows':
 *
 * - If a flow matching 'flow->key' exists in 'dpif':
 *
 *     Stores 0 into 'flow->stats.error' and stores statistics for the flow
 *     into 'flow->stats'.
 *
 *     If 'flow->n_actions' is zero, then 'flow->actions' is ignored.  If
 *     'flow->n_actions' is nonzero, then 'flow->actions' should point to an
 *     array of the specified number of actions.  At most that many of the
 *     flow's actions will be copied into that array.  'flow->n_actions' will
 *     be updated to the number of actions actually present in the flow, which
 *     may be greater than the number stored if the flow has more actions than
 *     space available in the array.
 *
 * - Flow-specific errors are indicated by a positive errno value in
 *   'flow->stats.error'.  In particular, ENOENT indicates that no flow
 *   matching 'flow->key' exists in 'dpif'.  When an error value is stored, the
 *   contents of 'flow->key' are preserved but other members of 'flow' should
 *   be treated as indeterminate.
 *
 * Returns 0 if all 'n' flows in 'flows' were updated (whether they were
 * individually successful or not is indicated by 'flow->stats.error',
 * however).  Returns a positive errno value if an error that prevented this
 * update occurred, in which the caller must not depend on any elements in
 * 'flows' being updated or not updated.
 */
int
dpif_flow_get_multiple(const struct dpif *dpif,
                       struct odp_flow flows[], size_t n)
{
    int error;
    size_t i;

    COVERAGE_ADD(dpif_flow_get, n);

    for (i = 0; i < n; i++) {
        check_rw_odp_flow(&flows[i]);
    }

    error = dpif->class->flow_get(dpif, flows, n);
    log_operation(dpif, "flow_get_multiple", error);
    return error;
}

/* Adds or modifies a flow in 'dpif' as specified in 'put':
 *
 * - If the flow specified in 'put->flow' does not exist in 'dpif', then
 *   behavior depends on whether ODPPF_CREATE is specified in 'put->flags': if
 *   it is, the flow will be added, otherwise the operation will fail with
 *   ENOENT.
 *
 * - Otherwise, the flow specified in 'put->flow' does exist in 'dpif'.
 *   Behavior in this case depends on whether ODPPF_MODIFY is specified in
 *   'put->flags': if it is, the flow's actions will be updated, otherwise the
 *   operation will fail with EEXIST.  If the flow's actions are updated, then
 *   its statistics will be zeroed if ODPPF_ZERO_STATS is set in 'put->flags',
 *   left as-is otherwise.
 *
 * Returns 0 if successful, otherwise a positive errno value.
 */
int
dpif_flow_put(struct dpif *dpif, struct odp_flow_put *put)
{
    int error;

    COVERAGE_INC(dpif_flow_put);

    error = dpif->class->flow_put(dpif, put);
    if (should_log_flow_message(error)) {
        log_flow_put(dpif, error, put);
    }
    return error;
}

/* Deletes a flow matching 'flow->key' from 'dpif' or returns ENOENT if 'dpif'
 * does not contain such a flow.
 *
 * If successful, updates 'flow->stats', 'flow->n_actions', and 'flow->actions'
 * as described for dpif_flow_get(). */
int
dpif_flow_del(struct dpif *dpif, struct odp_flow *flow)
{
    int error;

    COVERAGE_INC(dpif_flow_del);

    check_rw_odp_flow(flow);
    memset(&flow->stats, 0, sizeof flow->stats);

    error = dpif->class->flow_del(dpif, flow);
    if (should_log_flow_message(error)) {
        log_flow_operation(dpif, "delete flow", error, flow);
    }
    return error;
}

/* Stores up to 'n' flows in 'dpif' into 'flows', including their statistics
 * but not including any information about their actions.  If successful,
 * returns 0 and sets '*n_out' to the number of flows actually present in
 * 'dpif', which might be greater than the number stored (if 'dpif' has more
 * than 'n' flows).  On failure, returns a negative errno value and sets
 * '*n_out' to 0. */
int
dpif_flow_list(const struct dpif *dpif, struct odp_flow flows[], size_t n,
               size_t *n_out)
{
    uint32_t i;
    int retval;

    COVERAGE_INC(dpif_flow_query_list);
    if (RUNNING_ON_VALGRIND) {
        memset(flows, 0, n * sizeof *flows);
    } else {
        for (i = 0; i < n; i++) {
            flows[i].actions = NULL;
            flows[i].n_actions = 0;
        }
    }
    retval = dpif->class->flow_list(dpif, flows, n);
    if (retval < 0) {
        *n_out = 0;
        VLOG_WARN_RL(&error_rl, "%s: flow list failed (%s)",
                     dpif_name(dpif), strerror(-retval));
        return -retval;
    } else {
        COVERAGE_ADD(dpif_flow_query_list_n, retval);
        *n_out = MIN(n, retval);
        VLOG_DBG_RL(&dpmsg_rl, "%s: listed %zu flows (of %d)",
                    dpif_name(dpif), *n_out, retval);
        return 0;
    }
}

/* Retrieves all of the flows in 'dpif'.
 *
 * If successful, returns 0 and stores in '*flowsp' a pointer to a newly
 * allocated array of flows, including their statistics but not including any
 * information about their actions, and sets '*np' to the number of flows in
 * '*flowsp'.  The caller is responsible for freeing '*flowsp' by calling
 * free().
 *
 * On failure, returns a positive errno value and sets '*flowsp' to NULL and
 * '*np' to 0. */
int
dpif_flow_list_all(const struct dpif *dpif,
                   struct odp_flow **flowsp, size_t *np)
{
    struct odp_stats stats;
    struct odp_flow *flows;
    size_t n_flows;
    int error;

    *flowsp = NULL;
    *np = 0;

    error = dpif_get_dp_stats(dpif, &stats);
    if (error) {
        return error;
    }

    flows = xmalloc(sizeof *flows * stats.n_flows);
    error = dpif_flow_list(dpif, flows, stats.n_flows, &n_flows);
    if (error) {
        free(flows);
        return error;
    }

    if (stats.n_flows != n_flows) {
        VLOG_WARN_RL(&error_rl, "%s: datapath stats reported %"PRIu32" "
                     "flows but flow listing reported %zu",
                     dpif_name(dpif), stats.n_flows, n_flows);
    }
    *flowsp = flows;
    *np = n_flows;
    return 0;
}

/* Causes 'dpif' to perform the 'n_actions' actions in 'actions' on the
 * Ethernet frame specified in 'packet'.
 *
 * Pretends that the frame was originally received on the port numbered
 * 'in_port'.  This affects only ODPAT_OUTPUT_GROUP actions, which will not
 * send a packet out their input port.  Specify the number of an unused port
 * (e.g. UINT16_MAX is currently always unused) to avoid this behavior.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
dpif_execute(struct dpif *dpif, uint16_t in_port,
             const union odp_action actions[], size_t n_actions,
             const struct ofpbuf *buf)
{
    int error;

    COVERAGE_INC(dpif_execute);
    if (n_actions > 0) {
        error = dpif->class->execute(dpif, in_port, actions, n_actions, buf);
    } else {
        error = 0;
    }

    if (!(error ? VLOG_DROP_WARN(&error_rl) : VLOG_DROP_DBG(&dpmsg_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet = ofp_packet_to_string(buf->data, buf->size, buf->size);
        ds_put_format(&ds, "%s: execute ", dpif_name(dpif));
        format_odp_actions(&ds, actions, n_actions);
        if (error) {
            ds_put_format(&ds, " failed (%s)", strerror(error));
        }
        ds_put_format(&ds, " on packet %s", packet);
        vlog(THIS_MODULE, error ? VLL_WARN : VLL_DBG, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
        free(packet);
    }
    return error;
}

/* Retrieves 'dpif''s "listen mask" into '*listen_mask'.  Each ODPL_* bit set
 * in '*listen_mask' indicates that dpif_recv() will receive messages of that
 * type.  Returns 0 if successful, otherwise a positive errno value. */
int
dpif_recv_get_mask(const struct dpif *dpif, int *listen_mask)
{
    int error = dpif->class->recv_get_mask(dpif, listen_mask);
    if (error) {
        *listen_mask = 0;
    }
    log_operation(dpif, "recv_get_mask", error);
    return error;
}

/* Sets 'dpif''s "listen mask" to 'listen_mask'.  Each ODPL_* bit set in
 * '*listen_mask' requests that dpif_recv() receive messages of that type.
 * Returns 0 if successful, otherwise a positive errno value. */
int
dpif_recv_set_mask(struct dpif *dpif, int listen_mask)
{
    int error = dpif->class->recv_set_mask(dpif, listen_mask);
    log_operation(dpif, "recv_set_mask", error);
    return error;
}

/* Attempts to receive a message from 'dpif'.  If successful, stores the
 * message into '*packetp'.  The message, if one is received, will begin with
 * 'struct odp_msg' as a header.  Only messages of the types selected with
 * dpif_set_listen_mask() will ordinarily be received (but if a message type is
 * enabled and then later disabled, some stragglers might pop up).
 *
 * Returns 0 if successful, otherwise a positive errno value.  Returns EAGAIN
 * if no message is immediately available. */
int
dpif_recv(struct dpif *dpif, struct ofpbuf **packetp)
{
    int error = dpif->class->recv(dpif, packetp);
    if (!error) {
        if (VLOG_IS_DBG_ENABLED()) {
            struct ofpbuf *buf = *packetp;
            struct odp_msg *msg = buf->data;
            void *payload = msg + 1;
            size_t payload_len = buf->size - sizeof *msg;
            char *s = ofp_packet_to_string(payload, payload_len, payload_len);
            VLOG_DBG_RL(&dpmsg_rl, "%s: received %s message of length "
                        "%zu on port %"PRIu16": %s", dpif_name(dpif),
                        (msg->type == _ODPL_MISS_NR ? "miss"
                         : msg->type == _ODPL_ACTION_NR ? "action"
                         : "<unknown>"),
                        payload_len, msg->port, s);
            free(s);
        }
    } else {
        *packetp = NULL;
    }
    return error;
}

/* Discards all messages that would otherwise be received by dpif_recv() on
 * 'dpif'.  Returns 0 if successful, otherwise a positive errno value. */
int
dpif_recv_purge(struct dpif *dpif)
{
    struct odp_stats stats;
    unsigned int i;
    int error;

    COVERAGE_INC(dpif_purge);

    error = dpif_get_dp_stats(dpif, &stats);
    if (error) {
        return error;
    }

    for (i = 0; i < stats.max_miss_queue + stats.max_action_queue; i++) {
        struct ofpbuf *buf;
        error = dpif_recv(dpif, &buf);
        if (error) {
            return error == EAGAIN ? 0 : error;
        }
        ofpbuf_delete(buf);
    }
    return 0;
}

/* Arranges for the poll loop to wake up when 'dpif' has a message queued to be
 * received with dpif_recv(). */
void
dpif_recv_wait(struct dpif *dpif)
{
    dpif->class->recv_wait(dpif);
}

/* Obtains the NetFlow engine type and engine ID for 'dpif' into '*engine_type'
 * and '*engine_id', respectively. */
void
dpif_get_netflow_ids(const struct dpif *dpif,
                     uint8_t *engine_type, uint8_t *engine_id)
{
    *engine_type = dpif->netflow_engine_type;
    *engine_id = dpif->netflow_engine_id;
}

void
dpif_init(struct dpif *dpif, const struct dpif_class *class, const char *name,
          uint8_t netflow_engine_type, uint8_t netflow_engine_id)
{
    dpif->class = class;
    dpif->name = xstrdup(name);
    dpif->netflow_engine_type = netflow_engine_type;
    dpif->netflow_engine_id = netflow_engine_id;
}

static void
log_operation(const struct dpif *dpif, const char *operation, int error)
{
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: %s success", dpif_name(dpif), operation);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     dpif_name(dpif), operation, strerror(error));
    }
}

static enum vlog_level
flow_message_log_level(int error)
{
    return error ? VLL_WARN : VLL_DBG;
}

static bool
should_log_flow_message(int error)
{
    return !vlog_should_drop(THIS_MODULE, flow_message_log_level(error),
                             error ? &error_rl : &dpmsg_rl);
}

static void
log_flow_message(const struct dpif *dpif, int error, const char *operation,
                 const flow_t *flow, const struct odp_flow_stats *stats,
                 const union odp_action *actions, size_t n_actions)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "%s: ", dpif_name(dpif));
    if (error) {
        ds_put_cstr(&ds, "failed to ");
    }
    ds_put_format(&ds, "%s ", operation);
    if (error) {
        ds_put_format(&ds, "(%s) ", strerror(error));
    }
    flow_format(&ds, flow);
    if (stats) {
        ds_put_cstr(&ds, ", ");
        format_odp_flow_stats(&ds, stats);
    }
    if (actions || n_actions) {
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, n_actions);
    }
    vlog(THIS_MODULE, flow_message_log_level(error), "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
log_flow_operation(const struct dpif *dpif, const char *operation, int error,
                   struct odp_flow *flow)
{
    if (error) {
        flow->n_actions = 0;
    }
    log_flow_message(dpif, error, operation, &flow->key,
                     !error ? &flow->stats : NULL,
                     flow->actions, flow->n_actions);
}

static void
log_flow_put(struct dpif *dpif, int error, const struct odp_flow_put *put)
{
    enum { ODPPF_ALL = ODPPF_CREATE | ODPPF_MODIFY | ODPPF_ZERO_STATS };
    struct ds s;

    ds_init(&s);
    ds_put_cstr(&s, "put");
    if (put->flags & ODPPF_CREATE) {
        ds_put_cstr(&s, "[create]");
    }
    if (put->flags & ODPPF_MODIFY) {
        ds_put_cstr(&s, "[modify]");
    }
    if (put->flags & ODPPF_ZERO_STATS) {
        ds_put_cstr(&s, "[zero]");
    }
    if (put->flags & ~ODPPF_ALL) {
        ds_put_format(&s, "[%x]", put->flags & ~ODPPF_ALL);
    }
    log_flow_message(dpif, error, ds_cstr(&s), &put->flow.key,
                     !error ? &put->flow.stats : NULL,
                     put->flow.actions, put->flow.n_actions);
    ds_destroy(&s);
}

/* There is a tendency to construct odp_flow objects on the stack and to
 * forget to properly initialize their "actions" and "n_actions" members.
 * When this happens, we get memory corruption because the kernel
 * writes through the random pointer that is in the "actions" member.
 *
 * This function attempts to combat the problem by:
 *
 *      - Forcing a segfault if "actions" points to an invalid region (instead
 *        of just getting back EFAULT, which can be easily missed in the log).
 *
 *      - Storing a distinctive value that is likely to cause an
 *        easy-to-identify error later if it is dereferenced, etc.
 *
 *      - Triggering a warning on uninitialized memory from Valgrind if
 *        "actions" or "n_actions" was not initialized.
 */
static void
check_rw_odp_flow(struct odp_flow *flow)
{
    if (flow->n_actions) {
        memset(&flow->actions[0], 0xcc, sizeof flow->actions[0]);
    }
}

#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct dpifmon {
    struct dpif *dpif;
    struct nl_sock *sock;
    int local_ifindex;
};

int
dpifmon_create(const char *datapath_name, struct dpifmon **monp)
{
    struct dpifmon *mon;
    char local_name[IFNAMSIZ];
    int error;

    mon = *monp = xmalloc(sizeof *mon);

    error = dpif_open(datapath_name, &mon->dpif);
    if (error) {
        goto error;
    }
    error = dpif_port_get_name(mon->dpif, ODPP_LOCAL,
                               local_name, sizeof local_name);
    if (error) {
        goto error_close_dpif;
    }

    mon->local_ifindex = if_nametoindex(local_name);
    if (!mon->local_ifindex) {
        error = errno;
        VLOG_WARN("could not get ifindex of %s device: %s",
                  local_name, strerror(errno));
        goto error_close_dpif;
    }

    error = nl_sock_create(NETLINK_ROUTE, RTNLGRP_LINK, 0, 0, &mon->sock);
    if (error) {
        VLOG_WARN("could not create rtnetlink socket: %s", strerror(error));
        goto error_close_dpif;
    }

    return 0;

error_close_dpif:
    dpif_close(mon->dpif);
error:
    free(mon);
    *monp = NULL;
    return error;
}

void
dpifmon_destroy(struct dpifmon *mon)
{
    if (mon) {
        dpif_close(mon->dpif);
        nl_sock_destroy(mon->sock);
    }
}

int
dpifmon_poll(struct dpifmon *mon, char **devnamep)
{
    static struct vlog_rate_limit slow_rl = VLOG_RATE_LIMIT_INIT(1, 5);
    static const struct nl_policy rtnlgrp_link_policy[] = {
        [IFLA_IFNAME] = { .type = NL_A_STRING },
        [IFLA_MASTER] = { .type = NL_A_U32, .optional = true },
    };
    struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
    struct ofpbuf *buf;
    int error;

    *devnamep = NULL;
again:
    error = nl_sock_recv(mon->sock, &buf, false);
    switch (error) {
    case 0:
        if (!nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                             rtnlgrp_link_policy,
                             attrs, ARRAY_SIZE(rtnlgrp_link_policy))) {
            VLOG_WARN_RL(&slow_rl, "received bad rtnl message");
            error = ENOBUFS;
        } else {
            const char *devname = nl_attr_get_string(attrs[IFLA_IFNAME]);
            bool for_us;

            if (attrs[IFLA_MASTER]) {
                uint32_t master_ifindex = nl_attr_get_u32(attrs[IFLA_MASTER]);
                for_us = master_ifindex == mon->local_ifindex;
            } else {
                /* It's for us if that device is one of our ports. */
                struct odp_port port;
                for_us = !dpif_port_query_by_name(mon->dpif, devname, &port);
            }

            if (!for_us) {
                /* Not for us, try again. */
                ofpbuf_delete(buf);
                COVERAGE_INC(dpifmon_poll_false_wakeup);
                goto again;
            }
            COVERAGE_INC(dpifmon_poll_changed);
            *devnamep = xstrdup(devname);
        }
        ofpbuf_delete(buf);
        break;

    case EAGAIN:
        /* Nothing to do. */
        break;

    case ENOBUFS:
        VLOG_WARN_RL(&slow_rl, "dpifmon socket overflowed");
        break;

    default:
        VLOG_WARN_RL(&slow_rl, "error on dpifmon socket: %s", strerror(error));
        break;
    }
    return error;
}

void
dpifmon_run(struct dpifmon *mon UNUSED)
{
    /* Nothing to do in this implementation. */
}

void
dpifmon_wait(struct dpifmon *mon)
{
    nl_sock_wait(mon->sock, POLLIN);
}
