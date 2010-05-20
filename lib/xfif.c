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
#include "xfif-provider.h"

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
#include "xflow-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "svec.h"
#include "util.h"
#include "valgrind.h"

#include "vlog.h"
#define THIS_MODULE VLM_xfif

static const struct xfif_class *base_xfif_classes[] = {
    &xfif_linux_class,
    &xfif_netdev_class,
};

struct registered_xfif_class {
    struct xfif_class xfif_class;
    int refcount;
};
static struct shash xfif_classes = SHASH_INITIALIZER(&xfif_classes);

/* Rate limit for individual messages going to or from the datapath, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit dpmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Not really much point in logging many xfif errors. */
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static void log_operation(const struct xfif *, const char *operation,
                          int error);
static void log_flow_operation(const struct xfif *, const char *operation,
                               int error, struct xflow_flow *flow);
static void log_flow_put(struct xfif *, int error,
                         const struct xflow_flow_put *);
static bool should_log_flow_message(int error);
static void check_rw_xflow_flow(struct xflow_flow *);

static void
xf_initialize(void)
{
    static int status = -1;

    if (status < 0) {
        int i;

        status = 0;
        for (i = 0; i < ARRAY_SIZE(base_xfif_classes); i++) {
            xf_register_provider(base_xfif_classes[i]);
        }
    }
}

/* Performs periodic work needed by all the various kinds of xfifs.
 *
 * If your program opens any xfifs, it must call both this function and
 * netdev_run() within its main poll loop. */
void
xf_run(void)
{
    struct shash_node *node;
    SHASH_FOR_EACH(node, &xfif_classes) {
        const struct registered_xfif_class *registered_class = node->data;
        if (registered_class->xfif_class.run) {
            registered_class->xfif_class.run();
        }
    }
}

/* Arranges for poll_block() to wake up when xf_run() needs to be called.
 *
 * If your program opens any xfifs, it must call both this function and
 * netdev_wait() within its main poll loop. */
void
xf_wait(void)
{
    struct shash_node *node;
    SHASH_FOR_EACH(node, &xfif_classes) {
        const struct registered_xfif_class *registered_class = node->data;
        if (registered_class->xfif_class.wait) {
            registered_class->xfif_class.wait();
        }
    }
}

/* Registers a new datapath provider.  After successful registration, new
 * datapaths of that type can be opened using xfif_open(). */
int
xf_register_provider(const struct xfif_class *new_class)
{
    struct registered_xfif_class *registered_class;

    if (shash_find(&xfif_classes, new_class->type)) {
        VLOG_WARN("attempted to register duplicate datapath provider: %s",
                  new_class->type);
        return EEXIST;
    }

    registered_class = xmalloc(sizeof *registered_class);
    memcpy(&registered_class->xfif_class, new_class,
           sizeof registered_class->xfif_class);
    registered_class->refcount = 0;

    shash_add(&xfif_classes, new_class->type, registered_class);

    return 0;
}

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any xfifs.  After unregistration
 * new datapaths of that type cannot be opened using xfif_open(). */
int
xf_unregister_provider(const char *type)
{
    struct shash_node *node;
    struct registered_xfif_class *registered_class;

    node = shash_find(&xfif_classes, type);
    if (!node) {
        VLOG_WARN("attempted to unregister a datapath provider that is not "
                  "registered: %s", type);
        return EAFNOSUPPORT;
    }

    registered_class = node->data;
    if (registered_class->refcount) {
        VLOG_WARN("attempted to unregister in use datapath provider: %s", type);
        return EBUSY;
    }

    shash_delete(&xfif_classes, node);
    free(registered_class);

    return 0;
}

/* Clears 'types' and enumerates the types of all currently registered datapath
 * providers into it.  The caller must first initialize the svec. */
void
xf_enumerate_types(struct svec *types)
{
    struct shash_node *node;

    xf_initialize();
    svec_clear(types);

    SHASH_FOR_EACH(node, &xfif_classes) {
        const struct registered_xfif_class *registered_class = node->data;
        svec_add(types, registered_class->xfif_class.type);
    }
}

/* Clears 'names' and enumerates the names of all known created datapaths with
 * the given 'type'.  The caller must first initialize the svec. Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Some kinds of datapaths might not be practically enumerable.  This is not
 * considered an error. */
int
xf_enumerate_names(const char *type, struct svec *names)
{
    const struct registered_xfif_class *registered_class;
    const struct xfif_class *xfif_class;
    int error;

    xf_initialize();
    svec_clear(names);

    registered_class = shash_find_data(&xfif_classes, type);
    if (!registered_class) {
        VLOG_WARN("could not enumerate unknown type: %s", type);
        return EAFNOSUPPORT;
    }

    xfif_class = &registered_class->xfif_class;
    error = xfif_class->enumerate ? xfif_class->enumerate(names) : 0;

    if (error) {
        VLOG_WARN("failed to enumerate %s datapaths: %s", xfif_class->type,
                   strerror(error));
    }

    return error;
}

/* Parses 'datapath name', which is of the form type@name into its
 * component pieces.  'name' and 'type' must be freed by the caller. */
void
xf_parse_name(const char *datapath_name_, char **name, char **type)
{
    char *datapath_name = xstrdup(datapath_name_);
    char *separator;

    separator = strchr(datapath_name, '@');
    if (separator) {
        *separator = '\0';
        *type = datapath_name;
        *name = xstrdup(separator + 1);
    } else {
        *name = datapath_name;
        *type = NULL;
    }
}

static int
do_open(const char *name, const char *type, bool create, struct xfif **xfifp)
{
    struct xfif *xfif = NULL;
    int error;
    struct registered_xfif_class *registered_class;

    xf_initialize();

    if (!type || *type == '\0') {
        type = "system";
    }

    registered_class = shash_find_data(&xfif_classes, type);
    if (!registered_class) {
        VLOG_WARN("could not create datapath %s of unknown type %s", name,
                  type);
        error = EAFNOSUPPORT;
        goto exit;
    }

    error = registered_class->xfif_class.open(name, type, create, &xfif);
    if (!error) {
        registered_class->refcount++;
    }

exit:
    *xfifp = error ? NULL : xfif;
    return error;
}

/* Tries to open an existing datapath named 'name' and type 'type'.  Will fail
 * if no datapath with 'name' and 'type' exists.  'type' may be either NULL or
 * the empty string to specify the default system type.  Returns 0 if
 * successful, otherwise a positive errno value.  On success stores a pointer
 * to the datapath in '*xfifp', otherwise a null pointer. */
int
xfif_open(const char *name, const char *type, struct xfif **xfifp)
{
    return do_open(name, type, false, xfifp);
}

/* Tries to create and open a new datapath with the given 'name' and 'type'.
 * 'type' may be either NULL or the empty string to specify the default system
 * type.  Will fail if a datapath with 'name' and 'type' already exists.
 * Returns 0 if successful, otherwise a positive errno value.  On success
 * stores a pointer to the datapath in '*xfifp', otherwise a null pointer. */
int
xfif_create(const char *name, const char *type, struct xfif **xfifp)
{
    return do_open(name, type, true, xfifp);
}

/* Tries to open a datapath with the given 'name' and 'type', creating it if it
 * does not exist.  'type' may be either NULL or the empty string to specify
 * the default system type.  Returns 0 if successful, otherwise a positive
 * errno value. On success stores a pointer to the datapath in '*xfifp',
 * otherwise a null pointer. */
int
xfif_create_and_open(const char *name, const char *type, struct xfif **xfifp)
{
    int error;

    error = xfif_create(name, type, xfifp);
    if (error == EEXIST || error == EBUSY) {
        error = xfif_open(name, type, xfifp);
        if (error) {
            VLOG_WARN("datapath %s already exists but cannot be opened: %s",
                      name, strerror(error));
        }
    } else if (error) {
        VLOG_WARN("failed to create datapath %s: %s", name, strerror(error));
    }
    return error;
}

/* Closes and frees the connection to 'xfif'.  Does not destroy the datapath
 * itself; call xfif_delete() first, instead, if that is desirable. */
void
xfif_close(struct xfif *xfif)
{
    if (xfif) {
        struct registered_xfif_class *registered_class;

        registered_class = shash_find_data(&xfif_classes, 
                xfif->xfif_class->type);
        assert(registered_class);
        assert(registered_class->refcount);

        registered_class->refcount--;
        xfif_uninit(xfif, true);
    }
}

/* Returns the name of datapath 'xfif' prefixed with the type
 * (for use in log messages). */
const char *
xfif_name(const struct xfif *xfif)
{
    return xfif->full_name;
}

/* Returns the name of datapath 'xfif' without the type
 * (for use in device names). */
const char *
xfif_base_name(const struct xfif *xfif)
{
    return xfif->base_name;
}

/* Enumerates all names that may be used to open 'xfif' into 'all_names'.  The
 * Linux datapath, for example, supports opening a datapath both by number,
 * e.g. "dp0", and by the name of the datapath's local port.  For some
 * datapaths, this might be an infinite set (e.g. in a file name, slashes may
 * be duplicated any number of times), in which case only the names most likely
 * to be used will be enumerated.
 *
 * The caller must already have initialized 'all_names'.  Any existing names in
 * 'all_names' will not be disturbed. */
int
xfif_get_all_names(const struct xfif *xfif, struct svec *all_names)
{
    if (xfif->xfif_class->get_all_names) {
        int error = xfif->xfif_class->get_all_names(xfif, all_names);
        if (error) {
            VLOG_WARN_RL(&error_rl,
                         "failed to retrieve names for datpath %s: %s",
                         xfif_name(xfif), strerror(error));
        }
        return error;
    } else {
        svec_add(all_names, xfif_base_name(xfif));
        return 0;
    }
}

/* Destroys the datapath that 'xfif' is connected to, first removing all of its
 * ports.  After calling this function, it does not make sense to pass 'xfif'
 * to any functions other than xfif_name() or xfif_close(). */
int
xfif_delete(struct xfif *xfif)
{
    int error;

    COVERAGE_INC(xfif_destroy);

    error = xfif->xfif_class->destroy(xfif);
    log_operation(xfif, "delete", error);
    return error;
}

/* Retrieves statistics for 'xfif' into 'stats'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
xfif_get_xf_stats(const struct xfif *xfif, struct xflow_stats *stats)
{
    int error = xfif->xfif_class->get_stats(xfif, stats);
    if (error) {
        memset(stats, 0, sizeof *stats);
    }
    log_operation(xfif, "get_stats", error);
    return error;
}

/* Retrieves the current IP fragment handling policy for 'xfif' into
 * '*drop_frags': true indicates that fragments are dropped, false indicates
 * that fragments are treated in the same way as other IP packets (except that
 * the L4 header cannot be read).  Returns 0 if successful, otherwise a
 * positive errno value. */
int
xfif_get_drop_frags(const struct xfif *xfif, bool *drop_frags)
{
    int error = xfif->xfif_class->get_drop_frags(xfif, drop_frags);
    if (error) {
        *drop_frags = false;
    }
    log_operation(xfif, "get_drop_frags", error);
    return error;
}

/* Changes 'xfif''s treatment of IP fragments to 'drop_frags', whose meaning is
 * the same as for the get_drop_frags member function.  Returns 0 if
 * successful, otherwise a positive errno value. */
int
xfif_set_drop_frags(struct xfif *xfif, bool drop_frags)
{
    int error = xfif->xfif_class->set_drop_frags(xfif, drop_frags);
    log_operation(xfif, "set_drop_frags", error);
    return error;
}

/* Attempts to add 'devname' as a port on 'xfif', given the combination of
 * XFLOW_PORT_* flags in 'flags'.  If successful, returns 0 and sets '*port_nop'
 * to the new port's port number (if 'port_nop' is non-null).  On failure,
 * returns a positive errno value and sets '*port_nop' to UINT16_MAX (if
 * 'port_nop' is non-null). */
int
xfif_port_add(struct xfif *xfif, const char *devname, uint16_t flags,
              uint16_t *port_nop)
{
    uint16_t port_no;
    int error;

    COVERAGE_INC(xfif_port_add);

    error = xfif->xfif_class->port_add(xfif, devname, flags, &port_no);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: added %s as port %"PRIu16,
                    xfif_name(xfif), devname, port_no);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to add %s as port: %s",
                     xfif_name(xfif), devname, strerror(error));
        port_no = UINT16_MAX;
    }
    if (port_nop) {
        *port_nop = port_no;
    }
    return error;
}

/* Attempts to remove 'xfif''s port number 'port_no'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
xfif_port_del(struct xfif *xfif, uint16_t port_no)
{
    int error;

    COVERAGE_INC(xfif_port_del);

    error = xfif->xfif_class->port_del(xfif, port_no);
    log_operation(xfif, "port_del", error);
    return error;
}

/* Looks up port number 'port_no' in 'xfif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value. */
int
xfif_port_query_by_number(const struct xfif *xfif, uint16_t port_no,
                          struct xflow_port *port)
{
    int error = xfif->xfif_class->port_query_by_number(xfif, port_no, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port %"PRIu16" is device %s",
                    xfif_name(xfif), port_no, port->devname);
    } else {
        memset(port, 0, sizeof *port);
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %"PRIu16": %s",
                     xfif_name(xfif), port_no, strerror(error));
    }
    return error;
}

/* Looks up port named 'devname' in 'xfif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value. */
int
xfif_port_query_by_name(const struct xfif *xfif, const char *devname,
                        struct xflow_port *port)
{
    int error = xfif->xfif_class->port_query_by_name(xfif, devname, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: device %s is on port %"PRIu16,
                    xfif_name(xfif), devname, port->port);
    } else {
        memset(port, 0, sizeof *port);

        /* Log level is DBG here because all the current callers are interested
         * in whether 'xfif' actually has a port 'devname', so that it's not an
         * issue worth logging if it doesn't. */
        VLOG_DBG_RL(&error_rl, "%s: failed to query port %s: %s",
                    xfif_name(xfif), devname, strerror(error));
    }
    return error;
}

/* Looks up port number 'port_no' in 'xfif'.  On success, returns 0 and copies
 * the port's name into the 'name_size' bytes in 'name', ensuring that the
 * result is null-terminated.  On failure, returns a positive errno value and
 * makes 'name' the empty string. */
int
xfif_port_get_name(struct xfif *xfif, uint16_t port_no,
                   char *name, size_t name_size)
{
    struct xflow_port port;
    int error;

    assert(name_size > 0);

    error = xfif_port_query_by_number(xfif, port_no, &port);
    if (!error) {
        ovs_strlcpy(name, port.devname, name_size);
    } else {
        *name = '\0';
    }
    return error;
}

/* Obtains a list of all the ports in 'xfif'.
 *
 * If successful, returns 0 and sets '*portsp' to point to an array of
 * appropriately initialized port structures and '*n_portsp' to the number of
 * ports in the array.  The caller is responsible for freeing '*portp' by
 * calling free().
 *
 * On failure, returns a positive errno value and sets '*portsp' to NULL and
 * '*n_portsp' to 0. */
int
xfif_port_list(const struct xfif *xfif,
               struct xflow_port **portsp, size_t *n_portsp)
{
    struct xflow_port *ports;
    size_t n_ports = 0;
    int error;

    for (;;) {
        struct xflow_stats stats;
        int retval;

        error = xfif_get_xf_stats(xfif, &stats);
        if (error) {
            goto exit;
        }

        ports = xcalloc(stats.n_ports, sizeof *ports);
        retval = xfif->xfif_class->port_list(xfif, ports, stats.n_ports);
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
    log_operation(xfif, "port_list", error);
    return error;
}

/* Polls for changes in the set of ports in 'xfif'.  If the set of ports in
 * 'xfif' has changed, this function does one of the following:
 *
 * - Stores the name of the device that was added to or deleted from 'xfif' in
 *   '*devnamep' and returns 0.  The caller is responsible for freeing
 *   '*devnamep' (with free()) when it no longer needs it.
 *
 * - Returns ENOBUFS and sets '*devnamep' to NULL.
 *
 * This function may also return 'false positives', where it returns 0 and
 * '*devnamep' names a device that was not actually added or deleted or it
 * returns ENOBUFS without any change.
 *
 * Returns EAGAIN if the set of ports in 'xfif' has not changed.  May also
 * return other positive errno values to indicate that something has gone
 * wrong. */
int
xfif_port_poll(const struct xfif *xfif, char **devnamep)
{
    int error = xfif->xfif_class->port_poll(xfif, devnamep);
    if (error) {
        *devnamep = NULL;
    }
    return error;
}

/* Arranges for the poll loop to wake up when port_poll(xfif) will return a
 * value other than EAGAIN. */
void
xfif_port_poll_wait(const struct xfif *xfif)
{
    xfif->xfif_class->port_poll_wait(xfif);
}

/* Retrieves a list of the port numbers in port group 'group' in 'xfif'.
 *
 * On success, returns 0 and points '*ports' to a newly allocated array of
 * integers, each of which is a 'xfif' port number for a port in
 * 'group'.  Stores the number of elements in the array in '*n_ports'.  The
 * caller is responsible for freeing '*ports' by calling free().
 *
 * On failure, returns a positive errno value and sets '*ports' to NULL and
 * '*n_ports' to 0. */
int
xfif_port_group_get(const struct xfif *xfif, uint16_t group,
                    uint16_t **ports, size_t *n_ports)
{
    int error;

    *ports = NULL;
    *n_ports = 0;
    for (;;) {
        int retval = xfif->xfif_class->port_group_get(xfif, group,
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
    log_operation(xfif, "port_group_get", error);
    return error;
}

/* Updates port group 'group' in 'xfif', making it contain the 'n_ports' ports
 * whose 'xfif' port numbers are given in 'n_ports'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Behavior is undefined if the values in ports[] are not unique. */
int
xfif_port_group_set(struct xfif *xfif, uint16_t group,
                    const uint16_t ports[], size_t n_ports)
{
    int error;

    COVERAGE_INC(xfif_port_group_set);

    error = xfif->xfif_class->port_group_set(xfif, group, ports, n_ports);
    log_operation(xfif, "port_group_set", error);
    return error;
}

/* Deletes all flows from 'xfif'.  Returns 0 if successful, otherwise a
 * positive errno value.  */
int
xfif_flow_flush(struct xfif *xfif)
{
    int error;

    COVERAGE_INC(xfif_flow_flush);

    error = xfif->xfif_class->flow_flush(xfif);
    log_operation(xfif, "flow_flush", error);
    return error;
}

/* Queries 'xfif' for a flow entry matching 'flow->key'.
 *
 * If a flow matching 'flow->key' exists in 'xfif', stores statistics for the
 * flow into 'flow->stats'.  If 'flow->n_actions' is zero, then 'flow->actions'
 * is ignored.  If 'flow->n_actions' is nonzero, then 'flow->actions' should
 * point to an array of the specified number of actions.  At most that many of
 * the flow's actions will be copied into that array.  'flow->n_actions' will
 * be updated to the number of actions actually present in the flow, which may
 * be greater than the number stored if the flow has more actions than space
 * available in the array.
 *
 * If no flow matching 'flow->key' exists in 'xfif', returns ENOENT.  On other
 * failure, returns a positive errno value. */
int
xfif_flow_get(const struct xfif *xfif, struct xflow_flow *flow)
{
    int error;

    COVERAGE_INC(xfif_flow_get);

    check_rw_xflow_flow(flow);
    error = xfif->xfif_class->flow_get(xfif, flow, 1);
    if (!error) {
        error = flow->stats.error;
    }
    if (error) {
        /* Make the results predictable on error. */
        memset(&flow->stats, 0, sizeof flow->stats);
        flow->n_actions = 0;
    }
    if (should_log_flow_message(error)) {
        log_flow_operation(xfif, "flow_get", error, flow);
    }
    return error;
}

/* For each flow 'flow' in the 'n' flows in 'flows':
 *
 * - If a flow matching 'flow->key' exists in 'xfif':
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
 *   matching 'flow->key' exists in 'xfif'.  When an error value is stored, the
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
xfif_flow_get_multiple(const struct xfif *xfif,
                       struct xflow_flow flows[], size_t n)
{
    int error;
    size_t i;

    COVERAGE_ADD(xfif_flow_get, n);

    for (i = 0; i < n; i++) {
        check_rw_xflow_flow(&flows[i]);
    }

    error = xfif->xfif_class->flow_get(xfif, flows, n);
    log_operation(xfif, "flow_get_multiple", error);
    return error;
}

/* Adds or modifies a flow in 'xfif' as specified in 'put':
 *
 * - If the flow specified in 'put->flow' does not exist in 'xfif', then
 *   behavior depends on whether XFLOWPF_CREATE is specified in 'put->flags': if
 *   it is, the flow will be added, otherwise the operation will fail with
 *   ENOENT.
 *
 * - Otherwise, the flow specified in 'put->flow' does exist in 'xfif'.
 *   Behavior in this case depends on whether XFLOWPF_MODIFY is specified in
 *   'put->flags': if it is, the flow's actions will be updated, otherwise the
 *   operation will fail with EEXIST.  If the flow's actions are updated, then
 *   its statistics will be zeroed if XFLOWPF_ZERO_STATS is set in 'put->flags',
 *   left as-is otherwise.
 *
 * Returns 0 if successful, otherwise a positive errno value.
 */
int
xfif_flow_put(struct xfif *xfif, struct xflow_flow_put *put)
{
    int error;

    COVERAGE_INC(xfif_flow_put);

    error = xfif->xfif_class->flow_put(xfif, put);
    if (should_log_flow_message(error)) {
        log_flow_put(xfif, error, put);
    }
    return error;
}

/* Deletes a flow matching 'flow->key' from 'xfif' or returns ENOENT if 'xfif'
 * does not contain such a flow.
 *
 * If successful, updates 'flow->stats', 'flow->n_actions', and 'flow->actions'
 * as described for xfif_flow_get(). */
int
xfif_flow_del(struct xfif *xfif, struct xflow_flow *flow)
{
    int error;

    COVERAGE_INC(xfif_flow_del);

    check_rw_xflow_flow(flow);
    memset(&flow->stats, 0, sizeof flow->stats);

    error = xfif->xfif_class->flow_del(xfif, flow);
    if (should_log_flow_message(error)) {
        log_flow_operation(xfif, "delete flow", error, flow);
    }
    return error;
}

/* Stores up to 'n' flows in 'xfif' into 'flows', including their statistics
 * but not including any information about their actions.  If successful,
 * returns 0 and sets '*n_out' to the number of flows actually present in
 * 'xfif', which might be greater than the number stored (if 'xfif' has more
 * than 'n' flows).  On failure, returns a negative errno value and sets
 * '*n_out' to 0. */
int
xfif_flow_list(const struct xfif *xfif, struct xflow_flow flows[], size_t n,
               size_t *n_out)
{
    uint32_t i;
    int retval;

    COVERAGE_INC(xfif_flow_query_list);
    if (RUNNING_ON_VALGRIND) {
        memset(flows, 0, n * sizeof *flows);
    } else {
        for (i = 0; i < n; i++) {
            flows[i].actions = NULL;
            flows[i].n_actions = 0;
        }
    }
    retval = xfif->xfif_class->flow_list(xfif, flows, n);
    if (retval < 0) {
        *n_out = 0;
        VLOG_WARN_RL(&error_rl, "%s: flow list failed (%s)",
                     xfif_name(xfif), strerror(-retval));
        return -retval;
    } else {
        COVERAGE_ADD(xfif_flow_query_list_n, retval);
        *n_out = MIN(n, retval);
        VLOG_DBG_RL(&dpmsg_rl, "%s: listed %zu flows (of %d)",
                    xfif_name(xfif), *n_out, retval);
        return 0;
    }
}

/* Retrieves all of the flows in 'xfif'.
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
xfif_flow_list_all(const struct xfif *xfif,
                   struct xflow_flow **flowsp, size_t *np)
{
    struct xflow_stats stats;
    struct xflow_flow *flows;
    size_t n_flows;
    int error;

    *flowsp = NULL;
    *np = 0;

    error = xfif_get_xf_stats(xfif, &stats);
    if (error) {
        return error;
    }

    flows = xmalloc(sizeof *flows * stats.n_flows);
    error = xfif_flow_list(xfif, flows, stats.n_flows, &n_flows);
    if (error) {
        free(flows);
        return error;
    }

    if (stats.n_flows != n_flows) {
        VLOG_WARN_RL(&error_rl, "%s: datapath stats reported %"PRIu32" "
                     "flows but flow listing reported %zu",
                     xfif_name(xfif), stats.n_flows, n_flows);
    }
    *flowsp = flows;
    *np = n_flows;
    return 0;
}

/* Causes 'xfif' to perform the 'n_actions' actions in 'actions' on the
 * Ethernet frame specified in 'packet'.
 *
 * Pretends that the frame was originally received on the port numbered
 * 'in_port'.  This affects only XFLOWAT_OUTPUT_GROUP actions, which will not
 * send a packet out their input port.  Specify the number of an unused port
 * (e.g. UINT16_MAX is currently always unused) to avoid this behavior.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
xfif_execute(struct xfif *xfif, uint16_t in_port,
             const union xflow_action actions[], size_t n_actions,
             const struct ofpbuf *buf)
{
    int error;

    COVERAGE_INC(xfif_execute);
    if (n_actions > 0) {
        error = xfif->xfif_class->execute(xfif, in_port, actions,
                                          n_actions, buf);
    } else {
        error = 0;
    }

    if (!(error ? VLOG_DROP_WARN(&error_rl) : VLOG_DROP_DBG(&dpmsg_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet = ofp_packet_to_string(buf->data, buf->size, buf->size);
        ds_put_format(&ds, "%s: execute ", xfif_name(xfif));
        format_xflow_actions(&ds, actions, n_actions);
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

/* Retrieves 'xfif''s "listen mask" into '*listen_mask'.  Each XFLOWL_* bit set
 * in '*listen_mask' indicates that xfif_recv() will receive messages of that
 * type.  Returns 0 if successful, otherwise a positive errno value. */
int
xfif_recv_get_mask(const struct xfif *xfif, int *listen_mask)
{
    int error = xfif->xfif_class->recv_get_mask(xfif, listen_mask);
    if (error) {
        *listen_mask = 0;
    }
    log_operation(xfif, "recv_get_mask", error);
    return error;
}

/* Sets 'xfif''s "listen mask" to 'listen_mask'.  Each XFLOWL_* bit set in
 * '*listen_mask' requests that xfif_recv() receive messages of that type.
 * Returns 0 if successful, otherwise a positive errno value. */
int
xfif_recv_set_mask(struct xfif *xfif, int listen_mask)
{
    int error = xfif->xfif_class->recv_set_mask(xfif, listen_mask);
    log_operation(xfif, "recv_set_mask", error);
    return error;
}

/* Retrieve the sFlow sampling probability.  '*probability' is expressed as the
 * number of packets out of UINT_MAX to sample, e.g. probability/UINT_MAX is
 * the probability of sampling a given packet.
 *
 * Returns 0 if successful, otherwise a positive errno value.  EOPNOTSUPP
 * indicates that 'xfif' does not support sFlow sampling. */
int
xfif_get_sflow_probability(const struct xfif *xfif, uint32_t *probability)
{
    int error = (xfif->xfif_class->get_sflow_probability
                 ? xfif->xfif_class->get_sflow_probability(xfif, probability)
                 : EOPNOTSUPP);
    if (error) {
        *probability = 0;
    }
    log_operation(xfif, "get_sflow_probability", error);
    return error;
}

/* Set the sFlow sampling probability.  'probability' is expressed as the
 * number of packets out of UINT_MAX to sample, e.g. probability/UINT_MAX is
 * the probability of sampling a given packet.
 *
 * Returns 0 if successful, otherwise a positive errno value.  EOPNOTSUPP
 * indicates that 'xfif' does not support sFlow sampling. */
int
xfif_set_sflow_probability(struct xfif *xfif, uint32_t probability)
{
    int error = (xfif->xfif_class->set_sflow_probability
                 ? xfif->xfif_class->set_sflow_probability(xfif, probability)
                 : EOPNOTSUPP);
    log_operation(xfif, "set_sflow_probability", error);
    return error;
}

/* Attempts to receive a message from 'xfif'.  If successful, stores the
 * message into '*packetp'.  The message, if one is received, will begin with
 * 'struct xflow_msg' as a header, and will have at least XFIF_RECV_MSG_PADDING
 * bytes of headroom.  Only messages of the types selected with
 * xfif_set_listen_mask() will ordinarily be received (but if a message type is
 * enabled and then later disabled, some stragglers might pop up).
 *
 * Returns 0 if successful, otherwise a positive errno value.  Returns EAGAIN
 * if no message is immediately available. */
int
xfif_recv(struct xfif *xfif, struct ofpbuf **packetp)
{
    int error = xfif->xfif_class->recv(xfif, packetp);
    if (!error) {
        struct ofpbuf *buf = *packetp;

        assert(ofpbuf_headroom(buf) >= XFIF_RECV_MSG_PADDING);
        if (VLOG_IS_DBG_ENABLED()) {
            struct xflow_msg *msg = buf->data;
            void *payload = msg + 1;
            size_t payload_len = buf->size - sizeof *msg;
            char *s = ofp_packet_to_string(payload, payload_len, payload_len);
            VLOG_DBG_RL(&dpmsg_rl, "%s: received %s message of length "
                        "%zu on port %"PRIu16": %s", xfif_name(xfif),
                        (msg->type == _XFLOWL_MISS_NR ? "miss"
                         : msg->type == _XFLOWL_ACTION_NR ? "action"
                         : msg->type == _XFLOWL_SFLOW_NR ? "sFlow"
                         : "<unknown>"),
                        payload_len, msg->port, s);
            free(s);
        }
    } else {
        *packetp = NULL;
    }
    return error;
}

/* Discards all messages that would otherwise be received by xfif_recv() on
 * 'xfif'.  Returns 0 if successful, otherwise a positive errno value. */
int
xfif_recv_purge(struct xfif *xfif)
{
    struct xflow_stats stats;
    unsigned int i;
    int error;

    COVERAGE_INC(xfif_purge);

    error = xfif_get_xf_stats(xfif, &stats);
    if (error) {
        return error;
    }

    for (i = 0; i < stats.max_miss_queue + stats.max_action_queue + stats.max_sflow_queue; i++) {
        struct ofpbuf *buf;
        error = xfif_recv(xfif, &buf);
        if (error) {
            return error == EAGAIN ? 0 : error;
        }
        ofpbuf_delete(buf);
    }
    return 0;
}

/* Arranges for the poll loop to wake up when 'xfif' has a message queued to be
 * received with xfif_recv(). */
void
xfif_recv_wait(struct xfif *xfif)
{
    xfif->xfif_class->recv_wait(xfif);
}

/* Obtains the NetFlow engine type and engine ID for 'xfif' into '*engine_type'
 * and '*engine_id', respectively. */
void
xfif_get_netflow_ids(const struct xfif *xfif,
                     uint8_t *engine_type, uint8_t *engine_id)
{
    *engine_type = xfif->netflow_engine_type;
    *engine_id = xfif->netflow_engine_id;
}

void
xfif_init(struct xfif *xfif, const struct xfif_class *xfif_class,
          const char *name,
          uint8_t netflow_engine_type, uint8_t netflow_engine_id)
{
    xfif->xfif_class = xfif_class;
    xfif->base_name = xstrdup(name);
    xfif->full_name = xasprintf("%s@%s", xfif_class->type, name);
    xfif->netflow_engine_type = netflow_engine_type;
    xfif->netflow_engine_id = netflow_engine_id;
}

/* Undoes the results of initialization.
 *
 * Normally this function only needs to be called from xfif_close().
 * However, it may be called by providers due to an error on opening
 * that occurs after initialization.  In this case xfif_close() would
 * never be called. */
void
xfif_uninit(struct xfif *xfif, bool close)
{
    char *base_name = xfif->base_name;
    char *full_name = xfif->full_name;

    if (close) {
        xfif->xfif_class->close(xfif);
    }

    free(base_name);
    free(full_name);
}

static void
log_operation(const struct xfif *xfif, const char *operation, int error)
{
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: %s success", xfif_name(xfif), operation);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     xfif_name(xfif), operation, strerror(error));
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
log_flow_message(const struct xfif *xfif, int error, const char *operation,
                 const struct xflow_key *flow,
                 const struct xflow_flow_stats *stats,
                 const union xflow_action *actions, size_t n_actions)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "%s: ", xfif_name(xfif));
    if (error) {
        ds_put_cstr(&ds, "failed to ");
    }
    ds_put_format(&ds, "%s ", operation);
    if (error) {
        ds_put_format(&ds, "(%s) ", strerror(error));
    }
    format_xflow_key(&ds, flow);
    if (stats) {
        ds_put_cstr(&ds, ", ");
        format_xflow_flow_stats(&ds, stats);
    }
    if (actions || n_actions) {
        ds_put_cstr(&ds, ", actions:");
        format_xflow_actions(&ds, actions, n_actions);
    }
    vlog(THIS_MODULE, flow_message_log_level(error), "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
log_flow_operation(const struct xfif *xfif, const char *operation, int error,
                   struct xflow_flow *flow)
{
    if (error) {
        flow->n_actions = 0;
    }
    log_flow_message(xfif, error, operation, &flow->key,
                     !error ? &flow->stats : NULL,
                     flow->actions, flow->n_actions);
}

static void
log_flow_put(struct xfif *xfif, int error, const struct xflow_flow_put *put)
{
    enum { XFLOWPF_ALL = XFLOWPF_CREATE | XFLOWPF_MODIFY | XFLOWPF_ZERO_STATS };
    struct ds s;

    ds_init(&s);
    ds_put_cstr(&s, "put");
    if (put->flags & XFLOWPF_CREATE) {
        ds_put_cstr(&s, "[create]");
    }
    if (put->flags & XFLOWPF_MODIFY) {
        ds_put_cstr(&s, "[modify]");
    }
    if (put->flags & XFLOWPF_ZERO_STATS) {
        ds_put_cstr(&s, "[zero]");
    }
    if (put->flags & ~XFLOWPF_ALL) {
        ds_put_format(&s, "[%x]", put->flags & ~XFLOWPF_ALL);
    }
    log_flow_message(xfif, error, ds_cstr(&s), &put->flow.key,
                     !error ? &put->flow.stats : NULL,
                     put->flow.actions, put->flow.n_actions);
    ds_destroy(&s);
}

/* There is a tendency to construct xflow_flow objects on the stack and to
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
check_rw_xflow_flow(struct xflow_flow *flow)
{
    if (flow->n_actions) {
        memset(&flow->actions[0], 0xcc, sizeof flow->actions[0]);
    }
}
