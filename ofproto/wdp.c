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
#include "wdp-provider.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netdev.h"
#include "netlink.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "svec.h"
#include "timeval.h"
#include "util.h"
#include "valgrind.h"
#include "wdp-xflow.h"

#include "vlog.h"
#define THIS_MODULE VLM_wdp

/* wdp_rule */

/* Initializes a new 'struct wdp_rule', copying in the 'n_actions' elements of
 * 'actions'.
 *
 * The caller is responsible for initializing 'rule->cr'. */
void
wdp_rule_init(struct wdp_rule *rule, const union ofp_action *actions,
              size_t n_actions)
{
    rule->actions = xmemdup(actions, n_actions * sizeof *actions);
    rule->n_actions = n_actions;
    rule->created = time_msec();
    rule->idle_timeout = 0;
    rule->hard_timeout = 0;
    rule->client_data = NULL;
}

/* Frees the data in 'rule'. */
void
wdp_rule_uninit(struct wdp_rule *rule)
{
    free(rule->actions);
}

/* wdp */

static const struct wdp_class *base_wdp_classes[] = {
    /* XXX none yet */
};

struct registered_wdp_class {
    const struct wdp_class *wdp_class;
    int refcount;
};

static struct shash wdp_classes = SHASH_INITIALIZER(&wdp_classes);

/* Rate limit for individual messages going to or from the datapath, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit wdpmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Not really much point in logging many wdp errors. */
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

static void log_operation(const struct wdp *, const char *operation,
                          int error);

static void
wdp_initialize(void)
{
    static int status = -1;

    if (status < 0) {
        int i;

        status = 0;
        for (i = 0; i < ARRAY_SIZE(base_wdp_classes); i++) {
            wdp_register_provider(base_wdp_classes[i]);
        }
        wdp_xflow_register();
    }
}

/* Performs periodic work needed by all the various kinds of wdps.
 *
 * If your program opens any wdps, it must call both this function and
 * netdev_run() within its main poll loop. */
void
wdp_run(void)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, &wdp_classes) {
        const struct registered_wdp_class *registered_class = node->data;
        if (registered_class->wdp_class->run) {
            registered_class->wdp_class->run();
        }
    }
}

/* Arranges for poll_block() to wake up when wdp_run() needs to be called.
 *
 * If your program opens any wdps, it must call both this function and
 * netdev_wait() within its main poll loop. */
void
wdp_wait(void)
{
    struct shash_node *node;
    SHASH_FOR_EACH(node, &wdp_classes) {
        const struct registered_wdp_class *registered_class = node->data;
        if (registered_class->wdp_class->wait) {
            registered_class->wdp_class->wait();
        }
    }
}

/* Registers a new datapath provider.  After successful registration, new
 * datapaths of that type can be opened using wdp_open(). */
int
wdp_register_provider(const struct wdp_class *new_class)
{
    struct registered_wdp_class *registered_class;

    if (shash_find(&wdp_classes, new_class->type)) {
        VLOG_WARN("attempted to register duplicate datapath provider: %s",
                  new_class->type);
        return EEXIST;
    }

    registered_class = xmalloc(sizeof *registered_class);
    registered_class->wdp_class = new_class;
    registered_class->refcount = 0;

    shash_add(&wdp_classes, new_class->type, registered_class);

    return 0;
}

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any wdps.  After unregistration
 * new datapaths of that type cannot be opened using wdp_open(). */
int
wdp_unregister_provider(const char *type)
{
    struct shash_node *node;
    struct registered_wdp_class *registered_class;

    node = shash_find(&wdp_classes, type);
    if (!node) {
        VLOG_WARN("attempted to unregister a datapath provider that is not "
                  "registered: %s", type);
        return EAFNOSUPPORT;
    }

    registered_class = node->data;
    if (registered_class->refcount) {
        VLOG_WARN("attempted to unregister in use datapath provider: %s",
                  type);
        return EBUSY;
    }

    shash_delete(&wdp_classes, node);
    free(registered_class);

    return 0;
}

/* Clears 'types' and enumerates the types of all currently registered wdp
 * providers into it.  The caller must first initialize the svec. */
void
wdp_enumerate_types(struct svec *types)
{
    struct shash_node *node;

    wdp_initialize();
    svec_clear(types);

    SHASH_FOR_EACH (node, &wdp_classes) {
        const struct registered_wdp_class *registered_class = node->data;
        svec_add(types, registered_class->wdp_class->type);
    }
}

/* Clears 'names' and enumerates the names of all known created datapaths
 * with the given 'type'.  The caller must first initialize the svec. Returns 0
 * if successful, otherwise a positive errno value.
 *
 * Some kinds of datapaths might not be practically enumerable.  This is not
 * considered an error. */
int
wdp_enumerate_names(const char *type, struct svec *names)
{
    const struct registered_wdp_class *registered_class;
    const struct wdp_class *wdp_class;
    int error;

    wdp_initialize();
    svec_clear(names);

    registered_class = shash_find_data(&wdp_classes, type);
    if (!registered_class) {
        VLOG_WARN("could not enumerate unknown type: %s", type);
        return EAFNOSUPPORT;
    }

    wdp_class = registered_class->wdp_class;
    error = (wdp_class->enumerate
             ? wdp_class->enumerate(wdp_class, names)
             : 0);

    if (error) {
        VLOG_WARN("failed to enumerate %s datapaths: %s", wdp_class->type,
                  strerror(error));
    }

    return error;
}

/* Parses 'datapath_name', which is of the form type@name, into its
 * component pieces.  'name' and 'type' must be freed by the caller. */
void
wdp_parse_name(const char *datapath_name_, char **name, char **type)
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
do_open(const char *name, const char *type, bool create, struct wdp **wdpp)
{
    struct wdp *wdp = NULL;
    int error;
    struct registered_wdp_class *registered_class;

    wdp_initialize();

    if (!type || *type == '\0') {
        type = "system";
    }

    registered_class = shash_find_data(&wdp_classes, type);
    if (!registered_class) {
        VLOG_WARN("could not create datapath %s of unknown type %s", name,
                  type);
        error = EAFNOSUPPORT;
        goto exit;
    }

    error = registered_class->wdp_class->open(registered_class->wdp_class,
                                              name, create, &wdp);
    if (!error) {
        registered_class->refcount++;
    }

exit:
    *wdpp = error ? NULL : wdp;
    return error;
}

/* Tries to open an existing datapath named 'name' and type 'type'.  Will fail
 * if no datapath with 'name' and 'type' exists.  'type' may be either NULL or
 * the empty string to specify the default system type.  Returns 0 if
 * successful, otherwise a positive errno value.  On success stores a pointer
 * to the datapath in '*wdpp', otherwise a null pointer. */
int
wdp_open(const char *name, const char *type, struct wdp **wdpp)
{
    return do_open(name, type, false, wdpp);
}

/* Tries to create and open a new datapath with the given 'name' and 'type'.
 * 'type' may be either NULL or the empty string to specify the default system
 * type.  Will fail if a datapath with 'name' and 'type' already exists.
 * Returns 0 if successful, otherwise a positive errno value.  On success
 * stores a pointer to the datapath in '*wdpp', otherwise a null pointer. */
int
wdp_create(const char *name, const char *type, struct wdp **wdpp)
{
    return do_open(name, type, true, wdpp);
}

/* Tries to open a datapath with the given 'name' and 'type', creating it if it
 * does not exist.  'type' may be either NULL or the empty string to specify
 * the default system type.  Returns 0 if successful, otherwise a positive
 * errno value. On success stores a pointer to the datapath in '*wdpp',
 * otherwise a null pointer. */
int
wdp_create_and_open(const char *name, const char *type, struct wdp **wdpp)
{
    int error;

    error = wdp_create(name, type, wdpp);
    if (error == EEXIST || error == EBUSY) {
        error = wdp_open(name, type, wdpp);
        if (error) {
            VLOG_WARN("datapath %s already exists but cannot be opened: %s",
                      name, strerror(error));
        }
    } else if (error) {
        VLOG_WARN("failed to create datapath %s: %s", name, strerror(error));
    }
    return error;
}

/* Closes and frees the connection to 'wdp'.  Does not destroy the wdp
 * itself; call wdp_delete() first, instead, if that is desirable. */
void
wdp_close(struct wdp *wdp)
{
    if (wdp) {
        struct registered_wdp_class *registered_class;

        registered_class = shash_find_data(&wdp_classes, 
                                           wdp->wdp_class->type);
        assert(registered_class);
        assert(registered_class->refcount);

        registered_class->refcount--;
        wdp_uninit(wdp, true);
    }
}

/* Returns the name of datapath 'wdp' prefixed with the type
 * (for use in log messages). */
const char *
wdp_name(const struct wdp *wdp)
{
    return wdp->full_name;
}

/* Returns the name of datapath 'wdp' without the type
 * (for use in device names). */
const char *
wdp_base_name(const struct wdp *wdp)
{
    return wdp->base_name;
}

/* Enumerates all names that may be used to open 'wdp' into 'all_names'.  The
 * Linux datapath, for example, supports opening a datapath both by number,
 * e.g. "wdp0", and by the name of the datapath's local port.  For some
 * datapaths, this might be an infinite set (e.g. in a file name, slashes may
 * be duplicated any number of times), in which case only the names most likely
 * to be used will be enumerated.
 *
 * The caller must already have initialized 'all_names'.  Any existing names in
 * 'all_names' will not be disturbed. */
int
wdp_get_all_names(const struct wdp *wdp, struct svec *all_names)
{
    if (wdp->wdp_class->get_all_names) {
        int error = wdp->wdp_class->get_all_names(wdp, all_names);
        if (error) {
            VLOG_WARN_RL(&error_rl,
                         "failed to retrieve names for datpath %s: %s",
                         wdp_name(wdp), strerror(error));
        }
        return error;
    } else {
        svec_add(all_names, wdp_base_name(wdp));
        return 0;
    }
}

/* Destroys the datapath that 'wdp' is connected to, first removing all of
 * its ports.  After calling this function, it does not make sense to pass
 * 'wdp' to any functions other than wdp_name() or wdp_close(). */
int
wdp_delete(struct wdp *wdp)
{
    int error;

    COVERAGE_INC(wdp_destroy);

    error = wdp->wdp_class->destroy(wdp);
    log_operation(wdp, "delete", error);
    return error;
}

/* Obtains the set of features supported by 'wdp'.
 *
 * If successful, returns 0 and stores in '*featuresp' a newly allocated
 * "struct ofp_switch_features" that describes the features and ports supported
 * by 'wdp'.  The caller is responsible for initializing the header,
 * datapath_id, and n_buffers members of the returned "struct
 * ofp_switch_features".  The caller must free the returned buffer (with
 * ofpbuf_delete()) when it is no longer needed.
 *
 * On error, returns an OpenFlow error code (as constructed by ofp_mkerr()) and
 * sets '*featuresp' to NULL. */
int
wdp_get_features(const struct wdp *wdp, struct ofpbuf **featuresp)
{
    int error = wdp->wdp_class->get_features(wdp, featuresp);
    if (error) {
        *featuresp = NULL;
    }
    return error;
}

/* Retrieves statistics for 'wdp' into 'stats'.  Returns 0 if successful,
 * otherwise a positive errno value.  On error, clears 'stats' to
 * all-bits-zero. */
int
wdp_get_wdp_stats(const struct wdp *wdp, struct wdp_stats *stats)
{
    int error = wdp->wdp_class->get_stats(wdp, stats);
    if (error) {
        memset(stats, 0, sizeof *stats);
    }
    log_operation(wdp, "get_stats", error);
    return error;
}

/* Retrieves the current IP fragment handling policy for 'wdp' into
 * '*drop_frags': true indicates that fragments are dropped, false indicates
 * that fragments are treated in the same way as other IP packets (except that
 * the L4 header cannot be read).  Returns 0 if successful, otherwise a
 * positive errno value. */
int
wdp_get_drop_frags(const struct wdp *wdp, bool *drop_frags)
{
    int error = wdp->wdp_class->get_drop_frags(wdp, drop_frags);
    if (error) {
        *drop_frags = false;
    }
    log_operation(wdp, "get_drop_frags", error);
    return error;
}

/* Changes 'wdp''s treatment of IP fragments to 'drop_frags', whose meaning is
 * the same as for the get_drop_frags member function.  Returns 0 if
 * successful, otherwise a positive errno value.  EOPNOTSUPP indicates that
 * 'wdp''s fragment dropping policy is not configurable. */
int
wdp_set_drop_frags(struct wdp *wdp, bool drop_frags)
{
    int error;
    error = (wdp->wdp_class->set_drop_frags
             ? wdp->wdp_class->set_drop_frags(wdp, drop_frags)
             : EOPNOTSUPP);
    log_operation(wdp, "set_drop_frags", error);
    return error;
}

/* Clears the contents of 'port'. */
void
wdp_port_clear(struct wdp_port *port)
{
    memset(port, 0, sizeof *port);
}

/* Makes a deep copy of 'old' in 'port'.  The caller may free 'port''s data
 * with wdp_port_free(). */
void
wdp_port_copy(struct wdp_port *port, const struct wdp_port *old)
{
    port->netdev = old->netdev ? netdev_reopen(old->netdev) : NULL;
    port->opp = old->opp;
    port->devname = old->devname ? xstrdup(old->devname) : NULL;
    port->internal = old->internal;
}

/* Frees the data that 'port' points to (but not 'port' itself). */
void
wdp_port_free(struct wdp_port *port)
{
    if (port) {
        netdev_close(port->netdev);
        free(port->devname);
    }
}

/* Frees the data that each of the 'n' ports in 'ports' points to, and then
 * frees 'ports' itself. */
void
wdp_port_array_free(struct wdp_port *ports, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        wdp_port_free(&ports[i]);
    }
    free(ports);
}

/* Attempts to add 'devname' as a port on 'wdp':
 *
 *   - If 'internal' is true, attempts to create a new internal port (a virtual
 *     port implemented in software) by that name.
 *
 *   - If 'internal' is false, 'devname' must name an existing network device.
 *
 * If successful, returns 0 and sets '*port_nop' to the new port's OpenFlow
 * port number (if 'port_nop' is non-null).  On failure, returns a positive
 * errno value and sets '*port_nop' to OFPP_NONE (if 'port_nop' is non-null).
 *
 * Some wildcarded datapaths might have fixed sets of ports.  For these
 * datapaths this function will always fail.
 *
 * Possible error return values include:
 *
 *   - ENODEV: No device named 'devname' exists (if 'internal' is false).
 *
 *   - EEXIST: A device named 'devname' already exists (if 'internal' is true).
 *
 *   - EINVAL: Device 'devname' is not supported as part of a datapath (e.g. it
 *     is not an Ethernet device), or 'devname' is too long for a network
 *     device name (if 'internal' is true)
 *
 *   - EFBIG: The datapath already has as many ports as it can support.
 *
 *   - EOPNOTSUPP: 'wdp' has a fixed set of ports.
 */
int
wdp_port_add(struct wdp *wdp, const char *devname,
             bool internal, uint16_t *port_nop)
{
    uint16_t port_no;
    int error;

    COVERAGE_INC(wdp_port_add);

    error = (wdp->wdp_class->port_add
             ? wdp->wdp_class->port_add(wdp, devname, internal, &port_no)
             : EOPNOTSUPP);
    if (!error) {
        VLOG_DBG_RL(&wdpmsg_rl, "%s: added %s as port %"PRIu16,
                    wdp_name(wdp), devname, port_no);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to add %s as port: %s",
                     wdp_name(wdp), devname, strerror(error));
        port_no = OFPP_NONE;
    }
    if (port_nop) {
        *port_nop = port_no;
    }
    return error;
}

/* Attempts to remove 'wdp''s port numbered 'port_no'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Some wildcarded datapaths might have fixed sets of ports.  For these
 * datapaths this function will always fail.
 *
 * Possible error return values include:
 *
 *   - EINVAL: 'port_no' is outside the valid range, or this particular port is
 *     not removable (e.g. it is the local port).
 *
 *   - ENOENT: 'wdp' currently has no port numbered 'port_no'.
 *
 *   - EOPNOTSUPP: 'wdp' has a fixed set of ports.
 */
int
wdp_port_del(struct wdp *wdp, uint16_t port_no)
{
    int error;

    COVERAGE_INC(wdp_port_del);

    error = (wdp->wdp_class->port_del
             ? wdp->wdp_class->port_del(wdp, port_no)
             : EOPNOTSUPP);
    log_operation(wdp, "port_del", error);
    return error;
}

/* Looks up port number 'port_no' in 'wdp'.  On success, returns 0 and
 * initializes 'port' with port details.  On failure, returns a positive errno
 * value and clears the contents of 'port' (with wdp_port_clear()).
 *
 * The caller must not modify or free the returned wdp_port.  Calling
 * wdp_run() or wdp_port_poll() may free the returned wdp_port.
 *
 * Possible error return values include:
 *
 *   - EINVAL: 'port_no' is outside the valid range.
 *
 *   - ENOENT: 'wdp' currently has no port numbered 'port_no'.
 */
int
wdp_port_query_by_number(const struct wdp *wdp, uint16_t port_no,
                         struct wdp_port *port)
{
    int error;

    error = wdp->wdp_class->port_query_by_number(wdp, port_no, port);
    if (!error) {
        VLOG_DBG_RL(&wdpmsg_rl, "%s: port %"PRIu16" is device %s",
                    wdp_name(wdp), port_no, port->devname);
    } else {
        wdp_port_clear(port);
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %"PRIu16": %s",
                     wdp_name(wdp), port_no, strerror(error));
    }
    return error;
}

/* Same as wdp_port_query_by_number() except that it look for a port named
 * 'devname' in 'wdp'.
 *
 * Possible error return values include:
 *
 *   - ENODEV: No device named 'devname' exists.
 *
 *   - ENOENT: 'devname' exists but it is not attached as a port on 'wdp'.
 */
int
wdp_port_query_by_name(const struct wdp *wdp, const char *devname,
                       struct wdp_port *port)
{
    int error = wdp->wdp_class->port_query_by_name(wdp, devname, port);
    if (!error) {
        VLOG_DBG_RL(&wdpmsg_rl, "%s: device %s is on port %"PRIu16,
                    wdp_name(wdp), devname, port->opp.port_no);
    } else {
        wdp_port_clear(port);

        /* Log level is DBG here because all the current callers are interested
         * in whether 'wdp' actually has a port 'devname', so that it's not
         * an issue worth logging if it doesn't. */
        VLOG_DBG_RL(&error_rl, "%s: failed to query port %s: %s",
                    wdp_name(wdp), devname, strerror(error));
    }
    return error;
}

/* Looks up port number 'port_no' in 'wdp'.  On success, returns 0 and stores
 * a copy of the port's name in '*namep'.  On failure, returns a positive errno
 * value and stores NULL in '*namep'.
 *
 * Error return values are the same as for wdp_port_query_by_name().
 *
 * The caller is responsible for freeing '*namep' (with free()). */
int
wdp_port_get_name(struct wdp *wdp, uint16_t port_no, char **namep)
{
    struct wdp_port port;
    int error;

    error = wdp_port_query_by_number(wdp, port_no, &port);
    *namep = port.devname;
    port.devname = NULL;
    wdp_port_free(&port);

    return error;
}

/* Obtains a list of all the ports in 'wdp', in no particular order.
 *
 * If successful, returns 0 and sets '*portsp' to point to an array of struct
 * wdp_port and '*n_portsp' to the number of pointers in the array.  On
 * failure, returns a positive errno value and sets '*portsp' to NULL and
 * '*n_portsp' to 0.
 *
 * The caller is responsible for freeing '*portsp' and the individual wdp_port
 * structures, e.g. with wdp_port_array_free().  */
int
wdp_port_list(const struct wdp *wdp,
              struct wdp_port **portsp, size_t *n_portsp)
{
    int error;

    error = wdp->wdp_class->port_list(wdp, portsp, n_portsp);
    if (error) {
        *portsp = NULL;
        *n_portsp = 0;
    }
    log_operation(wdp, "port_list", error);
    return error;
}

int
wdp_port_set_config(struct wdp *wdp, uint16_t port_no, uint32_t config)
{
    return wdp->wdp_class->port_set_config(wdp, port_no, config);
}

/* Polls for changes in the set of ports in 'wdp'.  If the set of ports in
 * 'wdp' has changed, this function does one of the following:
 *
 * - Stores the name of the device that was added to or deleted from 'wdp' in
 *   '*devnamep' and returns 0.  The caller is responsible for freeing
 *   '*devnamep' (with free()) when it no longer needs it.
 *
 * - Returns ENOBUFS and sets '*devnamep' to NULL.
 *
 * This function may also return 'false positives', where it returns 0 and
 * '*devnamep' names a device that was not actually added or deleted or it
 * returns ENOBUFS without any change.
 *
 * Returns EAGAIN if the set of ports in 'wdp' has not changed.  May also
 * return other positive errno values to indicate that something has gone
 * wrong. */
int
wdp_port_poll(const struct wdp *wdp, char **devnamep)
{
    int error = (wdp->wdp_class->port_poll
                 ? wdp->wdp_class->port_poll(wdp, devnamep)
                 : EAGAIN);
    if (error) {
        *devnamep = NULL;
    }
    return error;
}

/* Arranges for the poll loop to wake up when port_poll(wdp) will return a
 * value other than EAGAIN. */
void
wdp_port_poll_wait(const struct wdp *wdp)
{
    if (wdp->wdp_class->port_poll_wait) {
        wdp->wdp_class->port_poll_wait(wdp);
    }
}

/* Deletes all flows from 'wdp'.  Returns 0 if successful, otherwise a
 * positive errno value.  */
int
wdp_flow_flush(struct wdp *wdp)
{
    int error;

    COVERAGE_INC(wdp_flow_flush);

    error = wdp->wdp_class->flow_flush(wdp);
    log_operation(wdp, "flow_flush", error);
    return error;
}

struct wdp_rule *
wdp_flow_get(struct wdp *wdp, const flow_t *flow)
{
    return wdp->wdp_class->flow_get(wdp, flow);
}

struct wdp_rule *
wdp_flow_match(struct wdp *wdp, const flow_t *flow)
{
    return wdp->wdp_class->flow_match(wdp, flow);
}

void
wdp_flow_for_each_match(const struct wdp *wdp, const flow_t *target,
                        int include, wdp_flow_cb_func *callback, void *aux)
{
    wdp->wdp_class->flow_for_each_match(wdp, target, include,
                                        callback, aux); 
}

int
wdp_flow_get_stats(const struct wdp *wdp, const struct wdp_rule *rule,
                   struct wdp_flow_stats *stats)
{
    int error = wdp->wdp_class->flow_get_stats(wdp, rule, stats);
    if (error) {
        memset(stats, 0, sizeof *stats);
    }
    return error;
}

bool
wdp_flow_overlaps(const struct wdp *wdp, const flow_t *flow)
{
    return wdp->wdp_class->flow_overlaps(wdp, flow);
}

int
wdp_flow_put(struct wdp *wdp, struct wdp_flow_put *put,
             struct wdp_flow_stats *old_stats, struct wdp_rule **rulep)
{
    int error = wdp->wdp_class->flow_put(wdp, put, old_stats, rulep);
    if (error) {
        if (old_stats) {
            memset(old_stats, 0, sizeof *old_stats);
        }
        if (rulep) {
            *rulep = NULL;
        }
    }
    return error;
}

int
wdp_flow_delete(struct wdp *wdp, struct wdp_rule *rule,
                struct wdp_flow_stats *final_stats)
{
    int error = wdp->wdp_class->flow_delete(wdp, rule, final_stats);
    if (error && final_stats) {
        memset(final_stats, 0, sizeof *final_stats);
    }
    return error;
}

int
wdp_flow_inject(struct wdp *wdp, struct wdp_rule *rule,
                uint16_t in_port, const struct ofpbuf *packet)
{
    return wdp->wdp_class->flow_inject(wdp, rule, in_port, packet);
}

int
wdp_execute(struct wdp *wdp, uint16_t in_port,
            const union ofp_action actions[], size_t n_actions,
            const struct ofpbuf *buf)
{
    int error;

    COVERAGE_INC(wdp_execute);
    if (n_actions > 0) {
        error = wdp->wdp_class->execute(wdp, in_port, actions,
                                        n_actions, buf);
    } else {
        error = 0;
    }
    return error;
}

/* Retrieves 'wdp''s "listen mask" into '*listen_mask'.  Each bit set in
 * '*listen_mask' indicates that wdp_recv() will receive messages of the
 * corresponding WDP_CHAN_* type.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
wdp_recv_get_mask(const struct wdp *wdp, int *listen_mask)
{
    int error = wdp->wdp_class->recv_get_mask(wdp, listen_mask);
    if (error) {
        *listen_mask = 0;
    }
    log_operation(wdp, "recv_get_mask", error);
    return error;
}

/* Sets 'wdp''s "listen mask" to 'listen_mask'.  Each bit set in
 * '*listen_mask' requests that wdp_recv() receive messages of the
 * corresponding WDP_CHAN_* type.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
wdp_recv_set_mask(struct wdp *wdp, int listen_mask)
{
    int error = wdp->wdp_class->recv_set_mask(wdp, listen_mask);
    log_operation(wdp, "recv_set_mask", error);
    return error;
}

/* Retrieve the sFlow sampling probability.  '*probability' is expressed as the
 * number of packets out of UINT_MAX to sample, e.g. probability/UINT_MAX is
 * the probability of sampling a given packet.
 *
 * Returns 0 if successful, otherwise a positive errno value.  EOPNOTSUPP
 * indicates that 'wdp' does not support sFlow sampling. */
int
wdp_get_sflow_probability(const struct wdp *wdp, uint32_t *probability)
{
    int error = (wdp->wdp_class->get_sflow_probability
                 ? wdp->wdp_class->get_sflow_probability(wdp, probability)
                 : EOPNOTSUPP);
    if (error) {
        *probability = 0;
    }
    log_operation(wdp, "get_sflow_probability", error);
    return error;
}

/* Set the sFlow sampling probability.  'probability' is expressed as the
 * number of packets out of UINT_MAX to sample, e.g. probability/UINT_MAX is
 * the probability of sampling a given packet.
 *
 * Returns 0 if successful, otherwise a positive errno value.  EOPNOTSUPP
 * indicates that 'wdp' does not support sFlow sampling. */
int
wdp_set_sflow_probability(struct wdp *wdp, uint32_t probability)
{
    int error = (wdp->wdp_class->set_sflow_probability
                 ? wdp->wdp_class->set_sflow_probability(wdp, probability)
                 : EOPNOTSUPP);
    log_operation(wdp, "set_sflow_probability", error);
    return error;
}

/* Attempts to receive a message from 'wdp'.  If successful, stores the
 * message into '*packetp'.  Only messages of the types selected with
 * wdp_set_listen_mask() will ordinarily be received (but if a message type
 * is enabled and then later disabled, some stragglers might pop up).
 *
 * Returns 0 if successful, otherwise a positive errno value.  Returns EAGAIN
 * if no message is immediately available. */
int
wdp_recv(struct wdp *wdp, struct wdp_packet *packet)
{
    int error = wdp->wdp_class->recv(wdp, packet);
    if (!error) {
        /* XXX vlog_dbg received packet */
    } else {
        memset(packet, 0, sizeof *packet);
        packet->channel = -1;
    }
    return error;
}

/* Discards all messages that would otherwise be received by wdp_recv() on
 * 'wdp'.  Returns 0 if successful, otherwise a positive errno value. */
int
wdp_recv_purge(struct wdp *wdp)
{
    struct wdp_stats stats;
    unsigned int i;
    int error;

    COVERAGE_INC(wdp_purge);

    error = wdp_get_wdp_stats(wdp, &stats);
    if (error) {
        return error;
    }

    for (i = 0; i < stats.max_miss_queue + stats.max_action_queue + stats.max_sflow_queue; i++) {
        struct wdp_packet packet;

        error = wdp_recv(wdp, &packet);
        if (error) {
            return error == EAGAIN ? 0 : error;
        }
        ofpbuf_delete(packet.payload);
    }
    return 0;
}

/* Arranges for the poll loop to wake up when 'wdp' has a message queued to be
 * received with wdp_recv(). */
void
wdp_recv_wait(struct wdp *wdp)
{
    wdp->wdp_class->recv_wait(wdp);
}

/* Obtains the NetFlow engine type and engine ID for 'wdp' into '*engine_type'
 * and '*engine_id', respectively. */
void
wdp_get_netflow_ids(const struct wdp *wdp,
                    uint8_t *engine_type, uint8_t *engine_id)
{
    *engine_type = wdp->netflow_engine_type;
    *engine_id = wdp->netflow_engine_id;
}

void
wdp_packet_destroy(struct wdp_packet *packet)
{
    if (packet) {
        ofpbuf_delete(packet->payload);
        free(packet);
    }
}

void
wdp_init(struct wdp *wdp, const struct wdp_class *wdp_class,
         const char *name,
         uint8_t netflow_engine_type, uint8_t netflow_engine_id)
{
    wdp->wdp_class = wdp_class;
    wdp->base_name = xstrdup(name);
    wdp->full_name = xasprintf("%s@%s", wdp_class->type, name);
    wdp->netflow_engine_type = netflow_engine_type;
    wdp->netflow_engine_id = netflow_engine_id;
}

/* Undoes the results of initialization.
 *
 * Normally this function only needs to be called from wdp_close().
 * However, it may be called by providers due to an error on opening
 * that occurs after initialization.  It this case wdp_close() would
 * never be called. */
void
wdp_uninit(struct wdp *wdp, bool close)
{
    char *base_name = wdp->base_name;
    char *full_name = wdp->full_name;

    if (close) {
        wdp->wdp_class->close(wdp);
    }

    free(base_name);
    free(full_name);
}

static void
log_operation(const struct wdp *wdp, const char *operation, int error)
{
    if (!error) {
        VLOG_DBG_RL(&wdpmsg_rl, "%s: %s success", wdp_name(wdp), operation);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     wdp_name(wdp), operation, strerror(error));
    }
}
