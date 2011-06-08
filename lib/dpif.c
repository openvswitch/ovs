/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "util.h"
#include "valgrind.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif);

COVERAGE_DEFINE(dpif_destroy);
COVERAGE_DEFINE(dpif_port_add);
COVERAGE_DEFINE(dpif_port_del);
COVERAGE_DEFINE(dpif_flow_flush);
COVERAGE_DEFINE(dpif_flow_get);
COVERAGE_DEFINE(dpif_flow_put);
COVERAGE_DEFINE(dpif_flow_del);
COVERAGE_DEFINE(dpif_flow_query_list);
COVERAGE_DEFINE(dpif_flow_query_list_n);
COVERAGE_DEFINE(dpif_execute);
COVERAGE_DEFINE(dpif_purge);

static const struct dpif_class *base_dpif_classes[] = {
#ifdef HAVE_NETLINK
    &dpif_linux_class,
#endif
    &dpif_netdev_class,
};

struct registered_dpif_class {
    const struct dpif_class *dpif_class;
    int refcount;
};
static struct shash dpif_classes = SHASH_INITIALIZER(&dpif_classes);

/* Rate limit for individual messages going to or from the datapath, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit dpmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Not really much point in logging many dpif errors. */
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static void log_flow_message(const struct dpif *dpif, int error,
                             const char *operation,
                             const struct nlattr *key, size_t key_len,
                             const struct dpif_flow_stats *stats,
                             const struct nlattr *actions, size_t actions_len);
static void log_operation(const struct dpif *, const char *operation,
                          int error);
static bool should_log_flow_message(int error);

static void
dp_initialize(void)
{
    static int status = -1;

    if (status < 0) {
        int i;

        status = 0;
        for (i = 0; i < ARRAY_SIZE(base_dpif_classes); i++) {
            dp_register_provider(base_dpif_classes[i]);
        }
    }
}

/* Registers a new datapath provider.  After successful registration, new
 * datapaths of that type can be opened using dpif_open(). */
int
dp_register_provider(const struct dpif_class *new_class)
{
    struct registered_dpif_class *registered_class;

    if (shash_find(&dpif_classes, new_class->type)) {
        VLOG_WARN("attempted to register duplicate datapath provider: %s",
                  new_class->type);
        return EEXIST;
    }

    registered_class = xmalloc(sizeof *registered_class);
    registered_class->dpif_class = new_class;
    registered_class->refcount = 0;

    shash_add(&dpif_classes, new_class->type, registered_class);

    return 0;
}

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any dpifs.  After unregistration
 * new datapaths of that type cannot be opened using dpif_open(). */
int
dp_unregister_provider(const char *type)
{
    struct shash_node *node;
    struct registered_dpif_class *registered_class;

    node = shash_find(&dpif_classes, type);
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

    shash_delete(&dpif_classes, node);
    free(registered_class);

    return 0;
}

/* Clears 'types' and enumerates the types of all currently registered datapath
 * providers into it.  The caller must first initialize the sset. */
void
dp_enumerate_types(struct sset *types)
{
    struct shash_node *node;

    dp_initialize();
    sset_clear(types);

    SHASH_FOR_EACH(node, &dpif_classes) {
        const struct registered_dpif_class *registered_class = node->data;
        sset_add(types, registered_class->dpif_class->type);
    }
}

/* Clears 'names' and enumerates the names of all known created datapaths with
 * the given 'type'.  The caller must first initialize the sset.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Some kinds of datapaths might not be practically enumerable.  This is not
 * considered an error. */
int
dp_enumerate_names(const char *type, struct sset *names)
{
    const struct registered_dpif_class *registered_class;
    const struct dpif_class *dpif_class;
    int error;

    dp_initialize();
    sset_clear(names);

    registered_class = shash_find_data(&dpif_classes, type);
    if (!registered_class) {
        VLOG_WARN("could not enumerate unknown type: %s", type);
        return EAFNOSUPPORT;
    }

    dpif_class = registered_class->dpif_class;
    error = dpif_class->enumerate ? dpif_class->enumerate(names) : 0;

    if (error) {
        VLOG_WARN("failed to enumerate %s datapaths: %s", dpif_class->type,
                   strerror(error));
    }

    return error;
}

/* Parses 'datapath_name_', which is of the form [type@]name into its
 * component pieces.  'name' and 'type' must be freed by the caller.
 *
 * The returned 'type' is normalized, as if by dpif_normalize_type(). */
void
dp_parse_name(const char *datapath_name_, char **name, char **type)
{
    char *datapath_name = xstrdup(datapath_name_);
    char *separator;

    separator = strchr(datapath_name, '@');
    if (separator) {
        *separator = '\0';
        *type = datapath_name;
        *name = xstrdup(dpif_normalize_type(separator + 1));
    } else {
        *name = datapath_name;
        *type = xstrdup(dpif_normalize_type(NULL));
    }
}

static int
do_open(const char *name, const char *type, bool create, struct dpif **dpifp)
{
    struct dpif *dpif = NULL;
    int error;
    struct registered_dpif_class *registered_class;

    dp_initialize();

    type = dpif_normalize_type(type);

    registered_class = shash_find_data(&dpif_classes, type);
    if (!registered_class) {
        VLOG_WARN("could not create datapath %s of unknown type %s", name,
                  type);
        error = EAFNOSUPPORT;
        goto exit;
    }

    error = registered_class->dpif_class->open(registered_class->dpif_class,
                                               name, create, &dpif);
    if (!error) {
        assert(dpif->dpif_class == registered_class->dpif_class);
        registered_class->refcount++;
    }

exit:
    *dpifp = error ? NULL : dpif;
    return error;
}

/* Tries to open an existing datapath named 'name' and type 'type'.  Will fail
 * if no datapath with 'name' and 'type' exists.  'type' may be either NULL or
 * the empty string to specify the default system type.  Returns 0 if
 * successful, otherwise a positive errno value.  On success stores a pointer
 * to the datapath in '*dpifp', otherwise a null pointer. */
int
dpif_open(const char *name, const char *type, struct dpif **dpifp)
{
    return do_open(name, type, false, dpifp);
}

/* Tries to create and open a new datapath with the given 'name' and 'type'.
 * 'type' may be either NULL or the empty string to specify the default system
 * type.  Will fail if a datapath with 'name' and 'type' already exists.
 * Returns 0 if successful, otherwise a positive errno value.  On success
 * stores a pointer to the datapath in '*dpifp', otherwise a null pointer. */
int
dpif_create(const char *name, const char *type, struct dpif **dpifp)
{
    return do_open(name, type, true, dpifp);
}

/* Tries to open a datapath with the given 'name' and 'type', creating it if it
 * does not exist.  'type' may be either NULL or the empty string to specify
 * the default system type.  Returns 0 if successful, otherwise a positive
 * errno value. On success stores a pointer to the datapath in '*dpifp',
 * otherwise a null pointer. */
int
dpif_create_and_open(const char *name, const char *type, struct dpif **dpifp)
{
    int error;

    error = dpif_create(name, type, dpifp);
    if (error == EEXIST || error == EBUSY) {
        error = dpif_open(name, type, dpifp);
        if (error) {
            VLOG_WARN("datapath %s already exists but cannot be opened: %s",
                      name, strerror(error));
        }
    } else if (error) {
        VLOG_WARN("failed to create datapath %s: %s", name, strerror(error));
    }
    return error;
}

/* Closes and frees the connection to 'dpif'.  Does not destroy the datapath
 * itself; call dpif_delete() first, instead, if that is desirable. */
void
dpif_close(struct dpif *dpif)
{
    if (dpif) {
        struct registered_dpif_class *registered_class;

        registered_class = shash_find_data(&dpif_classes,
                dpif->dpif_class->type);
        assert(registered_class);
        assert(registered_class->refcount);

        registered_class->refcount--;
        dpif_uninit(dpif, true);
    }
}

/* Performs periodic work needed by 'dpif'. */
void
dpif_run(struct dpif *dpif)
{
    if (dpif->dpif_class->run) {
        dpif->dpif_class->run(dpif);
    }
}

/* Arranges for poll_block() to wake up when dp_run() needs to be called for
 * 'dpif'. */
void
dpif_wait(struct dpif *dpif)
{
    if (dpif->dpif_class->wait) {
        dpif->dpif_class->wait(dpif);
    }
}

/* Returns the name of datapath 'dpif' prefixed with the type
 * (for use in log messages). */
const char *
dpif_name(const struct dpif *dpif)
{
    return dpif->full_name;
}

/* Returns the name of datapath 'dpif' without the type
 * (for use in device names). */
const char *
dpif_base_name(const struct dpif *dpif)
{
    return dpif->base_name;
}

/* Returns the fully spelled out name for the given datapath 'type'.
 *
 * Normalized type string can be compared with strcmp().  Unnormalized type
 * string might be the same even if they have different spellings. */
const char *
dpif_normalize_type(const char *type)
{
    return type && type[0] ? type : "system";
}

/* Destroys the datapath that 'dpif' is connected to, first removing all of its
 * ports.  After calling this function, it does not make sense to pass 'dpif'
 * to any functions other than dpif_name() or dpif_close(). */
int
dpif_delete(struct dpif *dpif)
{
    int error;

    COVERAGE_INC(dpif_destroy);

    error = dpif->dpif_class->destroy(dpif);
    log_operation(dpif, "delete", error);
    return error;
}

/* Retrieves statistics for 'dpif' into 'stats'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
dpif_get_dp_stats(const struct dpif *dpif, struct odp_stats *stats)
{
    int error = dpif->dpif_class->get_stats(dpif, stats);
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
    int error = dpif->dpif_class->get_drop_frags(dpif, drop_frags);
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
    int error = dpif->dpif_class->set_drop_frags(dpif, drop_frags);
    log_operation(dpif, "set_drop_frags", error);
    return error;
}

/* Attempts to add 'netdev' as a port on 'dpif'.  If successful, returns 0 and
 * sets '*port_nop' to the new port's port number (if 'port_nop' is non-null).
 * On failure, returns a positive errno value and sets '*port_nop' to
 * UINT16_MAX (if 'port_nop' is non-null). */
int
dpif_port_add(struct dpif *dpif, struct netdev *netdev, uint16_t *port_nop)
{
    const char *netdev_name = netdev_get_name(netdev);
    uint16_t port_no;
    int error;

    COVERAGE_INC(dpif_port_add);

    error = dpif->dpif_class->port_add(dpif, netdev, &port_no);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: added %s as port %"PRIu16,
                    dpif_name(dpif), netdev_name, port_no);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to add %s as port: %s",
                     dpif_name(dpif), netdev_name, strerror(error));
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

    error = dpif->dpif_class->port_del(dpif, port_no);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port_del(%"PRIu16")",
                    dpif_name(dpif), port_no);
    } else {
        log_operation(dpif, "port_del", error);
    }
    return error;
}

/* Makes a deep copy of 'src' into 'dst'. */
void
dpif_port_clone(struct dpif_port *dst, const struct dpif_port *src)
{
    dst->name = xstrdup(src->name);
    dst->type = xstrdup(src->type);
    dst->port_no = src->port_no;
    dst->stats = src->stats;
}

/* Frees memory allocated to members of 'dpif_port'.
 *
 * Do not call this function on a dpif_port obtained from
 * dpif_port_dump_next(): that function retains ownership of the data in the
 * dpif_port. */
void
dpif_port_destroy(struct dpif_port *dpif_port)
{
    free(dpif_port->name);
    free(dpif_port->type);
}

/* Looks up port number 'port_no' in 'dpif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * The caller owns the data in 'port' and must free it with
 * dpif_port_destroy() when it is no longer needed. */
int
dpif_port_query_by_number(const struct dpif *dpif, uint16_t port_no,
                          struct dpif_port *port)
{
    int error = dpif->dpif_class->port_query_by_number(dpif, port_no, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port %"PRIu16" is device %s",
                    dpif_name(dpif), port_no, port->name);
    } else {
        memset(port, 0, sizeof *port);
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %"PRIu16": %s",
                     dpif_name(dpif), port_no, strerror(error));
    }
    return error;
}

/* Looks up port named 'devname' in 'dpif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * The caller owns the data in 'port' and must free it with
 * dpif_port_destroy() when it is no longer needed. */
int
dpif_port_query_by_name(const struct dpif *dpif, const char *devname,
                        struct dpif_port *port)
{
    int error = dpif->dpif_class->port_query_by_name(dpif, devname, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: device %s is on port %"PRIu16,
                    dpif_name(dpif), devname, port->port_no);
    } else {
        memset(port, 0, sizeof *port);

        /* For ENOENT or ENODEV we use DBG level because the caller is probably
         * interested in whether 'dpif' actually has a port 'devname', so that
         * it's not an issue worth logging if it doesn't.  Other errors are
         * uncommon and more likely to indicate a real problem. */
        VLOG_RL(&error_rl,
                error == ENOENT || error == ENODEV ? VLL_DBG : VLL_WARN,
                "%s: failed to query port %s: %s",
                dpif_name(dpif), devname, strerror(error));
    }
    return error;
}

/* Returns one greater than the maximum port number accepted in flow
 * actions. */
int
dpif_get_max_ports(const struct dpif *dpif)
{
    return dpif->dpif_class->get_max_ports(dpif);
}

/* Looks up port number 'port_no' in 'dpif'.  On success, returns 0 and copies
 * the port's name into the 'name_size' bytes in 'name', ensuring that the
 * result is null-terminated.  On failure, returns a positive errno value and
 * makes 'name' the empty string. */
int
dpif_port_get_name(struct dpif *dpif, uint16_t port_no,
                   char *name, size_t name_size)
{
    struct dpif_port port;
    int error;

    assert(name_size > 0);

    error = dpif_port_query_by_number(dpif, port_no, &port);
    if (!error) {
        ovs_strlcpy(name, port.name, name_size);
        dpif_port_destroy(&port);
    } else {
        *name = '\0';
    }
    return error;
}

/* Initializes 'dump' to begin dumping the ports in a dpif.
 *
 * This function provides no status indication.  An error status for the entire
 * dump operation is provided when it is completed by calling
 * dpif_port_dump_done().
 */
void
dpif_port_dump_start(struct dpif_port_dump *dump, const struct dpif *dpif)
{
    dump->dpif = dpif;
    dump->error = dpif->dpif_class->port_dump_start(dpif, &dump->state);
    log_operation(dpif, "port_dump_start", dump->error);
}

/* Attempts to retrieve another port from 'dump', which must have been
 * initialized with dpif_port_dump_start().  On success, stores a new dpif_port
 * into 'port' and returns true.  On failure, returns false.
 *
 * Failure might indicate an actual error or merely that the last port has been
 * dumped.  An error status for the entire dump operation is provided when it
 * is completed by calling dpif_port_dump_done().
 *
 * The dpif owns the data stored in 'port'.  It will remain valid until at
 * least the next time 'dump' is passed to dpif_port_dump_next() or
 * dpif_port_dump_done(). */
bool
dpif_port_dump_next(struct dpif_port_dump *dump, struct dpif_port *port)
{
    const struct dpif *dpif = dump->dpif;

    if (dump->error) {
        return false;
    }

    dump->error = dpif->dpif_class->port_dump_next(dpif, dump->state, port);
    if (dump->error == EOF) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: dumped all ports", dpif_name(dpif));
    } else {
        log_operation(dpif, "port_dump_next", dump->error);
    }

    if (dump->error) {
        dpif->dpif_class->port_dump_done(dpif, dump->state);
        return false;
    }
    return true;
}

/* Completes port table dump operation 'dump', which must have been initialized
 * with dpif_port_dump_start().  Returns 0 if the dump operation was
 * error-free, otherwise a positive errno value describing the problem. */
int
dpif_port_dump_done(struct dpif_port_dump *dump)
{
    const struct dpif *dpif = dump->dpif;
    if (!dump->error) {
        dump->error = dpif->dpif_class->port_dump_done(dpif, dump->state);
        log_operation(dpif, "port_dump_done", dump->error);
    }
    return dump->error == EOF ? 0 : dump->error;
}

/* Polls for changes in the set of ports in 'dpif'.  If the set of ports in
 * 'dpif' has changed, this function does one of the following:
 *
 * - Stores the name of the device that was added to or deleted from 'dpif' in
 *   '*devnamep' and returns 0.  The caller is responsible for freeing
 *   '*devnamep' (with free()) when it no longer needs it.
 *
 * - Returns ENOBUFS and sets '*devnamep' to NULL.
 *
 * This function may also return 'false positives', where it returns 0 and
 * '*devnamep' names a device that was not actually added or deleted or it
 * returns ENOBUFS without any change.
 *
 * Returns EAGAIN if the set of ports in 'dpif' has not changed.  May also
 * return other positive errno values to indicate that something has gone
 * wrong. */
int
dpif_port_poll(const struct dpif *dpif, char **devnamep)
{
    int error = dpif->dpif_class->port_poll(dpif, devnamep);
    if (error) {
        *devnamep = NULL;
    }
    return error;
}

/* Arranges for the poll loop to wake up when port_poll(dpif) will return a
 * value other than EAGAIN. */
void
dpif_port_poll_wait(const struct dpif *dpif)
{
    dpif->dpif_class->port_poll_wait(dpif);
}

/* Appends a human-readable representation of 'stats' to 's'. */
void
dpif_flow_stats_format(const struct dpif_flow_stats *stats, struct ds *s)
{
    ds_put_format(s, "packets:%"PRIu64", bytes:%"PRIu64", used:",
                  stats->n_packets, stats->n_bytes);
    if (stats->used) {
        ds_put_format(s, "%.3fs", (time_msec() - stats->used) / 1000.0);
    } else {
        ds_put_format(s, "never");
    }
    /* XXX tcp_flags? */
}

/* Deletes all flows from 'dpif'.  Returns 0 if successful, otherwise a
 * positive errno value.  */
int
dpif_flow_flush(struct dpif *dpif)
{
    int error;

    COVERAGE_INC(dpif_flow_flush);

    error = dpif->dpif_class->flow_flush(dpif);
    log_operation(dpif, "flow_flush", error);
    return error;
}

/* Queries 'dpif' for a flow entry.  The flow is specified by the Netlink
 * attributes with types ODP_KEY_ATTR_* in the 'key_len' bytes starting at
 * 'key'.
 *
 * Returns 0 if successful.  If no flow matches, returns ENOENT.  On other
 * failure, returns a positive errno value.
 *
 * If 'actionsp' is nonnull, then on success '*actionsp' will be set to an
 * ofpbuf owned by the caller that contains the Netlink attributes for the
 * flow's actions.  The caller must free the ofpbuf (with ofpbuf_delete()) when
 * it is no longer needed.
 *
 * If 'stats' is nonnull, then on success it will be updated with the flow's
 * statistics. */
int
dpif_flow_get(const struct dpif *dpif,
              const struct nlattr *key, size_t key_len,
              struct ofpbuf **actionsp, struct dpif_flow_stats *stats)
{
    int error;

    COVERAGE_INC(dpif_flow_get);

    error = dpif->dpif_class->flow_get(dpif, key, key_len, actionsp, stats);
    if (error) {
        if (actionsp) {
            *actionsp = NULL;
        }
        if (stats) {
            memset(stats, 0, sizeof *stats);
        }
    }
    if (should_log_flow_message(error)) {
        const struct nlattr *actions;
        size_t actions_len;

        if (!error && actionsp) {
            actions = (*actionsp)->data;
            actions_len = (*actionsp)->size;
        } else {
            actions = NULL;
            actions_len = 0;
        }
        log_flow_message(dpif, error, "flow_get", key, key_len, stats,
                         actions, actions_len);
    }
    return error;
}

/* Adds or modifies a flow in 'dpif'.  The flow is specified by the Netlink
 * attributes with types ODP_KEY_ATTR_* in the 'key_len' bytes starting at
 * 'key'.  The associated actions are specified by the Netlink attributes with
 * types ODP_ACTION_ATTR_* in the 'actions_len' bytes starting at 'actions'.
 *
 * - If the flow's key does not exist in 'dpif', then the flow will be added if
 *   'flags' includes DPIF_FP_CREATE.  Otherwise the operation will fail with
 *   ENOENT.
 *
 *   If the operation succeeds, then 'stats', if nonnull, will be zeroed.
 *
 * - If the flow's key does exist in 'dpif', then the flow's actions will be
 *   updated if 'flags' includes DPIF_FP_MODIFY.  Otherwise the operation will
 *   fail with EEXIST.  If the flow's actions are updated, then its statistics
 *   will be zeroed if 'flags' includes DPIF_FP_ZERO_STATS, and left as-is
 *   otherwise.
 *
 *   If the operation succeeds, then 'stats', if nonnull, will be set to the
 *   flow's statistics before the update.
 */
int
dpif_flow_put(struct dpif *dpif, enum dpif_flow_put_flags flags,
              const struct nlattr *key, size_t key_len,
              const struct nlattr *actions, size_t actions_len,
              struct dpif_flow_stats *stats)
{
    int error;

    COVERAGE_INC(dpif_flow_put);
    assert(!(flags & ~(DPIF_FP_CREATE | DPIF_FP_MODIFY | DPIF_FP_ZERO_STATS)));

    error = dpif->dpif_class->flow_put(dpif, flags, key, key_len,
                                       actions, actions_len, stats);
    if (error && stats) {
        memset(stats, 0, sizeof *stats);
    }
    if (should_log_flow_message(error)) {
        struct ds s;

        ds_init(&s);
        ds_put_cstr(&s, "put");
        if (flags & DPIF_FP_CREATE) {
            ds_put_cstr(&s, "[create]");
        }
        if (flags & DPIF_FP_MODIFY) {
            ds_put_cstr(&s, "[modify]");
        }
        if (flags & DPIF_FP_ZERO_STATS) {
            ds_put_cstr(&s, "[zero]");
        }
        log_flow_message(dpif, error, ds_cstr(&s), key, key_len, stats,
                         actions, actions_len);
        ds_destroy(&s);
    }
    return error;
}

/* Deletes a flow from 'dpif' and returns 0, or returns ENOENT if 'dpif' does
 * not contain such a flow.  The flow is specified by the Netlink attributes
 * with types ODP_KEY_ATTR_* in the 'key_len' bytes starting at 'key'.
 *
 * If the operation succeeds, then 'stats', if nonnull, will be set to the
 * flow's statistics before its deletion. */
int
dpif_flow_del(struct dpif *dpif,
              const struct nlattr *key, size_t key_len,
              struct dpif_flow_stats *stats)
{
    int error;

    COVERAGE_INC(dpif_flow_del);

    error = dpif->dpif_class->flow_del(dpif, key, key_len, stats);
    if (error && stats) {
        memset(stats, 0, sizeof *stats);
    }
    if (should_log_flow_message(error)) {
        log_flow_message(dpif, error, "flow_del", key, key_len,
                         !error ? stats : NULL, NULL, 0);
    }
    return error;
}

/* Initializes 'dump' to begin dumping the flows in a dpif.
 *
 * This function provides no status indication.  An error status for the entire
 * dump operation is provided when it is completed by calling
 * dpif_flow_dump_done().
 */
void
dpif_flow_dump_start(struct dpif_flow_dump *dump, const struct dpif *dpif)
{
    dump->dpif = dpif;
    dump->error = dpif->dpif_class->flow_dump_start(dpif, &dump->state);
    log_operation(dpif, "flow_dump_start", dump->error);
}

/* Attempts to retrieve another flow from 'dump', which must have been
 * initialized with dpif_flow_dump_start().  On success, updates the output
 * parameters as described below and returns true.  Otherwise, returns false.
 * Failure might indicate an actual error or merely the end of the flow table.
 * An error status for the entire dump operation is provided when it is
 * completed by calling dpif_flow_dump_done().
 *
 * On success, if 'key' and 'key_len' are nonnull then '*key' and '*key_len'
 * will be set to Netlink attributes with types ODP_KEY_ATTR_* representing the
 * dumped flow's key.  If 'actions' and 'actions_len' are nonnull then they are
 * set to Netlink attributes with types ODP_ACTION_ATTR_* representing the
 * dumped flow's actions.  If 'stats' is nonnull then it will be set to the
 * dumped flow's statistics.
 *
 * All of the returned data is owned by 'dpif', not by the caller, and the
 * caller must not modify or free it.  'dpif' guarantees that it remains
 * accessible and unchanging until at least the next call to 'flow_dump_next'
 * or 'flow_dump_done' for 'dump'. */
bool
dpif_flow_dump_next(struct dpif_flow_dump *dump,
                    const struct nlattr **key, size_t *key_len,
                    const struct nlattr **actions, size_t *actions_len,
                    const struct dpif_flow_stats **stats)
{
    const struct dpif *dpif = dump->dpif;
    int error = dump->error;

    if (!error) {
        error = dpif->dpif_class->flow_dump_next(dpif, dump->state,
                                                 key, key_len,
                                                 actions, actions_len,
                                                 stats);
        if (error) {
            dpif->dpif_class->flow_dump_done(dpif, dump->state);
        }
    }
    if (error) {
        if (key) {
            *key = NULL;
            *key_len = 0;
        }
        if (actions) {
            *actions = NULL;
            *actions_len = 0;
        }
        if (stats) {
            *stats = NULL;
        }
    }
    if (!dump->error) {
        if (error == EOF) {
            VLOG_DBG_RL(&dpmsg_rl, "%s: dumped all flows", dpif_name(dpif));
        } else if (should_log_flow_message(error)) {
            log_flow_message(dpif, error, "flow_dump",
                             key ? *key : NULL, key ? *key_len : 0,
                             stats ? *stats : NULL, actions ? *actions : NULL,
                             actions ? *actions_len : 0);
        }
    }
    dump->error = error;
    return !error;
}

/* Completes flow table dump operation 'dump', which must have been initialized
 * with dpif_flow_dump_start().  Returns 0 if the dump operation was
 * error-free, otherwise a positive errno value describing the problem. */
int
dpif_flow_dump_done(struct dpif_flow_dump *dump)
{
    const struct dpif *dpif = dump->dpif;
    if (!dump->error) {
        dump->error = dpif->dpif_class->flow_dump_done(dpif, dump->state);
        log_operation(dpif, "flow_dump_done", dump->error);
    }
    return dump->error == EOF ? 0 : dump->error;
}

/* Causes 'dpif' to perform the 'actions_len' bytes of actions in 'actions' on
 * the Ethernet frame specified in 'packet' taken from the flow specified in
 * the 'key_len' bytes of 'key'.  ('key' is mostly redundant with 'packet', but
 * it contains some metadata that cannot be recovered from 'packet', such as
 * tun_id and in_port.)
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
dpif_execute(struct dpif *dpif,
             const struct nlattr *key, size_t key_len,
             const struct nlattr *actions, size_t actions_len,
             const struct ofpbuf *buf)
{
    int error;

    COVERAGE_INC(dpif_execute);
    if (actions_len > 0) {
        error = dpif->dpif_class->execute(dpif, key, key_len,
                                          actions, actions_len, buf);
    } else {
        error = 0;
    }

    if (!(error ? VLOG_DROP_WARN(&error_rl) : VLOG_DROP_DBG(&dpmsg_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet = ofp_packet_to_string(buf->data, buf->size, buf->size);
        ds_put_format(&ds, "%s: execute ", dpif_name(dpif));
        format_odp_actions(&ds, actions, actions_len);
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

/* Returns a string that represents 'type', for use in log messages. */
const char *
dpif_upcall_type_to_string(enum dpif_upcall_type type)
{
    switch (type) {
    case DPIF_UC_MISS: return "miss";
    case DPIF_UC_ACTION: return "action";
    case DPIF_UC_SAMPLE: return "sample";
    case DPIF_N_UC_TYPES: default: return "<unknown>";
    }
}

static bool OVS_UNUSED
is_valid_listen_mask(int listen_mask)
{
    return !(listen_mask & ~((1u << DPIF_UC_MISS) |
                             (1u << DPIF_UC_ACTION) |
                             (1u << DPIF_UC_SAMPLE)));
}

/* Retrieves 'dpif''s "listen mask" into '*listen_mask'.  A 1-bit of value 2**X
 * set in '*listen_mask' indicates that dpif_recv() will receive messages of
 * the type (from "enum dpif_upcall_type") with value X.  Returns 0 if
 * successful, otherwise a positive errno value. */
int
dpif_recv_get_mask(const struct dpif *dpif, int *listen_mask)
{
    int error = dpif->dpif_class->recv_get_mask(dpif, listen_mask);
    if (error) {
        *listen_mask = 0;
    }
    assert(is_valid_listen_mask(*listen_mask));
    log_operation(dpif, "recv_get_mask", error);
    return error;
}

/* Sets 'dpif''s "listen mask" to 'listen_mask'.  A 1-bit of value 2**X set in
 * '*listen_mask' requests that dpif_recv() will receive messages of the type
 * (from "enum dpif_upcall_type") with value X.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
dpif_recv_set_mask(struct dpif *dpif, int listen_mask)
{
    int error;

    assert(is_valid_listen_mask(listen_mask));

    error = dpif->dpif_class->recv_set_mask(dpif, listen_mask);
    log_operation(dpif, "recv_set_mask", error);
    return error;
}

/* Retrieve the sFlow sampling probability.  '*probability' is expressed as the
 * number of packets out of UINT_MAX to sample, e.g. probability/UINT_MAX is
 * the probability of sampling a given packet.
 *
 * Returns 0 if successful, otherwise a positive errno value.  EOPNOTSUPP
 * indicates that 'dpif' does not support sFlow sampling. */
int
dpif_get_sflow_probability(const struct dpif *dpif, uint32_t *probability)
{
    int error = (dpif->dpif_class->get_sflow_probability
                 ? dpif->dpif_class->get_sflow_probability(dpif, probability)
                 : EOPNOTSUPP);
    if (error) {
        *probability = 0;
    }
    log_operation(dpif, "get_sflow_probability", error);
    return error;
}

/* Set the sFlow sampling probability.  'probability' is expressed as the
 * number of packets out of UINT_MAX to sample, e.g. probability/UINT_MAX is
 * the probability of sampling a given packet.
 *
 * Returns 0 if successful, otherwise a positive errno value.  EOPNOTSUPP
 * indicates that 'dpif' does not support sFlow sampling. */
int
dpif_set_sflow_probability(struct dpif *dpif, uint32_t probability)
{
    int error = (dpif->dpif_class->set_sflow_probability
                 ? dpif->dpif_class->set_sflow_probability(dpif, probability)
                 : EOPNOTSUPP);
    log_operation(dpif, "set_sflow_probability", error);
    return error;
}

/* Polls for an upcall from 'dpif'.  If successful, stores the upcall into
 * '*upcall'.  Only upcalls of the types selected with dpif_recv_set_mask()
 * member function will ordinarily be received (but if a message type is
 * enabled and then later disabled, some stragglers might pop up).
 *
 * The caller takes ownership of the data that 'upcall' points to.
 * 'upcall->key' and 'upcall->actions' (if nonnull) point into data owned by
 * 'upcall->packet', so their memory cannot be freed separately.  (This is
 * hardly a great way to do things but it works out OK for the dpif providers
 * and clients that exist so far.)
 *
 * Returns 0 if successful, otherwise a positive errno value.  Returns EAGAIN
 * if no upcall is immediately available. */
int
dpif_recv(struct dpif *dpif, struct dpif_upcall *upcall)
{
    int error = dpif->dpif_class->recv(dpif, upcall);
    if (!error && !VLOG_DROP_DBG(&dpmsg_rl)) {
        struct ds flow;
        char *packet;

        packet = ofp_packet_to_string(upcall->packet->data,
                                      upcall->packet->size,
                                      upcall->packet->size);

        ds_init(&flow);
        odp_flow_key_format(upcall->key, upcall->key_len, &flow);

        VLOG_DBG("%s: %s upcall:\n%s\n%s",
                 dpif_name(dpif), dpif_upcall_type_to_string(upcall->type),
                 ds_cstr(&flow), packet);

        ds_destroy(&flow);
        free(packet);
    }
    return error;
}

/* Discards all messages that would otherwise be received by dpif_recv() on
 * 'dpif'. */
void
dpif_recv_purge(struct dpif *dpif)
{
    COVERAGE_INC(dpif_purge);
    if (dpif->dpif_class->recv_purge) {
        dpif->dpif_class->recv_purge(dpif);
    }
}

/* Arranges for the poll loop to wake up when 'dpif' has a message queued to be
 * received with dpif_recv(). */
void
dpif_recv_wait(struct dpif *dpif)
{
    dpif->dpif_class->recv_wait(dpif);
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

/* Translates OpenFlow queue ID 'queue_id' (in host byte order) into a priority
 * value for use in the ODP_ACTION_ATTR_SET_PRIORITY action.  On success,
 * returns 0 and stores the priority into '*priority'.  On failure, returns a
 * positive errno value and stores 0 into '*priority'. */
int
dpif_queue_to_priority(const struct dpif *dpif, uint32_t queue_id,
                       uint32_t *priority)
{
    int error = (dpif->dpif_class->queue_to_priority
                 ? dpif->dpif_class->queue_to_priority(dpif, queue_id,
                                                       priority)
                 : EOPNOTSUPP);
    if (error) {
        *priority = 0;
    }
    log_operation(dpif, "queue_to_priority", error);
    return error;
}

void
dpif_init(struct dpif *dpif, const struct dpif_class *dpif_class,
          const char *name,
          uint8_t netflow_engine_type, uint8_t netflow_engine_id)
{
    dpif->dpif_class = dpif_class;
    dpif->base_name = xstrdup(name);
    dpif->full_name = xasprintf("%s@%s", dpif_class->type, name);
    dpif->netflow_engine_type = netflow_engine_type;
    dpif->netflow_engine_id = netflow_engine_id;
}

/* Undoes the results of initialization.
 *
 * Normally this function only needs to be called from dpif_close().
 * However, it may be called by providers due to an error on opening
 * that occurs after initialization.  It this case dpif_close() would
 * never be called. */
void
dpif_uninit(struct dpif *dpif, bool close)
{
    char *base_name = dpif->base_name;
    char *full_name = dpif->full_name;

    if (close) {
        dpif->dpif_class->close(dpif);
    }

    free(base_name);
    free(full_name);
}

static void
log_operation(const struct dpif *dpif, const char *operation, int error)
{
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: %s success", dpif_name(dpif), operation);
    } else if (is_errno(error)) {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     dpif_name(dpif), operation, strerror(error));
    } else {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%d/%d)",
                     dpif_name(dpif), operation,
                     get_ofp_err_type(error), get_ofp_err_code(error));
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
                 const struct nlattr *key, size_t key_len,
                 const struct dpif_flow_stats *stats,
                 const struct nlattr *actions, size_t actions_len)
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
    odp_flow_key_format(key, key_len, &ds);
    if (stats) {
        ds_put_cstr(&ds, ", ");
        dpif_flow_stats_format(stats, &ds);
    }
    if (actions || actions_len) {
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len);
    }
    vlog(THIS_MODULE, flow_message_log_level(error), "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}
