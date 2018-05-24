/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "coverage.h"
#include "dpctl.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "flow.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "route-table.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "util.h"
#include "uuid.h"
#include "valgrind.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif);

COVERAGE_DEFINE(dpif_destroy);
COVERAGE_DEFINE(dpif_port_add);
COVERAGE_DEFINE(dpif_port_del);
COVERAGE_DEFINE(dpif_flow_flush);
COVERAGE_DEFINE(dpif_flow_get);
COVERAGE_DEFINE(dpif_flow_put);
COVERAGE_DEFINE(dpif_flow_del);
COVERAGE_DEFINE(dpif_execute);
COVERAGE_DEFINE(dpif_purge);
COVERAGE_DEFINE(dpif_execute_with_help);
COVERAGE_DEFINE(dpif_meter_set);
COVERAGE_DEFINE(dpif_meter_get);
COVERAGE_DEFINE(dpif_meter_del);

static const struct dpif_class *base_dpif_classes[] = {
#if defined(__linux__) || defined(_WIN32)
    &dpif_netlink_class,
#endif
    &dpif_netdev_class,
};

struct registered_dpif_class {
    const struct dpif_class *dpif_class;
    int refcount;
};
static struct shash dpif_classes = SHASH_INITIALIZER(&dpif_classes);
static struct sset dpif_blacklist = SSET_INITIALIZER(&dpif_blacklist);

/* Protects 'dpif_classes', including the refcount, and 'dpif_blacklist'. */
static struct ovs_mutex dpif_mutex = OVS_MUTEX_INITIALIZER;

/* Rate limit for individual messages going to or from the datapath, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit dpmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Not really much point in logging many dpif errors. */
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static void log_operation(const struct dpif *, const char *operation,
                          int error);
static bool should_log_flow_message(const struct vlog_module *module,
                                    int error);

/* Incremented whenever tnl route, arp, etc changes. */
struct seq *tnl_conf_seq;

static bool
dpif_is_internal_port(const char *type)
{
    /* For userspace datapath, tap devices are the equivalent
     * of internal devices in the kernel datapath, so both
     * these types are 'internal' devices. */
    return !strcmp(type, "internal") || !strcmp(type, "tap");
}

static void
dp_initialize(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        int i;

        tnl_conf_seq = seq_create();
        dpctl_unixctl_register();
        tnl_port_map_init();
        tnl_neigh_cache_init();
        route_table_init();

        for (i = 0; i < ARRAY_SIZE(base_dpif_classes); i++) {
            dp_register_provider(base_dpif_classes[i]);
        }

        ovsthread_once_done(&once);
    }
}

static int
dp_register_provider__(const struct dpif_class *new_class)
{
    struct registered_dpif_class *registered_class;
    int error;

    if (sset_contains(&dpif_blacklist, new_class->type)) {
        VLOG_DBG("attempted to register blacklisted provider: %s",
                 new_class->type);
        return EINVAL;
    }

    if (shash_find(&dpif_classes, new_class->type)) {
        VLOG_WARN("attempted to register duplicate datapath provider: %s",
                  new_class->type);
        return EEXIST;
    }

    error = new_class->init ? new_class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize %s datapath class: %s",
                  new_class->type, ovs_strerror(error));
        return error;
    }

    registered_class = xmalloc(sizeof *registered_class);
    registered_class->dpif_class = new_class;
    registered_class->refcount = 0;

    shash_add(&dpif_classes, new_class->type, registered_class);

    return 0;
}

/* Registers a new datapath provider.  After successful registration, new
 * datapaths of that type can be opened using dpif_open(). */
int
dp_register_provider(const struct dpif_class *new_class)
{
    int error;

    ovs_mutex_lock(&dpif_mutex);
    error = dp_register_provider__(new_class);
    ovs_mutex_unlock(&dpif_mutex);

    return error;
}

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any dpifs.  After unregistration
 * new datapaths of that type cannot be opened using dpif_open(). */
static int
dp_unregister_provider__(const char *type)
{
    struct shash_node *node;
    struct registered_dpif_class *registered_class;

    node = shash_find(&dpif_classes, type);
    if (!node) {
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

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any dpifs.  After unregistration
 * new datapaths of that type cannot be opened using dpif_open(). */
int
dp_unregister_provider(const char *type)
{
    int error;

    dp_initialize();

    ovs_mutex_lock(&dpif_mutex);
    error = dp_unregister_provider__(type);
    ovs_mutex_unlock(&dpif_mutex);

    return error;
}

/* Blacklists a provider.  Causes future calls of dp_register_provider() with
 * a dpif_class which implements 'type' to fail. */
void
dp_blacklist_provider(const char *type)
{
    ovs_mutex_lock(&dpif_mutex);
    sset_add(&dpif_blacklist, type);
    ovs_mutex_unlock(&dpif_mutex);
}

/* Adds the types of all currently registered datapath providers to 'types'.
 * The caller must first initialize the sset. */
void
dp_enumerate_types(struct sset *types)
{
    struct shash_node *node;

    dp_initialize();

    ovs_mutex_lock(&dpif_mutex);
    SHASH_FOR_EACH(node, &dpif_classes) {
        const struct registered_dpif_class *registered_class = node->data;
        sset_add(types, registered_class->dpif_class->type);
    }
    ovs_mutex_unlock(&dpif_mutex);
}

static void
dp_class_unref(struct registered_dpif_class *rc)
{
    ovs_mutex_lock(&dpif_mutex);
    ovs_assert(rc->refcount);
    rc->refcount--;
    ovs_mutex_unlock(&dpif_mutex);
}

static struct registered_dpif_class *
dp_class_lookup(const char *type)
{
    struct registered_dpif_class *rc;

    ovs_mutex_lock(&dpif_mutex);
    rc = shash_find_data(&dpif_classes, type);
    if (rc) {
        rc->refcount++;
    }
    ovs_mutex_unlock(&dpif_mutex);

    return rc;
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
    struct registered_dpif_class *registered_class;
    const struct dpif_class *dpif_class;
    int error;

    dp_initialize();
    sset_clear(names);

    registered_class = dp_class_lookup(type);
    if (!registered_class) {
        VLOG_WARN("could not enumerate unknown type: %s", type);
        return EAFNOSUPPORT;
    }

    dpif_class = registered_class->dpif_class;
    error = (dpif_class->enumerate
             ? dpif_class->enumerate(names, dpif_class)
             : 0);
    if (error) {
        VLOG_WARN("failed to enumerate %s datapaths: %s", dpif_class->type,
                   ovs_strerror(error));
    }
    dp_class_unref(registered_class);

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
    registered_class = dp_class_lookup(type);
    if (!registered_class) {
        VLOG_WARN("could not create datapath %s of unknown type %s", name,
                  type);
        error = EAFNOSUPPORT;
        goto exit;
    }

    error = registered_class->dpif_class->open(registered_class->dpif_class,
                                               name, create, &dpif);
    if (!error) {
        struct dpif_port_dump port_dump;
        struct dpif_port dpif_port;

        ovs_assert(dpif->dpif_class == registered_class->dpif_class);

        DPIF_PORT_FOR_EACH(&dpif_port, &port_dump, dpif) {
            struct netdev *netdev;
            int err;

            if (dpif_is_internal_port(dpif_port.type)) {
                continue;
            }

            err = netdev_open(dpif_port.name, dpif_port.type, &netdev);

            if (!err) {
                netdev_ports_insert(netdev, dpif->dpif_class, &dpif_port);
                netdev_close(netdev);
            } else {
                VLOG_WARN("could not open netdev %s type %s: %s",
			  dpif_port.name, dpif_port.type, ovs_strerror(err));
            }
        }
    } else {
        dp_class_unref(registered_class);
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
                      name, ovs_strerror(error));
        }
    } else if (error) {
        VLOG_WARN("failed to create datapath %s: %s",
                  name, ovs_strerror(error));
    }
    return error;
}

static void
dpif_remove_netdev_ports(struct dpif *dpif) {
        struct dpif_port_dump port_dump;
        struct dpif_port dpif_port;

        DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
            if (!dpif_is_internal_port(dpif_port.type)) {
                netdev_ports_remove(dpif_port.port_no, dpif->dpif_class);
            }
        }
}

/* Closes and frees the connection to 'dpif'.  Does not destroy the datapath
 * itself; call dpif_delete() first, instead, if that is desirable. */
void
dpif_close(struct dpif *dpif)
{
    if (dpif) {
        struct registered_dpif_class *rc;

        rc = shash_find_data(&dpif_classes, dpif->dpif_class->type);

        if (rc->refcount == 1) {
            dpif_remove_netdev_ports(dpif);
        }
        dpif_uninit(dpif, true);
        dp_class_unref(rc);
    }
}

/* Performs periodic work needed by 'dpif'. */
bool
dpif_run(struct dpif *dpif)
{
    if (dpif->dpif_class->run) {
        return dpif->dpif_class->run(dpif);
    }
    return false;
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

/* Returns the type of datapath 'dpif'. */
const char *
dpif_type(const struct dpif *dpif)
{
    return dpif->dpif_class->type;
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
dpif_get_dp_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    int error = dpif->dpif_class->get_stats(dpif, stats);
    if (error) {
        memset(stats, 0, sizeof *stats);
    }
    log_operation(dpif, "get_stats", error);
    return error;
}

const char *
dpif_port_open_type(const char *datapath_type, const char *port_type)
{
    struct registered_dpif_class *rc;

    datapath_type = dpif_normalize_type(datapath_type);

    ovs_mutex_lock(&dpif_mutex);
    rc = shash_find_data(&dpif_classes, datapath_type);
    if (rc && rc->dpif_class->port_open_type) {
        port_type = rc->dpif_class->port_open_type(rc->dpif_class, port_type);
    }
    ovs_mutex_unlock(&dpif_mutex);

    return port_type;
}

/* Attempts to add 'netdev' as a port on 'dpif'.  If 'port_nop' is
 * non-null and its value is not ODPP_NONE, then attempts to use the
 * value as the port number.
 *
 * If successful, returns 0 and sets '*port_nop' to the new port's port
 * number (if 'port_nop' is non-null).  On failure, returns a positive
 * errno value and sets '*port_nop' to ODPP_NONE (if 'port_nop' is
 * non-null). */
int
dpif_port_add(struct dpif *dpif, struct netdev *netdev, odp_port_t *port_nop)
{
    const char *netdev_name = netdev_get_name(netdev);
    odp_port_t port_no = ODPP_NONE;
    int error;

    COVERAGE_INC(dpif_port_add);

    if (port_nop) {
        port_no = *port_nop;
    }

    error = dpif->dpif_class->port_add(dpif, netdev, &port_no);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: added %s as port %"PRIu32,
                    dpif_name(dpif), netdev_name, port_no);

        if (!dpif_is_internal_port(netdev_get_type(netdev))) {

            struct dpif_port dpif_port;

            dpif_port.type = CONST_CAST(char *, netdev_get_type(netdev));
            dpif_port.name = CONST_CAST(char *, netdev_name);
            dpif_port.port_no = port_no;
            netdev_ports_insert(netdev, dpif->dpif_class, &dpif_port);
        }
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to add %s as port: %s",
                     dpif_name(dpif), netdev_name, ovs_strerror(error));
        port_no = ODPP_NONE;
    }
    if (port_nop) {
        *port_nop = port_no;
    }
    return error;
}

/* Attempts to remove 'dpif''s port number 'port_no'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
dpif_port_del(struct dpif *dpif, odp_port_t port_no, bool local_delete)
{
    int error = 0;

    COVERAGE_INC(dpif_port_del);

    if (!local_delete) {
        error = dpif->dpif_class->port_del(dpif, port_no);
        if (!error) {
            VLOG_DBG_RL(&dpmsg_rl, "%s: port_del(%"PRIu32")",
                        dpif_name(dpif), port_no);
        } else {
            log_operation(dpif, "port_del", error);
        }
    }

    netdev_ports_remove(port_no, dpif->dpif_class);
    return error;
}

/* Makes a deep copy of 'src' into 'dst'. */
void
dpif_port_clone(struct dpif_port *dst, const struct dpif_port *src)
{
    dst->name = xstrdup(src->name);
    dst->type = xstrdup(src->type);
    dst->port_no = src->port_no;
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

/* Checks if port named 'devname' exists in 'dpif'.  If so, returns
 * true; otherwise, returns false. */
bool
dpif_port_exists(const struct dpif *dpif, const char *devname)
{
    int error = dpif->dpif_class->port_query_by_name(dpif, devname, NULL);
    if (error != 0 && error != ENODEV) {
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %s: %s",
                     dpif_name(dpif), devname, ovs_strerror(error));
    }

    return !error;
}

/* Refreshes configuration of 'dpif's port. */
int
dpif_port_set_config(struct dpif *dpif, odp_port_t port_no,
                     const struct smap *cfg)
{
    int error = 0;

    if (dpif->dpif_class->port_set_config) {
        error = dpif->dpif_class->port_set_config(dpif, port_no, cfg);
        if (error) {
            log_operation(dpif, "port_set_config", error);
        }
    }

    return error;
}

/* Looks up port number 'port_no' in 'dpif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * Retuns ENODEV if the port doesn't exist.
 *
 * The caller owns the data in 'port' and must free it with
 * dpif_port_destroy() when it is no longer needed. */
int
dpif_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                          struct dpif_port *port)
{
    int error = dpif->dpif_class->port_query_by_number(dpif, port_no, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port %"PRIu32" is device %s",
                    dpif_name(dpif), port_no, port->name);
    } else {
        memset(port, 0, sizeof *port);
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %"PRIu32": %s",
                     dpif_name(dpif), port_no, ovs_strerror(error));
    }
    return error;
}

/* Looks up port named 'devname' in 'dpif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * Retuns ENODEV if the port doesn't exist.
 *
 * The caller owns the data in 'port' and must free it with
 * dpif_port_destroy() when it is no longer needed. */
int
dpif_port_query_by_name(const struct dpif *dpif, const char *devname,
                        struct dpif_port *port)
{
    int error = dpif->dpif_class->port_query_by_name(dpif, devname, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: device %s is on port %"PRIu32,
                    dpif_name(dpif), devname, port->port_no);
    } else {
        memset(port, 0, sizeof *port);

        /* For ENODEV we use DBG level because the caller is probably
         * interested in whether 'dpif' actually has a port 'devname', so that
         * it's not an issue worth logging if it doesn't.  Other errors are
         * uncommon and more likely to indicate a real problem. */
        VLOG_RL(&error_rl, error == ENODEV ? VLL_DBG : VLL_WARN,
                "%s: failed to query port %s: %s",
                dpif_name(dpif), devname, ovs_strerror(error));
    }
    return error;
}

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
 * A 'port_no' of ODPP_NONE is a special case: it returns a reserved PID, not
 * allocated to any port, that the client may use for special purposes.
 *
 * The return value is only meaningful when DPIF_UC_ACTION has been enabled in
 * the 'dpif''s listen mask.  It is allowed to change when DPIF_UC_ACTION is
 * disabled and then re-enabled, so a client that does that must be prepared to
 * update all of the flows that it installed that contain
 * OVS_ACTION_ATTR_USERSPACE actions. */
uint32_t
dpif_port_get_pid(const struct dpif *dpif, odp_port_t port_no, uint32_t hash)
{
    return (dpif->dpif_class->port_get_pid
            ? (dpif->dpif_class->port_get_pid)(dpif, port_no, hash)
            : 0);
}

/* Looks up port number 'port_no' in 'dpif'.  On success, returns 0 and copies
 * the port's name into the 'name_size' bytes in 'name', ensuring that the
 * result is null-terminated.  On failure, returns a positive errno value and
 * makes 'name' the empty string. */
int
dpif_port_get_name(struct dpif *dpif, odp_port_t port_no,
                   char *name, size_t name_size)
{
    struct dpif_port port;
    int error;

    ovs_assert(name_size > 0);

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

/* Extracts the flow stats for a packet.  The 'flow' and 'packet'
 * arguments must have been initialized through a call to flow_extract().
 * 'used' is stored into stats->used. */
void
dpif_flow_stats_extract(const struct flow *flow, const struct dp_packet *packet,
                        long long int used, struct dpif_flow_stats *stats)
{
    stats->tcp_flags = ntohs(flow->tcp_flags);
    stats->n_bytes = dp_packet_size(packet);
    stats->n_packets = 1;
    stats->used = used;
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
    if (stats->tcp_flags) {
        ds_put_cstr(s, ", flags:");
        packet_format_tcp_flags(s, stats->tcp_flags);
    }
}

/* Places the hash of the 'key_len' bytes starting at 'key' into '*hash'. */
void
dpif_flow_hash(const struct dpif *dpif OVS_UNUSED,
               const void *key, size_t key_len, ovs_u128 *hash)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static uint32_t secret;

    if (ovsthread_once_start(&once)) {
        secret = random_uint32();
        ovsthread_once_done(&once);
    }
    hash_bytes128(key, key_len, secret, hash);
    uuid_set_bits_v4((struct uuid *)hash);
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

/* Attempts to install 'key' into the datapath, fetches it, then deletes it.
 * Returns true if the datapath supported installing 'flow', false otherwise.
 */
bool
dpif_probe_feature(struct dpif *dpif, const char *name,
                   const struct ofpbuf *key, const struct ofpbuf *actions,
                   const ovs_u128 *ufid)
{
    struct dpif_flow flow;
    struct ofpbuf reply;
    uint64_t stub[DPIF_FLOW_BUFSIZE / 8];
    bool enable_feature = false;
    int error;
    const struct nlattr *nl_actions = actions ? actions->data : NULL;
    const size_t nl_actions_size = actions ? actions->size : 0;

    /* Use DPIF_FP_MODIFY to cover the case where ovs-vswitchd is killed (and
     * restarted) at just the right time such that feature probes from the
     * previous run are still present in the datapath. */
    error = dpif_flow_put(dpif, DPIF_FP_CREATE | DPIF_FP_MODIFY | DPIF_FP_PROBE,
                          key->data, key->size, NULL, 0,
                          nl_actions, nl_actions_size,
                          ufid, NON_PMD_CORE_ID, NULL);
    if (error) {
        if (error != EINVAL && error != EOVERFLOW) {
            VLOG_WARN("%s: %s flow probe failed (%s)",
                      dpif_name(dpif), name, ovs_strerror(error));
        }
        return false;
    }

    ofpbuf_use_stack(&reply, &stub, sizeof stub);
    error = dpif_flow_get(dpif, key->data, key->size, ufid,
                          NON_PMD_CORE_ID, &reply, &flow);
    if (!error
        && (!ufid || (flow.ufid_present
                      && ovs_u128_equals(*ufid, flow.ufid)))) {
        enable_feature = true;
    }

    error = dpif_flow_del(dpif, key->data, key->size, ufid,
                          NON_PMD_CORE_ID, NULL);
    if (error) {
        VLOG_WARN("%s: failed to delete %s feature probe flow",
                  dpif_name(dpif), name);
    }

    return enable_feature;
}

/* A dpif_operate() wrapper for performing a single DPIF_OP_FLOW_GET. */
int
dpif_flow_get(struct dpif *dpif,
              const struct nlattr *key, size_t key_len, const ovs_u128 *ufid,
              const unsigned pmd_id, struct ofpbuf *buf, struct dpif_flow *flow)
{
    struct dpif_op *opp;
    struct dpif_op op;

    op.type = DPIF_OP_FLOW_GET;
    op.flow_get.key = key;
    op.flow_get.key_len = key_len;
    op.flow_get.ufid = ufid;
    op.flow_get.pmd_id = pmd_id;
    op.flow_get.buffer = buf;

    memset(flow, 0, sizeof *flow);
    op.flow_get.flow = flow;
    op.flow_get.flow->key = key;
    op.flow_get.flow->key_len = key_len;

    opp = &op;
    dpif_operate(dpif, &opp, 1);

    return op.error;
}

/* A dpif_operate() wrapper for performing a single DPIF_OP_FLOW_PUT. */
int
dpif_flow_put(struct dpif *dpif, enum dpif_flow_put_flags flags,
              const struct nlattr *key, size_t key_len,
              const struct nlattr *mask, size_t mask_len,
              const struct nlattr *actions, size_t actions_len,
              const ovs_u128 *ufid, const unsigned pmd_id,
              struct dpif_flow_stats *stats)
{
    struct dpif_op *opp;
    struct dpif_op op;

    op.type = DPIF_OP_FLOW_PUT;
    op.flow_put.flags = flags;
    op.flow_put.key = key;
    op.flow_put.key_len = key_len;
    op.flow_put.mask = mask;
    op.flow_put.mask_len = mask_len;
    op.flow_put.actions = actions;
    op.flow_put.actions_len = actions_len;
    op.flow_put.ufid = ufid;
    op.flow_put.pmd_id = pmd_id;
    op.flow_put.stats = stats;

    opp = &op;
    dpif_operate(dpif, &opp, 1);

    return op.error;
}

/* A dpif_operate() wrapper for performing a single DPIF_OP_FLOW_DEL. */
int
dpif_flow_del(struct dpif *dpif,
              const struct nlattr *key, size_t key_len, const ovs_u128 *ufid,
              const unsigned pmd_id, struct dpif_flow_stats *stats)
{
    struct dpif_op *opp;
    struct dpif_op op;

    op.type = DPIF_OP_FLOW_DEL;
    op.flow_del.key = key;
    op.flow_del.key_len = key_len;
    op.flow_del.ufid = ufid;
    op.flow_del.pmd_id = pmd_id;
    op.flow_del.stats = stats;
    op.flow_del.terse = false;

    opp = &op;
    dpif_operate(dpif, &opp, 1);

    return op.error;
}

/* Creates and returns a new 'struct dpif_flow_dump' for iterating through the
 * flows in 'dpif'. If 'terse' is true, then only UFID and statistics will
 * be returned in the dump. Otherwise, all fields will be returned.
 *
 * This function always successfully returns a dpif_flow_dump.  Error
 * reporting is deferred to dpif_flow_dump_destroy(). */
struct dpif_flow_dump *
dpif_flow_dump_create(const struct dpif *dpif, bool terse, char *type)
{
    return dpif->dpif_class->flow_dump_create(dpif, terse, type);
}

/* Destroys 'dump', which must have been created with dpif_flow_dump_create().
 * All dpif_flow_dump_thread structures previously created for 'dump' must
 * previously have been destroyed.
 *
 * Returns 0 if the dump operation was error-free, otherwise a positive errno
 * value describing the problem. */
int
dpif_flow_dump_destroy(struct dpif_flow_dump *dump)
{
    const struct dpif *dpif = dump->dpif;
    int error = dpif->dpif_class->flow_dump_destroy(dump);
    log_operation(dpif, "flow_dump_destroy", error);
    return error == EOF ? 0 : error;
}

/* Returns new thread-local state for use with dpif_flow_dump_next(). */
struct dpif_flow_dump_thread *
dpif_flow_dump_thread_create(struct dpif_flow_dump *dump)
{
    return dump->dpif->dpif_class->flow_dump_thread_create(dump);
}

/* Releases 'thread'. */
void
dpif_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread)
{
    thread->dpif->dpif_class->flow_dump_thread_destroy(thread);
}

/* Attempts to retrieve up to 'max_flows' more flows from 'thread'.  Returns 0
 * if and only if no flows remained to be retrieved, otherwise a positive
 * number reflecting the number of elements in 'flows[]' that were updated.
 * The number of flows returned might be less than 'max_flows' because
 * fewer than 'max_flows' remained, because this particular datapath does not
 * benefit from batching, or because an error occurred partway through
 * retrieval.  Thus, the caller should continue calling until a 0 return value,
 * even if intermediate return values are less than 'max_flows'.
 *
 * No error status is immediately provided.  An error status for the entire
 * dump operation is provided when it is completed by calling
 * dpif_flow_dump_destroy().
 *
 * All of the data stored into 'flows' is owned by the datapath, not by the
 * caller, and the caller must not modify or free it.  The datapath guarantees
 * that it remains accessible and unchanged until the first of:
 *  - The next call to dpif_flow_dump_next() for 'thread', or
 *  - The next rcu quiescent period. */
int
dpif_flow_dump_next(struct dpif_flow_dump_thread *thread,
                    struct dpif_flow *flows, int max_flows)
{
    struct dpif *dpif = thread->dpif;
    int n;

    ovs_assert(max_flows > 0);
    n = dpif->dpif_class->flow_dump_next(thread, flows, max_flows);
    if (n > 0) {
        struct dpif_flow *f;

        for (f = flows; f < &flows[n]
             && should_log_flow_message(&this_module, 0); f++) {
            log_flow_message(dpif, 0, &this_module, "flow_dump",
                             f->key, f->key_len, f->mask, f->mask_len,
                             &f->ufid, &f->stats, f->actions, f->actions_len);
        }
    } else {
        VLOG_DBG_RL(&dpmsg_rl, "%s: dumped all flows", dpif_name(dpif));
    }
    return n;
}

struct dpif_execute_helper_aux {
    struct dpif *dpif;
    const struct flow *flow;
    int error;
    const struct nlattr *meter_action; /* Non-NULL, if have a meter action. */
};

/* This is called for actions that need the context of the datapath to be
 * meaningful. */
static void
dpif_execute_helper_cb(void *aux_, struct dp_packet_batch *packets_,
                       const struct nlattr *action, bool should_steal)
{
    struct dpif_execute_helper_aux *aux = aux_;
    int type = nl_attr_type(action);
    struct dp_packet *packet = packets_->packets[0];

    ovs_assert(packets_->count == 1);

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_METER:
        /* Maintain a pointer to the first meter action seen. */
        if (!aux->meter_action) {
            aux->meter_action = action;
        }
	break;

    case OVS_ACTION_ATTR_CT:
    case OVS_ACTION_ATTR_OUTPUT:
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
    case OVS_ACTION_ATTR_TUNNEL_POP:
    case OVS_ACTION_ATTR_USERSPACE:
    case OVS_ACTION_ATTR_RECIRC: {
        struct dpif_execute execute;
        struct ofpbuf execute_actions;
        uint64_t stub[256 / 8];
        struct pkt_metadata *md = &packet->md;

        if (flow_tnl_dst_is_set(&md->tunnel) || aux->meter_action) {
            ofpbuf_use_stub(&execute_actions, stub, sizeof stub);

            if (aux->meter_action) {
                const struct nlattr *a = aux->meter_action;

                /* XXX: This code collects meter actions since the last action
                 * execution via the datapath to be executed right before the
                 * current action that needs to be executed by the datapath.
                 * This is only an approximation, but better than nothing.
                 * Fundamentally, we should have a mechanism by which the
                 * datapath could return the result of the meter action so that
                 * we could execute them at the right order. */
                do {
                    ofpbuf_put(&execute_actions, a, NLA_ALIGN(a->nla_len));
                    /* Find next meter action before 'action', if any. */
                    do {
                        a = nl_attr_next(a);
                    } while (a != action &&
                             nl_attr_type(a) != OVS_ACTION_ATTR_METER);
                } while (a != action);
            }

            /* The Linux kernel datapath throws away the tunnel information
             * that we supply as metadata.  We have to use a "set" action to
             * supply it. */
            if (md->tunnel.ip_dst) {
                odp_put_tunnel_action(&md->tunnel, &execute_actions, NULL);
            }
            ofpbuf_put(&execute_actions, action, NLA_ALIGN(action->nla_len));

            execute.actions = execute_actions.data;
            execute.actions_len = execute_actions.size;
        } else {
            execute.actions = action;
            execute.actions_len = NLA_ALIGN(action->nla_len);
        }

        struct dp_packet *clone = NULL;
        uint32_t cutlen = dp_packet_get_cutlen(packet);
        if (cutlen && (type == OVS_ACTION_ATTR_OUTPUT
                        || type == OVS_ACTION_ATTR_TUNNEL_PUSH
                        || type == OVS_ACTION_ATTR_TUNNEL_POP
                        || type == OVS_ACTION_ATTR_USERSPACE)) {
            dp_packet_reset_cutlen(packet);
            if (!should_steal) {
                packet = clone = dp_packet_clone(packet);
            }
            dp_packet_set_size(packet, dp_packet_size(packet) - cutlen);
        }

        execute.packet = packet;
        execute.flow = aux->flow;
        execute.needs_help = false;
        execute.probe = false;
        execute.mtu = 0;
        aux->error = dpif_execute(aux->dpif, &execute);
        log_execute_message(aux->dpif, &this_module, &execute,
                            true, aux->error);

        dp_packet_delete(clone);

        if (flow_tnl_dst_is_set(&md->tunnel) || aux->meter_action) {
            ofpbuf_uninit(&execute_actions);

            /* Do not re-use the same meters for later output actions. */
            aux->meter_action = NULL;
        }
        break;
    }

    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_TRUNC:
    case OVS_ACTION_ATTR_PUSH_ETH:
    case OVS_ACTION_ATTR_POP_ETH:
    case OVS_ACTION_ATTR_CLONE:
    case OVS_ACTION_ATTR_PUSH_NSH:
    case OVS_ACTION_ATTR_POP_NSH:
    case OVS_ACTION_ATTR_CT_CLEAR:
    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }
    dp_packet_delete_batch(packets_, should_steal);
}

/* Executes 'execute' by performing most of the actions in userspace and
 * passing the fully constructed packets to 'dpif' for output and userspace
 * actions.
 *
 * This helps with actions that a given 'dpif' doesn't implement directly. */
static int
dpif_execute_with_help(struct dpif *dpif, struct dpif_execute *execute)
{
    struct dpif_execute_helper_aux aux = {dpif, execute->flow, 0, NULL};
    struct dp_packet_batch pb;

    COVERAGE_INC(dpif_execute_with_help);

    dp_packet_batch_init_packet(&pb, execute->packet);
    odp_execute_actions(&aux, &pb, false, execute->actions,
                        execute->actions_len, dpif_execute_helper_cb);
    return aux.error;
}

/* Returns true if the datapath needs help executing 'execute'. */
static bool
dpif_execute_needs_help(const struct dpif_execute *execute)
{
    return execute->needs_help || nl_attr_oversized(execute->actions_len);
}

/* A dpif_operate() wrapper for performing a single DPIF_OP_EXECUTE. */
int
dpif_execute(struct dpif *dpif, struct dpif_execute *execute)
{
    if (execute->actions_len) {
        struct dpif_op *opp;
        struct dpif_op op;

        op.type = DPIF_OP_EXECUTE;
        op.execute = *execute;

        opp = &op;
        dpif_operate(dpif, &opp, 1);

        return op.error;
    } else {
        return 0;
    }
}

/* Executes each of the 'n_ops' operations in 'ops' on 'dpif', in the order in
 * which they are specified.  Places each operation's results in the "output"
 * members documented in comments, and 0 in the 'error' member on success or a
 * positive errno on failure. */
void
dpif_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    while (n_ops > 0) {
        size_t chunk;

        /* Count 'chunk', the number of ops that can be executed without
         * needing any help.  Ops that need help should be rare, so we
         * expect this to ordinarily be 'n_ops', that is, all the ops. */
        for (chunk = 0; chunk < n_ops; chunk++) {
            struct dpif_op *op = ops[chunk];

            if (op->type == DPIF_OP_EXECUTE
                && dpif_execute_needs_help(&op->execute)) {
                break;
            }
        }

        if (chunk) {
            /* Execute a chunk full of ops that the dpif provider can
             * handle itself, without help. */
            size_t i;

            dpif->dpif_class->operate(dpif, ops, chunk);

            for (i = 0; i < chunk; i++) {
                struct dpif_op *op = ops[i];
                int error = op->error;

                switch (op->type) {
                case DPIF_OP_FLOW_PUT: {
                    struct dpif_flow_put *put = &op->flow_put;

                    COVERAGE_INC(dpif_flow_put);
                    log_flow_put_message(dpif, &this_module, put, error);
                    if (error && put->stats) {
                        memset(put->stats, 0, sizeof *put->stats);
                    }
                    break;
                }

                case DPIF_OP_FLOW_GET: {
                    struct dpif_flow_get *get = &op->flow_get;

                    COVERAGE_INC(dpif_flow_get);
                    if (error) {
                        memset(get->flow, 0, sizeof *get->flow);
                    }
                    log_flow_get_message(dpif, &this_module, get, error);

                    break;
                }

                case DPIF_OP_FLOW_DEL: {
                    struct dpif_flow_del *del = &op->flow_del;

                    COVERAGE_INC(dpif_flow_del);
                    log_flow_del_message(dpif, &this_module, del, error);
                    if (error && del->stats) {
                        memset(del->stats, 0, sizeof *del->stats);
                    }
                    break;
                }

                case DPIF_OP_EXECUTE:
                    COVERAGE_INC(dpif_execute);
                    log_execute_message(dpif, &this_module, &op->execute,
                                        false, error);
                    break;
                }
            }

            ops += chunk;
            n_ops -= chunk;
        } else {
            /* Help the dpif provider to execute one op. */
            struct dpif_op *op = ops[0];

            COVERAGE_INC(dpif_execute);
            op->error = dpif_execute_with_help(dpif, &op->execute);
            ops++;
            n_ops--;
        }
    }
}

/* Returns a string that represents 'type', for use in log messages. */
const char *
dpif_upcall_type_to_string(enum dpif_upcall_type type)
{
    switch (type) {
    case DPIF_UC_MISS: return "miss";
    case DPIF_UC_ACTION: return "action";
    case DPIF_N_UC_TYPES: default: return "<unknown>";
    }
}

/* Enables or disables receiving packets with dpif_recv() on 'dpif'.  Returns 0
 * if successful, otherwise a positive errno value.
 *
 * Turning packet receive off and then back on may change the Netlink PID
 * assignments returned by dpif_port_get_pid().  If the client does this, it
 * must update all of the flows that have OVS_ACTION_ATTR_USERSPACE actions
 * using the new PID assignment. */
int
dpif_recv_set(struct dpif *dpif, bool enable)
{
    int error = 0;

    if (dpif->dpif_class->recv_set) {
        error = dpif->dpif_class->recv_set(dpif, enable);
        log_operation(dpif, "recv_set", error);
    }
    return error;
}

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
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
dpif_handlers_set(struct dpif *dpif, uint32_t n_handlers)
{
    int error = 0;

    if (dpif->dpif_class->handlers_set) {
        error = dpif->dpif_class->handlers_set(dpif, n_handlers);
        log_operation(dpif, "handlers_set", error);
    }
    return error;
}

void
dpif_register_dp_purge_cb(struct dpif *dpif, dp_purge_callback *cb, void *aux)
{
    if (dpif->dpif_class->register_dp_purge_cb) {
        dpif->dpif_class->register_dp_purge_cb(dpif, cb, aux);
    }
}

void
dpif_register_upcall_cb(struct dpif *dpif, upcall_callback *cb, void *aux)
{
    if (dpif->dpif_class->register_upcall_cb) {
        dpif->dpif_class->register_upcall_cb(dpif, cb, aux);
    }
}

void
dpif_enable_upcall(struct dpif *dpif)
{
    if (dpif->dpif_class->enable_upcall) {
        dpif->dpif_class->enable_upcall(dpif);
    }
}

void
dpif_disable_upcall(struct dpif *dpif)
{
    if (dpif->dpif_class->disable_upcall) {
        dpif->dpif_class->disable_upcall(dpif);
    }
}

void
dpif_print_packet(struct dpif *dpif, struct dpif_upcall *upcall)
{
    if (!VLOG_DROP_DBG(&dpmsg_rl)) {
        struct ds flow;
        char *packet;

        packet = ofp_dp_packet_to_string(&upcall->packet);

        ds_init(&flow);
        odp_flow_key_format(upcall->key, upcall->key_len, &flow);

        VLOG_DBG("%s: %s upcall:\n%s\n%s",
                 dpif_name(dpif), dpif_upcall_type_to_string(upcall->type),
                 ds_cstr(&flow), packet);

        ds_destroy(&flow);
        free(packet);
    }
}

/* Pass custom configuration to the datapath implementation.  Some of the
 * changes can be postponed until dpif_run() is called. */
int
dpif_set_config(struct dpif *dpif, const struct smap *cfg)
{
    int error = 0;

    if (dpif->dpif_class->set_config) {
        error = dpif->dpif_class->set_config(dpif, cfg);
        if (error) {
            log_operation(dpif, "set_config", error);
        }
    }

    return error;
}

/* Polls for an upcall from 'dpif' for an upcall handler.  Since there can
 * be multiple poll loops, 'handler_id' is needed as index to identify the
 * corresponding poll loop.  If successful, stores the upcall into '*upcall',
 * using 'buf' for storage.  Should only be called if 'recv_set' has been used
 * to enable receiving packets from 'dpif'.
 *
 * 'upcall->key' and 'upcall->userdata' point into data in the caller-provided
 * 'buf', so their memory cannot be freed separately from 'buf'.
 *
 * The caller owns the data of 'upcall->packet' and may modify it.  If
 * packet's headroom is exhausted as it is manipulated, 'upcall->packet'
 * will be reallocated.  This requires the data of 'upcall->packet' to be
 * released with ofpbuf_uninit() before 'upcall' is destroyed.  However,
 * when an error is returned, the 'upcall->packet' may be uninitialized
 * and should not be released.
 *
 * Returns 0 if successful, otherwise a positive errno value.  Returns EAGAIN
 * if no upcall is immediately available. */
int
dpif_recv(struct dpif *dpif, uint32_t handler_id, struct dpif_upcall *upcall,
          struct ofpbuf *buf)
{
    int error = EAGAIN;

    if (dpif->dpif_class->recv) {
        error = dpif->dpif_class->recv(dpif, handler_id, upcall, buf);
        if (!error) {
            dpif_print_packet(dpif, upcall);
        } else if (error != EAGAIN) {
            log_operation(dpif, "recv", error);
        }
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

/* Arranges for the poll loop for an upcall handler to wake up when 'dpif'
 * 'dpif' has a message queued to be received with the recv member
 * function.  Since there can be multiple poll loops, 'handler_id' is
 * needed as index to identify the corresponding poll loop. */
void
dpif_recv_wait(struct dpif *dpif, uint32_t handler_id)
{
    if (dpif->dpif_class->recv_wait) {
        dpif->dpif_class->recv_wait(dpif, handler_id);
    }
}

/*
 * Return the datapath version. Caller is responsible for freeing
 * the string.
 */
char *
dpif_get_dp_version(const struct dpif *dpif)
{
    char *version = NULL;

    if (dpif->dpif_class->get_datapath_version) {
        version = dpif->dpif_class->get_datapath_version();
    }

    return version;
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
 * value used for setting packet priority.
 * On success, returns 0 and stores the priority into '*priority'.
 * On failure, returns a positive errno value and stores 0 into '*priority'. */
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
    } else if (ofperr_is_valid(error)) {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     dpif_name(dpif), operation, ofperr_get_name(error));
    } else {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     dpif_name(dpif), operation, ovs_strerror(error));
    }
}

static enum vlog_level
flow_message_log_level(int error)
{
    /* If flows arrive in a batch, userspace may push down multiple
     * unique flow definitions that overlap when wildcards are applied.
     * Kernels that support flow wildcarding will reject these flows as
     * duplicates (EEXIST), so lower the log level to debug for these
     * types of messages. */
    return (error && error != EEXIST) ? VLL_WARN : VLL_DBG;
}

static bool
should_log_flow_message(const struct vlog_module *module, int error)
{
    return !vlog_should_drop(module, flow_message_log_level(error),
                             error ? &error_rl : &dpmsg_rl);
}

void
log_flow_message(const struct dpif *dpif, int error,
                 const struct vlog_module *module,
                 const char *operation,
                 const struct nlattr *key, size_t key_len,
                 const struct nlattr *mask, size_t mask_len,
                 const ovs_u128 *ufid, const struct dpif_flow_stats *stats,
                 const struct nlattr *actions, size_t actions_len)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "%s: ", dpif_name(dpif));
    if (error) {
        ds_put_cstr(&ds, "failed to ");
    }
    ds_put_format(&ds, "%s ", operation);
    if (error) {
        ds_put_format(&ds, "(%s) ", ovs_strerror(error));
    }
    if (ufid) {
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " ");
    }
    odp_flow_format(key, key_len, mask, mask_len, NULL, &ds, true);
    if (stats) {
        ds_put_cstr(&ds, ", ");
        dpif_flow_stats_format(stats, &ds);
    }
    if (actions || actions_len) {
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len, NULL);
    }
    vlog(module, flow_message_log_level(error), "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

void
log_flow_put_message(const struct dpif *dpif,
                     const struct vlog_module *module,
                     const struct dpif_flow_put *put,
                     int error)
{
    if (should_log_flow_message(module, error)
        && !(put->flags & DPIF_FP_PROBE)) {
        struct ds s;

        ds_init(&s);
        ds_put_cstr(&s, "put");
        if (put->flags & DPIF_FP_CREATE) {
            ds_put_cstr(&s, "[create]");
        }
        if (put->flags & DPIF_FP_MODIFY) {
            ds_put_cstr(&s, "[modify]");
        }
        if (put->flags & DPIF_FP_ZERO_STATS) {
            ds_put_cstr(&s, "[zero]");
        }
        log_flow_message(dpif, error, module, ds_cstr(&s),
                         put->key, put->key_len, put->mask, put->mask_len,
                         put->ufid, put->stats, put->actions,
                         put->actions_len);
        ds_destroy(&s);
    }
}

void
log_flow_del_message(const struct dpif *dpif,
                     const struct vlog_module *module,
                     const struct dpif_flow_del *del,
                     int error)
{
    if (should_log_flow_message(module, error)) {
        log_flow_message(dpif, error, module, "flow_del",
                         del->key, del->key_len,
                         NULL, 0, del->ufid, !error ? del->stats : NULL,
                         NULL, 0);
    }
}

/* Logs that 'execute' was executed on 'dpif' and completed with errno 'error'
 * (0 for success).  'subexecute' should be true if the execution is a result
 * of breaking down a larger execution that needed help, false otherwise.
 *
 *
 * XXX In theory, the log message could be deceptive because this function is
 * called after the dpif_provider's '->execute' function, which is allowed to
 * modify execute->packet and execute->md.  In practice, though:
 *
 *     - dpif-netlink doesn't modify execute->packet or execute->md.
 *
 *     - dpif-netdev does modify them but it is less likely to have problems
 *       because it is built into ovs-vswitchd and cannot have version skew,
 *       etc.
 *
 * It would still be better to avoid the potential problem.  I don't know of a
 * good way to do that, though, that isn't expensive. */
void
log_execute_message(const struct dpif *dpif,
                    const struct vlog_module *module,
                    const struct dpif_execute *execute,
                    bool subexecute, int error)
{
    if (!(error ? VLOG_DROP_WARN(&error_rl) : VLOG_DROP_DBG(&dpmsg_rl))
        && !execute->probe) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet;
        uint64_t stub[1024 / 8];
        struct ofpbuf md = OFPBUF_STUB_INITIALIZER(stub);

        packet = ofp_packet_to_string(dp_packet_data(execute->packet),
                                      dp_packet_size(execute->packet),
                                      execute->packet->packet_type);
        odp_key_from_dp_packet(&md, execute->packet);
        ds_put_format(&ds, "%s: %sexecute ",
                      dpif_name(dpif),
                      (subexecute ? "sub-"
                       : dpif_execute_needs_help(execute) ? "super-"
                       : ""));
        format_odp_actions(&ds, execute->actions, execute->actions_len, NULL);
        if (error) {
            ds_put_format(&ds, " failed (%s)", ovs_strerror(error));
        }
        ds_put_format(&ds, " on packet %s", packet);
        ds_put_format(&ds, " with metadata ");
        odp_flow_format(md.data, md.size, NULL, 0, NULL, &ds, true);
        ds_put_format(&ds, " mtu %d", execute->mtu);
        vlog(module, error ? VLL_WARN : VLL_DBG, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
        free(packet);
        ofpbuf_uninit(&md);
    }
}

void
log_flow_get_message(const struct dpif *dpif,
                     const struct vlog_module *module,
                     const struct dpif_flow_get *get,
                     int error)
{
    if (should_log_flow_message(module, error)) {
        log_flow_message(dpif, error, module, "flow_get",
                         get->key, get->key_len,
                         get->flow->mask, get->flow->mask_len,
                         get->ufid, &get->flow->stats,
                         get->flow->actions, get->flow->actions_len);
    }
}

bool
dpif_supports_tnl_push_pop(const struct dpif *dpif)
{
    return dpif_is_netdev(dpif);
}

/* Meters */
void
dpif_meter_get_features(const struct dpif *dpif,
                        struct ofputil_meter_features *features)
{
    memset(features, 0, sizeof *features);
    if (dpif->dpif_class->meter_get_features) {
        dpif->dpif_class->meter_get_features(dpif, features);
    }
}

/* Adds or modifies meter identified by 'meter_id' in 'dpif'.  If '*meter_id'
 * is UINT32_MAX, adds a new meter, otherwise modifies an existing meter.
 *
 * If meter is successfully added, sets '*meter_id' to the new meter's
 * meter number. */
int
dpif_meter_set(struct dpif *dpif, ofproto_meter_id *meter_id,
               struct ofputil_meter_config *config)
{
    int error;

    COVERAGE_INC(dpif_meter_set);

    error = dpif->dpif_class->meter_set(dpif, meter_id, config);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: DPIF meter %"PRIu32" set",
                    dpif_name(dpif), meter_id->uint32);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to set DPIF meter %"PRIu32": %s",
                     dpif_name(dpif), meter_id->uint32, ovs_strerror(error));
        meter_id->uint32 = UINT32_MAX;
    }
    return error;
}

int
dpif_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id,
               struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    int error;

    COVERAGE_INC(dpif_meter_get);

    error = dpif->dpif_class->meter_get(dpif, meter_id, stats, n_bands);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: DPIF meter %"PRIu32" get stats",
                    dpif_name(dpif), meter_id.uint32);
    } else {
        VLOG_WARN_RL(&error_rl,
                     "%s: failed to get DPIF meter %"PRIu32" stats: %s",
                     dpif_name(dpif), meter_id.uint32, ovs_strerror(error));
        stats->packet_in_count = ~0;
        stats->byte_in_count = ~0;
        stats->n_bands = 0;
    }
    return error;
}

int
dpif_meter_del(struct dpif *dpif, ofproto_meter_id meter_id,
               struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    int error;

    COVERAGE_INC(dpif_meter_del);

    error = dpif->dpif_class->meter_del(dpif, meter_id, stats, n_bands);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: DPIF meter %"PRIu32" deleted",
                    dpif_name(dpif), meter_id.uint32);
    } else {
        VLOG_WARN_RL(&error_rl,
                     "%s: failed to delete DPIF meter %"PRIu32": %s",
                     dpif_name(dpif), meter_id.uint32, ovs_strerror(error));
        if (stats) {
            stats->packet_in_count = ~0;
            stats->byte_in_count = ~0;
            stats->n_bands = 0;
        }
    }
    return error;
}
